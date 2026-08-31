use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hyper::header::{COOKIE, ORIGIN, REFERER};
use hyper::{HeaderMap, Method};
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;

use crate::backend::{SliderGesture, SliderPointerPhase, ViewPointer, ViewWheel};

pub(crate) const TOKEN_HEADER: &str = "x-obscura-bridge-token";
pub(crate) const SESSION_COOKIE: &str = "obscura_bridge_session";
pub(crate) const MAX_VIEW_WHEEL_DELTA: f64 = 2.0;

pub(crate) struct AuthState {
    token: String,
    session: Option<Session>,
    ttl: Duration,
    retired: bool,
}

struct Session {
    value: String,
    expires_at: Instant,
}

impl AuthState {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            token: random_secret(),
            session: None,
            ttl,
            retired: false,
        }
    }

    pub(crate) fn launch_token(&self) -> &str {
        &self.token
    }

    pub(crate) fn issue_session_cookie(&mut self) -> String {
        assert!(!self.retired, "retired gateway sessions cannot be reissued");
        let expired = self
            .session
            .as_ref()
            .is_none_or(|session| Instant::now() >= session.expires_at);
        if expired {
            self.session = Some(Session {
                value: random_secret(),
                expires_at: Instant::now() + self.ttl,
            });
        }
        let session = self.session.as_ref().expect("session was issued");
        format!(
            "{SESSION_COOKIE}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
            session.value,
            self.ttl.as_secs()
        )
    }

    pub(crate) fn rotate_session_cookie(&mut self) -> String {
        assert!(!self.retired, "retired gateway sessions cannot be rotated");
        self.session = None;
        self.issue_session_cookie()
    }

    pub(crate) fn retire_if_expired(&mut self) -> SessionExpiry {
        if self.retired {
            return SessionExpiry::Retired;
        }
        if self
            .session
            .as_ref()
            .is_some_and(|session| Instant::now() >= session.expires_at)
        {
            self.session = None;
            // The launch URL contains the previous token and can no longer be
            // used to mint a fresh bridge session after the TTL boundary.
            self.token = random_secret();
            self.retired = true;
            return SessionExpiry::ExpiredNow;
        }
        SessionExpiry::Active
    }

    fn session_value(&self) -> Option<&str> {
        let session = self.session.as_ref()?;
        (Instant::now() < session.expires_at).then_some(session.value.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionExpiry {
    Active,
    ExpiredNow,
    Retired,
}

fn random_secret() -> String {
    // Two independent UUIDv4 values provide substantially more entropy than a
    // bearer token needs while keeping the fragment/header alphabet simple.
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn secret_eq(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

pub(crate) fn loopback_origin(address: SocketAddr) -> String {
    match address {
        SocketAddr::V4(address) => format!("http://{}:{}", address.ip(), address.port()),
        SocketAddr::V6(address) => format!("http://[{}]:{}", address.ip(), address.port()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationError {
    MissingOrInvalidToken,
    MissingOrInvalidSession,
    InvalidOrigin,
}

pub(crate) fn authorize_api(
    headers: &HeaderMap,
    method: &Method,
    expected_origin: &str,
    auth: &AuthState,
) -> Result<(), AuthorizationError> {
    let supplied_token = headers
        .get(TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthorizationError::MissingOrInvalidToken)?;
    if !secret_eq(supplied_token, &auth.token) {
        return Err(AuthorizationError::MissingOrInvalidToken);
    }

    let expected_session = auth
        .session_value()
        .ok_or(AuthorizationError::MissingOrInvalidSession)?;
    if !cookie_has_exact_session(headers, expected_session) {
        return Err(AuthorizationError::MissingOrInvalidSession);
    }

    let mutating = !matches!(*method, Method::GET | Method::HEAD);
    match headers.get(ORIGIN).and_then(|value| value.to_str().ok()) {
        Some(origin) if exact_origin(origin, expected_origin) => {}
        Some(_) => return Err(AuthorizationError::InvalidOrigin),
        None if mutating => return Err(AuthorizationError::InvalidOrigin),
        None => {
            let same_site = headers
                .get("sec-fetch-site")
                .and_then(|value| value.to_str().ok())
                == Some("same-origin");
            let trusted_referer = headers
                .get(REFERER)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|referer| url_has_origin(referer, expected_origin));
            if !same_site || !trusted_referer {
                return Err(AuthorizationError::InvalidOrigin);
            }
        }
    }
    Ok(())
}

pub(crate) fn authorize_same_origin_document(
    headers: &HeaderMap,
    expected_origin: &str,
    auth: &AuthState,
) -> Result<(), AuthorizationError> {
    let expected_session = auth
        .session_value()
        .ok_or(AuthorizationError::MissingOrInvalidSession)?;
    if !cookie_has_exact_session(headers, expected_session) {
        return Err(AuthorizationError::MissingOrInvalidSession);
    }
    let same_site = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        == Some("same-origin");
    let trusted_referer = headers
        .get(REFERER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|referer| url_has_origin(referer, expected_origin));
    if !same_site || !trusted_referer {
        return Err(AuthorizationError::InvalidOrigin);
    }
    Ok(())
}

fn cookie_has_exact_session(headers: &HeaderMap, expected: &str) -> bool {
    let mut found = None;
    for value in headers.get_all(COOKIE) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        for pair in value.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name == SESSION_COOKIE {
                if found.is_some() {
                    return false;
                }
                found = Some(value);
            }
        }
    }
    found.is_some_and(|value| secret_eq(value, expected))
}

fn exact_origin(value: &str, expected: &str) -> bool {
    value == expected && url_has_origin(value, expected)
}

fn url_has_origin(value: &str, expected: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let Some(port) = url.port_or_known_default() else {
        return false;
    };
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_ascii_lowercase()
    };
    let origin = match (url.scheme(), port) {
        ("http", 80) => format!("http://{host}"),
        ("https", 443) => format!("https://{host}"),
        ("http" | "https", port) => format!("{}://{host}:{port}", url.scheme()),
        _ => return false,
    };
    origin == expected
}

pub(crate) fn validate_slider_gesture(gesture: &SliderGesture) -> Result<(), InputValidationError> {
    let samples = &gesture.samples;
    if samples.len() < 3
        || samples.len() > 512
        || samples.first().map(|sample| sample.phase) != Some(SliderPointerPhase::Down)
        || samples.last().map(|sample| sample.phase) != Some(SliderPointerPhase::Up)
        || samples[0].x > 0.12
        || samples[0].elapsed_ms > 50
    {
        return Err(InputValidationError::InvalidSequence);
    }
    let start = &samples[0];
    let mut last_sequence = start.sequence;
    let mut last_elapsed = start.elapsed_ms;
    let mut moved = false;
    for (index, sample) in samples.iter().enumerate() {
        validate_normalized_point(sample.x, sample.y)?;
        if index == 0 {
            continue;
        }
        let is_last = index + 1 == samples.len();
        if sample.sequence <= last_sequence
            || sample.elapsed_ms < last_elapsed
            || sample.elapsed_ms > 30_000
            || (is_last && sample.phase != SliderPointerPhase::Up)
            || (!is_last && sample.phase != SliderPointerPhase::Move)
        {
            return Err(InputValidationError::InvalidSequence);
        }
        if sample.phase == SliderPointerPhase::Move
            && ((sample.x - start.x).abs() > 0.001 || (sample.y - start.y).abs() > 0.001)
        {
            moved = true;
        }
        last_sequence = sample.sequence;
        last_elapsed = sample.elapsed_ms;
    }
    moved
        .then_some(())
        .ok_or(InputValidationError::InvalidSequence)
}

#[derive(Default)]
pub(crate) struct ViewSequence {
    last_sequence: Option<u64>,
}

impl ViewSequence {
    pub(crate) fn accept(&mut self, event: ViewPointer) -> Result<(), InputValidationError> {
        self.accept_sample(event.sequence, event.x, event.y)
    }

    pub(crate) fn accept_wheel(&mut self, event: ViewWheel) -> Result<(), InputValidationError> {
        validate_view_wheel(event)?;
        self.accept_sample(event.sequence, event.x, event.y)
    }

    fn accept_sample(&mut self, sequence: u64, x: f64, y: f64) -> Result<(), InputValidationError> {
        validate_normalized_point(x, y)?;
        if self.last_sequence.is_some_and(|last| sequence <= last) {
            return Err(InputValidationError::InvalidSequence);
        }
        self.last_sequence = Some(sequence);
        Ok(())
    }

    pub(crate) fn reset(&mut self) {
        self.last_sequence = None;
    }
}

pub(crate) fn validate_view_wheel(event: ViewWheel) -> Result<(), InputValidationError> {
    validate_normalized_point(event.x, event.y)?;
    if !event.delta_x.is_finite()
        || !event.delta_y.is_finite()
        || event.delta_x.abs() > MAX_VIEW_WHEEL_DELTA
        || event.delta_y.abs() > MAX_VIEW_WHEEL_DELTA
        || (event.delta_x == 0.0 && event.delta_y == 0.0)
    {
        return Err(InputValidationError::InvalidCoordinates);
    }
    Ok(())
}

fn validate_normalized_point(x: f64, y: f64) -> Result<(), InputValidationError> {
    if x.is_finite() && y.is_finite() && (0.0..=1.0).contains(&x) && (0.0..=1.0).contains(&y) {
        Ok(())
    } else {
        Err(InputValidationError::InvalidCoordinates)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputValidationError {
    InvalidCoordinates,
    InvalidSequence,
}

pub(crate) struct FixedWindowLimit {
    started_at: Instant,
    count: u16,
    max: u16,
    period: Duration,
}

impl FixedWindowLimit {
    pub(crate) fn per_minute(max: u16) -> Self {
        Self::new(max, Duration::from_secs(60))
    }

    pub(crate) fn per_second(max: u16) -> Self {
        Self::new(max, Duration::from_secs(1))
    }

    fn new(max: u16, period: Duration) -> Self {
        Self {
            started_at: Instant::now(),
            count: 0,
            max,
            period,
        }
    }

    pub(crate) fn take(&mut self) -> bool {
        if self.started_at.elapsed() >= self.period {
            self.started_at = Instant::now();
            self.count = 0;
        }
        if self.count >= self.max {
            return false;
        }
        self.count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn authorized_headers(auth: &mut AuthState, origin: &str) -> HeaderMap {
        let cookie = auth.issue_session_cookie();
        let cookie = cookie.split(';').next().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            TOKEN_HEADER,
            HeaderValue::from_str(auth.launch_token()).unwrap(),
        );
        headers.insert(COOKIE, HeaderValue::from_str(cookie).unwrap());
        headers.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        headers
    }

    #[test]
    fn api_needs_token_session_and_exact_origin() {
        let origin = "http://127.0.0.1:9173";
        let mut auth = AuthState::new(Duration::from_secs(60));
        let headers = authorized_headers(&mut auth, origin);
        assert_eq!(
            authorize_api(&headers, &Method::POST, origin, &auth),
            Ok(())
        );

        let mut wrong = headers.clone();
        wrong.insert(ORIGIN, HeaderValue::from_static("http://localhost:9173"));
        assert_eq!(
            authorize_api(&wrong, &Method::POST, origin, &auth),
            Err(AuthorizationError::InvalidOrigin)
        );

        let mut missing = headers;
        missing.remove(TOKEN_HEADER);
        assert_eq!(
            authorize_api(&missing, &Method::POST, origin, &auth),
            Err(AuthorizationError::MissingOrInvalidToken)
        );
    }

    #[test]
    fn duplicate_session_cookie_is_rejected() {
        let origin = "http://127.0.0.1:9173";
        let mut auth = AuthState::new(Duration::from_secs(60));
        let mut headers = authorized_headers(&mut auth, origin);
        let session = auth.session_value().unwrap();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!(
                "{SESSION_COOKIE}={session}; {SESSION_COOKIE}={session}"
            ))
            .unwrap(),
        );
        assert_eq!(
            authorize_api(&headers, &Method::POST, origin, &auth),
            Err(AuthorizationError::MissingOrInvalidSession)
        );
    }

    #[test]
    fn same_origin_get_uses_fetch_metadata_and_referer() {
        let origin = "http://127.0.0.1:9173";
        let mut auth = AuthState::new(Duration::from_secs(60));
        let cookie = auth.issue_session_cookie();
        let mut headers = HeaderMap::new();
        headers.insert(
            TOKEN_HEADER,
            HeaderValue::from_str(auth.launch_token()).unwrap(),
        );
        headers.insert(
            COOKIE,
            HeaderValue::from_str(cookie.split(';').next().unwrap()).unwrap(),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        headers.insert(
            REFERER,
            HeaderValue::from_static("http://127.0.0.1:9173/view"),
        );
        assert_eq!(authorize_api(&headers, &Method::GET, origin, &auth), Ok(()));
        headers.remove(REFERER);
        assert_eq!(
            authorize_api(&headers, &Method::GET, origin, &auth),
            Err(AuthorizationError::InvalidOrigin)
        );
    }

    #[test]
    fn slider_requires_ordered_down_move_up_without_distance_field() {
        let event = |phase, sequence, x, elapsed_ms| crate::backend::SliderPointer {
            phase,
            x,
            y: 0.5,
            sequence,
            elapsed_ms,
        };
        let valid = SliderGesture {
            generation: 7,
            samples: vec![
                event(SliderPointerPhase::Down, 1, 0.05, 0),
                event(SliderPointerPhase::Move, 2, 0.4, 180),
                event(SliderPointerPhase::Up, 3, 0.5, 260),
            ],
        };
        assert!(validate_slider_gesture(&valid).is_ok());
        assert_eq!(
            validate_slider_gesture(&SliderGesture {
                generation: 7,
                samples: vec![
                    event(SliderPointerPhase::Down, 1, 0.05, 0),
                    event(SliderPointerPhase::Up, 2, 0.5, 200),
                ],
            }),
            Err(InputValidationError::InvalidSequence)
        );
        assert_eq!(
            validate_slider_gesture(&SliderGesture {
                generation: 7,
                samples: vec![
                    event(SliderPointerPhase::Down, 1, 0.5, 0),
                    event(SliderPointerPhase::Move, 2, 0.6, 100),
                    event(SliderPointerPhase::Up, 3, 0.7, 200),
                ],
            }),
            Err(InputValidationError::InvalidSequence)
        );
        assert!(serde_json::from_value::<SliderGesture>(serde_json::json!({
            "generation": 7,
            "samples": [{
                "phase": "down",
                "x": 0.0,
                "y": 0.5,
                "sequence": 1,
                "elapsed_ms": 0
            }],
            "distance": 180
        }))
        .is_err());
    }

    #[test]
    fn remote_wheel_is_ordered_normalized_and_delta_bounded() {
        let sample = |sequence, x, delta_y| ViewWheel {
            x,
            y: 0.5,
            delta_x: 0.0,
            delta_y,
            sequence,
        };
        let mut sequence = ViewSequence::default();
        assert!(sequence.accept_wheel(sample(1, 0.25, 0.5)).is_ok());
        assert_eq!(
            sequence.accept_wheel(sample(1, 0.25, 0.5)),
            Err(InputValidationError::InvalidSequence)
        );
        assert_eq!(
            sequence.accept_wheel(sample(2, 1.1, 0.5)),
            Err(InputValidationError::InvalidCoordinates)
        );
        assert_eq!(
            sequence.accept_wheel(sample(2, 0.25, MAX_VIEW_WHEEL_DELTA + 0.01)),
            Err(InputValidationError::InvalidCoordinates)
        );
        assert_eq!(
            sequence.accept_wheel(sample(2, 0.25, 0.0)),
            Err(InputValidationError::InvalidCoordinates)
        );
        assert!(sequence.accept_wheel(sample(2, 0.25, -2.0)).is_ok());
    }

    #[test]
    fn remote_wheel_rate_limit_allows_only_thirty_samples_per_second() {
        let mut limit = FixedWindowLimit::per_second(30);
        for _ in 0..30 {
            assert!(limit.take());
        }
        assert!(!limit.take());
    }

    #[test]
    fn pointer_and_wheel_share_one_monotonic_view_sequence() {
        let mut sequence = ViewSequence::default();
        sequence
            .accept_wheel(ViewWheel {
                x: 0.5,
                y: 0.5,
                delta_x: 0.0,
                delta_y: 0.25,
                sequence: 1,
            })
            .unwrap();
        sequence
            .accept(ViewPointer {
                kind: crate::backend::ViewPointerKind::Down,
                x: 0.5,
                y: 0.5,
                sequence: 2,
            })
            .unwrap();
        assert_eq!(
            sequence.accept_wheel(ViewWheel {
                x: 0.5,
                y: 0.5,
                delta_x: 0.0,
                delta_y: 0.25,
                sequence: 2,
            }),
            Err(InputValidationError::InvalidSequence)
        );
    }

    #[test]
    fn rotating_session_changes_the_http_only_strict_cookie() {
        let mut auth = AuthState::new(Duration::from_secs(60));
        let first = auth.issue_session_cookie();
        let second = auth.rotate_session_cookie();
        assert_ne!(first, second);
        assert!(second.contains("HttpOnly"));
        assert!(second.contains("SameSite=Strict"));
        assert!(second.contains("Path=/"));
        assert!(!second.contains("Domain="));
    }

    #[test]
    fn expired_session_retires_launch_token_permanently() {
        let mut auth = AuthState::new(Duration::from_secs(60));
        let launch_token = auth.launch_token().to_string();
        auth.issue_session_cookie();
        auth.session.as_mut().unwrap().expires_at = Instant::now() - Duration::from_secs(1);

        assert_eq!(auth.retire_if_expired(), SessionExpiry::ExpiredNow);
        assert_ne!(auth.launch_token(), launch_token);
        assert!(auth.session_value().is_none());
        assert_eq!(auth.retire_if_expired(), SessionExpiry::Retired);
    }
}
