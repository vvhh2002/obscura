//! Browser-owned integration primitives for legacy login pages.
//!
//! This module deliberately relays user input to the original live widget. It
//! does not calculate CAPTCHA answers, expose provider tokens, or manufacture a
//! pointer trail. A lease is tied to one document generation and to retained
//! DOM nodes in the realm where the login form/widget was observed.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{CaptchaAdapter, Page};

const MAX_INSPECTED_FRAMES: usize = 32;
const MAX_EVAL_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_LEGACY_WHEEL_DELTA: f64 = 8_192.0;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl LegacyRect {
    pub fn contains_with_slop(self, x: f64, y: f64, slop: f64) -> bool {
        x >= self.x - slop
            && y >= self.y - slop
            && x <= self.x + self.width + slop
            && y <= self.y + self.height + slop
    }

    fn translated(self, x: f64, y: f64) -> Self {
        Self {
            x: self.x + x,
            y: self.y + y,
            ..self
        }
    }

    fn is_usable(self) -> bool {
        self.x.is_finite()
            && self.y.is_finite()
            && self.width.is_finite()
            && self.height.is_finite()
            && self.width > 0.0
            && self.height > 0.0
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyLoginSelectors {
    pub username: Option<String>,
    pub password: Option<String>,
    pub submit: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LegacyLoginTarget {
    pub frame_id: u32,
    pub username_label: String,
    pub password_label: String,
    pub submit_label: Option<String>,
    /// A unique selector observed during discovery, when the page exposes a
    /// stable id/name/autocomplete attribute. Runtime interaction never trusts
    /// these strings after inspection; retained node leases remain authoritative.
    pub username_selector: Option<String>,
    pub password_selector: Option<String>,
    pub submit_selector: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LegacyCaptchaTarget {
    pub adapter: CaptchaAdapter,
    pub mode: String,
    pub frame_id: u32,
    /// Widget crop in its owning frame's viewport coordinates.
    pub frame_crop_rect: LegacyRect,
    /// Drag handle in its owning frame's viewport coordinates.
    pub frame_start_rect: LegacyRect,
    /// Widget crop translated into the top page's viewport coordinates.
    pub top_viewport_rect: LegacyRect,
}

/// Stable realm chosen for one remote-view pointer sequence. Coordinates
/// supplied by the wrapper are top-viewport CSS pixels; this target retains
/// the owning child realm and the translation needed to preserve that same
/// realm until pointer-up.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LegacyViewTarget {
    pub frame_id: u32,
    pub top_offset_x: f64,
    pub top_offset_y: f64,
}

impl LegacyViewTarget {
    pub fn frame_point(self, top_x: f64, top_y: f64) -> (f64, f64) {
        (top_x - self.top_offset_x, top_y - self.top_offset_y)
    }
}

/// Opaque retained-node lease. The nonce is intentionally not exposed: callers
/// can hold/clone the lease, but cannot serialize it into a browser response.
#[derive(Clone, Debug)]
pub struct LegacyTargetLease {
    nonce: String,
    document_generation: u64,
    login_frame_id: Option<u32>,
    captcha_frame_id: Option<u32>,
}

impl LegacyTargetLease {
    pub fn document_generation(&self) -> u64 {
        self.document_generation
    }
}

#[derive(Clone, Debug)]
pub struct LegacyInspection {
    pub page_url: String,
    pub document_generation: u64,
    pub login: Option<LegacyLoginTarget>,
    pub captcha: Option<LegacyCaptchaTarget>,
    pub diagnostics: Vec<String>,
    lease: LegacyTargetLease,
}

impl LegacyInspection {
    pub fn lease(&self) -> &LegacyTargetLease {
        &self.lease
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyPointerPhase {
    Down,
    Move,
    Up,
    Cancel,
}

impl LegacyPointerPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Down => "down",
            Self::Move => "move",
            Self::Up => "up",
            Self::Cancel => "cancel",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyAuthProbe {
    /// Number of elements matching the configured success selector across the
    /// top document and inspected child-frame realms, regardless of visibility.
    pub success_candidate_count: usize,
    pub matched: bool,
    /// True when no subject selector was requested, or it resolved to exactly
    /// one visible subject in the authenticated realm.
    pub subject_matched: bool,
    /// Display-only legacy subject text. It must not be used to grant roles;
    /// production account mapping needs a configured authenticated endpoint.
    pub subject: Option<String>,
}

#[derive(Debug)]
struct RealmAuthProbe {
    candidate_count: usize,
    matched: Option<LegacyAuthProbe>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RealmInspection {
    #[serde(default)]
    parent_frame_id: u32,
    #[serde(default)]
    login_count: usize,
    #[serde(default)]
    captcha_count: usize,
    login: Option<RealmLogin>,
    captcha: Option<RealmCaptcha>,
    #[serde(default)]
    diagnostics: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RealmLogin {
    username_label: String,
    password_label: String,
    submit_label: Option<String>,
    username_selector: Option<String>,
    password_selector: Option<String>,
    submit_selector: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RealmCaptcha {
    adapter: String,
    mode: String,
    crop_rect: LegacyRect,
    start_rect: LegacyRect,
}

/// Install trusted-builtin snapshots and retained-node lease storage in every
/// new document. This must run before navigation (like the CAPTCHA capture
/// preload); installing it after a page has replaced DOM methods is rejected by
/// inspection because no bridge exists in that live realm.
pub fn install_legacy_bridge_preload(page: &mut Page) {
    page.add_preload_script(LEGACY_BRIDGE_PRELOAD);
}

/// Inspect the live top document and child frames for one unambiguous login
/// form and one unambiguous supported slide CAPTCHA. Detection is read-only;
/// retained targets can only be used through the returned opaque lease.
pub fn inspect_legacy_page(
    page: &mut Page,
    adapter: CaptchaAdapter,
    selectors: &LegacyLoginSelectors,
    timeout: Duration,
) -> Result<LegacyInspection, String> {
    let timeout = bounded_timeout(timeout);
    let nonce = uuid::Uuid::new_v4().as_simple().to_string();
    let options = json!({
        "adapter": adapter.as_str(),
        "selectors": selectors,
    });
    let options = serde_json::to_string(&options).map_err(|error| error.to_string())?;
    let nonce_literal = serde_json::to_string(&nonce).map_err(|error| error.to_string())?;
    let expression =
        format!("globalThis.__obscuraLegacyBridge?.inspect({nonce_literal},{options}) ?? null");

    let mut realms = Vec::new();
    let top = evaluate_realm(page, 0, &expression, timeout)?;
    realms.push((0, parse_realm_inspection(top, 0)?));
    let snapshots = page.frame_snapshots();
    if snapshots.len() > MAX_INSPECTED_FRAMES {
        revoke_nonce(page, &nonce, timeout);
        return Err(format!(
            "legacy page has {} live child frames; inspection limit is {MAX_INSPECTED_FRAMES}",
            snapshots.len()
        ));
    }
    for frame in snapshots {
        let value = evaluate_realm(page, frame.frame_id, &expression, timeout)?;
        realms.push((
            frame.frame_id,
            parse_realm_inspection(value, frame.frame_id)?,
        ));
    }

    let login_count = realms
        .iter()
        .map(|(_, realm)| realm.login_count)
        .sum::<usize>();
    let captcha_count = realms
        .iter()
        .map(|(_, realm)| realm.captcha_count)
        .sum::<usize>();
    if login_count > 1 || captcha_count > 1 {
        revoke_nonce(page, &nonce, timeout);
        let mut ambiguous = Vec::new();
        if login_count > 1 {
            ambiguous.push(format!("{login_count} login forms"));
        }
        if captcha_count > 1 {
            ambiguous.push(format!("{captcha_count} supported slide CAPTCHA widgets"));
        }
        return Err(format!(
            "legacy page inspection is ambiguous: {}",
            ambiguous.join(" and ")
        ));
    }

    let mut diagnostics = realms
        .iter()
        .flat_map(|(frame_id, realm)| {
            realm
                .diagnostics
                .iter()
                .map(move |message| format!("frame {frame_id}: {message}"))
        })
        .collect::<Vec<_>>();
    diagnostics.sort();
    diagnostics.dedup();

    let login = realms.iter().find_map(|(frame_id, realm)| {
        realm.login.as_ref().map(|login| LegacyLoginTarget {
            frame_id: *frame_id,
            username_label: login.username_label.clone(),
            password_label: login.password_label.clone(),
            submit_label: login.submit_label.clone(),
            username_selector: login.username_selector.clone(),
            password_selector: login.password_selector.clone(),
            submit_selector: login.submit_selector.clone(),
        })
    });

    let parents = realms
        .iter()
        .map(|(frame_id, realm)| (*frame_id, realm.parent_frame_id))
        .collect::<HashMap<_, _>>();
    let captcha = realms
        .iter()
        .find_map(|(frame_id, realm)| realm.captcha.as_ref().map(|captcha| (*frame_id, captcha)))
        .map(|(frame_id, captcha)| {
            let adapter = captcha
                .adapter
                .parse::<CaptchaAdapter>()
                .map_err(|error| format!("legacy bridge returned an invalid adapter: {error}"))?;
            if !captcha.crop_rect.is_usable() || !captcha.start_rect.is_usable() {
                return Err("legacy CAPTCHA has unusable layout geometry".to_string());
            }
            let (offset_x, offset_y) = frame_top_offset(page, frame_id, &parents, timeout)?;
            Ok(LegacyCaptchaTarget {
                adapter,
                mode: captcha.mode.clone(),
                frame_id,
                frame_crop_rect: captcha.crop_rect,
                frame_start_rect: captcha.start_rect,
                top_viewport_rect: captcha.crop_rect.translated(offset_x, offset_y),
            })
        })
        .transpose()?;

    let generation = page.document_generation();
    let lease = LegacyTargetLease {
        nonce,
        document_generation: generation,
        login_frame_id: login.as_ref().map(|target| target.frame_id),
        captcha_frame_id: captcha.as_ref().map(|target| target.frame_id),
    };
    Ok(LegacyInspection {
        page_url: page.url_string(),
        document_generation: generation,
        login,
        captcha,
        diagnostics,
        lease,
    })
}

pub fn fill_legacy_credentials(
    page: &mut Page,
    lease: &LegacyTargetLease,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<(), String> {
    validate_generation(page, lease)?;
    let frame_id = lease
        .login_frame_id
        .ok_or_else(|| "the legacy inspection did not retain a login form".to_string())?;
    if username.len() > 4_096 || password.len() > 16_384 {
        return Err("legacy credentials exceed the bounded field length".to_string());
    }
    let expression = bridge_call(
        "fill",
        &lease.nonce,
        json!({"username": username, "password": password}),
    )?;
    expect_bridge_ok(evaluate_sensitive_realm(
        page,
        frame_id,
        &expression,
        bounded_timeout(timeout),
    )?)
}

/// Dispatch one real client sample to the original retained widget. Coordinates
/// are frame-local CSS pixels. Callers must preserve the user's ordering and
/// timing; this API intentionally accepts neither an answer nor a distance.
pub fn dispatch_legacy_captcha_pointer(
    page: &mut Page,
    lease: &LegacyTargetLease,
    phase: LegacyPointerPhase,
    x: f64,
    y: f64,
    timeout: Duration,
) -> Result<(), String> {
    validate_generation(page, lease)?;
    if !x.is_finite() || !y.is_finite() {
        return Err("legacy pointer coordinates must be finite".to_string());
    }
    let frame_id = lease
        .captcha_frame_id
        .ok_or_else(|| "the legacy inspection did not retain a CAPTCHA widget".to_string())?;
    let expression = bridge_call(
        "captchaPointer",
        &lease.nonce,
        json!({"phase": phase.as_str(), "x": x, "y": y}),
    )?;
    expect_bridge_ok(evaluate_realm(
        page,
        frame_id,
        &expression,
        bounded_timeout(timeout),
    )?)
}

/// Re-check the retained widget after asynchronous provider callbacks have
/// settled. `false` means the original image/layout/node lease changed; the
/// caller must rescan before accepting another gesture or submitting.
pub fn legacy_captcha_target_is_current(
    page: &mut Page,
    lease: &LegacyTargetLease,
    timeout: Duration,
) -> Result<bool, String> {
    validate_generation(page, lease)?;
    let frame_id = lease
        .captcha_frame_id
        .ok_or_else(|| "the legacy inspection did not retain a CAPTCHA widget".to_string())?;
    let expression = bridge_call("captchaCurrent", &lease.nonce, json!({}))?;
    let value = evaluate_realm(page, frame_id, &expression, bounded_timeout(timeout))?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(bridge_error(&value));
    }
    value
        .get("current")
        .and_then(Value::as_bool)
        .ok_or_else(|| "legacy CAPTCHA lease validation returned an invalid result".to_string())
}

pub fn submit_legacy_login(
    page: &mut Page,
    lease: &LegacyTargetLease,
    timeout: Duration,
) -> Result<(), String> {
    validate_generation(page, lease)?;
    let frame_id = lease
        .login_frame_id
        .ok_or_else(|| "the legacy inspection did not retain a login form".to_string())?;
    let expression = bridge_call("submit", &lease.nonce, json!({}))?;
    expect_bridge_ok(evaluate_realm(
        page,
        frame_id,
        &expression,
        bounded_timeout(timeout),
    )?)
}

/// Pointer relay for the authenticated remote viewport. The nonce is generated
/// by the server session and never accepted as a selector or DOM id.
pub fn dispatch_legacy_view_pointer(
    page: &mut Page,
    session_nonce: &str,
    frame_id: u32,
    phase: LegacyPointerPhase,
    x: f64,
    y: f64,
    timeout: Duration,
) -> Result<(), String> {
    if session_nonce.len() < 16 || session_nonce.len() > 128 {
        return Err("invalid legacy view session nonce".to_string());
    }
    if !x.is_finite() || !y.is_finite() {
        return Err("legacy pointer coordinates must be finite".to_string());
    }
    let expression = bridge_call(
        "viewPointer",
        session_nonce,
        json!({"phase": phase.as_str(), "x": x, "y": y}),
    )?;
    expect_bridge_ok(evaluate_realm(
        page,
        frame_id,
        &expression,
        bounded_timeout(timeout),
    )?)
}

/// Relay one pixel-mode wheel sample to the deepest realm selected by the
/// caller. The bridge snapshots trusted event, hit-test and dispatch
/// primitives before page code can replace them, and follows the same nested
/// overflow-then-root default-action semantics as CDP `mouseWheel`.
pub fn dispatch_legacy_view_wheel(
    page: &mut Page,
    frame_id: u32,
    x: f64,
    y: f64,
    delta_x: f64,
    delta_y: f64,
    timeout: Duration,
) -> Result<(), String> {
    if !x.is_finite()
        || !y.is_finite()
        || !delta_x.is_finite()
        || !delta_y.is_finite()
        || delta_x.abs() > MAX_LEGACY_WHEEL_DELTA
        || delta_y.abs() > MAX_LEGACY_WHEEL_DELTA
        || (delta_x == 0.0 && delta_y == 0.0)
    {
        return Err("legacy wheel coordinates or deltas are invalid".to_string());
    }
    let payload = serde_json::to_string(&json!({
        "x": x,
        "y": y,
        "deltaX": delta_x,
        "deltaY": delta_y,
    }))
    .map_err(|error| error.to_string())?;
    let expression = format!("globalThis.__obscuraLegacyBridge?.viewWheel({payload}) ?? null");
    expect_bridge_ok(evaluate_realm(
        page,
        frame_id,
        &expression,
        bounded_timeout(timeout),
    )?)
}

pub fn type_into_legacy_view(
    page: &mut Page,
    frame_id: u32,
    text: &str,
    timeout: Duration,
) -> Result<(), String> {
    if text.len() > 16_384 {
        return Err("legacy text input exceeds the bounded field length".to_string());
    }
    let literal = serde_json::to_string(text).map_err(|error| error.to_string())?;
    let expression = format!("globalThis.__obscuraLegacyBridge?.typeText({literal}) ?? null");
    expect_bridge_ok(evaluate_realm(
        page,
        frame_id,
        &expression,
        bounded_timeout(timeout),
    )?)
}

pub fn probe_legacy_authentication(
    page: &mut Page,
    success_selector: &str,
    subject_selector: Option<&str>,
    timeout: Duration,
) -> Result<LegacyAuthProbe, String> {
    validate_selector_length(success_selector)?;
    if let Some(selector) = subject_selector {
        validate_selector_length(selector)?;
    }
    let success = serde_json::to_string(success_selector).map_err(|error| error.to_string())?;
    let subject = serde_json::to_string(&subject_selector).map_err(|error| error.to_string())?;
    let expression =
        format!("globalThis.__obscuraLegacyBridge?.probe({success},{subject}) ?? null");
    let timeout = bounded_timeout(timeout);
    let mut candidate_count = 0usize;
    let mut matched = Vec::new();
    let top = evaluate_realm(page, 0, &expression, timeout)?;
    let top = parse_probe(top)?;
    candidate_count = candidate_count
        .checked_add(top.candidate_count)
        .ok_or_else(|| "legacy authentication probe match count overflowed".to_string())?;
    if let Some(probe) = top.matched {
        matched.push(probe);
    }
    for frame in page
        .frame_snapshots()
        .into_iter()
        .take(MAX_INSPECTED_FRAMES)
    {
        let value = evaluate_realm(page, frame.frame_id, &expression, timeout)?;
        let realm = parse_probe(value)?;
        candidate_count = candidate_count
            .checked_add(realm.candidate_count)
            .ok_or_else(|| "legacy authentication probe match count overflowed".to_string())?;
        if let Some(probe) = realm.matched {
            matched.push(probe);
        }
    }
    if candidate_count != 1 || matched.len() != 1 {
        return Ok(LegacyAuthProbe {
            success_candidate_count: candidate_count,
            matched: false,
            subject_matched: subject_selector.is_none(),
            subject: None,
        });
    }
    let mut probe = matched.pop().expect("one authentication match was checked");
    probe.success_candidate_count = candidate_count;
    Ok(probe)
}

/// Return the top-viewport offset of a child frame. Remote-view input uses this
/// to retain the same realm for an entire drag without trusting client selectors.
pub fn legacy_frame_top_offset(
    page: &mut Page,
    frame_id: u32,
    timeout: Duration,
) -> Result<(f64, f64), String> {
    let timeout = bounded_timeout(timeout);
    let mut parents = HashMap::from([(0, 0)]);
    for frame in page
        .frame_snapshots()
        .into_iter()
        .take(MAX_INSPECTED_FRAMES)
    {
        let value = evaluate_realm(
            page,
            frame.frame_id,
            "globalThis.__obscuraLegacyBridge?.metadata() ?? null",
            timeout,
        )?;
        let parent = value
            .get("parentFrameId")
            .and_then(Value::as_u64)
            .ok_or_else(|| "legacy frame metadata is unavailable".to_string())?;
        parents.insert(frame.frame_id, parent as u32);
    }
    frame_top_offset(page, frame_id, &parents, timeout)
}

/// Resolve a top-viewport point into the deepest live Obscura child realm.
/// The returned target is retained by the caller for the full down/move/up
/// sequence, so moving outside the child frame does not retarget a drag.
pub fn locate_legacy_view_target(
    page: &mut Page,
    top_x: f64,
    top_y: f64,
    timeout: Duration,
) -> Result<LegacyViewTarget, String> {
    if !top_x.is_finite() || !top_y.is_finite() {
        return Err("legacy remote-view coordinates must be finite".to_string());
    }
    let timeout = bounded_timeout(timeout);
    let snapshots = page.frame_snapshots();
    if snapshots.len() > MAX_INSPECTED_FRAMES {
        return Err(format!(
            "legacy page has {} live child frames; remote-view limit is {MAX_INSPECTED_FRAMES}",
            snapshots.len()
        ));
    }
    let mut parents = HashMap::from([(0, 0)]);
    for frame in &snapshots {
        let value = evaluate_realm(
            page,
            frame.frame_id,
            "globalThis.__obscuraLegacyBridge?.metadata() ?? null",
            timeout,
        )?;
        let parent = value
            .get("parentFrameId")
            .and_then(Value::as_u64)
            .ok_or_else(|| "legacy frame metadata is unavailable".to_string())?;
        parents.insert(frame.frame_id, parent as u32);
    }

    let mut selected = LegacyViewTarget {
        frame_id: 0,
        top_offset_x: 0.0,
        top_offset_y: 0.0,
    };
    let mut selected_depth = 0usize;
    for frame in snapshots {
        let rect = frame_top_rect(page, frame.frame_id, &parents, timeout)?;
        let depth = frame_depth(frame.frame_id, &parents)?;
        if rect.contains_with_slop(top_x, top_y, 0.0) && depth > selected_depth {
            selected = LegacyViewTarget {
                frame_id: frame.frame_id,
                top_offset_x: rect.x,
                top_offset_y: rect.y,
            };
            selected_depth = depth;
        }
    }
    Ok(selected)
}

fn validate_selector_length(selector: &str) -> Result<(), String> {
    if selector.trim().is_empty() || selector.len() > 1_024 {
        Err("legacy probe selector is empty or too long".to_string())
    } else {
        Ok(())
    }
}

fn parse_probe(value: Value) -> Result<RealmAuthProbe, String> {
    if value.is_null() {
        return Ok(RealmAuthProbe {
            candidate_count: 0,
            matched: None,
        });
    }
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(bridge_error(&value));
    }
    let candidate_count = value
        .get("candidateCount")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| "legacy authentication probe returned an invalid match count".to_string())?;
    if value.get("matched").and_then(Value::as_bool) != Some(true) {
        return Ok(RealmAuthProbe {
            candidate_count,
            matched: None,
        });
    }
    let subject = value
        .get("subject")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(512).collect());
    let subject_matched = value
        .get("subjectMatched")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            "legacy authentication probe returned invalid subject evidence".to_string()
        })?;
    Ok(RealmAuthProbe {
        candidate_count,
        matched: Some(LegacyAuthProbe {
            success_candidate_count: candidate_count,
            matched: true,
            subject_matched,
            subject,
        }),
    })
}

fn validate_generation(page: &Page, lease: &LegacyTargetLease) -> Result<(), String> {
    if page.document_generation() != lease.document_generation {
        Err("legacy target lease expired after document navigation".to_string())
    } else {
        Ok(())
    }
}

fn bounded_timeout(timeout: Duration) -> Duration {
    if timeout.is_zero() {
        Duration::from_millis(250)
    } else {
        timeout.min(MAX_EVAL_TIMEOUT)
    }
}

fn parse_realm_inspection(value: Value, frame_id: u32) -> Result<RealmInspection, String> {
    if value.is_null() {
        return Err(format!(
            "legacy bridge preload is unavailable in frame {frame_id}; install it before navigation"
        ));
    }
    serde_json::from_value(value)
        .map_err(|error| format!("invalid legacy inspection in frame {frame_id}: {error}"))
}

fn evaluate_realm(
    page: &mut Page,
    frame_id: u32,
    expression: &str,
    timeout: Duration,
) -> Result<Value, String> {
    if frame_id == 0 {
        let value = page.evaluate_with_timeout(expression, timeout);
        if value.is_null() {
            Err("legacy bridge evaluation failed in the top document".to_string())
        } else {
            Ok(value)
        }
    } else {
        let snapshots = page.frame_snapshots();
        let index = snapshots
            .iter()
            .position(|frame| frame.frame_id == frame_id)
            .ok_or_else(|| "legacy target frame was detached".to_string())?;
        page.evaluate_in_frame_with_timeout(index, expression, timeout)
            .map_err(|_| "legacy bridge evaluation failed in a child frame".to_string())
    }
}

fn evaluate_sensitive_realm(
    page: &mut Page,
    frame_id: u32,
    expression: &str,
    timeout: Duration,
) -> Result<Value, String> {
    if frame_id == 0 {
        page.evaluate_sensitive_with_timeout(expression, timeout)
            .map_err(|_| "sensitive legacy bridge evaluation failed".to_string())
    } else {
        let snapshots = page.frame_snapshots();
        let index = snapshots
            .iter()
            .position(|frame| frame.frame_id == frame_id)
            .ok_or_else(|| "legacy target frame was detached".to_string())?;
        page.evaluate_in_frame_with_timeout(index, expression, timeout)
            .map_err(|_| "sensitive legacy bridge evaluation failed in a child frame".to_string())
    }
}

fn bridge_call(method: &str, nonce: &str, payload: Value) -> Result<String, String> {
    let nonce = serde_json::to_string(nonce).map_err(|error| error.to_string())?;
    let payload = serde_json::to_string(&payload).map_err(|error| error.to_string())?;
    Ok(format!(
        "globalThis.__obscuraLegacyBridge?.{method}({nonce},{payload}) ?? null"
    ))
}

fn expect_bridge_ok(value: Value) -> Result<(), String> {
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(bridge_error(&value))
    }
}

fn bridge_error(value: &Value) -> String {
    value
        .get("error")
        .and_then(Value::as_str)
        .map(|message| message.chars().take(256).collect())
        .unwrap_or_else(|| "legacy bridge rejected the operation".to_string())
}

fn revoke_nonce(page: &mut Page, nonce: &str, timeout: Duration) {
    let Ok(nonce) = serde_json::to_string(nonce) else {
        return;
    };
    let expression = format!("globalThis.__obscuraLegacyBridge?.revoke({nonce})");
    let _ = page.evaluate_with_timeout(&expression, timeout);
    let snapshots = page.frame_snapshots();
    for index in 0..snapshots.len().min(MAX_INSPECTED_FRAMES) {
        let _ = page.evaluate_in_frame_with_timeout(index, &expression, timeout);
    }
}

fn frame_top_offset(
    page: &mut Page,
    frame_id: u32,
    parents: &HashMap<u32, u32>,
    timeout: Duration,
) -> Result<(f64, f64), String> {
    let mut current = frame_id;
    let mut x = 0.0;
    let mut y = 0.0;
    for _ in 0..MAX_INSPECTED_FRAMES {
        if current == 0 {
            return Ok((x, y));
        }
        let parent = *parents
            .get(&current)
            .ok_or_else(|| "legacy frame parent metadata is unavailable".to_string())?;
        let expression =
            format!("globalThis.__obscuraLegacyBridge?.frameOwnerRect({current}) ?? null");
        let value = evaluate_realm(page, parent, &expression, timeout)?;
        let rect: LegacyRect = serde_json::from_value(value)
            .map_err(|_| "legacy frame owner geometry is unavailable".to_string())?;
        if !rect.is_usable() {
            return Err("legacy frame owner has unusable layout geometry".to_string());
        }
        x += rect.x;
        y += rect.y;
        current = parent;
    }
    Err("legacy frame nesting exceeds the inspection limit".to_string())
}

fn frame_top_rect(
    page: &mut Page,
    frame_id: u32,
    parents: &HashMap<u32, u32>,
    timeout: Duration,
) -> Result<LegacyRect, String> {
    let parent = *parents
        .get(&frame_id)
        .ok_or_else(|| "legacy frame parent metadata is unavailable".to_string())?;
    let expression =
        format!("globalThis.__obscuraLegacyBridge?.frameOwnerRect({frame_id}) ?? null");
    let value = evaluate_realm(page, parent, &expression, timeout)?;
    let rect: LegacyRect = serde_json::from_value(value)
        .map_err(|_| "legacy frame owner geometry is unavailable".to_string())?;
    if !rect.is_usable() {
        return Err("legacy frame owner has unusable layout geometry".to_string());
    }
    let (offset_x, offset_y) = frame_top_offset(page, parent, parents, timeout)?;
    Ok(rect.translated(offset_x, offset_y))
}

fn frame_depth(mut frame_id: u32, parents: &HashMap<u32, u32>) -> Result<usize, String> {
    let mut depth = 0usize;
    for _ in 0..MAX_INSPECTED_FRAMES {
        if frame_id == 0 {
            return Ok(depth);
        }
        frame_id = *parents
            .get(&frame_id)
            .ok_or_else(|| "legacy frame parent metadata is unavailable".to_string())?;
        depth += 1;
    }
    Err("legacy frame nesting exceeds the inspection limit".to_string())
}

// The closure snapshots browser-provided methods before page code can replace
// them. Its maps retain actual node objects; neither selectors nor node ids are
// accepted by mutation/interaction calls after inspection.
const LEGACY_BRIDGE_PRELOAD: &str = r#"(()=>{
  if(globalThis.__obscuraLegacyBridge)return;
  const apply=Reflect.apply;
  const call=(fn,self,args)=>apply(fn,self,args);
  const objectGetPrototypeOf=Object.getPrototypeOf,numberToString=Number.prototype.toString,mathImul=Math.imul;
  const docQS=Document.prototype.querySelector,docQSA=Document.prototype.querySelectorAll;
  const elQS=Element.prototype.querySelector,elQSA=Element.prototype.querySelectorAll;
  const fragQS=DocumentFragment.prototype.querySelector,fragQSA=DocumentFragment.prototype.querySelectorAll;
  const getAttr=Element.prototype.getAttribute,hasAttr=Element.prototype.hasAttribute;
  const matches=Element.prototype.matches,closest=Element.prototype.closest;
  const rectFn=Element.prototype.getBoundingClientRect,getRoot=Node.prototype.getRootNode;
  const dispatch=EventTarget.prototype.dispatchEvent,focusFn=HTMLElement.prototype.focus;
  const clickFn=HTMLElement.prototype.click;
  const inputValue=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')?.set;
  const textValue=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value')?.set;
  const nativeComputed=globalThis.getComputedStyle;
  const nativeElementFromPoint=Document.prototype.elementFromPoint;
  const nativeMouseEvent=globalThis.MouseEvent,nativeWheelEvent=globalThis.WheelEvent,nativeEvent=globalThis.Event;
  const markTrusted=globalThis.__obscura_markTrusted;
  const elementScrollBy=Element.prototype.scrollBy;
  const nativeSetTimeout=globalThis.setTimeout;
  const mapGet=Map.prototype.get,mapSet=Map.prototype.set,mapDelete=Map.prototype.delete;
  const canvasGetContext=globalThis.HTMLCanvasElement?.prototype?.getContext;
  const canvasWidth=Object.getOwnPropertyDescriptor(globalThis.HTMLCanvasElement?.prototype||{},'width')?.get;
  const canvasHeight=Object.getOwnPropertyDescriptor(globalThis.HTMLCanvasElement?.prototype||{},'height')?.get;
  let canvasGetImageData=globalThis.CanvasRenderingContext2D?.prototype?.getImageData||null;
  const frameElements=globalThis.__obscura_frameElements;
  const leases=new Map(),viewDrags=new Map();
  const attr=(el,name)=>{try{return call(getAttr,el,[name]);}catch(_){return null;}};
  const query=(root,selector)=>{try{
    const fn=root?.nodeType===9?docQS:root?.nodeType===11?fragQS:elQS;
    return fn?call(fn,root,[selector]):null;
  }catch(_){return null;}};
  const queryAll=(root,selector)=>{try{
    const fn=root?.nodeType===9?docQSA:root?.nodeType===11?fragQSA:elQSA;
    return fn?Array.from(call(fn,root,[selector])):[];
  }catch(_){return [];}};
  const getRect=(el)=>{try{const r=call(rectFn,el,[]);return{x:+r.x||0,y:+r.y||0,width:+r.width||0,height:+r.height||0};}catch(_){return{x:0,y:0,width:0,height:0};}};
  const usable=(r)=>Number.isFinite(r.x)&&Number.isFinite(r.y)&&r.width>0&&r.height>0;
  const connected=(node)=>{try{return!!node?.isConnected;}catch(_){return false;}};
  const visible=(el)=>{
    if(!connected(el))return false;
    let cur=el;
    for(let i=0;cur&&i<128;i++){
      try{if(call(hasAttr,cur,['hidden']))return false;}catch(_){return false;}
      try{const s=call(nativeComputed,globalThis,[cur]);if(s&&(s.display==='none'||s.visibility==='hidden'||s.visibility==='collapse'||s.opacity==='0'||s.contentVisibility==='hidden'))return false;}catch(_){return false;}
      let parent=cur.parentElement;
      if(!parent){try{const root=call(getRoot,cur,[]);parent=root?.host||null;}catch(_){parent=null;}}
      cur=parent;
    }
    return usable(getRect(el));
  };
  const disabled=(el)=>!!(el?.disabled||attr(el,'disabled')!==null||attr(el,'aria-disabled')==='true');
  const roots=()=>{
    const out=[document],seen=new Set(out);
    for(let i=0;i<out.length&&out.length<64;i++){
      for(const el of queryAll(out[i],'*')){let shadow=null;try{shadow=el.shadowRoot;}catch(_){}if(shadow&&!seen.has(shadow)){seen.add(shadow);out.push(shadow);}}
    }
    return out;
  };
  const all=(selector)=>{const out=[];for(const root of roots())for(const el of queryAll(root,selector))if(!out.includes(el))out.push(el);return out;};
  const one=(selector)=>{const found=all(selector).filter(visible);return found.length===1?found[0]:null;};
  const text=(el)=>String(el?.textContent||attr(el,'aria-label')||attr(el,'title')||'').trim().slice(0,160);
  const label=(el,fallback)=>String(attr(el,'aria-label')||attr(el,'placeholder')||attr(el,'name')||attr(el,'id')||fallback).trim().slice(0,160);
  const attrSelectorValue=(value)=>'"'+String(value).replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/[\r\n\f]/g,' ')+'"';
  const stableSelector=(el)=>{
    if(!el)return null;
    const tag=String(el.localName||'').toLowerCase();if(!tag)return null;
    const candidates=[],id=attr(el,'id'),name=attr(el,'name'),autocomplete=attr(el,'autocomplete'),type=attr(el,'type');
    if(id)candidates.push('[id='+attrSelectorValue(id)+']');
    if(name)candidates.push(tag+'[name='+attrSelectorValue(name)+']');
    if(autocomplete)candidates.push(tag+'[autocomplete='+attrSelectorValue(autocomplete)+']');
    if(name&&type)candidates.push(tag+'[name='+attrSelectorValue(name)+'][type='+attrSelectorValue(type)+']');
    if(type)candidates.push(tag+'[type='+attrSelectorValue(type)+']');
    candidates.push(tag);
    for(const selector of candidates){if(selector.length<=1024&&all(selector).length===1)return selector;}
    return null;
  };
  const sameForm=(el,form)=>{try{return el.form===form||(form&&call(closest,el,['form'])===form);}catch(_){return false;}};
  const loginCandidates=(selectors,diagnostics)=>{
    const explicit=selectors&&Object.values(selectors).some(v=>typeof v==='string'&&v.trim());
    if(explicit){
      const username=selectors.username?one(selectors.username):null;
      const password=selectors.password?one(selectors.password):null;
      const submit=selectors.submit?one(selectors.submit):null;
      if(!username||!password||(selectors.submit&&!submit)){diagnostics.push('configured login selectors did not resolve uniquely');return[];}
      const form=password.form||call(closest,password,['form']);
      if(!form||!sameForm(username,form)||(submit&&!sameForm(submit,form))){diagnostics.push('configured login fields are not owned by one form');return[];}
      return[{username,password,submit,form,selectors:{username:selectors.username||null,password:selectors.password||null,submit:selectors.submit||null}}];
    }
    const passwords=all('input').filter(el=>String(attr(el,'type')||'').toLowerCase()==='password'&&visible(el)&&!disabled(el));
    const out=[];
    for(const password of passwords){
      const form=password.form||call(closest,password,['form']);if(!form)continue;
      const users=all('input').filter(el=>{
        const type=String(attr(el,'type')||'text').toLowerCase();
        return el!==password&&sameForm(el,form)&&visible(el)&&!disabled(el)&&['','text','email','tel'].includes(type);
      });
      const scored=users.map(el=>{const key=(attr(el,'autocomplete')||'')+' '+(attr(el,'name')||'')+' '+(attr(el,'id')||'')+' '+(attr(el,'placeholder')||'');let score=/username/i.test(attr(el,'autocomplete')||'')?100:0;if(/user|login|account|email|mail|phone|mobile|用户名|账号|手机|邮箱/i.test(key))score+=40;return{el,score};}).sort((a,b)=>b.score-a.score);
      if(!scored.length||(scored.length>1&&scored[0].score===scored[1].score)){diagnostics.push('login username field is missing or ambiguous');continue;}
      const submits=all('button,input').filter(el=>{if(!sameForm(el,form)||!visible(el)||disabled(el))return false;const tag=String(el.tagName||'').toLowerCase(),type=String(attr(el,'type')||'').toLowerCase();return tag==='button'?(type===''||type==='submit'):type==='submit'||type==='image';});
      if(submits.length>1){diagnostics.push('login submit control is ambiguous');continue;}
      const username=scored[0].el,submit=submits[0]||null;
      out.push({username,password,submit,form,selectors:{username:stableSelector(username),password:stableSelector(password),submit:stableSelector(submit)}});
    }
    return out;
  };
  const classHas=(el,name)=>{try{return call(matches,el,['.'+name]);}catch(_){return false;}};
  const captchaCandidates=(adapter,diagnostics)=>{
    const out=[],accept=name=>adapter==='auto'||adapter===name;
    if(accept('tianai'))for(const root of all('#tianai-captcha')){
      if(!visible(root)||!classHas(root,'tianai-captcha-slider')||query(root,'.tianai-captcha-rotate,.tianai-captcha-concat,.tianai-captcha-word-click'))continue;
      const start=query(root,'#tianai-captcha-slider-move-btn'),bg=query(root,'#tianai-captcha-slider-bg-img'),piece=query(root,'#tianai-captcha-slider-move-img');
      if(start&&bg&&piece&&visible(start)&&visible(bg)&&visible(piece))out.push({adapter:'tianai',mode:'slider',root,start,images:[bg,piece]});
    }
    if(accept('go-captcha'))for(const root of all('.go-captcha.gc-wrapper.gc-slide-mode')){
      if(!visible(root))continue;const start=query(root,'.gc-drag-block');
      const bg=query(root,'.gc-body img.gc-picture,.gc-body .gc-picture img'),piece=query(root,'.gc-body .gc-tile img');
      if(start&&bg&&piece&&visible(start)&&visible(bg)&&visible(piece))out.push({adapter:'go-captcha',mode:'slide',root,start,images:[bg,piece]});
    }
    if(accept('aj-captcha'))for(const panel of all('.verify-img-panel')){
      const imageOut=panel.parentElement,scope=imageOut?.parentElement,start=scope&&query(scope,'.verify-bar-area .verify-move-block');
      const bg=query(panel,'.backImg,.back-img,img'),piece=scope&&query(scope,'.verify-sub-block .bock-backImg,.verify-sub-block img');
      if(scope&&start&&bg&&piece&&visible(scope)&&visible(start)&&visible(bg)&&visible(piece))out.push({adapter:'aj-captcha',mode:'block_puzzle',root:scope,start,images:[bg,piece]});
    }
    if(accept('slider-captcha-js'))for(const stage of all('.slider-captcha-stage')){
      const root=stage.parentElement,start=root&&query(root,'.slider-captcha-thumb'),track=root&&query(root,'.slider-captcha-track');
      const layers=queryAll(stage,'img,canvas');
      if(root&&start&&track&&layers.length>=2&&visible(root)&&visible(start)&&visible(stage))out.push({adapter:'slider-captcha-js',mode:'slider',root,start,images:layers});
    }
    if(out.length===0)diagnostics.push('no complete visible supported slide CAPTCHA widget was found');
    return out;
  };
  const canvasFingerprint=(canvas)=>{
    let width=0,height=0;
    try{
      width=canvasWidth?+call(canvasWidth,canvas,[]):+canvas.width||0;
      height=canvasHeight?+call(canvasHeight,canvas,[]):+canvas.height||0;
    }catch(_){}
    width=Number.isFinite(width)&&width>0?Math.floor(width):0;
    height=Number.isFinite(height)&&height>0?Math.floor(height):0;
    const prefix='canvas:'+width+'x'+height+':';
    if(!width||!height)return prefix+'empty';
    if(!canvasGetContext)return prefix+'unreadable';
    try{
      const context=call(canvasGetContext,canvas,['2d']);
      if(!context)return prefix+'no-2d';
      if(!canvasGetImageData){
        const prototype=call(objectGetPrototypeOf,Object,[context]);
        canvasGetImageData=prototype?.getImageData||null;
      }
      if(typeof canvasGetImageData!=='function')return prefix+'unreadable';
      const columns=Math.min(8,width),rows=Math.min(8,height);
      let hash=2166136261>>>0;
      for(let row=0;row<rows;row++){
        const y=Math.min(height-1,Math.floor((row+.5)*height/rows));
        for(let column=0;column<columns;column++){
          const x=Math.min(width-1,Math.floor((column+.5)*width/columns));
          const data=call(canvasGetImageData,context,[x,y,1,1])?.data;
          if(!data||data.length<4)throw new Error('canvas pixel read unavailable');
          for(let channel=0;channel<4;channel++)hash=call(mathImul,Math,[(hash^(+data[channel]||0))>>>0,16777619])>>>0;
        }
      }
      return prefix+call(numberToString,hash,[16]);
    }catch(_){
      // Cross-origin/tainted canvases are deliberately opaque. Dimensions still
      // participate in the lease, and an unreadable canvas never makes inspect
      // or pointer dispatch throw.
      return prefix+'opaque';
    }
  };
  const imageFingerprint=(el)=>String(el.currentSrc||el.src||'');
  const fingerprint=(captcha)=>captcha.images.map(el=>String(el?.tagName||'').toLowerCase()==='canvas'?canvasFingerprint(el):imageFingerprint(el)).join('\n');
  const validCaptcha=(entry)=>{
    const c=entry?.captcha;if(!c||!connected(c.root)||!connected(c.start))return false;
    for(let i=0;i<c.images.length;i++)if(!connected(c.images[i]))return false;
    if(fingerprint(c)!==entry.fingerprint)return false;
    const now=getRect(c.root),was=entry.rootRect;
    return usable(now)&&Math.abs(now.x-was.x)<3&&Math.abs(now.y-was.y)<3&&Math.abs(now.width-was.width)<3&&Math.abs(now.height-was.height)<3;
  };
  const event=(type,x,y,buttons,button,mx,my)=>new nativeMouseEvent(type,{bubbles:true,cancelable:true,view:globalThis,clientX:x,clientY:y,screenX:x,screenY:y,button,buttons,movementX:mx||0,movementY:my||0});
  const send=(target,type,x,y,buttons,button,mx,my)=>call(dispatch,target,[call(markTrusted,globalThis,[event(type,x,y,buttons,button,mx,my)])]);
  const sendWheel=(target,x,y,dx,dy)=>call(dispatch,target,[call(markTrusted,globalThis,[new nativeWheelEvent('wheel',{bubbles:true,cancelable:true,view:globalThis,clientX:x,clientY:y,screenX:x,screenY:y,button:0,buttons:0,deltaX:dx,deltaY:dy,deltaMode:0})])]);
  const setValue=(el,value)=>{const setter=String(el?.tagName||'').toLowerCase()==='textarea'?textValue:inputValue;if(!setter)throw new Error('field setter unavailable');call(setter,el,[String(value)]);call(dispatch,el,[call(markTrusted,globalThis,[new nativeEvent('input',{bubbles:true})])]);call(dispatch,el,[call(markTrusted,globalThis,[new nativeEvent('change',{bubbles:true})])]);};
  const api={
    metadata(){return{parentFrameId:globalThis.__obscura_parentFrameId>>>0};},
    inspect(nonce,options){
      const diagnostics=[],logins=loginCandidates(options?.selectors||{},diagnostics),captchas=captchaCandidates(String(options?.adapter||'auto'),diagnostics);
      const entry={login:logins.length===1?logins[0]:null,captcha:captchas.length===1?captchas[0]:null};
      if(entry.captcha){entry.rootRect=getRect(entry.captcha.root);entry.fingerprint=fingerprint(entry.captcha);}
      call(mapSet,leases,[String(nonce),entry]);
      return{parentFrameId:globalThis.__obscura_parentFrameId>>>0,loginCount:logins.length,captchaCount:captchas.length,
        login:entry.login?{usernameLabel:label(entry.login.username,'用户名'),passwordLabel:label(entry.login.password,'密码'),submitLabel:entry.login.submit?text(entry.login.submit)||'登录':null,
          usernameSelector:entry.login.selectors?.username||null,passwordSelector:entry.login.selectors?.password||null,submitSelector:entry.login.selectors?.submit||null}:null,
        captcha:entry.captcha?{adapter:entry.captcha.adapter,mode:entry.captcha.mode,cropRect:getRect(entry.captcha.root),startRect:getRect(entry.captcha.start)}:null,diagnostics};
    },
    revoke(nonce){call(mapDelete,leases,[String(nonce)]);return true;},
    fill(nonce,payload){try{const e=call(mapGet,leases,[String(nonce)]);if(!e?.login||!connected(e.login.username)||!connected(e.login.password))return{ok:false,error:'legacy login target expired'};setValue(e.login.username,payload?.username||'');setValue(e.login.password,payload?.password||'');return{ok:true};}catch(_){return{ok:false,error:'legacy credential fill failed'};}},
    captchaPointer(nonce,payload){try{
      const e=call(mapGet,leases,[String(nonce)]);if(!validCaptcha(e))return{ok:false,error:'legacy CAPTCHA lease expired'};
      const p=String(payload?.phase||''),x=+payload?.x,y=+payload?.y;if(!Number.isFinite(x)||!Number.isFinite(y))return{ok:false,error:'invalid pointer coordinates'};
      if(p==='down'){const r=getRect(e.captcha.start);if(x<r.x-12||y<r.y-12||x>r.x+r.width+12||y>r.y+r.height+12)return{ok:false,error:'pointer did not begin on the retained slider control'};e.drag={x,y};send(e.captcha.start,'mousedown',x,y,1,0,0,0);return{ok:true};}
      if(!e.drag)return{ok:false,error:'slider pointer sequence has no active down event'};const mx=x-e.drag.x,my=y-e.drag.y;e.drag={x,y};
      if(p==='move'){send(e.captcha.start,'mousemove',x,y,1,0,mx,my);return{ok:true};}
      if(p==='up'||p==='cancel'){send(e.captcha.start,'mouseup',x,y,0,0,mx,my);e.drag=null;return{ok:true};}
      return{ok:false,error:'unsupported pointer phase'};
    }catch(_){return{ok:false,error:'legacy CAPTCHA pointer dispatch failed'};}},
    captchaCurrent(nonce){try{const e=call(mapGet,leases,[String(nonce)]);return{ok:true,current:validCaptcha(e)};}catch(_){return{ok:false,error:'legacy CAPTCHA lease validation failed'};}},
    submit(nonce){try{const e=call(mapGet,leases,[String(nonce)]);if(!e?.login||!connected(e.login.form))return{ok:false,error:'legacy login target expired'};if(e.login.submit&&connected(e.login.submit))call(clickFn,e.login.submit,[]);else if(typeof e.login.form.requestSubmit==='function')e.login.form.requestSubmit();else e.login.form.submit();return{ok:true};}catch(_){return{ok:false,error:'legacy login submission failed'};}},
    probe(successSelector,subjectSelector){try{const matches=all(String(successSelector)),candidateCount=matches.length;if(candidateCount!==1||!visible(matches[0]))return{ok:true,matched:false,subject:null,subjectMatched:!subjectSelector,candidateCount};const subjects=subjectSelector?all(String(subjectSelector)).filter(visible):[],subjectMatched=!subjectSelector||subjects.length===1;const subject=subjectMatched&&subjectSelector?subjects[0]:null;return{ok:true,matched:true,subjectMatched,subject:subject?text(subject):null,candidateCount};}catch(_){return{ok:false,error:'legacy authentication probe failed'};}},
    frameOwnerRect(frameId){const el=frameElements?.[frameId>>>0];return el&&connected(el)?getRect(el):null;},
    viewPointer(nonce,payload){try{
      const key=String(nonce),p=String(payload?.phase||''),x=+payload?.x,y=+payload?.y;if(!Number.isFinite(x)||!Number.isFinite(y))return{ok:false,error:'invalid pointer coordinates'};
      if(p==='down'){const target=call(nativeElementFromPoint,document,[x,y])||document.body;if(!target)return{ok:false,error:'no pointer target'};try{call(focusFn,target,[]);}catch(_){}call(mapSet,viewDrags,[key,{target,startX:x,startY:y,x,y}]);send(target,'mousedown',x,y,1,0,0,0);return{ok:true};}
      const drag=call(mapGet,viewDrags,[key]);if(!drag||!connected(drag.target))return{ok:false,error:'remote view pointer sequence has no active target'};const mx=x-drag.x,my=y-drag.y;drag.x=x;drag.y=y;
      if(p==='move'){send(drag.target,'mousemove',x,y,1,0,mx,my);return{ok:true};}
      if(p==='up'||p==='cancel'){send(drag.target,'mouseup',x,y,0,0,mx,my);call(mapDelete,viewDrags,[key]);if(p==='up'&&Math.hypot(x-drag.startX,y-drag.startY)<5)call(clickFn,drag.target,[]);return{ok:true};}
      return{ok:false,error:'unsupported pointer phase'};
    }catch(_){return{ok:false,error:'legacy remote pointer dispatch failed'};}},
    viewWheel(payload){try{
      const x=+payload?.x,y=+payload?.y,dx=+payload?.deltaX,dy=+payload?.deltaY;
      if(!Number.isFinite(x)||!Number.isFinite(y)||!Number.isFinite(dx)||!Number.isFinite(dy)||Math.abs(dx)>8192||Math.abs(dy)>8192||(dx===0&&dy===0))return{ok:false,error:'invalid wheel coordinates or deltas'};
      const target=call(nativeElementFromPoint,document,[x,y])||document.body||document.documentElement;if(!target)return{ok:false,error:'no wheel target'};
      if(!sendWheel(target,x,y,dx,dy))return{ok:true};
      const root=document.scrollingElement||document.documentElement||document.body;
      let scrollTarget=null,el=target;
      while(el&&el.nodeType===1&&el!==root&&el!==document.body&&el!==document.documentElement){
        const maxX=Math.max(0,(el.scrollWidth||0)-(el.clientWidth||0)),maxY=Math.max(0,(el.scrollHeight||0)-(el.clientHeight||0));
        let style=null;try{style=call(nativeComputed,globalThis,[el]);}catch(_){}
        const ox=style?(style.overflowX||style.overflow||''):'',oy=style?(style.overflowY||style.overflow||''):'';
        const allowX=ox==='auto'||ox==='scroll'||ox==='overlay',allowY=oy==='auto'||oy==='scroll'||oy==='overlay';
        const consumesX=allowX&&((dx>0&&el.scrollLeft<maxX)||(dx<0&&el.scrollLeft>0));
        const consumesY=allowY&&((dy>0&&el.scrollTop<maxY)||(dy<0&&el.scrollTop>0));
        if(consumesX||consumesY){scrollTarget=el;break;}
        let parent=el.parentElement;
        if(!parent){try{parent=call(getRoot,el,[])?.host||null;}catch(_){parent=null;}}
        el=parent;
      }
      if(!scrollTarget)scrollTarget=root;
      if(!scrollTarget||typeof elementScrollBy!=='function')return{ok:false,error:'wheel scroll target is unavailable'};
      const beforeX=scrollTarget.scrollLeft||0,beforeY=scrollTarget.scrollTop||0;
      call(elementScrollBy,scrollTarget,[dx,dy]);
      if(scrollTarget===root&&(scrollTarget.scrollLeft!==beforeX||scrollTarget.scrollTop!==beforeY))call(nativeSetTimeout,globalThis,[()=>{
        try{call(dispatch,document,[call(markTrusted,globalThis,[new nativeEvent('scroll',{bubbles:false})])]);}catch(_){}
        try{call(dispatch,globalThis,[call(markTrusted,globalThis,[new nativeEvent('scroll',{bubbles:false})])]);}catch(_){}
      },0]);
      return{ok:true};
    }catch(_){return{ok:false,error:'legacy remote wheel dispatch failed'};}},
    typeText(value){try{const target=document.activeElement;if(!target||!['input','textarea'].includes(String(target.localName)))return{ok:false,error:'legacy remote view has no focused text field'};setValue(target,String(value));return{ok:true};}catch(_){return{ok:false,error:'legacy remote text input failed'};}}
  };
  Object.freeze(api);
  Object.defineProperty(globalThis,'__obscuraLegacyBridge',{value:api,writable:false,configurable:false,enumerable:false});
})()"#;

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use std::sync::Arc;

    fn page(name: &str) -> Page {
        let context = Arc::new(crate::BrowserContext::with_storage_and_network(
            name.to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = Page::new(name.to_string(), context);
        install_legacy_bridge_preload(&mut page);
        page
    }

    fn data_html(html: &str) -> String {
        format!("data:text/html;base64,{}", BASE64.encode(html))
    }

    const LOGIN: &str = r#"<form id='login'><input name='username' autocomplete='username'><input name='password' type='password'><button type='submit'>登录</button></form>"#;

    async fn inspect_fixture(
        name: &str,
        widget: &str,
        adapter: CaptchaAdapter,
    ) -> (Page, LegacyInspection) {
        let mut page = page(name);
        let html = format!("<!doctype html><html><body>{LOGIN}{widget}</body></html>");
        page.navigate(&data_html(&html)).await.unwrap();
        let inspection = inspect_legacy_page(
            &mut page,
            adapter,
            &LegacyLoginSelectors::default(),
            Duration::from_secs(1),
        )
        .unwrap();
        (page, inspection)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recognizes_all_four_live_slider_controls() {
        let fixtures = [
            (
                CaptchaAdapter::Tianai,
                r#"<div id='tianai-captcha' class='tianai-captcha-slider' style='width:320px;height:220px'><img id='tianai-captcha-slider-bg-img' style='width:300px;height:150px' src='data:image/png;base64,AA=='><img id='tianai-captcha-slider-move-img' style='width:60px;height:60px' src='data:image/png;base64,AA=='><button id='tianai-captcha-slider-move-btn' style='width:40px;height:40px'>slide</button></div>"#,
            ),
            (
                CaptchaAdapter::GoCaptcha,
                r#"<div class='go-captcha gc-wrapper gc-slide-mode' style='width:320px;height:220px'><div class='gc-body'><img class='gc-picture' style='width:300px;height:150px' src='data:image/png;base64,AA=='><div class='gc-tile'><img style='width:60px;height:60px' src='data:image/png;base64,AA=='></div></div><div class='gc-footer'><div class='gc-drag-slide-bar'><button class='gc-drag-block' style='width:40px;height:40px'>slide</button></div></div></div>"#,
            ),
            (
                CaptchaAdapter::AjCaptcha,
                r#"<div class='verify-wrap' style='width:320px;height:240px'><div class='verify-img-out'><div class='verify-img-panel'><img class='backImg' style='width:300px;height:150px' src='data:image/png;base64,AA=='></div></div><div class='verify-bar-area'><button class='verify-move-block' style='width:40px;height:40px'><span class='verify-sub-block'><img class='bock-backImg' style='width:40px;height:40px' src='data:image/png;base64,AA=='></span></button></div></div>"#,
            ),
            (
                CaptchaAdapter::SliderCaptchaJs,
                r#"<div class='slider-captcha' style='width:320px;height:240px'><div class='slider-captcha-stage'><canvas width='300' height='150'></canvas><canvas width='300' height='150'></canvas><canvas width='60' height='60'></canvas></div><div class='slider-captcha-bar'><div class='slider-captcha-track'></div><button class='slider-captcha-thumb' style='width:40px;height:40px'>slide</button><div class='slider-captcha-status'></div></div></div>"#,
            ),
        ];
        for (index, (adapter, fixture)) in fixtures.into_iter().enumerate() {
            let (_page, inspection) =
                inspect_fixture(&format!("legacy-{index}"), fixture, adapter).await;
            let login = inspection.login.as_ref().expect("login target");
            assert_eq!(
                login.username_selector.as_deref(),
                Some("input[name=\"username\"]")
            );
            assert_eq!(
                login.password_selector.as_deref(),
                Some("input[name=\"password\"]")
            );
            assert_eq!(
                login.submit_selector.as_deref(),
                Some("button[type=\"submit\"]")
            );
            let captcha = inspection.captcha.unwrap_or_else(|| {
                panic!(
                    "fixture {index} ({adapter:?}) did not expose a slider CAPTCHA: {:?}",
                    inspection.diagnostics,
                )
            });
            assert_eq!(captcha.adapter, adapter);
            assert!(captcha.frame_crop_rect.is_usable());
            assert!(captcha.frame_start_rect.is_usable());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn go_captcha_slide_region_drag_drop_is_out_of_scope() {
        // GoCaptcha SlideRegion binds a free two-dimensional drag directly to
        // `.gc-tile`; it is a drag-drop mode, not the horizontal Slide mode
        // requested by the legacy gateway. Never present it as an actionable
        // one-dimensional slider.
        let widget = r#"<div class='go-captcha gc-wrapper gc-slide-mode' style='width:320px;height:220px'><div class='gc-body'><img class='gc-picture' style='width:300px;height:150px' src='data:image/png;base64,AA=='><div class='gc-tile' style='width:60px;height:60px'><img style='width:60px;height:60px' src='data:image/png;base64,AA=='></div></div></div>"#;
        let (_page, inspection) =
            inspect_fixture("legacy-go-region", widget, CaptchaAdapter::GoCaptcha).await;
        assert!(inspection.login.is_some());
        assert!(inspection.captcha.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relays_original_pointer_samples_and_fills_without_returning_secrets() {
        let widget = r#"<div id='tianai-captcha' class='tianai-captcha-slider' style='width:320px;height:220px'><img id='tianai-captcha-slider-bg-img' style='width:300px;height:150px' src='data:image/png;base64,AA=='><img id='tianai-captcha-slider-move-img' style='width:60px;height:60px' src='data:image/png;base64,AA=='><button id='tianai-captcha-slider-move-btn' style='width:40px;height:40px'>slide</button></div><script>globalThis.samples=[];const b=document.getElementById('tianai-captcha-slider-move-btn');for(const t of ['mousedown','mousemove','mouseup'])b.addEventListener(t,e=>samples.push([t,e.clientX,e.clientY,e.pageX,e.pageY]));document.getElementById('login').addEventListener('submit',e=>{e.preventDefault();globalThis.submitted=true;});</script>"#;
        let (mut page, inspection) =
            inspect_fixture("legacy-relay", widget, CaptchaAdapter::Tianai).await;
        fill_legacy_credentials(
            &mut page,
            inspection.lease(),
            "alice",
            "correct horse",
            Duration::from_secs(1),
        )
        .unwrap();
        let captcha = inspection.captcha.as_ref().unwrap();
        let x = captcha.frame_start_rect.x + captcha.frame_start_rect.width / 2.0;
        let y = captcha.frame_start_rect.y + captcha.frame_start_rect.height / 2.0;
        for (phase, dx, dy) in [
            (LegacyPointerPhase::Down, 0.0, 0.0),
            (LegacyPointerPhase::Move, 30.0, 1.0),
            (LegacyPointerPhase::Up, 60.0, 2.0),
        ] {
            dispatch_legacy_captcha_pointer(
                &mut page,
                inspection.lease(),
                phase,
                x + dx,
                y + dy,
                Duration::from_secs(1),
            )
            .unwrap();
        }
        submit_legacy_login(&mut page, inspection.lease(), Duration::from_secs(1)).unwrap();
        let observed = page.evaluate("({user:document.querySelector('[name=username]').value,password:document.querySelector('[name=password]').value,samples,submitted:globalThis.submitted===true})");
        assert_eq!(observed["user"], "alice");
        assert_eq!(observed["password"], "correct horse");
        assert_eq!(observed["samples"].as_array().unwrap().len(), 3);
        assert_eq!(observed["submitted"], true);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn navigation_expires_the_retained_lease() {
        let widget = r#"<div id='tianai-captcha' class='tianai-captcha-slider' style='width:320px;height:220px'><img id='tianai-captcha-slider-bg-img' style='width:300px;height:150px' src='data:image/png;base64,AA=='><img id='tianai-captcha-slider-move-img' style='width:60px;height:60px' src='data:image/png;base64,AA=='><button id='tianai-captcha-slider-move-btn' style='width:40px;height:40px'>slide</button></div>"#;
        let (mut page, inspection) =
            inspect_fixture("legacy-expiry", widget, CaptchaAdapter::Tianai).await;
        page.navigate_blank();
        let error = fill_legacy_credentials(
            &mut page,
            inspection.lease(),
            "alice",
            "secret",
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("expired"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refreshed_captcha_generation_expires_the_retained_widget() {
        let widget = r#"<div id='tianai-captcha' class='tianai-captcha-slider' style='width:320px;height:220px'><img id='tianai-captcha-slider-bg-img' style='width:300px;height:150px' src='data:image/png;base64,AA=='><img id='tianai-captcha-slider-move-img' style='width:60px;height:60px' src='data:image/png;base64,AA=='><button id='tianai-captcha-slider-move-btn' style='width:40px;height:40px'>slide</button></div>"#;
        let (mut page, inspection) =
            inspect_fixture("legacy-refresh", widget, CaptchaAdapter::Tianai).await;
        page.evaluate("document.getElementById('tianai-captcha-slider-bg-img').src='data:image/png;base64,AQ=='");
        let captcha = inspection.captcha.as_ref().unwrap();
        let x = captcha.frame_start_rect.x + captcha.frame_start_rect.width / 2.0;
        let y = captcha.frame_start_rect.y + captcha.frame_start_rect.height / 2.0;
        let error = dispatch_legacy_captcha_pointer(
            &mut page,
            inspection.lease(),
            LegacyPointerPhase::Down,
            x,
            y,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("expired"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn same_size_canvas_redraw_expires_the_retained_widget() {
        let widget = r#"<div class='slider-captcha' style='width:320px;height:240px'><div class='slider-captcha-stage'><canvas width='300' height='150'></canvas><canvas width='300' height='150'></canvas><canvas width='60' height='60'></canvas></div><div class='slider-captcha-bar'><div class='slider-captcha-track'></div><button class='slider-captcha-thumb' style='width:40px;height:40px'>slide</button><div class='slider-captcha-status'></div></div></div>"#;
        let (mut page, inspection) = inspect_fixture(
            "legacy-canvas-refresh",
            widget,
            CaptchaAdapter::SliderCaptchaJs,
        )
        .await;
        assert!(legacy_captcha_target_is_current(
            &mut page,
            inspection.lease(),
            Duration::from_secs(1),
        )
        .unwrap());

        page.evaluate(
            "(() => { const canvas=document.querySelector('.slider-captcha-stage canvas'); const context=canvas.getContext('2d'); context.fillStyle='rgb(220, 20, 60)'; context.fillRect(0,0,canvas.width,canvas.height); })()",
        );

        assert!(!legacy_captcha_target_is_current(
            &mut page,
            inspection.lease(),
            Duration::from_secs(1),
        )
        .unwrap());
        let captcha = inspection.captcha.as_ref().unwrap();
        let error = dispatch_legacy_captcha_pointer(
            &mut page,
            inspection.lease(),
            LegacyPointerPhase::Down,
            captcha.frame_start_rect.x + captcha.frame_start_rect.width / 2.0,
            captcha.frame_start_rect.y + captcha.frame_start_rect.height / 2.0,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("expired"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authentication_probe_requires_one_visible_match() {
        let mut page = page("legacy-auth-visible");
        page.navigate(&data_html(
            r#"<!doctype html><html><body><section id='auth-shell' hidden><div id='signed-in' style='width:120px;height:24px'>alice</div></section></body></html>"#,
        ))
        .await
        .unwrap();

        let hidden =
            probe_legacy_authentication(&mut page, "#signed-in", None, Duration::from_secs(1))
                .unwrap();
        assert!(!hidden.matched);
        assert_eq!(hidden.success_candidate_count, 1);

        page.evaluate("document.getElementById('auth-shell').hidden=false");
        let visible =
            probe_legacy_authentication(&mut page, "#signed-in", None, Duration::from_secs(1))
                .unwrap();
        assert!(visible.matched);
        assert_eq!(visible.success_candidate_count, 1);
        assert!(visible.subject_matched);
        assert_eq!(visible.subject, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authentication_probe_reports_ambiguous_subject_evidence() {
        let mut page = page("legacy-auth-subject-ambiguous");
        page.navigate(&data_html(
            r#"<!doctype html><html><body><div id='signed-in' style='width:120px;height:24px'>ready</div><span class='subject' style='width:80px;height:20px'>alice</span><span class='subject' style='width:80px;height:20px'>duplicate</span></body></html>"#,
        ))
        .await
        .unwrap();

        let probe = probe_legacy_authentication(
            &mut page,
            "#signed-in",
            Some(".subject"),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(probe.matched);
        assert!(!probe.subject_matched);
        assert_eq!(probe.subject, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authentication_probe_rejects_multiple_visible_matches() {
        let mut page = page("legacy-auth-ambiguous");
        page.navigate(&data_html(
            r#"<!doctype html><html><body><div class='signed-in' style='width:120px;height:24px'>alice</div><div class='signed-in' style='width:120px;height:24px'>duplicate</div></body></html>"#,
        ))
        .await
        .unwrap();

        let probe =
            probe_legacy_authentication(&mut page, ".signed-in", None, Duration::from_secs(1))
                .unwrap();
        assert!(!probe.matched);
        assert_eq!(probe.success_candidate_count, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authentication_probe_counts_hidden_success_candidates() {
        let mut page = page("legacy-auth-hidden-ambiguous");
        page.navigate(&data_html(
            r#"<!doctype html><html><body><div class='signed-in' hidden>first</div><div class='signed-in' hidden>duplicate</div></body></html>"#,
        ))
        .await
        .unwrap();

        let probe =
            probe_legacy_authentication(&mut page, ".signed-in", None, Duration::from_secs(1))
                .unwrap();
        assert!(!probe.matched);
        assert_eq!(probe.success_candidate_count, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authentication_probe_requires_uniqueness_across_frames() {
        let mut page = page("legacy-auth-cross-frame-ambiguous");
        page.navigate(&data_html(
            r#"<!doctype html><html><body><div class='signed-in' style='width:120px;height:24px'>top</div><iframe style='width:320px;height:200px' srcdoc='<div class="signed-in" style="width:120px;height:24px">child</div>'></iframe></body></html>"#,
        ))
        .await
        .unwrap();

        let probe =
            probe_legacy_authentication(&mut page, ".signed-in", None, Duration::from_secs(1))
                .unwrap();
        assert!(!probe.matched);
        assert_eq!(probe.success_candidate_count, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retains_login_and_captcha_inside_a_child_frame() {
        let mut page = page("legacy-frame");
        let child = format!(
            r#"<!doctype html><html><body>{LOGIN}<div id="tianai-captcha" class="tianai-captcha-slider" style="width:320px;height:220px"><img id="tianai-captcha-slider-bg-img" style="width:300px;height:150px" src="data:image/png;base64,AA=="><img id="tianai-captcha-slider-move-img" style="width:60px;height:60px" src="data:image/png;base64,AA=="><button id="tianai-captcha-slider-move-btn" style="width:40px;height:40px">slide</button></div></body></html>"#
        );
        let child = child
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let parent = format!(
            r#"<!doctype html><html><body><iframe style="width:640px;height:480px" srcdoc="{child}"></iframe></body></html>"#
        );
        page.navigate(&data_html(&parent)).await.unwrap();
        let inspection = inspect_legacy_page(
            &mut page,
            CaptchaAdapter::Auto,
            &LegacyLoginSelectors::default(),
            Duration::from_secs(1),
        )
        .unwrap();
        let login = inspection
            .login
            .as_ref()
            .unwrap_or_else(|| panic!("frame login: {:?}", inspection.diagnostics));
        let captcha = inspection
            .captcha
            .as_ref()
            .unwrap_or_else(|| panic!("frame captcha: {:?}", inspection.diagnostics));
        assert_ne!(login.frame_id, 0);
        assert_eq!(login.frame_id, captcha.frame_id);
        assert!(captcha.top_viewport_rect.x >= captcha.frame_crop_rect.x);
        fill_legacy_credentials(
            &mut page,
            inspection.lease(),
            "framed-user",
            "framed-password",
            Duration::from_secs(1),
        )
        .unwrap();
        let frame_index = page
            .frame_snapshots()
            .iter()
            .position(|frame| frame.frame_id == login.frame_id)
            .unwrap();
        let value = page
            .evaluate_in_frame(
                frame_index,
                "document.querySelector('[name=username]').value",
            )
            .unwrap();
        assert_eq!(value, "framed-user");
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn remote_wheel_maps_top_coordinates_into_child_realm() {
        let mut page = page("legacy-view-wheel-child");
        let child = r#"<!doctype html><html><body style='margin:0'><div id='target' style='position:absolute;left:20px;top:20px;width:180px;height:120px'></div></body></html>"#;
        let child = child
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let parent = format!(
            r#"<!doctype html><html><body style="margin:0"><iframe style="position:absolute;left:80px;top:60px;width:400px;height:260px" srcdoc="{child}"></iframe></body></html>"#
        );
        page.navigate(&data_html(&parent)).await.unwrap();

        let target =
            locate_legacy_view_target(&mut page, 130.0, 110.0, Duration::from_secs(1)).unwrap();
        assert_ne!(
            target.frame_id, 0,
            "point should resolve into the child realm"
        );
        let (frame_x, frame_y) = target.frame_point(130.0, 110.0);
        assert!(
            (frame_x - 50.0).abs() < 0.1,
            "unexpected child x: {frame_x}"
        );
        assert!(
            (frame_y - 50.0).abs() < 0.1,
            "unexpected child y: {frame_y}"
        );
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn remote_wheel_scrolls_nested_container_then_root() {
        let mut page = page("legacy-view-wheel-scroll");
        page.navigate(&data_html(
            r#"<!doctype html><html><body style='margin:0'>
              <div id='page' style='width:1800px;height:2400px'></div>
              <div id='box' style='position:absolute;left:20px;top:20px;width:180px;height:120px;overflow:auto'>
                <div id='inner' style='width:700px;height:800px'></div>
              </div>
            </body></html>"#,
        ))
        .await
        .unwrap();
        dispatch_legacy_view_wheel(
            &mut page,
            0,
            50.0,
            50.0,
            35.0,
            120.0,
            Duration::from_secs(1),
        )
        .unwrap();

        let state = page.evaluate(
            "({left:document.getElementById('box').scrollLeft,top:document.getElementById('box').scrollTop,rootY:scrollY})",
        );
        assert_eq!(state["left"], 35.0, "unexpected wheel state: {state}");
        assert_eq!(state["top"], 120.0, "unexpected wheel state: {state}");
        assert_eq!(state["rootY"], 0.0);
        page.evaluate(
            "document.getElementById('box').scrollTop=document.getElementById('box').scrollHeight",
        );
        dispatch_legacy_view_wheel(&mut page, 0, 50.0, 50.0, 0.0, 90.0, Duration::from_secs(1))
            .unwrap();
        page.settle(20).await;
        let chained = page.evaluate("({rootY:scrollY})");
        assert_eq!(chained["rootY"], 90.0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remote_wheel_rejects_excessive_delta_before_page_dispatch() {
        let mut page = page("legacy-view-wheel-bound");
        page.navigate(&data_html("<html><body></body></html>"))
            .await
            .unwrap();
        let error = dispatch_legacy_view_wheel(
            &mut page,
            0,
            20.0,
            20.0,
            0.0,
            MAX_LEGACY_WHEEL_DELTA + 1.0,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("invalid"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ambiguous_login_or_captcha_fails_closed() {
        let mut page = page("legacy-ambiguous");
        let html = format!("<html><body>{LOGIN}{LOGIN}</body></html>");
        page.navigate(&data_html(&html)).await.unwrap();
        let error = inspect_legacy_page(
            &mut page,
            CaptchaAdapter::Auto,
            &LegacyLoginSelectors::default(),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("ambiguous"));
    }
}
