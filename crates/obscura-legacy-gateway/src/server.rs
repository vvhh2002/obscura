use std::cell::{Cell, RefCell};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, PRAGMA, SET_COOKIE,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};

use crate::assets::{APP_CSS, APP_JS, INDEX_HTML, VIEW_HTML, VIEW_JS};
use crate::backend::{
    BackendError, BackendSnapshot, CaptchaImage, Credentials, DiscoveryProfile, GatewayPhase,
    LegacyBackend, SliderGesture, ViewInput, ViewPointer, ViewWheel,
};
use crate::config::{GatewayConfig, GatewayConfigError};
use crate::security::{
    authorize_api, authorize_same_origin_document, loopback_origin, validate_slider_gesture,
    AuthState, FixedWindowLimit, SessionExpiry, ViewSequence,
};

type HttpResponse = Response<Full<Bytes>>;
const MAX_PNG_BYTES: usize = 16 * 1024 * 1024;
const CAPTCHA_GENERATION_HEADER: &str = "x-obscura-captcha-generation";

/// One-shot discovery commit invoked only after the authenticated state has
/// been confirmed. The profile contains no credentials, cookies, or dynamic
/// challenge material.
pub type DiscoveryCommitHook =
    Box<dyn for<'profile> FnMut(&'profile DiscoveryProfile) -> Result<(), String>>;

pub struct BoundGateway {
    listener: TcpListener,
    local_addr: SocketAddr,
    launch_url: String,
    runtime: Rc<RuntimeState>,
}

struct RuntimeState {
    config: GatewayConfig,
    origin: String,
    authority: String,
    auth: RefCell<AuthState>,
    backend: Mutex<Box<dyn LegacyBackend>>,
    interaction: RefCell<InteractionState>,
    discovery_commit: RefCell<Option<DiscoveryCommitHook>>,
    discovery_completed: Cell<bool>,
}

struct InteractionState {
    view: ViewSequence,
    gesture_limit: FixedWindowLimit,
    credentials_limit: FixedWindowLimit,
    submit_limit: FixedWindowLimit,
    rescan_limit: FixedWindowLimit,
    type_limit: FixedWindowLimit,
    wheel_limit: FixedWindowLimit,
    was_authenticated: bool,
}

impl InteractionState {
    fn new() -> Self {
        Self {
            view: ViewSequence::default(),
            gesture_limit: FixedWindowLimit::per_minute(30),
            credentials_limit: FixedWindowLimit::per_minute(10),
            submit_limit: FixedWindowLimit::per_minute(10),
            rescan_limit: FixedWindowLimit::per_minute(20),
            type_limit: FixedWindowLimit::per_minute(120),
            // The iframe coalesces native wheel events before sending them.
            // Keep a separate short window so a compromised client cannot
            // turn high-frequency trackpad input into an unbounded Page load.
            wheel_limit: FixedWindowLimit::per_second(30),
            was_authenticated: false,
        }
    }

    fn reset(&mut self) {
        self.view.reset();
        self.was_authenticated = false;
    }

    fn authentication_transition(&mut self, phase: GatewayPhase) -> bool {
        let authenticated = phase == GatewayPhase::Authenticated;
        let transitioned = authenticated && !self.was_authenticated;
        self.was_authenticated = authenticated;
        transitioned
    }
}

impl BoundGateway {
    pub async fn bind(
        config: GatewayConfig,
        backend: Box<dyn LegacyBackend>,
    ) -> Result<Self, GatewayError> {
        Self::bind_with_discovery_commit(config, backend, None).await
    }

    pub async fn bind_with_discovery_commit(
        config: GatewayConfig,
        mut backend: Box<dyn LegacyBackend>,
        discovery_commit: Option<DiscoveryCommitHook>,
    ) -> Result<Self, GatewayError> {
        config.validate()?;
        let listener = TcpListener::bind(config.bind_addr).await?;
        let local_addr = listener.local_addr()?;
        if !local_addr.ip().is_loopback() {
            return Err(GatewayError::Config(GatewayConfigError::NonLoopbackBind));
        }
        let origin = loopback_origin(local_addr);
        let authority = origin
            .strip_prefix("http://")
            .expect("loopback origin is HTTP")
            .to_string();
        let auth = AuthState::new(config.session_ttl);
        let launch_url = format!("{origin}/#{}", auth.launch_token());

        let snapshot = backend
            .start(&config.legacy_url)
            .await
            .map_err(GatewayError::BackendStartup)?;
        ensure_allowed_navigation(&config, backend.as_mut(), snapshot)
            .await
            .map_err(GatewayError::BackendStartup)?;

        Ok(Self {
            listener,
            local_addr,
            launch_url,
            runtime: Rc::new(RuntimeState {
                config,
                origin,
                authority,
                auth: RefCell::new(auth),
                backend: Mutex::new(backend),
                interaction: RefCell::new(InteractionState::new()),
                discovery_commit: RefCell::new(discovery_commit),
                discovery_completed: Cell::new(false),
            }),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// URL containing the one process-local bearer token in its fragment. Do
    /// not log or persist this value; hand it directly to the local browser.
    pub fn launch_url(&self) -> &str {
        &self.launch_url
    }

    /// Run on a current-thread runtime. All accepted connections are local
    /// tasks and every Page operation is serialized through one !Send backend.
    pub async fn serve(self) -> Result<(), GatewayError> {
        tokio::task::LocalSet::new()
            .run_until(self.serve_local())
            .await
    }

    async fn serve_local(self) -> Result<(), GatewayError> {
        let semaphore = Arc::new(Semaphore::new(self.runtime.config.max_connections));
        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            if !peer_addr.ip().is_loopback() {
                continue;
            }
            let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                continue;
            };
            let runtime = self.runtime.clone();
            let timeout = runtime.config.connection_timeout;
            let header_limit = runtime.config.request_header_limit;
            tokio::task::spawn_local(async move {
                let service = service_fn(move |request| handle_request(runtime.clone(), request));
                let mut builder = http1::Builder::new();
                builder
                    .keep_alive(false)
                    .max_headers(64)
                    .max_buf_size(header_limit.max(8 * 1024));
                let connection = builder.serve_connection(TokioIo::new(stream), service);
                let _ = tokio::time::timeout(timeout, connection).await;
                drop(permit);
            });
        }
    }
}

async fn handle_request(
    runtime: Rc<RuntimeState>,
    request: Request<Incoming>,
) -> Result<HttpResponse, Infallible> {
    let response = route_request(runtime, request).await;
    Ok(response)
}

async fn route_request(runtime: Rc<RuntimeState>, request: Request<Incoming>) -> HttpResponse {
    if !valid_host(&request, &runtime.authority) || request.uri().query().is_some() {
        return error_response(StatusCode::BAD_REQUEST, "请求地址无效");
    }

    let expiry = runtime.auth.borrow_mut().retire_if_expired();
    if expiry == SessionExpiry::ExpiredNow {
        let mut backend = runtime.backend.lock().await;
        let _ = backend.quarantine().await;
        runtime.interaction.borrow_mut().reset();
    }
    if expiry != SessionExpiry::Active {
        return session_expired_response();
    }

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    match (method.clone(), path.as_str()) {
        (Method::GET, "/") => {
            let cookie = runtime.auth.borrow_mut().issue_session_cookie();
            html_response(INDEX_HTML, RootDocument::Index, Some(&cookie))
        }
        (Method::GET, "/assets/app.css") => static_response("text/css; charset=utf-8", APP_CSS),
        (Method::GET, "/assets/app.js") => {
            static_response("text/javascript; charset=utf-8", APP_JS)
        }
        (Method::GET, "/assets/view.js") => {
            static_response("text/javascript; charset=utf-8", VIEW_JS)
        }
        (Method::GET, "/view") => {
            let authorized = {
                let auth = runtime.auth.borrow();
                authorize_same_origin_document(request.headers(), &runtime.origin, &auth)
            };
            if authorized.is_err() {
                error_response(StatusCode::FORBIDDEN, "请求未获授权")
            } else {
                html_response(VIEW_HTML, RootDocument::View, None)
            }
        }
        _ if path.starts_with("/api/") => {
            let authorized = {
                let auth = runtime.auth.borrow();
                authorize_api(request.headers(), &method, &runtime.origin, &auth)
            };
            if authorized.is_err() {
                return error_response(StatusCode::FORBIDDEN, "请求未获授权");
            }
            route_api(runtime, request, method, &path).await
        }
        _ => error_response(StatusCode::NOT_FOUND, "未找到请求资源"),
    }
}

async fn route_api(
    runtime: Rc<RuntimeState>,
    request: Request<Incoming>,
    method: Method,
    path: &str,
) -> HttpResponse {
    if runtime.discovery_completed.get() {
        return if method == Method::GET && path == "/api/state" {
            discovery_complete_response()
        } else {
            error_response(
                StatusCode::CONFLICT,
                "发现配置已保存，请使用配置启动正式网关",
            )
        };
    }
    match (method, path) {
        (Method::GET, "/api/state") => {
            let mut backend = runtime.backend.lock().await;
            let snapshot = match backend.snapshot().await {
                Ok(snapshot) => snapshot,
                Err(error) => return backend_error_response(error),
            };
            match ensure_allowed_navigation(&runtime.config, backend.as_mut(), snapshot).await {
                Ok(snapshot) => {
                    state_response_for_runtime(&runtime, backend.as_mut(), snapshot).await
                }
                Err(error) => backend_error_response(error),
            }
        }
        (Method::GET, "/api/captcha/background") => {
            let generation = match captcha_generation(request.headers()) {
                Ok(generation) => generation,
                Err(response) => return response,
            };
            png_from_backend(&runtime, CaptchaImage::Background, generation).await
        }
        (Method::GET, "/api/captcha/puzzle") => {
            let generation = match captcha_generation(request.headers()) {
                Ok(generation) => generation,
                Err(response) => return response,
            };
            png_from_backend(&runtime, CaptchaImage::Puzzle, generation).await
        }
        (Method::GET, "/api/frame.png") => {
            let mut backend = runtime.backend.lock().await;
            let snapshot = match backend.snapshot().await {
                Ok(snapshot) => snapshot,
                Err(error) => return backend_error_response(error),
            };
            if let Err(error) =
                ensure_allowed_navigation(&runtime.config, backend.as_mut(), snapshot).await
            {
                return backend_error_response(error);
            }
            let bytes = match backend.frame_png().await {
                Ok(bytes) => bytes,
                Err(error) => return backend_error_response(error),
            };
            let after = match backend.snapshot().await {
                Ok(snapshot) => snapshot,
                Err(error) => return backend_error_response(error),
            };
            if let Err(error) =
                ensure_allowed_navigation(&runtime.config, backend.as_mut(), after).await
            {
                return backend_error_response(error);
            }
            if bytes.len() <= MAX_PNG_BYTES {
                png_response(bytes)
            } else {
                error_response(StatusCode::PAYLOAD_TOO_LARGE, "画面超过安全大小限制")
            }
        }
        (Method::POST, "/api/credentials") => {
            if !runtime.interaction.borrow_mut().credentials_limit.take() {
                return error_response(StatusCode::TOO_MANY_REQUESTS, "操作过于频繁，请稍后重试");
            }
            let credentials: Credentials =
                match read_json(request, runtime.config.request_body_limit).await {
                    Ok(value) => value,
                    Err(response) => return response,
                };
            if credentials.username.is_empty()
                || credentials.username.len() > 512
                || credentials.password.is_empty()
                || credentials.password.len() > 4_096
                || credentials.username.contains('\0')
                || credentials.password.contains('\0')
            {
                return error_response(StatusCode::BAD_REQUEST, "凭据格式无效");
            }
            call_snapshot_operation(&runtime, |backend| backend.fill_credentials(credentials)).await
        }
        (Method::POST, "/api/captcha/drag") => {
            if !runtime.interaction.borrow_mut().gesture_limit.take() {
                return error_response(StatusCode::TOO_MANY_REQUESTS, "操作过于频繁，请稍后重试");
            }
            let gesture: SliderGesture =
                match read_json(request, runtime.config.request_body_limit).await {
                    Ok(value) => value,
                    Err(response) => return response,
                };
            if validate_slider_gesture(&gesture).is_err() {
                return error_response(StatusCode::CONFLICT, "拖动轨迹顺序无效，请重新开始");
            }
            call_snapshot_operation(&runtime, |backend| backend.slider_gesture(gesture)).await
        }
        (Method::POST, "/api/submit") => {
            if !runtime.interaction.borrow_mut().submit_limit.take() {
                return error_response(StatusCode::TOO_MANY_REQUESTS, "操作过于频繁，请稍后重试");
            }
            if let Err(response) = read_empty_json(request, runtime.config.request_body_limit).await
            {
                return response;
            }
            call_snapshot_operation(&runtime, |backend| backend.submit()).await
        }
        (Method::POST, "/api/rescan") => {
            if !runtime.interaction.borrow_mut().rescan_limit.take() {
                return error_response(StatusCode::TOO_MANY_REQUESTS, "操作过于频繁，请稍后重试");
            }
            if let Err(response) = read_empty_json(request, runtime.config.request_body_limit).await
            {
                return response;
            }
            call_snapshot_operation(&runtime, |backend| backend.rescan()).await
        }
        (Method::POST, "/api/view/pointer") => {
            let pointer: ViewPointer =
                match read_json(request, runtime.config.request_body_limit).await {
                    Ok(value) => value,
                    Err(response) => return response,
                };
            if runtime
                .interaction
                .borrow_mut()
                .view
                .accept(pointer)
                .is_err()
            {
                return error_response(StatusCode::CONFLICT, "远程指针顺序无效");
            }
            let response =
                call_snapshot_operation(&runtime, |backend| backend.view_pointer(pointer)).await;
            if !response.status().is_success() {
                runtime.interaction.borrow_mut().view.reset();
            }
            response
        }
        (Method::POST, "/api/view/wheel") => {
            if !runtime.interaction.borrow_mut().wheel_limit.take() {
                return error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "滚动操作过于频繁，请稍后重试",
                );
            }
            let wheel: ViewWheel = match read_json(request, runtime.config.request_body_limit).await
            {
                Ok(value) => value,
                Err(response) => return response,
            };
            if runtime
                .interaction
                .borrow_mut()
                .view
                .accept_wheel(wheel)
                .is_err()
            {
                return error_response(StatusCode::CONFLICT, "远程滚动参数或顺序无效");
            }
            call_snapshot_operation(&runtime, |backend| backend.view_wheel(wheel)).await
        }
        (Method::POST, "/api/view/type") => {
            if !runtime.interaction.borrow_mut().type_limit.take() {
                return error_response(StatusCode::TOO_MANY_REQUESTS, "操作过于频繁，请稍后重试");
            }
            let body: ViewTypeRequest =
                match read_json(request, runtime.config.request_body_limit).await {
                    Ok(value) => value,
                    Err(response) => return response,
                };
            if body.text.len() > 4_096 || body.text.contains('\0') {
                return error_response(StatusCode::BAD_REQUEST, "输入内容格式无效");
            }
            call_snapshot_operation(&runtime, |backend| {
                backend.view_input(ViewInput::Text(body.text))
            })
            .await
        }
        (Method::POST, "/api/logout") => {
            if let Err(response) = read_empty_json(request, runtime.config.request_body_limit).await
            {
                return response;
            }
            let mut backend = runtime.backend.lock().await;
            if let Err(error) = backend.logout(&runtime.config.legacy_url).await {
                return backend_error_response(error);
            }
            runtime.interaction.borrow_mut().reset();
            let snapshot = match backend.snapshot().await {
                Ok(snapshot) => snapshot,
                Err(error) => return backend_error_response(error),
            };
            let snapshot = match ensure_allowed_navigation(
                &runtime.config,
                backend.as_mut(),
                snapshot,
            )
            .await
            {
                Ok(snapshot) => snapshot,
                Err(error) => return backend_error_response(error),
            };
            let cookie = runtime.auth.borrow_mut().rotate_session_cookie();
            let mut response = state_response(snapshot);
            if let Ok(value) = hyper::header::HeaderValue::from_str(&cookie) {
                response.headers_mut().insert(SET_COOKIE, value);
            }
            response
        }
        _ => error_response(StatusCode::NOT_FOUND, "未找到请求资源"),
    }
}

async fn png_from_backend(
    runtime: &Rc<RuntimeState>,
    image: CaptchaImage,
    expected_generation: u64,
) -> HttpResponse {
    let mut backend = runtime.backend.lock().await;
    let snapshot = match backend.snapshot().await {
        Ok(snapshot) => snapshot,
        Err(error) => return backend_error_response(error),
    };
    if let Err(error) = ensure_allowed_navigation(&runtime.config, backend.as_mut(), snapshot).await
    {
        return backend_error_response(error);
    }
    let bytes = match backend.captcha_png(image, expected_generation).await {
        Ok(bytes) => bytes,
        Err(error) => return backend_error_response(error),
    };
    let after = match backend.snapshot().await {
        Ok(snapshot) => snapshot,
        Err(error) => return backend_error_response(error),
    };
    if let Err(error) = ensure_allowed_navigation(&runtime.config, backend.as_mut(), after).await {
        return backend_error_response(error);
    }
    match bytes {
        Some(bytes) if bytes.len() <= MAX_PNG_BYTES => png_response(bytes),
        Some(_) => error_response(StatusCode::PAYLOAD_TOO_LARGE, "画面超过安全大小限制"),
        None => error_response(StatusCode::NOT_FOUND, "当前验证图形不可用"),
    }
}

fn captcha_generation(headers: &hyper::HeaderMap) -> Result<u64, HttpResponse> {
    let mut values = headers.get_all(CAPTCHA_GENERATION_HEADER).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if values.next().is_some() || value.is_none() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "缺少或无效的验证码代次",
        ));
    }
    Ok(value.expect("checked above"))
}

async fn call_snapshot_operation<F>(runtime: &Rc<RuntimeState>, operation: F) -> HttpResponse
where
    F: for<'a> FnOnce(
        &'a mut dyn LegacyBackend,
    )
        -> crate::backend::LocalFuture<'a, Result<BackendSnapshot, BackendError>>,
{
    let mut backend = runtime.backend.lock().await;
    let before = match backend.snapshot().await {
        Ok(snapshot) => snapshot,
        Err(error) => return backend_error_response(error),
    };
    if let Err(error) = ensure_allowed_navigation(&runtime.config, backend.as_mut(), before).await {
        return backend_error_response(error);
    }
    let snapshot = match operation(backend.as_mut()).await {
        Ok(snapshot) => snapshot,
        Err(error) => return backend_error_response(error),
    };
    match ensure_allowed_navigation(&runtime.config, backend.as_mut(), snapshot).await {
        Ok(snapshot) => state_response_for_runtime(runtime, backend.as_mut(), snapshot).await,
        Err(error) => backend_error_response(error),
    }
}

async fn ensure_allowed_navigation(
    config: &GatewayConfig,
    backend: &mut dyn LegacyBackend,
    snapshot: BackendSnapshot,
) -> Result<BackendSnapshot, BackendError> {
    if snapshot
        .navigation_url
        .as_ref()
        .is_some_and(|url| !config.navigation_is_allowed(url))
    {
        let _ = backend.quarantine().await;
        return Err(BackendError::NavigationBlocked);
    }
    Ok(snapshot)
}

async fn read_json<T: for<'de> Deserialize<'de>>(
    request: Request<Incoming>,
    limit: usize,
) -> Result<T, HttpResponse> {
    if request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
    {
        return Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "仅接受 JSON 请求",
        ));
    }
    let bytes = read_bounded_body(request.into_body(), limit).await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "请求格式无效"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewTypeRequest {
    text: String,
}

async fn read_empty_json(request: Request<Incoming>, limit: usize) -> Result<(), HttpResponse> {
    let _: EmptyRequest = read_json(request, limit).await?;
    Ok(())
}

async fn read_bounded_body(mut body: Incoming, limit: usize) -> Result<Bytes, HttpResponse> {
    let mut output = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| error_response(StatusCode::BAD_REQUEST, "请求正文无效"))?;
        if let Some(data) = frame.data_ref() {
            if output.len().saturating_add(data.len()) > limit {
                return Err(error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "请求正文过大",
                ));
            }
            output.extend_from_slice(data);
        }
    }
    Ok(output.freeze())
}

fn valid_host(request: &Request<Incoming>, expected_authority: &str) -> bool {
    request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        == Some(expected_authority)
}

#[derive(Serialize)]
struct StateResponse {
    phase: GatewayPhase,
    subject: Option<String>,
    login_detected: bool,
    captcha: Option<CaptchaResponse>,
    frame_ready: bool,
    generation: u64,
    message: Option<String>,
}

#[derive(Serialize)]
struct CaptchaResponse {
    adapter: &'static str,
    generation: u64,
    background_available: bool,
    puzzle_available: bool,
    aspect_ratio: f64,
    puzzle_width_ratio: Option<f64>,
    puzzle_y_ratio: Option<f64>,
    puzzle_initial_x_ratio: Option<f64>,
}

impl From<BackendSnapshot> for StateResponse {
    fn from(snapshot: BackendSnapshot) -> Self {
        Self {
            phase: snapshot.phase,
            subject: snapshot
                .subject
                .map(|subject| subject.chars().take(160).collect()),
            login_detected: snapshot.login_detected,
            captcha: snapshot.captcha.map(|captcha| CaptchaResponse {
                adapter: captcha.adapter.as_str(),
                generation: captcha.generation,
                background_available: captcha.background_available,
                puzzle_available: captcha.puzzle_available,
                aspect_ratio: captcha.aspect_ratio.clamp(0.2, 8.0),
                puzzle_width_ratio: bounded_ratio(captcha.puzzle_width_ratio),
                puzzle_y_ratio: bounded_ratio(captcha.puzzle_y_ratio),
                puzzle_initial_x_ratio: bounded_ratio(captcha.puzzle_initial_x_ratio),
            }),
            frame_ready: snapshot.frame_ready,
            generation: snapshot.generation,
            message: snapshot
                .message
                .map(|message| message.chars().take(240).collect()),
        }
    }
}

fn bounded_ratio(value: Option<f64>) -> Option<f64> {
    value
        .filter(|value| value.is_finite())
        .map(|value| value.clamp(0.0, 1.0))
}

fn state_response(snapshot: BackendSnapshot) -> HttpResponse {
    json_response(StatusCode::OK, &StateResponse::from(snapshot))
}

async fn state_response_for_runtime(
    runtime: &Rc<RuntimeState>,
    backend: &mut dyn LegacyBackend,
    snapshot: BackendSnapshot,
) -> HttpResponse {
    let transitioned = runtime
        .interaction
        .borrow_mut()
        .authentication_transition(snapshot.phase);
    if transitioned {
        if runtime.discovery_commit.borrow().is_some() {
            let profile = match backend.finalize_discovery(&runtime.config.legacy_url).await {
                Ok(profile) => profile,
                Err(error) => return backend_error_response(error),
            };
            let commit_result = runtime
                .discovery_commit
                .borrow_mut()
                .as_mut()
                .expect("discovery commit was checked")(&profile);
            runtime.discovery_commit.borrow_mut().take();
            if commit_result.is_err() {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "发现配置写入失败；认证上下文已销毁，请重新运行发现",
                );
            }
            runtime.discovery_completed.set(true);
            let cookie = runtime.auth.borrow_mut().rotate_session_cookie();
            let mut response = discovery_complete_response();
            if let Ok(value) = hyper::header::HeaderValue::from_str(&cookie) {
                response.headers_mut().insert(SET_COOKIE, value);
            }
            return response;
        }
    }
    let cookie = transitioned.then(|| runtime.auth.borrow_mut().rotate_session_cookie());
    let mut response = state_response(snapshot);
    if let Some(cookie) = cookie {
        if let Ok(value) = hyper::header::HeaderValue::from_str(&cookie) {
            response.headers_mut().insert(SET_COOKIE, value);
        }
    }
    response
}

fn discovery_complete_response() -> HttpResponse {
    state_response(BackendSnapshot {
        phase: GatewayPhase::DiscoveryComplete,
        navigation_url: None,
        subject: None,
        login_detected: false,
        captcha: None,
        frame_ready: false,
        generation: 0,
        message: Some("发现配置已保存；认证与预检浏览器上下文均已销毁".to_string()),
    })
}

#[cfg(test)]
fn rotate_session_on_authentication_transition(
    interaction: &mut InteractionState,
    auth: &mut AuthState,
    phase: GatewayPhase,
) -> Option<String> {
    interaction
        .authentication_transition(phase)
        .then(|| auth.rotate_session_cookie())
}

fn backend_error_response(error: BackendError) -> HttpResponse {
    let (status, message) = match error {
        BackendError::NotReady | BackendError::StaleTarget => {
            (StatusCode::CONFLICT, "旧系统状态已变化，请重新识别")
        }
        BackendError::LoginUnavailable => (StatusCode::CONFLICT, "未识别到唯一登录入口"),
        BackendError::ConfigurationDrift => (
            StatusCode::CONFLICT,
            "旧系统页面与发现配置不一致，请重新发现",
        ),
        BackendError::CaptchaUnavailable => (StatusCode::CONFLICT, "滑块验证当前不可用"),
        BackendError::NavigationBlocked => {
            (StatusCode::FORBIDDEN, "旧系统跳转超出允许范围，页面已隔离")
        }
        BackendError::Timeout => (StatusCode::GATEWAY_TIMEOUT, "旧系统响应超时"),
        BackendError::CaptureFailed => (StatusCode::SERVICE_UNAVAILABLE, "旧系统画面暂时不可用"),
        BackendError::Failed => (StatusCode::BAD_GATEWAY, "旧系统操作失败"),
    };
    error_response(status, message)
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
}

fn error_response(status: StatusCode, message: &str) -> HttpResponse {
    json_response(status, &ErrorResponse { error: message })
}

fn session_expired_response() -> HttpResponse {
    let mut response = error_response(
        StatusCode::GONE,
        "本机网关会话已到期，旧系统隔离状态已清除；请重新启动网关",
    );
    response.headers_mut().insert(
        SET_COOKIE,
        hyper::header::HeaderValue::from_static(
            "obscura_bridge_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        ),
    );
    response
}

fn json_response(status: StatusCode, value: &impl Serialize) -> HttpResponse {
    let bytes =
        serde_json::to_vec(value).unwrap_or_else(|_| b"{\"error\":\"response failed\"}".to_vec());
    response(
        status,
        "application/json; charset=utf-8",
        bytes,
        DocumentPolicy::Api,
    )
}

fn png_response(bytes: Vec<u8>) -> HttpResponse {
    response(StatusCode::OK, "image/png", bytes, DocumentPolicy::Api)
}

fn static_response(content_type: &'static str, body: &'static str) -> HttpResponse {
    response(
        StatusCode::OK,
        content_type,
        body.as_bytes().to_vec(),
        DocumentPolicy::Static,
    )
}

#[derive(Clone, Copy)]
enum RootDocument {
    Index,
    View,
}

fn html_response(body: &'static str, document: RootDocument, cookie: Option<&str>) -> HttpResponse {
    let policy = match document {
        RootDocument::Index => DocumentPolicy::Root,
        RootDocument::View => DocumentPolicy::View,
    };
    let mut response = response(
        StatusCode::OK,
        "text/html; charset=utf-8",
        body.as_bytes().to_vec(),
        policy,
    );
    if let Some(cookie) = cookie {
        if let Ok(value) = hyper::header::HeaderValue::from_str(cookie) {
            response.headers_mut().insert(SET_COOKIE, value);
        }
    }
    response
}

#[derive(Clone, Copy)]
enum DocumentPolicy {
    Root,
    View,
    Static,
    Api,
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
    policy: DocumentPolicy,
) -> HttpResponse {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(content_type),
    );
    headers.insert(
        CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(PRAGMA, hyper::header::HeaderValue::from_static("no-cache"));
    headers.insert(
        "x-content-type-options",
        hyper::header::HeaderValue::from_static("nosniff"),
    );
    // Same-origin fetches need a referer for the strict GET/iframe checks. URL
    // fragments are never included in Referer, so the launch token remains
    // absent from every HTTP request.
    headers.insert(
        "referrer-policy",
        hyper::header::HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        hyper::header::HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-opener-policy",
        hyper::header::HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "permissions-policy",
        hyper::header::HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()",
        ),
    );
    let csp = match policy {
        DocumentPolicy::Root => "default-src 'none'; base-uri 'none'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self' blob: data:; script-src 'self'; style-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'",
        DocumentPolicy::View => "default-src 'none'; base-uri 'none'; connect-src 'self'; img-src 'self' blob:; script-src 'self'; style-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'self'",
        DocumentPolicy::Static | DocumentPolicy::Api => {
            "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
        }
    };
    headers.insert(
        CONTENT_SECURITY_POLICY,
        hyper::header::HeaderValue::from_static(csp),
    );
    response
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error(transparent)]
    Config(#[from] GatewayConfigError),
    #[error("failed to bind or serve the loopback gateway")]
    Io(#[from] std::io::Error),
    #[error("failed to initialize the configured legacy page: {0}")]
    BackendStartup(BackendError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_response_disables_storage_and_sniffing() {
        for policy in [
            DocumentPolicy::Root,
            DocumentPolicy::View,
            DocumentPolicy::Static,
            DocumentPolicy::Api,
        ] {
            let response = response(StatusCode::OK, "text/plain", Vec::new(), policy);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store, max-age=0");
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert!(response
                .headers()
                .get("access-control-allow-origin")
                .is_none());
        }
    }

    #[test]
    fn root_cannot_be_framed_but_remote_view_is_same_origin_only() {
        let root = html_response(
            INDEX_HTML,
            RootDocument::Index,
            Some("obscura_bridge_session=test; HttpOnly; SameSite=Strict; Path=/"),
        );
        let view = html_response(VIEW_HTML, RootDocument::View, None);
        assert!(root.headers()[CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
        assert!(view.headers()[CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'self'"));
        assert!(root.headers()[SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("HttpOnly; SameSite=Strict"));
        assert_eq!(root.headers()["referrer-policy"], "same-origin");
    }

    #[test]
    fn state_payload_has_no_navigation_url_or_target_material() {
        let encoded = serde_json::to_value(StateResponse::from(BackendSnapshot {
            phase: GatewayPhase::Captcha,
            navigation_url: Some(url::Url::parse("https://legacy.example/login?secret=x").unwrap()),
            subject: Some("Alice".to_string()),
            login_detected: true,
            captcha: None,
            frame_ready: false,
            generation: 4,
            message: Some("Ready".to_string()),
        }))
        .unwrap();
        assert!(encoded.get("navigation_url").is_none());
        assert!(encoded.get("title").is_none());
        assert!(encoded.get("lease").is_none());
        assert!(encoded.get("selector").is_none());
        assert!(!encoded.to_string().contains("secret=x"));
    }

    #[test]
    fn captcha_image_requires_one_exact_generation_header() {
        let mut headers = hyper::HeaderMap::new();
        assert_eq!(
            captcha_generation(&headers).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
        headers.append(
            CAPTCHA_GENERATION_HEADER,
            hyper::header::HeaderValue::from_static("7"),
        );
        assert_eq!(captcha_generation(&headers).unwrap(), 7);
        headers.append(
            CAPTCHA_GENERATION_HEADER,
            hyper::header::HeaderValue::from_static("8"),
        );
        assert_eq!(
            captcha_generation(&headers).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn authentication_transition_rotates_once_until_logout_or_auth_loss() {
        let mut state = InteractionState::new();
        let mut auth = AuthState::new(std::time::Duration::from_secs(60));
        let initial = auth.issue_session_cookie();
        assert!(rotate_session_on_authentication_transition(
            &mut state,
            &mut auth,
            GatewayPhase::Credentials
        )
        .is_none());
        let authenticated = rotate_session_on_authentication_transition(
            &mut state,
            &mut auth,
            GatewayPhase::Authenticated,
        )
        .expect("first authentication transition rotates the cookie");
        assert_ne!(initial, authenticated);
        assert!(authenticated.contains("HttpOnly; SameSite=Strict"));
        assert!(rotate_session_on_authentication_transition(
            &mut state,
            &mut auth,
            GatewayPhase::Authenticated
        )
        .is_none());
        assert!(rotate_session_on_authentication_transition(
            &mut state,
            &mut auth,
            GatewayPhase::Credentials
        )
        .is_none());
        assert!(rotate_session_on_authentication_transition(
            &mut state,
            &mut auth,
            GatewayPhase::Authenticated
        )
        .is_some());
        state.reset();
        assert!(rotate_session_on_authentication_transition(
            &mut state,
            &mut auth,
            GatewayPhase::Authenticated
        )
        .is_some());
    }

    #[test]
    fn remote_wheel_body_is_minimal_and_rejects_unbounded_fields() {
        let valid = serde_json::from_value::<ViewWheel>(serde_json::json!({
            "x": 0.25,
            "y": 0.75,
            "delta_x": 0.0,
            "delta_y": 0.5,
            "sequence": 9
        }))
        .expect("bounded wheel envelope parses");
        assert_eq!(valid.sequence, 9);
        assert!(serde_json::from_value::<ViewWheel>(serde_json::json!({
            "x": 0.25,
            "y": 0.75,
            "delta_x": 0.0,
            "delta_y": 0.5,
            "sequence": 9,
            "selector": "body",
            "url": "https://other.example/"
        }))
        .is_err());
    }
}
