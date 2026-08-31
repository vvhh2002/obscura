use std::future::Future;
use std::pin::Pin;

use obscura_browser::CaptchaAdapter;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub type LocalFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayPhase {
    Starting,
    Detecting,
    Credentials,
    Captcha,
    ReadyToSubmit,
    Submitting,
    Authenticated,
    DiscoveryComplete,
    Blocked,
    Error,
}

#[derive(Clone, Debug)]
pub struct CaptchaPresentation {
    pub adapter: CaptchaAdapter,
    pub generation: u64,
    pub background_available: bool,
    pub puzzle_available: bool,
    /// Width divided by height for the challenge presentation. This is only
    /// layout metadata, never an answer or a target distance.
    pub aspect_ratio: f64,
    pub puzzle_width_ratio: Option<f64>,
    pub puzzle_y_ratio: Option<f64>,
    pub puzzle_initial_x_ratio: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct BackendSnapshot {
    pub phase: GatewayPhase,
    pub navigation_url: Option<Url>,
    /// Display-only legacy identity text. Never use this value to grant roles.
    pub subject: Option<String>,
    pub login_detected: bool,
    pub captcha: Option<CaptchaPresentation>,
    pub frame_ready: bool,
    pub generation: u64,
    /// A short, pre-sanitized status suitable for display. The server truncates
    /// this again and never serializes backend errors.
    pub message: Option<String>,
}

/// Stable, non-secret metadata observed from one successful legacy-login
/// onboarding run. Dynamic challenge URLs, cookies, credentials, and provider
/// tokens are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryProfile {
    pub captcha_adapter: CaptchaAdapter,
    pub captcha_mode: String,
    pub login: DiscoveredLogin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredLogin {
    pub username_label: String,
    pub password_label: String,
    pub submit_label: Option<String>,
    pub username_selector: Option<String>,
    pub password_selector: Option<String>,
    pub submit_selector: Option<String>,
}

impl BackendSnapshot {
    pub fn starting() -> Self {
        Self {
            phase: GatewayPhase::Starting,
            navigation_url: None,
            subject: None,
            login_detected: false,
            captcha: None,
            frame_ready: false,
            generation: 0,
            message: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SliderPointerPhase {
    Down,
    Move,
    Up,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SliderPointer {
    pub phase: SliderPointerPhase,
    pub x: f64,
    pub y: f64,
    pub sequence: u64,
    /// Monotonic milliseconds since the user's pointer-down sample.
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SliderGesture {
    /// Gateway scan generation displayed while the gesture was captured.
    pub generation: u64,
    pub samples: Vec<SliderPointer>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewPointerKind {
    Move,
    Down,
    Up,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewPointer {
    pub kind: ViewPointerKind,
    pub x: f64,
    pub y: f64,
    pub sequence: u64,
}

/// One bounded wheel sample over the authenticated remote viewport. Position
/// and deltas are normalized against the displayed viewport; the concrete
/// backend converts them back to its fixed CSS-pixel viewport.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewWheel {
    pub x: f64,
    pub y: f64,
    pub delta_x: f64,
    pub delta_y: f64,
    pub sequence: u64,
}

#[derive(Clone, Debug)]
pub enum ViewInput {
    Text(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptchaImage {
    Background,
    Puzzle,
}

/// Object-safe, current-thread contract between the HTTP boundary and one
/// Obscura Page owner. Implementations must keep the same BrowserContext/Page
/// for the login and remote view; `logout` must discard that context and create
/// a fresh one.
pub trait LegacyBackend {
    fn start<'a>(
        &'a mut self,
        legacy_url: &'a Url,
    ) -> LocalFuture<'a, Result<BackendSnapshot, BackendError>>;

    fn snapshot(&mut self) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>>;

    /// Return the last complete login/widget profile observed in the live
    /// page. Implementations must never include credentials or session data.
    fn discovery_profile(&self) -> Option<DiscoveryProfile> {
        None
    }

    /// Revalidate discovery in a fresh, logged-out context, discard the
    /// authenticated discovery context, and return only stable metadata.
    fn finalize_discovery<'a>(
        &'a mut self,
        _legacy_url: &'a Url,
    ) -> LocalFuture<'a, Result<DiscoveryProfile, BackendError>> {
        Box::pin(async { Err(BackendError::NotReady) })
    }

    fn captcha_png(
        &mut self,
        image: CaptchaImage,
        expected_generation: u64,
    ) -> LocalFuture<'_, Result<Option<Vec<u8>>, BackendError>>;

    fn frame_png(&mut self) -> LocalFuture<'_, Result<Vec<u8>, BackendError>>;

    fn fill_credentials(
        &mut self,
        credentials: Credentials,
    ) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>>;

    fn slider_gesture(
        &mut self,
        gesture: SliderGesture,
    ) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>>;

    fn submit(&mut self) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>>;

    fn rescan(&mut self) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>>;

    fn view_pointer(
        &mut self,
        pointer: ViewPointer,
    ) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>>;

    fn view_wheel(
        &mut self,
        wheel: ViewWheel,
    ) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>>;

    fn view_input(
        &mut self,
        input: ViewInput,
    ) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>>;

    fn logout<'a>(&'a mut self, legacy_url: &'a Url) -> LocalFuture<'a, Result<(), BackendError>>;

    /// Called before a navigation outside the exact configured allowlist can
    /// be reported to a client. Implementations should stop pending work and
    /// replace the page with an inert document.
    fn quarantine(&mut self) -> LocalFuture<'_, Result<(), BackendError>>;
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BackendError {
    #[error("legacy page is not ready")]
    NotReady,
    #[error("legacy page state changed; rescan required")]
    StaleTarget,
    #[error("legacy login is ambiguous or unavailable")]
    LoginUnavailable,
    #[error("legacy page no longer matches the discovered integration profile")]
    ConfigurationDrift,
    #[error("slider CAPTCHA is unavailable")]
    CaptchaUnavailable,
    #[error("navigation left the configured allowlist")]
    NavigationBlocked,
    #[error("legacy operation timed out")]
    Timeout,
    #[error("legacy capture failed")]
    CaptureFailed,
    #[error("legacy operation failed")]
    Failed,
}
