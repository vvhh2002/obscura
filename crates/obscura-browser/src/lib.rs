pub mod captcha;
pub mod context;
mod fork_virtual_url;
pub mod legacy;
pub mod lifecycle;
pub mod page;
#[cfg(feature = "render")]
pub mod pdf;
pub mod profiles;

pub use captcha::{
    extract_captcha, install_captcha_capture_preload, CaptchaAdapter, CaptchaArtifact,
    CaptchaEvidenceKind, CaptchaExtraction, CaptchaImageRole, CaptchaSourceKind,
};
pub use context::BrowserContext;
pub use legacy::{
    dispatch_legacy_captcha_pointer, dispatch_legacy_view_pointer, dispatch_legacy_view_wheel,
    fill_legacy_credentials, inspect_legacy_page, install_legacy_bridge_preload,
    legacy_captcha_target_is_current, legacy_frame_top_offset, locate_legacy_view_target,
    probe_legacy_authentication, submit_legacy_login, type_into_legacy_view, LegacyAuthProbe,
    LegacyCaptchaTarget, LegacyInspection, LegacyLoginSelectors, LegacyLoginTarget,
    LegacyPointerPhase, LegacyRect, LegacyTargetLease, LegacyViewTarget,
};
pub use lifecycle::{CaptureReadyOptions, CaptureReadyReport, LifecycleState, WaitUntil};
pub use obscura_js::HTML_TO_MARKDOWN_JS;
#[cfg(feature = "render")]
pub use obscura_js::{
    validate_capture_region, AnimationSample, AnimationSampleMode, AnimationSampleTime,
    CaptureError, CaptureRegion,
};
#[cfg(feature = "render")]
pub use page::ScreenshotResourceWarmupReport;
pub use page::{
    CapturedResource, FrameResourceDiagnostic, FrameSnapshot, NavigationEvent, NetworkEvent, Page,
    PageError, ResourceCapture, ResourceCaptureLimits,
};
#[cfg(feature = "render")]
pub use pdf::{RasterPdfError, RasterPdfOptions, RasterPdfPageRange};
// Re-exported so the embeddable `obscura` crate (which depends on obscura-browser,
// not obscura-js) can surface the interception channel types.
pub use obscura_js::ops::{InterceptResolution, InterceptedRequest};
