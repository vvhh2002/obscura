//! A loopback-only bridge for presenting one configured legacy login through a
//! controlled UI.
//!
//! The bridge deliberately does not reverse-proxy legacy HTML and never copies
//! legacy cookies into the user's browser. The old system stays inside one
//! Obscura page owned by the backend; the browser receives PNG frames and sends
//! bounded input events to that same page.

mod assets;
mod backend;
mod config;
mod manifest;
#[cfg(feature = "render")]
mod obscura_backend;
#[cfg(feature = "render")]
mod origin_policy;
mod security;
mod server;

pub use backend::{
    BackendError, BackendSnapshot, CaptchaImage, CaptchaPresentation, Credentials, DiscoveredLogin,
    DiscoveryProfile, GatewayPhase, LegacyBackend, LocalFuture, SliderGesture, SliderPointer,
    SliderPointerPhase, ViewInput, ViewPointer, ViewPointerKind, ViewWheel,
};
pub use config::{GatewayConfig, GatewayConfigError, Viewport};
pub use manifest::{
    LegacyCaptchaAdapter, LegacyGatewayManifest, ManifestAuthentication, ManifestDetection,
    ManifestError, ManifestLoginSelectors, ManifestOrigins, ManifestValidationError,
    ManifestViewport, LEGACY_GATEWAY_MANIFEST_SCHEMA_VERSION, MAX_LEGACY_GATEWAY_MANIFEST_BYTES,
};
#[cfg(feature = "render")]
pub use obscura_backend::{ObscuraBackendConfig, ObscuraLegacyBackend};
#[cfg(feature = "render")]
pub use origin_policy::{install_exact_resource_origin_policy, ExactResourceOriginPolicy};
pub use server::{BoundGateway, DiscoveryCommitHook, GatewayError};
