//! Versioned, secret-free configuration for a discovered legacy login.
//!
//! A manifest contains only stable integration metadata. Runtime credentials,
//! cookies, bearer values, CAPTCHA tokens, and challenge URLs have no fields in
//! this schema, and unknown JSON fields are rejected at every object boundary.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::backend::{DiscoveredLogin, DiscoveryProfile};
use crate::config::{canonical_origin, GatewayConfig, Viewport};

pub const LEGACY_GATEWAY_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MAX_LEGACY_GATEWAY_MANIFEST_BYTES: usize = 64 * 1024;

const MAX_LOGIN_URL_BYTES: usize = 4 * 1024;
const MAX_SELECTOR_BYTES: usize = 1024;
const MAX_DETECTION_VALUE_BYTES: usize = 160;
const MAX_USER_AGENT_BYTES: usize = 1024;
const MAX_ORIGINS_PER_LIST: usize = 256;
const MIN_VIEWPORT_WIDTH: u32 = 320;
const MAX_VIEWPORT_WIDTH: u32 = 4096;
const MIN_VIEWPORT_HEIGHT: u32 = 240;
const MAX_VIEWPORT_HEIGHT: u32 = 2160;
const MIN_SESSION_TTL_SECONDS: u64 = 60;
const MAX_SESSION_TTL_SECONDS: u64 = 24 * 60 * 60;

/// Stable spelling for the supported legacy slider adapters.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum LegacyCaptchaAdapter {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "tianai")]
    Tianai,
    #[serde(rename = "gocaptcha-slide")]
    GoCaptchaSlide,
    #[serde(rename = "aj-captcha")]
    AjCaptcha,
    #[serde(rename = "slider-captcha-js")]
    SliderCaptchaJs,
}

impl From<LegacyCaptchaAdapter> for obscura_browser::CaptchaAdapter {
    fn from(value: LegacyCaptchaAdapter) -> Self {
        match value {
            LegacyCaptchaAdapter::Auto => Self::Auto,
            LegacyCaptchaAdapter::Tianai => Self::Tianai,
            LegacyCaptchaAdapter::GoCaptchaSlide => Self::GoCaptcha,
            LegacyCaptchaAdapter::AjCaptcha => Self::AjCaptcha,
            LegacyCaptchaAdapter::SliderCaptchaJs => Self::SliderCaptchaJs,
        }
    }
}

impl From<obscura_browser::CaptchaAdapter> for LegacyCaptchaAdapter {
    fn from(value: obscura_browser::CaptchaAdapter) -> Self {
        match value {
            obscura_browser::CaptchaAdapter::Auto => Self::Auto,
            obscura_browser::CaptchaAdapter::Tianai => Self::Tianai,
            obscura_browser::CaptchaAdapter::GoCaptcha => Self::GoCaptchaSlide,
            obscura_browser::CaptchaAdapter::AjCaptcha => Self::AjCaptcha,
            obscura_browser::CaptchaAdapter::SliderCaptchaJs => Self::SliderCaptchaJs,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestLoginSelectors {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit: Option<String>,
}

impl From<&ManifestLoginSelectors> for obscura_browser::LegacyLoginSelectors {
    fn from(value: &ManifestLoginSelectors) -> Self {
        Self {
            username: value.username.clone(),
            password: value.password.clone(),
            submit: value.submit.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestAuthentication {
    pub success_selector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_selector: Option<String>,
}

/// Stable evidence used to reject a changed or ambiguously detected login UI
/// before credentials are accepted in serve mode.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestDetection {
    pub captcha_mode: String,
    pub username_label: String,
    pub password_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit_label: Option<String>,
}

/// Complete exact-origin allowlists. `BTreeSet` keeps emitted JSON stable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestOrigins {
    pub navigation: BTreeSet<String>,
    pub resources: BTreeSet<String>,
}

impl<'de> Deserialize<'de> for ManifestOrigins {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireOrigins {
            navigation: Vec<String>,
            resources: Vec<String>,
        }

        let wire = WireOrigins::deserialize(deserializer)?;
        let navigation_len = wire.navigation.len();
        let navigation = wire.navigation.into_iter().collect::<BTreeSet<_>>();
        if navigation.len() != navigation_len {
            return Err(<D::Error as serde::de::Error>::custom(
                "navigation origins must not contain duplicates",
            ));
        }
        let resources_len = wire.resources.len();
        let resources = wire.resources.into_iter().collect::<BTreeSet<_>>();
        if resources.len() != resources_len {
            return Err(<D::Error as serde::de::Error>::custom(
                "resource origins must not contain duplicates",
            ));
        }
        Ok(Self {
            navigation,
            resources,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestViewport {
    pub width: u32,
    pub height: u32,
}

impl Default for ManifestViewport {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
        }
    }
}

impl From<ManifestViewport> for Viewport {
    fn from(value: ManifestViewport) -> Self {
        Self {
            width: value.width,
            height: value.height,
        }
    }
}

/// Schema v1 of the persistent legacy gateway integration contract.
///
/// Fields are public for discovery tooling, but both serde directions and all
/// file/JSON helpers call [`Self::validate`]. Invalid values therefore cannot
/// be emitted or accepted through the supported persistence APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyGatewayManifest {
    pub schema_version: u32,
    pub login_url: String,
    pub captcha_adapter: LegacyCaptchaAdapter,
    pub selectors: ManifestLoginSelectors,
    pub authentication: ManifestAuthentication,
    pub detection: ManifestDetection,
    pub origins: ManifestOrigins,
    pub viewport: ManifestViewport,
    pub session_ttl_seconds: u64,
    pub allow_insecure_legacy_http: bool,
    pub user_agent: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestWire {
    schema_version: u32,
    login_url: String,
    captcha_adapter: LegacyCaptchaAdapter,
    selectors: ManifestLoginSelectors,
    authentication: ManifestAuthentication,
    detection: ManifestDetection,
    origins: ManifestOrigins,
    viewport: ManifestViewport,
    session_ttl_seconds: u64,
    allow_insecure_legacy_http: bool,
    #[serde(default)]
    user_agent: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestWireRef<'a> {
    schema_version: u32,
    login_url: &'a str,
    captcha_adapter: LegacyCaptchaAdapter,
    selectors: &'a ManifestLoginSelectors,
    authentication: &'a ManifestAuthentication,
    detection: &'a ManifestDetection,
    origins: &'a ManifestOrigins,
    viewport: ManifestViewport,
    session_ttl_seconds: u64,
    allow_insecure_legacy_http: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<&'a str>,
}

impl Serialize for LegacyGatewayManifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate()
            .map_err(<S::Error as serde::ser::Error>::custom)?;
        ManifestWireRef {
            schema_version: self.schema_version,
            login_url: &self.login_url,
            captcha_adapter: self.captcha_adapter,
            selectors: &self.selectors,
            authentication: &self.authentication,
            detection: &self.detection,
            origins: &self.origins,
            viewport: self.viewport,
            session_ttl_seconds: self.session_ttl_seconds,
            allow_insecure_legacy_http: self.allow_insecure_legacy_http,
            user_agent: self.user_agent.as_deref(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LegacyGatewayManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ManifestWire::deserialize(deserializer)?;
        let manifest = Self {
            schema_version: wire.schema_version,
            login_url: wire.login_url,
            captcha_adapter: wire.captcha_adapter,
            selectors: wire.selectors,
            authentication: wire.authentication,
            detection: wire.detection,
            origins: wire.origins,
            viewport: wire.viewport,
            session_ttl_seconds: wire.session_ttl_seconds,
            allow_insecure_legacy_http: wire.allow_insecure_legacy_http,
            user_agent: wire.user_agent,
        };
        manifest
            .validate()
            .map_err(<D::Error as serde::de::Error>::custom)?;
        Ok(manifest)
    }
}

impl LegacyGatewayManifest {
    /// Construct a manifest with the same viewport, TTL, and startup-origin
    /// defaults as the current `legacy-gateway` CLI.
    pub fn new(
        login_url: impl Into<String>,
        captcha_adapter: LegacyCaptchaAdapter,
        selectors: ManifestLoginSelectors,
        authentication: ManifestAuthentication,
        detection: ManifestDetection,
        allow_insecure_legacy_http: bool,
    ) -> Result<Self, ManifestValidationError> {
        let login_url = login_url.into();
        let parsed = validate_login_url(&login_url, allow_insecure_legacy_http)?;
        let startup_origin =
            canonical_origin(&parsed).map_err(|_| ManifestValidationError::InvalidLoginUrl)?;
        let manifest = Self {
            schema_version: LEGACY_GATEWAY_MANIFEST_SCHEMA_VERSION,
            login_url,
            captcha_adapter,
            selectors,
            authentication,
            detection,
            origins: ManifestOrigins {
                navigation: BTreeSet::from([startup_origin.clone()]),
                resources: BTreeSet::from([startup_origin]),
            },
            viewport: ManifestViewport::default(),
            session_ttl_seconds: 30 * 60,
            allow_insecure_legacy_http,
            user_agent: None,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Build the persistent contract directly from the backend's finalized
    /// one-shot discovery result. Runtime-only material is not represented.
    pub fn from_discovery_profile(
        login_url: impl Into<String>,
        profile: &DiscoveryProfile,
        authentication: ManifestAuthentication,
        allow_insecure_legacy_http: bool,
    ) -> Result<Self, ManifestValidationError> {
        Self::new(
            login_url,
            profile.captcha_adapter.into(),
            ManifestLoginSelectors {
                username: profile.login.username_selector.clone(),
                password: profile.login.password_selector.clone(),
                submit: profile.login.submit_selector.clone(),
            },
            authentication,
            ManifestDetection {
                captcha_mode: profile.captcha_mode.clone(),
                username_label: profile.login.username_label.clone(),
                password_label: profile.login.password_label.clone(),
                submit_label: profile.login.submit_label.clone(),
            },
            allow_insecure_legacy_http,
        )
    }

    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        if self.schema_version != LEGACY_GATEWAY_MANIFEST_SCHEMA_VERSION {
            return Err(ManifestValidationError::UnsupportedSchemaVersion);
        }
        let login_url = validate_login_url(&self.login_url, self.allow_insecure_legacy_http)?;

        let expected_captcha_mode = expected_captcha_mode(self.captcha_adapter)
            .ok_or(ManifestValidationError::AutoCaptchaAdapterNotPersistable)?;
        validate_detection_value("detection.captchaMode", &self.detection.captcha_mode)?;
        validate_detection_value("detection.usernameLabel", &self.detection.username_label)?;
        validate_detection_value("detection.passwordLabel", &self.detection.password_label)?;
        if let Some(submit_label) = self.detection.submit_label.as_deref() {
            validate_detection_value("detection.submitLabel", submit_label)?;
        }
        if self.detection.captcha_mode != expected_captcha_mode {
            return Err(ManifestValidationError::CaptchaModeMismatch);
        }

        validate_optional_selector("selectors.username", self.selectors.username.as_deref())?;
        validate_optional_selector("selectors.password", self.selectors.password.as_deref())?;
        validate_optional_selector("selectors.submit", self.selectors.submit.as_deref())?;
        if self.selectors.username.is_none() {
            return Err(ManifestValidationError::MissingRequiredLoginSelector {
                field: "selectors.username",
            });
        }
        if self.selectors.password.is_none() {
            return Err(ManifestValidationError::MissingRequiredLoginSelector {
                field: "selectors.password",
            });
        }
        if self.detection.submit_label.is_some() && self.selectors.submit.is_none() {
            return Err(ManifestValidationError::MissingSubmitSelector);
        }
        validate_selector(
            "authentication.successSelector",
            &self.authentication.success_selector,
        )?;
        validate_optional_selector(
            "authentication.subjectSelector",
            self.authentication.subject_selector.as_deref(),
        )?;

        validate_origin_list(
            "navigation",
            &self.origins.navigation,
            self.allow_insecure_legacy_http,
        )?;
        validate_origin_list(
            "resources",
            &self.origins.resources,
            self.allow_insecure_legacy_http,
        )?;

        let startup_origin =
            canonical_origin(&login_url).map_err(|_| ManifestValidationError::InvalidLoginUrl)?;
        if !self.origins.navigation.contains(&startup_origin) {
            return Err(ManifestValidationError::LoginOriginNotAllowedForNavigation);
        }
        // GatewayConfig::new and the CLI put the startup origin in both sets.
        // Preserve that behavior when the manifest replaces CLI discovery.
        if !self.origins.resources.contains(&startup_origin) {
            return Err(ManifestValidationError::LoginOriginNotAllowedForResources);
        }

        if !(MIN_VIEWPORT_WIDTH..=MAX_VIEWPORT_WIDTH).contains(&self.viewport.width)
            || !(MIN_VIEWPORT_HEIGHT..=MAX_VIEWPORT_HEIGHT).contains(&self.viewport.height)
        {
            return Err(ManifestValidationError::InvalidViewport);
        }
        if !(MIN_SESSION_TTL_SECONDS..=MAX_SESSION_TTL_SECONDS).contains(&self.session_ttl_seconds)
        {
            return Err(ManifestValidationError::InvalidSessionTtl);
        }
        if let Some(user_agent) = self.user_agent.as_deref() {
            validate_user_agent(user_agent)?;
        }
        Ok(())
    }

    /// Recreate the exact profile expected by serve-mode drift validation.
    /// Selectors intentionally come from `manifest.selectors`, rather than
    /// being duplicated inside the detection object.
    pub fn expected_discovery_profile(&self) -> Result<DiscoveryProfile, ManifestValidationError> {
        self.validate()?;
        Ok(DiscoveryProfile {
            captcha_adapter: self.captcha_adapter.into(),
            captcha_mode: self.detection.captcha_mode.clone(),
            login: DiscoveredLogin {
                username_label: self.detection.username_label.clone(),
                password_label: self.detection.password_label.clone(),
                submit_label: self.detection.submit_label.clone(),
                username_selector: self.selectors.username.clone(),
                password_selector: self.selectors.password.clone(),
                submit_selector: self.selectors.submit.clone(),
            },
        })
    }

    pub fn parsed_login_url(&self) -> Result<Url, ManifestValidationError> {
        self.validate()?;
        Url::parse(&self.login_url).map_err(|_| ManifestValidationError::InvalidLoginUrl)
    }

    /// Materialize the persisted gateway fields while retaining runtime-only
    /// GatewayConfig defaults such as loopback binding and connection limits.
    pub fn to_gateway_config(&self) -> Result<GatewayConfig, ManifestValidationError> {
        let login_url = self.parsed_login_url()?;
        let mut config = GatewayConfig::new(login_url);
        config.allowed_navigation_origins = self.origins.navigation.clone();
        config.allowed_resource_origins = self.origins.resources.clone();
        config.allow_insecure_legacy_http = self.allow_insecure_legacy_http;
        config.viewport = self.viewport.into();
        config.session_ttl = Duration::from_secs(self.session_ttl_seconds);
        config
            .validate()
            .map_err(|_| ManifestValidationError::IncompatibleGatewayConfiguration)?;
        Ok(config)
    }

    pub fn from_json_slice(input: &[u8]) -> Result<Self, ManifestError> {
        if input.len() > MAX_LEGACY_GATEWAY_MANIFEST_BYTES {
            return Err(ManifestError::ManifestTooLarge);
        }
        Ok(serde_json::from_slice(input)?)
    }

    pub fn from_json_str(input: &str) -> Result<Self, ManifestError> {
        Self::from_json_slice(input.as_bytes())
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self, ManifestError> {
        let file = File::open(path)?;
        let mut input = Vec::new();
        file.take((MAX_LEGACY_GATEWAY_MANIFEST_BYTES + 1) as u64)
            .read_to_end(&mut input)?;
        Self::from_json_slice(&input)
    }

    pub fn to_json_pretty(&self) -> Result<String, ManifestError> {
        self.validate()?;
        let json = serde_json::to_string_pretty(self)?;
        if json.len() + 1 > MAX_LEGACY_GATEWAY_MANIFEST_BYTES {
            return Err(ManifestError::ManifestTooLarge);
        }
        Ok(json)
    }

    /// Atomically publish a new manifest without replacing any existing file.
    ///
    /// The fully written and synced temporary file is hard-linked into place in
    /// the destination directory. Creating that link is atomic and fails with
    /// [`ManifestError::DestinationExists`] if any filesystem entry already
    /// occupies `path`.
    pub fn write_atomic_new(&self, path: impl AsRef<Path>) -> Result<(), ManifestError> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let file_name = path
            .file_name()
            .ok_or(ManifestError::InvalidDestination)?
            .to_string_lossy();
        let mut json = self.to_json_pretty()?.into_bytes();
        json.push(b'\n');

        let (temporary_path, mut temporary_file) = (0..16)
            .find_map(|_| {
                let candidate =
                    parent.join(format!(".{file_name}.{}.tmp", Uuid::new_v4().simple()));
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o600);
                }
                match options.open(&candidate) {
                    Ok(file) => Some(Ok((candidate, file))),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .transpose()?
            .ok_or(ManifestError::TemporaryNameExhausted)?;
        let temporary = TemporaryManifest::new(temporary_path);

        temporary_file.write_all(&json)?;
        temporary_file.sync_all()?;
        drop(temporary_file);

        match fs::hard_link(temporary.path(), path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(ManifestError::DestinationExists);
            }
            Err(error) => return Err(ManifestError::Io(error)),
        }

        // Publication is already complete. Directory syncing is a durability
        // improvement on Unix, not part of the no-overwrite guarantee.
        #[cfg(unix)]
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    }
}

fn validate_login_url(
    value: &str,
    allow_insecure_http: bool,
) -> Result<Url, ManifestValidationError> {
    if value.is_empty() || value.len() > MAX_LOGIN_URL_BYTES || value.trim() != value {
        return Err(ManifestValidationError::InvalidLoginUrl);
    }
    let url = Url::parse(value).map_err(|_| ManifestValidationError::InvalidLoginUrl)?;
    if url.host_str().is_none() {
        return Err(ManifestValidationError::InvalidLoginUrl);
    }
    if has_explicit_userinfo(value) || !url.username().is_empty() || url.password().is_some() {
        return Err(ManifestValidationError::LoginUrlCredentials);
    }
    if url.fragment().is_some() {
        return Err(ManifestValidationError::LoginUrlFragment);
    }
    match url.scheme() {
        "https" => {}
        "http" if allow_insecure_http => {}
        "http" => return Err(ManifestValidationError::InsecureHttpNotAllowed),
        _ => return Err(ManifestValidationError::UnsupportedLoginUrlScheme),
    }
    if url
        .query_pairs()
        .any(|(name, _)| sensitive_query_name(&name))
    {
        return Err(ManifestValidationError::SensitiveLoginUrlQuery);
    }
    Ok(url)
}

fn has_explicit_userinfo(value: &str) -> bool {
    let Some((_, remainder)) = value.split_once("://") else {
        return false;
    };
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    remainder[..authority_end].contains('@')
}

fn sensitive_query_name(name: &str) -> bool {
    let normalized = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    normalized.contains("captcha")
        || matches!(
            normalized.as_str(),
            "token"
                | "accesstoken"
                | "refreshtoken"
                | "idtoken"
                | "cookie"
                | "session"
                | "sessionid"
                | "jsessionid"
                | "credential"
                | "credentials"
                | "password"
                | "passwd"
                | "secret"
                | "clientsecret"
                | "ticket"
                | "code"
                | "authcode"
                | "authorizationcode"
        )
}

fn validate_optional_selector(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ManifestValidationError> {
    match value {
        Some(value) => validate_selector(field, value),
        None => Ok(()),
    }
}

fn expected_captcha_mode(adapter: LegacyCaptchaAdapter) -> Option<&'static str> {
    match adapter {
        LegacyCaptchaAdapter::Auto => None,
        LegacyCaptchaAdapter::Tianai | LegacyCaptchaAdapter::SliderCaptchaJs => Some("slider"),
        LegacyCaptchaAdapter::GoCaptchaSlide => Some("slide"),
        LegacyCaptchaAdapter::AjCaptcha => Some("block_puzzle"),
    }
}

fn validate_detection_value(
    field: &'static str,
    value: &str,
) -> Result<(), ManifestValidationError> {
    if value.is_empty()
        || value.len() > MAX_DETECTION_VALUE_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ManifestValidationError::InvalidDetectionValue { field });
    }
    Ok(())
}

fn validate_selector(field: &'static str, value: &str) -> Result<(), ManifestValidationError> {
    if value.is_empty()
        || value.len() > MAX_SELECTOR_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ManifestValidationError::InvalidSelector { field });
    }
    Ok(())
}

fn validate_origin_list(
    list: &'static str,
    origins: &BTreeSet<String>,
    allow_insecure_http: bool,
) -> Result<(), ManifestValidationError> {
    if origins.is_empty() {
        return Err(ManifestValidationError::MissingOrigins { list });
    }
    if origins.len() > MAX_ORIGINS_PER_LIST {
        return Err(ManifestValidationError::TooManyOrigins { list });
    }
    for origin in origins {
        let url =
            Url::parse(origin).map_err(|_| ManifestValidationError::InvalidOrigin { list })?;
        match url.scheme() {
            "https" => {}
            "http" if allow_insecure_http => {}
            "http" => return Err(ManifestValidationError::InsecureOrigin { list }),
            _ => return Err(ManifestValidationError::InvalidOrigin { list }),
        }
        let canonical =
            canonical_origin(&url).map_err(|_| ManifestValidationError::InvalidOrigin { list })?;
        if canonical != *origin {
            return Err(ManifestValidationError::NonCanonicalOrigin { list });
        }
    }
    Ok(())
}

fn validate_user_agent(value: &str) -> Result<(), ManifestValidationError> {
    if value.is_empty()
        || value.len() > MAX_USER_AGENT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ManifestValidationError::InvalidUserAgent);
    }
    Ok(())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ManifestValidationError {
    #[error("unsupported legacy gateway manifest schemaVersion")]
    UnsupportedSchemaVersion,
    #[error("loginUrl must be an absolute HTTP(S) URL with a host")]
    InvalidLoginUrl,
    #[error("loginUrl must use HTTP or HTTPS")]
    UnsupportedLoginUrlScheme,
    #[error("HTTP requires allowInsecureLegacyHttp=true")]
    InsecureHttpNotAllowed,
    #[error("loginUrl must not contain userinfo credentials")]
    LoginUrlCredentials,
    #[error("loginUrl must not contain a fragment")]
    LoginUrlFragment,
    #[error("loginUrl must not persist a token, session, credential, or CAPTCHA query")]
    SensitiveLoginUrlQuery,
    #[error("a persisted discovery result must use a concrete CAPTCHA adapter, not auto")]
    AutoCaptchaAdapterNotPersistable,
    #[error("detection.captchaMode does not match captchaAdapter")]
    CaptchaModeMismatch,
    #[error("{field} must be trimmed, control-free, and between 1 and 160 bytes")]
    InvalidDetectionValue { field: &'static str },
    #[error("{field} must be trimmed, control-free, and between 1 and 1024 bytes")]
    InvalidSelector { field: &'static str },
    #[error("{field} is required in a persisted discovery result")]
    MissingRequiredLoginSelector { field: &'static str },
    #[error("selectors.submit is required when detection.submitLabel is present")]
    MissingSubmitSelector,
    #[error("the {list} exact-origin list must not be empty")]
    MissingOrigins { list: &'static str },
    #[error("the {list} exact-origin list contains too many entries")]
    TooManyOrigins { list: &'static str },
    #[error("the {list} exact-origin list contains an invalid origin")]
    InvalidOrigin { list: &'static str },
    #[error("the {list} exact-origin list contains a non-canonical origin")]
    NonCanonicalOrigin { list: &'static str },
    #[error("HTTP in the {list} exact-origin list requires allowInsecureLegacyHttp=true")]
    InsecureOrigin { list: &'static str },
    #[error("the loginUrl origin must be present in origins.navigation")]
    LoginOriginNotAllowedForNavigation,
    #[error("the loginUrl origin must be present in origins.resources")]
    LoginOriginNotAllowedForResources,
    #[error("viewport must be between 320x240 and 4096x2160")]
    InvalidViewport,
    #[error("sessionTtlSeconds must be between 60 and 86400")]
    InvalidSessionTtl,
    #[error("userAgent must be trimmed, control-free, and between 1 and 1024 bytes")]
    InvalidUserAgent,
    #[error("manifest values are incompatible with GatewayConfig")]
    IncompatibleGatewayConfiguration,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("legacy gateway manifest exceeds 64 KiB")]
    ManifestTooLarge,
    #[error("manifest destination is not a file path")]
    InvalidDestination,
    #[error("manifest destination already exists")]
    DestinationExists,
    #[error("could not allocate a unique manifest temporary file")]
    TemporaryNameExhausted,
    #[error("legacy gateway manifest I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("legacy gateway manifest JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Validation(#[from] ManifestValidationError),
}

struct TemporaryManifest {
    path: PathBuf,
}

impl TemporaryManifest {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryManifest {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> LegacyGatewayManifest {
        let mut manifest = LegacyGatewayManifest::new(
            "https://legacy.example/login?service=portal",
            LegacyCaptchaAdapter::GoCaptchaSlide,
            ManifestLoginSelectors {
                username: Some("#account".to_string()),
                password: Some("#password".to_string()),
                submit: Some("button[type=submit]".to_string()),
            },
            ManifestAuthentication {
                success_selector: "#signed-in-shell".to_string(),
                subject_selector: Some(".current-user".to_string()),
            },
            ManifestDetection {
                captcha_mode: "slide".to_string(),
                username_label: "Account".to_string(),
                password_label: "Password".to_string(),
                submit_label: Some("Sign in".to_string()),
            },
            false,
        )
        .unwrap();
        manifest
            .origins
            .navigation
            .insert("https://sso.example:8443".to_string());
        manifest
            .origins
            .resources
            .insert("https://static.example".to_string());
        manifest.user_agent = Some("Legacy Browser/1.0".to_string());
        manifest
    }

    #[test]
    fn valid_manifest_round_trips_and_materializes_gateway_config() {
        let expected = manifest();
        let json = expected.to_json_pretty().unwrap();
        assert!(json.contains(r#""schemaVersion": 1"#));
        assert!(json.contains(r#""captchaAdapter": "gocaptcha-slide""#));
        assert!(json.contains(r#""sessionTtlSeconds": 1800"#));
        assert!(json.contains(r#""allowInsecureLegacyHttp": false"#));
        assert!(json.contains(r#""captchaMode": "slide""#));
        assert!(!json.contains("cookie"));
        assert!(!json.contains("captchaUrl"));

        let actual = LegacyGatewayManifest::from_json_str(&json).unwrap();
        assert_eq!(actual, expected);
        let config = actual.to_gateway_config().unwrap();
        assert_eq!(config.legacy_url.as_str(), expected.login_url);
        assert_eq!(config.viewport, Viewport::default());
        assert_eq!(config.session_ttl, Duration::from_secs(1800));
        assert_eq!(
            config.allowed_navigation_origins,
            expected.origins.navigation
        );
        assert_eq!(config.allowed_resource_origins, expected.origins.resources);
    }

    #[test]
    fn all_and_only_supported_adapter_spellings_deserialize() {
        for (adapter, mode) in [
            ("tianai", "slider"),
            ("gocaptcha-slide", "slide"),
            ("aj-captcha", "block_puzzle"),
            ("slider-captcha-js", "slider"),
        ] {
            let json = manifest()
                .to_json_pretty()
                .unwrap()
                .replace("\"gocaptcha-slide\"", &format!("\"{adapter}\""))
                .replace(
                    "\"captchaMode\": \"slide\"",
                    &format!("\"captchaMode\": \"{mode}\""),
                );
            assert!(
                LegacyGatewayManifest::from_json_str(&json).is_ok(),
                "{adapter}"
            );
        }
        for adapter in [
            "auto",
            "go-captcha",
            "gocaptcha",
            "slider-captcha",
            "custom",
        ] {
            let json = manifest()
                .to_json_pretty()
                .unwrap()
                .replace("\"gocaptcha-slide\"", &format!("\"{adapter}\""));
            assert!(
                LegacyGatewayManifest::from_json_str(&json).is_err(),
                "{adapter}"
            );
        }
    }

    #[test]
    fn unknown_and_secret_fields_are_rejected_at_every_object_boundary() {
        let value = serde_json::to_value(manifest()).unwrap();
        for field in ["credentials", "cookies", "token", "captchaUrl"] {
            let mut candidate = value.clone();
            candidate
                .as_object_mut()
                .unwrap()
                .insert(field.to_string(), serde_json::json!("secret"));
            assert!(serde_json::from_value::<LegacyGatewayManifest>(candidate).is_err());
        }

        let mut nested = value;
        nested["selectors"]["captchaUrl"] = serde_json::json!("https://captcha.invalid/new");
        assert!(serde_json::from_value::<LegacyGatewayManifest>(nested).is_err());

        let mut detection = serde_json::to_value(manifest()).unwrap();
        detection["detection"]["captchaUrl"] = serde_json::json!("https://captcha.invalid/new");
        assert!(serde_json::from_value::<LegacyGatewayManifest>(detection).is_err());
    }

    #[test]
    fn schema_http_and_url_security_are_explicit() {
        let mut value = manifest();
        value.schema_version = 2;
        assert_eq!(
            value.validate(),
            Err(ManifestValidationError::UnsupportedSchemaVersion)
        );

        for login_url in [
            "ftp://legacy.example/login",
            "https://user:secret@legacy.example/login",
            "https://legacy.example/login#token",
            "https://legacy.example/login?access_token=secret",
            "https://legacy.example/login?captchaUrl=%2Fchallenge",
        ] {
            let mut value = manifest();
            value.login_url = login_url.to_string();
            assert!(value.validate().is_err(), "{login_url}");
        }

        let insecure = LegacyGatewayManifest::new(
            "http://legacy.example/login",
            LegacyCaptchaAdapter::Tianai,
            ManifestLoginSelectors {
                username: Some("#username".to_string()),
                password: Some("#password".to_string()),
                submit: None,
            },
            ManifestAuthentication {
                success_selector: "#ready".to_string(),
                subject_selector: None,
            },
            ManifestDetection {
                captcha_mode: "slider".to_string(),
                username_label: "Username".to_string(),
                password_label: "Password".to_string(),
                submit_label: None,
            },
            false,
        );
        assert_eq!(
            insecure,
            Err(ManifestValidationError::InsecureHttpNotAllowed)
        );
        assert!(LegacyGatewayManifest::new(
            "http://legacy.example/login",
            LegacyCaptchaAdapter::Tianai,
            ManifestLoginSelectors {
                username: Some("#username".to_string()),
                password: Some("#password".to_string()),
                submit: None,
            },
            ManifestAuthentication {
                success_selector: "#ready".to_string(),
                subject_selector: None,
            },
            ManifestDetection {
                captcha_mode: "slider".to_string(),
                username_label: "Username".to_string(),
                password_label: "Password".to_string(),
                submit_label: None,
            },
            true,
        )
        .is_ok());
    }

    #[test]
    fn detection_is_concrete_bounded_and_adapter_specific() {
        let mut value = manifest();
        value.captcha_adapter = LegacyCaptchaAdapter::Auto;
        assert_eq!(
            value.validate(),
            Err(ManifestValidationError::AutoCaptchaAdapterNotPersistable)
        );

        let mut value = manifest();
        value.detection.captcha_mode = "slider".to_string();
        assert_eq!(
            value.validate(),
            Err(ManifestValidationError::CaptchaModeMismatch)
        );

        for invalid in [String::new(), " ".to_string(), "x".repeat(161)] {
            let mut value = manifest();
            value.detection.username_label = invalid;
            assert!(matches!(
                value.validate(),
                Err(ManifestValidationError::InvalidDetectionValue { .. })
            ));
        }
    }

    #[test]
    fn discovery_profile_converts_without_duplicating_selectors() {
        let profile = DiscoveryProfile {
            captcha_adapter: obscura_browser::CaptchaAdapter::AjCaptcha,
            captcha_mode: "block_puzzle".to_string(),
            login: DiscoveredLogin {
                username_label: "账号".to_string(),
                password_label: "密码".to_string(),
                submit_label: Some("登录".to_string()),
                username_selector: Some("[id=account]".to_string()),
                password_selector: Some("[id=password]".to_string()),
                submit_selector: Some("button[type=submit]".to_string()),
            },
        };
        let manifest = LegacyGatewayManifest::from_discovery_profile(
            "https://legacy.example/login",
            &profile,
            ManifestAuthentication {
                success_selector: "#ready".to_string(),
                subject_selector: Some("#subject".to_string()),
            },
            false,
        )
        .unwrap();
        assert_eq!(manifest.expected_discovery_profile().unwrap(), profile);

        let mut changed_selectors = manifest;
        changed_selectors.selectors.username = Some("[name=user]".to_string());
        assert_eq!(
            changed_selectors
                .expected_discovery_profile()
                .unwrap()
                .login
                .username_selector
                .as_deref(),
            Some("[name=user]")
        );
    }

    #[test]
    fn origins_must_be_complete_exact_and_canonical() {
        for origin in [
            "https://legacy.example/",
            "https://legacy.example/path",
            "https://LEGACY.example",
            "https://legacy.example:443",
            "https://user@legacy.example",
            "https://legacy.example#fragment",
        ] {
            let mut value = manifest();
            value.origins.navigation = BTreeSet::from([origin.to_string()]);
            assert!(value.validate().is_err(), "{origin}");
        }

        let mut missing_navigation = manifest();
        missing_navigation.origins.navigation = BTreeSet::from(["https://sso.example".to_string()]);
        assert_eq!(
            missing_navigation.validate(),
            Err(ManifestValidationError::LoginOriginNotAllowedForNavigation)
        );

        let mut missing_resource = manifest();
        missing_resource.origins.resources = BTreeSet::from(["https://static.example".to_string()]);
        assert_eq!(
            missing_resource.validate(),
            Err(ManifestValidationError::LoginOriginNotAllowedForResources)
        );
    }

    #[test]
    fn duplicate_origins_are_rejected_in_json() {
        let json = manifest().to_json_pretty().unwrap();
        let json = json.replace(
            r#""navigation": ["#,
            r#""navigation": [
      "https://legacy.example","#,
        );
        assert!(LegacyGatewayManifest::from_json_str(&json).is_err());
    }

    #[test]
    fn selector_viewport_ttl_and_user_agent_bounds_are_enforced() {
        let mut value = manifest();
        value.authentication.success_selector = " ".to_string();
        assert!(matches!(
            value.validate(),
            Err(ManifestValidationError::InvalidSelector { .. })
        ));

        let mut value = manifest();
        value.selectors.username = Some("x".repeat(MAX_SELECTOR_BYTES + 1));
        assert!(matches!(
            value.validate(),
            Err(ManifestValidationError::InvalidSelector { .. })
        ));

        let mut value = manifest();
        value.viewport.width = MIN_VIEWPORT_WIDTH - 1;
        assert_eq!(
            value.validate(),
            Err(ManifestValidationError::InvalidViewport)
        );

        let mut value = manifest();
        value.session_ttl_seconds = MIN_SESSION_TTL_SECONDS - 1;
        assert_eq!(
            value.validate(),
            Err(ManifestValidationError::InvalidSessionTtl)
        );

        let mut value = manifest();
        value.user_agent = Some("Legacy\r\nInjected: value".to_string());
        assert_eq!(
            value.validate(),
            Err(ManifestValidationError::InvalidUserAgent)
        );
    }

    #[test]
    fn invalid_public_values_cannot_be_serialized() {
        let mut value = manifest();
        value.authentication.success_selector.clear();
        assert!(serde_json::to_string(&value).is_err());
    }

    #[test]
    fn persisted_selectors_cannot_fall_back_to_auto_detection() {
        let mut value = manifest();
        value.selectors.username = None;
        assert_eq!(
            value.validate(),
            Err(ManifestValidationError::MissingRequiredLoginSelector {
                field: "selectors.username",
            })
        );

        let mut value = manifest();
        value.selectors.password = None;
        assert_eq!(
            value.validate(),
            Err(ManifestValidationError::MissingRequiredLoginSelector {
                field: "selectors.password",
            })
        );

        let mut value = manifest();
        value.selectors.submit = None;
        assert_eq!(
            value.validate(),
            Err(ManifestValidationError::MissingSubmitSelector)
        );

        let mut no_submit = manifest();
        no_submit.detection.submit_label = None;
        no_submit.selectors.submit = None;
        assert!(no_submit.validate().is_ok());
    }

    #[test]
    fn atomic_write_is_round_trippable_and_never_overwrites() {
        let directory = std::env::temp_dir().join(format!(
            "obscura-legacy-manifest-test-{}",
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("legacy.json");

        let first = manifest();
        first.write_atomic_new(&path).unwrap();
        assert_eq!(LegacyGatewayManifest::read(&path).unwrap(), first);

        let mut second = manifest();
        second.authentication.success_selector = "#different".to_string();
        assert!(matches!(
            second.write_atomic_new(&path),
            Err(ManifestError::DestinationExists)
        ));
        assert_eq!(LegacyGatewayManifest::read(&path).unwrap(), first);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);

        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn oversized_input_is_rejected_before_json_parsing() {
        let input = vec![b' '; MAX_LEGACY_GATEWAY_MANIFEST_BYTES + 1];
        assert!(matches!(
            LegacyGatewayManifest::from_json_slice(&input),
            Err(ManifestError::ManifestTooLarge)
        ));
    }
}
