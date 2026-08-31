use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use thiserror::Error;
use url::Url;

const MIN_BODY_BYTES: usize = 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MIN_HEADER_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Viewport {
    pub width: u32,
    pub height: u32,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
        }
    }
}

/// Configuration for exactly one legacy origin and one in-memory browser
/// session. There is intentionally no request parameter which can replace
/// `legacy_url` at runtime.
#[derive(Clone, Debug)]
pub struct GatewayConfig {
    pub legacy_url: Url,
    pub bind_addr: SocketAddr,
    pub allowed_navigation_origins: BTreeSet<String>,
    /// Exact origins which any document, redirect hop, script, stylesheet,
    /// image, font, or fetch/XHR request may contact. This is separate from
    /// the broad private-network transport opt-in.
    pub allowed_resource_origins: BTreeSet<String>,
    pub allow_insecure_legacy_http: bool,
    pub viewport: Viewport,
    pub request_body_limit: usize,
    pub request_header_limit: usize,
    pub max_connections: usize,
    pub session_ttl: Duration,
    pub connection_timeout: Duration,
}

impl GatewayConfig {
    pub fn new(legacy_url: Url) -> Self {
        let mut allowed_navigation_origins = BTreeSet::new();
        let mut allowed_resource_origins = BTreeSet::new();
        if let Ok(origin) = canonical_origin(&legacy_url) {
            allowed_navigation_origins.insert(origin.clone());
            allowed_resource_origins.insert(origin);
        }
        Self {
            legacy_url,
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            allowed_navigation_origins,
            allowed_resource_origins,
            allow_insecure_legacy_http: false,
            viewport: Viewport::default(),
            // A bounded raw pointer gesture can contain up to 512 samples.
            // Keep the default large enough for that JSON envelope while the
            // hard maximum remains 64 KiB.
            request_body_limit: 64 * 1024,
            request_header_limit: 16 * 1024,
            max_connections: 32,
            session_ttl: Duration::from_secs(30 * 60),
            connection_timeout: Duration::from_secs(30),
        }
    }

    pub fn allow_navigation_origin(&mut self, url: &Url) -> Result<(), GatewayConfigError> {
        self.allowed_navigation_origins
            .insert(canonical_origin(url)?);
        Ok(())
    }

    pub fn allow_resource_origin(&mut self, url: &Url) -> Result<(), GatewayConfigError> {
        self.allowed_resource_origins.insert(canonical_origin(url)?);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), GatewayConfigError> {
        validate_legacy_url(&self.legacy_url, self.allow_insecure_legacy_http)?;
        if !self.bind_addr.ip().is_loopback() {
            return Err(GatewayConfigError::NonLoopbackBind);
        }
        if self.allowed_navigation_origins.is_empty() {
            return Err(GatewayConfigError::MissingAllowedOrigin);
        }
        if self.allowed_resource_origins.is_empty() {
            return Err(GatewayConfigError::MissingAllowedResourceOrigin);
        }
        let startup_origin = canonical_origin(&self.legacy_url)?;
        if !self.allowed_navigation_origins.contains(&startup_origin) {
            return Err(GatewayConfigError::StartupOriginNotAllowed);
        }
        for origin in &self.allowed_navigation_origins {
            let parsed =
                Url::parse(origin).map_err(|_| GatewayConfigError::InvalidAllowedOrigin)?;
            if canonical_origin(&parsed).as_deref() != Ok(origin.as_str()) {
                return Err(GatewayConfigError::InvalidAllowedOrigin);
            }
            validate_origin_scheme(&parsed, self.allow_insecure_legacy_http)?;
        }
        for origin in &self.allowed_resource_origins {
            let parsed =
                Url::parse(origin).map_err(|_| GatewayConfigError::InvalidAllowedOrigin)?;
            if canonical_origin(&parsed).as_deref() != Ok(origin.as_str()) {
                return Err(GatewayConfigError::InvalidAllowedOrigin);
            }
            validate_origin_scheme(&parsed, self.allow_insecure_legacy_http)?;
        }
        if !(320..=4096).contains(&self.viewport.width)
            || !(240..=2160).contains(&self.viewport.height)
        {
            return Err(GatewayConfigError::InvalidViewport);
        }
        if !(MIN_BODY_BYTES..=MAX_BODY_BYTES).contains(&self.request_body_limit) {
            return Err(GatewayConfigError::InvalidBodyLimit);
        }
        if !(MIN_HEADER_BYTES..=MAX_HEADER_BYTES).contains(&self.request_header_limit) {
            return Err(GatewayConfigError::InvalidHeaderLimit);
        }
        if !(1..=256).contains(&self.max_connections) {
            return Err(GatewayConfigError::InvalidConnectionLimit);
        }
        if self.session_ttl < Duration::from_secs(60)
            || self.session_ttl > Duration::from_secs(24 * 60 * 60)
        {
            return Err(GatewayConfigError::InvalidSessionTtl);
        }
        if self.connection_timeout < Duration::from_secs(1)
            || self.connection_timeout > Duration::from_secs(5 * 60)
        {
            return Err(GatewayConfigError::InvalidConnectionTimeout);
        }
        Ok(())
    }

    pub(crate) fn navigation_is_allowed(&self, url: &Url) -> bool {
        canonical_origin(url)
            .ok()
            .is_some_and(|origin| self.allowed_navigation_origins.contains(&origin))
    }
}

fn validate_legacy_url(url: &Url, allow_http: bool) -> Result<(), GatewayConfigError> {
    validate_origin_scheme(url, allow_http)?;
    if url.host_str().is_none() {
        return Err(GatewayConfigError::MissingLegacyHost);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(GatewayConfigError::LegacyUrlCredentials);
    }
    if url.fragment().is_some() {
        return Err(GatewayConfigError::LegacyUrlFragment);
    }
    Ok(())
}

fn validate_origin_scheme(url: &Url, allow_http: bool) -> Result<(), GatewayConfigError> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_http => Ok(()),
        "http" => Err(GatewayConfigError::InsecureLegacyUrl),
        _ => Err(GatewayConfigError::UnsupportedLegacyScheme),
    }
}

pub(crate) fn canonical_origin(url: &Url) -> Result<String, GatewayConfigError> {
    let host = url
        .host_str()
        .ok_or(GatewayConfigError::MissingLegacyHost)?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(GatewayConfigError::UnsupportedLegacyScheme);
    }
    let default_port = if scheme == "https" { 443 } else { 80 };
    let port = url
        .port_or_known_default()
        .ok_or(GatewayConfigError::MissingLegacyHost)?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_ascii_lowercase()
    };
    if port == default_port {
        Ok(format!("{scheme}://{host}"))
    } else {
        Ok(format!("{scheme}://{host}:{port}"))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GatewayConfigError {
    #[error("the gateway only binds to a loopback address")]
    NonLoopbackBind,
    #[error("the legacy URL must use HTTPS unless insecure HTTP is explicitly enabled")]
    InsecureLegacyUrl,
    #[error("the legacy URL must use HTTP or HTTPS")]
    UnsupportedLegacyScheme,
    #[error("the legacy URL must include a host")]
    MissingLegacyHost,
    #[error("credentials are not permitted in the legacy URL")]
    LegacyUrlCredentials,
    #[error("a fragment is not permitted in the legacy URL")]
    LegacyUrlFragment,
    #[error("at least one exact navigation origin is required")]
    MissingAllowedOrigin,
    #[error("at least one exact resource origin is required")]
    MissingAllowedResourceOrigin,
    #[error("the configured startup origin must be allowed")]
    StartupOriginNotAllowed,
    #[error("an allowed navigation origin is not canonical")]
    InvalidAllowedOrigin,
    #[error("viewport must be between 320x240 and 4096x2160")]
    InvalidViewport,
    #[error("request body limit must be between 1 KiB and 64 KiB")]
    InvalidBodyLimit,
    #[error("request header limit must be between 8 KiB and 64 KiB")]
    InvalidHeaderLimit,
    #[error("connection limit must be between 1 and 256")]
    InvalidConnectionLimit,
    #[error("session TTL must be between one minute and one day")]
    InvalidSessionTtl,
    #[error("connection timeout must be between one second and five minutes")]
    InvalidConnectionTimeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_loopback_and_https_only() {
        let config = GatewayConfig::new(Url::parse("https://legacy.example/login").unwrap());
        assert!(config.bind_addr.ip().is_loopback());
        assert_eq!(config.bind_addr.port(), 0);
        assert!(config.validate().is_ok());
        assert_eq!(
            config.allowed_resource_origins,
            BTreeSet::from(["https://legacy.example".to_string()])
        );

        let insecure = GatewayConfig::new(Url::parse("http://legacy.example/login").unwrap());
        assert_eq!(
            insecure.validate(),
            Err(GatewayConfigError::InsecureLegacyUrl)
        );
    }

    #[test]
    fn canonical_origin_is_exact_and_drops_paths() {
        assert_eq!(
            canonical_origin(&Url::parse("https://EXAMPLE.com:443/a?q=1").unwrap()).unwrap(),
            "https://example.com"
        );
        assert_eq!(
            canonical_origin(&Url::parse("https://example.com:8443/a").unwrap()).unwrap(),
            "https://example.com:8443"
        );
    }

    #[test]
    fn embedded_credentials_and_non_loopback_bind_are_rejected() {
        let credentials =
            GatewayConfig::new(Url::parse("https://user:secret@legacy.example/login").unwrap());
        assert_eq!(
            credentials.validate(),
            Err(GatewayConfigError::LegacyUrlCredentials)
        );

        let mut public = GatewayConfig::new(Url::parse("https://legacy.example/login").unwrap());
        public.bind_addr = "0.0.0.0:9080".parse().unwrap();
        assert_eq!(public.validate(), Err(GatewayConfigError::NonLoopbackBind));
    }
}
