use std::collections::BTreeSet;

use obscura_browser::Page;
use obscura_net::interceptor::{InterceptAction, RequestInterceptor};
use obscura_net::{RequestInfo, ResourceType};
use url::Url;

use crate::config::canonical_origin;

/// Exact-origin network policy installed on the isolated Obscura HTTP client.
/// Obscura-net invokes the interceptor before every request and again for every
/// redirect hop, so an allowed legacy origin cannot redirect into another
/// private host. Paths, host suffixes, and globs are intentionally unsupported.
pub struct ExactResourceOriginPolicy {
    navigation_origins: BTreeSet<String>,
    resource_origins: BTreeSet<String>,
}

impl ExactResourceOriginPolicy {
    pub fn new(
        navigation_origins: BTreeSet<String>,
        resource_origins: BTreeSet<String>,
    ) -> Result<Self, String> {
        if navigation_origins.is_empty() || resource_origins.is_empty() {
            return Err("the exact resource-origin allowlist is empty".to_string());
        }
        for origin in navigation_origins.iter().chain(&resource_origins) {
            let url = Url::parse(origin)
                .map_err(|_| "the resource-origin allowlist is invalid".to_string())?;
            if canonical_origin(&url).as_deref() != Ok(origin.as_str()) {
                return Err("the resource-origin allowlist is not canonical".to_string());
            }
        }
        Ok(Self {
            navigation_origins,
            resource_origins,
        })
    }

    pub fn allows_resource(&self, url: &Url) -> bool {
        canonical_origin(url)
            .ok()
            .is_some_and(|origin| self.resource_origins.contains(&origin))
    }

    pub fn allows_request(&self, request: &RequestInfo) -> bool {
        let origins = if request.resource_type == ResourceType::Document && request.frame_id == 0 {
            &self.navigation_origins
        } else {
            // Child-frame documents are deliberately treated as embedded
            // resources. If they attempt to replace the top page, the new
            // frame-zero Document request is checked against the stricter
            // navigation set.
            &self.resource_origins
        };
        canonical_origin(&request.url)
            .ok()
            .is_some_and(|origin| origins.contains(&origin))
    }
}

#[async_trait::async_trait]
impl RequestInterceptor for ExactResourceOriginPolicy {
    async fn intercept(&self, request: &RequestInfo) -> InterceptAction {
        if self.allows_request(request) {
            InterceptAction::Continue
        } else {
            InterceptAction::Block
        }
    }
}

/// Install the policy before the first navigation. A fresh page/context has no
/// concurrent HTTP-client users, so failure to acquire the write slot is a
/// configuration error rather than a reason to continue without isolation.
pub fn install_exact_resource_origin_policy(
    page: &Page,
    navigation_origins: BTreeSet<String>,
    resource_origins: BTreeSet<String>,
) -> Result<(), String> {
    if page.context.stealth {
        return Err(
            "legacy gateway resource isolation is unavailable for the stealth transport"
                .to_string(),
        );
    }
    let policy = ExactResourceOriginPolicy::new(navigation_origins, resource_origins)?;
    let mut slot =
        page.http_client.interceptor.try_write().map_err(|_| {
            "legacy resource policy must be installed before navigation".to_string()
        })?;
    if slot.is_some() {
        return Err("legacy resource policy cannot replace an existing interceptor".to_string());
    }
    *slot = Some(Box::new(policy));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str, resource_type: ResourceType, frame_id: u32) -> RequestInfo {
        RequestInfo {
            url: Url::parse(url).unwrap(),
            method: "GET".to_string(),
            headers: std::collections::HashMap::new(),
            resource_type,
            document_generation: 1,
            frame_id,
            initiator: None,
        }
    }

    #[test]
    fn exact_origin_allows_paths_but_not_suffixes_ports_or_other_schemes() {
        let policy = ExactResourceOriginPolicy::new(
            BTreeSet::from(["https://legacy.example".to_string()]),
            BTreeSet::from([
                "https://legacy.example".to_string(),
                "https://static.example:8443".to_string(),
            ]),
        )
        .unwrap();
        assert!(policy.allows_resource(&Url::parse("https://legacy.example/a/b?q=1").unwrap()));
        assert!(policy.allows_resource(&Url::parse("https://static.example:8443/app.js").unwrap()));
        assert!(!policy.allows_resource(&Url::parse("https://legacy.example.evil/a").unwrap()));
        assert!(!policy.allows_resource(&Url::parse("https://legacy.example:8443/a").unwrap()));
        assert!(!policy.allows_resource(&Url::parse("http://legacy.example/a").unwrap()));
        assert!(!policy
            .allows_resource(&Url::parse("http://169.254.169.254/latest/meta-data").unwrap()));
    }

    #[test]
    fn policy_rejects_noncanonical_or_empty_configuration() {
        assert!(ExactResourceOriginPolicy::new(BTreeSet::new(), BTreeSet::new()).is_err());
        assert!(ExactResourceOriginPolicy::new(
            BTreeSet::from(["https://legacy.example".to_string()]),
            BTreeSet::from(["https://legacy.example/path".to_string()])
        )
        .is_err());
    }

    #[test]
    fn resource_only_origin_cannot_become_the_top_level_document() {
        let policy = ExactResourceOriginPolicy::new(
            BTreeSet::from(["https://legacy.example".to_string()]),
            BTreeSet::from([
                "https://legacy.example".to_string(),
                "https://cdn.example".to_string(),
            ]),
        )
        .unwrap();

        assert!(policy.allows_request(&request(
            "https://cdn.example/app.js",
            ResourceType::Script,
            0,
        )));
        assert!(policy.allows_request(&request(
            "https://cdn.example/embedded",
            ResourceType::Document,
            7,
        )));
        assert!(!policy.allows_request(&request(
            "https://cdn.example/replaced-top",
            ResourceType::Document,
            0,
        )));
    }
}
