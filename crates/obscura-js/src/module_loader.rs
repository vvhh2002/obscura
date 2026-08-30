use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::sync::Arc;

use deno_core::error::ModuleLoaderError;
use deno_core::futures::future::{FutureExt, LocalBoxFuture, Shared};
use deno_core::ModuleLoadResponse;
use deno_core::ModuleLoader;
use deno_core::ModuleSource;
use deno_core::ModuleSourceCode;
use deno_core::ModuleSpecifier;
use deno_core::RequestedModuleType;

use crate::import_map::ImportMap;
use crate::ops::ObscuraState;

#[derive(Clone)]
struct CachedModuleSource {
    code: String,
    found: ModuleSpecifier,
}

type CachedModuleResult = Result<Rc<CachedModuleSource>, Rc<String>>;
type SharedModuleLoad = Shared<LocalBoxFuture<'static, CachedModuleResult>>;

/// Observable load and evaluation activity for ES-module graphs.
///
/// deno_core keeps dynamic-import state inside its private module map. The
/// browser lifecycle still needs to distinguish a genuinely idle page from a
/// graph whose fetch future is being advanced in short event-loop slices. A
/// loader-owned counter provides that signal without treating unrelated
/// fetch/XHR analytics as render-blocking work. Frame realms also hold this
/// counter across module evaluation, so top-level await and cancellation are
/// visible at the browser capture boundary.
#[derive(Debug, Default)]
pub(crate) struct ModuleLoadActivity {
    pending: std::sync::atomic::AtomicUsize,
    last_activity: std::sync::Mutex<Option<std::time::Instant>>,
}

impl ModuleLoadActivity {
    pub(crate) fn begin(self: &Arc<Self>) -> ModuleLoadGuard {
        self.pending
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *self
            .last_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(std::time::Instant::now());
        ModuleLoadGuard(self.clone())
    }

    pub(crate) fn is_pending_or_recent(&self, grace: std::time::Duration) -> bool {
        if self.pending.load(std::sync::atomic::Ordering::Relaxed) != 0 {
            return true;
        }
        self.last_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some_and(|last| last.elapsed() <= grace)
    }
}

pub(crate) struct ModuleLoadGuard(Arc<ModuleLoadActivity>);

impl Drop for ModuleLoadGuard {
    fn drop(&mut self) {
        let previous = self
            .0
            .pending
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        debug_assert!(previous > 0, "module load activity counter underflow");
        *self
            .0
            .last_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(std::time::Instant::now());
    }
}

pub struct ObscuraModuleLoader {
    pub base_url: String,
    /// Proxy URL threaded through to every dynamic ES-module fetch (#139).
    /// `None` keeps the pre-#139 direct-connection behaviour for callers
    /// that haven't been updated.
    pub proxy_url: Option<String>,
    /// The owning page's network context. Production runtimes always install
    /// this so every module in a graph uses the same cookie jar, configured
    /// identity, redirect/security policy, interception, and callbacks as the
    /// entry module. Directly-constructed standalone loaders remain supported.
    page_state: Option<Weak<RefCell<ObscuraState>>>,
    /// Directly-constructed loaders still use Obscura's network policy and
    /// connection pool; they simply have an isolated cookie jar.
    standalone_client: Option<Arc<obscura_net::ObscuraHttpClient>>,
    import_map: Rc<RefCell<ImportMap>>,
    /// Import-map snapshot selected when each static graph starts. The map is
    /// propagated from a referrer to every resolved child, so a map inserted
    /// while network fetches are in flight cannot rewrite that graph. Dynamic
    /// import deliberately consults the document's current resolved-module
    /// map instead.
    graph_import_maps: Rc<RefCell<HashMap<String, Rc<RefCell<ImportMap>>>>>,
    /// Browser module maps cache source fetch results. deno_core already
    /// deduplicates registered modules; these two stores additionally prevent
    /// concurrent graph preparations from issuing duplicate HTTP requests
    /// before either result has reached the realm's ModuleMap.
    completed_sources: Rc<RefCell<HashMap<String, CachedModuleResult>>>,
    in_flight_sources: Rc<RefCell<HashMap<String, SharedModuleLoad>>>,
    activity: Arc<ModuleLoadActivity>,
}

impl ObscuraModuleLoader {
    pub fn new(base_url: &str) -> Self {
        Self::with_proxy(base_url, None)
    }

    pub fn with_proxy(base_url: &str, proxy_url: Option<String>) -> Self {
        let import_map = Rc::new(RefCell::new(ImportMap::default()));
        Self::with_proxy_and_import_map(base_url, proxy_url, import_map)
    }

    fn with_proxy_and_import_map(
        base_url: &str,
        proxy_url: Option<String>,
        import_map: Rc<RefCell<ImportMap>>,
    ) -> Self {
        let standalone_client = Arc::new(obscura_net::ObscuraHttpClient::with_options(
            Arc::new(obscura_net::CookieJar::new()),
            proxy_url.as_deref(),
        ));
        ObscuraModuleLoader {
            base_url: base_url.to_string(),
            proxy_url,
            page_state: None,
            standalone_client: Some(standalone_client),
            import_map,
            graph_import_maps: Rc::new(RefCell::new(HashMap::new())),
            completed_sources: Rc::new(RefCell::new(HashMap::new())),
            in_flight_sources: Rc::new(RefCell::new(HashMap::new())),
            activity: Arc::new(ModuleLoadActivity::default()),
        }
    }

    pub(crate) fn with_page_state(
        base_url: &str,
        proxy_url: Option<String>,
        page_state: &Rc<RefCell<ObscuraState>>,
        import_map: Rc<RefCell<ImportMap>>,
    ) -> Self {
        ObscuraModuleLoader {
            base_url: base_url.to_string(),
            proxy_url,
            page_state: Some(Rc::downgrade(page_state)),
            standalone_client: None,
            import_map,
            graph_import_maps: Rc::new(RefCell::new(HashMap::new())),
            completed_sources: Rc::new(RefCell::new(HashMap::new())),
            in_flight_sources: Rc::new(RefCell::new(HashMap::new())),
            activity: Arc::new(ModuleLoadActivity::default()),
        }
    }

    pub(crate) fn activity(&self) -> Arc<ModuleLoadActivity> {
        self.activity.clone()
    }
}

fn io_err(msg: String) -> ModuleLoaderError {
    std::io::Error::new(std::io::ErrorKind::Other, msg).into()
}

impl ModuleLoader for ObscuraModuleLoader {
    fn resolve(
        &self,
        specifier: &str,
        referrer: &str,
        kind: deno_core::ResolutionKind,
    ) -> Result<ModuleSpecifier, ModuleLoaderError> {
        // deno_core represents the root passed to load_side_es_module with a
        // synthetic "." referrer. A browser resolves <script type=module src>
        // as a resource URL before it starts a graph; the document import map
        // must not remap that root URL.
        if referrer == "." {
            return deno_core::resolve_import(specifier, &self.base_url)
                .map_err(|error| error.into());
        }

        let base = if referrer.is_empty() || referrer.starts_with('<') || referrer == "about:blank"
        {
            &self.base_url
        } else {
            referrer
        };

        let base = ModuleSpecifier::parse(base)
            .map_err(|e| io_err(format!("Invalid module referrer {}: {}", base, e)))?;
        let graph_map = if kind == deno_core::ResolutionKind::Import {
            self.graph_import_maps
                .try_borrow()
                .map_err(|_| io_err("Module graph map is already borrowed".to_string()))?
                .get(base.as_str())
                .cloned()
        } else {
            None
        };
        let resolved = match graph_map.as_ref() {
            Some(snapshot) => self
                .import_map
                .try_borrow_mut()
                .map_err(|_| io_err("Import map is already borrowed".to_string()))?
                .resolve_from_snapshot(
                    &mut *snapshot
                        .try_borrow_mut()
                        .map_err(|_| io_err("Graph import map is already borrowed".to_string()))?,
                    specifier,
                    &base,
                ),
            None => self
                .import_map
                .try_borrow_mut()
                .map_err(|_| io_err("Import map is already borrowed".to_string()))?
                .resolve(specifier, &base),
        }
        .map_err(io_err)?;

        if let Some(snapshot) = graph_map {
            self.graph_import_maps
                .try_borrow_mut()
                .map_err(|_| io_err("Module graph map is already borrowed".to_string()))?
                .entry(resolved.to_string())
                .or_insert(snapshot);
        }
        Ok(resolved)
    }

    fn prepare_load(
        &self,
        module_specifier: &ModuleSpecifier,
        _maybe_referrer: Option<String>,
        is_dyn_import: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(), ModuleLoaderError>>>> {
        if !is_dyn_import {
            let snapshot = match self.import_map.try_borrow() {
                Ok(import_map) => import_map.clone(),
                Err(_) => {
                    return async { Err(io_err("Import map is already borrowed".to_string())) }
                        .boxed_local();
                }
            };
            match self.graph_import_maps.try_borrow_mut() {
                Ok(mut graphs) => {
                    // The unregistered explicit-root API deliberately permits
                    // multiple inline modules to share the document URL. Each
                    // call is nevertheless a new graph start and must freeze
                    // the import map visible at that parser position. Keeping
                    // the first snapshot with `or_insert` made every later
                    // inline graph at the same URL inherit an obsolete map.
                    // Replacing the root snapshot here is safe: deno_core calls
                    // prepare_load at a graph boundary before resolving that
                    // graph's edges, while resolved child entries below retain
                    // the snapshot propagated for their active graph.
                    graphs.insert(
                        module_specifier.to_string(),
                        Rc::new(RefCell::new(snapshot)),
                    );
                }
                Err(_) => {
                    return async {
                        Err(io_err("Module graph map is already borrowed".to_string()))
                    }
                    .boxed_local();
                }
            }
        }
        async { Ok(()) }.boxed_local()
    }

    fn load(
        &self,
        module_specifier: &ModuleSpecifier,
        maybe_referrer: Option<&ModuleSpecifier>,
        _is_dyn_import: bool,
        _requested_module_type: RequestedModuleType,
    ) -> ModuleLoadResponse {
        let url = module_specifier.to_string();
        // Module-graph CORS and same-origin credentials are relative to the
        // owning document, not to the importing module. The importer remains
        // the HTTP referrer for a dependency; keeping these URLs distinct
        // prevents a cross-origin parent module from gaining CDN cookies when
        // it imports a sibling on that CDN.
        let document_url =
            ModuleSpecifier::parse(&self.base_url).unwrap_or_else(|_| module_specifier.clone());
        let referrer = maybe_referrer
            .cloned()
            .unwrap_or_else(|| document_url.clone());
        // Capture the loader's proxy here so the async closure below owns a
        // plain Option<String> rather than borrowing &self across an `await`.
        let proxy_url = self.proxy_url.clone();
        let activity = self.activity.clone();
        let completed_sources = self.completed_sources.clone();
        let in_flight_sources = self.in_flight_sources.clone();
        let graph_import_maps = self.graph_import_maps.clone();
        let referrer_graph = graph_import_maps.borrow().get(referrer.as_str()).cloned();
        if let Some(referrer_graph) = referrer_graph {
            graph_import_maps
                .borrow_mut()
                .entry(url.clone())
                .or_insert(referrer_graph);
        }
        let page_network = match self.page_state.as_ref() {
            Some(weak) => (|| {
                let state = weak
                    .upgrade()
                    .ok_or_else(|| "Module loader page state was dropped".to_string())?;
                let state = state
                    .try_borrow()
                    .map_err(|_| "Module loader page state is already borrowed".to_string())?;
                let client = state
                    .http_client
                    .clone()
                    .ok_or_else(|| "No http_client wired to module loader".to_string())?;
                // Fork: in stealth mode an ES module must be fetched over the
                // same transport as the document. Upstream sends it through the
                // plain reqwest client, so a `type="module"` script arrives with
                // a different TLS fingerprint and none of the browser identity
                // headers, while the HTML that referenced it came over wreq.
                // That cross-transport mismatch is trivially detectable.
                #[cfg(feature = "stealth")]
                let stealth = state.stealth_client.clone();
                #[cfg(not(feature = "stealth"))]
                let stealth: Option<std::sync::Arc<()>> = None;
                Ok((client, stealth, state.callbacks.clone(), state.frame_id))
            })(),
            None => self
                .standalone_client
                .clone()
                .map(|client| {
                    #[cfg(feature = "stealth")]
                    let stealth = None;
                    #[cfg(not(feature = "stealth"))]
                    let stealth: Option<std::sync::Arc<()>> = None;
                    (client, stealth, None, 0)
                })
                .ok_or_else(|| "No network context wired to module loader".to_string()),
        };

        let cached = completed_sources.borrow().get(&url).cloned();
        let shared = cached
            .map(|cached| async move { cached }.boxed_local().shared())
            .or_else(|| in_flight_sources.borrow().get(&url).cloned());
        let shared = shared.unwrap_or_else(|| {
            // Register before returning the future. The lifecycle can inspect
            // the runtime between deno_core accepting the load and first
            // polling it. Cancellation decrements through the guard's Drop.
            let activity_guard = activity.begin();
            let requested_url = url.clone();
            let fetch = async move {
                let _activity_guard = activity_guard;
                tracing::debug!(
                    "Loading ES module: {} (proxy: {})",
                    requested_url,
                    proxy_url.as_deref().unwrap_or("direct")
                );

                match page_network {
                    Ok((client, stealth, callbacks, frame_id)) => {
                        let requested = ModuleSpecifier::parse(&requested_url).map_err(|e| {
                            Rc::new(format!("Invalid module URL {}: {}", requested_url, e))
                        })?;
                        let request =
                            obscura_net::ResourceRequest::module_script(&document_url, &referrer)
                                .in_frame(frame_id);
                        #[cfg(feature = "stealth")]
                        let resp = match stealth {
                            Some(stealth) => {
                                stealth
                                    .fetch_resource_with_callbacks(
                                        &requested,
                                        request,
                                        callbacks.as_deref(),
                                    )
                                    .await
                            }
                            None => {
                                client
                                    .fetch_resource_with_callbacks(
                                        &requested,
                                        request,
                                        callbacks.as_deref(),
                                    )
                                    .await
                            }
                        }
                        .map_err(|e| {
                            Rc::new(format!("Failed to fetch module {}: {}", requested_url, e))
                        })?;
                        #[cfg(not(feature = "stealth"))]
                        let resp = {
                            let _ = &stealth;
                            client
                                .fetch_resource_with_callbacks(
                                    &requested,
                                    request,
                                    callbacks.as_deref(),
                                )
                                .await
                                .map_err(|e| {
                                    Rc::new(format!(
                                        "Failed to fetch module {}: {}",
                                        requested_url, e
                                    ))
                                })?
                        };
                        if !(200..=299).contains(&resp.status) {
                            return Err(Rc::new(format!(
                                "Module {} returned HTTP {}",
                                requested_url, resp.status
                            )));
                        }
                        let found = ModuleSpecifier::parse(resp.url.as_str()).map_err(|e| {
                            Rc::new(format!("Invalid final module URL {}: {}", resp.url, e))
                        })?;
                        if found.as_str() != requested.as_str() {
                            let snapshot =
                                graph_import_maps.borrow().get(requested.as_str()).cloned();
                            if let Some(snapshot) = snapshot {
                                graph_import_maps
                                    .borrow_mut()
                                    .entry(found.to_string())
                                    .or_insert(snapshot);
                            }
                        }
                        let code = obscura_net::decode_non_html(&resp.body, resp.content_type());
                        Ok(Rc::new(CachedModuleSource { code, found }))
                    }
                    Err(error) => Err(Rc::new(error)),
                }
            }
            .boxed_local()
            .shared();
            in_flight_sources
                .borrow_mut()
                .insert(url.clone(), fetch.clone());
            fetch
        });

        ModuleLoadResponse::Async(Pin::from(Box::new(async move {
            let result = shared.await;
            in_flight_sources.borrow_mut().remove(&url);
            completed_sources
                .borrow_mut()
                .entry(url.clone())
                .or_insert_with(|| result.clone());
            match result {
                Ok(cached) => {
                    completed_sources
                        .borrow_mut()
                        .entry(cached.found.to_string())
                        .or_insert_with(|| Ok(cached.clone()));
                    let requested = ModuleSpecifier::parse(&url)
                        .map_err(|error| io_err(format!("Invalid module URL {url}: {error}")))?;
                    Ok(ModuleSource::new_with_redirect(
                        deno_core::ModuleType::JavaScript,
                        ModuleSourceCode::String(cached.code.clone().into()),
                        &requested,
                        &cached.found,
                        None,
                    ))
                }
                Err(error) => Err(io_err((*error).clone())),
            }
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn static_graph_uses_start_snapshot_while_later_graph_and_dynamic_import_use_new_map() {
        let loader = ObscuraModuleLoader::new("https://example.test/page.html");
        let slow_root = ModuleSpecifier::parse("https://example.test/slow.js").unwrap();
        loader.prepare_load(&slow_root, None, false).await.unwrap();

        loader.import_map.borrow_mut().merge(
            ImportMap::parse(
                r#"{"imports":{"late":"/late.js","dynamic":"/dynamic.js"}}"#,
                "https://example.test/page.html",
            )
            .unwrap(),
        );
        assert!(loader
            .resolve(
                "late",
                slow_root.as_str(),
                deno_core::ResolutionKind::Import
            )
            .is_err());
        assert_eq!(
            loader
                .resolve(
                    "dynamic",
                    slow_root.as_str(),
                    deno_core::ResolutionKind::DynamicImport,
                )
                .unwrap()
                .as_str(),
            "https://example.test/dynamic.js",
        );

        let later_root = ModuleSpecifier::parse("https://example.test/later-root.js").unwrap();
        loader.prepare_load(&later_root, None, false).await.unwrap();
        assert_eq!(
            loader
                .resolve(
                    "late",
                    later_root.as_str(),
                    deno_core::ResolutionKind::Import
                )
                .unwrap()
                .as_str(),
            "https://example.test/late.js",
        );
    }
}
