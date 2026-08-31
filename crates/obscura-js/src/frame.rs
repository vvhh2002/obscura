//! Child frame realms.
//!
//! An iframe is a separate browsing context: its own JavaScript realm, its own
//! DOM tree, and its own origin. Without this, a frame's HTML is fetched and its
//! body dropped into a detached document in the *parent's* realm, so no script
//! inside a frame ever runs (issue #600).
//!
//! A frame realm is a second `v8::Context` in the page's isolate. Three things
//! make that practical:
//!
//! - The startup snapshot already contains the whole bootstrap, so a restored
//!   context arrives with every DOM class installed. A realm costs a context
//!   restore, not a re-parse.
//! - The realm's op table is filled from the page realm's, so every shim in the
//!   frame can call ops.
//! - Each realm registers its document in `RealmStates`, and an op looks up the
//!   realm that called it. Making a realm current around the host's calls into
//!   it is not enough, because a frame's timers and settled promises re-enter
//!   JavaScript straight from the event loop.
//!
//! Staying in one isolate is what lets same-origin frames share objects with
//! their parent, the way `iframe.contentWindow.document` does in a browser. A
//! second isolate could never do that.

use std::rc::Rc;
use std::sync::Arc;

use obscura_dom::{parse_html, ParserYield, StreamingDocumentParser};

use crate::import_map::ImportMap;
use crate::module_loader::{ModuleLoadActivity, ObscuraModuleLoader};
use crate::ops::{ObscuraState, RealmStates};
use crate::runtime::ObscuraJsRuntime;

/// One child browsing context: its own realm, document and origin, living in
/// the page's isolate.
pub struct FrameRealm {
    module_realm: deno_core::ManagedJsRealm,
    /// Shared by the realm's loader and its host-driven evaluation calls so a
    /// browser capture cannot call a frame quiet between graph fetch and TLA.
    module_activity: Arc<ModuleLoadActivity>,
    context: deno_core::v8::Global<deno_core::v8::Context>,
    /// Held so the frame's entry can be taken out again when the frame dies.
    realms: Rc<std::cell::RefCell<RealmStates>>,
    frame_id: u32,
    parent_frame_id: u32,
    url: String,
    origin: String,
    lifecycle: std::cell::Cell<FrameLifecycleState>,
    /// Parser-owned nodes are frozen before any new-document preload runs.
    /// A preload may insert or move scripts, but it must neither enroll a new
    /// dynamic script in the parser pass nor make an original parser script
    /// execute once dynamically and once again as parser work.
    parser_scripts: Vec<DocumentScript>,
    parser_stylesheets: Vec<DocumentStylesheet>,
    parser_inline_stylesheets: Vec<DocumentInlineStylesheet>,
    /// Encounter position of the parsed `<body>` in the same ordering domain
    /// as parser script and stylesheet callbacks.
    parser_body_order: Option<usize>,
    module_evaluations:
        std::cell::RefCell<std::collections::HashMap<deno_core::ModuleId, Result<(), String>>>,
    evaluated_module_urls:
        std::cell::RefCell<std::collections::HashMap<String, Result<(), String>>>,
    executed_module_scripts: std::cell::RefCell<std::collections::HashSet<u32>>,
    /// Browser-owned frame documents use the same pausable html5ever parser as
    /// the top document. Low-level embedders retain the eager constructor for
    /// compatibility; Page opts into this state through the streaming staged
    /// constructor below.
    streaming_document: std::cell::RefCell<Option<FrameStreamingDocument>>,
    /// Effective sandbox policy for this document generation. Browser-owned
    /// lifecycle and resource plumbing still execute in the realm; only
    /// page-authored classic, module, dynamic, and content-handler code is
    /// disabled.
    scripts_allowed: bool,
    document_invalidated: std::cell::Cell<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameLifecycleState {
    Loading,
    DomContentLoaded,
    Loaded,
    Failed,
}

/// Resource state read from one live frame realm without converting realm or
/// JSON failures into an apparently empty document.
pub struct FrameResourceProbe {
    pub unsupported_module_scripts: usize,
    pub style_sources: Vec<String>,
    pub pending_dynamic_scripts: bool,
}

/// A fetched and instantiated module graph owned by one frame realm.
/// Evaluation is kept separate so an HTML scheduler can prepare defer/module
/// graphs during parsing and run them in encounter order after EOF.
pub struct PreparedFrameModule {
    module_id: deno_core::ModuleId,
    description: String,
    entry_url: Option<String>,
    graph_modules: Vec<(deno_core::ModuleId, String)>,
    document_generation: u64,
}

struct FrameStreamingDocument {
    parser: Rc<std::cell::RefCell<StreamingDocumentParser>>,
    source: String,
}

impl Drop for FrameRealm {
    fn drop(&mut self) {
        self.invalidate_document_generation();
        self.realms.borrow_mut().forget(&self.context);
        // Page severs the stable WindowProxy backend before removing a
        // published frame from its owner list. Staged realms have never been
        // published. In either case this is the final ownership boundary: stop
        // polling the old ModuleMap and reclaim its context slots now instead
        // of retaining every navigated iframe until the page isolate dies.
        self.module_realm.retire();
    }
}

impl FrameRealm {
    /// Builds a frame realm around an already-fetched document.
    ///
    /// The frame inherits the page's browser identity and its shared resources,
    /// by copying them from the parent rather than by being told them, so the
    /// two cannot drift apart.
    pub fn new(
        parent: &mut ObscuraJsRuntime,
        frame_id: u32,
        parent_frame_id: u32,
        url: &str,
        html: &str,
    ) -> Option<Self> {
        Self::new_with_inherited_context(parent, frame_id, parent_frame_id, url, None, None, html)
    }

    /// Builds an inline frame with separately inherited base and origin.
    /// They must remain distinct because `<base href>` can be cross-origin
    /// without changing the embedding document's principal.
    pub fn new_with_inherited_context(
        parent: &mut ObscuraJsRuntime,
        frame_id: u32,
        parent_frame_id: u32,
        url: &str,
        inherited_base_url: Option<&str>,
        inherited_origin: Option<&str>,
        html: &str,
    ) -> Option<Self> {
        let realm = Self::new_staged_with_inherited_context(
            parent,
            frame_id,
            parent_frame_id,
            url,
            inherited_base_url,
            inherited_origin,
            html,
        )?;
        realm.publish_to_owners(parent).then_some(realm)
    }

    /// Build and initialize a realm without publishing its Window/Document to
    /// the embedding realm. Page uses this transaction form while it awaits
    /// parser resources: dropping that future then drops an unpublished realm,
    /// and PendingFrameDrain can restore the document without leaving an old
    /// context reachable from an owner registry.
    pub fn new_staged_with_inherited_context(
        parent: &mut ObscuraJsRuntime,
        frame_id: u32,
        parent_frame_id: u32,
        url: &str,
        inherited_base_url: Option<&str>,
        inherited_origin: Option<&str>,
        html: &str,
    ) -> Option<Self> {
        Self::new_staged_with_inherited_context_and_script_policy(
            parent,
            frame_id,
            parent_frame_id,
            url,
            inherited_base_url,
            inherited_origin,
            html,
            true,
        )
    }

    /// Transactional frame construction with the effective iframe sandbox
    /// scripting policy captured at navigation start. This remains separate
    /// from origin inheritance: `allow-same-origin` and `allow-scripts` are
    /// independent sandbox tokens.
    pub fn new_staged_with_inherited_context_and_script_policy(
        parent: &mut ObscuraJsRuntime,
        frame_id: u32,
        parent_frame_id: u32,
        url: &str,
        inherited_base_url: Option<&str>,
        inherited_origin: Option<&str>,
        html: &str,
        scripts_allowed: bool,
    ) -> Option<Self> {
        Self::new_staged_impl(
            parent,
            frame_id,
            parent_frame_id,
            url,
            inherited_base_url,
            inherited_origin,
            html,
            scripts_allowed,
            false,
        )
    }

    /// Browser document constructor: resource discovery still uses one inert
    /// full-tree snapshot, but the realm is handed back with an empty live
    /// `StreamingDocumentParser` tree. Author scripts therefore run at real
    /// parser pause boundaries and cannot observe source after themselves.
    pub fn new_streaming_staged_with_inherited_context_and_script_policy(
        parent: &mut ObscuraJsRuntime,
        frame_id: u32,
        parent_frame_id: u32,
        url: &str,
        inherited_base_url: Option<&str>,
        inherited_origin: Option<&str>,
        html: &str,
        scripts_allowed: bool,
    ) -> Option<Self> {
        Self::new_staged_impl(
            parent,
            frame_id,
            parent_frame_id,
            url,
            inherited_base_url,
            inherited_origin,
            html,
            scripts_allowed,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_staged_impl(
        parent: &mut ObscuraJsRuntime,
        frame_id: u32,
        parent_frame_id: u32,
        url: &str,
        inherited_base_url: Option<&str>,
        inherited_origin: Option<&str>,
        html: &str,
        scripts_allowed: bool,
        streaming: bool,
    ) -> Option<Self> {
        let mut state = ObscuraState::new();
        state.dom = Some(parse_html(html));
        state.url = url.to_string();
        state.scripting_enabled = scripts_allowed;
        state.inherited_base_url = inherited_base_url.map(str::to_string);
        state.inherited_origin = inherited_origin.map(str::to_string);
        state.frame_id = frame_id;
        parent.share_resources_with(&mut state);
        let state = Rc::new(std::cell::RefCell::new(state));
        let import_map = state.borrow().import_map.clone();
        let module_loader = Rc::new(ObscuraModuleLoader::with_page_state(
            url, None, &state, import_map,
        ));
        let module_activity = module_loader.activity();
        let module_realm = parent.create_realm_context(module_loader)?;
        let context = module_realm.context().clone();
        if !parent.share_ops_with_realm(&context) {
            return None;
        }
        parent.copy_identity_to_realm(&context);

        // Same-origin access is relative to the immediate owner, while a frame
        // can also be same-origin with the top document across a cross-origin
        // intermediate frame. Keep the two relationships separate: A -> B -> A
        // may be published to top when it has a reference, but never into B;
        // A -> B -> B inherits B's token and is published only into B.
        let origin = inherited_origin
            .map(str::to_string)
            .unwrap_or_else(|| origin_of(url));
        let top_origin = parent.page_origin();
        let owner_origin = if parent_frame_id == 0 {
            Some(top_origin.clone())
        } else {
            parent.frame_origin(parent_frame_id)
        };
        let same_origin_with_top = origin != "null" && origin == top_origin;
        let same_origin_with_owner = origin != "null" && owner_origin.as_deref() == Some(&origin);
        if same_origin_with_top {
            parent.share_security_token_with_realm(&context);
        } else if same_origin_with_owner && parent_frame_id != 0 {
            if !parent.share_security_token_with_frame(&context, parent_frame_id) {
                return None;
            }
        }

        let realms = parent.realm_states();
        realms
            .borrow_mut()
            .register(context.clone(), frame_id, state);

        let mut realm = FrameRealm {
            module_realm,
            module_activity,
            context,
            realms,
            frame_id,
            parent_frame_id,
            url: url.to_string(),
            origin,
            lifecycle: std::cell::Cell::new(FrameLifecycleState::Loading),
            parser_scripts: Vec::new(),
            parser_stylesheets: Vec::new(),
            parser_inline_stylesheets: Vec::new(),
            parser_body_order: None,
            module_evaluations: std::cell::RefCell::new(std::collections::HashMap::new()),
            evaluated_module_urls: std::cell::RefCell::new(std::collections::HashMap::new()),
            executed_module_scripts: std::cell::RefCell::new(std::collections::HashSet::new()),
            streaming_document: std::cell::RefCell::new(None),
            scripts_allowed,
            document_invalidated: std::cell::Cell::new(false),
        };
        // Both ids before init, not after: init is what installs `parent` and
        // `top`, and a document that runs even one script believing it is
        // top-level has already taken the wrong branch.
        realm
            .run(
                parent,
                &format!(
                    "globalThis.__obscura_frameId = {frame_id};\
                     globalThis.__obscura_parentFrameId = {parent_frame_id};\
                     globalThis.__obscura_streamingDocumentInit = {streaming};\
                     globalThis.__documentReadyState__ = 'loading';\
                     globalThis.__obscura_init();\
                     delete globalThis.__obscura_streamingDocumentInit;"
                ),
            )
            .ok()?;
        realm.parser_scripts = realm.list_scripts(parent).ok()?;
        realm.parser_stylesheets = realm.list_stylesheets(parent).ok()?;
        realm.parser_inline_stylesheets = realm.list_inline_stylesheets(parent).ok()?;
        realm.parser_body_order = realm.list_parser_body_order(parent).ok()?;
        // A streaming realm replaces the inert discovery DOM below. Native
        // node ids from that snapshot may then collide with a different live
        // node (including a script created by document.write), so never carry
        // its already-started ids across the replacement. The streaming loop
        // marks each real tokenizer-yielded nid immediately before execution.
        let parser_nids = if streaming {
            Vec::new()
        } else {
            realm
                .parser_scripts
                .iter()
                .map(|script| script.nid)
                .collect::<Vec<_>>()
        };
        let parser_stylesheet_markers = realm
            .parser_stylesheets
            .iter()
            .filter(|stylesheet| {
                !stylesheet.disabled && !stylesheet.loaded && !stylesheet.href.is_empty()
            })
            .map(|stylesheet| {
                serde_json::json!({
                    "nid": stylesheet.nid,
                    "rawHref": stylesheet.href.clone(),
                    "requestHref": realm.resolve_from(
                        url::Url::parse(&stylesheet.base_url).ok().as_ref(),
                        &stylesheet.href,
                    ),
                })
            })
            .collect::<Vec<_>>();
        realm
            .run(
                parent,
                &format!(
                    "globalThis.__markParserScripts({});globalThis.__markParserStylesheets({});",
                    serde_json::to_string(&parser_nids).ok()?,
                    serde_json::to_string(&parser_stylesheet_markers).ok()?,
                ),
            )
            .ok()?;
        if streaming {
            let parser = Rc::new(std::cell::RefCell::new(StreamingDocumentParser::new()));
            let live_dom = parser.borrow().dom().clone();
            let state = realm.realms.borrow().by_frame_id(frame_id)?;
            {
                let mut state = state.borrow_mut();
                state.dom = Some(live_dom);
                state.install_streaming_parser(parser.clone());
            }
            realm
                .streaming_document
                .replace(Some(FrameStreamingDocument {
                    parser,
                    source: html.to_string(),
                }));
        }
        Some(realm)
    }

    /// Commit a staged realm into every same-origin owner registry. The helper
    /// invoked by the runtime closes over registry storage, so page code cannot
    /// interpose a Proxy setter or make teardown retain this context.
    pub fn publish_to_owners(&self, parent: &mut ObscuraJsRuntime) -> bool {
        let top_origin = parent.page_origin();
        let owner_origin = if self.parent_frame_id == 0 {
            Some(top_origin.clone())
        } else {
            parent.frame_origin(self.parent_frame_id)
        };
        let same_origin_with_top = self.origin != "null" && self.origin == top_origin;
        let same_origin_with_owner =
            self.origin != "null" && owner_origin.as_deref() == Some(self.origin.as_str());
        if same_origin_with_top && !parent.publish_realm_objects(&self.context, self.frame_id) {
            return false;
        }
        if same_origin_with_owner
            && self.parent_frame_id != 0
            && !parent.publish_realm_objects_to_frame(
                &self.context,
                self.frame_id,
                self.parent_frame_id,
            )
        {
            return false;
        }
        true
    }

    pub fn lifecycle_state(&self) -> FrameLifecycleState {
        self.lifecycle.get()
    }

    pub fn is_load_complete(&self) -> bool {
        self.lifecycle_state() == FrameLifecycleState::Loaded
    }

    pub fn mark_load_failed(&self) {
        self.lifecycle.set(FrameLifecycleState::Failed);
    }

    /// Whether this frame's module graph is fetching, evaluating (including
    /// top-level await), or has just crossed the fetch/evaluation hand-off.
    /// The short tail prevents capture-ready from observing a false idle slice
    /// between deno_core module-map turns.
    pub fn has_pending_module_work(&self) -> bool {
        self.module_activity
            .is_pending_or_recent(std::time::Duration::from_millis(100))
    }

    /// Permanently retire this document generation before its realm is
    /// detached, replaced, or discarded while staged. Async module futures
    /// retain the generation they started under and reject their continuation
    /// once this increments it.
    pub fn invalidate_document_generation(&self) -> bool {
        if self.document_invalidated.replace(true) {
            return false;
        }
        self.lifecycle.set(FrameLifecycleState::Failed);
        let state = self.realms.borrow().by_frame_id(self.frame_id);
        let Some(state) = state else {
            return false;
        };
        let mut state = state.borrow_mut();
        state.document_generation = state.document_generation.wrapping_add(1);
        state.activity_generation = state.activity_generation.wrapping_add(1);
        true
    }

    /// Finish parsing without claiming that descendant frames and resources
    /// have completed.
    pub fn dispatch_dom_content_loaded(&self, parent: &mut ObscuraJsRuntime) -> Result<(), String> {
        if self.lifecycle_state() != FrameLifecycleState::Loading {
            return Ok(());
        }
        self.execute_script(
            parent,
            "if (globalThis.__documentReadyState__ === 'loading') {\
               globalThis.__documentReadyState__ = 'interactive';\
               try { globalThis.__obscura_dispatchDocumentLifecycleEvent('readystatechange'); } catch (_) {}\
             }\
             try { globalThis.__obscura_dispatchDocumentLifecycleEvent('DOMContentLoaded'); } catch (_) {}",
        )?;
        self.lifecycle.set(FrameLifecycleState::DomContentLoaded);
        Ok(())
    }

    /// Complete this document after its load-event delay set becomes empty.
    pub fn dispatch_load(&self, parent: &mut ObscuraJsRuntime) -> Result<(), String> {
        if self.lifecycle_state() == FrameLifecycleState::Loaded {
            return Ok(());
        }
        self.dispatch_dom_content_loaded(parent)?;
        self.execute_script(
            parent,
            "globalThis.__documentReadyState__ = 'complete';\
             try { globalThis.__obscura_dispatchDocumentLifecycleEvent('readystatechange'); } catch (_) {}\
             try { globalThis.__obscura_dispatchWindowLoad(); } catch (_) {}",
        )?;
        self.lifecycle.set(FrameLifecycleState::Loaded);
        Ok(())
    }

    pub fn dispatch_load_events(&self, parent: &mut ObscuraJsRuntime) -> Result<(), String> {
        self.dispatch_dom_content_loaded(parent)?;
        self.dispatch_load(parent)
    }

    /// Delivers a `postMessage` that another realm sent to this one.
    pub fn deliver_message(
        &self,
        parent: &mut ObscuraJsRuntime,
        data_json: &str,
        origin: &str,
        source_frame_id: u32,
    ) -> Result<(), String> {
        self.execute_script(
            parent,
            &format!(
                "globalThis.__obscura_deliverMessage({}, {}, {source_frame_id});",
                encode_json_argument(data_json),
                encode_json_argument(origin),
            ),
        )
    }

    pub fn frame_id(&self) -> u32 {
        self.frame_id
    }

    /// Sets the frame document's viewport before any of its scripts run.
    pub fn set_viewport(
        &self,
        parent: &mut ObscuraJsRuntime,
        width: f64,
        height: f64,
    ) -> Result<(), String> {
        let width = if width.is_finite() && width > 0.0 {
            width
        } else {
            300.0
        };
        let height = if height.is_finite() && height > 0.0 {
            height
        } else {
            150.0
        };
        #[cfg(feature = "render")]
        {
            let state = self
                .realms
                .borrow()
                .by_frame_id(self.frame_id)
                .ok_or_else(|| "frame realm is no longer live".to_string())?;
            let mut state = state.borrow_mut();
            let viewport = (width as f32, height as f32);
            if state.viewport != viewport {
                state.viewport = viewport;
                state.prepared_render = None;
                state.pending_style_mutations.clear();
                state.resolved_scroll = None;
            }
        }
        self.execute_script(
            parent,
            &format!(
                "globalThis.__obscura_viewport_w={width};\
                 globalThis.__obscura_viewport_h={height};\
                 globalThis.innerWidth={width};globalThis.innerHeight={height};\
                 if(globalThis.visualViewport){{\
                   globalThis.visualViewport.width={width};\
                   globalThis.visualViewport.height={height};\
                 }}"
            ),
        )
    }

    pub fn parent_frame_id(&self) -> u32 {
        self.parent_frame_id
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// The frame's origin, or `"null"` for a document with an opaque origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Effective iframe sandbox script policy captured for this document.
    pub fn scripts_allowed(&self) -> bool {
        self.scripts_allowed
    }

    /// Absolute URLs fetched from this frame's realm. Frame documents keep
    /// their DOM and request bookkeeping separate from the page realm, so a
    /// page-level asset dump has to aggregate these explicitly.
    pub fn fetched_urls(&self) -> Vec<String> {
        let state = self.realms.borrow().by_frame_id(self.frame_id);
        state
            .map(|state| state.borrow().fetched_urls.clone())
            .unwrap_or_default()
    }

    /// Whether script from `other_origin` may reach into this frame's DOM. Two
    /// opaque origins are never same-origin, which is why `"null"` never
    /// matches.
    pub fn is_same_origin_as(&self, other_origin: &str) -> bool {
        self.origin != "null" && self.origin == other_origin
    }

    /// Runs `source` in the frame's realm. Ops called from it find the frame's
    /// document by looking up the realm they were called from.
    fn run(&self, parent: &mut ObscuraJsRuntime, source: &str) -> Result<String, String> {
        parent.eval_in_realm(&self.context, source)
    }

    /// Runs a script inside the frame, reporting a script error as `Err`.
    pub fn execute_script(
        &self,
        parent: &mut ObscuraJsRuntime,
        source: &str,
    ) -> Result<(), String> {
        self.run(parent, source).map(|_| ())
    }

    /// Merge an import map into this frame's independent resolution state.
    /// Resolutions already observed by this frame remain frozen by
    /// `ImportMap::merge`; sibling and parent realms have separate maps.
    pub fn add_import_map(&self, source: &str, base_url: &str) -> Result<(), String> {
        let map = ImportMap::parse(source, base_url)?;
        let state = self
            .realms
            .borrow()
            .by_frame_id(self.frame_id)
            .ok_or_else(|| "frame realm is no longer live".to_string())?;
        let import_map = state.borrow().import_map.clone();
        import_map
            .try_borrow_mut()
            .map_err(|_| "Frame import map is already borrowed".to_string())?
            .merge(map);
        Ok(())
    }

    /// Fetch and instantiate an external module graph in this frame's
    /// ModuleMap. `source` may provide an already-fetched entry while static
    /// descendants and later dynamic imports continue through the frame's
    /// shared browser HTTP state.
    pub async fn prepare_external_module(
        &self,
        parent: &mut ObscuraJsRuntime,
        url: &str,
        source: Option<&str>,
        budget_ms: u64,
    ) -> Result<PreparedFrameModule, String> {
        let document_generation = self.document_generation()?;
        let (module_id, graph_modules) = parent
            .load_module_in_realm(&self.module_realm, url, source, false, budget_ms)
            .await?;
        self.ensure_document_generation(document_generation)?;
        Ok(PreparedFrameModule {
            module_id,
            description: format!("Frame module {url}"),
            entry_url: Some(url.to_string()),
            graph_modules,
            document_generation,
        })
    }

    /// Fetch and instantiate an inline module graph. The document URL remains
    /// the module's observable base and import.meta URL, matching top-level
    /// module handling.
    pub async fn prepare_inline_module(
        &self,
        parent: &mut ObscuraJsRuntime,
        source: &str,
        base_url: &str,
        budget_ms: u64,
    ) -> Result<PreparedFrameModule, String> {
        let document_generation = self.document_generation()?;
        let (module_id, graph_modules) = parent
            .load_module_in_realm(&self.module_realm, base_url, Some(source), true, budget_ms)
            .await?;
        self.ensure_document_generation(document_generation)?;
        Ok(PreparedFrameModule {
            module_id,
            description: "Inline frame module".to_string(),
            entry_url: None,
            graph_modules,
            document_generation,
        })
    }

    /// Evaluate a prepared graph, including top-level await, while the owning
    /// runtime polls all managed realms. Duplicate roots reuse their first
    /// browser-style outcome instead of hitting deno_core's duplicate-eval
    /// assertion.
    pub async fn evaluate_prepared_module(
        &self,
        parent: &mut ObscuraJsRuntime,
        prepared: PreparedFrameModule,
        budget_ms: u64,
    ) -> Result<(), String> {
        self.ensure_document_generation(prepared.document_generation)?;
        if let Some(outcome) = self
            .module_evaluations
            .borrow()
            .get(&prepared.module_id)
            .cloned()
        {
            return outcome;
        }
        if let Some(outcome) = prepared
            .entry_url
            .as_ref()
            .and_then(|url| self.evaluated_module_urls.borrow().get(url).cloned())
        {
            return outcome;
        }

        let _evaluation_activity = self.module_activity.begin();
        let outcome = parent
            .evaluate_module_in_realm(
                &self.module_realm,
                prepared.module_id,
                budget_ms,
                &prepared.description,
            )
            .await;
        self.ensure_document_generation(prepared.document_generation)?;
        self.module_evaluations
            .borrow_mut()
            .insert(prepared.module_id, outcome.clone());
        let has_external_entry = prepared.entry_url.is_some();
        if let Some(entry_url) = prepared.entry_url {
            self.evaluated_module_urls
                .borrow_mut()
                .insert(entry_url, outcome.clone());
        }
        if outcome.is_ok() {
            for (module_id, specifier) in prepared.graph_modules {
                self.module_evaluations
                    .borrow_mut()
                    .insert(module_id, Ok(()));
                if module_id != prepared.module_id || has_external_entry {
                    self.evaluated_module_urls
                        .borrow_mut()
                        .insert(specifier, Ok(()));
                }
            }
        }
        outcome
    }

    pub async fn load_external_module(
        &self,
        parent: &mut ObscuraJsRuntime,
        url: &str,
        source: Option<&str>,
        budget_ms: u64,
    ) -> Result<(), String> {
        if let Some(outcome) = self.evaluated_module_urls.borrow().get(url).cloned() {
            return outcome;
        }
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(budget_ms);
        let prepared = self
            .prepare_external_module(parent, url, source, budget_ms)
            .await?;
        let remaining_ms = remaining_budget_ms(deadline).ok_or_else(|| {
            format!("Frame module {url} exhausted its {budget_ms}ms load+evaluation budget")
        })?;
        self.evaluate_prepared_module(parent, prepared, remaining_ms)
            .await
    }

    pub async fn load_inline_module(
        &self,
        parent: &mut ObscuraJsRuntime,
        source: &str,
        base_url: &str,
        budget_ms: u64,
    ) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(budget_ms);
        let prepared = self
            .prepare_inline_module(parent, source, base_url, budget_ms)
            .await?;
        let remaining_ms = remaining_budget_ms(deadline).ok_or_else(|| {
            format!("Inline frame module exhausted its {budget_ms}ms load+evaluation budget")
        })?;
        self.evaluate_prepared_module(parent, prepared, remaining_ms)
            .await
    }

    fn document_generation(&self) -> Result<u64, String> {
        if self.document_invalidated.get() {
            return Err("frame document is no longer current".to_string());
        }
        let state = self
            .realms
            .borrow()
            .by_frame_id(self.frame_id)
            .ok_or_else(|| "frame realm is no longer live".to_string())?;
        let generation = state.borrow().document_generation;
        Ok(generation)
    }

    fn ensure_document_generation(&self, expected: u64) -> Result<(), String> {
        if self.document_invalidated.get() {
            return Err(
                "frame document was replaced while its module graph was loading".to_string(),
            );
        }
        let current = self.document_generation()?;
        if current == expected {
            Ok(())
        } else {
            Err("frame document was replaced while its module graph was loading".to_string())
        }
    }

    /// A parser continuation is stale not only when a navigation increments
    /// the native generation, but also as soon as its owner (or an ancestor
    /// owner) leaves the composed tree. Page performs the same check at the
    /// transaction boundary; streaming parsing needs it between script pauses
    /// so a first script cannot detach the iframe and let later source run.
    fn ensure_streaming_document_is_current(
        &self,
        parent: &mut ObscuraJsRuntime,
        expected_generation: u64,
    ) -> Result<(), String> {
        self.ensure_document_generation(expected_generation)?;

        let mut child_frame_id = self.frame_id;
        let mut owner_frame_id = self.parent_frame_id;
        loop {
            let expression = format!(
                "({{live:globalThis.__obscura_frameOwnerIsLive({child_frame_id}),\
                   parentFrameId:(globalThis.__obscura_parentFrameId || 0) >>> 0}})"
            );
            let value = if owner_frame_id == 0 {
                parent.evaluate_host_probe(&expression)?
            } else {
                let owner_context = self
                    .realms
                    .borrow()
                    .context_by_frame_id(owner_frame_id)
                    .ok_or_else(|| format!("frame owner realm {owner_frame_id} disappeared"))?;
                parent.eval_json_in_realm(&owner_context, &expression)?
            };
            let live = value
                .get("live")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| {
                    format!("frame owner liveness probe in realm {owner_frame_id} was invalid")
                })?;
            if !live {
                self.invalidate_document_generation();
                return Err("frame document was detached while parser work was pending".to_string());
            }
            if owner_frame_id == 0 {
                return Ok(());
            }
            child_frame_id = owner_frame_id;
            owner_frame_id = value
                .get("parentFrameId")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| {
                    format!("frame owner ancestry probe in realm {child_frame_id} was invalid")
                })?;
        }
    }

    /// Installs a CDP Runtime binding in this realm while keeping the native
    /// op table outside the frame's global object.
    pub fn install_cdp_binding(
        &self,
        parent: &mut ObscuraJsRuntime,
        name: &str,
    ) -> Result<(), String> {
        parent.install_cdp_binding_in_realm(&self.context, name)
    }

    /// Evaluates an expression inside the frame and decodes it as JSON.
    pub fn evaluate(
        &self,
        parent: &mut ObscuraJsRuntime,
        expression: &str,
    ) -> Result<serde_json::Value, String> {
        parent.eval_json_in_realm(&self.context, expression)
    }

    /// Watchdog-bounded evaluation for browser-owned probes.
    pub fn evaluate_with_timeout(
        &self,
        parent: &mut ObscuraJsRuntime,
        expression: &str,
        timeout: std::time::Duration,
    ) -> Result<serde_json::Value, String> {
        parent.eval_json_in_realm_with_timeout(&self.context, expression, timeout)
    }

    /// Runs the frame document's classic scripts, in document order.
    ///
    /// `load_external` resolves a `src=` script to its source text; returning
    /// `None` skips it, which is what a failed subresource fetch looks like to
    /// the page. One script throwing does not stop the ones after it, matching
    /// how a browser treats separate classic scripts.
    ///
    /// Module and import-map scripts are handled by
    /// [`Self::run_document_modules`] after the parser/classic pass.
    ///
    /// Returns one message per script that failed or was skipped.
    pub fn run_document_scripts(
        &self,
        parent: &mut ObscuraJsRuntime,
        load_external: impl Fn(&str) -> Option<String>,
    ) -> Vec<String> {
        self.run_document_scripts_with_stylesheet_events(
            parent,
            load_external,
            std::collections::BTreeMap::new(),
        )
    }

    fn ordered_parser_stylesheet_events(
        &self,
        events: &mut std::collections::BTreeMap<u32, String>,
    ) -> std::collections::VecDeque<(usize, String)> {
        let mut ordered = self
            .parser_stylesheets
            .iter()
            .map(|stylesheet| (stylesheet.nid, stylesheet.parser_order))
            .chain(
                self.parser_inline_stylesheets
                    .iter()
                    .map(|stylesheet| (stylesheet.nid, stylesheet.parser_order)),
            )
            .filter_map(|(nid, parser_order)| {
                events.remove(&nid).map(|source| (parser_order, source))
            })
            .collect::<Vec<_>>();
        ordered.sort_by_key(|(parser_order, _)| *parser_order);
        std::collections::VecDeque::from(ordered)
    }

    /// Frame parser runner with already-fetched stylesheet completions keyed
    /// by the stable native node id of their owner link. The CSS bytes may be
    /// ready before parsing, but installation and load/error dispatch happen
    /// at the link's encounter point relative to classic scripts.
    pub fn run_document_scripts_with_stylesheet_events(
        &self,
        parent: &mut ObscuraJsRuntime,
        load_external: impl Fn(&str) -> Option<String>,
        mut stylesheet_events: std::collections::BTreeMap<u32, String>,
    ) -> Vec<String> {
        let scripts = &self.parser_scripts;

        let mut stylesheet_events = self.ordered_parser_stylesheet_events(&mut stylesheet_events);

        let mut problems = Vec::new();
        let mut body_load_handler_installed = false;
        for (index, script) in scripts.iter().enumerate() {
            while stylesheet_events
                .front()
                .is_some_and(|(order, _)| *order < script.parser_order)
            {
                let (order, source) = stylesheet_events.pop_front().unwrap();
                if !body_load_handler_installed
                    && self
                        .parser_body_order
                        .is_some_and(|body_order| body_order < order)
                {
                    if let Err(error) = self.install_parsed_body_load_handler(parent) {
                        problems.push(format!("frame body load handler setup failed: {error}"));
                    }
                    body_load_handler_installed = true;
                }
                if let Err(error) = self.execute_script(parent, &source) {
                    problems.push(format!("frame parser stylesheet event failed: {error}"));
                }
            }
            if !body_load_handler_installed
                && self
                    .parser_body_order
                    .is_some_and(|body_order| body_order < script.parser_order)
            {
                if let Err(error) = self.install_parsed_body_load_handler(parent) {
                    problems.push(format!("frame body load handler setup failed: {error}"));
                }
                body_load_handler_installed = true;
            }
            if !self.scripts_allowed {
                continue;
            }
            if !script.is_classic() {
                continue;
            }

            let external = !script.src.is_empty();
            let (name, source) = if !external {
                (format!("inline {index}"), script.text.clone())
            } else {
                let resolved =
                    self.resolve_from(url::Url::parse(&script.base_url).ok().as_ref(), &script.src);
                match load_external(&resolved) {
                    Some(source) => (resolved, source),
                    None => {
                        problems.push(format!("frame script {resolved} could not be loaded"));
                        self.dispatch_parser_script_event(parent, script.nid, "error");
                        continue;
                    }
                }
            };
            if source.trim().is_empty() {
                if external {
                    self.dispatch_parser_script_event(parent, script.nid, "load");
                }
                continue;
            }
            let _ = self.execute_script(
                parent,
                &format!("globalThis.__currentScriptNid={};", script.nid),
            );
            if let Err(error) = self.execute_script(parent, &source) {
                problems.push(format!("frame script {name} failed: {error}"));
            }
            let _ = self.execute_script(parent, "globalThis.__currentScriptNid=0;");
            // A classic external script fires load after a successful fetch,
            // even when evaluating its body reports a JavaScript exception.
            if external {
                self.dispatch_parser_script_event(parent, script.nid, "load");
            }
        }
        while let Some((order, source)) = stylesheet_events.pop_front() {
            if !body_load_handler_installed
                && self
                    .parser_body_order
                    .is_some_and(|body_order| body_order < order)
            {
                if let Err(error) = self.install_parsed_body_load_handler(parent) {
                    problems.push(format!("frame body load handler setup failed: {error}"));
                }
                body_load_handler_installed = true;
            }
            if let Err(error) = self.execute_script(parent, &source) {
                problems.push(format!("frame parser stylesheet event failed: {error}"));
            }
        }
        if !body_load_handler_installed {
            if let Err(error) = self.install_parsed_body_load_handler(parent) {
                problems.push(format!("frame body load handler setup failed: {error}"));
            }
        }
        problems
    }

    /// Execute the complete parser script set, including import maps and ES
    /// modules, against this frame's managed realm.
    ///
    /// Module graphs are prepared at their encounter point, which freezes the
    /// import-map rules visible to that graph. Ordinary module scripts defer
    /// evaluation until the parser pass is complete; `async` modules evaluate
    /// as soon as their graph is ready. External classic and module entry
    /// sources may be supplied from the page transport so resource archiving
    /// does not need a second request.
    pub async fn run_document_scripts_and_modules_with_stylesheet_events(
        &self,
        parent: &mut ObscuraJsRuntime,
        load_external: impl Fn(&str) -> Option<String>,
        mut stylesheet_events: std::collections::BTreeMap<u32, String>,
        module_budget_ms: u64,
    ) -> Vec<String> {
        let has_streaming_document = self.streaming_document.borrow().is_some();
        if has_streaming_document {
            return self
                .run_streaming_document_scripts_and_modules(
                    parent,
                    &load_external,
                    stylesheet_events,
                    module_budget_ms,
                )
                .await;
        }
        let document_generation = match self.document_generation() {
            Ok(generation) => generation,
            Err(error) => return vec![error],
        };
        let mut stylesheet_events = self.ordered_parser_stylesheet_events(&mut stylesheet_events);
        let mut deferred_modules = Vec::new();
        let mut problems = Vec::new();
        let mut body_load_handler_installed = false;

        for (index, script) in self.parser_scripts.iter().enumerate() {
            while stylesheet_events
                .front()
                .is_some_and(|(order, _)| *order < script.parser_order)
            {
                let (order, source) = stylesheet_events.pop_front().unwrap();
                if !body_load_handler_installed
                    && self
                        .parser_body_order
                        .is_some_and(|body_order| body_order < order)
                {
                    if let Err(error) = self.install_parsed_body_load_handler(parent) {
                        problems.push(format!("frame body load handler setup failed: {error}"));
                    }
                    body_load_handler_installed = true;
                }
                if let Err(error) = self.execute_script(parent, &source) {
                    problems.push(format!("frame parser stylesheet event failed: {error}"));
                }
            }
            if !body_load_handler_installed
                && self
                    .parser_body_order
                    .is_some_and(|body_order| body_order < script.parser_order)
            {
                if let Err(error) = self.install_parsed_body_load_handler(parent) {
                    problems.push(format!("frame body load handler setup failed: {error}"));
                }
                body_load_handler_installed = true;
            }

            if !self.scripts_allowed {
                continue;
            }

            if script.type_attribute == "importmap" {
                let result = if script.src.is_empty() {
                    self.add_import_map(&script.text, &script.base_url)
                } else {
                    Err("external import maps are not supported".to_string())
                };
                if let Err(error) = result {
                    problems.push(format!("frame import map {index} failed: {error}"));
                    self.dispatch_parser_script_event(parent, script.nid, "error");
                }
                continue;
            }

            if script.type_attribute == "module" {
                let external = !script.src.is_empty();
                let prepared = if external {
                    let resolved = self
                        .resolve_from(url::Url::parse(&script.base_url).ok().as_ref(), &script.src);
                    let source = load_external(&resolved);
                    self.prepare_external_module(
                        parent,
                        &resolved,
                        source.as_deref(),
                        module_budget_ms,
                    )
                    .await
                } else {
                    self.prepare_inline_module(
                        parent,
                        &script.text,
                        &script.base_url,
                        module_budget_ms,
                    )
                    .await
                };
                if let Err(error) = self.ensure_document_generation(document_generation) {
                    problems.push(error);
                    return problems;
                }

                match prepared {
                    Ok(prepared) if script.async_attribute => {
                        let result = self
                            .evaluate_prepared_module(parent, prepared, module_budget_ms)
                            .await;
                        if let Err(error) = self.ensure_document_generation(document_generation) {
                            problems.push(error);
                            return problems;
                        }
                        self.executed_module_scripts.borrow_mut().insert(script.nid);
                        match result {
                            Ok(()) => self.dispatch_parser_script_event(parent, script.nid, "load"),
                            Err(error) => {
                                problems
                                    .push(format!("frame async module {index} failed: {error}"));
                                self.dispatch_parser_script_event(parent, script.nid, "error");
                            }
                        }
                    }
                    Ok(prepared) => deferred_modules.push((index, script.nid, prepared)),
                    Err(error) => {
                        self.executed_module_scripts.borrow_mut().insert(script.nid);
                        problems.push(format!("frame module {index} failed: {error}"));
                        self.dispatch_parser_script_event(parent, script.nid, "error");
                    }
                }
                continue;
            }

            if !script.is_classic() {
                continue;
            }
            let external = !script.src.is_empty();
            let (name, source) = if external {
                let resolved =
                    self.resolve_from(url::Url::parse(&script.base_url).ok().as_ref(), &script.src);
                match load_external(&resolved) {
                    Some(source) => (resolved, source),
                    None => {
                        problems.push(format!("frame script {resolved} could not be loaded"));
                        self.dispatch_parser_script_event(parent, script.nid, "error");
                        continue;
                    }
                }
            } else {
                (format!("inline {index}"), script.text.clone())
            };
            if source.trim().is_empty() {
                if external {
                    self.dispatch_parser_script_event(parent, script.nid, "load");
                }
                continue;
            }
            let _ = self.execute_script(
                parent,
                &format!("globalThis.__currentScriptNid={};", script.nid),
            );
            if let Err(error) = self.execute_script(parent, &source) {
                problems.push(format!("frame script {name} failed: {error}"));
            }
            let _ = self.execute_script(parent, "globalThis.__currentScriptNid=0;");
            if external {
                self.dispatch_parser_script_event(parent, script.nid, "load");
            }
        }

        while let Some((order, source)) = stylesheet_events.pop_front() {
            if !body_load_handler_installed
                && self
                    .parser_body_order
                    .is_some_and(|body_order| body_order < order)
            {
                if let Err(error) = self.install_parsed_body_load_handler(parent) {
                    problems.push(format!("frame body load handler setup failed: {error}"));
                }
                body_load_handler_installed = true;
            }
            if let Err(error) = self.execute_script(parent, &source) {
                problems.push(format!("frame parser stylesheet event failed: {error}"));
            }
        }
        if !body_load_handler_installed {
            if let Err(error) = self.install_parsed_body_load_handler(parent) {
                problems.push(format!("frame body load handler setup failed: {error}"));
            }
        }

        for (index, nid, prepared) in deferred_modules {
            let result = self
                .evaluate_prepared_module(parent, prepared, module_budget_ms)
                .await;
            if let Err(error) = self.ensure_document_generation(document_generation) {
                problems.push(error);
                return problems;
            }
            self.executed_module_scripts.borrow_mut().insert(nid);
            match result {
                Ok(()) => self.dispatch_parser_script_event(parent, nid, "load"),
                Err(error) => {
                    problems.push(format!("frame module {index} failed: {error}"));
                    self.dispatch_parser_script_event(parent, nid, "error");
                }
            }
        }
        problems
    }

    /// Drive the child document's live tokenizer and execute parser work at
    /// html5ever's real `TokenizerResult::Script` boundary. The complete
    /// response is already decoded by the iframe fetch shim, but remains only
    /// buffered tokenizer input: source after a blocking script is not added to
    /// the DOM until this method resumes the parser.
    async fn run_streaming_document_scripts_and_modules<F>(
        &self,
        parent: &mut ObscuraJsRuntime,
        load_external: &F,
        mut stylesheet_events: std::collections::BTreeMap<u32, String>,
        module_budget_ms: u64,
    ) -> Vec<String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let document_generation = match self.document_generation() {
            Ok(generation) => generation,
            Err(error) => return vec![error],
        };
        if let Err(error) = self.ensure_streaming_document_is_current(parent, document_generation) {
            return vec![error];
        }
        let Some(mut document) = self.streaming_document.borrow_mut().take() else {
            return vec!["frame streaming parser was already consumed".to_string()];
        };
        let mut stylesheet_events = self.ordered_parser_stylesheet_events(&mut stylesheet_events);
        let mut deferred_classics = Vec::new();
        let mut deferred_modules = Vec::new();
        let mut problems = Vec::new();
        let mut body_load_handler_installed = false;
        let mut script_cursor = 0usize;
        // Keep the response buffer separate from the parser borrow. Besides
        // satisfying Rust's aliasing rules, this makes the ownership model
        // explicit: bytes remain buffered input until `resume` exposes them.
        let source = std::mem::take(&mut document.source);
        let mut parser_state = document.parser.borrow_mut().feed(&source);

        loop {
            // Enrol only resources exposed by the tokenizer so far. The JS
            // helper is weak-set guarded, which makes this safe at every pause
            // while preserving encounter-before-script timing.
            if let Err(error) = self.execute_script(
                parent,
                "globalThis.__obscura_startParserCreatedResources();",
            ) {
                problems.push(format!("frame parser resource sweep failed: {error}"));
            }
            if let Err(error) =
                self.ensure_streaming_document_is_current(parent, document_generation)
            {
                problems.push(error);
                return problems;
            }
            match parser_state {
                ParserYield::NeedInput => parser_state = document.parser.borrow_mut().finish(),
                ParserYield::Finished => break,
                ParserYield::Script(nid) => {
                    let index = script_cursor;
                    script_cursor = script_cursor.saturating_add(1);
                    let Some(mut script) = self.parser_scripts.get(index).cloned() else {
                        problems.push(format!(
                            "frame parser yielded unexpected script node {}",
                            nid.raw(),
                        ));
                        parser_state = document.parser.borrow_mut().resume();
                        continue;
                    };
                    // Discovery happens on an inert full-tree clone before the
                    // live parser starts. Preloads may allocate native nodes in
                    // between, so encounter order is stable but arena ids are
                    // not. The tokenizer's id is authoritative for currentScript
                    // and load/error dispatch.
                    script.nid = nid.raw();
                    let _ = self.execute_script(
                        parent,
                        &format!("globalThis.__markParserScripts([{}]);", script.nid),
                    );

                    while stylesheet_events
                        .front()
                        .is_some_and(|(order, _)| *order < script.parser_order)
                    {
                        let (order, source) = stylesheet_events.pop_front().unwrap();
                        if !body_load_handler_installed
                            && self
                                .parser_body_order
                                .is_some_and(|body_order| body_order < order)
                        {
                            if let Err(error) = self.install_parsed_body_load_handler(parent) {
                                problems
                                    .push(format!("frame body load handler setup failed: {error}"));
                            }
                            body_load_handler_installed = true;
                        }
                        if let Err(error) = self.execute_script(parent, &source) {
                            problems.push(format!("frame parser stylesheet event failed: {error}"));
                        }
                        if let Err(error) =
                            self.ensure_streaming_document_is_current(parent, document_generation)
                        {
                            problems.push(error);
                            return problems;
                        }
                    }
                    if !body_load_handler_installed
                        && self
                            .parser_body_order
                            .is_some_and(|body_order| body_order < script.parser_order)
                    {
                        if let Err(error) = self.install_parsed_body_load_handler(parent) {
                            problems.push(format!("frame body load handler setup failed: {error}"));
                        }
                        body_load_handler_installed = true;
                    }

                    if self.scripts_allowed {
                        if script.type_attribute == "importmap" {
                            let result = if script.src.is_empty() {
                                self.add_import_map(&script.text, &script.base_url)
                            } else {
                                Err("external import maps are not supported".to_string())
                            };
                            if let Err(error) = result {
                                problems.push(format!("frame import map {index} failed: {error}"));
                                self.dispatch_parser_script_event(parent, script.nid, "error");
                            }
                        } else if script.type_attribute == "module" {
                            let external = !script.src.is_empty();
                            let prepared = if external {
                                let resolved = self.resolve_from(
                                    url::Url::parse(&script.base_url).ok().as_ref(),
                                    &script.src,
                                );
                                let source = load_external(&resolved);
                                self.prepare_external_module(
                                    parent,
                                    &resolved,
                                    source.as_deref(),
                                    module_budget_ms,
                                )
                                .await
                            } else {
                                self.prepare_inline_module(
                                    parent,
                                    &script.text,
                                    &script.base_url,
                                    module_budget_ms,
                                )
                                .await
                            };
                            if let Err(error) = self
                                .ensure_streaming_document_is_current(parent, document_generation)
                            {
                                problems.push(error);
                                return problems;
                            }
                            match prepared {
                                Ok(prepared) if script.async_attribute => {
                                    let result = self
                                        .evaluate_prepared_module(
                                            parent,
                                            prepared,
                                            module_budget_ms,
                                        )
                                        .await;
                                    if let Err(error) = self.ensure_streaming_document_is_current(
                                        parent,
                                        document_generation,
                                    ) {
                                        problems.push(error);
                                        return problems;
                                    }
                                    self.executed_module_scripts.borrow_mut().insert(script.nid);
                                    match result {
                                        Ok(()) => self.dispatch_parser_script_event(
                                            parent, script.nid, "load",
                                        ),
                                        Err(error) => {
                                            problems.push(format!(
                                                "frame async module {index} failed: {error}"
                                            ));
                                            self.dispatch_parser_script_event(
                                                parent, script.nid, "error",
                                            );
                                        }
                                    }
                                }
                                Ok(prepared) => {
                                    deferred_modules.push((index, script.nid, prepared))
                                }
                                Err(error) => {
                                    self.executed_module_scripts.borrow_mut().insert(script.nid);
                                    problems.push(format!("frame module {index} failed: {error}"));
                                    self.dispatch_parser_script_event(parent, script.nid, "error");
                                }
                            }
                        } else if script.is_classic() {
                            // defer is meaningful only on external classic
                            // scripts; async wins when both attributes exist.
                            if !script.src.is_empty()
                                && script.defer_attribute
                                && !script.async_attribute
                            {
                                deferred_classics.push((index, script));
                            } else {
                                if !self.execute_streaming_classic(
                                    parent,
                                    index,
                                    &script,
                                    load_external,
                                    document_generation,
                                    &mut problems,
                                ) {
                                    return problems;
                                }
                            }
                        }
                    }
                    if let Err(error) =
                        self.ensure_streaming_document_is_current(parent, document_generation)
                    {
                        problems.push(error);
                        return problems;
                    }
                    parser_state = document.parser.borrow_mut().resume();
                }
            }
        }

        while let Some((order, source)) = stylesheet_events.pop_front() {
            if !body_load_handler_installed
                && self
                    .parser_body_order
                    .is_some_and(|body_order| body_order < order)
            {
                if let Err(error) = self.install_parsed_body_load_handler(parent) {
                    problems.push(format!("frame body load handler setup failed: {error}"));
                }
                body_load_handler_installed = true;
            }
            if let Err(error) = self.execute_script(parent, &source) {
                problems.push(format!("frame parser stylesheet event failed: {error}"));
            }
            if let Err(error) =
                self.ensure_streaming_document_is_current(parent, document_generation)
            {
                problems.push(error);
                return problems;
            }
        }
        if !body_load_handler_installed {
            if let Err(error) = self.install_parsed_body_load_handler(parent) {
                problems.push(format!("frame body load handler setup failed: {error}"));
            }
        }

        // The realm was initialised against the live empty tree at commit.
        // Enrol parser-created resources now that EOF made them visible, then
        // perform the parser-complete ready-state transition before defer and
        // ordinary module evaluation. DOMContentLoaded itself remains owned by
        // the parent frame driver after those scripts settle.
        if let Err(error) = self.execute_script(
            parent,
            "globalThis.__obscura_startParserCreatedResources();\
             if (globalThis.__documentReadyState__ === 'loading') {\
               globalThis.__documentReadyState__ = 'interactive';\
               try { globalThis.__obscura_dispatchDocumentLifecycleEvent('readystatechange'); } catch (_) {}\
             }",
        ) {
            problems.push(format!("frame parser EOF transition failed: {error}"));
        }
        if let Err(error) = self.ensure_streaming_document_is_current(parent, document_generation) {
            problems.push(error);
            return problems;
        }

        if self.scripts_allowed {
            for (index, script) in deferred_classics {
                if !self.execute_streaming_classic(
                    parent,
                    index,
                    &script,
                    load_external,
                    document_generation,
                    &mut problems,
                ) {
                    return problems;
                }
                if let Err(error) =
                    self.ensure_streaming_document_is_current(parent, document_generation)
                {
                    problems.push(error);
                    return problems;
                }
            }
            for (index, nid, prepared) in deferred_modules {
                let result = self
                    .evaluate_prepared_module(parent, prepared, module_budget_ms)
                    .await;
                if let Err(error) =
                    self.ensure_streaming_document_is_current(parent, document_generation)
                {
                    problems.push(error);
                    return problems;
                }
                self.executed_module_scripts.borrow_mut().insert(nid);
                match result {
                    Ok(()) => self.dispatch_parser_script_event(parent, nid, "load"),
                    Err(error) => {
                        problems.push(format!("frame module {index} failed: {error}"));
                        self.dispatch_parser_script_event(parent, nid, "error");
                    }
                }
            }
        }
        if let Some(state) = self.realms.borrow().by_frame_id(self.frame_id) {
            state.borrow_mut().clear_streaming_parser();
        }
        problems
    }

    fn execute_streaming_classic<F>(
        &self,
        parent: &mut ObscuraJsRuntime,
        index: usize,
        script: &DocumentScript,
        load_external: &F,
        document_generation: u64,
        problems: &mut Vec<String>,
    ) -> bool
    where
        F: Fn(&str) -> Option<String>,
    {
        let external = !script.src.is_empty();
        let (name, source) = if external {
            let resolved =
                self.resolve_from(url::Url::parse(&script.base_url).ok().as_ref(), &script.src);
            let loaded = load_external(&resolved);
            if let Err(error) =
                self.ensure_streaming_document_is_current(parent, document_generation)
            {
                problems.push(error);
                return false;
            }
            match loaded {
                Some(source) => (resolved, source),
                None => {
                    problems.push(format!("frame script {resolved} could not be loaded"));
                    self.dispatch_parser_script_event(parent, script.nid, "error");
                    return match self
                        .ensure_streaming_document_is_current(parent, document_generation)
                    {
                        Ok(()) => true,
                        Err(error) => {
                            problems.push(error);
                            false
                        }
                    };
                }
            }
        } else {
            (format!("inline {index}"), script.text.clone())
        };
        if source.trim().is_empty() {
            if external {
                self.dispatch_parser_script_event(parent, script.nid, "load");
            }
            return match self.ensure_streaming_document_is_current(parent, document_generation) {
                Ok(()) => true,
                Err(error) => {
                    problems.push(error);
                    false
                }
            };
        }
        let _ = self.execute_script(
            parent,
            &format!("globalThis.__currentScriptNid={};", script.nid),
        );
        if let Err(error) = self.execute_script(parent, &source) {
            problems.push(format!("frame script {name} failed: {error}"));
        }
        let _ = self.execute_script(parent, "globalThis.__currentScriptNid=0;");
        if external {
            self.dispatch_parser_script_event(parent, script.nid, "load");
        }
        match self.ensure_streaming_document_is_current(parent, document_generation) {
            Ok(()) => true,
            Err(error) => {
                problems.push(error);
                false
            }
        }
    }

    fn install_parsed_body_load_handler(
        &self,
        parent: &mut ObscuraJsRuntime,
    ) -> Result<(), String> {
        self.execute_script(
            parent,
            "globalThis.__obscura_installParsedBodyLoadHandler?.();",
        )
    }

    fn dispatch_parser_script_event(
        &self,
        parent: &mut ObscuraJsRuntime,
        nid: u32,
        event_type: &str,
    ) {
        debug_assert!(matches!(event_type, "load" | "error"));
        let _ = self.execute_script(
            parent,
            &format!(
                "globalThis.__obscura_dispatchParserScriptEvent({nid}, {})",
                encode_json_argument(event_type),
            ),
        );
    }

    /// Absolute URLs of the frame's `src=` classic scripts, in document order.
    ///
    /// A caller that fetches over the network needs the list before running
    /// anything, because `run_document_scripts` resolves sources synchronously.
    pub fn external_script_urls(&self, parent: &mut ObscuraJsRuntime) -> Vec<String> {
        let _ = parent;
        if !self.scripts_allowed {
            return Vec::new();
        }
        self.parser_scripts
            .iter()
            .filter(|script| script.is_classic() && !script.src.is_empty())
            .map(|script| {
                self.resolve_from(url::Url::parse(&script.base_url).ok().as_ref(), &script.src)
            })
            .collect()
    }

    /// Absolute entry URLs for parser-owned external module scripts. Static
    /// descendants remain the managed realm loader's responsibility.
    pub fn external_module_urls(&self) -> Vec<String> {
        if !self.scripts_allowed {
            return Vec::new();
        }
        self.parser_scripts
            .iter()
            .filter(|script| script.type_attribute == "module" && !script.src.is_empty())
            .map(|script| {
                self.resolve_from(url::Url::parse(&script.base_url).ok().as_ref(), &script.src)
            })
            .collect()
    }

    /// Parser-owned linked stylesheets frozen before new-document preloads.
    ///
    /// The live stylesheet scan intentionally excludes these links while the
    /// native parser transport owns them. Enumerate the frozen snapshot here
    /// so initial frame attachment still fetches those roots, while a preload
    /// that inserts or rewrites a link can be discovered separately as
    /// dynamic work by `external_stylesheet_urls`. The final tuple member is
    /// the frozen raw `href`, used to decide whether the live owner still names
    /// the parser request after a preload has run.
    pub fn parser_stylesheet_urls(&self) -> Vec<(usize, u32, String, u8, String)> {
        self.parser_stylesheets
            .iter()
            .filter(|stylesheet| {
                !stylesheet.disabled && !stylesheet.loaded && !stylesheet.href.is_empty()
            })
            .map(|stylesheet| {
                (
                    stylesheet.link_index,
                    stylesheet.nid,
                    self.resolve_from(
                        url::Url::parse(&stylesheet.base_url).ok().as_ref(),
                        &stylesheet.href,
                    ),
                    stylesheet.import_depth,
                    stylesheet.href.clone(),
                )
            })
            .collect()
    }

    /// Linked author stylesheets in document order, with their index among all
    /// stylesheet links. The index lets the page materialize fetched CSS next
    /// to the link that owns it without moving the sheet in cascade order.
    pub fn external_stylesheet_urls(
        &self,
        parent: &mut ObscuraJsRuntime,
    ) -> Vec<(usize, u32, String, u8)> {
        let base = self.document_base_url(parent);
        self.list_stylesheets(parent)
            .unwrap_or_default()
            .into_iter()
            .filter(|stylesheet| {
                !stylesheet.disabled
                    && !stylesheet.loaded
                    && !stylesheet.parser_pending
                    && !stylesheet.href.is_empty()
            })
            .map(|stylesheet| {
                let resolved = base
                    .as_ref()
                    .and_then(|base| base.join(&stylesheet.href).ok())
                    .map(|url| url.to_string())
                    .unwrap_or(stylesheet.href);
                (
                    stylesheet.link_index,
                    stylesheet.nid,
                    resolved,
                    stylesheet.import_depth,
                )
            })
            .collect()
    }

    /// CSS authored directly in this document, including `<style>` contents
    /// and `style=` declarations. The page transport scans these for paint and
    /// font URLs because they never pass through an external-sheet response.
    pub fn style_sources(&self, parent: &mut ObscuraJsRuntime) -> Vec<String> {
        self.try_style_sources(parent).unwrap_or_default()
    }

    /// Renderer resource-bearing CSS from the frame's ordinary DOM and all of
    /// its nested open or closed shadow roots. This reads the frame-owned native
    /// DomTree rather than JavaScript selectors, which intentionally cannot
    /// pierce a closed root.
    #[cfg(feature = "render")]
    pub fn render_resource_style_sources(&self) -> Vec<String> {
        let Some(state) = self.realms.borrow().by_frame_id(self.frame_id) else {
            return Vec::new();
        };
        let sources = ObscuraJsRuntime::render_resource_style_sources_for_state(&state.borrow());
        sources
    }

    /// Inline stylesheet text in this frame's nested open and closed shadow
    /// roots. It is separate from the general CSS resource scan so archive
    /// callers can conservatively diagnose unsupported shadow `@import`
    /// ownership without blocking direct background/font URL capture.
    #[cfg(feature = "render")]
    pub fn shadow_inline_stylesheet_sources(&self) -> Vec<String> {
        let Some(state) = self.realms.borrow().by_frame_id(self.frame_id) else {
            return Vec::new();
        };
        let sources = ObscuraJsRuntime::shadow_inline_stylesheet_sources_for_state(&state.borrow());
        sources
    }

    /// Shadow-root stylesheet links for which no dynamic-loader style bridge
    /// exists. Until those parser-created owners can be materialized in-place,
    /// archive callers use this list to avoid a false `complete: true` result.
    #[cfg(feature = "render")]
    pub fn unresolved_shadow_stylesheet_hrefs(&self) -> Vec<String> {
        let Some(state) = self.realms.borrow().by_frame_id(self.frame_id) else {
            return Vec::new();
        };
        let hrefs = ObscuraJsRuntime::unresolved_shadow_stylesheet_hrefs_for_state(&state.borrow());
        hrefs
    }

    /// Inline author stylesheets in stable author order. Obscura's bridge
    /// styles are excluded: they represent a linked/imported owner elsewhere
    /// in the DOM and treating them as new author sheets would fetch an
    /// `@import` twice and disturb cascade order.
    pub fn parser_inline_stylesheet_sources(
        &self,
    ) -> Vec<(usize, u32, String, String, String, usize)> {
        self.parser_inline_stylesheets
            .iter()
            .map(|stylesheet| {
                (
                    stylesheet.author_index,
                    stylesheet.nid,
                    stylesheet.text.clone(),
                    stylesheet.media.clone(),
                    stylesheet.base_url.clone(),
                    stylesheet.parser_order,
                )
            })
            .collect()
    }

    /// Live inline author stylesheets. Parser-time callers should prefer
    /// [`Self::parser_inline_stylesheet_sources`], whose owners and encounter
    /// bases were frozen before any new-document preload could mutate them.
    pub fn inline_stylesheet_sources(
        &self,
        parent: &mut ObscuraJsRuntime,
    ) -> Result<Vec<(usize, String, String)>, String> {
        self.evaluate(
            parent,
            r#"[...document.querySelectorAll('style')]
                .filter(node => {
                    if (node.hasAttribute('data-obscura-adopted')
                        || node.hasAttribute('data-obscura-linked')
                        || node.hasAttribute('data-obscura-external-stylesheets')
                        || node.hasAttribute('data-obscura-inline-import')
                        || node.hasAttribute('data-obscura-imports-materialized')) return false;
                    var type = (node.getAttribute('type') || '').trim().toLowerCase();
                    return !type || type === 'text/css';
                })
                .map((node, author_index) => [
                    author_index,
                    node.textContent || '',
                    node.getAttribute('media') || '',
                ])"#,
        )
        .map_err(|error| format!("could not list frame inline stylesheets: {error}"))
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| format!("could not decode frame inline stylesheets: {error}"))
        })
    }

    fn try_style_sources(&self, parent: &mut ObscuraJsRuntime) -> Result<Vec<String>, String> {
        self.evaluate(
            parent,
            r#"[
                ...[...document.querySelectorAll('style')].map(node => node.textContent || ''),
                ...[...document.querySelectorAll('[style]')].map(node => node.getAttribute('style') || ''),
            ]"#,
        )
        .map_err(|error| format!("could not list frame style sources: {error}"))
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| format!("could not decode frame style sources: {error}"))
        })
    }

    /// Number of module scripts still present but not evaluated in this live
    /// frame. A sandboxed document deliberately reports zero: its module
    /// elements are inert by policy rather than unsupported archive work.
    pub fn unsupported_module_script_count(&self, parent: &mut ObscuraJsRuntime) -> usize {
        self.try_unsupported_module_script_count(parent)
            .unwrap_or_default()
    }

    fn try_unsupported_module_script_count(
        &self,
        parent: &mut ObscuraJsRuntime,
    ) -> Result<usize, String> {
        if !self.scripts_allowed {
            return Ok(0);
        }
        Ok(self
            .list_scripts(parent)?
            .iter()
            .filter(|script| {
                script.type_attribute == "module"
                    && !self.executed_module_scripts.borrow().contains(&script.nid)
            })
            .count())
    }

    /// Whether this realm still has a dynamically inserted script being
    /// fetched/evaluated or queued for execution. The queue lives inside each
    /// realm's bootstrap closure, so asking only the top-level runtime misses
    /// exactly the kind of late work used by embedded challenge widgets.
    pub fn has_pending_dynamic_scripts(&self, parent: &mut ObscuraJsRuntime) -> bool {
        self.try_has_pending_dynamic_scripts(parent)
            // A failed probe cannot prove that work completed. Retaining the
            // bounded frame is recoverable; firing load or ending capture is
            // not.
            .unwrap_or(true)
    }

    /// Whether a script, observed image, or dynamic stylesheet in this realm
    /// still delays its document's load event.
    pub fn has_pending_load_delaying_resources(&self, parent: &mut ObscuraJsRuntime) -> bool {
        self.evaluate(
            parent,
            "globalThis.__obscura_hasPendingLoadDelayingResources?.() === true",
        )
        .ok()
        .and_then(|value| value.as_bool())
        .unwrap_or(true)
    }

    fn try_has_pending_dynamic_scripts(
        &self,
        parent: &mut ObscuraJsRuntime,
    ) -> Result<bool, String> {
        self.evaluate(
            parent,
            "globalThis.__obscura_hasPendingDynamicScripts?.() === true",
        )
        .map_err(|error| format!("could not inspect frame dynamic scripts: {error}"))?
        .as_bool()
        .ok_or_else(|| "could not decode frame dynamic-script state".to_string())
    }

    /// Read every frame resource diagnostic with fallible realm evaluation.
    /// Archive completeness must not interpret an evaluation failure as zero
    /// scripts, zero styles, and no pending work.
    pub fn resource_archive_probe(
        &self,
        parent: &mut ObscuraJsRuntime,
    ) -> Result<FrameResourceProbe, String> {
        Ok(FrameResourceProbe {
            unsupported_module_scripts: self.try_unsupported_module_script_count(parent)?,
            style_sources: self.try_style_sources(parent)?,
            pending_dynamic_scripts: self.try_has_pending_dynamic_scripts(parent)?,
        })
    }

    /// A navigation requested by this realm but not committed by the host.
    /// Child-frame navigation is intentionally separate from top navigation;
    /// surfacing it lets archive callers report the unsupported transition.
    pub fn pending_navigation_url(&self) -> Option<String> {
        let state = self.realms.borrow().by_frame_id(self.frame_id)?;
        let pending_url = state
            .borrow()
            .pending_navigation
            .as_ref()
            .map(|(url, _, _)| url.clone());
        pending_url
    }

    /// Seed a frame's retained render cache with a resource already fetched by
    /// the page transport, avoiding a second renderer-side download.
    #[cfg(feature = "render")]
    pub fn seed_render_resource(&self, url: String, bytes: Option<Vec<u8>>) {
        let Some(state) = self.realms.borrow().by_frame_id(self.frame_id) else {
            return;
        };
        let mut state = state.borrow_mut();
        match bytes {
            Some(bytes) => {
                state.render_resources.seed(url, bytes);
                crate::ops::invalidate_render_resource_geometry(&mut state);
            }
            None => state.render_resources.seed_missing(url),
        }
    }

    /// Return unresolved responsive `<img>`/`<picture>` candidates and video
    /// posters from this frame's own DOM. The selection and cache check are
    /// shared with the top-level runtime so `srcset`, `sizes`, media queries,
    /// and CORS profiles cannot diverge between browsing contexts.
    #[cfg(feature = "render")]
    pub fn pending_render_image_urls(&self) -> Vec<(String, crate::ops::ImageRequestProfile)> {
        let Some(state) = self.realms.borrow().by_frame_id(self.frame_id) else {
            return Vec::new();
        };
        let urls = ObscuraJsRuntime::pending_render_image_urls_for_state(&state.borrow());
        urls
    }

    /// Seed one profiled frame image response after the page transport has
    /// fetched it. A CORS image and an ordinary no-CORS image intentionally do
    /// not share cache outcomes.
    #[cfg(feature = "render")]
    pub fn seed_render_image_resource(
        &self,
        url: String,
        profile: crate::ops::ImageRequestProfile,
        bytes: Option<Vec<u8>>,
    ) {
        let Some(state) = self.realms.borrow().by_frame_id(self.frame_id) else {
            return;
        };
        let mut state = state.borrow_mut();
        match bytes {
            Some(bytes) if obscura_render::image_intrinsic_dimensions(&bytes).is_some() => {
                let needs_geometry = match (&state.prepared_render, &state.dom) {
                    (Some(prepared), Some(dom)) => {
                        prepared.image_resource_needs_geometry(dom, &url, profile)
                    }
                    _ => true,
                };
                state.render_resources.seed_image(url, profile, bytes);
                state.activity_generation = state.activity_generation.wrapping_add(1);
                if needs_geometry {
                    crate::ops::invalidate_render_resource_geometry(&mut state);
                }
            }
            _ => state.render_resources.seed_image_missing(url, profile),
        }
    }

    /// Whether a non-profiled CSS image/font outcome is already retained in
    /// this frame's render cache.
    #[cfg(feature = "render")]
    pub fn render_resource_is_known(&self, url: &str) -> bool {
        self.realms
            .borrow()
            .by_frame_id(self.frame_id)
            .is_some_and(|state| state.borrow().render_resources.has_live_outcome(url))
    }

    /// Resolves a subresource URL against the frame's own document URL, not the
    /// parent's. A relative `src` in a frame is relative to the frame.
    fn resolve_from(&self, base: Option<&url::Url>, src: &str) -> String {
        base.cloned()
            .or_else(|| url::Url::parse(&self.url).ok())
            .and_then(|base| base.join(src).ok())
            .map(|url| url.to_string())
            .unwrap_or_else(|| src.to_string())
    }

    /// Fallback base before the HTML parser encounters the first `<base href>`.
    /// `about:srcdoc` inherits this value from its owner document; ordinary
    /// frame documents fall back to their own final response URL.
    fn fallback_document_base_url(&self) -> Option<url::Url> {
        self.realms
            .borrow()
            .by_frame_id(self.frame_id)
            .and_then(|state| {
                let state = state.borrow();
                state
                    .inherited_base_url
                    .as_deref()
                    .and_then(|base| url::Url::parse(base).ok())
            })
            .or_else(|| url::Url::parse(&self.url).ok())
    }

    /// Effective HTML document base used by inline CSS and other relative
    /// document-owned resources.
    pub fn document_base_url(&self, parent: &mut ObscuraJsRuntime) -> Option<url::Url> {
        let document_url = self.fallback_document_base_url()?;
        let base_href = self
            .evaluate(
                parent,
                "document.querySelector('base[href]')?.getAttribute('href') || null",
            )
            .ok()
            .and_then(|value| value.as_str().map(str::to_string));
        base_href
            .and_then(|href| document_url.join(&href).ok())
            .or(Some(document_url))
    }

    fn list_scripts(&self, parent: &mut ObscuraJsRuntime) -> Result<Vec<DocumentScript>, String> {
        let fallback_base = self
            .fallback_document_base_url()
            .map(|url| url.to_string())
            .unwrap_or_else(|| self.url.clone());
        let listed = self.evaluate(
            parent,
            &format!(
                r#"(function(){{
                  let activeBase = {};
                  let foundBase = false;
                  let parserOrder = 0;
                  const scripts = [];
                  const parserNodes = document.querySelectorAll(
                    'base[href],body,script,link[rel~="stylesheet"]'
                  );
                  for (const node of parserNodes) {{
                    if (node.localName === 'base') {{
                      if (!foundBase) {{
                        foundBase = true;
                        try {{ activeBase = new URL(node.getAttribute('href'), activeBase).href; }}
                        catch (_) {{}}
                      }}
                      continue;
                    }}
                    const order = parserOrder++;
                    if (node.localName === 'body') continue;
                    if (node.localName !== 'script') continue;
                    scripts.push({{
                      nid: node._nid >>> 0,
                      src: node.getAttribute('src') || '',
                      type: (node.getAttribute('type') || '').toLowerCase(),
                      text: node.textContent || '',
                      async: node.hasAttribute('async'),
                      defer: node.hasAttribute('defer'),
                      baseUrl: activeBase,
                      parserOrder: order,
                    }});
                  }}
                  return scripts;
                }})()"#,
                encode_json_argument(&fallback_base),
            ),
        );
        match listed {
            Ok(value) => serde_json::from_value(value)
                .map_err(|error| format!("could not decode frame scripts: {error}")),
            Err(error) => Err(format!("could not list frame scripts: {error}")),
        }
    }

    fn list_stylesheets(
        &self,
        parent: &mut ObscuraJsRuntime,
    ) -> Result<Vec<DocumentStylesheet>, String> {
        let fallback_base = self
            .fallback_document_base_url()
            .map(|url| url.to_string())
            .unwrap_or_else(|| self.url.clone());
        let listed = self.evaluate(
            parent,
            &format!(
                r#"(function(){{
                  let activeBase = {};
                  let foundBase = false;
                  let parserOrder = 0;
                  let linkIndex = 0;
                  const stylesheets = [];
                  const parserNodes = document.querySelectorAll(
                    'base[href],body,script,link[rel~="stylesheet"]'
                  );
                  for (const node of parserNodes) {{
                    if (node.localName === 'base') {{
                      if (!foundBase) {{
                        foundBase = true;
                        try {{ activeBase = new URL(node.getAttribute('href'), activeBase).href; }}
                        catch (_) {{}}
                      }}
                      continue;
                    }}
                    const order = parserOrder++;
                    if (node.localName === 'body') continue;
                    if (node.localName !== 'link') continue;
                    stylesheets.push({{
                      nid: node._nid >>> 0,
                      link_index: linkIndex++,
                      href: node.getAttribute('href') || '',
                      disabled: node.hasAttribute('disabled'),
                      loaded: node.sheet != null,
                      parser_pending: globalThis.__obscura_isParserStylesheetPending?.(node) === true,
                      import_depth: Number(node.getAttribute('data-obscura-import-depth') || 0),
                      baseUrl: activeBase,
                      parserOrder: order,
                    }});
                  }}
                  return stylesheets;
                }})()"#,
                encode_json_argument(&fallback_base),
            ),
        );
        match listed {
            Ok(value) => serde_json::from_value(value)
                .map_err(|error| format!("could not decode frame stylesheets: {error}")),
            Err(error) => Err(format!("could not list frame stylesheets: {error}")),
        }
    }

    fn list_inline_stylesheets(
        &self,
        parent: &mut ObscuraJsRuntime,
    ) -> Result<Vec<DocumentInlineStylesheet>, String> {
        let fallback_base = self
            .fallback_document_base_url()
            .map(|url| url.to_string())
            .unwrap_or_else(|| self.url.clone());
        let listed = self.evaluate(
            parent,
            &format!(
                r#"(function(){{
                  let activeBase = {};
                  let foundBase = false;
                  let authorIndex = 0;
                  const stylesheets = [];
                  let parserOrder = 0;
                  const parserNodes = document.querySelectorAll(
                    'base[href],body,script,link[rel~="stylesheet"],style'
                  );
                  for (const node of parserNodes) {{
                    if (node.localName === 'base') {{
                      if (!foundBase) {{
                        foundBase = true;
                        try {{ activeBase = new URL(node.getAttribute('href'), activeBase).href; }}
                        catch (_) {{}}
                      }}
                      continue;
                    }}
                    const order = parserOrder++;
                    if (node.localName !== 'style') continue;
                    if (node.hasAttribute('data-obscura-adopted')
                        || node.hasAttribute('data-obscura-linked')
                        || node.hasAttribute('data-obscura-external-stylesheets')
                        || node.hasAttribute('data-obscura-inline-import')
                        || node.hasAttribute('data-obscura-imports-materialized')) continue;
                    const type = (node.getAttribute('type') || '').trim().toLowerCase();
                    if (type && type !== 'text/css') continue;
                    stylesheets.push({{
                      authorIndex: authorIndex++,
                      nid: node._nid,
                      text: node.textContent || '',
                      media: node.getAttribute('media') || '',
                      baseUrl: activeBase,
                      parserOrder: order,
                    }});
                  }}
                  return stylesheets;
                }})()"#,
                encode_json_argument(&fallback_base),
            ),
        );
        match listed {
            Ok(value) => serde_json::from_value(value)
                .map_err(|error| format!("could not decode frame inline stylesheets: {error}")),
            Err(error) => Err(format!("could not list frame inline stylesheets: {error}")),
        }
    }

    fn list_parser_body_order(
        &self,
        parent: &mut ObscuraJsRuntime,
    ) -> Result<Option<usize>, String> {
        self.evaluate(
            parent,
            r#"(function(){
              let parserOrder = 0;
              const parserNodes = document.querySelectorAll(
                'base[href],body,script,link[rel~="stylesheet"]'
              );
              for (const node of parserNodes) {
                if (node.localName === 'base') continue;
                const order = parserOrder++;
                if (node.localName === 'body') return order;
              }
              return null;
            })()"#,
        )
        .map_err(|error| format!("could not locate frame body encounter: {error}"))
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| format!("could not decode frame body encounter: {error}"))
        })
    }
}

fn remaining_budget_ms(deadline: tokio::time::Instant) -> Option<u64> {
    let remaining = deadline.checked_duration_since(tokio::time::Instant::now())?;
    if remaining.is_zero() {
        return None;
    }
    let millis = remaining
        .as_millis()
        .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0));
    Some(millis.min(u128::from(u64::MAX)) as u64)
}

#[derive(Clone, serde::Deserialize)]
struct DocumentScript {
    nid: u32,
    src: String,
    #[serde(rename = "type")]
    type_attribute: String,
    text: String,
    #[serde(rename = "async")]
    async_attribute: bool,
    #[serde(rename = "defer")]
    defer_attribute: bool,
    #[serde(rename = "baseUrl")]
    base_url: String,
    #[serde(rename = "parserOrder")]
    parser_order: usize,
}

#[derive(serde::Deserialize)]
struct DocumentStylesheet {
    nid: u32,
    link_index: usize,
    href: String,
    disabled: bool,
    loaded: bool,
    parser_pending: bool,
    import_depth: u8,
    #[serde(rename = "baseUrl")]
    base_url: String,
    #[serde(rename = "parserOrder")]
    parser_order: usize,
}

#[derive(serde::Deserialize)]
struct DocumentInlineStylesheet {
    #[serde(rename = "authorIndex")]
    author_index: usize,
    nid: u32,
    text: String,
    media: String,
    #[serde(rename = "baseUrl")]
    base_url: String,
    #[serde(rename = "parserOrder")]
    parser_order: usize,
}

impl DocumentScript {
    /// An empty type, or a JavaScript MIME type, is a classic script. Anything
    /// else is data or a module.
    fn is_classic(&self) -> bool {
        self.type_attribute.is_empty()
            || matches!(
                self.type_attribute.as_str(),
                "text/javascript" | "application/javascript" | "text/ecmascript"
            )
    }
}

/// Embeds a string in JavaScript source as a literal, so a payload holding
/// quotes or newlines cannot end the literal and be read as code.
fn encode_json_argument(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

/// Serializes an origin the way `location.origin` does, using `"null"` for
/// schemes that have no tuple origin.
fn origin_of(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(parsed) => {
            let origin = parsed.origin();
            if origin.is_tuple() {
                origin.ascii_serialization()
            } else {
                "null".to_string()
            }
        }
        Err(_) => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn spawn_frame_module_server(expected_requests: usize) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let length = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..length]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/");
                let (status, body) = match path {
                    "/dep.js" => ("200 OK", "export const value = 'static';"),
                    "/dynamic.js" => ("200 OK", "export const value = 'dynamic';"),
                    _ => ("404 Not Found", "not found"),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\n\
                     Content-Type: application/javascript\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len(),
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        format!("http://{address}")
    }

    fn install_local_module_client(runtime: &ObscuraJsRuntime) {
        let jar = std::sync::Arc::new(obscura_net::CookieJar::new());
        runtime.set_http_client(std::sync::Arc::new(
            obscura_net::ObscuraHttpClient::with_full_options(jar, None, true),
        ));
    }

    fn page(url: &str, html: &str) -> ObscuraJsRuntime {
        let mut runtime = ObscuraJsRuntime::new();
        runtime.set_dom(parse_html(html));
        runtime.set_url(url);
        runtime.run_page_init();
        runtime
    }

    fn streaming_frame(
        parent: &mut ObscuraJsRuntime,
        html: &str,
        scripts_allowed: bool,
    ) -> FrameRealm {
        FrameRealm::new_streaming_staged_with_inherited_context_and_script_policy(
            parent,
            1,
            0,
            "https://child.example/frame.html",
            None,
            None,
            html,
            scripts_allowed,
        )
        .expect("streaming frame realm")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn streaming_frame_blocking_script_cannot_see_parser_tail() {
        let mut parent = page(
            "https://parent.example/",
            "<html><body><iframe></iframe></body></html>",
        );
        let frame = streaming_frame(
            &mut parent,
            concat!(
                "<!doctype html><html><body>",
                "<script>globalThis.__tailAtPause = document.getElementById('tail') !== null;</script>",
                "<div id='tail'>after script</div>",
                "</body></html>",
            ),
            true,
        );

        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |_| None,
                std::collections::BTreeMap::new(),
                1_000,
            )
            .await;

        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "[globalThis.__tailAtPause, document.getElementById('tail')?.textContent]",
                )
                .unwrap(),
            serde_json::json!([false, "after script"]),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn streaming_frame_document_write_splices_primary_tokenizer_recursively() {
        let mut parent = page(
            "https://parent.example/",
            "<html><body><iframe></iframe></body></html>",
        );
        let frame = streaming_frame(
            &mut parent,
            concat!(
                "<!doctype html><html><body>",
                "<script>",
                "globalThis.__writeOrder=['outer-before'];",
                "document.write('<script>__writeOrder.push(\\\"nested\\\");",
                "document.write(\\\"<span id=written>inserted</span>\\\");<\\/script>');",
                "__writeOrder.push('outer-after');",
                "</script>",
                "<script>__writeOrder.push(document.getElementById('source-tail')?'tail-seen':'tail-hidden');</script>",
                "<div id='source-tail'>tail</div>",
                "</body></html>",
            ),
            true,
        );

        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |_| None,
                std::collections::BTreeMap::new(),
                1_000,
            )
            .await;

        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "[globalThis.__writeOrder, document.getElementById('written')?.textContent, !!document.getElementById('source-tail')]",
                )
                .unwrap(),
            serde_json::json!([
                ["outer-before", "nested", "outer-after", "tail-hidden"],
                "inserted",
                true,
            ]),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn streaming_frame_external_defer_runs_at_eof_in_encounter_order() {
        let mut parent = page(
            "https://parent.example/",
            "<html><body><iframe></iframe></body></html>",
        );
        let frame = streaming_frame(
            &mut parent,
            concat!(
                "<!doctype html><html><body>",
                "<script>globalThis.__streamOrder = [];globalThis.__streamReady = [];",
                "document.addEventListener('readystatechange',()=>__streamReady.push(document.readyState));",
                "document.addEventListener('DOMContentLoaded',()=>__streamReady.push('dcl:'+document.readyState));</script>",
                "<script defer src='/first.js'></script>",
                "<script>__streamOrder.push('blocking:' + (document.getElementById('tail') !== null));</script>",
                "<span id='tail'></span>",
                "<script defer src='/second.js'></script>",
                "</body></html>",
            ),
            true,
        );

        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |url| {
                    if url.ends_with("/first.js") {
                        Some(
                            "__streamOrder.push('first:' + document.readyState + ':' + (document.getElementById('tail') !== null));"
                                .to_string(),
                        )
                    } else if url.ends_with("/second.js") {
                        Some(
                            "__streamOrder.push('second:' + document.readyState + ':' + (document.getElementById('tail') !== null));"
                                .to_string(),
                        )
                    } else {
                        None
                    }
                },
                std::collections::BTreeMap::new(),
                1_000,
            )
            .await;

        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        assert_eq!(
            frame
                .evaluate(&mut parent, "globalThis.__streamOrder")
                .unwrap(),
            serde_json::json!([
                "blocking:false",
                "first:interactive:true",
                "second:interactive:true"
            ]),
        );
        assert_eq!(
            frame
                .evaluate(&mut parent, "globalThis.__streamReady")
                .unwrap(),
            serde_json::json!(["interactive"]),
        );
        frame.dispatch_dom_content_loaded(&mut parent).unwrap();
        assert_eq!(
            frame
                .evaluate(&mut parent, "globalThis.__streamReady")
                .unwrap(),
            serde_json::json!(["interactive", "dcl:interactive"]),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn streaming_frame_reselects_media_when_source_appears_after_parser_pause() {
        let mut parent = page(
            "https://parent.example/",
            "<html><body><iframe></iframe></body></html>",
        );
        let frame = streaming_frame(
            &mut parent,
            concat!(
                "<!doctype html><video id='movie'>",
                "<script>globalThis.__mediaBeforeSource = document.getElementById('movie').networkState;</script>",
                "<source src='data:video/mp4;base64,AA=='>",
                "<script>globalThis.__mediaAfterSource = document.getElementById('movie').currentSrc;</script>",
                "</video>",
                "<video id='direct' src='data:video/mp4;base64,AQ=='>",
                "<script>globalThis.__directBeforeSource = [document.getElementById('direct').currentSrc,document.getElementById('direct')._mediaRequest];</script>",
                "<source src='data:video/mp4;base64,Ag=='>",
                "<script>globalThis.__directAfterSource = [document.getElementById('direct').currentSrc,document.getElementById('direct')._mediaRequest];</script>",
                "</video>",
            ),
            true,
        );

        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |_| None,
                std::collections::BTreeMap::new(),
                1_000,
            )
            .await;

        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "[globalThis.__mediaBeforeSource, globalThis.__mediaAfterSource, globalThis.__directBeforeSource, globalThis.__directAfterSource]",
                )
                .unwrap(),
            serde_json::json!([
                3,
                "data:video/mp4;base64,AA==",
                ["data:video/mp4;base64,AQ==", 1],
                ["data:video/mp4;base64,AQ==", 1]
            ]),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn streaming_parser_resource_bridge_resists_author_weakset_poisoning() {
        let mut parent = page(
            "https://parent.example/",
            "<html><body><iframe></iframe></body></html>",
        );
        let frame = streaming_frame(
            &mut parent,
            concat!(
                "<!doctype html><html><body>",
                "<script>",
                "globalThis.__parserPrivateNames = [typeof _parserResourcePreparation, typeof _startParserCreatedResources];",
                "globalThis.__parserBridgeOriginal = globalThis.__obscura_startParserCreatedResources;",
                "const descriptor = Object.getOwnPropertyDescriptor(globalThis, '__obscura_startParserCreatedResources');",
                "globalThis.__parserBridgeDescriptor = [descriptor.writable, descriptor.enumerable, descriptor.configurable];",
                "globalThis.__parserBridgeDefineRejected = false;",
                "try { Object.defineProperty(globalThis, '__obscura_startParserCreatedResources', { value() { throw new Error('replaced'); } }); }",
                "catch (_) { globalThis.__parserBridgeDefineRejected = true; }",
                "globalThis.__obscura_startParserCreatedResources = () => { throw new Error('assigned'); };",
                "globalThis._parserResourcePreparation = { has() { throw new Error('forged private state'); } };",
                "globalThis._startParserCreatedResources = () => { throw new Error('forged helper'); };",
                "globalThis.__savedWeakSet = WeakSet;",
                "globalThis.__savedWeakSetHas = WeakSet.prototype.has;",
                "globalThis.__savedWeakSetAdd = WeakSet.prototype.add;",
                "globalThis.__poisonImageQueueCalls = 0;",
                "globalThis.__originalPoisonImageQueue = HTMLImageElement.prototype._queueImageRequest;",
                "HTMLImageElement.prototype._queueImageRequest = function(...args) { __poisonImageQueueCalls++; return __originalPoisonImageQueue.apply(this, args); };",
                "WeakSet.prototype.has = () => { throw new Error('poisoned has'); };",
                "WeakSet.prototype.add = () => { throw new Error('poisoned add'); };",
                "globalThis.WeakSet = class PoisonedWeakSet { constructor() { throw new Error('poisoned constructor'); } };",
                "</script>",
                "<img id='poison-image' src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAIAAAADCAYAAAC56t6BAAAAFklEQVR4nGP8z8Dwn4GBgYGJAQrgDAAxOwIE7x6DkQAAAABJRU5ErkJggg=='>",
                "<video id='poison-media' src='data:video/mp4;base64,AA=='></video>",
                "<script>",
                "const poisonImage = document.getElementById('poison-image');",
                "const poisonMedia = document.getElementById('poison-media');",
                "const poisonImagePrepared = poisonImage._imageQueued || (poisonImage._imageComplete && poisonImage._imageDecoded);",
                "globalThis.__poisonSweepState = [",
                "  globalThis.__obscura_startParserCreatedResources === globalThis.__parserBridgeOriginal,",
                "  globalThis.__poisonImageQueueCalls, poisonImagePrepared, poisonMedia._mediaRequest, poisonMedia.currentSrc",
                "];",
                "HTMLImageElement.prototype._queueImageRequest = globalThis.__originalPoisonImageQueue;",
                "globalThis.__savedWeakSet.prototype.has = globalThis.__savedWeakSetHas;",
                "globalThis.__savedWeakSet.prototype.add = globalThis.__savedWeakSetAdd;",
                "globalThis.WeakSet = globalThis.__savedWeakSet;",
                "</script>",
                "</body></html>",
            ),
            true,
        );

        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |_| None,
                std::collections::BTreeMap::new(),
                1_000,
            )
            .await;

        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "[globalThis.__parserPrivateNames, globalThis.__parserBridgeDescriptor, globalThis.__parserBridgeDefineRejected, globalThis.__poisonSweepState]",
                )
                .unwrap(),
            serde_json::json!([
                ["undefined", "undefined"],
                [false, false, false],
                true,
                [true, 1, true, 1, "data:video/mp4;base64,AA=="]
            ]),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn streaming_parser_eof_resource_sweep_is_idempotent_across_resource_types() {
        let mut parent = page(
            "https://parent.example/",
            "<html><body><iframe></iframe></body></html>",
        );
        let frame = streaming_frame(
            &mut parent,
            concat!(
                "<!doctype html><html><body>",
                "<script>",
                "globalThis.__resourceSweepCalls = { image: 0, media: 0, poster: 0, track: 0, frame: 0 };",
                "globalThis.__originalImageQueue = HTMLImageElement.prototype._queueImageRequest;",
                "globalThis.__originalMediaQueue = HTMLMediaElement.prototype._queueMediaRequest;",
                "globalThis.__originalPosterQueue = HTMLVideoElement.prototype._queuePosterRequest;",
                "globalThis.__originalTrackQueue = HTMLTrackElement.prototype._queueTrackRequest;",
                "globalThis.__originalBlankLoad = HTMLIFrameElement.prototype._loadIframeBlank;",
                "HTMLImageElement.prototype._queueImageRequest = function(...args) { __resourceSweepCalls.image++; return __originalImageQueue.apply(this, args); };",
                "HTMLMediaElement.prototype._queueMediaRequest = function(...args) { __resourceSweepCalls.media++; return __originalMediaQueue.apply(this, args); };",
                "HTMLVideoElement.prototype._queuePosterRequest = function(...args) { __resourceSweepCalls.poster++; return __originalPosterQueue.apply(this, args); };",
                "HTMLTrackElement.prototype._queueTrackRequest = function(...args) { __resourceSweepCalls.track++; return __originalTrackQueue.apply(this, args); };",
                "HTMLIFrameElement.prototype._loadIframeBlank = function(...args) { __resourceSweepCalls.frame++; return __originalBlankLoad.apply(this, args); };",
                "</script>",
                "<img id='eof-image' src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAIAAAADCAYAAAC56t6BAAAAFklEQVR4nGP8z8Dwn4GBgYGJAQrgDAAxOwIE7x6DkQAAAABJRU5ErkJggg=='>",
                "<video id='eof-media' src='data:video/mp4;base64,AA==' poster='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAIAAAADCAYAAAC56t6BAAAAFklEQVR4nGP8z8Dwn4GBgYGJAQrgDAAxOwIE7x6DkQAAAABJRU5ErkJggg=='>",
                "<track id='eof-track' default src='data:text/vtt,WEBVTT'>",
                "</video>",
                "<iframe id='eof-frame' src='about:blank'></iframe>",
                "</body></html>",
            ),
            true,
        );

        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |_| None,
                std::collections::BTreeMap::new(),
                1_000,
            )
            .await;
        assert!(problems.is_empty(), "unexpected problems: {problems:?}");

        // data: media/poster requests complete locally. Pump their promise
        // reactions so this regression also proves they never fall into the
        // HTTP-only page transport when synchronous render loading is off.
        parent.run_event_loop_bounded(100).await.unwrap();

        // The parser driver sweeps after the final resume and again at its EOF
        // transition. Repeating the fixed bridge here must still be a no-op.
        frame
            .execute_script(
                &mut parent,
                "globalThis.__obscura_startParserCreatedResources(); globalThis.__obscura_startParserCreatedResources();",
            )
            .unwrap();
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "(() => { const image = document.getElementById('eof-image'); const media = document.getElementById('eof-media'); return [globalThis.__resourceSweepCalls, image._imageQueued || (image._imageComplete && image._imageDecoded), media._mediaRequest, media.readyState, media.networkState, media._posterRequest, media._posterQueued, document.getElementById('eof-track').readyState, document.getElementById('eof-frame')._iframeLoadingUrl]; })()",
                )
                .unwrap(),
            serde_json::json!([
                {"image": 1, "media": 1, "poster": 1, "track": 1, "frame": 1},
                true,
                1,
                1,
                1,
                1,
                false,
                2,
                "about:blank"
            ]),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn streaming_frame_async_script_completion_is_inside_load_gate() {
        let mut parent = page(
            "https://parent.example/",
            "<html><body><iframe></iframe></body></html>",
        );
        let frame = streaming_frame(
            &mut parent,
            concat!(
                "<!doctype html><html><body>",
                "<script>globalThis.__asyncEvents = [];</script>",
                "<script async src='/async.js' onload=\"__asyncEvents.push('load')\"></script>",
                "<div id='tail'></div>",
                "</body></html>",
            ),
            true,
        );

        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |url| {
                    url.ends_with("/async.js").then(|| {
                        "__asyncEvents.push('body:' + (document.getElementById('tail') !== null));"
                            .to_string()
                    })
                },
                std::collections::BTreeMap::new(),
                1_000,
            )
            .await;

        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "[globalThis.__asyncEvents, document.getElementById('tail') !== null]",
                )
                .unwrap(),
            serde_json::json!([["body:false", "load"], true]),
            "the scheduler returned before async execution and its owner load event completed",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn streaming_frame_generation_change_rejects_stale_external_source() {
        let mut parent = page(
            "https://parent.example/",
            "<html><body><iframe></iframe></body></html>",
        );
        let frame = streaming_frame(
            &mut parent,
            concat!(
                "<!doctype html><html><body>",
                "<script src='/stale.js'></script>",
                "<div id='tail'></div>",
                "</body></html>",
            ),
            true,
        );

        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |_| {
                    assert!(frame.invalidate_document_generation());
                    Some("globalThis.__staleExternalRan = true;".to_string())
                },
                std::collections::BTreeMap::new(),
                1_000,
            )
            .await;

        assert!(
            problems.iter().any(|problem| problem.contains("replaced")),
            "generation cancellation was not reported: {problems:?}",
        );
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "[typeof globalThis.__staleExternalRan, document.getElementById('tail') !== null]",
                )
                .unwrap(),
            serde_json::json!(["undefined", false]),
            "stale script work or parser tail escaped after generation invalidation",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn streaming_frame_detach_stops_later_parser_work() {
        let mut parent = page(
            "https://child.example/parent.html",
            "<html><body><iframe></iframe></body></html>",
        );
        let frame = streaming_frame(
            &mut parent,
            concat!(
                "<!doctype html><html><body>",
                "<script>globalThis.__firstRan=true;</script>",
                "<script>globalThis.__staleTailScript=true;</script>",
                "<div id='tail'></div>",
                "</body></html>",
            ),
            true,
        );
        parent
            .execute_script(
                "detach-streaming-owner",
                "document.querySelector('iframe').remove();",
            )
            .unwrap();

        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |_| None,
                std::collections::BTreeMap::new(),
                1_000,
            )
            .await;

        assert!(
            problems.iter().any(|problem| problem.contains("detached")),
            "detachment was not reported: {problems:?}",
        );
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "[globalThis.__firstRan, typeof globalThis.__staleTailScript, document.getElementById('tail') !== null]",
                )
                .unwrap(),
            serde_json::json!([serde_json::Value::Null, "undefined", false]),
        );
    }

    #[test]
    fn frame_has_its_own_realm_dom_and_origin() {
        let mut parent = page(
            "https://parent.example/page",
            "<html><body><h1>Parent</h1></body></html>",
        );
        parent
            .execute_script("p", "globalThis.marker = 'parent';")
            .unwrap();

        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/frame",
            "<html><body><h1>Child</h1></body></html>",
        )
        .expect("frame realm");

        frame
            .execute_script(&mut parent, "globalThis.marker = 'child';")
            .unwrap();

        // Separate realm: own globals, own DOM, own URL.
        assert_eq!(
            frame
                .evaluate(&mut parent, "document.querySelector('h1').textContent")
                .unwrap(),
            serde_json::json!("Child")
        );
        assert_eq!(
            frame.evaluate(&mut parent, "globalThis.marker").unwrap(),
            serde_json::json!("child")
        );
        assert_eq!(
            frame.evaluate(&mut parent, "location.href").unwrap(),
            serde_json::json!("https://child.example/frame")
        );

        // The parent keeps its own document and globals throughout.
        assert_eq!(
            parent
                .evaluate("document.querySelector('h1').textContent")
                .unwrap(),
            serde_json::json!("Parent")
        );
        assert_eq!(
            parent.evaluate("globalThis.marker").unwrap(),
            serde_json::json!("parent")
        );

        assert_eq!(frame.origin(), "https://child.example");
        assert_eq!(frame.frame_id(), 1);
        assert!(!frame.is_same_origin_as("https://parent.example"));
        assert!(frame.is_same_origin_as("https://child.example"));
    }

    #[test]
    fn frame_host_probes_ignore_author_json_stringify() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            100,
            0,
            "https://child.example/frame",
            "<html><body><iframe></iframe></body></html>",
        )
        .expect("frame realm");
        let live_frame_ids = frame
            .evaluate(
                &mut parent,
                "(document.querySelector('iframe'), globalThis.__obscura_liveFrameIds())",
            )
            .expect("initial liveness probe");
        assert!(
            live_frame_ids.is_array(),
            "liveness must remain an id array"
        );

        frame
            .execute_script(&mut parent, r#"JSON.stringify = () => "true";"#)
            .expect("author mutations");

        assert_eq!(
            frame
                .evaluate(&mut parent, "globalThis.__obscura_liveFrameIds()")
                .expect("liveness probe after JSON mutation"),
            live_frame_ids,
        );
        assert!(!frame.has_pending_dynamic_scripts(&mut parent));
        assert!(!frame.has_pending_load_delaying_resources(&mut parent));
        assert_eq!(
            frame
                .evaluate(&mut parent, "({ native: true, values: [1, 2] })")
                .expect("native V8 conversion"),
            serde_json::json!({"native": true, "values": [1, 2]}),
        );
    }

    #[test]
    fn frame_cannot_reach_host_ops_after_handoff() {
        let mut parent = page(
            "https://parent.example/",
            "<html><body><p id='parent'>parent</p></body></html>",
        );
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/frame",
            "<html><body><p id='child'>child</p></body></html>",
        )
        .expect("frame realm");

        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    r#"({
                        deno: typeof Deno,
                        core: typeof _core,
                        handoff: typeof globalThis.__obscura_core_handoff,
                        ownerHelper: typeof _fetchWithResourceOwner,
                        dom: document.getElementById('child').textContent,
                        fetch: typeof fetch,
                    })"#,
                )
                .unwrap(),
            serde_json::json!({
                "deno": "undefined",
                "core": "undefined",
                "handoff": "undefined",
                "ownerHelper": "undefined",
                "dom": "child",
                "fetch": "function",
            }),
        );
    }

    #[test]
    fn frame_shadow_ops_use_the_frame_dom_when_node_ids_collide() {
        const HTML: &str = "<!doctype html><main id='outer'></main>";
        const SCRIPT: &str = r#"
            globalThis.__shadowRuns = (globalThis.__shadowRuns || 0) + 1;
            const outer = document.getElementById('outer');
            const outerRoot = outer.attachShadow({ mode: 'closed' });
            const inner = document.createElement('section');
            outerRoot.appendChild(inner);
            const innerRoot = inner.attachShadow({ mode: 'closed' });
            innerRoot.appendChild(document.createElement('span'));
            globalThis.__outerHost = outer;
            globalThis.__innerHost = inner;
        "#;

        let mut parent = page("https://parent.example/", HTML);
        parent.execute_script("<top-shadow>", SCRIPT).unwrap();
        let frame = FrameRealm::new(&mut parent, 1, 0, "https://parent.example/frame.html", HTML)
            .expect("frame realm");

        // Node ids are document-local and deliberately collide here. Shadow
        // ops must therefore resolve the realm before consulting the tree.
        let parent_host_nid = parent
            .evaluate("document.getElementById('outer')._nid")
            .unwrap()
            .as_f64();
        let frame_host_nid = frame
            .evaluate(&mut parent, "document.getElementById('outer')._nid")
            .unwrap()
            .as_f64();
        assert_eq!(parent_host_nid, frame_host_nid);
        frame
            .execute_script(&mut parent, SCRIPT)
            .expect("frame nested closed shadows");

        assert_eq!(
            parent.evaluate("globalThis.__shadowRuns").unwrap().as_f64(),
            Some(1.0),
        );
        assert_eq!(
            frame
                .evaluate(&mut parent, "globalThis.__shadowRuns")
                .unwrap()
                .as_f64(),
            Some(1.0),
        );
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "__outerHost.shadowRoot === null && __innerHost.shadowRoot === null",
                )
                .unwrap(),
            serde_json::json!(true),
        );
    }

    #[test]
    fn parser_created_srcdoc_keeps_about_location_and_inherits_parent_base() {
        let mut parent = page(
            "https://parent.example/path/page.html",
            concat!(
                "<!doctype html><base href='https://cdn.example/assets/'>",
                "<iframe src='https://ignored.example/frame.html' ",
                "srcdoc=\"<!doctype html><script src='child.js'></script>",
                "<img src='child.png'>\"></iframe>",
            ),
        );
        let pending = parent.take_pending_frames();
        assert_eq!(pending.len(), 1);
        let pending = pending.into_iter().next().unwrap();
        assert_eq!(pending.url, "about:srcdoc");
        assert_eq!(
            pending.inherited_base_url.as_deref(),
            Some("https://cdn.example/assets/"),
        );
        assert_eq!(
            pending.inherited_origin.as_deref(),
            Some("https://parent.example"),
        );

        let frame = FrameRealm::new_with_inherited_context(
            &mut parent,
            pending.frame_id,
            pending.parent_frame_id,
            &pending.url,
            pending.inherited_base_url.as_deref(),
            pending.inherited_origin.as_deref(),
            &pending.html,
        )
        .expect("srcdoc frame realm");
        let requested = std::cell::RefCell::new(Vec::new());
        let problems = frame.run_document_scripts(&mut parent, |url| {
            requested.borrow_mut().push(url.to_string());
            Some("globalThis.__srcdocExternalRan = true;".to_string())
        });
        assert!(problems.is_empty(), "srcdoc script problems: {problems:?}");
        assert_eq!(
            requested.into_inner(),
            vec!["https://cdn.example/assets/child.js"],
        );
        assert_eq!(frame.url(), "about:srcdoc");
        assert_eq!(frame.origin(), "https://parent.example");
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "({url:document.URL,base:document.baseURI,ran:globalThis.__srcdocExternalRan,img:document.querySelector('img').src})",
                )
                .unwrap(),
            serde_json::json!({
                "url": "about:srcdoc",
                "base": "https://cdn.example/assets/",
                "ran": true,
                "img": "https://cdn.example/assets/child.png",
            }),
        );
    }

    #[test]
    fn initial_blank_window_proxy_survives_managed_realm_commit_and_removal() {
        let mut parent = page(
            "https://parent.example/path/page.html",
            "<!doctype html><iframe id='child'></iframe>",
        );
        assert_eq!(
            parent
                .evaluate(
                    r#"(() => {
                      const frame = document.getElementById('child');
                      globalThis.__savedBlankWindow = frame.contentWindow;
                      return {
                        href: __savedBlankWindow.location.href,
                        origin: __savedBlankWindow.location.origin,
                        document: frame.contentDocument === __savedBlankWindow.document,
                      };
                    })()"#,
                )
                .unwrap(),
            serde_json::json!({
                "href": "about:blank",
                "origin": "https://parent.example",
                "document": true,
            }),
        );

        let mut pending = parent.take_pending_frames();
        assert_eq!(pending.len(), 1, "initial about:blank was not managed");
        let pending = pending.remove(0);
        assert_eq!(pending.url, "about:blank");
        assert_eq!(
            pending.inherited_base_url.as_deref(),
            Some("https://parent.example/path/page.html"),
        );
        assert_eq!(
            pending.inherited_origin.as_deref(),
            Some("https://parent.example"),
        );

        let frame = FrameRealm::new_with_inherited_context(
            &mut parent,
            pending.frame_id,
            pending.parent_frame_id,
            &pending.url,
            pending.inherited_base_url.as_deref(),
            pending.inherited_origin.as_deref(),
            &pending.html,
        )
        .expect("managed initial blank realm");
        assert_eq!(parent.managed_realm_count(), 1);
        frame
            .execute_script(&mut parent, "globalThis.__managedBlankMarker = 'realm';")
            .unwrap();
        frame.dispatch_load_events(&mut parent).unwrap();

        assert_eq!(
            parent
                .evaluate(
                    r#"(() => {
                      const current = document.getElementById('child').contentWindow;
                      return {
                        identity: __savedBlankWindow === current,
                        marker: __savedBlankWindow.__managedBlankMarker,
                        document: __savedBlankWindow.document === document.getElementById('child').contentDocument,
                        readyState: __savedBlankWindow.document.readyState,
                      };
                    })()"#,
                )
                .unwrap(),
            serde_json::json!({
                "identity": true,
                "marker": "realm",
                "document": true,
                "readyState": "complete",
            }),
        );

        parent
            .execute_script(
                "replace-frame",
                "document.getElementById('child').srcdoc = '<!doctype html><p>replacement</p>';",
            )
            .unwrap();
        let mut replacement = parent.take_pending_frames();
        assert_eq!(replacement.len(), 1);
        let replacement = replacement.remove(0);
        assert_eq!(replacement.url, "about:srcdoc");
        assert_ne!(replacement.frame_id, frame.frame_id());
        let replacement_realm = FrameRealm::new_with_inherited_context(
            &mut parent,
            replacement.frame_id,
            replacement.parent_frame_id,
            &replacement.url,
            replacement.inherited_base_url.as_deref(),
            replacement.inherited_origin.as_deref(),
            &replacement.html,
        )
        .expect("replacement realm");
        assert_eq!(parent.managed_realm_count(), 2);
        replacement_realm
            .execute_script(&mut parent, "globalThis.__replacementMarker = 'new-realm';")
            .unwrap();
        assert_eq!(
            parent
                .evaluate(
                    r#"({
                      identity: __savedBlankWindow === document.getElementById('child').contentWindow,
                      oldMarker: typeof __savedBlankWindow.__managedBlankMarker,
                      replacementMarker: __savedBlankWindow.__replacementMarker,
                    })"#,
                )
                .unwrap(),
            serde_json::json!({
                "identity": true,
                "oldMarker": "undefined",
                "replacementMarker": "new-realm",
            }),
        );

        // Committing the replacement has already moved the stable proxy's
        // backend away from the initial blank context. Its host realm can now
        // be retired without changing proxy identity or exposing stale data.
        drop(frame);
        assert_eq!(parent.managed_realm_count(), 1);
        assert_eq!(
            parent
                .evaluate(
                    "({ identity: __savedBlankWindow === document.getElementById('child').contentWindow, replacementMarker: __savedBlankWindow.__replacementMarker })",
                )
                .unwrap(),
            serde_json::json!({"identity": true, "replacementMarker": "new-realm"}),
        );

        // Removal synchronously detaches the proxy backend before the host can
        // drop the FrameRealm. A page-held WindowProxy must remain safe to
        // inspect and must no longer retain author globals from the old realm.
        parent
            .execute_script("remove-frame", "document.getElementById('child').remove();")
            .unwrap();
        assert_eq!(
            parent
                .evaluate(
                    "({ marker: typeof __savedBlankWindow.__managedBlankMarker, href: __savedBlankWindow.location.href })",
                )
                .unwrap(),
            serde_json::json!({"marker": "undefined", "href": "about:blank"}),
        );
        drop(replacement_realm);
        assert_eq!(parent.managed_realm_count(), 0);
        assert_eq!(
            parent
                .evaluate("typeof __savedBlankWindow.document")
                .unwrap(),
            serde_json::json!("object"),
            "saved proxy became unsafe after managed realm drop",
        );
    }

    #[test]
    fn repeated_staged_frame_churn_retires_every_managed_realm() {
        let mut parent = page(
            "https://parent.example/",
            "<!doctype html><html><body></body></html>",
        );

        for frame_id in 1..=32 {
            let frame = FrameRealm::new_staged_with_inherited_context(
                &mut parent,
                frame_id,
                0,
                &format!("https://child.example/{frame_id}.html"),
                None,
                None,
                "<!doctype html><p>frame</p>",
            )
            .expect("staged frame realm");
            let managed = frame.module_realm.clone();
            assert_eq!(parent.managed_realm_count(), 1);

            drop(frame);

            assert_eq!(parent.managed_realm_count(), 0);
            assert!(managed.is_retired());
            assert!(!managed.retire(), "retirement must be idempotent");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retired_managed_realm_is_not_polled_again() {
        let mut parent = page(
            "https://parent.example/",
            "<!doctype html><html><body></body></html>",
        );
        let frame = FrameRealm::new_staged_with_inherited_context(
            &mut parent,
            1,
            0,
            "https://child.example/frame.html",
            None,
            None,
            "<!doctype html><p>frame</p>",
        )
        .expect("staged frame realm");
        let managed = frame.module_realm.clone();

        parent.run_event_loop().await.unwrap();
        let polls_before_retirement = managed.event_loop_poll_count();
        assert!(polls_before_retirement > 0);

        drop(frame);
        assert_eq!(parent.managed_realm_count(), 0);
        assert!(managed.is_retired());

        // Advance a real main-realm microtask and event-loop turn. A stale
        // registry entry would increment the retired realm's diagnostic count
        // even if its ModuleMap happened to have no pending work.
        parent
            .execute_script(
                "main-after-frame-retirement",
                "Promise.resolve().then(() => { globalThis.__mainAfterRetire = true; });",
            )
            .unwrap();
        parent.run_event_loop().await.unwrap();
        assert_eq!(managed.event_loop_poll_count(), polls_before_retirement,);
        assert_eq!(
            parent.evaluate("globalThis.__mainAfterRetire").unwrap(),
            serde_json::json!(true),
        );
    }

    #[test]
    fn sandboxed_initial_blank_has_an_opaque_origin() {
        let mut parent = page(
            "https://parent.example/page.html",
            "<!doctype html><iframe id='child' sandbox src='about:blank#section'></iframe>",
        );
        assert_eq!(
            parent
                .evaluate(
                    r#"(() => {
                      const frame = document.getElementById('child');
                      globalThis.__sandboxWindow = frame.contentWindow;
                      return {
                        href: __sandboxWindow.location.href,
                        origin: __sandboxWindow.location.origin,
                        documentBlocked: frame.contentDocument === null,
                        proxyDocumentBlocked: typeof __sandboxWindow.document === 'undefined',
                      };
                    })()"#,
                )
                .unwrap(),
            serde_json::json!({
                "href": "about:blank#section",
                "origin": "null",
                "documentBlocked": true,
                "proxyDocumentBlocked": true,
            }),
        );

        let mut pending = parent.take_pending_frames();
        assert_eq!(pending.len(), 1);
        let pending = pending.remove(0);
        assert_eq!(pending.url, "about:blank#section");
        assert_eq!(pending.inherited_origin.as_deref(), Some("null"));
        assert!(!pending.scripts_allowed);
        let frame = FrameRealm::new_staged_with_inherited_context_and_script_policy(
            &mut parent,
            pending.frame_id,
            pending.parent_frame_id,
            &pending.url,
            pending.inherited_base_url.as_deref(),
            pending.inherited_origin.as_deref(),
            &pending.html,
            pending.scripts_allowed,
        )
        .expect("sandboxed blank realm");
        assert!(frame.publish_to_owners(&mut parent));
        frame
            .execute_script(&mut parent, "globalThis.__sandboxSecret = 'hidden';")
            .unwrap();
        assert_eq!(frame.origin(), "null");
        assert_eq!(
            parent
                .evaluate(
                    "({ same: __sandboxWindow === document.getElementById('child').contentWindow, secret: typeof __sandboxWindow.__sandboxSecret })",
                )
                .unwrap(),
            serde_json::json!({"same": true, "secret": "undefined"}),
        );
    }

    #[test]
    fn iframe_allow_scripts_policy_is_captured_in_each_pending_navigation() {
        let parent = page(
            "https://parent.example/page.html",
            concat!(
                "<!doctype html>",
                "<iframe sandbox srcdoc='<p>blocked</p>'></iframe>",
                "<iframe sandbox='ALLOW-SCRIPTS allow-same-origin' srcdoc='<p>allowed</p>'></iframe>",
                "<iframe srcdoc='<p>ordinary</p>'></iframe>",
            ),
        );
        let pending = parent.take_pending_frames();
        assert_eq!(pending.len(), 3);
        assert_eq!(
            pending
                .iter()
                .map(|frame| frame.scripts_allowed)
                .collect::<Vec<_>>(),
            vec![false, true, true],
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sandboxed_frame_keeps_dom_and_lifecycle_but_suppresses_all_author_scripts() {
        let mut parent = page(
            "https://parent.example/page.html",
            "<!doctype html><html><body></body></html>",
        );
        let frame = FrameRealm::new_staged_with_inherited_context_and_script_policy(
            &mut parent,
            1,
            0,
            "https://child.example/frame.html",
            None,
            None,
            concat!(
                "<!doctype html><html><body onload='globalThis.__contentHandlers++'>",
                "<p id='kept'>sandbox DOM</p>",
                "<button id='handler' onclick='globalThis.__contentHandlers++'>click</button>",
                "<script>globalThis.__classicRuns++;</script>",
                "<script src='ignored-classic.js'></script>",
                "<script type='module'>globalThis.__moduleRuns++;</script>",
                "<script type='module' src='ignored-module.js'></script>",
                "<iframe srcdoc='<script>globalThis.__nestedRuns = true;</script><p>nested</p>'></iframe>",
                "</body></html>",
            ),
            false,
        )
        .expect("sandboxed frame realm");
        assert!(!frame.scripts_allowed());

        // A disabled sandbox flag propagates through descendant browsing
        // contexts even when the nested iframe has no sandbox attribute.
        let nested = parent.take_pending_frames();
        assert_eq!(nested.len(), 1);
        assert!(!nested[0].scripts_allowed);

        frame
            .execute_script(
                &mut parent,
                r#"
                  globalThis.__classicRuns = 0;
                  globalThis.__moduleRuns = 0;
                  globalThis.__dynamicRuns = 0;
                  globalThis.__contentHandlers = 0;
                  globalThis.__lifecycle = [];
                  document.addEventListener('DOMContentLoaded', () => __lifecycle.push('dcl'));
                  addEventListener('load', () => __lifecycle.push('load'));

                  const inline = document.createElement('script');
                  inline.textContent = 'globalThis.__dynamicRuns += 1';
                  document.body.appendChild(inline);

                  const external = document.createElement('script');
                  external.src = 'data:text/javascript,globalThis.__dynamicRuns%20%2B%3D%201';
                  document.body.appendChild(external);

                  const module = document.createElement('script');
                  module.type = 'module';
                  module.textContent = 'globalThis.__dynamicRuns += 1';
                  document.body.appendChild(module);
                "#,
            )
            .expect("host setup in sandboxed realm");

        assert!(frame.external_script_urls(&mut parent).is_empty());
        assert!(frame.external_module_urls().is_empty());
        let attempted_fetches = std::cell::Cell::new(0usize);
        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |_| {
                    attempted_fetches.set(attempted_fetches.get() + 1);
                    None
                },
                std::collections::BTreeMap::new(),
                1_000,
            )
            .await;
        assert!(
            problems.is_empty(),
            "sandboxed parser reported: {problems:?}"
        );
        assert_eq!(attempted_fetches.get(), 0);
        assert_eq!(frame.unsupported_module_script_count(&mut parent), 0);
        assert!(!frame.has_pending_dynamic_scripts(&mut parent));

        frame.dispatch_load_events(&mut parent).unwrap();
        frame
            .execute_script(&mut parent, "document.getElementById('handler').click();")
            .unwrap();
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "({classic:__classicRuns,module:__moduleRuns,dynamic:__dynamicRuns,handlers:__contentHandlers,lifecycle:__lifecycle,ready:document.readyState,dom:document.getElementById('kept').textContent})",
                )
                .unwrap(),
            serde_json::json!({
                "classic": 0,
                "module": 0,
                "dynamic": 0,
                "handlers": 0,
                "lifecycle": ["dcl", "load"],
                "ready": "complete",
                "dom": "sandbox DOM",
            }),
        );
    }

    #[test]
    fn parser_created_srcdoc_inside_declarative_shadow_root_is_queued() {
        let parent = page(
            "https://parent.example/path/page.html",
            concat!(
                "<!doctype html><section><template shadowrootmode='closed'>",
                "<iframe srcdoc=\"<p data-shadow='srcdoc'>inside</p>\"></iframe>",
                "</template></section>",
            ),
        );
        let pending = parent.take_pending_frames();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].url, "about:srcdoc");
        assert_eq!(
            pending[0].inherited_base_url.as_deref(),
            Some("https://parent.example/path/page.html"),
        );
        assert_eq!(
            pending[0].inherited_origin.as_deref(),
            Some("https://parent.example"),
        );
        assert!(pending[0].html.contains("data-shadow='srcdoc'"));
    }

    #[test]
    fn frame_uses_its_embedding_viewport() {
        let mut parent = page(
            "https://parent.example/page",
            "<html><body><iframe style='width:300px;height:65px'></iframe></body></html>",
        );
        let mut pending = parent.take_pending_frames();
        assert_eq!(pending.len(), 1);
        let pending = pending.remove(0);
        let frame = FrameRealm::new_with_inherited_context(
            &mut parent,
            pending.frame_id,
            pending.parent_frame_id,
            &pending.url,
            pending.inherited_base_url.as_deref(),
            pending.inherited_origin.as_deref(),
            &pending.html,
        )
        .expect("frame realm");

        frame.set_viewport(&mut parent, 300.0, 65.0).unwrap();
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "[innerWidth,innerHeight,visualViewport.width,visualViewport.height]",
                )
                .unwrap(),
            serde_json::json!([300, 65, 300, 65]),
        );
    }

    #[cfg(feature = "render")]
    #[test]
    fn frame_viewport_updates_native_layout_state() {
        let mut parent = page(
            "https://parent.example/page",
            "<html><body><iframe style='width:300px;height:65px'></iframe></body></html>",
        );
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/frame",
            "<html style='margin:0'><body style='margin:0'><div id='box' style='width:100%;height:20px;visibility:hidden'></div></body></html>",
        )
        .expect("frame realm");

        frame.set_viewport(&mut parent, 300.0, 65.0).unwrap();
        let first = frame
            .evaluate(
                &mut parent,
                "[document.getElementById('box').getBoundingClientRect().width, innerWidth, getComputedStyle(document.getElementById('box')).visibility]",
            )
            .unwrap();
        let first = first.as_array().unwrap();
        let first_width = first[0].as_f64().unwrap();
        assert!(first_width > 0.0);
        assert_eq!(first[1], serde_json::json!(300));
        assert_eq!(first[2], serde_json::json!("hidden"));
        let state = frame
            .realms
            .borrow()
            .by_frame_id(frame.frame_id())
            .expect("live frame state");
        {
            let state = state.borrow();
            assert_eq!(state.viewport, (300.0, 65.0));
            assert!(state.prepared_render.is_some());
        }

        frame.set_viewport(&mut parent, 500.0, 65.0).unwrap();
        {
            let state = state.borrow();
            assert_eq!(state.viewport, (500.0, 65.0));
            assert!(state.prepared_render.is_none());
            assert!(state.pending_style_mutations.is_empty());
            assert!(state.resolved_scroll.is_none());
        }
        let second = frame
            .evaluate(
                &mut parent,
                "[document.getElementById('box').getBoundingClientRect().width, innerWidth, getComputedStyle(document.getElementById('box')).visibility]",
            )
            .unwrap();
        let second = second.as_array().unwrap();
        let second_width = second[0].as_f64().unwrap();
        assert!(second_width > 0.0);
        assert_eq!(second[1], serde_json::json!(500));
        assert_eq!(second[2], serde_json::json!("hidden"));
    }

    /// A frame must not look like a different browser than its parent. Anti-bot
    /// code fingerprints inside the frame and compares it with the top document.
    #[test]
    fn frame_inherits_the_parent_browser_identity() {
        let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestAgent/150.0.0.0";
        let mut parent = ObscuraJsRuntime::new();
        parent.set_user_agent(user_agent);
        parent.set_platform("Win32", "Windows", "19.0.0");
        parent.set_dom(parse_html("<html><body></body></html>"));
        parent.set_url("https://parent.example/");
        parent.run_page_init();

        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/f",
            "<html><body></body></html>",
        )
        .expect("frame realm");

        for surface in [
            "navigator.userAgent",
            "navigator.platform",
            "navigator.userAgentData.platform",
        ] {
            assert_eq!(
                frame.evaluate(&mut parent, surface).unwrap(),
                parent.evaluate(surface).unwrap(),
                "frame and parent disagree on {surface}"
            );
        }
        assert_eq!(
            frame.evaluate(&mut parent, "navigator.userAgent").unwrap(),
            serde_json::json!(user_agent)
        );
    }

    /// The capability the frame realm exists for: scripts that arrived with the
    /// frame's document run, in order, against the frame's own DOM.
    #[test]
    fn frame_runs_its_document_scripts_in_order() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/dir/page",
            r#"<html><body><div id="out"></div>
               <script>window.log = ['inline1'];</script>
               <script src="first.js"></script>
               <script src="/second.js"></script>
               <script>window.log.push('inline2');
                       document.getElementById('out').textContent = window.log.join(',');</script>
               </body></html>"#,
        )
        .expect("frame realm");

        let requested = RefCell::new(Vec::new());
        let problems = frame.run_document_scripts(&mut parent, |url| {
            requested.borrow_mut().push(url.to_string());
            match url {
                "https://child.example/dir/first.js" => Some("window.log.push('ext1');".into()),
                "https://child.example/second.js" => Some("window.log.push('ext2');".into()),
                _ => None,
            }
        });

        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        // Relative and root-relative src resolve against the frame's URL, not
        // the parent's.
        assert_eq!(
            requested.into_inner(),
            vec![
                "https://child.example/dir/first.js".to_string(),
                "https://child.example/second.js".to_string(),
            ]
        );
        assert_eq!(
            frame
                .evaluate(&mut parent, "document.getElementById('out').textContent")
                .unwrap(),
            serde_json::json!("inline1,ext1,ext2,inline2")
        );
        // The frame's document writes never touch the parent's DOM.
        assert_eq!(
            parent.evaluate("document.body.innerHTML").unwrap(),
            serde_json::json!("")
        );
    }

    #[test]
    fn frame_parser_script_snapshot_precedes_new_document_preloads() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/frame",
            r#"<html><body>
               <script data-parser>
                 globalThis.__parserRuns = (globalThis.__parserRuns || 0) + 1;
               </script>
               </body></html>"#,
        )
        .expect("frame realm");

        // This is the mutation pattern available to a new-document preload.
        // The inserted script executes dynamically once. Moving the original
        // parser-owned script must not execute it before the parser runner and
        // must not make the inserted script part of that runner's later list.
        frame
            .execute_script(
                &mut parent,
                r#"globalThis.__parserRuns = 0;
                   globalThis.__insertedRuns = 0;
                   const original = document.querySelector('script[data-parser]');
                   const inserted = document.createElement('script');
                   inserted.textContent = 'globalThis.__insertedRuns++;';
                   document.body.appendChild(inserted);
                   document.body.appendChild(original);"#,
            )
            .unwrap();
        assert_eq!(
            frame
                .evaluate(&mut parent, "[__parserRuns, __insertedRuns]")
                .unwrap(),
            serde_json::json!([0, 1])
        );

        let problems = frame.run_document_scripts(&mut parent, |_| None);
        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        assert_eq!(
            frame
                .evaluate(&mut parent, "[__parserRuns, __insertedRuns]")
                .unwrap(),
            serde_json::json!([1, 1])
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn frame_parser_resources_keep_the_base_at_their_encounter_point() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/original/page.html",
            r#"<html><head>
               <script src="before.js"></script>
               <link rel="stylesheet" href="before.css">
               <style>@import "before-import.css";</style>
               <base href="/shifted/">
               <script src="after.js"></script>
               <link rel="stylesheet" href="after.css">
               <style>@import "after-import.css";</style>
               <base href="/ignored/">
               <script src="after-second-base.js"></script>
               </head><body></body></html>"#,
        )
        .expect("frame realm");

        assert_eq!(
            frame.external_script_urls(&mut parent),
            vec![
                "https://child.example/original/before.js".to_string(),
                "https://child.example/shifted/after.js".to_string(),
                "https://child.example/shifted/after-second-base.js".to_string(),
            ]
        );
        assert_eq!(
            frame
                .parser_stylesheet_urls()
                .into_iter()
                .map(|(_, _, url, _, _)| url)
                .collect::<Vec<_>>(),
            vec![
                "https://child.example/original/before.css".to_string(),
                "https://child.example/shifted/after.css".to_string(),
            ]
        );
        assert_eq!(
            frame
                .parser_stylesheet_urls()
                .into_iter()
                .map(|(_, _, _, _, raw_href)| raw_href)
                .collect::<Vec<_>>(),
            vec!["before.css".to_string(), "after.css".to_string()]
        );
        assert_eq!(
            frame
                .parser_inline_stylesheet_sources()
                .into_iter()
                .map(|(_, _, _, _, base, _)| base)
                .collect::<Vec<_>>(),
            vec![
                "https://child.example/original/page.html".to_string(),
                "https://child.example/shifted/".to_string(),
            ]
        );

        // A new-document preload runs after these snapshots. Rewriting the
        // live first base must not retarget parser-owned requests retroactively.
        frame
            .execute_script(
                &mut parent,
                "document.querySelector('base').setAttribute('href', '/preload-rewrite/');",
            )
            .unwrap();
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "[...document.querySelectorAll('link')].map(link => __obscura_isParserStylesheetPending(link))",
                )
                .unwrap(),
            serde_json::json!([true, true]),
        );
        assert_eq!(
            frame.external_script_urls(&mut parent)[0],
            "https://child.example/original/before.js"
        );
        assert_eq!(
            frame.parser_stylesheet_urls()[1].2,
            "https://child.example/shifted/after.css"
        );
        frame
            .execute_script(
                &mut parent,
                "const rewritten = document.querySelector('link');\
                 rewritten.remove();\
                 rewritten.setAttribute('href', 'rewritten.css');\
                 globalThis.__rewrittenParserLink = rewritten;",
            )
            .unwrap();
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "__obscura_isParserStylesheetPending(globalThis.__rewrittenParserLink)",
                )
                .unwrap(),
            serde_json::json!(false),
        );
    }

    #[test]
    fn frame_body_onload_is_installed_at_body_encounter_before_body_stylesheet_event() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/frame",
            r#"<html><head>
               <link rel="stylesheet" href="head.css">
               </head><body onload="globalThis.__parsedBodyLoadRan = true">
               <link rel="stylesheet" href="body.css">
               </body></html>"#,
        )
        .expect("frame realm");
        frame
            .execute_script(&mut parent, "globalThis.__bodyHandlerAtSheet = [];")
            .unwrap();

        let mut events = std::collections::BTreeMap::new();
        for stylesheet in &frame.parser_stylesheets {
            events.insert(
                stylesheet.nid,
                "globalThis.__bodyHandlerAtSheet.push(typeof document.body.onload === 'function');"
                    .to_string(),
            );
        }
        let problems =
            frame.run_document_scripts_with_stylesheet_events(&mut parent, |_| None, events);

        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        assert_eq!(
            frame
                .evaluate(&mut parent, "globalThis.__bodyHandlerAtSheet")
                .unwrap(),
            serde_json::json!([false, true]),
        );
    }

    #[test]
    fn classic_pass_leaves_modules_for_the_managed_module_runner() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/",
            r#"<html><body>
               <script>window.log = ['a'];</script>
               <script>throw new Error('boom');</script>
               <script src="missing.js"></script>
               <script type="module">window.log.push('module');</script>
               <script>window.log.push('b');</script>
               </body></html>"#,
        )
        .expect("frame realm");

        let problems = frame.run_document_scripts(&mut parent, |_| None);

        assert_eq!(
            frame.evaluate(&mut parent, "window.log.join(',')").unwrap(),
            serde_json::json!("a,b")
        );
        assert_eq!(problems.len(), 2, "problems: {problems:?}");
        assert!(problems.iter().any(|p| p.contains("boom")), "{problems:?}");
        assert!(
            problems.iter().any(|p| p.contains("missing.js")),
            "{problems:?}"
        );
        assert_eq!(frame.unsupported_module_script_count(&mut parent), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn managed_frame_inline_module_waits_for_top_level_await() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/frame.html",
            "<html><body></body></html>",
        )
        .expect("frame realm");

        frame
            .load_inline_module(
                &mut parent,
                "await Promise.resolve(); globalThis.__frameTla = 'complete';",
                "https://child.example/frame.html",
                1_000,
            )
            .await
            .unwrap();

        assert_eq!(
            frame
                .evaluate(&mut parent, "globalThis.__frameTla")
                .unwrap(),
            serde_json::json!("complete"),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn managed_frame_external_graph_uses_its_import_map_and_dynamic_import() {
        let base = spawn_frame_module_server(2);
        let frame_url = format!("{base}/frame.html");
        let mut parent = page(&format!("{base}/parent.html"), "<html><body></body></html>");
        install_local_module_client(&parent);
        let frame = FrameRealm::new(&mut parent, 1, 0, &frame_url, "<html><body></body></html>")
            .expect("frame realm");
        frame
            .add_import_map(
                &format!(
                    r#"{{"imports":{{"dep":"{base}/dep.js","dynamic":"{base}/dynamic.js"}}}}"#
                ),
                &frame_url,
            )
            .unwrap();

        frame
            .load_external_module(
                &mut parent,
                &format!("{base}/entry.js"),
                Some(
                    "import { value as left } from 'dep';\
                     const right = (await import('dynamic')).value;\
                     globalThis.__frameGraph = `${left}:${right}`;",
                ),
                2_000,
            )
            .await
            .unwrap();

        assert_eq!(
            frame
                .evaluate(&mut parent, "globalThis.__frameGraph")
                .unwrap(),
            serde_json::json!("static:dynamic"),
        );
        assert_eq!(
            parent.evaluate("typeof globalThis.__frameGraph").unwrap(),
            serde_json::json!("undefined"),
            "frame module global leaked into the parent realm",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn frame_import_map_is_frozen_when_the_first_graph_starts() {
        let base = spawn_frame_module_server(1);
        let frame_url = format!("{base}/frame.html");
        let mut parent = page(&format!("{base}/parent.html"), "<html><body></body></html>");
        install_local_module_client(&parent);
        let html = format!(
            r#"<html><body>
               <script type="importmap">{{"imports":{{"pkg":"{base}/dep.js"}}}}</script>
               <script type="module" src="entry-one.js"></script>
               <script type="importmap">{{"imports":{{"pkg":"{base}/dynamic.js"}}}}</script>
               <script type="module" src="entry-two.js"></script>
               </body></html>"#,
        );
        let frame = FrameRealm::new(&mut parent, 1, 0, &frame_url, &html).expect("frame realm");

        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |url| {
                    if url.ends_with("entry-one.js") {
                        Some(
                            "import { value } from 'pkg'; globalThis.__firstMap = value;"
                                .to_string(),
                        )
                    } else if url.ends_with("entry-two.js") {
                        Some(
                            "import { value } from 'pkg'; globalThis.__secondMap = value;"
                                .to_string(),
                        )
                    } else {
                        None
                    }
                },
                std::collections::BTreeMap::new(),
                2_000,
            )
            .await;

        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        assert_eq!(
            frame
                .evaluate(
                    &mut parent,
                    "[globalThis.__firstMap, globalThis.__secondMap]"
                )
                .unwrap(),
            serde_json::json!(["static", "static"]),
            "a later import map changed a resolution already observed by the frame",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sibling_frames_have_independent_module_maps_and_caches() {
        let base = spawn_frame_module_server(2);
        let mut parent = page(&format!("{base}/parent.html"), "<html><body></body></html>");
        install_local_module_client(&parent);
        let first_url = format!("{base}/first.html");
        let second_url = format!("{base}/second.html");
        let first =
            FrameRealm::new(&mut parent, 1, 0, &first_url, "<html></html>").expect("first frame");
        let second =
            FrameRealm::new(&mut parent, 2, 0, &second_url, "<html></html>").expect("second frame");
        first
            .add_import_map(
                &format!(r#"{{"imports":{{"pkg":"{base}/dep.js"}}}}"#),
                &first_url,
            )
            .unwrap();
        second
            .add_import_map(
                &format!(r#"{{"imports":{{"pkg":"{base}/dynamic.js"}}}}"#),
                &second_url,
            )
            .unwrap();

        first
            .load_external_module(
                &mut parent,
                &format!("{base}/first-entry.js"),
                Some("import { value } from 'pkg'; globalThis.__which = value;"),
                2_000,
            )
            .await
            .unwrap();
        second
            .load_external_module(
                &mut parent,
                &format!("{base}/second-entry.js"),
                Some("import { value } from 'pkg'; globalThis.__which = value;"),
                2_000,
            )
            .await
            .unwrap();

        assert_eq!(
            first.evaluate(&mut parent, "globalThis.__which").unwrap(),
            serde_json::json!("static"),
        );
        assert_eq!(
            second.evaluate(&mut parent, "globalThis.__which").unwrap(),
            serde_json::json!("dynamic"),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn document_module_runner_executes_modules_and_clears_archive_diagnostic() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/frame.html",
            r#"<html><body>
               <script>globalThis.__order = ['classic'];</script>
               <script type="module">
                 await Promise.resolve();
                 globalThis.__order.push('module');
               </script>
               </body></html>"#,
        )
        .expect("frame realm");

        let problems = frame
            .run_document_scripts_and_modules_with_stylesheet_events(
                &mut parent,
                |_| None,
                std::collections::BTreeMap::new(),
                1_000,
            )
            .await;

        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
        assert_eq!(
            frame.evaluate(&mut parent, "globalThis.__order").unwrap(),
            serde_json::json!(["classic", "module"]),
        );
        assert_eq!(frame.unsupported_module_script_count(&mut parent), 0);
    }

    #[test]
    fn many_frames_can_be_alive_at_once() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frames: Vec<FrameRealm> = (0..4)
            .map(|index| {
                FrameRealm::new(
                    &mut parent,
                    // Frame ids start at 1: 0 names the page itself, which is
                    // what a DOM call from an unframed realm reports.
                    index + 1,
                    0,
                    &format!("https://f{index}.example/"),
                    &format!("<html><body><h1>{index}</h1></body></html>"),
                )
                .expect("frame realm")
            })
            .collect();

        for (index, frame) in frames.iter().enumerate() {
            frame
                .execute_script(&mut parent, &format!("globalThis.n = {index};"))
                .unwrap();
        }
        // Out-of-order access must be safe: each frame carries its own state.
        for (index, frame) in frames.iter().enumerate().rev() {
            assert_eq!(
                frame
                    .evaluate(&mut parent, "globalThis.n")
                    .unwrap()
                    .as_f64(),
                Some(index as f64)
            );
            assert_eq!(
                frame
                    .evaluate(&mut parent, "document.querySelector('h1').textContent")
                    .unwrap(),
                serde_json::json!(index.to_string())
            );
        }
    }

    /// The hard case. A frame's deferred work re-enters JavaScript from the
    /// event loop, long after the host last called into the frame, so nothing
    /// can have made the frame "current" for it. It has to find its own
    /// document anyway.
    #[tokio::test(flavor = "current_thread")]
    async fn a_frames_deferred_work_still_sees_the_frames_document() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/",
            "<html><body></body></html>",
        )
        .expect("frame realm");

        // 50ms, not 0: a zero delay drains as a microtask while the host is
        // still inside the frame, which would hide the bug this guards.
        frame
            .execute_script(
                &mut parent,
                "setTimeout(() => { document.body.setAttribute('data-who', location.href); }, 50);",
            )
            .unwrap();
        parent.run_event_loop_bounded(300).await.unwrap();

        assert_eq!(
            frame
                .evaluate(&mut parent, "document.body.getAttribute('data-who')")
                .unwrap(),
            serde_json::json!("https://child.example/"),
            "the frame's timer did not write to the frame's own document"
        );
        assert_eq!(
            parent
                .evaluate("document.body.getAttribute('data-who')")
                .unwrap(),
            serde_json::Value::Null,
            "the frame's timer wrote to the parent's document"
        );
    }

    /// A frame's timers cannot go through deno_core's queue: `op_timer_queue`
    /// reads per-context state that only a deno_core-created context carries,
    /// and queueing from a snapshot realm dereferences uninitialized memory,
    /// which aborts the process rather than failing a test. This is the guard
    /// against that path ever being restored.
    #[tokio::test(flavor = "current_thread")]
    async fn a_frame_timer_fires_without_deno_cores_timer_queue() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/",
            "<html><body></body></html>",
        )
        .expect("frame realm");
        frame
            .execute_script(
                &mut parent,
                "setTimeout(() => { globalThis.fired = 1; }, 50);",
            )
            .unwrap();
        parent.run_event_loop_bounded(300).await.unwrap();
        assert_eq!(
            frame
                .evaluate(&mut parent, "globalThis.fired || 0")
                .unwrap(),
            serde_json::json!(1),
            "the frame's timer callback never ran"
        );
    }

    /// Frame timers run on a separate queue from the page's, so cancelling one
    /// has its own path and its own way to go wrong.
    #[tokio::test(flavor = "current_thread")]
    async fn clear_timeout_cancels_a_frame_timer() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/",
            "<html><body></body></html>",
        )
        .expect("frame realm");
        frame
            .execute_script(
                &mut parent,
                "globalThis.kept = 0;\
                 const cancelled = setTimeout(() => { globalThis.kept = 1; }, 50);\
                 setTimeout(() => { globalThis.kept = 2; }, 50);\
                 clearTimeout(cancelled);",
            )
            .unwrap();
        parent.run_event_loop_bounded(300).await.unwrap();
        assert_eq!(
            frame.evaluate(&mut parent, "globalThis.kept").unwrap(),
            serde_json::json!(2),
            "clearTimeout did not cancel exactly the frame timer it was given"
        );
    }

    /// V8 reports the frame as the microtask context, so a promise continuation
    /// resolves ops against the frame without any help from the host.
    #[tokio::test(flavor = "current_thread")]
    async fn a_frames_promise_continuation_sees_the_frames_document() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/",
            "<html><body></body></html>",
        )
        .expect("frame realm");
        frame
            .execute_script(
                &mut parent,
                "Promise.resolve().then(() => { \
                   document.body.setAttribute('data-who', location.href); });",
            )
            .unwrap();
        parent.run_event_loop_bounded(300).await.unwrap();
        assert_eq!(
            frame
                .evaluate(&mut parent, "document.body.getAttribute('data-who')")
                .unwrap(),
            serde_json::json!("https://child.example/"),
        );
    }

    /// A frame posting to `parent` must reach the page, arrive trusted, and
    /// carry the frame's origin. Turnstile and every widget like it drop an
    /// untrusted message silently, so an untrusted delivery is not a cosmetic
    /// difference, it is the widget hanging forever.
    #[test]
    fn a_frame_posts_to_its_parent_as_a_trusted_message() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        parent
            .execute_script(
                "p",
                "globalThis.got = [];\
                 addEventListener('message', (e) => globalThis.got.push(\
                   [e.data, e.origin, e.isTrusted]));",
            )
            .unwrap();
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/f",
            "<html><body></body></html>",
        )
        .expect("frame realm");

        frame
            .execute_script(&mut parent, "parent.postMessage({token: 'ok'}, '*');")
            .unwrap();
        // The host is the transport, exactly as `Page` does between turns.
        let queued = parent.take_pending_frame_messages();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].target_frame_id, 0);
        assert_eq!(queued[0].source_frame_id, 1);
        let script = format!(
            "globalThis.__obscura_deliverMessage({}, {}, {});",
            serde_json::to_string(&queued[0].data_json).unwrap(),
            serde_json::to_string(&queued[0].origin).unwrap(),
            queued[0].source_frame_id,
        );
        parent.execute_script("<frame-message>", &script).unwrap();

        assert_eq!(
            parent.evaluate("globalThis.got").unwrap(),
            serde_json::json!([[{"token": "ok"}, "https://child.example", true]]),
        );
    }

    /// `parent === window` is how a document decides it is top-level, so a
    /// framed realm must not see itself as the top.
    #[test]
    fn a_framed_realm_does_not_look_top_level() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            2,
            0,
            "https://child.example/f",
            "<html><body></body></html>",
        )
        .expect("frame realm");
        assert_eq!(
            frame
                .evaluate(&mut parent, "[parent === window, top === window]")
                .unwrap(),
            serde_json::json!([false, false]),
        );
        // The page itself really is the top and must still say so.
        assert_eq!(
            parent
                .evaluate("[parent === window, top === window]")
                .unwrap(),
            serde_json::json!([true, true]),
        );
    }

    /// Script can post in a synchronous loop while the host only drains between
    /// event loop turns, and this queue is on the process heap rather than
    /// V8's, where the heap-limit guard would never see it.
    #[test]
    fn a_flood_of_messages_cannot_grow_the_queue_without_bound() {
        std::env::set_var("OBSCURA_FRAME_MESSAGE_QUEUE_ENTRIES", "64");
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/f",
            "<html><body></body></html>",
        )
        .expect("frame realm");

        frame
            .execute_script(
                &mut parent,
                "for (let i = 0; i < 5000; i++) parent.postMessage(i, '*');",
            )
            .unwrap();

        let (queued_entries, queued_bytes) = parent.pending_frame_message_queue();
        assert_eq!(queued_entries, 64, "the pending queue count was hidden");
        assert!(queued_bytes > 0, "the pending queue byte count was hidden");
        assert_eq!(
            parent.resource_archive_incomplete_reasons(),
            vec!["frame postMessage queue entry cap reached (64 message(s))".to_string()],
            "dropping messages must make a byte-exact archive incomplete",
        );
        let queued = parent.take_pending_frame_messages();
        assert_eq!(queued.len(), 64, "the queue was not capped");
        assert_eq!(parent.pending_frame_message_queue(), (0, 0));
        // The messages kept are the earliest, which is the half of a handshake
        // that matters.
        assert_eq!(queued[0].data_json, r#"{"v":0}"#);
        std::env::remove_var("OBSCURA_FRAME_MESSAGE_QUEUE_ENTRIES");
    }

    /// The page realm holds the frame's window and document, so a discarded
    /// frame leaves the page naming objects from a context the host no longer
    /// holds. Reading one must be safe. A regression here is an access
    /// violation that takes the process down, not a failed assertion.
    ///
    /// It must also not read as anything: V8 severs a global proxy when its
    /// context goes, which is the same thing a browser does to a WindowProxy
    /// when it discards a browsing context.
    #[test]
    fn a_discarded_realm_leaves_the_page_safe_to_run() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        {
            let frame = FrameRealm::new(
                &mut parent,
                1,
                0,
                "https://parent.example/child",
                "<html><body><h1>Child</h1></body></html>",
            )
            .expect("frame realm");
            frame
                .execute_script(&mut parent, "globalThis.marker = 'child';")
                .unwrap();
            // Reachable from the page while the frame is alive.
            assert_eq!(
                parent
                    .evaluate("globalThis.__obscura_frameObjects[1].window.marker")
                    .unwrap(),
                serde_json::json!("child"),
            );
        }

        // Dropping the realm does not free it, and must not make touching it
        // unsafe: the page still names its window, so V8 keeps the context
        // alive and the read still answers. This is exactly why a discarded
        // frame has to have its entry removed rather than merely dropped, and
        // what `Page::release_detached_frames` is for.
        assert_eq!(
            parent
                .evaluate("globalThis.__obscura_frameObjects[1].window.marker")
                .unwrap(),
            serde_json::json!("child"),
        );
        // The page's own DOM work still resolves against the page.
        assert_eq!(
            parent.evaluate("document.body.innerHTML").unwrap(),
            serde_json::json!(""),
        );
        // Dropping the page's reference is what lets the frame be collected.
        parent
            .execute_script("p", "globalThis.__obscura_forgetFrame(1);")
            .unwrap();
        assert_eq!(
            parent
                .evaluate("globalThis.__obscura_frameObjects[1] === undefined")
                .unwrap(),
            serde_json::json!(true),
        );
    }

    /// A DOM call names the realm it belongs to, so the page reading the
    /// frame's document gets the frame's document. Resolving from the running
    /// context instead would silently answer with the page's own.
    #[test]
    fn the_page_reads_the_frames_document_through_its_own_object() {
        let mut parent = page(
            "https://parent.example/",
            "<html><head><title>parent</title></head><body></body></html>",
        );
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://parent.example/child",
            "<html><head><title>BEFORE</title></head><body><p>child</p></body></html>",
        )
        .expect("frame realm");
        frame
            .execute_script(&mut parent, "document.title = 'RAN-IN-CHILD';")
            .unwrap();

        // Read the frame's document from the *page's* realm.
        assert_eq!(
            parent
                .evaluate("globalThis.__obscura_frameObjects[1].document.title")
                .unwrap(),
            serde_json::json!("RAN-IN-CHILD"),
        );
        assert_eq!(
            parent
                .evaluate(
                    "globalThis.__obscura_frameObjects[1].document.querySelector('p').textContent"
                )
                .unwrap(),
            serde_json::json!("child"),
        );
        // The page's own title is untouched by any of that.
        assert_eq!(
            parent.evaluate("document.title").unwrap(),
            serde_json::json!("parent"),
        );
    }

    /// A cross-origin frame must stay opaque. Nothing about it is published to
    /// the page, and V8's own access check answers `undefined` for anything the
    /// page reaches for, because the two realms keep different security tokens.
    #[test]
    fn a_cross_origin_frame_is_not_reachable_from_the_page() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://other.example/f",
            "<html><body></body></html>",
        )
        .expect("frame realm");
        frame
            .execute_script(&mut parent, "globalThis.secret = 'do-not-leak';")
            .unwrap();

        assert_eq!(
            parent
                .evaluate("globalThis.__obscura_frameObjects[1] === undefined")
                .unwrap(),
            serde_json::json!(true),
            "a cross-origin frame was published to the page"
        );
        // The frame still works on its own side.
        assert_eq!(
            frame.evaluate(&mut parent, "globalThis.secret").unwrap(),
            serde_json::json!("do-not-leak"),
        );
    }

    #[test]
    fn opaque_origin_frames_are_never_same_origin() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "about:blank",
            "<html><body></body></html>",
        )
        .expect("frame realm");
        assert_eq!(frame.origin(), "null");
        assert!(!frame.is_same_origin_as("null"));
        assert!(!frame.is_same_origin_as("https://parent.example"));
    }

    #[test]
    fn frame_module_evaluation_is_visible_as_pending_activity() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/frame.html",
            "<html><body></body></html>",
        )
        .expect("frame realm");
        assert!(!frame.has_pending_module_work());
        // `evaluate_prepared_module` holds this same guard across deno_core's
        // evaluation future. Exercise the shared readiness signal directly so
        // this regression test does not depend on V8's stalled-TLA policy.
        let evaluation_activity = frame.module_activity.begin();
        assert!(
            frame.has_pending_module_work(),
            "top-level await was invisible to capture readiness",
        );

        assert!(frame.invalidate_document_generation());
        drop(evaluation_activity);
        assert!(
            frame.has_pending_module_work(),
            "cancelling evaluation lost the completion activity edge",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalidated_frame_rejects_a_prepared_module_continuation() {
        let mut parent = page("https://parent.example/", "<html><body></body></html>");
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/frame.html",
            "<html><body></body></html>",
        )
        .expect("frame realm");
        let prepared = frame
            .prepare_inline_module(
                &mut parent,
                "globalThis.__staleModuleRan = true;",
                "https://child.example/frame.html",
                1_000,
            )
            .await
            .expect("prepared module");

        assert!(frame.invalidate_document_generation());
        let error = frame
            .evaluate_prepared_module(&mut parent, prepared, 1_000)
            .await
            .expect_err("an old module continuation was accepted");
        assert!(error.contains("replaced"), "unexpected error: {error}");
        assert_eq!(
            frame
                .evaluate(&mut parent, "typeof globalThis.__staleModuleRan")
                .unwrap(),
            serde_json::json!("undefined"),
        );
    }
}
