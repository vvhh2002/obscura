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

use obscura_dom::parse_html;

use crate::ops::{ObscuraState, RealmStates};
use crate::runtime::ObscuraJsRuntime;

/// One child browsing context: its own realm, document and origin, living in
/// the page's isolate.
pub struct FrameRealm {
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

impl Drop for FrameRealm {
    fn drop(&mut self) {
        self.realms.borrow_mut().forget(&self.context);
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
        let context = parent.create_realm_context()?;
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

        let mut state = ObscuraState::new();
        state.dom = Some(parse_html(html));
        state.url = url.to_string();
        state.inherited_base_url = inherited_base_url.map(str::to_string);
        state.inherited_origin = inherited_origin.map(str::to_string);
        state.frame_id = frame_id;
        parent.share_resources_with(&mut state);

        let realms = parent.realm_states();
        realms.borrow_mut().register(
            context.clone(),
            frame_id,
            Rc::new(std::cell::RefCell::new(state)),
        );

        let mut realm = FrameRealm {
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
                     globalThis.__documentReadyState__ = 'loading';\
                     globalThis.__obscura_init();"
                ),
            )
            .ok()?;
        realm.parser_scripts = realm.list_scripts(parent).ok()?;
        realm.parser_stylesheets = realm.list_stylesheets(parent).ok()?;
        realm.parser_inline_stylesheets = realm.list_inline_stylesheets(parent).ok()?;
        realm.parser_body_order = realm.list_parser_body_order(parent).ok()?;
        let parser_nids = realm
            .parser_scripts
            .iter()
            .map(|script| script.nid)
            .collect::<Vec<_>>();
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

    /// Finish parsing without claiming that descendant frames and resources
    /// have completed.
    pub fn dispatch_dom_content_loaded(&self, parent: &mut ObscuraJsRuntime) -> Result<(), String> {
        if self.lifecycle_state() != FrameLifecycleState::Loading {
            return Ok(());
        }
        self.execute_script(
            parent,
            "globalThis.__documentReadyState__ = 'interactive';\
             try { globalThis.__obscura_dispatchDocumentLifecycleEvent('readystatechange'); } catch (_) {}\
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
        self.execute_script(
            parent,
            &format!(
                "globalThis.innerWidth={width};globalThis.innerHeight={height};\
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

    /// Runs the frame document's classic scripts, in document order.
    ///
    /// `load_external` resolves a `src=` script to its source text; returning
    /// `None` skips it, which is what a failed subresource fetch looks like to
    /// the page. One script throwing does not stop the ones after it, matching
    /// how a browser treats separate classic scripts.
    ///
    /// Module scripts are skipped and reported: they need the frame's own module
    /// loader, which is not wired up yet.
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

        let mut stylesheet_events = self
            .parser_stylesheets
            .iter()
            .into_iter()
            .filter_map(|stylesheet| {
                stylesheet_events
                    .remove(&stylesheet.nid)
                    .map(|source| (stylesheet.parser_order, source))
            })
            .collect::<Vec<_>>();
        stylesheet_events.sort_by_key(|(order, _)| *order);
        let mut stylesheet_events = std::collections::VecDeque::from(stylesheet_events);

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
            if !script.is_classic() {
                if script.type_attribute == "module" {
                    problems.push(format!(
                        "frame module script {index} skipped: not supported"
                    ));
                    self.dispatch_parser_script_event(parent, script.nid, "error");
                }
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
        self.parser_scripts
            .iter()
            .filter(|script| script.is_classic() && !script.src.is_empty())
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
    pub fn parser_inline_stylesheet_sources(&self) -> Vec<(usize, String, String, String)> {
        self.parser_inline_stylesheets
            .iter()
            .map(|stylesheet| {
                (
                    stylesheet.author_index,
                    stylesheet.text.clone(),
                    stylesheet.media.clone(),
                    stylesheet.base_url.clone(),
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

    /// Number of module scripts still present in this live frame. Frame module
    /// execution is not wired up yet, so callers use this to mark a resource
    /// archive incomplete instead of silently claiming full coverage.
    pub fn unsupported_module_script_count(&self, parent: &mut ObscuraJsRuntime) -> usize {
        self.try_unsupported_module_script_count(parent)
            .unwrap_or_default()
    }

    fn try_unsupported_module_script_count(
        &self,
        parent: &mut ObscuraJsRuntime,
    ) -> Result<usize, String> {
        Ok(self
            .list_scripts(parent)?
            .iter()
            .filter(|script| script.type_attribute == "module")
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
                  const parserNodes = document.querySelectorAll('base[href],style');
                  for (const node of parserNodes) {{
                    if (node.localName === 'base') {{
                      if (!foundBase) {{
                        foundBase = true;
                        try {{ activeBase = new URL(node.getAttribute('href'), activeBase).href; }}
                        catch (_) {{}}
                      }}
                      continue;
                    }}
                    if (node.hasAttribute('data-obscura-adopted')
                        || node.hasAttribute('data-obscura-linked')
                        || node.hasAttribute('data-obscura-external-stylesheets')
                        || node.hasAttribute('data-obscura-inline-import')
                        || node.hasAttribute('data-obscura-imports-materialized')) continue;
                    const type = (node.getAttribute('type') || '').trim().toLowerCase();
                    if (type && type !== 'text/css') continue;
                    stylesheets.push({{
                      authorIndex: authorIndex++,
                      text: node.textContent || '',
                      media: node.getAttribute('media') || '',
                      baseUrl: activeBase,
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

#[derive(serde::Deserialize)]
struct DocumentScript {
    nid: u32,
    src: String,
    #[serde(rename = "type")]
    type_attribute: String,
    text: String,
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
    text: String,
    media: String,
    #[serde(rename = "baseUrl")]
    base_url: String,
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

    fn page(url: &str, html: &str) -> ObscuraJsRuntime {
        let mut runtime = ObscuraJsRuntime::new();
        runtime.set_dom(parse_html(html));
        runtime.set_url(url);
        runtime.run_page_init();
        runtime
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
            1,
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
        assert!(live_frame_ids.is_array(), "liveness must remain an id array");

        frame
            .execute_script(
                &mut parent,
                r#"JSON.stringify = () => "true";"#,
            )
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
        let frame = FrameRealm::new(
            &mut parent,
            1,
            0,
            "https://child.example/frame",
            "<html><body></body></html>",
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
                .map(|(_, _, _, base)| base)
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
    fn one_bad_frame_script_does_not_stop_the_rest() {
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
        assert_eq!(problems.len(), 3, "problems: {problems:?}");
        assert!(problems.iter().any(|p| p.contains("boom")), "{problems:?}");
        assert!(
            problems.iter().any(|p| p.contains("missing.js")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("module")),
            "{problems:?}"
        );
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
}
