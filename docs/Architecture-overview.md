Obscura is a workspace of nine crates.

```
obscura-cli       CLI entry point. fetch, serve, scrape, mcp.
obscura-cdp       Chrome DevTools Protocol server. WebSocket, dispatch, domain handlers.
obscura-browser   Page type, navigation, lifecycle events.
obscura-js        V8 runtime via deno_core. bootstrap.js + Rust ops.
obscura-dom       DOM tree implementation.
obscura-net       HTTP client, stealth client, cookie jar, robots cache, tracker blocklist.
obscura-mcp       Model Context Protocol server.
obscura-render    CSS cascade, retained layout, text shaping, and CPU paint.
obscura           Embeddable Rust library API (Browser, Page, Element, CookieStore).
```

## Request flow

A `Page.navigate` from a CDP client:

```
CDP client (Puppeteer)
        │ WebSocket frame
        ▼
obscura-cdp/server.rs           accept, route by sessionId
        │
        ▼
obscura-cdp/dispatch.rs         method router, acquires v8_lock
        │
        ▼
obscura-cdp/domains/page.rs     Page.navigate handler
        │
        ▼
obscura-browser/page.rs         navigate_with_wait
        │
        ├──► obscura-net/client.rs        HTTP fetch
        │
        ├──► obscura-dom/tree_sink.rs     retain the pausable html5ever parser
        │
        └──► obscura-js/runtime.rs        run scripts against the live tree
                  │
                  └──► bootstrap.js + ops.rs    DOM bindings
```

The dispatcher forwards the main-frame commit (`Page.frameNavigated`), main
lifecycle events (`Page.lifecycleEvent`), and transport-timed `Network.*`
request/header/data/terminal phases through the same WebSocket while navigation continues. Raw
`Page.navigate` returns at commit when its optional Obscura `waitUntil`
extension is absent. The observer belongs to the target rather than one command,
so later fetch/XHR and response-body continuation reuse the same real-time path.
Child-frame lifecycle delivery is described below and retains the snapshot
drain as a compatibility fallback for pages without an observer.

## Rendering flow

`obscura-render` consumes the shared DOM and computed style state. Taffy
provides the flex/grid foundation; Obscura adds browser formatting behavior,
text shaping, intrinsic replaced-element sizing, retained geometry, scrolling,
and CPU-backed paint. `obscura-js` exposes renderer-owned geometry to DOM APIs,
`obscura-browser` prepares resources and owns capture, and `obscura-cdp` maps
screenshots, screencast frames, and raster PDF output onto CDP.

Layout is retained between captures and invalidated by relevant DOM, style,
viewport, scroll, animation, font, and resource changes. The same geometry
therefore drives browser APIs and paint instead of maintaining separate
measurement and screenshot models.

## Single V8 isolate

All pages in a process share one V8 isolate. The isolate is single-threaded by design.

`obscura_js::v8_lock::global()` is a `tokio::sync::Mutex` that serializes V8 work. A handler that wants to run JS must acquire the lock first:

```rust
let _guard = obscura_js::v8_lock::global().lock().await;
page.evaluate(expr).await
```

The dispatcher routes long-running operations (navigation, eval) through `process_with_interception` in `server.rs`, which spawns the work onto the tokio `LocalSet` and releases the dispatcher to keep handling other CDP messages.

This is why `Target.createTarget` from many concurrent clients works: each `newPage` returns immediately while the actual navigation runs in a spawned task.

## Robustness

One page cannot hang or crash the process. `obscura-js/runtime.rs` provides a V8 termination watchdog (`arm_watchdog`, `run_event_loop_bounded`) that terminates the isolate from a separate thread when synchronous work overruns a budget, because `tokio::time::timeout` cannot preempt synchronous V8. It bounds the post-load settle, the navigation event-loop pumps, and `--eval`. The complete script phase is bounded by `OBSCURA_SCRIPT_DEADLINE_MS`; enhancement modules have a shorter per-module graph-loading/evaluation budget controlled by `OBSCURA_MODULE_BUDGET_MS`, while modules mounting an empty SPA shell receive the full script deadline. `obscura-js/cdp_watchdog.rs` is a single shared watchdog the dispatcher arms around every CDP command, so a runaway page cannot hold the V8 lock and wedge other sessions (tunable via `OBSCURA_CDP_COMMAND_TIMEOUT_MS`). `op_dom` is wrapped in `catch_unwind` so a DOM-op panic degrades to a null result instead of aborting the process through V8's FFI frame, and `obscura-dom/tree.rs` rejects cyclic reparenting that would make tree walks loop forever. Scripted `fetch()`/XHR and module network requests are timeout-bounded (`OBSCURA_FETCH_TIMEOUT_MS`), and the one-shot `fetch` CLI has a process-level hard deadline as a final backstop.

## JS bridge

`obscura-js/js/bootstrap.js` provides the browser globals: `document`, `window`, `navigator`, `location`, observers, fetch, indexedDB, etc.

`obscura-js/src/ops.rs` registers Rust ops that the bootstrap calls into:

```js
Deno.core.ops.op_dom('insert_before', parentNid, refNid, newNid);
```

Adding a Web API usually means:

1. JS shim in `bootstrap.js` that exposes the API surface.
2. Rust op in `ops.rs` that performs the side effect (DOM mutation, fetch, crypto).
3. Register the op in `build_extension()`.

Worked example: [Adding a CDP method or Web API](Adding-a-CDP-method-or-Web-API.md).

## CDP session model

Each CDP client connection gets attached to one or more targets.
Session IDs are `"{targetId}-session"`. The dispatcher routes by `sessionId` in the incoming frame to the right `Page`.

Targets are created by `Target.createTarget`. Closing the WebSocket detaches all sessions but leaves the pages running.

## Document and Window lifecycle

The DOM lifecycle and the CDP lifecycle are related but separate. For an
ordinary top-level HTTP, HTTPS, or data document, the DOM-facing sequence is:

```text
Document.readyState = "loading"
    parser-blocking scripts run
    parser reaches EOF
Document.readyState = "interactive"
    Document readystatechange
    defer classics and non-async modules finish
    Document DOMContentLoaded
    child documents and load-delaying resources finish
Document.readyState = "complete"
    Document readystatechange
    Window load
```

Both `readystatechange` events are non-bubbling and non-cancelable and target
the `Document`. `DOMContentLoaded` is dispatched at the `Document`, is
non-cancelable, and bubbles through the Window event path. A listener on Window
therefore still sees `event.target === document` and
`event.currentTarget === window`. The navigation `load` event is dispatched at
Window once, after the transition to `complete`. It is non-bubbling and
non-cancelable, uses the legacy `Document` target, and has Window as its current
target.

`body.onload` is an alias for `window.onload`; it is not a second event target.
The IDL property, `window.onload`, and a parsed `<body onload="...">` attribute
all select the same Window handler. That handler and Window
`addEventListener("load", ...)` listeners run from the single Window load
dispatch with `this === window`. The parsed body handler is installed at the
body start-tag encounter, before a later script or stylesheet owner callback in
the body can register another Window load listener, so registration order is
preserved even when the body contains no script element.

Element lifecycle events use the same listener records as the other
`EventTarget` implementations. Registration is de-duplicated by callback,
type, and capture flag; `once`, `AbortSignal`, object `handleEvent` listeners,
and capture-at-target ordering are honored. IDL/content handlers retain their
position relative to listeners, dispatch uses one listener snapshot, and
`eventPhase`, `target`, and `currentTarget` are set for each path entry before
`currentTarget`/`eventPhase` are cleared after dispatch. Script, stylesheet,
image, and iframe-owner `load`/`error` events all use this path. Events emitted
by the browser lifecycle are trusted and use closure-captured constructors and
dispatch primitives; replacing `Event`, `dispatchEvent`, or the hidden host
entry points from page code cannot suppress or forge their completion.

### Parser script completion events

The top document uses a retained html5ever parser and the same live `DomTree`
as V8. Parser-inserted classic scripts yield the tokenizer; source after the
script is not visible until the host executes or schedules that script and
resumes parsing. External classic `defer` and `async` fetches start at their
encounter, defer scripts execute after EOF in encounter order, and async
classics execute in response-completion order while delaying load rather than
DOMContentLoaded. Each supported script element is marked as already started,
then its element completion event is dispatched through `EventTarget`, so a
content/IDL handler and `addEventListener` listeners observe one event path
rather than two independent callbacks.

| Parser-discovered script | Element completion event |
| --- | --- |
| External classic script with a successful HTTP fetch | `load`, even if evaluating the fetched source throws. |
| External classic script whose fetch fails, has an unsuccessful HTTP status, is blocked, or misses the script deadline | `error`; its response body is not evaluated. |
| External or inline module whose graph preparation and evaluation succeed | `load`. |
| External or inline module whose graph preparation, dependency fetch, parsing, evaluation, or budget check fails | `error`. A top-level exception is therefore different from a classic-script exception. |
| Inline classic script | No element `load` or `error`; its evaluation exception is reported without changing the document sequence. |

These parser script `load`/`error` events are non-bubbling and non-cancelable.
Deferred external classics and non-async modules gate `DOMContentLoaded`. At
EOF the host changes `readyState` to `interactive` and dispatches its
`readystatechange` before evaluating that ordered post-parse queue. Parser
async classic completion may occur after DCL but must precede Window load.

Parser-owned requests retain their encounter order, effective base URL, stable
native node id, and top-document generation. A resource before the first
`<base href>` therefore keeps the document URL while later resources use that
first base; later base elements do not retroactively retarget started work.
Linked-sheet snapshots also retain the raw `href` and resolved request URL. A
rewrite starts dynamic work, while a late response for the old request is
discarded before CSS installation or owner completion.

At every live-tokenizer yield, a realm-local, weak-set-guarded resource sweep
starts the parser-created eager images, selected media/poster/default-track
requests, and non-lazy child browsing contexts exposed so far. This runs before
the parser-blocking script at that boundary. Streaming child realms skip the
initial inert discovery tree, so those requests are neither started ahead of
the tokenizer nor restarted by the EOF sweep.

While a parser-inserted script is running, `document.write()`/`writeln()` feed
the browser-owned primary tokenizer at that script's insertion point. The
parser temporarily removes the unread response tail, parses the written input
with the existing tokenizer/tree-builder state, synchronously returns and runs
nested inline parser scripts, then restores the outer script pause and unread
tail. Recursively written markup therefore stays in the same live DOM and
cannot expose later response source. Once the document parser has reached EOF,
the existing persistent write-stream compatibility path remains available; it
does not implement full `document.open()`/`close()` document replacement.

The ordinary HTTP client retains an owned response stream across commit.
Charset selection uses an authoritative HTTP charset or at most a 1024-byte
HTML sniff, after which one incremental `encoding_rs` decoder feeds transport
chunks to the retained parser. Raw bytes are accumulated simultaneously for
response-body and archive consumers. The stealth transport, `data:`, and
synthetic documents remain buffered. Import maps and module preparation run at
their parser positions. Each static graph receives a graph-start import-map snapshot;
resolved pairs are then frozen in the document cache, so a later import map
cannot alter work already started. deno_core 0.350 `RecursiveModuleLoad`, not a
`deno_graph` dependency, discovers and concurrently fetches the static graph
through the realm loader's completed/in-flight source cache. Stylesheet roots
are fetched at the next blocking-classic gate or EOF, not at link encounter,
and module graph preparation currently holds the parser instead of racing
alongside it. See [Document loading and
capture readiness](Document-loading-and-capture-ready.md#parser-and-script-scheduling)
for these precise implementation boundaries.

### Load-event delay set

After `DOMContentLoaded`, `Page` alternates cooperative JavaScript turns with
native frame attachment until the load-event delay set is empty. The current
set contains:

- A connected, dynamically inserted external classic or module script, and an
  inline dynamic module, prepared before `readyState` becomes `complete`.
  This includes scripts inserted by a `DOMContentLoaded` listener. Completion
  means the element's `load` or `error` processing has finished.
- Every connected parser-created eager `HTMLImageElement`, plus a dynamic image
  request which the shim queues before `complete`. Images with
  `loading="lazy"` are intentionally excluded. A tracked image leaves the set
  after image load or decode failure.
- A dynamically inserted `<link rel="stylesheet" href="...">` prepared before
  `complete`. It leaves the set only after the sheet and the supported recursive
  `@import` graph have been materialized and its `load` or `error` event has
  run. Ordinary and null-namespace `href`/`rel` mutations use the same loader;
  enabling an initially disabled link starts it, and stale completion after a
  removal or rewrite cannot consume the replacement request's event.
- Child document fetches which are reserved or queued, and live child realms
  whose own load sequence is unfinished.
- A selected audio/video source whose preload/autoplay policy starts a metadata
  request, a video poster request, and a selected default text-track request.
  Obscura stops media at metadata and does not decode or play it.

The membership decision is made when a dynamic resource is prepared. Scripts
created by a Window load handler are therefore post-load work and do not reopen
the completed document. Arbitrary timers, `fetch()`/XHR, `FontFace`, and
ordinary CSS/SVG `url()` subresources are not direct DOM load blockers. They
are observed by the separate capture-ready/resource-preparation policy when
they actually start work. A timer alone does not keep that policy busy, but a
timer-caused request or connected-DOM mutation resets its quiet window.

### Frame completion order

Every child realm independently transitions from `loading` to `interactive`,
fires `readystatechange` and `DOMContentLoaded`, waits for its own tracked
resources and children, then transitions to `complete` and fires its Window
load. Frames are completed from the leaves upward. Immediately after a child
Window load, the parent dispatches one non-bubbling, non-cancelable `load` on
the matching `<iframe>` owner. Only then can the parent Window load and its own
owner event run. The top Window load waits for the same process across every
direct child.

A frame parser stylesheet root is not completed when only its root response
arrives. Obscura fetches and materializes the bounded recursive `@import` graph
first, then dispatches the root link owner event at its frozen parser encounter
position. Thus root-link completion precedes that child Window load, while the
whole import graph precedes the root-link event.

Owner dispatch is keyed by frame id and checks that the element is still
connected and still owns that frame. This suppresses duplicate events and
stale completion after an iframe is removed or its `src`/`srcdoc` is replaced.
The host converts frame lifecycle and liveness probe results directly from the
target realm's V8 values; replacing the realm's `JSON.stringify` cannot forge
those decisions. A probe error, non-boolean owner result, or malformed live-id
list fails the page lifecycle and retains the existing realms instead of
discarding a possibly live frame or continuing to a false successful load.
A write to the fallback children of an already active iframe (for example,
`iframe.innerHTML = ...`) does not replace that nested browsing context or
dispatch another owner load. Descendant iframe elements actually removed by a
subtree replacement are still cancelled normally.
A failed iframe fetch has no child realm and follows the compatibility path
which dispatches the owner `load` directly.

Child V8 contexts are created as managed snapshot realms. The in-tree
`deno_core 0.350.0` patch gives each realm a separate `ModuleMap`, initializes
the context embedder slots used by V8's dynamic-import and import-meta
callbacks, retains the realm while attached, and includes each attached realm's
module map in the runtime event-loop poll. Detach/replacement explicitly
retires the registration before stale work can run. Consequently a dynamic
`import()` is loaded and evaluated by the frame which initiated it. Static
graphs use deno_core's `RecursiveModuleLoad` plus Obscura's graph-start import
map snapshot and source cache; after instantiation, graph ids are read from the
actual realm `ModuleMap` so evaluating a root also populates the host cache for
its descendants. Each inline module root is retained by its explicit ModuleId
but omitted from the URL name map, so multiple inline elements can share the
document URL without sharing source or evaluation state; V8 still observes the
canonical document URL through `import.meta.url` and relative resolution.
Parent and sibling realms retain independent import maps,
module maps, source caches, and evaluation caches. The ordinary
frame-attachment path invokes the combined classic/module scheduler. This path
has focused regression coverage for DCL interaction, detach/generation
cancellation, activity accounting, rejection propagation, and realm
retirement. Fully concurrent async ordering and complete CORS/final-URL
attribution remain bounded compatibility areas. Any unexecuted module remains
an archive diagnostic.

### Wait conditions, deadlines, and current limits

`WaitUntil::Commit` returns after response metadata, URL, the live empty parser
tree, V8 realm, and preloads are installed. The raw CDP owner deliberately
keeps driving that parser continuation toward Load after sending its early
response. A directly embedded page retains the continuation but needs the
autonomous owner or a subsequent settle call to resume it. The CLI's normal
post-navigation settle follows the same path;
`--wait 0` deliberately leaves the document at commit.
`WaitUntil::DomContentLoaded` returns after the top DCL transition and initial
bounded frame attachment. It does not wait for the load-delay set.
`WaitUntil::Load` waits for Window load.
`networkidle0` and `networkidle2` run after load and require at most 0 or 2
active requests for 500 ms. The network-idle poll has a five-second ceiling; if
the threshold is not observed, navigation returns an error and does not publish
the network-idle milestone. Capture-ready reports timeout and pending state
separately when callers need a diagnostic observation instead of navigation
failure.

`WaitUntil::CaptureReady` first reaches Load and then applies a second bounded
policy. `CaptureReadyOptions` defaults to a five-second total timeout and a
500 ms quiet window. Its report separates `quiescent`, `timed_out`, and
`archive_complete`, includes pending network/resource/frame counters, and
returns sorted incompleteness reasons. This is deliberately not another DOM
lifecycle event. See [Document loading and capture
readiness](Document-loading-and-capture-ready.md#rust-api).

CDP `Runtime.evaluate` with `awaitPromise: true` alternates runtime tasks with
the same page-owned frame driver. This matters when the awaited promise is
resolved by `iframe.onload`: the child realm must be attached and completed by
`Page` before the owner event can settle the promise, so keeping the entire
await inside the JavaScript runtime would deadlock those two operations.
The command timeout is one absolute deadline across the initial synchronous
evaluation, autonomous browser turns, and promise settlement. Likewise,
`Runtime.callFunctionOn` reuses one deadline for the function invocation and
its returned promise. A V8 termination watchdog bounds synchronous code, while
deadline cleanup removes the temporary promise sentinel so a timed-out command
does not poison the retained realm.

The connection-owned CDP pump retains one pinned autonomous Page turn while it
forwards the live network events produced by that turn. Merely observing
`requestWillBeSent`, response data, or a terminal phase therefore cannot drop
and restart the parser script, stylesheet graph, module, or frame request which
emitted it. Such host-owned resource awaits are marked non-cancelable and an
unrelated protocol command is deferred until that await returns; a matching
Fetch-domain continue/fulfill/fail response is resolved in place without
cancelling the turn.

Other autonomous work, including the primary body-stream continuation, is
cancellation-safe. If a higher-priority CDP command interrupts it, an
`Rc`-backed lease restores the exact `PendingDocumentLoad`: decoder and byte
offset, tokenizer pause, ordered post-parse index, and response stream. The
command can inspect the committed DOM immediately and a later turn resumes the
same parse. This scheduling cancellation is not a network failure and does not
emit `Network.loadingFailed`. A replacement navigation is different: before
resetting the observer generation, CDP emits exactly one canceled terminal for
every still-active request owned by the outgoing loader. Generation checks then
suppress any stale evaluation or element/lifecycle event.

The load wait shares the absolute script-phase deadline and V8 watchdog; it
does not receive a fresh budget after DOMContentLoaded. This includes script
bodies and callbacks reached while draining the delay set, frame lifecycle
callbacks, iframe-owner handlers, and the final Window load handler. A
cancelled navigation drops and disarms its watchdog rather than leaving a
detached thread which could terminate the reused isolate later.
Frames attached by an autonomous turn after an earlier
`WaitUntil::DomContentLoaded` return receive their own scoped lifecycle
watchdog; an overrun in parser work or the frame DOMContentLoaded callback marks
both the frame and page failed instead of pinning the autonomous pump.
`OBSCURA_SCRIPT_DEADLINE_MS` defaults to 30,000 ms and covers parser script
fetch/execution, module work, and the remaining load blockers. If a `load` wait
reaches it, navigation fails with the document left blocked rather than
synthesizing `readyState = "complete"` or a Window load event. The page-scoped navigation timeout, defaulting from
`OBSCURA_NAV_TIMEOUT_MS` to 30,000 ms, bounds the whole navigation and can fire
first. The CLI `--timeout` sets that page timeout and also wraps navigation.
Raise both the script and caller/navigation deadlines when a page needs more
time. Script-initiated network operations have their own
`OBSCURA_FETCH_TIMEOUT_MS` deadline, also 30,000 ms by default.

Top-level enhancement modules use `OBSCURA_MODULE_BUDGET_MS`, 3,000 ms by
default, for graph preparation plus evaluation; an empty SPA shell receives
the full script deadline. A bounded renderer host-call grace can be configured
with `OBSCURA_MODULE_HOSTCALL_GRACE_MS`, but the page-wide script deadline
remains authoritative.

The current model is deliberately bounded:

- The ordinary top-level HTTP path is transport-streamed and incrementally
  decoded. The stealth transport remains buffered. Stylesheet fetches start at
  the next blocking-classic gate or EOF rather than link encounter; module
  preparation occurs at parser position but holds the parser instead of racing
  alongside it. Writes from the currently paused parser-inserted script use the
  primary tokenizer; writes after parser EOF use the separate compatibility
  write stream.
- Browser-owned child documents use the live pausable parser, managed realms,
  generation cancellation, ordered defer classics, and real module
  evaluation. Their already-fetched response is supplied to the tokenizer as
  one buffer, while external entry sources and stylesheets are prefetched;
  ready async work therefore has simplified encounter-order timing.
- Managed frame-module loading has focused coverage for static graphs,
  dynamic import, import-map freezing, TLA, realm isolation, duplicate
  evaluation, and detach/replacement cancellation. CORS/final-URL attribution
  and fully concurrent async timing remain narrower than a complete browser.
- Only `body.onload` has the body-to-Window event-handler alias in this path;
  the other body/frameset Window handler aliases are not implemented here.
- Parser-created eager images are DOM load blockers even when page script never
  observes them; `loading="lazy"` images are not. The linked-sheet `@import`
  materializer remains bounded at depth 4. Eager connected iframes enter the
  load driver; `iframe[loading=lazy]` starts on a post-load turn and remains
  visible to capture-ready. Viewport-distance-based lazy selection is not yet
  implemented.
- Explicit top-level `about:blank` now follows the normal synthetic lifecycle
  without a network request. Iframes keep one stable WindowProxy while blank,
  managed, and replacement document backends are swapped; removal detaches the
  backend without invalidating page-held proxy references.
- CDP lifecycle milestones are sent while navigation continues. Raw
  `Page.navigate` defaults to commit when `waitUntil` is omitted, and
  `Page.lifecycleEvent` is only sent to sessions that enabled it. A persistent
  target observer forwards request start, headers, data chunks, and exactly one
  success/failure terminal phase; completed response snapshots are not replayed
  as a duplicate request sequence.
- Media resource selection and metadata loading are modeled, but media
  decoding and playback are not. Service Workers and full re-entrant
  `document.open()`/`close()` are also outside the current scope.

The observable milestone order is:

```text
request start/headers → init/commit → data/parser → DOMContentLoaded → load → requested network-idle
```

## Storage

`--storage-dir` persists cookies (`cookies.json`) and localStorage (`localStorage/<origin>.json`). Reads on process start, writes on every navigation and on graceful shutdown.

## Stealth

`--stealth` swaps the default `reqwest` client for `obscura-net/wreq_client.rs`, which presents a real browser's TLS ClientHello, ALPN, and cipher order (a consistent Chrome fingerprint, not a randomized one) so the TLS layer matches the User-Agent and JS surfaces. It also applies the bundled tracker blocklist before any request leaves the process. Scripted `fetch()`/XHR go through the same stealth client, so subresource requests carry the same fingerprint as the navigation. `--stealth` is a global CLI flag that applies to `fetch`, `serve`, `scrape`, and `mcp`.

## Workspace conventions

- One crate per layer. Cross-crate calls go through the layer above, not sideways.
- All async is `tokio` with a `LocalSet` because V8 is `!Send`.
- All DOM ops go through `op_dom` to keep the JS/Rust boundary narrow.
