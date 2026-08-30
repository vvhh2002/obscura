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
        ├──► obscura-dom/tree.rs          parse HTML into the tree
        │
        └──► obscura-js/runtime.rs        run inline scripts
                  │
                  └──► bootstrap.js + ops.rs    DOM bindings
```

The dispatcher emits CDP events (`Network.requestWillBeSent`, `Page.frameNavigated`, `Page.lifecycleEvent`) back to the client through the same WebSocket.

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
    parser-discovered scripts run
Document.readyState = "interactive"
    Document readystatechange
    deferred classic scripts and non-async modules finish
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

The top document is parsed into a DOM before `obscura-browser` drives its
parser-discovered scripts. Each supported script element is marked as already
started, then its element completion event is dispatched through `EventTarget`,
so a content/IDL handler and `addEventListener` listeners observe one event
path rather than two independent callbacks.

| Parser-discovered script | Element completion event |
| --- | --- |
| External classic script with a successful HTTP fetch | `load`, even if evaluating the fetched source throws. |
| External classic script whose fetch fails, has an unsuccessful HTTP status, is blocked, or misses the script deadline | `error`; its response body is not evaluated. |
| External or inline module whose graph preparation and evaluation succeed | `load`. |
| External or inline module whose graph preparation, dependency fetch, parsing, evaluation, or budget check fails | `error`. A top-level exception is therefore different from a classic-script exception. |
| Inline classic script | No element `load` or `error`; its evaluation exception is reported without changing the document sequence. |

These parser script `load`/`error` events are non-bubbling and non-cancelable
and finish before `DOMContentLoaded`. Deferred external classics and non-async
modules run while `readyState` is `interactive` but still gate
`DOMContentLoaded`.

Top and child realms freeze their parser script and stylesheet node lists,
encounter order, the effective base URL at each individual encounter, and
stable native node ids before any new-document preload runs. A resource before
the first `<base href>` therefore keeps the document URL while resources after
it use that first base; later base elements do not retroactively retarget
already encountered work. Linked-sheet snapshots also retain the raw `href`
and resolved request URL. A preload that rewrites the raw `href` starts new
dynamic work, while a late response for the old parser request is discarded
before CSS installation or owner completion. Original script nodes are marked
as already started at the same boundary. Consequently a preload can insert a
dynamic script or stylesheet, change `<base>`, rewrite a link, or move an
original parser script without enrolling new parser work, duplicating a
request, or executing the original node twice.

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

The membership decision is made when a dynamic resource is prepared. Scripts
created by a Window load handler are therefore post-load work and do not reopen
the completed document. `import()`, arbitrary timers, `fetch()`/XHR, fonts,
media, and CSS `url()` subresources are not added to this DOM load-delay set;
callers that need those results must request a settle or resource warm-up.

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

### Wait conditions, deadlines, and current limits

`WaitUntil::DomContentLoaded` returns after the top DOMContentLoaded transition
and initial bounded frame attachment. It does not wait for the load-delay set.
The continuously owned CDP page, or a library caller that keeps driving browser
turns, can later complete the pending `complete`/Window load transition.
`WaitUntil::Load` waits for that transition. `networkidle0` and `networkidle2`
run after load and require at most 0 or 2 active requests for 500 ms; the
current network-idle poll is a best-effort five-second window and advances the
internal lifecycle even if that window expires.

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

The current model is deliberately bounded and is not yet a complete streaming
HTML scheduler:

- Parser-discovered top-level scripts are driven after the DOM has been built,
  and their completion events all precede DOMContentLoaded. Full parser pause,
  async-script race, and streaming-network ordering are not modeled.
- Child realms currently execute parser-discovered classic scripts in document
  order and synthesize their element `load`/`error` completion. Frame module
  scripts are not evaluated and instead receive `error`. Frame `async` and
  `defer` scheduling is not yet separated from document-order execution.
- Only `body.onload` has the body-to-Window event-handler alias in this path;
  the other body/frameset Window handler aliases are not implemented here.
- Parser-created eager images are DOM load blockers even when page script never
  observes them; `loading="lazy"` images are not. The JavaScript linked-sheet
  `@import` materializer remains bounded at depth 4.
- The `about:blank` fast path commits directly as loaded rather than replaying
  the ordinary event sequence.
- CDP navigation notifications are still emitted as a batched compatibility
  sequence. Raw `Page.navigate` defaults to server-side
  `DomContentLoaded` when `waitUntil` is omitted, so its batched CDP `load`
  notification can precede the DOM Window load described above. Treat
  `document.readyState`, the DOM events, or an explicit server-side
  `waitUntil: "load"` as the authoritative DOM boundary.

The CDP-facing progression remains:

```text
init → commit → domcontentloaded → load → networkidle2 → networkidle0
```

## Storage

`--storage-dir` persists cookies (`cookies.json`) and localStorage (`localStorage/<origin>.json`). Reads on process start, writes on every navigation and on graceful shutdown.

## Stealth

`--stealth` swaps the default `reqwest` client for `obscura-net/wreq_client.rs`, which presents a real browser's TLS ClientHello, ALPN, and cipher order (a consistent Chrome fingerprint, not a randomized one) so the TLS layer matches the User-Agent and JS surfaces. It also applies the bundled tracker blocklist before any request leaves the process. Scripted `fetch()`/XHR go through the same stealth client, so subresource requests carry the same fingerprint as the navigation. `--stealth` is a global CLI flag that applies to `fetch`, `serve`, `scrape`, and `mcp`.

## Workspace conventions

- One crate per layer. Cross-crate calls go through the layer above, not sideways.
- All async is `tokio` with a `LocalSet` because V8 is `!Send`.
- All DOM ops go through `op_dom` to keep the JS/Rust boundary narrow.
