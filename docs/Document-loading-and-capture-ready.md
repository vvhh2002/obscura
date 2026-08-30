# Document loading and capture readiness

Obscura exposes two different completion boundaries:

- `load` is the document lifecycle event defined by HTML. It is suitable when
  page code is waiting for `window.onload`.
- `capture-ready` is an Obscura observation boundary. It waits for post-load
  resource and DOM activity to become quiet, then reports whether the resource
  archive has any known gaps.

Do not use `capture-ready` as a replacement name for `load`. A request may
correctly continue after Window load and still matter to a screenshot or
response archive.

## Parser and script scheduling

The top document uses html5ever's incremental tokenizer against the same
`DomTree` that is installed in V8. The tokenizer yields at parser-inserted
script end tags. A parser-blocking classic script therefore cannot see source
after that tag, while mutations made by the script remain in the live tree when
tokenization resumes.

For the ordinary HTTP transport, navigation keeps the response body open after
headers. An authoritative HTTP charset can commit immediately; otherwise
Obscura uses at most the first 1024 response bytes for HTML encoding sniffing
(the transport may deliver those bytes as part of a larger first chunk, which
is retained for parsing and capture). A retained `encoding_rs` decoder accepts each transport chunk and feeds the
tokenizer in bounded UTF-8 slices. The same raw bytes are accumulated for the
resource archive and `Network.getResponseBody`. Synthetic `about:blank` and
`data:` documents are local buffered inputs. The optional stealth transport is
also still buffered because its backend does not yet expose an owned response
stream.

The implemented top-document classic-script ordering is:

| Script | Fetch/evaluation behavior | Delays |
| --- | --- | --- |
| Inline or external parser-blocking classic | Runs at the tokenizer pause; source after the tag is not yet visible. | parser, DCL, load |
| External classic with `defer` | Fetch starts when encountered; executes after EOF in encounter order. | DCL, load |
| External classic with `async` | Fetch starts when encountered; ready results execute in completion order while parsing advances. | load, not DCL |

At every tokenizer yield, Obscura starts the parser-created eager images,
selected media/poster/default-track requests, and non-lazy child browsing
contexts which have become visible so far. A realm-local weak set makes the
sweep idempotent and shares its markers with dynamic insertion steps. Child
streaming realms skip resource startup on their temporary inert discovery tree,
so a resource cannot run ahead of the live parser. At EOF, `readyState` changes
to `interactive` and its `readystatechange` fires before ordered defer classics
and ordinary modules evaluate; DOMContentLoaded follows that queue.

Async results carry the current top-document generation. A response for a
replaced document is discarded before evaluation or element event dispatch.
During an active parser-inserted script, `document.write()` and `writeln()` use
the retained primary tokenizer itself. The parser suspends its unread response
tail, consumes the written input at the calling script's insertion point, and
restores the outer pause and tail after that call. A written inline parser
script is yielded at the normal html5ever script boundary, executed
synchronously, and may recursively write more markup before the outer script
continues. Tokenizer state and the live DOM are shared throughout. After parser
EOF, calls fall back to the existing persistent write-stream compatibility
path. Full `document.open()`/`close()` re-entrant document replacement remains
outside the current implementation.

Import maps and top-level module preparation run at their parser positions.
When a static graph starts, its loader snapshots the import map then propagates
that snapshot from each referrer to its resolved children. A map encountered
while the graph is fetching therefore cannot rewrite that graph. The
document-wide resolved-module cache freezes both successful and failed
`(referrer, specifier)` resolutions, while a later graph can still use rules
which were not visible to the earlier snapshot. Dynamic `import()` consults
that same document cache from its owning realm at execution time.

Obscura does not depend on `deno_graph`. The pinned deno_core 0.350
`RecursiveModuleLoad` performs the equivalent recursive static-graph discovery
and concurrent dependency fetch. The realm loader supplies the resulting
source through deno_core's `ModuleLoader`, with per-realm completed and
in-flight source caches to avoid duplicate requests. After instantiation, the
host reads graph membership from the realm's real `ModuleMap` and caches
evaluation by module id, including static descendants.

Inline module elements use distinct unregistered root ModuleIds. Their module
records retain the canonical document URL for `import.meta.url`, relative
imports, and import-map scopes, but that shared URL is not entered into the
realm's importable-name table. Preparing a later inline element therefore
cannot alias or overwrite an earlier element's source or evaluation state.

Before a parser-blocking classic executes, Obscura fetches and recursively
materializes the blocking stylesheets encountered so far; roots remaining at
EOF are materialized before defer/module evaluation. Consequently the
following cases are not yet equivalent to a fully concurrent browser loader:

- stylesheet requests start at the next blocking-classic gate or EOF, rather
  than immediately when the link or style is encountered;
- module graph preparation is awaited at the parser pause instead of fetching
  in parallel with continued parsing, and async-module completion/DCL races
  remain simplified.

## Child frame realms

Every attached child document owns a separate V8 context, DOM, origin/base,
document generation, import map, and module cache while sharing the page HTTP
client, cookies, request interception, and response capture. Parent, sibling,
and child globals do not share module state.

The repository pins and vendors `deno_core 0.350.0` to support managed snapshot
realms. Each managed realm has its own loader and `ModuleMap`. Its context
embedder slots point at that realm-local map, so V8 routes `import()` and
`import.meta` callbacks back to the frame which initiated them instead of the
top realm. The parent runtime owns each attached realm and polls its module
map's dynamic-import and module-evaluation work, so top-level `await` can
complete without a dangling context or module-map pointer. Detaching or
replacing a frame explicitly retires the realm's strong registration and
event-loop polling before later work can run. See
[`vendor/deno-core/OBSCURA-VENDORING.md`](../vendor/deno-core/OBSCURA-VENDORING.md)
for the source record and [`vendor/deno-core/LICENSE`](../vendor/deno-core/LICENSE)
for the MIT license.

The managed-realm module API is tested directly for inline modules, external
graphs, graph-start import-map freezing, sibling cache isolation, realm-local
dynamic import, duplicate descendant evaluation, and top-level await. Ordinary
frame attachment invokes the combined classic/module scheduler; a module which
cannot be prepared or evaluated remains an archive-incompleteness diagnostic
instead of being treated as captured.

Browser-owned frame documents use the same `StreamingDocumentParser` type and
the same live-DOM pause boundary as the top document. A blocking child script
cannot see source after its end tag, defer scripts run after EOF in encounter
order, and frame completion proceeds from leaves to root: child Window load,
owner iframe load, then the parent can finish. Document-generation and owner
liveness checks suppress work after replacement or removal.

The child transport and scheduler are deliberately one step less concurrent
than the top path. The iframe response is currently fetched and decoded in
full, then supplied as one tokenizer input; Page also prefetches external
classic/module entry sources and stylesheet graphs before the child parser
runs. The live parser still pauses correctly, but ready async classics execute
in encounter order rather than actual socket-completion order, module graph
preparation is awaited at encounter. While the child parser is active, frame
`document.write()` uses that child's primary tokenizer and supports recursive
written inline scripts; calls after its EOF use the same compatibility path as
the top document. These are timing/concurrency differences, not a return to the
former fully parsed detached-DOM runner.

An explicit top-level `about:blank` navigation uses a synthetic HTML document.
It produces the ordinary `loading` → `interactive`/DCL → `complete`/load
sequence without a Document network request. A fragment is allowed;
unsupported `about:*` URLs, including direct top-level `about:srcdoc`, fail.
`about:srcdoc` remains an internal URL for iframe `srcdoc` documents. An
iframe owns one stable WindowProxy for the life of its browsing context: the
initial inherited-origin blank realm, a later managed document realm, and a
replacement all swap the proxy backend without changing `contentWindow`
identity. Removal detaches the backend while page-held proxy references remain
safe to inspect.

## What delays Window load

The current load-delay behavior is summarized below. “Capture-ready” means the
work is observed by the later quiet-window/resource checks, not that a response
is guaranteed to succeed.

| Work | Delays Window load | Observed by capture-ready |
| --- | --- | --- |
| parser `async` classic/module and connected dynamic scripts started before completion | yes | yes |
| eager selected images | yes | yes |
| `loading="lazy"` images | no | only if a request is actually selected/started during the capture policy |
| linked stylesheets and supported recursive `@import` | yes | yes |
| live child documents and their load-delaying descendants | yes | yes |
| `iframe[loading="lazy"]` child documents | no | yes; navigation starts just after the parent load boundary |
| selected audio/video source when preload/autoplay starts it | yes, through metadata fetch | yes |
| video poster and default text track fetch | yes | yes |
| `fetch()` and XHR | no | yes |
| timers by themselves | no | no; a timer-caused DOM mutation or request resets the quiet window |
| `FontFace` and ordinary CSS/SVG `url()` resources | no direct DOM load blocker | yes when renderer/resource preparation starts them |

Obscura implements media resource selection and the observable network/ready
states needed for loading and capture. A successful media fetch stops at
`HAVE_METADATA`; container decoding, playback, audio/video dimensions, and
rendering are not implemented. Eager connected iframes enter the load driver.
`iframe[loading=lazy]` is held outside the parent load-delay set and starts on
the first post-load turn so capture-ready can still observe and archive it;
viewport-distance-based lazy selection is not implemented.

A transport-level failure (for example, connection refusal or a response body
which terminates prematurely) can still become quiescent after its promise is
rejected, but it is retained as an archive diagnostic. It therefore yields
`archive_complete=false`. An HTTP error status with a complete response is not
a transport failure: a fully captured 404 or 500 response can remain archive
complete.

## Rust API

`Page::goto()` retains its library compatibility behavior and waits for Load.
Use `goto_with_wait()` for another boundary:

```rust
use obscura::{Browser, CaptureReadyOptions, WaitUntil};
use std::time::Duration;

let browser = Browser::new()?;
let mut page = browser.new_page().await?;
page.goto_with_wait("https://example.com", WaitUntil::Load).await?;

let report = page.wait_for_capture_ready_with_options(CaptureReadyOptions {
    timeout: Duration::from_secs(5),
    quiet_window: Duration::from_millis(500),
}).await;
```

`WaitUntil` supports `Commit`, `DomContentLoaded`, `Load`, `NetworkIdle2`,
`NetworkIdle0`, and `CaptureReady`. `WaitUntil::CaptureReady` first reaches
ordinary Load, then runs the default capture-ready waiter.

`Commit` retains a parser continuation. The continuously owned CDP page drives
that continuation after sending its early command response. The embedded Rust
page does not start an independent background task, but `settle()` and
`settle_following_navigations()` resume the retained parser before pumping
later work; the low-level fixed-duration and autonomous page pumps do the same.
The CLI's ordinary post-navigation settle therefore completes parsing after
`--wait-until commit`.
With a zero-length settle, the caller deliberately observes the initial
committed DOM instead.

`CaptureReadyReport` keeps readiness and archive diagnostics separate:

| Field | Meaning |
| --- | --- |
| `quiescent` / `ready` | The page was idle for the requested quiet window. `ready` is the compatibility alias. |
| `timed_out` | The quiet boundary was not reached within the total timeout. |
| `archive_complete` | No known engine/archive diagnostic was present at the final observation. |
| `elapsed`, `quiet_for`, `lifecycle` | Timing and final DOM lifecycle state. |
| `pending_network_requests` | Page-wide requests still awaiting a response or error. |
| `pending_resource_work` | Dynamic/parser-script or other response-producing queues still active. |
| `pending_frame_documents`, `pending_frame_messages`, `pending_frames` | Child-document, cross-frame delivery, and frame lifecycle counts. |
| `incomplete_reasons` | Sorted diagnostic text for failures, safety caps, unsupported work, and waiter errors. The wording is not a stable machine schema. |

`is_complete()` requires quiescence, no timeout, and `archive_complete`. The
default total timeout is five seconds and the quiet window is 500 ms. A waiter
or lifecycle failure is surfaced through `incomplete_reasons`; an exhausted
budget is surfaced through `timed_out`. Neither is converted to readiness just
because the network queue became empty. A completed non-2xx response may still
be a completely captured response under archive semantics.

With the `render` feature, capture-ready runs bounded, repeatable final-DOM
resource-preparation passes inside that same five-second budget. Ordinary
CSS/SVG `url()` assets, authored fonts, posters, and responsive image
candidates enter the observation barrier there. Navigation no longer performs
those passes before DOMContentLoaded or Window load, so decorative resources
cannot accidentally become lifecycle blockers. Explicit `settle()` and
screenshot/archive preparation retain their own warm-up paths.

`archive_complete` reports known engine diagnostics, capture-ready deadline
failures, and non-zero `ResourceCapture.omitted_resources`/`omitted_bytes` when
response capture is enabled. It does not enable capture by itself; callers
should still validate the returned capture artifact before writing it.
Renderer-enabled archive code must also run its bounded resource-preparation
passes before claiming that final-DOM images, fonts, CSS/SVG URLs, and posters
were covered.

## CLI

`obscura fetch` accepts:

```bash
obscura fetch https://example.com --wait-until commit
obscura fetch https://example.com --wait-until capture-ready
```

The complete token list is `commit`, `domcontentloaded`, `load`,
`networkidle2`, `networkidle0`, and `capture-ready`; the CLI default remains
`load`. The ordinary post-navigation `--wait` policy still runs after the
selected boundary.

## CDP behavior and migration

Raw CDP `Page.navigate` without Obscura's optional `waitUntil` parameter now
returns at document commit. The navigation continues in the owned page and
forwards the main-frame commit/DCL/load milestones and network transport phases
as work completes. Child-frame attach/navigate/DCL/load/detach notifications
use the same persistent observer; a bounded frame snapshot drain remains only
as a compatibility fallback for pages created outside that live server path.
Obscura's non-standard
`waitUntil` extension can request `domcontentloaded`, `load`, `networkidle2`,
`networkidle0`, or `capture-ready` when a raw CDP caller wants the command
response held to that boundary.

Call `Page.setLifecycleEventsEnabled` with `enabled: true` to receive
`Page.lifecycleEvent`. Subscription is session-scoped. The standard
`Page.domContentEventFired`, `Page.loadEventFired`, and
`Page.frameStoppedLoading` events continue independently. Main-frame commit,
DCL/load, request/header/data/terminal phases, and a requested network-idle notification
are no longer reconstructed as one post-navigation batch. Obscura does not emit
network idle merely because DCL or load occurred. The existing network-idle
waiter has a five-second ceiling. If the requested 500 ms threshold is not
observed by then, navigation returns an error and no network-idle milestone is
published. Capture-ready instead exposes `timed_out` and pending counters in
its report.

The browser-to-CDP observer is retained for the lifetime of the target rather
than one navigation command. It maps request start, response headers, each data
chunk, and the one success/failure terminal phase when the transport publishes
them, including fetch/XHR work started after navigation. Completed response
snapshots remain the archive/body authority and are explicitly not replayed as
a second CDP request sequence.

After commit, the connection owns one pinned autonomous Page turn while
forwarding events produced by that turn. Parser script, stylesheet, module, and
frame awaits which cannot be safely reconstructed are marked non-cancelable;
ordinary protocol commands wait for the await to return, while the Fetch-domain
resolution needed by that same await is handled without dropping it. This
prevents observing a request-start event from cancelling and retrying the
request which emitted it.

The retained primary body continuation is cancellation-safe. When an incoming
CDP command interrupts that autonomous turn, a lease restores the exact
decoder, decoded-byte offset, tokenizer pause, post-parse position, and response
stream. The command can run against the committed DOM, and a later turn resumes
the same continuation. This scheduler cancellation emits no transport failure.
When a new navigation actually replaces the document, however, the observer
first emits one canceled `Network.loadingFailed` terminal for each request
still active under the outgoing loader, then advances generation; stale old
results cannot execute or dispatch lifecycle/element events.

High-level Puppeteer and Playwright navigation APIs apply their own defaults
and listen for the lifecycle/network events they require. Code which sends raw
`Page.navigate` and previously assumed its response meant DCL must migrate by
either:

1. subscribing before navigation and waiting for the desired lifecycle event;
2. passing Obscura's explicit `waitUntil: "load"` extension; or
3. using the Rust API's `goto_with_wait()` when embedding Obscura directly.

## Deliberate boundaries

This loading model does not implement Service Workers, media decoding/playback,
or full re-entrant `document.open()`/`close()`. Remaining timing boundaries are
the buffered iframe/stealth transports, stylesheet transport starting at the
next blocking-script gate or EOF instead of link encounter, fully concurrent
module/style races, and the post-EOF `document.write()` compatibility path.
These are conformance boundaries, not reasons to label a failed or incomplete
capture as successful.

## Standards references

- [HTML scripting](https://html.spec.whatwg.org/multipage/scripting.html)
- [HTML parsing](https://html.spec.whatwg.org/multipage/parsing.html)
- [HTML critical subresources](https://html.spec.whatwg.org/multipage/infrastructure.html)
- [CDP Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [CDP Network domain](https://chromedevtools.github.io/devtools-protocol/tot/Network/)
