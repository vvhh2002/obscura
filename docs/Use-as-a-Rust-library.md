The `obscura` crate embeds the engine in a Rust program with a `Browser` / `Page` / `Element` API plus a cookie store, no CDP round-trips. It builds V8 from source, so it is a git dependency rather than a crates.io release.

## Add the dependency

```toml
[dependencies]
obscura = { git = "https://github.com/h4ckf0r0day/obscura" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
anyhow = "1"
```

The first build compiles V8 from source, so it is slow and needs the same build tools as [Build from source](Build-from-source.md). Pin a tag for reproducible builds:

```toml
obscura = { git = "https://github.com/h4ckf0r0day/obscura", tag = "v0.1.7" }
```

Enable the `render` feature when the application must download resources loaded
through `new Image()` or `<img>` (including images created inside child frames):

```toml
obscura = { git = "https://github.com/h4ckf0r0day/obscura", features = ["render"] }
```

## Quickstart

```rust
use obscura::Browser;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let browser = Browser::builder()
        .stealth(true)
        .build()?;

    let mut page = browser.new_page().await?;
    page.goto("https://example.com").await?;

    println!("URL: {}", page.url());
    println!("HTML bytes: {}", page.content().len());

    let el = page.wait_for_selector("h1", Duration::from_secs(5)).await?;
    println!("Heading: {}", el.text());

    let title = page.evaluate("document.title");
    println!("Title: {}", title);

    Ok(())
}
```

## API surface

`Browser::builder()` configures the engine: `.stealth(bool)`, `.proxy(url)`, `.user_agent(ua)`, `.storage_dir(dir)`, then `.build()`. `Browser::new()` uses defaults.

`Page`:
- `goto(url).await` navigate and wait for load
- `goto_with_wait(url, WaitUntil).await` navigate to commit, DCL, load,
  network-idle, or capture-ready
- `wait_for_capture_ready().await` apply the default five-second/500 ms quiet
  policy and return a `CaptureReadyReport`
- `wait_for_capture_ready_with_options(options).await` use caller-provided
  total timeout and quiet-window durations
- `content()` rendered HTML
- `url()` current URL
- `frame_urls()` child-frame URLs in creation order
- `evaluate_in_frame(index, js)` run JavaScript in a child frame realm
- `fetched_urls()` resource URLs fetched by the page and its child frames
- `evaluate(js)` run JavaScript, returns a `serde_json::Value`
- `query_selector(css)` first match as an `Element`, or `None`
- `wait_for_selector(css, Duration).await` poll until present
- `settle(max_ms).await` drive the event loop so async work (`fetch`, timers) completes
- `settle_following_navigations(max_ms).await` settle and commit delayed top-level `location` navigations
- `enable_resource_capture(limits)` / `take_resource_capture()` retain byte-exact responses for the final document generation
- `has_pending_resource_work()` report top-level or child-frame request/dynamic-script work that can still extend a capture
- `resource_archive_incomplete_reasons()` report engine caps, frame probe failures, unsupported frame work, and pending queues without silently treating them as empty
- `on_request(cb)` / `on_response(cb)` passive callbacks for every request and response
- `enable_interception()` channel to block, mock, or rewrite requests
- `add_preload_script(js)` run a script before the page's own scripts

`Element`: `text()`, `attribute(name)`, `click()`.

`CookieStore`: `set`, `get_all`, `get_for_url`, `save_to_file`, `load_from_file`.

## Select a navigation or capture boundary

`goto()` continues to wait for standard Window load. Use `goto_with_wait()` to
return at a different lifecycle boundary, and use capture readiness when
post-load requests or DOM mutations matter to the result:

```rust
use obscura::{Browser, CaptureReadyOptions, WaitUntil};
use std::time::Duration;

let browser = Browser::new()?;
let mut page = browser.new_page().await?;
page.goto_with_wait("https://example.com", WaitUntil::Load).await?;

let report = page.wait_for_capture_ready_with_options(CaptureReadyOptions {
    timeout: Duration::from_secs(8),
    quiet_window: Duration::from_millis(750),
}).await;

anyhow::ensure!(report.quiescent, "page did not become quiet: {report:?}");
anyhow::ensure!(!report.timed_out, "capture-ready timed out: {report:?}");
anyhow::ensure!(report.archive_complete, "known archive gaps: {:?}", report.incomplete_reasons);
```

`WaitUntil::Commit` retains a resumable parser but does not spawn a background
task in the embedded API. A following `settle()` resumes that continuation
before it pumps timers, requests, and frames. Prefer DCL, Load, or CaptureReady
when the immediate return itself must contain parser-tail DOM.

The default options are a five-second total budget and a 500 ms quiet window.
`CaptureReadyReport` also includes lifecycle state, a pending-resource-work
flag, and pending network, child-document, cross-frame-message, and incomplete-
frame counts.
Timers do not stay pending by themselves, but a timer-created request or DOM
mutation resets the quiet window.

`archive_complete` is a known-gap diagnostic, not proof that response capture
was enabled. When capture is enabled its omission counters are included in the
report, but byte-exact callers should still run renderer resource preparation
and validate the returned `ResourceCapture` artifact as shown below.

## Intercept requests

The interception API observes, blocks, mocks, and rewrites the requests a page makes, including JavaScript `fetch()` and XHR. Use it to capture API payloads while crawling, block trackers, or mock responses in tests.

### Passive callbacks

`on_request` and `on_response` fire for every request and response (navigation and JS `fetch()`/XHR) and are non-blocking. `on_response` is the main path for capturing the JSON an SPA loads asynchronously. Both return a stable id; pass it to `off_request` / `off_response` to detach the callback when a crawl phase is done. Callbacks are scoped to the page that registered them: they never fire for another page's requests and are dropped with the page.

```rust
use obscura::{Browser, ResourceType};
use std::sync::Arc;

let browser = Browser::new()?;
let mut page = browser.new_page().await?;

page.on_response(Arc::new(|info, resp| {
    if info.resource_type == ResourceType::Fetch {
        println!("{} -> {} bytes", info.url, resp.body.len());
    }
}));

page.goto("https://example.com").await?;
page.settle(2000).await;   // let in-page fetch() calls resolve
```

### Active interception

`enable_interception()` returns a channel of every JS `fetch()`/XHR request. Resolve each through its `resolver` to pass, block, mock, or rewrite it.

```rust
use obscura::{Browser, InterceptResolution};

let mut page = browser.new_page().await?;
let mut rx = page.enable_interception();

tokio::spawn(async move {
    while let Some(req) = rx.recv().await {
        let action = if req.url.contains("/ads") {
            InterceptResolution::Fail { reason: "blocked".into() }
        } else if req.url.ends_with("/api/flags") {
            InterceptResolution::Fulfill {
                status: 200,
                headers: Default::default(),
                body: r#"{"newDashboard":true}"#.into(),
            }
        } else {
            // Pass through, or rewrite by setting url/method/headers/body.
            InterceptResolution::Continue { url: None, method: None, headers: None, body: None }
        };
        let _ = req.resolver.send(action);
    }
});

page.goto("https://example.com").await?;
page.settle(2000).await;
```

A `Continue` with `url: Some(...)` rewrites the target. The new URL is re-checked against the SSRF / private-network gate, so a rewrite cannot reach an internal address that would otherwise need `--allow-private-network`.

### Preload scripts

`add_preload_script` runs a script before any of the page's own `<script>` tags (the CDP `Page.addScriptToEvaluateOnNewDocument` contract), so it can install hooks before the page bootstraps. Call it before `goto`.

```rust
let mut page = browser.new_page().await?;
page.add_preload_script("window.__patched = true;");
page.goto("https://example.com").await?;
```

`resource_type` reports `Fetch` for JS-initiated requests and does not yet split `Xhr` from `Fetch`.

### Final-document resource capture

Use resource capture when response bodies must be archived rather than merely
observed. Requests snapshot the current top-level document generation when they
start. A later real navigation resets the capture, and a slow response from the
replaced page cannot leak into the final result.

This response-completeness workflow requires the renderer warmup API, so
enable the `render` feature shown above. Do not conditionally skip the warmup
when describing the captured response set as complete under its bounded policy.

```rust
use obscura::{Browser, ResourceCaptureLimits};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let browser = Browser::new()?;
    let mut page = browser.new_page().await?;
    page.enable_resource_capture(ResourceCaptureLimits::default());
    page.goto("https://example.com").await?;
    page.settle_following_navigations(5_000).await?;

    // Repeat because loading one resource can run an onload handler that
    // inserts another resource or commits a replacement document.
    let mut warmup_complete = false;
    for round in 0..4 {
        let before = page.url();
        let warmup = page.prepare_screenshot_resources_with_report(5_000).await;
        page.settle_following_navigations(5_000).await?;
        if page.url() != before {
            continue;
        }
        anyhow::ensure!(
            warmup.failed == 0 && warmup.timed_out == 0,
            "resource warmup failed or timed out: {warmup:?}",
        );
        let post_settle = page.prepare_screenshot_resources_with_report(0).await;
        if round != 0
            && warmup.remaining == 0
            && post_settle.remaining == 0
            && !page.has_pending_resource_work()
        {
            warmup_complete = true;
            break;
        }
    }
    anyhow::ensure!(
        warmup_complete,
        "resource work did not reach a complete bounded capture state",
    );
    let incomplete_reasons = page.resource_archive_incomplete_reasons();
    anyhow::ensure!(
        incomplete_reasons.is_empty(),
        "engine reported an incomplete archive: {incomplete_reasons:?}",
    );

    let capture = page.take_resource_capture().expect("capture enabled");
    anyhow::ensure!(
        capture.omitted_resources == 0 && capture.omitted_bytes == 0,
        "capture limits omitted {} resources ({} bytes)",
        capture.omitted_resources,
        capture.omitted_bytes,
    );

    // Use a fresh directory: create_dir refuses to reuse one, so a later run
    // cannot silently overwrite files from an earlier capture.
    let output_dir = std::path::Path::new("responses");
    std::fs::create_dir(output_dir)?;
    for (ordinal, response) in capture.resources.into_iter().enumerate() {
        let path = output_dir.join(format!("response-{ordinal:06}.bin"));
        std::fs::write(path, response.body)?;
    }
    Ok(())
}
```

`ResourceCaptureLimits` bounds count and total retained bytes. If either limit
is reached, `omitted_resources` is non-zero and `omitted_bytes` reports the
discarded body bytes (which can itself be zero); applications must treat either
reported omission as incomplete. Before describing a capture as complete,
repeat renderer warmup followed by bounded settling, probe again after each
settle, and require `has_pending_resource_work()` to be false. Every accepted
`prepare_screenshot_resources_with_report()` pass must have zero `failed` and
`timed_out` fields; a non-zero `remaining` must be drained by a later bounded
pass. The report makes the per-pass resource limit and deadline explicit
instead of treating `loaded == 0` as an idle signal. Finally require
`resource_archive_incomplete_reasons()` to be empty; it covers stylesheet
depth/count caps, frame queue/realm caps, failed frame diagnostics, and
unsupported or pending child-frame work.

Those are the engine-side response checks. A writer claiming parity with the
CLI manifest must additionally serialize every live frame successfully and
verify that each final-DOM classic script has a captured response owned by the
same frame. See [Archive final-page resources](Archive-final-page-resources.md)
for the full manifest contract.

## When to use which interface

- Embedding the engine in a Rust service: this crate.
- Driving from Node/Python with existing Puppeteer/Playwright code: the [CDP server](Connect-Puppeteer-or-Playwright.md).
- Giving an AI agent browser tools: the [MCP server](Use-the-MCP-server.md).
- One-off fetches and scraping from the shell: the [CLI](CLI-reference.md).
