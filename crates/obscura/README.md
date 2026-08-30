# obscura

Embeddable Rust API for the [Obscura](https://github.com/h4ckf0r0day/obscura)
headless browser. Drive a real V8 + DOM browser (`Browser`, `Page`, `Element`,
`CookieStore`) directly from Rust, with no separate process or CDP round-trips.

## Install

This crate is not published to crates.io, so depend on it via git. Building it
compiles Obscura from source, including its embedded V8 (`deno_core`), so the
first build is large and slow.

```toml
[dependencies]
obscura = { git = "https://github.com/h4ckf0r0day/obscura", features = ["api"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
anyhow = "1"
```

## Usage

```rust,no_run
use obscura::Browser;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let browser = Browser::builder()
        .stealth(true)
        .storage_dir("/tmp/cookies")
        .build()?;

    let mut page = browser.new_page().await?;
    page.goto("https://example.com").await?;

    let el = page.wait_for_selector("a", Duration::from_secs(5)).await?;
    println!("{} -> {:?}", el.text(), el.attribute("href"));

    Ok(())
}
```

## Capture final-page resource responses

Resource capture is opt-in because it retains byte-exact response bodies. A
real top-level navigation starts a new document generation, so after HTTP or
JavaScript redirects the drained capture contains only the final document and
requests initiated by it and its live child frames.

For this workflow, enable `render` instead of `api`; `render` includes the Rust
API and exposes the renderer resource warmup report used below:

```toml
obscura = { git = "https://github.com/h4ckf0r0day/obscura", features = ["render"] }
```

```rust,no_run
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
    for response in capture.resources {
        println!("{}: {} bytes", response.final_url, response.body.len());
    }
    Ok(())
}
```

See `examples/basic.rs` for a runnable version (`cargo run --example basic`).
