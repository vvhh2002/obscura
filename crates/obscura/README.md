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
tokio = { version = "1", features = ["rt", "macros"] }
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

```rust,no_run
use obscura::{Browser, ResourceCaptureLimits};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let browser = Browser::new()?;
    let mut page = browser.new_page().await?;
    page.enable_resource_capture(ResourceCaptureLimits::default());
    page.goto("https://example.com").await?;
    page.settle_following_navigations(5_000).await?;
    #[cfg(feature = "render")]
    {
        let warmup = page.prepare_screenshot_resources_with_report(5_000).await;
        anyhow::ensure!(warmup.is_complete(), "resource warmup incomplete: {warmup:?}");
    }
    anyhow::ensure!(
        page.resource_archive_incomplete_reasons().is_empty(),
        "engine reported incomplete resource work",
    );

    let capture = page.take_resource_capture().expect("capture enabled");
    for response in capture.resources {
        println!("{}: {} bytes", response.final_url, response.body.len());
    }
    Ok(())
}
```

See `examples/basic.rs` for a runnable version (`cargo run --example basic`).
