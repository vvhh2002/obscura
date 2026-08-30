Obscura speaks the Chrome DevTools Protocol over WebSocket. Puppeteer and
Playwright can connect to its CDP endpoint for the supported workflows below.

## Start the server

```bash
obscura serve --port 9222
```

```
obscura listening on ws://127.0.0.1:9222
```

## Puppeteer

```bash
npm install puppeteer-core
```

```js
const puppeteer = require('puppeteer-core');

const browser = await puppeteer.connect({
  browserWSEndpoint: 'ws://127.0.0.1:9222',
});

const page = await browser.newPage();
await page.goto('https://example.com');
console.log(await page.title()); // "Example Domain"

await browser.disconnect();
```

Use `puppeteer-core`, not `puppeteer`. The `puppeteer` package bundles a Chrome download.

## Playwright

```bash
npm install playwright
```

```js
const { chromium } = require('playwright');

const browser = await chromium.connectOverCDP('ws://127.0.0.1:9222');
const context = browser.contexts()[0] || await browser.newContext();
const page = await context.newPage();

await page.goto('https://example.com');
console.log(await page.title());

await browser.close();
```

Use `connectOverCDP`, not `connect`. Playwright's `connect` speaks Playwright's own protocol, which obscura does not implement.

## `waitUntil`

Puppeteer and Playwright apply their own high-level `page.goto()` defaults and
wait for the lifecycle/network event they require. They do not generally add
Obscura's non-standard `waitUntil` field to raw `Page.navigate`. To request the
standard Window load explicitly:

```js
await page.goto('https://example.com', { waitUntil: 'load' });
```

| Value | Returns when |
| --- | --- |
| `commit` | URL, live parser tree, V8 realm, and preloads are installed |
| `domcontentloaded` | Deferred classic/module work and DCL are complete |
| `load` | The standard Window load-delay set is empty and Window load ran |
| `networkidle2` | At most two network requests are active for 500 ms after load |
| `networkidle0` | No network request is active for 500 ms after load |
| `capture-ready` | Load completed, then Obscura observed a 500 ms resource/DOM quiet window |

`commit` and `capture-ready` are Obscura extensions and may not be accepted by
the high-level client's typed `waitUntil` option. Use the raw CDP command, the
Rust API, or the CLI for those boundaries.

### Raw `Page.navigate` migration

Raw CDP `Page.navigate` without a `waitUntil` field returns at document commit,
not at DCL or load. The document continues loading in the retained page. A raw
CDP caller should subscribe before navigation and wait for the event it needs:

```js
const cdp = await page.createCDPSession();
await cdp.send('Page.enable');
await cdp.send('Page.setLifecycleEventsEnabled', { enabled: true });

const loaded = new Promise(resolve => {
  const listener = event => {
    if (event.name === 'load') {
      cdp.off('Page.lifecycleEvent', listener);
      resolve();
    }
  };
  cdp.on('Page.lifecycleEvent', listener);
});

await cdp.send('Page.navigate', { url: 'https://example.com' });
await loaded;
```

`Page.lifecycleEvent` is emitted only for sessions which enabled it. Standard
`Page.domContentEventFired`, `Page.loadEventFired`, and
`Page.frameStoppedLoading` continue independently. Obscura also accepts an
explicit, non-standard `waitUntil: 'load'` field on raw `Page.navigate` when a
caller prefers to hold the command response.

The main-frame commit and DCL/load lifecycle are forwarded during navigation
instead of being reconstructed as one final batch. The persistent network
bridge emits request start, response headers, data chunks, and exactly one
loading-finished/loading-failed terminal phase when each transport boundary is
observed, including post-navigation fetch/XHR. Completed request records remain
available for response bodies but are not replayed as duplicate events.

The connection retains one autonomous browser turn while forwarding the
events it produces, so observing a parser-script, stylesheet, module, or frame
request cannot cancel and retry that request. An unrelated command is deferred
while one of those non-cancelable host awaits is active. The streaming primary
body is cancellation-safe instead: if a command interrupts that turn, Obscura
restores the exact decoder/tokenizer/response continuation, serves the command
against the committed DOM, and resumes parsing on a later turn without emitting
a transport failure.

Starting another navigation has replacement semantics rather than scheduling
semantics. Before switching loader generations, Obscura closes every active
request of the outgoing loader with exactly one canceled
`Network.loadingFailed`; later results from the replaced generation cannot run
scripts or dispatch lifecycle events. See [Document loading and capture
readiness](Document-loading-and-capture-ready.md#cdp-behavior-and-migration)
for the detailed lifecycle model.

Child-frame events use the live observer when available and retain the
post-command snapshot drain as a compatibility fallback. The current
network-idle waiter has a five-second ceiling. If its requested 500 ms
threshold is not reached, navigation fails and no network-idle milestone is
published. Use capture-ready when timeout and pending counters should be
returned as a report rather than as a navigation failure.

## Supported

- `page.goto`, `page.reload`, `page.goBack`, `page.goForward`
- `page.evaluate`, `page.evaluateHandle`
- `page.click`, `page.type`, `page.fill`, `page.focus`
- `page.waitForSelector`, `page.waitForFunction`, `page.waitForNavigation`
- `page.cookies`, `page.setCookie`, `context.cookies`
- `page.setRequestInterception`, block / modify
- `page.exposeFunction`
- `page.content`, `page.title`, `page.url`
- `page.screenshot` for viewport, clipped, and full-page capture
- `page.pdf` for raster-backed print output
- raw CDP `Page.startScreencast` with frame acknowledgements (`page.createCDPSession()`
  in Puppeteer; `context.newCDPSession(page)` in Playwright)

DOM-agent frameworks such as browser-use also connect: obscura implements `DOMSnapshot.captureSnapshot` and `Target.targetInfoChanged` for perception, and `DOM.focus` so a focused field receives `Input.dispatchKeyEvent` keystrokes.

## Capture example

```js
await page.setViewport({ width: 1440, height: 1000 });
await page.screenshot({ path: 'viewport.png' });
await page.screenshot({ path: 'full-page.png', fullPage: true });
await page.pdf({ path: 'page.pdf', format: 'A4', printBackground: true });
```

Rendering is included in official binaries and requires `--features render`
for source builds. The client-specific guides cover scrolling, raw CDP
screencasting, and current output limits.

## Current limits

- Pages share one V8 isolate. CPU-bound JavaScript on one page can delay others.
- PDF output is raster-backed; text is not selectable and tagged PDF,
  headers/footers, outlines, and full CSS paged media are not implemented.
- Service workers, native media playback, some Web APIs, and long-tail CSS or
  compositor effects are still incomplete relative to Chromium.
- Ordinary top-level HTTP documents stream after commit, but iframe responses
  and the stealth document transport are currently buffered. Stylesheet fetch
  start and module preparation timing remain less concurrent than Chromium.
