## `obscura`

Top-level flags apply to every subcommand.

```
-v, --verbose                Enable info logging
-p, --port <PORT>            CDP port (default 9222)
    --proxy <URL>            HTTP or SOCKS5 proxy
    --stealth                Consistent browser fingerprint + tracker blocking
    --obey-robots            Respect robots.txt
    --user-agent <UA>        Override the User-Agent
    --storage-dir <DIR>      Persistent cookies and localStorage
    --allow-private-network  Permit loopback / RFC1918 / link-local
    --v8-flags <FLAGS>       Raw V8 flags, applied at startup
-h, --help                   Help
-V, --version                Version
```

## `obscura fetch <URL>`

Load a URL and print its content or an evaluated expression.

```
    --dump <FORMAT>          html | text | links | markdown | original | assets | cookies
                             (default html)
    --selector <CSS>         Narrow output to a CSS selector
    --wait <SECONDS>         Fixed post-load delay; omitted usually uses adaptive settle (5s cap)
    --timeout <SECONDS>      Navigation/eval timeout (default 30)
    --wait-until <LEVEL>     commit | domcontentloaded | load | networkidle2 |
                             networkidle0 | capture-ready
                             (default load)
    --user-agent <UA>        Override the User-Agent
    --assets-dir <DIR>       With --dump assets, save final-page response files and manifest
    --assets-max-bytes <N>   Maximum captured response bytes (default 536870912)
    --assets-max-resources <N>
                             Maximum captured responses (default 4096)
    --proxy <URL>            HTTP or SOCKS5 proxy
    --stealth                Consistent browser fingerprint + tracker blocking (global)
-e, --eval <JS>              Evaluate JS, print the result as JSON
-o, --output <FILE>          Write to a file instead of stdout
-s, --screenshot <FILE>      Capture the settled page as PNG (single URL)
-q, --quiet                  Suppress info logging
-v, --verbose                Enable verbose logging
```

`--screenshot` requires a render-enabled build. It uses a 1280×720 viewport by
default and may be combined with `--eval`; the expression runs before capture,
which is useful for scrolling or preparing page state. It is not available in
`--file` batch mode.

`commit` returns after the document URL, live parser tree, V8 realm, and
new-document preload scripts are installed. The CLI's ordinary post-navigation
settle resumes the retained parser before producing output; `--wait 0`
deliberately leaves the output at the initial commit boundary. `capture-ready`
first waits for the standard Window load, then requires 500 ms without new
observed network/resource/frame or connected-DOM activity, bounded by five
seconds. It does not change the DOM definition of load. See [Document loading
and capture readiness](Document-loading-and-capture-ready.md).

When `--wait` is omitted, Obscura normally drives timers and async work until
the page becomes quiescent, with a five-second ceiling. Supplying `--wait N`
requests a fixed `N`-second delay. With `--assets-dir`, the settle window is
always fixed (five seconds when `--wait` is omitted), and final resource
warm-up can add bounded passes after it. `--timeout` separately bounds each
navigation and an `--eval` expression when present, so total archive runtime
can exceed `--timeout + --wait`.

`--dump` values:

| Value      | Output                                                    |
| ---------- | --------------------------------------------------------- |
| `html`     | Rendered HTML (default)                                   |
| `text`     | Plain text                                                |
| `markdown` | Markdown conversion                                       |
| `links`    | Every `<a href>`, one URL per line                        |
| `assets`   | Best-effort URL inventory, one JSON object per line (selected top-level light-DOM attributes plus URLs recorded by live page/frame runtimes) |
| `original` | Raw HTTP response body (binary-safe, bypasses the engine) |
| `cookies`  | All cookies in the jar as a JSON array, including HttpOnly cookies invisible to `document.cookie` |

`--dump assets` keeps its historical line-oriented URL inventory for
compatibility. It does not recursively scan child-frame DOMs, shadow trees, CSS
graphs, or all responsive-resource attributes, and it is not one-to-one with
the response records in `manifest.assets`. Add `--assets-dir DIR` to create the
authoritative byte-exact archive of responses loaded by the final top-level
document and its live child frames. Obscura follows HTTP
redirects and JavaScript top-level navigations during the configured settle
window; when a new document commits, responses from the replaced document are
discarded.

The archive contains `manifest.json`, the rendered `page.html`, child documents
under `frames/`, and content-addressed response bodies under `resources/`.
`manifest.json` records request and final URLs, redirect chains, resource type,
frame id, status, MIME type, byte count, SHA-256, and file path. Before writing,
the archive driver also drains resource work in the top document and every live
frame. If a configured capture limit is reached, a network/dynamic-script task
is still pending, renderer discovery reports a failed/timed-out/unresolved
image or font, a live frame cannot be serialized, a classic script in the
final DOM has no response owned by that frame, or a live child frame contains
an unexecuted module or pending navigation, the manifest is written with
`complete: false` and the command exits unsuccessfully instead of silently
claiming a complete archive. Internal stylesheet/frame count or depth caps and
frame diagnostic failures are reported the same way. This mode requires a
build with the `render` feature. Archive mode accepts one URL and conflicts
with `--file`. The destination must be absent or empty and cannot be a symlink;
`--output` and `--screenshot` must be outside the archive tree.

Live frame images, posters, inline CSS URLs, dynamically inserted stylesheets,
and bounded recursive `@import` graphs are archived with their owning frame id.

`complete: true` describes the bounded final-page snapshot after the requested
settle window. A page can always defer new work until a future timer, user
gesture, or lazy-scroll event, so choose `--wait` to cover the state you need
and retain the manifest with the files.

```bash
obscura fetch https://example.com --dump assets --assets-dir ./example-assets \
  --output ./example-assets.ndjson --wait 5
```

The optional `--output` keeps the compatibility NDJSON outside the archive;
omit it to print that inventory to stdout after a complete archive is written.
An incomplete archive and a command combined with `--screenshot` do not emit
this compatibility inventory.

See [Archive final-page resources](Archive-final-page-resources.md) for the
manifest v1 schema, exact completeness contract, supported resource owners,
destination safety rules, and verification examples.

## `obscura serve`

Run the CDP server. Puppeteer and Playwright connect over WebSocket.

```
-p, --port <PORT>            CDP port (default 9222)
    --host <HOST>            Bind host (default 127.0.0.1)
    --proxy <URL>            HTTP or SOCKS5 proxy
    --user-agent <UA>        Override the User-Agent
    --stealth                Consistent browser fingerprint + tracker blocking (global)
    --workers <N>            Worker processes (default 1)
    --allow-file-access      Permit CDP clients to navigate to file:// URLs
    --storage-dir <DIR>      Persistent cookies and localStorage
    --allow-private-network  Permit loopback / RFC1918 / link-local
-q, --quiet                  Suppress info logging
-v, --verbose                Enable info logging
```

Default endpoint is `ws://127.0.0.1:9222`.

## `obscura scrape [URLS]...`

Run a JS expression across many URLs in parallel.

```
-e, --eval <JS>              JS to run on each page
    --concurrency <N>        Parallel pages (default 10)
    --format <FORMAT>        Output format (default json)
    --timeout <SECONDS>      Per-URL timeout (default 60)
    --proxy <URL>            HTTP or SOCKS5 proxy
    --stealth                Consistent browser fingerprint + tracker blocking (global)
    --allow-private-network  Permit loopback / RFC1918 / link-local
-q, --quiet                  Suppress info logging
-v, --verbose                Enable verbose logging
```

`--stealth`, `--proxy`, and `--allow-private-network` are global flags: they work before or after any subcommand, so each worker in a `scrape` run inherits stealth too.

Read URLs from stdin with `-`:

```bash
cat urls.txt | obscura scrape - --eval "document.title" --concurrency 20
```

Requires `obscura-worker` next to `obscura` in `PATH`.

## `obscura mcp`

Run obscura as an MCP server.

```
    --http                   HTTP transport instead of stdio
    --host <HOST>            HTTP bind host (default 127.0.0.1)
    --port <PORT>            HTTP port (default 3000)
    --proxy <URL>            HTTP or SOCKS5 proxy
    --user-agent <UA>        Override the User-Agent
    --stealth                Consistent browser fingerprint + tracker blocking (global)
    --allow-private-network  Permit loopback / RFC1918 / link-local
-v, --verbose                Enable info logging
```

`--host` only applies with `--http`. The default `127.0.0.1` keeps the server loopback-only; set `0.0.0.0` to bind all interfaces (for example a Docker Compose sidecar) and pair it with `OBSCURA_MCP_ALLOWED_ORIGINS`.

Default transport is stdio. See [Use the MCP server](Use-the-MCP-server.md).

Render-enabled builds add `browser_screenshot` and `browser_pdf` to the MCP
tool list. Streaming screencasts are available through CDP rather than MCP.
