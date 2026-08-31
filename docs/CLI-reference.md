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
    --captcha-adapter <ADAPTER>
                             auto | tianai | go-captcha | aj-captcha | slider-captcha-js
    --captcha-images-dir <DIR>
                             Write background/puzzle images and a sanitized manifest
    --captcha-urls-output <FILE>
                             Write the sensitive source/provenance JSON report; use - for stdout
    --captcha-max-bytes <N>  Maximum CAPTCHA capture bytes (default 67108864)
    --captcha-max-resources <N>
                             Maximum CAPTCHA capture responses (default 512)
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

`--captcha-adapter` enables read-only slide-CAPTCHA extraction and requires
`--captcha-images-dir` and/or `--captcha-urls-output`. It conflicts with
`--file`, `--dump`, `--output`, `--assets-dir`, `--screenshot`, and `--eval`;
the adapter never solves, clicks, drags, or submits a challenge. See
[Slide CAPTCHA adapters](Slide-Captcha-Adapters.zh-CN.md) for the exact four
supported provider families and slide modes, completeness rules, output
schemas, and URL-data sensitivity guidance.

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

## `obscura legacy-gateway [<LEGACY_URL> | --config <FILE>]`

Expose one administrator-configured legacy login page through a loopback-only
conversion UI. The command recognizes a login form and the slide mode of
Tianai, GoCaptcha, AJ-Captcha, or slider-captcha-js. Other CAPTCHA modes are
out of scope. It shows the authenticated legacy page as a remote PNG viewport
inside a same-origin iframe; the iframe does not navigate to the legacy URL.

Login and the remote viewport reuse the same Obscura `BrowserContext + Page`,
so the legacy session naturally continues after authentication. The gateway
does not copy legacy cookies into the new UI. One user gesture is submitted as
one bounded batch of real `down -> move+ -> up` samples with the CAPTCHA
generation, sequence numbers, normalized coordinates, and relative timing.
The server validates the generation and replays the samples with bounded
original inter-sample timing. It neither solves the CAPTCHA nor calculates or
accepts a final distance.

```
    --discover-output <FILE>             After one confirmed login, create a
                                         validated version 1 integration manifest
    --config <FILE>                      Serve from a manifest created by
                                         --discover-output; LEGACY_URL is omitted
    --success-selector <CSS>             Required post-login authentication probe
    --subject-selector <CSS>             Optional display-only identity text
    --username-selector <CSS>            Override username-field detection
    --password-selector <CSS>            Override password-field detection
    --submit-selector <CSS>              Override submit-control detection
    --captcha-adapter <ADAPTER>          auto | tianai | gocaptcha-slide |
                                         aj-captcha |
                                         slider-captcha-js (default auto)
    --allowed-navigation-origin <ORIGIN> Allow an exact redirect/navigation origin;
                                         repeat for additional origins
    --allowed-resource-origin <ORIGIN>   Allow an exact script/image/font/frame/
                                         fetch origin; repeat for additional origins
    --allow-insecure-legacy-http         Explicitly permit HTTP legacy origins
    --host <IP>                          Loopback listen IP (default 127.0.0.1)
    --port <PORT>                        Listen port; 0 selects a free port (default 0)
    --viewport-width <PX>                320..4096 (default 1280)
    --viewport-height <PX>               240..2160 (default 720)
    --session-ttl <SECONDS>              60..86400 (default 1800)
    --user-agent <UA>                    Legacy browser User-Agent override
    --proxy <URL>                        HTTP or SOCKS5 proxy (global)
    --allow-private-network              Permit loopback/RFC1918/link-local fetches (global)
```

The startup origin is automatically included in both allowlists. Navigation
and resource origins are separate: allowing an SSO redirect does not silently
allow that origin to host scripts or receive fetch/XHR requests. Origins are
matched by scheme, host, and effective port. HTTPS is required unless
`--allow-insecure-legacy-http` is present, and the gateway rejects non-loopback
`--host` values.

For a repeatable integration, run the gateway in two stages. The first command
starts the ordinary conversion UI but, after one login has been confirmed,
creates a secret-free discovery manifest instead of retaining that session:

```bash
obscura legacy-gateway https://legacy.example/login \
  --discover-output ./legacy-login.json \
  --success-selector '#application-shell' \
  --subject-selector '.current-user'
```

Discovery requires two consecutive pre-login probes in the same document
generation with no visible success-selector match and no multiple-match
ambiguity. One hidden candidate is permitted in this logged-out baseline, but
multiple candidates fail closed. Post-login, the selector must have exactly one
connected and visible match in two consecutive probes. Discovery then loads the
login URL in a fresh logged-out browser context and requires the same concrete
CAPTCHA adapter/mode, labels, and stable unique login selectors. Its success
selector must again have no visible match and no multiple-match ambiguity in
two consecutive probes. Before the version 1 JSON is published, both the
authenticated discovery context and this preflight context are destroyed;
neither session can become the production session. A failed preflight is
configuration drift and no manifest is written.

The destination must not already exist. Publication is atomic and create-new:
discovery never truncates, replaces, or follows an existing destination. Once
the file has been reviewed, start the long-lived integration with:

```bash
obscura legacy-gateway --config ./legacy-login.json
```

The version 1 manifest contains only stable integration metadata:

```json
{
  "schemaVersion": 1,
  "loginUrl": "https://legacy.example/login",
  "captchaAdapter": "gocaptcha-slide",
  "selectors": {
    "username": "input[name=\"username\"]",
    "password": "input[name=\"password\"]",
    "submit": "button[type=\"submit\"]"
  },
  "authentication": {
    "successSelector": "#application-shell",
    "subjectSelector": ".current-user"
  },
  "detection": {
    "captchaMode": "slide",
    "usernameLabel": "Account",
    "passwordLabel": "Password",
    "submitLabel": "Sign in"
  },
  "origins": {
    "navigation": ["https://legacy.example"],
    "resources": ["https://legacy.example", "https://static.example"]
  },
  "viewport": { "width": 1280, "height": 720 },
  "sessionTtlSeconds": 1800,
  "allowInsecureLegacyHttp": false,
  "userAgent": "Legacy Browser/1.0"
}
```

`captchaAdapter` is always a concrete supported adapter, never `auto`, and
`detection.captchaMode` is its exact supported mode. `userAgent` is optional.
The schema has no fields for usernames, passwords, cookies, bearer/provider
tokens, dynamic CAPTCHA URLs, challenge images, or image/canvas fingerprints.
Unknown fields and invalid or non-canonical values are rejected.

In `--config` mode, the initial logged-out page must exactly match the persisted
adapter, mode, labels, and selectors before credentials are accepted. A missing,
ambiguous, or changed profile fails closed as configuration drift; the gateway
does not fall back to fresh auto-detection or update the manifest in place.

`--config` conflicts with `LEGACY_URL`, `--discover-output`, the CAPTCHA adapter,
all login and authentication selector flags, both origin flags, the HTTP opt-in,
viewport flags, session TTL, and the subcommand-local `--user-agent`. `--host`
and `--port` remain runtime choices. Process-level network options such as
`--proxy` and `--allow-private-network` also remain available. A top-level
`--user-agent` placed before `legacy-gateway` is a runtime override and takes
precedence over the optional manifest value; `--stealth` remains unsupported.

If neither `--discover-output` nor `--config` is supplied, the original one-shot
form remains unchanged: pass `LEGACY_URL` and `--success-selector`, detect the
page at startup, and keep that run's authenticated context until logout, expiry,
or process termination. It does not read or write a manifest.

`--session-ttl` is an absolute lifetime rather than an idle timeout. It starts
when the UI session is issued and restarts once when successful authentication
rotates that session; polling and input do not extend it. On expiry, the next
request permanently retires that process's launch token, discards the legacy
`BrowserContext + Page`, installs a blank isolated context, and returns HTTP
410. Restart `legacy-gateway` to create a new launch URL.

The command requires a build with `--features render`. It rejects `--stealth`
because the current stealth transport bypasses the exact resource-origin
interceptor. It also deliberately ignores persistent `--storage-dir` state:
initial login and every logout use a newly allocated `BrowserContext`, CookieJar,
HTTP client, and Page.

On success the process prints exactly one launch URL, such as
`http://127.0.0.1:49152/#...`, then serves until stopped. The fragment is a
process-local bearer and must be handed directly to the local browser rather
than logged, copied into monitoring systems, or persisted. Neither the fixed
legacy URL nor selectors can be replaced through an HTTP request.

```bash
cargo run --release --features render -p obscura-cli -- \
  legacy-gateway https://legacy.example/login \
  --success-selector '#application-shell' \
  --subject-selector '.current-user' \
  --captcha-adapter gocaptcha-slide \
  --allowed-resource-origin https://static.example
```

See [旧系统登录与滑块验证码转换网关](Legacy-System-Gateway.zh-CN.md)
for the interaction lease, authentication probe, iframe, and security model.

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
