# Archive final-page resources

Obscura can save the response bodies that belong to the final rendered page,
including resources loaded by JavaScript and live child frames. This runs in
Obscura's own browser engine; it does not require Chrome, Chromium, CDP, or a
remote debugging connection.

Use this mode when a URL may redirect, bootstrap an application with
JavaScript, or create an iframe before the files of interest are requested.
The result is an archive with content-addressed response files and a
machine-readable manifest.

## Build requirement

Resource archives require the rendering feature because final-DOM image, CSS,
font, poster, responsive-image, and frame discovery uses the renderer's
resource preparation pass.

```bash
cargo build --release -p obscura-cli --bin obscura --features render,stealth
```

Omit `stealth` if its transport and fingerprint protections are not needed.
The executable is `target/release/obscura` (`obscura.exe` on Windows).

The release workflow builds native executables for Linux x86_64/ARM64, macOS
Apple Silicon/Intel, and Windows x86_64. Linux release artifacts target GNU
libc 2.35 or newer; they are standalone application archives, not fully static
musl binaries. See [Build from source](Build-from-source.md) for platform
toolchains and feature combinations.

## Capture a page

```bash
obscura --stealth fetch https://example.com/app \
  --dump assets \
  --assets-dir ./example-assets \
  --output ./example-assets.ndjson \
  --wait 10 \
  --timeout 60
```

`--dump assets` retains its historical best-effort URL inventory as NDJSON. It
scans selected top-level light-DOM attributes and includes URLs recorded by
live page/frame runtimes, but it is neither exhaustive nor one-to-one with
captured responses. `--assets-dir` writes the authoritative response archive;
the optional `--output` above keeps the compatibility NDJSON outside that
archive. Without `--output`, the NDJSON is printed to stdout after a complete
archive is written. An incomplete archive exits before emitting the NDJSON, and
`--screenshot` mode returns after writing the screenshot instead of emitting
the inventory.

The relevant options are:

| Option | Meaning |
| --- | --- |
| `--assets-dir DIR` | New or empty destination directory. Requires `--dump assets`. |
| `--wait SECONDS` | Fixed post-load observation window in archive mode; default `5` when omitted. Delayed timers and asynchronous work can run during it. |
| `--timeout SECONDS` | Deadline used for navigation and any `--eval` expression, separate from settling and final resource warm-up. |
| `--assets-max-resources N` | Maximum retained responses; default `4096`. |
| `--assets-max-bytes N` | Maximum total retained response bytes; default `536870912` (512 MiB). |
| `--quiet` | Suppress progress logging; it does not change the archive. |

HTTP redirects are followed normally. Obscura also processes top-level
JavaScript navigations during the settle window. When another top-level
document commits, capture advances to a new document generation and discards
responses owned only by the replaced document. The manifest therefore
describes the final committed page, not a mixture of intermediate pages.

Archive mode accepts a single URL and conflicts with `--file`; use a distinct
new directory for each URL in a multi-page workflow. After the fixed settle
window, Obscura can run up to four bounded renderer resource warm-up/settle
rounds. Total runtime can therefore exceed `--timeout + --wait`. Resource and
byte limits count response entries before content-addressed body deduplication.

## Archive layout

```text
example-assets/
├── manifest.json
├── page.html
├── frames/
│   ├── 0000.html
│   └── 0001.html
└── resources/
    ├── 0a12....js
    ├── 4bc9....png
    └── f18d....woff2
```

- `page.html` is a serialization of the final top-level light DOM at the
  capture boundary.
- `frames/*.html` contains each live child frame that could be serialized; a
  serialization failure makes the manifest incomplete.
- `resources/*` contains byte-exact HTTP response bodies.
- `manifest.json` maps requests and frames to those files.

Resource filenames are a SHA-256 digest plus a conservative extension inferred
from the response MIME type and final URL. Identical content with the same
extension shares one file, while every captured response keeps its own `assets`
entry. Consequently, the number of manifest entries can be larger than the
number of files under `resources/`.

## Manifest version 1

The top-level object has this shape:

```json
{
  "version": 1,
  "input_url": "https://example.com/app",
  "final_url": "https://example.com/dashboard",
  "complete": true,
  "incomplete_reasons": [],
  "document_generation": 3,
  "rendered_document": "page.html",
  "frames": [],
  "captured_response_bytes": 123456,
  "assets": []
}
```

Top-level fields:

| Field | Meaning |
| --- | --- |
| `version` | Manifest schema version. Currently `1`. |
| `input_url` | URL supplied on the command line. |
| `final_url` | URL of the final committed top-level document. |
| `complete` | Whether Obscura found any known omission under the configured capture policy at the capture boundary. |
| `incomplete_reasons` | Sorted, human-readable diagnostics for known omissions; wording may change between versions. |
| `document_generation` | Internal final-document generation used to reject late responses from replaced pages. |
| `rendered_document` | Relative path of the top-level DOM serialization. |
| `frames` | Live child-frame records. |
| `captured_response_bytes` | Sum of response bytes across manifest asset entries, including duplicate bodies. |
| `assets` | Captured request/response records. |

Each frame record contains:

```json
{
  "frame_id": 1,
  "url": "https://widget.example/frame.html",
  "path": "frames/0000.html"
}
```

Each asset record contains:

```json
{
  "request_url": "https://cdn.example/app.js",
  "final_url": "https://cdn.example/app.abc123.js",
  "redirected_from": ["https://cdn.example/app.js"],
  "method": "GET",
  "resource_type": "script",
  "document_generation": 3,
  "frame_id": 0,
  "initiator": "https://example.com/dashboard",
  "status": 200,
  "content_type": "application/javascript",
  "bytes": 48123,
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "path": "resources/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.js"
}
```

Asset field details:

| Field | Meaning |
| --- | --- |
| `request_url` | URL at the start of this request chain. |
| `final_url` | Response URL after HTTP redirects. |
| `redirected_from` | Ordered redirect history reported by the transport. |
| `method` | HTTP request method. |
| `resource_type` | Engine classification: `document`, `script`, `stylesheet`, `image`, `font`, `xhr`, `fetch`, or `other`. |
| `document_generation` | Owning top-level document generation. |
| `frame_id` | `0` for the top document; non-zero for a child frame. |
| `initiator` | Document URL that initiated the request, when known. |
| `status` | HTTP response status. |
| `content_type` | MIME type without parameters, when available. |
| `bytes` | Exact stored response-body length. |
| `sha256` | Digest of the stored bytes. |
| `path` | Relative content-addressed file path. |

The archive observes bytes at the browser transport boundary. A response can
therefore be retained even when page JavaScript is not allowed to read it due
to CORS. This does not change the JavaScript-visible CORS result.

Version-aware consumers should machine-check `version`, the process exit
status, and `complete`; do not parse `incomplete_reasons` text as a stable API.
The manifest intentionally does not persist request/response headers or
cookies.

## What is included

During the bounded capture, Obscura accounts for resources from the top-level
document and live frame realms, including:

- top-level and fetched iframe document responses;
- live `iframe[srcdoc]` documents serialized under `frames/` with
  `url`/`initiator` attribution of `about:srcdoc`; they have no separate HTTP
  response body, `srcdoc` takes precedence over `src`, and relative resource
  URLs inherit the effective base URL from the parent document;
- parser-created and dynamically inserted classic scripts;
- module graph responses supported by the top-level module loader;
- `fetch()` and XMLHttpRequest responses;
- static and dynamically inserted images;
- selected `srcset`/`picture` candidates, video posters, and SVG `use`
  references;
- linked stylesheets, inline CSS URLs, fonts, and bounded recursive `@import`
  graphs in supported document stylesheets;
- images, selected responsive-image candidates, posters, CSS URLs, and SVG
  `use` references inside nested open or closed shadow roots.

Inline `@import` inside a shadow root is not recursively materialized in all
cases. An unmaterializable shadow stylesheet owner is reported as
`complete: false` rather than silently accepted.

Frame documents and their subresources keep the child `frame_id`. A frame
removed or replaced before the capture boundary is not part of the final
archive, and its late responses are filtered out.

## Meaning of `complete`

`complete: true` means no *known* omission remained under the configured
capture policy at the end of the requested observation and resource-warmup
windows. It is intentionally stronger than "navigation returned" or "the
network looked idle once," but it is not a claim that every response was 2xx,
that JavaScript could read every response through CORS, or that all browser
semantics were reproduced. A captured 404 response can still be complete.

Obscura writes `complete: false` with one or more reasons when it detects, for
example:

- a response-count or total-byte capture limit was reached;
- network, dynamic-script, frame-document, or cross-frame message work remains
  pending at the deadline;
- an image, font, stylesheet, or imported stylesheet failed, timed out, was
  deferred by a safety cap, or remained unresolved;
- a final-DOM classic script has no captured response owned by the same frame;
- a live frame cannot be inspected or serialized;
- a child frame still has an unsupported module script or pending navigation;
- a frame/realm/stylesheet count or recursion-depth safety cap was reached;
- a shadow-root stylesheet owner cannot be materialized safely.

The manifest is still written when the result is incomplete, and the command
returns unsuccessfully. Consumers should always require both a successful
process exit and `complete === true` before treating an archive as complete.

No finite browser run can predict resources requested only after a future user
gesture, scroll position, long-delay timer, service event, or application state
change. Such work is outside the snapshot if it did not occur during the
configured window. Increase `--wait`, prepare the page with `--eval`, or capture
the required state separately when those resources matter.

Requests excluded by network safety or interception policy, including blocked
private-network/SSRF targets, are outside the retained-response set. Likewise,
`complete: true` is not an offline-replay guarantee: archive URLs are not
rewritten, serialized HTML omits runtime JS heap/listener state and canvas
pixels, and `outerHTML` does not encode dynamic shadow-root trees. The archive
is evidence of a bounded capture, not a self-contained browser session.

## Destination safety

The archive writer refuses:

- a non-empty destination directory;
- a destination or internal target that is a symbolic link;
- an existing file that would otherwise be overwritten;
- `--output` or `--screenshot` paths inside, above, or aliased to the archive
  tree, including conservative case-folded aliases on macOS and Windows.

These checks protect the archive from truncating unrelated output and keep
manifest paths controlled. Use a new directory per capture rather than reusing
or cleaning one automatically.

A failure after writing starts can leave a partial, non-empty directory. The
writer does not resume or clean it automatically; inspect or remove that exact
directory before retrying with a fresh destination.

## Verify an archive

Inspect the high-level result with `jq`:

```bash
jq '{final_url, complete, incomplete_reasons,
     assets: (.assets | length), frames: (.frames | length),
     captured_response_bytes}' example-assets/manifest.json
```

To locate saved images or scripts:

```bash
jq -r '.assets[]
  | select(.resource_type == "image" or .resource_type == "script")
  | [.resource_type, .frame_id, .content_type, .path, .final_url]
  | @tsv' example-assets/manifest.json
```

To verify a body manually, compute SHA-256 for the relative `path` and compare
it with that asset entry's `sha256` value. Do not derive filenames from remote
URLs; use the manifest path.

## Privacy and credentials

An archive can contain authenticated HTML, API bodies, full query strings,
redirect locations, session identifiers, and other sensitive page data. Treat
the entire directory as potentially confidential. Redact or remove secrets
before sharing an archive, and do not commit real captures to a public
repository.

## Rust API

Embedders can use `ResourceCaptureLimits`, `enable_resource_capture()`,
`take_resource_capture()`, `has_pending_resource_work()`,
`prepare_screenshot_resources_with_report()`, and
`resource_archive_incomplete_reasons()` to implement a custom writer. See
[Use as a Rust library](Use-as-a-Rust-library.md#final-document-resource-capture)
for the engine-side response checks. A manifest-equivalent writer must also
serialize every live frame and verify final-DOM classic-script response
ownership, as described in the `complete` section above.
