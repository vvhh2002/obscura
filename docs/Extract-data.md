`--dump` formats the page output without writing JavaScript.

```bash
obscura fetch https://example.com --dump html
obscura fetch https://example.com --dump text
obscura fetch https://example.com --dump markdown
obscura fetch https://example.com --dump links
obscura fetch https://example.com --dump assets
obscura fetch https://example.com --dump original
obscura fetch https://example.com --dump cookies
```

## `html`

Rendered HTML after JavaScript runs. Default.

```bash
obscura fetch https://news.ycombinator.com --dump html > hn.html
```

## `text`

Plain text. No markup.

```bash
obscura fetch https://en.wikipedia.org/wiki/Rust_(programming_language) --dump text
```

## `markdown`

Markdown conversion: headings, lists, links, code blocks, images.

```bash
obscura fetch https://docs.example.com/page --dump markdown > page.md
```

## `links`

Every `<a href>` on the page, one per line.

```bash
obscura fetch https://example.com --dump links
```

## `assets`

Every external resource (stylesheets, scripts, images, fonts, iframes), plus the URLs the page requested through `fetch()`/XHR, one JSON object per line.

```bash
obscura fetch https://example.com --dump assets
```

To save the response files rather than only list URLs, add `--assets-dir`:

```bash
obscura fetch https://example.com \
  --dump assets \
  --assets-dir ./example-assets \
  --wait 5
```

The directory contains `manifest.json`, rendered `page.html`, child documents
under `frames/`, and response bodies under `resources/`. Bodies are stored
byte-for-byte and named by SHA-256, so query strings, duplicate filenames, and
identical content cannot overwrite one another. The manifest maps every
request to its saved file and records its final URL after HTTP redirects,
resource type, owning frame, status, MIME type, and size.

Top-level HTTP redirects and JavaScript `location` navigations are followed
during the settle window. Committing a replacement document resets the capture,
so scripts and images belonging only to an intermediate page do not appear in
the final archive. This mode requires a render-enabled build and refuses a
non-empty or symlinked destination directory. `--output` and `--screenshot`
must also remain outside that directory. Capture-limit failures, failed,
timed-out, or unresolved renderer resources, network or dynamic-script work
still pending at the archive deadline, a live frame that cannot be serialized,
final-DOM classic scripts without a response owned by their frame, and detected
unsupported child-frame module or navigation work still write a
manifest with `complete: false`, then return a non-zero exit status.
Internal stylesheet/frame safety caps and frame-inspection failures also make
the archive explicitly incomplete.

Live child-frame images, responsive `<picture>` candidates, video posters,
inline CSS resources, dynamically inserted stylesheets, and bounded recursive
`@import` graphs are fetched through the owning frame's page transport and keep
that frame's id and final document URL as their archive attribution.

The manifest describes a bounded snapshot after the configured settle window;
future user-triggered or lazy-loaded work is outside that snapshot. Increase
`--wait` when the page deliberately delays the state you want to archive.

## `original`

The raw HTML the server sent, before JavaScript ran.

```bash
obscura fetch https://my-spa.example --dump original > before.html
obscura fetch https://my-spa.example --dump html     > after.html
diff before.html after.html
```

## `cookies`

Every cookie in the jar as a JSON array, including HttpOnly cookies that `document.cookie` cannot see. Useful for capturing session tokens set by anti-bot challenges.

```bash
obscura fetch https://example.com --dump cookies
```

## With `--wait-until`

`--dump` runs after the wait condition:

```bash
obscura fetch https://my-spa.example --wait-until load --dump markdown
```

## Pipe and redirect

```bash
obscura fetch https://example.com --dump markdown > example.md
obscura fetch https://example.com --dump text --quiet | wc -w
```
