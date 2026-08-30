`obscura fetch` loads a URL, runs its JavaScript, and prints the result.

## Load a page

```bash
obscura fetch https://example.com
```

Prints the rendered HTML.

## Run JavaScript with `--eval`

```bash
obscura fetch https://example.com --eval "document.title"
```

```
"Example Domain"
```

Returns JSON:

```bash
obscura fetch https://news.ycombinator.com \
  --eval "Array.from(document.querySelectorAll('.titleline a')).slice(0, 5).map(a => a.textContent)"
```

## Multi-statement eval

`--eval` evaluates one expression. For multiple statements, wrap in an IIFE:

```bash
obscura fetch https://example.com --eval "(function(){
  const links = document.querySelectorAll('a');
  return Array.from(links).map(a => a.href);
})()"
```

A bare block starting with `const` or `let` returns `null` because V8 gives top-level declarations an empty completion value.

## Wait for the right moment

CLI default is `load`. For faster returns on slow sites:

```bash
obscura fetch https://my-spa.example --wait-until domcontentloaded --eval "document.title"
```

| Level              | Returns when                                  |
| ------------------ | --------------------------------------------- |
| `commit`           | Initial live document installed; parser continuation retained |
| `domcontentloaded` | HTML parsed and DCL-delaying script work finished |
| `load`             | Standard load-delay set finished (default)    |
| `networkidle2`     | ≤2 network connections active for 500ms       |
| `networkidle0`     | 0 network connections active for 500ms        |
| `capture-ready`    | Load plus a bounded 500ms resource/DOM quiet window |

The network-idle waiter has a five-second ceiling. If the requested 500 ms
threshold is not observed, navigation fails and no network-idle milestone is
published. Use capture-ready when timeout and pending counts should be returned
as a diagnostic report instead.

Puppeteer and Playwright apply their own high-level navigation defaults. Raw
CDP `Page.navigate` without Obscura's optional `waitUntil` field returns at
commit. See [Document loading and capture
readiness](Document-loading-and-capture-ready.md).

## Common flags

```
--user-agent "..."        Override the User-Agent
--timeout 30                Navigation timeout in seconds (default 30)
--wait 5                    Extra wait after the page settles, in seconds (default 5)
--selector ".main"          CSS selector to narrow output to
--proxy http://host:port    Route through a proxy
--stealth                   Stealth client (TLS fingerprint, tracker blocking)
-o, --output file.html      Write output to a file
-q, --quiet                 Suppress info logging
```

Full list: [CLI reference](CLI-reference.md).
