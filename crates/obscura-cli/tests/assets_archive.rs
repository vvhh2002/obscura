#![cfg(feature = "render")]

use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::process::Command;
use std::sync::{Arc, Mutex};

const INTERMEDIATE_HTML: &[u8] = br#"<!doctype html><html><body data-page="intermediate">
<script src="/old.js"></script>
<script>
  fetch('/old-slow.bin');
  setTimeout(function () { location.replace('/final'); }, 100);
</script>
</body></html>"#;
const OLD_SCRIPT: &[u8] = b"window.__oldScriptRan = true;\n";
const OLD_SLOW_BINARY: &[u8] = b"old-generation-response\x00\xff";

const FINAL_HTML: &[u8] = br#"<!doctype html><html><head>
<title>final archive fixture</title>
<link rel="stylesheet" href="/final.css">
<link rel="stylesheet" href="/same.css">
<script src="/final.js"></script>
<script src="/same.js"></script>
</head><body data-page="final">
<img id="top-image" src="/top-route.png">
<iframe src="/child.html"></iframe>
<script>
  fetch('/payload.bin').then(function (response) { return response.arrayBuffer(); });
</script>
</body></html>"#;
const FINAL_SCRIPT: &[u8] = b"window.__finalExternalScriptRan = true;\n";
const FINAL_CSS: &[u8] = b"body { color: rgb(12, 34, 56); }\n";
const SAME_SCRIPT_AND_STYLESHEET: &[u8] = b"/* identical response bytes */\n";
const FETCH_BINARY: &[u8] = b"\x00\x01final-fetch\xff\xfe\x7f";
const TOP_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0xfc, 0xcf, 0xc0, 0x50,
    0x0f, 0x00, 0x05, 0x83, 0x02, 0x7f, 0x94, 0xff, 0x2f, 0x59, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

const CHILD_HTML: &[u8] = br#"<!doctype html><html><body data-frame="child">
<script src="/child.js"></script>
</body></html>"#;
const CHILD_SCRIPT: &[u8] = br#"window.__childExternalScriptRan = true;
window.__childImage = new Image();
window.__childImage.src = '/child.png';
"#;
const DETACHED_FRAME_PARENT_HTML: &[u8] = br#"<!doctype html><html><body>
<iframe id="transient-frame" src="/detached-child.html"></iframe>
<script>
  fetch('/detached-top-data.bin');
  setTimeout(function () {
    document.getElementById('transient-frame').remove();
  }, 150);
</script>
</body></html>"#;
const DETACHED_FRAME_CHILD_HTML: &[u8] = br#"<!doctype html><html><body>
<script>fetch('/detached-child-data.bin');</script>
</body></html>"#;
const DETACHED_TOP_DATA: &[u8] = b"live top-level fetch";
const DETACHED_CHILD_DATA: &[u8] = b"detached child fetch";
const STATIC_FRAME_PARENT_HTML: &[u8] =
    br#"<!doctype html><iframe src="/static-frame-child.html"></iframe>"#;
const STATIC_FRAME_CHILD_HTML: &[u8] =
    br#"<!doctype html><img id="frame-static" src="/static-frame.png">"#;
const SRCDOC_PARENT_HTML: &[u8] = br#"<!doctype html><html><head><base href="/srcdoc-base/"></head><body>
<iframe src="/must-not-request.html" srcdoc="<!doctype html><html><head><link rel=&quot;stylesheet&quot; href=&quot;frame.css&quot;><script src=&quot;frame.js&quot;></script></head><body data-frame=&quot;srcdoc&quot;><img src=&quot;frame.png&quot;></body></html>"></iframe>
</body></html>"#;
const SRCDOC_SCRIPT: &[u8] = b"window.__srcdocScriptRan = true;\n";
const SRCDOC_CSS: &[u8] = b"body { background-image: url('css.png'); }\n";
const SRCDOC_MISSING_SCRIPT_PARENT_HTML: &[u8] = br#"<!doctype html><base href="/srcdoc-base/"><iframe srcdoc="<script src=&quot;missing.js&quot;></script>"></iframe>"#;
const TOP_DYNAMIC_IMPORT_HTML: &[u8] = br#"<!doctype html><html><head></head><body>
<script>
  setTimeout(function () {
    var style = document.createElement('style');
    style.textContent = "@import '/top-dynamic-root.css'; .inline { background-image:url('/top-dynamic-inline.png') }";
    document.head.appendChild(style);
  }, 50);
</script>
</body></html>"#;
const TOP_DYNAMIC_ROOT_CSS: &[u8] =
    b"@import '/top-dynamic-nested.css'; .root { background-image:url('/top-dynamic-root.png') }\n";
const TOP_DYNAMIC_NESTED_CSS: &[u8] =
    b".nested { background-image:url('/top-dynamic-nested.png') }\n";
const SHADOW_PARENT_HTML: &[u8] = br#"<!doctype html><html><body>
<div id="shadow-host"></div>
<iframe src="/shadow-frame.html"></iframe>
<script>
  setTimeout(function () {
    if (globalThis.__shadowFixtureInstalled) return;
    globalThis.__shadowFixtureInstalled = true;
    var outer = document.getElementById('shadow-host').attachShadow({mode: 'closed'});
    var nestedHost = document.createElement('div');
    outer.appendChild(nestedHost);
    var nested = nestedHost.attachShadow({mode: 'closed'});

    var style = document.createElement('style');
    style.textContent = ".paint { background-image: url('/shadow-style.png') }";
    nested.appendChild(style);
    var paint = document.createElement('div');
    paint.className = 'paint';
    paint.setAttribute('style', "mask-image: url('/shadow-attribute.png')");
    nested.appendChild(paint);

    var image = document.createElement('img');
    image.src = '/shadow-image.png';
    nested.appendChild(image);

    var picture = document.createElement('picture');
    var source = document.createElement('source');
    source.setAttribute('srcset', '/shadow-picture.png');
    var fallback = document.createElement('img');
    fallback.src = '/shadow-picture-fallback.png';
    picture.appendChild(source);
    picture.appendChild(fallback);
    nested.appendChild(picture);

    var video = document.createElement('video');
    video.poster = '/shadow-poster.png';
    nested.appendChild(video);

    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    var use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', '/shadow-symbol.svg#tile');
    svg.appendChild(use);
    nested.appendChild(svg);
  }, 50);
</script>
</body></html>"#;
const SHADOW_FRAME_HTML: &[u8] = br#"<!doctype html><html><body>
<div><template shadowrootmode="closed">
  <div><template shadowrootmode="closed">
    <style>.frame-paint { background-image: url('/shadow-frame-style.png') }</style>
    <img src="/shadow-frame-image.png">
  </template></div>
</template></div>
</body></html>"#;
const SHADOW_MISSING_HTML: &[u8] = br#"<!doctype html><html><body><div id="host"></div>
<script>
  var root = document.getElementById('host').attachShadow({mode: 'closed'});
  var style = document.createElement('style');
  style.textContent = ".missing { background-image: url('/shadow-missing.png') }";
  root.appendChild(style);
</script></body></html>"#;
const SHADOW_IMPORT_HTML: &[u8] = br#"<!doctype html><html><body><div id="host"></div>
<script>
  var root = document.getElementById('host').attachShadow({mode: 'closed'});
  var style = document.createElement('style');
  style.textContent = "@import '/shadow-import.css'; .paint { color: green }";
  root.appendChild(style);
</script></body></html>"#;
const SHADOW_IMPORT_CSS: &[u8] = b".imported { background: rebeccapurple }\n";
const SHADOW_MISSING_BODY: &[u8] = b"shadow background missing\x00\xff";
const SHADOW_SVG: &[u8] =
    br#"<svg xmlns="http://www.w3.org/2000/svg"><symbol id="tile"><rect width="1" height="1"/></symbol></svg>"#;
const CHILD_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x08, 0x06, 0x00, 0x00, 0x00, 0xb9, 0xea, 0xde,
    0x81, 0x00, 0x00, 0x00, 0x16, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xfc, 0xcf, 0xc0, 0xf0,
    0x9f, 0x81, 0x81, 0x81, 0x81, 0x89, 0x01, 0x0a, 0xe0, 0x0c, 0x00, 0x31, 0x3b, 0x02, 0x04, 0xef,
    0x1e, 0x83, 0x91, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];
const DYNAMIC_PARENT_HTML: &[u8] =
    br#"<!doctype html><html><body><iframe src="/dynamic-child.html"></iframe></body></html>"#;
const DYNAMIC_CHILD_HTML: &[u8] = br#"<!doctype html><html><body data-frame="dynamic-child">
<script>
  setTimeout(function () {
    var script = document.createElement('script');
    script.src = '/dynamic-frame.js';
    document.body.appendChild(script);
  }, 50);
</script>
</body></html>"#;
const DYNAMIC_FRAME_SCRIPT: &[u8] = b"window.__dynamicFrameArchiveRan = true;\n";
const SLOW_DYNAMIC_PARENT_HTML: &[u8] =
    br#"<!doctype html><html><body><iframe src="/slow-dynamic-child.html"></iframe></body></html>"#;
const SLOW_DYNAMIC_CHILD_HTML: &[u8] =
    br#"<!doctype html><html><body data-frame="slow-dynamic-child">
<script>
  setTimeout(function () {
    var script = document.createElement('script');
    script.src = '/very-slow-frame.js';
    document.body.appendChild(script);
  }, 50);
</script>
</body></html>"#;
const VERY_SLOW_FRAME_SCRIPT: &[u8] = b"window.__verySlowFrameArchiveRan = true;\n";
const TINY_HTML: &[u8] = b"<p>tiny archive limit fixture</p>";
const SLOW_RENDER_HTML: &[u8] = br#"<!doctype html><html><body>
<div style="width:20px;height:20px;background-image:url('/very-slow-paint.png')"></div>
</body></html>"#;
const BROKEN_MODULE_HTML: &[u8] = br#"<!doctype html><html><head>
<script type="module" src="/broken-module.js"></script>
</head><body>broken module fixture</body></html>"#;
const BROKEN_MODULE_BODY: &[u8] = b"missing module";

struct Fixture {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
}

fn spawn_fixture() -> Fixture {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("fixture listener");
    let address = listener.local_addr().expect("fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed_requests = Arc::clone(&requests);

    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let observed_requests = Arc::clone(&observed_requests);
            std::thread::spawn(move || {
                let mut stream = match incoming {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let mut request = [0u8; 8192];
                let read = stream.read(&mut request).unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..read]);
                let path = request
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .split('?')
                    .next()
                    .unwrap_or("/")
                    .to_string();
                observed_requests.lock().unwrap().push(path.clone());

                let (status, content_type, extra_headers, body): (&str, &str, &str, &'static [u8]) =
                    match path.as_str() {
                        "/entry" => (
                            "302 Found",
                            "text/plain",
                            "Location: /intermediate\r\n",
                            b"",
                        ),
                        "/intermediate" => ("200 OK", "text/html", "", INTERMEDIATE_HTML),
                        "/old.js" => ("200 OK", "application/javascript", "", OLD_SCRIPT),
                        "/old-slow.bin" => {
                            std::thread::sleep(std::time::Duration::from_millis(400));
                            ("200 OK", "application/octet-stream", "", OLD_SLOW_BINARY)
                        }
                        "/final" => ("200 OK", "text/html", "", FINAL_HTML),
                        "/final.js" => ("200 OK", "application/javascript", "", FINAL_SCRIPT),
                        "/final.css" => ("200 OK", "text/css", "", FINAL_CSS),
                        "/same.js" => (
                            "200 OK",
                            "application/javascript",
                            "",
                            SAME_SCRIPT_AND_STYLESHEET,
                        ),
                        "/same.css" => ("200 OK", "text/css", "", SAME_SCRIPT_AND_STYLESHEET),
                        "/top-route.png" => {
                            ("302 Found", "image/png", "Location: /top.png\r\n", b"")
                        }
                        "/top.png" => ("200 OK", "image/png", "", TOP_PNG),
                        "/payload.bin" => ("200 OK", "application/octet-stream", "", FETCH_BINARY),
                        "/child.html" => ("200 OK", "text/html", "", CHILD_HTML),
                        "/child.js" => ("200 OK", "application/javascript", "", CHILD_SCRIPT),
                        "/child.png" => ("200 OK", "image/png", "", CHILD_PNG),
                        "/detached-frame-final" => {
                            ("200 OK", "text/html", "", DETACHED_FRAME_PARENT_HTML)
                        }
                        "/detached-child.html" => {
                            ("200 OK", "text/html", "", DETACHED_FRAME_CHILD_HTML)
                        }
                        "/detached-top-data.bin" => {
                            std::thread::sleep(std::time::Duration::from_millis(350));
                            (
                                "200 OK",
                                "application/octet-stream",
                                "",
                                DETACHED_TOP_DATA,
                            )
                        }
                        "/detached-child-data.bin" => {
                            std::thread::sleep(std::time::Duration::from_millis(350));
                            (
                                "200 OK",
                                "application/octet-stream",
                                "",
                                DETACHED_CHILD_DATA,
                            )
                        }
                        "/static-frame-final" => {
                            ("200 OK", "text/html", "", STATIC_FRAME_PARENT_HTML)
                        }
                        "/static-frame-child.html" => {
                            ("200 OK", "text/html", "", STATIC_FRAME_CHILD_HTML)
                        }
                        "/static-frame.png" => ("200 OK", "image/png", "", TOP_PNG),
                        "/srcdoc-final" => ("200 OK", "text/html", "", SRCDOC_PARENT_HTML),
                        "/srcdoc-missing-final" => {
                            ("200 OK", "text/html", "", SRCDOC_MISSING_SCRIPT_PARENT_HTML)
                        }
                        "/srcdoc-base/frame.js" => {
                            ("200 OK", "application/javascript", "", SRCDOC_SCRIPT)
                        }
                        "/srcdoc-base/frame.css" => ("200 OK", "text/css", "", SRCDOC_CSS),
                        "/srcdoc-base/frame.png" | "/srcdoc-base/css.png" => {
                            ("200 OK", "image/png", "", TOP_PNG)
                        }
                        "/top-dynamic-import-final" => {
                            ("200 OK", "text/html", "", TOP_DYNAMIC_IMPORT_HTML)
                        }
                        "/top-dynamic-root.css" => ("200 OK", "text/css", "", TOP_DYNAMIC_ROOT_CSS),
                        "/top-dynamic-nested.css" => {
                            ("200 OK", "text/css", "", TOP_DYNAMIC_NESTED_CSS)
                        }
                        "/top-dynamic-inline.png"
                        | "/top-dynamic-root.png"
                        | "/top-dynamic-nested.png" => ("200 OK", "image/png", "", TOP_PNG),
                        "/shadow-final" => ("200 OK", "text/html", "", SHADOW_PARENT_HTML),
                        "/shadow-frame.html" => ("200 OK", "text/html", "", SHADOW_FRAME_HTML),
                        "/shadow-style.png"
                        | "/shadow-attribute.png"
                        | "/shadow-image.png"
                        | "/shadow-picture.png"
                        | "/shadow-picture-fallback.png"
                        | "/shadow-poster.png"
                        | "/shadow-frame-style.png"
                        | "/shadow-frame-image.png" => ("200 OK", "image/png", "", TOP_PNG),
                        "/shadow-symbol.svg" => ("200 OK", "image/svg+xml", "", SHADOW_SVG),
                        "/shadow-missing-final" => ("200 OK", "text/html", "", SHADOW_MISSING_HTML),
                        "/shadow-missing.png" => (
                            "404 Not Found",
                            "application/octet-stream",
                            "",
                            SHADOW_MISSING_BODY,
                        ),
                        "/shadow-import-final" => ("200 OK", "text/html", "", SHADOW_IMPORT_HTML),
                        "/shadow-import.css" => ("200 OK", "text/css", "", SHADOW_IMPORT_CSS),
                        "/dynamic-final" => ("200 OK", "text/html", "", DYNAMIC_PARENT_HTML),
                        "/dynamic-child.html" => ("200 OK", "text/html", "", DYNAMIC_CHILD_HTML),
                        "/dynamic-frame.js" => {
                            std::thread::sleep(std::time::Duration::from_millis(300));
                            ("200 OK", "application/javascript", "", DYNAMIC_FRAME_SCRIPT)
                        }
                        "/slow-dynamic-final" => {
                            ("200 OK", "text/html", "", SLOW_DYNAMIC_PARENT_HTML)
                        }
                        "/slow-dynamic-child.html" => {
                            ("200 OK", "text/html", "", SLOW_DYNAMIC_CHILD_HTML)
                        }
                        "/very-slow-frame.js" => {
                            std::thread::sleep(std::time::Duration::from_millis(1_500));
                            (
                                "200 OK",
                                "application/javascript",
                                "",
                                VERY_SLOW_FRAME_SCRIPT,
                            )
                        }
                        "/slow-render-final" => ("200 OK", "text/html", "", SLOW_RENDER_HTML),
                        "/very-slow-paint.png" => {
                            std::thread::sleep(std::time::Duration::from_millis(1_500));
                            ("200 OK", "image/png", "", TOP_PNG)
                        }
                        "/broken-module-final" => ("200 OK", "text/html", "", BROKEN_MODULE_HTML),
                        "/broken-module.js" => (
                            "404 Not Found",
                            "application/javascript",
                            "",
                            BROKEN_MODULE_BODY,
                        ),
                        "/tiny" => ("200 OK", "text/html", "", TINY_HTML),
                        _ => ("404 Not Found", "text/plain", "", b"not found"),
                    };
                let response_headers = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n",
                    body.len(),
                );
                let _ = stream.write_all(response_headers.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.shutdown(std::net::Shutdown::Both);
            });
        }
    });

    Fixture {
        origin: format!("http://{address}"),
        requests,
    }
}

struct TempTree(std::path::PathBuf);

impl TempTree {
    fn new() -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "obscura-assets-archive-e2e-{}-{unique}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&path).expect("temporary test root");
        Self(path)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ExpectedAsset {
    request_route: &'static str,
    route: &'static str,
    body: &'static [u8],
    resource_type: &'static str,
    frame_id: u64,
    extension: &'static str,
}

impl ExpectedAsset {
    fn direct(
        route: &'static str,
        body: &'static [u8],
        resource_type: &'static str,
        frame_id: u64,
        extension: &'static str,
    ) -> Self {
        Self {
            request_route: route,
            route,
            body,
            resource_type,
            frame_id,
            extension,
        }
    }

    fn redirected(
        request_route: &'static str,
        route: &'static str,
        body: &'static [u8],
        resource_type: &'static str,
        frame_id: u64,
        extension: &'static str,
    ) -> Self {
        Self {
            request_route,
            route,
            body,
            resource_type,
            frame_id,
            extension,
        }
    }
}

fn assert_asset(
    archive: &std::path::Path,
    origin: &str,
    assets: &[serde_json::Value],
    expected: ExpectedAsset,
) {
    let final_url = format!("{origin}{}", expected.route);
    let request_url = format!("{origin}{}", expected.request_route);
    let matching = assets
        .iter()
        .filter(|asset| asset["final_url"].as_str() == Some(final_url.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one archived response for {}: {matching:?}",
        expected.route,
    );
    let asset = matching[0];
    assert_eq!(asset["request_url"].as_str(), Some(request_url.as_str()));
    let expected_redirected_from = if expected.request_route == expected.route {
        serde_json::json!([])
    } else {
        serde_json::json!([request_url])
    };
    assert_eq!(asset["redirected_from"], expected_redirected_from);
    assert_eq!(
        asset["resource_type"].as_str(),
        Some(expected.resource_type)
    );
    assert_eq!(asset["frame_id"].as_u64(), Some(expected.frame_id));
    assert_eq!(asset["bytes"].as_u64(), Some(expected.body.len() as u64));

    let sha256 = format!("{:x}", Sha256::digest(expected.body));
    let expected_path = format!("resources/{sha256}.{}", expected.extension);
    assert_eq!(asset["sha256"].as_str(), Some(sha256.as_str()));
    assert_eq!(asset["path"].as_str(), Some(expected_path.as_str()));
    assert_eq!(
        std::fs::read(archive.join(&expected_path)).expect("archived raw response"),
        expected.body,
        "archive changed the raw bytes for {}",
        expected.route,
    );
}

fn asset_archive_command(
    archive: &std::path::Path,
    url: &str,
    wait_seconds: &str,
    max_bytes: Option<usize>,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_obscura"));
    command.args([
        "--allow-private-network",
        "fetch",
        "--quiet",
        "--wait",
        wait_seconds,
        "--dump",
        "assets",
        "--assets-dir",
    ]);
    command.arg(archive);
    if let Some(max_bytes) = max_bytes {
        command.arg("--assets-max-bytes").arg(max_bytes.to_string());
    }
    command.arg(url);
    for variable in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ] {
        command.env_remove(variable);
    }
    command
}

#[test]
fn assets_dir_rejects_output_and_screenshot_paths_inside_the_archive() {
    let temp = TempTree::new();
    for (ordinal, (flag, leaf)) in [("--output", "manifest.json"), ("--screenshot", "page.html")]
        .into_iter()
        .enumerate()
    {
        let archive = temp.0.join(format!("conflicting-archive-{ordinal}"));
        let mut command = asset_archive_command(&archive, "https://example.invalid/", "0", None);
        command.arg(flag).arg(archive.join(leaf));
        let output = command.output().expect("run conflicting archive command");
        assert!(!output.status.success(), "{flag} conflict must be rejected");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("path must be outside --assets-dir"),
            "unexpected {flag} conflict diagnostic: {}",
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            !archive.exists(),
            "path conflict must be rejected before creating the archive",
        );
    }
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn assets_dir_rejects_a_case_only_output_alias_inside_the_archive() {
    let temp = TempTree::new();
    let archive = temp.0.join("Capture");
    let aliased_manifest = temp.0.join("capture/manifest.json");
    let mut command = asset_archive_command(&archive, "https://example.invalid/", "0", None);
    command.arg("--output").arg(&aliased_manifest);

    let output = command
        .output()
        .expect("run case-aliased archive command");
    assert!(
        !output.status.success(),
        "case-only output alias must be rejected before it can replace manifest.json",
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("path must be outside --assets-dir"),
        "unexpected case-alias diagnostic: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !archive.exists(),
        "case-only alias conflict must be rejected before creating the archive",
    );
}

#[cfg(unix)]
#[test]
fn assets_dir_rejects_a_symlinked_output_alias_inside_the_archive() {
    use std::os::unix::fs::symlink;

    let temp = TempTree::new();
    let actual_parent = temp.0.join("actual");
    let alias_parent = temp.0.join("alias");
    std::fs::create_dir_all(&actual_parent).expect("actual parent");
    symlink(&actual_parent, &alias_parent).expect("parent alias");

    let archive = actual_parent.join("archive");
    let mut command = asset_archive_command(&archive, "https://example.invalid/", "0", None);
    command
        .arg("--output")
        .arg(alias_parent.join("archive/manifest.json"));
    let output = command.output().expect("run aliased archive command");
    assert!(!output.status.success(), "symlink alias conflict must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("path must be outside --assets-dir"),
        "unexpected alias conflict diagnostic: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(!archive.exists());
}

#[cfg(unix)]
#[test]
fn assets_dir_rejects_a_symlink_as_the_archive_directory() {
    use std::os::unix::fs::symlink;

    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let actual_archive = temp.0.join("actual-archive");
    let archive_alias = temp.0.join("archive-alias");
    std::fs::create_dir(&actual_archive).expect("actual archive");
    symlink(&actual_archive, &archive_alias).expect("archive alias");

    let output = asset_archive_command(
        &archive_alias,
        &format!("{}/tiny", fixture.origin),
        "0",
        None,
    )
    .output()
    .expect("run symlinked archive command");
    assert!(!output.status.success(), "symlinked archive must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("asset archive path must not be a symbolic link"),
        "unexpected archive symlink diagnostic: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        std::fs::read_dir(&actual_archive)
            .expect("actual archive directory")
            .next()
            .is_none(),
        "a symlinked archive target must remain untouched",
    );
}

#[cfg(unix)]
#[test]
fn assets_dir_rejects_symlinked_internal_targets_without_overwriting_them() {
    use std::os::unix::fs::symlink;

    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("archive-with-symlink");
    let outside = temp.0.join("outside-page.html");
    std::fs::create_dir(&archive).expect("archive directory");
    std::fs::write(&outside, b"outside sentinel").expect("outside sentinel");
    symlink(&outside, archive.join("page.html")).expect("internal page alias");

    let output = asset_archive_command(&archive, &format!("{}/tiny", fixture.origin), "0", None)
        .output()
        .expect("run archive with internal symlink");
    assert!(!output.status.success(), "internal symlink must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("asset archive contains a symbolic link"),
        "unexpected internal symlink diagnostic: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        std::fs::read(&outside).expect("outside sentinel after rejection"),
        b"outside sentinel",
        "archive creation must not follow or truncate an internal symlink",
    );
}

#[test]
fn assets_dir_archives_only_final_document_resources_with_frame_ownership() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("archive");
    let entry_url = format!("{}/entry", fixture.origin);

    let output = asset_archive_command(&archive, &entry_url, "1", None)
        .output()
        .expect("run obscura asset archive");
    assert!(
        output.status.success(),
        "asset archive command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let requested_paths = fixture.requests.lock().unwrap().clone();
    for old_path in ["/intermediate", "/old.js", "/old-slow.bin"] {
        assert!(
            requested_paths.iter().any(|path| path == old_path),
            "fixture never exercised old-document request {old_path}: {requested_paths:?}",
        );
    }
    for redirected_image_path in ["/top-route.png", "/top.png"] {
        assert!(
            requested_paths
                .iter()
                .any(|path| path == redirected_image_path),
            "fixture did not exercise image redirect hop {redirected_image_path}: {requested_paths:?}",
        );
    }

    let manifest_bytes = std::fs::read(archive.join("manifest.json")).expect("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("valid manifest JSON");
    assert_eq!(manifest["version"].as_u64(), Some(1));
    assert_eq!(manifest["input_url"].as_str(), Some(entry_url.as_str()));
    assert_eq!(
        manifest["final_url"].as_str(),
        Some(format!("{}/final", fixture.origin).as_str()),
    );
    assert_eq!(manifest["complete"].as_bool(), Some(true));
    assert_eq!(manifest["rendered_document"].as_str(), Some("page.html"));

    let assets = manifest["assets"].as_array().expect("manifest assets");
    for excluded in ["/entry", "/intermediate", "/old.js", "/old-slow.bin"] {
        assert!(
            assets.iter().all(|asset| {
                !asset["final_url"]
                    .as_str()
                    .unwrap_or_default()
                    .ends_with(excluded)
            }),
            "old-document resource {excluded} leaked into final archive",
        );
    }

    let expected_assets = [
        ExpectedAsset::direct("/final", FINAL_HTML, "document", 0, "html"),
        ExpectedAsset::direct("/final.js", FINAL_SCRIPT, "script", 0, "js"),
        ExpectedAsset::direct("/final.css", FINAL_CSS, "stylesheet", 0, "css"),
        ExpectedAsset::direct("/same.js", SAME_SCRIPT_AND_STYLESHEET, "script", 0, "js"),
        ExpectedAsset::direct(
            "/same.css",
            SAME_SCRIPT_AND_STYLESHEET,
            "stylesheet",
            0,
            "css",
        ),
        ExpectedAsset::redirected("/top-route.png", "/top.png", TOP_PNG, "image", 0, "png"),
        ExpectedAsset::direct("/payload.bin", FETCH_BINARY, "fetch", 0, "bin"),
        ExpectedAsset::direct("/child.html", CHILD_HTML, "document", 1, "html"),
        ExpectedAsset::direct("/child.js", CHILD_SCRIPT, "script", 1, "js"),
        ExpectedAsset::direct("/child.png", CHILD_PNG, "image", 1, "png"),
    ];
    assert_eq!(
        assets.len(),
        expected_assets.len(),
        "unexpected final-document archive contents: {assets:#?}",
    );
    for expected in expected_assets {
        assert_asset(&archive, &fixture.origin, assets, expected);
    }

    let page_document =
        std::fs::read_to_string(archive.join("page.html")).expect("rendered page document");
    assert!(page_document.contains("data-page=\"final\""));
    assert!(!page_document.contains("data-page=\"intermediate\""));
    let frames = manifest["frames"].as_array().expect("manifest frames");
    assert_eq!(frames.len(), 1, "expected one child frame: {frames:?}");
    assert_eq!(frames[0]["frame_id"].as_u64(), Some(1));
    assert_eq!(
        frames[0]["url"].as_str(),
        Some(format!("{}/child.html", fixture.origin).as_str()),
    );
    assert_eq!(frames[0]["path"].as_str(), Some("frames/0000.html"));
    let child_document =
        std::fs::read_to_string(archive.join("frames/0000.html")).expect("child frame document");
    assert!(child_document.contains("data-frame=\"child\""));
    assert!(child_document.contains("src=\"/child.js\""));
}

#[test]
fn assets_dir_excludes_a_removed_frame_document_and_its_fetches() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("detached-frame-archive");
    let url = format!("{}/detached-frame-final", fixture.origin);

    let output = asset_archive_command(&archive, &url, "1", None)
        .output()
        .expect("run detached-frame asset archive");
    assert!(
        output.status.success(),
        "detached-frame archive failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let requested_paths = fixture.requests.lock().unwrap().clone();
    for exercised in [
        "/detached-child.html",
        "/detached-child-data.bin",
        "/detached-top-data.bin",
    ] {
        assert!(
            requested_paths.iter().any(|path| path == exercised),
            "fixture never exercised {exercised}: {requested_paths:?}",
        );
    }

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(true));
    assert_eq!(
        manifest["frames"].as_array().map(Vec::len),
        Some(0),
        "a removed frame must not remain live: {manifest:#?}",
    );

    let assets = manifest["assets"].as_array().expect("manifest assets");
    for excluded in ["/detached-child.html", "/detached-child-data.bin"] {
        assert!(
            assets.iter().all(|asset| {
                !asset["final_url"]
                    .as_str()
                    .unwrap_or_default()
                    .ends_with(excluded)
            }),
            "removed-frame resource {excluded} leaked into the final archive: {assets:#?}",
        );
    }
    assert_asset(
        &archive,
        &fixture.origin,
        assets,
        ExpectedAsset::direct(
            "/detached-frame-final",
            DETACHED_FRAME_PARENT_HTML,
            "document",
            0,
            "html",
        ),
    );
    assert_asset(
        &archive,
        &fixture.origin,
        assets,
        ExpectedAsset::direct(
            "/detached-top-data.bin",
            DETACHED_TOP_DATA,
            "fetch",
            0,
            "bin",
        ),
    );
}

#[test]
fn assets_dir_writes_an_incomplete_manifest_before_reporting_capture_limits() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("limited-archive");
    let tiny_url = format!("{}/tiny", fixture.origin);

    let output = asset_archive_command(&archive, &tiny_url, "0", Some(1))
        .output()
        .expect("run size-limited obscura asset archive");
    assert!(
        !output.status.success(),
        "capture above --assets-max-bytes must report a non-zero exit status",
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("asset archive is incomplete"),
        "limit failure did not explain the incomplete archive: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let manifest_bytes = std::fs::read(archive.join("manifest.json"))
        .expect("incomplete capture must still write manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("valid incomplete manifest JSON");
    assert_eq!(manifest["input_url"].as_str(), Some(tiny_url.as_str()));
    assert_eq!(manifest["final_url"].as_str(), Some(tiny_url.as_str()));
    assert_eq!(manifest["complete"].as_bool(), Some(false));
    assert_eq!(manifest["captured_response_bytes"].as_u64(), Some(0));
    assert_eq!(manifest["assets"].as_array().map(Vec::len), Some(0));
    assert_eq!(
        manifest["incomplete_reasons"],
        serde_json::json!([format!(
            "capture limits omitted 1 responses ({} bytes)",
            TINY_HTML.len(),
        )]),
    );

    let rendered_document =
        std::fs::read_to_string(archive.join("page.html")).expect("limited rendered document");
    assert!(rendered_document.contains("tiny archive limit fixture"));
    assert!(
        std::fs::read_dir(archive.join("resources"))
            .expect("resources directory")
            .next()
            .is_none(),
        "an omitted response must not leave a raw resource file",
    );
}

#[test]
fn assets_dir_marks_failed_top_level_external_module_incomplete() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("broken-module-archive");
    let url = format!("{}/broken-module-final", fixture.origin);

    let output = asset_archive_command(&archive, &url, "0", None)
        .output()
        .expect("run broken-module asset archive");
    assert!(
        !output.status.success(),
        "a failed external module must make the archive command non-zero",
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("incomplete manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(false));
    assert!(manifest["incomplete_reasons"]
        .as_array()
        .expect("incomplete reasons")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|reason| {
            reason
                == format!(
                    "top-level module graph preparation failed: {}/broken-module.js",
                    fixture.origin,
                )
        }));
    assert_asset(
        &archive,
        &fixture.origin,
        manifest["assets"].as_array().expect("manifest assets"),
        ExpectedAsset::direct("/broken-module.js", BROKEN_MODULE_BODY, "script", 0, "js"),
    );
}

#[test]
fn assets_dir_archives_a_static_child_frame_image() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("static-frame-archive");
    let url = format!("{}/static-frame-final", fixture.origin);

    let output = asset_archive_command(&archive, &url, "0", None)
        .output()
        .expect("run static child-frame asset archive");
    assert!(
        output.status.success(),
        "static child-frame archive failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(true));
    assert_asset(
        &archive,
        &fixture.origin,
        manifest["assets"].as_array().expect("manifest assets"),
        ExpectedAsset::direct("/static-frame.png", TOP_PNG, "image", 1, "png"),
    );
}

#[test]
fn assets_dir_archives_srcdoc_resources_with_inherited_base_and_frame_ownership() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("srcdoc-frame-archive");
    let url = format!("{}/srcdoc-final", fixture.origin);

    let output = asset_archive_command(&archive, &url, "0", None)
        .output()
        .expect("run srcdoc child-frame asset archive");
    assert!(
        output.status.success(),
        "srcdoc child-frame archive failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(true));
    let frames = manifest["frames"].as_array().expect("manifest frames");
    assert_eq!(
        frames.len(),
        1,
        "expected one live srcdoc frame: {frames:?}"
    );
    let frame_id = frames[0]["frame_id"].as_u64().expect("srcdoc frame id");
    assert_ne!(frame_id, 0);
    assert_eq!(frames[0]["url"].as_str(), Some("about:srcdoc"));

    let assets = manifest["assets"].as_array().expect("manifest assets");
    for expected in [
        ExpectedAsset::direct(
            "/srcdoc-base/frame.js",
            SRCDOC_SCRIPT,
            "script",
            frame_id,
            "js",
        ),
        ExpectedAsset::direct(
            "/srcdoc-base/frame.css",
            SRCDOC_CSS,
            "stylesheet",
            frame_id,
            "css",
        ),
        ExpectedAsset::direct("/srcdoc-base/frame.png", TOP_PNG, "image", frame_id, "png"),
        ExpectedAsset::direct("/srcdoc-base/css.png", TOP_PNG, "image", frame_id, "png"),
    ] {
        assert_asset(&archive, &fixture.origin, assets, expected);
    }
    assert!(
        assets
            .iter()
            .filter(|asset| asset["frame_id"].as_u64() == Some(frame_id))
            .all(|asset| asset["initiator"].as_str() == Some("about:srcdoc")),
        "srcdoc resources lost their frame-document initiator: {assets:#?}",
    );
    let requested = fixture.requests.lock().unwrap();
    assert!(
        !requested
            .iter()
            .any(|path| path == "/must-not-request.html"),
        "src must be ignored while srcdoc is present: {requested:?}",
    );
    let frame_document =
        std::fs::read_to_string(archive.join("frames/0000.html")).expect("serialized srcdoc frame");
    assert!(frame_document.contains("data-frame=\"srcdoc\""));
    assert!(frame_document.contains("src=\"frame.png\""));
}

#[test]
fn assets_dir_marks_a_failed_srcdoc_classic_script_incomplete() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("srcdoc-missing-script-archive");
    let url = format!("{}/srcdoc-missing-final", fixture.origin);

    let output = asset_archive_command(&archive, &url, "0", None)
        .output()
        .expect("run srcdoc missing-script asset archive");
    assert!(
        !output.status.success(),
        "a failed srcdoc classic script must make the archive command non-zero",
    );
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(false));
    assert!(manifest["incomplete_reasons"]
        .as_array()
        .expect("incomplete reasons")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|reason| {
            reason.contains("classic script")
                && reason.contains("/srcdoc-base/missing.js")
                && reason.contains("HTTP 404")
        }));
}

#[test]
fn assets_dir_archives_top_dynamic_inline_stylesheet_import_graph() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("top-dynamic-import-archive");
    let url = format!("{}/top-dynamic-import-final", fixture.origin);

    let output = asset_archive_command(&archive, &url, "1", None)
        .output()
        .expect("run top dynamic inline-import asset archive");
    assert!(
        output.status.success(),
        "top dynamic inline-import archive failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(true));
    let assets = manifest["assets"].as_array().expect("manifest assets");
    for expected in [
        ExpectedAsset::direct(
            "/top-dynamic-root.css",
            TOP_DYNAMIC_ROOT_CSS,
            "stylesheet",
            0,
            "css",
        ),
        ExpectedAsset::direct(
            "/top-dynamic-nested.css",
            TOP_DYNAMIC_NESTED_CSS,
            "stylesheet",
            0,
            "css",
        ),
        ExpectedAsset::direct("/top-dynamic-inline.png", TOP_PNG, "image", 0, "png"),
        ExpectedAsset::direct("/top-dynamic-root.png", TOP_PNG, "image", 0, "png"),
        ExpectedAsset::direct("/top-dynamic-nested.png", TOP_PNG, "image", 0, "png"),
    ] {
        assert_asset(&archive, &fixture.origin, assets, expected);
    }
    let document_url = format!("{}/top-dynamic-import-final", fixture.origin);
    assert!(assets
        .iter()
        .filter(|asset| asset["resource_type"].as_str() == Some("stylesheet"))
        .all(|asset| asset["initiator"].as_str() == Some(document_url.as_str())));
}

#[test]
fn assets_dir_archives_nested_closed_shadow_resources_for_top_and_frame() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("shadow-resource-archive");
    let url = format!("{}/shadow-final", fixture.origin);

    let output = asset_archive_command(&archive, &url, "1", None)
        .output()
        .expect("run closed-shadow asset archive");
    assert!(
        output.status.success(),
        "closed-shadow archive failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(true));
    let assets = manifest["assets"].as_array().expect("manifest assets");
    for expected in [
        ExpectedAsset::direct("/shadow-style.png", TOP_PNG, "image", 0, "png"),
        ExpectedAsset::direct("/shadow-attribute.png", TOP_PNG, "image", 0, "png"),
        ExpectedAsset::direct("/shadow-image.png", TOP_PNG, "image", 0, "png"),
        ExpectedAsset::direct("/shadow-picture.png", TOP_PNG, "image", 0, "png"),
        ExpectedAsset::direct("/shadow-poster.png", TOP_PNG, "image", 0, "png"),
        ExpectedAsset::direct("/shadow-symbol.svg", SHADOW_SVG, "image", 0, "svg"),
        ExpectedAsset::direct("/shadow-frame-style.png", TOP_PNG, "image", 1, "png"),
        ExpectedAsset::direct("/shadow-frame-image.png", TOP_PNG, "image", 1, "png"),
    ] {
        assert_asset(&archive, &fixture.origin, assets, expected);
    }

    let top_initiator = format!("{}/shadow-final", fixture.origin);
    let frame_initiator = format!("{}/shadow-frame.html", fixture.origin);
    assert!(assets
        .iter()
        .filter(|asset| asset["final_url"].as_str().is_some_and(|url| {
            url.contains("/shadow-") && asset["resource_type"].as_str() == Some("image")
        }))
        .all(|asset| {
            let expected = if asset["frame_id"].as_u64() == Some(1) {
                frame_initiator.as_str()
            } else {
                top_initiator.as_str()
            };
            asset["initiator"].as_str() == Some(expected)
        }));
}

#[test]
fn assets_dir_marks_failed_closed_shadow_background_incomplete() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("missing-shadow-resource-archive");
    let url = format!("{}/shadow-missing-final", fixture.origin);

    let output = asset_archive_command(&archive, &url, "0", None)
        .output()
        .expect("run missing closed-shadow asset archive");
    assert!(
        !output.status.success(),
        "a failed closed-shadow background must make the archive command non-zero",
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("incomplete manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(false));
    let reasons = manifest["incomplete_reasons"]
        .as_array()
        .expect("incomplete reasons");
    assert!(
        reasons
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|reason| reason
                .contains("renderer resource request(s) failed during final-page warmup")),
        "missing shadow-resource failure diagnostic: {reasons:?}",
    );
    let assets = manifest["assets"].as_array().expect("manifest assets");
    let missing_url = format!("{}/shadow-missing.png", fixture.origin);
    let missing = assets
        .iter()
        .filter(|asset| asset["final_url"].as_str() == Some(missing_url.as_str()))
        .collect::<Vec<_>>();
    assert!(
        !missing.is_empty(),
        "the failed closed-shadow response body was not archived",
    );
    let sha256 = format!("{:x}", Sha256::digest(SHADOW_MISSING_BODY));
    let expected_path = format!("resources/{sha256}.png");
    for asset in missing {
        assert_eq!(asset["status"].as_u64(), Some(404));
        assert_eq!(asset["resource_type"].as_str(), Some("image"));
        assert_eq!(asset["frame_id"].as_u64(), Some(0));
        assert_eq!(
            asset["bytes"].as_u64(),
            Some(SHADOW_MISSING_BODY.len() as u64)
        );
        assert_eq!(asset["sha256"].as_str(), Some(sha256.as_str()));
        assert_eq!(asset["path"].as_str(), Some(expected_path.as_str()));
    }
    assert_eq!(
        std::fs::read(archive.join(expected_path)).expect("archived failed shadow response"),
        SHADOW_MISSING_BODY,
    );
}

#[test]
fn assets_dir_marks_closed_shadow_inline_import_incomplete() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("shadow-import-archive");
    let url = format!("{}/shadow-import-final", fixture.origin);

    let output = asset_archive_command(&archive, &url, "0", None)
        .output()
        .expect("run closed-shadow import archive");
    assert!(
        !output.status.success(),
        "an unsupported closed-shadow @import must not claim completeness",
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("incomplete manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(false));
    assert!(manifest["incomplete_reasons"]
        .as_array()
        .expect("incomplete reasons")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|reason| reason
            == "top-level shadow-root inline stylesheets contain 1 unsupported @import rule(s)"));
}

#[test]
fn assets_dir_waits_for_a_delayed_dynamic_child_frame_script() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("dynamic-frame-archive");
    let url = format!("{}/dynamic-final", fixture.origin);

    let output = asset_archive_command(&archive, &url, "0", None)
        .output()
        .expect("run dynamic frame asset archive");
    assert!(
        output.status.success(),
        "dynamic frame archive failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(true));
    let assets = manifest["assets"].as_array().expect("manifest assets");
    assert_asset(
        &archive,
        &fixture.origin,
        assets,
        ExpectedAsset::direct("/dynamic-frame.js", DYNAMIC_FRAME_SCRIPT, "fetch", 1, "js"),
    );
}

#[test]
fn assets_dir_marks_pending_dynamic_frame_script_incomplete_at_deadline() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("pending-dynamic-frame-archive");
    let url = format!("{}/slow-dynamic-final", fixture.origin);

    let mut command = asset_archive_command(&archive, &url, "0", None);
    command.env("OBSCURA_RENDER_RESOURCE_DEADLINE_MS", "100");
    let output = command.output().expect("run pending frame asset archive");
    assert!(
        !output.status.success(),
        "a response still pending beyond the archive deadline must be non-zero",
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("incomplete manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(false));
    let reasons = manifest["incomplete_reasons"]
        .as_array()
        .expect("incomplete reasons")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        reasons.contains("pending page network requests")
            || reasons.contains("dynamic scripts still pending"),
        "pending work was not reported: {reasons}",
    );
    assert!(
        reasons.contains("very-slow-frame.js") || reasons.contains("frame 1"),
        "the incomplete reason did not identify the child-frame resource: {reasons}",
    );
}

#[test]
fn assets_dir_marks_timed_out_renderer_resource_incomplete() {
    let fixture = spawn_fixture();
    let temp = TempTree::new();
    let archive = temp.0.join("slow-render-archive");
    let url = format!("{}/slow-render-final", fixture.origin);

    let mut command = asset_archive_command(&archive, &url, "0", None);
    command.env("OBSCURA_RENDER_RESOURCE_DEADLINE_MS", "50");
    let output = command.output().expect("run slow renderer archive");
    assert!(
        !output.status.success(),
        "a renderer resource beyond every warmup deadline must be non-zero",
    );

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(archive.join("manifest.json")).expect("incomplete manifest.json"),
    )
    .expect("valid manifest JSON");
    assert_eq!(manifest["complete"].as_bool(), Some(false));
    let reasons = manifest["incomplete_reasons"]
        .as_array()
        .expect("incomplete reasons")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        reasons.contains("renderer resource request attempt(s)")
            || reasons.contains("renderer resource(s) remained unresolved"),
        "timed-out paint resource was not reported: {reasons}",
    );
}
