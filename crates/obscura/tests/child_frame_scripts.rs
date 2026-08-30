//! Regression test for issue #600: a child iframe's document was fetched and
//! parsed, but the frame never got a scripting context, so a `<script>` inside
//! it stayed an inert node. This is the reporter's loopback repro, reduced to
//! the part that needs no network: two documents on one local server.

use std::io::{Read, Write};

use obscura::Browser;

const PARENT_HTML: &str = r#"<!doctype html><html><head><title>parent</title></head><body>
<script>
  var f = document.createElement('iframe');
  f.src = '/child.html';
  document.body.appendChild(f);
</script>
</body></html>"#;

const ATTRIBUTE_PARENT_HTML: &str = r#"<!doctype html><html><head><title>parent</title></head><body>
<script>
  var f = document.createElement('iframe');
  f.setAttribute('src', '/child.html');
  document.body.appendChild(f);
</script>
</body></html>"#;

const SHADOW_PARENT_HTML: &str = r#"<!doctype html><html><head><title>parent</title></head><body>
<script>
  var host = document.createElement('div');
  var root = host.attachShadow({mode: 'open'});
  var f = document.createElement('iframe');
  f.setAttribute('src', '/child.html');
  root.appendChild(f);
  document.body.appendChild(host);
</script>
</body></html>"#;

const CLOSED_SHADOW_REINSERT_PARENT_HTML: &str = r#"<!doctype html><html><body>
<script>
  window.__shadowReinsert = { loads: 0, childRuns: [] };
  const host = document.createElement('div');
  const root = host.attachShadow({mode: 'closed'});
  const frame = document.createElement('iframe');
  let firstWindow = null;
  frame.srcdoc = '<!doctype html><script>window.__ran = (window.__ran || 0) + 1;<\/script>';
  frame.onload = function () {
    __shadowReinsert.loads++;
    __shadowReinsert.childRuns.push(frame.contentWindow.__ran || 0);
    if (__shadowReinsert.loads === 1) {
      firstWindow = frame.contentWindow;
      __shadowReinsert.firstFrameId = frame._frameId;
      host.remove();
      __shadowReinsert.resetFrameId = frame._frameId;
      document.body.appendChild(host);
    } else if (__shadowReinsert.loads === 2) {
      __shadowReinsert.secondFrameId = frame._frameId;
      __shadowReinsert.windowChanged = frame.contentWindow !== firstWindow;
    }
  };
  root.appendChild(frame);
  document.body.appendChild(host);
  window.__closedShadowHost = host;
</script>
</body></html>"#;

const RESET_PARENT_HTML: &str = r#"<!doctype html><html><head><title>parent</title></head><body>
<script>
  var f = document.createElement('iframe');
  f.src = '/child.html';
  document.body.appendChild(f);
  setTimeout(function () { f.src = 'about:blank'; }, 150);
</script>
</body></html>"#;

const STATIC_PARENT_HTML: &str = r#"<!doctype html><html><head><title>parent</title></head><body>
<iframe src="/child.html"></iframe>
</body></html>"#;

const CHILD_HTML: &str = r#"<!doctype html><html><head><title>BEFORE</title></head><body>
<p>child</p>
<script>
  window.__ran = "YES";
  document.title = "RAN-IN-CHILD";
</script>
</body></html>"#;

/// The reporter's original pair: the child reports to its parent over
/// postMessage, which is how every embedded widget returns a result.
const MESSAGING_PARENT_HTML: &str = r#"<!doctype html><html><head><title>parent</title></head><body>
<script>
  window.__res = {parentGot: [], trusted: [], fromChildWindow: []};
  window.addEventListener('message', function (e) {
    window.__res.parentGot.push(String(e.data));
    window.__res.trusted.push(e.isTrusted === true);
    window.__res.fromChildWindow.push(e.source === document.querySelector('iframe').contentWindow);
  });
  var f = document.createElement('iframe');
  f.src = '/child-messaging.html';
  document.body.appendChild(f);
</script>
</body></html>"#;

const MESSAGING_CHILD_HTML: &str = r#"<!doctype html><html><body>
<script>
  try { parent.postMessage("FROM-CHILD", "*"); }
  catch (e) { document.title = "POST-THREW:" + e.message; }
  window.addEventListener('message', function (e) {
    window.__heard = String(e.data) + ':' + (e.isTrusted === true);
  });
</script>
</body></html>"#;

/// Minimal HTTP/1.1 server serving the parent document at `/` and the child at
/// `/child.html`.
fn spawn_server(parent_html: &'static str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = match incoming {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let mut buf = [0u8; 2048];
            let read = stream.read(&mut buf).unwrap_or(0);
            let body = if buf[..read].starts_with(b"GET /child.html ") {
                CHILD_HTML
            } else if buf[..read].starts_with(b"GET /child-messaging.html ") {
                MESSAGING_CHILD_HTML
            } else {
                parent_html
            };
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    format!("http://{addr}")
}

#[cfg(feature = "render")]
fn spawn_detached_image_frame_server() -> String {
    const PARENT: &[u8] = br#"<!doctype html><html><body>
<iframe src="/image-child.html"></iframe>
</body></html>"#;
    const CHILD: &[u8] = br#"<!doctype html><html><body><script>
  window.__detachedImageState = ["pending", false, 0, 0];
  window.__detachedImage = new Image();
  window.__detachedImage.onload = function () {
    window.__detachedImageState = [
      "load",
      window.__detachedImage.complete,
      window.__detachedImage.naturalWidth,
      window.__detachedImage.naturalHeight
    ];
  };
  window.__detachedImage.onerror = function () {
    window.__detachedImageState = [
      "error",
      window.__detachedImage.complete,
      window.__detachedImage.naturalWidth,
      window.__detachedImage.naturalHeight
    ];
  };
  window.__detachedImage.src = "/pixel.png";
</script></body></html>"#;
    const PIXEL_PNG: &[u8] = &[
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
        0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
        0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78,
        0xda, 0x63, 0xfc, 0xcf, 0xc0, 0x50, 0x0f, 0x00, 0x05, 0x83, 0x02, 0x7f, 0x94, 0xff,
        0x2f, 0x59, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ];

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let mut stream = match incoming {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let mut buf = [0u8; 2048];
            let read = stream.read(&mut buf).unwrap_or(0);
            let (content_type, body): (&str, &[u8]) =
                if buf[..read].starts_with(b"GET /image-child.html ") {
                    ("text/html", CHILD)
                } else if buf[..read].starts_with(b"GET /pixel.png ") {
                    ("image/png", PIXEL_PNG)
                } else {
                    ("text/html", PARENT)
                };
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn a_child_frame_runs_its_own_script() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_server(PARENT_HTML);

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();
    page.settle(2000).await;

    assert_eq!(
        page.frame_urls(),
        vec![format!("{base}/child.html")],
        "the child document never became a frame"
    );
    assert_eq!(
        page.evaluate_in_frame(0, "window.__ran").unwrap(),
        serde_json::json!("YES"),
        "the child frame's script did not run"
    );
    // The child's own script wrote this over the static <title>, so it proves
    // the script ran against the frame's document rather than anywhere else.
    assert_eq!(
        page.evaluate_in_frame(0, "document.title").unwrap(),
        serde_json::json!("RAN-IN-CHILD"),
    );
    // The frame's writes must not reach the parent's document.
    assert_eq!(
        page.evaluate("document.title").as_str().unwrap_or(""),
        "parent",
    );
    assert_eq!(page.evaluate("window.__ran"), serde_json::Value::Null);
}

#[tokio::test]
async fn a_child_frame_set_by_attribute_runs_its_own_script() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_server(ATTRIBUTE_PARENT_HTML);

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();
    page.settle(2000).await;

    assert_eq!(
        page.frame_urls(),
        vec![format!("{base}/child.html")],
        "setAttribute('src') did not start the child document"
    );
    assert_eq!(
        page.evaluate_in_frame(0, "window.__ran").unwrap(),
        serde_json::json!("YES"),
    );
}

#[tokio::test]
async fn a_shadow_dom_child_frame_stays_alive_and_runs_its_script() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_server(SHADOW_PARENT_HTML);

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();
    page.settle(2000).await;

    assert_eq!(
        page.frame_urls(),
        vec![format!("{base}/child.html")],
        "a shadow-root iframe realm was released as detached"
    );
    assert_eq!(
        page.evaluate_in_frame(0, "window.__ran").unwrap(),
        serde_json::json!("YES"),
    );
}

#[tokio::test]
async fn removing_and_reinserting_a_closed_shadow_host_recreates_its_iframe() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_server(CLOSED_SHADOW_REINSERT_PARENT_HTML);

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();
    page.settle(2_000).await;

    let state = page.evaluate("window.__shadowReinsert");
    assert_eq!(state["loads"], 2, "closed-shadow iframe did not reload: {state:#?}");
    assert_eq!(state["childRuns"], serde_json::json!([1, 1]), "replacement child script did not run: {state:#?}");
    assert_eq!(state["resetFrameId"], 0, "removed iframe kept its frame id: {state:#?}");
    assert_ne!(state["firstFrameId"], state["secondFrameId"], "frame id was reused: {state:#?}");
    assert_eq!(state["windowChanged"], true, "contentWindow survived removal: {state:#?}");
    assert_eq!(page.evaluate("window.__closedShadowHost.shadowRoot"), serde_json::Value::Null);
    assert_eq!(page.frame_urls(), vec!["about:srcdoc".to_string()]);
}

/// The whole point of a child frame having a scripting context: it can report
/// its result back out. This is the reporter's `parentGot` assertion.
#[tokio::test]
async fn a_child_frame_reaches_its_parent_with_post_message() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_server(MESSAGING_PARENT_HTML);

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();
    page.settle(2000).await;

    assert_eq!(
        page.evaluate("window.__res.parentGot"),
        serde_json::json!(["FROM-CHILD"]),
        "the child's message never reached the parent"
    );
    // A widget gates on isTrusted and drops anything else without a word.
    assert_eq!(
        page.evaluate("window.__res.trusted"),
        serde_json::json!([true]),
    );
    // And it replies through event.source, so that has to be the frame's window.
    assert_eq!(
        page.evaluate("window.__res.fromChildWindow"),
        serde_json::json!([true]),
    );
}

/// The other direction: a page talking into its frame.
#[tokio::test]
async fn a_parent_reaches_its_child_with_post_message() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_server(MESSAGING_PARENT_HTML);

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();
    page.settle(2000).await;

    page.evaluate("document.querySelector('iframe').contentWindow.postMessage('TO-CHILD', '*')");
    page.settle(1000).await;

    assert_eq!(
        page.evaluate_in_frame(0, "window.__heard").unwrap(),
        serde_json::json!("TO-CHILD:true"),
        "the parent's message never reached the child"
    );
}

/// `window.postMessage(x, '*')` targets the same window, and its listener has
/// to hear it. This was a no-op stub, so a page posting to itself waited
/// forever.
#[tokio::test]
async fn window_post_message_delivers_to_the_same_window() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_server(
        r#"<!doctype html><html><body><script>
  window.__got = [];
  window.addEventListener('message', (e) => window.__got.push([String(e.data), e.isTrusted === true]));
  window.postMessage('SELF', '*');
  window.__syncGot = window.__got.length;
</script></body></html>"#,
    );

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();
    page.settle(1000).await;

    assert_eq!(
        page.evaluate("window.__got"),
        serde_json::json!([["SELF", true]]),
    );
    // postMessage never delivers synchronously.
    assert_eq!(page.evaluate("window.__syncGot").as_f64(), Some(0.0));
}

/// A parser-created `<iframe src>` never goes through the `src` setter, so
/// nothing used to start its load at all.
#[tokio::test]
async fn a_static_child_frame_runs_its_own_script() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_server(STATIC_PARENT_HTML);

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();
    page.settle(2000).await;

    assert_eq!(
        page.frame_urls(),
        vec![format!("{base}/child.html")],
        "a static iframe never started loading"
    );
    assert_eq!(
        page.evaluate_in_frame(0, "window.__ran").unwrap(),
        serde_json::json!("YES"),
    );
}

#[cfg(feature = "render")]
#[tokio::test]
async fn a_detached_new_image_in_a_child_frame_loads_once() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_detached_image_frame_server();

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    let image_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_requests = image_requests.clone();
    page.on_request(std::sync::Arc::new(move |request| {
        if request.url.path() == "/pixel.png" {
            observed_requests
                .lock()
                .unwrap()
                .push(request.resource_type);
        }
    }));

    page.goto(&base).await.unwrap();
    for _ in 0..20 {
        page.settle(250).await;
        if page.frame_urls().len() == 1
            && page
                .evaluate_in_frame(0, "window.__detachedImageState[0] === 'load'")
                .ok()
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
        {
            break;
        }
    }

    assert_eq!(
        page.evaluate_in_frame(0, "window.__detachedImageState")
            .unwrap(),
        serde_json::json!(["load", true, 1, 1]),
        "the child frame's detached Image did not complete with decoded dimensions",
    );
    assert_eq!(
        *image_requests.lock().unwrap(),
        vec![obscura::ResourceType::Image],
        "the child image must issue exactly one observable Image request",
    );
    assert!(
        page.fetched_urls().contains(&format!("{base}/pixel.png")),
        "page assets did not aggregate the child frame's image request",
    );
}

#[tokio::test]
async fn a_rejected_child_frame_does_not_leave_js_references() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    std::env::set_var("OBSCURA_MAX_LIVE_FRAMES", "0");
    let base = spawn_server(STATIC_PARENT_HTML);

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();
    page.settle(2000).await;

    assert!(page.frame_urls().is_empty(), "the frame cap was not applied");
    assert_eq!(
        page.resource_archive_incomplete_reasons(),
        vec!["live frame cap reached (0 realms)".to_string()],
        "refusing the realm must make a final resource archive incomplete",
    );
    for registry in [
        "__obscura_frameObjects",
        "__obscura_frameWindows",
        "__obscura_frameElements",
    ] {
        assert_eq!(
            page.evaluate(&format!("Object.keys(globalThis.{registry}).length"))
                .as_f64(),
            Some(0.0),
            "rejected frame stayed in {registry}",
        );
    }
}

#[tokio::test]
async fn navigating_blank_releases_child_realms() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_server(STATIC_PARENT_HTML);

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();
    page.settle(2000).await;
    assert_eq!(page.frame_urls().len(), 1);

    page.goto("about:blank").await.unwrap();
    assert!(page.frame_urls().is_empty(), "old frame realm survived navigation");
}

#[tokio::test]
async fn changing_iframe_src_releases_the_previous_realm() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let base = spawn_server(RESET_PARENT_HTML);

    let browser = Browser::new().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&base).await.unwrap();
    page.settle(1000).await;

    assert!(page.frame_urls().is_empty(), "old src realm survived replacement");
    for registry in ["__obscura_frameWindows", "__obscura_frameElements"] {
        assert_eq!(
            page.evaluate(&format!("Object.keys(globalThis.{registry}).length"))
                .as_f64(),
            Some(0.0),
            "old iframe stayed in {registry}",
        );
    }
}
