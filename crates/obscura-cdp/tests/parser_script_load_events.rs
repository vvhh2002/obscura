// Parser-discovered scripts are run by obscura-browser's Rust-side HTML
// script runner, not bootstrap's dynamic-script queue. Keep their element
// load/error events covered independently from dynamic script insertion.

use obscura_cdp::dispatch::{dispatch, CdpContext};
use obscura_cdp::types::CdpRequest;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PAGE: &str = r#"<!doctype html>
<html><head>
<script>
globalThis.__parserEvents = [];
globalThis.__recordParserEvent = function(label, owner, event) {
  globalThis.__parserEvents.push({
    label: label,
    kind: 'event',
    type: event.type,
    targetIsOwner: event.target === owner,
    currentTargetIsOwner: event.currentTarget === owner,
    currentTargetIsDocument: event.currentTarget === document,
    bubbles: event.bubbles,
    cancelable: event.cancelable,
    readyState: document.readyState
  });
};
document.addEventListener('DOMContentLoaded', function() {
  globalThis.__parserEvents.push({ label: 'dcl', kind: 'lifecycle' });
});

// A streaming parser must not expose the script elements below before it has
// reached them. Exercise addEventListener through a capturing document
// listener instead; script load/error do not bubble, but they do traverse the
// capture path.
const __parserScriptIds = new Set([
  'classic-ok', 'classic-throws', 'classic-missing',
  'module-ok', 'module-throws', 'module-missing',
  'inline-module-ok', 'inline-module-bad'
]);
function __captureParserScriptCompletion(event) {
  const script = event.target;
  if (script && script.localName === 'script' && __parserScriptIds.has(script.id)) {
    __recordParserEvent(script.id + ':' + event.type + ':listener', script, event);
  }
}
document.addEventListener('load', __captureParserScriptCompletion, true);
document.addEventListener('error', __captureParserScriptCompletion, true);
</script>

<script id="classic-ok" src="/classic-ok.js"
  onload="__recordParserEvent('classic-ok:load:property', this, event)"
  onerror="__recordParserEvent('classic-ok:error:property', this, event)"></script>
<script id="classic-throws" src="/classic-throws.js"
  onload="__recordParserEvent('classic-throws:load:property', this, event)"
  onerror="__recordParserEvent('classic-throws:error:property', this, event)"></script>
<script id="classic-missing" src="/classic-missing.js"
  onload="__recordParserEvent('classic-missing:load:property', this, event)"
  onerror="__recordParserEvent('classic-missing:error:property', this, event)"></script>

<script id="module-ok" type="module" src="/module-ok.js"
  onload="__recordParserEvent('module-ok:load:property', this, event)"
  onerror="__recordParserEvent('module-ok:error:property', this, event)"></script>
<script id="module-throws" type="module" src="/module-throws.js"
  onload="__recordParserEvent('module-throws:load:property', this, event)"
  onerror="__recordParserEvent('module-throws:error:property', this, event)"></script>
<script id="module-missing" type="module" src="/module-missing.js"
  onload="__recordParserEvent('module-missing:load:property', this, event)"
  onerror="__recordParserEvent('module-missing:error:property', this, event)"></script>

<script id="inline-module-ok" type="module"
  onload="__recordParserEvent('inline-module-ok:load:property', this, event)"
  onerror="__recordParserEvent('inline-module-ok:error:property', this, event)">
globalThis.__parserEvents.push({ label: 'inline-module-ok:exec', kind: 'exec' });
</script>
<script id="inline-module-bad" type="module"
  onload="__recordParserEvent('inline-module-bad:load:property', this, event)"
  onerror="__recordParserEvent('inline-module-bad:error:property', this, event)">
export {
</script>
</head><body></body></html>"#;

async fn serve_fixture() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                let count = socket.read(&mut request).await.unwrap_or(0);
                let request_text = String::from_utf8_lossy(&request[..count]);
                let path = request_text
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/");
                let (status, content_type, body) = match path {
                    "/classic-ok.js" => (
                        "200 OK",
                        "application/javascript",
                        "globalThis.__parserEvents.push({label:'classic-ok:exec',kind:'exec'});",
                    ),
                    "/classic-throws.js" => (
                        "200 OK",
                        "application/javascript",
                        "globalThis.__parserEvents.push({label:'classic-throws:exec',kind:'exec'});throw new Error('classic boom');",
                    ),
                    "/module-ok.js" => (
                        "200 OK",
                        "application/javascript",
                        "globalThis.__parserEvents.push({label:'module-ok:exec',kind:'exec'});export const ok=true;",
                    ),
                    "/module-throws.js" => (
                        "200 OK",
                        "application/javascript",
                        "globalThis.__parserEvents.push({label:'module-throws:exec',kind:'exec'});throw new Error('module boom');",
                    ),
                    "/classic-missing.js" | "/module-missing.js" => (
                        "404 Not Found",
                        "application/javascript",
                        "globalThis.__parserEvents.push({label:'missing:must-not-execute',kind:'exec'});",
                    ),
                    _ => ("200 OK", "text/html; charset=utf-8", PAGE),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{address}/")
}

async fn cdp(
    context: &mut CdpContext,
    id: u64,
    method: &str,
    params: Value,
    session_id: &str,
) -> Value {
    let response = dispatch(
        &CdpRequest {
            id,
            method: method.to_string(),
            params,
            session_id: Some(session_id.to_string()),
        },
        context,
    )
    .await;
    assert!(
        response.error.is_none(),
        "CDP {method} failed: {:?}",
        response.error
    );
    response.result.unwrap_or_else(|| json!({}))
}

fn label_index(events: &[Value], label: &str) -> usize {
    events
        .iter()
        .position(|event| event["label"] == label)
        .unwrap_or_else(|| panic!("missing event {label}: {events:#?}"))
}

#[tokio::test(flavor = "current_thread")]
async fn parser_classic_and_module_scripts_dispatch_load_or_error_once() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
    std::env::set_var("no_proxy", "127.0.0.1,localhost");
    let url = serve_fixture().await;
    let mut context = CdpContext::new();
    let page_id = context.create_page();
    let session_id = "parser-script-events";
    context.sessions.insert(session_id.to_string(), page_id);

    cdp(
        &mut context,
        1,
        "Page.navigate",
        json!({"url": url, "waitUntil": "load"}),
        session_id,
    )
    .await;

    let result = cdp(
        &mut context,
        2,
        "Runtime.evaluate",
        json!({
            "expression": "JSON.stringify(globalThis.__parserEvents)",
            "returnByValue": true,
        }),
        session_id,
    )
    .await;
    let events: Vec<Value> = serde_json::from_str(result["result"]["value"].as_str().unwrap())
        .expect("event log must be JSON");

    let expected_pairs = [
        ("classic-ok", "load"),
        ("classic-throws", "load"),
        ("classic-missing", "error"),
        ("module-ok", "load"),
        ("module-throws", "error"),
        ("module-missing", "error"),
        ("inline-module-ok", "load"),
        ("inline-module-bad", "error"),
    ];
    for (id, event_type) in expected_pairs {
        let property = format!("{id}:{event_type}:property");
        let listener = format!("{id}:{event_type}:listener");
        let matching: Vec<_> = events
            .iter()
            .filter(|event| event["label"] == property || event["label"] == listener)
            .collect();
        assert_eq!(
            matching.len(),
            2,
            "{id} must dispatch exactly one {event_type} through both handler paths: {events:#?}"
        );
        assert_eq!(
            matching
                .iter()
                .filter(|event| event["label"] == property)
                .count(),
            1,
            "{id} property handler must run exactly once"
        );
        assert_eq!(
            matching
                .iter()
                .filter(|event| event["label"] == listener)
                .count(),
            1,
            "{id} capture listener must run exactly once"
        );
        for event in matching {
            assert_eq!(event["type"], event_type);
            assert_eq!(event["targetIsOwner"], true);
            if event["label"] == property {
                assert_eq!(event["currentTargetIsOwner"], true);
                assert_eq!(event["currentTargetIsDocument"], false);
            } else {
                assert_eq!(event["currentTargetIsOwner"], false);
                assert_eq!(event["currentTargetIsDocument"], true);
            }
            assert_eq!(event["bubbles"], false);
            assert_eq!(event["cancelable"], false);
        }

        let opposite = if event_type == "load" {
            "error"
        } else {
            "load"
        };
        assert!(
            !events.iter().any(|event| {
                event["label"] == format!("{id}:{opposite}:property")
                    || event["label"] == format!("{id}:{opposite}:listener")
            }),
            "{id} must not also dispatch {opposite}: {events:#?}"
        );
    }

    for id in [
        "classic-ok",
        "classic-throws",
        "module-ok",
        "inline-module-ok",
    ] {
        assert!(
            label_index(&events, &format!("{id}:exec"))
                < label_index(&events, &format!("{id}:load:property")),
            "{id} must execute before load"
        );
    }
    assert!(
        !events
            .iter()
            .any(|event| event["label"] == "missing:must-not-execute"),
        "unsuccessful HTTP responses must not execute as script"
    );

    let dcl = label_index(&events, "dcl");
    assert!(
        events
            .iter()
            .enumerate()
            .filter(|(_, event)| event["kind"] == "event")
            .all(|(index, _)| index < dcl),
        "all parser script completion events must precede DOMContentLoaded: {events:#?}"
    );
}
