//! Browser lifecycle regression coverage.
//!
//! These assertions intentionally observe state from inside the event handlers,
//! rather than only checking the final document. An iframe owner `load` that
//! fires before its child realm exists, or a top-level `load` that fires before
//! its delay set is empty, cannot be repaired retroactively by a later settle.

use obscura_cdp::dispatch::{dispatch, CdpContext};
use obscura_cdp::types::CdpRequest;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TOP_PAGE: &str = r#"<!doctype html>
<html><head><script>
globalThis.__topEvents = [{ label: 'initial', state: document.readyState }];
globalThis.__topPropertyCalls = 0;
globalThis.__topListenerCalls = 0;
globalThis.__directOwnerPropertyCalls = 0;
globalThis.__directOwnerListenerCalls = 0;
globalThis.__dynamicExecuted = false;
globalThis.__dynamicLoadCalls = 0;

function recordTop(label, event) {
  globalThis.__topEvents.push({
    label,
    state: document.readyState,
    type: event.type,
    targetIsDocument: event.target === document,
    currentTargetIsDocument: event.currentTarget === document,
    currentTargetIsWindow: event.currentTarget === window,
    trusted: event.isTrusted,
    bubbles: event.bubbles,
    cancelable: event.cancelable
  });
}

function directSnapshot() {
  const iframe = document.getElementById('direct');
  const child = iframe && iframe.contentWindow;
  const childDocument = iframe && iframe.contentDocument;
  return {
    readyState: childDocument && childDocument.readyState,
    dclCalls: child && child.__childDclCalls,
    dclObserved: child && child.__childDclObserved,
    loadCalls: child && child.__childLoadCalls,
    loadObserved: child && child.__childLoadObserved,
    bodyLoadCalls: child && child.__childBodyLoadCalls,
    headLoadCalls: child && child.__childHeadLoadCalls,
    loadSawNestedComplete: child && child.__childLoadSawNestedComplete,
    nestedOwnerPropertyCalls: child && child.__nestedOwnerPropertyCalls,
    nestedOwnerListenerCalls: child && child.__nestedOwnerListenerCalls,
    nestedOwnerObserved: child && child.__nestedOwnerObserved
  };
}

document.addEventListener('readystatechange', event =>
  recordTop('readystatechange', event));
document.addEventListener('DOMContentLoaded', event =>
  recordTop('document-dcl', event));
window.addEventListener('DOMContentLoaded', event =>
  recordTop('window-dcl', event));

window.onload = function(event) {
  globalThis.__topPropertyCalls++;
  recordTop('window-onload', event);
  globalThis.__topPropertyObserved = {
    dynamicExecuted: globalThis.__dynamicExecuted,
    dynamicLoadCalls: globalThis.__dynamicLoadCalls,
    directOwnerPropertyCalls: globalThis.__directOwnerPropertyCalls,
    directOwnerListenerCalls: globalThis.__directOwnerListenerCalls,
    direct: directSnapshot()
  };
};
window.addEventListener('load', function(event) {
  globalThis.__topListenerCalls++;
  recordTop('window-load-listener', event);
  globalThis.__topListenerObserved = {
    dynamicExecuted: globalThis.__dynamicExecuted,
    dynamicLoadCalls: globalThis.__dynamicLoadCalls,
    directOwnerPropertyCalls: globalThis.__directOwnerPropertyCalls,
    directOwnerListenerCalls: globalThis.__directOwnerListenerCalls,
    direct: directSnapshot()
  };
});
// Browser lifecycle dispatch must use bootstrap-captured primitives. Author
// interposition here happens before interactive/DCL/complete/load.
globalThis.Event = function InterposedEvent() {
  throw new Error('author Event constructor ran');
};
Document.prototype.dispatchEvent = function() {
  throw new Error('author Document.dispatchEvent ran');
};
document.dispatchEvent = Document.prototype.dispatchEvent;
</script></head><body>
<iframe id="direct" src="/child.html"></iframe>
<script>
const direct = document.getElementById('direct');
direct.onload = function(event) {
  globalThis.__directOwnerPropertyCalls++;
  globalThis.__directOwnerPropertyObserved = {
    targetIsOwner: event.target === direct,
    currentTargetIsOwner: event.currentTarget === direct,
    bubbles: event.bubbles,
    cancelable: event.cancelable,
    child: directSnapshot()
  };
};
direct.addEventListener('load', function(event) {
  globalThis.__directOwnerListenerCalls++;
  globalThis.__directOwnerListenerObserved = {
    targetIsOwner: event.target === direct,
    currentTargetIsOwner: event.currentTarget === direct,
    child: directSnapshot()
  };
});

const dynamic = document.createElement('script');
dynamic.src = '/delayed.js';
dynamic.onload = function(event) {
  globalThis.__dynamicLoadCalls++;
  globalThis.__dynamicLoadObserved = {
    targetIsOwner: event.target === dynamic,
    currentTargetIsOwner: event.currentTarget === dynamic,
    executed: globalThis.__dynamicExecuted
  };
};
document.head.appendChild(dynamic);
</script>
</body></html>"#;

const CHILD_PAGE: &str = r#"<!doctype html>
<html><head><script>
globalThis.__childDclCalls = 0;
globalThis.__childLoadCalls = 0;
globalThis.__childBodyLoadCalls = 0;
globalThis.__childHeadLoadCalls = 0;
window.onload = function() { globalThis.__childHeadLoadCalls++; };
globalThis.__nestedOwnerPropertyCalls = 0;
globalThis.__nestedOwnerListenerCalls = 0;

document.addEventListener('DOMContentLoaded', function(event) {
  globalThis.__childDclCalls++;
  globalThis.__childDclObserved = {
    trusted: event.isTrusted,
    targetIsDocument: event.target === document,
    currentTargetIsDocument: event.currentTarget === document,
    readyState: document.readyState
  };
});
window.addEventListener('load', function(event) {
  globalThis.__childLoadCalls++;
  const nested = document.getElementById('nested');
  globalThis.__childLoadSawNestedComplete =
    globalThis.__nestedOwnerPropertyCalls === 1 &&
    globalThis.__nestedOwnerListenerCalls === 1 &&
    !!globalThis.__nestedOwnerObserved &&
    nested.contentDocument.readyState === 'complete';
  globalThis.__childLoadObserved = {
    trusted: event.isTrusted,
    targetIsDocument: event.target === document,
    currentTargetIsWindow: event.currentTarget === window,
    readyState: document.readyState
  };
});
globalThis.Event = function InterposedEvent() {
  throw new Error('child author Event constructor ran');
};
Document.prototype.dispatchEvent = function() {
  throw new Error('child author Document.dispatchEvent ran');
};
document.dispatchEvent = Document.prototype.dispatchEvent;
</script></head><body onload="globalThis.__childBodyLoadCalls++">
<iframe id="nested" src="/nested.html"></iframe>
<script>
const nested = document.getElementById('nested');
function nestedSnapshot() {
  return {
    readyState: nested.contentDocument && nested.contentDocument.readyState,
    dclCalls: nested.contentWindow && nested.contentWindow.__nestedDclCalls,
    loadCalls: nested.contentWindow && nested.contentWindow.__nestedLoadCalls
  };
}
nested.onload = function(event) {
  globalThis.__nestedOwnerPropertyCalls++;
  globalThis.__nestedOwnerObserved = {
    targetIsOwner: event.target === nested,
    currentTargetIsOwner: event.currentTarget === nested,
    child: nestedSnapshot()
  };
};
nested.addEventListener('load', function(event) {
  globalThis.__nestedOwnerListenerCalls++;
  globalThis.__nestedOwnerListenerObserved = {
    targetIsOwner: event.target === nested,
    currentTargetIsOwner: event.currentTarget === nested,
    child: nestedSnapshot()
  };
});
</script>
</body></html>"#;

const NESTED_PAGE: &str = r#"<!doctype html>
<html><head><script>
globalThis.__nestedDclCalls = 0;
globalThis.__nestedLoadCalls = 0;
document.addEventListener('DOMContentLoaded', function(event) {
  globalThis.__nestedDclCalls++;
  globalThis.__nestedDclObserved = {
    targetIsDocument: event.target === document,
    currentTargetIsDocument: event.currentTarget === document,
    readyState: document.readyState
  };
});
window.addEventListener('load', function(event) {
  globalThis.__nestedLoadCalls++;
  globalThis.__nestedLoadObserved = {
    targetIsDocument: event.target === document,
    currentTargetIsWindow: event.currentTarget === window,
    readyState: document.readyState
  };
});
</script></head><body>nested</body></html>"#;

const BODY_ONLOAD_PAGE: &str = r#"<!doctype html>
<html><head><script>
globalThis.__bodyLoadCalls = 0;
globalThis.__bodyListenerCalls = 0;
globalThis.__headWindowLoadCalls = 0;
window.onload = function() { globalThis.__headWindowLoadCalls++; };
window.addEventListener('load', function(event) {
  globalThis.__bodyListenerCalls++;
  globalThis.__bodyListenerObserved = {
    targetIsDocument: event.target === document,
    currentTargetIsWindow: event.currentTarget === window,
    thisIsWindow: this === window
  };
});
</script></head>
<body onload="globalThis.__bodyLoadCalls++; globalThis.__bodyLoadObserved = { targetIsDocument: event.target === document, currentTargetIsWindow: event.currentTarget === window, thisIsWindow: this === window }">
body load
</body></html>"#;

const LOAD_DELAYING_RESOURCES_PAGE: &str = r#"<!doctype html>
<html><head><script>
globalThis.__stylesheetLoadCalls = 0;
globalThis.__imageLoadCalls = 0;
globalThis.__resourceWindowLoadCalls = 0;

window.addEventListener('load', function(event) {
  globalThis.__resourceWindowLoadCalls++;
  globalThis.__resourceWindowObserved = {
    stylesheetLoadCalls: globalThis.__stylesheetLoadCalls,
    imageLoadCalls: globalThis.__imageLoadCalls,
    imageComplete: document.getElementById('pixel').complete,
    imageNaturalWidth: document.getElementById('pixel').naturalWidth,
    subtreeImageComplete: document.getElementById('subtree-pixel').complete,
    subtreeImageNaturalWidth: document.getElementById('subtree-pixel').naturalWidth,
    targetIsDocument: event.target === document,
    currentTargetIsWindow: event.currentTarget === window
  };
});
</script></head><body><script>
const stylesheet = document.createElement('link');
stylesheet.setAttribute('rel', 'stylesheet');
stylesheet.setAttribute('href', '/delayed.css');
stylesheet.addEventListener('load', function(event) {
  globalThis.__stylesheetLoadCalls++;
  globalThis.__stylesheetObserved = {
    targetIsOwner: event.target === stylesheet,
    currentTargetIsOwner: event.currentTarget === stylesheet,
    bubbles: event.bubbles,
    cancelable: event.cancelable
  };
});
document.head.appendChild(stylesheet);

const image = document.createElement('img');
image.id = 'pixel';
image.addEventListener('load', function(event) {
  globalThis.__imageLoadCalls++;
  globalThis.__imageObserved = {
    targetIsOwner: event.target === image,
    currentTargetIsOwner: event.currentTarget === image,
    bubbles: event.bubbles,
    cancelable: event.cancelable
  };
});
image.src = '/pixel.png';
document.body.appendChild(image);

const imageSubtree = document.createElement('div');
imageSubtree.innerHTML = '<img id="subtree-pixel" src="/subtree-pixel.png">';
document.body.appendChild(imageSubtree);
</script></body></html>"#;

const EVENT_TARGET_PAGE: &str = r#"<!doctype html>
<html><head><script>
globalThis.__eventTargetLog = [];

function record(label, event) {
  __eventTargetLog.push({
    label,
    state: document.readyState,
    phase: event.eventPhase,
    targetIsDocument: event.target === document,
    currentIsDocument: event.currentTarget === document,
    currentIsWindow: event.currentTarget === window
  });
}

window.addEventListener('readystatechange', event => record('window-capture', event), true);
document.addEventListener('readystatechange', event => record('document-target', event));

const stopped = [];
function stoppedFirst(event) { stopped.push('first'); }
function stoppedLast(event) { stopped.push('last'); }
window.addEventListener('load', stoppedFirst);
window.onload = function(event) { stopped.push('handler'); event.stopImmediatePropagation(); };
window.addEventListener('load', stoppedLast);
window.dispatchEvent(new Event('load'));
window.removeEventListener('load', stoppedFirst);
window.removeEventListener('load', stoppedLast);
window.onload = null;
globalThis.__stoppedLog = stopped;

window.addEventListener('load', function first(event) {
  __eventTargetLog.push({ label: 'load-first' });
});
window.onload = function handler(event) {
  __eventTargetLog.push({ label: 'load-handler' });
  window.addEventListener('load', function addedDuringDispatch() {
    __eventTargetLog.push({ label: 'load-added-during-dispatch' });
  });
};
window.addEventListener('load', function last(event) {
  __eventTargetLog.push({ label: 'load-last' });
});
</script></head><body><script>
document.body.dispatchEvent(new Event('load'));
globalThis.__windowCallsAfterBodyLoad = __eventTargetLog.filter(
  entry => String(entry.label).startsWith('load-')
).length;
</script></body></html>"#;

const ELEMENT_EVENT_TARGET_PAGE: &str = r#"<!doctype html>
<html><head><script>
globalThis.__elementEventTarget = { log: [] };
const state = globalThis.__elementEventTarget;
const seenEvents = [];
const owner = document.createElement('script');
owner.src = '/delayed.js';

function record(name, event, thisOk) {
  let round = seenEvents.indexOf(event);
  if (round < 0) {
    seenEvents.push(event);
    round = seenEvents.length - 1;
  }
  state.log.push({
    round: round + 1,
    name,
    thisOk,
    phase: event.eventPhase,
    targetIsOwner: event.target === owner,
    currentIsOwner: event.currentTarget === owner,
    currentIsDocument: event.currentTarget === document
  });
}

function documentCapture(event) {
  if (event.target === owner) record('document-capture', event, this === document);
}
document.addEventListener('load', documentCapture, true);
owner.addEventListener('load', function before(event) { record('before', event, this === owner); });
owner.onload = function oldHandler(event) { record('handler-old', event, this === owner); };
owner.addEventListener('load', function after(event) { record('after', event, this === owner); });
owner.onload = function handler(event) { record('handler', event, this === owner); };

function duplicate(event) { record('duplicate', event, this === owner); }
owner.addEventListener('load', duplicate);
owner.addEventListener('load', duplicate);
owner.addEventListener('load', function once(event) { record('once', event, this === owner); }, { once: true });
const controller = new AbortController();
owner.addEventListener('load', function aborted(event) { record('aborted', event, this === owner); }, { signal: controller.signal });
controller.abort();
const objectListener = {
  handleEvent(event) { record('handleEvent', event, this === objectListener); }
};
owner.addEventListener('load', objectListener);
owner.addEventListener('load', function capture(event) { record('capture', event, this === owner); }, true);

window.addEventListener('load', function finishProbe() {
  state.finishEntered = true;
  try {
    const first = seenEvents[0];
    state.afterFirst = {
      currentTargetIsNull: first.currentTarget === null,
      phase: first.eventPhase,
      targetIsOwner: first.target === owner
    };
    const second = new Event('load', { bubbles: false, cancelable: false });
    owner.dispatchEvent(second);
    state.afterSecond = {
      currentTargetIsNull: second.currentTarget === null,
      phase: second.eventPhase,
      targetIsOwner: second.target === owner
    };
    state.eventCount = seenEvents.length;
    document.removeEventListener('load', documentCapture, true);
  } catch (error) {
    state.finishError = String(error && error.stack || error);
  }
});
document.head.appendChild(owner);
</script></head><body></body></html>"#;

const CONNECTED_INNER_HTML_PAGE: &str = r#"<!doctype html><html><body><script>
globalThis.__innerHtmlImageLoads = 0;
globalThis.__innerHtmlSheetLoads = 0;
globalThis.__innerHtmlFrameLoads = 0;

const light = document.createElement('div');
document.body.appendChild(light);
light.innerHTML = '<img src="/pixel.png" onload="globalThis.__innerHtmlImageLoads++">' +
  '<link rel="stylesheet" href="/delayed.css" onload="globalThis.__innerHtmlSheetLoads++">' +
  '<iframe onload="globalThis.__innerHtmlFrameLoads++"></iframe>';

const host = document.createElement('div');
document.body.appendChild(host);
const closed = host.attachShadow({mode: 'closed'});
closed.innerHTML = '<img src="/subtree-pixel.png" onload="globalThis.__innerHtmlImageLoads++">' +
  '<link rel="stylesheet" href="/delayed.css?shadow" onload="globalThis.__innerHtmlSheetLoads++">' +
  '<iframe onload="globalThis.__innerHtmlFrameLoads++"></iframe>';

window.addEventListener('load', function () {
  globalThis.__innerHtmlWindowObserved = {
    images: __innerHtmlImageLoads,
    sheets: __innerHtmlSheetLoads,
    frames: __innerHtmlFrameLoads,
    readyState: document.readyState,
    closedRootHidden: host.shadowRoot === null
  };
});
</script></body></html>"#;

const BLANK_IFRAME_PAGE: &str = r#"<!doctype html>
<html><head><script>
globalThis.__blankOwnerCalls = 0;
globalThis.__replacementOwnerCalls = 0;
globalThis.__subtreeOwnerCalls = 0;
globalThis.__detachedFrameExecuted = 0;
</script></head><body>
<iframe id="parser-blank"></iframe>
<script>
const parserBlank = document.getElementById('parser-blank');
parserBlank.addEventListener('load', () => { __blankOwnerCalls++; });

const replacement = document.createElement('iframe');
replacement.addEventListener('load', () => { __replacementOwnerCalls++; });
document.body.appendChild(replacement);
replacement.srcdoc = '<!doctype html><script>parent.__replacementExecuted = (parent.__replacementExecuted || 0) + 1;<\/script>';

const detached = document.createElement('iframe');
detached.srcdoc = '<!doctype html><script>parent.__detachedFrameExecuted++;<\/script>';
globalThis.__detachedFrameId = detached._frameId || 0;

const subtree = document.createElement('div');
subtree.innerHTML = '<iframe id="subtree-frame" srcdoc="<!doctype html><p>connected</p>"></iframe>';
subtree.querySelector('iframe').addEventListener('load', () => { __subtreeOwnerCalls++; });
document.body.appendChild(subtree);

window.addEventListener('load', () => {
  globalThis.__blankWindowObserved = {
    blankOwnerCalls: __blankOwnerCalls,
    replacementOwnerCalls: __replacementOwnerCalls,
    replacementUrl: replacement.contentDocument && replacement.contentDocument.URL,
    replacementFrameId: replacement._frameId || 0,
    subtreeOwnerCalls: __subtreeOwnerCalls,
    detachedFrameExecuted: __detachedFrameExecuted,
    detachedFrameId: __detachedFrameId
  };
});
</script></body></html>"#;

const PARSER_IMAGE_PAGE: &str = r#"<!doctype html>
<html><head><script>
globalThis.__parserImageStarted = Date.now();
window.addEventListener('load', () => {
  const eager = document.getElementById('parser-eager');
  const lazy = document.getElementById('parser-lazy');
  globalThis.__parserImageObserved = {
    elapsed: Date.now() - __parserImageStarted,
    eagerComplete: eager.complete,
    eagerWidth: eager.naturalWidth,
    lazyComplete: lazy.complete,
    lazyWidth: lazy.naturalWidth
  };
});
</script></head><body>
<img id="parser-eager" src="/parser-eager.png">
<img id="parser-lazy" loading="LAZY" src="/parser-lazy.png">
</body></html>"#;

const STYLESHEET_ERROR_PAGE: &str = r#"<!doctype html>
<html><head>
<link id="blocked-sheet" rel="stylesheet" href="file:///obscura-blocked.css"
  onerror="globalThis.__stylesheetErrorCalls = (globalThis.__stylesheetErrorCalls || 0) + 1; globalThis.__stylesheetErrorObserved = { targetIsOwner: event.target === this, currentTargetIsOwner: event.currentTarget === this, bubbles: event.bubbles, cancelable: event.cancelable, readyState: document.readyState }">
<script>
window.addEventListener('load', () => {
  globalThis.__stylesheetErrorWindowObserved = {
    errorCalls: globalThis.__stylesheetErrorCalls || 0,
    readyState: document.readyState
  };
});
</script></head><body></body></html>"#;

const PARSER_STYLESHEET_ORDER_PAGE: &str = r#"<!doctype html><html><head>
<script>globalThis.__parserStyleLog = ['start'];</script>
<link id="first-sheet" rel="stylesheet" href="file:///first-blocked.css"
  onerror="globalThis.__parserStyleLog.push('first-error')">
<script>
document.getElementById('first-sheet').remove();
globalThis._wrap = () => null;
globalThis.__obscura_completeLinkedStylesheet = () => false;
globalThis.__obscura_registerLinkedStylesheet = () => null;
globalThis.__parserStyleLog.push('between');
</script>
<link id="second-sheet" rel="stylesheet" href="file:///second-blocked.css"
  onerror="globalThis.__parserStyleLog.push('second-error')">
<script>globalThis.__parserStyleLog.push('after');</script>
</head><body></body></html>"#;

const FRAME_PARSER_STYLESHEET_ORDER_PAGE: &str = r#"<!doctype html><html><body><script>
globalThis.__frameParserStyleLog = null;
const frame = document.createElement('iframe');
frame.onload = function () {
  globalThis.__frameParserStyleLog = frame.contentWindow.__parserStyleLog;
};
frame.srcdoc = `<!doctype html><html><head>
<script>globalThis.__parserStyleLog = ['start'];<\/script>
<link id="first-sheet" rel="stylesheet" href="file:///frame-first-blocked.css"
  onerror="globalThis.__parserStyleLog.push('first-error')">
<script>
document.getElementById('first-sheet').remove();
globalThis._wrap = () => null;
globalThis.__obscura_completeLinkedStylesheet = () => false;
globalThis.__obscura_registerLinkedStylesheet = () => null;
globalThis.__parserStyleLog.push('between');
<\/script>
<link id="second-sheet" rel="stylesheet" href="file:///frame-second-blocked.css"
  onerror="globalThis.__parserStyleLog.push('second-error')">
<script>globalThis.__parserStyleLog.push('after');<\/script>
</head><body></body></html>`;
document.body.appendChild(frame);
</script></body></html>"#;

const FRAME_PARSER_STYLESHEET_IMPORT_PAGE: &str = r#"<!doctype html><html><body><script>
globalThis.__frameImportEvents = [];
const frame = document.createElement('iframe');
frame.addEventListener('load', function () {
  const childEvents = frame.contentWindow.__frameImportEvents || [];
  globalThis.__frameImportEvents.push(...childEvents);
  globalThis.__frameImportEvents.push({
    label: 'frame-owner-load',
    childState: frame.contentDocument && frame.contentDocument.readyState
  });
});
window.addEventListener('load', function () {
  globalThis.__frameImportEvents.push({ label: 'top-window-load', state: document.readyState });
});
frame.src = '/frame-parser-stylesheet-import-child.html';
document.body.appendChild(frame);
</script></body></html>"#;

const FRAME_PARSER_STYLESHEET_IMPORT_CHILD: &str = r#"<!doctype html><html><head>
<script>
globalThis.__frameImportEvents = [];
globalThis.__frameImportServerStarted = __SERVER_STARTED_MS__;
function recordRootSheetLoad(owner) {
  let sheetText = '';
  let sheetError = null;
  try {
    sheetText = Array.from(owner.sheet.cssRules, rule => rule.cssText || '').join('\n');
  } catch (error) {
    sheetError = String(error && error.stack || error);
  }
  globalThis.__frameImportEvents.push({
    label: 'root-link-load',
    elapsed: Date.now() - globalThis.__frameImportServerStarted,
    state: document.readyState,
    sheetText,
    sheetError
  });
}
</script>
<link id="root-sheet" rel="stylesheet" href="/frame-parser-root.css"
  onload="recordRootSheetLoad(this)">
<script>
window.addEventListener('load', function () {
  globalThis.__frameImportEvents.push({ label: 'child-window-load', state: document.readyState });
});
</script>
</head><body class="frame-import-target">child</body></html>"#;

const SIBLING_FRAME_REMOVAL_PAGE: &str = r#"<!doctype html><html><body><script>
globalThis.__removedSiblingWindowLoads = 0;
const first = document.createElement('iframe');
const second = document.createElement('iframe');
globalThis.__secondFrame = second;
first.onload = () => second.remove();
first.srcdoc = '<!doctype html><p>first</p>';
second.srcdoc = `<!doctype html><script>
window.addEventListener('load', () => parent.__removedSiblingWindowLoads++);
<\/script>`;
document.body.append(first, second);
window.addEventListener('load', () => {
  globalThis.__siblingRemovalObserved = {
    removedSiblingWindowLoads: __removedSiblingWindowLoads,
    secondConnected: second.isConnected,
    secondFrameId: second._frameId || 0
  };
});
</script></body></html>"#;

const DETACHED_PARENT_PENDING_DESCENDANT_PAGE: &str = r#"<!doctype html><html><body><script>
globalThis.__detachedDescendantRuns = 0;
const parentFrame = document.createElement('iframe');
globalThis.__detachedParentFrame = parentFrame;
window.addEventListener('message', event => {
  if (event.data === 'remove-parent') parentFrame.remove();
});
parentFrame.srcdoc = `<!doctype html><script>
const nested = document.createElement('iframe');
nested.srcdoc = '<!doctype html><script>parent.parent.__detachedDescendantRuns++;<\\/script>';
document.body.appendChild(nested);
parent.postMessage('remove-parent', '*');
<\/script>`;
document.body.appendChild(parentFrame);
window.addEventListener('load', () => {
  globalThis.__detachedParentObserved = {
    descendantRuns: __detachedDescendantRuns,
    parentConnected: parentFrame.isConnected,
    parentFrameId: parentFrame._frameId || 0
  };
});
</script></body></html>"#;

const IFRAME_FALLBACK_INNER_HTML_PAGE: &str = r#"<!doctype html><html><body><script>
globalThis.__fallbackOwnerLoads = 0;
const frame = document.createElement('iframe');
frame.onload = () => {
  globalThis.__fallbackOwnerLoads++;
  if (globalThis.__fallbackOwnerLoads === 1) {
    frame.innerHTML = '<p>new fallback content</p>';
  }
};
frame.srcdoc = '<!doctype html><script>globalThis.__fallbackChildExecutions = (globalThis.__fallbackChildExecutions || 0) + 1;<\/script>';
document.body.appendChild(frame);
window.addEventListener('load', () => {
  globalThis.__fallbackInnerHtmlObserved = {
    childExecutions: frame.contentWindow.__fallbackChildExecutions,
    ownerLoads: globalThis.__fallbackOwnerLoads,
    frameId: frame._frameId || 0,
    fallbackText: frame.textContent.trim()
  };
});
</script></body></html>"#;

const PIXEL_PNG: &[u8] = &[
    137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0,
    0, 1, 8, 4, 0, 0, 0, 181, 28, 12, 2, 0, 0, 0, 11, 73, 68, 65, 84, 120, 218, 99,
    100, 248, 15, 0, 1, 5, 1, 1, 39, 24, 227, 102, 0, 0, 0, 0, 73, 69, 78, 68, 174,
    66, 96, 130,
];

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
                    .and_then(|target| target.split('?').next())
                    .unwrap_or("/");

                let (content_type, body, delay_ms) = match path {
                    "/child.html" => (
                        "text/html; charset=utf-8",
                        CHILD_PAGE.as_bytes().to_vec(),
                        40,
                    ),
                    "/nested.html" => (
                        "text/html; charset=utf-8",
                        NESTED_PAGE.as_bytes().to_vec(),
                        80,
                    ),
                    "/body-onload.html" => (
                        "text/html; charset=utf-8",
                        BODY_ONLOAD_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/load-delaying-resources.html" => (
                        "text/html; charset=utf-8",
                        LOAD_DELAYING_RESOURCES_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/event-target.html" => (
                        "text/html; charset=utf-8",
                        EVENT_TARGET_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/element-event-target.html" => (
                        "text/html; charset=utf-8",
                        ELEMENT_EVENT_TARGET_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/connected-inner-html.html" => (
                        "text/html; charset=utf-8",
                        CONNECTED_INNER_HTML_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/blank-iframes.html" => (
                        "text/html; charset=utf-8",
                        BLANK_IFRAME_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/parser-images.html" => (
                        "text/html; charset=utf-8",
                        PARSER_IMAGE_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/stylesheet-error.html" => (
                        "text/html; charset=utf-8",
                        STYLESHEET_ERROR_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/parser-stylesheet-order.html" => (
                        "text/html; charset=utf-8",
                        PARSER_STYLESHEET_ORDER_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/frame-parser-stylesheet-order.html" => (
                        "text/html; charset=utf-8",
                        FRAME_PARSER_STYLESHEET_ORDER_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/frame-parser-stylesheet-import.html" => (
                        "text/html; charset=utf-8",
                        FRAME_PARSER_STYLESHEET_IMPORT_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/frame-parser-stylesheet-import-child.html" => (
                        "text/html; charset=utf-8",
                        FRAME_PARSER_STYLESHEET_IMPORT_CHILD
                            .replace(
                                "__SERVER_STARTED_MS__",
                                &std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .expect("fixture clock before Unix epoch")
                                    .as_millis()
                                    .to_string(),
                            )
                            .into_bytes(),
                        0,
                    ),
                    "/frame-parser-root.css" => (
                        "text/css; charset=utf-8",
                        b"@import url('/frame-parser-delayed-import.css'); body { --frame-root-ready: yes; }".to_vec(),
                        0,
                    ),
                    "/frame-parser-delayed-import.css" => (
                        "text/css; charset=utf-8",
                        b".frame-import-target { --frame-import-ready: yes; }".to_vec(),
                        220,
                    ),
                    "/sibling-frame-removal.html" => (
                        "text/html; charset=utf-8",
                        SIBLING_FRAME_REMOVAL_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/detached-parent-pending-descendant.html" => (
                        "text/html; charset=utf-8",
                        DETACHED_PARENT_PENDING_DESCENDANT_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/iframe-fallback-inner-html.html" => (
                        "text/html; charset=utf-8",
                        IFRAME_FALLBACK_INNER_HTML_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                    "/delayed.js" => (
                        "application/javascript",
                        b"globalThis.__dynamicExecuted = true;".to_vec(),
                        125,
                    ),
                    "/delayed.css" => (
                        "text/css; charset=utf-8",
                        b"body { color: rgb(1, 2, 3); }".to_vec(),
                        90,
                    ),
                    "/pixel.png" => ("image/png", PIXEL_PNG.to_vec(), 125),
                    "/subtree-pixel.png" => ("image/png", PIXEL_PNG.to_vec(), 140),
                    "/parser-eager.png" | "/parser-lazy.png" => {
                        ("image/png", PIXEL_PNG.to_vec(), 180)
                    }
                    _ => (
                        "text/html; charset=utf-8",
                        TOP_PAGE.as_bytes().to_vec(),
                        0,
                    ),
                };
                if delay_ms != 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            });
        }
    });
    format!("http://{address}")
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

async fn navigate_and_evaluate(url: String, expression: &str) -> Value {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
    std::env::set_var("no_proxy", "127.0.0.1,localhost");

    let mut context = CdpContext::new();
    let page_id = context.create_page();
    let session_id = "load-lifecycle-session";
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
            "expression": format!(
                "Promise.resolve(\n{expression}\n).then(value => JSON.stringify(value))"
            ),
            "returnByValue": true,
            "awaitPromise": true,
        }),
        session_id,
    )
    .await;
    serde_json::from_str(
        result["result"]["value"]
            .as_str()
            .expect("evaluation must return JSON text"),
    )
    .expect("evaluation result must be valid JSON")
}

fn only_event<'a>(events: &'a [Value], label: &str) -> &'a Value {
    let matching = events
        .iter()
        .filter(|event| event["label"] == label)
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "{label} must be dispatched exactly once: {events:#?}"
    );
    matching[0]
}

fn event_index(events: &[Value], label: &str) -> usize {
    events
        .iter()
        .position(|event| event["label"] == label)
        .unwrap_or_else(|| panic!("missing event {label}: {events:#?}"))
}

#[tokio::test(flavor = "current_thread")]
async fn top_document_dispatches_browser_shaped_lifecycle_events_once() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/top.html"),
        "({ events: globalThis.__topEvents, propertyCalls: globalThis.__topPropertyCalls, listenerCalls: globalThis.__topListenerCalls })",
    )
    .await;
    let events = value["events"].as_array().expect("top event log");

    assert_eq!(events[0]["label"], "initial");
    assert_eq!(events[0]["state"], "loading");

    let ready = events
        .iter()
        .filter(|event| event["label"] == "readystatechange")
        .collect::<Vec<_>>();
    assert_eq!(
        ready.len(),
        2,
        "loading -> interactive -> complete has two readystatechange events: {events:#?}"
    );
    assert_eq!(ready[0]["state"], "interactive");
    assert_eq!(ready[1]["state"], "complete");
    for event in ready {
        assert_eq!(event["type"], "readystatechange");
        assert_eq!(event["targetIsDocument"], true);
        assert_eq!(event["currentTargetIsDocument"], true);
        assert_eq!(event["trusted"], true);
        assert_eq!(event["bubbles"], false);
        assert_eq!(event["cancelable"], false);
    }

    let document_dcl = only_event(events, "document-dcl");
    assert_eq!(document_dcl["state"], "interactive");
    assert_eq!(document_dcl["targetIsDocument"], true);
    assert_eq!(document_dcl["currentTargetIsDocument"], true);
    assert_eq!(document_dcl["trusted"], true);
    assert_eq!(document_dcl["bubbles"], true);
    assert_eq!(document_dcl["cancelable"], false);

    let window_dcl = only_event(events, "window-dcl");
    assert_eq!(window_dcl["state"], "interactive");
    assert_eq!(window_dcl["targetIsDocument"], true);
    assert_eq!(window_dcl["currentTargetIsWindow"], true);
    assert_eq!(window_dcl["trusted"], true);
    assert_eq!(window_dcl["bubbles"], true);
    assert_eq!(window_dcl["cancelable"], false);

    let onload = only_event(events, "window-onload");
    let load_listener = only_event(events, "window-load-listener");
    for event in [onload, load_listener] {
        assert_eq!(event["state"], "complete");
        assert_eq!(event["type"], "load");
        assert_eq!(event["targetIsDocument"], true);
        assert_eq!(event["currentTargetIsWindow"], true);
        assert_eq!(event["trusted"], true);
        assert_eq!(event["bubbles"], false);
        assert_eq!(event["cancelable"], false);
    }
    assert_eq!(value["propertyCalls"], 1);
    assert_eq!(value["listenerCalls"], 1);

    assert!(event_index(events, "readystatechange") < event_index(events, "document-dcl"));
    assert!(event_index(events, "document-dcl") < event_index(events, "window-dcl"));
    let complete_index = events
        .iter()
        .rposition(|event| event["label"] == "readystatechange")
        .unwrap();
    assert!(event_index(events, "window-dcl") < complete_index);
    assert!(complete_index < event_index(events, "window-onload"));
    assert!(complete_index < event_index(events, "window-load-listener"));
}

#[tokio::test(flavor = "current_thread")]
async fn body_onload_aliases_window_and_uses_the_single_window_load_dispatch() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/body-onload.html"),
        "({ bodyCalls: globalThis.__bodyLoadCalls, headCalls: globalThis.__headWindowLoadCalls, listenerCalls: globalThis.__bodyListenerCalls, body: globalThis.__bodyLoadObserved, listener: globalThis.__bodyListenerObserved, aliasesWindow: document.body.onload === window.onload })",
    )
    .await;

    assert_eq!(value["bodyCalls"], 1, "body onload must run exactly once");
    assert_eq!(
        value["headCalls"], 0,
        "the later parser body attribute must replace an earlier head assignment"
    );
    assert_eq!(
        value["listenerCalls"], 1,
        "the same load dispatch must also reach Window listeners exactly once"
    );
    assert_eq!(value["aliasesWindow"], true);
    for path in ["body", "listener"] {
        assert_eq!(value[path]["targetIsDocument"], true);
        assert_eq!(value[path]["currentTargetIsWindow"], true);
        assert_eq!(value[path]["thisIsWindow"], true);
    }
}

fn assert_loaded_child(snapshot: &Value, context: &str) {
    assert_eq!(
        snapshot["readyState"], "complete",
        "{context}: {snapshot:#?}"
    );
    assert_eq!(snapshot["dclCalls"], 1, "{context}: {snapshot:#?}");
    assert_eq!(snapshot["loadCalls"], 1, "{context}: {snapshot:#?}");
    for event in ["dclObserved", "loadObserved"] {
        if !snapshot[event].is_object() {
            continue;
        }
        assert_eq!(
            snapshot[event]["trusted"], true,
            "{context} {event}: {snapshot:#?}"
        );
        assert_eq!(
            snapshot[event]["targetIsDocument"], true,
            "{context} {event}: {snapshot:#?}"
        );
    }
}

fn assert_top_load_waited(observed: &Value, context: &str) {
    assert_eq!(
        observed["dynamicExecuted"], true,
        "{context}: {observed:#?}"
    );
    assert_eq!(observed["dynamicLoadCalls"], 1, "{context}: {observed:#?}");
    assert_eq!(
        observed["directOwnerPropertyCalls"], 1,
        "{context}: {observed:#?}"
    );
    assert_eq!(
        observed["directOwnerListenerCalls"], 1,
        "{context}: {observed:#?}"
    );
    let child = &observed["direct"];
    assert_loaded_child(child, context);
    assert_eq!(child["bodyLoadCalls"], 1, "{context}: {child:#?}");
    assert_eq!(child["headLoadCalls"], 0, "{context}: {child:#?}");
    assert_eq!(
        child["loadSawNestedComplete"], true,
        "{context}: direct child load ran before its nested frame completed: {child:#?}"
    );
    assert_eq!(
        child["nestedOwnerPropertyCalls"], 1,
        "{context}: {child:#?}"
    );
    assert_eq!(
        child["nestedOwnerListenerCalls"], 1,
        "{context}: {child:#?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn iframe_and_dynamic_script_delay_their_owner_window_load_events() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/top.html"),
        "({ topPropertyCalls: globalThis.__topPropertyCalls, topListenerCalls: globalThis.__topListenerCalls, topProperty: globalThis.__topPropertyObserved, topListener: globalThis.__topListenerObserved, directPropertyCalls: globalThis.__directOwnerPropertyCalls, directListenerCalls: globalThis.__directOwnerListenerCalls, directProperty: globalThis.__directOwnerPropertyObserved, directListener: globalThis.__directOwnerListenerObserved, dynamicLoadCalls: globalThis.__dynamicLoadCalls, dynamic: globalThis.__dynamicLoadObserved })",
    )
    .await;

    assert_eq!(value["dynamicLoadCalls"], 1);
    assert_eq!(value["dynamic"]["executed"], true);
    assert_eq!(value["dynamic"]["targetIsOwner"], true);
    assert_eq!(value["dynamic"]["currentTargetIsOwner"], true);

    assert_eq!(value["directPropertyCalls"], 1);
    assert_eq!(value["directListenerCalls"], 1);
    for path in ["directProperty", "directListener"] {
        assert_eq!(value[path]["targetIsOwner"], true);
        assert_eq!(value[path]["currentTargetIsOwner"], true);
        assert_loaded_child(&value[path]["child"], path);
        assert_eq!(
            value[path]["child"]["loadSawNestedComplete"], true,
            "direct iframe owner load ran before the nested iframe completed: {value:#?}"
        );
    }

    let nested = &value["directProperty"]["child"]["nestedOwnerObserved"];
    assert_eq!(nested["targetIsOwner"], true);
    assert_eq!(nested["currentTargetIsOwner"], true);
    assert_loaded_child(&nested["child"], "nested iframe owner load");

    assert_eq!(value["topPropertyCalls"], 1);
    assert_eq!(value["topListenerCalls"], 1);
    assert_top_load_waited(&value["topProperty"], "window.onload");
    assert_top_load_waited(&value["topListener"], "Window load listener");
}

#[tokio::test(flavor = "current_thread")]
async fn image_and_dynamic_stylesheet_delay_window_load_until_their_owner_events() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/load-delaying-resources.html"),
        "({ windowCalls: globalThis.__resourceWindowLoadCalls, window: globalThis.__resourceWindowObserved, stylesheetCalls: globalThis.__stylesheetLoadCalls, stylesheet: globalThis.__stylesheetObserved, imageCalls: globalThis.__imageLoadCalls, image: globalThis.__imageObserved })",
    )
    .await;

    assert_eq!(value["stylesheetCalls"], 1);
    assert_eq!(value["imageCalls"], 1);
    assert_eq!(value["windowCalls"], 1);
    for path in ["stylesheet", "image"] {
        assert_eq!(value[path]["targetIsOwner"], true, "{path}: {value:#?}");
        assert_eq!(
            value[path]["currentTargetIsOwner"], true,
            "{path}: {value:#?}"
        );
        assert_eq!(value[path]["bubbles"], false, "{path}: {value:#?}");
        assert_eq!(value[path]["cancelable"], false, "{path}: {value:#?}");
    }
    assert_eq!(value["window"]["stylesheetLoadCalls"], 1);
    assert_eq!(value["window"]["imageLoadCalls"], 1);
    assert_eq!(value["window"]["imageComplete"], true);
    #[cfg(feature = "render")]
    assert_eq!(value["window"]["imageNaturalWidth"], 1);
    assert_eq!(value["window"]["subtreeImageComplete"], true);
    #[cfg(feature = "render")]
    assert_eq!(value["window"]["subtreeImageNaturalWidth"], 1);
    assert_eq!(value["window"]["targetIsDocument"], true);
    assert_eq!(value["window"]["currentTargetIsWindow"], true);
}

#[tokio::test(flavor = "current_thread")]
async fn event_target_preserves_order_snapshot_phases_and_body_load_aliasing() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/event-target.html"),
        "({ log: globalThis.__eventTargetLog, stopped: globalThis.__stoppedLog, afterBody: globalThis.__windowCallsAfterBodyLoad })",
    )
    .await;

    assert_eq!(value["stopped"], json!(["first", "handler"]));
    assert_eq!(value["afterBody"], 0, "body load must not invoke Window handlers");
    let log = value["log"].as_array().expect("event target log");
    let load_labels = log
        .iter()
        .filter_map(|entry| entry["label"].as_str())
        .filter(|label| label.starts_with("load-"))
        .collect::<Vec<_>>();
    assert_eq!(load_labels, vec!["load-first", "load-handler", "load-last"]);

    let lifecycle = log
        .iter()
        .filter(|entry| {
            matches!(
                entry["label"].as_str(),
                Some("window-capture" | "document-target")
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(lifecycle.len(), 4, "two readyState transitions: {log:#?}");
    for pair in lifecycle.chunks_exact(2) {
        assert_eq!(pair[0]["label"], "window-capture");
        assert_eq!(pair[0]["phase"], 1);
        assert_eq!(pair[0]["targetIsDocument"], true);
        assert_eq!(pair[0]["currentIsWindow"], true);
        assert_eq!(pair[1]["label"], "document-target");
        assert_eq!(pair[1]["phase"], 2);
        assert_eq!(pair[1]["targetIsDocument"], true);
        assert_eq!(pair[1]["currentIsDocument"], true);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn element_owner_events_use_the_shared_event_target_algorithm() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/element-event-target.html"),
        "Object.assign({}, globalThis.__elementEventTarget, { readyState: document.readyState, runtimeErrors: globalThis.__obscura_errors })",
    )
    .await;

    assert_eq!(value["eventCount"], 2, "real plus synthetic dispatch: {value:#?}");
    let log = value["log"].as_array().expect("element EventTarget log");
    let labels = |round: u64| {
        log.iter()
            .filter(|entry| entry["round"].as_u64() == Some(round))
            .map(|entry| entry["name"].as_str().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        labels(1),
        vec![
            "document-capture",
            "capture",
            "before",
            "handler",
            "after",
            "duplicate",
            "once",
            "handleEvent",
        ],
        "first dispatch ordering/options: {log:#?}",
    );
    assert_eq!(
        labels(2),
        vec![
            "document-capture",
            "capture",
            "before",
            "handler",
            "after",
            "duplicate",
            "handleEvent",
        ],
        "once and duplicate behavior on redispatch: {log:#?}",
    );
    assert!(
        !log.iter().any(|entry| {
            matches!(
                entry["name"].as_str(),
                Some("aborted" | "handler-old")
            )
        }),
        "aborted listener or replaced handler ran: {log:#?}",
    );
    for entry in log {
        assert_eq!(entry["targetIsOwner"], true, "{entry:#?}");
        assert_eq!(entry["thisOk"], true, "{entry:#?}");
        if entry["name"] == "document-capture" {
            assert_eq!(entry["phase"], 1, "{entry:#?}");
            assert_eq!(entry["currentIsDocument"], true, "{entry:#?}");
        } else {
            assert_eq!(entry["phase"], 2, "{entry:#?}");
            assert_eq!(entry["currentIsOwner"], true, "{entry:#?}");
        }
    }
    for after in ["afterFirst", "afterSecond"] {
        assert_eq!(value[after]["currentTargetIsNull"], true, "{value:#?}");
        assert_eq!(value[after]["phase"], 0, "{value:#?}");
        assert_eq!(value[after]["targetIsOwner"], true, "{value:#?}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn connected_light_and_closed_shadow_inner_html_start_load_delaying_resources() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/connected-inner-html.html"),
        "globalThis.__innerHtmlWindowObserved",
    )
    .await;

    assert_eq!(value["images"], 2, "innerHTML images did not complete: {value:#?}");
    assert_eq!(value["sheets"], 2, "innerHTML stylesheets did not complete: {value:#?}");
    assert_eq!(value["frames"], 2, "innerHTML iframes did not complete: {value:#?}");
    assert_eq!(value["readyState"], "complete", "{value:#?}");
    assert_eq!(value["closedRootHidden"], true, "{value:#?}");
}

#[tokio::test(flavor = "current_thread")]
async fn blank_and_connected_subtree_iframes_complete_once_without_detached_execution() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/blank-iframes.html"),
        "globalThis.__blankWindowObserved",
    )
    .await;

    assert_eq!(value["blankOwnerCalls"], 1);
    assert_eq!(value["replacementOwnerCalls"], 1);
    assert_eq!(value["replacementUrl"], "about:srcdoc", "{value:#?}");
    assert!(value["replacementFrameId"].as_u64().unwrap_or_default() > 0);
    assert_eq!(value["subtreeOwnerCalls"], 1);
    assert_eq!(value["detachedFrameExecuted"], 0);
    assert_eq!(value["detachedFrameId"], 0);
}

#[tokio::test(flavor = "current_thread")]
async fn untouched_parser_eager_image_delays_load_while_lazy_image_does_not() {
    std::env::set_var("OBSCURA_RENDER_RESOURCE_WARMUP_MS", "0");
    std::env::set_var("OBSCURA_RENDER_RESOURCE_POST_SCRIPT_WARMUP_MS", "0");
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/parser-images.html"),
        "globalThis.__parserImageObserved",
    )
    .await;

    assert_eq!(value["eagerComplete"], true, "{value:#?}");
    #[cfg(feature = "render")]
    assert_eq!(value["eagerWidth"], 1, "{value:#?}");
    assert_eq!(value["lazyComplete"], false, "{value:#?}");
    assert_eq!(value["lazyWidth"], 0, "{value:#?}");
    #[cfg(feature = "render")]
    assert!(
        value["elapsed"].as_u64().unwrap_or_default() >= 150,
        "Window load fired before the eager parser image completed: {value:#?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_parser_stylesheet_dispatches_owner_error_before_window_load() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/stylesheet-error.html"),
        "({ errorCalls: globalThis.__stylesheetErrorCalls || 0, error: globalThis.__stylesheetErrorObserved, window: globalThis.__stylesheetErrorWindowObserved })",
    )
    .await;

    assert_eq!(value["errorCalls"], 1, "{value:#?}");
    assert_eq!(value["error"]["targetIsOwner"], true, "{value:#?}");
    assert_eq!(value["error"]["currentTargetIsOwner"], true, "{value:#?}");
    assert_eq!(value["error"]["bubbles"], false, "{value:#?}");
    assert_eq!(value["error"]["cancelable"], false, "{value:#?}");
    assert_eq!(value["error"]["readyState"], "loading", "{value:#?}");
    assert_eq!(value["window"]["errorCalls"], 1, "{value:#?}");
    assert_eq!(value["window"]["readyState"], "complete", "{value:#?}");
}

#[tokio::test(flavor = "current_thread")]
async fn top_parser_stylesheet_events_follow_scripts_and_stable_owner_identity() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/parser-stylesheet-order.html"),
        "globalThis.__parserStyleLog",
    )
    .await;
    assert_eq!(
        value,
        json!(["start", "first-error", "between", "second-error", "after"]),
    );
}

#[tokio::test(flavor = "current_thread")]
async fn frame_parser_stylesheet_events_follow_scripts_and_stable_owner_identity() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/frame-parser-stylesheet-order.html"),
        "globalThis.__frameParserStyleLog",
    )
    .await;
    assert_eq!(
        value,
        json!(["start", "first-error", "between", "second-error", "after"]),
    );
}

#[tokio::test(flavor = "current_thread")]
async fn frame_parser_stylesheet_root_load_waits_for_delayed_import_chain() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/frame-parser-stylesheet-import.html"),
        "globalThis.__frameImportEvents",
    )
    .await;
    let events = value.as_array().expect("frame import event log");
    assert_eq!(
        events
            .iter()
            .map(|event| event["label"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec![
            "root-link-load",
            "child-window-load",
            "frame-owner-load",
            "top-window-load",
        ],
        "stylesheet import, owner, child, iframe owner, and top load order: {value:#?}",
    );
    assert_eq!(events[0]["state"], "loading", "{value:#?}");
    assert!(
        events[0]["elapsed"].as_u64().unwrap_or_default() >= 180,
        "root link load fired before its delayed @import completed: {value:#?}",
    );
    assert!(
        events[0]["sheetText"]
            .as_str()
            .unwrap_or_default()
            .contains("--frame-import-ready"),
        "root sheet did not contain the completed import graph: {value:#?}",
    );
    assert_eq!(events[1]["state"], "complete", "{value:#?}");
    assert_eq!(events[2]["childState"], "complete", "{value:#?}");
    assert_eq!(events[3]["state"], "complete", "{value:#?}");
}

#[tokio::test(flavor = "current_thread")]
async fn earlier_frame_owner_load_cannot_complete_a_removed_sibling_window() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/sibling-frame-removal.html"),
        "new Promise(resolve => setTimeout(() => resolve({ \
            removedSiblingWindowLoads: globalThis.__removedSiblingWindowLoads, \
            secondConnected: globalThis.__secondFrame.isConnected, \
            secondFrameId: globalThis.__secondFrame._frameId || 0 \
        }), 20))",
    )
    .await;
    assert_eq!(value["removedSiblingWindowLoads"], 0, "{value:#?}");
    assert_eq!(value["secondConnected"], false, "{value:#?}");
    assert_eq!(value["secondFrameId"], 0, "{value:#?}");
}

#[tokio::test(flavor = "current_thread")]
async fn detached_parent_discards_its_queued_descendant_before_attachment() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/detached-parent-pending-descendant.html"),
        "new Promise(resolve => setTimeout(() => resolve({ \
            descendantRuns: globalThis.__detachedDescendantRuns, \
            parentConnected: globalThis.__detachedParentFrame.isConnected, \
            parentFrameId: globalThis.__detachedParentFrame._frameId || 0 \
        }), 20))",
    )
    .await;
    assert_eq!(value["descendantRuns"], 0, "{value:#?}");
    assert_eq!(value["parentConnected"], false, "{value:#?}");
    assert_eq!(value["parentFrameId"], 0, "{value:#?}");
}

#[tokio::test(flavor = "current_thread")]
async fn iframe_fallback_inner_html_does_not_reload_its_browsing_context() {
    let base = serve_fixture().await;
    let value = navigate_and_evaluate(
        format!("{base}/iframe-fallback-inner-html.html"),
        "globalThis.__fallbackInnerHtmlObserved",
    )
    .await;
    assert_eq!(value["childExecutions"], 1, "{value:#?}");
    assert_eq!(value["ownerLoads"], 1, "{value:#?}");
    assert!(value["frameId"].as_u64().unwrap_or_default() > 0, "{value:#?}");
    // HTML's iframe element is a RAWTEXT container. Its fallback text is not
    // parsed into a child <p>; changing it must nevertheless leave the already
    // active nested browsing context alone.
    assert_eq!(
        value["fallbackText"],
        "<p>new fallback content</p>",
        "{value:#?}"
    );
}
