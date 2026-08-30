use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use obscura_dom::{parse_html, DomTree};
use obscura_js::frame::{FrameLifecycleState, FrameRealm};
use obscura_js::runtime::{ObscuraJsRuntime, WatchdogToken};
use obscura_net::{
    CallbackRegistry, ObscuraHttpClient, ObscuraNetError, RequestCallback, RequestInfo,
    ResourceRequest, ResourceType, Response, ResponseCallback,
};
use url::Url;

use crate::context::BrowserContext;
use crate::lifecycle::LifecycleState;

struct ScriptLoadPhase {
    deadline: tokio::time::Instant,
    watchdog: Option<WatchdogToken>,
}

const LIFECYCLE_CALLBACK_WATCHDOG_MS: u64 = 5_500;
static NEXT_CDP_PAGE_AWAIT_ID: AtomicU64 = AtomicU64::new(1);

/// Parse `OBSCURA_GEOLOCATION="lat,lon"` for the navigator.geolocation shim.
/// Returns None when unset or malformed, leaving the built-in default in place.
/// Lets a deployment align the reported coordinates with the region its exit IP
/// resolves to, so timezone and location stay consistent (issue #228).
fn env_geolocation() -> Option<(f64, f64)> {
    let raw = std::env::var("OBSCURA_GEOLOCATION").ok()?;
    let (lat, lon) = raw.split_once(',')?;
    let lat: f64 = lat.trim().parse().ok()?;
    let lon: f64 = lon.trim().parse().ok()?;
    let valid = lat.is_finite()
        && lon.is_finite()
        && (-90.0..=90.0).contains(&lat)
        && (-180.0..=180.0).contains(&lon);
    valid.then_some((lat, lon))
}

fn decode_data_uri(uri: &str) -> Option<Vec<u8>> {
    let rest = uri.strip_prefix("data:")?;
    let comma = rest.find(',')?;
    let meta = &rest[..comma];
    let payload = &rest[comma + 1..];
    if meta.split(';').any(|t| t.eq_ignore_ascii_case("base64")) {
        let cleaned: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
        BASE64.decode(cleaned).ok()
    } else {
        Some(percent_decode(payload))
    }
}

fn percent_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = hex_val(b[i + 1]);
            let lo = hex_val(b[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Truncate `s` to at most `max` bytes without splitting a UTF-8 character.
/// `&s[..max]` panics if `max` lands inside a multi-byte char; the evaluated
/// expression logged below is caller-controlled, so slice it safely.
/// (`str::floor_char_boundary` would do this but is still unstable.)
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(feature = "render")]
fn remaining_settle_resource_warmup_ms(
    max_ms: u64,
    elapsed: std::time::Duration,
    configured_ms: u64,
) -> u64 {
    std::time::Duration::from_millis(max_ms)
        .checked_sub(elapsed)
        .map(|remaining| {
            (remaining.as_millis().min(u128::from(u64::MAX)) as u64).min(configured_ms)
        })
        .unwrap_or(0)
}

#[cfg(feature = "stealth")]
use obscura_net::StealthHttpClient;

/// Returns true when a JS-initiated navigation would step from a
/// non-file scheme into a file: URL. We treat that move as an SOP
/// violation because the existing realm survives the navigation and
/// can read the new document's body.
fn cross_scheme_to_file(from: &str, to: &str) -> bool {
    let to_is_file = Url::parse(to)
        .map(|u| u.scheme().eq_ignore_ascii_case("file"))
        .unwrap_or(false);
    if !to_is_file {
        return false;
    }
    Url::parse(from)
        .map(|u| !u.scheme().eq_ignore_ascii_case("file"))
        .unwrap_or(true)
}

/// Sub-resource fetch policy. http(s) is always fine; data: is allowed
/// because the bytes are inline in the URI (no network fetch, no SSRF);
/// file: is only allowed when the page itself was loaded from file:;
/// everything else (javascript:, chrome:, etc) is blocked.
/// Real Chrome allows data: subresources by default; Instagram and most
/// Meta properties depend on this for their inline bootstrap scripts.
fn subresource_allowed(page_url: Option<&Url>, resource: &str) -> bool {
    let Ok(target) = Url::parse(resource) else {
        return false;
    };
    let scheme = target.scheme().to_ascii_lowercase();
    match scheme.as_str() {
        "http" | "https" | "data" => true,
        "file" => page_url
            .map(|u| u.scheme().eq_ignore_ascii_case("file"))
            .unwrap_or(false),
        _ => false,
    }
}

/// Compute the default `strict-origin-when-cross-origin` referrer value used
/// for a document-initiated navigation. Direct navigations bypass this helper
/// and use an empty referrer. Referrer-Policy overrides are not yet plumbed
/// through the navigation request.
fn navigation_referrer(source: &Url, target: &Url) -> String {
    if !matches!(source.scheme(), "http" | "https")
        || !matches!(target.scheme(), "http" | "https")
        || (source.scheme() == "https" && target.scheme() == "http")
    {
        return String::new();
    }

    if source.origin() == target.origin() {
        let mut sanitized = source.clone();
        sanitized.set_fragment(None);
        let _ = sanitized.set_username("");
        let _ = sanitized.set_password(None);
        return sanitized.to_string();
    }

    let mut origin = source.origin().ascii_serialization();
    origin.push('/');
    origin
}

/// Escape a value for safe inclusion inside a JavaScript template
/// literal. The previous implementation only escaped `\`, `` ` `` and
/// `${`; that left U+2028 / U+2029 (the JS-specific line terminators)
/// and other control characters as breakout vectors. Done at the
/// callsite means future tweaks come back to one function.
fn escape_for_js_template_literal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '`' => out.push_str("\\`"),
            '$' => out.push_str("\\$"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            '\u{0000}' => out.push_str("\\0"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct NetworkEvent {
    pub request_id: String,
    pub url: String,
    pub method: String,
    pub resource_type: String,
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub response_headers: Arc<std::collections::HashMap<String, String>>,
    pub body_size: usize,
    pub timestamp: f64,
}

#[derive(Debug, Clone)]
pub struct StoredResponseBody {
    pub body: String,
    pub base64_encoded: bool,
}

/// Stable identity and final document URL of one currently live child frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameSnapshot {
    pub frame_id: u32,
    pub url: String,
}

/// Unsupported resource work still visible in one live child frame.
/// Callers producing resource archives can use any returned entry to mark the
/// result incomplete rather than silently omitting it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameResourceDiagnostic {
    pub frame_id: u32,
    pub url: String,
    pub unsupported_module_scripts: usize,
    pub unsupported_stylesheet_imports: usize,
    pub pending_navigation_url: Option<String>,
    pub pending_dynamic_scripts: bool,
    /// Realm evaluation/listing failure. When present, the numeric and boolean
    /// fields above are not evidence of an empty resource set.
    pub diagnostic_error: Option<String>,
}

/// Outcome of one bounded renderer-resource warmup pass.
///
/// `remaining` includes both requests that exceeded the pass deadline and
/// candidates deferred by the per-pass request cap. A caller which needs a
/// complete resource archive must therefore require all of `remaining`,
/// `timed_out`, and `failed` to be zero (or retain the non-zero diagnostic as
/// an incomplete reason while retrying later passes).
#[cfg(feature = "render")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScreenshotResourceWarmupReport {
    /// Cache-missing renderer resources discovered at the start of this pass.
    pub discovered: usize,
    /// Resources actually scheduled in this pass (currently capped at 128).
    pub attempted: usize,
    /// Successful 2xx responses inserted into the renderer cache.
    pub loaded: usize,
    /// Completed requests which failed transport or returned a non-2xx status.
    pub failed: usize,
    /// Scheduled requests still unfinished when the deadline expired.
    pub timed_out: usize,
    /// Discovered resources not completed by this pass, including deferred and
    /// timed-out requests. Completed failures are reported only by `failed`.
    pub remaining: usize,
}

#[cfg(feature = "render")]
impl ScreenshotResourceWarmupReport {
    /// Whether this pass discovered no unresolved or failed resource work.
    pub fn is_complete(self) -> bool {
        self.remaining == 0 && self.timed_out == 0 && self.failed == 0
    }
}

/// Memory bounds for lossless page resource capture. The capture API is
/// opt-in because keeping every response body is intentionally more expensive
/// than the bounded CDP response-body cache.
#[derive(Clone, Copy, Debug)]
pub struct ResourceCaptureLimits {
    pub max_resources: usize,
    pub max_total_bytes: usize,
}

impl Default for ResourceCaptureLimits {
    fn default() -> Self {
        Self {
            max_resources: 4_096,
            max_total_bytes: 512 * 1024 * 1024,
        }
    }
}

/// One byte-exact response initiated by the current top-level document or one
/// of its child frames.
#[derive(Clone, Debug)]
pub struct CapturedResource {
    pub requested_url: Url,
    pub final_url: Url,
    pub method: String,
    pub resource_type: ResourceType,
    pub document_generation: u64,
    pub frame_id: u32,
    pub initiator: Option<Url>,
    pub status: u16,
    pub request_headers: std::collections::HashMap<String, String>,
    pub response_headers: std::collections::HashMap<String, String>,
    pub redirected_from: Vec<Url>,
    pub body: Vec<u8>,
}

/// Lossless responses retained for the final top-level document. A non-zero
/// omitted count means the configured safety bounds were reached and callers
/// must not describe the archive as complete.
#[derive(Debug, Default)]
pub struct ResourceCapture {
    pub document_generation: u64,
    pub resources: Vec<CapturedResource>,
    pub total_bytes: usize,
    pub omitted_resources: usize,
    pub omitted_bytes: usize,
}

struct ResourceCaptureState {
    limits: ResourceCaptureLimits,
    capture: ResourceCapture,
}

impl ResourceCaptureState {
    fn new(limits: ResourceCaptureLimits, document_generation: u64) -> Self {
        Self {
            limits,
            capture: ResourceCapture {
                document_generation,
                ..ResourceCapture::default()
            },
        }
    }

    fn begin_document(&mut self, document_generation: u64) {
        self.capture = ResourceCapture {
            document_generation,
            ..ResourceCapture::default()
        };
    }

    fn record(&mut self, request: &RequestInfo, response: &Response) {
        if request.document_generation != self.capture.document_generation {
            return;
        }
        let body_bytes = response.body.len();
        let over_count = self.capture.resources.len() >= self.limits.max_resources;
        let over_bytes = self
            .capture
            .total_bytes
            .checked_add(body_bytes)
            .is_none_or(|total| total > self.limits.max_total_bytes);
        if over_count || over_bytes {
            self.capture.omitted_resources = self.capture.omitted_resources.saturating_add(1);
            self.capture.omitted_bytes = self.capture.omitted_bytes.saturating_add(body_bytes);
            return;
        }

        let requested_url = response
            .redirected_from
            .first()
            .cloned()
            .unwrap_or_else(|| request.url.clone());
        self.capture.total_bytes += body_bytes;
        self.capture.resources.push(CapturedResource {
            requested_url,
            final_url: response.url.clone(),
            method: request.method.clone(),
            resource_type: request.resource_type,
            document_generation: request.document_generation,
            frame_id: request.frame_id,
            initiator: request.initiator.clone(),
            status: response.status,
            request_headers: request.headers.clone(),
            response_headers: response.headers.clone(),
            redirected_from: response.redirected_from.clone(),
            body: response.body.clone(),
        });
    }
}

#[derive(Clone, Copy)]
struct DeviceMetricsBaseline {
    viewport: (f32, f32),
    device_scale_factor: f32,
}

pub struct Page {
    pub id: String,
    pub frame_id: String,
    pub url: Option<Url>,
    pub dom: Option<DomTree>,
    /// Live child frame realms, in creation order. Declared before `js` on
    /// purpose: a realm holds a V8 handle into that isolate, and fields drop in
    /// declaration order, so the frames must go first.
    pub frames: Vec<FrameRealm>,
    pub js: Option<ObscuraJsRuntime>,
    pub lifecycle: LifecycleState,
    /// The top document has fired DOMContentLoaded but still has load-event
    /// blockers. Autonomous browser turns may complete it after a caller that
    /// waited only for DOMContentLoaded has already returned.
    top_load_pending: bool,
    pub http_client: Arc<ObscuraHttpClient>,
    pub context: Arc<BrowserContext>,
    pub title: String,
    /// Source document URL for the current document. This is deliberately
    /// separate from `url`: direct automation navigations have no referrer,
    /// while a navigation requested by page script uses the previous document.
    pub referrer: String,
    /// CSS viewport used by responsive page JavaScript and CDP screenshots.
    /// The physical `screen` fingerprint remains independent.
    pub viewport: (f32, f32),
    /// Optional CDP physical-screen override. This is separate from the CSS
    /// viewport and survives navigation, matching device-metrics emulation.
    screen_size_override: Option<(f32, f32)>,
    screen_metrics_emulated: bool,
    /// Metrics captured when CDP device emulation is first enabled. Chromium
    /// keeps this baseline across subsequent override calls and restores it
    /// only when the override is cleared.
    device_metrics_baseline: Option<DeviceMetricsBaseline>,
    /// Output device pixels per CSS pixel for CDP surface capture. Layout and
    /// CSSOM stay in CSS pixels; Emulation.setDeviceMetricsOverride owns this
    /// independent raster scale.
    pub device_scale_factor: f32,
    /// DevTools override for the compositor's base surface. It is page-owned,
    /// so it survives document navigation without leaking to other targets.
    default_background_color_override: Option<[u8; 4]>,
    /// WHATWG canonical name of the current document's character encoding
    /// (e.g. "UTF-8", "EUC-JP"), detected when the response body is decoded.
    /// Exposed to JS as `document.characterSet` and used for the URL query
    /// encoding override on `<a>`/`<area>` hrefs in legacy-charset documents.
    pub encoding: String,
    /// Monotonic origin for the current document's CSS animation timeline.
    /// It is reset once author styles are installed, so stylesheet download
    /// latency does not incorrectly advance newly-created animations.
    document_timeline_origin: std::time::Instant,
    /// Optional page-scoped ceiling for an end-to-end navigation. Automation
    /// frontends set this from their request timeout so a caller asking for a
    /// 50-second navigation is not silently cut off by the process default.
    /// Pages without an override retain the environment-configurable default.
    navigation_timeout: Option<std::time::Duration>,
    /// Navigation history for Page.getNavigationHistory / navigateToHistoryEntry.
    /// Entries are URLs in visit order; `history_index` is the current position.
    /// Pushed on every successful navigation; truncated on goBack -> new nav.
    pub history: Vec<String>,
    pub history_index: usize,
    pub network_events: Vec<NetworkEvent>,
    response_bodies: std::collections::HashMap<String, StoredResponseBody>,
    response_body_order: std::collections::VecDeque<String>,
    network_event_counter: u32,
    pub intercept_enabled: bool,
    pub intercept_block_patterns: Vec<String>,
    pub blocked_url_patterns: Vec<String>,
    intercept_tx: Option<tokio::sync::mpsc::UnboundedSender<obscura_js::ops::InterceptedRequest>>,
    // Scripts to execute in the page's JS context BEFORE any of the page's
    // own scripts run — the CDP `Page.addScriptToEvaluateOnNewDocument`
    // contract.
    preload_scripts: Vec<String>,
    // CDP Runtime binding names are kept separately from author-visible
    // preload source. The runtime installs their functions with a private V8
    // closure over the single binding op, so hiding `Deno.core.ops` does not
    // break exposeFunction or reopen the full native op table.
    preload_bindings: Vec<String>,
    /// Fetched parser stylesheet completions waiting for their encounter point
    /// in the HTML script runner. Fetching may happen eagerly, but installing
    /// the sheet or dispatching its owner event must not jump ahead of an
    /// earlier parser-blocking script.
    pending_parser_stylesheet_events: std::collections::BTreeMap<u32, (usize, String)>,
    /// Document-owned HTML script preparation flags saved while the V8 realm
    /// is suspended for CDP/MCP tab switching.  These are restored only when
    /// the same surviving DomTree is resumed; navigation clears them.
    suspended_started_script_ids: Vec<u32>,
    /// Passive on_request/on_response callbacks, scoped to this page (issue
    /// #408): they fire only for requests this page drives and die with it.
    /// Arc because the JS runtime state holds a second handle for fetch()/XHR.
    callbacks: Arc<CallbackRegistry>,
    resource_capture: Option<Arc<std::sync::Mutex<ResourceCaptureState>>>,
    resource_capture_callback_id: Option<u64>,
    /// Final-document resource omissions detected outside the response
    /// callback. A sorted set gives archive manifests deterministic ordering
    /// and prevents repeated settle/diagnostic passes from multiplying text.
    resource_archive_incomplete_reasons: std::collections::BTreeSet<String>,
    #[cfg(feature = "stealth")]
    pub stealth_client: Option<Arc<StealthHttpClient>>,
}

const MAX_STYLESHEET_IMPORT_DEPTH: u8 = 4;
const MAX_STYLESHEET_RESOURCES: usize = 128;
const DEFAULT_NAVIGATION_TIMEOUT_MS: u64 = 30_000;

/// How many child frame realms one document may hold at once.
///
/// Real pages use a handful; the cap exists so a page that creates iframes in a
/// loop cannot make the engine hold an unbounded number of contexts and DOM
/// trees. Frames are released when the document is replaced.
fn max_live_frames() -> usize {
    std::env::var("OBSCURA_MAX_LIVE_FRAMES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64)
}

fn default_navigation_timeout() -> std::time::Duration {
    navigation_timeout_from_env_value(std::env::var("OBSCURA_NAV_TIMEOUT_MS").ok().as_deref())
}

fn navigation_timeout_from_env_value(value: Option<&str>) -> std::time::Duration {
    let milliseconds = value
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_NAVIGATION_TIMEOUT_MS);
    std::time::Duration::from_millis(milliseconds)
}

fn duration_millis_u64(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[derive(Clone)]
struct LoadedStylesheet {
    response_url: Url,
    imports: Vec<StylesheetImport>,
    rules: String,
}

struct FetchedStylesheets {
    materialized: Vec<(AuthorStylesheetTarget, String)>,
    failed_links: Vec<(u32, usize, String, Option<String>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StylesheetImport {
    url: String,
    media: Option<String>,
}

#[derive(Clone)]
enum AuthorStylesheetTarget {
    Linked {
        nid: u32,
        parser_order: usize,
        raw_href: String,
        request_href: String,
    },
    InlineImport {
        nid: u32,
    },
}

#[derive(Clone)]
struct ParserStylesheetLinkSnapshot {
    nid: u32,
    parser_order: usize,
    raw_href: String,
    base_url: Url,
}

#[derive(Clone)]
struct ParserInlineImportSnapshot {
    nid: u32,
    import: StylesheetImport,
    base_url: Url,
}

struct ParserStylesheetSnapshot {
    links: Vec<ParserStylesheetLinkSnapshot>,
    inline_imports: Vec<ParserInlineImportSnapshot>,
    body_parser_order: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
enum ScriptKind {
    Classic,
    Module,
    ImportMap,
}

#[derive(Debug)]
struct ScriptInfo {
    src: Option<String>,
    inline: String,
    is_defer: bool,
    is_async: bool,
    kind: ScriptKind,
    nid: u32,
    after_body_start: bool,
    /// Document base URL at this element's parser encounter point.
    base_url: String,
    parser_order: usize,
}

fn canonical_stylesheet_url(mut url: Url) -> (String, Url) {
    url.set_fragment(None);
    (url.to_string(), url)
}

/// Expand a cached stylesheet graph in CSS cascade order. Network deduplication
/// is separate from expansion: a shared import is downloaded once but expanded
/// at each import position, while the active stack cuts cycles.
fn materialize_stylesheet_graph(
    key: &str,
    sheets: &std::collections::HashMap<String, LoadedStylesheet>,
    aliases: &std::collections::HashMap<String, String>,
    active: &mut std::collections::HashSet<String>,
) -> Option<String> {
    let actual_key = aliases.get(key).map(String::as_str).unwrap_or(key);
    if !active.insert(actual_key.to_string()) {
        return None;
    }
    let Some(sheet) = sheets.get(actual_key).cloned() else {
        active.remove(actual_key);
        return None;
    };

    let mut output = String::new();
    for import in &sheet.imports {
        let Ok(import_url) = sheet.response_url.join(&import.url) else {
            continue;
        };
        let (import_key, _) = canonical_stylesheet_url(import_url);
        if let Some(imported) = materialize_stylesheet_graph(&import_key, sheets, aliases, active) {
            if let Some(media) = import.media.as_deref() {
                output.push_str("@media ");
                output.push_str(media);
                output.push_str(" {\n");
                output.push_str(&imported);
                output.push_str("\n}\n");
            } else {
                output.push_str(&imported);
                output.push('\n');
            }
        }
    }
    output.push_str(&rebase_css_urls(&sheet.rules, &sheet.response_url));
    active.remove(actual_key);
    Some(output)
}

/// Preserve the URL base of a fetched stylesheet after it is materialized as
/// inline CSS. Relative `url(...)` values resolve against the stylesheet's
/// URL in browsers, not the document URL; failing to rebase them drops common
/// background, mask, cursor, and font assets from nested theme directories.
fn rebase_css_urls(css: &str, base: &url::Url) -> String {
    let mut out = String::with_capacity(css.len());
    let mut index = 0usize;
    while index < css.len() {
        let rest = &css[index..];
        if rest.starts_with("/*") {
            if let Some(end) = rest[2..].find("*/") {
                let length = end + 4;
                out.push_str(&rest[..length]);
                index += length;
            } else {
                out.push_str(rest);
                break;
            }
            continue;
        }
        let Some(first) = rest.chars().next() else {
            break;
        };
        if first == '"' || first == '\'' {
            let quote = first;
            let mut escaped = false;
            let mut length = quote.len_utf8();
            for ch in rest[quote.len_utf8()..].chars() {
                length += ch.len_utf8();
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == quote {
                    break;
                }
            }
            out.push_str(&rest[..length]);
            index += length;
            continue;
        }
        let is_url = rest
            .get(..4)
            .map_or(false, |prefix| prefix.eq_ignore_ascii_case("url("));
        if !is_url {
            out.push(first);
            index += first.len_utf8();
            continue;
        }

        let mut quote = None;
        let mut escaped = false;
        let mut end = None;
        for (offset, ch) in rest[4..].char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            match quote {
                Some(open) if ch == open => quote = None,
                Some(_) => {}
                None if ch == '"' || ch == '\'' => quote = Some(ch),
                None if ch == ')' => {
                    end = Some(4 + offset);
                    break;
                }
                None => {}
            }
        }
        let Some(end) = end else {
            out.push_str(rest);
            break;
        };
        let raw = rest[4..end].trim();
        let value = if raw.len() >= 2
            && ((raw.starts_with('"') && raw.ends_with('"'))
                || (raw.starts_with('\'') && raw.ends_with('\'')))
        {
            &raw[1..raw.len() - 1]
        } else {
            raw
        };
        let resolved = if value.is_empty()
            || value.starts_with('#')
            || value.contains("var(")
            || url::Url::parse(value).is_ok()
        {
            None
        } else {
            base.join(value).ok().map(|url| url.to_string())
        };
        if let Some(resolved) = resolved {
            out.push_str("url(\"");
            for ch in resolved.chars() {
                if ch == '\\' || ch == '"' {
                    out.push('\\');
                }
                out.push(ch);
            }
            out.push_str("\")");
        } else {
            out.push_str(&rest[..=end]);
        }
        index += end + 1;
    }
    out
}

/// Extract network-backed `url(...)` assets while respecting CSS comments and
/// strings. Linked sheets have already been rebased before materialization;
/// inline declarations are resolved against the document base here.
fn css_resource_urls(css: &str, base: &url::Url) -> Vec<String> {
    let mut urls = Vec::new();
    let mut index = 0usize;
    while index < css.len() {
        let rest = &css[index..];
        if rest.starts_with("/*") {
            if let Some(end) = rest[2..].find("*/") {
                index += end + 4;
            } else {
                break;
            }
            continue;
        }
        // `@import url(...)` is a stylesheet dependency, not a paint asset.
        // It is fetched by the bounded stylesheet graph above. Letting the
        // generic image/font warmup rediscover it issues a second request with
        // the wrong ResourceType::Image classification.
        if let Some(length) = css_import_rule_len(rest) {
            index += length;
            continue;
        }
        let Some(first) = rest.chars().next() else {
            break;
        };
        if first == '"' || first == '\'' {
            let quote = first;
            let mut escaped = false;
            let mut length = quote.len_utf8();
            for ch in rest[quote.len_utf8()..].chars() {
                length += ch.len_utf8();
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == quote {
                    break;
                }
            }
            index += length;
            continue;
        }
        if !rest
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("url("))
        {
            index += first.len_utf8();
            continue;
        }
        let mut quote = None;
        let mut escaped = false;
        let mut end = None;
        for (offset, ch) in rest[4..].char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            match quote {
                Some(open) if ch == open => quote = None,
                Some(_) => {}
                None if ch == '"' || ch == '\'' => quote = Some(ch),
                None if ch == ')' => {
                    end = Some(4 + offset);
                    break;
                }
                None => {}
            }
        }
        let Some(end) = end else { break };
        let raw = rest[4..end].trim();
        let value = if raw.len() >= 2
            && ((raw.starts_with('"') && raw.ends_with('"'))
                || (raw.starts_with('\'') && raw.ends_with('\'')))
        {
            &raw[1..raw.len() - 1]
        } else {
            raw
        };
        if !value.is_empty()
            && !value.starts_with('#')
            && !value.starts_with("data:")
            && !value.contains("var(")
        {
            if let Ok(mut url) = base.join(value) {
                url.set_fragment(None);
                if matches!(url.scheme(), "http" | "https") {
                    urls.push(url.to_string());
                }
            }
        }
        index += end + 1;
    }
    urls
}

/// Return the byte length of a leading CSS `@import` rule, including its
/// terminating semicolon. Semicolons inside quoted URLs, comments, or `url()`
/// parentheses do not end the rule. A malformed import is left to the normal
/// scanner so this helper cannot swallow following declarations.
fn css_import_rule_len(css: &str) -> Option<usize> {
    let prefix = css.get(..7)?;
    if !prefix.eq_ignore_ascii_case("@import") {
        return None;
    }
    if css[7..]
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return None;
    }

    let bytes = css.as_bytes();
    let mut index = 7usize;
    let mut quote = None;
    let mut escaped = false;
    let mut paren_depth = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(open) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == open {
                quote = None;
            }
            index += 1;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let Some(end) = css[index + 2..].find("*/") else {
                return None;
            };
            index += end + 4;
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b';' if paren_depth == 0 => return Some(index + 1),
            b'{' if paren_depth == 0 => return None,
            _ => {}
        }
        index += 1;
    }
    None
}

fn render_resource_type(url: &url::Url) -> ResourceType {
    let path = url.path().to_ascii_lowercase();
    if [".woff", ".woff2", ".ttf", ".otf", ".eot"]
        .iter()
        .any(|extension| path.ends_with(extension))
    {
        ResourceType::Font
    } else {
        ResourceType::Image
    }
}

/// Pull leading `@import` rules out of a stylesheet. Returns each import target
/// URL with its optional media condition plus the CSS with those `@import`
/// statements removed. Browsers fetch media-gated imports even when they do
/// not match the current screen; preserving the condition lets the same bytes
/// participate in a later PDF print cascade. Handles `@import "x.css";`,
/// `@import url("x.css");`, `@import url(x.css);` and an optional trailing
/// media query.
fn split_css_imports(css: &str) -> (Vec<StylesheetImport>, String) {
    let mut urls = Vec::new();
    let mut stripped = String::with_capacity(css.len());
    let mut rest = css;
    loop {
        let Some(pos) = rest.find("@import") else {
            stripped.push_str(rest);
            break;
        };
        // Real sheets place `@import` at the top (after an optional @charset), so
        // scanning for it anywhere is safe in practice and tolerates minified
        // whitespace. Text before this match carries through unchanged.
        stripped.push_str(&rest[..pos]);
        let after = &rest[pos + "@import".len()..];
        let Some(semi) = after.find(';') else {
            // Malformed; keep the remainder verbatim.
            stripped.push_str(&rest[pos..]);
            break;
        };
        let stmt = &after[..semi];
        if let Some(target) = parse_import_url(stmt) {
            urls.push(target);
        } else {
            // Could not parse a URL; preserve the statement so we don't lose it.
            stripped.push_str("@import");
            stripped.push_str(&after[..=semi]);
        }
        rest = &after[semi + 1..];
    }
    (urls, stripped)
}

/// Extract the URL and optional trailing media query from an `@import`
/// statement body (the text between `@import` and `;`).
fn parse_import_url(stmt: &str) -> Option<StylesheetImport> {
    let s = stmt.trim();
    let is_url_fn = s.len() >= 4 && s[..4].eq_ignore_ascii_case("url(");
    let (url, media) = if is_url_fn {
        let rest = &s[4..];
        let end = rest.find(')')?;
        let inner = rest[..end].trim().trim_matches(|c| c == '"' || c == '\'');
        (inner.to_string(), rest[end + 1..].trim())
    } else {
        let quote = s.chars().next().filter(|c| *c == '"' || *c == '\'')?;
        let rest = &s[1..];
        let end = rest.find(quote)?;
        (rest[..end].to_string(), rest[end + 1..].trim())
    };
    if url.is_empty() {
        return None;
    }
    Some(StylesheetImport {
        url,
        media: (!media.is_empty()).then(|| media.to_string()),
    })
}

/// Materialize a fetched linked sheet immediately after its source `<link>`.
///
/// Keeping each sheet at its document position matters when linked and inline
/// author sheets are interleaved. Appending one aggregate `<style>` to `<head>`
/// makes every external rule later than every inline rule, which changes the
/// CSS cascade even when the external fetches themselves complete in order.
/// The synthetic style retains the link's effective media query so the same
/// fetched bytes can enter print layout without leaking into screen layout.
fn materialize_stylesheet_for_owner_script(
    owner_expression: &str,
    css: &str,
    request_href: Option<&str>,
    expected_raw_href: Option<&str>,
) -> String {
    let escaped_css = escape_for_js_template_literal(css);
    let request_href = request_href
        .and_then(|value| serde_json::to_string(value).ok())
        .unwrap_or_else(|| "null".to_string());
    let expected_raw_href = expected_raw_href
        .and_then(|value| serde_json::to_string(value).ok())
        .unwrap_or_else(|| "null".to_string());
    format!(
        r#"(function() {{
            var link = {owner_expression};
            if (!link || !link.parentNode) return;
            var requestHref = {request_href};
            var expectedRawHref = {expected_raw_href};
            // Parser transport owns the request captured at the element's
            // encounter point. A later href rewrite starts distinct dynamic
            // work; the stale parser response must not install CSS or complete
            // that newer request. Compare the raw token rather than baseURI,
            // because a later <base> legitimately changes the live resolver
            // without changing the already-started parser request.
            if (expectedRawHref !== null
                && link.getAttribute('href') !== expectedRawHref) return;
            // href/rel removal invalidates the parser request even if script
            // restores the same raw href before its response arrives. The
            // closure-owned marker distinguishes that new processing epoch;
            // raw-string equality alone cannot.
            if (expectedRawHref !== null
                && (!globalThis.__obscura_isParserStylesheetPending
                    || !globalThis.__obscura_isParserStylesheetPending(link))) return;
            // The JS loader may have completed while the page transport was
            // fetching the same candidate. Its sheet and owner event win;
            // materializing again would duplicate both CSS and load.
            if (link.sheet != null) return;
            var style = null;
            function effectiveMedia() {{
                // Until the generic Element shim reflects HTMLLinkElement.media,
                // `this.media = "all"` creates an own property while the parsed
                // media="print" attribute remains unchanged.
                if (Object.prototype.hasOwnProperty.call(link, 'media')) {{
                    return String(link.media || '');
                }}
                return link.getAttribute('media') || '';
            }}
            function syncSheet() {{
                if (!style) {{
                    style = document.createElement('style');
                    style.setAttribute('data-obscura-external-stylesheets', '');
                    style.textContent = `{escaped_css}`;
                    globalThis.__obscura_registerLinkedStylesheet(
                        link, style, requestHref === null ? undefined : requestHref);
                }}
                var enabled = link.parentNode
                    && !link.disabled
                    && !link.hasAttribute('disabled');
                if (!enabled) {{
                    if (style && style.parentNode) style.parentNode.removeChild(style);
                    return;
                }}
                var media = effectiveMedia().trim();
                if (media) style.setAttribute('media', media);
                else style.removeAttribute('media');
                if (!style.parentNode) {{
                    link.parentNode.insertBefore(style, link.nextSibling);
                }}
            }}

            // A non-matching sheet still loads and fires its event. Its handler
            // may then make the sheet applicable (the common
            // media=print/onload="this.media='all'" async-CSS pattern).
            syncSheet();
            try {{
                globalThis.__obscura_completeLinkedStylesheet(
                    link,
                    'load',
                    requestHref === null ? undefined : requestHref,
                    expectedRawHref === null ? undefined : expectedRawHref);
            }}
            finally {{ syncSheet(); }}
        }})()"#
    )
}

fn materialize_linked_stylesheet_script(link_index: usize, css: &str) -> String {
    materialize_stylesheet_for_owner_script(
        &format!("document.querySelectorAll('link[rel~=\"stylesheet\"]')[{link_index}]"),
        css,
        None,
        None,
    )
}

/// Parser stylesheet completion addressed by the owner's stable native node
/// id. Earlier parser scripts may insert, remove, or reorder other links, so a
/// querySelectorAll index captured before script execution is not an identity.
fn materialize_parser_stylesheet_script_with_token(
    link_nid: u32,
    css: &str,
    request_href: &str,
    expected_raw_href: &str,
) -> String {
    materialize_stylesheet_for_owner_script(
        &format!("globalThis._wrap && globalThis._wrap({link_nid})"),
        css,
        Some(request_href),
        Some(expected_raw_href),
    )
}

fn materialize_parser_stylesheet_script(link_nid: u32, css: &str) -> String {
    materialize_stylesheet_for_owner_script(
        &format!("globalThis._wrap && globalThis._wrap({link_nid})"),
        css,
        None,
        None,
    )
}

fn complete_parser_stylesheet_script_with_token(
    link_nid: u32,
    event_type: &str,
    request_href: Option<&str>,
    expected_raw_href: &str,
) -> String {
    debug_assert!(matches!(event_type, "load" | "error"));
    let request_href = request_href
        .and_then(|value| serde_json::to_string(value).ok())
        .unwrap_or_else(|| "undefined".to_string());
    let expected_raw_href =
        serde_json::to_string(expected_raw_href).unwrap_or_else(|_| "\"\"".to_string());
    format!(
        r#"(function() {{
            var link = globalThis._wrap && globalThis._wrap({link_nid});
            if (link && typeof globalThis.__obscura_completeLinkedStylesheet === 'function') {{
                globalThis.__obscura_completeLinkedStylesheet(
                    link, '{event_type}', {request_href}, {expected_raw_href});
            }}
        }})()"#
    )
}

fn complete_parser_stylesheet_script(link_nid: u32, event_type: &str) -> String {
    debug_assert!(matches!(event_type, "load" | "error"));
    format!(
        r#"(function() {{
            var link = globalThis._wrap && globalThis._wrap({link_nid});
            if (link && typeof globalThis.__obscura_completeLinkedStylesheet === 'function') {{
                globalThis.__obscura_completeLinkedStylesheet(link, '{event_type}');
            }}
        }})()"#
    )
}

/// Turn a fetched frame stylesheet's leading `@import` rules into ordinary
/// pending `<link rel=stylesheet>` owners. The next bounded archive/render
/// warmup fetches those links through the same frame-aware page transport,
/// which naturally handles arbitrary import graphs one depth at a time while
/// keeping every response attributable to the child frame.
fn queue_stylesheet_imports_for_owner_script(
    owner_expression: &str,
    imports: &[StylesheetImport],
    response_url: &Url,
    next_depth: u8,
) -> String {
    let imports = imports
        .iter()
        .filter_map(|import| {
            response_url.join(&import.url).ok().map(|url| {
                serde_json::json!({
                    "href": url,
                    "media": import.media,
                })
            })
        })
        .collect::<Vec<_>>();
    let imports = serde_json::to_string(&imports).unwrap_or_else(|_| "[]".to_string());
    format!(
        r#"(function() {{
            var owner = {owner_expression};
            if (!owner || !owner.parentNode) throw new Error('stylesheet owner disappeared');
            var inherited = (owner.getAttribute('media') || '').trim();
            var imports = {imports};
            for (var i = 0; i < imports.length; i++) {{
                var pending = document.createElement('link');
                pending.setAttribute('rel', 'stylesheet');
                pending.setAttribute('href', imports[i].href);
                pending.setAttribute('data-obscura-import-depth', '{next_depth}');
                pending.setAttribute('data-obscura-page-transport', '');
                var own = String(imports[i].media || '').trim();
                var media = inherited && own
                    ? '(' + inherited + ') and (' + own + ')'
                    : (inherited || own);
                if (media) pending.setAttribute('media', media);
                owner.parentNode.insertBefore(pending, owner);
            }}
        }})()"#,
    )
}

/// Queue imports for a stylesheet discovered after parser execution. Archive
/// warmup re-scans the live document on each pass, so its current selector
/// index intentionally identifies the owner in that same pass.
fn queue_stylesheet_imports_script(
    link_index: usize,
    imports: &[StylesheetImport],
    response_url: &Url,
    next_depth: u8,
) -> String {
    queue_stylesheet_imports_for_owner_script(
        &format!("document.querySelectorAll('link[rel~=\"stylesheet\"]')[{link_index}]"),
        imports,
        response_url,
        next_depth,
    )
}

/// Replace one frame-owned inline stylesheet's leading `@import` rules with
/// pending link owners. They are deliberately ordinary stylesheet links so
/// the frame-aware warmup can reuse its byte-exact transport, attribution,
/// depth cap, recursive import handling, and failure diagnostics.
fn queue_inline_stylesheet_imports_script(
    style_index: usize,
    rules: &str,
    imports: &[StylesheetImport],
    document_base: &Url,
    import_depth: u8,
) -> String {
    let escaped_rules = escape_for_js_template_literal(rules);
    let imports = imports
        .iter()
        .filter_map(|import| {
            document_base.join(&import.url).ok().map(|url| {
                serde_json::json!({
                    "href": url,
                    "media": import.media,
                })
            })
        })
        .collect::<Vec<_>>();
    let imports = serde_json::to_string(&imports).unwrap_or_else(|_| "[]".to_string());
    format!(
        r#"(function() {{
            var styles = [...document.querySelectorAll('style')].filter(function(node) {{
                if (node.hasAttribute('data-obscura-adopted')
                    || node.hasAttribute('data-obscura-linked')
                    || node.hasAttribute('data-obscura-external-stylesheets')
                    || node.hasAttribute('data-obscura-inline-import')
                    || node.hasAttribute('data-obscura-imports-materialized')) return false;
                var type = (node.getAttribute('type') || '').trim().toLowerCase();
                return !type || type === 'text/css';
            }});
            var source = styles[{style_index}];
            if (!source || !source.parentNode) throw new Error('inline stylesheet owner disappeared');
            source.textContent = `{escaped_rules}`;
            var inherited = (source.getAttribute('media') || '').trim();
            var imports = {imports};
            for (var i = 0; i < imports.length; i++) {{
                var pending = document.createElement('link');
                pending.setAttribute('rel', 'stylesheet');
                pending.setAttribute('href', imports[i].href);
                pending.setAttribute('data-obscura-import-depth', '{import_depth}');
                pending.setAttribute('data-obscura-page-transport', '');
                var own = String(imports[i].media || '').trim();
                var media = inherited && own
                    ? '(' + inherited + ') and (' + own + ')'
                    : (inherited || own);
                if (media) pending.setAttribute('media', media);
                source.parentNode.insertBefore(pending, source);
            }}
        }})()"#,
    )
}

/// Materialize one fetched `@import` immediately before its source inline
/// `<style>`. Imported rules precede the importing sheet in the author cascade,
/// and inherit the source sheet's own media condition in addition to the
/// import rule's media wrapper.
fn materialize_inline_import_script(style_nid: u32, css: &str) -> String {
    let escaped_css = escape_for_js_template_literal(css);
    format!(
        r#"(function() {{
            var source = globalThis._wrap && globalThis._wrap({style_nid});
            if (!source || !source.parentNode) return;
            source.setAttribute('data-obscura-imports-materialized', '');
            var imported = document.createElement('style');
            imported.setAttribute('data-obscura-inline-import', '');
            var media = source.getAttribute('media') || '';
            if (media.trim()) imported.setAttribute('media', media);
            imported.textContent = `{escaped_css}`;
            source.parentNode.insertBefore(imported, source);
        }})()"#
    )
}

/// Parser stylesheet requests with stable owner ids and encounter order. Page
/// freezes these before new-document preload code can insert, move, or rewrite
/// live style/link nodes in the already-parsed backing tree.
fn parser_stylesheet_requests(
    dom: &DomTree,
    document_url: &Url,
) -> (
    Vec<ParserStylesheetLinkSnapshot>,
    Vec<ParserInlineImportSnapshot>,
    Option<usize>,
) {
    let mut order = std::collections::HashMap::new();
    let mut bases_at_node = std::collections::HashMap::new();
    let mut active_base = document_url.clone();
    let mut found_base = false;
    let mut body_parser_order = None;
    for (parser_order, nid) in dom.descendants(dom.document()).into_iter().enumerate() {
        order.insert(nid.raw(), parser_order);
        let Some(node) = dom.get_node(nid) else {
            continue;
        };
        let Some(name) = node.as_element() else {
            continue;
        };
        let local_name = name.local.as_ref();
        if local_name == "base" && !found_base {
            if let Some(href) = node.get_attribute("href") {
                found_base = true;
                if let Ok(resolved) = active_base.join(href) {
                    active_base = resolved;
                }
            }
            continue;
        }
        if local_name == "body" && body_parser_order.is_none() {
            body_parser_order = Some(parser_order);
        }
        if matches!(local_name, "link" | "style") {
            bases_at_node.insert(nid.raw(), active_base.clone());
        }
    }

    let mut links = Vec::new();
    for lid in dom
        .query_selector_all("link[rel~=\"stylesheet\"]")
        .unwrap_or_default()
    {
        let Some(node) = dom.get_node(lid) else {
            continue;
        };
        if node.get_attribute("disabled").is_some() {
            continue;
        }
        if let Some(href) = node.get_attribute("href") {
            links.push(ParserStylesheetLinkSnapshot {
                nid: lid.raw(),
                parser_order: order.get(&lid.raw()).copied().unwrap_or(usize::MAX),
                raw_href: href.to_string(),
                base_url: bases_at_node
                    .get(&lid.raw())
                    .cloned()
                    .unwrap_or_else(|| document_url.clone()),
            });
        }
    }

    let mut inline_imports = Vec::new();
    for style_id in dom.query_selector_all("style").unwrap_or_default() {
        let Some(node) = dom.get_node(style_id) else {
            continue;
        };
        if node
            .get_attribute("data-obscura-external-stylesheets")
            .is_some()
            || node.get_attribute("data-obscura-inline-import").is_some()
        {
            continue;
        }
        let (style_imports, _) = split_css_imports(&dom.text_content(style_id));
        let base_url = bases_at_node
            .get(&style_id.raw())
            .cloned()
            .unwrap_or_else(|| document_url.clone());
        inline_imports.extend(
            style_imports
                .into_iter()
                .map(|import| ParserInlineImportSnapshot {
                    nid: style_id.raw(),
                    import,
                    base_url: base_url.clone(),
                }),
        );
    }
    (links, inline_imports, body_parser_order)
}

/// Discover linked author sheets in document order.
///
/// Media queries control whether a loaded sheet participates in the cascade;
/// they do not suppress its fetch or `load` event. Keep the index among all
/// stylesheet links so the materialization script addresses the same node.
#[cfg(test)]
fn linked_stylesheet_requests(dom: &DomTree) -> Vec<(usize, String)> {
    let link_ids = dom
        .query_selector_all("link[rel~=\"stylesheet\"]")
        .unwrap_or_default();
    let mut links = Vec::new();
    for (link_index, lid) in link_ids.into_iter().enumerate() {
        if let Some(node) = dom.get_node(lid) {
            // Disabled alternate sheets remain dormant until script enables
            // them. Media-gated sheets are different: they still load.
            if node.get_attribute("disabled").is_some() {
                continue;
            }
            if let Some(href) = node.get_attribute("href") {
                links.push((link_index, href.to_string()));
            }
        }
    }
    links
}

impl Page {
    pub fn new(id: String, context: Arc<BrowserContext>) -> Self {
        let http_client = context.http_client.clone();
        // Chromium convention: the main frame's frameId == the targetId.
        // Playwright's frame manager looks up the main frame by targetId
        // (via target._targetInfo.targetId), so any divergence here makes
        // Page.getFrameTree return a frame the client cannot match,
        // triggering a Target.closeTarget and "Frame has been detached".
        let frame_id = id.clone();
        #[cfg(feature = "stealth")]
        let stealth_client = if context.stealth {
            // The wreq client backing StealthHttpClient does not speak SOCKS5.
            // Callers must validate the proxy scheme up front and fail loudly
            // (see obscura-cli) rather than silently rewriting socks5:// to
            // http://, which only works when the upstream happens to be a
            // Clash-style mixed-mode proxy and breaks plain SOCKS5 servers
            // like `ssh -ND` (#160).
            Some(Arc::new(StealthHttpClient::with_proxy(
                context.cookie_jar.clone(),
                context.proxy_url.as_deref(),
            )))
        } else {
            None
        };

        Page {
            id,
            frame_id,
            url: None,
            dom: None,
            frames: Vec::new(),
            js: None,
            lifecycle: LifecycleState::Idle,
            top_load_pending: false,
            http_client,
            context,
            title: String::new(),
            referrer: String::new(),
            viewport: (1280.0, 720.0),
            screen_size_override: None,
            screen_metrics_emulated: false,
            device_metrics_baseline: None,
            device_scale_factor: 1.0,
            default_background_color_override: None,
            encoding: "UTF-8".to_string(),
            document_timeline_origin: std::time::Instant::now(),
            navigation_timeout: None,
            history: Vec::new(),
            history_index: 0,
            network_events: Vec::new(),
            response_bodies: std::collections::HashMap::new(),
            response_body_order: std::collections::VecDeque::new(),
            network_event_counter: 0,
            intercept_enabled: false,
            intercept_block_patterns: Vec::new(),
            blocked_url_patterns: Vec::new(),
            intercept_tx: None,
            preload_scripts: Vec::new(),
            preload_bindings: Vec::new(),
            pending_parser_stylesheet_events: std::collections::BTreeMap::new(),
            suspended_started_script_ids: Vec::new(),
            callbacks: Arc::new(CallbackRegistry::new()),
            resource_capture: None,
            resource_capture_callback_id: None,
            resource_archive_incomplete_reasons: std::collections::BTreeSet::new(),
            #[cfg(feature = "stealth")]
            stealth_client,
        }
    }

    /// Set the end-to-end navigation deadline for this page. This page-scoped
    /// value takes precedence over `OBSCURA_NAV_TIMEOUT_MS`; callers that do
    /// not set it retain the existing environment-configurable 30s default.
    pub fn set_navigation_timeout(&mut self, timeout: std::time::Duration) {
        self.navigation_timeout = Some(timeout);
    }

    /// Return the effective end-to-end navigation deadline for this page.
    pub fn navigation_timeout(&self) -> std::time::Duration {
        self.navigation_timeout
            .unwrap_or_else(default_navigation_timeout)
    }

    fn mark_resource_archive_incomplete(&mut self, reason: impl Into<String>) {
        self.resource_archive_incomplete_reasons
            .insert(reason.into());
    }

    fn begin_top_document(&mut self) {
        self.top_load_pending = false;
        self.pending_parser_stylesheet_events.clear();
        self.resource_archive_incomplete_reasons.clear();
        let document_generation = self.callbacks.begin_document();
        if let Some(capture) = &self.resource_capture {
            capture
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .begin_document(document_generation);
        }
    }

    fn should_block_url(&self, url: &str) -> bool {
        for pattern in &self.blocked_url_patterns {
            if url_matches_cdp_pattern(pattern, url) {
                return true;
            }
        }
        if self.intercept_enabled {
            for pattern in &self.intercept_block_patterns {
                if url_matches_cdp_pattern(pattern, url) {
                    return true;
                }
            }
        }
        false
    }

    /// Gives every frame document the page has fetched a realm of its own, and
    /// runs the scripts that came with it (issue #600).
    ///
    /// Building a realm needs the whole runtime, which an op cannot reach, so
    /// the JS side queues the fetched document and this drains the queue between
    /// event loop turns. Reports whether anything was attached, so a caller can
    /// settle and come back for frames that these frames created.
    async fn attach_pending_frames(&mut self) -> bool {
        let mut pending = match self.js.as_ref() {
            Some(js) => js.take_pending_frame_drain(),
            None => return false,
        };
        if pending.is_empty() {
            return false;
        }

        while let Some(frame) = pending.next() {
            // The queue was moved into this cancellation-safe drain before we
            // started attaching it. An earlier child can synchronously remove
            // a later iframe while its PendingFrame is already in the drain,
            // beyond the reach of op_cancel_frame_document. Revalidate the
            // owner id and composed-tree connection at the attachment boundary.
            match self.frame_owner_is_live(frame.parent_frame_id, frame.frame_id) {
                Ok(true) => {}
                Ok(false) => {
                    self.forget_frame_references(frame.frame_id, frame.parent_frame_id);
                    pending.finish_current();
                    continue;
                }
                Err(error) => {
                    tracing::warn!(
                        "could not verify owner liveness for frame {}: {error}",
                        frame.frame_id
                    );
                    self.top_load_pending = false;
                    self.lifecycle = LifecycleState::Failed;
                    return false;
                }
            }
            // A realm is a live v8::Context plus a DOM tree, and the page realm
            // holds its window and document, so nothing here can be collected
            // while the document lives. Frames are released when the document
            // is replaced, so a page that churns iframes would otherwise grow
            // the process without bound. Refuse past the cap rather than let a
            // page decide how much memory to take.
            let cap = max_live_frames();
            if self.frames.len() >= cap {
                tracing::warn!(
                    "refusing a realm for frame {}: already at the {} live frame cap",
                    frame.url,
                    cap,
                );
                self.mark_resource_archive_incomplete(format!(
                    "live frame cap reached ({cap} realms)"
                ));
                self.dispatch_frame_owner_load(frame.parent_frame_id, frame.frame_id);
                self.forget_frame_references(frame.frame_id, frame.parent_frame_id);
                pending.finish_current();
                continue;
            }
            let realm = match self.js.as_mut().and_then(|js| {
                FrameRealm::new_staged_with_inherited_context(
                    js,
                    frame.frame_id,
                    frame.parent_frame_id,
                    &frame.url,
                    frame.inherited_base_url.as_deref(),
                    frame.inherited_origin.as_deref(),
                    &frame.html,
                )
            }) {
                Some(realm) => realm,
                None => {
                    tracing::warn!("could not build a realm for frame {}", frame.url);
                    self.mark_resource_archive_incomplete(format!(
                        "frame realm creation failed: {}",
                        frame.url,
                    ));
                    self.dispatch_frame_owner_load(frame.parent_frame_id, frame.frame_id);
                    self.forget_frame_references(frame.frame_id, frame.parent_frame_id);
                    pending.finish_current();
                    continue;
                }
            };

            // A frame's static resources resolve and are fetched against the
            // frame's own final document URL. Fetch linked stylesheets before
            // document scripts, matching parser-time stylesheet loading and
            // making the CSS available to synchronous getComputedStyle calls.
            let initiator =
                Url::parse(realm.url()).unwrap_or_else(|_| Url::parse("about:blank").unwrap());
            let style_base = match self.js.as_mut() {
                Some(js) => realm
                    .document_base_url(js)
                    .unwrap_or_else(|| initiator.clone()),
                None => initiator.clone(),
            };
            let inline_stylesheets = realm.parser_inline_stylesheet_sources();
            for (style_index, css, _, base_url) in inline_stylesheets {
                let style_encounter_base =
                    Url::parse(&base_url).unwrap_or_else(|_| style_base.clone());
                let (imports, rules) = split_css_imports(&css);
                if imports.is_empty() {
                    continue;
                }
                for import in &imports {
                    if style_encounter_base.join(&import.url).is_err() {
                        self.mark_resource_archive_incomplete(format!(
                            "frame {} inline stylesheet import URL could not be resolved: {}",
                            realm.frame_id(),
                            import.url,
                        ));
                    }
                }
                let queued = match self.js.as_mut() {
                    Some(js) => realm.execute_script(
                        js,
                        &queue_inline_stylesheet_imports_script(
                            style_index,
                            &rules,
                            &imports,
                            &style_encounter_base,
                            1,
                        ),
                    ),
                    None => Err("frame JavaScript runtime disappeared".to_string()),
                };
                if let Err(error) = queued {
                    self.mark_resource_archive_incomplete(format!(
                        "frame {} inline stylesheet import setup failed: {}",
                        realm.frame_id(),
                        error,
                    ));
                }
            }
            let mut wanted_stylesheets = realm
                .parser_stylesheet_urls()
                .into_iter()
                .map(|(link_index, link_nid, url, import_depth, raw_href)| {
                    (link_index, link_nid, url, import_depth, Some(raw_href))
                })
                .collect::<Vec<_>>();
            if let Some(js) = self.js.as_mut() {
                wanted_stylesheets.extend(realm.external_stylesheet_urls(js).into_iter().map(
                    |(link_index, link_nid, url, import_depth)| {
                        (link_index, link_nid, url, import_depth, None)
                    },
                ));
            }
            let inline_style_sources = match self.js.as_mut() {
                Some(js) => realm.style_sources(js),
                None => Vec::new(),
            };
            let mut stylesheet_assets = std::collections::BTreeMap::new();
            for css in &inline_style_sources {
                for resource_url in css_resource_urls(css, &style_base) {
                    if let Ok(parsed) = Url::parse(&resource_url) {
                        stylesheet_assets
                            .entry(resource_url)
                            .or_insert_with(|| render_resource_type(&parsed));
                    }
                }
            }
            // Fetch the complete parser stylesheet graph before any owner
            // completion is queued. A linked sheet is not ready when only its
            // root response has arrived: every leading @import must reach a
            // terminal response first, and the root link's load/error event
            // must remain at its parser position after that work completes.
            let mut stylesheet_roots = Vec::new();
            let mut stylesheet_sheets = std::collections::HashMap::new();
            let mut stylesheet_aliases = std::collections::HashMap::new();
            let mut scheduled_stylesheets = std::collections::HashSet::new();
            let mut pending_stylesheets = Vec::new();
            let mut failed_stylesheet_links = Vec::new();
            for (link_index, link_nid, url, import_depth, raw_href) in wanted_stylesheets {
                // Non-zero depths identify synthetic links created above for
                // inline @import rules. Fetch those through this same graph,
                // but materialize them directly later: unlike depth-zero
                // parser links, they are not in the frame's parser snapshot.
                let is_parser_owner = raw_href.is_some();
                let Ok(parsed) = Url::parse(&url) else {
                    failed_stylesheet_links.push((
                        link_index,
                        link_nid,
                        is_parser_owner,
                        raw_href,
                        None,
                    ));
                    continue;
                };
                if self.should_block_url(&url)
                    || !subresource_allowed(Some(&initiator), parsed.as_str())
                {
                    failed_stylesheet_links.push((
                        link_index,
                        link_nid,
                        is_parser_owner,
                        raw_href,
                        Some(url),
                    ));
                    continue;
                }
                let (key, parsed) = canonical_stylesheet_url(parsed);
                stylesheet_roots.push((
                    link_index,
                    link_nid,
                    key.clone(),
                    is_parser_owner,
                    raw_href,
                    url,
                ));
                if scheduled_stylesheets.insert(key.clone()) {
                    if scheduled_stylesheets.len() <= MAX_STYLESHEET_RESOURCES {
                        pending_stylesheets.push((key, parsed, import_depth));
                    } else {
                        self.mark_resource_archive_incomplete(format!(
                            "frame {} stylesheet resource cap reached ({MAX_STYLESHEET_RESOURCES} resources)",
                            realm.frame_id(),
                        ));
                    }
                }
            }

            while let Some((key, parsed, import_depth)) = pending_stylesheets.pop() {
                let request = ResourceRequest::subresource(ResourceType::Stylesheet, &initiator)
                    .in_frame(realm.frame_id());
                match self.do_fetch_resource(&parsed, request).await {
                    Ok(response) => {
                        self.record_network_event_with_body(
                            response.url.as_str(),
                            "GET",
                            "Stylesheet",
                            response.status,
                            &response.headers,
                            &response.body,
                            false,
                        );
                        if !(200..300).contains(&response.status) {
                            self.mark_resource_archive_incomplete(format!(
                                "frame {} stylesheet {} returned HTTP {}",
                                realm.frame_id(),
                                parsed,
                                response.status,
                            ));
                            continue;
                        }
                        let css =
                            obscura_net::decode_non_html(&response.body, response.content_type());
                        for resource_url in css_resource_urls(&css, &response.url) {
                            if let Ok(parsed) = Url::parse(&resource_url) {
                                stylesheet_assets
                                    .entry(resource_url)
                                    .or_insert_with(|| render_resource_type(&parsed));
                            }
                        }
                        let (response_key, response_url) =
                            canonical_stylesheet_url(response.url.clone());
                        if let Some(existing) = stylesheet_aliases.get(&response_key).cloned() {
                            stylesheet_aliases.insert(key, existing);
                            continue;
                        }
                        let (discovered_imports, rules) = split_css_imports(&css);
                        if import_depth >= MAX_STYLESHEET_IMPORT_DEPTH
                            && !discovered_imports.is_empty()
                        {
                            self.mark_resource_archive_incomplete(format!(
                                "frame {} stylesheet import depth cap reached ({MAX_STYLESHEET_IMPORT_DEPTH}): {}",
                                realm.frame_id(), response_url,
                            ));
                        }
                        let imports = if import_depth < MAX_STYLESHEET_IMPORT_DEPTH {
                            discovered_imports
                        } else {
                            Vec::new()
                        };
                        stylesheet_aliases.insert(key.clone(), key.clone());
                        stylesheet_aliases.insert(response_key, key.clone());
                        stylesheet_sheets.insert(
                            key,
                            LoadedStylesheet {
                                response_url: response_url.clone(),
                                imports: imports.clone(),
                                rules,
                            },
                        );

                        if import_depth >= MAX_STYLESHEET_IMPORT_DEPTH {
                            continue;
                        }
                        // Reverse before pushing onto the LIFO worklist so
                        // network observation remains in CSS source order.
                        for import in imports.into_iter().rev() {
                            let Ok(import_url) = response_url.join(&import.url) else {
                                self.mark_resource_archive_incomplete(format!(
                                    "frame {} stylesheet import URL could not be resolved: {}",
                                    realm.frame_id(),
                                    import.url,
                                ));
                                continue;
                            };
                            let (import_key, import_url) = canonical_stylesheet_url(import_url);
                            if stylesheet_aliases.contains_key(&import_key)
                                || scheduled_stylesheets.contains(&import_key)
                            {
                                continue;
                            }
                            if self.should_block_url(import_url.as_str())
                                || !subresource_allowed(Some(&initiator), import_url.as_str())
                            {
                                self.mark_resource_archive_incomplete(format!(
                                    "frame {} stylesheet import was blocked: {}",
                                    realm.frame_id(),
                                    import_url,
                                ));
                                continue;
                            }
                            if scheduled_stylesheets.len() >= MAX_STYLESHEET_RESOURCES {
                                self.mark_resource_archive_incomplete(format!(
                                    "frame {} stylesheet resource cap reached ({MAX_STYLESHEET_RESOURCES} resources)",
                                    realm.frame_id(),
                                ));
                                continue;
                            }
                            scheduled_stylesheets.insert(import_key.clone());
                            pending_stylesheets.push((
                                import_key,
                                import_url,
                                import_depth.saturating_add(1),
                            ));
                        }
                    }
                    Err(error) => {
                        tracing::warn!("frame stylesheet {} failed: {}", parsed, error);
                        self.mark_resource_archive_incomplete(format!(
                            "frame {} stylesheet fetch failed: {}: {}",
                            realm.frame_id(),
                            parsed,
                            error,
                        ));
                    }
                }
            }

            let mut stylesheets = Vec::new();
            for (link_index, link_nid, key, is_parser_owner, raw_href, request_href) in
                stylesheet_roots
            {
                match materialize_stylesheet_graph(
                    &key,
                    &stylesheet_sheets,
                    &stylesheet_aliases,
                    &mut std::collections::HashSet::new(),
                ) {
                    Some(css) => stylesheets.push((
                        link_index,
                        link_nid,
                        css,
                        is_parser_owner,
                        raw_href,
                        request_href,
                    )),
                    None => failed_stylesheet_links.push((
                        link_index,
                        link_nid,
                        is_parser_owner,
                        raw_href,
                        Some(request_href),
                    )),
                }
            }

            for (url, resource_type) in stylesheet_assets {
                let Ok(parsed) = Url::parse(&url) else {
                    continue;
                };
                if self.should_block_url(&url)
                    || !subresource_allowed(Some(&initiator), parsed.as_str())
                {
                    continue;
                }
                let request = ResourceRequest::subresource(resource_type, &initiator)
                    .in_frame(realm.frame_id());
                match self.do_fetch_resource(&parsed, request).await {
                    Ok(response) => {
                        self.record_network_event_with_body(
                            response.url.as_str(),
                            "GET",
                            match resource_type {
                                ResourceType::Font => "Font",
                                _ => "Image",
                            },
                            response.status,
                            &response.headers,
                            &response.body,
                            true,
                        );
                        #[cfg(feature = "render")]
                        realm.seed_render_resource(
                            url,
                            (200..300)
                                .contains(&response.status)
                                .then(|| response.body.clone()),
                        );
                        if !(200..300).contains(&response.status) {
                            self.mark_resource_archive_incomplete(format!(
                                "frame {} stylesheet resource {} returned HTTP {}",
                                realm.frame_id(),
                                response.url,
                                response.status,
                            ));
                        }
                    }
                    Err(error) => {
                        tracing::warn!("frame stylesheet resource {} failed: {}", url, error);
                        self.mark_resource_archive_incomplete(format!(
                            "frame {} stylesheet resource fetch failed: {}: {}",
                            realm.frame_id(),
                            url,
                            error,
                        ));
                    }
                }
            }

            // External classic script loading is synchronous from the realm's
            // point of view, so collect their source text before execution.
            let wanted = match self.js.as_mut() {
                Some(js) => realm.external_script_urls(js),
                None => Vec::new(),
            };
            let mut sources: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            for url in wanted {
                let Ok(parsed) = Url::parse(&url) else {
                    self.mark_resource_archive_incomplete(format!(
                        "frame {} classic script URL could not be resolved: {}",
                        realm.frame_id(),
                        url,
                    ));
                    continue;
                };
                if self.should_block_url(&url) {
                    self.mark_resource_archive_incomplete(format!(
                        "frame {} classic script was blocked: {}",
                        realm.frame_id(),
                        url,
                    ));
                    continue;
                }
                let request = ResourceRequest::subresource(ResourceType::Script, &initiator)
                    .in_frame(realm.frame_id());
                match self.do_fetch_resource(&parsed, request).await {
                    Ok(response) => {
                        if script_response_is_executable(response.status) {
                            sources
                                .insert(url, String::from_utf8_lossy(&response.body).into_owned());
                        } else {
                            self.mark_resource_archive_incomplete(format!(
                                "frame {} classic script {} returned HTTP {}",
                                realm.frame_id(),
                                response.url,
                                response.status,
                            ));
                        }
                    }
                    Err(error) => {
                        tracing::warn!("frame script {} failed: {}", url, error);
                        self.mark_resource_archive_incomplete(format!(
                            "frame {} classic script fetch failed: {}: {}",
                            realm.frame_id(),
                            url,
                            error,
                        ));
                    }
                }
            }

            let lifecycle_watchdog = self.js.as_mut().map(|js| {
                js.arm_watchdog(std::time::Duration::from_millis(
                    LIFECYCLE_CALLBACK_WATCHDOG_MS,
                ))
            });
            let lifecycle_result = if let Some(js) = self.js.as_mut() {
                // Page.addScriptToEvaluateOnNewDocument applies before any
                // page-authored callback in a child document, including the
                // load/error owner event of a parser stylesheet.
                for name in &self.preload_bindings {
                    if let Err(error) = realm.install_cdp_binding(js, name) {
                        tracing::debug!(
                            "frame {} binding {} setup failed: {error}",
                            frame.url,
                            name,
                        );
                    }
                }
                for source in &self.preload_scripts {
                    if let Err(error) = realm.execute_script(js, source) {
                        tracing::debug!("frame {} preload failed: {error}", frame.url);
                    }
                }
                let mut parser_stylesheet_events = std::collections::BTreeMap::new();
                failed_stylesheet_links.sort_unstable();
                failed_stylesheet_links.dedup();
                for (_, link_nid, is_parser_owner, raw_href, request_href) in
                    failed_stylesheet_links
                {
                    let completion = if let Some(raw_href) = raw_href.as_deref() {
                        complete_parser_stylesheet_script_with_token(
                            link_nid,
                            "error",
                            request_href.as_deref(),
                            raw_href,
                        )
                    } else {
                        complete_parser_stylesheet_script(link_nid, "error")
                    };
                    if is_parser_owner {
                        parser_stylesheet_events.insert(link_nid, completion);
                    } else if let Err(error) = realm.execute_script(js, &completion) {
                        tracing::debug!(
                            "frame {} inline import owner error dispatch failed: {error}",
                            frame.url,
                        );
                    }
                }
                if let Err(error) = realm.set_viewport(
                    js,
                    frame.viewport_width as f64,
                    frame.viewport_height as f64,
                ) {
                    tracing::debug!("frame {} viewport setup failed: {error}", frame.url);
                }
                if !stylesheets.is_empty() {
                    let combined_css = stylesheets
                        .iter()
                        .map(|(_, _, css, _, _, _)| css.as_str())
                        .collect::<Vec<_>>()
                        .join("\n");
                    let code = format!(
                        "globalThis.__obscura_css = `{}`;",
                        escape_for_js_template_literal(&combined_css),
                    );
                    if let Err(error) = realm.execute_script(js, &code) {
                        tracing::debug!("frame {} CSS setup failed: {error}", frame.url);
                    }
                    for (_, link_nid, css, is_parser_owner, raw_href, request_href) in &stylesheets
                    {
                        let completion = if let Some(raw_href) = raw_href.as_deref() {
                            materialize_parser_stylesheet_script_with_token(
                                *link_nid,
                                css,
                                request_href,
                                raw_href,
                            )
                        } else {
                            materialize_parser_stylesheet_script(*link_nid, css)
                        };
                        if *is_parser_owner {
                            parser_stylesheet_events.insert(*link_nid, completion);
                        } else if let Err(error) = realm.execute_script(js, &completion) {
                            tracing::debug!(
                                "frame {} inline import materialization failed: {error}",
                                frame.url,
                            );
                        }
                    }
                }
                for problem in realm.run_document_scripts_with_stylesheet_events(
                    js,
                    |url| sources.get(url).cloned(),
                    parser_stylesheet_events,
                ) {
                    tracing::debug!("frame {}: {}", frame.url, problem);
                }
                // Parsing and parser scripts are complete, but descendant
                // frames and load-delaying dynamic resources still gate load.
                realm.dispatch_dom_content_loaded(js)
            } else {
                Err("JavaScript runtime disappeared".to_string())
            };
            let watchdog_fired = match (self.js.as_mut(), lifecycle_watchdog) {
                (Some(js), Some(watchdog)) => js.disarm_watchdog(watchdog),
                _ => false,
            };
            if watchdog_fired || lifecycle_result.is_err() {
                tracing::warn!(
                    "frame {} parser lifecycle failed: {}",
                    frame.url,
                    lifecycle_result
                        .err()
                        .unwrap_or_else(|| "lifecycle task budget exceeded".to_string()),
                );
                realm.mark_load_failed();
                self.top_load_pending = false;
                self.lifecycle = LifecycleState::Failed;
            }
            let publish_watchdog = self.js.as_mut().map(|js| {
                js.arm_watchdog(std::time::Duration::from_millis(
                    LIFECYCLE_CALLBACK_WATCHDOG_MS,
                ))
            });
            let published = self
                .js
                .as_mut()
                .is_some_and(|js| realm.publish_to_owners(js));
            let publish_watchdog_fired = match (self.js.as_mut(), publish_watchdog) {
                (Some(js), Some(watchdog)) => js.disarm_watchdog(watchdog),
                _ => false,
            };
            if publish_watchdog_fired || !published {
                tracing::warn!("frame {} realm publication failed", frame.url);
                if let Some(js) = self.js.as_ref() {
                    js.cancel_frame_documents_owned_by(&[realm.frame_id()]);
                }
                self.forget_frame_references(realm.frame_id(), realm.parent_frame_id());
                self.top_load_pending = false;
                self.lifecycle = LifecycleState::Failed;
                pending.finish_current();
                continue;
            }
            self.frames.push(realm);
            pending.finish_current();
        }
        true
    }

    /// Hands each queued `postMessage` to the realm it was addressed to.
    ///
    /// Reports whether anything was delivered, because a message usually causes
    /// a reply: a widget posts its result, the page answers, and the exchange
    /// only finishes if the caller settles and drains again.
    fn deliver_frame_messages(&mut self) -> bool {
        let pending = match self.js.as_ref() {
            Some(js) => js.take_pending_frame_messages(),
            None => return false,
        };
        if pending.is_empty() {
            return false;
        }

        let mut retry = Vec::new();
        for message in pending {
            let escaped_data = serde_json::to_string(&message.data_json).unwrap_or_default();
            let escaped_origin = serde_json::to_string(&message.origin).unwrap_or_default();
            if message.target_frame_id == 0 {
                let watchdog = self.js.as_mut().map(|js| {
                    js.arm_watchdog(std::time::Duration::from_millis(
                        LIFECYCLE_CALLBACK_WATCHDOG_MS,
                    ))
                });
                let Some(js) = self.js.as_mut() else { continue };
                let script = format!(
                    "globalThis.__obscura_deliverMessage({escaped_data}, {escaped_origin}, {});",
                    message.source_frame_id,
                );
                let result = js.execute_script("<frame-message>", &script);
                let watchdog_fired = match (self.js.as_mut(), watchdog) {
                    (Some(js), Some(watchdog)) => js.disarm_watchdog(watchdog),
                    _ => false,
                };
                if watchdog_fired || result.is_err() {
                    let error = result
                        .err()
                        .unwrap_or_else(|| "message handler task budget exceeded".to_string());
                    tracing::debug!("message to the page failed: {error}");
                    self.top_load_pending = false;
                    self.lifecycle = LifecycleState::Failed;
                    break;
                }
                continue;
            }

            let Some(index) = self
                .frames
                .iter()
                .position(|frame| frame.frame_id() == message.target_frame_id)
            else {
                // A parent parser script can post to a child it just created.
                // Its fetched document is queued during this same attachment
                // pass and receives a realm on the next pass; retain that
                // message rather than mistaking the not-yet-attached target
                // for a browsing context which was torn down.
                if self
                    .js
                    .as_ref()
                    .is_some_and(|js| js.frame_document_is_pending(message.target_frame_id))
                {
                    retry.push(message);
                } else {
                    tracing::debug!(
                        "message for frame {} which is gone",
                        message.target_frame_id
                    );
                }
                continue;
            };
            let watchdog = self.js.as_mut().map(|js| {
                js.arm_watchdog(std::time::Duration::from_millis(
                    LIFECYCLE_CALLBACK_WATCHDOG_MS,
                ))
            });
            let Some(js) = self.js.as_mut() else { continue };
            let result = self.frames[index].deliver_message(
                js,
                &message.data_json,
                &message.origin,
                message.source_frame_id,
            );
            let watchdog_fired = match (self.js.as_mut(), watchdog) {
                (Some(js), Some(watchdog)) => js.disarm_watchdog(watchdog),
                _ => false,
            };
            if watchdog_fired || result.is_err() {
                let error = result
                    .err()
                    .unwrap_or_else(|| "message handler task budget exceeded".to_string());
                tracing::debug!(
                    "message to frame {} failed: {error}",
                    message.target_frame_id
                );
                self.frames[index].mark_load_failed();
                self.top_load_pending = false;
                self.lifecycle = LifecycleState::Failed;
                break;
            }
        }
        if !retry.is_empty() {
            if let Some(js) = self.js.as_ref() {
                js.restore_pending_frame_messages(retry);
            }
        }
        true
    }

    /// Removes the JS references owned by the iframe's parent realm and by the
    /// page's same-origin frame table. This also covers a frame rejected before
    /// a `FrameRealm` exists, so the normal drop path cannot be skipped.
    fn forget_frame_references(&mut self, frame_id: u32, parent_frame_id: u32) {
        let script = format!("globalThis.__obscura_forgetFrame({frame_id});");
        let watchdog = self.js.as_mut().map(|js| {
            js.arm_watchdog(std::time::Duration::from_millis(
                LIFECYCLE_CALLBACK_WATCHDOG_MS,
            ))
        });
        let owner_result = self.execute_frame_owner_script(parent_frame_id, &script);
        let watchdog_fired = match (self.js.as_mut(), watchdog) {
            (Some(js), Some(watchdog)) => js.disarm_watchdog(watchdog),
            _ => false,
        };
        if watchdog_fired {
            self.top_load_pending = false;
            self.lifecycle = LifecycleState::Failed;
        } else if let Err(error) = owner_result {
            tracing::debug!("releasing owner references for frame {frame_id} failed: {error}");
        }
        if parent_frame_id != 0 {
            let page_script = format!("globalThis.__obscura_forgetFrame({frame_id});");
            if let Some(js) = self.js.as_mut() {
                if let Err(error) = js.execute_script("<frame-detach>", &page_script) {
                    tracing::debug!("releasing page frame reference failed: {error}");
                }
            }
        }
    }

    /// Executes cleanup in the realm that owns the iframe element. Nested
    /// iframe registries live in their parent frame, not in the page realm.
    fn execute_frame_owner_script(
        &mut self,
        parent_frame_id: u32,
        script: &str,
    ) -> Result<(), String> {
        if parent_frame_id == 0 {
            return self
                .js
                .as_mut()
                .ok_or_else(|| "JavaScript runtime disappeared".to_string())?
                .execute_script("<frame-owner>", script);
        }

        let Some(index) = self
            .frames
            .iter()
            .position(|frame| frame.frame_id() == parent_frame_id)
        else {
            return Err(format!("frame owner realm {parent_frame_id} disappeared"));
        };
        let js = self
            .js
            .as_mut()
            .ok_or_else(|| "JavaScript runtime disappeared".to_string())?;
        self.frames[index].execute_script(js, script)
    }

    fn evaluate_lifecycle_probe(
        &mut self,
        realm_frame_id: Option<u32>,
        expression: &str,
    ) -> Result<serde_json::Value, String> {
        if self.js.is_none() {
            return Err("JavaScript runtime disappeared".to_string());
        }
        let realm_index = match realm_frame_id {
            Some(frame_id) => Some(
                self.frames
                    .iter()
                    .position(|frame| frame.frame_id() == frame_id)
                    .ok_or_else(|| format!("frame owner realm {frame_id} disappeared"))?,
            ),
            None => None,
        };
        let watchdog = self
            .js
            .as_mut()
            .unwrap()
            .arm_watchdog(std::time::Duration::from_millis(
                LIFECYCLE_CALLBACK_WATCHDOG_MS,
            ));
        let result = if let Some(index) = realm_index {
            self.frames[index].evaluate(self.js.as_mut().unwrap(), expression)
        } else {
            self.js.as_mut().unwrap().evaluate_host_probe(expression)
        };
        let fired = self
            .js
            .as_mut()
            .is_some_and(|js| js.disarm_watchdog(watchdog));
        if fired {
            self.top_load_pending = false;
            self.lifecycle = LifecycleState::Failed;
            return Err("lifecycle probe task budget exceeded".to_string());
        }
        result
    }

    fn direct_frame_owner_is_live(
        &mut self,
        parent_frame_id: u32,
        frame_id: u32,
    ) -> Result<bool, String> {
        let expression = format!("globalThis.__obscura_frameOwnerIsLive({frame_id})");
        let value = self.evaluate_lifecycle_probe(
            (parent_frame_id != 0).then_some(parent_frame_id),
            &expression,
        )?;
        value.as_bool().ok_or_else(|| {
            format!("frame owner liveness probe in realm {parent_frame_id} returned a non-boolean")
        })
    }

    fn frame_owner_is_live(
        &mut self,
        mut parent_frame_id: u32,
        mut frame_id: u32,
    ) -> Result<bool, String> {
        loop {
            if !self.direct_frame_owner_is_live(parent_frame_id, frame_id)? {
                return Ok(false);
            }
            if parent_frame_id == 0 {
                return Ok(true);
            }
            let Some(parent) = self
                .frames
                .iter()
                .find(|frame| frame.frame_id() == parent_frame_id)
            else {
                return Ok(false);
            };
            frame_id = parent_frame_id;
            parent_frame_id = parent.parent_frame_id();
        }
    }

    fn dispatch_frame_owner_load(&mut self, parent_frame_id: u32, frame_id: u32) {
        let watchdog = self.js.as_mut().map(|js| {
            js.arm_watchdog(std::time::Duration::from_millis(
                LIFECYCLE_CALLBACK_WATCHDOG_MS,
            ))
        });
        let dispatch_result = self.execute_frame_owner_script(
            parent_frame_id,
            &format!(
                "if (typeof globalThis.__obscura_dispatchFrameOwnerLoad === 'function') \
                 globalThis.__obscura_dispatchFrameOwnerLoad({frame_id});"
            ),
        );
        let watchdog_fired = match (self.js.as_mut(), watchdog) {
            (Some(js), Some(watchdog)) => js.disarm_watchdog(watchdog),
            _ => false,
        };
        if watchdog_fired || dispatch_result.is_err() {
            tracing::warn!(
                "iframe owner load dispatch failed: {}",
                dispatch_result
                    .err()
                    .unwrap_or_else(|| "lifecycle task budget exceeded".to_string()),
            );
            if parent_frame_id != 0 {
                if let Some(parent) = self
                    .frames
                    .iter()
                    .find(|frame| frame.frame_id() == parent_frame_id)
                {
                    parent.mark_load_failed();
                }
            }
            self.top_load_pending = false;
            self.lifecycle = LifecycleState::Failed;
        }
    }

    /// Discards the realms whose iframe element has left the document.
    ///
    /// A browser discards a child browsing context when its element is
    /// removed: the document and its context are torn down. Nothing here can
    /// be collected on its own, because the page realm holds each frame's
    /// window and document so that `contentWindow` can be the frame's real
    /// object, so a page that replaces an iframe repeatedly would otherwise
    /// accumulate contexts and DOM trees for the life of the document.
    ///
    /// A detached parent discards its complete browsing-context subtree in the
    /// same pass, before a descendant can be mistaken for a load candidate.
    fn release_detached_frames(&mut self) -> bool {
        self.release_detached_frames_with_probe("__obscura_liveFrameIds()")
    }

    fn release_detached_frames_with_probe(&mut self, live_frame_ids_probe: &str) -> bool {
        if self.frames.is_empty() {
            return false;
        }
        // Each realm reports its own frames whose element is still connected.
        // Liveness is asked of the element rather than of a document query,
        // because an iframe inside a shadow root is absent from
        // `document.querySelectorAll('iframe')` — the shape a challenge widget
        // uses — and treating it as detached tears down a live frame.
        let mut live: Vec<u32> = Vec::new();
        match self.evaluate_lifecycle_probe(None, live_frame_ids_probe) {
            Ok(value) => match serde_json::from_value::<Vec<u32>>(value) {
                Ok(ids) => live.extend(ids),
                Err(error) => {
                    tracing::warn!("page live-frame probe returned an invalid value: {error}");
                    self.top_load_pending = false;
                    self.lifecycle = LifecycleState::Failed;
                    return false;
                }
            },
            Err(error) => {
                tracing::warn!("could not list the page's live frames: {error}");
                self.top_load_pending = false;
                self.lifecycle = LifecycleState::Failed;
                return false;
            }
        }
        // A frame's own children are in that frame's document, not the page's.
        for index in 0..self.frames.len() {
            let frame_id = self.frames[index].frame_id();
            match self.evaluate_lifecycle_probe(Some(frame_id), live_frame_ids_probe) {
                Ok(value) => match serde_json::from_value::<Vec<u32>>(value) {
                    Ok(ids) => live.extend(ids),
                    Err(error) => {
                        tracing::warn!(
                            "frame {frame_id} live-frame probe returned an invalid value: {error}"
                        );
                        self.frames[index].mark_load_failed();
                        self.top_load_pending = false;
                        self.lifecycle = LifecycleState::Failed;
                        return false;
                    }
                },
                Err(error) => {
                    tracing::warn!("could not list frame {frame_id}'s live frames: {error}");
                    self.frames[index].mark_load_failed();
                    self.top_load_pending = false;
                    self.lifecycle = LifecycleState::Failed;
                    return false;
                }
            }
        }

        let reported_live = live.into_iter().collect::<std::collections::HashSet<_>>();
        let mut retained = std::collections::HashSet::new();
        loop {
            let before = retained.len();
            for frame in &self.frames {
                if reported_live.contains(&frame.frame_id())
                    && (frame.parent_frame_id() == 0 || retained.contains(&frame.parent_frame_id()))
                {
                    retained.insert(frame.frame_id());
                }
            }
            if retained.len() == before {
                break;
            }
        }

        let discarded: Vec<(u32, u32)> = self
            .frames
            .iter()
            .map(|frame| (frame.frame_id(), frame.parent_frame_id()))
            .filter(|(id, _)| !retained.contains(id))
            .collect();
        if discarded.is_empty() {
            return false;
        }

        let discarded_ids = discarded
            .iter()
            .map(|(frame_id, _)| *frame_id)
            .collect::<Vec<_>>();
        if let Some(js) = self.js.as_ref() {
            js.cancel_frame_documents_owned_by(&discarded_ids);
        }

        // Clean owner realms before dropping any parent. This matters for a
        // nested child whose iframe registry lives in a parent that is also
        // being removed during this pass.
        for &(frame_id, parent_frame_id) in &discarded {
            self.forget_frame_references(frame_id, parent_frame_id);
        }
        self.frames
            .retain(|frame| retained.contains(&frame.frame_id()));
        tracing::debug!("discarded {} detached frame realm(s)", discarded.len());
        true
    }

    /// Complete child documents from the leaves upward. A frame's Window load
    /// precedes the load event on its owner iframe element, and an ancestor
    /// remains blocked while any direct descendant or queued child document is
    /// unfinished.
    fn complete_ready_frames(&mut self) -> bool {
        let mut progressed = false;
        loop {
            let blockers = self
                .js
                .as_ref()
                .map(ObscuraJsRuntime::frame_document_load_blockers_by_parent)
                .unwrap_or_default();
            let candidates = self
                .frames
                .iter()
                .filter(|frame| {
                    frame.lifecycle_state() == FrameLifecycleState::DomContentLoaded
                        && blockers.get(&frame.frame_id()).copied().unwrap_or(0) == 0
                        && !self.frames.iter().any(|child| {
                            child.parent_frame_id() == frame.frame_id() && !child.is_load_complete()
                        })
                })
                .map(|frame| frame.frame_id())
                .collect::<Vec<_>>();
            if candidates.is_empty() {
                break;
            }

            let mut completed_this_pass = false;
            for frame_id in candidates {
                let Some(index) = self
                    .frames
                    .iter()
                    .position(|frame| frame.frame_id() == frame_id)
                else {
                    continue;
                };
                let parent_frame_id = self.frames[index].parent_frame_id();
                match self.frame_owner_is_live(parent_frame_id, frame_id) {
                    Ok(true) => {}
                    Ok(false) => {
                        self.release_detached_frames();
                        completed_this_pass = true;
                        progressed = true;
                        continue;
                    }
                    Err(error) => {
                        self.frames[index].mark_load_failed();
                        self.top_load_pending = false;
                        self.lifecycle = LifecycleState::Failed;
                        tracing::warn!(
                            "could not verify owner liveness for frame {frame_id}: {error}"
                        );
                        return true;
                    }
                }
                let pending_resources = match self.js.as_mut() {
                    Some(js) => self.frames[index].has_pending_load_delaying_resources(js),
                    None => true,
                };
                if pending_resources {
                    continue;
                }
                let watchdog = self.js.as_mut().map(|js| {
                    js.arm_watchdog(std::time::Duration::from_millis(
                        LIFECYCLE_CALLBACK_WATCHDOG_MS,
                    ))
                });
                let result = match self.js.as_mut() {
                    Some(js) => self.frames[index].dispatch_load(js),
                    None => Err("JavaScript runtime disappeared".to_string()),
                };
                let watchdog_fired = match (self.js.as_mut(), watchdog) {
                    (Some(js), Some(watchdog)) => js.disarm_watchdog(watchdog),
                    _ => false,
                };
                if watchdog_fired {
                    self.frames[index].mark_load_failed();
                    self.top_load_pending = false;
                    self.lifecycle = LifecycleState::Failed;
                    tracing::warn!(
                        "frame {frame_id} load handler exceeded the lifecycle task budget"
                    );
                    return true;
                }
                if let Err(error) = result {
                    self.frames[index].mark_load_failed();
                    self.top_load_pending = false;
                    self.lifecycle = LifecycleState::Failed;
                    tracing::warn!("frame {frame_id} load events failed: {error}");
                    return true;
                }

                // A frame's own Window.load can synchronously remove its
                // iframe, an ancestor owner, or a later sibling. Do not follow
                // it with a stale owner-element load dispatch.
                match self.frame_owner_is_live(parent_frame_id, frame_id) {
                    Ok(true) => {}
                    Ok(false) => {
                        self.release_detached_frames();
                        completed_this_pass = true;
                        progressed = true;
                        continue;
                    }
                    Err(error) => {
                        self.frames[index].mark_load_failed();
                        self.top_load_pending = false;
                        self.lifecycle = LifecycleState::Failed;
                        tracing::warn!(
                            "could not revalidate owner liveness for frame {frame_id}: {error}"
                        );
                        return true;
                    }
                }
                self.dispatch_frame_owner_load(parent_frame_id, frame_id);
                completed_this_pass = true;
                progressed = true;
            }
            if !completed_this_pass {
                break;
            }
        }
        progressed
    }

    fn try_dispatch_top_load(&mut self) -> bool {
        if !self.top_load_pending {
            return false;
        }
        let frame_blocked = self.js.as_ref().is_some_and(|js| {
            js.frame_document_load_blockers_by_parent()
                .get(&0)
                .copied()
                .unwrap_or(0)
                != 0
        });
        if frame_blocked
            || self
                .frames
                .iter()
                .any(|frame| frame.parent_frame_id() == 0 && !frame.is_load_complete())
        {
            return false;
        }
        let resource_blocked = self
            .js
            .as_mut()
            .is_some_and(ObscuraJsRuntime::has_pending_load_delaying_resources);
        if resource_blocked {
            return false;
        }

        let watchdog = self.js.as_mut().map(|js| {
            js.arm_watchdog(std::time::Duration::from_millis(
                LIFECYCLE_CALLBACK_WATCHDOG_MS,
            ))
        });
        let result = self.js.as_mut().map(|js| {
            js.execute_script(
                "<load-event>",
                "globalThis.__documentReadyState__ = 'complete';\
                 try { globalThis.__obscura_dispatchDocumentLifecycleEvent('readystatechange'); } catch (_) {}\
                 try { globalThis.__obscura_dispatchWindowLoad(); } catch (_) {}",
            )
        });
        let watchdog_fired = match (self.js.as_mut(), watchdog) {
            (Some(js), Some(watchdog)) => js.disarm_watchdog(watchdog),
            _ => false,
        };
        if watchdog_fired {
            tracing::warn!("top-level load handler exceeded the lifecycle task budget");
            self.top_load_pending = false;
            self.lifecycle = LifecycleState::Failed;
            return true;
        }
        if !matches!(result, Some(Ok(()))) {
            tracing::warn!("top document load event dispatch failed: {result:?}");
            self.top_load_pending = false;
            self.lifecycle = LifecycleState::Failed;
            return true;
        }
        self.top_load_pending = false;
        self.lifecycle = LifecycleState::Loaded;
        true
    }

    /// Moves the frame tree forward by one step: give any fetched frame
    /// document a realm, then hand on any message waiting for a realm.
    ///
    /// Reports whether anything happened, so a caller can pump again. A new
    /// frame runs scripts that can post, and a message usually causes a reply,
    /// so neither queue is finished until both are quiet.
    async fn advance_frames(&mut self) -> bool {
        // A timer or earlier browser task may have removed a complete parent
        // browsing-context subtree. Release it before taking the pending
        // document snapshot, so queued descendants cannot execute in a realm
        // whose direct owner still looks connected only inside that detached
        // parent's private document.
        let released_before = self.release_detached_frames();
        let attached = self.attach_pending_frames().await;
        let delivered = self.deliver_frame_messages();
        let released_after = self.release_detached_frames();
        let completed = self.complete_ready_frames();
        let top_loaded = self.try_dispatch_top_load();
        released_before || attached || delivered || released_after || completed || top_loaded
    }

    /// URLs of the page's live child frames, in creation order.
    pub fn frame_urls(&self) -> Vec<String> {
        self.frames
            .iter()
            .map(|frame| frame.url().to_string())
            .collect()
    }

    /// Snapshot the native ids and final document URLs of live child frames in
    /// creation order. Unlike deriving ids from vector positions, these ids
    /// remain correct after frames are detached or nested frames are attached.
    pub fn frame_snapshots(&self) -> Vec<FrameSnapshot> {
        self.frames
            .iter()
            .map(|frame| FrameSnapshot {
                frame_id: frame.frame_id(),
                url: frame.url().to_string(),
            })
            .collect()
    }

    /// Report live frames whose resource set is known to be incomplete.
    pub fn frame_resource_diagnostics(&mut self) -> Vec<FrameResourceDiagnostic> {
        let diagnostics = {
            let Some(js) = self.js.as_mut() else {
                return Vec::new();
            };
            self.frames
                .iter()
                .filter_map(|frame| {
                    let pending_navigation_url = frame.pending_navigation_url();
                    match frame.resource_archive_probe(js) {
                        Ok(probe) => {
                            let unsupported_stylesheet_imports = probe
                                .style_sources
                                .iter()
                                .map(|css| split_css_imports(css).0.len())
                                .sum();
                            (probe.unsupported_module_scripts > 0
                                || unsupported_stylesheet_imports > 0
                                || pending_navigation_url.is_some()
                                || probe.pending_dynamic_scripts)
                                .then(|| FrameResourceDiagnostic {
                                    frame_id: frame.frame_id(),
                                    url: frame.url().to_string(),
                                    unsupported_module_scripts: probe.unsupported_module_scripts,
                                    unsupported_stylesheet_imports,
                                    pending_navigation_url,
                                    pending_dynamic_scripts: probe.pending_dynamic_scripts,
                                    diagnostic_error: None,
                                })
                        }
                        Err(error) => Some(FrameResourceDiagnostic {
                            frame_id: frame.frame_id(),
                            url: frame.url().to_string(),
                            unsupported_module_scripts: 0,
                            unsupported_stylesheet_imports: 0,
                            pending_navigation_url,
                            pending_dynamic_scripts: false,
                            diagnostic_error: Some(error),
                        }),
                    }
                })
                .collect::<Vec<_>>()
        };
        for diagnostic in &diagnostics {
            if diagnostic.diagnostic_error.is_some() {
                self.mark_resource_archive_incomplete(format!(
                    "frame resource diagnostic failed for frame {} ({})",
                    diagnostic.frame_id, diagnostic.url,
                ));
            }
        }
        diagnostics
    }

    /// De-duplicated, sorted human-readable reasons the current final-document
    /// resource archive must not claim completeness. The text is diagnostic,
    /// not a versioned machine-readable schema. The set resets at every
    /// committed top-level document, including JavaScript navigation chains.
    pub fn resource_archive_incomplete_reasons(&mut self) -> Vec<String> {
        let frame_diagnostics = self.frame_resource_diagnostics();
        let mut reasons = self.resource_archive_incomplete_reasons.clone();
        if let Some(js) = self.js.as_ref() {
            reasons.extend(js.resource_archive_incomplete_reasons());
            #[cfg(feature = "render")]
            {
                let import_count = js
                    .shadow_inline_stylesheet_sources()
                    .iter()
                    .map(|css| split_css_imports(css).0.len())
                    .sum::<usize>();
                if import_count != 0 {
                    reasons.insert(format!(
                        "top-level shadow-root inline stylesheets contain {import_count} unsupported @import rule(s)",
                    ));
                }
            }
            #[cfg(feature = "render")]
            for href in js.unresolved_shadow_stylesheet_hrefs() {
                reasons.insert(format!(
                    "top-level shadow-root stylesheet has no materialized response owner: {href}",
                ));
            }
            let (documents, bytes) = js.pending_frame_document_queue();
            if documents != 0 {
                reasons.insert(format!(
                    "pending frame documents awaiting realms: {documents} documents, {bytes} bytes"
                ));
            }
            let (messages, bytes) = js.pending_frame_message_queue();
            if messages != 0 {
                reasons.insert(format!(
                    "pending frame postMessage deliveries: {messages} message(s), {bytes} bytes"
                ));
            }
        }
        let pending_network_requests = self.pending_network_request_count();
        if pending_network_requests != 0 {
            reasons.insert(format!(
                "pending page network requests: {pending_network_requests}"
            ));
        }
        if self.has_pending_top_level_dynamic_scripts() {
            reasons.insert("top-level dynamic scripts still pending".to_string());
        }
        #[cfg(feature = "render")]
        for frame in &self.frames {
            let import_count = frame
                .shadow_inline_stylesheet_sources()
                .iter()
                .map(|css| split_css_imports(css).0.len())
                .sum::<usize>();
            if import_count != 0 {
                reasons.insert(format!(
                    "frame {} shadow-root inline stylesheets contain {import_count} unsupported @import rule(s)",
                    frame.frame_id(),
                ));
            }
            for href in frame.unresolved_shadow_stylesheet_hrefs() {
                reasons.insert(format!(
                    "frame {} shadow-root stylesheet has no materialized response owner: {href}",
                    frame.frame_id(),
                ));
            }
        }
        for diagnostic in frame_diagnostics {
            if diagnostic.unsupported_module_scripts != 0 {
                reasons.insert(format!(
                    "frame {} ({}) has {} unsupported module scripts",
                    diagnostic.frame_id, diagnostic.url, diagnostic.unsupported_module_scripts,
                ));
            }
            if diagnostic.unsupported_stylesheet_imports != 0 {
                reasons.insert(format!(
                    "frame {} ({}) has {} unsupported stylesheet imports",
                    diagnostic.frame_id, diagnostic.url, diagnostic.unsupported_stylesheet_imports,
                ));
            }
            if let Some(target) = diagnostic.pending_navigation_url {
                reasons.insert(format!(
                    "frame {} ({}) has a pending navigation to {}",
                    diagnostic.frame_id, diagnostic.url, target,
                ));
            }
            if diagnostic.pending_dynamic_scripts {
                reasons.insert(format!(
                    "frame {} ({}) has dynamic scripts still pending",
                    diagnostic.frame_id, diagnostic.url,
                ));
            }
        }
        reasons.into_iter().collect()
    }

    /// Page-wide count of network operations still awaiting a response or
    /// error. Child frames share the same counter, so zero is required before
    /// a byte-exact resource archive can truthfully claim completeness.
    pub fn pending_network_request_count(&self) -> u32 {
        self.js
            .as_ref()
            .map(ObscuraJsRuntime::pending_network_request_count)
            .unwrap_or(0)
    }

    /// Whether the top-level document still has dynamically inserted scripts
    /// queued, fetching, or evaluating.
    pub fn has_pending_top_level_dynamic_scripts(&mut self) -> bool {
        self.js
            .as_mut()
            .is_some_and(ObscuraJsRuntime::has_pending_dynamic_scripts)
    }

    /// Resource work which can still add response bodies to the current
    /// document generation. This deliberately includes every child realm's
    /// private dynamic-script queue, cross-realm message deliveries, and the
    /// shared network counter.
    pub fn has_pending_resource_work(&mut self) -> bool {
        if self.pending_network_request_count() != 0
            || self.has_pending_top_level_dynamic_scripts()
            || self
                .js
                .as_ref()
                .is_some_and(|js| js.pending_frame_message_queue().0 != 0)
            || self
                .js
                .as_ref()
                .is_some_and(|js| js.pending_frame_document_queue().0 != 0)
        {
            return true;
        }
        let Some(js) = self.js.as_mut() else {
            return false;
        };
        self.frames
            .iter()
            .any(|frame| frame.has_pending_dynamic_scripts(js))
    }

    /// Evaluates an expression inside one of the page's child frames.
    pub fn evaluate_in_frame(
        &mut self,
        index: usize,
        expression: &str,
    ) -> Result<serde_json::Value, String> {
        let realm = self.frames.get(index).ok_or("no such frame")?;
        let js = self.js.as_mut().ok_or("no runtime")?;
        realm.evaluate(js, expression)
    }

    /// Update the page's CSS viewport. Calling this before navigation makes
    /// responsive scripts observe it from their first instruction; calling it
    /// on a live page mirrors CDP's device-metrics override surfaces.
    pub fn set_viewport(&mut self, viewport: (f32, f32)) {
        if !viewport.0.is_finite()
            || !viewport.1.is_finite()
            || viewport.0 <= 0.0
            || viewport.1 <= 0.0
        {
            return;
        }
        self.viewport = viewport;
        if let Some(js) = &mut self.js {
            js.set_viewport(viewport.0 as f64, viewport.1 as f64);
        }
    }

    /// Set or clear the CDP physical-screen override independently of layout.
    pub fn set_screen_size_override(&mut self, size: Option<(f32, f32)>, emulated: bool) {
        self.screen_size_override = size.filter(|(width, height)| {
            width.is_finite() && height.is_finite() && *width > 0.0 && *height > 0.0
        });
        self.screen_metrics_emulated = emulated;
        if let Some(js) = &mut self.js {
            js.set_screen_size_override(
                self.screen_size_override
                    .map(|(width, height)| (width as f64, height as f64)),
                self.screen_metrics_emulated,
            );
        }
    }

    /// Apply CDP device metrics relative to the metrics that were active when
    /// emulation was first enabled. A zero protocol dimension/scale is passed
    /// as `None` and therefore restores that axis from the retained baseline.
    pub fn apply_device_metrics_override(
        &mut self,
        width: Option<f32>,
        height: Option<f32>,
        device_scale_factor: Option<f32>,
        screen_size: Option<(f32, f32)>,
        mobile: bool,
    ) {
        let baseline = *self
            .device_metrics_baseline
            .get_or_insert(DeviceMetricsBaseline {
                viewport: self.viewport,
                device_scale_factor: self.device_scale_factor,
            });
        let viewport = (
            width.unwrap_or(baseline.viewport.0),
            height.unwrap_or(baseline.viewport.1),
        );
        self.set_viewport(viewport);

        // Blink uses the effective widget size as the screen size for mobile
        // emulation when no complete explicit screen size was supplied.
        let effective_screen_size = screen_size.or_else(|| mobile.then_some(viewport));
        self.set_screen_size_override(effective_screen_size, true);
        self.set_device_scale_factor(device_scale_factor.unwrap_or(baseline.device_scale_factor));
    }

    /// Disable CDP device metrics and restore the state captured by the first
    /// override. Clearing while emulation is inactive is intentionally a no-op.
    pub fn clear_device_metrics_override(&mut self) {
        let Some(baseline) = self.device_metrics_baseline.take() else {
            return;
        };
        self.set_viewport(baseline.viewport);
        self.set_screen_size_override(None, false);
        self.set_device_scale_factor(baseline.device_scale_factor);
    }

    /// Set the screenshot surface density without changing CSS layout. CDP
    /// uses zero to disable its override, which restores the native 1x surface
    /// in Obscura's headless-only model.
    pub fn set_device_scale_factor(&mut self, device_scale_factor: f32) {
        if !device_scale_factor.is_finite() || device_scale_factor < 0.0 {
            return;
        }
        self.device_scale_factor = if device_scale_factor == 0.0 {
            1.0
        } else {
            device_scale_factor
        };
        if let Some(js) = &mut self.js {
            let _ = js.execute_script(
                "<device-metrics>",
                &format!("globalThis.devicePixelRatio={};", self.device_scale_factor),
            );
        }
    }

    pub fn set_default_background_color_override(&mut self, color: Option<[u8; 4]>) {
        self.default_background_color_override = color;
    }

    #[cfg(feature = "render")]
    fn capture_surface_color(&self) -> [u8; 4] {
        self.default_background_color_override
            .unwrap_or([255, 255, 255, 255])
    }

    async fn do_fetch(&self, url: &Url) -> Result<Response, ObscuraNetError> {
        self.do_fetch_resource(url, ResourceRequest::navigation())
            .await
    }

    async fn do_fetch_resource(
        &self,
        url: &Url,
        request: ResourceRequest,
    ) -> Result<Response, ObscuraNetError> {
        #[cfg(feature = "stealth")]
        if let Some(ref stealth) = self.stealth_client {
            return stealth
                .fetch_resource_with_callbacks(url, request, Some(&self.callbacks))
                .await;
        }
        self.http_client
            .fetch_resource_with_callbacks(url, request, Some(&self.callbacks))
            .await
    }
    fn init_js(&mut self) {
        // init_js is also the new-document path.  Only resume_js explicitly
        // takes these IDs out before entering here and restores them after the
        // same DomTree is installed; a navigation must never inherit IDs from
        // a suspended prior document whose allocator may reuse them.
        self.suspended_started_script_ids.clear();
        // Drop any existing runtime so the JS realm starts clean on
        // every navigation. The old code reused the V8 isolate and
        // only re-bound `globalThis.document`, leaving window.onload,
        // custom window properties and event handlers from the prior
        // page in place. That made it possible for a page to set
        // attacker-controlled state, trigger a navigation, and then
        // run code in the next document's context.
        if self.js.is_some() {
            // Every frame realm holds a V8 handle into this isolate, so the
            // frames of the outgoing document must go before the runtime does.
            self.frames.clear();
            let _ = self.js.take();
        }

        // Thread the BrowserContext's proxy through to the ES-module loader
        // and op_fetch_url so dynamic imports and JS fetch() honour the
        // configured upstream proxy (#139). When proxy_url is None this is
        // equivalent to with_base_url() (direct connection).
        let mut rt = ObscuraJsRuntime::with_base_url_and_proxy(
            &self.url_string(),
            self.context.proxy_url.clone(),
        );
        rt.set_url(&self.url_string());
        rt.set_encoding(&self.encoding);
        rt.set_title(&self.title);
        rt.set_referrer(&self.referrer);

        #[cfg(feature = "stealth")]
        if self.stealth_client.is_some() {
            rt.set_stealth(true);
            rt.set_user_agent(obscura_net::STEALTH_USER_AGENT);
            rt.set_platform(
                obscura_net::STEALTH_NAVIGATOR_PLATFORM,
                obscura_net::STEALTH_UA_PLATFORM,
                obscura_net::STEALTH_UA_PLATFORM_VERSION,
            );
        } else {
            if let Ok(ua) = self.http_client.user_agent.try_read() {
                rt.set_user_agent(&ua);
            }
            rt.set_platform(
                &self.context.platform,
                &self.context.ua_platform,
                &self.context.ua_platform_version,
            );
        }
        #[cfg(not(feature = "stealth"))]
        {
            if let Ok(ua) = self.http_client.user_agent.try_read() {
                rt.set_user_agent(&ua);
            }
            rt.set_platform(
                &self.context.platform,
                &self.context.ua_platform,
                &self.context.ua_platform_version,
            );
        }
        if let Some((lat, lon)) = env_geolocation() {
            rt.set_geolocation(lat, lon);
        }
        rt.set_viewport(self.viewport.0 as f64, self.viewport.1 as f64);
        rt.set_screen_size_override(
            self.screen_size_override
                .map(|(width, height)| (width as f64, height as f64)),
            self.screen_metrics_emulated,
        );

        rt.set_cookie_jar(self.context.cookie_jar.clone());
        rt.set_http_client(self.http_client.clone());
        rt.set_callbacks(self.callbacks.clone());
        rt.set_blocked_urls(self.blocked_url_patterns.clone());
        #[cfg(feature = "stealth")]
        if let Some(ref stealth) = self.stealth_client {
            rt.set_stealth_client(stealth.clone());
        }

        if let Some(tx) = &self.intercept_tx {
            rt.set_intercept_tx(tx.clone());
        }
        // Re-apply intercept_enabled: enable_interception()/enable_intercept()
        // called before the first navigation sets this on the Page while the
        // runtime does not exist yet, so the new runtime would otherwise start
        // with interception disabled and op_fetch_url would never intercept.
        rt.set_intercept_enabled(self.intercept_enabled);

        if let Some(dom) = self.dom.take() {
            rt.set_dom(dom);
        }

        rt.run_page_init();
        for name in &self.preload_bindings {
            if let Err(error) = rt.install_cdp_binding(name) {
                tracing::debug!("binding {name} setup failed: {error}");
            }
        }
        let _ = rt.execute_script(
            "<device-metrics>",
            &format!("globalThis.devicePixelRatio={};", self.device_scale_factor),
        );

        self.js = Some(rt);
    }

    /// Resolve the document base URL per HTML spec:
    /// https://html.spec.whatwg.org/multipage/urls-and-fetching.html#document-base-url
    /// Falls back to self.url when no <base href> exists.
    fn resolve_base_url(&self) -> Option<url::Url> {
        let doc_url = self.url.as_ref()?;
        let base_href: Option<String> = self.js.as_ref().and_then(|js| {
            js.with_dom(|dom| match dom.query_selector("base[href]") {
                Ok(Some(nid)) => dom
                    .get_node(nid)
                    .and_then(|n| n.get_attribute("href").map(|s| s.to_string())),
                _ => None,
            })
            .flatten()
        });
        match base_href {
            Some(href) => doc_url.join(&href).ok(),
            None => Some(doc_url.clone()),
        }
    }

    /// Freeze the parser-owned script list before any new-document preload can
    /// see the fully parsed backing tree. Preloads may create their own scripts
    /// or move nodes which already belong to the parser; neither operation may
    /// enroll new parser work or execute an original parser script twice.
    fn snapshot_parser_scripts(&self) -> Option<Vec<ScriptInfo>> {
        let js = self.js.as_ref()?;
        let document_url = self.url_string();
        js.with_dom(|dom| {
            let script_ids = dom.query_selector_all("script").unwrap_or_default();
            let mut bases_at_script = std::collections::HashMap::new();
            let mut parser_order_at_script = std::collections::HashMap::new();
            let mut active_base = url::Url::parse(&document_url).ok();
            let mut found_base = false;
            for (parser_order, nid) in dom.descendants(dom.document()).into_iter().enumerate() {
                let Some(node) = dom.get_node(nid) else {
                    continue;
                };
                let Some(name) = node.as_element() else {
                    continue;
                };
                if name.local.as_ref() == "base" && !found_base {
                    if let Some(href) = node.get_attribute("href") {
                        found_base = true;
                        if let Some(resolved) =
                            active_base.as_ref().and_then(|base| base.join(href).ok())
                        {
                            active_base = Some(resolved);
                        }
                    }
                } else if name.local.as_ref() == "script" {
                    parser_order_at_script.insert(nid.raw(), parser_order);
                    bases_at_script.insert(
                        nid.raw(),
                        active_base
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| document_url.clone()),
                    );
                }
            }
            let body_descendants = dom
                .query_selector("body")
                .ok()
                .flatten()
                .map(|body| {
                    dom.descendants(body)
                        .into_iter()
                        .map(|nid| nid.raw())
                        .collect::<std::collections::HashSet<_>>()
                })
                .unwrap_or_default();

            script_ids
                .into_iter()
                .filter_map(|sid| {
                    let node = dom.get_node(sid)?;
                    let src = node.get_attribute("src").map(str::to_string);
                    let script_type = node
                        .get_attribute("type")
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase();
                    let kind = match script_type.as_str() {
                        "module" => ScriptKind::Module,
                        "importmap" => ScriptKind::ImportMap,
                        "" | "text/javascript" | "application/javascript" => ScriptKind::Classic,
                        _ => return None,
                    };
                    let inline = if src.is_none() {
                        dom.text_content(sid)
                    } else {
                        String::new()
                    };
                    if !matches!(kind, ScriptKind::ImportMap)
                        && src.is_none()
                        && inline.trim().is_empty()
                    {
                        return None;
                    }
                    Some(ScriptInfo {
                        src,
                        inline,
                        is_defer: node.get_attribute("defer").is_some(),
                        is_async: node.get_attribute("async").is_some(),
                        kind,
                        nid: sid.raw(),
                        after_body_start: body_descendants.contains(&sid.raw()),
                        base_url: bases_at_script
                            .get(&sid.raw())
                            .cloned()
                            .unwrap_or_else(|| document_url.clone()),
                        parser_order: parser_order_at_script
                            .get(&sid.raw())
                            .copied()
                            .unwrap_or(usize::MAX),
                    })
                })
                .collect()
        })
    }

    #[cfg(test)]
    fn snapshot_parser_body_order(&self) -> Option<usize> {
        self.js
            .as_ref()?
            .with_dom(|dom| {
                let body = dom.query_selector("body").ok().flatten()?;
                dom.descendants(dom.document())
                    .into_iter()
                    .position(|nid| nid == body)
            })
            .flatten()
    }

    fn install_parsed_body_load_handler(&mut self) {
        if let Some(js) = self.js.as_mut() {
            let _ = js.execute_script(
                "<body-load-handler>",
                "globalThis.__obscura_installParsedBodyLoadHandler?.();",
            );
        }
    }

    fn mark_parser_scripts_started(&mut self, scripts: &[ScriptInfo]) {
        let Some(js) = self.js.as_mut() else {
            return;
        };
        let ids = scripts
            .iter()
            .map(|script| script.nid.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let _ = js.execute_script(
            "<parser-scripts>",
            &format!("globalThis.__markParserScripts([{}]);", ids),
        );
    }

    fn snapshot_parser_stylesheets(&self) -> Option<ParserStylesheetSnapshot> {
        let document_url = self.url.clone()?;
        let (links, inline_imports, body_parser_order) = self
            .js
            .as_ref()?
            .with_dom(|dom| parser_stylesheet_requests(dom, &document_url))
            .unwrap_or_default();
        Some(ParserStylesheetSnapshot {
            links,
            inline_imports,
            body_parser_order,
        })
    }

    fn mark_parser_stylesheets_pending(&mut self, snapshot: &ParserStylesheetSnapshot) {
        let Some(js) = self.js.as_mut() else {
            return;
        };
        let tokens = snapshot
            .links
            .iter()
            .map(|link| {
                serde_json::json!({
                    "nid": link.nid,
                    "rawHref": link.raw_href,
                    "requestHref": link
                        .base_url
                        .join(&link.raw_href)
                        .ok()
                        .map(|url| url.to_string()),
                })
            })
            .collect::<Vec<_>>();
        let tokens = serde_json::to_string(&tokens).unwrap_or_else(|_| "[]".to_string());
        let _ = js.execute_script(
            "<parser-stylesheets>",
            &format!("globalThis.__markParserStylesheets({tokens});"),
        );
    }

    fn execute_top_lifecycle_script(&mut self, name: &str, source: &str) -> Result<(), String> {
        let Some(js) = self.js.as_mut() else {
            return Err("JavaScript runtime disappeared".to_string());
        };
        let watchdog = js.arm_watchdog(std::time::Duration::from_millis(
            LIFECYCLE_CALLBACK_WATCHDOG_MS,
        ));
        let result = js.execute_script(name, source);
        let watchdog_fired = js.disarm_watchdog(watchdog);
        if watchdog_fired || result.is_err() {
            self.top_load_pending = false;
            self.lifecycle = LifecycleState::Failed;
            return Err(result
                .err()
                .unwrap_or_else(|| "lifecycle task budget exceeded".to_string()));
        }
        Ok(())
    }

    #[cfg(test)]
    async fn fetch_stylesheets(&mut self) -> FetchedStylesheets {
        let Some(snapshot) = self.snapshot_parser_stylesheets() else {
            tracing::info!("fetch_stylesheets: no js runtime");
            return FetchedStylesheets {
                materialized: Vec::new(),
                failed_links: Vec::new(),
            };
        };
        self.fetch_stylesheets_from_snapshot(snapshot).await
    }

    async fn fetch_stylesheets_from_snapshot(
        &mut self,
        snapshot: ParserStylesheetSnapshot,
    ) -> FetchedStylesheets {
        let ParserStylesheetSnapshot {
            links: all_links,
            inline_imports,
            body_parser_order: _,
        } = snapshot;

        tracing::info!(
            "fetch_stylesheets: found {} stylesheet links and {} inline imports",
            all_links.len(),
            inline_imports.len()
        );

        let Some(document_url) = self.url.clone() else {
            return FetchedStylesheets {
                materialized: Vec::new(),
                failed_links: Vec::new(),
            };
        };
        let mut roots = Vec::new();
        let mut failed_links = Vec::new();
        let mut scheduled = std::collections::HashSet::new();
        let mut pending = Vec::new();
        for link in all_links {
            let Ok(resolved) = link.base_url.join(&link.raw_href) else {
                failed_links.push((link.nid, link.parser_order, link.raw_href, None));
                continue;
            };
            let request_href = resolved.to_string();
            let (key, resolved) = canonical_stylesheet_url(resolved);
            if !subresource_allowed(Some(&document_url), resolved.as_str()) {
                tracing::warn!(
                    "blocking cross-scheme <link rel=stylesheet href>: page={} href={}",
                    self.url_string(),
                    resolved,
                );
                failed_links.push((
                    link.nid,
                    link.parser_order,
                    link.raw_href,
                    Some(request_href),
                ));
                continue;
            }
            if self.should_block_url(resolved.as_str()) {
                tracing::info!("Blocked stylesheet by interception: {}", resolved);
                failed_links.push((
                    link.nid,
                    link.parser_order,
                    link.raw_href,
                    Some(request_href),
                ));
                continue;
            }
            roots.push((
                AuthorStylesheetTarget::Linked {
                    nid: link.nid,
                    parser_order: link.parser_order,
                    raw_href: link.raw_href,
                    request_href,
                },
                key.clone(),
                None,
            ));
            if scheduled.insert(key.clone()) {
                if scheduled.len() <= MAX_STYLESHEET_RESOURCES {
                    pending.push((key, resolved, 0u8));
                } else {
                    self.mark_resource_archive_incomplete(format!(
                        "top-level stylesheet resource cap reached ({MAX_STYLESHEET_RESOURCES} resources)"
                    ));
                }
            }
        }
        for inline_import in inline_imports {
            let Ok(resolved) = inline_import.base_url.join(&inline_import.import.url) else {
                continue;
            };
            let (key, resolved) = canonical_stylesheet_url(resolved);
            if !subresource_allowed(Some(&document_url), resolved.as_str())
                || self.should_block_url(resolved.as_str())
            {
                tracing::info!("Blocked inline stylesheet import: {}", resolved);
                continue;
            }
            roots.push((
                AuthorStylesheetTarget::InlineImport {
                    nid: inline_import.nid,
                },
                key.clone(),
                inline_import.import.media,
            ));
            if scheduled.insert(key.clone()) {
                if scheduled.len() <= MAX_STYLESHEET_RESOURCES {
                    pending.push((key, resolved, 1u8));
                } else {
                    self.mark_resource_archive_incomplete(format!(
                        "top-level stylesheet resource cap reached ({MAX_STYLESHEET_RESOURCES} resources)"
                    ));
                }
            }
        }

        let mut sheets = std::collections::HashMap::new();
        let mut aliases = std::collections::HashMap::new();
        while !pending.is_empty() {
            let batch = std::mem::take(&mut pending);
            let client = self.http_client.clone();
            #[cfg(feature = "stealth")]
            let stealth_client = self.stealth_client.clone();
            let callbacks = self.callbacks.clone();
            let initiator = document_url.clone();
            use futures::StreamExt as _;
            let results: Vec<_> =
                futures::stream::iter(batch.into_iter().map(|(key, requested_url, depth)| {
                    let client = client.clone();
                    #[cfg(feature = "stealth")]
                    let stealth_client = stealth_client.clone();
                    let callbacks = callbacks.clone();
                    let initiator = initiator.clone();
                    async move {
                        let request =
                            ResourceRequest::subresource(ResourceType::Stylesheet, &initiator);
                        #[cfg(feature = "stealth")]
                        let result = if let Some(stealth_client) = stealth_client {
                            stealth_client
                                .fetch_resource_with_callbacks(
                                    &requested_url,
                                    request,
                                    Some(&callbacks),
                                )
                                .await
                        } else {
                            client
                                .fetch_resource_with_callbacks(
                                    &requested_url,
                                    request,
                                    Some(&callbacks),
                                )
                                .await
                        };
                        #[cfg(not(feature = "stealth"))]
                        let result = client
                            .fetch_resource_with_callbacks(
                                &requested_url,
                                request,
                                Some(&callbacks),
                            )
                            .await;
                        (key, requested_url, depth, result)
                    }
                }))
                .buffered(16)
                .collect()
                .await;

            for (key, requested_url, depth, result) in results {
                let response = match result {
                    Ok(response) => response,
                    Err(error) => {
                        tracing::debug!("Failed to fetch stylesheet {}: {}", requested_url, error);
                        self.mark_resource_archive_incomplete(format!(
                            "top-level stylesheet fetch failed: {requested_url}"
                        ));
                        continue;
                    }
                };
                let response_url = response.url.clone();
                self.record_network_event_with_body(
                    response_url.as_str(),
                    "GET",
                    "Stylesheet",
                    response.status,
                    &response.headers,
                    &response.body,
                    false,
                );
                if !(200..300).contains(&response.status) {
                    self.mark_resource_archive_incomplete(format!(
                        "top-level stylesheet {requested_url} returned HTTP {}",
                        response.status,
                    ));
                    continue;
                }

                let (response_key, response_url) = canonical_stylesheet_url(response_url);
                if let Some(existing) = aliases.get(&response_key).cloned() {
                    aliases.insert(key, existing);
                    continue;
                }
                let css = obscura_net::decode_non_html(&response.body, response.content_type());
                let (discovered_imports, rules) = split_css_imports(&css);
                if depth >= MAX_STYLESHEET_IMPORT_DEPTH && !discovered_imports.is_empty() {
                    self.mark_resource_archive_incomplete(format!(
                        "top-level stylesheet import depth cap reached ({MAX_STYLESHEET_IMPORT_DEPTH}): {response_url}"
                    ));
                }
                let imports = if depth < MAX_STYLESHEET_IMPORT_DEPTH {
                    discovered_imports
                } else {
                    Vec::new()
                };
                aliases.insert(key.clone(), key.clone());
                aliases.insert(response_key, key.clone());
                sheets.insert(
                    key,
                    LoadedStylesheet {
                        response_url: response_url.clone(),
                        imports: imports.clone(),
                        rules,
                    },
                );

                if depth >= MAX_STYLESHEET_IMPORT_DEPTH {
                    continue;
                }
                for import in imports {
                    let Ok(import_url) = response_url.join(&import.url) else {
                        continue;
                    };
                    let (import_key, import_url) = canonical_stylesheet_url(import_url);
                    if aliases.contains_key(&import_key) || scheduled.contains(&import_key) {
                        continue;
                    }
                    if scheduled.len() >= MAX_STYLESHEET_RESOURCES {
                        tracing::warn!(
                            "stylesheet resource cap reached at {} resources",
                            MAX_STYLESHEET_RESOURCES
                        );
                        self.mark_resource_archive_incomplete(format!(
                            "top-level stylesheet resource cap reached ({MAX_STYLESHEET_RESOURCES} resources)"
                        ));
                        continue;
                    }
                    if !subresource_allowed(Some(&document_url), import_url.as_str())
                        || self.should_block_url(import_url.as_str())
                    {
                        tracing::info!("Blocked stylesheet import: {}", import_url);
                        continue;
                    }
                    scheduled.insert(import_key.clone());
                    pending.push((import_key, import_url, depth + 1));
                }
            }
        }

        let mut materialized = Vec::new();
        for (target, key, media) in roots {
            match materialize_stylesheet_graph(
                &key,
                &sheets,
                &aliases,
                &mut std::collections::HashSet::new(),
            ) {
                Some(css) => {
                    let css = match media {
                        Some(media) => format!("@media {media} {{\n{css}\n}}\n"),
                        None => css,
                    };
                    materialized.push((target, css));
                }
                None => {
                    if let AuthorStylesheetTarget::Linked {
                        nid,
                        parser_order,
                        raw_href,
                        request_href,
                    } = target
                    {
                        failed_links.push((nid, parser_order, raw_href, Some(request_href)));
                    }
                }
            }
        }
        failed_links.sort_unstable();
        failed_links.dedup();
        FetchedStylesheets {
            materialized,
            failed_links,
        }
    }

    #[cfg(test)]
    async fn execute_scripts(&mut self) {
        self.execute_scripts_with_module_budget(None).await;
    }

    /// Drive only dynamic script elements which participate in the current
    /// document's load-event delay set. Browser script runners keep this set
    /// separate from arbitrary post-load imports, timers, and enhancement
    /// scripts; navigation readiness must not turn those into an implicit
    /// multi-second settle.
    #[cfg(test)]
    async fn drive_load_delaying_scripts(
        js: &mut ObscuraJsRuntime,
        deadline: tokio::time::Instant,
    ) -> bool {
        while js.has_pending_load_delaying_resources() {
            let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            else {
                return false;
            };
            if remaining.is_zero() {
                return false;
            }
            let poll_budget = remaining.min(tokio::time::Duration::from_millis(25));
            match tokio::time::timeout(poll_budget, js.run_load_delaying_event_loop_tick()).await {
                Ok(Ok(_idle)) => {
                    if js.has_pending_load_delaying_resources() {
                        tokio::task::yield_now().await;
                    }
                }
                Ok(Err(error)) => {
                    if obscura_js::runtime::is_fatal_event_loop_error(&error) {
                        tracing::warn!("load-delaying dynamic script event loop failed: {error}");
                        return false;
                    }
                    // A load-delaying script threw or left an unhandled
                    // rejection. Chrome reports the error and runs the rest;
                    // killing the pump would strand every still-pending script
                    // (#699). The absolute deadline above bounds a page that
                    // errors on every turn.
                    tracing::warn!("load-delaying script task error, continuing: {error}");
                    tokio::task::yield_now().await;
                }
                Err(_) => {
                    // This timeout only cancels a parked event-loop poll. The
                    // shared absolute deadline above remains authoritative.
                }
            }
        }
        true
    }

    /// Alternate JavaScript tasks with native frame attachment until the top
    /// document's complete/readystatechange/load transition can run.
    async fn drive_document_load(&mut self, deadline: tokio::time::Instant) -> bool {
        loop {
            self.advance_frames().await;
            if self.lifecycle == LifecycleState::Failed {
                return false;
            }
            if !self.top_load_pending {
                return true;
            }
            let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            else {
                return false;
            };
            if remaining.is_zero() {
                return false;
            }
            let poll_budget = remaining.min(tokio::time::Duration::from_millis(25));
            let Some(js) = self.js.as_mut() else {
                return false;
            };
            match tokio::time::timeout(poll_budget, js.run_load_delaying_event_loop_tick()).await {
                Ok(Ok(_)) => tokio::task::yield_now().await,
                Ok(Err(error)) => {
                    tracing::warn!("document load event loop failed: {error}");
                    return false;
                }
                Err(_) => {}
            }
        }
    }

    #[cfg(test)]
    async fn execute_scripts_with_module_budget(&mut self, module_budget_override: Option<u64>) {
        // Unit fixtures construct a fully parsed document directly instead of
        // entering through navigate_single(). Match the real navigation
        // boundary so scripts inserted by parser code join the load-delay set
        // and the lifecycle driver actually pumps their fetches.
        if let Some(js) = self.js.as_mut() {
            let _ = js.execute_script(
                "<ready-state>",
                "globalThis.__documentReadyState__ = 'loading';",
            );
        }
        let parser_body_order = self.snapshot_parser_body_order();
        let Some(phase) = self
            .execute_scripts_to_dom_content_loaded(module_budget_override, None, parser_body_order)
            .await
        else {
            return;
        };
        self.top_load_pending = true;
        if !self.drive_document_load(phase.deadline).await {
            tracing::warn!("document load deadline reached with blockers still pending");
        }
        if let (Some(js), Some(watchdog)) = (self.js.as_mut(), phase.watchdog) {
            if js.disarm_watchdog(watchdog) {
                self.top_load_pending = false;
                self.lifecycle = LifecycleState::Failed;
            }
        }
    }

    async fn execute_scripts_to_dom_content_loaded(
        &mut self,
        module_budget_override: Option<u64>,
        parser_scripts: Option<Vec<ScriptInfo>>,
        parser_body_order: Option<usize>,
    ) -> Option<ScriptLoadPhase> {
        let scripts_started = std::time::Instant::now();
        tracing::info!(
            "execute_scripts called, js runtime exists: {}",
            self.js.is_some()
        );
        // Soft deadline on the entire script-execution phase. Heavy SPAs
        // (GitHub, Linear, CodeSandbox) ship 50+ scripts and our serial
        // fetch + execute loop can blow past a Puppeteer/Playwright goto
        // timeout. The old 10s default was too tight: a heavy React/Vue/Angular
        // SPA had its remaining scripts skipped before the app booted, so it
        // never fired its XHR/fetch calls and page.on('response') saw nothing
        // (issue #361). Only pages that actually run past the deadline are
        // affected; fast pages finish and return well before it, so a larger
        // budget costs them nothing. 30s gives an app room to initialize while
        // the per-phase watchdog (armed at this + 1s) still bounds a real
        // synchronous hang. Raise it further with OBSCURA_SCRIPT_DEADLINE_MS=<ms>
        // for very heavy SPAs on slow networks (pair it with a matching client
        // navigation timeout).
        let script_deadline_ms: u64 = std::env::var("OBSCURA_SCRIPT_DEADLINE_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30_000);
        let script_deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_millis(script_deadline_ms);

        // Hard backstop over the WHOLE script-execution phase. Inline scripts
        // run back-to-back with no await between them, so neither the soft
        // deadline above (only checked between scripts) nor the per-script guard
        // can interrupt a page that burns the budget across many synchronous
        // scripts (the real-world SPA / anti-bot busy-loop hang). This watchdog
        // terminates the isolate if cumulative synchronous script work overruns.
        let exec_wd = self
            .js
            .as_mut()
            .map(|js| js.arm_watchdog(std::time::Duration::from_millis(script_deadline_ms + 1000)));

        let external_module_url = |script: &ScriptInfo| {
            let src = script.src.as_ref()?;
            Some(
                if src.starts_with("http://")
                    || src.starts_with("https://")
                    || src.starts_with("data:")
                {
                    src.clone()
                } else {
                    url::Url::parse(&script.base_url)
                        .ok()
                        .and_then(|base| base.join(src).ok())
                        .map(|url| url.to_string())
                        .unwrap_or_else(|| src.clone())
                },
            )
        };

        let all_scripts = match parser_scripts {
            Some(scripts) => scripts,
            None => self.snapshot_parser_scripts()?,
        };

        // HTML scripts have an "already started" flag. Mark every
        // parser-discovered script before running page code so React/Next
        // hydration can move or hoist those nodes without appendChild
        // executing them a second time.
        self.mark_parser_scripts_started(&all_scripts);

        tracing::info!("Found {} parser-discovered scripts", all_scripts.len());
        let mut fetch_tasks: Vec<(usize, String)> = Vec::new();

        for (i, script) in all_scripts.iter().enumerate() {
            if !matches!(script.kind, ScriptKind::Classic) {
                continue;
            }
            if let Some(src_url) = &script.src {
                let full_url = if src_url.starts_with("http://") || src_url.starts_with("https://")
                {
                    src_url.clone()
                } else {
                    url::Url::parse(&script.base_url)
                        .ok()
                        .and_then(|base| base.join(src_url).ok())
                        .map(|url| url.to_string())
                        .unwrap_or_else(|| src_url.clone())
                };

                if !subresource_allowed(self.url.as_ref(), &full_url) {
                    // Block file://, data:, javascript:, and other
                    // off-origin schemes from being injected as a
                    // <script src>. Without this an http page can
                    // include <script src="file:///etc/passwd"> and
                    // see the body parsed as JS source.
                    tracing::warn!(
                        "blocking cross-scheme <script src>: page={} src={}",
                        self.url_string(),
                        full_url,
                    );
                    continue;
                }
                if self.should_block_url(&full_url) {
                    tracing::info!("Blocked script by interception: {}", full_url);
                    continue;
                }
                fetch_tasks.push((i, full_url));
            }
        }

        let client = self.http_client.clone();
        let page_callbacks = self.callbacks.clone();
        let script_initiator = self
            .url
            .clone()
            .unwrap_or_else(|| Url::parse("about:blank").unwrap());
        let fetch_futures: Vec<_> = fetch_tasks
            .iter()
            .map(|(idx, url)| {
                let client = client.clone();
                let cbs = page_callbacks.clone();
                let initiator = script_initiator.clone();
                let url = url.clone();
                let idx = *idx;
                async move {
                    let parsed =
                        Url::parse(&url).unwrap_or_else(|_| Url::parse("about:blank").unwrap());
                    if parsed.scheme() == "data" {
                        // data: URIs are inline; decode locally, no network fetch.
                        // Instagram and other Meta properties serve their bootstrap
                        // as <script src="data:application/x-javascript;base64,...">.
                        let body = decode_data_uri(&url).unwrap_or_default();
                        let content_type = url
                            .strip_prefix("data:")
                            .and_then(|s| s.split(',').next())
                            .unwrap_or("application/javascript")
                            .split(';')
                            .next()
                            .unwrap_or("application/javascript")
                            .to_string();
                        let mut headers = std::collections::HashMap::new();
                        headers.insert("content-type".to_string(), content_type);
                        let resp = obscura_net::Response {
                            url: parsed,
                            status: 200,
                            headers,
                            body,
                            redirected_from: Vec::new(),
                        };
                        return Some((idx, url, resp));
                    }
                    let request = ResourceRequest::subresource(ResourceType::Script, &initiator);
                    match client
                        .fetch_resource_with_callbacks(&parsed, request, Some(&cbs))
                        .await
                    {
                        Ok(resp) => Some((idx, url, resp)),
                        Err(e) => {
                            tracing::warn!("Failed to fetch script {}: {}", url, e);
                            None
                        }
                    }
                }
            })
            .collect();

        // Bound concurrency: a page with 100 external scripts would
        // otherwise open 100 sockets at once, exhausting the connection
        // pool / ephemeral ports and triggering OS-level backpressure.
        // 16 is well above the per-host pool ceiling most browsers use
        // and matches what real Chrome does for a given origin.
        use futures::StreamExt as _;
        let fetch_stream = futures::stream::iter(fetch_futures).buffer_unordered(16);
        let fetch_results = match tokio::time::timeout_at(
            script_deadline,
            fetch_stream.collect::<Vec<_>>(),
        )
        .await
        {
            Ok(results) => results,
            Err(_) => {
                tracing::warn!(
                    "execute_scripts: fetch deadline reached, some scripts may not have loaded"
                );
                Vec::new()
            }
        };

        let mut fetched: std::collections::HashMap<usize, (String, String, obscura_net::Response)> =
            std::collections::HashMap::new();
        for result in fetch_results {
            if let Some((idx, url, resp)) = result {
                if !script_response_is_executable(resp.status) {
                    self.record_network_event_with_body(
                        &url,
                        "GET",
                        "Script",
                        resp.status,
                        &resp.headers,
                        &resp.body,
                        false,
                    );
                    tracing::warn!(
                        "Refusing to execute script {} after HTTP {}",
                        url,
                        resp.status
                    );
                    continue;
                }
                // Script bodies: only the HTTP Content-Type charset matters
                // (no in-band meta-charset for JS).
                let code = obscura_net::decode_non_html(&resp.body, resp.content_type());
                fetched.insert(idx, (url, code, resp));
            }
        }

        // Per-module budget. Modules on an already-rendered page are
        // enhancement, not the app: give them a short budget so one slow
        // non-essential module (e.g. YC's bookface, whose top-level eval
        // idle-waits ~10s) cannot block navigation completion. A page whose
        // body is still an empty shell IS the SPA (issue #205), so give it the
        // full script budget and the app module still mounts.
        let module_budget_ms: u64 = {
            let body_nodes = self
                .js
                .as_ref()
                .and_then(|js| {
                    js.with_dom(|dom| {
                        dom.query_selector("body")
                            .ok()
                            .flatten()
                            .map(|b| dom.descendants(b).len())
                            .unwrap_or(0)
                    })
                })
                .unwrap_or(0);
            let short_ms: u64 = module_budget_override.unwrap_or_else(|| {
                std::env::var("OBSCURA_MODULE_BUDGET_MS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(3_000)
            });
            // A rendered body has hundreds of descendants; an unmounted Vite/Next
            // shell is <root> plus maybe a spinner.
            if module_budget_override.is_some() || body_nodes > 50 {
                short_ms
            } else {
                script_deadline_ms
            }
        };
        // V8 can flag an overrun while a synchronous renderer host call is in
        // progress, but it cannot preempt Rust after entering that call. Allow
        // one bounded, finite style/layout flush without weakening the
        // page-wide script deadline. Private test overrides keep zero grace.
        let module_hostcall_grace_ms = if module_budget_override.is_some() {
            0
        } else {
            std::env::var("OBSCURA_MODULE_HOSTCALL_GRACE_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5_000)
        };

        enum ScheduledScript {
            Classic(usize),
            Module {
                prepared: obscura_js::runtime::PreparedModule,
                url: Option<String>,
                nid: u32,
                remaining_active_ms: u64,
                graph_elapsed_ms: u64,
                queued_at: std::time::Instant,
            },
        }

        let remaining_budget_ms = |deadline: tokio::time::Instant| -> Option<u64> {
            let remaining = deadline.checked_duration_since(tokio::time::Instant::now())?;
            if remaining.is_zero() {
                return None;
            }
            let millis = remaining
                .as_millis()
                .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0));
            Some(millis.min(u128::from(u64::MAX)) as u64)
        };
        let elapsed_ms_ceil = |elapsed: std::time::Duration| -> u64 {
            elapsed
                .as_micros()
                .div_ceil(1_000)
                .max(1)
                .min(u128::from(u64::MAX)) as u64
        };
        let evaluation_budget_ms = |remaining_active_ms: u64| -> Option<u64> {
            let remaining_page_ms = remaining_budget_ms(script_deadline)?;
            let budget = remaining_active_ms
                .saturating_add(module_hostcall_grace_ms)
                .min(remaining_page_ms);
            (budget != 0).then_some(budget)
        };

        // Parser-discovered scripts are prepared by the Rust-side HTML script
        // runner rather than bootstrap's dynamic-script queue, so completion
        // must be reflected back through the element's EventTarget explicitly.
        // Dispatching (instead of calling `onload` / `onerror` directly) keeps
        // IDL/content-attribute handlers and addEventListener listeners on the
        // same single event path.
        let dispatch_script_event = |page: &mut Self, nid: u32, event_type: &'static str| {
            debug_assert!(matches!(event_type, "load" | "error"));
            if let Some(js) = &mut page.js {
                let _ = js.execute_script(
                    "<parser-script-event>",
                    &format!(
                        "globalThis.__obscura_dispatchParserScriptEvent({nid}, '{event_type}')"
                    ),
                );
            }
        };

        let execute_classic =
            |page: &mut Self,
             script: &ScriptInfo,
             fetched_script: Option<(String, String, obscura_net::Response)>| {
                if script.src.is_some() {
                    if let Some((url, code, resp)) = fetched_script {
                        tracing::info!("Executing script ({} bytes): {}", code.len(), url);
                        let execution_url = resp.url.to_string();
                        page.record_network_event_with_body(
                            &url,
                            "GET",
                            "Script",
                            resp.status,
                            &resp.headers,
                            &resp.body,
                            false,
                        );
                        if let Some(js) = &mut page.js {
                            let _ = js.execute_script(
                                "<current-script>",
                                &format!("globalThis.__currentScriptNid={};", script.nid),
                            );
                            if let Err(error) = js.execute_script_guarded(&execution_url, &code) {
                                tracing::warn!("Script error ({}): {}", execution_url, error);
                            }
                            let _ = js.execute_script(
                                "<current-script>",
                                "globalThis.__currentScriptNid=0;",
                            );
                        }
                        // A successfully fetched classic script fires load even
                        // when evaluating its source reports a JS exception.
                        // Fetch/HTTP failures take the error path below.
                        dispatch_script_event(page, script.nid, "load");
                    } else {
                        dispatch_script_event(page, script.nid, "error");
                    }
                } else if !script.inline.is_empty() {
                    if let Some(js) = &mut page.js {
                        let _ = js.execute_script(
                            "<current-script>",
                            &format!("globalThis.__currentScriptNid={};", script.nid),
                        );
                        if let Err(error) =
                            js.execute_script_guarded(&script.base_url, &script.inline)
                        {
                            tracing::warn!("Inline script error: {}", error);
                        }
                        let _ = js
                            .execute_script("<current-script>", "globalThis.__currentScriptNid=0;");
                    }
                }
            };

        let mut post_parse = Vec::new();
        let mut body_load_handler_installed = false;
        let mut parser_stylesheet_events =
            std::mem::take(&mut self.pending_parser_stylesheet_events)
                .into_values()
                .collect::<Vec<_>>();
        parser_stylesheet_events.sort_by_key(|(order, _)| *order);
        let mut parser_stylesheet_events =
            std::collections::VecDeque::from(parser_stylesheet_events);
        let mut parser_stylesheet_failed = false;

        // Process parser-discovered scripts in encounter order. Import maps
        // register at their exact position; module graphs start there too, but
        // evaluation of non-async modules remains post-parse.
        for (index, script) in all_scripts.iter().enumerate() {
            while parser_stylesheet_events
                .front()
                .is_some_and(|(order, _)| *order < script.parser_order)
            {
                let (order, source) = parser_stylesheet_events.pop_front().unwrap();
                if !body_load_handler_installed
                    && parser_body_order.is_some_and(|body_order| body_order < order)
                {
                    self.install_parsed_body_load_handler();
                    body_load_handler_installed = true;
                }
                if let Err(error) =
                    self.execute_top_lifecycle_script("<parser-stylesheet-event>", &source)
                {
                    tracing::warn!("parser stylesheet owner event failed: {error}");
                    parser_stylesheet_failed = true;
                    break;
                }
            }
            if parser_stylesheet_failed {
                break;
            }
            if !body_load_handler_installed
                && parser_body_order
                    .map(|body_order| body_order < script.parser_order)
                    .unwrap_or(script.after_body_start)
            {
                self.install_parsed_body_load_handler();
                body_load_handler_installed = true;
            }
            if tokio::time::Instant::now() >= script_deadline {
                tracing::warn!(
                    "execute_scripts: deadline reached, skipping {} remaining scripts",
                    all_scripts.len() - index,
                );
                for skipped in &all_scripts[index..] {
                    if matches!(skipped.kind, ScriptKind::Module) {
                        if let Some(url) = external_module_url(skipped) {
                            self.mark_resource_archive_incomplete(format!(
                                "top-level module was not processed before the script deadline: {url}"
                            ));
                        }
                    }
                    if skipped.src.is_some() || matches!(skipped.kind, ScriptKind::Module) {
                        dispatch_script_event(self, skipped.nid, "error");
                    }
                }
                break;
            }

            match script.kind {
                ScriptKind::ImportMap => {
                    if script.src.is_some() {
                        tracing::warn!("External import maps are not supported");
                        continue;
                    }
                    if let Some(js) = &self.js {
                        if let Err(error) = js.add_import_map(&script.inline, &script.base_url) {
                            tracing::warn!("Ignoring invalid import map: {}", error);
                        }
                    }
                }
                ScriptKind::Classic => {
                    if script.is_defer && !script.is_async && script.src.is_some() {
                        post_parse.push(ScheduledScript::Classic(index));
                    } else {
                        let fetched_script = fetched.remove(&index);
                        execute_classic(self, script, fetched_script);
                    }
                }
                ScriptKind::Module => {
                    let external_url = external_module_url(script);
                    // Graph loading and evaluation share one active-work
                    // allowance. Queue time behind other post-parse scripts is
                    // not work performed by this module.
                    let Some(remaining_page_ms) = remaining_budget_ms(script_deadline) else {
                        tracing::warn!("ES module budget exhausted before graph preparation");
                        if let Some(url) = external_url.as_deref() {
                            self.mark_resource_archive_incomplete(format!(
                                "top-level module page budget exhausted before graph preparation: {url}"
                            ));
                        }
                        dispatch_script_event(self, script.nid, "error");
                        continue;
                    };
                    let prepare_budget_ms = module_budget_ms.min(remaining_page_ms);
                    let prepare_started = std::time::Instant::now();
                    let (prepared, module_url) = if let Some(full_url) = external_url {
                        tracing::info!("Preparing ES module graph: {}", full_url);
                        let result = match &mut self.js {
                            Some(js) => js.prepare_module(&full_url, prepare_budget_ms).await,
                            None => {
                                self.mark_resource_archive_incomplete(format!(
                                    "top-level module graph preparation could not start: {full_url}"
                                ));
                                dispatch_script_event(self, script.nid, "error");
                                continue;
                            }
                        };
                        tracing::debug!(
                            phase = "module-graph",
                            module = %full_url,
                            elapsed_ms = prepare_started.elapsed().as_millis(),
                            budget_ms = prepare_budget_ms,
                            success = result.is_ok(),
                            "ES module phase complete",
                        );
                        match result {
                            Ok(prepared) => (prepared, Some(full_url)),
                            Err(error) => {
                                tracing::warn!("ES module error ({}): {}", full_url, error);
                                self.mark_resource_archive_incomplete(format!(
                                    "top-level module graph preparation failed: {full_url}"
                                ));
                                dispatch_script_event(self, script.nid, "error");
                                continue;
                            }
                        }
                    } else {
                        let result = match &mut self.js {
                            Some(js) => {
                                js.prepare_inline_module(
                                    &script.inline,
                                    &script.base_url,
                                    prepare_budget_ms,
                                )
                                .await
                            }
                            None => {
                                dispatch_script_event(self, script.nid, "error");
                                continue;
                            }
                        };
                        tracing::debug!(
                            phase = "module-graph",
                            module = "<inline>",
                            elapsed_ms = prepare_started.elapsed().as_millis(),
                            budget_ms = prepare_budget_ms,
                            success = result.is_ok(),
                            "ES module phase complete",
                        );
                        match result {
                            Ok(prepared) => (prepared, None),
                            Err(error) => {
                                tracing::warn!("Inline ES module error: {}", error);
                                dispatch_script_event(self, script.nid, "error");
                                continue;
                            }
                        }
                    };
                    let graph_elapsed_ms = elapsed_ms_ceil(prepare_started.elapsed());
                    let remaining_active_ms = module_budget_ms.saturating_sub(graph_elapsed_ms);
                    if remaining_active_ms == 0 {
                        tracing::warn!(
                            module = module_url.as_deref().unwrap_or("<inline>"),
                            graph_elapsed_ms,
                            active_budget_ms = module_budget_ms,
                            "ES module exhausted its active budget during graph preparation",
                        );
                        if let Some(url) = module_url.as_deref() {
                            self.mark_resource_archive_incomplete(format!(
                                "top-level module active budget exhausted during graph preparation: {url}"
                            ));
                        }
                        dispatch_script_event(self, script.nid, "error");
                        continue;
                    }
                    let scheduled = ScheduledScript::Module {
                        prepared,
                        url: module_url,
                        nid: script.nid,
                        remaining_active_ms,
                        graph_elapsed_ms,
                        queued_at: std::time::Instant::now(),
                    };
                    if script.is_async {
                        let ScheduledScript::Module {
                            prepared,
                            url,
                            nid,
                            remaining_active_ms,
                            graph_elapsed_ms,
                            queued_at,
                        } = scheduled
                        else {
                            unreachable!();
                        };
                        let Some(evaluation_budget_ms) = evaluation_budget_ms(remaining_active_ms)
                        else {
                            tracing::warn!(
                                module = url.as_deref().unwrap_or("<inline>"),
                                graph_elapsed_ms,
                                queue_wait_ms = queued_at.elapsed().as_millis(),
                                "ES module exhausted the page budget before evaluation",
                            );
                            if let Some(url) = url.as_deref() {
                                self.mark_resource_archive_incomplete(format!(
                                    "top-level module page budget exhausted before evaluation: {url}"
                                ));
                            }
                            dispatch_script_event(self, nid, "error");
                            continue;
                        };
                        let queue_wait_ms = queued_at.elapsed().as_millis();
                        let evaluation_started = std::time::Instant::now();
                        let result = match &mut self.js {
                            Some(js) => {
                                js.evaluate_prepared_module(prepared, evaluation_budget_ms)
                                    .await
                            }
                            None => {
                                if let Some(url) = url.as_deref() {
                                    self.mark_resource_archive_incomplete(format!(
                                        "top-level module evaluation could not start: {url}"
                                    ));
                                }
                                dispatch_script_event(self, nid, "error");
                                continue;
                            }
                        };
                        tracing::debug!(
                            phase = "module-evaluation",
                            module = url.as_deref().unwrap_or("<inline>"),
                            elapsed_ms = evaluation_started.elapsed().as_millis(),
                            graph_elapsed_ms,
                            queue_wait_ms,
                            remaining_active_ms,
                            evaluation_ceiling_ms = evaluation_budget_ms,
                            success = result.is_ok(),
                            "ES module phase complete",
                        );
                        if let Err(error) = result {
                            tracing::warn!("ES module evaluation error: {}", error);
                            if let Some(url) = url.as_deref() {
                                self.mark_resource_archive_incomplete(format!(
                                    "top-level module evaluation failed: {url}"
                                ));
                            }
                            dispatch_script_event(self, nid, "error");
                        } else if let Some(url) = url {
                            tracing::info!("ES module loaded: {}", url);
                            self.record_network_event(
                                &url,
                                "GET",
                                "Script",
                                200,
                                &std::collections::HashMap::new(),
                                0,
                            );
                            dispatch_script_event(self, nid, "load");
                        } else {
                            dispatch_script_event(self, nid, "load");
                        }
                    } else {
                        post_parse.push(scheduled);
                    }
                }
            }
        }

        while let Some((order, source)) = parser_stylesheet_events.pop_front() {
            if !body_load_handler_installed
                && parser_body_order.is_some_and(|body_order| body_order < order)
            {
                self.install_parsed_body_load_handler();
                body_load_handler_installed = true;
            }
            if let Err(error) =
                self.execute_top_lifecycle_script("<parser-stylesheet-event>", &source)
            {
                tracing::warn!("parser stylesheet owner event failed: {error}");
                break;
            }
        }

        if !body_load_handler_installed {
            self.install_parsed_body_load_handler();
        }

        // Parsing has finished before defer scripts and non-async modules run.
        // They still gate DOMContentLoaded, but observe the browser's
        // `interactive` readyState while they execute.
        if let Some(js) = &mut self.js {
            let _ = js.execute_script(
                "<ready-state-interactive>",
                "globalThis.__documentReadyState__ = 'interactive';\
                 try { globalThis.__obscura_dispatchDocumentLifecycleEvent('readystatechange'); } catch (_) {}",
            );
        }

        for scheduled in post_parse {
            if tokio::time::Instant::now() >= script_deadline {
                tracing::warn!("execute_scripts: deadline reached during post-parse scripts");
                match &scheduled {
                    ScheduledScript::Classic(index) => {
                        let script = &all_scripts[*index];
                        dispatch_script_event(self, script.nid, "error");
                    }
                    ScheduledScript::Module { url, nid, .. } => {
                        if let Some(url) = url {
                            self.mark_resource_archive_incomplete(format!(
                                "top-level module was not evaluated before the script deadline: {url}"
                            ));
                        }
                        dispatch_script_event(self, *nid, "error");
                    }
                }
                continue;
            }
            match scheduled {
                ScheduledScript::Classic(index) => {
                    let script = &all_scripts[index];
                    let fetched_script = fetched.remove(&index);
                    execute_classic(self, script, fetched_script);
                }
                ScheduledScript::Module {
                    prepared,
                    url,
                    nid,
                    remaining_active_ms,
                    graph_elapsed_ms,
                    queued_at,
                } => {
                    let Some(evaluation_budget_ms) = evaluation_budget_ms(remaining_active_ms)
                    else {
                        tracing::warn!(
                            module = url.as_deref().unwrap_or("<inline>"),
                            graph_elapsed_ms,
                            queue_wait_ms = queued_at.elapsed().as_millis(),
                            "ES module exhausted the page budget before post-parse evaluation",
                        );
                        if let Some(url) = url.as_deref() {
                            self.mark_resource_archive_incomplete(format!(
                                "top-level module page budget exhausted before post-parse evaluation: {url}"
                            ));
                        }
                        dispatch_script_event(self, nid, "error");
                        continue;
                    };
                    let queue_wait_ms = queued_at.elapsed().as_millis();
                    let evaluation_started = std::time::Instant::now();
                    let result = match &mut self.js {
                        Some(js) => {
                            js.evaluate_prepared_module(prepared, evaluation_budget_ms)
                                .await
                        }
                        None => {
                            if let Some(url) = url.as_deref() {
                                self.mark_resource_archive_incomplete(format!(
                                    "top-level module post-parse evaluation could not start: {url}"
                                ));
                            }
                            dispatch_script_event(self, nid, "error");
                            continue;
                        }
                    };
                    tracing::debug!(
                        phase = "module-evaluation",
                        module = url.as_deref().unwrap_or("<inline>"),
                        elapsed_ms = evaluation_started.elapsed().as_millis(),
                        graph_elapsed_ms,
                        queue_wait_ms,
                        remaining_active_ms,
                        evaluation_ceiling_ms = evaluation_budget_ms,
                        success = result.is_ok(),
                        "ES module phase complete",
                    );
                    if let Err(error) = result {
                        tracing::warn!("ES module evaluation error: {}", error);
                        if let Some(url) = url.as_deref() {
                            self.mark_resource_archive_incomplete(format!(
                                "top-level module evaluation failed: {url}"
                            ));
                        }
                        dispatch_script_event(self, nid, "error");
                    } else if let Some(url) = url {
                        tracing::info!("ES module loaded: {}", url);
                        self.record_network_event(
                            &url,
                            "GET",
                            "Script",
                            200,
                            &std::collections::HashMap::new(),
                            0,
                        );
                        dispatch_script_event(self, nid, "load");
                    } else {
                        dispatch_script_event(self, nid, "load");
                    }
                }
            }
        }

        if let Some(js) = &mut self.js {
            // DOMContentLoaded follows parser/defer/module work, but async
            // dynamic script elements do not gate it. They do remain in the
            // document's load-event delay set, including scripts inserted by
            // a DOMContentLoaded listener.
            let _ = js.execute_script(
                "<dom-content-loaded>",
                "try { globalThis.__obscura_dispatchDocumentLifecycleEvent('DOMContentLoaded'); } catch(e) {}",
            );
        }
        tracing::debug!(
            phase = "script-execution-total",
            elapsed_ms = scripts_started.elapsed().as_millis(),
            budget_ms = script_deadline_ms,
            "script execution phase complete",
        );
        Some(ScriptLoadPhase {
            deadline: script_deadline,
            watchdog: exec_wd,
        })
    }

    pub async fn navigate(&mut self, url_str: &str) -> Result<(), PageError> {
        self.navigate_with_wait(url_str, crate::lifecycle::WaitUntil::Load)
            .await
    }

    pub async fn navigate_with_wait(
        &mut self,
        url_str: &str,
        wait_until: crate::lifecycle::WaitUntil,
    ) -> Result<(), PageError> {
        self.navigate_with_wait_post(url_str, wait_until, "GET", "")
            .await
    }

    pub async fn navigate_with_wait_post(
        &mut self,
        url_str: &str,
        wait_until: crate::lifecycle::WaitUntil,
        method: &str,
        body: &str,
    ) -> Result<(), PageError> {
        // Hard ceiling on a single end-to-end navigation. Without this a slow
        // primary fetch or a runaway settle loop can hold the V8 lock for
        // arbitrarily long (we've measured 60+ seconds on JS-heavy news
        // sites), wedging every other in-flight CDP request because the
        // dispatcher holds the lock across the entire handler. 30 seconds
        // matches reqwest's default per-request timeout — the worst case is
        // one slow primary GET plus one slow JS-redirect chain step. Override
        // with `OBSCURA_NAV_TIMEOUT_MS=NN`, or set a page-scoped deadline when
        // the automation request already has an explicit timeout.
        let nav_timeout = self.navigation_timeout();
        let nav_timeout_ms = duration_millis_u64(nav_timeout);

        let result = match tokio::time::timeout(
            nav_timeout,
            self.navigate_with_wait_post_inner(url_str, wait_until, method, body, ""),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => {
                self.lifecycle = crate::lifecycle::LifecycleState::Failed;
                Err(PageError::NetworkError(format!(
                    "navigation exceeded {nav_timeout_ms}ms deadline"
                )))
            }
        };
        if result.is_ok() {
            self.push_history(self.url_string());
        }
        result
    }

    /// Drive the JS event loop after navigation so deferred work can run:
    /// pending timers (setTimeout / setInterval), queued microtasks, in-flight
    /// fetches, and completion callbacks such as testharness's
    /// `add_completion_callback`. Returns as soon as the loop goes idle, or
    /// after `max_ms`. Without this the page is observed exactly as it stood at
    /// the load event, before any async work settles, which silently strands
    /// timer-driven tests and dynamic pages.
    pub async fn settle(&mut self, max_ms: u64) {
        if max_ms == 0 {
            return;
        }
        let settle_started = std::time::Instant::now();
        let settle_deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_millis(max_ms);
        // Pump, then give any frame document that finished fetching a realm of
        // its own. Attaching one runs its scripts, which can start timers,
        // fetches and further frames, so keep alternating until no new frame
        // appears or the budget is gone (issue #600).
        loop {
            let remaining = max_ms.saturating_sub(settle_started.elapsed().as_millis() as u64);
            if remaining == 0 {
                break;
            }
            if let Some(js) = &mut self.js {
                if std::env::var_os("OBSCURA_STRICT_SETTLE").is_some() {
                    if let Err(error) = Self::settle_runtime_for_duration(js, remaining).await {
                        tracing::warn!("strict settle JavaScript task failed: {error}");
                        self.top_load_pending = false;
                        self.lifecycle = LifecycleState::Failed;
                        break;
                    }
                } else {
                    // A deno_core event loop remains "busy" for any future timer,
                    // including analytics intervals and animation loops which do
                    // not make the page more ready. Require a short window without
                    // observable document/network/script activity instead. The
                    // absolute caller budget and V8 watchdog still bound both
                    // asynchronous work and synchronous microtask storms.
                    if let Err(error) = js.run_event_loop_until_quiescent(remaining, 150).await {
                        tracing::warn!("adaptive settle JavaScript task failed: {error}");
                        self.top_load_pending = false;
                        self.lifecycle = LifecycleState::Failed;
                        break;
                    }
                }
            }
            let advanced =
                match tokio::time::timeout_at(settle_deadline, self.advance_frames()).await {
                    Ok(advanced) => advanced,
                    Err(_) => break,
                };
            if !advanced {
                break;
            }
        }
        #[cfg(feature = "render")]
        {
            // Timers, fetch completions, and framework commits commonly append
            // images or @font-face rules during settling. Seed those resources
            // here so a following capture remains a fast observation of the
            // retained page rather than initiating its own network phase.
            let warmup_ms = std::env::var("OBSCURA_RENDER_RESOURCE_SETTLE_WARMUP_MS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1_000);
            let remaining_ms =
                remaining_settle_resource_warmup_ms(max_ms, settle_started.elapsed(), warmup_ms);
            if remaining_ms != 0 {
                let _ = self.prepare_screenshot_resources(remaining_ms).await;
            }
        }
    }

    /// Pump the event loop and retain the full requested wall-clock delay.
    /// The CLI uses this for an explicitly supplied `--wait`; callers asking
    /// for a fixed capture delay should not be silently shortened by adaptive
    /// readiness heuristics.
    pub async fn settle_for_duration(&mut self, duration_ms: u64) {
        if duration_ms == 0 {
            return;
        }
        // A fixed wait must retain its full wall clock, but it still has to
        // alternate runtime work with frame attachment and message delivery.
        // Attaching frames only after the entire delay strands their timers,
        // fetches and multi-turn postMessage handshakes until a second settle.
        // Challenge widgets are a common example: the child reports ready,
        // the parent sends configuration, then the child starts image loads.
        const FRAME_PUMP_SLICE_MS: u64 = 50;
        let started = std::time::Instant::now();
        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_millis(duration_ms);
        loop {
            let remaining = duration_ms.saturating_sub(started.elapsed().as_millis() as u64);
            if remaining == 0 {
                break;
            }
            let slice = remaining.min(FRAME_PUMP_SLICE_MS);
            if let Some(js) = &mut self.js {
                if let Err(error) = Self::settle_runtime_for_duration(js, slice).await {
                    tracing::warn!("fixed settle JavaScript task failed: {error}");
                    self.top_load_pending = false;
                    self.lifecycle = LifecycleState::Failed;
                    break;
                }
            } else {
                tokio::time::sleep(tokio::time::Duration::from_millis(slice)).await;
            }
            if tokio::time::timeout_at(deadline, self.advance_frames())
                .await
                .is_err()
            {
                break;
            }
        }
    }

    /// Pump the page for a fixed wall-clock budget while committing any
    /// top-level navigation requested by page script. Unlike a plain settle,
    /// this follows post-load `location` changes, resets the old document, and
    /// continues pumping the final page for the remaining budget.
    pub async fn settle_for_duration_following_navigations(
        &mut self,
        duration_ms: u64,
    ) -> Result<(), PageError> {
        const BROWSER_PUMP_SLICE_MS: u64 = 50;
        let started = std::time::Instant::now();
        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_millis(duration_ms);
        loop {
            while self.process_pending_navigation().await? {}

            let remaining = duration_ms.saturating_sub(started.elapsed().as_millis() as u64);
            if remaining == 0 {
                break;
            }
            let slice = remaining.min(BROWSER_PUMP_SLICE_MS);
            if let Some(js) = &mut self.js {
                if let Err(error) = Self::settle_runtime_for_duration(js, slice).await {
                    self.top_load_pending = false;
                    self.lifecycle = LifecycleState::Failed;
                    return Err(PageError::NetworkError(format!(
                        "fixed settle JavaScript task failed: {error}"
                    )));
                }
            } else {
                tokio::time::sleep(tokio::time::Duration::from_millis(slice)).await;
            }
            if tokio::time::timeout_at(deadline, self.advance_frames())
                .await
                .is_err()
            {
                break;
            }
        }
        Ok(())
    }

    /// Advance one wake-driven browser task for a continuously owned page.
    /// `true` means deno_core reached full idle; `false` means one wake/task was
    /// delivered and the owner should offer another turn after servicing any
    /// higher-priority automation commands.
    #[doc(hidden)]
    pub async fn run_autonomous_event_loop_turn(&mut self) -> Result<bool, String> {
        let turn = match self.js.as_mut() {
            Some(js) => js.run_autonomous_event_loop_turn().await,
            None => Ok(true),
        };
        let reached_idle = match turn {
            Ok(reached_idle) => reached_idle,
            Err(error) => {
                // A bounded JS task failure is terminal for this document's
                // lifecycle. In particular, a non-returning dynamic resource
                // load/error handler may leave its JS-side delay counter set;
                // retaining DomContentLoaded+pending would make Window.load
                // appear capable of completing even though the pump stopped.
                self.top_load_pending = false;
                self.lifecycle = LifecycleState::Failed;
                return Err(error);
            }
        };
        // Dynamic iframe fetches finish on the page event loop, but their
        // realms must be built by Page between turns. Keep the autonomous CDP
        // pump on the same generic frame path as settle(), so a client that
        // stays attached can observe and run child documents as they arrive.
        let frame_work = self.advance_frames().await;
        Ok(reached_idle && !frame_work)
    }

    async fn settle_runtime_for_duration(
        js: &mut ObscuraJsRuntime,
        duration_ms: u64,
    ) -> Result<(), String> {
        let started = tokio::time::Instant::now();
        let result = js.run_event_loop_for_duration(duration_ms).await;
        let requested = tokio::time::Duration::from_millis(duration_ms);
        let elapsed = started.elapsed();
        if elapsed < requested {
            tokio::time::sleep(requested - elapsed).await;
        }
        result
    }

    /// Append the current URL to the history stack, truncating any forward
    /// entries past the cursor (matches real Chrome: navigating after a
    /// goBack clobbers the forward history).
    pub fn push_history(&mut self, url: String) {
        if url.is_empty() {
            return;
        }
        // Don't dupe consecutive entries (Page.reload would otherwise pile up).
        if self.history.get(self.history_index) == Some(&url) {
            return;
        }
        if !self.history.is_empty() && self.history_index < self.history.len() - 1 {
            self.history.truncate(self.history_index + 1);
        }
        self.history.push(url);
        self.history_index = self.history.len() - 1;
    }

    /// Move the history cursor without re-navigating; used by
    /// Page.navigateToHistoryEntry which then drives the actual fetch.
    pub fn set_history_index(&mut self, idx: usize) {
        if idx < self.history.len() {
            self.history_index = idx;
        }
    }

    async fn navigate_with_wait_post_inner(
        &mut self,
        url_str: &str,
        wait_until: crate::lifecycle::WaitUntil,
        method: &str,
        body: &str,
        initial_referrer: &str,
    ) -> Result<(), PageError> {
        let mut current_url = url_str.to_string();
        let mut current_method = method.to_string();
        let mut current_body = body.to_string();
        let mut document_referrer = initial_referrer.to_string();
        const REDIRECT_LIMIT: usize = 10;
        for chain in 0..REDIRECT_LIMIT {
            self.navigate_single(
                &current_url,
                wait_until,
                &current_method,
                &current_body,
                &document_referrer,
            )
            .await?;
            if let Some((next_url, next_method, next_body)) = self.take_pending_navigation() {
                if cross_scheme_to_file(&current_url, &next_url) {
                    // SOP gate. A web page must not be able to drive
                    // a navigation to file:// and then read the loaded
                    // document. Without this an http(s) page sets
                    // window.onload, calls location.href = "file:..."
                    // and harvests document.body from a local file
                    // once the new document loads.
                    tracing::warn!(
                        "blocking JS-initiated cross-scheme navigation to file: {} -> {}",
                        current_url,
                        next_url,
                    );
                    break;
                }
                tracing::info!(
                    "JS-triggered navigation chain: {} {} -> {}",
                    current_method,
                    current_url,
                    next_url
                );
                document_referrer = self
                    .url
                    .as_ref()
                    .and_then(|source| {
                        Url::parse(&next_url)
                            .ok()
                            .map(|target| navigation_referrer(source, &target))
                    })
                    .unwrap_or_default();
                current_url = next_url;
                current_method = next_method;
                current_body = next_body;
                if chain + 1 == REDIRECT_LIMIT {
                    // Hit the cap and the page still wants to keep
                    // chaining. Surface that as an error instead of
                    // returning Ok(()) so callers can distinguish a
                    // successful load from a redirect storm.
                    return Err(PageError::TooManyRedirects(REDIRECT_LIMIT));
                }
                continue;
            }
            break;
        }
        Ok(())
    }

    async fn navigate_single(
        &mut self,
        url_str: &str,
        wait_until: crate::lifecycle::WaitUntil,
        method: &str,
        body: &str,
        referrer: &str,
    ) -> Result<(), PageError> {
        let url = Url::parse(url_str).map_err(|e| PageError::InvalidUrl(e.to_string()))?;

        self.begin_top_document();

        self.lifecycle = LifecycleState::Loading;
        self.referrer = referrer.to_string();
        self.url = Some(url.clone());
        self.network_events.clear();

        if self.context.obey_robots {
            if url.scheme() == "http" || url.scheme() == "https" {
                let origin = url.origin().ascii_serialization();
                if !self.context.robots_cache.contains(&origin) {
                    let mut robots_url = url.clone();
                    robots_url.set_path("/robots.txt");
                    robots_url.set_query(None);
                    robots_url.set_fragment(None);
                    // robots.txt is a crawler policy probe, not a resource
                    // requested or rendered by the document. Keep it outside
                    // page callbacks and final-document resource archives.
                    let body = match self.http_client.fetch(&robots_url).await {
                        Ok(resp) if resp.status == 200 => {
                            String::from_utf8_lossy(&resp.body).into_owned()
                        }
                        _ => String::new(),
                    };
                    self.context.robots_cache.parse_and_store(
                        &origin,
                        &body,
                        &self.context.user_agent,
                    );
                }

                if !self.context.robots_cache.is_allowed(&origin, url.path()) {
                    self.lifecycle = LifecycleState::Failed;
                    return Err(PageError::NetworkError(format!(
                        "Blocked by robots.txt: {}",
                        url
                    )));
                }
            }
        }

        if url.scheme() == "about" {
            self.commit_blank_document();
            self.init_js();
            // Preloads (Page.addScriptToEvaluateOnNewDocument, the
            // Runtime.addBinding shim) must run on about:blank too —
            // puppeteer's `browser.newPage()` lands on about:blank and
            // a follow-up `exposeFunction` is unusable otherwise.
            let preload_sources = self.preload_scripts.clone();
            if let Some(js) = &mut self.js {
                for source in &preload_sources {
                    if let Err(e) = js.execute_script_guarded("<preload>", source.as_str()) {
                        tracing::debug!("Preload script error on about:blank: {}", e);
                    }
                }
            }
            return Ok(());
        }

        let response = if url.scheme() == "data" {
            let content_type = url_str
                .strip_prefix("data:")
                .and_then(|s| s.split(',').next())
                .unwrap_or("text/html")
                .split(';')
                .next()
                .unwrap_or("text/html")
                .to_string();
            let body_bytes = decode_data_uri(url_str).unwrap_or_default();
            let mut headers = std::collections::HashMap::new();
            headers.insert("content-type".to_string(), content_type);
            Ok(obscura_net::Response {
                url: url.clone(),
                status: 200,
                headers,
                body: body_bytes,
                redirected_from: Vec::new(),
            })
        } else if method == "POST" {
            self.http_client
                .post_form_with_callbacks(&url, body, Some(&self.callbacks))
                .await
        } else {
            self.do_fetch(&url).await
        }
        .map_err(|e| {
            self.lifecycle = LifecycleState::Failed;
            PageError::NetworkError(e.to_string())
        })?;

        // Store binary main resources (images, PDFs, octet-stream) base64 so
        // Network.getResponseBody returns intact bytes. A UTF-8-lossy text store
        // corrupts them (issue #340). Text-like types stay as text.
        let main_is_binary = !is_text_like_content_type(response.content_type());
        self.record_network_event_with_body(
            url.as_str(),
            "GET",
            "Document",
            response.status,
            &response.headers,
            &response.body,
            main_is_binary,
        );

        if !response.redirected_from.is_empty() {
            self.url = Some(response.url.clone());
        }

        // Honor the response charset: HTTP Content-Type → <meta charset> sniff
        // in the first 1KB → UTF-8 fallback. Without this, every non-UTF-8
        // page (GBK, Big5, Shift-JIS, Windows-125x, EUC-KR, ISO-8859-x)
        // came through as replacement characters.
        let (body_text, encoding_name) =
            obscura_net::decode_response_with_name(&response.body, response.content_type());
        self.encoding = encoding_name.to_string();
        let dom = parse_html(&body_text);

        self.title = dom
            .query_selector("title")
            .ok()
            .flatten()
            .map(|title_id| dom.text_content(title_id))
            .unwrap_or_default();

        self.dom = Some(dom);
        self.init_js();

        // Freeze parser-owned resources, their encounter order, and their URL
        // bases before CDP new-document code sees the fully parsed backing
        // tree. Preloads may append, move, or rewrite nodes; that must neither
        // enroll new parser work nor change the request base of existing work.
        // Marking original scripts started here also prevents a preload which
        // moves one from triggering it through the dynamic-script path.
        let parser_scripts = self
            .snapshot_parser_scripts()
            .ok_or_else(|| PageError::ParseError("JavaScript runtime disappeared".to_string()))?;
        self.mark_parser_scripts_started(&parser_scripts);
        let parser_stylesheets = self
            .snapshot_parser_stylesheets()
            .ok_or_else(|| PageError::ParseError("JavaScript runtime disappeared".to_string()))?;
        let parser_body_order = parser_stylesheets.body_parser_order;
        self.mark_parser_stylesheets_pending(&parser_stylesheets);

        // Static stylesheet owner events are the first page-authored
        // callbacks this realm can dispatch. Establish parser readiness and
        // install CDP new-document sources before starting their frozen
        // network requests, so load/error handlers observe `loading` and the
        // preload state.
        if let Some(js) = &mut self.js {
            let _ = js.execute_script(
                "<ready-state>",
                "globalThis.__documentReadyState__ = 'loading';",
            );
        }
        let preload_sources = self.preload_scripts.clone();
        let preload_watchdog = self.js.as_mut().map(|js| {
            js.arm_watchdog(std::time::Duration::from_millis(
                LIFECYCLE_CALLBACK_WATCHDOG_MS,
            ))
        });
        if let Some(js) = &mut self.js {
            for source in &preload_sources {
                if let Err(error) = js.execute_script_guarded("<preload>", source) {
                    tracing::debug!("Preload script error: {error}");
                }
            }
        }
        let preload_watchdog_fired = match (self.js.as_mut(), preload_watchdog) {
            (Some(js), Some(watchdog)) => js.disarm_watchdog(watchdog),
            _ => false,
        };
        if preload_watchdog_fired {
            self.top_load_pending = false;
            self.lifecycle = LifecycleState::Failed;
            return Err(PageError::NetworkError(
                "new-document preload exceeded its execution budget".to_string(),
            ));
        }
        let fetched_stylesheets = self
            .fetch_stylesheets_from_snapshot(parser_stylesheets)
            .await;
        let author_stylesheets = fetched_stylesheets.materialized;
        if self.lifecycle == LifecycleState::Failed {
            return Err(PageError::NetworkError(
                "parser stylesheet lifecycle callback failed".to_string(),
            ));
        }

        // Inject CSS as a global so getComputedStyle and any CSS-aware shim
        // can read it. Has to happen before scripts run, regardless of
        // waitUntil, so handlers that read window.__obscura_css see it.
        if !author_stylesheets.is_empty() {
            let combined_css = author_stylesheets
                .iter()
                .map(|(_, css)| css.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            // Use the thorough template-literal escape that covers U+2028 /
            // U+2029 and other controls, so CSS cannot escape this assignment.
            let escaped = escape_for_js_template_literal(&combined_css);
            let code = format!("globalThis.__obscura_css = `{}`;", escaped);
            if let Some(js) = &mut self.js {
                let _ = js.execute_script("<css>", &code);
            }
            for (target, css) in &author_stylesheets {
                let result = match target {
                    AuthorStylesheetTarget::Linked {
                        nid,
                        parser_order,
                        raw_href,
                        request_href,
                    } => {
                        self.pending_parser_stylesheet_events.insert(
                            *nid,
                            (
                                *parser_order,
                                materialize_parser_stylesheet_script_with_token(
                                    *nid,
                                    css,
                                    request_href,
                                    raw_href,
                                ),
                            ),
                        );
                        Ok(())
                    }
                    AuthorStylesheetTarget::InlineImport { nid } => self.js.as_mut().map_or_else(
                        || Err("JavaScript runtime disappeared".to_string()),
                        |js| {
                            js.execute_script(
                                "<fetch_stylesheets>",
                                &materialize_inline_import_script(*nid, css),
                            )
                        },
                    ),
                };
                if let Err(error) = result {
                    self.top_load_pending = false;
                    self.lifecycle = LifecycleState::Failed;
                    return Err(PageError::NetworkError(format!(
                        "parser stylesheet lifecycle callback failed: {error}"
                    )));
                }
            }
        }
        for (nid, parser_order, raw_href, request_href) in fetched_stylesheets.failed_links {
            self.pending_parser_stylesheet_events.insert(
                nid,
                (
                    parser_order,
                    complete_parser_stylesheet_script_with_token(
                        nid,
                        "error",
                        request_href.as_deref(),
                        &raw_href,
                    ),
                ),
            );
        }
        self.document_timeline_origin = std::time::Instant::now();
        #[cfg(feature = "render")]
        if let Some(js) = &self.js {
            js.reset_animation_timeline();
        }
        if let Some(js) = &mut self.js {
            let _ = js.execute_script("<iframe-load>",
                "(function() { var iframes = document.querySelectorAll('iframe[src]'); for (var i = 0; i < iframes.length; i++) { if (iframes[i].hasAttribute('srcdoc')) continue; var src = iframes[i].getAttribute('src'); if (src && src !== 'about:blank') iframes[i]._loadIframeSrc(src); } })()");
        }

        // Scripts can synchronously flush style/layout through
        // getComputedStyle(), geometry, ResizeObserver, or IntersectionObserver.
        // Seed their image/font dependencies concurrently through the page
        // transport first. Otherwise the first CSSOM read falls into the
        // renderer's synchronous resource loader and serial network latency pins
        // V8, making framework startup take many seconds. This is deliberately
        // bounded: navigation should not wait indefinitely for decorative
        // resources.
        #[cfg(feature = "render")]
        {
            let warmup_ms = std::env::var("OBSCURA_RENDER_RESOURCE_WARMUP_MS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1_000);
            let _ = self.prepare_screenshot_resources(warmup_ms).await;
        }

        // Spec: DOMContentLoaded fires AFTER parser-blocking scripts run,
        // not before. Skipping execute_scripts() on the DCL path meant
        // every inline <script> in the page was silently dropped: form
        // listeners never registered, frameworks never bootstrapped,
        // page.click() handlers were no-ops. Run through DOMContentLoaded here;
        // the separate load gate below waits for frames and resources.
        let script_phase = self
            .execute_scripts_to_dom_content_loaded(None, Some(parser_scripts), parser_body_order)
            .await
            .ok_or_else(|| PageError::ParseError("JavaScript runtime disappeared".to_string()))?;
        if self.lifecycle == LifecycleState::Failed {
            if let (Some(js), Some(watchdog)) = (self.js.as_mut(), script_phase.watchdog) {
                let _ = js.disarm_watchdog(watchdog);
            }
            self.top_load_pending = false;
            return Err(PageError::NetworkError(
                "parser stylesheet lifecycle callback failed".to_string(),
            ));
        }
        let script_deadline = script_phase.deadline;

        #[cfg(feature = "render")]
        {
            // Page scripts and their bounded post-script event-loop pass can
            // create responsive images, inline styles, and @font-face rules
            // that did not exist during the parser warmup above. Discover them
            // before navigation becomes capture-ready. Known parser resources
            // are filtered by the render cache, so ordinary pages pay only the
            // inexpensive scan on this second pass.
            let warmup_ms = std::env::var("OBSCURA_RENDER_RESOURCE_POST_SCRIPT_WARMUP_MS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1_000);
            let _ = self.prepare_screenshot_resources(warmup_ms).await;
        }

        self.lifecycle = LifecycleState::DomContentLoaded;
        // Establish the browser-side load gate before frame attachment or any
        // other cancellable await. A caller timing out does not cancel the
        // underlying document load in browsers; autonomous turns may still
        // complete it and dispatch the pending lifecycle events.
        self.top_load_pending = true;

        // Before any `wait_until` can return, because the frames belong to the
        // document rather than to one readiness level. Puppeteer and Playwright
        // send `Page.navigate` with no `waitUntil`, which lands here and returns
        // on the next line, so building frames further down left every real CDP
        // client seeing a page with no frames at all.
        self.build_document_frames().await;

        if wait_until == crate::lifecycle::WaitUntil::DomContentLoaded {
            let watchdog_fired = match (self.js.as_mut(), script_phase.watchdog) {
                (Some(js), Some(watchdog)) => js.disarm_watchdog(watchdog),
                _ => false,
            };
            if watchdog_fired || self.lifecycle == LifecycleState::Failed {
                self.top_load_pending = false;
                self.lifecycle = LifecycleState::Failed;
                return Err(PageError::NetworkError(
                    "document lifecycle callback exceeded its execution budget".to_string(),
                ));
            }
            return Ok(());
        }

        let document_loaded = self.drive_document_load(script_deadline).await;
        let watchdog_fired = match (self.js.as_mut(), script_phase.watchdog) {
            (Some(js), Some(watchdog)) => js.disarm_watchdog(watchdog),
            _ => false,
        };
        if watchdog_fired {
            self.top_load_pending = false;
            self.lifecycle = LifecycleState::Failed;
        }
        if !document_loaded || self.lifecycle == LifecycleState::Failed {
            self.lifecycle = LifecycleState::Failed;
            return Err(PageError::NetworkError(
                "document load event remained blocked at the script deadline".to_string(),
            ));
        }

        if let Some(js) = &mut self.js {
            if let Ok(new_title) = js.evaluate("document.title") {
                if let Some(t) = new_title.as_str() {
                    self.title = t.to_string();
                }
            }
        }

        if matches!(
            wait_until,
            crate::lifecycle::WaitUntil::NetworkIdle0 | crate::lifecycle::WaitUntil::NetworkIdle2
        ) {
            let threshold = match wait_until {
                crate::lifecycle::WaitUntil::NetworkIdle0 => 0,
                crate::lifecycle::WaitUntil::NetworkIdle2 => 2,
                _ => 0,
            };

            // Same hazard as the post-script settle: a synchronous poll can pin
            // the thread past the 5s network-idle deadline, so arm a watchdog
            // that terminates the isolate ~500ms past it.
            let netidle_wd = self
                .js
                .as_mut()
                .map(|js| js.arm_watchdog(std::time::Duration::from_millis(5500)));
            let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
            let mut idle_since: Option<tokio::time::Instant> = None;
            let mut event_loop_failed = false;

            loop {
                let active = self.http_client.active_requests();
                let now = tokio::time::Instant::now();

                if active <= threshold {
                    if idle_since.is_none() {
                        idle_since = Some(now);
                    }
                    if now.duration_since(idle_since.unwrap())
                        >= tokio::time::Duration::from_millis(500)
                    {
                        break;
                    }
                } else {
                    idle_since = None;
                }

                if now >= deadline {
                    tracing::debug!(
                        "Network idle timeout reached with {} active requests",
                        active
                    );
                    break;
                }

                if let Some(js) = &mut self.js {
                    if matches!(
                        tokio::time::timeout(
                            tokio::time::Duration::from_millis(50),
                            js.run_event_loop(),
                        )
                        .await,
                        Ok(Err(_))
                    ) {
                        event_loop_failed = true;
                        break;
                    }
                } else {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }

            let watchdog_fired = if let Some(token) = netidle_wd {
                if let Some(js) = self.js.as_mut() {
                    js.disarm_watchdog(token)
                } else {
                    false
                }
            } else {
                false
            };
            if event_loop_failed || watchdog_fired {
                self.top_load_pending = false;
                self.lifecycle = LifecycleState::Failed;
                return Err(PageError::NetworkError(
                    "JavaScript execution failed while waiting for network idle".to_string(),
                ));
            }
            self.lifecycle = LifecycleState::NetworkIdle;
        }

        Ok(())
    }

    /// Builds the child frames of the document that just loaded.
    ///
    /// Loading a document includes loading the frames in it, so this belongs to
    /// navigation rather than to `settle`: a CDP client that only navigates
    /// would otherwise be told the page has no frames, because nothing had
    /// given them realms yet.
    ///
    /// A frame's document is fetched by page script, so it arrives from the
    /// event loop rather than being ready the moment parsing ends. Pages
    /// without an iframe skip the pumping entirely and pay one native selector
    /// query.
    async fn build_document_frames(&mut self) {
        // How many rounds of "attach a frame, let it start its own" to follow.
        // A frame can add a frame, so this needs a bound rather than a loop
        // until quiet: a page that adds one on every turn would never finish.
        const ROUNDS: usize = 8;
        const ROUND_MS: u64 = 50;

        let has_iframe = self
            .with_dom(|dom| dom.query_selector("iframe").ok().flatten().is_some())
            .unwrap_or(false);
        let has_pending_frame = self
            .js
            .as_ref()
            .is_some_and(|js| js.pending_frame_document_queue().0 != 0);
        if !has_iframe && !has_pending_frame {
            return;
        }

        for _ in 0..ROUNDS {
            if let Some(js) = &mut self.js {
                let _ = tokio::time::timeout(
                    tokio::time::Duration::from_millis(ROUND_MS),
                    js.run_event_loop(),
                )
                .await;
            }
            let advanced = self.advance_frames().await;
            let pending = self
                .js
                .as_ref()
                .is_some_and(|js| js.pending_frame_document_queue().0 != 0);
            if !advanced && !pending {
                break;
            }
        }
    }

    fn commit_blank_document(&mut self) {
        self.frames.clear();
        self.js = None;
        self.url = Some(Url::parse("about:blank").unwrap());
        self.dom = Some(parse_html(
            "<!DOCTYPE html><html><head></head><body></body></html>",
        ));
        self.title = String::new();
        self.lifecycle = LifecycleState::Loaded;
        self.top_load_pending = false;
        self.document_timeline_origin = std::time::Instant::now();
    }

    pub fn navigate_blank(&mut self) {
        self.begin_top_document();
        self.commit_blank_document();
    }

    pub fn url_string(&self) -> String {
        self.url
            .as_ref()
            .map(|u| u.to_string())
            .unwrap_or_else(|| "about:blank".to_string())
    }

    pub fn with_dom<R>(&self, f: impl FnOnce(&DomTree) -> R) -> Option<R> {
        if let Some(js) = &self.js {
            return js.with_dom(f);
        }
        self.dom.as_ref().map(f)
    }

    /// Concurrently seed the synchronous renderer cache through the owning
    /// page transport. This removes serial image/font HTTP from the first
    /// screenshot while retaining cookies, proxy policy, interception, CORS,
    /// response limits, and connection pooling.
    #[cfg(feature = "render")]
    pub async fn prepare_screenshot_resources(&mut self, max_ms: u64) -> usize {
        self.prepare_screenshot_resources_with_report(max_ms)
            .await
            .loaded
    }

    /// Concurrently seed the synchronous renderer cache and report all work
    /// which did not complete in this bounded pass.
    ///
    /// This is the diagnostic form of [`Page::prepare_screenshot_resources`].
    /// It prevents archive callers from mistaking `loaded == 0` for completion
    /// when the pass timed out or when more than 128 candidates were present.
    #[cfg(feature = "render")]
    pub async fn prepare_screenshot_resources_with_report(
        &mut self,
        max_ms: u64,
    ) -> ScreenshotResourceWarmupReport {
        #[derive(Clone)]
        struct WarmupCandidate {
            raw: String,
            initiator: Url,
            frame_id: u32,
            profile: Option<obscura_js::ImageRequestProfile>,
            kind: ResourceType,
            /// Non-empty only for a not-yet-loaded frame stylesheet. Multiple
            /// links to the same URL share one response but each gets its own
            /// CSSOM/materialized owner.
            stylesheet_links: Vec<(usize, u8)>,
        }

        let started = std::time::Instant::now();
        if self.js.is_none() {
            return ScreenshotResourceWarmupReport::default();
        }
        let Some(document_url) = self.url.clone() else {
            return ScreenshotResourceWarmupReport::default();
        };
        let base_url = self
            .resolve_base_url()
            .unwrap_or_else(|| document_url.clone());
        let mut candidates: std::collections::BTreeMap<
            (u32, u8, String, Option<obscura_js::ImageRequestProfile>),
            WarmupCandidate,
        > = std::collections::BTreeMap::new();

        let mut top_inline_import_problems = Vec::new();
        if let Some(js) = self.js.as_mut() {
            match js.inline_stylesheet_sources() {
                Ok(inline_stylesheets) => {
                    for (style_index, css, _) in inline_stylesheets {
                        let (imports, rules) = split_css_imports(&css);
                        if imports.is_empty() {
                            continue;
                        }
                        for import in &imports {
                            if base_url.join(&import.url).is_err() {
                                top_inline_import_problems.push(format!(
                                    "top-level inline stylesheet import URL could not be resolved: {}",
                                    import.url,
                                ));
                            }
                        }
                        if let Err(error) = js.execute_script(
                            "<archive:inline-import>",
                            &queue_inline_stylesheet_imports_script(
                                style_index,
                                &rules,
                                &imports,
                                &base_url,
                                1,
                            ),
                        ) {
                            top_inline_import_problems.push(format!(
                                "top-level inline stylesheet import setup failed: {error}",
                            ));
                        }
                    }
                }
                Err(error) => top_inline_import_problems
                    .push(format!("top-level inline stylesheet scan failed: {error}",)),
            }
            for (raw, profile) in js.pending_render_image_urls() {
                if let Ok(mut url) = url::Url::parse(&raw) {
                    url.set_fragment(None);
                    let raw = url.to_string();
                    if !js.render_image_resource_is_known(&raw, profile) {
                        candidates.insert(
                            (0, 0, raw.clone(), Some(profile)),
                            WarmupCandidate {
                                raw,
                                initiator: document_url.clone(),
                                frame_id: 0,
                                profile: Some(profile),
                                kind: ResourceType::Image,
                                stylesheet_links: Vec::new(),
                            },
                        );
                    }
                }
            }
            let css_sources = js.render_resource_style_sources();
            for css in css_sources {
                for raw in css_resource_urls(&css, &base_url) {
                    if let Ok(mut url) = url::Url::parse(&raw) {
                        let kind = render_resource_type(&url);
                        url.set_fragment(None);
                        let raw = url.to_string();
                        if !js.render_resource_is_known(&raw) {
                            candidates.insert(
                                (0, 0, raw.clone(), None),
                                WarmupCandidate {
                                    raw,
                                    initiator: document_url.clone(),
                                    frame_id: 0,
                                    profile: None,
                                    kind,
                                    stylesheet_links: Vec::new(),
                                },
                            );
                        }
                    }
                }
            }
            match js.external_stylesheet_urls() {
                Ok(stylesheets) => {
                    for (link_index, href, import_depth) in stylesheets {
                        let Ok(mut url) = base_url.join(&href) else {
                            top_inline_import_problems.push(format!(
                                "top-level stylesheet URL could not be resolved: {href}",
                            ));
                            continue;
                        };
                        url.set_fragment(None);
                        let raw = url.to_string();
                        let key = (0, 1, raw.clone(), None);
                        candidates
                            .entry(key)
                            .and_modify(|candidate| {
                                candidate.stylesheet_links.push((link_index, import_depth));
                            })
                            .or_insert_with(|| WarmupCandidate {
                                raw,
                                initiator: document_url.clone(),
                                frame_id: 0,
                                profile: None,
                                kind: ResourceType::Stylesheet,
                                stylesheet_links: vec![(link_index, import_depth)],
                            });
                    }
                }
                Err(error) => top_inline_import_problems
                    .push(format!("top-level linked stylesheet scan failed: {error}",)),
            }
        }
        for problem in top_inline_import_problems {
            self.mark_resource_archive_incomplete(problem);
        }

        // A frame has its own DOM and render cache. Re-scan every live realm on
        // every pass: frame scripts commonly install a responsive image,
        // inline background, or stylesheet only after a timer/postMessage.
        // The final archive warmup calls this method repeatedly, so a newly
        // materialized stylesheet's url()/font dependencies are discovered on
        // the next pass without teaching the renderer a second CSS parser.
        let mut frame_inline_import_problems = Vec::new();
        if let Some(js) = self.js.as_mut() {
            for frame in &self.frames {
                let frame_id = frame.frame_id();
                let Ok(initiator) = Url::parse(frame.url()) else {
                    continue;
                };
                for (raw, profile) in frame.pending_render_image_urls() {
                    if let Ok(mut url) = Url::parse(&raw) {
                        url.set_fragment(None);
                        let raw = url.to_string();
                        candidates.insert(
                            (frame_id, 0, raw.clone(), Some(profile)),
                            WarmupCandidate {
                                raw,
                                initiator: initiator.clone(),
                                frame_id,
                                profile: Some(profile),
                                kind: ResourceType::Image,
                                stylesheet_links: Vec::new(),
                            },
                        );
                    }
                }

                let style_base = frame
                    .document_base_url(js)
                    .unwrap_or_else(|| initiator.clone());
                match frame.inline_stylesheet_sources(js) {
                    Ok(inline_stylesheets) => {
                        for (style_index, css, _) in inline_stylesheets {
                            let (imports, rules) = split_css_imports(&css);
                            if imports.is_empty() {
                                continue;
                            }
                            for import in &imports {
                                if style_base.join(&import.url).is_err() {
                                    frame_inline_import_problems.push(format!(
                                        "frame {frame_id} inline stylesheet import URL could not be resolved: {}",
                                        import.url,
                                    ));
                                }
                            }
                            if let Err(error) = frame.execute_script(
                                js,
                                &queue_inline_stylesheet_imports_script(
                                    style_index,
                                    &rules,
                                    &imports,
                                    &style_base,
                                    1,
                                ),
                            ) {
                                frame_inline_import_problems.push(format!(
                                    "frame {frame_id} inline stylesheet import setup failed: {error}",
                                ));
                            }
                        }
                    }
                    Err(error) => frame_inline_import_problems.push(format!(
                        "frame {frame_id} inline stylesheet scan failed: {error}",
                    )),
                }
                for css in frame.render_resource_style_sources() {
                    for raw in css_resource_urls(&css, &style_base) {
                        if let Ok(mut url) = Url::parse(&raw) {
                            let kind = render_resource_type(&url);
                            url.set_fragment(None);
                            let raw = url.to_string();
                            if !frame.render_resource_is_known(&raw) {
                                candidates.insert(
                                    (frame_id, 0, raw.clone(), None),
                                    WarmupCandidate {
                                        raw,
                                        initiator: initiator.clone(),
                                        frame_id,
                                        profile: None,
                                        kind,
                                        stylesheet_links: Vec::new(),
                                    },
                                );
                            }
                        }
                    }
                }

                for (link_index, _, raw, import_depth) in frame.external_stylesheet_urls(js) {
                    let Ok(mut url) = Url::parse(&raw) else {
                        continue;
                    };
                    url.set_fragment(None);
                    let raw = url.to_string();
                    let key = (frame_id, 1, raw.clone(), None);
                    candidates
                        .entry(key)
                        .and_modify(|candidate| {
                            candidate.stylesheet_links.push((link_index, import_depth));
                        })
                        .or_insert_with(|| WarmupCandidate {
                            raw,
                            initiator: initiator.clone(),
                            frame_id,
                            profile: None,
                            kind: ResourceType::Stylesheet,
                            stylesheet_links: vec![(link_index, import_depth)],
                        });
                }
            }
        }
        for problem in frame_inline_import_problems {
            self.mark_resource_archive_incomplete(problem);
        }

        candidates.retain(|_, candidate| {
            subresource_allowed(Some(&candidate.initiator), &candidate.raw)
                && !self.should_block_url(&candidate.raw)
        });
        let discovered = candidates.len();
        if max_ms == 0 {
            return ScreenshotResourceWarmupReport {
                discovered,
                remaining: discovered,
                ..ScreenshotResourceWarmupReport::default()
            };
        }
        if candidates.len() > 128 {
            candidates = candidates.into_iter().take(128).collect();
        }
        if candidates.is_empty() {
            return ScreenshotResourceWarmupReport::default();
        }

        let requested: Vec<WarmupCandidate> = candidates.into_values().collect();
        let attempted = requested.len();
        let client = self.http_client.clone();
        #[cfg(feature = "stealth")]
        let stealth_client = self.stealth_client.clone();
        let callbacks = self.callbacks.clone();
        use futures::StreamExt as _;
        let requests = futures::stream::iter(requested.into_iter().map(|candidate| {
            let client = client.clone();
            #[cfg(feature = "stealth")]
            let stealth_client = stealth_client.clone();
            let callbacks = callbacks.clone();
            async move {
                let parsed =
                    url::Url::parse(&candidate.raw).expect("validated render resource URL");
                let mut request =
                    ResourceRequest::subresource(candidate.kind, &candidate.initiator)
                        .in_frame(candidate.frame_id);
                match candidate.profile {
                    Some(obscura_js::ImageRequestProfile::CorsSameOrigin) => {
                        request.mode = obscura_net::RequestMode::Cors;
                        request.credentials = obscura_net::RequestCredentials::SameOrigin;
                    }
                    Some(obscura_js::ImageRequestProfile::CorsInclude) => {
                        request.mode = obscura_net::RequestMode::Cors;
                        request.credentials = obscura_net::RequestCredentials::Include;
                    }
                    _ => {}
                }
                #[cfg(feature = "stealth")]
                let result = if let Some(stealth_client) = stealth_client {
                    stealth_client
                        .fetch_resource_with_callbacks(&parsed, request, Some(&callbacks))
                        .await
                } else {
                    client
                        .fetch_resource_with_callbacks(&parsed, request, Some(&callbacks))
                        .await
                };
                #[cfg(not(feature = "stealth"))]
                let result = client
                    .fetch_resource_with_callbacks(&parsed, request, Some(&callbacks))
                    .await;
                (candidate, result)
            }
        }))
        .buffer_unordered(16);
        futures::pin_mut!(requests);
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(max_ms);
        let mut loaded = 0usize;
        let mut failed = 0usize;
        let mut timed_out = 0usize;
        let mut fetched_stylesheets = Vec::new();
        loop {
            match tokio::time::timeout_at(deadline, requests.next()).await {
                Ok(Some((candidate, result))) => {
                    let mut outcome = None;
                    let mut successful = false;
                    match result {
                        Ok(response) => {
                            self.record_network_event_with_body(
                                response.url.as_str(),
                                "GET",
                                match candidate.kind {
                                    ResourceType::Stylesheet => "Stylesheet",
                                    ResourceType::Font => "Font",
                                    _ => "Image",
                                },
                                response.status,
                                &response.headers,
                                &response.body,
                                candidate.kind != ResourceType::Stylesheet,
                            );
                            if candidate.kind == ResourceType::Stylesheet
                                && (200..300).contains(&response.status)
                            {
                                fetched_stylesheets.push((candidate, response));
                                continue;
                            }
                            if (200..300).contains(&response.status) {
                                successful = true;
                                outcome = Some(response.body);
                            } else if candidate.kind == ResourceType::Stylesheet {
                                let owner = if candidate.frame_id == 0 {
                                    "top-level".to_string()
                                } else {
                                    format!("frame {}", candidate.frame_id)
                                };
                                self.mark_resource_archive_incomplete(format!(
                                    "{owner} stylesheet {} returned HTTP {}",
                                    candidate.raw, response.status,
                                ));
                            } else if candidate.frame_id != 0 {
                                self.mark_resource_archive_incomplete(format!(
                                    "frame {} resource {} returned HTTP {}",
                                    candidate.frame_id, candidate.raw, response.status,
                                ));
                            }
                        }
                        Err(error) => {
                            if candidate.kind == ResourceType::Stylesheet {
                                let owner = if candidate.frame_id == 0 {
                                    "top-level".to_string()
                                } else {
                                    format!("frame {}", candidate.frame_id)
                                };
                                self.mark_resource_archive_incomplete(format!(
                                    "{owner} stylesheet fetch failed: {}: {}",
                                    candidate.raw, error,
                                ));
                            } else if candidate.frame_id != 0 {
                                self.mark_resource_archive_incomplete(format!(
                                    "frame {} resource fetch failed: {}: {}",
                                    candidate.frame_id, candidate.raw, error,
                                ));
                            }
                        }
                    }
                    if successful {
                        loaded += 1;
                    } else {
                        failed += 1;
                    }
                    if candidate.kind != ResourceType::Stylesheet {
                        if candidate.frame_id == 0 {
                            if let Some(js) = &mut self.js {
                                match candidate.profile {
                                    Some(profile) => js.seed_render_image_resource(
                                        candidate.raw,
                                        profile,
                                        outcome,
                                    ),
                                    None => js.seed_render_resource(candidate.raw, outcome),
                                }
                            }
                        } else if let Some(frame) = self
                            .frames
                            .iter()
                            .find(|frame| frame.frame_id() == candidate.frame_id)
                        {
                            match candidate.profile {
                                Some(profile) => frame.seed_render_image_resource(
                                    candidate.raw,
                                    profile,
                                    outcome,
                                ),
                                None => frame.seed_render_resource(candidate.raw, outcome),
                            }
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    timed_out =
                        attempted.saturating_sub(loaded + failed + fetched_stylesheets.len());
                    break;
                }
            }
        }
        // A deadline drops unfinished futures without negative-caching them,
        // so a later warmup can retry slow resources.
        drop(requests);

        // Materialize every fetched sheet before inserting any synthetic
        // import links. Link indices are stable during this phase; inserting
        // imports only afterwards (in descending owner order) prevents one
        // stylesheet from shifting another response's owner.
        struct ImportedStylesheet {
            frame_id: u32,
            link_index: usize,
            import_depth: u8,
            imports: Vec<StylesheetImport>,
            response_url: Url,
            requested_url: String,
        }
        let mut imported_stylesheets = Vec::new();
        for (candidate, response) in fetched_stylesheets {
            let css = obscura_net::decode_non_html(&response.body, response.content_type());
            let (imports, rules) = split_css_imports(&css);
            let rules = rebase_css_urls(&rules, &response.url);
            let materialized = if candidate.frame_id == 0 {
                match self.js.as_mut() {
                    Some(js) => {
                        candidate
                            .stylesheet_links
                            .iter()
                            .try_for_each(|(link_index, _)| {
                                js.execute_script(
                                    "<archive:stylesheet>",
                                    &materialize_linked_stylesheet_script(*link_index, &rules),
                                )
                            })
                    }
                    None => Err("top-level JavaScript runtime disappeared".to_string()),
                }
            } else {
                let frame_index = self
                    .frames
                    .iter()
                    .position(|frame| frame.frame_id() == candidate.frame_id);
                match (frame_index, self.js.as_mut()) {
                    (Some(frame_index), Some(js)) => candidate
                        .stylesheet_links
                        .iter()
                        .try_for_each(|(link_index, _)| {
                            self.frames[frame_index].execute_script(
                                js,
                                &materialize_linked_stylesheet_script(*link_index, &rules),
                            )
                        }),
                    _ => Err("owning frame disappeared".to_string()),
                }
            };
            match materialized {
                Ok(()) => {
                    loaded += 1;
                    for (link_index, import_depth) in candidate.stylesheet_links {
                        if import_depth >= MAX_STYLESHEET_IMPORT_DEPTH && !imports.is_empty() {
                            let owner = if candidate.frame_id == 0 {
                                "top-level".to_string()
                            } else {
                                format!("frame {}", candidate.frame_id)
                            };
                            self.mark_resource_archive_incomplete(format!(
                                "{owner} stylesheet import depth cap reached ({MAX_STYLESHEET_IMPORT_DEPTH}): {}",
                                response.url,
                            ));
                            continue;
                        }
                        if !imports.is_empty() {
                            imported_stylesheets.push(ImportedStylesheet {
                                frame_id: candidate.frame_id,
                                link_index,
                                import_depth,
                                imports: imports.clone(),
                                response_url: response.url.clone(),
                                requested_url: candidate.raw.clone(),
                            });
                        }
                    }
                }
                Err(error) => {
                    failed += 1;
                    let owner = if candidate.frame_id == 0 {
                        "top-level".to_string()
                    } else {
                        format!("frame {}", candidate.frame_id)
                    };
                    self.mark_resource_archive_incomplete(format!(
                        "{owner} stylesheet materialization failed for {}: {}",
                        candidate.raw, error,
                    ));
                }
            }
        }
        imported_stylesheets.sort_by(|left, right| {
            left.frame_id
                .cmp(&right.frame_id)
                .then_with(|| right.link_index.cmp(&left.link_index))
        });
        for imported in imported_stylesheets {
            let code = queue_stylesheet_imports_script(
                imported.link_index,
                &imported.imports,
                &imported.response_url,
                imported.import_depth.saturating_add(1),
            );
            let queued = if imported.frame_id == 0 {
                match self.js.as_mut() {
                    Some(js) => js.execute_script("<archive:stylesheet-import>", &code),
                    None => Err("top-level JavaScript runtime disappeared".to_string()),
                }
            } else {
                let frame_index = self
                    .frames
                    .iter()
                    .position(|frame| frame.frame_id() == imported.frame_id);
                match (frame_index, self.js.as_mut()) {
                    (Some(frame_index), Some(js)) => {
                        self.frames[frame_index].execute_script(js, &code)
                    }
                    _ => Err("owning frame disappeared".to_string()),
                }
            };
            if let Err(error) = queued {
                let owner = if imported.frame_id == 0 {
                    "top-level".to_string()
                } else {
                    format!("frame {}", imported.frame_id)
                };
                self.mark_resource_archive_incomplete(format!(
                    "{owner} stylesheet import setup failed for {}: {}",
                    imported.requested_url, error,
                ));
            }
        }
        let report = ScreenshotResourceWarmupReport {
            discovered,
            attempted,
            loaded,
            failed,
            timed_out,
            remaining: discovered.saturating_sub(loaded + failed),
        };
        tracing::debug!(
            discovered = report.discovered,
            attempted = report.attempted,
            loaded = report.loaded,
            failed = report.failed,
            timed_out = report.timed_out,
            remaining = report.remaining,
            elapsed_ms = started.elapsed().as_millis(),
            "prepared screenshot resources through page transport"
        );
        report
    }

    /// Rasterize the current DOM to PNG bytes at `viewport` (CSS pixels), when
    /// the render feature is compiled in. None if the page has no DOM or the
    /// viewport is zero-sized.
    #[cfg(feature = "render")]
    pub fn screenshot(&self, viewport: (f32, f32)) -> Option<Vec<u8>> {
        self.screenshot_with_animation_sample(viewport, self.live_animation_sample())
    }

    /// Rasterize every CSS animation at one explicit local time. This mirrors
    /// Web Animations `currentTime` and is intended for deterministic parity
    /// capture; ordinary screenshots use each live instance's start epoch.
    #[cfg(feature = "render")]
    pub fn screenshot_at_animation_time(
        &self,
        viewport: (f32, f32),
        animation_sample_time: obscura_js::AnimationSampleTime,
    ) -> Option<Vec<u8>> {
        self.screenshot_with_animation_sample(
            viewport,
            obscura_js::AnimationSample {
                time: animation_sample_time,
                mode: obscura_js::AnimationSampleMode::LocalOverride,
            },
        )
    }

    #[cfg(feature = "render")]
    pub fn screenshot_with_animation_sample(
        &self,
        viewport: (f32, f32),
        animation_sample: obscura_js::AnimationSample,
    ) -> Option<Vec<u8>> {
        // Needed to resolve the relative image URLs ("logo.svg") that make up
        // the overwhelming majority of real markup.
        let base_url = self.resolve_base_url();
        let base_url = base_url.as_ref().map(|u| u.as_str());
        if let Some(js) = &self.js {
            if !js.set_animation_sample(animation_sample) {
                return None;
            }
            if let Some(png) = js.screenshot_prepared_with_surface_color(
                viewport,
                base_url,
                self.capture_surface_color(),
            ) {
                return Some(png);
            }
        }
        // Compatibility path for a page without a JS runtime or an ad-hoc
        // viewport/base that does not match the runtime's CSSOM render key.
        let scroll = self
            .js
            .as_ref()
            .map(|js| js.scroll_offset())
            .unwrap_or((0.0, 0.0));
        // When there IS a runtime, paint against the resource cache it already
        // holds for this document. Building a fresh one here refetched every
        // image on every capture, so a caller repeating a screenshot at a
        // viewport that does not match the prepared key paid the whole network
        // cost per frame.
        if let Some(js) = &self.js {
            if let Some(png) = js.screenshot_unprepared_with_retained_resources(
                viewport,
                base_url,
                scroll,
                animation_sample.time,
                self.capture_surface_color(),
            ) {
                return Some(png);
            }
        }
        self.with_dom(|dom| {
            obscura_js::screenshot_png_scrolled_at_animation_time_with_surface_color(
                dom,
                viewport,
                base_url,
                scroll,
                animation_sample.time,
                self.capture_surface_color(),
            )
        })
        .flatten()
    }

    /// Rasterize an immutable document-space rectangle from the page's retained
    /// layout. Unlike [`Self::screenshot`], this may address content outside the
    /// live viewport and scale the output without relayout or scripted scroll.
    #[cfg(feature = "render")]
    pub fn screenshot_region(
        &self,
        region: obscura_js::CaptureRegion,
    ) -> Result<Vec<u8>, obscura_js::CaptureError> {
        self.screenshot_region_with_animation_sample(region, self.live_animation_sample())
    }

    #[cfg(feature = "render")]
    pub fn screenshot_region_at_animation_time(
        &self,
        region: obscura_js::CaptureRegion,
        animation_sample_time: obscura_js::AnimationSampleTime,
    ) -> Result<Vec<u8>, obscura_js::CaptureError> {
        self.screenshot_region_with_animation_sample(
            region,
            obscura_js::AnimationSample {
                time: animation_sample_time,
                mode: obscura_js::AnimationSampleMode::LocalOverride,
            },
        )
    }

    #[cfg(feature = "render")]
    pub fn screenshot_region_with_animation_sample(
        &self,
        region: obscura_js::CaptureRegion,
        animation_sample: obscura_js::AnimationSample,
    ) -> Result<Vec<u8>, obscura_js::CaptureError> {
        let js = self
            .js
            .as_ref()
            .ok_or(obscura_js::CaptureError::PaintFailed)?;
        if !js.set_animation_sample(animation_sample) {
            return Err(obscura_js::CaptureError::PaintFailed);
        }
        js.screenshot_prepared_region_with_surface_color(region, self.capture_surface_color())
    }

    /// Scrollable document dimensions from the retained render layout. Unlike
    /// DOM properties evaluated in page JavaScript, this cannot be shadowed or
    /// monkey-patched by the document being captured.
    #[cfg(feature = "render")]
    pub fn prepared_content_size(&self) -> Option<(f32, f32)> {
        self.prepared_content_size_with_animation_sample(self.live_animation_sample())
    }

    #[cfg(feature = "render")]
    pub fn prepared_content_size_at_animation_time(
        &self,
        animation_sample_time: obscura_js::AnimationSampleTime,
    ) -> Option<(f32, f32)> {
        self.prepared_content_size_with_animation_sample(obscura_js::AnimationSample {
            time: animation_sample_time,
            mode: obscura_js::AnimationSampleMode::LocalOverride,
        })
    }

    #[cfg(feature = "render")]
    pub fn prepared_content_size_with_animation_sample(
        &self,
        animation_sample: obscura_js::AnimationSample,
    ) -> Option<(f32, f32)> {
        let js = self.js.as_ref()?;
        js.set_animation_sample(animation_sample)
            .then(|| js.prepared_content_size())
            .flatten()
    }

    #[cfg(feature = "render")]
    pub fn live_animation_sample(&self) -> obscura_js::AnimationSample {
        if let Some(js) = &self.js {
            return js.live_animation_sample();
        }
        let milliseconds = self.document_timeline_origin.elapsed().as_secs_f64() * 1_000.0;
        obscura_js::AnimationSample {
            time: obscura_js::AnimationSampleTime {
                milliseconds: milliseconds.min(f64::from(f32::MAX)) as f32,
            },
            mode: obscura_js::AnimationSampleMode::DocumentTime,
        }
    }

    #[cfg(feature = "render")]
    pub fn prepared_has_active_css_animations(&self) -> bool {
        self.js
            .as_ref()
            .is_some_and(|js| js.prepared_has_active_css_animations())
    }

    /// Renderer-owned root scroll offset for document-space capture routing.
    #[cfg(feature = "render")]
    pub fn screenshot_scroll_offset(&self) -> (f32, f32) {
        self.js
            .as_ref()
            .map(|js| js.scroll_offset())
            .unwrap_or((0.0, 0.0))
    }

    /// Absolute URLs pulled in through fetch/XHR or Image by the page and its
    /// child frames (issue #301). Empty when no live realm fetched a resource.
    pub fn fetched_urls(&self) -> Vec<String> {
        let mut urls = self
            .js
            .as_ref()
            .map(|js| js.fetched_urls())
            .unwrap_or_default();
        for frame in &self.frames {
            urls.extend(frame.fetched_urls());
        }
        urls
    }

    /// Move network events recorded for script-initiated requests
    /// (fetch/XHR/dynamic resource) from the JS runtime into this page's
    /// network_events, so the CDP layer emits Network.requestWillBeSent /
    /// responseReceived for them (issue #406). Idempotent: the runtime's queue
    /// is drained, so calling this repeatedly does not duplicate events. The
    /// fetch-{N} request id is preserved so Network.getResponseBody resolves.
    pub fn sync_js_network_events(&mut self) {
        let events = match self.js.as_ref() {
            Some(js) => js.take_js_network_events(),
            None => return,
        };
        for ev in events {
            self.network_events.push(NetworkEvent {
                request_id: ev.request_id,
                url: ev.url,
                method: ev.method,
                resource_type: "Fetch".to_string(),
                status: ev.status,
                headers: std::collections::HashMap::new(),
                response_headers: Arc::new(ev.response_headers),
                body_size: ev.body_size,
                timestamp: ev.timestamp,
            });
        }
    }

    pub fn dom(&self) -> Option<&DomTree> {
        self.dom.as_ref()
    }

    /// V8 isolate handle for this page's runtime, if it has been initialized.
    /// Lets the CDP dispatcher arm a per-command watchdog (which bounds any one
    /// command so a hung page cannot hold this connection's V8 lock forever)
    /// without taking `&mut self`.
    pub fn isolate_handle(&self) -> Option<obscura_js::runtime::IsolateHandle> {
        self.js.as_ref().map(|js| js.isolate_handle())
    }

    /// Clear a V8 termination left by a per-command watchdog so the next command
    /// on this page can run. No-op if the runtime is absent or not terminating.
    pub fn cancel_v8_termination(&mut self) {
        if let Some(js) = self.js.as_mut() {
            js.cancel_termination();
        }
    }

    /// Like [`Self::evaluate`] but bounded by a V8 watchdog so a runaway
    /// expression cannot hang the process. A non-zero `timeout` of zero falls
    /// back to the unbounded path.
    pub fn evaluate_with_timeout(
        &mut self,
        expression: &str,
        timeout: std::time::Duration,
    ) -> serde_json::Value {
        if let Some(js) = &mut self.js {
            match js.evaluate_with_timeout(expression, timeout) {
                Ok(val) => val,
                Err(e) => {
                    tracing::debug!(
                        "JS eval error/timeout for '{}': {}",
                        truncate_on_char_boundary(expression, 80),
                        e
                    );
                    serde_json::Value::Null
                }
            }
        } else {
            self.evaluate(expression)
        }
    }

    pub fn evaluate(&mut self, expression: &str) -> serde_json::Value {
        if let Some(js) = &mut self.js {
            match js.evaluate(expression) {
                Ok(val) => val,
                Err(e) => {
                    tracing::debug!(
                        "JS eval error for '{}': {}",
                        truncate_on_char_boundary(expression, 80),
                        e
                    );
                    serde_json::Value::Null
                }
            }
        } else {
            match expression.trim() {
                "document.title" => serde_json::Value::String(self.title.clone()),
                "document.URL" | "document.location.href" | "window.location.href" => {
                    serde_json::Value::String(self.url_string())
                }
                _ => serde_json::Value::Null,
            }
        }
    }

    pub async fn evaluate_for_cdp(
        &mut self,
        expression: &str,
        return_by_value: bool,
        await_promise: bool,
    ) -> obscura_js::runtime::RemoteObjectInfo {
        if self.js.is_some() {
            match self
                .evaluate_for_cdp_with_timeout(expression, return_by_value, await_promise, 30_000)
                .await
            {
                Ok(info) => info,
                Err(e) => {
                    tracing::debug!("evaluate_for_cdp error: {}", e);
                    obscura_js::runtime::RemoteObjectInfo {
                        js_type: "undefined".into(),
                        subtype: None,
                        class_name: String::new(),
                        description: String::new(),
                        object_id: None,
                        value: None,
                    }
                }
            }
        } else {
            let val = self.evaluate(expression);
            obscura_js::runtime::RemoteObjectInfo {
                js_type: match &val {
                    serde_json::Value::String(_) => "string".into(),
                    serde_json::Value::Number(_) => "number".into(),
                    serde_json::Value::Bool(_) => "boolean".into(),
                    _ => "undefined".into(),
                },
                subtype: None,
                class_name: String::new(),
                description: String::new(),
                object_id: None,
                value: Some(val),
            }
        }
    }

    pub async fn evaluate_for_cdp_with_timeout(
        &mut self,
        expression: &str,
        return_by_value: bool,
        await_promise: bool,
        await_timeout_ms: u64,
    ) -> Result<obscura_js::runtime::RemoteObjectInfo, String> {
        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_millis(await_timeout_ms);
        self.evaluate_for_cdp_until(
            expression,
            return_by_value,
            await_promise,
            deadline,
            await_timeout_ms,
        )
        .await
    }

    fn remaining_cdp_budget(
        deadline: tokio::time::Instant,
        operation: &str,
        timeout_ms: u64,
    ) -> Result<std::time::Duration, String> {
        deadline
            .checked_duration_since(tokio::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| format!("{operation} exceeded its {timeout_ms}ms command budget"))
    }

    fn cdp_budget_millis(remaining: std::time::Duration) -> u64 {
        u64::try_from(remaining.as_millis())
            .unwrap_or(u64::MAX)
            .max(1)
    }

    fn cleanup_cdp_await_sentinel(&mut self, await_key_json: &str) {
        if let Some(js) = self.js.as_mut() {
            // Cleanup is deliberately bounded on its own. It must run even when
            // the caller's deadline has just expired, otherwise every ordinary
            // CDP timeout leaks a page-global result cell and its continuation.
            let _ = js.evaluate_with_timeout(
                &format!("delete globalThis[{await_key_json}]"),
                std::time::Duration::from_millis(100),
            );
        }
    }

    fn remaining_cdp_await_budget(
        &mut self,
        deadline: tokio::time::Instant,
        timeout_ms: u64,
        await_key_json: &str,
    ) -> Result<std::time::Duration, String> {
        Self::remaining_cdp_budget(deadline, "Runtime.evaluate", timeout_ms).map_err(|error| {
            self.cleanup_cdp_await_sentinel(await_key_json);
            error
        })
    }

    async fn evaluate_for_cdp_until(
        &mut self,
        expression: &str,
        return_by_value: bool,
        await_promise: bool,
        deadline: tokio::time::Instant,
        await_timeout_ms: u64,
    ) -> Result<obscura_js::runtime::RemoteObjectInfo, String> {
        if self.js.is_none() {
            let value = self.evaluate(expression);
            return Ok(obscura_js::runtime::RemoteObjectInfo {
                js_type: match &value {
                    serde_json::Value::String(_) => "string".into(),
                    serde_json::Value::Number(_) => "number".into(),
                    serde_json::Value::Bool(_) => "boolean".into(),
                    _ => "undefined".into(),
                },
                subtype: None,
                class_name: String::new(),
                description: String::new(),
                object_id: None,
                value: Some(value),
            });
        }
        if !await_promise {
            let remaining =
                Self::remaining_cdp_budget(deadline, "Runtime.evaluate", await_timeout_ms)?;
            let js = self.js.as_mut().expect("runtime checked above");
            let watchdog = js.arm_watchdog(remaining);
            let result = js
                .evaluate_for_cdp_with_timeout(
                    expression,
                    return_by_value,
                    false,
                    Self::cdp_budget_millis(remaining),
                )
                .await;
            let watchdog_fired = js.disarm_watchdog(watchdog);
            if watchdog_fired {
                return Err(format!(
                    "Runtime.evaluate exceeded its {await_timeout_ms}ms command budget"
                ));
            }
            return result;
        }

        // An awaited expression may depend on iframe.onload. Child realms are
        // attached by Page, between runtime turns, rather than from a JS op.
        // Letting ObscuraJsRuntime own the complete await would therefore
        // deadlock: the promise waits for the owner event while Page cannot
        // attach and complete the child until the await returns. Store the
        // result behind a unique page-global sentinel, then alternate one
        // runtime task with the ordinary frame lifecycle driver.
        let await_id = NEXT_CDP_PAGE_AWAIT_ID.fetch_add(1, Ordering::Relaxed);
        let await_key = format!("__obscura_page_await_{await_id}");
        let await_key_json = serde_json::to_string(&await_key)
            .map_err(|error| format!("could not encode CDP await key: {error}"))?;
        let cleaned_expression = expression
            .trim()
            .trim_end_matches(|character: char| character == ';' || character.is_whitespace());
        let start_script = format!(
            "(function() {{\n\
                const key = {await_key_json};\n\
                globalThis[key] = {{ done: false, rejected: false, value: undefined }};\n\
                (async function() {{\n\
                    try {{\n\
                        globalThis[key].value = await (\n{cleaned_expression}\n);\n\
                    }} catch (error) {{\n\
                        globalThis[key].rejected = true;\n\
                        globalThis[key].value = error;\n\
                    }} finally {{\n\
                        globalThis[key].done = true;\n\
                    }}\n\
                }})();\n\
                return key;\n\
            }})()"
        );
        let start_result =
            match self.remaining_cdp_await_budget(deadline, await_timeout_ms, &await_key_json) {
                Ok(remaining) => self
                    .js
                    .as_mut()
                    .expect("runtime checked above")
                    .evaluate_with_timeout(&start_script, remaining),
                Err(error) => Err(error),
            };
        if let Err(error) = start_result {
            self.cleanup_cdp_await_sentinel(&await_key_json);
            return Err(format!("Runtime.evaluate could not start: {error}"));
        }

        let done_script = format!("globalThis[{await_key_json}]?.done === true");
        loop {
            let remaining =
                match Self::remaining_cdp_budget(deadline, "Runtime.evaluate", await_timeout_ms) {
                    Ok(remaining) => remaining,
                    Err(_) => {
                        self.cleanup_cdp_await_sentinel(&await_key_json);
                        return Err(format!(
                            "Runtime.evaluate promise did not settle within {await_timeout_ms}ms"
                        ));
                    }
                };
            let done = match self
                .js
                .as_mut()
                .ok_or_else(|| "JavaScript runtime disappeared".to_string())?
                .evaluate_with_timeout(&done_script, remaining)
            {
                Ok(value) => value.as_bool().unwrap_or(false),
                Err(error) => {
                    self.cleanup_cdp_await_sentinel(&await_key_json);
                    return Err(format!("Runtime.evaluate completion probe failed: {error}"));
                }
            };
            if done {
                break;
            }

            let remaining =
                self.remaining_cdp_await_budget(deadline, await_timeout_ms, &await_key_json)?;
            // Tokio can cancel a parked network/timer/frame future at the
            // absolute command deadline. The V8 watchdog covers the part where
            // one callback or microtask keeps this thread inside V8 and Tokio
            // cannot observe that deadline.
            let turn_watchdog = self
                .js
                .as_mut()
                .ok_or_else(|| "JavaScript runtime disappeared".to_string())?
                .arm_watchdog(remaining);
            let turn =
                tokio::time::timeout_at(deadline, self.run_autonomous_event_loop_turn()).await;
            let turn_watchdog_fired = self
                .js
                .as_mut()
                .is_some_and(|js| js.disarm_watchdog(turn_watchdog));
            let reached_idle = match turn {
                Ok(Ok(reached_idle)) if !turn_watchdog_fired => reached_idle,
                Ok(Err(error)) if !turn_watchdog_fired => {
                    self.cleanup_cdp_await_sentinel(&await_key_json);
                    return Err(error);
                }
                Ok(_) | Err(_) => {
                    self.cleanup_cdp_await_sentinel(&await_key_json);
                    return Err(format!(
                        "Runtime.evaluate promise did not settle within {await_timeout_ms}ms"
                    ));
                }
            };
            if self.lifecycle == LifecycleState::Failed {
                self.cleanup_cdp_await_sentinel(&await_key_json);
                return Err("page lifecycle failed while awaiting Runtime.evaluate".to_string());
            }
            if reached_idle {
                let remaining =
                    self.remaining_cdp_await_budget(deadline, await_timeout_ms, &await_key_json)?;
                tokio::time::sleep(remaining.min(tokio::time::Duration::from_millis(1))).await;
            }
        }

        let rejected_script = format!("globalThis[{await_key_json}].rejected === true");
        let remaining =
            self.remaining_cdp_await_budget(deadline, await_timeout_ms, &await_key_json)?;
        let rejected = match self
            .js
            .as_mut()
            .ok_or_else(|| "JavaScript runtime disappeared".to_string())?
            .evaluate_with_timeout(&rejected_script, remaining)
        {
            Ok(value) => value.as_bool().unwrap_or(false),
            Err(error) => {
                self.cleanup_cdp_await_sentinel(&await_key_json);
                return Err(format!("Runtime.evaluate rejection probe failed: {error}"));
            }
        };
        if rejected {
            let error_script = format!(
                "String(globalThis[{await_key_json}].value && \
                 (globalThis[{await_key_json}].value.message || \
                  globalThis[{await_key_json}].value))"
            );
            let remaining =
                self.remaining_cdp_await_budget(deadline, await_timeout_ms, &await_key_json)?;
            let message = self
                .js
                .as_mut()
                .ok_or_else(|| "JavaScript runtime disappeared".to_string())?
                .evaluate_with_timeout(&error_script, remaining)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default();
            self.cleanup_cdp_await_sentinel(&await_key_json);
            return Err(format!("Promise rejected: {message}"));
        }

        let result_expression = format!("globalThis[{await_key_json}].value");
        let remaining =
            self.remaining_cdp_await_budget(deadline, await_timeout_ms, &await_key_json)?;
        let js = self
            .js
            .as_mut()
            .ok_or_else(|| "JavaScript runtime disappeared".to_string())?;
        let result_watchdog = js.arm_watchdog(remaining);
        let info = js
            .evaluate_for_cdp_with_timeout(
                &result_expression,
                return_by_value,
                false,
                Self::cdp_budget_millis(remaining),
            )
            .await;
        let result_watchdog_fired = js.disarm_watchdog(result_watchdog);
        self.cleanup_cdp_await_sentinel(&await_key_json);
        if result_watchdog_fired {
            return Err(format!(
                "Runtime.evaluate exceeded its {await_timeout_ms}ms command budget"
            ));
        }
        info
    }

    pub async fn call_function_on_for_cdp(
        &mut self,
        function_declaration: &str,
        object_id: Option<&str>,
        args: &[serde_json::Value],
        return_by_value: bool,
        await_promise: bool,
    ) -> obscura_js::runtime::RemoteObjectInfo {
        if self.js.is_some() {
            match self
                .call_function_on_for_cdp_with_timeout(
                    function_declaration,
                    object_id,
                    args,
                    return_by_value,
                    await_promise,
                    30_000,
                )
                .await
            {
                Ok(info) => info,
                Err(e) => {
                    tracing::debug!("callFunctionOn error: {}", e);
                    obscura_js::runtime::RemoteObjectInfo {
                        js_type: "undefined".into(),
                        subtype: None,
                        class_name: String::new(),
                        description: String::new(),
                        object_id: None,
                        value: None,
                    }
                }
            }
        } else {
            obscura_js::runtime::RemoteObjectInfo {
                js_type: "undefined".into(),
                subtype: None,
                class_name: String::new(),
                description: String::new(),
                object_id: None,
                value: None,
            }
        }
    }

    pub async fn call_function_on_for_cdp_with_timeout(
        &mut self,
        function_declaration: &str,
        object_id: Option<&str>,
        args: &[serde_json::Value],
        return_by_value: bool,
        await_promise: bool,
        await_timeout_ms: u64,
    ) -> Result<obscura_js::runtime::RemoteObjectInfo, String> {
        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_millis(await_timeout_ms);
        if !await_promise {
            let remaining =
                Self::remaining_cdp_budget(deadline, "Runtime.callFunctionOn", await_timeout_ms)?;
            let js = self.js.as_mut().ok_or("JavaScript runtime unavailable")?;
            let watchdog = js.arm_watchdog(remaining);
            let result = js
                .call_function_on_for_cdp_with_timeout(
                    function_declaration,
                    object_id,
                    args,
                    return_by_value,
                    false,
                    Self::cdp_budget_millis(remaining),
                )
                .await;
            let watchdog_fired = js.disarm_watchdog(watchdog);
            if watchdog_fired {
                return Err(format!(
                    "Runtime.callFunctionOn exceeded its {await_timeout_ms}ms command budget"
                ));
            }
            return result;
        }

        // Start the function synchronously and retain its raw return value as
        // an ordinary remote object. Await that value through Page's generic
        // promise driver, which alternates runtime turns with `advance_frames`.
        // This is the callFunctionOn counterpart of Runtime.evaluate's iframe
        // interleave and prevents a Promise waiting on iframe.onload from
        // deadlocking the native frame queue.
        let remaining =
            Self::remaining_cdp_budget(deadline, "Runtime.callFunctionOn", await_timeout_ms)?;
        let js = self.js.as_mut().ok_or("JavaScript runtime unavailable")?;
        let watchdog = js.arm_watchdog(remaining);
        let pending = js
            .call_function_on_for_cdp_with_timeout(
                function_declaration,
                object_id,
                args,
                false,
                false,
                Self::cdp_budget_millis(remaining),
            )
            .await;
        let watchdog_fired = js.disarm_watchdog(watchdog);
        if watchdog_fired {
            return Err(format!(
                "Runtime.callFunctionOn exceeded its {await_timeout_ms}ms command budget"
            ));
        }
        let pending = pending?;
        let pending_object_id = pending
            .object_id
            .ok_or_else(|| "Runtime.callFunctionOn did not retain its return value".to_string())?;
        let pending_expression = match self
            .js
            .as_ref()
            .and_then(|js| js.object_expression_for_cdp(&pending_object_id))
        {
            Some(expression) => expression,
            None => {
                if let Some(js) = self.js.as_mut() {
                    js.release_object(&pending_object_id);
                }
                return Err("Runtime.callFunctionOn return object disappeared".to_string());
            }
        };

        let result = self
            .evaluate_for_cdp_until(
                &pending_expression,
                return_by_value,
                true,
                deadline,
                await_timeout_ms,
            )
            .await;
        if let Some(js) = self.js.as_mut() {
            js.release_object(&pending_object_id);
        }
        result
    }

    pub fn set_blocked_urls(&mut self, patterns: Vec<String>) {
        self.blocked_url_patterns = patterns.clone();
        if let Some(js) = &self.js {
            js.set_blocked_urls(patterns);
        }
    }

    pub fn release_object(&mut self, object_id: &str) {
        if let Some(js) = &mut self.js {
            js.release_object(object_id);
        }
    }

    fn record_network_event(
        &mut self,
        url: &str,
        method: &str,
        resource_type: &str,
        status: u16,
        response_headers: &std::collections::HashMap<String, String>,
        body_size: usize,
    ) {
        self.record_network_event_inner(
            url,
            method,
            resource_type,
            status,
            response_headers,
            body_size,
        );
    }

    fn record_network_event_with_body(
        &mut self,
        url: &str,
        method: &str,
        resource_type: &str,
        status: u16,
        response_headers: &std::collections::HashMap<String, String>,
        body: &[u8],
        base64_encoded: bool,
    ) {
        let request_id = self.record_network_event_inner(
            url,
            method,
            resource_type,
            status,
            response_headers,
            body.len(),
        );
        self.store_response_body(request_id, body, base64_encoded);
    }

    fn record_network_event_inner(
        &mut self,
        url: &str,
        method: &str,
        resource_type: &str,
        status: u16,
        response_headers: &std::collections::HashMap<String, String>,
        body_size: usize,
    ) -> String {
        self.network_event_counter += 1;
        let request_id = format!("{}.{}", self.id, self.network_event_counter);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        self.network_events.push(NetworkEvent {
            request_id: request_id.clone(),
            url: url.to_string(),
            method: method.to_string(),
            resource_type: resource_type.to_string(),
            status,
            headers: std::collections::HashMap::new(),
            response_headers: Arc::new(response_headers.clone()),
            body_size,
            timestamp,
        });
        request_id
    }

    fn store_response_body(&mut self, request_id: String, body: &[u8], base64_encoded: bool) {
        let max_entries = response_body_entry_limit();
        let max_bytes = response_body_byte_limit();
        if max_entries == 0 || max_bytes == 0 || body.len() > max_bytes {
            return;
        }
        let body = if base64_encoded {
            BASE64.encode(body)
        } else {
            String::from_utf8_lossy(body).to_string()
        };
        self.response_bodies.insert(
            request_id.clone(),
            StoredResponseBody {
                body,
                base64_encoded,
            },
        );
        self.response_body_order.push_back(request_id);
        while self.response_body_order.len() > max_entries {
            if let Some(oldest) = self.response_body_order.pop_front() {
                self.response_bodies.remove(&oldest);
            }
        }
    }

    pub fn get_response_body(&self, request_id: &str) -> Option<StoredResponseBody> {
        self.response_bodies.get(request_id).cloned().or_else(|| {
            self.js
                .as_ref()?
                .get_network_response_body(request_id)
                .map(|body| StoredResponseBody {
                    body: body.body,
                    base64_encoded: body.base64_encoded,
                })
        })
    }

    /// Take a stored response body as raw bytes for CDP streaming
    /// (Fetch.takeResponseBodyAsStream). Removes it from the in-memory cache and
    /// transfers ownership to the caller, so a large body is held once and freed
    /// when the stream is closed rather than lingering in this long-running
    /// process (issue #360). Binary bodies are stored base64 (byte-exact); text
    /// bodies return their UTF-8 bytes. Returns None if the body was never
    /// cached (e.g. it exceeded OBSCURA_NETWORK_BODY_BUFFER_BYTES and was
    /// dropped) or the id is unknown.
    pub fn take_response_body_raw(&mut self, request_id: &str) -> Option<Vec<u8>> {
        let stored = if let Some(body) = self.response_bodies.remove(request_id) {
            self.response_body_order.retain(|id| id != request_id);
            body
        } else {
            self.js
                .as_ref()?
                .get_network_response_body(request_id)
                .map(|b| StoredResponseBody {
                    body: b.body,
                    base64_encoded: b.base64_encoded,
                })?
        };
        if stored.base64_encoded {
            BASE64.decode(stored.body.as_bytes()).ok()
        } else {
            Some(stored.body.into_bytes())
        }
    }

    /// Make the body stored under `from_id` also retrievable under `to_id`.
    /// The main navigation resource is stored under its internal request id, but
    /// the CDP layer reports it to clients with the navigation's loaderId as the
    /// requestId (Chrome's `requestId === loaderId` convention). Without this
    /// alias, `Network.getResponseBody(loaderId)` misses and a client navigating
    /// straight to an image or other resource cannot read the main-response body
    /// (issue #340).
    pub fn alias_response_body(&mut self, from_id: &str, to_id: &str) {
        if from_id == to_id || self.response_bodies.contains_key(to_id) {
            return;
        }
        if let Some(body) = self.response_bodies.get(from_id).cloned() {
            self.response_bodies.insert(to_id.to_string(), body);
            self.response_body_order.push_back(to_id.to_string());
        }
    }

    pub fn clear_response_bodies(&mut self) {
        self.response_bodies.clear();
        self.response_body_order.clear();
        if let Some(js) = &self.js {
            js.clear_network_response_bodies();
        }
    }

    pub fn execute_preload_script(&mut self, source: &str) -> Result<(), String> {
        if let Some(js) = &mut self.js {
            js.execute_script("<preload>", source)
        } else {
            Err("No JS runtime".to_string())
        }
    }

    pub fn suspend_js(&mut self) {
        let Some(js) = &self.js else {
            return;
        };
        let started_script_ids = js.started_script_ids();
        let dom = js.take_dom();
        if let Some(dom) = dom {
            self.dom = Some(dom);
            self.suspended_started_script_ids = started_script_ids;
        } else {
            self.suspended_started_script_ids.clear();
        }
        // Every frame realm holds a V8 handle into this isolate, so the frames
        // go before the runtime does — the same order init_js keeps on a new
        // document. Suspending is a teardown of the realm the frames live in,
        // and a realm cannot be suspended and resumed the way the page's DOM
        // can, so they are rebuilt when the page next loads a document.
        self.frames.clear();
        self.js = None;
    }

    pub fn resume_js(&mut self) {
        if self.js.is_some() {
            return;
        }
        let started_script_ids = std::mem::take(&mut self.suspended_started_script_ids);
        self.init_js();
        if let Some(js) = &self.js {
            js.restore_started_script_ids(&started_script_ids);
        }
    }

    pub fn has_js(&self) -> bool {
        self.js.is_some()
    }

    pub fn release_object_group(&mut self) {
        if let Some(js) = &mut self.js {
            js.release_object_group();
        }
    }

    pub fn take_pending_navigation(&self) -> Option<(String, String, String)> {
        if let Some(js) = &self.js {
            js.take_pending_navigation()
        } else {
            None
        }
    }

    pub fn take_pending_binding_calls(&self) -> Vec<(String, String)> {
        if let Some(js) = &self.js {
            js.take_pending_binding_calls()
        } else {
            Vec::new()
        }
    }

    pub fn set_preload_scripts(&mut self, scripts: Vec<String>) {
        self.preload_scripts = scripts;
    }

    /// Replace the CDP Runtime bindings that must exist in every new page and
    /// child-frame realm before author scripts execute.
    pub fn set_preload_bindings(&mut self, bindings: Vec<String>) {
        self.preload_bindings = bindings;
    }

    /// Install one CDP Runtime binding now and retain it for future documents.
    pub fn add_preload_binding(&mut self, name: &str) -> Result<(), String> {
        if !self.preload_bindings.iter().any(|item| item == name) {
            self.preload_bindings.push(name.to_string());
        }
        if let Some(js) = &mut self.js {
            js.install_cdp_binding(name)?;
        }
        Ok(())
    }

    /// Remove a CDP Runtime binding from this document and future documents.
    pub fn remove_preload_binding(&mut self, name: &str) {
        self.preload_bindings.retain(|item| item != name);
        if let Some(js) = &mut self.js {
            let encoded = serde_json::to_string(name).unwrap_or_else(|_| "\"\"".to_string());
            let _ = js.execute_script(
                "<remove-binding>",
                &format!("delete globalThis[{encoded}];"),
            );
        }
    }

    /// Append a script that runs in the page before any of the page's own
    /// `<script>` tags, matching CDP `Page.addScriptToEvaluateOnNewDocument`.
    /// Takes effect on the next navigation (`goto` / `navigate*`).
    pub fn add_preload_script(&mut self, script: &str) {
        self.preload_scripts.push(script.to_string());
    }

    /// Enable CDP-Fetch-style interception of JS-initiated `fetch()`/XHR.
    /// Returns a receiver yielding every such request; resolve each through its
    /// `resolver` with `InterceptResolution::{Continue, Fulfill, Fail}` to pass,
    /// mock, or block it. Works in stealth and non-stealth. Mirrors how the CDP
    /// server wires the channel (`obscura-cdp/src/server.rs`).
    pub fn enable_interception(
        &mut self,
    ) -> tokio::sync::mpsc::UnboundedReceiver<obscura_js::ops::InterceptedRequest> {
        let (tx, rx) =
            tokio::sync::mpsc::unbounded_channel::<obscura_js::ops::InterceptedRequest>();
        self.set_intercept_tx(tx);
        self.enable_intercept(true);
        rx
    }

    /// Register a passive callback fired for every JS `fetch()`/XHR (and
    /// navigation) request this page makes, once the method/headers/body are
    /// known and before it is sent. Non-blocking; use `enable_interception` to
    /// mutate or block. Returns a stable id; pass it to `off_request` to
    /// detach (issue #408). Scoped to this page: it never sees sibling pages'
    /// requests and dies with the page.
    pub fn on_request(&mut self, cb: RequestCallback) -> u64 {
        self.callbacks.add_request(cb)
    }

    /// Register a passive callback fired with every JS `fetch()`/XHR (and
    /// navigation) response this page receives, including its body.
    /// Non-blocking. The main path for crawlers that need to capture API
    /// response payloads. Returns a stable id for `off_response`. Page-scoped
    /// like `on_request`.
    pub fn on_response(&mut self, cb: ResponseCallback) -> u64 {
        self.callbacks.add_response(cb)
    }

    /// Detach a request observer registered with `on_request`. Returns true if
    /// one was removed.
    pub fn off_request(&mut self, id: u64) -> bool {
        self.callbacks.remove_request(id)
    }

    /// Detach a response observer registered with `on_response`. Returns true if
    /// one was removed.
    pub fn off_response(&mut self, id: u64) -> bool {
        self.callbacks.remove_response(id)
    }

    /// Retain byte-exact responses for the current and subsequent top-level
    /// documents. Each committed top-level navigation resets the archive, so
    /// after HTTP or JavaScript redirects it contains only the final page and
    /// resources initiated by that page and its child frames.
    pub fn enable_resource_capture(&mut self, limits: ResourceCaptureLimits) {
        if let Some(state) = &self.resource_capture {
            let generation = self.callbacks.document_generation();
            let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
            state.limits = limits;
            state.begin_document(generation);
            return;
        }

        let generation = self.callbacks.document_generation();
        let state = Arc::new(std::sync::Mutex::new(ResourceCaptureState::new(
            limits, generation,
        )));
        let observed = Arc::clone(&state);
        let callback_id = self
            .callbacks
            .add_response(Arc::new(move |request, response| {
                observed
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .record(request, response);
            }));
        self.resource_capture = Some(state);
        self.resource_capture_callback_id = Some(callback_id);
    }

    fn retain_final_resource_scope(&mut self, mut capture: ResourceCapture) -> ResourceCapture {
        // A frame can remove itself in its final script turn, after its
        // responses have already been captured. Refresh realm liveness at the
        // archive boundary so those superseded browsing contexts do not leak
        // into a snapshot of the final page.
        self.release_detached_frames();
        let live_frame_ids: std::collections::HashSet<u32> =
            self.frames.iter().map(|frame| frame.frame_id()).collect();
        let document_generation = self.callbacks.document_generation();
        capture.resources.retain(|resource| {
            resource.document_generation == document_generation
                && (resource.frame_id == 0 || live_frame_ids.contains(&resource.frame_id))
        });
        capture.document_generation = document_generation;
        capture.total_bytes = capture.resources.iter().fold(0usize, |total, resource| {
            total.saturating_add(resource.body.len())
        });
        capture
    }

    /// Drain the final document's captured responses while keeping capture
    /// enabled for later requests or navigations.
    pub fn take_resource_capture(&mut self) -> Option<ResourceCapture> {
        let capture = {
            let state = self.resource_capture.as_ref()?;
            let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
            let generation = self.callbacks.document_generation();
            std::mem::replace(
                &mut state.capture,
                ResourceCapture {
                    document_generation: generation,
                    ..ResourceCapture::default()
                },
            )
        };
        Some(self.retain_final_resource_scope(capture))
    }

    /// Stop lossless response retention and return everything captured so far.
    pub fn disable_resource_capture(&mut self) -> Option<ResourceCapture> {
        if let Some(callback_id) = self.resource_capture_callback_id.take() {
            self.callbacks.remove_response(callback_id);
        }
        let state = self.resource_capture.take()?;
        let capture = {
            let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
            std::mem::take(&mut state.capture)
        };
        Some(self.retain_final_resource_scope(capture))
    }

    pub async fn process_pending_navigation(&mut self) -> Result<bool, PageError> {
        if let Some((url, method, body)) = self.take_pending_navigation() {
            let source_url = self
                .url
                .as_ref()
                .and_then(|source| {
                    Url::parse(&url)
                        .ok()
                        .map(|target| navigation_referrer(source, &target))
                })
                .unwrap_or_default();
            let nav_timeout = self.navigation_timeout();
            let nav_timeout_ms = duration_millis_u64(nav_timeout);
            let result = tokio::time::timeout(
                nav_timeout,
                self.navigate_with_wait_post_inner(
                    &url,
                    crate::lifecycle::WaitUntil::Load,
                    &method,
                    &body,
                    &source_url,
                ),
            )
            .await
            .map_err(|_| {
                self.lifecycle = crate::lifecycle::LifecycleState::Failed;
                PageError::NetworkError(format!("navigation exceeded {nav_timeout_ms}ms deadline"))
            })?;
            result?;
            self.push_history(self.url_string());
            Ok(true)
        } else {
            // Fork: a page that routed itself through history has still
            // navigated. See fork_virtual_url.rs.
            Ok(self.sync_virtual_url())
        }
    }

    pub fn set_intercept_tx(
        &mut self,
        tx: tokio::sync::mpsc::UnboundedSender<obscura_js::ops::InterceptedRequest>,
    ) {
        self.intercept_tx = Some(tx.clone());
        if let Some(js) = &self.js {
            js.set_intercept_tx(tx);
        }
    }

    pub fn enable_intercept(&mut self, enabled: bool) {
        self.intercept_enabled = enabled;
        if let Some(js) = &self.js {
            js.set_intercept_enabled(enabled);
        }
    }
}

fn script_response_is_executable(status: u16) -> bool {
    (200..=299).contains(&status)
}

fn url_matches_cdp_pattern(pattern: &str, url: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let mut remainder = url;
    let mut first = true;
    for part in pattern.split('*') {
        if part.is_empty() {
            continue;
        }

        let Some(index) = remainder.find(part) else {
            return false;
        };

        if first && !pattern.starts_with('*') && index != 0 {
            return false;
        }

        remainder = &remainder[index + part.len()..];
        first = false;
    }

    pattern.ends_with('*') || remainder.is_empty()
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "render")]
    use super::remaining_settle_resource_warmup_ms;
    use super::{
        css_resource_urls, linked_stylesheet_requests, materialize_linked_stylesheet_script,
        materialize_parser_stylesheet_script_with_token, materialize_stylesheet_graph,
        navigation_referrer, navigation_timeout_from_env_value, parse_import_url,
        parser_stylesheet_requests, rebase_css_urls, script_response_is_executable,
        split_css_imports, truncate_on_char_boundary, url_matches_cdp_pattern, LoadedStylesheet,
        StylesheetImport, MAX_STYLESHEET_RESOURCES,
    };
    use base64::Engine as _;
    use obscura_dom::parse_html;

    #[test]
    fn navigation_timeout_environment_default_remains_thirty_seconds() {
        assert_eq!(
            navigation_timeout_from_env_value(None),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(
            navigation_timeout_from_env_value(Some("not-a-timeout")),
            std::time::Duration::from_secs(30)
        );
    }

    #[test]
    fn navigation_timeout_environment_override_remains_available() {
        assert_eq!(
            navigation_timeout_from_env_value(Some("42000")),
            std::time::Duration::from_secs(42)
        );
    }

    #[test]
    fn parser_stylesheets_keep_the_base_at_each_encounter_point() {
        let dom = parse_html(
            r#"<!doctype html><html><head>
               <link rel="stylesheet" href="before.css">
               <style>@import "before-import.css";</style>
               <base href="/shifted/">
               <link rel="stylesheet" href="after.css">
               <style>@import "after-import.css";</style>
               <base href="/ignored/">
               </head><body></body></html>"#,
        );
        let document_url = url::Url::parse("https://example.test/original/page.html").unwrap();
        let (links, inline_imports, body_order) = parser_stylesheet_requests(&dom, &document_url);

        assert_eq!(
            links
                .iter()
                .map(|link| link.base_url.join(&link.raw_href).unwrap().to_string())
                .collect::<Vec<_>>(),
            vec![
                "https://example.test/original/before.css".to_string(),
                "https://example.test/shifted/after.css".to_string(),
            ]
        );
        assert_eq!(
            inline_imports
                .iter()
                .map(|item| item.base_url.join(&item.import.url).unwrap().to_string())
                .collect::<Vec<_>>(),
            vec![
                "https://example.test/original/before-import.css".to_string(),
                "https://example.test/shifted/after-import.css".to_string(),
            ]
        );
        assert!(body_order.is_some());
    }

    #[test]
    fn css_resource_discovery_ignores_strings_comments_data_and_fragments() {
        let base = url::Url::parse("https://example.test/css/app/main.css").unwrap();
        let css = r#"
            /* url(ignored.png) */
            .copy::before { content: "url(also-ignored.png)"; }
            @import URL("theme.css") print;
            @import url("semi;colon.css") screen;
            .hero { background: url('../img/hero.png'); }
            .icon { mask: URL("https://cdn.test/icon.svg#shape"); }
            .inline { background: url(data:image/svg+xml,<svg/>); }
            .local { mask: url(#local); }
        "#;
        assert_eq!(
            css_resource_urls(css, &base),
            vec![
                "https://example.test/css/img/hero.png".to_string(),
                "https://cdn.test/icon.svg".to_string(),
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stylesheet_caps_depth_and_fetch_failures_are_archive_diagnostics() {
        let directory = std::env::temp_dir().join(format!(
            "obscura-stylesheet-archive-diagnostics-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&directory).unwrap();
        for depth in 0..=5 {
            let css = if depth == 5 {
                ".leaf { color: green }".to_string()
            } else {
                format!(
                    "@import '{}.css'; .depth-{depth} {{ color: green }}",
                    depth + 1
                )
            };
            std::fs::write(directory.join(format!("{depth}.css")), css).unwrap();
        }

        let mut page = frame_page("stylesheet-archive-diagnostics");
        let document_url = url::Url::from_file_path(directory.join("index.html")).unwrap();
        page.url = Some(document_url);
        page.dom = Some(parse_html(
            "<html><head><link rel=stylesheet href='0.css'></head></html>",
        ));
        page.init_js();
        page.fetch_stylesheets().await;
        assert!(page
            .resource_archive_incomplete_reasons()
            .iter()
            .any(|reason| reason.contains("stylesheet import depth cap reached (4)")));

        let links = (0..=MAX_STYLESHEET_RESOURCES)
            .map(|index| {
                format!(
                    "<link rel=stylesheet href='file:///obscura-missing-archive-diagnostic-{index}.css'>"
                )
            })
            .collect::<String>();
        page.dom = Some(parse_html(&format!("<html><head>{links}</head></html>")));
        page.init_js();
        page.fetch_stylesheets().await;
        let reasons = page.resource_archive_incomplete_reasons();
        assert_eq!(
            reasons
                .iter()
                .filter(|reason| reason.contains("stylesheet resource cap reached"))
                .count(),
            1,
            "the same cap must remain de-duplicated across every refused root",
        );
        assert!(reasons
            .iter()
            .any(|reason| reason.contains("top-level stylesheet fetch failed:")));
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn spawn_stylesheet_graph_server(
        expected_requests: usize,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let response_origin = origin.clone();
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let length = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..length]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                request_tx.send(path.clone()).unwrap();
                let (content_type, body) = match path.as_str() {
                    "/" => (
                        "text/html",
                        r#"<!doctype html><html><head>
                            <link rel="stylesheet" href="/css/root.css#first">
                            <link rel="stylesheet" href="/css/root.css#second">
                            <link rel="preload stylesheet" href="/theme/second.css">
                        </head><body></body></html>"#
                            .to_string(),
                    ),
                    "/css/root.css" => (
                        "text/css",
                        "@import '/css/nested/shared.css';@import '/blocked.css';@import '/intercepted.css';.root{background:url('img/root.png')}".to_string(),
                    ),
                    "/theme/second.css" => (
                        "text/css",
                        "@import '../css/nested/shared.css';.second{background:url('img/second.png')}".to_string(),
                    ),
                    "/css/nested/shared.css" => (
                        "text/css",
                        "@import '../root.css';.shared{background:url('../img/shared.png')}".to_string(),
                    ),
                    _ => ("text/plain", "unexpected".to_string()),
                };
                let status = if path == "/blocked.css" || path == "/intercepted.css" {
                    "500 Unexpected Request"
                } else {
                    "200 OK"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Origin: {response_origin}\r\n\r\n{body}",
                    body.len(),
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (origin, request_rx)
    }

    fn spawn_inline_import_server() -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            // Five requests are expected after import/image deduplication. Keep
            // two extra accepts alive so a regression's bogus CSS-as-image
            // warmup still reaches the request callback and server cleanly.
            for _ in 0..7 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let length = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..length]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                request_tx.send(path.clone()).unwrap();
                let (content_type, body) = match path.as_str() {
                    "/" => (
                        "text/html",
                        r#"<!doctype html><style media="screen, print">
                            @import url('/a.css') print;
                            @import '/b.css' print;
                            .local { color: white; background-image: url('/local.svg') }
                        </style><div class="local imported-a imported-b">marker</div>"#,
                    ),
                    "/a.css" => (
                        "text/css",
                        ".imported-a{background:#9020d0 url('/imported.svg')}",
                    ),
                    "/b.css" => ("text/css", ".imported-b{border-color:#f0d020}"),
                    "/local.svg" | "/imported.svg" => (
                        "image/svg+xml",
                        r#"<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1" fill="white"/></svg>"#,
                    ),
                    _ => ("text/plain", "unexpected"),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (origin, request_rx)
    }

    #[test]
    fn default_navigation_referrer_matches_strict_origin_when_cross_origin() {
        let source = url::Url::parse("https://user:pass@source.example/path?q=1#fragment").unwrap();
        let same_origin = url::Url::parse("https://source.example/next").unwrap();
        let cross_origin = url::Url::parse("https://target.example/next").unwrap();
        let downgrade = url::Url::parse("http://source.example/next").unwrap();

        assert_eq!(
            navigation_referrer(&source, &same_origin),
            "https://source.example/path?q=1"
        );
        assert_eq!(
            navigation_referrer(&source, &cross_origin),
            "https://source.example/"
        );
        assert_eq!(navigation_referrer(&source, &downgrade), "");

        let data_source = url::Url::parse("data:text/html,source").unwrap();
        assert_eq!(navigation_referrer(&data_source, &cross_origin), "");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn document_navigation_referrer_survives_http_redirects() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let length = stream.read(&mut request).unwrap();
                let request_text = String::from_utf8_lossy(&request[..length]);
                let path = request_text
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/");
                let response = match path {
                    "/source" => {
                        let body = "<script>location.href='/redirect'</script>";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len(),
                        )
                    }
                    "/redirect" => "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/final" => {
                        let body = "<!doctype html><title>final</title>";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len(),
                        )
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                };
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "referrer-redirect".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("referrer-redirect".to_string(), context);
        let source = format!("http://{address}/source");
        page.navigate(&source).await.unwrap();

        let observed = page
            .js
            .as_mut()
            .unwrap()
            .evaluate("[document.URL, document.referrer]")
            .unwrap();
        assert_eq!(
            observed,
            serde_json::json!([format!("http://{address}/final"), source])
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn linked_stylesheet_graph_fetches_once_and_preserves_order_and_bases() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (origin, requests) = spawn_stylesheet_graph_server(4);
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "stylesheet-graph".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("stylesheet-graph".to_string(), context);
        page.set_blocked_urls(vec!["*blocked.css".to_string()]);
        page.intercept_block_patterns = vec!["*intercepted.css".to_string()];
        page.enable_intercept(true);

        let request_count = std::sync::Arc::new(AtomicUsize::new(0));
        let response_count = std::sync::Arc::new(AtomicUsize::new(0));
        let observed_requests = request_count.clone();
        page.on_request(std::sync::Arc::new(move |request| {
            if request.resource_type == obscura_net::ResourceType::Stylesheet {
                observed_requests.fetch_add(1, Ordering::SeqCst);
            }
        }));
        let observed_responses = response_count.clone();
        page.on_response(std::sync::Arc::new(move |request, _| {
            if request.resource_type == obscura_net::ResourceType::Stylesheet {
                observed_responses.fetch_add(1, Ordering::SeqCst);
            }
        }));

        page.navigate(&format!("{origin}/")).await.unwrap();

        let mut paths = (0..4)
            .map(|_| {
                requests
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "/".to_string(),
                "/css/nested/shared.css".to_string(),
                "/css/root.css".to_string(),
                "/theme/second.css".to_string(),
            ]
        );
        assert_eq!(request_count.load(Ordering::SeqCst), 3);
        assert_eq!(response_count.load(Ordering::SeqCst), 3);
        assert_eq!(
            page.network_events
                .iter()
                .filter(|event| event.resource_type == "Stylesheet")
                .count(),
            3
        );

        let sheets = page
            .js
            .as_ref()
            .unwrap()
            .with_dom(|dom| {
                dom.query_selector_all("style[data-obscura-external-stylesheets]")
                    .unwrap()
                    .into_iter()
                    .map(|nid| dom.text_content(nid))
                    .collect::<Vec<_>>()
            })
            .unwrap();
        assert_eq!(sheets.len(), 3);
        assert_eq!(sheets[0], sheets[1], "duplicate links reuse one download");
        let shared = sheets[0].find(".shared").unwrap();
        let root = sheets[0].find(".root").unwrap();
        assert!(shared < root, "imports precede the importing sheet");
        assert!(sheets[0].contains(&format!("url(\"{origin}/css/img/shared.png\")")));
        assert!(sheets[0].contains(&format!("url(\"{origin}/css/img/root.png\")")));
        let root = sheets[2].find(".root").unwrap();
        let shared = sheets[2].find(".shared").unwrap();
        let second = sheets[2].find(".second").unwrap();
        assert!(
            root < shared && shared < second,
            "cycle is cut without reordering rules"
        );
        assert!(sheets[2].contains(&format!("url(\"{origin}/theme/img/second.png\")")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inline_imports_fetch_in_order_and_materialize_before_source_style() {
        let (origin, requests) = spawn_inline_import_server();
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "inline-imports".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("inline-imports".to_string(), context);
        page.set_viewport((100.0, 80.0));
        let observed_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let callback_requests = observed_requests.clone();
        page.on_request(std::sync::Arc::new(move |request| {
            callback_requests
                .lock()
                .unwrap()
                .push((request.url.path().to_string(), request.resource_type));
        }));
        page.navigate(&format!("{origin}/")).await.unwrap();

        let mut paths = (0..3)
            .map(|_| {
                requests
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(paths, vec!["/", "/a.css", "/b.css"]);
        let observed_requests = observed_requests.lock().unwrap();
        for path in ["/a.css", "/b.css"] {
            assert_eq!(
                observed_requests
                    .iter()
                    .filter(|(request_path, _)| request_path == path)
                    .map(|(_, resource_type)| *resource_type)
                    .collect::<Vec<_>>(),
                vec![obscura_net::ResourceType::Stylesheet],
                "an inline import must fetch exactly once as a stylesheet"
            );
        }
        #[cfg(feature = "render")]
        {
            for path in ["/local.svg", "/imported.svg"] {
                assert_eq!(
                    observed_requests
                        .iter()
                        .filter(|(request_path, _)| request_path == path)
                        .map(|(_, resource_type)| *resource_type)
                        .collect::<Vec<_>>(),
                    vec![obscura_net::ResourceType::Image],
                    "ordinary rule assets must remain in render warmup"
                );
            }
        }
        drop(observed_requests);

        let styles = page
            .js
            .as_ref()
            .unwrap()
            .with_dom(|dom| {
                dom.query_selector_all("style")
                    .unwrap()
                    .into_iter()
                    .map(|nid| {
                        let node = dom.get_node(nid).unwrap();
                        (
                            node.get_attribute("data-obscura-inline-import").is_some(),
                            node.get_attribute("media").map(str::to_string),
                            dom.text_content(nid),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap();
        assert_eq!(styles.len(), 3);
        assert!(styles[0].0 && styles[0].2.contains(".imported-a"));
        assert!(styles[1].0 && styles[1].2.contains(".imported-b"));
        assert!(!styles[2].0 && styles[2].2.contains(".local"));
        assert_eq!(styles[0].1.as_deref(), Some("screen, print"));
        assert_eq!(styles[1].1.as_deref(), Some("screen, print"));
        assert!(styles[0].2.starts_with("@media print {\n"));
        assert!(styles[1].2.starts_with("@media print {\n"));

        #[cfg(feature = "render")]
        {
            let pdf = page
                .raster_pdf(crate::RasterPdfOptions {
                    print_background: true,
                    paper_width_in: 100.0 / 72.0,
                    paper_height_in: 80.0 / 72.0,
                    margin_top_in: 0.0,
                    margin_bottom_in: 0.0,
                    margin_left_in: 0.0,
                    margin_right_in: 0.0,
                    ..crate::RasterPdfOptions::default()
                })
                .expect("inline-import print PDF");
            assert!(pdf.starts_with(b"%PDF-1.4"));
        }
    }

    fn client_replacement_page(name: &str, deferred: bool) -> super::Page {
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            name.to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new(name.to_string(), context);
        let server_content = (0..45)
            .map(|index| format!("<p>server content item {index} with enough text</p>"))
            .collect::<String>();
        let start = if deferred {
            "window.addEventListener('mount-client', () => setTimeout(mountClient, 0));"
        } else {
            "mountClient();"
        };
        let html = format!(
            r#"<!doctype html><html><body><main id="ssr">{server_content}</main><script>
                function mountClient() {{
                    document.body.innerHTML = '<button id="client" data-clicks="0">Client view</button>';
                    const button = document.getElementById('client');
                    button.addEventListener('click', () => {{
                        button.setAttribute('data-clicks', String(Number(button.getAttribute('data-clicks')) + 1));
                    }});
                }}
                {start}
            </script></body></html>"#,
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(html);
        page.url =
            Some(url::Url::parse(&format!("data:text/html;base64,{encoded}")).expect("data URL"));
        page
    }

    fn assert_client_replacement_survived(page: &mut super::Page) {
        let state = page
            .js
            .as_mut()
            .expect("page runtime")
            .evaluate(
                r#"
                var clientReplacementCheck = true;
                const button = document.getElementById('client');
                if (button) button.dispatchEvent(new Event('click'));
                return {
                    staleServerContent: !!document.getElementById('ssr'),
                    clientPresent: !!button,
                    clientText: button ? button.textContent : null,
                    clicks: button ? button.getAttribute('data-clicks') : null,
                    bodyElements: document.querySelectorAll('body *').length
                };
                "#,
            )
            .expect("inspect client replacement");
        assert_eq!(
            state,
            serde_json::json!({
                "staleServerContent": false,
                "clientPresent": true,
                "clientText": "Client view",
                "clicks": "1",
                "bodyElements": 1,
            }),
        );
    }

    fn spawn_parser_import_map_server(
        expected_requests: usize,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let length = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..length]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                request_tx.send(path.clone()).unwrap();
                let (status, body) = match path.as_str() {
                    "/app/before.js" => ("200 OK", "export const value = 'before-first-module';"),
                    "/app/later.js" => ("200 OK", "export const value = 'later-map';"),
                    "/app/async.js" => (
                        "200 OK",
                        "import('too-late')\
                           .then(module => globalThis.__async_before_map = module.value)\
                           .catch(() => globalThis.__async_before_map = 'rejected');",
                    ),
                    _ => ("404 Not Found", "not found"),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (format!("http://{}", address), request_rx)
    }

    fn spawn_delayed_classic_script_server(
        delay: std::time::Duration,
        body: &'static str,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let length = stream.read(&mut request).unwrap();
            let path = String::from_utf8_lossy(&request[..length])
                .lines()
                .next()
                .and_then(|line| line.split_ascii_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            request_tx.send(path).unwrap();
            std::thread::sleep(delay);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        (format!("http://{address}"), request_rx)
    }

    fn spawn_script_resource_cache_server(
        distinct: bool,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::Ordering;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let script_requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_requests = script_requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let observed_requests = observed_requests.clone();
                std::thread::spawn(move || {
                    let mut request = [0u8; 2048];
                    let length = stream.read(&mut request).unwrap_or(0);
                    let request_text = String::from_utf8_lossy(&request[..length]);
                    let path = request_text
                        .lines()
                        .next()
                        .and_then(|line| line.split_ascii_whitespace().nth(1))
                        .unwrap_or("/");
                    let (content_type, cache_control, body) = if path == "/duplicate.html" {
                        let tags = (0..32)
                            .map(|_| "<script src='/shared.js'></script>")
                            .collect::<String>();
                        (
                            "text/html",
                            "no-store",
                            format!(
                                "<!doctype html><html><body><script>globalThis.__runs=0</script>{tags}</body></html>"
                            ),
                        )
                    } else if path == "/distinct.html" {
                        let tags = (0..24)
                            .map(|index| format!("<script src='/distinct/{index}.js'></script>"))
                            .collect::<String>();
                        (
                            "text/html",
                            "no-store",
                            format!(
                                "<!doctype html><html><body><script>globalThis.__runs=0</script>{tags}</body></html>"
                            ),
                        )
                    } else if path == "/shared.js" || path.starts_with("/distinct/") {
                        observed_requests.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(80));
                        (
                            "application/javascript",
                            "public, max-age=3600",
                            "globalThis.__runs=(globalThis.__runs||0)+1;".to_string(),
                        )
                    } else {
                        ("text/plain", "no-store", "not found".to_string())
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: {cache_control}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                    );
                    let _ = stream.write_all(response.as_bytes());
                });
            }
        });
        let page = if distinct {
            "distinct.html"
        } else {
            "duplicate.html"
        };
        (format!("http://{address}/{page}"), script_requests)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn duplicate_cacheable_scripts_fetch_once_but_execute_for_each_element() {
        use std::sync::atomic::Ordering;

        let (url, script_requests) = spawn_script_resource_cache_server(false);
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "duplicate-script-cache".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("duplicate-script-cache".to_string(), context);

        page.navigate(&url).await.unwrap();

        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__runs")
                .unwrap(),
            serde_json::json!(32.0),
            "a cached response must still execute for every script element",
        );
        assert_eq!(script_requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn distinct_cacheable_scripts_keep_distinct_network_requests() {
        use std::sync::atomic::Ordering;

        let (url, script_requests) = spawn_script_resource_cache_server(true);
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "distinct-script-cache".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("distinct-script-cache".to_string(), context);

        page.navigate(&url).await.unwrap();

        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__runs")
                .unwrap(),
            serde_json::json!(24.0),
        );
        assert_eq!(script_requests.load(Ordering::SeqCst), 24);
    }

    #[test]
    fn external_scripts_require_a_successful_http_status() {
        assert!(script_response_is_executable(200));
        assert!(script_response_is_executable(204));
        assert!(script_response_is_executable(299));
        assert!(!script_response_is_executable(0));
        assert!(!script_response_is_executable(304));
        assert!(!script_response_is_executable(401));
        assert!(!script_response_is_executable(404));
        assert!(!script_response_is_executable(500));
    }

    /// `/` puts its iframe inside a closed shadow root, `/plain.html` puts the
    /// same iframe straight in the document, and `/child.html` is the frame.
    async fn spawn_shadow_frame_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 2048];
                    let read = socket.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..read]).to_string();
                    let (content_type, body) = if request.starts_with("GET /child.html ") {
                        (
                            "text/html",
                            "<html><body><script>window.__ran = 'YES';</script></body></html>",
                        )
                    } else if request.starts_with("GET /plain.html ") {
                        (
                            "text/html",
                            "<html><body><iframe src=\"/child.html\"></iframe></body></html>",
                        )
                    } else if request.starts_with("GET /fixed-wait.html ") {
                        (
                            "text/html",
                            "<html><body><script>\
                             setTimeout(function () {\
                               var f = document.createElement('iframe');\
                               f.src = '/async-child.html';\
                               document.body.appendChild(f);\
                             }, 100);\
                             </script></body></html>",
                        )
                    } else if request.starts_with("GET /async-child.html ") {
                        (
                            "text/html",
                            "<html><body><script>\
                             setTimeout(function () {\
                               fetch('/frame-resource.txt')\
                                 .then(function (response) { return response.text(); })\
                                 .then(function (text) { window.__deferredFrameWork = text; });\
                             }, 100);\
                             </script></body></html>",
                        )
                    } else if request.starts_with("GET /frame-resource.txt ") {
                        ("text/plain", "FRAME-READY")
                    } else if request.starts_with("GET /dynamic-frame-parent.html ") {
                        (
                            "text/html",
                            "<html><body><iframe src=\"/dynamic-frame.html\"></iframe></body></html>",
                        )
                    } else if request.starts_with("GET /dynamic-frame.html ") {
                        (
                            "text/html",
                            "<html><body><script>\
                             window.__dynamicFrameLoads = 0;\
                             var script = document.createElement('script');\
                             script.src = '/frame-dynamic.js';\
                             script.onload = function () { window.__dynamicFrameOnload = true; };\
                             document.body.appendChild(script);\
                             </script></body></html>",
                        )
                    } else if request.starts_with("GET /frame-dynamic.js ") {
                        ("application/javascript", "window.__dynamicFrameLoads += 1;")
                    } else {
                        (
                            "text/html",
                            "<html><body><div id=\"host\"></div><script>\
                         var r = document.getElementById('host').attachShadow({mode:'closed'});\
                         var f = document.createElement('iframe');\
                         f.src = '/child.html';\
                         r.appendChild(f);\
                         </script></body></html>",
                        )
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        });
        format!("http://{addr}/")
    }

    fn spawn_redirected_frame_stylesheet_server() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            while let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 4096];
                let length = stream.read(&mut request).unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..length]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/");
                let response = match path {
                    "/parent.html" => {
                        let body = "<!doctype html><iframe src=\"/frame/start\"></iframe>";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len(),
                        )
                    }
                    "/frame/start" => "HTTP/1.1 302 Found\r\nLocation: /frame/final.html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    "/frame/final.html" => {
                        let body = concat!(
                            "<!doctype html><html><head>",
                            "<link rel=\"stylesheet\" href=\"frame.css\">",
                            "<style>@import url('unsupported.css'); .inline-style { mask-image: url(inline.svg); }</style>",
                            "</head><body>",
                            "<div class=\"inline-style\" style=\"background-image: url(attribute.svg)\"></div>",
                            "<script src=\"child.js\"></script>",
                            "<script>window.__frameCssReady = globalThis.__obscura_css.includes('redirected-frame-sheet');</script>",
                            "<script type=\"module\" src=\"module.js\"></script>",
                            "<script>location.href='/later-frame.html';</script>",
                            "</body></html>",
                        );
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len(),
                        )
                    }
                    "/frame/frame.css" => {
                        let body = "body { --redirected-frame-sheet: yes; background-image: url(icon.svg); }";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len(),
                        )
                    }
                    "/frame/child.js" => {
                        let body = "window.__redirectedChildScript = 'loaded';";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len(),
                        )
                    }
                    "/frame/icon.svg" | "/frame/inline.svg" | "/frame/attribute.svg" => {
                        let body = format!(
                            "<svg xmlns=\"http://www.w3.org/2000/svg\"><title>{path}</title></svg>"
                        );
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len(),
                        )
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                };
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{address}")
    }

    const FRAME_RENDER_CHILD_HTML: &str = concat!(
        "<!doctype html><html><head>",
        "<style>@import '/inline-root.css'; .inline { background-image:url('/inline.svg') }</style>",
        "</head><body>",
        "<img src=\"/static.svg\">",
        "<picture><source media=\"(min-width:1px)\" srcset=\"/picture.svg\">",
        "<img src=\"/fallback.svg\"></picture>",
        "<video poster=\"/poster.svg\"></video>",
        "<script>setTimeout(function(){",
        "var image=document.createElement('img');image.src='/dynamic.svg';document.body.appendChild(image);",
        "var style=document.createElement('style');style.textContent=\"@import '/dynamic-inline.css'; .dynamic{background-image:url('/dynamic-style.svg')}\";document.head.appendChild(style);",
        "var link=document.createElement('link');link.rel='stylesheet';link.href='/late.css';document.head.appendChild(link);",
        "},25)</script>",
        "</body></html>",
    );
    const FRAME_RENDER_LATE_CSS: &str =
        "@import '/nested.css'; .linked { background-image:url('/linked.svg') }";
    const FRAME_RENDER_INLINE_ROOT_CSS: &str =
        "@import '/inline-nested.css'; .inline-root { background-image:url('/inline-root.svg') }";
    const FRAME_RENDER_INLINE_NESTED_CSS: &str =
        ".inline-nested { background-image:url('/inline-nested.svg') }";
    const FRAME_RENDER_DYNAMIC_INLINE_CSS: &str =
        ".dynamic-inline { background-image:url('/dynamic-inline.svg') }";
    const FRAME_RENDER_NESTED_CSS: &str = "@font-face { font-family:nested; src:url('/nested.woff2') } .nested { background-image:url('/nested.svg') }";
    const FRAME_RENDER_FONT_BYTES: &str = "frame-font-response-bytes";

    fn frame_render_svg_body(path: &str) -> String {
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"2\" height=\"3\"><title>{path}</title></svg>"
        )
    }

    fn spawn_frame_render_resource_server() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            while let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 4096];
                let length = stream.read(&mut request).unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..length]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/");
                let (content_type, body) = match path {
                    "/parent.html" => (
                        "text/html",
                        "<!doctype html><iframe src=\"/child.html\"></iframe>".to_string(),
                    ),
                    "/top-dynamic.html" => (
                        "text/html",
                        concat!(
                            "<!doctype html><html><head></head><body>",
                            "<script>setTimeout(function(){",
                            "var style=document.createElement('style');",
                            "style.textContent=\"@import '/top-inline-root.css'; .top{background:url('/top-inline.svg')}\";",
                            "document.head.appendChild(style);",
                            "},25)</script></body></html>",
                        )
                        .to_string(),
                    ),
                    "/top-missing.html" => (
                        "text/html",
                        concat!(
                            "<!doctype html><script>setTimeout(function(){",
                            "var style=document.createElement('style');",
                            "style.textContent=\"@import '/top-missing.css';\";",
                            "document.head.appendChild(style);",
                            "},25)</script>",
                        )
                        .to_string(),
                    ),
                    "/shadow-parent.html" => (
                        "text/html",
                        concat!(
                            "<!doctype html><div id='host'></div><iframe src='/shadow-frame.html'></iframe>",
                            "<script>setTimeout(function(){",
                            "var outer=document.getElementById('host').attachShadow({mode:'closed'});",
                            "var innerHost=document.createElement('div');outer.appendChild(innerHost);",
                            "var inner=innerHost.attachShadow({mode:'closed'});",
                            "var style=document.createElement('style');",
                            "style.textContent=\".paint{background-image:url('/shadow-top-byte.svg')}\";",
                            "inner.appendChild(style);",
                            "},25)</script>",
                        )
                        .to_string(),
                    ),
                    "/shadow-frame.html" => (
                        "text/html",
                        concat!(
                            "<!doctype html><div><template shadowrootmode='closed'>",
                            "<div><template shadowrootmode='closed'>",
                            "<style>.paint{background-image:url('/shadow-frame-byte.svg')}</style>",
                            "</template></div></template></div>",
                        )
                        .to_string(),
                    ),
                    "/shadow-unsupported.html" => (
                        "text/html",
                        concat!(
                            "<!doctype html>",
                            "<div><template shadowrootmode='closed'>",
                            "<link rel='stylesheet' href='/shadow-link.css'>",
                            "</template></div><div id='import-host'></div>",
                            "<script>",
                            "var root=document.getElementById('import-host').attachShadow({mode:'closed'});",
                            "var style=document.createElement('style');",
                            "style.textContent=\"@import '/shadow-import.css'; .paint{color:green}\";",
                            "root.appendChild(style);",
                            "</script>",
                        )
                        .to_string(),
                    ),
                    "/shadow-link.css" | "/shadow-import.css" => (
                        "text/css",
                        ".shadow-sheet { color: green }".to_string(),
                    ),
                    "/child.html" => (
                        "text/html",
                        FRAME_RENDER_CHILD_HTML.to_string(),
                    ),
                    "/missing-parent.html" => (
                        "text/html",
                        "<!doctype html><iframe src=\"/missing-child.html\"></iframe>"
                            .to_string(),
                    ),
                    "/missing-child.html" => (
                        "text/html",
                        "<!doctype html><script>var link=document.createElement('link');link.rel='stylesheet';link.href='/missing.css';document.head.appendChild(link)</script>"
                            .to_string(),
                    ),
                    "/late.css" => (
                        "text/css",
                        FRAME_RENDER_LATE_CSS.to_string(),
                    ),
                    "/inline-root.css" => (
                        "text/css",
                        FRAME_RENDER_INLINE_ROOT_CSS.to_string(),
                    ),
                    "/inline-nested.css" => (
                        "text/css",
                        FRAME_RENDER_INLINE_NESTED_CSS.to_string(),
                    ),
                    "/dynamic-inline.css" => (
                        "text/css",
                        FRAME_RENDER_DYNAMIC_INLINE_CSS.to_string(),
                    ),
                    "/top-inline-root.css" => (
                        "text/css",
                        "@import '/top-inline-nested.css'; .top-root { background-image:url('/top-root.svg') }"
                            .to_string(),
                    ),
                    "/top-inline-nested.css" => (
                        "text/css",
                        ".top-nested { background-image:url('/top-nested.svg') }"
                            .to_string(),
                    ),
                    "/nested.css" => (
                        "text/css",
                        FRAME_RENDER_NESTED_CSS.to_string(),
                    ),
                    "/nested.woff2" => ("font/woff2", FRAME_RENDER_FONT_BYTES.to_string()),
                    path if path.ends_with(".svg") =>
                        ("image/svg+xml", frame_render_svg_body(path)),
                    _ => ("text/plain", "not found".to_string()),
                };
                let status = if body == "not found" {
                    "404 Not Found"
                } else {
                    "200 OK"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{address}")
    }

    fn spawn_srcdoc_frame_server() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            while let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 4096];
                let length = stream.read(&mut request).unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..length]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/");
                let (status, content_type, body) = match path {
                    "/parser.html" => (
                        "200 OK",
                        "text/html",
                        concat!(
                            "<!doctype html><base href='/assets/'>",
                            "<iframe src='/ignored.html' srcdoc=\"<!doctype html><html><head>",
                            "<link rel=&quot;stylesheet&quot; href=&quot;parser.css&quot;>",
                            "<script src=&quot;parser.js&quot;></script></head>",
                            "<body data-srcdoc=&quot;parser&quot;><img src=&quot;parser.svg&quot;>",
                            "</body></html>\"></iframe>",
                        ),
                    ),
                    "/dynamic.html" => (
                        "200 OK",
                        "text/html",
                        concat!(
                            "<!doctype html><base href='/assets/'><iframe id='frame' src='/fallback.html'></iframe>",
                            "<script>var f=document.getElementById('frame');",
                            "f.srcdoc='<img src=\"stale.svg\">';",
                            "f.srcdoc='<body data-srcdoc=\"dynamic\"><img src=\"dynamic.svg\"></body>';",
                            "</script>",
                        ),
                    ),
                    "/fallback.html" => (
                        "200 OK",
                        "text/html",
                        "<!doctype html><body data-srcdoc='fallback'><img src='/assets/fallback.svg'>",
                    ),
                    "/assets/parser.js" => (
                        "200 OK",
                        "application/javascript",
                        "globalThis.__srcdocParserScript = 'ran';",
                    ),
                    "/assets/parser.css" => (
                        "200 OK",
                        "text/css",
                        "body { background-image:url('css.svg') }",
                    ),
                    path if path.ends_with(".svg") => (
                        "200 OK",
                        "image/svg+xml",
                        "<svg xmlns='http://www.w3.org/2000/svg' width='2' height='3'></svg>",
                    ),
                    _ => ("404 Not Found", "text/plain", "not found"),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{address}")
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn srcdoc_frames_inherit_base_capture_resources_and_replace_their_realm() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let origin = spawn_srcdoc_frame_server();
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "srcdoc-frame-lifecycle".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("srcdoc-frame-lifecycle".to_string(), context);
        page.enable_resource_capture(super::ResourceCaptureLimits::default());
        page.navigate(&format!("{origin}/parser.html"))
            .await
            .unwrap();
        page.settle_for_duration(50).await;
        for _ in 0..3 {
            let report = page.prepare_screenshot_resources_with_report(1_000).await;
            assert_eq!(report.failed, 0, "srcdoc warmup failed: {report:?}");
            assert_eq!(report.timed_out, 0, "srcdoc warmup timed out: {report:?}");
        }

        let parser_frame = page.frame_snapshots().into_iter().next().unwrap();
        assert_ne!(parser_frame.frame_id, 0);
        assert_eq!(parser_frame.url, "about:srcdoc");
        assert_eq!(
            page.evaluate_in_frame(
                0,
                "({url:document.URL,base:document.baseURI,ran:globalThis.__srcdocParserScript})",
            )
            .unwrap(),
            serde_json::json!({
                "url": "about:srcdoc",
                "base": format!("{origin}/assets/"),
                "ran": "ran",
            }),
        );
        let capture = page.take_resource_capture().unwrap();
        let parser_urls = capture
            .resources
            .iter()
            .filter(|resource| resource.frame_id == parser_frame.frame_id)
            .map(|resource| resource.final_url.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        for path in ["parser.js", "parser.css", "parser.svg", "css.svg"] {
            assert!(
                parser_urls.contains(&format!("{origin}/assets/{path}")),
                "missing srcdoc resource {path}: {parser_urls:#?}",
            );
        }

        page.navigate(&format!("{origin}/dynamic.html"))
            .await
            .unwrap();
        page.settle_for_duration(50).await;
        let first = page.frame_snapshots();
        assert_eq!(
            first.len(),
            1,
            "stale queued srcdoc realm survived: {first:?}"
        );
        assert_eq!(first[0].url, "about:srcdoc");
        let first_id = first[0].frame_id;
        page.evaluate(
            "document.getElementById('frame').srcdoc='<body data-srcdoc=\"replacement\"><img src=\"replacement.svg\"></body>'",
        );
        page.settle_for_duration(50).await;
        let replacement = page.frame_snapshots();
        assert_eq!(replacement.len(), 1);
        assert_ne!(replacement[0].frame_id, first_id);
        assert_eq!(replacement[0].url, "about:srcdoc");
        assert_eq!(
            page.evaluate_in_frame(0, "document.body.getAttribute('data-srcdoc')")
                .unwrap(),
            serde_json::json!("replacement"),
        );

        let replacement_id = replacement[0].frame_id;
        page.evaluate("document.getElementById('frame').removeAttribute('srcdoc')");
        page.settle_for_duration(50).await;
        let fallback = page.frame_snapshots();
        assert_eq!(fallback.len(), 1);
        assert_ne!(fallback[0].frame_id, replacement_id);
        assert_eq!(fallback[0].url, format!("{origin}/fallback.html"));

        page.set_blocked_urls(vec!["*parser.js".to_string()]);
        page.navigate(&format!("{origin}/parser.html"))
            .await
            .unwrap();
        page.settle_for_duration(50).await;
        assert!(page
            .resource_archive_incomplete_reasons()
            .iter()
            .any(|reason| {
                reason.contains("classic script was blocked")
                    && reason.contains("/assets/parser.js")
            }));
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn frame_render_warmup_captures_static_and_dynamic_final_dom_resources() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let origin = spawn_frame_render_resource_server();
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "frame-render-resource-warmup".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("frame-render-resource-warmup".to_string(), context);
        page.enable_resource_capture(super::ResourceCaptureLimits::default());
        page.navigate(&format!("{origin}/parent.html"))
            .await
            .unwrap();
        page.settle_for_duration(100).await;

        for _ in 0..5 {
            let report = page.prepare_screenshot_resources_with_report(1_000).await;
            assert_eq!(report.failed, 0, "frame warmup failed: {report:?}");
            assert_eq!(report.timed_out, 0, "frame warmup timed out: {report:?}");
        }

        let frame = page.frame_snapshots().into_iter().next().unwrap();
        let capture = page.take_resource_capture().unwrap();
        let frame_resources = capture
            .resources
            .iter()
            .filter(|resource| resource.frame_id == frame.frame_id)
            .collect::<Vec<_>>();
        assert_eq!(
            frame_resources.len(),
            18,
            "unexpected frame capture: {frame_resources:#?}"
        );

        let document_resources = frame_resources
            .iter()
            .copied()
            .filter(|resource| resource.resource_type == obscura_net::ResourceType::Document)
            .collect::<Vec<_>>();
        assert_eq!(document_resources.len(), 1);
        let document = document_resources[0];
        assert_eq!(document.requested_url.as_str(), frame.url);
        assert_eq!(document.final_url.as_str(), frame.url);
        assert_eq!(document.method, "GET");
        assert_eq!(document.status, 200);
        assert!(document.redirected_from.is_empty());
        assert_eq!(document.body, FRAME_RENDER_CHILD_HTML.as_bytes());
        assert_eq!(
            document.initiator.as_ref().map(url::Url::as_str),
            Some(format!("{origin}/parent.html").as_str()),
        );

        let mut expected = vec![
            (
                "/dynamic-inline.css",
                obscura_net::ResourceType::Stylesheet,
                FRAME_RENDER_DYNAMIC_INLINE_CSS.as_bytes().to_vec(),
            ),
            (
                "/inline-nested.css",
                obscura_net::ResourceType::Stylesheet,
                FRAME_RENDER_INLINE_NESTED_CSS.as_bytes().to_vec(),
            ),
            (
                "/inline-root.css",
                obscura_net::ResourceType::Stylesheet,
                FRAME_RENDER_INLINE_ROOT_CSS.as_bytes().to_vec(),
            ),
            (
                "/late.css",
                obscura_net::ResourceType::Fetch,
                FRAME_RENDER_LATE_CSS.as_bytes().to_vec(),
            ),
            (
                "/nested.css",
                obscura_net::ResourceType::Fetch,
                FRAME_RENDER_NESTED_CSS.as_bytes().to_vec(),
            ),
            (
                "/nested.woff2",
                obscura_net::ResourceType::Font,
                FRAME_RENDER_FONT_BYTES.as_bytes().to_vec(),
            ),
        ];
        for path in [
            "/dynamic-inline.svg",
            "/dynamic-style.svg",
            "/dynamic.svg",
            "/inline-nested.svg",
            "/inline-root.svg",
            "/inline.svg",
            "/linked.svg",
            "/nested.svg",
            "/picture.svg",
            "/poster.svg",
            "/static.svg",
        ] {
            expected.push((
                path,
                obscura_net::ResourceType::Image,
                frame_render_svg_body(path).into_bytes(),
            ));
        }
        expected.sort_by(|left, right| left.0.cmp(right.0));

        let mut subresources = frame_resources
            .into_iter()
            .filter(|resource| resource.resource_type != obscura_net::ResourceType::Document)
            .collect::<Vec<_>>();
        subresources.sort_by(|left, right| left.final_url.path().cmp(right.final_url.path()));
        assert_eq!(subresources.len(), expected.len());
        for (resource, (path, resource_type, body)) in subresources.into_iter().zip(expected) {
            assert_eq!(resource.requested_url.as_str(), format!("{origin}{path}"));
            assert_eq!(resource.final_url.as_str(), format!("{origin}{path}"));
            assert_eq!(
                resource.resource_type, resource_type,
                "wrong type for {path}"
            );
            assert_eq!(resource.body, body, "wrong response bytes for {path}");
            assert_eq!(resource.method, "GET");
            assert_eq!(resource.status, 200);
            assert!(resource.redirected_from.is_empty());
            assert_eq!(
                resource.initiator.as_ref().map(url::Url::as_str),
                Some(frame.url.as_str()),
                "wrong initiator for {path}",
            );
        }
        assert!(page.resource_archive_incomplete_reasons().is_empty());
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn top_render_warmup_captures_dynamic_inline_stylesheet_import_graph() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let origin = spawn_frame_render_resource_server();
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "top-inline-import-warmup".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("top-inline-import-warmup".to_string(), context);
        page.enable_resource_capture(super::ResourceCaptureLimits::default());
        page.navigate(&format!("{origin}/top-dynamic.html"))
            .await
            .unwrap();
        page.settle_for_duration(100).await;

        for _ in 0..4 {
            let report = page.prepare_screenshot_resources_with_report(1_000).await;
            assert_eq!(report.failed, 0, "top warmup failed: {report:?}");
            assert_eq!(report.timed_out, 0, "top warmup timed out: {report:?}");
        }

        let capture = page.take_resource_capture().unwrap();
        let resources = capture
            .resources
            .iter()
            .filter(|resource| resource.frame_id == 0)
            .collect::<Vec<_>>();
        let urls = resources
            .iter()
            .map(|resource| resource.final_url.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        for path in [
            "/top-inline-root.css",
            "/top-inline-nested.css",
            "/top-inline.svg",
            "/top-root.svg",
            "/top-nested.svg",
        ] {
            assert!(
                urls.contains(&format!("{origin}{path}")),
                "missing top-level dynamic inline import resource {path}: {urls:#?}",
            );
        }
        let document_url = format!("{origin}/top-dynamic.html");
        assert!(resources
            .iter()
            .filter(|resource| resource.final_url.as_str() != document_url)
            .all(|resource| {
                resource.initiator.as_ref().map(url::Url::as_str) == Some(document_url.as_str())
            }));
        assert!(page.resource_archive_incomplete_reasons().is_empty());
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn top_dynamic_inline_stylesheet_http_failure_is_archive_incomplete() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let origin = spawn_frame_render_resource_server();
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "top-inline-import-failure".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("top-inline-import-failure".to_string(), context);
        page.navigate(&format!("{origin}/top-missing.html"))
            .await
            .unwrap();
        page.settle_for_duration(100).await;

        let report = page.prepare_screenshot_resources_with_report(1_000).await;
        assert_eq!(report.failed, 1, "unexpected top warmup: {report:?}");
        assert!(page
            .resource_archive_incomplete_reasons()
            .iter()
            .any(|reason| {
                reason.contains("top-level stylesheet")
                    && reason.contains("top-missing.css")
                    && reason.contains("HTTP 404")
            }));
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn shadow_render_warmup_archives_closed_nested_resources_with_ownership() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let origin = spawn_frame_render_resource_server();
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "closed-shadow-render-resource-warmup".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page =
            super::Page::new("closed-shadow-render-resource-warmup".to_string(), context);
        page.enable_resource_capture(super::ResourceCaptureLimits::default());
        page.navigate(&format!("{origin}/shadow-parent.html"))
            .await
            .unwrap();
        page.settle_for_duration(500).await;

        for _ in 0..3 {
            let report = page.prepare_screenshot_resources_with_report(1_000).await;
            assert_eq!(report.failed, 0, "shadow warmup failed: {report:?}");
            assert_eq!(report.timed_out, 0, "shadow warmup timed out: {report:?}");
        }
        assert!(page.resource_archive_incomplete_reasons().is_empty());

        let frame = page
            .frame_snapshots()
            .into_iter()
            .find(|frame| frame.url.ends_with("/shadow-frame.html"))
            .expect("live shadow fixture frame");
        let capture = page.take_resource_capture().unwrap();
        for (path, frame_id, initiator) in [
            (
                "/shadow-top-byte.svg",
                0,
                format!("{origin}/shadow-parent.html"),
            ),
            (
                "/shadow-frame-byte.svg",
                frame.frame_id,
                format!("{origin}/shadow-frame.html"),
            ),
        ] {
            let url = format!("{origin}{path}");
            let resource = capture
                .resources
                .iter()
                .find(|resource| resource.final_url.as_str() == url)
                .unwrap_or_else(|| panic!("missing closed-shadow resource {url}"));
            assert_eq!(resource.frame_id, frame_id);
            assert_eq!(
                resource.initiator.as_ref().map(url::Url::as_str),
                Some(initiator.as_str()),
            );
            assert_eq!(resource.resource_type, obscura_net::ResourceType::Image);
            assert_eq!(resource.status, 200);
            assert_eq!(
                resource.body,
                format!(
                    "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"2\" height=\"3\"><title>{path}</title></svg>"
                )
                .into_bytes(),
                "resource capture changed closed-shadow response bytes",
            );
        }
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn unsupported_shadow_stylesheet_owners_are_archive_incomplete() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let origin = spawn_frame_render_resource_server();
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "unsupported-shadow-stylesheets".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("unsupported-shadow-stylesheets".to_string(), context);
        page.navigate(&format!("{origin}/shadow-unsupported.html"))
            .await
            .unwrap();

        let reasons = page.resource_archive_incomplete_reasons();
        assert!(reasons.iter().any(|reason| {
            reason
                == "top-level shadow-root inline stylesheets contain 1 unsupported @import rule(s)"
        }));
        assert!(reasons.iter().any(|reason| {
            reason.contains("shadow-root stylesheet has no materialized response owner")
                && reason.contains("/shadow-link.css")
        }));
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn dynamic_frame_stylesheet_http_failure_is_archive_incomplete() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let origin = spawn_frame_render_resource_server();
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "frame-stylesheet-http-failure".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("frame-stylesheet-http-failure".to_string(), context);
        page.navigate(&format!("{origin}/missing-parent.html"))
            .await
            .unwrap();
        page.settle_for_duration(50).await;

        let report = page.prepare_screenshot_resources_with_report(1_000).await;
        assert_eq!(report.failed, 1, "unexpected frame warmup: {report:?}");
        assert!(page
            .resource_archive_incomplete_reasons()
            .iter()
            .any(|reason| {
                reason.contains("stylesheet")
                    && reason.contains("missing.css")
                    && reason.contains("HTTP 404")
            }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirected_frame_uses_final_url_and_loads_stylesheet_in_its_frame() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let origin = spawn_redirected_frame_stylesheet_server();
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "redirected-frame-stylesheet".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("redirected-frame-stylesheet".to_string(), context);
        let observed_stylesheets = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed_images = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = observed_stylesheets.clone();
        let observed_image_responses = observed_images.clone();
        page.on_response(std::sync::Arc::new(move |request, response| {
            if request.resource_type == obscura_net::ResourceType::Stylesheet {
                observed.lock().unwrap().push((
                    request.frame_id,
                    request.initiator.as_ref().map(url::Url::to_string),
                    response.url.to_string(),
                    response.body.clone(),
                ));
            } else if request.resource_type == obscura_net::ResourceType::Image {
                observed_image_responses.lock().unwrap().push((
                    request.frame_id,
                    request.initiator.as_ref().map(url::Url::to_string),
                    response.url.to_string(),
                    response.body.clone(),
                ));
            }
        }));

        page.navigate(&format!("{origin}/parent.html"))
            .await
            .unwrap();
        page.settle_for_duration(500).await;

        let snapshots = page.frame_snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_ne!(snapshots[0].frame_id, 0);
        assert_eq!(
            snapshots[0].url,
            format!("{origin}/frame/final.html"),
            "the frame realm kept the pre-redirect iframe src as its document URL",
        );

        let mut stylesheets = observed_stylesheets.lock().unwrap().clone();
        stylesheets.sort_by(|left, right| left.2.cmp(&right.2));
        assert_eq!(
            stylesheets
                .iter()
                .map(|stylesheet| stylesheet.2.as_str())
                .collect::<Vec<_>>(),
            vec![
                format!("{origin}/frame/frame.css"),
                format!("{origin}/frame/unsupported.css"),
            ],
            "each linked or imported stylesheet must be fetched exactly once",
        );
        assert!(stylesheets.iter().all(|stylesheet| {
            stylesheet.0 == snapshots[0].frame_id
                && stylesheet.1.as_deref() == Some(snapshots[0].url.as_str())
        }));
        assert_eq!(
            stylesheets[0].3,
            b"body { --redirected-frame-sheet: yes; background-image: url(icon.svg); }",
        );
        assert!(
            stylesheets[1].3.is_empty(),
            "the fixture's 404 import response body changed",
        );
        let mut images = observed_images.lock().unwrap().clone();
        images.sort_by(|left, right| left.2.cmp(&right.2));
        assert_eq!(images.len(), 3);
        assert_eq!(
            images
                .iter()
                .map(|image| image.2.as_str())
                .collect::<Vec<_>>(),
            vec![
                format!("{origin}/frame/attribute.svg"),
                format!("{origin}/frame/icon.svg"),
                format!("{origin}/frame/inline.svg"),
            ],
        );
        assert!(images.iter().all(|image| {
            image.0 == snapshots[0].frame_id
                && image.1.as_deref() == Some(snapshots[0].url.as_str())
                && !image.3.is_empty()
        }));
        assert_eq!(
            page.evaluate_in_frame(0, "window.__frameCssReady").unwrap(),
            serde_json::json!(true),
            "frame scripts ran before the linked stylesheet was installed",
        );
        assert_eq!(
            page.evaluate_in_frame(0, "window.__redirectedChildScript")
                .unwrap(),
            serde_json::json!("loaded"),
            "the relative frame script did not resolve against the final redirected URL",
        );
        assert_eq!(
            page.evaluate_in_frame(
                0,
                "document.querySelector('style[data-obscura-external-stylesheets]').textContent",
            )
            .unwrap(),
            serde_json::json!(format!(
                "body {{ --redirected-frame-sheet: yes; background-image: url(\"{origin}/frame/icon.svg\"); }}"
            )),
        );

        let diagnostics = page.frame_resource_diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].frame_id, snapshots[0].frame_id);
        assert_eq!(diagnostics[0].unsupported_module_scripts, 1);
        assert_eq!(diagnostics[0].unsupported_stylesheet_imports, 0);
        assert_eq!(
            diagnostics[0].pending_navigation_url.as_deref(),
            Some(format!("{origin}/later-frame.html").as_str()),
        );
        assert!(page
            .resource_archive_incomplete_reasons()
            .iter()
            .any(|reason| { reason.contains("unsupported.css") && reason.contains("HTTP 404") }));
    }

    /// A `FrameRealm` owns a `v8::Global` into the runtime's isolate, which is
    /// why `init_js` clears the frames before it drops the runtime. `suspend_js`
    /// drops the same runtime and has to honour the same order, otherwise the
    /// realms of a suspended page outlive the isolate they point into and the
    /// next navigation drops those handles against a different one.
    #[tokio::test]
    async fn suspending_the_runtime_releases_the_frame_realms_it_owns() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let base = spawn_shadow_frame_server().await;
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "suspend-frames".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("suspend-frames".to_string(), context);
        page.navigate(&format!("{base}plain.html")).await.unwrap();
        assert_eq!(
            page.frame_urls().len(),
            1,
            "the page never built its child frame, so this proves nothing"
        );

        page.suspend_js();
        assert!(
            page.frame_urls().is_empty(),
            "the frame realms outlived the isolate they hold a handle into: {:?}",
            page.frame_urls()
        );

        // The page still works afterwards: resuming rebuilds the runtime, and
        // navigating again builds the frames of the new document.
        page.resume_js();
        page.navigate(&format!("{base}plain.html")).await.unwrap();
        assert_eq!(page.frame_urls().len(), 1);
    }

    fn frame_page(name: &str) -> super::Page {
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            name.to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        super::Page::new(name.to_string(), context)
    }

    #[test]
    fn rewritten_parser_stylesheet_rejects_the_stale_frozen_response() {
        let mut page = frame_page("parser-stylesheet-frozen-href-token");
        page.url = Some(url::Url::parse("https://example.test/original/page.html").unwrap());
        page.dom = Some(parse_html(
            r#"<!doctype html><html><head>
               <link id="sheet" rel="stylesheet" href="old.css">
               </head><body></body></html>"#,
        ));
        page.init_js();

        let snapshot = page.snapshot_parser_stylesheets().unwrap();
        let link = snapshot.links[0].clone();
        let request_href = link.base_url.join(&link.raw_href).unwrap().to_string();
        page.mark_parser_stylesheets_pending(&snapshot);
        page.js
            .as_mut()
            .unwrap()
            .execute_script(
                "<preload-rewrite>",
                "document.getElementById('sheet').setAttribute('href', 'data:text/css,html%7B--new-sheet:1%7D');",
            )
            .unwrap();

        let materialize = materialize_parser_stylesheet_script_with_token(
            link.nid,
            "html { --stale-parser-sheet: 1; }",
            &request_href,
            &link.raw_href,
        );
        page.js
            .as_mut()
            .unwrap()
            .execute_script("<stale-parser-sheet>", &materialize)
            .unwrap();
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate(
                    "[...document.querySelectorAll('style')].some(style => style.textContent.includes('--stale-parser-sheet'))",
                )
                .unwrap(),
            serde_json::json!(false),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn removed_and_restored_parser_stylesheet_rejects_the_old_response() {
        let mut page = frame_page("parser-stylesheet-invalidated-epoch");
        page.url = Some(url::Url::parse("https://example.test/original/page.html").unwrap());
        page.dom = Some(parse_html(
            r#"<!doctype html><html><head>
               <link id="sheet" rel="stylesheet" href="old.css">
               </head><body></body></html>"#,
        ));
        page.init_js();

        let snapshot = page.snapshot_parser_stylesheets().unwrap();
        let link = snapshot.links[0].clone();
        let request_href = link.base_url.join(&link.raw_href).unwrap().to_string();
        page.mark_parser_stylesheets_pending(&snapshot);
        page.js
            .as_mut()
            .unwrap()
            .execute_script(
                "<preload-remove-reset>",
                "var link = document.getElementById('sheet');\
                 link.removeAttribute('href');\
                 link.setAttribute('href', 'old.css');",
            )
            .unwrap();

        let materialize = materialize_parser_stylesheet_script_with_token(
            link.nid,
            "html { --stale-parser-sheet: 1; }",
            &request_href,
            &link.raw_href,
        );
        page.js
            .as_mut()
            .unwrap()
            .execute_script("<stale-parser-sheet>", &materialize)
            .unwrap();
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate(
                    "[globalThis.__obscura_isParserStylesheetPending(document.getElementById('sheet')),\
                     [...document.querySelectorAll('style')].some(style => style.textContent.includes('--stale-parser-sheet'))]",
                )
                .unwrap(),
            serde_json::json!([false, false]),
        );
    }

    #[test]
    fn frame_diagnostic_evaluation_failure_is_incomplete_and_navigation_resets_it() {
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(parse_html("<html><body>parent</body></html>"));
        runtime.set_url("https://parent.example/");
        runtime.run_page_init();
        let frame = obscura_js::frame::FrameRealm::new(
            &mut runtime,
            7,
            0,
            "https://frame.example/",
            "<html><body><script type=module></script></body></html>",
        )
        .unwrap();
        frame
            .execute_script(&mut runtime, "document.querySelectorAll = undefined;")
            .unwrap();

        let mut page = frame_page("frame-diagnostic-failure");
        page.frames.push(frame);
        page.js = Some(runtime);
        let diagnostics = page.frame_resource_diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].diagnostic_error.is_some());
        assert_eq!(diagnostics[0].unsupported_module_scripts, 0);
        assert_eq!(
            page.resource_archive_incomplete_reasons(),
            vec![
                "frame resource diagnostic failed for frame 7 (https://frame.example/)".to_string()
            ],
        );
        assert_eq!(
            page.resource_archive_incomplete_reasons().len(),
            1,
            "repeated diagnostic passes must be de-duplicated",
        );

        page.navigate_blank();
        assert!(page.resource_archive_incomplete_reasons().is_empty());
    }

    #[test]
    fn invalid_live_frame_probe_fails_lifecycle_without_discarding_frames() {
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(parse_html("<html><body>parent</body></html>"));
        runtime.set_url("https://parent.example/");
        runtime.run_page_init();
        let frame = obscura_js::frame::FrameRealm::new(
            &mut runtime,
            7,
            0,
            "https://parent.example/frame",
            "<html><body></body></html>",
        )
        .unwrap();

        let mut page = frame_page("invalid-live-frame-probe");
        page.frames.push(frame);
        page.js = Some(runtime);
        page.top_load_pending = true;
        page.lifecycle = crate::LifecycleState::DomContentLoaded;

        assert!(!page.release_detached_frames_with_probe(
            "(JSON.stringify = () => '[]', globalThis.__obscura_frameId === 0 ? [7] : [])"
        ));
        assert_eq!(page.lifecycle, crate::LifecycleState::DomContentLoaded);
        assert!(page.top_load_pending);
        assert_eq!(
            page.frames.len(),
            1,
            "author JSON.stringify must not forge the top-realm live-id list"
        );

        assert!(!page.release_detached_frames_with_probe("({ forged: true })"));
        assert_eq!(page.lifecycle, crate::LifecycleState::Failed);
        assert!(!page.top_load_pending);
        assert_eq!(
            page.frames.len(),
            1,
            "a malformed liveness probe must not irreversibly discard a frame"
        );
    }

    #[test]
    fn pending_frame_messages_block_archive_readiness_and_queue_loss_resets_on_navigation() {
        std::env::set_var("OBSCURA_FRAME_MESSAGE_QUEUE_ENTRIES", "1");
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(parse_html("<html><body>parent</body></html>"));
        runtime.set_url("https://parent.example/");
        runtime.run_page_init();
        let frame = obscura_js::frame::FrameRealm::new(
            &mut runtime,
            7,
            0,
            "https://frame.example/",
            "<html><body></body></html>",
        )
        .unwrap();
        frame
            .execute_script(
                &mut runtime,
                "parent.postMessage('first', '*'); parent.postMessage('dropped', '*');",
            )
            .unwrap();

        let mut page = frame_page("frame-message-archive-readiness");
        page.frames.push(frame);
        page.js = Some(runtime);
        assert!(
            page.has_pending_resource_work(),
            "a queued receiver can still start resource requests",
        );
        let reasons = page.resource_archive_incomplete_reasons();
        assert!(reasons
            .iter()
            .any(|reason| reason == "frame postMessage queue entry cap reached (1 message(s))"));
        assert!(reasons.iter().any(|reason| {
            reason.starts_with("pending frame postMessage deliveries: 1 message(s), ")
        }));

        assert!(page.deliver_frame_messages());
        assert!(!page.has_pending_resource_work());
        assert!(page
            .resource_archive_incomplete_reasons()
            .iter()
            .any(|reason| reason == "frame postMessage queue entry cap reached (1 message(s))"));

        page.navigate_blank();
        assert!(page.resource_archive_incomplete_reasons().is_empty());
        std::env::remove_var("OBSCURA_FRAME_MESSAGE_QUEUE_ENTRIES");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_srcdoc_frame_is_pending_resource_work_until_attachment_completes() {
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(parse_html("<html><body></body></html>"));
        runtime.set_url("https://parent.example/");
        runtime.run_page_init();
        runtime
            .evaluate(
                r#"(() => {
                  const frame = document.createElement('iframe');
                  frame.srcdoc = '<!doctype html><script>globalThis.__childRan = true;<\/script>';
                  document.body.appendChild(frame);
                  return frame._frameId;
                })()"#,
            )
            .unwrap();

        let mut page = frame_page("pending-srcdoc-resource-work");
        page.js = Some(runtime);
        assert!(
            page.has_pending_resource_work(),
            "a queued frame can still execute scripts and request resources",
        );
        for _ in 0..4 {
            if !page.advance_frames().await {
                break;
            }
        }
        assert_eq!(page.frame_urls(), vec!["about:srcdoc"]);
        assert!(!page.has_pending_resource_work());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blank_navigation_advances_generation_once_and_resets_capture_state() {
        let mut page = frame_page("blank-navigation-generation");
        page.enable_resource_capture(super::ResourceCaptureLimits::default());
        page.mark_resource_archive_incomplete("old document diagnostic");
        {
            let mut state = page.resource_capture.as_ref().unwrap().lock().unwrap();
            state.capture.omitted_resources = 1;
            state.capture.omitted_bytes = 42;
        }

        let initial_generation = page.callbacks.document_generation();
        page.navigate_blank();
        let direct_generation = page.callbacks.document_generation();
        assert_eq!(direct_generation, initial_generation + 1);
        assert!(page.resource_archive_incomplete_reasons().is_empty());
        {
            let state = page.resource_capture.as_ref().unwrap().lock().unwrap();
            assert_eq!(state.capture.document_generation, direct_generation);
            assert_eq!(state.capture.omitted_resources, 0);
            assert_eq!(state.capture.omitted_bytes, 0);
        }

        page.navigate("about:blank").await.unwrap();
        let routed_generation = page.callbacks.document_generation();
        assert_eq!(
            routed_generation,
            direct_generation + 1,
            "navigate(about:blank) must not advance once in navigate_single and again in navigate_blank",
        );
        let capture = page.take_resource_capture().unwrap();
        assert_eq!(capture.document_generation, routed_generation);
        assert!(capture.resources.is_empty());
    }

    /// An iframe inside a shadow root is absent from
    /// `document.querySelectorAll('iframe')` — real Chrome reports 0 for it too
    /// — so a liveness check built on that query reads a live frame as detached
    /// and tears it down. That is the shape a challenge widget uses, so the
    /// frame it depends on would be discarded moments after it loaded.
    #[tokio::test(flavor = "current_thread")]
    async fn a_frame_inside_a_shadow_root_survives_the_detach_sweep() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let base = spawn_shadow_frame_server().await;
        let mut page = frame_page("shadow-frame-survives");
        page.navigate(&base).await.unwrap();
        page.settle(1_000).await;

        assert_eq!(
            page.frames.len(),
            1,
            "the shadow-root frame was discarded as detached: {:?}",
            page.frame_urls()
        );
        // The realm is not merely alive; the page can still reach into it.
        let published = page
            .js
            .as_mut()
            .unwrap()
            .evaluate("Object.keys(globalThis.__obscura_frameObjects).length")
            .unwrap();
        assert_eq!(
            published.as_f64(),
            Some(1.0),
            "the page cannot reach the frame"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn frame_preload_runs_before_parser_stylesheet_owner_error() {
        const TOP_HTML: &str = r#"<!doctype html><html><body><script>
            const frame = document.createElement('iframe');
            frame.srcdoc = '<!doctype html><link rel="stylesheet" href="file:///obscura-frame-blocked.css" onerror="globalThis.__preloadAtStyleError = globalThis.__preloaded === true; globalThis.__styleErrorReadyState = document.readyState">';
            document.body.appendChild(frame);
        </script></body></html>"#;

        let encoded = base64::engine::general_purpose::STANDARD.encode(TOP_HTML);
        let url = format!("data:text/html;base64,{encoded}");
        let mut page = frame_page("frame-preload-before-style-error");
        page.set_preload_scripts(vec!["globalThis.__preloaded = true;".to_string()]);
        page.navigate_with_wait(&url, crate::WaitUntil::Load)
            .await
            .expect("frame navigation");

        assert_eq!(page.frame_urls(), vec!["about:srcdoc".to_string()]);
        assert_eq!(
            page.evaluate_in_frame(0, "globalThis.__preloadAtStyleError")
                .unwrap(),
            serde_json::json!(true),
        );
        assert_eq!(
            page.evaluate_in_frame(0, "globalThis.__styleErrorReadyState")
                .unwrap(),
            serde_json::json!("loading"),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn new_document_preload_dynamic_inline_script_executes_exactly_once() {
        const HTML: &str = "<!doctype html><html><head></head><body></body></html>";
        let encoded = base64::engine::general_purpose::STANDARD.encode(HTML);
        let mut page = frame_page("preload-dynamic-inline-exactly-once");
        page.set_preload_scripts(vec![r#"
            globalThis.__preloadDynamicInlineRuns = 0;
            const script = document.createElement('script');
            script.textContent = 'globalThis.__preloadDynamicInlineRuns += 1;';
            document.head.appendChild(script);
        "#
        .to_string()]);

        page.navigate_with_wait(
            &format!("data:text/html;base64,{encoded}"),
            crate::WaitUntil::Load,
        )
        .await
        .expect("preload dynamic script navigation");

        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__preloadDynamicInlineRuns")
                .unwrap(),
            serde_json::json!(1.0),
            "a preload-created script is dynamic work, not a parser script to run again",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn new_document_preload_dynamic_stylesheet_fetches_and_loads_exactly_once() {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stylesheet_requests = std::sync::Arc::new(AtomicUsize::new(0));
        let observed_requests = stylesheet_requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let observed_requests = observed_requests.clone();
                std::thread::spawn(move || {
                    let mut request = [0u8; 2048];
                    let length = stream.read(&mut request).unwrap_or(0);
                    let request = String::from_utf8_lossy(&request[..length]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_ascii_whitespace().nth(1))
                        .unwrap_or("/");
                    let (content_type, body) = if path == "/preload.css" {
                        observed_requests.fetch_add(1, Ordering::SeqCst);
                        ("text/css", "html { --preload-style: loaded; }")
                    } else {
                        (
                            "text/html",
                            "<!doctype html><html><head></head><body></body></html>",
                        )
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                    );
                    let _ = stream.write_all(response.as_bytes());
                });
            }
        });

        let mut page = frame_page("preload-dynamic-stylesheet-exactly-once");
        page.set_preload_scripts(vec![r#"
            globalThis.__preloadStyleLoads = 0;
            const link = document.createElement('link');
            link.setAttribute('rel', 'stylesheet');
            link.setAttribute('href', '/preload.css');
            link.addEventListener('load', () => globalThis.__preloadStyleLoads += 1);
            document.head.appendChild(link);
        "#
        .to_string()]);

        // This regression isolates parser-resource enrollment. Render builds
        // also run a separate pre-script archive warmup which intentionally
        // scans the live DOM; that transport/JS-loader race is independent of
        // whether preload-created links leak into the frozen parser snapshot.
        #[cfg(feature = "render")]
        let previous_warmup = [
            (
                "OBSCURA_RENDER_RESOURCE_WARMUP_MS",
                std::env::var_os("OBSCURA_RENDER_RESOURCE_WARMUP_MS"),
            ),
            (
                "OBSCURA_RENDER_RESOURCE_POST_SCRIPT_WARMUP_MS",
                std::env::var_os("OBSCURA_RENDER_RESOURCE_POST_SCRIPT_WARMUP_MS"),
            ),
        ];
        #[cfg(feature = "render")]
        for (name, _) in &previous_warmup {
            std::env::set_var(name, "0");
        }
        let page_url = format!("http://{address}/index.html");
        let navigation = page.navigate_with_wait(&page_url, crate::WaitUntil::Load);
        let navigation = navigation.await;
        #[cfg(feature = "render")]
        for (name, value) in previous_warmup {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        navigation.expect("preload dynamic stylesheet navigation");

        assert_eq!(
            stylesheet_requests.load(Ordering::SeqCst),
            1,
            "a preload-created link is dynamic work, not a parser stylesheet to fetch again",
        );
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__preloadStyleLoads")
                .unwrap(),
            serde_json::json!(1.0),
            "the dynamic stylesheet owner must receive one completion",
        );
    }

    /// An explicit CLI `--wait` uses `settle_for_duration`. The fixed wait
    /// previously attached a dynamically loaded frame only after the entire
    /// delay, which left the child timer, fetch and every postMessage reply for
    /// a later settle that the caller never requested.
    #[tokio::test(flavor = "current_thread")]
    async fn fixed_settle_interleaves_deferred_child_frame_work() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let base = spawn_shadow_frame_server().await;
        let mut page = frame_page("fixed-settle-frame-work");
        page.navigate(&format!("{base}fixed-wait.html"))
            .await
            .unwrap();

        page.settle_for_duration(1_000).await;

        assert_eq!(
            page.frame_urls(),
            vec![format!("{base}async-child.html")],
            "the delayed iframe was not attached during the fixed wait",
        );
        assert_eq!(
            page.evaluate_in_frame(0, "window.__deferredFrameWork")
                .unwrap(),
            serde_json::json!("FRAME-READY"),
            "the child realm's deferred work was stranded after attachment",
        );
        assert!(
            page.fetched_urls()
                .contains(&format!("{base}frame-resource.txt")),
            "a fetch made by the child realm was absent from page assets",
        );
    }

    #[test]
    fn autonomous_pump_bounds_a_timer_created_frame_dcl_handler() {
        const TOP_HTML: &str = r#"<!doctype html><html><body><script>
            setTimeout(function () {
                const frame = document.createElement('iframe');
                frame.srcdoc = "<script>document.addEventListener('DOMContentLoaded', function () { while (true) {} });<\/script>";
                document.body.appendChild(frame);
            }, 0);
        </script></body></html>"#;

        #[derive(Debug)]
        struct Outcome {
            before_page: crate::LifecycleState,
            before_top_load_pending: bool,
            before_frames: usize,
            turn: Result<bool, String>,
            after_page: crate::LifecycleState,
            after_top_load_pending: bool,
            after_frames: Vec<obscura_js::frame::FrameLifecycleState>,
            elapsed: std::time::Duration,
        }

        // A missing V8 watchdog pins the executor inside the frame callback,
        // so keep that work on a disposable OS thread. The receiving test still
        // fails in bounded time instead of hanging the test runner forever.
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("autonomous-frame-watchdog".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test runtime");
                let outcome = runtime.block_on(async {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(TOP_HTML);
                    let url = format!("data:text/html;base64,{encoded}");
                    let mut page = frame_page("autonomous-frame-watchdog");
                    page.navigate_with_wait(&url, crate::WaitUntil::DomContentLoaded)
                        .await
                        .expect("DOMContentLoaded navigation");

                    let before_page = page.lifecycle;
                    let before_top_load_pending = page.top_load_pending;
                    let before_frames = page.frames.len();
                    let started = std::time::Instant::now();
                    let turn = page.run_autonomous_event_loop_turn().await;
                    Outcome {
                        before_page,
                        before_top_load_pending,
                        before_frames,
                        turn,
                        after_page: page.lifecycle,
                        after_top_load_pending: page.top_load_pending,
                        after_frames: page
                            .frames
                            .iter()
                            .map(|frame| frame.lifecycle_state())
                            .collect(),
                        elapsed: started.elapsed(),
                    }
                });
                let _ = tx.send(outcome);
            })
            .expect("spawn watchdog test worker");

        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("autonomous pump did not return within the watchdog ceiling");
        worker.join().expect("watchdog test worker panicked");

        assert_eq!(outcome.before_page, crate::LifecycleState::DomContentLoaded);
        assert!(outcome.before_top_load_pending);
        assert_eq!(
            outcome.before_frames, 0,
            "the timer ran before DCL returned"
        );
        assert_eq!(
            outcome.turn,
            Ok(false),
            "attaching the frame is browser work"
        );
        assert_eq!(outcome.after_page, crate::LifecycleState::Failed);
        assert!(!outcome.after_top_load_pending);
        assert_eq!(
            outcome.after_frames,
            vec![obscura_js::frame::FrameLifecycleState::Failed],
        );
        assert!(
            outcome.elapsed < std::time::Duration::from_secs(10),
            "scoped lifecycle watchdog returned too late: {:?}",
            outcome.elapsed,
        );
    }

    #[test]
    fn autonomous_pump_marks_a_nonreturning_dynamic_script_load_handler_failed() {
        const TOP_HTML: &str = r#"<!doctype html><html><head><script>
            document.addEventListener('DOMContentLoaded', function () {
                const script = document.createElement('script');
                script.src = 'data:text/javascript,globalThis.__dynamicRan%3Dtrue';
                script.onload = function () { while (true) {} };
                document.head.appendChild(script);
            });
        </script></head><body></body></html>"#;

        #[derive(Debug)]
        struct Outcome {
            before_page: crate::LifecycleState,
            before_top_load_pending: bool,
            turn: Result<bool, String>,
            after_page: crate::LifecycleState,
            after_top_load_pending: bool,
            elapsed: std::time::Duration,
        }

        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("autonomous-resource-watchdog".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test runtime");
                let outcome = runtime.block_on(async {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(TOP_HTML);
                    let url = format!("data:text/html;base64,{encoded}");
                    let mut page = frame_page("autonomous-resource-watchdog");
                    page.navigate_with_wait(&url, crate::WaitUntil::DomContentLoaded)
                        .await
                        .expect("DOMContentLoaded navigation");

                    let before_page = page.lifecycle;
                    let before_top_load_pending = page.top_load_pending;
                    let started = std::time::Instant::now();
                    let turn = page.run_autonomous_event_loop_turn().await;
                    Outcome {
                        before_page,
                        before_top_load_pending,
                        turn,
                        after_page: page.lifecycle,
                        after_top_load_pending: page.top_load_pending,
                        elapsed: started.elapsed(),
                    }
                });
                let _ = tx.send(outcome);
            })
            .expect("spawn dynamic resource watchdog test worker");

        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("autonomous resource callback did not respect the watchdog ceiling");
        worker.join().expect("watchdog test worker panicked");

        assert_eq!(outcome.before_page, crate::LifecycleState::DomContentLoaded);
        assert!(outcome.before_top_load_pending);
        assert!(
            outcome.turn.is_err(),
            "watchdog failure was hidden: {outcome:?}"
        );
        assert_eq!(outcome.after_page, crate::LifecycleState::Failed);
        assert!(!outcome.after_top_load_pending);
        assert!(
            outcome.elapsed < std::time::Duration::from_secs(10),
            "resource callback watchdog returned too late: {:?}",
            outcome.elapsed,
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parsed_body_onload_precedes_listeners_registered_by_body_resource_callbacks() {
        const HTML: &str = r#"<!doctype html><html><head>
            <script>globalThis.__bodyResourceLoadOrder = [];</script>
        </head><body onload="globalThis.__bodyResourceLoadOrder.push('body-handler')">
            <link rel="stylesheet" href="file:///blocked-body-sheet.css"
                  onerror="window.addEventListener('load', () => globalThis.__bodyResourceLoadOrder.push('resource-listener'))">
        </body></html>"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(HTML);
        let mut page = frame_page("body-handler-parser-encounter-order");
        page.navigate_with_wait(
            &format!("data:text/html;base64,{encoded}"),
            crate::WaitUntil::Load,
        )
        .await
        .expect("body/resource lifecycle navigation");

        assert_eq!(
            page.evaluate("globalThis.__bodyResourceLoadOrder"),
            serde_json::json!(["body-handler", "resource-listener"]),
        );
    }

    #[test]
    fn parser_stylesheet_owner_handler_is_bounded_before_the_script_phase() {
        const TOP_HTML: &str = r#"<!doctype html><html><head>
            <link rel="stylesheet" href="file:///obscura-blocked.css"
                  onerror="while (true) {}">
        </head><body></body></html>"#;

        #[derive(Debug)]
        struct Outcome {
            navigation: Result<(), String>,
            lifecycle: crate::LifecycleState,
            top_load_pending: bool,
            elapsed: std::time::Duration,
        }

        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("parser-stylesheet-watchdog".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test runtime");
                let outcome = runtime.block_on(async {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(TOP_HTML);
                    let url = format!("data:text/html;base64,{encoded}");
                    let mut page = frame_page("parser-stylesheet-watchdog");
                    let started = std::time::Instant::now();
                    let navigation = page
                        .navigate_with_wait(&url, crate::WaitUntil::Load)
                        .await
                        .map_err(|error| error.to_string());
                    Outcome {
                        navigation,
                        lifecycle: page.lifecycle,
                        top_load_pending: page.top_load_pending,
                        elapsed: started.elapsed(),
                    }
                });
                let _ = tx.send(outcome);
            })
            .expect("spawn stylesheet watchdog test worker");

        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("stylesheet owner callback did not respect the watchdog ceiling");
        worker.join().expect("stylesheet watchdog worker panicked");

        assert!(
            outcome.navigation.is_err(),
            "navigation unexpectedly succeeded: {outcome:?}"
        );
        assert_eq!(outcome.lifecycle, crate::LifecycleState::Failed);
        assert!(!outcome.top_load_pending);
        assert!(
            outcome.elapsed < std::time::Duration::from_secs(10),
            "stylesheet watchdog returned too late: {:?}",
            outcome.elapsed,
        );
    }

    #[test]
    fn cdp_evaluate_and_call_function_share_one_absolute_watchdog_deadline() {
        #[derive(Debug)]
        struct Outcome {
            sync_evaluate: Result<obscura_js::runtime::RemoteObjectInfo, String>,
            sync_call: Result<obscura_js::runtime::RemoteObjectInfo, String>,
            distant_timer: Result<obscura_js::runtime::RemoteObjectInfo, String>,
            leaked_sentinels: serde_json::Value,
            isolate_reusable: serde_json::Value,
            elapsed: std::time::Duration,
        }

        // A regression in the initial synchronous entry would pin the current
        // test thread inside V8 forever. Keep the isolate on a disposable worker
        // so the receiver still reports the missing watchdog in bounded time.
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("cdp-absolute-deadline-watchdog".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test runtime");
                let outcome = runtime.block_on(async {
                    let mut page = frame_page("cdp-absolute-deadline-watchdog");
                    page.url = Some(url::Url::parse("https://deadline.example/").unwrap());
                    page.dom = Some(parse_html("<html><body></body></html>"));
                    page.init_js();

                    let started = std::time::Instant::now();
                    let sync_evaluate = page
                        .evaluate_for_cdp_with_timeout(
                            "(() => { while (true) {} })()",
                            true,
                            true,
                            40,
                        )
                        .await;
                    let sync_call = page
                        .call_function_on_for_cdp_with_timeout(
                            "function () { while (true) {} }",
                            None,
                            &[],
                            true,
                            true,
                            40,
                        )
                        .await;
                    let distant_timer = page
                        .evaluate_for_cdp_with_timeout(
                            "new Promise(resolve => setTimeout(resolve, 60000))",
                            true,
                            true,
                            40,
                        )
                        .await;
                    let elapsed = started.elapsed();
                    let leaked_sentinels = page.evaluate(
                        "Object.getOwnPropertyNames(globalThis).filter(\
                         name => name.startsWith('__obscura_page_await_')).length",
                    );
                    let isolate_reusable = page.evaluate(
                        "(document.body.setAttribute('data-after-cdp-timeout', 'usable'), \
                         document.body.getAttribute('data-after-cdp-timeout'))",
                    );
                    Outcome {
                        sync_evaluate,
                        sync_call,
                        distant_timer,
                        leaked_sentinels,
                        isolate_reusable,
                        elapsed,
                    }
                });
                let _ = tx.send(outcome);
            })
            .expect("spawn CDP watchdog test worker");

        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("a CDP deadline failed to bound synchronous V8 or a distant timer");
        worker.join().expect("CDP watchdog worker panicked");

        assert!(outcome.sync_evaluate.is_err(), "{outcome:?}");
        assert!(outcome.sync_call.is_err(), "{outcome:?}");
        assert!(outcome.distant_timer.is_err(), "{outcome:?}");
        assert_eq!(outcome.leaked_sentinels.as_f64(), Some(0.0), "{outcome:?}");
        assert_eq!(
            outcome.isolate_reusable,
            serde_json::json!("usable"),
            "{outcome:?}"
        );
        assert!(
            outcome.elapsed < std::time::Duration::from_secs(2),
            "the three 40ms commands escaped their shared deadlines: {outcome:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn child_frame_dynamic_script_executes_and_keeps_frame_request_context() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let base = spawn_shadow_frame_server().await;
        let mut page = frame_page("child-frame-dynamic-script");
        page.enable_resource_capture(super::ResourceCaptureLimits::default());

        page.navigate(&format!("{base}dynamic-frame-parent.html"))
            .await
            .unwrap();
        page.settle_for_duration(1_000).await;

        assert_eq!(
            page.evaluate_in_frame(
                0,
                "[window.__dynamicFrameLoads, window.__dynamicFrameOnload]",
            )
            .unwrap(),
            serde_json::json!([1, true]),
            "the dynamically inserted child-frame script did not fetch, execute, and fire load",
        );
        assert!(!page.has_pending_resource_work());

        let snapshot = page.frame_snapshots().into_iter().next().unwrap();
        let script_url = format!("{base}frame-dynamic.js");
        let capture = page.take_resource_capture().unwrap();
        let resource = capture
            .resources
            .iter()
            .find(|resource| resource.final_url.as_str() == script_url)
            .expect("dynamic child-frame script response was not captured");
        assert_eq!(resource.frame_id, snapshot.frame_id);
        assert_eq!(
            resource.initiator.as_ref().map(url::Url::as_str),
            Some(snapshot.url.as_str()),
        );
        assert_eq!(resource.body, b"window.__dynamicFrameLoads += 1;");
    }

    /// The sweep still does its job: an iframe removed from the document has
    /// its realm and every reference the page realm holds to it released.
    #[tokio::test(flavor = "current_thread")]
    async fn removing_an_iframe_releases_its_realm() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let base = spawn_shadow_frame_server().await;
        let mut page = frame_page("detached-frame-released");
        page.navigate(&format!("{base}plain.html")).await.unwrap();
        page.settle(1_000).await;
        assert_eq!(page.frames.len(), 1, "no frame to remove");

        page.js
            .as_mut()
            .unwrap()
            .evaluate("(document.querySelector('iframe').remove(), 1)")
            .unwrap();
        page.release_detached_frames();

        assert!(page.frames.is_empty(), "the detached realm was kept");
        let left = page
            .js
            .as_mut()
            .unwrap()
            .evaluate(
                "Object.keys(globalThis.__obscura_frameObjects).length\
                 + Object.keys(globalThis.__obscura_frameWindows).length\
                 + Object.keys(globalThis.__obscura_frameElements).length",
            )
            .unwrap();
        assert_eq!(
            left.as_f64(),
            Some(0.0),
            "a reference to the discarded frame survived, so its context cannot be collected"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn final_resource_capture_excludes_detached_frame_responses() {
        std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
        let base = spawn_shadow_frame_server().await;
        let mut page = frame_page("detached-frame-capture-filter");
        page.enable_resource_capture(super::ResourceCaptureLimits::default());
        page.navigate(&format!("{base}dynamic-frame-parent.html"))
            .await
            .unwrap();
        page.settle(1_000).await;

        let frame_id = page.frame_snapshots()[0].frame_id;
        let bytes_before_detach = {
            let state = page.resource_capture.as_ref().unwrap().lock().unwrap();
            assert!(
                state
                    .capture
                    .resources
                    .iter()
                    .any(|resource| resource.frame_id == frame_id),
                "the frame produced no captured response, so filtering it proves nothing",
            );
            state.capture.total_bytes
        };

        page.js
            .as_mut()
            .unwrap()
            .evaluate("(document.querySelector('iframe').remove(), 1)")
            .unwrap();
        let capture = page.take_resource_capture().unwrap();

        assert!(
            page.frames.is_empty(),
            "the archive boundary kept a detached realm"
        );
        assert!(
            capture
                .resources
                .iter()
                .all(|resource| resource.frame_id == 0),
            "a detached frame response leaked into the final archive: {:?}",
            capture
                .resources
                .iter()
                .map(|resource| (resource.frame_id, resource.final_url.as_str()))
                .collect::<Vec<_>>(),
        );
        assert!(capture
            .resources
            .iter()
            .all(|resource| resource.document_generation == capture.document_generation),);
        assert_eq!(
            capture.total_bytes,
            capture
                .resources
                .iter()
                .map(|resource| resource.body.len())
                .sum::<usize>(),
        );
        assert!(capture.total_bytes < bytes_before_detach);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn suspend_resume_preserves_document_script_start_state() {
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "script-state-suspend".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("script-state-suspend".to_string(), context);
        page.url = Some(url::Url::parse("http://example.com/suspend.html").unwrap());
        page.dom = Some(parse_html(
            r#"<html><head></head><body data-parser-runs="0" data-dynamic-runs="0" data-inert-runs="0">
            <script id="parser">
              document.body.setAttribute("data-parser-runs", String(Number(document.body.getAttribute("data-parser-runs")) + 1));
            </script>
            </body></html>"#,
        ));
        page.init_js();
        page.execute_scripts().await;

        let before = page
            .js
            .as_mut()
            .unwrap()
            .evaluate(
                r#"
                var scriptStateSetup = true;
                const dynamic = document.createElement("script");
                dynamic.id = "dynamic";
                dynamic.textContent =
                  'document.body.setAttribute("data-dynamic-runs", String(Number(document.body.getAttribute("data-dynamic-runs")) + 1))';
                document.body.appendChild(dynamic);

                const holder = document.createElement("div");
                holder.innerHTML =
                  '<script id="inert">document.body.setAttribute("data-inert-runs", String(Number(document.body.getAttribute("data-inert-runs")) + 1))<\/script>';
                document.body.appendChild(holder.firstChild);
                return [
                  document.body.getAttribute("data-parser-runs"),
                  document.body.getAttribute("data-dynamic-runs"),
                  document.body.getAttribute("data-inert-runs")
                ];
                "#,
            )
            .unwrap();
        assert_eq!(before, serde_json::json!(["1", "1", "0"]));

        page.suspend_js();
        page.suspend_js();
        page.resume_js();

        let after = page
            .js
            .as_mut()
            .unwrap()
            .evaluate(
                r#"
                var scriptStateCheck = true;
                for (const id of ["parser", "dynamic", "inert"]) {
                  const script = document.getElementById(id);
                  document.head.appendChild(script);
                  document.body.appendChild(script.cloneNode(true));
                }
                return [
                  document.body.getAttribute("data-parser-runs"),
                  document.body.getAttribute("data-dynamic-runs"),
                  document.body.getAttribute("data-inert-runs")
                ];
                "#,
            )
            .unwrap();
        assert_eq!(after, serde_json::json!(["1", "1", "0"]));
    }

    #[test]
    fn new_document_does_not_inherit_suspended_script_ids() {
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "script-state-navigation".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("script-state-navigation".to_string(), context);
        page.url = Some(url::Url::parse("http://example.com/old.html").unwrap());
        page.dom = Some(parse_html(
            "<html><head></head><body><script id=old></script></body></html>",
        ));
        page.init_js();
        page.js
            .as_mut()
            .unwrap()
            .evaluate(
                "var setup = true; const old = document.getElementById('old'); globalThis.__markParserScripts([old._nid]); return old._nid;",
            )
            .unwrap();
        page.suspend_js();

        page.url = Some(url::Url::parse("http://example.com/new.html").unwrap());
        page.dom = Some(parse_html(
            "<html><head></head><body data-fresh-runs=0><script id=fresh>document.body.setAttribute('data-fresh-runs', '1')</script></body></html>",
        ));
        page.init_js();
        let result = page
            .js
            .as_mut()
            .unwrap()
            .evaluate(
                "var check = true; document.head.appendChild(document.getElementById('fresh')); return document.body.getAttribute('data-fresh-runs');",
            )
            .unwrap();
        assert_eq!(result, serde_json::json!("1"));
    }

    fn import_map_test_page(name: &str, base: &str, html: &str) -> super::Page {
        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            name.to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new(name.to_string(), context);
        page.url = Some(url::Url::parse(&format!("{}/app/index.html", base)).unwrap());
        page.dom = Some(parse_html(html));
        page.init_js();
        page
    }

    fn spawn_single_module_response(
        status: &'static str,
        body: &'static [u8],
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let length = stream.read(&mut request).unwrap();
            let path = String::from_utf8_lossy(&request[..length])
                .lines()
                .next()
                .and_then(|line| line.split_ascii_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            request_tx.send(path).unwrap();
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len(),
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });
        (format!("http://{address}"), request_rx)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn successful_external_module_response_is_captured_byte_exactly() {
        const MODULE: &[u8] = b"globalThis.__externalModuleCaptured = true;\n";
        let (base, requests) = spawn_single_module_response("200 OK", MODULE);
        let mut page = import_map_test_page(
            "external-module-capture",
            &base,
            r#"<html><head><script type="module" src="./entry.js"></script></head><body></body></html>"#,
        );
        page.enable_resource_capture(super::ResourceCaptureLimits::default());

        page.execute_scripts_with_module_budget(Some(1_000)).await;

        assert_eq!(
            requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/app/entry.js",
        );
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__externalModuleCaptured === true")
                .unwrap(),
            serde_json::json!(true),
        );
        assert!(page.resource_archive_incomplete_reasons().is_empty());
        let capture = page.take_resource_capture().unwrap();
        let resource = capture
            .resources
            .iter()
            .find(|resource| resource.final_url.as_str() == format!("{base}/app/entry.js"))
            .expect("external module response was not captured");
        assert_eq!(resource.resource_type, obscura_net::ResourceType::Script);
        assert_eq!(resource.frame_id, 0);
        assert_eq!(resource.body, MODULE);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_external_module_preparation_marks_the_archive_incomplete() {
        let (base, requests) = spawn_single_module_response("404 Not Found", b"not found");
        let mut page = import_map_test_page(
            "failed-external-module",
            &base,
            r#"<html><head><script type="module" src="./missing.js"></script></head><body></body></html>"#,
        );

        page.execute_scripts_with_module_budget(Some(1_000)).await;

        assert_eq!(
            requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/app/missing.js",
        );
        assert_eq!(
            page.resource_archive_incomplete_reasons(),
            vec![format!(
                "top-level module graph preparation failed: {base}/app/missing.js"
            )],
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn module_graph_and_evaluation_share_one_active_budget() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let length = stream.read(&mut request).unwrap();
            let path = String::from_utf8_lossy(&request[..length])
                .lines()
                .next()
                .and_then(|line| line.split_ascii_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            request_tx.send(path).unwrap();

            // Spend part of the module's allowance loading its graph. The
            // synchronous top-level work then fits in a freshly reset budget,
            // but cannot fit in the shared active load+evaluation budget.
            std::thread::sleep(std::time::Duration::from_millis(100));
            let body = "export const delayed = true;";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let base = format!("http://{address}");
        let mut page = import_map_test_page(
            "shared-module-budget",
            &base,
            r#"<html><head><script type="module">
                import "./delayed.js";
                globalThis.__shared_deadline_started = true;
                const until = Date.now() + 300;
                while (Date.now() < until) {}
                globalThis.__shared_deadline_completed = true;
            </script></head><body></body></html>"#,
        );
        page.execute_scripts_with_module_budget(Some(350)).await;

        assert_eq!(
            request_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/app/delayed.js",
        );
        let state = page
            .js
            .as_mut()
            .unwrap()
            .evaluate(
                "[globalThis.__shared_deadline_started === true, \
                  globalThis.__shared_deadline_completed === true]",
            )
            .unwrap();
        assert_eq!(
            state,
            serde_json::json!([true, false]),
            "evaluation must be terminated at the remaining shared deadline",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_module_does_not_spend_its_budget_waiting_for_deferred_script() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let length = stream.read(&mut request).unwrap();
                let path = String::from_utf8_lossy(&request[..length])
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let body = if path.ends_with("deferred.js") {
                    "const until=Date.now()+500;while(Date.now()<until){}"
                } else {
                    "export const ready=true;"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        let base = format!("http://{address}");
        let mut page = import_map_test_page(
            "module-queue-budget",
            &base,
            r#"<html><head>
                <script defer src="./deferred.js"></script>
                <script type="module">
                    import { ready } from "./quick.js";
                    globalThis.__queued_module_completed = ready;
                </script>
            </head><body></body></html>"#,
        );
        page.execute_scripts_with_module_budget(Some(300)).await;

        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__queued_module_completed === true")
                .unwrap(),
            serde_json::json!(true),
            "queue latency must not consume a module's active-work budget",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parser_import_map_before_first_module_controls_resolution() {
        let (base, requests) = spawn_parser_import_map_server(1);
        let mut page = import_map_test_page(
            "import-map-order",
            &base,
            r#"<html><head>
            <script type="importmap">{"imports":{"ordered":"./before.js"}}</script>
            <script type="module">
                import { value } from "ordered";
                globalThis.__parser_import_map_value = value;
            </script>
            <script type="importmap">{"imports":{"ordered":"./after.js"}}</script>
        </head><body></body></html>"#,
        );
        page.execute_scripts().await;

        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__parser_import_map_value")
                .unwrap(),
            serde_json::json!("before-first-module"),
        );
        assert_eq!(
            requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/app/before.js"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn later_import_map_adds_unrelated_rule_without_rebinding_resolved_rule() {
        let (base, requests) = spawn_parser_import_map_server(2);
        let mut page = import_map_test_page(
            "multiple-import-map-order",
            &base,
            r#"<html><head>
            <script type="importmap">{"imports":{"fixed":"./before.js"}}</script>
            <script type="module">
                import { value } from "fixed";
                globalThis.__first_map_value = value;
            </script>
            <script type="importmap">{"imports":{"fixed":"./after.js","later":"./later.js"}}</script>
            <script type="module">
                import { value as fixed } from "fixed";
                import { value as later } from "later";
                globalThis.__later_map_values = [fixed, later];
            </script>
        </head><body></body></html>"#,
        );
        page.execute_scripts().await;

        let js = page.js.as_mut().unwrap();
        assert_eq!(
            js.evaluate("globalThis.__first_map_value").unwrap(),
            serde_json::json!("before-first-module")
        );
        assert_eq!(
            js.evaluate("globalThis.__later_map_values").unwrap(),
            serde_json::json!(["before-first-module", "later-map"])
        );
        let paths = (0..2)
            .map(|_| {
                requests
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(paths.contains(&"/app/before.js".to_string()), "{paths:?}");
        assert!(paths.contains(&"/app/later.js".to_string()), "{paths:?}");
        assert!(!paths.contains(&"/app/after.js".to_string()), "{paths:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn classic_dynamic_import_does_not_see_a_later_parser_import_map() {
        let (base, _requests) = spawn_parser_import_map_server(1);
        let mut page = import_map_test_page(
            "classic-before-import-map",
            &base,
            r#"<html><head>
            <script>
                import("too-late")
                    .then(() => globalThis.__classic_before_map = "resolved")
                    .catch(() => globalThis.__classic_before_map = "rejected");
            </script>
            <script type="importmap">{"imports":{"too-late":"./later.js"}}</script>
        </head><body></body></html>"#,
        );
        page.execute_scripts().await;
        page.settle_for_duration(500).await;
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__classic_before_map")
                .unwrap(),
            serde_json::json!("rejected"),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ready_async_classic_script_runs_before_a_later_parser_import_map() {
        let (base, requests) = spawn_parser_import_map_server(2);
        let mut page = import_map_test_page(
            "async-classic-before-map",
            &base,
            r#"<html><head>
            <script async src="./async.js"></script>
            <script type="importmap">{"imports":{"too-late":"./later.js"}}</script>
        </head><body></body></html>"#,
        );
        page.execute_scripts().await;
        page.settle_for_duration(500).await;
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__async_before_map")
                .unwrap(),
            serde_json::json!("rejected"),
        );
        assert_eq!(
            requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/app/async.js"
        );
        assert!(requests.try_recv().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dynamically_inserted_import_map_controls_later_dynamic_import() {
        let (base, requests) = spawn_parser_import_map_server(1);
        let mut page = import_map_test_page(
            "dynamic-import-map",
            &base,
            r#"<html><head></head><body>
            <script>
                const map = document.createElement("script");
                map.type = "importmap";
                map.textContent = JSON.stringify({imports:{dynamicName:"./later.js"}});
                document.head.appendChild(map);
                import("dynamicName")
                    .then(module => globalThis.__dynamic_map_value = module.value)
                    .catch(error => globalThis.__dynamic_map_value = error.message);
            </script>
        </body></html>"#,
        );
        page.execute_scripts().await;
        page.settle_for_duration(500).await;
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__dynamic_map_value")
                .unwrap(),
            serde_json::json!("later-map"),
        );
        assert_eq!(
            requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/app/later.js"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn preload_dynamic_script_delays_load_but_not_dom_content_loaded() {
        let (base, requests) = spawn_delayed_classic_script_server(
            std::time::Duration::from_millis(150),
            "globalThis.__lifecycleOrder.push('dynamic-exec');",
        );
        let html = format!(
            r#"<html><head></head><body><script>
                globalThis.__lifecycleOrder = [];
                document.addEventListener('DOMContentLoaded', () =>
                    globalThis.__lifecycleOrder.push('dom-content-loaded'));
                window.onload = () =>
                    globalThis.__lifecycleOrder.push('window-onload');
                window.addEventListener('load', () =>
                    globalThis.__lifecycleOrder.push('window-load'));
                const script = document.createElement('script');
                script.src = '{base}/preload-dynamic.js';
                script.onload = () => globalThis.__lifecycleOrder.push('script-load');
                document.head.appendChild(script);
            </script></body></html>"#,
        );
        let mut page =
            import_map_test_page("preload-dynamic-lifecycle", "http://127.0.0.1:9", &html);

        page.execute_scripts().await;

        assert_eq!(
            requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/preload-dynamic.js",
        );
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__lifecycleOrder")
                .unwrap(),
            serde_json::json!([
                "dom-content-loaded",
                "dynamic-exec",
                "script-load",
                "window-onload",
                "window-load"
            ]),
            "dynamic async scripts gate load, not DOMContentLoaded",
        );
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate(
                    "globalThis.__lifecycleOrder.filter(value => value === 'window-onload').length",
                )
                .unwrap(),
            serde_json::json!(1.0),
            "window.onload must fire exactly once",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn load_delaying_script_progresses_through_continuously_ready_timer_work() {
        let (base, requests) = spawn_delayed_classic_script_server(
            std::time::Duration::from_millis(75),
            "globalThis.__fairDynamicRan = true;",
        );
        let html = format!(
            r#"<html><head></head><body><script>
                globalThis.__schedulerTicks = 0;
                setInterval(() => globalThis.__schedulerTicks++, 0);
                const script = document.createElement('script');
                script.src = '{base}/fair-dynamic.js';
                script.onload = () => globalThis.__fairDynamicLoaded = true;
                document.head.appendChild(script);
            </script></body></html>"#,
        );
        let mut page = import_map_test_page(
            "load-delayer-scheduler-fairness",
            "http://127.0.0.1:9",
            &html,
        );
        let started = std::time::Instant::now();

        page.execute_scripts().await;

        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(1500),
            "continuous ready work must not starve a load-delaying fetch; elapsed={elapsed:?}",
        );
        assert_eq!(
            requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/fair-dynamic.js",
        );
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate(
                    "[globalThis.__fairDynamicRan === true, \
                     globalThis.__fairDynamicLoaded === true, \
                     globalThis.__schedulerTicks > 0]",
                )
                .unwrap(),
            serde_json::json!([true, true, true]),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn load_delaying_script_driver_respects_absolute_deadline() {
        let (base, requests) = spawn_delayed_classic_script_server(
            std::time::Duration::from_secs(1),
            "globalThis.__lateDynamicRan = true;",
        );
        let mut page = import_map_test_page(
            "load-delayer-deadline",
            "http://127.0.0.1:9",
            "<html><head></head><body></body></html>",
        );
        page.js
            .as_mut()
            .unwrap()
            .execute_script(
                "install-load-delayer",
                &format!(
                    "globalThis.__documentReadyState__ = 'loading'; \
                     const script = document.createElement('script'); \
                     script.src = '{base}/slow-dynamic.js'; \
                     document.head.appendChild(script);",
                ),
            )
            .unwrap();
        assert!(page
            .js
            .as_mut()
            .unwrap()
            .has_pending_load_delaying_scripts());
        let started = std::time::Instant::now();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(125);

        let completed =
            super::Page::drive_load_delaying_scripts(page.js.as_mut().unwrap(), deadline).await;

        let elapsed = started.elapsed();
        assert!(!completed, "the delayed resource must exceed the deadline");
        assert!(
            elapsed >= std::time::Duration::from_millis(100)
                && elapsed < std::time::Duration::from_millis(500),
            "the driver must honor its absolute wall-clock bound; elapsed={elapsed:?}",
        );
        assert!(page
            .js
            .as_mut()
            .unwrap()
            .has_pending_load_delaying_scripts());
        assert_eq!(
            requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/slow-dynamic.js",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn post_load_dynamic_script_waits_only_when_caller_requests_settle() {
        let (base, requests) = spawn_delayed_classic_script_server(
            std::time::Duration::from_millis(400),
            "globalThis.__postLoadDynamicRan = true;",
        );
        let html = format!(
            r#"<html><body><script>
                window.addEventListener('load', () => {{
                    const script = document.createElement('script');
                    script.src = '{base}/post-load.js';
                    document.head.appendChild(script);
                }});
            </script></body></html>"#,
        );
        let mut page = import_map_test_page("post-load-dynamic-lifecycle", &base, &html);
        let started = std::time::Instant::now();

        page.execute_scripts().await;

        let navigation_elapsed = started.elapsed();
        assert!(
            navigation_elapsed < std::time::Duration::from_millis(300),
            "post-load enhancement must not extend navigation; elapsed={navigation_elapsed:?}",
        );
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate(
                    "[document.readyState, globalThis.__postLoadDynamicRan === true, \
                     globalThis.__obscura_hasPendingDynamicScripts(), \
                     globalThis.__obscura_hasPendingLoadDelayingScripts()]",
                )
                .unwrap(),
            serde_json::json!(["complete", false, true, false]),
            "a script prepared by load is pending enhancement work, not a load blocker",
        );

        page.settle_for_duration(700).await;

        assert_eq!(
            requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/post-load.js",
        );
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__postLoadDynamicRan === true")
                .unwrap(),
            serde_json::json!(true),
            "an explicit caller settle must drive post-load script completion",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timer_hydration_runs_during_explicit_adaptive_settle_not_navigation_load() {
        let mut page = import_map_test_page(
            "timer-hydration-lifecycle",
            "http://example.com",
            r#"<html><body><main id="app">Server shell</main><script>
                window.addEventListener('load', () => {
                    setTimeout(() => {
                        document.getElementById('app').textContent = 'Hydrated app';
                        document.body.setAttribute('data-hydrated', 'true');
                    }, 80);
                });
            </script></body></html>"#,
        );

        page.execute_scripts().await;
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate(
                    "[document.readyState, document.body.getAttribute('data-hydrated'), \
                     document.getElementById('app').textContent]",
                )
                .unwrap(),
            serde_json::json!(["complete", null, "Server shell"]),
            "navigation load observes load semantics without inventing a timer settle",
        );

        page.settle(500).await;
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate(
                    "[document.body.getAttribute('data-hydrated'), \
                     document.getElementById('app').textContent]",
                )
                .unwrap(),
            serde_json::json!(["true", "Hydrated app"]),
            "the automation caller's adaptive settle must retain timer hydration",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lazy_module_graph_is_post_load_work_until_caller_settles() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let length = stream.read(&mut request).unwrap();
                let request_text = String::from_utf8_lossy(&request[..length]);
                let path = request_text
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/");
                let body = match path {
                    "/app/lazy.js" => "import { ready } from './lazy-child.js'; export { ready };",
                    "/app/lazy-child.js" => {
                        // Cross the lifecycle's 500ms fast-settle floor on a
                        // descendant edge. deno_core must propagate the lazy
                        // graph marker beyond its root for this to stay alive.
                        std::thread::sleep(std::time::Duration::from_millis(700));
                        "export const ready = 'lazy-ready';"
                    }
                    unexpected => panic!("unexpected module request: {unexpected}"),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        let base = format!("http://{address}");
        let mut page = import_map_test_page(
            "lazy-module-readiness",
            &base,
            r#"<html><body><script>
                import("./lazy.js").then(module => {
                    document.body.setAttribute("data-lazy-state", module.ready);
                });
            </script></body></html>"#,
        );
        let started = std::time::Instant::now();
        page.execute_scripts().await;

        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "dynamic import() must not become an implicit navigation settle",
        );
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("document.body.getAttribute('data-lazy-state')")
                .unwrap(),
            serde_json::Value::Null,
        );

        page.settle_for_duration(1_000).await;

        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("document.body.getAttribute('data-lazy-state')")
                .unwrap(),
            serde_json::json!("lazy-ready"),
            "an explicit caller settle must drive the lazy module graph",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_fetch_does_not_extend_dynamic_module_settle() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = accepted_tx.send(());
            let mut request = [0u8; 2048];
            let length = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..length]).starts_with("GET /app/analytics "));
            std::thread::sleep(std::time::Duration::from_secs(2));
            let body = "{}";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            let _ = stream.write_all(response.as_bytes());
        });

        let base = format!("http://{address}");
        let html = format!(
            r#"<html><body><script>
                globalThis.__analyticsStarted = true;
                fetch("{base}/app/analytics").catch(error => {{
                    globalThis.__analyticsError = error.message;
                }});
            </script></body></html>"#,
        );
        let mut page = import_map_test_page("ordinary-fetch-readiness", &base, &html);
        let started = std::time::Instant::now();
        page.execute_scripts().await;
        let elapsed = started.elapsed();

        assert!(
            accepted_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_ok(),
            "ordinary fetch fixture must actually start its network request",
        );
        assert!(
            elapsed < std::time::Duration::from_millis(1_500),
            "ordinary fetch/XHR must retain the fast settle path; elapsed={elapsed:?}",
        );
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__analyticsStarted")
                .unwrap(),
            serde_json::json!(true),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dynamic_import_map_uses_live_document_base_at_insertion() {
        let (base, requests) = spawn_parser_import_map_server(1);
        let mut page = import_map_test_page(
            "dynamic-import-map-base",
            &base,
            r#"<html><head><base href="/old/"></head><body>
            <script>
                document.querySelector("base").setAttribute("href", "/app/");
                const map = document.createElement("script");
                map.type = "importmap";
                map.textContent = JSON.stringify({imports:{liveBase:"./later.js"}});
                document.head.appendChild(map);
                import("liveBase")
                    .then(module => globalThis.__dynamic_map_base = module.value)
                    .catch(error => globalThis.__dynamic_map_base = error.message);
            </script>
        </body></html>"#,
        );
        page.execute_scripts().await;
        page.settle_for_duration(500).await;
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__dynamic_map_base")
                .unwrap(),
            serde_json::json!("later-map"),
        );
        assert_eq!(
            requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/app/later.js"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn later_base_element_does_not_rebase_an_earlier_import_map() {
        let (base, requests) = spawn_parser_import_map_server(1);
        let mut page = import_map_test_page(
            "temporal-import-map-base",
            &base,
            r#"<html><head>
            <script type="importmap">{"imports":{"fixed":"./before.js"}}</script>
            <base href="/assets/">
            <script type="module">
                import { value } from "fixed";
                globalThis.__temporal_base_value = value;
            </script>
        </head><body></body></html>"#,
        );
        page.execute_scripts().await;
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("globalThis.__temporal_base_value")
                .unwrap(),
            serde_json::json!("before-first-module"),
        );
        assert_eq!(
            requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            "/app/before.js"
        );
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn page_transport_prefetches_once_and_capture_reuses_the_bytes() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut request = [0u8; 2048];
                        let read = stream.read(&mut request).unwrap_or(0);
                        let first = String::from_utf8_lossy(&request[..read])
                            .lines()
                            .next()
                            .unwrap_or_default()
                            .to_string();
                        seen_tx.send(first).unwrap();
                        let body = br##"<svg xmlns="http://www.w3.org/2000/svg" width="20" height="10"><rect width="20" height="10" fill="#f00"/></svg>"##;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        stream.write_all(response.as_bytes()).unwrap();
                        stream.write_all(body).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "render-prefetch".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("render-prefetch".to_string(), context);
        page.set_viewport((100.0, 80.0));
        let page_url = format!("http://{address}/page");
        let asset_network_url = format!("http://{address}/asset.svg");
        let asset_url = format!("{asset_network_url}#icon");
        let dom = parse_html(&format!(
            r#"<html><body><img src="{asset_url}" style="width:20px;height:10px"></body></html>"#
        ));
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(dom);
        runtime.set_url(&page_url);
        runtime.set_viewport(100.0, 80.0);
        runtime.run_page_init();
        page.js = Some(runtime);
        page.url = Some(url::Url::parse(&page_url).unwrap());

        let report = page.prepare_screenshot_resources_with_report(1_000).await;
        assert_eq!(
            report,
            super::ScreenshotResourceWarmupReport {
                discovered: 1,
                attempted: 1,
                loaded: 1,
                failed: 0,
                timed_out: 0,
                remaining: 0,
            }
        );
        assert!(report.is_complete());
        assert_eq!(
            page.js
                .as_mut()
                .unwrap()
                .evaluate("document.querySelector('img').currentSrc")
                .unwrap(),
            serde_json::json!(asset_url),
            "cache/network fragment normalization must not alter currentSrc"
        );
        page.screenshot(page.viewport).expect("prefetched capture");
        let first_request = seen_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(
            first_request.starts_with("GET /asset.svg "),
            "unexpected warmup request line: {first_request:?}",
        );
        assert!(
            seen_rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "capture must not open a second synchronous renderer request"
        );
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn render_resource_deadline_does_not_negative_cache_cancelled_requests() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            std::thread::sleep(std::time::Duration::from_millis(100));
            let body = br##"<svg xmlns="http://www.w3.org/2000/svg" width="20" height="10"/>"##;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
        });

        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "render-deadline".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("render-deadline".to_string(), context);
        page.set_viewport((100.0, 80.0));
        let page_url = format!("http://{address}/page");
        let asset_url = format!("http://{address}/slow.svg");
        let dom = parse_html(&format!(
            r#"<html><body><img src="{asset_url}"></body></html>"#
        ));
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(dom);
        runtime.set_url(&page_url);
        runtime.set_viewport(100.0, 80.0);
        runtime.run_page_init();
        page.js = Some(runtime);
        page.url = Some(url::Url::parse(&page_url).unwrap());

        let report = page.prepare_screenshot_resources_with_report(5).await;
        assert_eq!(report.discovered, 1);
        assert_eq!(report.attempted, 1);
        assert_eq!(report.loaded, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(report.timed_out, 1);
        assert_eq!(report.remaining, 1);
        assert!(!report.is_complete());
        assert!(
            !page
                .js
                .as_ref()
                .unwrap()
                .render_resource_is_known(&asset_url),
            "a deadline-cancelled request must remain retryable"
        );
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn render_resource_failures_are_reported_separately_from_remaining_work() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            let response =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes());
        });

        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "render-failure-report".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("render-failure-report".to_string(), context);
        let page_url = format!("http://{address}/page");
        let asset_url = format!("http://{address}/missing.svg");
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(parse_html(&format!(
            r#"<html><body><img src="{asset_url}"></body></html>"#
        )));
        runtime.set_url(&page_url);
        runtime.run_page_init();
        page.js = Some(runtime);
        page.url = Some(url::Url::parse(&page_url).unwrap());

        let report = page.prepare_screenshot_resources_with_report(1_000).await;
        assert_eq!(report.discovered, 1);
        assert_eq!(report.attempted, 1);
        assert_eq!(report.loaded, 0);
        assert_eq!(report.failed, 1);
        assert_eq!(report.timed_out, 0);
        assert_eq!(report.remaining, 0);
        assert!(!report.is_complete());
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn render_resource_cap_is_visible_as_remaining_work() {
        use std::io::{Read, Write};
        const RESOURCE_COUNT: usize = 129;
        const ATTEMPT_CAP: usize = 128;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for _ in 0..ATTEMPT_CAP {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request);
                let body = br##"<svg xmlns="http://www.w3.org/2000/svg"/>"##;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
            }
        });

        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "render-cap-report".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("render-cap-report".to_string(), context);
        let page_url = format!("http://{address}/page");
        let images = (0..RESOURCE_COUNT)
            .map(|index| format!(r#"<img src="http://{address}/asset-{index}.svg">"#))
            .collect::<String>();
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(parse_html(&format!("<html><body>{images}</body></html>")));
        runtime.set_url(&page_url);
        runtime.run_page_init();
        page.js = Some(runtime);
        page.url = Some(url::Url::parse(&page_url).unwrap());

        let report = page.prepare_screenshot_resources_with_report(5_000).await;
        assert_eq!(report.discovered, RESOURCE_COUNT);
        assert_eq!(report.attempted, ATTEMPT_CAP);
        assert_eq!(report.loaded, ATTEMPT_CAP);
        assert_eq!(report.failed, 0);
        assert_eq!(report.timed_out, 0);
        assert_eq!(report.remaining, 1);
        assert!(!report.is_complete());
    }

    #[cfg(feature = "render")]
    #[tokio::test(flavor = "current_thread")]
    async fn navigation_post_script_warmup_seeds_dynamic_images_and_fonts() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let read = stream.read(&mut request).unwrap_or(0);
                let path = String::from_utf8_lossy(&request[..read])
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                seen_tx.send(path.clone()).unwrap();
                let (content_type, body): (&str, &[u8]) = match path.as_str() {
                    "/page" => (
                        "text/html",
                        br#"<!doctype html><html><head></head><body><script>
                            const image = document.createElement('img');
                            image.src = '/dynamic.svg';
                            document.body.appendChild(image);
                            const style = document.createElement('style');
                            style.textContent = "@font-face{font-family:Dynamic;src:url('/dynamic.woff2')}body{font-family:Dynamic}";
                            document.head.appendChild(style);
                        </script></body></html>"#,
                    ),
                    "/dynamic.svg" => (
                        "image/svg+xml",
                        br#"<svg xmlns="http://www.w3.org/2000/svg" width="20" height="10"><rect width="20" height="10" fill="red"/></svg>"#,
                    ),
                    "/dynamic.woff2" => ("font/woff2", b"not-a-real-font"),
                    _ => ("text/plain", b"not found"),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.write_all(body).unwrap();
            }
        });

        let context = std::sync::Arc::new(crate::BrowserContext::with_storage_and_network(
            "dynamic-render-warmup".to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        let mut page = super::Page::new("dynamic-render-warmup".to_string(), context);
        let page_url = format!("http://{address}/page");
        page.navigate(&page_url).await.unwrap();

        let mut paths = (0..3)
            .map(|_| {
                seen_rx
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "/dynamic.svg".to_string(),
                "/dynamic.woff2".to_string(),
                "/page".to_string(),
            ]
        );
        let js = page.js.as_ref().expect("navigation runtime");
        assert!(js.render_resource_is_known(&format!("http://{address}/dynamic.svg")));
        assert!(js.render_resource_is_known(&format!("http://{address}/dynamic.woff2")));
    }

    #[cfg(feature = "render")]
    #[test]
    fn page_screenshot_uses_the_live_window_scroll_offset() {
        let context = std::sync::Arc::new(crate::BrowserContext::new("scroll-test".to_string()));
        let mut page = super::Page::new("scroll-page".to_string(), context);
        page.set_viewport((100.0, 80.0));

        let dom = parse_html(
            r#"<html style="margin:0"><body style="margin:0">
                <div style="height:80px;background:#ff0000"></div>
                <div id="second" style="height:80px;background:#0000ff"></div>
                <div style="position:fixed;left:0;top:0;width:20px;height:20px;background:#00ff00"></div>
            </body></html>"#,
        );
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(dom);
        runtime.set_url("https://example.test/scroll");
        runtime.set_viewport(100.0, 80.0);
        runtime.run_page_init();
        page.js = Some(runtime);
        page.url = Some(url::Url::parse("https://example.test/scroll").unwrap());

        let before = page.screenshot(page.viewport).expect("top screenshot");
        assert_eq!(
            page.evaluate(
                "return (document.getElementById('second').scrollIntoView(), window.scrollY)"
            )
            .as_f64(),
            Some(80.0)
        );
        let after = page.screenshot(page.viewport).expect("scrolled screenshot");

        assert_ne!(
            before, after,
            "Page screenshot must paint the scrolled viewport"
        );
        assert_eq!(
            page.js.as_ref().expect("runtime").scroll_offset(),
            (0.0, 80.0)
        );
    }

    #[test]
    fn truncate_never_splits_a_multibyte_char() {
        // A caller-supplied expression whose byte 80 lands inside a multi-byte
        // char would make `&expression[..80]` panic; the helper truncates safely.
        let s = format!("{}€tail", "a".repeat(79));
        assert!(!s.is_char_boundary(80), "setup: byte 80 splits the € char");
        let t = truncate_on_char_boundary(&s, 80);
        assert!(s.starts_with(t));
        assert_eq!(t.len(), 79, "should stop right before the € char");
        assert_eq!(truncate_on_char_boundary("short", 80), "short");
    }

    #[test]
    fn parse_import_url_extracts_url_forms() {
        for (source, expected_url) in [
            (" url(\"basic.css\")", "basic.css"),
            (" url(basic.css)", "basic.css"),
            (" \"basic.css\"", "basic.css"),
            (" 'theme.css'", "theme.css"),
            (" URL('x.css')", "x.css"),
        ] {
            assert_eq!(
                parse_import_url(source),
                Some(StylesheetImport {
                    url: expected_url.to_string(),
                    media: None,
                })
            );
        }
    }

    #[test]
    fn parse_import_url_preserves_print_and_color_scheme_media() {
        assert_eq!(
            parse_import_url("url(\"p.css\") print"),
            Some(StylesheetImport {
                url: "p.css".to_string(),
                media: Some("print".to_string()),
            })
        );
        assert_eq!(
            parse_import_url("url(\"d.css\") (prefers-color-scheme: dark)"),
            Some(StylesheetImport {
                url: "d.css".to_string(),
                media: Some("(prefers-color-scheme: dark)".to_string()),
            })
        );
        assert_eq!(
            parse_import_url("url(\"a.css\") print, screen"),
            Some(StylesheetImport {
                url: "a.css".to_string(),
                media: Some("print, screen".to_string()),
            })
        );
    }

    #[test]
    fn split_css_imports_pulls_imports_and_strips_them() {
        let css = "@import url(\"basic.css\");\nbody { color: red; }";
        let (imports, stripped) = split_css_imports(css);
        assert_eq!(
            imports,
            vec![StylesheetImport {
                url: "basic.css".to_string(),
                media: None,
            }]
        );
        assert!(!stripped.contains("@import"));
        assert!(stripped.contains("body { color: red; }"));
    }

    #[test]
    fn split_css_imports_leaves_import_free_css_untouched() {
        let css = "body { color: red; }";
        let (imports, stripped) = split_css_imports(css);
        assert!(imports.is_empty());
        assert_eq!(stripped, css);
    }

    #[test]
    fn materialized_import_graph_retains_print_condition_and_import_base() {
        let root_url = url::Url::parse("https://example.test/css/root.css").unwrap();
        let print_url = root_url.join("print/print.css").unwrap();
        let mut sheets = std::collections::HashMap::new();
        sheets.insert(
            root_url.to_string(),
            LoadedStylesheet {
                response_url: root_url.clone(),
                imports: vec![StylesheetImport {
                    url: "print/print.css".to_string(),
                    media: Some("print".to_string()),
                }],
                rules: ".root{color:red}".to_string(),
            },
        );
        sheets.insert(
            print_url.to_string(),
            LoadedStylesheet {
                response_url: print_url.clone(),
                imports: Vec::new(),
                rules: ".print{background:url(../mark.svg)}".to_string(),
            },
        );
        let aliases = std::collections::HashMap::from([
            (root_url.to_string(), root_url.to_string()),
            (print_url.to_string(), print_url.to_string()),
        ]);
        let materialized = materialize_stylesheet_graph(
            root_url.as_str(),
            &sheets,
            &aliases,
            &mut std::collections::HashSet::new(),
        )
        .expect("materialized graph");

        assert!(materialized.starts_with("@media print {\n"));
        assert!(
            materialized.contains(r#".print{background:url("https://example.test/css/mark.svg")}"#)
        );
        assert!(materialized.ends_with(".root{color:red}"));
    }

    #[test]
    fn stylesheet_asset_urls_keep_the_importing_sheets_base() {
        let base = url::Url::parse("https://example.com/css/theme/app.css").unwrap();
        let css = r#"
            .hero { background:url("../img/hero.png") }
            .icon { mask-image:URL('./icons/mark.svg') }
            .data { background:url("data:image/svg+xml,<svg></svg>") }
            .fragment { mask:url(#shape) }
            .copy::before { content:"url(../not-an-asset.png)" }
            /* url(../not-an-asset-either.png) */
        "#;
        let rebased = rebase_css_urls(css, &base);

        assert!(rebased.contains(r#"url("https://example.com/css/img/hero.png")"#));
        assert!(rebased.contains(r#"url("https://example.com/css/theme/icons/mark.svg")"#));
        assert!(rebased.contains(r#"url("data:image/svg+xml,<svg></svg>")"#));
        assert!(rebased.contains("url(#shape)"));
        assert!(rebased.contains(r#"content:"url(../not-an-asset.png)""#));
        assert!(rebased.contains("/* url(../not-an-asset-either.png) */"));
    }

    #[test]
    fn stylesheet_rel_token_selector_includes_preloaded_stylesheets() {
        let dom = parse_html(
            r#"<link rel="preload stylesheet" href="app.css">
               <link rel="preload" href="font.woff2">"#,
        );
        let links = dom
            .query_selector_all(r#"link[rel~="stylesheet"]"#)
            .expect("valid selector");
        assert_eq!(links.len(), 1);
        assert_eq!(
            dom.get_node(links[0])
                .and_then(|node| node.get_attribute("href").map(str::to_owned)),
            Some("app.css".to_string())
        );
    }

    #[test]
    fn media_gated_stylesheets_are_fetched_but_disabled_sheets_are_not() {
        let dom = parse_html(
            r#"<link rel="stylesheet" href="screen.css">
               <link rel="stylesheet" href="async.css" media="print"
                     onload="this.media='all'">
               <link rel="stylesheet" href="dark.css"
                     media="(prefers-color-scheme: dark)">
               <link rel="stylesheet" href="disabled.css" disabled>"#,
        );

        assert_eq!(
            linked_stylesheet_requests(&dom),
            vec![
                (0, "screen.css".to_string()),
                (1, "async.css".to_string()),
                (2, "dark.css".to_string()),
            ]
        );
    }

    #[test]
    fn print_media_onload_can_activate_a_fetched_stylesheet() {
        let dom = parse_html(
            r#"<html><head>
                <link id="async" rel="stylesheet" href="async.css" media="print"
                      onload="this.media='all';this.setAttribute('data-loaded','yes')">
            </head><body></body></html>"#,
        );
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(dom);
        runtime.run_page_init();
        runtime
            .execute_script(
                "<async-sheet>",
                &materialize_linked_stylesheet_script(0, ".target{color:red}"),
            )
            .expect("load and materialize async linked sheet");

        let state = runtime
            .with_dom(|dom| {
                let link = dom
                    .query_selector("#async")
                    .expect("valid selector")
                    .expect("async link");
                let styles = dom
                    .query_selector_all("style[data-obscura-external-stylesheets]")
                    .expect("valid selector");
                (
                    dom.get_node(link)
                        .and_then(|node| node.get_attribute("data-loaded").map(str::to_owned)),
                    styles.first().map(|&nid| dom.text_content(nid)),
                )
            })
            .expect("live DOM");

        assert_eq!(
            state.0.as_deref(),
            Some("yes"),
            "link load handler must run"
        );
        assert_eq!(
            state.1.as_deref(),
            Some(".target{color:red}"),
            "the handler's `this.media = 'all'` must activate the sheet"
        );
    }

    #[test]
    fn true_print_stylesheet_loads_and_remains_media_gated() {
        let dom = parse_html(
            r#"<html><head>
                <link id="print" rel="stylesheet" href="print.css" media="print"
                      onload="this.setAttribute('data-loaded','yes')">
            </head><body></body></html>"#,
        );
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(dom);
        runtime.run_page_init();
        runtime
            .execute_script(
                "<print-sheet>",
                &materialize_linked_stylesheet_script(0, "body{display:none}"),
            )
            .expect("finish print linked sheet load");

        let state = runtime
            .with_dom(|dom| {
                let link = dom
                    .query_selector("#print")
                    .expect("valid selector")
                    .expect("print link");
                (
                    dom.get_node(link)
                        .and_then(|node| node.get_attribute("data-loaded").map(str::to_owned)),
                    dom.query_selector("style[data-obscura-external-stylesheets]")
                        .expect("valid selector")
                        .and_then(|style| {
                            dom.get_node(style)
                                .and_then(|node| node.get_attribute("media").map(str::to_owned))
                        }),
                )
            })
            .expect("live DOM");

        assert_eq!(
            state.0.as_deref(),
            Some("yes"),
            "print link still fires load"
        );
        assert_eq!(
            state.1.as_deref(),
            Some("print"),
            "the fetched sheet must remain available for PDF print selection"
        );
    }

    #[test]
    fn materialized_linked_stylesheets_expose_link_owned_cssom_with_origin_security() {
        let dom = parse_html(
            r#"<html><head>
                <link id="same" rel="stylesheet" href="/assets/app.css" title="app">
                <style id="inline">.inline { color: green }</style>
                <link id="cross" rel="stylesheet" href="https://cdn.example.test/theme.css">
            </head><body></body></html>"#,
        );
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(dom);
        runtime.set_url("https://example.test/products/widget");
        runtime.run_page_init();
        runtime
            .execute_script(
                "<same-origin-sheet>",
                &materialize_linked_stylesheet_script(
                    0,
                    ".app { color: red } .wide { width: 20px }",
                ),
            )
            .expect("materialize same-origin linked sheet");
        runtime
            .execute_script(
                "<cross-origin-sheet>",
                &materialize_linked_stylesheet_script(1, ".secret { color: purple }"),
            )
            .expect("materialize cross-origin linked sheet");

        let result = runtime
            .evaluate(
                r#"
                (() => {
                    const list = document.styleSheets;
                    const same = document.getElementById('same');
                    const inline = document.getElementById('inline');
                    const cross = document.getElementById('cross');
                    const sameSheet = same.sheet;
                    const sameRules = sameSheet.cssRules;
                    const crossSheet = cross.sheet;
                    const security = [];
                    for (const operation of [
                        () => crossSheet.cssRules,
                        () => crossSheet.rules,
                        () => crossSheet.insertRule('.leak {}', 0),
                        () => crossSheet.deleteRule(0),
                        () => crossSheet.replaceSync('.leak {}'),
                    ]) {
                        try { operation(); security.push('missing'); }
                        catch (error) { security.push(error && error.name); }
                    }
                    sameSheet.insertRule('.added { height: 9px }', sameRules.length);
                    const source = document.querySelector(
                        'style[data-obscura-external-stylesheets]'
                    );
                    return {
                        stableList: list === document.styleSheets,
                        length: list.length,
                        order: [list[0] === sameSheet, list[1] === inline.sheet,
                                list[2] === crossSheet],
                        sameIdentity: same.sheet === sameSheet,
                        owner: sameSheet.ownerNode === same,
                        href: sameSheet.href,
                        title: sameSheet.title,
                        rulesIdentity: sameSheet.cssRules === sameRules,
                        rules: Array.from(sameRules, rule => rule.selectorText),
                        sourceUpdated: source.textContent.includes('.added'),
                        crossOwner: crossSheet.ownerNode === cross,
                        crossHref: crossSheet.href,
                        bridgeSheetsHidden: same.nextSibling.sheet === null
                            && cross.nextSibling.sheet === null,
                        security,
                    };
                })()
                "#,
            )
            .expect("inspect linked stylesheet CSSOM");

        assert_eq!(
            result,
            serde_json::json!({
                "stableList": true,
                "length": 3,
                "order": [true, true, true],
                "sameIdentity": true,
                "owner": true,
                "href": "https://example.test/assets/app.css",
                "title": "app",
                "rulesIdentity": true,
                "rules": [".app", ".wide", ".added"],
                "sourceUpdated": true,
                "crossOwner": true,
                "crossHref": "https://cdn.example.test/theme.css",
                "bridgeSheetsHidden": true,
                "security": ["SecurityError", "SecurityError", "SecurityError",
                             "SecurityError", "SecurityError"],
            })
        );
    }

    #[test]
    fn external_stylesheets_keep_their_positions_between_inline_sheets() {
        let dom = parse_html(
            r#"<html><head>
                <link rel="stylesheet" href="first.css">
                <style data-name="inline">.target{height:20px}</style>
                <link rel="preload stylesheet" href="second.css">
            </head><body></body></html>"#,
        );
        let mut runtime = obscura_js::runtime::ObscuraJsRuntime::new();
        runtime.set_dom(dom);
        runtime.run_page_init();
        runtime
            .execute_script(
                "<first-sheet>",
                &materialize_linked_stylesheet_script(0, ".target{height:10px}"),
            )
            .expect("materialize first linked sheet");
        runtime
            .execute_script(
                "<second-sheet>",
                &materialize_linked_stylesheet_script(1, ".target{height:30px}"),
            )
            .expect("materialize second linked sheet");

        let sheet_text = runtime
            .with_dom(|dom| {
                dom.query_selector_all("style")
                    .expect("valid selector")
                    .into_iter()
                    .map(|nid| dom.text_content(nid))
                    .collect::<Vec<_>>()
            })
            .expect("live DOM");
        assert_eq!(
            sheet_text,
            vec![
                ".target{height:10px}",
                ".target{height:20px}",
                ".target{height:30px}",
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parser_script_body_replacement_survives_navigation() {
        let mut page = client_replacement_page("parser-client-replacement", false);
        let target = page.url_string();

        page.navigate(&target)
            .await
            .expect("navigate replacement page");

        assert_client_replacement_survived(&mut page);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timer_body_replacement_survives_settle() {
        let mut page = client_replacement_page("timer-client-replacement", true);
        let target = page.url_string();
        page.navigate(&target)
            .await
            .expect("navigate deferred replacement page");

        let before_timer = page
            .js
            .as_mut()
            .expect("page runtime")
            .evaluate(
                "var scheduleClientReplacement = true; window.dispatchEvent(new Event('mount-client')); return !!document.getElementById('ssr');",
            )
            .expect("schedule client replacement");
        assert_eq!(before_timer, serde_json::json!(true));

        page.settle(100).await;

        assert_client_replacement_survived(&mut page);
    }

    #[cfg(feature = "render")]
    #[test]
    fn settle_resource_warmup_uses_only_remaining_absolute_budget() {
        assert_eq!(
            remaining_settle_resource_warmup_ms(
                1_000,
                std::time::Duration::from_millis(250),
                1_000,
            ),
            750
        );
        assert_eq!(
            remaining_settle_resource_warmup_ms(1_000, std::time::Duration::from_millis(250), 100,),
            100
        );
        assert_eq!(
            remaining_settle_resource_warmup_ms(
                1_000,
                std::time::Duration::from_micros(999_500),
                1_000,
            ),
            0,
            "a sub-millisecond remainder cannot safely fund a millisecond timeout"
        );
        assert_eq!(
            remaining_settle_resource_warmup_ms(
                1_000,
                std::time::Duration::from_millis(1_001),
                1_000,
            ),
            0
        );
    }

    #[test]
    fn url_matches_cdp_pattern_handles_wildcards_across_url_parts() {
        assert!(url_matches_cdp_pattern(
            "*://*.gstatic.com/*.woff2",
            "https://fonts.gstatic.com/s/inter/v18/UcCO3FwrK3iLTcviYwYZ8UA3.woff2",
        ));
        assert!(url_matches_cdp_pattern(
            "*://*.google.com/maps/vt/*",
            "https://www.google.com/maps/vt/pb=!1m4!1m3",
        ));
        assert!(url_matches_cdp_pattern(
            "https://example.com/assets/*",
            "https://example.com/assets/app.js",
        ));
        assert!(!url_matches_cdp_pattern(
            "https://example.com/assets/*",
            "https://cdn.example.com/assets/app.js",
        ));
        assert!(!url_matches_cdp_pattern(
            "*://*.gstatic.com/*.woff2",
            "https://fonts.gstatic.com/s/inter/v18/font.woff",
        ));
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PageError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Too many redirects (limit {0})")]
    TooManyRedirects(usize),
}

impl From<ObscuraNetError> for PageError {
    fn from(e: ObscuraNetError) -> Self {
        PageError::NetworkError(e.to_string())
    }
}

/// Whether a Content-Type is text-like and can be stored/returned as a UTF-8
/// string. Everything else (images, PDF, fonts, octet-stream) is binary and must
/// be base64-encoded so Network.getResponseBody returns intact bytes.
fn is_text_like_content_type(content_type: Option<&str>) -> bool {
    let ct = match content_type {
        Some(c) => c.split(';').next().unwrap_or(c).trim().to_ascii_lowercase(),
        // No Content-Type: assume text (matches the HTML-parse default).
        None => return true,
    };
    if ct.is_empty() {
        return true;
    }
    ct.starts_with("text/")
        || ct == "application/json"
        || ct == "application/xml"
        || ct == "application/xhtml+xml"
        || ct == "application/javascript"
        || ct == "application/ecmascript"
        || ct == "image/svg+xml"
        || ct.ends_with("+json")
        || ct.ends_with("+xml")
}

fn response_body_entry_limit() -> usize {
    std::env::var("OBSCURA_NETWORK_BODY_BUFFER_ENTRIES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(128)
}

fn response_body_byte_limit() -> usize {
    std::env::var("OBSCURA_NETWORK_BODY_BUFFER_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2 * 1024 * 1024)
}
