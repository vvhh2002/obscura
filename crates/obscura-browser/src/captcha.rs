//! Read-only challenge-image extraction for supported CAPTCHA view libraries.
//!
//! The adapters deliberately stop at identifying the active challenge and
//! returning its displayed image sources/bytes. They do not calculate an
//! answer, synthesize pointer tracks, click, drag, or submit a challenge.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::{Map, Value};
use url::Url;

use crate::page::{CapturedResource, Page, ResourceCapture};

const MAX_DOM_ARTIFACTS: usize = 32;
const MAX_DOM_GROUPS: usize = 512;
const MAX_DOM_SOURCE_CHARS: usize = 32 * 1024 * 1024;
const MAX_SCAN_FRAMES: usize = 32;
const MAX_JSON_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_OBJECTS: usize = 32_768;
const MAX_NETWORK_GROUPS: usize = 512;
const MAX_NETWORK_STORED_CHARS: usize = 64 * 1024 * 1024;
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_MATERIALIZED_BYTES: usize = 64 * 1024 * 1024;
const MAX_DATA_URL_CHARS: usize = (MAX_IMAGE_BYTES * 4 / 3) + 4096;

/// One supported challenge-view adapter, or automatic provider detection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaptchaAdapter {
    Auto,
    Tianai,
    GoCaptcha,
    AjCaptcha,
    SliderCaptchaJs,
}

impl CaptchaAdapter {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Tianai => "tianai",
            Self::GoCaptcha => "go-captcha",
            Self::AjCaptcha => "aj-captcha",
            Self::SliderCaptchaJs => "slider-captcha-js",
        }
    }

    fn accepts(self, detected: Self) -> bool {
        self == Self::Auto || self == detected
    }
}

impl fmt::Display for CaptchaAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CaptchaAdapter {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "tianai" => Ok(Self::Tianai),
            "go-captcha" | "gocaptcha" => Ok(Self::GoCaptcha),
            "aj-captcha" | "ajcaptcha" => Ok(Self::AjCaptcha),
            "slider-captcha-js" | "slider-captcha" => Ok(Self::SliderCaptchaJs),
            other => Err(format!(
                "unsupported CAPTCHA adapter {other:?}; expected auto, tianai, go-captcha, aj-captcha, or slider-captcha-js"
            )),
        }
    }
}

/// Semantic role of one displayed challenge image.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaptchaImageRole {
    Background,
    Puzzle,
}

impl CaptchaImageRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Background => "background",
            Self::Puzzle => "puzzle",
        }
    }
}

impl fmt::Display for CaptchaImageRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Transport form in which the component supplied an image source.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaptchaSourceKind {
    HttpUrl,
    DataUri,
    BlobUrl,
    InlineBase64,
    RelativeUrl,
    Other,
}

impl CaptchaSourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HttpUrl => "http_url",
            Self::DataUri => "data_uri",
            Self::BlobUrl => "blob_url",
            Self::InlineBase64 => "inline_base64",
            Self::RelativeUrl => "relative_url",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for CaptchaSourceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where the adapter observed the active image reference.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaptchaEvidenceKind {
    DomImage,
    ImageProvenance,
    Canvas,
    ApiResponse,
}

impl CaptchaEvidenceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DomImage => "dom_image",
            Self::ImageProvenance => "image_provenance",
            Self::Canvas => "canvas",
            Self::ApiResponse => "api_response",
        }
    }
}

impl fmt::Display for CaptchaEvidenceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One active challenge graphic. `bytes` is populated only from a bounded data
/// URI decode or a byte-exact response already retained by resource capture.
#[derive(Clone, Debug)]
pub struct CaptchaArtifact {
    pub adapter: CaptchaAdapter,
    pub challenge_kind: String,
    /// Opaque extraction-local group identifier. It contains no provider
    /// token, but keeps multiple same-provider widgets in one frame separate.
    pub challenge_id: String,
    pub role: CaptchaImageRole,
    pub source_kind: CaptchaSourceKind,
    pub evidence_kind: CaptchaEvidenceKind,
    /// The source value supplied by the component. Inline Base64 fields are
    /// normalized to a data URI, but never interpreted as an HTTP URL.
    pub source: String,
    /// Absolute HTTP(S) image URL, when one exists. Data and canvas sources do
    /// not manufacture a network URL.
    pub resolved_url: Option<String>,
    pub frame_id: u32,
    pub frame_url: String,
    /// API response containing the source, when response capture established
    /// that provenance. This is not necessarily an image URL.
    pub response_url: Option<String>,
    pub selector: Option<String>,
    pub mime_type: Option<String>,
    pub bytes: Option<Vec<u8>>,
}

/// Read-only result for one settled page and all of its live child frames.
#[derive(Debug)]
pub struct CaptchaExtraction {
    pub page_url: String,
    pub artifacts: Vec<CaptchaArtifact>,
    pub diagnostics: Vec<String>,
    /// Number of distinct visible DOM instances and observed API-only
    /// challenge groups, including mounted instances with missing roles.
    pub challenge_groups: usize,
    /// False when a hard scan/capture bound, an unsettled request, an
    /// unverified API-only result, or a refresh ambiguity means the returned
    /// groups cannot prove that every active challenge and graphic generation
    /// was observed.
    pub evidence_complete: bool,
}

/// Install the bounded, trusted new-document hooks required by CAPTCHA
/// extraction. Call this before navigation. The hooks snapshot the DOM/image
/// builtins used by the final scan and associate slider-captcha-js' detached
/// `Image` with its background canvas. They record only sources actually
/// present in the document or passed to `drawImage`; they neither change a
/// request nor fetch anything.
pub fn install_captcha_capture_preload(page: &mut Page) {
    page.add_preload_script(CAPTCHA_CAPTURE_PRELOAD);
}

#[derive(Clone, Debug)]
struct Candidate {
    adapter: CaptchaAdapter,
    challenge_kind: String,
    challenge_id: String,
    role: CaptchaImageRole,
    source_kind: CaptchaSourceKind,
    evidence_kind: CaptchaEvidenceKind,
    source: String,
    resolved_url: Option<String>,
    frame_id: u32,
    frame_url: String,
    response_url: Option<String>,
    selector: Option<String>,
    /// Index of the captured response which supplied an API candidate.
    /// DOM/canvas candidates have no capture index.
    capture_index: Option<usize>,
    /// Whether a captured HTTP response body can safely be associated with
    /// this exact DOM image generation. A current URL alone is insufficient
    /// when a refresh reuses the same URL while the new image is still
    /// pending or has failed to decode.
    captured_bytes_safe: bool,
}

#[derive(Default)]
struct DomScan {
    scanned_frames: HashSet<u32>,
    /// Provider-owned DOM found in the final document, even when hidden. A
    /// hidden residual widget proves this is not a DOM-less API-only page and
    /// therefore fences captured challenge responses from the former widget.
    provider_seen: HashSet<(CaptchaAdapter, u32)>,
    mounted: HashSet<(CaptchaAdapter, u32)>,
    detected: HashSet<(CaptchaAdapter, u32)>,
    expected_groups: HashSet<(CaptchaAdapter, u32, String, String)>,
    candidates: Vec<Candidate>,
    diagnostics: Vec<String>,
    source_chars: usize,
    artifact_bound_reported: bool,
    source_bound_reported: bool,
    group_bound_reported: bool,
    incomplete: bool,
}

/// Extract active challenge sources from the live DOM and from the caller's
/// byte-exact response capture. The DOM is authoritative: when a provider is
/// mounted, a captured response is correlated only when its complete
/// background-and-puzzle pair matches the current DOM challenge role by role.
/// This call consumes the page's enabled resource capture.
pub fn extract_captcha(
    page: &mut Page,
    requested: CaptchaAdapter,
    eval_timeout: Duration,
) -> Result<CaptchaExtraction, String> {
    let page_url = page.url_string();
    // A completed response is not necessarily the current challenge when a
    // newer request is still in flight (especially when URLs are reused).
    // Check quiescence before the synchronous DOM snapshot; do not use API
    // response evidence at all when request ordering is still unresolved.
    let capture_had_transport_failure_before_scan = page.has_current_transport_failures();
    let capture_was_quiescent_before_scan = !page.has_pending_resource_work();
    let mut scan = scan_live_documents(page, eval_timeout);
    // Page-owned DOM methods/getters can synchronously start work while being
    // inspected. Require quiescence on both sides of the snapshot so the scan
    // itself cannot open a refresh race and then reuse an older response.
    let capture_had_transport_failure =
        capture_had_transport_failure_before_scan || page.has_current_transport_failures();
    let capture_was_quiescent =
        capture_was_quiescent_before_scan && !page.has_pending_resource_work();
    // Snapshot the live DOM before draining capture. Synchronous evaluation
    // cannot advance the page event loop, so this orders final-DOM identity
    // before the last already-completed response body without opening a race
    // in which the scan itself completes after capture has been disabled.
    let capture = page
        .take_resource_capture()
        .ok_or_else(|| "CAPTCHA extraction requires resource capture to be enabled".to_string())?;
    // Draining capture refreshes frame-owner liveness and removes detached
    // realms. Discard any DOM evidence observed in a frame that was detached
    // between its last lifecycle tick and this final-scope refresh.
    let live_frame_ids: HashSet<u32> = std::iter::once(0)
        .chain(
            page.frame_snapshots()
                .into_iter()
                .map(|frame| frame.frame_id),
        )
        .collect();
    scan.scanned_frames
        .retain(|frame_id| live_frame_ids.contains(frame_id));
    scan.provider_seen
        .retain(|(_, frame_id)| live_frame_ids.contains(frame_id));
    scan.mounted
        .retain(|(_, frame_id)| live_frame_ids.contains(frame_id));
    scan.detected
        .retain(|(_, frame_id)| live_frame_ids.contains(frame_id));
    scan.expected_groups
        .retain(|(_, frame_id, _, _)| live_frame_ids.contains(frame_id));
    scan.candidates
        .retain(|candidate| live_frame_ids.contains(&candidate.frame_id));
    scan.detected
        .retain(|(adapter, _)| requested.accepts(*adapter));
    scan.provider_seen
        .retain(|(adapter, _)| requested.accepts(*adapter));
    scan.mounted
        .retain(|(adapter, _)| requested.accepts(*adapter));
    scan.expected_groups
        .retain(|(adapter, _, _, _)| requested.accepts(*adapter));
    scan.candidates
        .retain(|candidate| requested.accepts(candidate.adapter));

    let mut candidates = std::mem::take(&mut scan.candidates);
    let (network_groups, network_scan_incomplete) =
        if capture_was_quiescent && capture.omitted_resources == 0 && capture.omitted_bytes == 0 {
            network_candidates_with_status(&capture, requested, &mut scan.diagnostics)
        } else {
            // Once any response is omitted, a retained API/image response cannot
            // prove that a newer same-URL challenge generation was not the omitted
            // one. Keep authoritative live DOM sources, but do not enrich or fall
            // back from incomplete capture history.
            (Vec::new(), false)
        };
    scan.incomplete |= network_scan_incomplete;
    if !capture_was_quiescent {
        scan.incomplete = true;
        scan.diagnostics.push(
            "CAPTCHA response evidence was not used because resource work was still pending at the final snapshot"
                .to_string(),
        );
    }
    let mut active_groups: HashMap<
        (CaptchaAdapter, u32, String),
        Vec<(CaptchaImageRole, String, String)>,
    > = HashMap::new();
    for candidate in &candidates {
        active_groups
            .entry((
                candidate.adapter,
                candidate.frame_id,
                candidate.challenge_id.clone(),
            ))
            .or_default()
            .push((
                candidate.role,
                candidate_identity(candidate),
                candidate.challenge_kind.clone(),
            ));
    }

    let mut mounted_network_groups: HashMap<(CaptchaAdapter, u32, String), Vec<Vec<Candidate>>> =
        HashMap::new();
    let mut unmounted_groups = Vec::new();
    let mut transport_fenced_api_only_group = false;
    for mut group in network_groups {
        let Some(first) = group.first() else { continue };
        let group_adapter = first.adapter;
        let group_frame_id = first.frame_id;
        let complete_dom = scan.detected.contains(&(group_adapter, group_frame_id));
        let provider_was_seen = scan
            .provider_seen
            .contains(&(group_adapter, group_frame_id));
        let frame_was_scanned = scan.scanned_frames.contains(&group_frame_id);
        let mut matching_active =
            active_groups
                .iter()
                .filter_map(|((adapter, frame_id, id), entries)| {
                    if *adapter != group_adapter || *frame_id != group_frame_id {
                        return None;
                    }
                    group
                        .iter()
                        .all(|network| {
                            entries.iter().any(|(role, identity, _)| {
                                *role == network.role && *identity == candidate_identity(network)
                            })
                        })
                        .then(|| (id.clone(), entries.first().map(|entry| entry.2.clone())))
                });
        let active_match = matching_active.next();
        let unique_active_match = active_match.filter(|_| matching_active.next().is_none());
        if complete_dom && has_complete_pair(&group) && unique_active_match.is_some() {
            let (challenge_id, challenge_kind) = unique_active_match.expect("checked active match");
            for network_candidate in &mut group {
                network_candidate.challenge_id = challenge_id.clone();
                if let Some(challenge_kind) = challenge_kind.as_ref() {
                    network_candidate.challenge_kind = challenge_kind.clone();
                }
            }
            mounted_network_groups
                .entry((group_adapter, group_frame_id, challenge_id))
                .or_default()
                .push(group);
        } else if !provider_was_seen
            && frame_was_scanned
            && !scan.incomplete
            && requested != CaptchaAdapter::Auto
        {
            if capture_had_transport_failure {
                transport_fenced_api_only_group = true;
            } else {
                unmounted_groups.push(group);
            }
        }
    }

    if transport_fenced_api_only_group {
        scan.incomplete = true;
        scan.diagnostics.push(
            "API-only CAPTCHA fallback was disabled because a current-document transport request failed"
                .to_string(),
        );
    }

    for ((_adapter, _frame_id, _challenge_id), groups) in mounted_network_groups {
        let response_urls: HashSet<String> = groups
            .iter()
            .flat_map(|group| {
                group
                    .iter()
                    .filter_map(|candidate| candidate.response_url.clone())
            })
            .collect();
        let mut selected = groups
            .last()
            .expect("mounted network group collection is non-empty")
            .clone();
        if response_urls.len() > 1 {
            for candidate in &mut selected {
                candidate.response_url = None;
            }
            scan.diagnostics.push(
                "multiple API response URLs matched one active DOM source pair; ambiguous response provenance was omitted"
                    .to_string(),
            );
        }
        candidates.extend(selected);
    }

    // API-only extraction is exposed only for an explicitly selected adapter,
    // and is always incomplete: after a widget is fully removed, a retained
    // response is indistinguishable from a genuinely DOM-less integration.
    // Preserve the requested material for diagnostics/output, but never claim
    // it proves the currently displayed challenge.
    // Without request-start identity, multiple byte-distinct challenge pairs
    // cannot be ordered by response completion time: an older request may
    // finish last. Accept repeated identical pairs, but reject differing
    // generations instead of guessing. Auto always requires live provider DOM.
    let mut fallback_groups: HashMap<(CaptchaAdapter, u32, String), Vec<Vec<Candidate>>> =
        HashMap::new();
    for group in unmounted_groups {
        let Some(first) = group.first() else { continue };
        let key = (first.adapter, first.frame_id, first.challenge_kind.clone());
        fallback_groups.entry(key).or_default().push(group);
    }
    for ((_adapter, _frame_id, _kind), groups) in fallback_groups {
        let valid_capture_indices = groups
            .iter()
            .flat_map(|group| group.iter().filter_map(|candidate| candidate.capture_index))
            .collect::<HashSet<_>>();
        if unrecognized_same_endpoint_response_exists(&capture, &valid_capture_indices) {
            scan.incomplete = true;
            scan.diagnostics.push(
                "API-only CAPTCHA capture observed another failed or unrecognized response from the same endpoint; response completion order was not used to reuse an older challenge pair"
                    .to_string(),
            );
            continue;
        }
        let signatures: HashSet<Vec<(CaptchaImageRole, String)>> = groups
            .iter()
            .map(|group| {
                let mut signature = group
                    .iter()
                    .map(|candidate| (candidate.role, candidate_identity(candidate)))
                    .collect::<Vec<_>>();
                signature.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
                signature
            })
            .collect();
        if signatures.len() != 1 {
            scan.incomplete = true;
            scan.diagnostics.push(
                "API-only CAPTCHA capture observed multiple challenge generations; completion order was not used to guess the active pair"
                    .to_string(),
            );
            continue;
        }
        let response_urls: HashSet<String> = groups
            .iter()
            .flat_map(|group| {
                group
                    .iter()
                    .filter_map(|candidate| candidate.response_url.clone())
            })
            .collect();
        let mut selected = groups
            .last()
            .expect("fallback group collection is non-empty")
            .clone();
        if response_urls.len() > 1 {
            for candidate in &mut selected {
                candidate.response_url = None;
            }
            scan.diagnostics.push(
                "repeated API-only source pairs came from different response URLs; ambiguous response provenance was omitted"
                    .to_string(),
            );
        }
        scan.incomplete = true;
        scan.diagnostics.push(
            "API-only CAPTCHA material has no live DOM identity and cannot prove that the response still belongs to a currently displayed challenge"
                .to_string(),
        );
        candidates.extend(selected);
    }

    let mut merged = merge_candidates(candidates);
    let mut artifacts = Vec::with_capacity(merged.len());
    let mut remaining_materialized_bytes = MAX_MATERIALIZED_BYTES;
    for candidate in merged.drain(..) {
        artifacts.push(materialize_candidate(
            candidate,
            &capture,
            &mut scan.diagnostics,
            &mut remaining_materialized_bytes,
            &mut scan.incomplete,
        ));
    }

    artifacts.sort_by(|left, right| {
        left.frame_id
            .cmp(&right.frame_id)
            .then_with(|| left.adapter.as_str().cmp(right.adapter.as_str()))
            .then_with(|| left.challenge_kind.cmp(&right.challenge_kind))
            .then_with(|| left.challenge_id.cmp(&right.challenge_id))
            .then_with(|| left.role.as_str().cmp(right.role.as_str()))
            .then_with(|| left.source.cmp(&right.source))
    });
    if artifacts.is_empty() {
        scan.diagnostics.push(match requested {
            CaptchaAdapter::Auto => {
                "no supported CAPTCHA challenge materialized in the final live DOM or captured API responses"
                    .to_string()
            }
            adapter => format!(
                "no active {} challenge materialized in the final live DOM or captured API responses",
                adapter.as_str()
            ),
        });
    }
    if let Some(reason) = capture.omission_reason() {
        scan.incomplete = true;
        scan.diagnostics.push(reason);
    }
    let mut challenge_groups = std::mem::take(&mut scan.expected_groups);
    challenge_groups.extend(artifacts.iter().map(|artifact| {
        (
            artifact.adapter,
            artifact.frame_id,
            artifact.challenge_kind.clone(),
            artifact.challenge_id.clone(),
        )
    }));
    let challenge_group_count = challenge_groups.len();
    let evidence_complete = !scan.incomplete;
    scan.diagnostics.sort();
    scan.diagnostics.dedup();

    Ok(CaptchaExtraction {
        page_url,
        artifacts,
        diagnostics: scan.diagnostics,
        challenge_groups: challenge_group_count,
        evidence_complete,
    })
}

fn scan_live_documents(page: &mut Page, timeout: Duration) -> DomScan {
    let mut scan = DomScan::default();
    // Treat the caller's timeout as one whole-page budget, not a per-frame
    // multiplier. A minimum keeps the underlying zero-duration API from
    // selecting its intentionally unbounded compatibility path; the maximum
    // keeps public API callers from requesting an unbounded hostile-page scan.
    let timeout = timeout.clamp(Duration::from_millis(1), Duration::from_secs(10));
    let started = std::time::Instant::now();
    let page_url = page.url_string();
    let top = page.evaluate_with_timeout(DOM_SCAN_SCRIPT, timeout);
    append_dom_scan(&mut scan, 0, &page_url, top);

    let frames = page.frame_snapshots();
    if frames.len() > MAX_SCAN_FRAMES {
        scan.incomplete = true;
        scan.diagnostics.push(format!(
            "CAPTCHA adapter scan skipped {} child frames after reaching its frame bound",
            frames.len() - MAX_SCAN_FRAMES
        ));
    }
    let scanned_frame_bound = frames.len().min(MAX_SCAN_FRAMES);
    for (index, frame) in frames.into_iter().take(MAX_SCAN_FRAMES).enumerate() {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            scan.incomplete = true;
            scan.diagnostics.push(format!(
                "CAPTCHA adapter scan skipped {} child frames after exhausting its whole-page evaluation budget",
                scanned_frame_bound - index
            ));
            break;
        }
        match page.evaluate_in_frame_with_timeout(index, DOM_SCAN_SCRIPT, remaining) {
            Ok(value) => append_dom_scan(&mut scan, frame.frame_id, &frame.url, value),
            Err(error) => {
                scan.incomplete = true;
                scan.diagnostics.push(format!(
                    "CAPTCHA adapter scan failed in frame {} ({}): {}",
                    frame.frame_id, frame.url, error
                ));
            }
        }
    }
    scan
}

fn append_dom_scan(scan: &mut DomScan, frame_id: u32, frame_url: &str, value: Value) {
    let Some(object) = value.as_object() else {
        scan.incomplete = true;
        scan.diagnostics.push(format!(
            "CAPTCHA adapter scan returned no structured result for frame {frame_id} ({frame_url})"
        ));
        return;
    };
    scan.scanned_frames.insert(frame_id);
    scan.incomplete |= object
        .get("incomplete")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    if let Some(seen) = object.get("seen").and_then(Value::as_array) {
        for entry in seen {
            let Some(adapter) = entry.as_str().and_then(parse_detected_adapter) else {
                continue;
            };
            scan.provider_seen.insert((adapter, frame_id));
        }
    }

    if let Some(mounted) = object.get("mounted").and_then(Value::as_array) {
        for entry in mounted {
            let Some(adapter) = entry
                .get("adapter")
                .and_then(Value::as_str)
                .and_then(parse_detected_adapter)
            else {
                continue;
            };
            scan.mounted.insert((adapter, frame_id));
            let Some(kind) = entry
                .get("kind")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 64)
            else {
                scan.incomplete = true;
                continue;
            };
            let Some(challenge_id) = entry
                .get("instance")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 64)
            else {
                scan.incomplete = true;
                continue;
            };
            let group = (
                adapter,
                frame_id,
                kind.to_string(),
                challenge_id.to_string(),
            );
            if !scan.expected_groups.contains(&group)
                && scan.expected_groups.len() >= MAX_DOM_GROUPS
            {
                scan.incomplete = true;
                if !scan.group_bound_reported {
                    scan.diagnostics.push(format!(
                        "CAPTCHA DOM scan reached its global challenge-group bound of {MAX_DOM_GROUPS}"
                    ));
                    scan.group_bound_reported = true;
                }
                continue;
            }
            scan.expected_groups.insert(group);
        }
    }

    if let Some(detected) = object.get("detected").and_then(Value::as_array) {
        for entry in detected {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            let Some(adapter) = entry
                .get("adapter")
                .and_then(Value::as_str)
                .and_then(parse_detected_adapter)
            else {
                continue;
            };
            scan.detected.insert((adapter, frame_id));
        }
    }

    if let Some(images) = object.get("images").and_then(Value::as_array) {
        for image in images {
            if scan.candidates.len() >= MAX_DOM_ARTIFACTS {
                scan.incomplete = true;
                if !scan.artifact_bound_reported {
                    scan.diagnostics.push(format!(
                        "CAPTCHA DOM scan reached its global artifact bound of {MAX_DOM_ARTIFACTS}"
                    ));
                    scan.artifact_bound_reported = true;
                }
                break;
            }
            let Some(image) = image.as_object() else {
                continue;
            };
            let Some(adapter) = image
                .get("adapter")
                .and_then(Value::as_str)
                .and_then(parse_detected_adapter)
            else {
                continue;
            };
            let Some(role) = image
                .get("role")
                .and_then(Value::as_str)
                .and_then(parse_role)
            else {
                continue;
            };
            let Some(challenge_id) = image
                .get("instance")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 64)
            else {
                continue;
            };
            let Some(source) = image.get("source").and_then(Value::as_str) else {
                continue;
            };
            if source.is_empty() || source.len() > MAX_DATA_URL_CHARS {
                scan.incomplete = true;
                scan.diagnostics.push(format!(
                    "{} {} source in frame {} was empty or exceeded the bounded source length",
                    adapter.as_str(),
                    role.as_str(),
                    frame_id
                ));
                continue;
            }
            let resolved_source = image
                .get("resolved")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty());
            // Keep the literal `src` as the reported source, while using the
            // pre-navigation trusted resolver/currentSrc snapshot for the
            // actual network identity. The Rust fallback covers absolute or
            // ordinary frame-relative sources when no resolved value exists.
            let resolved = resolved_source
                .and_then(resolve_http_source)
                .or_else(|| resolve_dom_http_source(source, frame_url));
            let stored_chars = source
                .len()
                .saturating_add(resolved.as_deref().map_or(0, str::len));
            if resolved_source.is_some_and(|value| value.len() > MAX_DATA_URL_CHARS)
                || scan.source_chars.saturating_add(stored_chars) > MAX_DOM_SOURCE_CHARS
            {
                scan.incomplete = true;
                if !scan.source_bound_reported {
                    scan.diagnostics.push(format!(
                        "CAPTCHA DOM scan reached its global source length bound of {MAX_DOM_SOURCE_CHARS} bytes"
                    ));
                    scan.source_bound_reported = true;
                }
                continue;
            }
            let evidence_kind = match image.get("evidence").and_then(Value::as_str) {
                Some("preload") => CaptchaEvidenceKind::ImageProvenance,
                Some("canvas") => CaptchaEvidenceKind::Canvas,
                _ => CaptchaEvidenceKind::DomImage,
            };
            scan.candidates.push(Candidate {
                adapter,
                challenge_kind: image
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                challenge_id: challenge_id.to_string(),
                role,
                source_kind: classify_source(source, resolved.as_deref(), false),
                evidence_kind,
                source: source.to_string(),
                resolved_url: resolved,
                frame_id,
                frame_url: frame_url.to_string(),
                response_url: None,
                selector: image
                    .get("selector")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                capture_index: None,
                captured_bytes_safe: image
                    .get("capturedBytesSafe")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            });
            scan.source_chars += stored_chars;
        }
    }

    if let Some(diagnostics) = object.get("diagnostics").and_then(Value::as_array) {
        for diagnostic in diagnostics.iter().take(64).filter_map(Value::as_str) {
            scan.diagnostics
                .push(format!("frame {frame_id} ({frame_url}): {diagnostic}"));
        }
    }
}

fn parse_detected_adapter(value: &str) -> Option<CaptchaAdapter> {
    match value {
        "tianai" => Some(CaptchaAdapter::Tianai),
        "go-captcha" => Some(CaptchaAdapter::GoCaptcha),
        "aj-captcha" => Some(CaptchaAdapter::AjCaptcha),
        "slider-captcha-js" => Some(CaptchaAdapter::SliderCaptchaJs),
        _ => None,
    }
}

fn parse_role(value: &str) -> Option<CaptchaImageRole> {
    match value {
        "background" => Some(CaptchaImageRole::Background),
        "puzzle" => Some(CaptchaImageRole::Puzzle),
        _ => None,
    }
}

fn classify_source(source: &str, resolved: Option<&str>, inline_base64: bool) -> CaptchaSourceKind {
    if inline_base64 {
        return CaptchaSourceKind::InlineBase64;
    }
    let normalized = source.trim().to_ascii_lowercase();
    if is_data_uri(source) {
        CaptchaSourceKind::DataUri
    } else if normalized.starts_with("blob:") {
        CaptchaSourceKind::BlobUrl
    } else if normalized.starts_with("http://") || normalized.starts_with("https://") {
        CaptchaSourceKind::HttpUrl
    } else if resolved.is_some_and(|url| url.starts_with("http://") || url.starts_with("https://"))
        || normalized.starts_with('/')
        || normalized.starts_with("./")
        || normalized.starts_with("../")
    {
        CaptchaSourceKind::RelativeUrl
    } else {
        CaptchaSourceKind::Other
    }
}

fn is_data_uri(value: &str) -> bool {
    value
        .trim_start()
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("data:"))
}

fn network_candidates_with_status(
    capture: &ResourceCapture,
    requested: CaptchaAdapter,
    diagnostics: &mut Vec<String>,
) -> (Vec<Vec<Candidate>>, bool) {
    // Inspect newest responses first so global safety bounds retain the final
    // challenge generation. Batches are reversed again before returning to
    // preserve capture order for newest-provenance merging.
    let mut batches = Vec::new();
    let mut group_count = 0usize;
    let mut stored_candidate_chars = 0usize;
    let mut source_bound_hit = false;
    let mut object_budget = MAX_JSON_OBJECTS;
    for (capture_index, resource) in capture.resources.iter().enumerate().rev() {
        if !(200..300).contains(&resource.status)
            || resource.body.len() > MAX_JSON_RESPONSE_BYTES
            || !looks_like_json_response(resource)
        {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(&resource.body) else {
            continue;
        };
        let mut resource_groups = Vec::new();
        let mut resource_stored_chars = 0usize;
        let mut object_ordinal = 0usize;
        walk_json_objects(&value, 0, &mut object_budget, &mut |object| {
            let current_ordinal = object_ordinal;
            object_ordinal = object_ordinal.saturating_add(1);
            if source_bound_hit || group_count + resource_groups.len() >= MAX_NETWORK_GROUPS {
                return;
            }
            let mut object_candidates = Vec::new();
            collect_object_candidates(object, resource, requested, &mut object_candidates);
            let challenge_id = format!("api-{capture_index}-{current_ordinal}");
            for candidate in &mut object_candidates {
                candidate.challenge_id.clone_from(&challenge_id);
                candidate.capture_index = Some(capture_index);
            }
            deduplicate_candidates(&mut object_candidates);
            for adapter in [
                CaptchaAdapter::Tianai,
                CaptchaAdapter::GoCaptcha,
                CaptchaAdapter::AjCaptcha,
                CaptchaAdapter::SliderCaptchaJs,
            ] {
                let group = object_candidates
                    .iter()
                    .filter(|candidate| candidate.adapter == adapter)
                    .cloned()
                    .collect::<Vec<_>>();
                if has_complete_pair(&group) {
                    let group_chars = group.iter().fold(0usize, |total, candidate| {
                        total
                            .saturating_add(candidate.source.len())
                            .saturating_add(candidate.resolved_url.as_deref().map_or(0, str::len))
                            .saturating_add(candidate.frame_url.len())
                            .saturating_add(candidate.response_url.as_deref().map_or(0, str::len))
                            .saturating_add(candidate.challenge_kind.len())
                            .saturating_add(candidate.challenge_id.len())
                    });
                    if stored_candidate_chars
                        .saturating_add(resource_stored_chars)
                        .saturating_add(group_chars)
                        > MAX_NETWORK_STORED_CHARS
                    {
                        source_bound_hit = true;
                        break;
                    }
                    resource_stored_chars = resource_stored_chars.saturating_add(group_chars);
                    resource_groups.push(group);
                    if group_count + resource_groups.len() >= MAX_NETWORK_GROUPS {
                        break;
                    }
                }
            }
        });
        stored_candidate_chars = stored_candidate_chars.saturating_add(resource_stored_chars);
        group_count += resource_groups.len();
        batches.push(resource_groups);
        if source_bound_hit {
            diagnostics.push(format!(
                "CAPTCHA JSON scan reached its global retained source bound of {MAX_NETWORK_STORED_CHARS} bytes"
            ));
            break;
        }
        if group_count >= MAX_NETWORK_GROUPS {
            diagnostics.push(format!(
                "CAPTCHA JSON scan reached its global complete-pair group bound of {MAX_NETWORK_GROUPS}"
            ));
            break;
        }
        if object_budget == 0 {
            diagnostics.push(format!(
                "CAPTCHA JSON scan reached its global object bound of {MAX_JSON_OBJECTS}"
            ));
            break;
        }
    }
    let incomplete = source_bound_hit || group_count >= MAX_NETWORK_GROUPS || object_budget == 0;
    (batches.into_iter().rev().flatten().collect(), incomplete)
}

#[cfg(test)]
fn network_candidates(
    capture: &ResourceCapture,
    requested: CaptchaAdapter,
    diagnostics: &mut Vec<String>,
) -> Vec<Vec<Candidate>> {
    network_candidates_with_status(capture, requested, diagnostics).0
}

fn has_complete_pair(candidates: &[Candidate]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate.role == CaptchaImageRole::Background)
        && candidates
            .iter()
            .any(|candidate| candidate.role == CaptchaImageRole::Puzzle)
}

fn looks_like_json_response(resource: &CapturedResource) -> bool {
    if response_content_type(resource).is_some_and(|value| {
        value.contains("application/json") || value.contains("+json") || value.contains("text/json")
    }) {
        return true;
    }
    matches!(
        resource
            .body
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace()),
        Some(b'{') | Some(b'[')
    )
}

fn walk_json_objects(
    value: &Value,
    depth: usize,
    budget: &mut usize,
    callback: &mut impl FnMut(&Map<String, Value>),
) {
    if depth > MAX_JSON_DEPTH || *budget == 0 {
        return;
    }
    match value {
        Value::Object(object) => {
            *budget -= 1;
            callback(object);
            for nested in object.values() {
                walk_json_objects(nested, depth + 1, budget, callback);
                if *budget == 0 {
                    break;
                }
            }
        }
        Value::Array(values) => {
            for nested in values {
                walk_json_objects(nested, depth + 1, budget, callback);
                if *budget == 0 {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn collect_object_candidates(
    object: &Map<String, Value>,
    resource: &CapturedResource,
    requested: CaptchaAdapter,
    output: &mut Vec<Candidate>,
) {
    if requested.accepts(CaptchaAdapter::Tianai) {
        collect_tianai_json(object, resource, output);
    }
    if requested.accepts(CaptchaAdapter::AjCaptcha) {
        collect_aj_json(object, resource, output);
    }
    if requested.accepts(CaptchaAdapter::SliderCaptchaJs) {
        collect_slider_captcha_json(object, resource, output);
    }
    // GoCaptcha's JavaScript library deliberately defines no transport schema.
    // Its two official service examples use the aliases below, so only parse
    // them when GoCaptcha was selected explicitly; automatic detection remains
    // grounded in the provider's distinctive DOM root.
    if requested == CaptchaAdapter::GoCaptcha {
        collect_go_captcha_json(object, resource, output);
    }
}

fn collect_tianai_json(
    object: &Map<String, Value>,
    resource: &CapturedResource,
    output: &mut Vec<Candidate>,
) {
    let code_is_success = object
        .get("code")
        .is_some_and(|value| value.as_i64() == Some(200) || value.as_str() == Some("200"));
    if !code_is_success {
        return;
    }
    let Some(data) = object.get("data").and_then(Value::as_object) else {
        return;
    };
    let Some(kind) = data.get("type").and_then(Value::as_str) else {
        return;
    };
    if kind != "SLIDER" {
        return;
    }
    let kind = "slider";
    let Some(background) = data
        .get("backgroundImage")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    let Some(template) = data
        .get("templateImage")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    push_api_candidate(
        output,
        CaptchaAdapter::Tianai,
        kind,
        CaptchaImageRole::Background,
        background,
        false,
        None,
        resource,
    );
    push_api_candidate(
        output,
        CaptchaAdapter::Tianai,
        kind,
        CaptchaImageRole::Puzzle,
        template,
        false,
        None,
        resource,
    );
}

fn collect_aj_json(
    object: &Map<String, Value>,
    resource: &CapturedResource,
    output: &mut Vec<Candidate>,
) {
    if object.get("repCode").and_then(Value::as_str) != Some("0000") {
        return;
    }
    let Some(data) = object.get("repData").and_then(Value::as_object) else {
        return;
    };
    let Some(original) = data
        .get("originalImageBase64")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    let puzzle = data
        .get("jigsawImageBase64")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(puzzle) = puzzle else {
        // This adapter intentionally supports AJ's blockPuzzle slider only,
        // not clickWord.
        return;
    };
    let kind = "block_puzzle";
    push_api_candidate(
        output,
        CaptchaAdapter::AjCaptcha,
        kind,
        CaptchaImageRole::Background,
        original,
        !is_data_uri(original),
        Some("image/png"),
        resource,
    );
    push_api_candidate(
        output,
        CaptchaAdapter::AjCaptcha,
        kind,
        CaptchaImageRole::Puzzle,
        puzzle,
        !is_data_uri(puzzle),
        Some("image/png"),
        resource,
    );
}

fn collect_slider_captcha_json(
    object: &Map<String, Value>,
    resource: &CapturedResource,
    output: &mut Vec<Candidate>,
) {
    let (Some(background), Some(puzzle)) = (
        object.get("bgUrl").and_then(Value::as_str),
        object.get("puzzleUrl").and_then(Value::as_str),
    ) else {
        return;
    };
    let background = background.trim();
    let puzzle = puzzle.trim();
    if background.is_empty() || puzzle.is_empty() {
        return;
    }
    push_api_candidate(
        output,
        CaptchaAdapter::SliderCaptchaJs,
        "slider",
        CaptchaImageRole::Background,
        background,
        false,
        None,
        resource,
    );
    push_api_candidate(
        output,
        CaptchaAdapter::SliderCaptchaJs,
        "slider",
        CaptchaImageRole::Puzzle,
        puzzle,
        false,
        None,
        resource,
    );
}

fn collect_go_captcha_json(
    object: &Map<String, Value>,
    resource: &CapturedResource,
    output: &mut Vec<Candidate>,
) {
    let is_slide = object.contains_key("tile_base64")
        || object.contains_key("tile_x")
        || object.contains_key("tile_y")
        || object.contains_key("display_x")
        || object.contains_key("display_y");
    if !is_slide {
        // image/thumb by themselves are also used by GoCaptcha click/rotate;
        // require one of the official slide coordinate/tile fields.
        return;
    }
    let background = string_alias(object, &["master_image_base64", "image_base64", "image"]);
    let puzzle = string_alias(
        object,
        &["thumb_image_base64", "tile_base64", "thumb_base64", "thumb"],
    );
    let (Some((background_field, background)), Some((puzzle_field, puzzle))) = (background, puzzle)
    else {
        return;
    };
    // Both official GoCaptcha slide widgets consume the same transport
    // fields. The live DOM refines this to `slide` or `slide_region`; an
    // explicitly requested API-only capture must not guess the variant.
    let kind = "slide_or_slide_region";
    push_api_candidate(
        output,
        CaptchaAdapter::GoCaptcha,
        kind,
        CaptchaImageRole::Background,
        background,
        is_inline_base64_field(background_field, background),
        None,
        resource,
    );
    push_api_candidate(
        output,
        CaptchaAdapter::GoCaptcha,
        kind,
        CaptchaImageRole::Puzzle,
        puzzle,
        is_inline_base64_field(puzzle_field, puzzle),
        None,
        resource,
    );
}

fn string_alias<'a>(
    object: &'a Map<String, Value>,
    names: &[&'a str],
) -> Option<(&'a str, &'a str)> {
    names.iter().find_map(|name| {
        object
            .get(*name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| (*name, value))
    })
}

fn is_inline_base64_field(field: &str, value: &str) -> bool {
    if !field.ends_with("_base64")
        || is_data_uri(value)
        || looks_like_url_reference(value)
        || value.len() > MAX_DATA_URL_CHARS
    {
        return false;
    }
    BASE64
        .decode(value.as_bytes())
        .ok()
        .is_some_and(|bytes| sniff_image_mime(&bytes).is_some())
}

fn looks_like_url_reference(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.starts_with("http://")
        || normalized.starts_with("https://")
        || normalized.starts_with("blob:")
        || normalized.starts_with('/')
        || normalized.starts_with("./")
        || normalized.starts_with("../")
}

#[allow(clippy::too_many_arguments)]
fn push_api_candidate(
    output: &mut Vec<Candidate>,
    adapter: CaptchaAdapter,
    challenge_kind: &str,
    role: CaptchaImageRole,
    raw_source: &str,
    inline_base64: bool,
    mime_hint: Option<&str>,
    resource: &CapturedResource,
) {
    let raw_source = raw_source.trim();
    if raw_source.is_empty() || raw_source.len() > MAX_DATA_URL_CHARS {
        return;
    }
    let source = if inline_base64 {
        format!(
            "data:{};base64,{}",
            mime_hint.unwrap_or("application/octet-stream"),
            raw_source
        )
    } else {
        raw_source.to_string()
    };
    let resolved_url = resolve_http_source(&source).or_else(|| {
        if is_data_uri(&source) || source.trim().to_ascii_lowercase().starts_with("blob:") {
            return None;
        }
        resource
            .initiator
            .as_ref()
            .unwrap_or(&resource.final_url)
            .join(&source)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https"))
            .map(|url| url.to_string())
    });
    output.push(Candidate {
        adapter,
        challenge_kind: challenge_kind.to_string(),
        challenge_id: String::new(),
        role,
        source_kind: classify_source(&source, resolved_url.as_deref(), inline_base64),
        evidence_kind: CaptchaEvidenceKind::ApiResponse,
        source,
        resolved_url,
        frame_id: resource.frame_id,
        frame_url: resource
            .initiator
            .as_ref()
            .unwrap_or(&resource.final_url)
            .to_string(),
        response_url: Some(resource.final_url.to_string()),
        selector: None,
        capture_index: None,
        captured_bytes_safe: true,
    });
}

fn resolve_http_source(source: &str) -> Option<String> {
    let parsed = Url::parse(source).ok()?;
    matches!(parsed.scheme(), "http" | "https").then(|| parsed.to_string())
}

fn resolve_dom_http_source(source: &str, frame_url: &str) -> Option<String> {
    resolve_http_source(source).or_else(|| {
        let base = Url::parse(frame_url).ok()?;
        let resolved = base.join(source).ok()?;
        matches!(resolved.scheme(), "http" | "https").then(|| resolved.to_string())
    })
}

fn candidate_identity(candidate: &Candidate) -> String {
    candidate
        .resolved_url
        .clone()
        .unwrap_or_else(|| candidate.source.clone())
}

fn unrecognized_same_endpoint_response_exists(
    capture: &ResourceCapture,
    valid_indices: &HashSet<usize>,
) -> bool {
    if valid_indices.is_empty() {
        return true;
    }
    valid_indices.iter().any(|valid_index| {
        let Some(valid) = capture.resources.get(*valid_index) else {
            return true;
        };
        capture
            .resources
            .iter()
            .enumerate()
            .filter(|(index, _)| !valid_indices.contains(index))
            .any(|(_, other)| {
                other.frame_id == valid.frame_id && response_url_chains_overlap(valid, other)
            })
    })
}

fn response_url_chains_overlap(left: &CapturedResource, right: &CapturedResource) -> bool {
    resource_response_urls(left).any(|left_url| {
        resource_response_urls(right).any(|right_url| same_response_endpoint(left_url, right_url))
    })
}

fn same_response_endpoint(left: &Url, right: &Url) -> bool {
    if matches!(left.scheme(), "http" | "https") && matches!(right.scheme(), "http" | "https") {
        left.scheme().eq_ignore_ascii_case(right.scheme())
            && left.host_str() == right.host_str()
            && left.port_or_known_default() == right.port_or_known_default()
            && left.path() == right.path()
    } else {
        left == right
    }
}

fn resource_response_urls(resource: &CapturedResource) -> impl Iterator<Item = &Url> {
    std::iter::once(&resource.requested_url)
        .chain(std::iter::once(&resource.final_url))
        .chain(resource.redirected_from.iter())
}

fn deduplicate_candidates(candidates: &mut Vec<Candidate>) {
    let mut seen = HashSet::new();
    candidates.retain(|candidate| {
        seen.insert((
            candidate.adapter,
            candidate.challenge_kind.clone(),
            candidate.challenge_id.clone(),
            candidate.role,
            candidate.frame_id,
            candidate_identity(candidate),
        ))
    });
}

fn merge_candidates(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut output: Vec<Candidate> = Vec::new();
    let mut positions: HashMap<
        (
            CaptchaAdapter,
            String,
            String,
            CaptchaImageRole,
            u32,
            String,
        ),
        usize,
    > = HashMap::new();
    for candidate in candidates {
        let key = (
            candidate.adapter,
            candidate.challenge_kind.clone(),
            candidate.challenge_id.clone(),
            candidate.role,
            candidate.frame_id,
            candidate_identity(&candidate),
        );
        if let Some(index) = positions.get(&key).copied() {
            let existing = &mut output[index];
            // Candidates are processed in capture order, so retain the newest
            // matching API provenance when a challenge refresh reuses the
            // same image URLs.
            if candidate.response_url.is_some() && response_provenance_safe(existing) {
                existing.response_url = candidate.response_url.clone();
            }
            // The live DOM remains authoritative for source form, selector and
            // challenge kind; API evidence only supplements provenance.
            if existing.evidence_kind == CaptchaEvidenceKind::ApiResponse
                && candidate.evidence_kind != CaptchaEvidenceKind::ApiResponse
            {
                let response_url = response_provenance_safe(&candidate)
                    .then(|| existing.response_url.take())
                    .flatten();
                *existing = candidate;
                existing.response_url = response_url;
            }
            continue;
        }
        positions.insert(key, output.len());
        output.push(candidate);
    }
    output
}

fn response_provenance_safe(candidate: &Candidate) -> bool {
    candidate.evidence_kind == CaptchaEvidenceKind::ApiResponse
        || candidate.resolved_url.is_none()
        || candidate.captured_bytes_safe
}

fn materialize_candidate(
    mut candidate: Candidate,
    capture: &ResourceCapture,
    diagnostics: &mut Vec<String>,
    remaining_bytes: &mut usize,
    evidence_incomplete: &mut bool,
) -> CaptchaArtifact {
    let mut mime_type = None;
    let mut bytes = None;
    if is_data_uri(&candidate.source) {
        match decode_data_uri(&candidate.source) {
            Ok((mime, decoded)) => {
                let sniffed = sniff_image_mime(&decoded);
                if sniffed.is_none() {
                    diagnostics.push(format!(
                        "{} {} inline source is not a recognized image",
                        candidate.adapter, candidate.role
                    ));
                } else if sniffed == Some("image/svg+xml") {
                    diagnostics.push(format!(
                        "{} {} inline SVG was not written because active image content is unsupported",
                        candidate.adapter, candidate.role
                    ));
                } else {
                    let effective_mime = sniffed.expect("checked image signature").to_string();
                    if candidate.adapter == CaptchaAdapter::AjCaptcha
                        && effective_mime != "image/png"
                    {
                        diagnostics.push(format!(
                            "{} {} source did not contain the PNG required by blockPuzzle",
                            candidate.adapter, candidate.role
                        ));
                    } else if decoded.len() > *remaining_bytes {
                        diagnostics.push(format!(
                            "{} {} image exceeded the total materialization byte budget",
                            candidate.adapter, candidate.role
                        ));
                    } else {
                        *remaining_bytes -= decoded.len();
                        if candidate.source_kind == CaptchaSourceKind::InlineBase64
                            && mime == "application/octet-stream"
                        {
                            if let Some((_, body)) = candidate.source.split_once(',') {
                                candidate.source = format!("data:{effective_mime};base64,{body}");
                            }
                        }
                        mime_type = Some(effective_mime);
                        bytes = Some(decoded);
                    }
                }
            }
            Err(error) => diagnostics.push(format!(
                "{} {} data URI could not be decoded: {}",
                candidate.adapter, candidate.role, error
            )),
        }
    } else if let Some(url) = candidate.resolved_url.as_deref() {
        if !candidate.captured_bytes_safe {
            diagnostics.push(format!(
                "{} {} DOM image was not fully decoded at the final snapshot; captured same-URL bytes were not reused",
                candidate.adapter, candidate.role
            ));
        } else {
            match find_captured_image(capture, candidate.frame_id, url) {
                Ok(Some(resource)) => {
                    if resource.body.len() > MAX_IMAGE_BYTES {
                        diagnostics.push(format!(
                            "{} {} captured image exceeded the per-image byte budget",
                            candidate.adapter, candidate.role
                        ));
                    } else if sniff_image_mime(&resource.body) == Some("image/svg+xml") {
                        diagnostics.push(format!(
                        "{} {} captured SVG was not written because active image content is unsupported",
                        candidate.adapter, candidate.role
                    ));
                    } else if let Some(sniffed) = sniff_image_mime(&resource.body) {
                        if candidate.adapter == CaptchaAdapter::AjCaptcha && sniffed != "image/png"
                        {
                            diagnostics.push(format!(
                                "{} {} response did not contain the PNG required by blockPuzzle",
                                candidate.adapter, candidate.role
                            ));
                        } else if resource.body.len() > *remaining_bytes {
                            diagnostics.push(format!(
                                "{} {} image exceeded the total materialization byte budget",
                                candidate.adapter, candidate.role
                            ));
                        } else {
                            *remaining_bytes -= resource.body.len();
                            mime_type = Some(sniffed.to_string());
                            bytes = Some(resource.body.clone());
                        }
                    } else {
                        diagnostics.push(format!(
                            "{} {} matched response is not a recognized image",
                            candidate.adapter, candidate.role
                        ));
                    }
                }
                Ok(None) => diagnostics.push(format!(
                    "{} {} URL has no byte-exact captured image response",
                    candidate.adapter, candidate.role
                )),
                Err(reason) => {
                    // A same-URL failure, omission, or byte-distinct refresh
                    // is an ordering ambiguity, not merely a missing optional
                    // image body. Mark the whole snapshot partial even when
                    // the caller requested only URLs.
                    *evidence_incomplete = true;
                    diagnostics.push(format!(
                        "{} {} URL was not materialized: {}",
                        candidate.adapter, candidate.role, reason
                    ));
                }
            }
        }
    } else if candidate.source_kind == CaptchaSourceKind::BlobUrl {
        diagnostics.push(format!(
            "{} {} uses an ephemeral blob URL; no byte-exact blob body was exposed by resource capture",
            candidate.adapter, candidate.role
        ));
    }

    CaptchaArtifact {
        adapter: candidate.adapter,
        challenge_kind: candidate.challenge_kind,
        challenge_id: candidate.challenge_id,
        role: candidate.role,
        source_kind: candidate.source_kind,
        evidence_kind: candidate.evidence_kind,
        source: candidate.source,
        resolved_url: candidate.resolved_url,
        frame_id: candidate.frame_id,
        frame_url: candidate.frame_url,
        response_url: candidate.response_url,
        selector: candidate.selector,
        mime_type,
        bytes,
    }
}

fn decode_data_uri(source: &str) -> Result<(String, Vec<u8>), String> {
    if source.len() > MAX_DATA_URL_CHARS {
        return Err("source exceeds the bounded data URI length".to_string());
    }
    let source = source.trim_start();
    if !is_data_uri(source) {
        return Err("missing data: scheme".to_string());
    }
    let rest = &source[5..];
    let (metadata, body) = rest
        .split_once(',')
        .ok_or_else(|| "missing data URI comma".to_string())?;
    let mut parts = metadata.split(';');
    let mime = parts
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("text/plain");
    let is_base64 = parts.any(|value| value.eq_ignore_ascii_case("base64"));
    let decoded = if is_base64 {
        BASE64
            .decode(body.as_bytes())
            .map_err(|error| format!("invalid Base64 payload: {error}"))?
    } else {
        percent_decode(body)?
    };
    if decoded.len() > MAX_IMAGE_BYTES {
        return Err("decoded image exceeds the bounded byte length".to_string());
    }
    Ok((mime.to_ascii_lowercase(), decoded))
}

fn percent_decode(value: &str) -> Result<Vec<u8>, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes
                .get(index + 1)
                .copied()
                .and_then(hex_value)
                .ok_or_else(|| "invalid percent escape".to_string())?;
            let low = bytes
                .get(index + 2)
                .copied()
                .and_then(hex_value)
                .ok_or_else(|| "invalid percent escape".to_string())?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(decoded)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn response_content_type(resource: &CapturedResource) -> Option<&str> {
    resource
        .response_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.split(';').next().unwrap_or(value).trim())
}

fn find_captured_image<'a>(
    capture: &'a ResourceCapture,
    frame_id: u32,
    source_url: &str,
) -> Result<Option<&'a CapturedResource>, &'static str> {
    if capture.omitted_resources != 0 || capture.omitted_bytes != 0 {
        return Err(
            "capture bounds omitted responses, so the final same-URL response cannot be proven",
        );
    }
    let matches = |resource: &&CapturedResource| {
        resource.method.eq_ignore_ascii_case("GET")
            && (resource.requested_url.as_str() == source_url
                || resource.final_url.as_str() == source_url
                || resource
                    .redirected_from
                    .iter()
                    .any(|url| url.as_str() == source_url))
    };
    let matching = capture
        .resources
        .iter()
        .filter(|resource| resource.frame_id == frame_id)
        .filter(matches)
        .collect::<Vec<_>>();
    if matching
        .iter()
        .any(|resource| !(200..300).contains(&resource.status))
    {
        return Err(
            "a failed or non-2xx response shares this frame and URL; the active image generation cannot be proven",
        );
    }
    let Some(first) = matching.first().copied() else {
        return Ok(None);
    };
    if matching
        .iter()
        .skip(1)
        .any(|resource| resource.body != first.body)
    {
        return Err(
            "multiple byte-distinct responses share this frame and URL; response completion order cannot prove the active generation",
        );
    }
    Ok(Some(first))
}

fn sniff_image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"BM") {
        Some("image/bmp")
    } else if bytes.starts_with(&[0, 0, 1, 0]) {
        Some("image/x-icon")
    } else {
        let prefix = bytes
            .iter()
            .copied()
            .skip_while(|byte| byte.is_ascii_whitespace())
            .take(256)
            .collect::<Vec<_>>();
        let text = String::from_utf8_lossy(&prefix).to_ascii_lowercase();
        (text.starts_with("<svg") || text.starts_with("<?xml") && text.contains("<svg"))
            .then_some("image/svg+xml")
    }
}

// slider-captcha-js local mode creates a detached `Image`, draws it into three
// canvases, and then drops every DOM-visible reference to the original source.
// The renderer cannot currently rasterize HTMLImageElement in drawImage, so a
// post-load canvas export may be blank. This opt-in preload records only the
// source passed to drawImage and associates it with that destination canvas.
// Weak collections bound retention to the page's own canvas/context lifetime.
const CAPTCHA_CAPTURE_PRELOAD: &str = r#"(()=>{
  const LOOKUP='__obscuraCaptchaCanvasSource';
  const BUILTINS='__obscuraCaptchaDomBuiltins';
  if(!globalThis[BUILTINS]){
    try{
      const apply=globalThis.Reflect&&globalThis.Reflect.apply;
      const DocumentCtor=globalThis.Document,ElementCtor=globalThis.Element;
      const NodeCtor=globalThis.Node,ShadowRootCtor=globalThis.ShadowRoot;
      const ImageCtor=globalThis.HTMLImageElement;
      const captchaDom=globalThis.__obscuraCaptchaNativeDom;
      const imagePrototype=ImageCtor&&ImageCtor.prototype;
      const propertyGetter=(prototype,name)=>{
        const value=prototype&&Object.getOwnPropertyDescriptor(prototype,name);
        return value&&value.get;
      };
      const imageGetter=(name)=>propertyGetter(imagePrototype,name);
      const builtins={
        apply,
        StringCtor:globalThis.String,
        stringTrim:globalThis.String&&globalThis.String.prototype&&globalThis.String.prototype.trim,
        stringToLowerCase:globalThis.String&&globalThis.String.prototype&&globalThis.String.prototype.toLowerCase,
        stringStartsWith:globalThis.String&&globalThis.String.prototype&&globalThis.String.prototype.startsWith,
        stringEndsWith:globalThis.String&&globalThis.String.prototype&&globalThis.String.prototype.endsWith,
        stringIndexOf:globalThis.String&&globalThis.String.prototype&&globalThis.String.prototype.indexOf,
        stringSlice:globalThis.String&&globalThis.String.prototype&&globalThis.String.prototype.slice,
        stringCharCodeAt:globalThis.String&&globalThis.String.prototype&&globalThis.String.prototype.charCodeAt,
        ImageCtor,
        createTreeWalker:DocumentCtor&&DocumentCtor.prototype&&DocumentCtor.prototype.createTreeWalker,
        matches:ElementCtor&&ElementCtor.prototype&&ElementCtor.prototype.matches,
        querySelector:captchaDom&&captchaDom.queryOne,
        getAttribute:captchaDom&&captchaDom.getAttribute,
        hasAttribute:captchaDom&&captchaDom.hasAttribute,
        getComputedStyle:globalThis.getComputedStyle,
        captchaComputedVisibility:globalThis.__obscuraCaptchaComputedVisibility,
        captchaResolveDocumentUrl:globalThis.__obscuraCaptchaResolveDocumentUrl,
        captchaImageState:globalThis.__obscuraCaptchaImageState,
        nodeType:captchaDom&&captchaDom.nodeType,
        parentNode:captchaDom&&captchaDom.parentNode,
        getRootNode:captchaDom&&captchaDom.rootNode,
        nextNode:captchaDom&&captchaDom.nextNode,
        elementChildren:captchaDom&&captchaDom.children,
        elementShadowRoot:captchaDom&&captchaDom.shadowRoot,
        shadowHost:captchaDom&&captchaDom.shadowHost,
        imageSrc:imageGetter('src'),
        imageCurrentSrc:imageGetter('currentSrc'),
        imageComplete:imageGetter('complete'),
        imageNaturalWidth:imageGetter('naturalWidth'),
        imageNaturalHeight:imageGetter('naturalHeight'),
        arrayPush:globalThis.Array&&globalThis.Array.prototype&&globalThis.Array.prototype.push,
        SetCtor:globalThis.Set,
        setHas:globalThis.Set&&globalThis.Set.prototype&&globalThis.Set.prototype.has,
        setAdd:globalThis.Set&&globalThis.Set.prototype&&globalThis.Set.prototype.add,
        weakMapGet:globalThis.WeakMap&&globalThis.WeakMap.prototype&&globalThis.WeakMap.prototype.get,
        weakMapSet:globalThis.WeakMap&&globalThis.WeakMap.prototype&&globalThis.WeakMap.prototype.set,
        weakMapDelete:globalThis.WeakMap&&globalThis.WeakMap.prototype&&globalThis.WeakMap.prototype.delete,
        weakSetHas:globalThis.WeakSet&&globalThis.WeakSet.prototype&&globalThis.WeakSet.prototype.has,
        weakSetAdd:globalThis.WeakSet&&globalThis.WeakSet.prototype&&globalThis.WeakSet.prototype.add
      };
      if(Object.values(builtins).every(value=>typeof value==='function')){
        Object.freeze(builtins);
        Object.defineProperty(globalThis,BUILTINS,{
          value:builtins,configurable:false,enumerable:false,writable:false
        });
      }
    }catch(_error){}
  }
  if(typeof globalThis[LOOKUP]==='function')return;
  const native=globalThis[BUILTINS];
  if(!native)return;
  const nativeApply=native.apply;
  const stringify=(value)=>nativeApply(native.StringCtor,undefined,[value]);
  const trimString=(value)=>nativeApply(native.stringTrim,stringify(value),[]);
  const Canvas=globalThis.HTMLCanvasElement;
  if(!Canvas||!Canvas.prototype||typeof Canvas.prototype.getContext!=='function')return;
  const provenance=new WeakMap(),wrapped=new WeakSet();
  const originalGetContext=Canvas.prototype.getContext;
  const sourceFromImage=(image)=>{
    if(!image)return null;
    let isImage=false;
    try{isImage=image instanceof native.ImageCtor;}catch(_error){}
    if(!isImage)return null;
    let raw='',resolved='',capturedBytesSafe=false;
    try{
      const state=nativeApply(native.captchaImageState,undefined,[image]);
      raw=state&&state.raw||'';resolved=state&&state.resolved||raw;
      capturedBytesSafe=state&&state.capturedBytesSafe===true;
    }catch(_error){resolved=raw;}
    raw=trimString(raw||'');resolved=trimString(resolved||'');
    if(!raw&&!resolved)return null;
    return {source:raw||resolved,resolved,capturedBytesSafe};
  };
  Canvas.prototype.getContext=function captchaCaptureGetContext(type,...args){
    const context=nativeApply(originalGetContext,this,[type,...args]);
    if(type!=='2d'||!context||nativeApply(native.weakSetHas,wrapped,[context])||typeof context.drawImage!=='function')return context;
    nativeApply(native.weakSetAdd,wrapped,[context]);
    const originalDrawImage=context.drawImage;
    const originalClearRect=typeof context.clearRect==='function'?context.clearRect:null;
    if(originalClearRect){
      context.clearRect=function captchaCaptureClearRect(...clearArgs){
        try{if(this&&this.canvas)nativeApply(native.weakMapDelete,provenance,[this.canvas]);}catch(_error){}
        return nativeApply(originalClearRect,this,clearArgs);
      };
    }
    context.drawImage=function captchaCaptureDrawImage(image,...drawArgs){
      const result=nativeApply(originalDrawImage,this,[image,...drawArgs]);
      try{
        const source=sourceFromImage(image);
        if(this&&this.canvas){
          if(source)nativeApply(native.weakMapSet,provenance,[this.canvas,source]);
          else nativeApply(native.weakMapDelete,provenance,[this.canvas]);
        }
      }catch(_error){}
      return result;
    };
    return context;
  };
  try{
    Object.defineProperty(globalThis,LOOKUP,{
      value:(canvas)=>nativeApply(native.weakMapGet,provenance,[canvas])||null,
      configurable:false,enumerable:false,writable:false
    });
  }catch(_error){}
})()"#;

// The provider selectors and field-to-role mapping below are pinned to the
// public DOM contracts of Tianai 1.5.x, go-captcha-jslib 1.0.x, AJ-Captcha
// 1.3.x, and slider-captcha-js 1.0.x. Scanning is limited to live documents and
// open shadow roots; closed roots remain intentionally inaccessible.
const DOM_SCAN_SCRIPT: &str = r#"(()=>{
  const out={seen:[],mounted:[],detected:[],images:[],diagnostics:[],incomplete:false};
  const MAX_IMAGES=32,MAX_MATCHES=128,MAX_ROOTS=64,MAX_NODES=50000,MAX_SOURCE=22373717,MAX_TOTAL_SOURCE=33554432;
  const native=globalThis.__obscuraCaptchaDomBuiltins;
  if(!native||!['apply','StringCtor','stringTrim','stringToLowerCase','stringStartsWith','stringEndsWith','stringIndexOf','stringSlice','stringCharCodeAt','querySelector','getAttribute','hasAttribute','captchaComputedVisibility','captchaImageState','nodeType','parentNode','getRootNode','nextNode','elementChildren','elementShadowRoot','shadowHost','arrayPush','SetCtor','setHas','setAdd'].every(name=>typeof native[name]==='function')){
    out.incomplete=true;
    out.diagnostics[out.diagnostics.length]='CAPTCHA DOM scan requires the pre-navigation trusted builtin snapshot';
    return out;
  }
  const nativeApply=native.apply;
  const stringify=(value)=>nativeApply(native.StringCtor,undefined,[value]);
  const trimString=(value)=>nativeApply(native.stringTrim,stringify(value),[]);
  const lowerString=(value)=>nativeApply(native.stringToLowerCase,stringify(value),[]);
  const startsWithString=(value,prefix)=>nativeApply(native.stringStartsWith,value,[prefix]);
  const endsWithString=(value,suffix)=>nativeApply(native.stringEndsWith,value,[suffix]);
  const indexOfString=(value,search)=>nativeApply(native.stringIndexOf,value,[search]);
  const sliceString=(value,start,end)=>nativeApply(native.stringSlice,value,[start,end]);
  const charCodeAtString=(value,index)=>nativeApply(native.stringCharCodeAt,value,[index]);
  const append=(array,value)=>nativeApply(native.arrayPush,array,[value]);
  const setHas=(set,value)=>nativeApply(native.setHas,set,[value]);
  const setAdd=(set,value)=>nativeApply(native.setAdd,set,[value]);
  const nodeTypeOf=(node)=>{try{return node&&nativeApply(native.nodeType,undefined,[node]);}catch(_error){return 0;}};
  const parentNodeOf=(node)=>{try{return node&&nativeApply(native.parentNode,undefined,[node]);}catch(_error){return null;}};
  const parentElementOf=(node)=>{const parent=parentNodeOf(node);return nodeTypeOf(parent)===1?parent:null;};
  const childrenOf=(element)=>{try{return element&&nativeApply(native.elementChildren,undefined,[element]);}catch(_error){return null;}};
  const shadowRootOf=(element)=>{try{return element&&nativeApply(native.elementShadowRoot,undefined,[element]);}catch(_error){return null;}};
  const shadowHostOf=(root)=>{try{return root&&nativeApply(native.shadowHost,undefined,[root]);}catch(_error){return null;}};
  const isConnectedNode=(node)=>{
    let current=node;
    for(let depth=0;current&&depth<64;depth++){
      let root=null;try{root=nativeApply(native.getRootNode,undefined,[current]);}catch(_error){return false;}
      if(nodeTypeOf(root)===9)return true;
      if(nodeTypeOf(root)!==11)return false;
      current=shadowHostOf(root);
    }
    return false;
  };
  let inspectedNodes=0,totalSource=0,instanceSequence=0,sourceBoundReported=false,nodeBoundReported=false,visibilityBoundReported=false,rootBoundReported=false,selectorBoundReported=false,imageBoundReported=false,traversalFailureReported=false,styleFailureReported=false;
  const roots=[document],allElements=[],seenRoots=new native.SetCtor(),seenImages=new native.SetCtor(),seenProviders=new native.SetCtor(),seenMounted=new native.SetCtor(),seenDetected=new native.SetCtor();
  for(let i=0;i<roots.length&&i<MAX_ROOTS;i++){
    const root=roots[i];
    if(!root||setHas(seenRoots,root))continue;
    setAdd(seenRoots,root);
    const remaining=Math.max(0,MAX_NODES-inspectedNodes);
    if(!remaining){out.incomplete=true;if(!nodeBoundReported){append(out.diagnostics,'CAPTCHA DOM scan reached its node bound');nodeBoundReported=true;}break;}
    let walked=0;
    try{
      let cursor=root;
      while(walked<remaining){
        cursor=nativeApply(native.nextNode,undefined,[root,cursor]);if(!cursor)break;
        walked++;
        if(nodeTypeOf(cursor)!==1)continue;
        append(allElements,cursor);
        const shadowRoot=shadowRootOf(cursor);
        if(shadowRoot&&!setHas(seenRoots,shadowRoot))append(roots,shadowRoot);
      }
    }catch(_error){out.incomplete=true;if(!traversalFailureReported){append(out.diagnostics,'CAPTCHA DOM traversal failed');traversalFailureReported=true;}}
    inspectedNodes+=walked;
    if(walked>=remaining){out.incomplete=true;if(!nodeBoundReported){append(out.diagnostics,'CAPTCHA DOM scan reached its node bound');nodeBoundReported=true;}break;}
  }
  if(roots.length>MAX_ROOTS){out.incomplete=true;if(!rootBoundReported){append(out.diagnostics,'CAPTCHA DOM scan reached its open-root bound');rootBoundReported=true;}}
  const hasClass=(element,name)=>{
    try{
      const value=attribute(element,'class')||'';
      let start=-1;
      for(let index=0;index<=value.length;index++){
        const code=index<value.length?charCodeAtString(value,index):32;
        const whitespace=code===9||code===10||code===12||code===13||code===32;
        if(whitespace){
          if(start>=0&&sliceString(value,start,index)===name)return true;
          start=-1;
        }else if(start<0)start=index;
      }
    }catch(_error){}
    return false;
  };
  const matchesFixedSelector=(element,selector)=>{
    if(selector==='#tianai-captcha')return attribute(element,'id')==='tianai-captcha';
    if(selector==='.verify-img-panel')return hasClass(element,'verify-img-panel');
    if(selector==='.slider-captcha-stage')return hasClass(element,'slider-captcha-stage');
    if(selector==='.go-captcha.gc-wrapper')return hasClass(element,'go-captcha')&&hasClass(element,'gc-wrapper');
    if(selector==='.go-captcha.gc-wrapper.gc-slide-mode')return hasClass(element,'go-captcha')&&hasClass(element,'gc-wrapper')&&hasClass(element,'gc-slide-mode');
    return false;
  };
  const queryAll=(selector)=>{
    const values=[];
    for(let elementIndex=0;elementIndex<allElements.length;elementIndex++){
      const value=allElements[elementIndex];
      try{if(matchesFixedSelector(value,selector)){
        if(values.length>=MAX_MATCHES){out.incomplete=true;if(!selectorBoundReported){append(out.diagnostics,'CAPTCHA DOM selector scan reached its match bound');selectorBoundReported=true;}return values;}
        append(values,value);
      }}catch(_error){}
    }
    return values;
  };
  const queryOne=(root,selector)=>{try{return root&&nativeApply(native.querySelector,undefined,[root,selector]);}catch(_error){return null;}};
  const attribute=(element,name)=>{try{return element&&nativeApply(native.getAttribute,undefined,[element,name]);}catch(_error){return null;}};
  const directChildWithClass=(root,name)=>{
    try{
      const children=childrenOf(root);if(!children)return null;
      for(let childIndex=0;childIndex<children.length;childIndex++){
        const child=children[childIndex];if(hasClass(child,name))return child;
      }
    }catch(_error){}
    return null;
  };
  const isDisplayed=(element)=>{
    let current=element;
    for(let depth=0;current&&depth<256;depth++){
      if(!isConnectedNode(current))return false;
      try{
        if(nativeApply(native.hasAttribute,undefined,[current,'hidden']))return false;
      }catch(_error){out.incomplete=true;if(!styleFailureReported){append(out.diagnostics,'CAPTCHA visibility style inspection failed');styleFailureReported=true;}return false;}
      try{
        const style=nativeApply(native.captchaComputedVisibility,undefined,[current]);
        if(style){
          const display=lowerString(style.display||'');
          const visibility=lowerString(style.visibility||'');
          const contentVisibility=lowerString(style.contentVisibility||style['content-visibility']||'');
          const opacity=trimString(style.opacity||'');
          if(display==='none'||visibility==='hidden'||visibility==='collapse'
            ||contentVisibility==='hidden'||opacity==='0')return false;
        }
      }catch(_error){out.incomplete=true;if(!styleFailureReported){append(out.diagnostics,'CAPTCHA visibility computed-style inspection failed');styleFailureReported=true;}return false;}
      const parent=parentNodeOf(current),parentType=nodeTypeOf(parent);
      let next=parentType===1?parent:parentType===11?shadowHostOf(parent):null;
      if(!next)return parentType===9;
      current=next;
    }
    if(current){
      out.incomplete=true;
      if(!visibilityBoundReported){append(out.diagnostics,'CAPTCHA visibility scan reached its ancestor bound');visibilityBoundReported=true;}
      return false;
    }
    return true;
  };
  const detected=(adapter,kind,instance)=>{
    const key=adapter+'\u0000'+kind+'\u0000'+instance;
    if(setHas(seenDetected,key))return;
    setAdd(seenDetected,key);append(out.detected,{adapter,kind,instance});
  };
  const providerSeen=(adapter)=>{
    if(setHas(seenProviders,adapter))return;
    setAdd(seenProviders,adapter);append(out.seen,adapter);
  };
  const mounted=(adapter,kind,instance)=>{
    const key=adapter+'\u0000'+kind+'\u0000'+instance;
    if(setHas(seenMounted,key))return;
    setAdd(seenMounted,key);append(out.mounted,{adapter,kind,instance});
  };
  const nextInstance=(adapter)=>adapter+'-'+stringify(instanceSequence++);
  const sourceKind=(source)=>{
    const value=lowerString(trimString(source||''));
    if(startsWithString(value,'data:'))return 'data';
    if(startsWithString(value,'blob:'))return 'blob';
    if(startsWithString(value,'http://')||startsWithString(value,'https://'))return 'http';
    return 'relative';
  };
  const usableSource=(source)=>{
    const value=trimString(source||'');if(!value)return false;
    if(startsWithString(lowerString(value),'data:')){
      const comma=indexOfString(value,',');
      return comma>=0&&trimString(sliceString(value,comma+1)).length>0;
    }
    return true;
  };
  const add=(adapter,kind,instance,role,source,resolved,evidence,selector,capturedBytesSafe)=>{
    source=trimString(source||'');resolved=trimString(resolved||'');
    if(!usableSource(source))return;
    if(source.length>MAX_SOURCE||resolved.length>MAX_SOURCE){out.incomplete=true;if(!sourceBoundReported){append(out.diagnostics,'CAPTCHA DOM sources reached their per-source length bound');sourceBoundReported=true;}return;}
    if(out.images.length>=MAX_IMAGES){out.incomplete=true;if(!imageBoundReported){append(out.diagnostics,'CAPTCHA DOM scan reached its image bound');imageBoundReported=true;}return;}
    const key=adapter+'\u0000'+kind+'\u0000'+instance+'\u0000'+role+'\u0000'+(resolved||source)+'\u0000'+evidence;
    if(setHas(seenImages,key))return;
    const storedLength=source.length+resolved.length;
    if(totalSource+storedLength>MAX_TOTAL_SOURCE){
      out.incomplete=true;
      if(!sourceBoundReported){append(out.diagnostics,'CAPTCHA DOM sources reached their total length bound');sourceBoundReported=true;}
      return;
    }
    setAdd(seenImages,key);
    totalSource+=storedLength;
    append(out.images,{adapter,kind,instance,role,source,resolved,evidence,selector,
      sourceKind:sourceKind(source),capturedBytesSafe:capturedBytesSafe!==false});
  };
  const readImg=(img,excludeDefault)=>{
    if(!img||!isDisplayed(img))return null;
    let raw='',resolved='',capturedBytesSafe=false;
    try{
      const state=nativeApply(native.captchaImageState,undefined,[img]);
      raw=state&&state.raw||'';resolved=state&&state.resolved||raw;
      capturedBytesSafe=state&&state.capturedBytesSafe===true;
    }catch(_error){resolved=raw;}
    const source=trimString(raw||resolved||'');
    resolved=trimString(resolved||source);
    let check=lowerString(resolved||source),end=check.length;
    const query=indexOfString(check,'?'),fragment=indexOfString(check,'#');
    if(query>=0&&query<end)end=query;if(fragment>=0&&fragment<end)end=fragment;
    check=sliceString(check,0,end);
    const defaultImage=check==='default.png'
      ||endsWithString(check,'/default.png')||endsWithString(check,'/default.jpg')
      ||endsWithString(check,'/default.jpeg')||endsWithString(check,'/default.gif')
      ||endsWithString(check,'/default.webp');
    if(!usableSource(source)||excludeDefault&&defaultImage)return null;
    return {source,resolved,capturedBytesSafe};
  };
  const addImgSource=(adapter,kind,instance,role,imageSource,selector)=>{
    if(imageSource)add(adapter,kind,instance,role,imageSource.source,imageSource.resolved,'img',selector,imageSource.capturedBytesSafe);
  };
  const canvasHasPixels=(canvas)=>{
    try{
      const context=canvas.getContext('2d');
      const width=typeof canvas.width==='number'?canvas.width:0;
      const height=typeof canvas.height==='number'?canvas.height:0;
      if(!context||width<=0||height<=0)return false;
      const columns=Math.min(32,width),rows=Math.min(32,height);
      for(let row=0;row<rows;row++)for(let column=0;column<columns;column++){
        const x=Math.min(width-1,Math.floor((column+.5)*width/columns));
        const y=Math.min(height-1,Math.floor((row+.5)*height/rows));
        const data=context.getImageData(x,y,1,1).data;
        if(data&&data.length>=4&&(data[0]||data[1]||data[2]||data[3]))return true;
      }
    }catch(_error){}
    return false;
  };
  // Tianai SLIDER only. The bounded element walk returns every duplicate
  // official ID directly, including standalone roots mixed with parent-owned
  // instances; document.querySelector would collapse those to the first one.
  const tianaiRoots=queryAll('#tianai-captcha');
  for(let rootIndex=0;rootIndex<tianaiRoots.length;rootIndex++){
    const active=tianaiRoots[rootIndex];
    providerSeen('tianai');
    if(!isDisplayed(active))continue;
    if(!hasClass(active,'tianai-captcha-slider')
      ||hasClass(active,'tianai-captcha-rotate')||queryOne(active,'.tianai-captcha-rotate')
      ||hasClass(active,'tianai-captcha-concat')||queryOne(active,'.tianai-captcha-concat')
      ||hasClass(active,'tianai-captcha-word-click')||queryOne(active,'.tianai-captcha-word-click'))continue;
    const kind='slider',instance=nextInstance('tianai');
    mounted('tianai',kind,instance);
    const background=readImg(queryOne(active,'#tianai-captcha-slider-bg-img'),false);
    const puzzle=readImg(queryOne(active,'#tianai-captcha-slider-move-img'),false);
    if(!background||!puzzle){append(out.diagnostics,'tianai slider is missing a usable '+(!background&&!puzzle?'background and puzzle':!background?'background':'puzzle')+' source');continue;}
    detected('tianai',kind,instance);
    addImgSource('tianai',kind,instance,'background',background,'#tianai-captcha-slider-bg-img');
    addImgSource('tianai',kind,instance,'puzzle',puzzle,'#tianai-captcha-slider-move-img');
  }

  // Any visible official GoCaptcha root suppresses API-only fallback. Only
  // Slide/SlideRegion roots proceed to extraction below.
  const goRoots=queryAll('.go-captcha.gc-wrapper');
  for(let rootIndex=0;rootIndex<goRoots.length;rootIndex++){
    providerSeen('go-captcha');
  }
  // GoCaptcha Slide/SlideRegion only.
  const goSlideRoots=queryAll('.go-captcha.gc-wrapper.gc-slide-mode');
  for(let rootIndex=0;rootIndex<goSlideRoots.length;rootIndex++){
    const root=goSlideRoots[rootIndex];
    const body=directChildWithClass(root,'gc-body'),footer=directChildWithClass(root,'gc-footer');
    if(!isDisplayed(root))continue;
    const kind=!footer?'slide_or_slide_region':directChildWithClass(footer,'gc-drag-slide-bar')?'slide':'slide_region';
    const instance=nextInstance('go-captcha');
    mounted('go-captcha',kind,instance);
    if(!body||!footer||!isDisplayed(body)||!isDisplayed(footer)){
      append(out.diagnostics,'go-captcha '+kind+' controls are not completely mounted or displayed');
      continue;
    }
    let backgroundElement=queryOne(body,'img.gc-picture');
    if(!backgroundElement)backgroundElement=queryOne(body,'.gc-picture img');
    const background=readImg(backgroundElement,false);
    const puzzle=readImg(queryOne(body,'.gc-tile img'),false);
    if(!background||!puzzle){append(out.diagnostics,'go-captcha '+kind+' is missing a usable '+(!background&&!puzzle?'background and puzzle':!background?'background':'puzzle')+' source');continue;}
    detected('go-captcha',kind,instance);
    addImgSource('go-captcha',kind,instance,'background',background,'.gc-body > .gc-picture');
    addImgSource('go-captcha',kind,instance,'puzzle',puzzle,'.gc-body > .gc-tile img');
  }

  // AJ-Captcha blockPuzzle only: require its move/sub-block structure too.
  const ajPanels=queryAll('.verify-img-panel');
  for(let panelIndex=0;panelIndex<ajPanels.length;panelIndex++){
    const panel=ajPanels[panelIndex];
    providerSeen('aj-captcha');
    const imageOut=parentElementOf(panel),scope=parentElementOf(imageOut);
    if(!imageOut||!scope||!hasClass(imageOut,'verify-img-out')
      ||directChildWithClass(imageOut,'verify-img-panel')!==panel
      ||directChildWithClass(scope,'verify-img-out')!==imageOut)continue;
    const bar=directChildWithClass(scope,'verify-bar-area');
    if(!bar||!isDisplayed(panel)||!isDisplayed(bar))continue;
    const move=queryOne(bar,'.verify-move-block'),sub=queryOne(move,'.verify-sub-block');
    if(!move||!sub)continue;
    const kind='block_puzzle',instance=nextInstance('aj-captcha');
    mounted('aj-captcha',kind,instance);
    let background=queryOne(panel,'.backImg')||queryOne(panel,'.back-img');
    if(!background){
      try{
        const children=childrenOf(panel)||[];
        for(let childIndex=0;childIndex<children.length;childIndex++){
          const child=children[childIndex];
          if(lowerString(child&&child.tagName||'')==='img'){background=child;break;}
        }
      }catch(_error){}
      if(!background)background=queryOne(panel,'img');
    }
    const backgroundSource=readImg(background,true);
    const puzzleSource=readImg(queryOne(sub,'.bock-backImg')||queryOne(sub,'img'),true);
    if(!backgroundSource||!puzzleSource){append(out.diagnostics,'aj-captcha block_puzzle is missing a usable '+(!backgroundSource&&!puzzleSource?'background and puzzle':!backgroundSource?'background':'puzzle')+' source');continue;}
    detected('aj-captcha',kind,instance);
    addImgSource('aj-captcha',kind,instance,'background',backgroundSource,'.verify-img-panel > img');
    addImgSource('aj-captcha',kind,instance,'puzzle',puzzleSource,'.verify-bar-area .verify-sub-block img');
  }

  // slider-captcha-js server mode appends two direct img children; local mode
  // appends bg/cut/piece canvases in that order. Export only bg and piece layers.
  const sliderStages=queryAll('.slider-captcha-stage');
  for(let stageIndex=0;stageIndex<sliderStages.length;stageIndex++){
    const stage=sliderStages[stageIndex];
    providerSeen('slider-captcha-js');
    let parent=parentElementOf(stage);
    const bar=parent&&directChildWithClass(parent,'slider-captcha-bar');
    if(!parent||parentElementOf(stage)!==parent
      ||directChildWithClass(parent,'slider-captcha-stage')!==stage||!bar)continue;
    if(!isDisplayed(stage))continue;
    const instance=nextInstance('slider-captcha-js');
    mounted('slider-captcha-js','slider',instance);
    if(!isDisplayed(bar)||!queryOne(bar,'.slider-captcha-track')
      ||!queryOne(bar,'.slider-captcha-thumb')||!queryOne(bar,'.slider-captcha-status')){
      append(out.diagnostics,'slider-captcha-js has a visible stage but its slider controls are not completely mounted');
      continue;
    }
    const direct=[],images=[],canvases=[];
    try{
      const children=childrenOf(stage)||[];
      for(let childIndex=0;childIndex<children.length;childIndex++){
        const child=children[childIndex],tag=lowerString(child&&child.tagName||'');
        append(direct,child);
        if(tag==='img')append(images,child);
        else if(tag==='canvas')append(canvases,child);
      }
    }catch(_error){}
    if(images.length>=2){
      const background=readImg(images[0],false),puzzle=readImg(images[1],false);
      if(background&&puzzle){
        detected('slider-captcha-js','slider',instance);
        addImgSource('slider-captcha-js','slider',instance,'background',background,'.slider-captcha-stage > img:nth-of-type(1)');
        addImgSource('slider-captcha-js','slider',instance,'puzzle',puzzle,'.slider-captcha-stage > img:nth-of-type(2)');
        continue;
      }
    }
    if(canvases.length<3){append(out.diagnostics,'slider-captcha-js slider has neither a complete server image pair nor three local canvas layers');continue;}
    detected('slider-captcha-js','slider',instance);
    const background=canvases[0];
    if(background&&!canvasHasPixels(background)){
      try{
        const lookup=globalThis.__obscuraCaptchaCanvasSource;
        const provenance=typeof lookup==='function'?lookup(background):null;
        if(provenance&&provenance.source){
          add('slider-captcha-js','slider',instance,'background',provenance.source,provenance.resolved||'','preload','.slider-captcha-stage > canvas:nth-of-type(1)',provenance.capturedBytesSafe);
        }
      }catch(error){append(out.diagnostics,'slider-captcha-js background provenance lookup failed: '+stringify(error&&error.message||error));}
    }
    const canvasIndexes=[0,2],canvasRoles=['background','puzzle'];
    for(let canvasIndex=0;canvasIndex<canvasIndexes.length;canvasIndex++){
      const index=canvasIndexes[canvasIndex],role=canvasRoles[canvasIndex];
      const canvas=canvases[index];if(!canvas)continue;
      try{
        if(index===2){
          append(out.diagnostics,'slider-captcha-js puzzle canvas is unsupported because local drawImage/clip rendering is incomplete');
          continue;
        }
        const hasPixels=canvasHasPixels(canvas);
        if(index===0&&!hasPixels&&out.images.some(image=>image.instance===instance&&image.role==='background'&&image.evidence==='preload'))continue;
        if(!hasPixels){
          append(out.diagnostics,'slider-captcha-js '+role+' canvas is blank; generated local-canvas graphic is unavailable');
          continue;
        }
        const source=canvas.toDataURL('image/png');
        if(source&&source!=='data:,')add('slider-captcha-js','slider',instance,role,source,'','canvas','.slider-captcha-stage > canvas:nth-of-type('+(index+1)+')');
      }catch(error){append(out.diagnostics,'slider-captcha-js '+role+' canvas export failed: '+stringify(error&&error.message||error));}
    }
  }
  return out;
})()"#;

#[cfg(test)]
mod tests {
    use super::*;
    use obscura_net::ResourceType;
    use std::sync::Arc;

    const PIXEL: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

    fn resource(url: &str, body: Vec<u8>, content_type: &str) -> CapturedResource {
        CapturedResource {
            requested_url: Url::parse(url).unwrap(),
            final_url: Url::parse(url).unwrap(),
            method: "GET".to_string(),
            resource_type: ResourceType::Fetch,
            document_generation: 1,
            frame_id: 0,
            initiator: Some(Url::parse("https://example.test/page").unwrap()),
            status: 200,
            request_headers: HashMap::new(),
            response_headers: HashMap::from([(
                "content-type".to_string(),
                content_type.to_string(),
            )]),
            redirected_from: Vec::new(),
            body,
        }
    }

    fn raw_page(name: &str) -> Page {
        let context = Arc::new(crate::BrowserContext::with_storage_and_network(
            name.to_string(),
            None,
            false,
            None,
            None,
            true,
        ));
        Page::new(name.to_string(), context)
    }

    fn page(name: &str) -> Page {
        let mut page = raw_page(name);
        install_captcha_capture_preload(&mut page);
        page
    }

    fn data_html(html: &str) -> String {
        format!("data:text/html;base64,{}", BASE64.encode(html))
    }

    fn tianai_api_capture() -> ResourceCapture {
        let challenge = serde_json::to_vec(&serde_json::json!({
            "code": 200,
            "data": {
                "type": "SLIDER",
                "backgroundImage": format!("data:image/png;base64,{PIXEL}"),
                "templateImage": format!("data:image/png;base64,{PIXEL}")
            }
        }))
        .unwrap();
        ResourceCapture {
            document_generation: 0,
            resources: vec![resource(
                "https://example.test/captcha/get",
                challenge,
                "application/json",
            )],
            total_bytes: 1,
            omitted_resources: 0,
            omitted_bytes: 0,
        }
    }

    fn slider_captcha_api_capture() -> ResourceCapture {
        let challenge = serde_json::to_vec(&serde_json::json!({
            "bgUrl": format!("data:image/png;base64,{PIXEL}"),
            "puzzleUrl": format!("data:image/png;base64,{PIXEL}")
        }))
        .unwrap();
        ResourceCapture {
            document_generation: 0,
            resources: vec![resource(
                "https://example.test/slider/challenge",
                challenge,
                "application/json",
            )],
            total_bytes: 1,
            omitted_resources: 0,
            omitted_bytes: 0,
        }
    }

    #[test]
    fn data_uri_decoder_accepts_base64_and_percent_encoded_svg() {
        let (mime, png) = decode_data_uri(&format!("data:image/png;base64,{PIXEL}")).unwrap();
        assert_eq!(mime, "image/png");
        assert_eq!(sniff_image_mime(&png), Some("image/png"));

        let (mime, svg) =
            decode_data_uri("data:image/svg+xml,%3Csvg%20xmlns='x'%3E%3C/svg%3E").unwrap();
        assert_eq!(mime, "image/svg+xml");
        assert!(String::from_utf8(svg).unwrap().starts_with("<svg"));

        let (mime, mixed_case) =
            decode_data_uri(&format!("DaTa:image/png;BaSe64,{PIXEL}")).unwrap();
        assert_eq!(mime, "image/png");
        assert_eq!(sniff_image_mime(&mixed_case), Some("image/png"));
    }

    #[test]
    fn aj_json_extracts_images_but_not_token_or_secret() {
        let json = serde_json::json!({
            "repCode": "0000",
            "repData": {
                "originalImageBase64": PIXEL,
                "jigsawImageBase64": PIXEL,
                "token": "do-not-export",
                "secretKey": "also-do-not-export"
            }
        });
        let captured = resource(
            "https://example.test/captcha/get",
            serde_json::to_vec(&json).unwrap(),
            "application/json",
        );
        let mut diagnostics = Vec::new();
        let groups = network_candidates(
            &ResourceCapture {
                document_generation: 1,
                resources: vec![captured],
                total_bytes: 1,
                omitted_resources: 0,
                omitted_bytes: 0,
            },
            CaptchaAdapter::AjCaptcha,
            &mut diagnostics,
        );
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 2);
        let serialized = format!("{groups:?}");
        assert!(!serialized.contains("do-not-export"));
        assert!(!serialized.contains("also-do-not-export"));
        assert!(groups[0]
            .iter()
            .all(|candidate| candidate.source.starts_with("data:image/png;base64,")));
    }

    #[test]
    fn tianai_json_requires_successful_complete_slider_envelope() {
        let success = serde_json::json!({
            "code": 200,
            "data": {
                "type": "SLIDER",
                "backgroundImage": format!("data:image/png;base64,{PIXEL}"),
                "templateImage": format!("data:image/png;base64,{PIXEL}")
            }
        });
        let rejected = [
            serde_json::json!({
                "code": 500,
                "data": success["data"].clone()
            }),
            serde_json::json!({
                "code": 200,
                "data": {"type": "ROTATE", "backgroundImage": "x", "templateImage": "y"}
            }),
            serde_json::json!({
                "code": 200,
                "data": {"type": "SLIDER", "backgroundImage": "x"}
            }),
        ];

        let capture_for = |value: &Value| ResourceCapture {
            document_generation: 1,
            resources: vec![resource(
                "https://example.test/captcha/get",
                serde_json::to_vec(value).unwrap(),
                "application/json",
            )],
            total_bytes: 1,
            omitted_resources: 0,
            omitted_bytes: 0,
        };
        let mut diagnostics = Vec::new();
        let groups = network_candidates(
            &capture_for(&success),
            CaptchaAdapter::Tianai,
            &mut diagnostics,
        );
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 2);
        for value in &rejected {
            assert!(network_candidates(
                &capture_for(value),
                CaptchaAdapter::Tianai,
                &mut diagnostics
            )
            .is_empty());
        }
    }

    #[test]
    fn api_only_fallback_is_fenced_by_unrecognized_same_endpoint_response() {
        let endpoint = "https://example.test/captcha/get?t=1";
        let success = serde_json::json!({
            "code": 200,
            "data": {
                "type": "SLIDER",
                "backgroundImage": format!("data:image/png;base64,{PIXEL}"),
                "templateImage": format!("data:image/png;base64,{PIXEL}")
            }
        });
        let valid = resource(
            endpoint,
            serde_json::to_vec(&success).unwrap(),
            "application/json",
        );
        let mut failed = resource(
            "https://example.test/captcha/get?t=2",
            b"refresh failed".to_vec(),
            "text/plain",
        );
        failed.status = 500;
        let capture = ResourceCapture {
            document_generation: 1,
            resources: vec![valid.clone(), failed],
            total_bytes: 1,
            omitted_resources: 0,
            omitted_bytes: 0,
        };
        let groups = network_candidates(&capture, CaptchaAdapter::Tianai, &mut Vec::new());
        let valid_indices = groups
            .iter()
            .flat_map(|group| group.iter().filter_map(|candidate| candidate.capture_index))
            .collect::<HashSet<_>>();
        assert_eq!(valid_indices, HashSet::from([0]));
        assert!(unrecognized_same_endpoint_response_exists(
            &capture,
            &valid_indices
        ));

        let repeated = ResourceCapture {
            resources: vec![valid.clone(), valid],
            ..capture
        };
        let groups = network_candidates(&repeated, CaptchaAdapter::Tianai, &mut Vec::new());
        let valid_indices = groups
            .iter()
            .flat_map(|group| group.iter().filter_map(|candidate| candidate.capture_index))
            .collect::<HashSet<_>>();
        assert_eq!(valid_indices, HashSet::from([0, 1]));
        assert!(!unrecognized_same_endpoint_response_exists(
            &repeated,
            &valid_indices
        ));
    }

    #[test]
    fn json_objects_remain_separate_complete_pairs() {
        let json = serde_json::json!([
            {"bgUrl": "https://example.test/old-bg.png", "puzzleUrl": "https://example.test/old-piece.png"},
            {"bgUrl": "https://example.test/new-bg.png", "puzzleUrl": "https://example.test/new-piece.png"}
        ]);
        let capture = ResourceCapture {
            document_generation: 1,
            resources: vec![resource(
                "https://example.test/slider/data",
                serde_json::to_vec(&json).unwrap(),
                "application/json",
            )],
            total_bytes: 1,
            omitted_resources: 0,
            omitted_bytes: 0,
        };
        let groups = network_candidates(&capture, CaptchaAdapter::SliderCaptchaJs, &mut Vec::new());
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|group| group.len() == 2));
        assert!(groups.iter().all(|group| has_complete_pair(group)));
    }

    #[test]
    fn go_captcha_url_fields_are_not_wrapped_as_base64() {
        let json = serde_json::json!({
            "tile_x": 12,
            "image_base64": "https://example.test/background.png",
            "tile_base64": "/captcha/puzzle.png"
        });
        let capture = ResourceCapture {
            document_generation: 1,
            resources: vec![resource(
                "https://example.test/captcha/get",
                serde_json::to_vec(&json).unwrap(),
                "application/json",
            )],
            total_bytes: 1,
            omitted_resources: 0,
            omitted_bytes: 0,
        };
        let groups = network_candidates(&capture, CaptchaAdapter::GoCaptcha, &mut Vec::new());
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0][0].source, "https://example.test/background.png");
        assert_eq!(groups[0][1].source, "/captcha/puzzle.png");
        assert!(!groups[0]
            .iter()
            .any(|item| item.source.contains(";base64,")));

        let relative_json = serde_json::json!({
            "tile_x": 12,
            "image_base64": "background.png",
            "tile_base64": "piece.png"
        });
        let relative_capture = ResourceCapture {
            document_generation: 1,
            resources: vec![resource(
                "https://example.test/captcha/get",
                serde_json::to_vec(&relative_json).unwrap(),
                "application/json",
            )],
            total_bytes: 1,
            omitted_resources: 0,
            omitted_bytes: 0,
        };
        let relative_groups = network_candidates(
            &relative_capture,
            CaptchaAdapter::GoCaptcha,
            &mut Vec::new(),
        );
        assert_eq!(relative_groups.len(), 1);
        assert_eq!(relative_groups[0][0].source, "background.png");
        assert_eq!(relative_groups[0][1].source, "piece.png");
        assert!(relative_groups[0]
            .iter()
            .all(|candidate| candidate.source_kind == CaptchaSourceKind::RelativeUrl));
        assert_eq!(
            relative_groups[0][0].resolved_url.as_deref(),
            Some("https://example.test/background.png")
        );
        assert_eq!(
            relative_groups[0][1].resolved_url.as_deref(),
            Some("https://example.test/piece.png")
        );
    }

    #[test]
    fn captured_image_lookup_rejects_ambiguous_or_omitted_same_url_bytes() {
        let mut old = resource(
            "https://example.test/reused.png",
            vec![0xff, 0xd8, 0xff, 1],
            "image/jpeg",
        );
        old.frame_id = 7;
        let mut new = resource(
            "https://example.test/reused.png",
            BASE64.decode(PIXEL).unwrap(),
            "image/png",
        );
        new.frame_id = 7;
        let repeated_new = new.clone();
        let capture = ResourceCapture {
            document_generation: 1,
            resources: vec![old, new],
            total_bytes: 1,
            omitted_resources: 0,
            omitted_bytes: 0,
        };
        assert!(find_captured_image(&capture, 7, "https://example.test/reused.png").is_err());
        assert!(
            find_captured_image(&capture, 0, "https://example.test/reused.png")
                .unwrap()
                .is_none()
        );

        let identical = ResourceCapture {
            document_generation: 1,
            resources: vec![repeated_new.clone(), repeated_new.clone()],
            total_bytes: 1,
            omitted_resources: 0,
            omitted_bytes: 0,
        };
        let matched = find_captured_image(&identical, 7, "https://example.test/reused.png")
            .unwrap()
            .unwrap();
        assert_eq!(sniff_image_mime(&matched.body), Some("image/png"));

        let omitted = ResourceCapture {
            omitted_resources: 1,
            ..identical
        };
        assert!(find_captured_image(&omitted, 7, "https://example.test/reused.png").is_err());

        let mut failed = resource(
            "https://example.test/reused.png",
            b"image refresh failed".to_vec(),
            "text/plain",
        );
        failed.frame_id = 7;
        failed.status = 500;
        let failed_refresh = ResourceCapture {
            document_generation: 1,
            resources: vec![repeated_new, failed],
            total_bytes: 1,
            omitted_resources: 0,
            omitted_bytes: 0,
        };
        assert!(
            find_captured_image(&failed_refresh, 7, "https://example.test/reused.png").is_err()
        );

        let candidate = Candidate {
            adapter: CaptchaAdapter::Tianai,
            challenge_kind: "slider".to_string(),
            challenge_id: "tianai-0".to_string(),
            role: CaptchaImageRole::Background,
            source_kind: CaptchaSourceKind::HttpUrl,
            evidence_kind: CaptchaEvidenceKind::DomImage,
            source: "https://example.test/reused.png".to_string(),
            resolved_url: Some("https://example.test/reused.png".to_string()),
            frame_id: 7,
            frame_url: "https://example.test/".to_string(),
            response_url: None,
            selector: None,
            capture_index: None,
            captured_bytes_safe: true,
        };
        let mut diagnostics = Vec::new();
        let mut remaining = MAX_MATERIALIZED_BYTES;
        let mut evidence_incomplete = false;
        let artifact = materialize_candidate(
            candidate,
            &failed_refresh,
            &mut diagnostics,
            &mut remaining,
            &mut evidence_incomplete,
        );
        assert!(artifact.bytes.is_none());
        assert!(evidence_incomplete);
    }

    #[test]
    fn pending_dom_image_does_not_reuse_completed_same_url_bytes() {
        let url = "https://example.test/reused.png";
        let candidate = Candidate {
            adapter: CaptchaAdapter::Tianai,
            challenge_kind: "slider".to_string(),
            challenge_id: "tianai-0".to_string(),
            role: CaptchaImageRole::Background,
            source_kind: CaptchaSourceKind::HttpUrl,
            evidence_kind: CaptchaEvidenceKind::DomImage,
            source: url.to_string(),
            resolved_url: Some(url.to_string()),
            frame_id: 0,
            frame_url: "https://example.test/".to_string(),
            response_url: None,
            selector: Some("#tianai-captcha-slider-bg-img".to_string()),
            capture_index: None,
            captured_bytes_safe: false,
        };
        let capture = ResourceCapture {
            document_generation: 1,
            resources: vec![resource(url, BASE64.decode(PIXEL).unwrap(), "image/png")],
            total_bytes: 1,
            omitted_resources: 0,
            omitted_bytes: 0,
        };
        let mut diagnostics = Vec::new();
        let mut remaining = MAX_MATERIALIZED_BYTES;
        let mut evidence_incomplete = false;

        let artifact = materialize_candidate(
            candidate,
            &capture,
            &mut diagnostics,
            &mut remaining,
            &mut evidence_incomplete,
        );

        assert!(artifact.bytes.is_none());
        assert_eq!(remaining, MAX_MATERIALIZED_BYTES);
        assert!(!evidence_incomplete);
        assert!(diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("captured same-URL bytes were not reused")));
    }

    #[test]
    fn declared_image_mime_does_not_accept_spoofed_bytes() {
        let candidate = Candidate {
            adapter: CaptchaAdapter::AjCaptcha,
            challenge_kind: "block_puzzle".to_string(),
            challenge_id: "aj-captcha-0".to_string(),
            role: CaptchaImageRole::Background,
            source_kind: CaptchaSourceKind::DataUri,
            evidence_kind: CaptchaEvidenceKind::DomImage,
            source: "data:image/png;base64,AA==".to_string(),
            resolved_url: None,
            frame_id: 0,
            frame_url: "https://example.test/".to_string(),
            response_url: None,
            selector: None,
            capture_index: None,
            captured_bytes_safe: true,
        };
        let capture = ResourceCapture {
            document_generation: 1,
            resources: Vec::new(),
            total_bytes: 0,
            omitted_resources: 0,
            omitted_bytes: 0,
        };
        let mut diagnostics = Vec::new();
        let mut remaining = MAX_MATERIALIZED_BYTES;
        let mut evidence_incomplete = false;
        let artifact = materialize_candidate(
            candidate,
            &capture,
            &mut diagnostics,
            &mut remaining,
            &mut evidence_incomplete,
        );
        assert!(artifact.bytes.is_none());
        assert!(artifact.mime_type.is_none());
        assert!(!evidence_incomplete);
    }

    #[test]
    fn merged_dom_challenge_accepts_single_correlated_api_provenance() {
        let dom = Candidate {
            adapter: CaptchaAdapter::SliderCaptchaJs,
            challenge_kind: "slider".to_string(),
            challenge_id: "slider-captcha-js-0".to_string(),
            role: CaptchaImageRole::Background,
            source_kind: CaptchaSourceKind::HttpUrl,
            evidence_kind: CaptchaEvidenceKind::DomImage,
            source: "https://example.test/reused.png".to_string(),
            resolved_url: Some("https://example.test/reused.png".to_string()),
            frame_id: 0,
            frame_url: "https://example.test/".to_string(),
            response_url: None,
            selector: Some(".slider-captcha-stage > img".to_string()),
            capture_index: None,
            captured_bytes_safe: true,
        };
        let mut api = dom.clone();
        api.evidence_kind = CaptchaEvidenceKind::ApiResponse;
        api.response_url = Some("https://example.test/challenge".to_string());
        api.selector = None;

        let merged = merge_candidates(vec![dom, api]);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].response_url.as_deref(),
            Some("https://example.test/challenge")
        );
        assert_eq!(merged[0].evidence_kind, CaptchaEvidenceKind::DomImage);

        let mut pending_dom = merged[0].clone();
        pending_dom.response_url = None;
        pending_dom.captured_bytes_safe = false;
        let mut stale_api = pending_dom.clone();
        stale_api.evidence_kind = CaptchaEvidenceKind::ApiResponse;
        stale_api.response_url = Some("https://example.test/stale-challenge".to_string());
        stale_api.captured_bytes_safe = true;
        let pending_merge = merge_candidates(vec![pending_dom, stale_api]);
        assert_eq!(pending_merge.len(), 1);
        assert!(pending_merge[0].response_url.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn live_dom_scan_recognizes_all_four_provider_roots() {
        let image = format!("data:image/png;base64,{PIXEL}");
        let html = format!(
            r#"<!doctype html><body>
          <div id="tianai-captcha-parent"><div id="tianai-captcha" class="tianai-captcha-slider">
            <img id="tianai-captcha-slider-bg-img" src="{image}">
            <img id="tianai-captcha-slider-move-img" src="{image}">
          </div></div>
          <div class="go-captcha gc-slide-mode gc-wrapper"><div class="gc-body">
            <img class="gc-picture" src="{image}"><div class="gc-tile"><img src="{image}"></div>
          </div><div class="gc-footer"><div class="gc-drag-slide-bar"></div></div></div>
          <div class="aj"><div class="verify-img-out"><div class="verify-img-panel"><img class="backImg" src="{image}"></div></div>
            <div class="verify-bar-area"><div class="verify-move-block"><div class="verify-sub-block"><img class="bock-backImg" src="{image}"></div></div></div></div>
          <div class="slider-root"><div class="slider-captcha-stage"><img src="{image}"><img src="{image}"></div>
            <div class="slider-captcha-bar"><div class="slider-captcha-track"></div><div class="slider-captcha-thumb"></div><div class="slider-captcha-status"></div></div></div>
        </body>"#
        );
        let mut page = page("captcha-dom-fixture");
        page.navigate(&data_html(&html)).await.unwrap();
        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        let adapters: HashSet<_> = scan.candidates.iter().map(|item| item.adapter).collect();
        assert_eq!(
            adapters,
            HashSet::from([
                CaptchaAdapter::Tianai,
                CaptchaAdapter::GoCaptcha,
                CaptchaAdapter::AjCaptcha,
                CaptchaAdapter::SliderCaptchaJs,
            ])
        );
        assert_eq!(scan.candidates.len(), 8);
        assert_eq!(scan.expected_groups.len(), 4);
        assert!(!scan.incomplete);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hidden_provider_roots_do_not_revive_stale_challenges() {
        let image = format!("data:image/png;base64,{PIXEL}");
        let tianai = |hidden: &str| {
            format!(
                r#"<div {hidden}><div id="tianai-captcha-parent"><div id="tianai-captcha" class="tianai-captcha-slider"><img id="tianai-captcha-slider-bg-img" src="{image}"><img id="tianai-captcha-slider-move-img" src="{image}"></div></div></div>"#
            )
        };
        let go = |hidden: &str| {
            format!(
                r#"<div {hidden}><div class="go-captcha gc-slide-mode gc-wrapper"><div class="gc-body"><img class="gc-picture" src="{image}"><div class="gc-tile"><img src="{image}"></div></div><div class="gc-footer"><div class="gc-drag-slide-bar"></div></div></div></div>"#
            )
        };
        let aj = |hidden: &str| {
            format!(
                r#"<div {hidden}><div class="aj"><div class="verify-img-out"><div class="verify-img-panel"><img class="backImg" src="{image}"></div></div><div class="verify-bar-area"><div class="verify-move-block"><div class="verify-sub-block"><img class="bock-backImg" src="{image}"></div></div></div></div></div>"#
            )
        };
        let slider = |hidden: &str| {
            format!(
                r#"<div {hidden}><div class="slider-root"><div class="slider-captcha-stage"><img src="{image}"><img src="{image}"></div><div class="slider-captcha-bar"><div class="slider-captcha-track"></div><div class="slider-captcha-thumb"></div><div class="slider-captcha-status"></div></div></div></div>"#
            )
        };
        let html = format!(
            "<body>{}{}{}{}{}{}{}{}</body>",
            tianai("hidden"),
            tianai(""),
            go("style=\"display:none\""),
            go(""),
            aj("style=\"visibility:hidden\""),
            aj(""),
            slider("style=\"opacity:0\""),
            slider("")
        );
        let mut page = page("captcha-hidden-roots-fixture");
        page.navigate(&data_html(&html)).await.unwrap();

        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        assert_eq!(scan.candidates.len(), 8, "{:#?}", scan.candidates);
        assert_eq!(scan.expected_groups.len(), 4);
        assert!(!scan.incomplete, "{:#?}", scan.diagnostics);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn aj_widget_scope_never_borrows_a_sibling_widgets_slider_bar() {
        let image = format!("data:image/png;base64,{PIXEL}");
        let html = format!(
            r#"<body><div class="shared">
          <div class="click-scope"><div class="verify-img-out"><div class="verify-img-panel"><img class="back-img" src="data:image/png;base64,AA=="></div></div></div>
          <div class="block-scope"><div class="verify-img-out"><div class="verify-img-panel"><img class="backImg" src="{image}"></div></div>
            <div class="verify-bar-area"><div class="verify-move-block"><div class="verify-sub-block"><img class="bock-backImg" src="{image}"></div></div></div></div>
        </div></body>"#
        );
        let mut page = page("captcha-aj-scope-fixture");
        page.navigate(&data_html(&html)).await.unwrap();

        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        assert_eq!(scan.candidates.len(), 2, "{:#?}", scan.candidates);
        assert_eq!(scan.expected_groups.len(), 1);
        assert!(scan
            .candidates
            .iter()
            .all(|candidate| !candidate.source.ends_with("AA==")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dom_image_bound_marks_many_visible_widgets_incomplete() {
        let image = format!("data:image/png;base64,{PIXEL}");
        let widget = format!(
            r#"<div class="go-captcha gc-slide-mode gc-wrapper"><div class="gc-body"><img class="gc-picture" src="{image}"><div class="gc-tile"><img src="{image}"></div></div><div class="gc-footer"><div class="gc-drag-slide-bar"></div></div></div>"#
        );
        let mut page = page("captcha-dom-bound-fixture");
        page.navigate(&data_html(&format!("<body>{}</body>", widget.repeat(17))))
            .await
            .unwrap();

        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        assert_eq!(scan.expected_groups.len(), 17);
        assert_eq!(scan.candidates.len(), MAX_DOM_ARTIFACTS);
        assert!(scan.incomplete);
        assert!(scan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("image bound")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provider_selectors_do_not_accept_unscoped_lookalikes() {
        let image = format!("data:image/png;base64,{PIXEL}");
        let html = format!(
            r#"<body>
          <img class="gc-picture backImg" src="{image}">
          <div class="verify-img-panel"><img src="{image}"></div>
          <div class="slider-captcha-stage"><img src="{image}"><img src="{image}"></div>
        </body>"#
        );
        let mut page = page("captcha-negative-fixture");
        page.navigate(&data_html(&html)).await.unwrap();
        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        assert!(scan.candidates.is_empty(), "{:#?}", scan.candidates);
        assert!(scan.detected.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn structurally_mounted_but_incomplete_slider_is_not_treated_as_absent() {
        let html = r#"<body><div id="tianai-captcha-parent">
          <div id="tianai-captcha" class="tianai-captcha-slider">
            <img id="tianai-captcha-slider-bg-img">
            <img id="tianai-captcha-slider-move-img">
          </div>
        </div></body>"#;
        let mut page = page("captcha-incomplete-mounted-fixture");
        page.navigate(&data_html(html)).await.unwrap();

        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        assert!(scan.scanned_frames.contains(&0));
        assert!(scan.mounted.contains(&(CaptchaAdapter::Tianai, 0)));
        assert!(!scan.detected.contains(&(CaptchaAdapter::Tianai, 0)));
        assert_eq!(scan.expected_groups.len(), 1);
        assert!(scan.candidates.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn complete_and_incomplete_widgets_remain_two_expected_groups() {
        let image = format!("data:image/png;base64,{PIXEL}");
        let html = format!(
            r#"<body>
          <div id="tianai-captcha-parent"><div id="tianai-captcha" class="tianai-captcha-slider"><img id="tianai-captcha-slider-bg-img" src="{image}"><img id="tianai-captcha-slider-move-img" src="{image}"></div></div>
          <div id="tianai-captcha-parent"><div id="tianai-captcha" class="tianai-captcha-slider"><img id="tianai-captcha-slider-bg-img" src="{image}"><img id="tianai-captcha-slider-move-img"></div></div>
        </body>"#
        );
        let mut page = page("captcha-mixed-completeness-fixture");
        page.navigate(&data_html(&html)).await.unwrap();

        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        assert_eq!(scan.expected_groups.len(), 2);
        assert_eq!(scan.candidates.len(), 2, "{:#?}", scan.candidates);
        assert!(!scan.incomplete);
        assert!(scan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("missing a usable puzzle source")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn structurally_partial_go_and_slider_widgets_remain_expected_groups() {
        let image = format!("data:image/png;base64,{PIXEL}");
        let html = format!(
            r#"<body>
          <div class="go-captcha gc-slide-mode gc-wrapper"><div class="gc-body"><img class="gc-picture" src="{image}"><div class="gc-tile"><img src="{image}"></div></div><div class="gc-footer"><div class="gc-drag-slide-bar"></div></div></div>
          <div class="go-captcha gc-slide-mode gc-wrapper"><div class="gc-body"></div></div>
          <div><div class="slider-captcha-stage"><img src="{image}"><img src="{image}"></div><div class="slider-captcha-bar"><div class="slider-captcha-track"></div><div class="slider-captcha-thumb"></div><div class="slider-captcha-status"></div></div></div>
          <div><div class="slider-captcha-stage"></div><div class="slider-captcha-bar"></div></div>
        </body>"#
        );
        let mut page = page("captcha-structurally-partial-groups");
        page.navigate(&data_html(&html)).await.unwrap();

        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        assert_eq!(scan.expected_groups.len(), 4);
        assert_eq!(
            scan.expected_groups
                .iter()
                .filter(|(adapter, _, _, _)| *adapter == CaptchaAdapter::GoCaptcha)
                .count(),
            2
        );
        assert_eq!(
            scan.expected_groups
                .iter()
                .filter(|(adapter, _, _, _)| *adapter == CaptchaAdapter::SliderCaptchaJs)
                .count(),
            2
        );
        assert_eq!(scan.candidates.len(), 4, "{:#?}", scan.candidates);
        assert!(scan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("go-captcha")
                && diagnostic.contains("not completely mounted")));
        assert!(scan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("slider-captcha-js")
                && diagnostic.contains("not completely mounted")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn same_provider_widgets_receive_distinct_challenge_ids() {
        let image = format!("data:image/png;base64,{PIXEL}");
        let widget = format!(
            r#"<div class="go-captcha gc-slide-mode gc-wrapper"><div class="gc-body">
              <img class="gc-picture" src="{image}"><div class="gc-tile"><img src="{image}"></div>
            </div><div class="gc-footer"><div class="gc-drag-slide-bar"></div></div></div>"#
        );
        let mut page = page("captcha-multi-instance-fixture");
        page.navigate(&data_html(&format!("<body>{widget}{widget}</body>")))
            .await
            .unwrap();

        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        let challenge_ids: HashSet<_> = scan
            .candidates
            .iter()
            .filter(|candidate| candidate.adapter == CaptchaAdapter::GoCaptcha)
            .map(|candidate| candidate.challenge_id.as_str())
            .collect();
        assert_eq!(scan.candidates.len(), 4);
        assert_eq!(challenge_ids.len(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relative_dom_sources_use_the_effective_document_base() {
        let html = r#"<base href="https://assets.example.test/captcha/">
          <div id="tianai-captcha" class="tianai-captcha-slider">
            <img id="tianai-captcha-slider-bg-img" src="images/background.png">
            <img id="tianai-captcha-slider-move-img" src="pieces/puzzle.png">
          </div>"#;
        let mut page = page("captcha-effective-base-fixture");
        page.navigate(&data_html(html)).await.unwrap();

        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        let urls = scan
            .candidates
            .iter()
            .filter_map(|candidate| candidate.resolved_url.as_deref())
            .collect::<HashSet<_>>();
        assert!(
            urls.contains("https://assets.example.test/captcha/images/background.png"),
            "{:#?}",
            scan.candidates
        );
        assert!(
            urls.contains("https://assets.example.test/captcha/pieces/puzzle.png"),
            "{:#?}",
            scan.candidates
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn preload_preserves_slider_local_background_source_when_canvas_is_blank() {
        let image = format!("data:image/png;base64,{PIXEL}");
        let html = format!(
            r#"<body><div class="slider-root">
              <div class="slider-captcha-stage" id="stage"></div>
              <div class="slider-captcha-bar"><div class="slider-captcha-track"></div><div class="slider-captcha-thumb"></div><div class="slider-captcha-status"></div></div>
            </div><script>
              const canvas=document.createElement('canvas');
              document.getElementById('stage').append(canvas,document.createElement('canvas'),document.createElement('canvas'));
              const image=new Image();image.src={};
              canvas.getContext('2d').drawImage(image,0,0);
            </script></body>"#,
            serde_json::to_string(&image).unwrap()
        );
        let mut page = page("captcha-slider-local-fixture");
        install_captcha_capture_preload(&mut page);
        page.navigate(&data_html(&html)).await.unwrap();

        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        let backgrounds = scan
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.adapter == CaptchaAdapter::SliderCaptchaJs
                    && candidate.role == CaptchaImageRole::Background
            })
            .collect::<Vec<_>>();
        assert_eq!(backgrounds.len(), 1, "{:#?}", scan.candidates);
        assert_eq!(backgrounds[0].source, image);
        assert_eq!(
            backgrounds[0].evidence_kind,
            CaptchaEvidenceKind::ImageProvenance
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn non_slide_provider_modes_are_rejected() {
        let image = format!("data:image/png;base64,{PIXEL}");
        let html = format!(
            r#"<body>
          <div id="tianai-captcha-parent"><div id="tianai-captcha" class="tianai-captcha-rotate">
            <img id="tianai-captcha-slider-bg-img" src="{image}">
            <img id="tianai-captcha-slider-move-img" src="{image}">
          </div></div>
          <div class="go-captcha gc-wrapper gc-click-mode"></div>
          <div class="aj-click"><div class="verify-img-out"><div class="verify-img-panel"><img class="back-img" src="{image}"></div></div>
            <div class="verify-bar-area"></div></div>
        </body>"#
        );
        let mut page = page("captcha-non-slide-fixture");
        page.navigate(&data_html(&html)).await.unwrap();

        let scan = scan_live_documents(&mut page, Duration::from_secs(2));
        assert!(scan.candidates.is_empty(), "{:#?}", scan.candidates);
        assert!(scan.detected.is_empty());
        assert!(scan.provider_seen.contains(&(CaptchaAdapter::Tianai, 0)));
        assert!(scan.provider_seen.contains(&(CaptchaAdapter::GoCaptcha, 0)));
        assert!(scan.provider_seen.contains(&(CaptchaAdapter::AjCaptcha, 0)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recognized_provider_dom_suppresses_stale_api_fallback() {
        let mut absent = page("captcha-api-only-control");
        absent.navigate(&data_html("<body></body>")).await.unwrap();
        absent.replace_resource_capture_for_test(tianai_api_capture());
        let extraction =
            extract_captcha(&mut absent, CaptchaAdapter::Tianai, Duration::from_secs(2)).unwrap();
        assert_eq!(
            extraction.artifacts.len(),
            2,
            "{:#?}",
            extraction.diagnostics
        );
        assert!(!extraction.evidence_complete);

        let rotate_dom = r#"
          <div hidden><div id="tianai-captcha-parent"><div id="tianai-captcha" class="tianai-captcha-slider"></div></div></div>
          <div id="tianai-captcha" class="tianai-captcha-rotate"></div>
        "#;
        let mut rotate = page("captcha-unsupported-provider-fallback");
        rotate.navigate(&data_html(rotate_dom)).await.unwrap();
        rotate.replace_resource_capture_for_test(tianai_api_capture());
        let extraction =
            extract_captcha(&mut rotate, CaptchaAdapter::Tianai, Duration::from_secs(2)).unwrap();
        assert!(
            extraction.artifacts.is_empty(),
            "{:#?}",
            extraction.artifacts
        );
        assert_eq!(extraction.challenge_groups, 0);

        let hidden_dom = r#"<div hidden><div id="tianai-captcha-parent"><div id="tianai-captcha" class="tianai-captcha-slider"></div></div></div>"#;
        let mut hidden = page("captcha-hidden-residual-fallback");
        hidden.navigate(&data_html(hidden_dom)).await.unwrap();
        hidden.replace_resource_capture_for_test(tianai_api_capture());
        let extraction =
            extract_captcha(&mut hidden, CaptchaAdapter::Tianai, Duration::from_secs(2)).unwrap();
        assert!(
            extraction.artifacts.is_empty(),
            "{:#?}",
            extraction.artifacts
        );
        assert_eq!(extraction.challenge_groups, 0);

        let partial_slider = r#"<div><div class="slider-captcha-stage"></div><div class="slider-captcha-bar"></div></div>"#;
        let mut slider = page("captcha-partial-slider-fallback");
        slider.navigate(&data_html(partial_slider)).await.unwrap();
        slider.replace_resource_capture_for_test(slider_captcha_api_capture());
        let extraction = extract_captcha(
            &mut slider,
            CaptchaAdapter::SliderCaptchaJs,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(
            extraction.artifacts.is_empty(),
            "{:#?}",
            extraction.artifacts
        );
        assert_eq!(extraction.challenge_groups, 1);

        let mut stage_only = page("captcha-residual-slider-stage-fallback");
        stage_only
            .navigate(&data_html(r#"<div class="slider-captcha-stage"></div>"#))
            .await
            .unwrap();
        stage_only.replace_resource_capture_for_test(slider_captcha_api_capture());
        let extraction = extract_captcha(
            &mut stage_only,
            CaptchaAdapter::SliderCaptchaJs,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(
            extraction.artifacts.is_empty(),
            "{:#?}",
            extraction.artifacts
        );
        assert_eq!(extraction.challenge_groups, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn extraction_without_trusted_preload_fails_closed() {
        let mut page = raw_page("captcha-missing-preload-fail-closed");
        page.navigate(&data_html("<body></body>")).await.unwrap();
        page.replace_resource_capture_for_test(tianai_api_capture());

        let extraction =
            extract_captcha(&mut page, CaptchaAdapter::Tianai, Duration::from_secs(2)).unwrap();
        assert!(
            extraction.artifacts.is_empty(),
            "{:#?}",
            extraction.artifacts
        );
        assert!(!extraction.evidence_complete);
        assert!(extraction
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("trusted builtin snapshot")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transport_failure_fencing_api_only_pair_marks_evidence_incomplete() {
        let mut page = page("captcha-api-only-transport-failure");
        page.navigate(&data_html("<body></body>")).await.unwrap();
        page.replace_resource_capture_for_test(tianai_api_capture());
        page.add_transport_failure_for_test();

        let extraction =
            extract_captcha(&mut page, CaptchaAdapter::Tianai, Duration::from_secs(2)).unwrap();
        assert!(extraction.artifacts.is_empty());
        assert_eq!(extraction.challenge_groups, 0);
        assert!(!extraction.evidence_complete);
        assert!(extraction
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("transport request failed")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn page_global_and_array_iterator_tampering_cannot_revive_stale_api_pair() {
        let html = r#"<div id="tianai-captcha" class="tianai-captcha-rotate"></div>
          <script>
            globalThis.String=()=>"https://example.test/stale.png";
            globalThis.Number=()=>1;
            Array.prototype[Symbol.iterator]=function(){
              return {next(){return {done:true}}};
            };
          </script>"#;
        let mut page = page("captcha-page-global-tampering");
        page.navigate(&data_html(html)).await.unwrap();
        page.replace_resource_capture_for_test(tianai_api_capture());

        let extraction =
            extract_captcha(&mut page, CaptchaAdapter::Tianai, Duration::from_secs(2)).unwrap();
        assert!(
            extraction.artifacts.is_empty(),
            "{:#?}",
            extraction.artifacts
        );
        assert_eq!(extraction.challenge_groups, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hidden_parent_remains_hidden_after_dom_and_cssom_tampering() {
        let image = format!("data:image/png;base64,{PIXEL}");
        let html = format!(
            r#"<div style="display:none"><div id="tianai-captcha" class="tianai-captcha-slider">
              <img id="tianai-captcha-slider-bg-img" src="{image}">
              <img id="tianai-captcha-slider-move-img" src="{image}">
            </div></div><script>
              const nativeParse=JSON.parse;
              JSON.parse=(value)=>{{
                const parsed=nativeParse(value);
                return parsed&&!Array.isArray(parsed)&&typeof parsed==='object'
                  ?{{display:'block',visibility:'visible',opacity:'1'}}:parsed;
              }};
              Object.prototype.hasOwnProperty=()=>false;
              CSSStyleDeclaration.prototype.getPropertyValue=()=>'';
              Object.defineProperty(Node.prototype,'parentElement',{{
                configurable:true,get(){{return null}}
              }});
              const active=document.getElementById('tianai-captcha');
              const background=document.getElementById('tianai-captcha-slider-bg-img');
              const puzzle=document.getElementById('tianai-captcha-slider-move-img');
              active._shadowParent=document;
              background._shadowParent=document;
              puzzle._shadowParent=document;
            </script>"#
        );
        let mut page = page("captcha-hidden-parent-tampering");
        page.navigate(&data_html(&html)).await.unwrap();
        page.replace_resource_capture_for_test(tianai_api_capture());

        let extraction =
            extract_captcha(&mut page, CaptchaAdapter::Tianai, Duration::from_secs(2)).unwrap();
        assert!(
            extraction.artifacts.is_empty(),
            "{:#?}",
            extraction.artifacts
        );
        assert_eq!(extraction.challenge_groups, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn child_frame_uses_preloaded_tree_walker_after_page_tampering() {
        let html = r#"<body><iframe srcdoc='<script>
          Document.prototype.createTreeWalker=function(){for(;;){}}
        </script>'></iframe></body>"#;
        let mut page = page("captcha-frame-watchdog-fixture");
        page.navigate(&data_html(html)).await.unwrap();
        assert_eq!(page.frame_snapshots().len(), 1);

        let started = std::time::Instant::now();
        let scan = scan_live_documents(&mut page, Duration::from_millis(50));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!scan.incomplete, "{:#?}", scan.diagnostics);
        assert!(!scan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("timed out")));
    }
}
