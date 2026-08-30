use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Idle,
    Loading,
    DomContentLoaded,
    Loaded,
    NetworkIdle,
    Failed,
}

impl LifecycleState {
    pub fn is_loading(&self) -> bool {
        matches!(self, LifecycleState::Loading)
    }

    pub fn is_loaded(&self) -> bool {
        matches!(self, LifecycleState::Loaded | LifecycleState::NetworkIdle)
    }

    pub fn is_network_idle(&self) -> bool {
        matches!(self, LifecycleState::NetworkIdle)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitUntil {
    Commit,
    Load,
    DomContentLoaded,
    NetworkIdle0,
    NetworkIdle2,
    CaptureReady,
}

impl WaitUntil {
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "commit" => WaitUntil::Commit,
            "domcontentloaded" => WaitUntil::DomContentLoaded,
            "networkidle0" | "networkidle" => WaitUntil::NetworkIdle0,
            "networkidle2" => WaitUntil::NetworkIdle2,
            "capture-ready" | "captureready" => WaitUntil::CaptureReady,
            _ => WaitUntil::Load,
        }
    }
}

/// Bounds for the capture-readiness phase which follows ordinary document
/// load. Readiness requires the page's existing network/resource/frame work to
/// remain empty for the full quiet window; future background timers alone do
/// not keep a page busy forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureReadyOptions {
    pub timeout: Duration,
    pub quiet_window: Duration,
}

impl Default for CaptureReadyOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            quiet_window: Duration::from_millis(500),
        }
    }
}

/// Observation returned at the end of a bounded capture-readiness phase.
/// `ready` describes the quiet boundary; `incomplete_reasons` separately
/// records permanent or diagnostic gaps which cannot become pending work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureReadyReport {
    /// The observed page stayed idle for the requested quiet window.
    pub quiescent: bool,
    /// Backwards-compatible alias for `quiescent`.
    pub ready: bool,
    pub timed_out: bool,
    /// Whether the resource archive has no known omissions or failures.
    pub archive_complete: bool,
    pub elapsed: Duration,
    pub quiet_for: Duration,
    pub lifecycle: LifecycleState,
    pub pending_network_requests: u32,
    pub pending_resource_work: bool,
    pub pending_frame_documents: usize,
    pub pending_frame_messages: usize,
    pub pending_frames: usize,
    pub incomplete_reasons: Vec<String>,
}

impl CaptureReadyReport {
    pub fn is_complete(&self) -> bool {
        self.quiescent && !self.timed_out && self.archive_complete
    }
}

#[cfg(test)]
mod tests {
    use super::{CaptureReadyOptions, WaitUntil};

    #[test]
    fn wait_until_parses_commit_and_capture_ready() {
        assert_eq!(WaitUntil::from_str("commit"), WaitUntil::Commit);
        assert_eq!(
            WaitUntil::from_str("capture-ready"),
            WaitUntil::CaptureReady
        );
        assert_eq!(WaitUntil::from_str("captureReady"), WaitUntil::CaptureReady);
        assert_eq!(WaitUntil::from_str("networkIdle"), WaitUntil::NetworkIdle0);
    }

    #[test]
    fn capture_ready_defaults_to_five_seconds_and_half_second_quiet() {
        let options = CaptureReadyOptions::default();
        assert_eq!(options.timeout.as_millis(), 5_000);
        assert_eq!(options.quiet_window.as_millis(), 500);
    }
}
