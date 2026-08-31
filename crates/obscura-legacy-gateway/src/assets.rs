pub(crate) const INDEX_HTML: &str = include_str!("../assets/index.html");
pub(crate) const VIEW_HTML: &str = include_str!("../assets/view.html");
pub(crate) const APP_CSS: &str = include_str!("../assets/app.css");
pub(crate) const APP_JS: &str = include_str!("../assets/app.js");
pub(crate) const VIEW_JS: &str = include_str!("../assets/view.js");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_fail_closed_without_authorized_javascript() {
        assert!(INDEX_HTML.contains("method=\"post\" action=\"/\" autocomplete=\"off\""));
        assert!(
            INDEX_HTML.contains("id=\"username\"")
                && INDEX_HTML.contains("placeholder=\"请输入旧系统账号\" disabled")
        );
        assert!(INDEX_HTML.contains("id=\"fill-credentials\" type=\"submit\" disabled"));
        assert!(VIEW_HTML.contains("method=\"post\" action=\"/view\" autocomplete=\"off\""));
        assert!(
            VIEW_HTML.contains("id=\"remote-input\"")
                && VIEW_HTML.contains("再在此输入\" disabled")
        );
    }

    #[test]
    fn captcha_client_binds_png_and_raw_gesture_to_generation() {
        assert!(APP_JS.contains("X-Obscura-Captcha-Generation"));
        assert!(APP_JS.contains("{ generation: dragGeneration, samples: dragSamples }"));
        assert!(APP_JS.contains("elapsed_ms"));
        assert!(!APP_JS.contains("distance:"));
    }

    #[test]
    fn remote_view_coalesces_and_captures_non_passive_wheel_input() {
        assert!(VIEW_JS.contains("WHEEL_FLUSH_MS = 50"));
        assert!(VIEW_JS.contains("/api/view/wheel"));
        assert!(VIEW_JS.contains("{ passive: false }"));
        assert!(VIEW_JS.contains("MAX_NORMALIZED_WHEEL_DELTA = 2"));
        assert!(VIEW_JS.contains("flushWheel(true)"));
        assert!(VIEW_JS.contains("wheelRequests > 0 && !force"));
        assert!(VIEW_JS.contains("interactionQueue = interactionQueue.catch"));
        assert!(!VIEW_JS.contains("selector:"));
    }
}
