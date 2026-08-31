use std::collections::BTreeSet;
use std::time::Duration;

use obscura_browser::{
    dispatch_legacy_captcha_pointer, dispatch_legacy_view_pointer, dispatch_legacy_view_wheel,
    fill_legacy_credentials, inspect_legacy_page, install_legacy_bridge_preload,
    legacy_captcha_target_is_current, locate_legacy_view_target, probe_legacy_authentication,
    submit_legacy_login, type_into_legacy_view, CaptchaAdapter, CaptureRegion, LegacyAuthProbe,
    LegacyInspection, LegacyLoginSelectors, LegacyPointerPhase, LegacyViewTarget, Page,
};
use url::Url;
use uuid::Uuid;

use crate::backend::{
    BackendError, BackendSnapshot, CaptchaImage, CaptchaPresentation, Credentials, DiscoveredLogin,
    DiscoveryProfile, GatewayPhase, LegacyBackend, LocalFuture, SliderGesture, SliderPointer,
    SliderPointerPhase, ViewInput, ViewPointer, ViewPointerKind, ViewWheel,
};
use crate::config::Viewport;
use crate::origin_policy::install_exact_resource_origin_policy;
use crate::security::{validate_slider_gesture, validate_view_wheel};

#[derive(Clone, Debug)]
pub struct ObscuraBackendConfig {
    pub captcha_adapter: CaptchaAdapter,
    pub login_selectors: LegacyLoginSelectors,
    /// A selector visible only after the legacy application has authenticated.
    /// It is evidence for UI state, not an authorization/role assertion.
    pub success_selector: String,
    pub subject_selector: Option<String>,
    pub viewport: Viewport,
    pub operation_timeout: Duration,
    pub interaction_settle_ms: u64,
    pub allowed_navigation_origins: BTreeSet<String>,
    pub allowed_resource_origins: BTreeSet<String>,
    /// A profile produced by discovery. When present, the initial live page
    /// must match it exactly before the gateway accepts credentials.
    pub expected_discovery_profile: Option<DiscoveryProfile>,
    /// Require a logged-out baseline and allow the one-shot discovery profile
    /// to be finalized after authentication.
    pub discovery_mode: bool,
}

impl ObscuraBackendConfig {
    pub fn validate(&self) -> Result<(), BackendError> {
        if self.success_selector.trim().is_empty() || self.success_selector.len() > 1_024 {
            return Err(BackendError::Failed);
        }
        if self
            .subject_selector
            .as_ref()
            .is_some_and(|selector| selector.trim().is_empty() || selector.len() > 1_024)
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(10)
            || self.interaction_settle_ms > 5_000
            || self.allowed_navigation_origins.is_empty()
            || self.allowed_resource_origins.is_empty()
            || (self.discovery_mode && self.expected_discovery_profile.is_some())
            || self
                .expected_discovery_profile
                .as_ref()
                .is_some_and(|profile| !valid_discovery_profile(profile))
        {
            return Err(BackendError::Failed);
        }
        Ok(())
    }
}

fn valid_discovery_profile(profile: &DiscoveryProfile) -> bool {
    let expected_mode = match profile.captcha_adapter {
        CaptchaAdapter::Tianai | CaptchaAdapter::SliderCaptchaJs => "slider",
        CaptchaAdapter::GoCaptcha => "slide",
        CaptchaAdapter::AjCaptcha => "block_puzzle",
        CaptchaAdapter::Auto => return false,
    };
    let labels = [
        Some(profile.login.username_label.as_str()),
        Some(profile.login.password_label.as_str()),
        profile.login.submit_label.as_deref(),
    ];
    let selectors = [
        profile.login.username_selector.as_deref(),
        profile.login.password_selector.as_deref(),
        profile.login.submit_selector.as_deref(),
    ];
    profile.captcha_mode == expected_mode
        && labels
            .into_iter()
            .flatten()
            .all(|value| !value.trim().is_empty() && value.len() <= 160)
        && selectors
            .into_iter()
            .flatten()
            .all(|value| !value.trim().is_empty() && value.len() <= 1_024)
}

/// Concrete backend for one current-thread Obscura Page. A factory is required
/// so logout can discard the complete BrowserContext, including HttpOnly
/// cookies and Web Storage, instead of trying to copy or selectively clear it.
pub struct ObscuraLegacyBackend {
    page_factory: Box<dyn FnMut() -> Page>,
    page: Page,
    config: ObscuraBackendConfig,
    inspection: Option<LegacyInspection>,
    credentials_filled: bool,
    captcha_released: bool,
    authenticated: bool,
    auth_probe_streak: u8,
    auth_probe_generation: u64,
    subject: Option<String>,
    generation: u64,
    view_nonce: String,
    view_drag_target: Option<LegacyViewTarget>,
    view_focus_frame_id: u32,
    last_discovery_profile: Option<DiscoveryProfile>,
    preauth_absent_streak: u8,
    preauth_probe_generation: u64,
    preauth_baseline_confirmed: bool,
}

impl ObscuraLegacyBackend {
    pub fn new(
        mut page_factory: Box<dyn FnMut() -> Page>,
        config: ObscuraBackendConfig,
    ) -> Result<Self, BackendError> {
        config.validate()?;
        let mut page = page_factory();
        prepare_page(
            &mut page,
            config.viewport,
            config.allowed_navigation_origins.clone(),
            config.allowed_resource_origins.clone(),
        )?;
        Ok(Self {
            page_factory,
            page,
            config,
            inspection: None,
            credentials_filled: false,
            captcha_released: false,
            authenticated: false,
            auth_probe_streak: 0,
            auth_probe_generation: 0,
            subject: None,
            generation: 0,
            view_nonce: Uuid::new_v4().simple().to_string(),
            view_drag_target: None,
            view_focus_frame_id: 0,
            last_discovery_profile: None,
            preauth_absent_streak: 0,
            preauth_probe_generation: 0,
            preauth_baseline_confirmed: false,
        })
    }

    async fn navigate_and_inspect(
        &mut self,
        legacy_url: &Url,
    ) -> Result<BackendSnapshot, BackendError> {
        self.page
            .navigate(legacy_url.as_str())
            .await
            .map_err(|_| BackendError::Failed)?;
        self.page.settle(self.config.interaction_settle_ms).await;
        self.rescan_internal(true)?;
        self.snapshot_internal()
    }

    fn rescan_internal(&mut self, require_expected_profile: bool) -> Result<(), BackendError> {
        let inspection = inspect_legacy_page(
            &mut self.page,
            self.config.captcha_adapter,
            &self.config.login_selectors,
            self.config.operation_timeout,
        )
        .map_err(map_legacy_error)?;
        let discovered = discovery_profile(&inspection);
        if let Some(expected) = &self.config.expected_discovery_profile {
            match discovered.as_ref() {
                Some(actual) if actual == expected => {}
                Some(_) => return Err(BackendError::ConfigurationDrift),
                None if require_expected_profile => return Err(BackendError::ConfigurationDrift),
                None => {}
            }
        }
        if let Some(discovered) = discovered {
            self.last_discovery_profile = Some(discovered);
        }
        self.inspection = Some(inspection);
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }

    fn probe_authenticated(&mut self) -> Result<bool, BackendError> {
        let probe = probe_legacy_authentication(
            &mut self.page,
            &self.config.success_selector,
            self.config.subject_selector.as_deref(),
            self.config.operation_timeout,
        )
        .map_err(map_legacy_error)?;
        let document_generation = self.page.document_generation();
        let require_logged_out_baseline =
            self.config.discovery_mode || self.config.expected_discovery_profile.is_some();
        if require_logged_out_baseline
            && probe.matched
            && self.config.subject_selector.is_some()
            && !probe.subject_matched
        {
            return Err(BackendError::ConfigurationDrift);
        }
        if require_logged_out_baseline && !self.preauth_baseline_confirmed {
            validate_logged_out_probe(&probe)?;
            self.preauth_absent_streak = if self.preauth_probe_generation == document_generation {
                self.preauth_absent_streak.saturating_add(1)
            } else {
                1
            };
            self.preauth_probe_generation = document_generation;
            self.preauth_baseline_confirmed = self.preauth_absent_streak >= 2;
            self.authenticated = false;
            self.subject = None;
            return Ok(false);
        }
        if probe.matched {
            self.auth_probe_streak = if self.auth_probe_generation == document_generation {
                self.auth_probe_streak.saturating_add(1)
            } else {
                1
            };
            self.auth_probe_generation = document_generation;
        } else {
            self.auth_probe_streak = 0;
            self.auth_probe_generation = document_generation;
        }
        // A single transient DOM insertion is not enough to rotate the local
        // bridge session or expose the authenticated viewport.
        self.authenticated = probe.matched && self.auth_probe_streak >= 2;
        self.subject = if self.authenticated {
            probe.subject
        } else {
            None
        };
        Ok(self.authenticated)
    }

    fn snapshot_internal(&mut self) -> Result<BackendSnapshot, BackendError> {
        let authenticated = self.probe_authenticated()?;
        let page_generation = self.page.document_generation();
        if self
            .inspection
            .as_ref()
            .is_none_or(|inspection| inspection.document_generation != page_generation)
        {
            self.rescan_internal(false)?;
            if !authenticated {
                self.credentials_filled = false;
                self.captcha_released = false;
            }
        }

        let inspection = self.inspection.as_ref();
        let login_detected = inspection.and_then(|value| value.login.as_ref()).is_some();
        let captcha = inspection
            .and_then(|value| value.captcha.as_ref())
            .map(|target| CaptchaPresentation {
                adapter: target.adapter,
                generation: self.generation,
                background_available: true,
                // LegacyInspection exposes the verified widget and drag handle,
                // but not an answer-bearing piece crop. Never mislabel the
                // handle as a puzzle image.
                puzzle_available: false,
                aspect_ratio: target.top_viewport_rect.width / target.top_viewport_rect.height,
                puzzle_width_ratio: None,
                puzzle_y_ratio: None,
                puzzle_initial_x_ratio: None,
            });
        let phase = if authenticated {
            GatewayPhase::Authenticated
        } else if !login_detected {
            GatewayPhase::Detecting
        } else if captcha.is_some() && !self.captcha_released {
            GatewayPhase::Captcha
        } else if self.credentials_filled {
            GatewayPhase::ReadyToSubmit
        } else {
            GatewayPhase::Credentials
        };
        let message = match phase {
            GatewayPhase::Authenticated => Some("旧系统登录状态已在隔离会话中同步".to_string()),
            GatewayPhase::Captcha => Some("请手动拖动滑块完成验证".to_string()),
            GatewayPhase::ReadyToSubmit => Some("验证轨迹已发送，可以提交登录".to_string()),
            GatewayPhase::Credentials => Some("已识别旧系统登录表单".to_string()),
            GatewayPhase::Detecting => Some("未识别到唯一登录入口，请检查选择器配置".to_string()),
            _ => None,
        };
        Ok(BackendSnapshot {
            phase,
            navigation_url: Url::parse(&self.page.url_string()).ok(),
            subject: authenticated.then(|| self.subject.clone()).flatten(),
            login_detected,
            captcha,
            frame_ready: authenticated,
            generation: self.generation,
            message,
        })
    }

    async fn capture_widget(&mut self) -> Result<Option<Vec<u8>>, BackendError> {
        let Some(target) = self
            .inspection
            .as_ref()
            .and_then(|inspection| inspection.captcha.as_ref())
        else {
            return Ok(None);
        };
        let rect = target.top_viewport_rect;
        let (scroll_x, scroll_y) = self.page.screenshot_scroll_offset();
        self.page.prepare_screenshot_resources(250).await;
        let region = CaptureRegion::new(
            rect.x as f32 + scroll_x,
            rect.y as f32 + scroll_y,
            rect.width as f32,
            rect.height as f32,
            1.0,
        );
        self.page
            .screenshot_region(region)
            .map(Some)
            .map_err(|_| BackendError::CaptureFailed)
    }

    fn slider_coordinates(
        &self,
        pointer: SliderPointer,
        down: SliderPointer,
    ) -> Result<(f64, f64), BackendError> {
        let target = self
            .inspection
            .as_ref()
            .and_then(|inspection| inspection.captcha.as_ref())
            .ok_or(BackendError::CaptchaUnavailable)?;
        let start = target.frame_start_rect;
        let crop = target.frame_crop_rect;
        let start_x = start.x + start.width / 2.0;
        let start_y = start.y + start.height / 2.0;
        let travel = (crop.x + crop.width - start_x - start.width / 2.0).max(1.0);
        // Preserve the user's grip offset by replaying displacement from the
        // actual pointer-down sample. The legacy handle center is only the
        // coordinate-space anchor; no answer distance is calculated here.
        let x = start_x + travel * (pointer.x - down.x);
        let y = start_y + start.height.min(24.0) * (pointer.y - down.y);
        Ok((x, y))
    }
}

impl LegacyBackend for ObscuraLegacyBackend {
    fn start<'a>(
        &'a mut self,
        legacy_url: &'a Url,
    ) -> LocalFuture<'a, Result<BackendSnapshot, BackendError>> {
        Box::pin(async move { self.navigate_and_inspect(legacy_url).await })
    }

    fn snapshot(&mut self) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>> {
        Box::pin(async move { self.snapshot_internal() })
    }

    fn discovery_profile(&self) -> Option<DiscoveryProfile> {
        self.last_discovery_profile.clone()
    }

    fn finalize_discovery<'a>(
        &'a mut self,
        legacy_url: &'a Url,
    ) -> LocalFuture<'a, Result<DiscoveryProfile, BackendError>> {
        Box::pin(async move {
            let expected = self
                .last_discovery_profile
                .clone()
                .ok_or(BackendError::NotReady);
            let result = async {
                if !self.config.discovery_mode
                    || !self.authenticated
                    || !self.preauth_baseline_confirmed
                {
                    return Err(BackendError::NotReady);
                }
                let expected = expected?;
                if expected.login.username_selector.is_none()
                    || expected.login.password_selector.is_none()
                    || (expected.login.submit_label.is_some()
                        && expected.login.submit_selector.is_none())
                {
                    return Err(BackendError::ConfigurationDrift);
                }
                let selectors = LegacyLoginSelectors {
                    username: expected.login.username_selector.clone(),
                    password: expected.login.password_selector.clone(),
                    submit: expected.login.submit_selector.clone(),
                };
                let mut preflight = (self.page_factory)();
                prepare_page(
                    &mut preflight,
                    self.config.viewport,
                    self.config.allowed_navigation_origins.clone(),
                    self.config.allowed_resource_origins.clone(),
                )?;
                preflight
                    .navigate(legacy_url.as_str())
                    .await
                    .map_err(|_| BackendError::Failed)?;
                preflight.settle(self.config.interaction_settle_ms).await;
                let inspection = inspect_legacy_page(
                    &mut preflight,
                    expected.captcha_adapter,
                    &selectors,
                    self.config.operation_timeout,
                )
                .map_err(map_legacy_error)?;
                if discovery_profile(&inspection).as_ref() != Some(&expected) {
                    return Err(BackendError::ConfigurationDrift);
                }
                for _ in 0..2 {
                    let probe = probe_legacy_authentication(
                        &mut preflight,
                        &self.config.success_selector,
                        self.config.subject_selector.as_deref(),
                        self.config.operation_timeout,
                    )
                    .map_err(map_legacy_error)?;
                    validate_logged_out_probe(&probe)?;
                }
                Ok(expected)
            }
            .await;

            // Discovery is one-shot. Destroy both the authenticated page and
            // the preflight context before returning evidence to the writer.
            let mut blank = (self.page_factory)();
            prepare_page(
                &mut blank,
                self.config.viewport,
                self.config.allowed_navigation_origins.clone(),
                self.config.allowed_resource_origins.clone(),
            )?;
            blank.navigate_blank();
            self.page = blank;
            self.inspection = None;
            self.credentials_filled = false;
            self.captcha_released = false;
            self.authenticated = false;
            self.auth_probe_streak = 0;
            self.auth_probe_generation = 0;
            self.subject = None;
            self.view_drag_target = None;
            self.view_focus_frame_id = 0;
            self.last_discovery_profile = None;
            self.preauth_absent_streak = 0;
            self.preauth_probe_generation = 0;
            self.preauth_baseline_confirmed = false;
            result
        })
    }

    fn captcha_png(
        &mut self,
        image: CaptchaImage,
        expected_generation: u64,
    ) -> LocalFuture<'_, Result<Option<Vec<u8>>, BackendError>> {
        Box::pin(async move {
            if expected_generation != self.generation {
                return Err(BackendError::StaleTarget);
            }
            let lease = self
                .inspection
                .as_ref()
                .ok_or(BackendError::NotReady)?
                .lease()
                .clone();
            match legacy_captcha_target_is_current(
                &mut self.page,
                &lease,
                self.config.operation_timeout,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    self.rescan_internal(false)?;
                    return Err(BackendError::StaleTarget);
                }
                Err(error) if legacy_target_became_stale(&error) => {
                    self.rescan_internal(false)?;
                    return Err(BackendError::StaleTarget);
                }
                Err(error) => return Err(map_legacy_error(error)),
            }
            match image {
                CaptchaImage::Background => self.capture_widget().await,
                CaptchaImage::Puzzle => Ok(None),
            }
        })
    }

    fn frame_png(&mut self) -> LocalFuture<'_, Result<Vec<u8>, BackendError>> {
        Box::pin(async move {
            self.page.prepare_screenshot_resources(250).await;
            self.page
                .screenshot((
                    self.config.viewport.width as f32,
                    self.config.viewport.height as f32,
                ))
                .ok_or(BackendError::CaptureFailed)
        })
    }

    fn fill_credentials(
        &mut self,
        credentials: Credentials,
    ) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>> {
        Box::pin(async move {
            let inspection = self.inspection.as_ref().ok_or(BackendError::NotReady)?;
            fill_legacy_credentials(
                &mut self.page,
                inspection.lease(),
                &credentials.username,
                &credentials.password,
                self.config.operation_timeout,
            )
            .map_err(map_legacy_error)?;
            self.credentials_filled = true;
            self.snapshot_internal()
        })
    }

    fn slider_gesture(
        &mut self,
        gesture: SliderGesture,
    ) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>> {
        Box::pin(async move {
            if gesture.generation != self.generation {
                return Err(BackendError::StaleTarget);
            }
            validate_slider_gesture(&gesture).map_err(|_| BackendError::Failed)?;
            let lease = self
                .inspection
                .as_ref()
                .ok_or(BackendError::NotReady)?
                .lease()
                .clone();
            let down = gesture.samples[0];
            let mut previous_elapsed = 0;
            self.captcha_released = false;
            for pointer in gesture.samples {
                let delay_ms = pointer.elapsed_ms.saturating_sub(previous_elapsed);
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                previous_elapsed = pointer.elapsed_ms;
                let (x, y) = self.slider_coordinates(pointer, down)?;
                let phase = match pointer.phase {
                    SliderPointerPhase::Down => LegacyPointerPhase::Down,
                    SliderPointerPhase::Move => LegacyPointerPhase::Move,
                    SliderPointerPhase::Up => LegacyPointerPhase::Up,
                };
                dispatch_legacy_captcha_pointer(
                    &mut self.page,
                    &lease,
                    phase,
                    x,
                    y,
                    self.config.operation_timeout,
                )
                .map_err(map_legacy_error)?;
            }

            self.page.settle(self.config.interaction_settle_ms).await;
            self.captcha_released = match legacy_captcha_target_is_current(
                &mut self.page,
                &lease,
                self.config.operation_timeout,
            ) {
                Ok(true) => true,
                Ok(false) => {
                    self.rescan_internal(false)?;
                    self.inspection
                        .as_ref()
                        .and_then(|inspection| inspection.captcha.as_ref())
                        .is_none()
                }
                Err(error) if legacy_target_became_stale(&error) => {
                    self.rescan_internal(false)?;
                    self.inspection
                        .as_ref()
                        .and_then(|inspection| inspection.captcha.as_ref())
                        .is_none()
                }
                Err(error) => return Err(map_legacy_error(error)),
            };
            self.snapshot_internal()
        })
    }

    fn submit(&mut self) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>> {
        Box::pin(async move {
            if !self.credentials_filled
                || (self
                    .inspection
                    .as_ref()
                    .and_then(|inspection| inspection.captcha.as_ref())
                    .is_some()
                    && !self.captcha_released)
            {
                return Err(BackendError::NotReady);
            }
            if self
                .inspection
                .as_ref()
                .and_then(|inspection| inspection.captcha.as_ref())
                .is_some()
            {
                let lease = self
                    .inspection
                    .as_ref()
                    .ok_or(BackendError::NotReady)?
                    .lease()
                    .clone();
                let current = legacy_captcha_target_is_current(
                    &mut self.page,
                    &lease,
                    self.config.operation_timeout,
                );
                let must_rescan = match current {
                    Ok(true) => false,
                    Ok(false) => true,
                    Err(error) if legacy_target_became_stale(&error) => true,
                    Err(error) => return Err(map_legacy_error(error)),
                };
                if must_rescan {
                    self.rescan_internal(false)?;
                    if self
                        .inspection
                        .as_ref()
                        .and_then(|inspection| inspection.captcha.as_ref())
                        .is_some()
                    {
                        self.captcha_released = false;
                        return Err(BackendError::StaleTarget);
                    }
                }
            }
            let inspection = self.inspection.as_ref().ok_or(BackendError::NotReady)?;
            submit_legacy_login(
                &mut self.page,
                inspection.lease(),
                self.config.operation_timeout,
            )
            .map_err(map_legacy_error)?;
            self.page.settle(self.config.interaction_settle_ms).await;
            self.snapshot_internal()
        })
    }

    fn rescan(&mut self) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>> {
        Box::pin(async move {
            self.rescan_internal(false)?;
            self.captcha_released = false;
            self.snapshot_internal()
        })
    }

    fn view_pointer(
        &mut self,
        pointer: ViewPointer,
    ) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>> {
        Box::pin(async move {
            if !self.authenticated {
                return Err(BackendError::NotReady);
            }
            let top_x = pointer.x * self.config.viewport.width as f64;
            let top_y = pointer.y * self.config.viewport.height as f64;
            let (target, phase) = match pointer.kind {
                ViewPointerKind::Down => {
                    let target = locate_legacy_view_target(
                        &mut self.page,
                        top_x,
                        top_y,
                        self.config.operation_timeout,
                    )
                    .map_err(map_legacy_error)?;
                    self.view_drag_target = Some(target);
                    self.view_focus_frame_id = target.frame_id;
                    (target, LegacyPointerPhase::Down)
                }
                ViewPointerKind::Move => (
                    self.view_drag_target.ok_or(BackendError::NotReady)?,
                    LegacyPointerPhase::Move,
                ),
                ViewPointerKind::Up => (
                    self.view_drag_target.ok_or(BackendError::NotReady)?,
                    LegacyPointerPhase::Up,
                ),
            };
            let (frame_x, frame_y) = target.frame_point(top_x, top_y);
            let result = dispatch_legacy_view_pointer(
                &mut self.page,
                &self.view_nonce,
                target.frame_id,
                phase,
                frame_x,
                frame_y,
                self.config.operation_timeout,
            );
            if pointer.kind == ViewPointerKind::Up || result.is_err() {
                self.view_drag_target = None;
            }
            result.map_err(map_legacy_error)?;
            self.page
                .settle(self.config.interaction_settle_ms.min(100))
                .await;
            self.snapshot_internal()
        })
    }

    fn view_input(
        &mut self,
        input: ViewInput,
    ) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>> {
        Box::pin(async move {
            if !self.authenticated {
                return Err(BackendError::NotReady);
            }
            let ViewInput::Text(text) = input;
            type_into_legacy_view(
                &mut self.page,
                self.view_focus_frame_id,
                &text,
                self.config.operation_timeout,
            )
            .map_err(map_legacy_error)?;
            self.snapshot_internal()
        })
    }

    fn view_wheel(
        &mut self,
        wheel: ViewWheel,
    ) -> LocalFuture<'_, Result<BackendSnapshot, BackendError>> {
        Box::pin(async move {
            if !self.authenticated {
                return Err(BackendError::NotReady);
            }
            let (top_x, top_y, delta_x, delta_y) = view_wheel_pixels(wheel, self.config.viewport)?;
            let target = locate_legacy_view_target(
                &mut self.page,
                top_x,
                top_y,
                self.config.operation_timeout,
            )
            .map_err(map_legacy_error)?;
            let (frame_x, frame_y) = target.frame_point(top_x, top_y);
            dispatch_legacy_view_wheel(
                &mut self.page,
                target.frame_id,
                frame_x,
                frame_y,
                delta_x,
                delta_y,
                self.config.operation_timeout,
            )
            .map_err(map_legacy_error)?;
            self.page
                .settle(self.config.interaction_settle_ms.min(100))
                .await;
            self.snapshot_internal()
        })
    }

    fn logout<'a>(&'a mut self, legacy_url: &'a Url) -> LocalFuture<'a, Result<(), BackendError>> {
        Box::pin(async move {
            let mut page = (self.page_factory)();
            prepare_page(
                &mut page,
                self.config.viewport,
                self.config.allowed_navigation_origins.clone(),
                self.config.allowed_resource_origins.clone(),
            )?;
            self.page = page;
            self.inspection = None;
            self.credentials_filled = false;
            self.captcha_released = false;
            self.authenticated = false;
            self.auth_probe_streak = 0;
            self.auth_probe_generation = 0;
            self.subject = None;
            self.generation = self.generation.saturating_add(1);
            self.view_nonce = Uuid::new_v4().simple().to_string();
            self.view_drag_target = None;
            self.view_focus_frame_id = 0;
            self.last_discovery_profile = None;
            self.preauth_absent_streak = 0;
            self.preauth_probe_generation = 0;
            self.preauth_baseline_confirmed = false;
            self.navigate_and_inspect(legacy_url).await?;
            Ok(())
        })
    }

    fn quarantine(&mut self) -> LocalFuture<'_, Result<(), BackendError>> {
        Box::pin(async move {
            let mut page = (self.page_factory)();
            prepare_page(
                &mut page,
                self.config.viewport,
                self.config.allowed_navigation_origins.clone(),
                self.config.allowed_resource_origins.clone(),
            )?;
            page.navigate_blank();
            self.page = page;
            self.inspection = None;
            self.credentials_filled = false;
            self.captcha_released = false;
            self.authenticated = false;
            self.auth_probe_streak = 0;
            self.auth_probe_generation = 0;
            self.subject = None;
            self.view_drag_target = None;
            self.view_focus_frame_id = 0;
            self.last_discovery_profile = None;
            self.preauth_absent_streak = 0;
            self.preauth_probe_generation = 0;
            self.preauth_baseline_confirmed = false;
            Ok(())
        })
    }
}

fn discovery_profile(inspection: &LegacyInspection) -> Option<DiscoveryProfile> {
    let login = inspection.login.as_ref()?;
    let captcha = inspection.captcha.as_ref()?;
    Some(DiscoveryProfile {
        captcha_adapter: captcha.adapter,
        captcha_mode: captcha.mode.clone(),
        login: DiscoveredLogin {
            username_label: login.username_label.clone(),
            password_label: login.password_label.clone(),
            submit_label: login.submit_label.clone(),
            username_selector: login.username_selector.clone(),
            password_selector: login.password_selector.clone(),
            submit_selector: login.submit_selector.clone(),
        },
    })
}

fn validate_logged_out_probe(probe: &LegacyAuthProbe) -> Result<(), BackendError> {
    if probe.matched || probe.success_candidate_count > 1 {
        Err(BackendError::ConfigurationDrift)
    } else {
        Ok(())
    }
}

fn view_wheel_pixels(
    wheel: ViewWheel,
    viewport: Viewport,
) -> Result<(f64, f64, f64, f64), BackendError> {
    validate_view_wheel(wheel).map_err(|_| BackendError::Failed)?;
    Ok((
        wheel.x * viewport.width as f64,
        wheel.y * viewport.height as f64,
        wheel.delta_x * viewport.width as f64,
        wheel.delta_y * viewport.height as f64,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_probe(success_candidate_count: usize, matched: bool) -> LegacyAuthProbe {
        LegacyAuthProbe {
            success_candidate_count,
            matched,
            subject_matched: true,
            subject: None,
        }
    }

    #[test]
    fn logged_out_baseline_accepts_zero_or_one_hidden_success_candidate() {
        assert_eq!(validate_logged_out_probe(&auth_probe(0, false)), Ok(()));
        assert_eq!(validate_logged_out_probe(&auth_probe(1, false)), Ok(()));
    }

    #[test]
    fn logged_out_baseline_rejects_ambiguous_or_visible_success_evidence() {
        assert_eq!(
            validate_logged_out_probe(&auth_probe(2, false)),
            Err(BackendError::ConfigurationDrift)
        );
        assert_eq!(
            validate_logged_out_probe(&auth_probe(1, true)),
            Err(BackendError::ConfigurationDrift)
        );
    }

    #[test]
    fn normalized_wheel_maps_to_fixed_legacy_viewport_pixels() {
        let mapped = view_wheel_pixels(
            ViewWheel {
                x: 0.25,
                y: 0.5,
                delta_x: -0.125,
                delta_y: 1.0,
                sequence: 7,
            },
            Viewport {
                width: 1280,
                height: 720,
            },
        )
        .unwrap();
        assert_eq!(mapped, (320.0, 360.0, -160.0, 720.0));
    }

    #[test]
    fn direct_backend_wheel_mapping_rechecks_delta_bound() {
        let error = view_wheel_pixels(
            ViewWheel {
                x: 0.25,
                y: 0.5,
                delta_x: 0.0,
                delta_y: 2.01,
                sequence: 7,
            },
            Viewport::default(),
        )
        .unwrap_err();
        assert_eq!(error, BackendError::Failed);
    }
}

fn prepare_page(
    page: &mut Page,
    viewport: Viewport,
    allowed_navigation_origins: BTreeSet<String>,
    allowed_resource_origins: BTreeSet<String>,
) -> Result<(), BackendError> {
    install_exact_resource_origin_policy(
        page,
        allowed_navigation_origins,
        allowed_resource_origins,
    )
    .map_err(|_| BackendError::Failed)?;
    install_legacy_bridge_preload(page);
    page.set_viewport((viewport.width as f32, viewport.height as f32));
    Ok(())
}

fn map_legacy_error(message: String) -> BackendError {
    let lower = message.to_ascii_lowercase();
    if lower.contains("expired") || lower.contains("generation") {
        BackendError::StaleTarget
    } else if lower.contains("captcha") {
        BackendError::CaptchaUnavailable
    } else if lower.contains("login") || lower.contains("ambiguous") {
        BackendError::LoginUnavailable
    } else if lower.contains("timeout") || lower.contains("terminated") {
        BackendError::Timeout
    } else {
        BackendError::Failed
    }
}

fn legacy_target_became_stale(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("expired")
        || lower.contains("generation")
        || lower.contains("detached")
        || lower.contains("lease")
}
