(() => {
  'use strict';

  const byId = (id) => document.getElementById(id);
  const elements = {
    connection: byId('connection'),
    notice: byId('notice'),
    noticeText: byId('notice-text'),
    form: byId('credentials-form'),
    fillCredentials: byId('fill-credentials'),
    username: byId('username'),
    password: byId('password'),
    togglePassword: byId('toggle-password'),
    captchaCard: byId('captcha-card'),
    captchaProvider: byId('captcha-provider'),
    captchaBackground: byId('captcha-background'),
    captchaLoading: byId('captcha-loading'),
    slider: byId('slider'),
    sliderThumb: byId('slider-thumb'),
    sliderFill: byId('slider-fill'),
    sliderCopy: byId('slider-copy'),
    submit: byId('submit-login'),
    rescan: byId('rescan'),
    logout: byId('logout'),
    empty: byId('empty-state'),
    iframe: byId('legacy-view'),
    viewStatus: byId('view-status-text'),
    steps: [byId('step-detect'), byId('step-captcha'), byId('step-session')]
  };

  let token = '';
  try { token = decodeURIComponent(location.hash.slice(1)); } catch (_) {}
  history.replaceState(null, '', location.pathname);
  if (!/^[a-f0-9]{64}$/i.test(token)) {
    elements.connection.classList.add('disconnected');
    elements.connection.lastElementChild.textContent = '缺少启动令牌';
    showNotice('请使用网关启动时输出的完整本机地址重新打开。', 'error');
    document.querySelectorAll('button,input').forEach((element) => { element.disabled = true; });
    return;
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    headers.set('X-Obscura-Bridge-Token', token);
    if (options.body) headers.set('Content-Type', 'application/json');
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok) {
      if (response.status === 410) token = '';
      let message = '操作失败，请稍后重试';
      try { message = (await response.json()).error || message; } catch (_) {}
      throw new Error(message);
    }
    const type = response.headers.get('content-type') || '';
    return type.includes('application/json') ? response.json() : response.blob();
  }

  function showNotice(message, kind = '') {
    elements.noticeText.textContent = message;
    elements.notice.classList.remove('error', 'success');
    if (kind) elements.notice.classList.add(kind);
  }

  function setProgress(index) {
    elements.steps.forEach((step, position) => {
      step.classList.toggle('active', position === index);
      step.classList.toggle('done', position < index);
    });
  }

  function providerLabel(provider) {
    const names = { tianai: 'Tianai 滑块', 'go-captcha': 'GoCaptcha 滑块', 'aj-captcha': 'AJ-Captcha 滑块', 'slider-captcha-js': 'slider-captcha-js' };
    return names[provider] || '旧系统滑块';
  }

  let activeCaptchaGeneration = -1;
  let captchaGeneration = -1;
  let captchaObjectUrl = '';
  let captchaAbortController = null;
  function clearCaptchaVisual() {
    captchaAbortController?.abort();
    captchaAbortController = null;
    captchaGeneration = -1;
    if (captchaObjectUrl) URL.revokeObjectURL(captchaObjectUrl);
    captchaObjectUrl = '';
    elements.captchaBackground.removeAttribute('src');
  }
  async function loadCaptcha(generation) {
    if (generation === captchaGeneration) return;
    captchaAbortController?.abort();
    const controller = new AbortController();
    captchaAbortController = controller;
    captchaGeneration = generation;
    elements.captchaLoading.hidden = false;
    elements.captchaLoading.textContent = '正在载入验证码画面';
    try {
      const blob = await api('/api/captcha/background', {
        headers: { 'X-Obscura-Captcha-Generation': String(generation) },
        signal: controller.signal
      });
      if (controller.signal.aborted || generation !== activeCaptchaGeneration) return;
      if (captchaObjectUrl) URL.revokeObjectURL(captchaObjectUrl);
      captchaObjectUrl = URL.createObjectURL(blob);
      elements.captchaBackground.src = captchaObjectUrl;
      elements.captchaLoading.hidden = true;
    } catch (error) {
      if (controller.signal.aborted) return;
      if (captchaGeneration === generation) captchaGeneration = -1;
      elements.captchaLoading.textContent = error.message;
    }
  }

  let viewVisible = false;
  let currentState = null;
  function renderState(state) {
    currentState = state;
    const discoveryComplete = state.phase === 'discovery_complete';
    const authenticated = state.phase === 'authenticated';
    const finished = authenticated || discoveryComplete;
    elements.connection.classList.remove('disconnected');
    elements.connection.classList.add('connected');
    elements.connection.lastElementChild.textContent = '本机安全连接';
    showNotice(state.message || '旧系统状态已更新', finished ? 'success' : '');
    elements.username.disabled = !state.login_detected || finished;
    elements.password.disabled = !state.login_detected || finished;
    elements.togglePassword.disabled = elements.password.disabled;
    elements.fillCredentials.disabled = !state.login_detected || finished;

    const hasCaptcha = Boolean(state.captcha);
    elements.captchaCard.hidden = !hasCaptcha || finished;
    if (hasCaptcha) {
      if (activeCaptchaGeneration !== state.captcha.generation) {
        activeCaptchaGeneration = state.captcha.generation;
        resetSlider();
      }
      elements.captchaProvider.textContent = providerLabel(state.captcha.adapter);
      loadCaptcha(state.captcha.generation);
    } else {
      activeCaptchaGeneration = -1;
      clearCaptchaVisual();
    }

    if (discoveryComplete) {
      clearCaptchaVisual();
      setProgress(2);
      elements.steps[2].classList.add('done');
      elements.submit.disabled = true;
      elements.empty.hidden = false;
      elements.iframe.hidden = true;
      elements.viewStatus.textContent = '配置已保存，可停止发现进程并按配置启动';
      elements.viewStatus.parentElement.classList.add('ready');
      viewVisible = false;
    } else if (authenticated) {
      clearCaptchaVisual();
      setProgress(2);
      elements.steps[2].classList.add('done');
      elements.submit.disabled = true;
      elements.empty.hidden = true;
      elements.iframe.hidden = false;
      elements.viewStatus.textContent = state.subject ? `会话已同步 · ${state.subject}` : '会话已同步';
      elements.viewStatus.parentElement.classList.add('ready');
      viewVisible = true;
      elements.iframe.contentWindow?.postMessage({ type: 'obscura-bridge-init', token }, location.origin);
    } else {
      if (viewVisible) {
        elements.empty.hidden = false;
        elements.iframe.hidden = true;
        elements.viewStatus.textContent = '等待登录';
        elements.viewStatus.parentElement.classList.remove('ready');
        viewVisible = false;
      }
      setProgress(hasCaptcha ? 1 : 0);
      elements.submit.disabled = state.phase !== 'ready_to_submit';
    }
  }

  async function refreshState() {
    try { renderState(await api('/api/state')); }
    catch (error) {
      elements.connection.classList.add('disconnected');
      showNotice(error.message, 'error');
      if (!token) document.querySelectorAll('button,input').forEach((element) => { element.disabled = true; });
    }
  }

  elements.togglePassword.addEventListener('click', () => {
    const showing = elements.password.type === 'text';
    elements.password.type = showing ? 'password' : 'text';
    elements.togglePassword.textContent = showing ? '显示' : '隐藏';
    elements.togglePassword.setAttribute('aria-label', showing ? '显示密码' : '隐藏密码');
  });

  elements.form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const username = elements.username.value;
    const password = elements.password.value;
    if (!username || !password) return;
    elements.form.querySelector('button[type="submit"]').disabled = true;
    try {
      const state = await api('/api/credentials', { method: 'POST', body: JSON.stringify({ username, password }) });
      elements.username.value = '';
      elements.password.value = '';
      renderState(state);
      showNotice('凭据已安全写入旧系统，请继续完成验证。');
    } catch (error) { showNotice(error.message, 'error'); }
    finally {
      elements.fillCredentials.disabled = !token || !currentState?.login_detected || ['authenticated', 'discovery_complete'].includes(currentState?.phase);
    }
  });

  let dragging = false;
  let sequence = 0;
  let dragStartedAt = 0;
  let dragGeneration = -1;
  let dragSamples = [];
  let dragInvalidReason = '';
  const MAX_GESTURE_SAMPLES = 512;
  function sliderPosition(event) {
    const rect = elements.slider.getBoundingClientRect();
    const travel = Math.max(1, rect.width - elements.sliderThumb.offsetWidth);
    const x = Math.max(0, Math.min(1, (event.clientX - rect.left - elements.sliderThumb.offsetWidth / 2) / travel));
    const y = Math.max(0, Math.min(1, (event.clientY - rect.top) / Math.max(1, rect.height)));
    return { x, y, pixels: x * travel };
  }
  function paintSlider(position) {
    elements.sliderThumb.style.transform = `translateX(${position.pixels}px)`;
    elements.sliderFill.style.width = `${position.pixels + elements.sliderThumb.offsetWidth}px`;
    elements.slider.setAttribute('aria-valuenow', String(Math.round(position.x * 100)));
  }
  function captureSliderSample(phase, event) {
    if (dragSamples.length >= MAX_GESTURE_SAMPLES - (phase === 'up' ? 0 : 1)) {
      dragInvalidReason = '拖动事件过多，请稍慢重试。';
      return null;
    }
    const position = sliderPosition(event);
    const elapsed = phase === 'down' ? 0 : Math.max(0, Math.round(performance.now() - dragStartedAt));
    if (elapsed > 30000) {
      dragInvalidReason = '拖动超过 30 秒，请重新操作。';
      return null;
    }
    dragSamples.push({ phase, x: position.x, y: position.y, sequence: ++sequence, elapsed_ms: elapsed });
    return position;
  }
  elements.slider.addEventListener('pointerdown', (event) => {
    if (dragging || event.button !== 0 || event.target !== elements.sliderThumb || activeCaptchaGeneration < 0) return;
    dragging = true;
    sequence = 0;
    dragStartedAt = performance.now();
    dragGeneration = activeCaptchaGeneration;
    dragSamples = [];
    dragInvalidReason = '';
    elements.slider.setPointerCapture(event.pointerId);
    const position = captureSliderSample('down', event);
    if (position) paintSlider(position);
  });
  elements.slider.addEventListener('pointermove', (event) => {
    if (!dragging) return;
    const samples = typeof event.getCoalescedEvents === 'function' ? event.getCoalescedEvents() : [event];
    for (const sample of samples.length ? samples : [event]) {
      const position = captureSliderSample('move', sample);
      if (position) paintSlider(position);
    }
  });
  async function endSlider(event) {
    if (!dragging) return;
    dragging = false;
    const position = captureSliderSample('up', event);
    if (position) paintSlider(position);
    const start = dragSamples[0];
    const hasMove = dragSamples.some((sample) => sample.phase === 'move' &&
      (Math.abs(sample.x - start.x) > 0.001 || Math.abs(sample.y - start.y) > 0.001));
    if (dragInvalidReason || !position || !hasMove || dragGeneration !== activeCaptchaGeneration) {
      const reason = dragInvalidReason || '未收到有效拖动轨迹，请重新操作。';
      resetSlider();
      showNotice(reason, 'error');
      return;
    }
    try {
      const state = await api('/api/captcha/drag', {
        method: 'POST',
        body: JSON.stringify({ generation: dragGeneration, samples: dragSamples })
      });
      elements.sliderCopy.textContent = '轨迹已发送';
      renderState(state);
    } catch (error) { showNotice(error.message, 'error'); }
  }
  elements.slider.addEventListener('pointerup', endSlider);
  elements.slider.addEventListener('pointercancel', () => {
    if (!dragging) return;
    resetSlider();
    showNotice('拖动已取消，请重新操作。');
  });

  elements.submit.addEventListener('click', async () => {
    elements.submit.disabled = true;
    showNotice('正在由旧系统校验并建立会话…');
    try { renderState(await api('/api/submit', { method: 'POST', body: '{}' })); }
    catch (error) { showNotice(error.message, 'error'); elements.submit.disabled = false; }
  });
  elements.rescan.addEventListener('click', async () => {
    clearCaptchaVisual();
    resetSlider();
    try { renderState(await api('/api/rescan', { method: 'POST', body: '{}' })); }
    catch (error) { showNotice(error.message, 'error'); }
  });
  elements.logout.addEventListener('click', async () => {
    try {
      const state = await api('/api/logout', { method: 'POST', body: '{}' });
      elements.empty.hidden = false;
      elements.iframe.hidden = true;
      elements.viewStatus.textContent = '等待登录';
      elements.viewStatus.parentElement.classList.remove('ready');
      viewVisible = false;
      clearCaptchaVisual();
      resetSlider();
      renderState(state);
      showNotice('旧系统 Cookie、令牌与页面状态已清除。', 'success');
    } catch (error) { showNotice(error.message, 'error'); }
  });
  function resetSlider() {
    dragging = false;
    dragSamples = [];
    dragInvalidReason = '';
    elements.sliderThumb.style.transform = '';
    elements.sliderFill.style.width = '0';
    elements.sliderCopy.textContent = '按住滑块并向右拖动';
    elements.slider.setAttribute('aria-valuenow', '0');
  }

  window.addEventListener('message', (event) => {
    if (event.origin !== location.origin || event.source !== elements.iframe.contentWindow) return;
    if (event.data?.type === 'obscura-view-ready' && viewVisible) {
      elements.iframe.contentWindow.postMessage({ type: 'obscura-bridge-init', token }, location.origin);
    }
  });

  refreshState();
  setInterval(() => { if (token) refreshState(); }, 1200);
})();
