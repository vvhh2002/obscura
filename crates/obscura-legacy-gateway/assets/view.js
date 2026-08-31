(() => {
  'use strict';
  const frame = document.getElementById('remote-frame');
  const canvas = document.getElementById('remote-canvas');
  const message = document.getElementById('remote-message');
  const form = document.getElementById('remote-input-form');
  const input = document.getElementById('remote-input');
  const submit = form.querySelector('button[type="submit"]');
  let token = '';
  let objectUrl = '';
  let polling = false;
  let pressed = false;
  let sequence = 0;
  let interactionQueue = Promise.resolve();
  let frameUpdating = false;
  let pendingWheel = null;
  let wheelTimer = 0;
  let wheelRequests = 0;
  const WHEEL_FLUSH_MS = 50;
  const MAX_NORMALIZED_WHEEL_DELTA = 2;

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('X-Obscura-Bridge-Token', token);
    if (options.body) headers.set('Content-Type', 'application/json');
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok) {
      if (response.status === 410) {
        token = '';
        input.disabled = true;
        submit.disabled = true;
        throw new Error('本机会话已到期，请重新启动网关');
      }
      throw new Error('远程视图操作失败');
    }
    const type = response.headers.get('content-type') || '';
    return type.includes('application/json') ? response.json() : response.blob();
  }

  async function updateFrame() {
    if (!token || document.hidden || frameUpdating) return;
    frameUpdating = true;
    try {
      const blob = await api('/api/frame.png');
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      objectUrl = URL.createObjectURL(blob);
      frame.src = objectUrl;
      message.hidden = true;
    } catch (error) {
      message.hidden = false;
      message.textContent = error.message || '画面暂时不可用，正在重试…';
    } finally {
      frameUpdating = false;
    }
  }

  function beginPolling() {
    if (polling) return;
    polling = true;
    updateFrame();
    setInterval(updateFrame, 650);
  }

  function point(event) {
    const rect = frame.getBoundingClientRect();
    return {
      x: Math.max(0, Math.min(1, (event.clientX - rect.left) / Math.max(1, rect.width))),
      y: Math.max(0, Math.min(1, (event.clientY - rect.top) / Math.max(1, rect.height)))
    };
  }

  function sendPointer(kind, event) {
    // Preserve browser input order when a wheel batch is waiting for its
    // coalescing timer: it happened before this pointer sample.
    flushWheel(true);
    const position = point(event);
    const payload = { kind, ...position, sequence: ++sequence };
    interactionQueue = interactionQueue.catch(() => {}).then(() => api('/api/view/pointer', { method: 'POST', body: JSON.stringify(payload) }));
    return interactionQueue;
  }

  function wheelScales(event, rect) {
    if (event.deltaMode === WheelEvent.DOM_DELTA_LINE) return { x: 16, y: 16 };
    if (event.deltaMode === WheelEvent.DOM_DELTA_PAGE) {
      return { x: Math.max(1, rect.width), y: Math.max(1, rect.height) };
    }
    return { x: 1, y: 1 };
  }

  function flushWheel(force = false) {
    if (wheelTimer) window.clearTimeout(wheelTimer);
    wheelTimer = 0;
    if (wheelRequests > 0 && !force) return;
    const wheel = pendingWheel;
    pendingWheel = null;
    if (!wheel || !token || (wheel.delta_x === 0 && wheel.delta_y === 0)) return;
    const payload = {
      x: wheel.x,
      y: wheel.y,
      delta_x: Math.max(-MAX_NORMALIZED_WHEEL_DELTA, Math.min(MAX_NORMALIZED_WHEEL_DELTA, wheel.delta_x)),
      delta_y: Math.max(-MAX_NORMALIZED_WHEEL_DELTA, Math.min(MAX_NORMALIZED_WHEEL_DELTA, wheel.delta_y)),
      sequence: ++sequence
    };
    wheelRequests += 1;
    interactionQueue = interactionQueue.catch(() => {}).then(() => api('/api/view/wheel', {
      method: 'POST',
      body: JSON.stringify(payload)
    })).finally(() => {
      wheelRequests -= 1;
      if (pendingWheel && !wheelTimer) wheelTimer = window.setTimeout(flushWheel, WHEEL_FLUSH_MS);
    });
    interactionQueue.catch((error) => {
      message.hidden = false;
      message.textContent = error.message || '滚动画面失败，请稍后重试';
    });
  }

  function queueWheel(event) {
    if (!token) return;
    event.preventDefault();
    const rect = frame.getBoundingClientRect();
    const position = point(event);
    const scale = wheelScales(event, rect);
    const deltaX = scale.x * event.deltaX / Math.max(1, rect.width);
    const deltaY = scale.y * event.deltaY / Math.max(1, rect.height);
    if (!Number.isFinite(deltaX) || !Number.isFinite(deltaY)) return;
    if (pendingWheel && (Math.abs(pendingWheel.x - position.x) > 0.02 || Math.abs(pendingWheel.y - position.y) > 0.02)) {
      // Never merge samples which may hit different nested scrollers.
      flushWheel(true);
    }
    const previous = pendingWheel || { x: position.x, y: position.y, delta_x: 0, delta_y: 0 };
    pendingWheel = {
      x: position.x,
      y: position.y,
      // Keep a wider bounded accumulator and clamp only at flush time, so a
      // direction reversal within one batch is not distorted by early clamp.
      delta_x: Math.max(-8, Math.min(8, previous.delta_x + deltaX)),
      delta_y: Math.max(-8, Math.min(8, previous.delta_y + deltaY))
    };
    if (!wheelTimer) wheelTimer = window.setTimeout(flushWheel, WHEEL_FLUSH_MS);
  }

  frame.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    pressed = true;
    frame.setPointerCapture(event.pointerId);
    sendPointer('down', event).catch(() => { pressed = false; });
  });
  frame.addEventListener('pointermove', (event) => {
    if (pressed) sendPointer('move', event).catch(() => { pressed = false; });
  });
  frame.addEventListener('pointerup', (event) => {
    if (!pressed) return;
    pressed = false;
    sendPointer('up', event).then(updateFrame).catch(() => {});
  });
  frame.addEventListener('pointercancel', (event) => {
    if (!pressed) return;
    pressed = false;
    sendPointer('up', event).catch(() => {});
  });
  frame.addEventListener('wheel', queueWheel, { passive: false });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!token) return;
    try {
      flushWheel(true);
      const text = input.value;
      interactionQueue = interactionQueue.catch(() => {}).then(() => api('/api/view/type', {
        method: 'POST',
        body: JSON.stringify({ text })
      }));
      await interactionQueue;
      input.value = '';
      updateFrame();
    } catch (_) {
      message.hidden = false;
      message.textContent = '请先点击旧系统画面中的输入框';
    }
  });

  window.addEventListener('message', (event) => {
    if (event.origin !== location.origin || event.source !== parent) return;
    if (event.data?.type !== 'obscura-bridge-init' || !/^[a-f0-9]{64}$/i.test(event.data.token || '')) return;
    token = event.data.token;
    input.disabled = false;
    submit.disabled = false;
    beginPolling();
  });
  parent.postMessage({ type: 'obscura-view-ready' }, location.origin);
})();
