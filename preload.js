const CLIPBOARD_DEBUG_TAG = '[ClipboardDebug/preload]';
const RUNTIME_READ_ALLOWLIST = new Set(['VERSION', 'plugin.json']);

const CLIPBOARD_DEBUG_ENABLED = (() => {
  try {
    return localStorage.getItem('google2fa_debug_clipboard') === '1';
  } catch (_) {
    return false;
  }
})();

function debugLog(...args) {
  if (CLIPBOARD_DEBUG_ENABLED) {
    console.log(...args);
  }
}

function debugError(...args) {
  if (CLIPBOARD_DEBUG_ENABLED) {
    console.error(...args);
  }
}

function maskClipboardPreview(text) {
  if (typeof text !== 'string') return text;
  let masked = text.replace(/(secret=)[^&\s]+/ig, '$1***');
  if (masked.length > 120) {
    masked = masked.slice(0, 120) + '...';
  }
  return masked;
}

function normalizeRuntimeReadPath(filePath) {
  if (typeof filePath !== 'string') return '';
  const normalized = filePath.replace(/\\/g, '/').trim().replace(/^\.\//, '');
  return RUNTIME_READ_ALLOWLIST.has(normalized) ? normalized : '';
}

window.utoolsBridge = {
  readText(filePath) {
    const safePath = normalizeRuntimeReadPath(filePath);
    if (!safePath || !window.utools) {
      return null;
    }
    return require('fs').readFileSync(safePath, 'utf8');
  },

  getClipboardText() {
    try {
      const hasUtoolsClipboard = !!(window.utools && window.utools.clipboard);
      const hasNavigatorClipboard = !!(navigator.clipboard && navigator.clipboard.readText);
      debugLog(CLIPBOARD_DEBUG_TAG, 'getClipboardText called', {
        hasUtoolsClipboard,
        hasNavigatorClipboard
      });

      if (hasUtoolsClipboard) {
        const text = window.utools.clipboard.readText();
        debugLog(CLIPBOARD_DEBUG_TAG, 'utools.clipboard.readText result', {
          type: typeof text,
          preview: maskClipboardPreview(text)
        });
        return text;
      }

      const result = navigator.clipboard?.readText() || null;
      debugLog(CLIPBOARD_DEBUG_TAG, 'navigator.clipboard.readText result', {
        type: typeof result,
        isPromise: !!(result && typeof result.then === 'function')
      });
      return result;
    } catch (e) {
      debugError(CLIPBOARD_DEBUG_TAG, 'getClipboardText error', e);
      return null;
    }
  },

  async debugClipboardSnapshot() {
    const snapshot = {
      hasUtools: !!window.utools,
      hasUtoolsClipboard: !!(window.utools && window.utools.clipboard),
      hasNavigatorClipboard: !!(navigator.clipboard && navigator.clipboard.readText)
    };

    try {
      if (snapshot.hasUtoolsClipboard) {
        const utoolsText = window.utools.clipboard.readText();
        snapshot.utoolsReadType = typeof utoolsText;
        snapshot.utoolsReadPreview = maskClipboardPreview(utoolsText);
      }
    } catch (e) {
      snapshot.utoolsReadError = e && e.message ? e.message : String(e);
    }

    try {
      if (snapshot.hasNavigatorClipboard) {
        const navText = await navigator.clipboard.readText();
        snapshot.navigatorReadType = typeof navText;
        snapshot.navigatorReadPreview = maskClipboardPreview(navText);
      }
    } catch (e) {
      snapshot.navigatorReadError = e && e.message ? e.message : String(e);
    }

    debugLog(CLIPBOARD_DEBUG_TAG, 'debugClipboardSnapshot', snapshot);
    return snapshot;
  },

  setClipboardText(text) {
    if (window.utools && window.utools.clipboard) {
      window.utools.clipboard.writeText(text);
    } else {
      navigator.clipboard?.writeText(text);
    }
  },

  getClipboardImage() {
    if (window.utools && window.utools.clipboard) {
      const img = window.utools.clipboard.readImage();
      if (img && !img.isEmpty()) {
        return img.toDataURL();
      }
    }
    return null;
  },

  openExternal(url) {
    if (!window.utools || !window.utools.shell || typeof url !== 'string') {
      return;
    }
    const trimmed = url.trim();
    if (!/^https?:\/\//i.test(trimmed)) {
      return;
    }
    window.utools.shell.openExternal(trimmed);
  },

  getScreenCapture() {
    if (window.utools && window.utools.getScreenCapture) {
      return window.utools.getScreenCapture();
    }
    return null;
  }
};
