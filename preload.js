// uTools 插件预加载脚本
// 提供与 Node.js 和 uTools 的桥接

const CLIPBOARD_DEBUG_TAG = '[ClipboardDebug/preload]';
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

// uTools 环境下使用 utools API，否则提供降级实现
window.utoolsBridge = {
  // 读取文本
  readText(filePath) {
    if (window.utools) {
      return require('fs').readFileSync(filePath, 'utf8');
    }
    return null;
  },

  // 写入文本
  writeText(filePath, content) {
    if (window.utools) {
      require('fs').writeFileSync(filePath, content, 'utf8');
    }
  },

  // 剪贴板 - 读取文本
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

      // 浏览器环境降级
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

  // 剪贴板调试快照
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

  // 剪贴板 - 写入文本
  setClipboardText(text) {
    if (window.utools && window.utools.clipboard) {
      window.utools.clipboard.writeText(text);
    } else {
      navigator.clipboard?.writeText(text);
    }
  },

  // 剪贴板 - 读取图片（返回 base64）
  getClipboardImage() {
    if (window.utools && window.utools.clipboard) {
      const img = window.utools.clipboard.readImage();
      if (img && !img.isEmpty()) {
        return img.toDataURL();
      }
    }
    return null;
  },

  // 打开外部链接
  openExternal(url) {
    if (window.utools && window.utools.shell) {
      window.utools.shell.openExternal(url);
    }
  },

  // 获取屏幕截图（用于二维码识别）
  getScreenCapture() {
    if (window.utools && window.utools.getScreenCapture) {
      return window.utools.getScreenCapture();
    }
    return null;
  }
};
