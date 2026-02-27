// uTools 插件预加载脚本
// 提供与 Node.js 和 uTools 的桥接

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
    if (window.utools && window.utools.clipboard) {
      return window.utools.clipboard.readText();
    }
    // 浏览器环境降级
    return navigator.clipboard?.readText() || null;
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
