// Google 2FA 验证器 - 核心逻辑

(function() {
  'use strict';

  // ==================== 工具函数 ====================

  // Base32 解码
  function base32ToBytes(base32) {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    base32 = base32.toUpperCase().replace(/[^A-Z2-7]/g, '').replace(/=+$/, '');
    const bytes = [];
    let buffer = 0;
    let bits = 0;

    for (const char of base32) {
      const value = base32Chars.indexOf(char);
      if (value === -1) continue;
      buffer = (buffer << 5) | value;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        bytes.push((buffer >> bits) & 0xff);
      }
    }
    return new Uint8Array(bytes);
  }

  // Hex 转字节数组
  function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
  }

  // HMAC-SHA1
  async function hmacSha1(key, message) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw', key,
      { name: 'HMAC', hash: 'SHA-1' },
      false, ['sign']
    );
    return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, message));
  }

  // HMAC-SHA256
  async function hmacSha256(key, message) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw', key,
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['sign']
    );
    return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, message));
  }

  // HMAC-SHA512
  async function hmacSha512(key, message) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw', key,
      { name: 'HMAC', hash: 'SHA-512' },
      false, ['sign']
    );
    return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, message));
  }

  // TOTP 生成
  async function generateTOTP(secret, options = {}) {
    const {
      algorithm = 'SHA1',
      digits = 6,
      period = 30
    } = options;

    const counter = Math.floor(Date.now() / 1000 / period);
    return generateHOTP(secret, { ...options, counter, digits });
  }

  // HOTP 生成
  async function generateHOTP(secret, options = {}) {
    const {
      algorithm = 'SHA1',
      digits = 6,
      counter = 0
    } = options;

    let key;
    try {
      key = base32ToBytes(secret);
    } catch (e) {
      try {
        key = hexToBytes(secret.replace(/\s/g, ''));
      } catch (e2) {
        throw new Error('无效的密钥格式');
      }
    }

    // 将 counter 转换为 8 字节数组（大端序）
    const counterBytes = new Uint8Array(8);
    let c = counter;
    for (let i = 7; i >= 0; i--) {
      counterBytes[i] = c & 0xff;
      c = Math.floor(c / 256);
    }

    // 计算 HMAC
    let hmac;
    switch (algorithm) {
      case 'SHA256':
        hmac = await hmacSha256(key, counterBytes);
        break;
      case 'SHA512':
        hmac = await hmacSha512(key, counterBytes);
        break;
      default:
        hmac = await hmacSha1(key, counterBytes);
    }

    // Dynamic Truncation
    const offset = hmac[hmac.length - 1] & 0xf;
    const code = ((hmac[offset] & 0x7f) << 24) |
                 ((hmac[offset + 1] & 0xff) << 16) |
                 ((hmac[offset + 2] & 0xff) << 8) |
                 (hmac[offset + 3] & 0xff);

    // 返回指定位数的数字
    return String(code % Math.pow(10, digits)).padStart(digits, '0');
  }

  // 解析 otpauth:// URL
  function parseOtpauthUrl(url) {
    try {
      const urlObj = new URL(url);
      if (urlObj.protocol !== 'otpauth:') return null;

      const type = urlObj.hostname; // totp 或 hotp
      const path = decodeURIComponent(urlObj.pathname.slice(1));
      const params = Object.fromEntries(urlObj.searchParams);

      const result = {
        type,
        name: path,
        secret: params.secret,
        issuer: params.issuer || '',
        algorithm: params.algorithm || 'SHA1',
        digits: parseInt(params.digits) || 6,
        period: parseInt(params.period) || 30
      };

      // HOTP 需要 counter
      if (type === 'hotp') {
        result.counter = parseInt(params.counter) || 0;
      }

      return result;
    } catch (e) {
      return null;
    }
  }

  // ==================== 数据存储 ====================

  const STORAGE_KEY = 'google2fa_entries';

  function getEntries() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
    } catch (e) {
      return [];
    }
  }

  function saveEntries(entries) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  }

  // ==================== 状态 ====================

  let entries = [];
  let currentView = 'home';
  let editingId = null;
  let refreshInterval = null;

  // ==================== DOM 元素 ====================

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  // ==================== UI 渲染 ====================

  // 渲染首页验证码卡片
  function renderHomeView() {
    const grid = $('#codeGrid');
    const empty = $('#emptyState');

    if (entries.length === 0) {
      grid.innerHTML = '';
      empty.classList.add('show');
      return;
    }

    empty.classList.remove('show');

    // 排序
    const sortType = $('#sortSelect').value;
    let sorted = [...entries];
    switch (sortType) {
      case 'name':
        sorted.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
        break;
      case 'recent':
        sorted.sort((a, b) => (b.lastUsed || 0) - (a.lastUsed || 0));
        break;
      default:
        // 默认：置顶 > 常用
        sorted.sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0));
    }

    // 搜索过滤
    const searchTerm = $('#searchInput').value.toLowerCase();
    if (searchTerm) {
      sorted = sorted.filter(e =>
        (e.name || '').toLowerCase().includes(searchTerm) ||
        (e.issuer || '').toLowerCase().includes(searchTerm)
      );
    }

    grid.innerHTML = sorted.map(entry => {
      const name = entry.name || '未命名';
      const issuer = entry.issuer || '';
      const period = entry.period || 30;
      const seconds = Math.floor(Date.now() / 1000) % period;
      const progress = ((period - seconds) / period) * 100;

      return `
        <div class="code-card" data-id="${entry.id}" onclick="window.app.editEntry('${entry.id}')">
          <div class="code-card-header">
            <div class="code-info">
              <div class="code-name">${escapeHtml(name)}</div>
              ${issuer ? `<div class="code-issuer">${escapeHtml(issuer)}</div>` : ''}
            </div>
          </div>
          <div class="code-value-row">
            <div class="code-value" data-secret="${escapeHtml(entry.secret)}"
                 data-algorithm="${entry.algorithm}"
                 data-digits="${entry.digits}"
                 data-type="${entry.type}"
                 data-period="${period}"
                 data-counter="${entry.counter || 0}">------</div>
            <div class="timer-circle" style="--progress: ${progress}">
              <span class="timer-text">${period - seconds}</span>
            </div>
          </div>
        </div>
      `;
    }).join('');

    // 立即刷新一次验证码
    refreshCodes();
  }

  // 渲染管理列表
  function renderManageView() {
    const list = $('#manageList');

    if (entries.length === 0) {
      list.innerHTML = '<div class="empty-state show"><p>暂无条目</p></div>';
      return;
    }

    list.innerHTML = entries.map(entry => `
      <div class="manage-item" data-id="${entry.id}">
        <div class="manage-item-info">
          <div class="manage-item-name">${escapeHtml(entry.name || '未命名')}</div>
          <div class="manage-item-issuer">${escapeHtml(entry.issuer || '')}</div>
        </div>
      </div>
    `).join('');

    // 绑定点击事件
    $$('.manage-item').forEach(item => {
      item.addEventListener('click', () => {
        const id = item.dataset.id;
        window.app.editEntry(id);
      });
    });
  }

  // 刷新验证码
  async function refreshCodes() {
    const codeEls = $$('#codeGrid .code-value');
    for (const el of codeEls) {
      try {
        const secret = el.dataset.secret;
        const options = {
          algorithm: el.dataset.algorithm || 'SHA1',
          digits: parseInt(el.dataset.digits) || 6,
          period: parseInt(el.dataset.period) || 30,
          type: el.dataset.type || 'totp'
        };

        if (options.type === 'hotp') {
          options.counter = parseInt(el.dataset.counter) || 0;
        }

        const code = options.type === 'hotp'
          ? await generateHOTP(secret, options)
          : await generateTOTP(secret, options);

        // 格式化显示（每3位加空格）
        el.textContent = code.replace(/(\d{3})/g, '$1 ').trim();
      } catch (e) {
        el.textContent = '------';
      }
    }

    // 刷新进度条
    const period = 30;
    const seconds = Math.floor(Date.now() / 1000) % period;
    const progress = ((period - seconds) / period) * 100;
    $$('.timer-circle').forEach(circle => {
      circle.style.setProperty('--progress', progress);
      const text = circle.querySelector('.timer-text');
      if (text) text.textContent = period - seconds;
    });
  }

  // ==================== 功能函数 ====================

  // 切换视图
  function switchView(view) {
    currentView = view;

    // 更新导航按钮
    $$('.nav-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.view === view);
    });

    // 更新视图显示
    $$('.view').forEach(v => {
      v.classList.toggle('active', v.id === view + 'View');
    });

    // 渲染对应视图
    if (view === 'home') {
      renderHomeView();
    } else {
      renderManageView();
    }
  }

  // 切换主题
  function toggleTheme() {
    const isDark = document.body.dataset.theme === 'dark';
    document.body.dataset.theme = isDark ? 'light' : 'dark';
    localStorage.setItem('google2fa_theme', document.body.dataset.theme);
  }

  // 初始化主题
  function initTheme() {
    const saved = localStorage.getItem('google2fa_theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.body.dataset.theme = saved || (prefersDark ? 'dark' : 'light');
  }

  // 显示 Toast
  function showToast(message, type = '') {
    const toast = $('#toast');
    toast.textContent = message;
    toast.className = 'toast ' + type;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2500);
  }

  // HTML 转义
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // 生成唯一 ID
  function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2);
  }

  // 添加/编辑条目
  async function saveEntry(data) {
    const entry = {
      id: data.id || generateId(),
      name: data.name || '',
      issuer: data.issuer || '',
      secret: data.secret || '',
      algorithm: data.algorithm || 'SHA1',
      digits: parseInt(data.digits) || 6,
      type: data.type || 'totp',
      period: parseInt(data.period) || 30,
      counter: parseInt(data.counter) || 0,
      pinned: data.pinned || false,
      lastUsed: Date.now()
    };

    // 验证密钥
    try {
      if (entry.type === 'hotp') {
        await generateHOTP(entry.secret, { counter: entry.counter });
      } else {
        await generateTOTP(entry.secret, { digits: entry.digits, period: entry.period });
      }
    } catch (e) {
      showToast('密钥无效：' + e.message, 'error');
      return false;
    }

    const index = entries.findIndex(e => e.id === entry.id);
    if (index >= 0) {
      entries[index] = entry;
    } else {
      entries.push(entry);
    }

    saveEntries(entries);
    renderCurrentView();
    return true;
  }

  // 删除条目
  function deleteEntry(id) {
    entries = entries.filter(e => e.id !== id);
    saveEntries(entries);
    renderCurrentView();
    showToast('已删除', 'success');
  }

  // 编辑条目
  function editEntry(id) {
    const entry = entries.find(e => e.id === id);
    if (!entry) return;

    editingId = id;
    $('#dialogTitle').textContent = '编辑验证码';
    $('#nameInput').value = entry.name || '';
    $('#secretInput').value = entry.secret || '';
    $('#algorithmInput').value = entry.algorithm || 'SHA1';
    $('#digitsInput').value = entry.digits || 6;
    $('#otpTypeInput').value = entry.type || 'totp';
    $('#periodInput').value = entry.period || 30;
    $('#deleteBtn').style.display = 'block';

    $('#addDialog').showModal();
  }

  // 渲染当前视图
  function renderCurrentView() {
    if (currentView === 'home') {
      renderHomeView();
    } else {
      renderManageView();
    }
  }

  // 从剪贴板粘贴并解析
  async function handlePaste() {
    try {
      const text = await (window.utoolsBridge.getClipboardText()
        || navigator.clipboard.readText());
      if (!text) return;

      // 尝试解析 otpauth URL
      const parsed = parseOtpauthUrl(text.trim());
      if (parsed) {
        $('#nameInput').value = parsed.name || '';
        $('#secretInput').value = parsed.secret || '';
        $('#algorithmInput').value = parsed.algorithm;
        $('#digitsInput').value = parsed.digits;
        $('#otpTypeInput').value = parsed.type;
        $('#periodInput').value = parsed.period;
        showToast('已从剪贴板解析', 'success');
        return;
      }

      // 尝试解析图片（需要用户选择文件）
      // 这里只是把文本放入输入框
      $('#secretInput').value = text.trim();
    } catch (e) {
      console.error('Paste error:', e);
    }
  }

  // 从图片识别二维码（简单实现 - 需要实际库支持）
  async function handleQrFile(file) {
    // 这是一个占位实现
    // 实际项目中可以使用 jsQR 库
    showToast('图片二维码识别需要额外库支持', 'error');
  }

  // 初始化验证码刷新定时器
  function initRefreshInterval() {
    if (refreshInterval) clearInterval(refreshInterval);
    refreshInterval = setInterval(refreshCodes, 1000);
  }

  // ==================== 事件绑定 ====================

  function init() {
    // 加载数据
    entries = getEntries();

    // 初始化主题
    initTheme();

    // 导航切换
    $$('.nav-btn').forEach(btn => {
      btn.addEventListener('click', () => switchView(btn.dataset.view));
    });

    // 主题切换
    $('#themeBtn').addEventListener('click', toggleTheme);

    // 添加按钮
    $('#addBtn').addEventListener('click', () => {
      editingId = null;
      $('#dialogTitle').textContent = '添加验证码';
      $('#addForm').reset();
      $('#deleteBtn').style.display = 'none';
      $('#addDialog').showModal();
    });

    $('#addFirstBtn')?.addEventListener('click', () => {
      $('#addBtn').click();
    });

    // 关闭弹窗
    $('#closeDialog').addEventListener('click', () => {
      $('#addDialog').close();
    });

    $('#addDialog').addEventListener('click', (e) => {
      if (e.target === $('#addDialog')) {
        $('#addDialog').close();
      }
    });

    // 粘贴按钮
    $('#pasteBtn').addEventListener('click', handlePaste);

    // 表单提交
    $('#addForm').addEventListener('submit', async (e) => {
      e.preventDefault();

      const data = {
        id: editingId,
        name: $('#nameInput').value.trim(),
        secret: $('#secretInput').value.trim(),
        algorithm: $('#algorithmInput').value,
        digits: parseInt($('#digitsInput').value),
        type: $('#otpTypeInput').value,
        period: parseInt($('#periodInput').value)
      };

      // 尝试解析 otpauth URL
      const parsed = parseOtpauthUrl(data.secret);
      if (parsed) {
        data.name = data.name || parsed.name;
        data.secret = parsed.secret;
        data.algorithm = parsed.algorithm;
        data.digits = parsed.digits;
        data.type = parsed.type;
        data.period = parsed.period;
        if (parsed.counter) data.counter = parsed.counter;
      }

      if (!data.name) {
        showToast('请输入名称', 'error');
        return;
      }

      if (!data.secret) {
        showToast('请输入密钥', 'error');
        return;
      }

      const success = await saveEntry(data);
      if (success) {
        $('#addDialog').close();
        showToast(editingId ? '已更新' : '已添加', 'success');
      }
    });

    // 删除按钮
    $('#deleteBtn').addEventListener('click', () => {
      if (editingId && confirm('确定要删除吗？')) {
        deleteEntry(editingId);
        $('#addDialog').close();
      }
    });

    // 搜索
    $('#searchInput').addEventListener('input', renderHomeView);

    // 排序
    $('#sortSelect').addEventListener('change', renderHomeView);

    // 导入按钮
    $('#importQrBtn').addEventListener('click', () => {
      // TODO: 实现屏幕二维码扫描
      showToast('屏幕扫描功能开发中', 'error');
      $('#importMenuDialog').close();
    });

    $('#qrFileInput').addEventListener('change', (e) => {
      if (e.target.files[0]) {
        handleQrFile(e.target.files[0]);
        $('#importMenuDialog').close();
      }
    });

    $('#importOtpauthBtn').addEventListener('click', () => {
      // 触发粘贴
      handlePaste();
      $('#importMenuDialog').close();
      $('#addDialog').showModal();
    });

    $('#importJsonBtn').addEventListener('click', async () => {
      try {
        const text = await (window.utoolsBridge.getClipboardText()
        || navigator.clipboard.readText());
        const data = JSON.parse(text);
        if (data.entries && Array.isArray(data.entries)) {
          for (const entry of data.entries) {
            if (entry.secret) {
              entries.push({
                id: generateId(),
                name: entry.name || entry.issuer || '',
                issuer: entry.issuer || '',
                secret: entry.secret,
                algorithm: entry.algorithm || 'SHA1',
                digits: parseInt(entry.digits) || 6,
                type: entry.type || 'totp',
                period: parseInt(entry.period) || 30,
                counter: parseInt(entry.counter) || 0
              });
            }
          }
          saveEntries(entries);
          renderCurrentView();
          showToast('导入成功', 'success');
        }
      } catch (e) {
        showToast('导入失败：请确保剪贴板中有有效的 JSON 数据', 'error');
      }
      $('#importMenuDialog').close();
    });

    $('#closeImportMenu').addEventListener('click', () => {
      $('#importMenuDialog').close();
    });

    $('#importMenuDialog').addEventListener('click', (e) => {
      if (e.target === $('#importMenuDialog')) {
        $('#importMenuDialog').close();
      }
    });

    // 初始渲染
    switchView('home');
    initRefreshInterval();

    // 启动时检查剪贴板（仅提示）
    setTimeout(async () => {
      try {
        const text = await (window.utoolsBridge.getClipboardText()
        || navigator.clipboard.readText());
        const parsed = parseOtpauthUrl(text?.trim() || '');
        if (parsed) {
          // 提示用户可以导入
          console.log('检测到剪贴板中有 otpauth URL');
        }
      } catch (e) {
        // 忽略权限错误
      }
    }, 1000);
  }

  // 启动
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // 暴露给全局
  window.app = {
    editEntry,
    switchView,
    toggleTheme
  };

})();
