// Google 2FA 验证器 - 核心逻辑

(function() {
  'use strict';

  // ==================== 工具函数 ====================

  // Base32 解码 - 标准实现
  function base32ToBytes(base32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    // 清理输入：转大写，移除非 Base32 字符，去除填充
    base32 = base32.toUpperCase().replace(/[^A-Z2-7]/g, '').replace(/=+$/, '');
    if (!base32) return new Uint8Array(0);

    const bytes = [];
    let buffer = 0;
    let bitsLeft = 0;

    for (let i = 0; i < base32.length; i++) {
      const charIndex = alphabet.indexOf(base32[i]);
      if (charIndex === -1) continue;

      buffer = (buffer << 5) | charIndex;
      bitsLeft += 5;

      if (bitsLeft >= 8) {
        bitsLeft -= 8;
        bytes.push((buffer >> bitsLeft) & 0xff);
      }
    }
    return new Uint8Array(bytes);
  }

  // Hex 字符串转字节数组
  function hexToBytes(hex) {
    hex = hex.replace(/\s/g, '');
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
  }

  // 异步 HMAC 计算 - 使用 Web Crypto API
  async function hmac(algorithm, key, message) {
    const hashName = {
      'SHA1': 'SHA-1',
      'SHA256': 'SHA-256',
      'SHA512': 'SHA-512'
    }[algorithm] || 'SHA-1';

    const cryptoKey = await crypto.subtle.importKey(
      'raw', key,
      { name: 'HMAC', hash: hashName },
      false, ['sign']
    );
    return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, message));
  }

  // TOTP 生成 - RFC 6238
  // TOTP = HOTP(K, T) 其中 T = floor((Unix time) / period)
  async function generateTOTP(secret, options = {}) {
    const period = options.period || 30;
    const counter = Math.floor(Date.now() / 1000 / period);
    return generateHOTP(secret, { ...options, counter });
  }

  // HOTP 生成 - RFC 4226
  // HOTP = Truncate(HMAC(K, C))
  async function generateHOTP(secret, options = {}) {
    const algorithm = options.algorithm || 'SHA1';
    const digits = options.digits || 6;
    const counter = options.counter || 0;

    // 1. 解析密钥 - 支持 Base32 和 Hex
    let key;
    const cleanedSecret = secret.replace(/\s/g, '').toUpperCase();

    // 尝试 Base32（最常见）
    if (/^[A-Z2-7]+=*$/.test(cleanedSecret)) {
      key = base32ToBytes(cleanedSecret);
    }
    // 尝试 Hex
    else if (/^[0-9A-Fa-f]+$/.test(cleanedSecret) && cleanedSecret.length % 2 === 0) {
      key = hexToBytes(cleanedSecret);
    }
    // 尝试原始密钥（可能是已经解码的）
    else if (/^[+/A-Za-z0-9]+=*$/.test(cleanedSecret)) {
      try {
        key = Uint8Array.from(atob(cleanedSecret), c => c.charCodeAt(0));
      } catch (e) {
        key = base32ToBytes(cleanedSecret);
      }
    }
    else {
      key = base32ToBytes(cleanedSecret);
    }

    if (key.length === 0) {
      throw new Error('无效的密钥');
    }

    // 2. 将 counter 转换为 8 字节（大端序 / Big-Endian）
    const counterBytes = new Uint8Array(8);
    let c = counter;
    for (let i = 7; i >= 0; i--) {
      counterBytes[i] = c & 0xff;
      c = Math.floor(c / 256);
    }

    // 3. 计算 HMAC
    const hmacResult = await hmac(algorithm, key, counterBytes);

    // 4. Dynamic Truncation - RFC 4226 Section 5.4
    const offset = hmacResult[hmacResult.length - 1] & 0x0f;

    const binary =
      ((hmacResult[offset] & 0x7f) << 24) |
      ((hmacResult[offset + 1] & 0xff) << 16) |
      ((hmacResult[offset + 2] & 0xff) << 8) |
      (hmacResult[offset + 3] & 0xff);

    // 5. 取指定位数
    const otp = binary % Math.pow(10, digits);
    return String(otp).padStart(digits, '0');
  }

  // 测试 TOTP - 可以用这个验证实现是否正确
  // Google 测试密钥: JBSWY3DPEHPK3PXP (secret)
  // 预期 TOTP (SHA1, 6位, 30秒): 需要实时验证
  window.testTOTP = async function() {
    const testSecret = 'JBSWY3DPEHPK3PXP'; // Google 官方测试密钥
    try {
      const code = await generateTOTP(testSecret);
      console.log('测试密钥 JBSWY3DPEHPK3PXP 生成的验证码:', code);
      console.log('当前时间戳:', Math.floor(Date.now() / 1000));
      console.log('当前 30 秒周期:', Math.floor(Date.now() / 1000 / 30));
      return code;
    } catch (e) {
      console.error('TOTP 生成失败:', e);
      return null;
    }
  };

  // ==================== otpauth:// URL 解析 ====================

  function parseOtpauthUrl(url) {
    try {
      if (typeof url !== 'string') return null;
      let trimmed = url.trim();
      if (!trimmed) return null;

      // 统一协议格式：支持 otpauth://... / otpauth:...
      if (trimmed.startsWith('otpauth://')) {
        // do nothing
      } else if (trimmed.startsWith('otpauth:')) {
        trimmed = 'otpauth://' + trimmed.slice('otpauth:'.length).replace(/^\/+/, '');
      } else {
        return null;
      }

      // 手动解析，避免部分环境对自定义协议 URL 解析不一致
      const body = trimmed.slice('otpauth://'.length);
      const firstSlash = body.indexOf('/');
      if (firstSlash <= 0) return null;

      const type = body.slice(0, firstSlash).toLowerCase();
      if (type !== 'totp' && type !== 'hotp') return null;

      const rest = body.slice(firstSlash + 1);
      const qIndex = rest.indexOf('?');
      const rawLabel = qIndex >= 0 ? rest.slice(0, qIndex) : rest;
      const rawQuery = qIndex >= 0 ? rest.slice(qIndex + 1) : '';

      let label = '';
      try {
        label = decodeURIComponent(rawLabel || '');
      } catch (_) {
        label = rawLabel || '';
      }

      let issuer = '';
      let name = label;
      const labelColonIndex = label.indexOf(':');
      if (labelColonIndex >= 0) {
        issuer = label.slice(0, labelColonIndex).trim();
        name = label.slice(labelColonIndex + 1).trim();
      }

      const params = {};
      if (rawQuery) {
        if (typeof URLSearchParams !== 'undefined') {
          const searchParams = new URLSearchParams(rawQuery);
          for (const [key, value] of searchParams.entries()) {
            params[key] = value;
          }
        } else {
          const safeDecode = (v) => {
            try {
              return decodeURIComponent(v.replace(/\+/g, ' '));
            } catch (_) {
              return v;
            }
          };
          rawQuery.split('&').forEach(pair => {
            if (!pair) return;
            const eqIndex = pair.indexOf('=');
            const rawKey = eqIndex >= 0 ? pair.slice(0, eqIndex) : pair;
            const rawValue = eqIndex >= 0 ? pair.slice(eqIndex + 1) : '';
            const key = safeDecode(rawKey);
            const value = safeDecode(rawValue);
            params[key] = value;
          });
        }
      }

      if (params.issuer) {
        issuer = params.issuer.trim();
      }

      const secretRaw = typeof params.secret === 'string' ? params.secret.trim() : '';
      if (!secretRaw) return null;

      const digits = parseInt(params.digits, 10);
      const period = parseInt(params.period, 10);

      const result = {
        type,
        name: (name || issuer || '未命名').trim(),
        issuer,
        secret: secretRaw.toUpperCase(),
        algorithm: (params.algorithm || 'SHA1').toUpperCase(),
        digits: Number.isFinite(digits) && digits > 0 ? digits : 6,
        period: Number.isFinite(period) && period > 0 ? period : 30
      };

      if (type === 'hotp') {
        const counter = parseInt(params.counter, 10);
        result.counter = Number.isFinite(counter) && counter >= 0 ? counter : 0;
      }

      return result;
    } catch (e) {
      console.error('解析 otpauth URL 失败:', e);
      return null;
    }
  }

  // ==================== 数据存储 ====================

  const STORAGE_KEY = 'google2fa_entries';
  const THEME_KEY = 'google2fa_theme';

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
  let addDialogInitialState = null;
  let addDialogEscapeRequested = false;

  // ==================== DOM 元素 ====================

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);
  const CLIPBOARD_DEBUG_TAG = '[ClipboardDebug]';

  function maskClipboardPreview(text) {
    if (typeof text !== 'string') return text;
    let masked = text.replace(/(secret=)[^&\s]+/ig, '$1***');
    if (masked.length > 120) {
      masked = masked.slice(0, 120) + '...';
    }
    return masked;
  }

  function logClipboardDebug(step, payload = {}) {
    console.log(CLIPBOARD_DEBUG_TAG, step, payload);
  }

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

    // 搜索过滤
    const searchTerm = $('#searchInput').value.toLowerCase();
    if (searchTerm) {
      sorted = sorted.filter(e =>
        (e.name || '').toLowerCase().includes(searchTerm) ||
        (e.issuer || '').toLowerCase().includes(searchTerm)
      );
    }

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

    grid.innerHTML = sorted.map(entry => {
      const name = entry.name || '未命名';
      const issuer = entry.issuer || '';
      const period = entry.period || 30;
      const seconds = Math.floor(Date.now() / 1000) % period;
      const progress = ((period - seconds) / period) * 100;

      // 存储数据在 data 属性中
      const dataAttrs = `data-id="${entry.id}"
        data-secret="${escapeHtml(entry.secret)}"
        data-algorithm="${entry.algorithm || 'SHA1'}"
        data-digits="${entry.digits || 6}"
        data-type="${entry.type || 'totp'}"
        data-period="${period}"
        data-counter="${entry.counter || 0}"`;

      return `
        <div class="code-card" ${dataAttrs} oncontextmenu="return window.app.showContextMenu(event, '${entry.id}')">
          <div class="code-card-header">
            <div class="code-info">
              <div class="code-name">${escapeHtml(name)}</div>
              ${issuer ? `<div class="code-issuer">${escapeHtml(issuer)}</div>` : ''}
            </div>
          </div>
          <div class="code-value-row">
            <div class="code-value" data-secret="${escapeHtml(entry.secret)}"
                 data-algorithm="${entry.algorithm || 'SHA1'}"
                 data-digits="${entry.digits || 6}"
                 data-type="${entry.type || 'totp'}"
                 data-period="${period}"
                 data-counter="${entry.counter || 0}">------</div>
            <div class="timer-circle" data-period="${period}">
              <svg viewBox="0 0 44 44">
                <circle class="circle-bg" cx="22" cy="22" r="19"/>
                <circle class="circle-progress" cx="22" cy="22" r="19"
                  style="stroke-dasharray: 119.38; stroke-dashoffset: ${119.38 * (1 - progress / 100)}"/>
              </svg>
              <span class="timer-text">${period - seconds}</span>
            </div>
          </div>
        </div>
      `;
    }).join('');

    // 绑定点击事件 - 复制验证码
    $$('.code-card').forEach(card => {
      card.addEventListener('click', (e) => {
        // 如果是右键菜单的，不触发链接复制
        if (e.button === 0) {
          const codeEl = card.querySelector('.code-value');
          const code = codeEl.textContent.replace(/\s/g, '');
          copyToClipboard(code, card);
        }
      });
    });

    // 立即刷新验证码
    refreshCodes();
  }

  // 渲染管理列表
  function renderManageView() {
    const list = $('#manageList');

    if (entries.length === 0) {
      list.innerHTML = '<div class="empty-state show"><p>暂无条目</p></div>';
      return;
    }

    // 搜索过滤
    const searchTerm = $('#searchInput').value.toLowerCase();
    let filtered = entries;
    if (searchTerm) {
      filtered = entries.filter(e =>
        (e.name || '').toLowerCase().includes(searchTerm) ||
        (e.issuer || '').toLowerCase().includes(searchTerm)
      );
    }

    if (filtered.length === 0) {
      list.innerHTML = '<div class="empty-state show"><p>未找到匹配条目</p></div>';
      return;
    }

    list.innerHTML = filtered.map(entry => `
      <div class="manage-item" data-id="${entry.id}" oncontextmenu="return window.app.showContextMenu(event, '${entry.id}')">
        <div class="manage-item-info">
          <div class="manage-item-name">${escapeHtml(entry.name || '未命名')}</div>
          <div class="manage-item-issuer">${escapeHtml(entry.issuer || '')}</div>
        </div>
      </div>
    `).join('');

    // 绑定点击事件 - 左键编辑
    $$('.manage-item').forEach(item => {
      item.addEventListener('click', (e) => {
        if (e.button === 0) {
          const id = item.dataset.id;
          editEntry(id);
        }
      });
    });
  }

  // 刷新验证码
  async function refreshCodes() {
    const codeEls = $$('#codeGrid .code-value');
    const now = Date.now();

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
        console.error('生成验证码失败:', e);
      }
    }

    // 刷新进度条
    const period = 30;
    const seconds = Math.floor(now / 1000) % period;
    const progress = ((period - seconds) / period) * 100;
    const circumference = 2 * Math.PI * 19; // r=19

    $$('.timer-circle').forEach(circle => {
      const progressCircle = circle.querySelector('.circle-progress');
      if (progressCircle) {
        progressCircle.style.strokeDashoffset = circumference * (1 - progress / 100);
      }
      const text = circle.querySelector('.timer-text');
      if (text) text.textContent = period - seconds;
    });
  }

  // ==================== 功能函数 ====================

  function getAddFormState() {
    return {
      name: $('#nameInput')?.value || '',
      issuer: $('#issuerInput')?.value || '',
      secret: $('#secretInput')?.value || '',
      algorithm: $('#algorithmInput')?.value || 'SHA1',
      digits: $('#digitsInput')?.value || '6',
      type: $('#otpTypeInput')?.value || 'totp',
      period: $('#periodInput')?.value || '30',
      counter: $('#counterInput')?.value || '0'
    };
  }

  function markAddDialogClean() {
    addDialogInitialState = JSON.stringify(getAddFormState());
  }

  function isAddDialogDirty() {
    if (!addDialogInitialState) return false;
    return JSON.stringify(getAddFormState()) !== addDialogInitialState;
  }

  function closeAddDialogWithGuard() {
    const dialog = $('#addDialog');
    if (!dialog || !dialog.open) return true;
    if (isAddDialogDirty()) {
      const confirmed = confirm('当前修改未保存，确定关闭吗？');
      if (!confirmed) return false;
    }
    dialog.close();
    return true;
  }

  function prepareCreateDialog() {
    editingId = null;
    $('#dialogTitle').textContent = '添加验证码';
    $('#addForm').reset();
    $('#deleteBtn').style.display = 'none';
    $('#clipboardHint').style.display = 'none';
    delete $('#clipboardHint').dataset.parsed;
  }

  // 切换视图
  function switchView(view) {
    currentView = view;

    // 更新导航按钮
    $$('.nav-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.view === view);
    });

    // 管理页不显示排序控件
    const sortSelect = $('#sortSelect');
    if (sortSelect) {
      sortSelect.style.display = view === 'home' ? '' : 'none';
    }

    // 更新视图显示 - 带动画
    $$('.view').forEach(v => {
      if (v.id === view + 'View') {
        v.classList.add('active');
        v.style.opacity = '0';
        v.style.transform = 'translateY(10px)';
        requestAnimationFrame(() => {
          v.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
          v.style.opacity = '1';
          v.style.transform = 'translateY(0)';
        });
      } else {
        v.classList.remove('active');
        v.style.opacity = '';
        v.style.transform = '';
      }
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
    localStorage.setItem(THEME_KEY, document.body.dataset.theme);
  }

  // 初始化主题
  function initTheme() {
    const saved = localStorage.getItem(THEME_KEY);
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

  // 复制到剪贴板
  async function copyToClipboard(text, cardEl) {
    try {
      if (window.utoolsBridge && window.utoolsBridge.setClipboardText) {
        window.utoolsBridge.setClipboardText(text);
      } else {
        await navigator.clipboard.writeText(text);
      }

      // 更新最后使用时间
      const id = cardEl?.dataset?.id;
      if (id) {
        const entry = entries.find(e => e.id === id);
        if (entry) {
          entry.lastUsed = Date.now();
          saveEntries(entries);
        }
      }

      showToast('已复制: ' + text, 'success');
    } catch (e) {
      showToast('复制失败', 'error');
    }
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
      lastUsed: data.lastUsed || Date.now()
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

  // 编辑条目 - 打开弹窗
  function editEntry(id) {
    const entry = entries.find(e => e.id === id);
    if (!entry) return;

    editingId = id;
    $('#dialogTitle').textContent = '编辑验证码';
    $('#nameInput').value = entry.name || '';
    $('#issuerInput').value = entry.issuer || '';
    $('#secretInput').value = entry.secret || '';
    $('#algorithmInput').value = entry.algorithm || 'SHA1';
    $('#digitsInput').value = entry.digits || 6;
    $('#otpTypeInput').value = entry.type || 'totp';
    $('#periodInput').value = entry.period || 30;
    $('#deleteBtn').style.display = 'block';

    $('#addDialog').showModal();
    markAddDialogClean();
  }

  // 显示右键菜单
  function showContextMenu(event, id) {
    event.preventDefault();

    // 移除已存在的菜单
    const existing = $('#contextMenu');
    if (existing) existing.remove();

    const menu = document.createElement('div');
    menu.id = 'contextMenu';
    menu.className = 'context-menu';
    menu.style.left = event.pageX + 'px';
    menu.style.top = event.pageY + 'px';

    menu.innerHTML = `
      <button class="context-item" data-action="copy">复制验证码</button>
      <button class="context-item" data-action="edit">编辑</button>
      <button class="context-item danger" data-action="delete">删除</button>
    `;

    document.body.appendChild(menu);

    // 绑定菜单项事件
    menu.querySelectorAll('.context-item').forEach(item => {
      item.addEventListener('click', () => {
        const action = item.dataset.action;
        const entry = entries.find(e => e.id === id);

        if (action === 'copy' && entry) {
          // 临时生成并复制
          (async () => {
            try {
              const code = await generateTOTP(entry.secret, {
                digits: entry.digits,
                period: entry.period
              });
              copyToClipboard(code);
            } catch (e) {
              showToast('生成失败', 'error');
            }
          })();
        } else if (action === 'edit') {
          editEntry(id);
        } else if (action === 'delete') {
          if (confirm('确定要删除吗？')) {
            deleteEntry(id);
          }
        }

        menu.remove();
      });
    });

    // 点击其他地方关闭菜单
    const closeMenu = (e) => {
      if (!menu.contains(e.target)) {
        menu.remove();
        document.removeEventListener('click', closeMenu);
      }
    };
    setTimeout(() => document.addEventListener('click', closeMenu), 0);

    return false;
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
  async function handlePaste(source = 'unknown') {
    try {
      logClipboardDebug('handlePaste:start', {
        source,
        hasBridge: !!window.utoolsBridge,
        hasBridgeGetClipboardText: !!(window.utoolsBridge && window.utoolsBridge.getClipboardText),
        hasNavigatorClipboard: !!(navigator.clipboard && navigator.clipboard.readText)
      });

      // 优先使用 utools bridge
      let text = null;
      if (window.utoolsBridge && window.utoolsBridge.getClipboardText) {
        logClipboardDebug('handlePaste:bridge:invoke');
        const clipboardResult = window.utoolsBridge.getClipboardText();
        logClipboardDebug('handlePaste:bridge:return', {
          returnType: typeof clipboardResult,
          isPromise: !!(clipboardResult && typeof clipboardResult.then === 'function')
        });
        text = (clipboardResult && typeof clipboardResult.then === 'function')
          ? await clipboardResult
          : clipboardResult;
        logClipboardDebug('handlePaste:bridge:resolved', {
          textType: typeof text,
          textPreview: maskClipboardPreview(text)
        });
      }
      if ((typeof text !== 'string' || !text) && navigator.clipboard) {
        logClipboardDebug('handlePaste:navigator:fallback:invoke');
        text = await navigator.clipboard.readText();
        logClipboardDebug('handlePaste:navigator:fallback:resolved', {
          textType: typeof text,
          textPreview: maskClipboardPreview(text)
        });
      }
      if (typeof text !== 'string') {
        logClipboardDebug('handlePaste:abort:not-string', { textType: typeof text });
        return null;
      }

      const trimmed = text.trim();
      if (!trimmed) {
        logClipboardDebug('handlePaste:abort:empty-string');
        return null;
      }

      // 尝试解析 otpauth URL
      const parsed = parseOtpauthUrl(trimmed);
      if (parsed) {
        logClipboardDebug('handlePaste:parsed:success', {
          name: parsed.name,
          issuer: parsed.issuer,
          type: parsed.type
        });
        return parsed;
      }

      logClipboardDebug('handlePaste:parsed:failed', {
        trimmedPreview: maskClipboardPreview(trimmed)
      });
      return null;
    } catch (e) {
      logClipboardDebug('handlePaste:error', {
        name: e && e.name ? e.name : 'Error',
        message: e && e.message ? e.message : String(e),
        stack: e && e.stack ? e.stack : ''
      });
      console.error('Paste error:', e);
      return null;
    }
  }

  // 应用解析结果到表单
  function applyParsedData(parsed) {
    if (!parsed) return false;

    $('#nameInput').value = parsed.name || '';
    $('#issuerInput').value = parsed.issuer || '';
    $('#secretInput').value = parsed.secret || '';
    $('#algorithmInput').value = parsed.algorithm;
    $('#digitsInput').value = parsed.digits;
    $('#otpTypeInput').value = parsed.type;
    $('#periodInput').value = parsed.period;
    if (parsed.counter) {
      $('#counterInput').value = parsed.counter;
    }

    // 隐藏剪贴板提示
    $('#clipboardHint').style.display = 'none';
    return true;
  }

  // 检测剪贴板并自动填写
  async function checkClipboardAndShowHint() {
    const parsed = await handlePaste('checkClipboardAndShowHint');
    const hint = $('#clipboardHint');

    if (parsed) {
      // 显示提示
      hint.style.display = 'flex';
      hint.querySelector('span').textContent = '检测到剪贴板验证码：' + (parsed.name || parsed.issuer || '点击导入');
      // 存储解析结果供导入使用
      hint.dataset.parsed = JSON.stringify(parsed);
    } else {
      hint.style.display = 'none';
      delete hint.dataset.parsed;
    }

    logClipboardDebug('checkClipboardAndShowHint:done', {
      parsed: !!parsed
    });
    return parsed;
  }

  // 一键导入剪贴板中的 otpauth
  async function applyClipboardImport() {
    const hint = $('#clipboardHint');
    try {
      if (!hint.dataset.parsed) return;
      const parsed = JSON.parse(hint.dataset.parsed);
      const success = applyParsedData(parsed);
      if (success) {
        showToast('已导入: ' + (parsed.name || parsed.issuer), 'success');
      }
    } catch (e) {
      logClipboardDebug('applyClipboardImport:error', {
        message: e && e.message ? e.message : String(e)
      });
      console.error('导入失败:', e);
    }
  }

  async function debugClipboard() {
    const result = {
      hasBridge: !!window.utoolsBridge,
      hasNavigatorClipboard: !!(navigator.clipboard && navigator.clipboard.readText)
    };

    try {
      if (window.utoolsBridge && window.utoolsBridge.debugClipboardSnapshot) {
        result.bridgeSnapshot = await window.utoolsBridge.debugClipboardSnapshot();
      } else if (window.utoolsBridge && window.utoolsBridge.getClipboardText) {
        const bridgeValue = window.utoolsBridge.getClipboardText();
        const bridgeText = (bridgeValue && typeof bridgeValue.then === 'function')
          ? await bridgeValue
          : bridgeValue;
        result.bridgeGetClipboardText = {
          type: typeof bridgeText,
          preview: maskClipboardPreview(bridgeText)
        };
      }
    } catch (e) {
      result.bridgeError = e && e.message ? e.message : String(e);
    }

    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        const navText = await navigator.clipboard.readText();
        result.navigatorReadText = {
          type: typeof navText,
          preview: maskClipboardPreview(navText)
        };
      }
    } catch (e) {
      result.navigatorError = e && e.message ? e.message : String(e);
    }

    try {
      const parsed = await handlePaste('manual-debug');
      result.parsed = parsed
        ? { name: parsed.name, issuer: parsed.issuer, type: parsed.type }
        : null;
    } catch (e) {
      result.handlePasteError = e && e.message ? e.message : String(e);
    }

    logClipboardDebug('manual-debug:result', result);
    return result;
  }

  // 尝试从图片识别二维码
  async function handleQrFromImage(imageData) {
    // 这需要二维码识别库 jsQR
    // 暂时返回 false，让用户手动输入
    showToast('图片识别需要额外支持', 'error');
    return false;
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

    // 添加按钮 - 新建时自动读取剪贴板
    $('#addBtn').addEventListener('click', async () => {
      prepareCreateDialog();
      $('#addDialog').showModal();

      // 检测剪贴板，仅提示，不自动导入
      await checkClipboardAndShowHint();
      markAddDialogClean();
    });

    // 一键导入按钮
    $('#applyClipboardBtn')?.addEventListener('click', applyClipboardImport);

    $('#addFirstBtn')?.addEventListener('click', async () => {
      prepareCreateDialog();
      $('#addDialog').showModal();

      // 检测剪贴板，仅提示，不自动导入
      await checkClipboardAndShowHint();
      markAddDialogClean();
    });

    // 关闭弹窗
    $('#closeDialog').addEventListener('click', () => {
      closeAddDialogWithGuard();
    });

    $('#addDialog').addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        addDialogEscapeRequested = true;
      }
    });

    $('#addDialog').addEventListener('cancel', (e) => {
      e.preventDefault();
      if (addDialogEscapeRequested) {
        closeAddDialogWithGuard();
      }
      addDialogEscapeRequested = false;
    });

    // 粘贴按钮
    $('#pasteBtn').addEventListener('click', async (e) => {
      logClipboardDebug('pasteBtn:click', {
        isTrusted: e.isTrusted
      });
      const parsed = await handlePaste('pasteBtn');
      logClipboardDebug('pasteBtn:result', { parsed: !!parsed });
      if (parsed) {
        applyParsedData(parsed);
      }
    });

    // 表单提交
    $('#addForm').addEventListener('submit', async (e) => {
      e.preventDefault();

      const data = {
        id: editingId,
        name: $('#nameInput').value.trim(),
        issuer: $('#issuerInput').value.trim(),
        secret: $('#secretInput').value.trim(),
        algorithm: $('#algorithmInput').value,
        digits: parseInt($('#digitsInput').value),
        type: $('#otpTypeInput').value,
        period: parseInt($('#periodInput').value),
        counter: parseInt($('#counterInput')?.value) || 0
      };

      if (!data.name) {
        showToast('请输入名称', 'error');
        return;
      }

      if (!data.secret) {
        showToast('请输入密钥', 'error');
        return;
      }

      // 尝试解析 otpauth URL（用户可能粘贴了完整链接）
      const parsed = parseOtpauthUrl(data.secret);
      if (parsed) {
        data.name = data.name || parsed.name;
        data.issuer = data.issuer || parsed.issuer;
        data.secret = parsed.secret;
        data.algorithm = parsed.algorithm;
        data.digits = parsed.digits;
        data.type = parsed.type;
        data.period = parsed.period;
        if (parsed.counter) data.counter = parsed.counter;
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

    // HOTP 类型切换时显示/隐藏 counter
    $('#otpTypeInput').addEventListener('change', (e) => {
      const counterLabel = $('#counterLabel');
      if (counterLabel) {
        counterLabel.style.display = e.target.value === 'hotp' ? 'flex' : 'none';
      }
    });

    // 搜索 - 两个视图都支持
    $('#searchInput').addEventListener('input', () => {
      if (currentView === 'home') {
        renderHomeView();
      } else {
        renderManageView();
      }
    });

    // 排序 - 仅首页
    $('#sortSelect').addEventListener('change', () => {
      if (currentView === 'home') renderHomeView();
    });

    // 初始渲染
    switchView('home');
    initRefreshInterval();
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
    toggleTheme,
    showContextMenu,
    testTOTP,  // 用于测试 TOTP 生成是否正确
    debugClipboard
  };

})();
