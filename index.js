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
      const trimmed = url.trim();
      if (!trimmed.startsWith('otpauth://')) {
        // 尝试自动添加协议
        if (trimmed.startsWith('otpauth')) {
          trimmed = 'otpauth://' + trimmed.slice(7);
        } else {
          return null;
        }
      }

      const urlObj = new URL(trimmed);
      if (urlObj.protocol !== 'otpauth:') return null;

      const type = urlObj.hostname.toLowerCase(); // totp 或 hotp
      if (type !== 'totp' && type !== 'hotp') return null;

      // 解析路径（通常是 issuer:name 或只有 name）
      let path = decodeURIComponent(urlObj.pathname.slice(1));
      let name = path;
      let issuer = '';

      // 路径格式可能是 "issuer:name" 或只有 "name"
      if (path.includes(':')) {
        const parts = path.split(':');
        issuer = parts[0];
        name = parts.slice(1).join(':');
      }

      // 解析查询参数
      const params = Object.fromEntries(urlObj.searchParams);

      // issuer 参数可能覆盖路径中的 issuer
      if (params.issuer) {
        issuer = params.issuer;
      }

      // secret 是必需的
      if (!params.secret) return null;

      const result = {
        type,
        name: name || issuer || '未命名',
        issuer: issuer,
        secret: params.secret.toUpperCase(),
        algorithm: (params.algorithm || 'SHA1').toUpperCase(),
        digits: parseInt(params.digits) || 6,
        period: parseInt(params.period) || 30
      };

      // HOTP 需要 counter
      if (type === 'hotp') {
        result.counter = parseInt(params.counter) || 0;
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
            <div class="timer-circle" style="--progress: ${progress}">
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

    list.innerHTML = entries.map(entry => `
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
  async function handlePaste() {
    try {
      // 优先使用 utools bridge
      let text = null;
      if (window.utoolsBridge && window.utoolsBridge.getClipboardText) {
        text = window.utoolsBridge.getClipboardText();
      }
      if (!text && navigator.clipboard) {
        text = await navigator.clipboard.readText();
      }
      if (!text) return;

      const trimmed = text.trim();

      // 1. 尝试解析 otpauth URL
      const parsed = parseOtpauthUrl(trimmed);
      if (parsed) {
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
        showToast('已从剪贴板解析 otpauth', 'success');
        return true;
      }

      // 2. 尝试从图片识别（需要实现）
      // 这里只是把文本放入输入框
      $('#secretInput').value = trimmed;
      return false;
    } catch (e) {
      console.error('Paste error:', e);
      return false;
    }
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
      editingId = null;
      $('#dialogTitle').textContent = '添加验证码';
      $('#addForm').reset();
      $('#deleteBtn').style.display = 'none';
      $('#addDialog').showModal();

      // 自动尝试从剪贴板读取
      await handlePaste();
    });

    $('#addFirstBtn')?.addEventListener('click', async () => {
      editingId = null;
      $('#dialogTitle').textContent = '添加验证码';
      $('#addForm').reset();
      $('#deleteBtn').style.display = 'none';
      $('#addDialog').showModal();

      // 自动尝试从剪贴板读取
      await handlePaste();
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

    // 搜索
    $('#searchInput').addEventListener('input', () => {
      if (currentView === 'home') renderHomeView();
    });

    // 排序
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
    testTOTP  // 用于测试 TOTP 生成是否正确
  };

})();
