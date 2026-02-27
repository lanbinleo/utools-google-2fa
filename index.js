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
  const testTOTP = async function() {
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

  function normalizeTags(tags) {
    if (!Array.isArray(tags)) return [];
    const normalized = tags
      .map(tag => (tag == null ? '' : String(tag)).trim())
      .filter(Boolean);
    return Array.from(new Set(normalized)).slice(0, 10);
  }

  function normalizeEntry(raw) {
    if (!raw || typeof raw !== 'object') return null;
    const pinned = !!raw.pinned;
    const pinnedAt = pinned
      ? (Number.isFinite(raw.pinnedAt) && raw.pinnedAt > 0
        ? raw.pinnedAt
        : (Number.isFinite(raw.lastUsed) ? raw.lastUsed : Date.now()))
      : 0;
    return {
      ...raw,
      tags: normalizeTags(raw.tags),
      pinned,
      pinnedAt,
      deprecated: !!raw.deprecated
    };
  }

  function getEntries() {
    try {
      const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
      return parsed.map(normalizeEntry).filter(Boolean);
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
  let toastTimer = null;
  let addDialogInitialState = null;
  let addDialogEscapeRequested = false;
  let selectedTags = [];

  // ==================== DOM 元素 ====================

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);
  const CLIPBOARD_DEBUG_TAG = '[ClipboardDebug]';
  const CLIPBOARD_DEBUG_ENABLED = (() => {
    try {
      return localStorage.getItem('google2fa_debug_clipboard') === '1';
    } catch (_) {
      return false;
    }
  })();

  function maskClipboardPreview(text) {
    if (typeof text !== 'string') return text;
    let masked = text.replace(/(secret=)[^&\s]+/ig, '$1***');
    if (masked.length > 120) {
      masked = masked.slice(0, 120) + '...';
    }
    return masked;
  }

  function logClipboardDebug(step, payload = {}) {
    if (!CLIPBOARD_DEBUG_ENABLED) return;
    console.log(CLIPBOARD_DEBUG_TAG, step, payload);
  }

  // ==================== UI 渲染 ====================

  function markLastRowCards() {
    const cards = Array.from($$('#codeGrid .code-card'));
    cards.forEach(card => card.classList.remove('is-last-row'));
    if (!cards.length) return;

    const maxTop = Math.max(...cards.map(card => card.offsetTop));
    cards.forEach(card => {
      if (card.offsetTop === maxTop) {
        card.classList.add('is-last-row');
      }
    });
  }

  function renderTagBadges(tags, maxCount = 2) {
    const safeTags = normalizeTags(tags);
    if (!safeTags.length) return '';
    const visible = safeTags.slice(0, maxCount).map(tag =>
      `<span class="tag-badge" title="${escapeHtml(tag)}">${escapeHtml(tag)}</span>`
    ).join('');
    const extra = safeTags.length > maxCount
      ? `<span class="tag-badge tag-badge-muted">+${safeTags.length - maxCount}</span>`
      : '';
    return visible + extra;
  }

  function byPinnedThenPinnedAtDesc(a, b) {
    if (!!a.pinned !== !!b.pinned) return a.pinned ? -1 : 1;
    if (a.pinned && b.pinned) return (b.pinnedAt || 0) - (a.pinnedAt || 0);
    return 0;
  }

  // 渲染首页验证码卡片
  function renderHomeView() {
    const grid = $('#codeGrid');
    const empty = $('#emptyState');
    const visibleEntries = entries.filter(e => !e.deprecated);

    // 排序
    const sortType = $('#sortSelect').value;
    let sorted = [...visibleEntries];

    // 搜索过滤
    const searchTerm = $('#searchInput').value.toLowerCase();
    if (searchTerm) {
      sorted = sorted.filter(e =>
        (e.name || '').toLowerCase().includes(searchTerm) ||
        (e.issuer || '').toLowerCase().includes(searchTerm) ||
        (normalizeTags(e.tags).join(' ').toLowerCase().includes(searchTerm))
      );
    }

    const secondarySort = {
      name: (a, b) => (a.name || '').localeCompare(b.name || ''),
      recent: (a, b) => (b.lastUsed || 0) - (a.lastUsed || 0),
      default: (a, b) => (b.lastUsed || 0) - (a.lastUsed || 0)
    }[sortType] || ((a, b) => (b.lastUsed || 0) - (a.lastUsed || 0));

    sorted.sort((a, b) => {
      const pinOrder = byPinnedThenPinnedAtDesc(a, b);
      if (pinOrder !== 0) return pinOrder;
      return secondarySort(a, b);
    });

    if (sorted.length === 0) {
      grid.innerHTML = '';
      empty.classList.add('show');
      return;
    }

    empty.classList.remove('show');

    grid.innerHTML = sorted.map(entry => {
      const name = entry.name || '未命名';
      const issuer = entry.issuer || '';
      const period = entry.period || 30;
      const seconds = Math.floor(Date.now() / 1000) % period;
      const progress = ((period - seconds) / period) * 100;
      const pinBadge = entry.pinned ? `
        <span class="pin-indicator" title="已置顶" aria-label="已置顶">
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><g id="SVGRepo_bgCarrier" stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"> <path d="M15.9894 4.9502L16.52 4.42014L16.52 4.42014L15.9894 4.9502ZM8.73845 19.429L8.20785 19.9591L8.73845 19.429ZM4.62176 15.3081L5.15236 14.7781L4.62176 15.3081ZM17.567 14.9943L17.3032 14.2922L17.567 14.9943ZM15.6499 15.7146L15.9137 16.4167L15.6499 15.7146ZM8.33227 8.38177L7.62805 8.12375H7.62805L8.33227 8.38177ZM9.02673 6.48636L9.73095 6.74438L9.02673 6.48636ZM5.84512 10.6735L6.04445 11.3965H6.04445L5.84512 10.6735ZM7.30174 10.1351L6.86354 9.52646L6.86354 9.52646L7.30174 10.1351ZM7.6759 9.79038L8.24673 10.2768H8.24673L7.6759 9.79038ZM14.2511 16.3805L14.7421 16.9475L14.7421 16.9475L14.2511 16.3805ZM13.3807 18.2012L12.6575 18.0022V18.0022L13.3807 18.2012ZM13.917 16.7466L13.3076 16.3094L13.3076 16.3094L13.917 16.7466ZM2.71854 12.7552L1.96855 12.76V12.76L2.71854 12.7552ZM2.93053 11.9521L2.28061 11.5778H2.28061L2.93053 11.9521ZM11.3053 21.3431L11.3064 20.5931H11.3064L11.3053 21.3431ZM12.0933 21.1347L11.7216 20.4833L11.7216 20.4833L12.0933 21.1347ZM21.9652 12.3049L22.6983 12.4634L21.9652 12.3049ZM11.6973 2.03606L11.8589 2.76845L11.6973 2.03606ZM22.3552 10.6303C22.1511 10.2699 21.6934 10.1433 21.333 10.3475C20.9726 10.5516 20.846 11.0093 21.0502 11.3697L22.3552 10.6303ZM18.006 8.03006C18.2988 8.3231 18.7737 8.32334 19.0667 8.0306C19.3597 7.73786 19.36 7.26298 19.0672 6.96994L18.006 8.03006ZM9.26905 18.8989L5.15236 14.7781L4.09116 15.8382L8.20785 19.9591L9.26905 18.8989ZM17.3032 14.2922L15.3861 15.0125L15.9137 16.4167L17.8308 15.6964L17.3032 14.2922ZM9.03649 8.63979L9.73095 6.74438L8.32251 6.22834L7.62805 8.12375L9.03649 8.63979ZM6.04445 11.3965C6.75591 11.2003 7.29726 11.0625 7.73995 10.7438L6.86354 9.52646C6.6906 9.65097 6.46608 9.72428 5.64578 9.95044L6.04445 11.3965ZM7.62805 8.12375C7.3351 8.92332 7.24345 9.14153 7.10507 9.30391L8.24673 10.2768C8.60048 9.86175 8.78237 9.33337 9.03649 8.63979L7.62805 8.12375ZM7.73995 10.7438C7.92704 10.6091 8.09719 10.4523 8.24673 10.2768L7.10507 9.30391C7.03377 9.38757 6.95268 9.46229 6.86354 9.52646L7.73995 10.7438ZM15.3861 15.0125C14.697 15.2714 14.1717 15.4571 13.7601 15.8135L14.7421 16.9475C14.9029 16.8082 15.1193 16.7152 15.9137 16.4167L15.3861 15.0125ZM14.1038 18.4001C14.3291 17.5813 14.4022 17.3569 14.5263 17.1838L13.3076 16.3094C12.9903 16.7517 12.853 17.2919 12.6575 18.0022L14.1038 18.4001ZM13.7601 15.8135C13.5904 15.9605 13.4385 16.1269 13.3076 16.3094L14.5263 17.1838C14.5888 17.0968 14.6612 17.0175 14.7421 16.9475L13.7601 15.8135ZM5.15236 14.7781C4.50623 14.1313 4.06806 13.691 3.78374 13.3338C3.49842 12.9753 3.46896 12.8201 3.46852 12.7505L1.96855 12.76C1.97223 13.3422 2.26135 13.8297 2.6101 14.2679C2.95984 14.7073 3.47123 15.2176 4.09116 15.8382L5.15236 14.7781ZM5.64578 9.95044C4.80056 10.1835 4.10403 10.3743 3.58304 10.5835C3.06349 10.792 2.57124 11.0732 2.28061 11.5778L3.58045 12.3264C3.61507 12.2663 3.717 12.146 4.14187 11.9755C4.56531 11.8055 5.16345 11.6394 6.04445 11.3965L5.64578 9.95044ZM3.46852 12.7505C3.46758 12.6016 3.50623 12.4553 3.58045 12.3264L2.28061 11.5778C2.07362 11.9372 1.96593 12.3452 1.96855 12.76L3.46852 12.7505ZM8.20785 19.9591C8.83172 20.5836 9.34472 21.0987 9.78654 21.4506C10.2271 21.8015 10.718 22.0922 11.3042 22.0931L11.3064 20.5931C11.237 20.593 11.0815 20.5644 10.7211 20.2773C10.3619 19.9912 9.91931 19.5499 9.26905 18.8989L8.20785 19.9591ZM12.6575 18.0022C12.4133 18.8897 12.2463 19.4924 12.0752 19.9188C11.9034 20.3467 11.7822 20.4487 11.7216 20.4833L12.4651 21.7861C12.9741 21.4956 13.2573 21.0004 13.4672 20.4775C13.6777 19.9532 13.8695 19.2516 14.1038 18.4001L12.6575 18.0022ZM11.3042 22.0931C11.7113 22.0937 12.1115 21.9879 12.4651 21.7861L11.7216 20.4833C11.5951 20.5555 11.452 20.5933 11.3064 20.5931L11.3042 22.0931ZM17.8308 15.6964C19.1922 15.1849 20.2941 14.773 21.0771 14.3384C21.8719 13.8973 22.5084 13.3416 22.6983 12.4634L21.2322 12.1464C21.178 12.3968 21.0002 12.6655 20.3492 13.0268C19.6865 13.3946 18.7113 13.7632 17.3032 14.2922L17.8308 15.6964ZM16.52 4.42014C15.4841 3.3832 14.6481 2.54353 13.9246 2.00638C13.1909 1.46165 12.4175 1.10912 11.5357 1.30367L11.8589 2.76845C12.1086 2.71335 12.4278 2.7633 13.0305 3.21075C13.6434 3.66579 14.3877 4.40801 15.4588 5.48026L16.52 4.42014ZM9.73095 6.74438C10.2526 5.32075 10.6162 4.33403 10.9813 3.66315C11.3403 3.00338 11.6091 2.82357 11.8589 2.76845L11.5357 1.30367C10.6541 1.49819 10.1006 2.14332 9.6637 2.94618C9.23286 3.73793 8.82695 4.85154 8.32251 6.22834L9.73095 6.74438ZM21.0502 11.3697C21.2515 11.7251 21.2745 11.9507 21.2322 12.1464L22.6983 12.4634C22.8404 11.8064 22.6796 11.2027 22.3552 10.6303L21.0502 11.3697ZM15.4588 5.48026L18.006 8.03006L19.0672 6.96994L16.52 4.42014L15.4588 5.48026Z" fill="currentColor"></path> <path d="M1.4694 21.4697C1.17666 21.7627 1.1769 22.2376 1.46994 22.5304C1.76298 22.8231 2.23786 22.8229 2.5306 22.5298L1.4694 21.4697ZM7.18383 17.8719C7.47657 17.5788 7.47633 17.1039 7.18329 16.8112C6.89024 16.5185 6.41537 16.5187 6.12263 16.8117L7.18383 17.8719ZM2.5306 22.5298L7.18383 17.8719L6.12263 16.8117L1.4694 21.4697L2.5306 22.5298Z" fill="currentColor"></path> </g></svg>
        </span>
      ` : '';
      const tagBadges = renderTagBadges(entry.tags, 1);
      const headerBadges = pinBadge || tagBadges
        ? `<div class="code-badges">${pinBadge}${tagBadges}</div>`
        : '';

      // 存储数据在 data 属性中
      const dataAttrs = `data-id="${entry.id}"
        data-secret="${escapeHtml(entry.secret)}"
        data-algorithm="${entry.algorithm || 'SHA1'}"
        data-digits="${entry.digits || 6}"
        data-type="${entry.type || 'totp'}"
        data-period="${period}"
        data-counter="${entry.counter || 0}"`;

      return `
        <div class="code-card" ${dataAttrs}>
          <div class="code-card-header">
            <div class="code-info">
              <div class="code-name">${escapeHtml(name)}</div>
              ${issuer ? `<div class="code-issuer">${escapeHtml(issuer)}</div>` : ''}
            </div>
            ${headerBadges}
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

    // 立即刷新验证码
    refreshCodes();
    markLastRowCards();
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
        (e.issuer || '').toLowerCase().includes(searchTerm) ||
        (normalizeTags(e.tags).join(' ').toLowerCase().includes(searchTerm))
      );
    }

    filtered = [...filtered].sort((a, b) => {
      if (!!a.deprecated !== !!b.deprecated) return a.deprecated ? 1 : -1;
      const pinOrder = byPinnedThenPinnedAtDesc(a, b);
      if (pinOrder !== 0) return pinOrder;
      return (a.name || '').localeCompare(b.name || '');
    });

    if (filtered.length === 0) {
      list.innerHTML = '<div class="empty-state show"><p>未找到匹配条目</p></div>';
      return;
    }

    list.innerHTML = filtered.map(entry => `
      <div class="manage-item ${entry.deprecated ? 'deprecated-state' : ''}" data-id="${entry.id}">
        <div class="manage-item-info">
          <div class="manage-item-name">${escapeHtml(entry.name || '未命名')}</div>
          <div class="manage-item-issuer">${escapeHtml(entry.issuer || '')}</div>
        </div>
        <div class="manage-item-meta">
          ${renderTagBadges(entry.tags, 2)}
          ${entry.pinned ? '<span class="status-badge">已置顶</span>' : ''}
          ${entry.deprecated ? '<span class="status-badge deprecated">已弃用</span>' : ''}
        </div>
        <div class="manage-item-actions">
          <button type="button" class="mini-action ${entry.pinned ? 'active' : ''}" data-action="toggle-pin">
            ${entry.pinned ? '取消置顶' : '置顶'}
          </button>
          <label class="mini-check ${entry.deprecated ? 'deprecated-active' : ''}" data-action="toggle-deprecated">
            <input type="checkbox" data-action="toggle-deprecated" ${entry.deprecated ? 'checked' : ''}>
            <span>弃用</span>
          </label>
        </div>
      </div>
    `).join('');
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

    const circumference = 2 * Math.PI * 19; // r=19

    $$('.timer-circle').forEach(circle => {
      const period = parseInt(circle.dataset.period) || 30;
      const seconds = Math.floor(now / 1000) % period;
      const progress = ((period - seconds) / period) * 100;

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
      counter: $('#counterInput')?.value || '0',
      pinned: Boolean($('#pinnedInput')?.checked),
      deprecated: Boolean($('#deprecatedInput')?.checked),
      tags: normalizeTags(selectedTags).join('|')
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

  function getAllTags() {
    return Array.from(new Set(
      entries.flatMap(entry => normalizeTags(entry.tags))
    )).sort((a, b) => a.localeCompare(b));
  }

  function setSelectedTags(tags) {
    selectedTags = normalizeTags(tags);
    renderSelectedTags();
    renderTagSuggestions();
  }

  function renderSelectedTags() {
    const container = $('#selectedTags');
    if (!container) return;
    container.innerHTML = selectedTags.map(tag => `
      <span class="selected-chip" data-tag="${escapeHtml(tag)}">
        ${escapeHtml(tag)}
        <button type="button" class="tag-remove" data-tag="${escapeHtml(tag)}" aria-label="移除标签">x</button>
      </span>
    `).join('');
  }

  function renderTagSuggestions(keyword = '') {
    const container = $('#tagSuggestions');
    if (!container) return;
    const normalizedKeyword = (keyword || '').trim().toLowerCase();
    const suggestions = getAllTags()
      .filter(tag => !selectedTags.includes(tag))
      .filter(tag => !normalizedKeyword || tag.toLowerCase().includes(normalizedKeyword))
      .slice(0, 8);
    container.innerHTML = suggestions.map(tag =>
      `<button type="button" class="tag-chip" data-tag="${escapeHtml(tag)}">${escapeHtml(tag)}</button>`
    ).join('');
  }

  function addTag(tag) {
    const normalized = String(tag || '').trim();
    if (!normalized) return;
    if (selectedTags.includes(normalized)) return;
    selectedTags = normalizeTags([...selectedTags, normalized]);
    renderSelectedTags();
    renderTagSuggestions();
    const tagInput = $('#tagInput');
    if (tagInput) tagInput.value = '';
  }

  function removeTag(tag) {
    selectedTags = selectedTags.filter(item => item !== tag);
    renderSelectedTags();
    renderTagSuggestions();
  }

  function toggleEntryPinned(id) {
    const entry = entries.find(e => e.id === id);
    if (!entry) return;
    if (entry.pinned) {
      entry.pinned = false;
      entry.pinnedAt = 0;
      showToast('已取消置顶', 'success');
    } else {
      entry.pinned = true;
      entry.pinnedAt = Date.now();
      showToast('已置顶', 'success');
    }
    saveEntries(entries);
    renderCurrentView();
  }

  function toggleEntryDeprecated(id) {
    const entry = entries.find(e => e.id === id);
    if (!entry) return;
    entry.deprecated = !entry.deprecated;
    showToast(entry.deprecated ? '已标记为弃用' : '已恢复启用', 'success');
    saveEntries(entries);
    renderCurrentView();
  }

  function syncOtpTypeVisibility() {
    const counterLabel = $('#counterLabel');
    const otpType = $('#otpTypeInput')?.value || 'totp';
    if (counterLabel) {
      counterLabel.style.display = otpType === 'hotp' ? 'flex' : 'none';
    }
  }

  function prepareCreateDialog() {
    editingId = null;
    $('#dialogTitle').textContent = '添加验证码';
    $('#addForm').reset();
    $('#pinnedInput').checked = false;
    $('#deprecatedInput').checked = false;
    $('#deleteBtn').style.display = 'none';
    $('#clipboardHint').style.display = 'none';
    delete $('#clipboardHint').dataset.parsed;
    setSelectedTags([]);
    syncOtpTypeVisibility();
  }

  function openImportMenu() {
    const importMenu = $('#importMenuDialog');
    if (importMenu && !importMenu.open) {
      importMenu.showModal();
    }
  }

  function closeImportMenu() {
    const importMenu = $('#importMenuDialog');
    if (importMenu && importMenu.open) {
      importMenu.close();
    }
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
    if (toastTimer) {
      clearTimeout(toastTimer);
    }
    toastTimer = setTimeout(() => {
      toast.classList.remove('show');
      toastTimer = null;
    }, 2500);
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
    const existingEntry = entries.find(e => e.id === data.id);
    const pinned = !!data.pinned;
    const wasPinned = !!existingEntry?.pinned;
    let pinnedAt = pinned ? (existingEntry?.pinnedAt || 0) : 0;
    if (pinned && !wasPinned) pinnedAt = Date.now();
    if (pinned && !pinnedAt) pinnedAt = Date.now();

    const entry = normalizeEntry({
      ...existingEntry,
      id: data.id || generateId(),
      name: data.name || '',
      issuer: data.issuer || '',
      secret: data.secret || '',
      algorithm: data.algorithm || 'SHA1',
      digits: parseInt(data.digits) || 6,
      type: data.type || 'totp',
      period: parseInt(data.period) || 30,
      counter: parseInt(data.counter) || 0,
      pinned,
      pinnedAt,
      deprecated: !!data.deprecated,
      tags: normalizeTags(data.tags),
      lastUsed: existingEntry?.lastUsed || data.lastUsed || Date.now()
    });

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
    $('#counterInput').value = entry.counter || 0;
    $('#pinnedInput').checked = !!entry.pinned;
    $('#deprecatedInput').checked = !!entry.deprecated;
    setSelectedTags(entry.tags || []);
    syncOtpTypeVisibility();
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
              const options = {
                algorithm: entry.algorithm || 'SHA1',
                digits: entry.digits || 6,
                period: entry.period || 30,
                counter: entry.counter || 0
              };
              const code = entry.type === 'hotp'
                ? await generateHOTP(entry.secret, options)
                : await generateTOTP(entry.secret, options);
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
      if (CLIPBOARD_DEBUG_ENABLED) {
        console.error('Paste error:', e);
      }
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
    if (parsed.counter !== undefined) {
      $('#counterInput').value = parsed.counter;
    }
    syncOtpTypeVisibility();

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
    setSelectedTags([]);

    // 初始化主题
    initTheme();

    // 导航切换
    $$('.nav-btn').forEach(btn => {
      btn.addEventListener('click', () => switchView(btn.dataset.view));
    });

    // 首页卡片事件委托
    $('#codeGrid')?.addEventListener('click', (e) => {
      const card = e.target.closest('.code-card');
      if (!card || !$('#codeGrid').contains(card)) return;
      const codeEl = card.querySelector('.code-value');
      const code = (codeEl?.textContent || '').replace(/\s/g, '');
      if (code) copyToClipboard(code, card);
    });

    $('#codeGrid')?.addEventListener('contextmenu', (e) => {
      const card = e.target.closest('.code-card');
      if (!card || !$('#codeGrid').contains(card)) return;
      const id = card.dataset.id;
      if (id) showContextMenu(e, id);
    });

    // 管理列表事件委托
    $('#manageList')?.addEventListener('click', (e) => {
      const item = e.target.closest('.manage-item');
      if (!item || !$('#manageList').contains(item)) return;
      const id = item.dataset.id;
      if (!id) return;

      const actionBtn = e.target.closest('[data-action]');
      if (actionBtn && item.contains(actionBtn)) {
        const action = actionBtn.dataset.action;
        if (action === 'toggle-pin') {
          toggleEntryPinned(id);
        } else if (action === 'toggle-deprecated') {
          toggleEntryDeprecated(id);
        }
        return;
      }

      editEntry(id);
    });

    $('#manageList')?.addEventListener('contextmenu', (e) => {
      const item = e.target.closest('.manage-item');
      if (!item || !$('#manageList').contains(item)) return;
      const id = item.dataset.id;
      if (id) showContextMenu(e, id);
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

    // 导入菜单
    $('#closeImportMenu')?.addEventListener('click', closeImportMenu);
    $('#importMenuDialog')?.addEventListener('cancel', (e) => {
      e.preventDefault();
      closeImportMenu();
    });

    $('#importOtpauthBtn')?.addEventListener('click', async () => {
      closeImportMenu();
      prepareCreateDialog();
      $('#addDialog').showModal();
      await checkClipboardAndShowHint();
      markAddDialogClean();
      $('#secretInput')?.focus();
    });

    $('#importQrBtn')?.addEventListener('click', () => {
      showToast('屏幕二维码导入即将上线', 'error');
      closeImportMenu();
    });

    $('#importJsonBtn')?.addEventListener('click', () => {
      showToast('JSON 导入即将上线', 'error');
      closeImportMenu();
    });

    $('#qrFileInput')?.addEventListener('change', async (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = async () => {
        await handleQrFromImage(reader.result);
        e.target.value = '';
      };
      reader.readAsDataURL(file);
      closeImportMenu();
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

    // 标签编辑
    $('#addTagBtn')?.addEventListener('click', () => {
      addTag($('#tagInput')?.value || '');
    });

    $('#tagInput')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        addTag(e.target.value);
      }
    });

    $('#tagInput')?.addEventListener('input', (e) => {
      renderTagSuggestions(e.target.value);
    });

    $('#tagSuggestions')?.addEventListener('click', (e) => {
      const chip = e.target.closest('.tag-chip');
      if (!chip) return;
      addTag(chip.dataset.tag);
    });

    $('#selectedTags')?.addEventListener('click', (e) => {
      const removeBtn = e.target.closest('.tag-remove');
      if (!removeBtn) return;
      removeTag(removeBtn.dataset.tag);
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
        counter: parseInt($('#counterInput')?.value) || 0,
        pinned: Boolean($('#pinnedInput')?.checked),
        deprecated: Boolean($('#deprecatedInput')?.checked),
        tags: normalizeTags(selectedTags)
      };

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
        if (parsed.counter !== undefined) data.counter = parsed.counter;
      }

      if (!data.name) {
        showToast('请输入名称', 'error');
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

    // HOTP 类型切换时显示/隐藏 counter
    $('#otpTypeInput').addEventListener('change', () => {
      syncOtpTypeVisibility();
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

    window.addEventListener('resize', () => {
      if (currentView === 'home') {
        markLastRowCards();
      }
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
    openImportMenu
  };

  if (CLIPBOARD_DEBUG_ENABLED) {
    window.app.testTOTP = testTOTP;
    window.app.debugClipboard = debugClipboard;
  }

})();
