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

  function bytesToBase32(bytes) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let output = '';
    let buffer = 0;
    let bitsLeft = 0;

    for (let i = 0; i < bytes.length; i++) {
      buffer = (buffer << 8) | (bytes[i] & 0xff);
      bitsLeft += 8;
      while (bitsLeft >= 5) {
        bitsLeft -= 5;
        output += alphabet[(buffer >> bitsLeft) & 0x1f];
      }
    }

    if (bitsLeft > 0) {
      output += alphabet[(buffer << (5 - bitsLeft)) & 0x1f];
    }

    return output;
  }

  function decodeBase64ToBytes(base64Text) {
    const normalized = String(base64Text || '')
      .trim()
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .replace(/\s+/g, '');

    if (!normalized) return null;

    const pad = normalized.length % 4;
    const padded = pad === 0 ? normalized : normalized + '='.repeat(4 - pad);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function readProtoVarint(bytes, offset) {
    let result = 0n;
    let shift = 0n;
    let pos = offset;

    while (pos < bytes.length) {
      const b = bytes[pos++];
      result |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) {
        return { value: result, offset: pos };
      }
      shift += 7n;
      if (shift > 70n) break;
    }

    return null;
  }

  function skipProtoField(bytes, offset, wireType) {
    if (wireType === 0) {
      const v = readProtoVarint(bytes, offset);
      return v ? v.offset : null;
    }
    if (wireType === 1) {
      return offset + 8 <= bytes.length ? offset + 8 : null;
    }
    if (wireType === 2) {
      const lenV = readProtoVarint(bytes, offset);
      if (!lenV) return null;
      const len = Number(lenV.value);
      const next = lenV.offset + len;
      return next <= bytes.length ? next : null;
    }
    if (wireType === 5) {
      return offset + 4 <= bytes.length ? offset + 4 : null;
    }
    return null;
  }

  function decodeUtf8Bytes(bytes) {
    try {
      if (typeof TextDecoder !== 'undefined') {
        return new TextDecoder('utf-8').decode(bytes);
      }
    } catch (_) {
      // ignore
    }
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      out += String.fromCharCode(bytes[i]);
    }
    try {
      return decodeURIComponent(escape(out));
    } catch (_) {
      return out;
    }
  }

  function parseMigrationOtpParameter(bytes) {
    const item = {
      secret: '',
      name: '',
      issuer: '',
      algorithm: 'SHA1',
      digits: 6,
      type: 'totp',
      period: 30,
      counter: 0
    };

    let offset = 0;
    while (offset < bytes.length) {
      const tagV = readProtoVarint(bytes, offset);
      if (!tagV) return null;
      offset = tagV.offset;
      const tag = Number(tagV.value);
      const field = tag >> 3;
      const wire = tag & 0x07;

      if (field === 1 && wire === 2) {
        const lenV = readProtoVarint(bytes, offset);
        if (!lenV) return null;
        const len = Number(lenV.value);
        const start = lenV.offset;
        const end = start + len;
        if (end > bytes.length) return null;
        item.secret = bytesToBase32(bytes.slice(start, end));
        offset = end;
        continue;
      }

      if ((field === 2 || field === 3) && wire === 2) {
        const lenV = readProtoVarint(bytes, offset);
        if (!lenV) return null;
        const len = Number(lenV.value);
        const start = lenV.offset;
        const end = start + len;
        if (end > bytes.length) return null;
        const text = decodeUtf8Bytes(bytes.slice(start, end));
        if (field === 2) item.name = text;
        if (field === 3) item.issuer = text;
        offset = end;
        continue;
      }

      if ((field === 4 || field === 5 || field === 6 || field === 7) && wire === 0) {
        const valueV = readProtoVarint(bytes, offset);
        if (!valueV) return null;
        const value = Number(valueV.value);
        if (field === 4) {
          item.algorithm = ({ 1: 'SHA1', 2: 'SHA256', 3: 'SHA512', 4: 'MD5' })[value] || 'SHA1';
        } else if (field === 5) {
          item.digits = ({ 1: 6, 2: 8 })[value] || 6;
        } else if (field === 6) {
          item.type = value === 1 ? 'hotp' : 'totp';
        } else if (field === 7) {
          item.counter = Number.isFinite(value) && value >= 0 ? value : 0;
        }
        offset = valueV.offset;
        continue;
      }

      const skipped = skipProtoField(bytes, offset, wire);
      if (skipped == null) return null;
      offset = skipped;
    }

    if (!item.secret) return null;
    if (!item.name) item.name = item.issuer || 'Imported';
    return item;
  }

  function parseMigrationPayload(bytes) {
    const items = [];
    let offset = 0;

    while (offset < bytes.length) {
      const tagV = readProtoVarint(bytes, offset);
      if (!tagV) return null;
      offset = tagV.offset;
      const tag = Number(tagV.value);
      const field = tag >> 3;
      const wire = tag & 0x07;

      if (field === 1 && wire === 2) {
        const lenV = readProtoVarint(bytes, offset);
        if (!lenV) return null;
        const len = Number(lenV.value);
        const start = lenV.offset;
        const end = start + len;
        if (end > bytes.length) return null;
        const parsed = parseMigrationOtpParameter(bytes.slice(start, end));
        if (parsed) items.push(parsed);
        offset = end;
        continue;
      }

      const skipped = skipProtoField(bytes, offset, wire);
      if (skipped == null) return null;
      offset = skipped;
    }

    return items;
  }

  function parseOtpauthMigrationDataPayload(dataText) {
    const bytes = decodeBase64ToBytes(dataText);
    if (!bytes || !bytes.length) return [];
    const parsedItems = parseMigrationPayload(bytes) || [];
    return parsedItems;
  }

  function parseOtpauthMigrationUrl(url) {
    try {
      if (typeof url !== 'string') return [];
      const trimmed = url.trim();
      if (!trimmed) return [];
      if (!trimmed.startsWith('otpauth-migration://')) return [];

      // 手动提取 data 参数，避免 URLSearchParams 把 '+' 解析为空格造成损坏。
      const match = trimmed.match(/[?&]data=([^&]+)/);
      if (!match || !match[1]) return [];
      const rawData = match[1];
      const decodedData = (() => {
        try {
          return decodeURIComponent(rawData);
        } catch (_) {
          return rawData;
        }
      })();

      return parseOtpauthMigrationDataPayload(decodedData);
    } catch (e) {
      console.error('解析 otpauth-migration URL 失败:', e);
      return [];
    }
  }

  function parseImportCandidatesFromText(text) {
    if (typeof text !== 'string') return [];
    const trimmed = text.trim();
    if (!trimmed) return [];

    const parsed = parseOtpauthUrl(trimmed);
    if (parsed) return [parsed];

    const migrated = parseOtpauthMigrationUrl(trimmed);
    if (migrated.length) return migrated;

    if (trimmed.startsWith('data=')) {
      const payload = trimmed.slice('data='.length);
      const payloadItems = parseOtpauthMigrationDataPayload(payload);
      if (payloadItems.length) return payloadItems;
    }

    // 兼容直接粘贴 data payload（不带 otpauth-migration:// 前缀）
    if (/^[A-Za-z0-9+/=_-]{80,}$/.test(trimmed)) {
      const payloadItems = parseOtpauthMigrationDataPayload(trimmed);
      if (payloadItems.length) return payloadItems;
    }

    return [];
  }

  function bytesToBase64(bytes) {
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.slice(i, i + chunkSize);
      binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
  }

  function utf8ToBytes(text) {
    if (typeof TextEncoder !== 'undefined') {
      return new TextEncoder().encode(String(text || ''));
    }
    const encoded = unescape(encodeURIComponent(String(text || '')));
    return Uint8Array.from(encoded, char => char.charCodeAt(0));
  }

  function encodeVarint(value) {
    let v = BigInt(Math.max(0, Number(value) || 0));
    const out = [];
    while (v >= 0x80n) {
      out.push(Number((v & 0x7fn) | 0x80n));
      v >>= 7n;
    }
    out.push(Number(v));
    return Uint8Array.from(out);
  }

  function concatBytes(chunks) {
    const total = chunks.reduce((sum, chunk) => sum + (chunk?.length || 0), 0);
    const result = new Uint8Array(total);
    let offset = 0;
    chunks.forEach(chunk => {
      if (!chunk || !chunk.length) return;
      result.set(chunk, offset);
      offset += chunk.length;
    });
    return result;
  }

  function encodeLengthDelimitedField(fieldNumber, dataBytes) {
    const tag = encodeVarint((fieldNumber << 3) | 2);
    const len = encodeVarint(dataBytes.length);
    return concatBytes([tag, len, dataBytes]);
  }

  function encodeVarintField(fieldNumber, value) {
    const tag = encodeVarint((fieldNumber << 3) | 0);
    const encodedValue = encodeVarint(value);
    return concatBytes([tag, encodedValue]);
  }

  function decodeSecretToBytes(secret) {
    const cleaned = String(secret || '').replace(/\s+/g, '').toUpperCase();
    if (!cleaned) return new Uint8Array(0);

    if (/^[A-Z2-7]+=*$/.test(cleaned)) {
      return base32ToBytes(cleaned);
    }
    if (/^[0-9A-F]+$/.test(cleaned) && cleaned.length % 2 === 0) {
      return hexToBytes(cleaned);
    }
    if (/^[+/A-Z0-9]+=*$/.test(cleaned)) {
      const decoded = decodeBase64ToBytes(cleaned);
      if (decoded && decoded.length) return decoded;
    }
    return base32ToBytes(cleaned);
  }

  function buildOtpauthUrl(entry) {
    const safeType = (entry.type || 'totp').toLowerCase() === 'hotp' ? 'hotp' : 'totp';
    const name = (entry.name || 'Imported').trim() || 'Imported';
    const issuer = (entry.issuer || '').trim();
    const secretBytes = decodeSecretToBytes(entry.secret);
    if (!secretBytes.length) return '';
    const secret = bytesToBase32(secretBytes);

    const label = issuer ? `${issuer}:${name}` : name;
    const query = new URLSearchParams();
    query.set('secret', secret);
    if (issuer) query.set('issuer', issuer);
    query.set('algorithm', String(entry.algorithm || 'SHA1').toUpperCase());
    query.set('digits', String(parseInt(entry.digits, 10) || 6));

    if (safeType === 'hotp') {
      query.set('counter', String(Math.max(0, parseInt(entry.counter, 10) || 0)));
    } else {
      query.set('period', String(Math.max(1, parseInt(entry.period, 10) || 30)));
    }

    return `otpauth://${safeType}/${encodeURIComponent(label)}?${query.toString()}`;
  }

  function buildMigrationUrlFromEntries(sourceEntries) {
    const algorithmMap = { SHA1: 1, SHA256: 2, SHA512: 3, MD5: 4 };
    const chunks = [];

    sourceEntries.forEach(entry => {
      const secretBytes = decodeSecretToBytes(entry.secret);
      if (!secretBytes.length) return;

      const itemChunks = [];
      itemChunks.push(encodeLengthDelimitedField(1, secretBytes));
      itemChunks.push(encodeLengthDelimitedField(2, utf8ToBytes(entry.name || 'Imported')));
      if (entry.issuer) {
        itemChunks.push(encodeLengthDelimitedField(3, utf8ToBytes(entry.issuer)));
      }
      itemChunks.push(encodeVarintField(4, algorithmMap[String(entry.algorithm || 'SHA1').toUpperCase()] || 1));
      itemChunks.push(encodeVarintField(5, parseInt(entry.digits, 10) === 8 ? 2 : 1));
      itemChunks.push(encodeVarintField(6, (entry.type || 'totp').toLowerCase() === 'hotp' ? 1 : 2));
      if ((entry.type || 'totp').toLowerCase() === 'hotp') {
        itemChunks.push(encodeVarintField(7, Math.max(0, parseInt(entry.counter, 10) || 0)));
      }

      const itemBytes = concatBytes(itemChunks);
      chunks.push(encodeLengthDelimitedField(1, itemBytes));
    });

    if (!chunks.length) return '';
    const payload = concatBytes(chunks);
    const data = bytesToBase64(payload);
    return `otpauth-migration://offline?data=${encodeURIComponent(data)}`;
  }

  function buildSpecialBackupText() {
    const backupPayload = {
      schema: 'google2fa-backup-v1',
      exportedAt: new Date().toISOString(),
      version: appMeta.version || '-',
      theme: localStorage.getItem(THEME_KEY) || 'light',
      entries
    };
    const jsonBytes = utf8ToBytes(JSON.stringify(backupPayload));
    return `${BACKUP_MAGIC}\n${bytesToBase64(jsonBytes)}`;
  }

  function parseSpecialBackupText(rawText) {
    if (typeof rawText !== 'string') {
      throw new Error('备份文件为空');
    }

    const normalized = rawText.replace(/\r/g, '');
    const firstNewlineIndex = normalized.indexOf('\n');
    if (firstNewlineIndex <= 0) {
      throw new Error('备份文件格式不正确');
    }

    const magic = normalized.slice(0, firstNewlineIndex).trim();
    if (magic !== BACKUP_MAGIC) {
      throw new Error('不是受支持的备份文件');
    }

    const encodedPayload = normalized.slice(firstNewlineIndex + 1).trim();
    const payloadBytes = decodeBase64ToBytes(encodedPayload);
    if (!payloadBytes || !payloadBytes.length) {
      throw new Error('备份文件内容损坏');
    }

    let payload = null;
    try {
      payload = JSON.parse(decodeUtf8Bytes(payloadBytes));
    } catch (_) {
      throw new Error('备份内容不是有效 JSON');
    }

    if (!payload || payload.schema !== 'google2fa-backup-v1' || !Array.isArray(payload.entries)) {
      throw new Error('备份版本不受支持');
    }

    return payload;
  }

  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ''));
      reader.onerror = () => reject(reader.error || new Error('读取文件失败'));
      reader.readAsText(file, 'utf-8');
    });
  }

  function downloadTextFile(filename, content, mimeType = 'text/plain;charset=utf-8') {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  }

  function getExportTimestamp() {
    return new Date().toISOString().replace(/[:.]/g, '-');
  }

  async function readRuntimeMetaFromBridgeOrFetch(path) {
    try {
      if (window.utoolsBridge && window.utoolsBridge.readText) {
        const bridgeValue = window.utoolsBridge.readText(path);
        const text = (bridgeValue && typeof bridgeValue.then === 'function')
          ? await bridgeValue
          : bridgeValue;
        if (typeof text === 'string' && text.trim()) return text;
      }
    } catch (_) {
      // ignore
    }

    try {
      const response = await fetch('./' + path + '?_=' + Date.now());
      if (response.ok) {
        const text = await response.text();
        if (typeof text === 'string' && text.trim()) return text;
      }
    } catch (_) {
      // ignore
    }

    return '';
  }

  async function loadAppMeta() {
    const next = { version: '-', author: '-', github: '' };
    const versionText = await readRuntimeMetaFromBridgeOrFetch('VERSION');
    if (versionText) {
      next.version = versionText.split(/\r?\n/)[0].trim() || '-';
    }

    const pluginText = await readRuntimeMetaFromBridgeOrFetch('plugin.json');
    if (pluginText) {
      try {
        const parsed = JSON.parse(pluginText);
        next.author = parsed.author || parsed.pluginAuthor || '-';
        next.github = parsed.homepage || parsed.repository || parsed.source || '';
      } catch (_) {
        // ignore
      }
    }

    appMeta = next;
    renderSettingsView();
  }

  async function exportFromSettings(format) {
    if (!entries.length) {
      showToast('当前没有可导出的条目', 'error');
      return;
    }

    const timestamp = getExportTimestamp();
    if (format === 'migration') {
      const migrationUrl = buildMigrationUrlFromEntries(entries);
      if (!migrationUrl) {
        showToast('无法生成 migration 数据，请检查密钥格式', 'error');
        return;
      }
      downloadTextFile(`google2fa-migration-${timestamp}.txt`, migrationUrl + '\n');
      showToast('已导出 migration 文件', 'success');
      return;
    }

    if (format === 'json') {
      const payload = {
        schema: 'google2fa-export-json-v1',
        exportedAt: new Date().toISOString(),
        entries: entries.map(entry => ({
          name: entry.name || '',
          issuer: entry.issuer || '',
          secret: entry.secret || '',
          algorithm: entry.algorithm || 'SHA1',
          digits: parseInt(entry.digits, 10) || 6,
          type: entry.type || 'totp',
          period: parseInt(entry.period, 10) || 30,
          counter: parseInt(entry.counter, 10) || 0
        }))
      };
      downloadTextFile(`google2fa-export-${timestamp}.json`, JSON.stringify(payload, null, 2), 'application/json;charset=utf-8');
      showToast('已导出 JSON 文件', 'success');
      return;
    }

    if (format === 'txt') {
      const lines = entries
        .map(entry => buildOtpauthUrl(entry))
        .filter(Boolean);
      if (!lines.length) {
        showToast('没有可导出的 otpauth 数据', 'error');
        return;
      }
      downloadTextFile(`google2fa-otpauth-${timestamp}.txt`, lines.join('\n') + '\n');
      showToast('已导出 TXT 文件', 'success');
      return;
    }

    if (format === 'backup') {
      const backupText = buildSpecialBackupText();
      downloadTextFile(`google2fa-backup-${timestamp}.g2fabak`, backupText + '\n');
      showToast('已导出备份文件', 'success');
      return;
    }

    showToast('未知导出格式', 'error');
  }

  async function importSpecialBackupFile(file) {
    const text = await readFileAsText(file);
    const payload = parseSpecialBackupText(text);
    const nextEntries = payload.entries.map(normalizeEntry).filter(Boolean);

    const confirmed = await showAppConfirm({
      title: '确认全量导入',
      message: `将覆盖当前 ${entries.length} 条数据并导入 ${nextEntries.length} 条，是否继续？`,
      confirmText: '覆盖导入',
      confirmVariant: 'danger'
    });
    if (!confirmed) return;

    entries = nextEntries;
    saveEntries(entries);

    const theme = payload.theme === 'dark' ? 'dark' : 'light';
    localStorage.setItem(THEME_KEY, theme);
    document.body.dataset.theme = theme;

    activeFilterTags = [];
    setSelectedTags([]);
    resetMigrationFlow();
    renderCurrentView();
    renderSettingsView();
    showToast(`导入完成，共 ${nextEntries.length} 条`, 'success');
  }

  // ==================== 数据存储 ====================

  const STORAGE_KEY = 'google2fa_entries';
  const THEME_KEY = 'google2fa_theme';
  const BACKUP_MAGIC = 'G2FA_BACKUP_V1';

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
  let toastCloseTimer = null;
  let addDialogInitialState = null;
  let addDialogEscapeRequested = false;
  let selectedTags = [];
  let activeFilterTags = [];
  const manageSectionExpanded = {};
  const emptySectionUserExpanded = {};
  let migrationPreviewItems = [];
  let migrationInvalidCount = 0;
  let migrationFlowStep = 1;
  let migrationActiveTab = 'import';
  let migrationLastImportResult = null;
  let migrationExportText = '';
  let migrationExportQrDataUrl = '';
  let appMeta = {
    version: '-',
    author: '-',
    github: ''
  };

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

  function getSearchTerm() {
    return ($('#searchInput')?.value || '').trim().toLowerCase();
  }

  function entryMatchesSearch(entry, searchTerm) {
    if (!searchTerm) return true;
    return (
      (entry.name || '').toLowerCase().includes(searchTerm) ||
      (entry.issuer || '').toLowerCase().includes(searchTerm) ||
      normalizeTags(entry.tags).join(' ').toLowerCase().includes(searchTerm)
    );
  }

  function entryMatchesTagFilter(entry) {
    if (!activeFilterTags.length) return true;
    const tags = normalizeTags(entry.tags);
    return activeFilterTags.some(tag => tags.includes(tag));
  }

  function filterEntries(sourceEntries) {
    const searchTerm = getSearchTerm();
    return sourceEntries.filter(entry =>
      entryMatchesSearch(entry, searchTerm) && entryMatchesTagFilter(entry)
    );
  }

  function renderFilterTags() {
    const container = $('#filterTags');
    if (!container) return;

    const allTags = getAllTags();
    activeFilterTags = activeFilterTags.filter(tag => allTags.includes(tag));

    if (!allTags.length) {
      container.innerHTML = '<span class="filter-empty">无标签</span>';
      return;
    }

    const allChip = `<button type="button" class="filter-chip ${activeFilterTags.length === 0 ? 'active' : ''}" data-tag="">全部</button>`;
    const chips = allTags.map(tag => {
      const active = activeFilterTags.includes(tag);
      return `<button type="button" class="filter-chip ${active ? 'active' : ''}" data-tag="${escapeHtml(tag)}">${escapeHtml(tag)}</button>`;
    }).join('');
    container.innerHTML = allChip + chips;
  }

  function getManageSectionExpanded(sectionKey, hasItems) {
    if (!hasItems) {
      return !!emptySectionUserExpanded[sectionKey];
    }
    if (manageSectionExpanded[sectionKey] === undefined) {
      manageSectionExpanded[sectionKey] = sectionKey !== 'deprecated';
    }
    return !!manageSectionExpanded[sectionKey];
  }

  function renderManageItem(entry) {
    const tagBadges = renderTagBadges(entry.tags, 2);
    return `
      <div class="manage-item ${entry.deprecated ? 'deprecated-state' : ''}" data-id="${entry.id}">
        <div class="manage-item-info">
          <div class="manage-item-name">${escapeHtml(entry.name || '未命名')}</div>
          <div class="manage-item-issuer">${escapeHtml(entry.issuer || '')}</div>
        </div>
        ${tagBadges ? `<div class="manage-item-meta">${tagBadges}</div>` : ''}
        <div class="manage-item-actions">
          <button type="button" class="mini-action ${entry.pinned ? 'active' : ''}" data-action="toggle-pin">
            ${entry.pinned ? '取消' : '置顶'}
          </button>
          <label class="mini-check ${entry.deprecated ? 'deprecated-active' : ''}" data-action="toggle-deprecated">
            <input type="checkbox" data-action="toggle-deprecated" ${entry.deprecated ? 'checked' : ''}>
            <span>弃用</span>
          </label>
        </div>
      </div>
    `;
  }

  function renderManageSection(sectionKey, title, items) {
    const expanded = getManageSectionExpanded(sectionKey, items.length > 0);
    const arrow = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M9 6l6 6-6 6"/>
      </svg>
    `;
    const content = items.length
      ? items.map(renderManageItem).join('')
      : '<div class="section-empty">暂无</div>';
    return `
      <section class="manage-section" data-section="${sectionKey}">
        <button type="button" class="section-toggle ${expanded ? 'expanded' : ''}" data-section="${sectionKey}" data-count="${items.length}">
          <span class="section-arrow">${arrow}</span>
          <span>${title}</span>
          <span class="section-count">${items.length}</span>
        </button>
        <div class="section-body ${expanded ? 'expanded' : ''}" data-section="${sectionKey}">
          ${content}
        </div>
      </section>
    `;
  }

  // 渲染首页验证码卡片
  function renderHomeView() {
    const grid = $('#codeGrid');
    const empty = $('#emptyState');
    const visibleEntries = entries.filter(e => !e.deprecated);
    const filteredEntries = filterEntries(visibleEntries);

    // 排序
    const sortType = $('#sortSelect').value;
    let sorted = [...filteredEntries];

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

    const filtered = filterEntries(entries);
    const pinned = filtered
      .filter(e => !e.deprecated && e.pinned)
      .sort((a, b) => (b.pinnedAt || 0) - (a.pinnedAt || 0));
    const regular = filtered
      .filter(e => !e.deprecated && !e.pinned)
      .sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    const deprecated = filtered
      .filter(e => e.deprecated)
      .sort((a, b) => (a.name || '').localeCompare(b.name || ''));

    list.innerHTML = [
      renderManageSection('pinned', '置顶', pinned),
      renderManageSection('regular', '常规', regular),
      renderManageSection('deprecated', '弃用', deprecated)
    ].join('');
  }

  function normalizeMigrationCandidate(raw) {
    if (!raw || typeof raw !== 'object') return null;
    const secret = typeof raw.secret === 'string' ? raw.secret.trim() : '';
    if (!secret) return null;

    const type = String(raw.type || raw.otpType || 'totp').toLowerCase();
    if (type !== 'totp' && type !== 'hotp') return null;

    const digits = parseInt(raw.digits, 10);
    const period = parseInt(raw.period, 10);
    const counter = parseInt(raw.counter, 10);

    return {
      name: String(raw.name || raw.account || raw.label || raw.issuer || '未命名').trim() || '未命名',
      issuer: String(raw.issuer || '').trim(),
      secret: secret.toUpperCase(),
      algorithm: String(raw.algorithm || 'SHA1').toUpperCase(),
      digits: Number.isFinite(digits) && digits > 0 ? digits : 6,
      type,
      period: Number.isFinite(period) && period > 0 ? period : 30,
      counter: type === 'hotp'
        ? (Number.isFinite(counter) && counter >= 0 ? counter : 0)
        : 0
    };
  }

  function parseMigrationInputText(text) {
    const trimmed = (text || '').trim();
    if (!trimmed) {
      return { items: [], invalidCount: 0 };
    }

    if (trimmed.includes('otpauth-migration://')) {
      const compact = trimmed.replace(/\s+/g, '');
      const migrated = parseImportCandidatesFromText(compact)
        .map(item => normalizeMigrationCandidate(item))
        .filter(Boolean);
      if (migrated.length > 0) {
        return { items: migrated, invalidCount: 0 };
      }
    }

    const lines = trimmed.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    const items = [];
    let invalidCount = 0;

    lines.forEach(line => {
      const parsedItems = parseImportCandidatesFromText(line);
      if (parsedItems.length > 0) {
        parsedItems.forEach(parsed => {
          const normalized = normalizeMigrationCandidate(parsed);
          if (normalized) items.push(normalized);
        });
      } else {
        invalidCount++;
      }
    });

    return { items, invalidCount };
  }

  function setMigrationPreview(items, invalidCount = 0) {
    migrationPreviewItems = Array.isArray(items) ? items : [];
    migrationInvalidCount = Number.isFinite(invalidCount) && invalidCount >= 0 ? invalidCount : 0;
    const applyBtn = $('#migrationApplyBtn');
    if (applyBtn) {
      applyBtn.disabled = migrationPreviewItems.length === 0;
    }
    renderMigrationPreview();
  }

  function setMigrationStep(step) {
    const normalized = [1, 2, 3].includes(step) ? step : 1;
    migrationFlowStep = normalized;

    $$('#migrationView .migration-step').forEach(node => {
      node.classList.toggle('active', Number(node.dataset.step) === normalized);
    });
    $$('#migrationView .migration-step-indicator').forEach(node => {
      const markerStep = Number(node.dataset.stepMarker);
      node.classList.toggle('active', markerStep === normalized);
      node.classList.toggle('done', markerStep < normalized);
    });
  }

  function setMigrationTab(tab) {
    const normalized = tab === 'export' ? 'export' : 'import';
    migrationActiveTab = normalized;

    $$('#migrationView .migration-tab').forEach(node => {
      const active = node.dataset.migrationTab === normalized;
      node.classList.toggle('active', active);
      node.setAttribute('aria-selected', active ? 'true' : 'false');
    });

    $$('#migrationView .migration-pane').forEach(node => {
      node.classList.toggle('active', node.dataset.migrationPane === normalized);
    });

    if (normalized === 'export') {
      renderMigrationExport();
    }
  }

  function resetMigrationFlow(options = {}) {
    const keepInput = !!options.keepInput;
    if (!keepInput) {
      const input = $('#migrationInput');
      if (input) input.value = '';
    }
    migrationLastImportResult = null;
    setMigrationPreview([], 0);
    setMigrationStep(1);
    renderMigrationLanding();
  }

  function toDataUrlBlob(dataUrl) {
    if (typeof dataUrl !== 'string' || !dataUrl.startsWith('data:')) return null;
    const comma = dataUrl.indexOf(',');
    if (comma < 0) return null;
    const meta = dataUrl.slice(5, comma);
    const body = dataUrl.slice(comma + 1);
    const mime = meta.split(';')[0] || 'image/png';
    const bytes = Uint8Array.from(atob(body), c => c.charCodeAt(0));
    return new Blob([bytes], { type: mime });
  }

  async function writeClipboardTextSimple(text) {
    if (window.utoolsBridge && window.utoolsBridge.setClipboardText) {
      window.utoolsBridge.setClipboardText(text);
      return true;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    return false;
  }

  function createMigrationQrDataUrl(text) {
    if (typeof text !== 'string' || !text.trim()) return '';
    if (typeof window.qrcode !== 'function') return '';
    try {
      const qr = window.qrcode(0, 'M');
      qr.addData(text, 'Byte');
      qr.make();
      return qr.createDataURL(8, 2);
    } catch (_) {
      return '';
    }
  }

  function renderMigrationExport() {
    const output = $('#migrationExportOutput');
    const qrImg = $('#migrationExportQrImage');
    const qrWrap = $('#migrationExportQrWrap');
    if (!output || !qrImg || !qrWrap) return;

    const migrationText = buildMigrationUrlFromEntries(entries);
    migrationExportText = migrationText || '';
    output.value = migrationExportText;

    if (!migrationExportText) {
      migrationExportQrDataUrl = '';
      qrImg.removeAttribute('src');
      qrWrap.classList.remove('has-qr');
      return;
    }

    const qrDataUrl = createMigrationQrDataUrl(migrationExportText);
    migrationExportQrDataUrl = qrDataUrl || '';
    if (migrationExportQrDataUrl) {
      qrImg.src = migrationExportQrDataUrl;
      qrWrap.classList.add('has-qr');
    } else {
      qrImg.removeAttribute('src');
      qrWrap.classList.remove('has-qr');
    }
  }

  async function copyMigrationExportText() {
    if (!migrationExportText) {
      renderMigrationExport();
    }
    if (!migrationExportText) {
      showToast('暂无可复制的迁移字符串', 'error');
      return;
    }
    try {
      await writeClipboardTextSimple(migrationExportText);
      showToast('迁移字符串已复制', 'success');
    } catch (_) {
      showToast('复制失败', 'error');
    }
  }

  async function copyMigrationExportQrImage() {
    if (!migrationExportQrDataUrl) {
      renderMigrationExport();
    }
    if (!migrationExportQrDataUrl) {
      showToast('暂无可复制的二维码', 'error');
      return;
    }

    const blob = toDataUrlBlob(migrationExportQrDataUrl);
    if (!blob) {
      showToast('二维码数据异常', 'error');
      return;
    }

    try {
      if (navigator.clipboard && navigator.clipboard.write && typeof ClipboardItem !== 'undefined') {
        await navigator.clipboard.write([new ClipboardItem({ [blob.type]: blob })]);
        showToast('二维码图片已复制', 'success');
      } else {
        showToast('当前环境不支持复制图片，请使用保存按钮', 'error');
      }
    } catch (_) {
      showToast('复制二维码失败，请尝试保存图片', 'error');
    }
  }

  function saveMigrationExportQrImage() {
    if (!migrationExportQrDataUrl) {
      renderMigrationExport();
    }
    if (!migrationExportQrDataUrl) {
      showToast('暂无可保存的二维码', 'error');
      return;
    }
    const anchor = document.createElement('a');
    anchor.href = migrationExportQrDataUrl;
    anchor.download = `migration-qr-${getExportTimestamp()}.png`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    showToast('二维码已保存', 'success');
  }

  function renderMigrationLanding() {
    const summary = $('#migrationLandingSummary');
    const details = $('#migrationLandingDetails');
    if (!summary || !details) return;

    if (!migrationLastImportResult) {
      summary.textContent = '导入完成后会在这里展示结果。';
      details.innerHTML = '<div class="migration-card-desc">你可以继续导入，或返回首页查看结果。</div>';
      return;
    }

    const {
      importedCount = 0,
      replacedCount = 0,
      skippedCount = 0,
      failedCount = 0,
      strategy = 'skip'
    } = migrationLastImportResult;

    summary.textContent = `导入成功 ${importedCount} 条，策略：${strategy}。`;
    details.innerHTML = [
      `<div class="migration-preview-item"><div class="migration-preview-name">新增/更新</div><span class="migration-preview-type">${importedCount}</span></div>`,
      `<div class="migration-preview-item"><div class="migration-preview-name">覆盖</div><span class="migration-preview-type">${replacedCount}</span></div>`,
      `<div class="migration-preview-item"><div class="migration-preview-name">跳过</div><span class="migration-preview-type">${skippedCount}</span></div>`,
      `<div class="migration-preview-item"><div class="migration-preview-name">失败</div><span class="migration-preview-type">${failedCount}</span></div>`
    ].join('');
  }

  function parseMigrationInputToPreview(text, options = {}) {
    const silent = !!options.silent;
    setMigrationTab('import');
    migrationLastImportResult = null;
    renderMigrationLanding();
    const parsed = parseMigrationInputText(text);
    setMigrationPreview(parsed.items, parsed.invalidCount);
    if (parsed.items.length > 0) {
      setMigrationStep(2);
      if (!silent) {
        showToast(`已解析 ${parsed.items.length} 条，进入预览`, 'success');
      }
    } else {
      setMigrationStep(1);
      if (!silent) {
        showToast('未识别到可导入条目', 'error');
      }
    }
    return parsed;
  }

  async function parseMigrationImageToPreview(imageData, source = 'migration-image') {
    setMigrationTab('import');
    migrationLastImportResult = null;
    renderMigrationLanding();
    const parsedItems = await parseImportCandidatesFromImageData(imageData, source);
    const normalized = parsedItems.map(item => normalizeMigrationCandidate(item)).filter(Boolean);
    if (!normalized.length) {
      showToast('图片中未识别到有效迁移条目', 'error');
      return [];
    }
    setMigrationPreview(normalized, 0);
    setMigrationStep(2);
    showToast(`已识别 ${normalized.length} 条，进入预览`, 'success');
    return normalized;
  }

  function renderMigrationPreview() {
    const previewList = $('#migrationPreviewList');
    const summary = $('#migrationPreviewSummary');
    if (!previewList || !summary) return;
    const applyBtn = $('#migrationApplyBtn');
    if (applyBtn) {
      applyBtn.disabled = migrationPreviewItems.length === 0;
    }

    if (!migrationPreviewItems.length) {
      summary.textContent = migrationInvalidCount > 0
        ? `可导入 0 条，无法识别 ${migrationInvalidCount} 条。`
        : '暂无待导入条目。';
      previewList.innerHTML = '<div class="migration-card-desc">请粘贴 otpauth 或 otpauth-migration 链接后解析。</div>';
      return;
    }

    summary.textContent = `可导入 ${migrationPreviewItems.length} 条${migrationInvalidCount ? `，无法识别 ${migrationInvalidCount} 条` : ''}。`;
    previewList.innerHTML = migrationPreviewItems.map(item => `
      <div class="migration-preview-item">
        <div>
          <div class="migration-preview-name">${escapeHtml(item.name || '未命名')}</div>
          <div class="migration-preview-meta">${escapeHtml(item.issuer || '无发行方')} · ${escapeHtml(item.algorithm || 'SHA1')} · ${item.digits || 6} 位</div>
        </div>
        <span class="migration-preview-type">${(item.type || 'totp').toUpperCase()}</span>
      </div>
    `).join('');
  }

  function renderMigrationView() {
    const badge = $('#migrationCountBadge');
    if (badge) {
      badge.textContent = `当前条目 ${entries.length}`;
    }
    renderMigrationPreview();
    renderMigrationLanding();
    setMigrationStep(migrationFlowStep);
    renderMigrationExport();
    setMigrationTab(migrationActiveTab);
  }

  function renderSettingsView() {
    const summary = $('#settingsDataSummary');
    if (summary) {
      summary.textContent = `当前共有 ${entries.length} 条验证码条目。`;
    }

    const versionText = $('#settingsVersionText');
    if (versionText) {
      versionText.textContent = `Version: ${appMeta.version || '-'}`;
    }

    const authorText = $('#settingsAuthorText');
    if (authorText) {
      authorText.textContent = `Author: ${appMeta.author || '-'}`;
    }

    const githubLink = $('#settingsGithubLink');
    if (githubLink) {
      const href = appMeta.github || '';
      githubLink.textContent = href ? 'GitHub' : 'GitHub: N/A';
      githubLink.href = href || '#';
      githubLink.style.pointerEvents = href ? '' : 'none';
      githubLink.style.opacity = href ? '' : '0.5';
    }
  }

  function buildImportedName(baseName, issuer, sourceEntries) {
    const seed = `${baseName || '未命名'} (Imported)`;
    const hasName = (name) => sourceEntries.some(entry =>
      (entry.name || '') === name && (entry.issuer || '') === (issuer || '')
    );

    if (!hasName(seed)) return seed;
    let index = 2;
    while (hasName(`${seed} ${index}`)) {
      index++;
    }
    return `${seed} ${index}`;
  }

  async function applyMigrationImport() {
    if (!migrationPreviewItems.length) {
      showToast('没有可导入的条目', 'error');
      return;
    }

    const strategy = $('#migrationConflictSelect')?.value || 'skip';
    const draft = [...entries];
    let importedCount = 0;
    let replacedCount = 0;
    let skippedCount = 0;
    let failedCount = 0;

    for (const item of migrationPreviewItems) {
      const name = (item.name || '未命名').trim() || '未命名';
      const issuer = (item.issuer || '').trim();
      const conflictIndex = draft.findIndex(entry =>
        (entry.name || '').trim() === name && (entry.issuer || '').trim() === issuer
      );
      const hasConflict = conflictIndex >= 0;

      if (hasConflict && strategy === 'skip') {
        skippedCount++;
        continue;
      }

      const base = hasConflict ? draft[conflictIndex] : null;
      const candidate = normalizeEntry({
        ...base,
        id: hasConflict && strategy === 'replace' ? base.id : generateId(),
        name: hasConflict && strategy === 'duplicate'
          ? buildImportedName(name, issuer, draft)
          : name,
        issuer,
        secret: item.secret || '',
        algorithm: item.algorithm || 'SHA1',
        digits: parseInt(item.digits, 10) || 6,
        type: item.type || 'totp',
        period: parseInt(item.period, 10) || 30,
        counter: parseInt(item.counter, 10) || 0,
        pinned: false,
        pinnedAt: 0,
        deprecated: false,
        tags: normalizeTags(item.tags),
        lastUsed: base?.lastUsed || Date.now()
      });

      try {
        if (candidate.type === 'hotp') {
          await generateHOTP(candidate.secret, { counter: candidate.counter });
        } else {
          await generateTOTP(candidate.secret, { digits: candidate.digits, period: candidate.period });
        }
      } catch (_) {
        failedCount++;
        continue;
      }

      if (hasConflict && strategy === 'replace') {
        draft[conflictIndex] = candidate;
        importedCount++;
        replacedCount++;
      } else {
        draft.push(candidate);
        importedCount++;
      }
    }

    const resultMessage = [
      `导入 ${importedCount} 条`,
      replacedCount ? `覆盖 ${replacedCount} 条` : '',
      skippedCount ? `跳过 ${skippedCount} 条` : '',
      failedCount ? `失败 ${failedCount} 条` : ''
    ].filter(Boolean).join('，');
    if (importedCount <= 0) {
      showToast(resultMessage || '没有成功导入的条目', 'error');
      return;
    }

    entries = draft;
    saveEntries(entries);
    migrationLastImportResult = {
      importedCount,
      replacedCount,
      skippedCount,
      failedCount,
      strategy
    };
    setMigrationPreview([], 0);
    setMigrationStep(3);
    renderMigrationView();
    showToast(resultMessage, 'success');
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

  async function closeAddDialogWithGuard() {
    const dialog = $('#addDialog');
    if (!dialog || !dialog.open) return true;
    if (isAddDialogDirty()) {
      const confirmed = await showAppConfirm({
        title: '放弃未保存修改',
        message: '当前修改尚未保存，确认关闭并放弃这些修改吗？',
        confirmText: '放弃修改',
        confirmVariant: 'danger'
      });
      if (!confirmed) return false;
    }
    dialog.close();
    return true;
  }

  function getEntryDisplayName(entry) {
    if (!entry) return '该条目';
    return (entry.name || entry.issuer || '该条目').trim();
  }

  function showAppConfirm(options = {}) {
    const dialog = $('#deleteConfirmDialog');
    const confirmBtn = $('#confirmDeleteBtn');
    const cancelBtn = $('#cancelDeleteBtn');
    const titleEl = $('#deleteConfirmTitle');
    const messageEl = $('#deleteConfirmMessage');

    if (!dialog || !confirmBtn || !cancelBtn || !messageEl || !titleEl) {
      showToast('确认弹窗初始化失败', 'error');
      return Promise.resolve(false);
    }

    const title = options.title || '请确认';
    const message = options.message || '确认执行该操作吗？';
    const confirmText = options.confirmText || '确认';
    const confirmVariant = options.confirmVariant || 'danger';

    titleEl.textContent = title;
    messageEl.textContent = message;
    confirmBtn.textContent = confirmText;
    confirmBtn.classList.remove('btn-danger', 'btn-primary');
    confirmBtn.classList.add(confirmVariant === 'primary' ? 'btn-primary' : 'btn-danger');

    return new Promise((resolve) => {
      let settled = false;

      const cleanup = () => {
        confirmBtn.removeEventListener('click', onConfirm);
        cancelBtn.removeEventListener('click', onCancel);
        dialog.removeEventListener('cancel', onDialogCancel);
        dialog.removeEventListener('click', onDialogClick);
      };

      const done = (result) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (dialog.open) dialog.close();
        resolve(result);
      };

      const onConfirm = () => done(true);
      const onCancel = () => done(false);
      const onDialogCancel = (e) => {
        e.preventDefault();
        done(false);
      };
      const onDialogClick = (e) => {
        // 禁止点击遮罩关闭，避免误删场景的误触。
        if (e.target === dialog) {
          e.preventDefault();
        }
      };

      confirmBtn.addEventListener('click', onConfirm);
      cancelBtn.addEventListener('click', onCancel);
      dialog.addEventListener('cancel', onDialogCancel);
      dialog.addEventListener('click', onDialogClick);
      try {
        dialog.showModal();
      } catch (e) {
        cleanup();
        resolve(false);
        return;
      }
      cancelBtn.focus();
    });
  }

  function confirmDeleteEntry(entry) {
    const displayName = getEntryDisplayName(entry);
    return showAppConfirm({
      title: '确认删除',
      message: `确定删除「${displayName}」吗？删除后不可恢复。`,
      confirmText: '删除',
      confirmVariant: 'danger'
    });
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
    const settingsBtn = $('#settingsBtn');
    if (settingsBtn) {
      settingsBtn.classList.toggle('active', view === 'settings');
    }

    // 仅首页显示排序；仅首页和管理显示工具栏
    const sortSelect = $('#sortSelect');
    if (sortSelect) {
      sortSelect.style.display = view === 'home' ? '' : 'none';
    }
    const toolbar = $('.toolbar');
    if (toolbar) {
      toolbar.style.display = (view === 'home' || view === 'manage') ? '' : 'none';
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
    renderCurrentView();
  }

  // 切换主题
  function toggleTheme() {
    const isDark = document.body.dataset.theme === 'dark';
    document.body.dataset.theme = isDark ? 'light' : 'dark';
    localStorage.setItem(THEME_KEY, document.body.dataset.theme);
    if (currentView === 'settings') {
      renderSettingsView();
    }
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
    if (!toast) return;
    if (toastCloseTimer) {
      clearTimeout(toastCloseTimer);
      toastCloseTimer = null;
    }
    toast.textContent = message;
    toast.className = 'toast ' + type;
    if (typeof toast.show === 'function' && !toast.open) {
      toast.show();
    } else if (!toast.open) {
      toast.setAttribute('open', '');
    }
    requestAnimationFrame(() => {
      toast.classList.add('show');
    });
    if (toastTimer) {
      clearTimeout(toastTimer);
    }
    toastTimer = setTimeout(() => {
      toast.classList.remove('show');
      toastCloseTimer = setTimeout(() => {
        if (typeof toast.close === 'function' && toast.open) {
          toast.close();
        } else if (toast.open) {
          toast.removeAttribute('open');
        }
        toastCloseTimer = null;
      }, 220);
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
      item.addEventListener('click', async () => {
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
          menu.remove();
          const confirmed = await confirmDeleteEntry(entry);
          if (confirmed) {
            deleteEntry(id);
          }
          return;
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
      renderFilterTags();
      renderHomeView();
      return;
    }
    if (currentView === 'manage') {
      renderFilterTags();
      renderManageView();
      return;
    }
    if (currentView === 'migration') {
      renderMigrationView();
      return;
    }
    if (currentView === 'settings') {
      renderSettingsView();
      return;
    }
    renderFilterTags();
    renderHomeView();
  }

  async function readClipboardTextRaw(source = 'unknown') {
    try {
      logClipboardDebug('readClipboardTextRaw:start', {
        source,
        hasBridge: !!window.utoolsBridge,
        hasBridgeGetClipboardText: !!(window.utoolsBridge && window.utoolsBridge.getClipboardText),
        hasNavigatorClipboard: !!(navigator.clipboard && navigator.clipboard.readText)
      });

      let text = null;
      if (window.utoolsBridge && window.utoolsBridge.getClipboardText) {
        logClipboardDebug('readClipboardTextRaw:bridge:invoke');
        const clipboardResult = window.utoolsBridge.getClipboardText();
        text = (clipboardResult && typeof clipboardResult.then === 'function')
          ? await clipboardResult
          : clipboardResult;
        logClipboardDebug('readClipboardTextRaw:bridge:resolved', {
          textType: typeof text,
          textPreview: maskClipboardPreview(text)
        });
      }
      if ((typeof text !== 'string' || !text) && navigator.clipboard?.readText) {
        logClipboardDebug('readClipboardTextRaw:navigator:fallback:invoke');
        text = await navigator.clipboard.readText();
        logClipboardDebug('readClipboardTextRaw:navigator:fallback:resolved', {
          textType: typeof text,
          textPreview: maskClipboardPreview(text)
        });
      }
      if (typeof text !== 'string') return '';
      return text.trim();
    } catch (e) {
      logClipboardDebug('readClipboardTextRaw:error', {
        source,
        name: e && e.name ? e.name : 'Error',
        message: errorToMessage(e)
      });
      return '';
    }
  }

  // 从剪贴板粘贴并解析（单条）
  async function handlePaste(source = 'unknown') {
    try {
      logClipboardDebug('handlePaste:start', {
        source,
        hasBridge: !!window.utoolsBridge,
        hasBridgeGetClipboardText: !!(window.utoolsBridge && window.utoolsBridge.getClipboardText),
        hasNavigatorClipboard: !!(navigator.clipboard && navigator.clipboard.readText)
      });

      const trimmed = await readClipboardTextRaw(source);
      if (!trimmed) {
        logClipboardDebug('handlePaste:abort:empty-string');
        return null;
      }

      const candidates = parseImportCandidatesFromText(trimmed);
      if (candidates.length > 0) {
        const parsed = candidates[0];
        logClipboardDebug('handlePaste:parsed:success', {
          candidateCount: candidates.length,
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

  function isImageDataUrl(value) {
    return typeof value === 'string' && /^data:image\/[a-zA-Z0-9.+-]+;base64,/.test(value);
  }

  function blobToDataUrl(blob) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error || new Error('读取图片失败'));
      reader.readAsDataURL(blob);
    });
  }

  function readFileAsDataUrl(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error || new Error('读取文件失败'));
      reader.readAsDataURL(file);
    });
  }

  function loadImage(dataUrl) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error('加载图片失败'));
      img.src = dataUrl;
    });
  }

  function errorToMessage(error) {
    if (!error) return '';
    if (typeof error === 'string') return error;
    return error.message || String(error);
  }

  async function getQrRuntimeSupportSnapshot() {
    const snapshot = {
      protocol: location?.protocol || '',
      isSecureContext: !!window.isSecureContext,
      userAgent: navigator?.userAgent || '',
      hasBridge: !!window.utoolsBridge,
      hasBridgeGetClipboardImage: !!(window.utoolsBridge && window.utoolsBridge.getClipboardImage),
      hasNavigatorClipboardRead: !!(navigator.clipboard && navigator.clipboard.read),
      hasNavigatorClipboardReadText: !!(navigator.clipboard && navigator.clipboard.readText),
      hasBarcodeDetector: typeof BarcodeDetector !== 'undefined',
      hasJsQr: typeof window.jsQR === 'function',
      barcodeDetectorConstructorOk: false,
      barcodeDetectorSupportedFormats: null,
      barcodeDetectorCanDetectQr: null,
      permissions: {}
    };

    if (snapshot.hasBarcodeDetector) {
      try {
        // 仅检测构造能力，不做实际识别。
        const detector = new BarcodeDetector({ formats: ['qr_code'] });
        snapshot.barcodeDetectorConstructorOk = !!detector;
      } catch (e) {
        snapshot.barcodeDetectorConstructorError = errorToMessage(e);
      }

      if (typeof BarcodeDetector.getSupportedFormats === 'function') {
        try {
          const formats = await BarcodeDetector.getSupportedFormats();
          snapshot.barcodeDetectorSupportedFormats = Array.isArray(formats) ? formats : [];
          snapshot.barcodeDetectorCanDetectQr = snapshot.barcodeDetectorSupportedFormats.includes('qr_code');
        } catch (e) {
          snapshot.barcodeDetectorSupportedFormatsError = errorToMessage(e);
        }
      }
    }

    if (navigator.permissions && navigator.permissions.query) {
      const permissionNames = ['clipboard-read', 'clipboard-write'];
      for (const name of permissionNames) {
        try {
          const status = await navigator.permissions.query({ name });
          snapshot.permissions[name] = status.state;
        } catch (e) {
          snapshot.permissions[name] = 'unsupported';
          snapshot.permissions[name + ':error'] = errorToMessage(e);
        }
      }
    }

    return snapshot;
  }

  async function decodeQrRawTextFromImage(imageData, source = 'image') {
    try {
      if (!isImageDataUrl(imageData)) {
        logClipboardDebug('decodeQrRawTextFromImage:skip:not-image-data-url', { source });
        return null;
      }

      const image = await loadImage(imageData);
      const width = image.naturalWidth || image.width;
      const height = image.naturalHeight || image.height;
      if (!width || !height) {
        logClipboardDebug('decodeQrRawTextFromImage:skip:invalid-size', { source, width, height });
        return null;
      }

      const maxSide = 1800;
      const scale = Math.min(1, maxSide / Math.max(width, height));
      const drawWidth = Math.max(1, Math.round(width * scale));
      const drawHeight = Math.max(1, Math.round(height * scale));

      const canvas = document.createElement('canvas');
      canvas.width = drawWidth;
      canvas.height = drawHeight;
      const ctx = canvas.getContext('2d');
      if (!ctx) {
        logClipboardDebug('decodeQrRawTextFromImage:skip:no-canvas-context', { source });
        return null;
      }
      ctx.drawImage(image, 0, 0, drawWidth, drawHeight);
      const imageBitmap = ctx.getImageData(0, 0, drawWidth, drawHeight);

      // 1) 尝试原生 BarcodeDetector（若存在）
      if (typeof BarcodeDetector !== 'undefined') {
        try {
          const detector = new BarcodeDetector({ formats: ['qr_code'] });
          const barcodes = await detector.detect(canvas);
          const nativeRawValue = (barcodes || [])
            .map(item => (item && typeof item.rawValue === 'string') ? item.rawValue.trim() : '')
            .find(Boolean) || null;

          if (nativeRawValue) {
            logClipboardDebug('decodeQrRawTextFromImage:done:native', {
              source,
              barcodeCount: Array.isArray(barcodes) ? barcodes.length : 0,
              rawPreview: maskClipboardPreview(nativeRawValue)
            });
            return nativeRawValue;
          }

          logClipboardDebug('decodeQrRawTextFromImage:native:no-result', {
            source,
            barcodeCount: Array.isArray(barcodes) ? barcodes.length : 0
          });
        } catch (e) {
          logClipboardDebug('decodeQrRawTextFromImage:native:error', {
            source,
            message: errorToMessage(e)
          });
        }
      } else {
        logClipboardDebug('decodeQrRawTextFromImage:native:unavailable', {
          source,
          protocol: location?.protocol || '',
          isSecureContext: !!window.isSecureContext
        });
      }

      // 2) fallback 到 jsQR（uTools/Electron 更常见）
      if (typeof window.jsQR === 'function') {
        try {
          const jsqrResult = window.jsQR(
            imageBitmap.data,
            imageBitmap.width,
            imageBitmap.height,
            { inversionAttempts: 'attemptBoth' }
          );
          const jsqrRawValue = jsqrResult && typeof jsqrResult.data === 'string'
            ? jsqrResult.data.trim()
            : null;

          logClipboardDebug('decodeQrRawTextFromImage:done:jsqr', {
            source,
            found: !!jsqrRawValue,
            rawPreview: maskClipboardPreview(jsqrRawValue)
          });
          return jsqrRawValue;
        } catch (e) {
          logClipboardDebug('decodeQrRawTextFromImage:jsqr:error', {
            source,
            message: errorToMessage(e)
          });
          return null;
        }
      }

      logClipboardDebug('decodeQrRawTextFromImage:jsqr:unavailable', { source });
      return null;
    } catch (e) {
      logClipboardDebug('decodeQrRawTextFromImage:error', {
        source,
        message: e && e.message ? e.message : String(e)
      });
      return null;
    }
  }

  async function getClipboardImageDataUrl() {
    logClipboardDebug('getClipboardImageDataUrl:start', {
      hasBridgeGetClipboardImage: !!(window.utoolsBridge && window.utoolsBridge.getClipboardImage),
      hasNavigatorClipboardRead: !!(navigator.clipboard && navigator.clipboard.read)
    });

    try {
      if (window.utoolsBridge && window.utoolsBridge.getClipboardImage) {
        const bridgeImage = window.utoolsBridge.getClipboardImage();
        const dataUrl = (bridgeImage && typeof bridgeImage.then === 'function')
          ? await bridgeImage
          : bridgeImage;
        if (isImageDataUrl(dataUrl)) {
          logClipboardDebug('getClipboardImageDataUrl:bridge:success', { length: dataUrl.length });
          return dataUrl;
        }
        logClipboardDebug('getClipboardImageDataUrl:bridge:not-image-data-url', {
          resultType: typeof dataUrl,
          preview: typeof dataUrl === 'string' ? dataUrl.slice(0, 40) : dataUrl
        });
      }
    } catch (e) {
      logClipboardDebug('getClipboardImageDataUrl:bridge:error', {
        message: errorToMessage(e)
      });
    }

    try {
      if (navigator.clipboard && navigator.clipboard.read) {
        const items = await navigator.clipboard.read();
        const itemTypes = items.map(item => item.types || []);
        logClipboardDebug('getClipboardImageDataUrl:navigator:items', {
          itemCount: items.length,
          itemTypes
        });

        for (const item of items) {
          const imageType = (item.types || []).find(type => type.startsWith('image/'));
          if (!imageType) continue;
          const blob = await item.getType(imageType);
          const dataUrl = await blobToDataUrl(blob);
          if (isImageDataUrl(dataUrl)) {
            logClipboardDebug('getClipboardImageDataUrl:navigator:success', {
              mime: imageType,
              length: dataUrl.length
            });
            return dataUrl;
          }
        }
      }
    } catch (e) {
      logClipboardDebug('getClipboardImageDataUrl:navigator:error', {
        message: errorToMessage(e),
        name: e && e.name ? e.name : ''
      });
    }

    logClipboardDebug('getClipboardImageDataUrl:none');
    return null;
  }

  async function parseImportCandidatesFromImageData(imageData, source = 'image') {
    const rawText = await decodeQrRawTextFromImage(imageData, source);
    if (!rawText) return [];
    return parseImportCandidatesFromText(rawText);
  }

  async function parseOtpauthFromImageData(imageData, source = 'image') {
    const items = await parseImportCandidatesFromImageData(imageData, source);
    return items.length ? items[0] : null;
  }

  async function parseOtpauthFromClipboardImage(source = 'clipboard-image') {
    const imageData = await getClipboardImageDataUrl();
    if (!imageData) return null;
    return parseOtpauthFromImageData(imageData, source);
  }

  // 检测剪贴板并自动填写
  async function checkClipboardAndShowHint() {
    let parsedSource = 'none';
    let parsed = await handlePaste('checkClipboardAndShowHint:text');
    if (parsed) {
      parsedSource = 'text';
    } else {
      parsed = await parseOtpauthFromClipboardImage('checkClipboardAndShowHint:image');
      if (parsed) parsedSource = 'image';
    }

    const hint = $('#clipboardHint');

    if (parsed) {
      // 显示提示
      hint.style.display = 'flex';
      const sourceLabel = parsedSource === 'image' ? '二维码' : '验证码';
      hint.querySelector('span').textContent = '检测到剪贴板' + sourceLabel + '：' + (parsed.name || parsed.issuer || '点击导入');
      // 存储解析结果供导入使用
      hint.dataset.parsed = JSON.stringify(parsed);
    } else {
      hint.style.display = 'none';
      delete hint.dataset.parsed;
    }

    logClipboardDebug('checkClipboardAndShowHint:done', {
      parsed: !!parsed,
      parsedSource
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

  async function debugQrImport() {
    const result = {
      runtime: await getQrRuntimeSupportSnapshot()
    };

    try {
      const imageData = await getClipboardImageDataUrl();
      result.clipboardImage = imageData
        ? {
            found: true,
            length: imageData.length,
            prefix: imageData.slice(0, 40)
          }
        : { found: false };

      if (imageData) {
        const rawValue = await decodeQrRawTextFromImage(imageData, 'manual-debug-qr');
        result.qrRawPreview = maskClipboardPreview(rawValue);
        if (rawValue) {
          const parsed = parseOtpauthUrl(rawValue);
          result.parsed = parsed
            ? { name: parsed.name, issuer: parsed.issuer, type: parsed.type }
            : null;
        } else {
          result.parsed = null;
        }
      }
    } catch (e) {
      result.error = errorToMessage(e);
    }

    logClipboardDebug('manual-debug-qr:result', result);
    return result;
  }

  // 尝试从图片识别二维码
  async function handleQrFromImage(imageData) {
    const parsed = await parseOtpauthFromImageData(imageData, 'import-file-image');
    if (!parsed) {
      showToast('未识别到有效的 otpauth 二维码', 'error');
      return false;
    }

    prepareCreateDialog();
    const dialog = $('#addDialog');
    if (dialog && !dialog.open) {
      dialog.showModal();
    }
    applyParsedData(parsed);
    markAddDialogClean();
    showToast('二维码已识别，请确认后保存', 'success');
    return true;
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
    loadAppMeta();

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
      const sectionToggle = e.target.closest('.section-toggle');
      if (sectionToggle && $('#manageList').contains(sectionToggle)) {
        const sectionKey = sectionToggle.dataset.section;
        const itemCount = parseInt(sectionToggle.dataset.count, 10) || 0;
        if (sectionKey) {
          if (itemCount > 0) {
            manageSectionExpanded[sectionKey] = !manageSectionExpanded[sectionKey];
          } else {
            emptySectionUserExpanded[sectionKey] = !emptySectionUserExpanded[sectionKey];
          }
          renderManageView();
        }
        return;
      }

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

    // 主题与设置
    $('#themeBtn').addEventListener('click', toggleTheme);
    $('#settingsBtn')?.addEventListener('click', () => {
      switchView('settings');
    });
    $('#settingsExportBtn')?.addEventListener('click', async () => {
      const format = $('#settingsExportFormat')?.value || 'backup';
      await exportFromSettings(format);
    });
    $('#settingsImportBtn')?.addEventListener('click', () => {
      $('#settingsImportInput')?.click();
    });
    $('#settingsImportInput')?.addEventListener('change', async (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      try {
        await importSpecialBackupFile(file);
      } catch (error) {
        showToast(errorToMessage(error) || '导入失败', 'error');
      } finally {
        e.target.value = '';
      }
    });
    $('#settingsGithubLink')?.addEventListener('click', (e) => {
      const url = appMeta.github || '';
      if (!url) {
        e.preventDefault();
        return;
      }
      if (window.utoolsBridge && window.utoolsBridge.openExternal) {
        e.preventDefault();
        window.utoolsBridge.openExternal(url);
      }
    });

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

    $('#importMigrationBtn')?.addEventListener('click', async () => {
      closeImportMenu();
      switchView('migration');
      setMigrationTab('import');
      const text = await readClipboardTextRaw('import-migration-btn');
      if (!text) {
        showToast('请先复制迁移链接或 migration data', 'error');
        return;
      }
      const input = $('#migrationInput');
      if (input) input.value = text;
      parseMigrationInputToPreview(text);
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

    // 迁移页面
    $('#migrationView')?.addEventListener('click', (e) => {
      const tabBtn = e.target.closest('.migration-tab');
      if (!tabBtn) return;
      const tab = tabBtn.dataset.migrationTab || 'import';
      setMigrationTab(tab);
    });

    $('#migrationParseBtn')?.addEventListener('click', () => {
      const text = $('#migrationInput')?.value || '';
      parseMigrationInputToPreview(text);
    });

    $('#migrationClearBtn')?.addEventListener('click', () => {
      resetMigrationFlow();
    });

    $('#migrationApplyBtn')?.addEventListener('click', async () => {
      await applyMigrationImport();
    });

    $('#migrationBackBtn')?.addEventListener('click', () => {
      setMigrationStep(1);
      $('#migrationInput')?.focus();
    });

    $('#migrationRestartBtn')?.addEventListener('click', () => {
      resetMigrationFlow();
      $('#migrationInput')?.focus();
    });

    $('#migrationGoHomeBtn')?.addEventListener('click', () => {
      switchView('home');
    });

    $('#migrationExportRefreshBtn')?.addEventListener('click', () => {
      renderMigrationExport();
      showToast('导出内容已刷新', 'success');
    });

    $('#migrationExportCopyTextBtn')?.addEventListener('click', async () => {
      await copyMigrationExportText();
    });

    $('#migrationExportCopyQrBtn')?.addEventListener('click', async () => {
      await copyMigrationExportQrImage();
    });

    $('#migrationExportSaveQrBtn')?.addEventListener('click', () => {
      saveMigrationExportQrImage();
    });

    $('#migrationPasteQuickBtn')?.addEventListener('click', async () => {
      const text = await readClipboardTextRaw('migration-paste-quick');
      if (!text) {
        showToast('剪贴板为空或无可识别文本', 'error');
        return;
      }
      const input = $('#migrationInput');
      if (input) input.value = text;
      parseMigrationInputToPreview(text);
    });

    $('#migrationQrFileBtn')?.addEventListener('click', () => {
      $('#migrationQrFileInput')?.click();
    });

    $('#migrationQrFileInput')?.addEventListener('change', async (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      try {
        const imageData = await readFileAsDataUrl(file);
        await parseMigrationImageToPreview(imageData, 'migration-qr-file');
      } catch (_) {
        showToast('读取二维码图片失败', 'error');
      } finally {
        e.target.value = '';
      }
    });

    $('#migrationInput')?.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        const text = $('#migrationInput')?.value || '';
        parseMigrationInputToPreview(text);
      }
    });

    const handleMigrationPasteImage = async (e) => {
      if (e.defaultPrevented) return;
      if (currentView !== 'migration') return;
      if (migrationActiveTab !== 'import') return;
      const items = Array.from(e.clipboardData?.items || []);
      const imageItem = items.find(item => item.kind === 'file' && item.type.startsWith('image/'));
      if (!imageItem) return;

      e.preventDefault();
      e.stopPropagation();
      const file = imageItem.getAsFile();
      if (!file) return;
      try {
        const imageData = await readFileAsDataUrl(file);
        await parseMigrationImageToPreview(imageData, 'migration-paste-image');
      } catch (_) {
        showToast('处理粘贴图片失败', 'error');
      }
    };

    document.addEventListener('paste', handleMigrationPasteImage);

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
    $('#closeDialog').addEventListener('click', async () => {
      await closeAddDialogWithGuard();
    });

    $('#addDialog').addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        addDialogEscapeRequested = true;
      }
    });

    $('#addDialog').addEventListener('cancel', async (e) => {
      e.preventDefault();
      if (addDialogEscapeRequested) {
        await closeAddDialogWithGuard();
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
    $('#deleteBtn').addEventListener('click', async () => {
      const entry = entries.find(e => e.id === editingId);
      const confirmed = editingId ? await confirmDeleteEntry(entry) : false;
      if (editingId && confirmed) {
        deleteEntry(editingId);
        $('#addDialog').close();
      }
    });

    // HOTP 类型切换时显示/隐藏 counter
    $('#otpTypeInput').addEventListener('change', () => {
      syncOtpTypeVisibility();
    });

    // 标签筛选
    $('#filterTags')?.addEventListener('click', (e) => {
      const chip = e.target.closest('.filter-chip');
      if (!chip) return;

      const tag = chip.dataset.tag || '';
      if (!tag) {
        activeFilterTags = [];
      } else if (activeFilterTags.includes(tag)) {
        activeFilterTags = activeFilterTags.filter(item => item !== tag);
      } else {
        activeFilterTags = [...activeFilterTags, tag];
      }
      renderCurrentView();
    });

    // 搜索 - 两个视图都支持
    $('#searchInput').addEventListener('input', () => {
      renderCurrentView();
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
    openImportMenu,
    debugQrImport
  };

  if (CLIPBOARD_DEBUG_ENABLED) {
    window.app.testTOTP = testTOTP;
    window.app.debugClipboard = debugClipboard;
  }

})();
