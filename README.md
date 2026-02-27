# Google 2FA (uTools 插件)

简约高效的 2FA 验证器，支持在 uTools 中快速查看与管理一次性验证码（TOTP/HOTP）。

## 功能特性

- 双视图：`验证码`（卡片）与 `管理`（列表）
- 支持 `TOTP` / `HOTP`
- 支持 `SHA1` / `SHA256` / `SHA512`
- 支持 `6/7/8` 位验证码、周期与计数器配置
- 支持 `otpauth://` 链接解析与导入
- 支持剪贴板检测（文本/图片二维码，显式确认后导入）
- 支持图片二维码识别（`BarcodeDetector` + `jsQR fallback`）
- 支持右键操作：复制、编辑、删除
- 支持搜索（名称/发行方/标签）与排序
- 支持 `Tags`、`置顶`、`弃用` 管理
- 支持浅色/深色主题切换

## 使用方式

### 新增验证码

1. 点击右上角 `+`
2. 输入名称与密钥（或粘贴 `otpauth://` 链接）
3. 点击保存

### 剪贴板导入

- 打开新增弹窗后，会优先检测剪贴板中的 `otpauth://` 文本
- 若剪贴板是图片，会尝试识别二维码并解析 `otpauth://`（uTools 下默认走 `jsQR`）
- 仅提示，不会自动覆盖表单
- 点击 `导入到表单` 后才会应用

## Pathways

- `手动新增`：`+` -> 输入名称/密钥 -> 保存
- `文本导入`：复制 `otpauth://` -> 打开新增弹窗 -> 点击 `导入到表单` -> 保存
- `剪贴板图片导入`：复制二维码图片 -> 打开新增弹窗 -> 检测提示 -> 点击 `导入到表单` -> 保存
- `文件图片导入`：导入菜单 -> `从图片识别二维码` -> 自动填充到新增表单 -> 保存

### 复制验证码

- 在主页点击验证码卡片即可复制
- 或右键卡片选择 `复制验证码`

## 数据存储

当前数据保存在浏览器 `localStorage`：

- 条目：`google2fa_entries`
- 主题：`google2fa_theme`

注意：当前为本地明文存储，适合个人本机使用场景。

## 调试

默认关闭剪贴板调试日志。若需开启：

```js
localStorage.setItem('google2fa_debug_clipboard', '1')
```

开启后可在控制台执行：

```js
await window.app.debugClipboard()
await window.app.debugQrImport()
```

关闭：

```js
localStorage.removeItem('google2fa_debug_clipboard')
```

## 项目结构

- `index.html`：页面结构
- `index.css`：样式与动画
- `index.js`：核心逻辑（OTP、渲染、交互）
- `preload.js`：uTools/Node 桥接
- `vendor/jsQR.js`：二维码识别 fallback 库
- `plugin.json`：插件配置

## 开发说明

- 插件窗口高度当前配置为 `550`（见 `plugin.json`）
- 首页与管理页滚动区域已做独立滚动处理
- 对话框支持 `ESC/关闭按钮` 关闭，并带未保存确认

## 打包说明

- 执行：`powershell -ExecutionPolicy Bypass -File scripts/package-utools.ps1`
- 输出目录：`dist/`（已在 `.gitignore` 忽略）
- 脚本为黑名单模式复制（自动排除 `.git`、`scripts`、`docs` 等）
- 版本号读取根目录 `VERSION`
- 水印模板：`scripts/watermark.template.txt`（占位符 `{{AUTHOR}}`、`{{SOURCE_URL}}`、`{{VERSION}}`、`{{BUILD_TIME_UTC}}`）

## Roadmap

下一步计划：

- 迁移与导出页面
  - 从其他 2FA 应用迁移
  - JSON/条目级导出
  - 迁移导出流程优化
