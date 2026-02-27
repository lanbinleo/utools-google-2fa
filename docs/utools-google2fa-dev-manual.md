# uTools Google 2FA 开发手册

## 1. 目标与范围
本插件是一个以 **低门槛导入** 和 **高上限配置** 为核心的 2FA 工具，支持：
- 双栏首页验证码查看
- 日夜主题切换（支持跟随系统）
- 新建、编辑、删除、置顶、常用排序
- 导入：otpauth、JSON、屏幕扫码、图片扫码
- 导出：明文 JSON、加密备份、otpauth 列表
- 安全存储：`dbCryptoStorage`

## 2. 官方流程映射（基于 uTools 文档）
### 2.1 快速开始
uTools 插件本质是 **Node.js 能力 + Web 前端页面**，开发流程是：开发 -> 调试 -> 打包 -> 发布。

### 2.2 插件核心配置 `plugin.json`
当前项目配置要点：
- `main`: `index.html`
- `preload`: `preload.js`
- `features`: 首页入口 + 管理页入口
- `pluginSetting.single`: 单例运行
- `pluginSetting.height`: 插件初始高度

### 2.3 生命周期与事件
项目已使用：
- `utools.onPluginEnter`: 区分进入首页或管理页
- `utools.onDbPull`: 多设备同步后刷新本地视图

### 2.4 数据存储策略
- 敏感数据（2FA 条目、密钥）: `utools.dbCryptoStorage`
- 轻量偏好（主题、排序、视图）: `utools.dbStorage`

### 2.5 屏幕能力
- `utools.screenCapture`: 截图后解析二维码，实现“屏幕扫码导入”

### 2.6 复制能力
- `utools.copyText`: 一键复制验证码

## 3. 项目结构
```text
Google 2FA/
├─ plugin.json         # 插件声明与入口
├─ preload.js          # 文件桥接能力
├─ index.html          # 页面结构（主页/管理页/导入导出弹窗）
├─ index.css           # 主题与布局样式
├─ index.js            # 状态、OTP 算法、交互、导入导出逻辑
└─ docs/
   └─ utools-google2fa-dev-manual.md
```

## 4. 关键实现说明
### 4.1 条目模型
每个条目包含：
- 基础：`id/name/issuer/account/secret`
- OTP：`otpType`(totp/hotp)、`algorithm`、`digits`、`period`、`counter`
- 管理：`tags/note/pinned/rankBoost/useCount/lastUsedAt`

### 4.2 排序规则
默认“常用优先”：
1. 置顶优先
2. 使用频次优先
3. 最近使用时间作为加分
可切换最近使用 / 名称排序。

### 4.3 OTP 算法
- 支持 `SHA1/SHA256/SHA512`
- Base32 和 Hex 两种密钥编码
- `TOTP` 每秒刷新剩余时间
- `HOTP` 支持“下一码”

### 4.4 导入导出
导入：
- 粘贴 `otpauth://...`
- 粘贴 JSON（支持加密备份解密）
- 屏幕截图扫码
- 上传图片扫码

导出：
- 明文 JSON
- 口令加密备份（AES-GCM + PBKDF2）
- otpauth 列表

### 4.5 安全与性能
- 密钥落地使用 `dbCryptoStorage`
- HMAC Key 做缓存，减少重复计算开销
- 1 秒刷新一次运行时验证码
- 仅在本地生成，不依赖网络

## 5. 调试建议
- 使用 uTools 开发者工具加载本项目目录
- 重点回归：
  - 新建/编辑后验证码正确性
  - 屏幕扫码导入
  - 导出后再导入一致性
  - 深色/浅色主题切换
  - HOTP 计数器递增行为

## 6. 后续增强建议
- 支持 `otpauth-migration://` 批量导入
- 为条目添加分组视图（按标签折叠）
- 增加可选本地二次解锁（PIN）
- 增加可选自动清理剪贴板验证码

## 7. 参考文档
- https://www.u-tools.cn/docs/developer/basic/getting-started.html
- https://www.u-tools.cn/docs/developer/information/plugin-json.html
- https://www.u-tools.cn/docs/developer/utools-api/events.html
- https://www.u-tools.cn/docs/developer/utools-api/db.html
- https://www.u-tools.cn/docs/developer/utools-api/window.html
- https://www.u-tools.cn/docs/developer/utools-api/screen.html
- https://www.u-tools.cn/docs/developer/utools-api/copy.html
- https://www.u-tools.cn/docs/developer/utools-api/system.html
