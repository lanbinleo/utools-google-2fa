# Google 2FA Dev Context

This file is the project-level implementation context for daily development.

## 1. App Layout (HTML)

Main structure in `index.html`:

1. `header.header`
  - Logo
  - Top nav: `home / manage / migration`
  - Right actions: theme toggle, add button
2. `div.toolbar`
  - `#searchInput`
  - `#filterTags`
  - `#sortSelect`
3. `main.main`
  - `#homeView`: card grid
  - `#manageView`: grouped manage list
  - `#migrationView`: migration/import workspace
4. dialogs
  - `#addDialog`
  - `#importMenuDialog`
  - `#deleteConfirmDialog`
5. feedback
  - `#toast`

## 2. JS Segments (index.js)

The file uses a single IIFE and is organized in functional blocks:

1. OTP core
  - `base32ToBytes`, `hexToBytes`
  - `hmac`, `generateTOTP`, `generateHOTP`
2. URL parsing
  - `parseOtpauthUrl`
3. persistence and normalization
  - `getEntries`, `saveEntries`, `normalizeEntry`, `normalizeTags`
4. rendering
  - `renderHomeView`
  - `renderManageView`
  - `renderMigrationView`
  - `renderCurrentView`
5. interaction and actions
  - CRUD: `saveEntry`, `deleteEntry`, `editEntry`
  - confirm modal: `confirmDeleteEntry`
  - clipboard: `handlePaste`, `checkClipboardAndShowHint`
6. image QR import
  - `parseOtpauthFromImageData`
  - `decodeQrRawTextFromImage` (native + jsQR fallback)
7. migration workspace
  - parse: `parseMigrationInputText`, `parseMigrationJsonPayload`
  - preview: `setMigrationPreview`, `renderMigrationPreview`
  - apply: `applyMigrationImport`
8. boot and events
  - `init`, `switchView`

## 3. Core Data Model

Entry fields currently used:

- identity: `id`, `name`, `issuer`
- OTP: `secret`, `algorithm`, `digits`, `type`, `period`, `counter`
- organization: `tags`, `pinned`, `pinnedAt`, `deprecated`
- activity: `lastUsed`

Storage:

- entries: `localStorage['google2fa_entries']`
- theme: `localStorage['google2fa_theme']`

## 4. CSS Method

`index.css` follows these rules:

1. tokens first
  - color, radius, shadow in `:root` and dark mode override
2. layout before components
  - `app/header/toolbar/view/main`
3. feature blocks
  - home card styles
  - manage list styles
  - dialog styles
  - migration page styles
4. responsive tail
  - single mobile breakpoint with structural overrides

For new UI:

- reuse existing tokens (`--bg`, `--surface`, `--border`, `--accent`)
- keep controls shape consistent (`--radius-sm`)
- avoid inline style except dynamic toggles

## 5. Migration View IDs (v1)

Main IDs in use:

- `#migrationInput`
- `#migrationParseBtn`
- `#migrationClearBtn`
- `#migrationPreviewList`
- `#migrationPreviewSummary`
- `#migrationConflictSelect`
- `#migrationApplyBtn`
- `#migrationPasteQuickBtn`
- `#migrationJsonFileBtn` / `#migrationJsonFileInput`
- `#migrationQrFileBtn` / `#migrationQrFileInput`

## 6. Build / Package

- script: `scripts/package-utools.ps1`
- version source: `VERSION`
- watermark template: `scripts/watermark.template.txt`
- output dir: `dist/`
- mode: blacklist copy + watermark injection for `html/css/js`

## 7. Safety Guardrails

- do not close critical dialogs by mask click
- destructive actions must use in-app confirm dialog
- migration import always preview-first, then apply
