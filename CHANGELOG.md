# Changelog

All notable changes to this project are documented in this file.

Notes:

1. `alpha-*` sections are retrospective and grouped from commit history (no historical tags).
2. `1.0.0` release point is fixed at `2026-02-27 10:50:15 UTC`.

## 1.1.2

Date: `2026-02-27`

### Added

1. Added migration workspace tabs: `导入` / `导出`.
2. Added migration export panel with direct migration text output.
3. Added export actions with icon buttons: refresh payload, copy text, copy QR image, save QR image.
4. Added local QR generation runtime for migration export (`vendor/qrcode.min.js`).

### Changed

1. Refactored migration page layout into a single unified card: title + tab panes.
2. Removed the previous separate top title/hero card from migration page.
3. Kept import flow step-by-step while nesting it under the `导入` tab.

### Fixed

1. Unified migration page scrollbar colors with app theme background to avoid visual mismatch.
2. Limited migration image-paste interception to `导入` tab only.

## 1.1.1

Date: `2026-02-27`

### Added

1. Added Settings entry as a top-right icon button.
2. Added settings data workspace for export/import operations.
3. Added export formats: `otpauth-migration` / `JSON` / `TXT` / special full backup file.
4. Added full-backup import flow with in-app confirmation before overwrite.
5. Added runtime footer metadata on settings page: version, author, GitHub link.

### Changed

1. Removed old text-based `settings` nav item from top navigation.
2. Settings page interaction is now backup-oriented instead of theme/debug toggles.
3. Gear icon sizing/styling was normalized to match header icon system.

### Fixed

1. Fixed toast layering under modal backdrop by switching toast to top-layer dialog behavior.
2. Fixed icon color mismatch in dark mode by unifying with `currentColor`.

## 1.1.0

Date: after `2026-02-27 10:50:15 UTC`

### Added

1. New `Migration` page with preview-first import workflow.
2. Support for `otpauth-migration://offline?data=...` payload parsing.
3. Support for pasting raw migration `data` payload directly.
4. Support for `Ctrl+V` image paste on migration page (QR recognition to preview).
5. Unified in-app confirm modal for destructive/critical actions.

### Changed

1. Removed JSON import entry from migration/import UI.
2. Import menu now routes migration flow to dedicated migration workspace.
3. Packaging/dev documentation was expanded (`AGENTS.md`, migration/dev context docs).

### Fixed

1. Avoided native `confirm` popups that could cause uTools plugin exit behavior.
2. Improved migration URL parsing robustness for `data=` extraction and decoding.

## 1.0.0

Release time: `2026-02-27 10:50:15 UTC`

This release includes all `alpha-1`, `alpha-2`, and `alpha-3` capabilities.

### Added

1. Core 2FA app with home/manage dual views.
2. Entry CRUD, TOTP/HOTP generation, algorithm/digits/period/counter support.
3. Clipboard hint flow for `otpauth://` import with explicit user confirmation.
4. Tags, pinning, and deprecation management.
5. Manage-page grouped sections with collapse/expand interactions.
6. Tag-based filter chips + text search integration.
7. QR import pipeline with `jsQR` fallback for uTools/Electron environments.
8. Build packaging script and release watermark injection pipeline.

### Changed

1. Dialog behavior hardened: no accidental backdrop-close, unsaved-change guard.
2. UI polishing across scroll behavior, spacing, alignment, and icon cleanup.
3. Toolbar sizing/order and manage row alignment tuned for stable layout.

### Fixed

1. Clipboard import UX corrected to avoid unsafe auto-overwrite behavior.
2. Multiple HOTP/counter/timer/copy context issues corrected.
3. Scroll/viewport issues fixed for constrained plugin window height.

## alpha-3 (retrospective)

Range (UTC): `2026-02-27 08:41:25` to `2026-02-27 10:29:11`

### Highlights

1. Stability and UX hardening pass around dialogs/toasts/events/layout.
2. Feature set expansion for tags/pinning/deprecation and manage grouping.
3. Import capability expansion to QR recognition path.
4. Packaging and release engineering baseline prepared.

## alpha-2 (retrospective)

Range (UTC): `2026-02-27 07:59:25` to `2026-02-27 08:39:22`

### Highlights

1. Command/config cleanup and plugin window consistency fixes.
2. Clipboard detection hint and one-click apply flow introduced.
3. Import menu behavior wired, plus a series of OTP correctness fixes:
HOTP counter handling, submit parsing order, timer/copy/context behaviors.

## alpha-1 (retrospective)

Range (UTC): `2026-02-27 07:22:05` to `2026-02-27 07:40:03`

### Highlights

1. Initial project bootstrap and major UI/core logic refactor.
2. Base app skeleton established (home/manage, dialogs, OTP flow).
3. Early style/function iteration (issuer input, HMAC/logic/menu improvements).
