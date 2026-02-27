# Project Agent Notes

Always read these files before large feature edits:

1. `docs/dev-context.md`
2. `docs/migration-v1-design.md` (if task touches migration/import)

Implementation preference:

1. keep UI behavior deterministic
2. keep destructive actions behind in-app confirmation
3. keep migration flow as preview-first, apply-second
