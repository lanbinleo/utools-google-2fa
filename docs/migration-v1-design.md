# Migration v1 Design

## Goal

Deliver a practical migration workspace for:

1. parsing imported payloads
2. previewing entries before write
3. applying conflict strategy in one batch

## Current Scope

Supported input channels:

1. paste otpauth lines
2. paste JSON payload
3. load JSON file
4. load QR image file
5. quick paste from clipboard otpauth

Supported conflict strategies:

1. `skip`
2. `replace`
3. `duplicate`

## User Flow

1. Go to `迁移`
2. Provide import payload
3. Click `解析预览`
4. Check summary and preview list
5. Pick conflict strategy
6. Click `确认导入`
7. Toast shows import result (`imported/replaced/skipped/failed`)

## Implementation Notes

Entry normalization pipeline:

1. parse source (`otpauth` / `json`)
2. normalize into migration candidate
3. validate OTP secret by generating one code
4. merge into draft list with strategy
5. save once (`saveEntries`)

Conflict key:

- `name + issuer`

Duplicate naming:

- `"{name} (Imported)"`, then `"{name} (Imported) 2"...`

## Next Iteration

1. add preview checkboxes for partial import
2. show conflict badge inline per row
3. support secure JSON import format
4. add dedicated migration feature code entry in `plugin.json`
