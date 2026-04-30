# Alaris Global Detections

## File Structure
- `detections/{slug}.detection` - JSON detection metadata
- `rules/siem/{slug}.sigma` - Sigma rules (.sigma extension, NOT .yml)
- Slug must match between .detection and .sigma filenames
- Flat structure, no subfolders per detection

## .detection File Rules
- Every .detection file MUST have a `uuid` field (valid v4 UUID) as the FIRST field
- Each UUID must be globally unique across all detections
- Do NOT include `compiledFrom`, `targets`, or `pinnedRules` (local-only platform fields)

## Validation
A git pre-commit hook (`.hooks/pre-commit` → `.hooks/validate-detections.sh`) blocks commits that fail validation. It checks:
- Valid v4 UUID on every .detection file
- No duplicate UUIDs
- Slug in filename matches slug in JSON
- Every .detection has a matching .sigma rule file

Activate the hook once per clone:

```bash
git config core.hooksPath .hooks
```

You can also run the validator manually at any time:

```bash
bash .hooks/validate-detections.sh
```
