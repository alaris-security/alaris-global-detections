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
A pre-commit hook runs `.hooks/validate-detections.sh` on every commit. It checks:
- Valid v4 UUID on every .detection file
- No duplicate UUIDs
- Slug in filename matches slug in JSON
- Every .detection has a matching .sigma rule file

The hook blocks commits that fail validation.
