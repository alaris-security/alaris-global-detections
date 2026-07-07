# Alaris Global Detections

## IMPORTANT — Contribution Attribution (read first)

These rules are mandatory for every contribution, automated or human:

- Do NOT mention, reference, credit, or otherwise indicate that an AI agent, assistant, model, or automated tool worked on this repository — anywhere.
- This applies to commit messages, commit authors/committers, pull request titles and bodies, code comments, file contents, and any metadata or trailers.
- Do NOT add `Co-Authored-By`, `Generated-by`, `Assisted-by`, or similar attribution lines.
- Do NOT name any agent, assistant, vendor, or model (generically or specifically).
- Author all commits under the human contributor's real identity only.
- Keep all output vendor-neutral; the work must read as if authored directly by the maintainers.

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
