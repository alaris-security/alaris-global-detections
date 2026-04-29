# Alaris Global Detection Library

## What This Repo Is

Curated detection content maintained by the Alaris research team. Changes sync into connected Alaris workspaces as inbound change requests.

## Repo Structure

```
detections/                 {slug}.detection        JSON metadata, flat
rules/
  siem/                     {slug}.sigma            Sigma rule, flat
config/
  pipeline.yml              tenant-side compilation defaults
scripts/
  validate.py               schema and cross-ref checks
  create.py                 scaffold a new detection
.alarisignore               sync ignore patterns
```

Both files for a detection share the same slug. There is no per-slug subdirectory.

## .detection schema (JSON, no extra keys)

Required fields:
- `slug` — kebab-case identifier; MUST equal the filename without `.detection`
- `title` — human-readable name
- `description` — what this detects and why
- `severity` — `low` | `medium` | `high` | `critical`
- `families` — list including `siem`
- `tags` — lowercase kebab-case
- `status` — `active` | `experimental` | `deprecated`
- `mitre` — list of `{ techniqueId, tacticId }` pairs
- `rules` — list of repo-relative paths to the associated `.sigma` files (under `rules/siem/`)
- `intent` — object with:
  - `conditions` (list)
  - `dataSourceRequirements` (list)
  - `tuningParameters` (object)
  - `sourceContext` (string)

Do NOT include `uuid`, `compiledFrom`, `targets`, or `pinnedRules` — those are local-only fields injected during sync.

## .sigma rule conventions

Standard Sigma YAML, with `.sigma` extension (not `.yml`).

- `title`
- `id` — random UUIDv4 (per-rule; not present in the .detection)
- `status: experimental`
- `description`
- `author: Alaris Global`
- `logsource` — must specify `category` or `service`
- `detection` — must define a `condition`
- `level` — mirrors `.detection` severity
- `tags` — canonical `attack.<tactic>` and `attack.<technique>` form

## Workflows

### Create a new detection

```bash
python3 scripts/create.py \
  --title "Suspicious Foo Activity" \
  --severity high \
  --mitre T1059.001:TA0002
```

Scaffolds `detections/{slug}.detection` and `rules/siem/{slug}.sigma`. Edit the Sigma rule and tune the `.detection` intent block, then validate.

### Validate

```bash
python3 scripts/validate.py
python3 scripts/validate.py --slug brute-force-login-attempts
```

Checks JSON schema, slug↔filename, rules cross-references, sigma syntax, MITRE ID format, tag casing.

### Update an existing detection

Edit `detections/{slug}.detection` and/or `rules/siem/{slug}.sigma`. Run validation. Bump `status` from `experimental` to `active` only after review.

## MITRE ATT&CK

Every detection MUST map to at least one `{ techniqueId, tacticId }` pair. Use canonical IDs (`T1059.001`, `TA0002`).

## Important Rules

- **Never commit directly to main** — open a PR.
- **Always run validation before committing** — `python3 scripts/validate.py`.
- **No compiled output in this repo** — `compiled/` is generated tenant-side and gitignored.
- **Slugs match exactly** — `.detection` filename, `slug` field, and `.sigma` filename must all align.
- **Tags are lowercase kebab-case** in `.detection`. Sigma `tags` follow the canonical `attack.*` form.
