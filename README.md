# Alaris Global Detection Library

Curated, vendor-neutral detection content maintained by the Alaris research team.

Each detection is a flat pair of files sharing a slug:
- `detections/{slug}.detection` — JSON metadata (intent, MITRE mapping, severity)
- `rules/siem/{slug}.sigma` — primary Sigma rule

Compilation to tenant-specific query languages happens downstream — this repo holds the authoritative source.

See [CLAUDE.md](./CLAUDE.md) for the full schema, conventions, and contribution workflow.

## Quick start

```bash
python3 scripts/validate.py
python3 scripts/create.py --title "..." --severity high --mitre T1059.001:TA0002
```

## Layout

- `detections/` — `.detection` JSON metadata, flat
- `rules/siem/` — `.sigma` rules, flat
- `config/pipeline.yml` — default compilation pipeline config
- `scripts/` — validation and scaffolding tools
