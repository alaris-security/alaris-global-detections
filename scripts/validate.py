#!/usr/bin/env python3
"""Validate Alaris detection content.

Layout:
  detections/{slug}.detection   JSON metadata
  rules/siem/{slug}.sigma       Sigma rule

Checks:
- .detection is valid JSON with required schema fields
- filename slug matches the `slug` field
- referenced .sigma rule exists
- intent block has conditions, dataSourceRequirements, tuningParameters, sourceContext
- tags are lowercase kebab-case
- severity / status / families values are in allowed sets
- MITRE techniqueId / tacticId follow canonical format
- .sigma is valid YAML with id (UUIDv4), logsource, and detection.condition
- every .sigma is referenced by some .detection
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required: pip install pyyaml\n")
    sys.exit(2)

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = ROOT / "detections"
SIGMA_DIR = ROOT / "rules" / "siem"

SEVERITIES = {"low", "medium", "high", "critical"}
STATUSES = {"active", "experimental", "deprecated"}
FAMILIES = {"siem", "endpoint", "network"}

REQUIRED_DETECTION_FIELDS = (
    "slug", "title", "description", "severity", "families",
    "tags", "status", "mitre", "rules", "intent",
)
REQUIRED_INTENT_FIELDS = (
    "conditions", "dataSourceRequirements", "tuningParameters", "sourceContext",
)
FORBIDDEN_DETECTION_FIELDS = ("uuid", "compiledFrom", "targets", "pinnedRules")

SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
TAG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTIC_RE = re.compile(r"^TA\d{4}$")


def is_uuid_v4(val: str) -> bool:
    try:
        u = uuid.UUID(val)
    except (ValueError, AttributeError, TypeError):
        return False
    return u.version == 4


def validate_detection(path: Path) -> tuple[list[str], set[str]]:
    """Validate one .detection file. Returns (errors, set of referenced sigma paths)."""
    errors: list[str] = []
    referenced: set[str] = set()
    slug_from_name = path.name[: -len(".detection")]

    if not SLUG_RE.match(slug_from_name):
        errors.append(f"{path.name}: filename slug must be lowercase kebab-case")

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        errors.append(f"{path.name}: invalid JSON ({e})")
        return errors, referenced

    for field in REQUIRED_DETECTION_FIELDS:
        if field not in data:
            errors.append(f"{path.name}: missing required field '{field}'")

    for field in FORBIDDEN_DETECTION_FIELDS:
        if field in data:
            errors.append(f"{path.name}: must not include '{field}' (local-only)")

    if errors:
        return errors, referenced

    if data["slug"] != slug_from_name:
        errors.append(f"{path.name}: slug field '{data['slug']}' does not match filename")

    if data["severity"] not in SEVERITIES:
        errors.append(f"{path.name}: invalid severity '{data['severity']}'")

    if data["status"] not in STATUSES:
        errors.append(f"{path.name}: invalid status '{data['status']}'")

    families = data.get("families") or []
    if not isinstance(families, list) or not families:
        errors.append(f"{path.name}: families must be a non-empty list")
    else:
        for fam in families:
            if fam not in FAMILIES:
                errors.append(f"{path.name}: invalid family '{fam}'")

    tags = data.get("tags") or []
    if not isinstance(tags, list):
        errors.append(f"{path.name}: tags must be a list")
    else:
        for tag in tags:
            if not isinstance(tag, str) or not TAG_RE.match(tag):
                errors.append(f"{path.name}: tag '{tag}' must be lowercase kebab-case")

    mitre = data.get("mitre") or []
    if not isinstance(mitre, list) or not mitre:
        errors.append(f"{path.name}: mitre must be a non-empty list")
    else:
        for entry in mitre:
            if not isinstance(entry, dict):
                errors.append(f"{path.name}: mitre entries must be objects")
                continue
            if not TECHNIQUE_RE.match(entry.get("techniqueId", "")):
                errors.append(f"{path.name}: invalid techniqueId '{entry.get('techniqueId')}'")
            if not TACTIC_RE.match(entry.get("tacticId", "")):
                errors.append(f"{path.name}: invalid tacticId '{entry.get('tacticId')}'")

    rules = data.get("rules") or []
    if not isinstance(rules, list) or not rules:
        errors.append(f"{path.name}: rules must be a non-empty list")
    else:
        for rule_path in rules:
            if not isinstance(rule_path, str):
                errors.append(f"{path.name}: rule entries must be strings")
                continue
            if not rule_path.startswith("rules/siem/") or not rule_path.endswith(".sigma"):
                errors.append(f"{path.name}: rule '{rule_path}' must be rules/siem/*.sigma")
                continue
            full = ROOT / rule_path
            if not full.exists():
                errors.append(f"{path.name}: referenced rule '{rule_path}' does not exist")
            referenced.add(rule_path)

    intent = data.get("intent") or {}
    if not isinstance(intent, dict):
        errors.append(f"{path.name}: intent must be an object")
    else:
        for key in REQUIRED_INTENT_FIELDS:
            if key not in intent:
                errors.append(f"{path.name}: intent missing '{key}'")
        if "conditions" in intent and not isinstance(intent["conditions"], list):
            errors.append(f"{path.name}: intent.conditions must be a list")
        if "dataSourceRequirements" in intent and not isinstance(intent["dataSourceRequirements"], list):
            errors.append(f"{path.name}: intent.dataSourceRequirements must be a list")
        if "tuningParameters" in intent and not isinstance(intent["tuningParameters"], dict):
            errors.append(f"{path.name}: intent.tuningParameters must be an object")
        if "sourceContext" in intent and not isinstance(intent["sourceContext"], str):
            errors.append(f"{path.name}: intent.sourceContext must be a string")

    return errors, referenced


def validate_sigma(path: Path) -> list[str]:
    errors: list[str] = []
    slug_from_name = path.name[: -len(".sigma")]

    if not SLUG_RE.match(slug_from_name):
        errors.append(f"{path.name}: filename slug must be lowercase kebab-case")

    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        errors.append(f"{path.name}: invalid YAML ({e})")
        return errors

    if not isinstance(data, dict):
        errors.append(f"{path.name}: top-level must be a mapping")
        return errors

    if "title" not in data:
        errors.append(f"{path.name}: missing 'title'")

    if "id" not in data or not is_uuid_v4(str(data["id"])):
        errors.append(f"{path.name}: id missing or not a UUIDv4")

    logsource = data.get("logsource")
    if not isinstance(logsource, dict):
        errors.append(f"{path.name}: missing logsource mapping")
    elif "category" not in logsource and "service" not in logsource:
        errors.append(f"{path.name}: logsource needs category or service")

    detection_block = data.get("detection")
    if not isinstance(detection_block, dict) or "condition" not in detection_block:
        errors.append(f"{path.name}: detection block missing condition")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--slug", help="validate a single slug")
    args = parser.parse_args()

    if not DETECTIONS_DIR.exists():
        sys.stderr.write(f"detections/ not found at {DETECTIONS_DIR}\n")
        return 2
    if not SIGMA_DIR.exists():
        sys.stderr.write(f"rules/siem/ not found at {SIGMA_DIR}\n")
        return 2

    if args.slug:
        det_paths = [DETECTIONS_DIR / f"{args.slug}.detection"]
        sigma_paths = [SIGMA_DIR / f"{args.slug}.sigma"]
    else:
        det_paths = sorted(DETECTIONS_DIR.glob("*.detection"))
        sigma_paths = sorted(SIGMA_DIR.glob("*.sigma"))

    all_errors: list[str] = []
    referenced_total: set[str] = set()

    for p in det_paths:
        if not p.exists():
            all_errors.append(f"{p.name}: not found")
            continue
        errs, refs = validate_detection(p)
        all_errors.extend(errs)
        referenced_total |= refs

    for p in sigma_paths:
        if not p.exists():
            all_errors.append(f"{p.name}: not found")
            continue
        all_errors.extend(validate_sigma(p))

    if not args.slug:
        for p in sigma_paths:
            rel = f"rules/siem/{p.name}"
            if rel not in referenced_total:
                all_errors.append(f"{p.name}: not referenced by any .detection")

    if all_errors:
        for err in all_errors:
            print(f"ERROR  {err}")
        print(f"\n{len(all_errors)} error(s) across "
              f"{len(det_paths)} detection(s) / {len(sigma_paths)} sigma rule(s)")
        return 1

    print(f"OK  {len(det_paths)} detection(s) and {len(sigma_paths)} sigma rule(s) validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
