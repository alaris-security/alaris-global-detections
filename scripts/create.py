#!/usr/bin/env python3
"""Scaffold a new Alaris detection: detections/{slug}.detection + rules/siem/{slug}.sigma."""
from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = ROOT / "detections"
SIGMA_DIR = ROOT / "rules" / "siem"

SEVERITIES = ("low", "medium", "high", "critical")


def slugify(title: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", title).strip("-").lower()
    return re.sub(r"-+", "-", slug)


def parse_mitre(values: list[str]) -> list[dict[str, str]]:
    out = []
    for v in values:
        if ":" not in v:
            raise ValueError(f"--mitre expects TXXXX[.XXX]:TAXXXX, got '{v}'")
        tech, tac = v.split(":", 1)
        out.append({"techniqueId": tech.strip(), "tacticId": tac.strip()})
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--title", required=True)
    parser.add_argument("--description", default="")
    parser.add_argument("--severity", choices=SEVERITIES, default="medium")
    parser.add_argument("--status", default="experimental")
    parser.add_argument("--mitre", action="append", default=[],
                        help="Repeatable. Format: TXXXX[.XXX]:TAXXXX")
    parser.add_argument("--tag", action="append", default=[],
                        help="Repeatable. Lowercase kebab-case.")
    args = parser.parse_args()

    slug = slugify(args.title)
    if not slug:
        sys.stderr.write("title produced an empty slug\n")
        return 2

    det_path = DETECTIONS_DIR / f"{slug}.detection"
    sigma_path = SIGMA_DIR / f"{slug}.sigma"
    if det_path.exists() or sigma_path.exists():
        sys.stderr.write(f"{slug} already exists\n")
        return 2

    DETECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    SIGMA_DIR.mkdir(parents=True, exist_ok=True)

    sigma_id = str(uuid.uuid4())
    description = args.description or f"Detects {args.title}."
    mitre = parse_mitre(args.mitre) if args.mitre else []
    rule_path = f"rules/siem/{slug}.sigma"

    detection = {
        "slug": slug,
        "title": args.title,
        "description": description,
        "severity": args.severity,
        "families": ["siem"],
        "tags": args.tag,
        "status": args.status,
        "mitre": mitre,
        "rules": [rule_path],
        "intent": {
            "conditions": [],
            "dataSourceRequirements": [],
            "tuningParameters": {},
            "sourceContext": args.title,
        },
    }

    sigma = (
        f"title: {args.title}\n"
        f"id: {sigma_id}\n"
        f"status: experimental\n"
        f"description: {description}\n"
        f"author: Alaris Global\n"
        f"logsource:\n"
        f"  category: process_creation\n"
        f"  product: windows\n"
        f"detection:\n"
        f"  selection:\n"
        f"    Image|endswith: '\\example.exe'\n"
        f"  condition: selection\n"
        f"level: {args.severity}\n"
    )

    det_path.write_text(json.dumps(detection, indent=2) + "\n")
    sigma_path.write_text(sigma)

    print(f"Created {det_path.relative_to(ROOT)}")
    print(f"Created {sigma_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
