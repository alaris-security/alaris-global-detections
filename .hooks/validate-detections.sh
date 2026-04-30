#!/usr/bin/env bash
set -euo pipefail

errors=0
uuids=()

for f in detections/*.detection; do
  [ -f "$f" ] || continue
  slug=$(basename "$f" .detection)

  # Check uuid exists and is valid v4
  uuid=$(jq -r '.uuid // empty' "$f")
  if [ -z "$uuid" ]; then
    echo "FAIL: $f missing uuid"
    errors=$((errors + 1))
    continue
  fi
  if ! echo "$uuid" | grep -qE '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'; then
    echo "FAIL: $f invalid uuid: $uuid"
    errors=$((errors + 1))
  fi

  # Check for duplicate UUIDs
  for seen in "${uuids[@]+"${uuids[@]}"}"; do
    if [ "$seen" = "$uuid" ]; then
      echo "FAIL: $f duplicate uuid: $uuid"
      errors=$((errors + 1))
    fi
  done
  uuids+=("$uuid")

  # Check slug matches filename
  file_slug=$(jq -r '.slug // empty' "$f")
  if [ "$file_slug" != "$slug" ]; then
    echo "FAIL: $f slug mismatch: filename=$slug json=$file_slug"
    errors=$((errors + 1))
  fi

  # Check matching .sigma rule exists
  if [ ! -f "rules/siem/${slug}.sigma" ]; then
    echo "FAIL: $f missing rule file: rules/siem/${slug}.sigma"
    errors=$((errors + 1))
  fi
done

if [ $errors -gt 0 ]; then
  echo "$errors validation error(s) found"
  exit 1
fi
echo "All detections valid"
