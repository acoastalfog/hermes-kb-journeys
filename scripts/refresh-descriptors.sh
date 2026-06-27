#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
engine_root=${KB_ENGINE_SOURCE:-/home/abcosta/Knowledge/kb-engine-k3}
exporter=${KB_ENGINE_DESCRIPTOR_EXPORTER:-${engine_root}/scripts/export-harness-descriptors.py}
output=${1:-${repo_root}/generated/kb-engine-descriptors.json}

if [[ ! -f "${exporter}" ]]; then
  echo "descriptor exporter not found: ${exporter}" >&2
  exit 2
fi
engine_revision=$(git -C "${engine_root}" rev-parse HEAD)
if [[ -n $(git -C "${engine_root}" status --porcelain --untracked-files=no) ]]; then
  echo "kb-engine descriptor source must be a clean tracked tree" >&2
  exit 2
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT
raw=${tmp_dir}/raw.json

python3 "${exporter}" --profile journey_first_strict --output "${raw}"
python3 - "${raw}" "${output}" "${engine_revision}" <<'PY'
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


selected_names = {
    "attention.cockpit",
    "lifecycle.review",
    "publication.status",
    "review.batch_decide_confirmed",
    "review.decision_preview",
    "review.inbox",
    "review.restore_confirmed",
    "review.restore_preview",
    "run.health",
    "run.summary",
    "workflow.plan_request",
    "workflow.start_confirmed",
}
legacy_names = {"kb_sync.preview", "kb_sync.confirmed", "update_kb"}


def digest(value: object) -> str:
    canonical = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
tools = [
    tool
    for tool in source.get("tools", [])
    if tool.get("name") in selected_names and tool.get("name") not in legacy_names
]
found = {tool.get("name") for tool in tools}
missing = sorted(selected_names - found)
if missing:
    raise SystemExit("exporter is missing selected Hermes descriptors: " + ", ".join(missing))
actions = [action for action in source.get("actions", []) if action.get("name") in found]
journeys = []
for journey in source.get("journeys", []):
    required = set(journey.get("required_tools") or [])
    if required and required.issubset(found):
        journeys.append(journey)

body = {
    "schema_version": source.get("schema_version"),
    "engine_version": source.get("engine_version"),
    "engine_source_revision": sys.argv[3],
    "profile": source.get("profile"),
    "source_export_digest": source.get("digest"),
    "selection": "hermes_primary",
    "journeys": sorted(journeys, key=lambda item: item.get("journey_id", "")),
    "actions": sorted(actions, key=lambda item: item.get("name", "")),
    "tools": sorted(tools, key=lambda item: item.get("name", "")),
}
packet = {**body, "digest": digest(body)}
output = Path(sys.argv[2])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(
    json.dumps(packet, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
