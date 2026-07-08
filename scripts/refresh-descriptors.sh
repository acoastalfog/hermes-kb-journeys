#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
engine_root=${KB_ENGINE_SOURCE:?set KB_ENGINE_SOURCE to an exact clean kb-engine checkout}
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

python3 "${exporter}" \
  --profile journey_first_strict \
  --selection primary_chat \
  --output "${raw}"
python3 - "${raw}" "${output}" "${engine_revision}" <<'PY'
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


legacy_names = {"kb_sync.preview", "kb_sync.confirmed", "update_kb"}
canonical_sync_tools = {"kb.sync.prepare", "kb.sync.status", "kb.sync.resume"}


def digest(value: object) -> str:
    canonical = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if source.get("selection") != "primary_chat":
    raise SystemExit("exporter did not return the primary_chat selection")
tools = source.get("tools")
if not isinstance(tools, list) or not 1 <= len(tools) <= 13:
    raise SystemExit("primary_chat must export between one and thirteen tools")
tool_names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
if tool_names.intersection(legacy_names) or any(str(name).startswith("kb_sync.") for name in tool_names):
    raise SystemExit("primary_chat export contains a forbidden legacy tool")
if not canonical_sync_tools.issubset(tool_names):
    raise SystemExit("primary_chat export is missing the canonical kb.sync prepare/status/resume tools")
for journey in source.get("journeys") or []:
    if not isinstance(journey, dict):
        raise SystemExit("primary_chat export contains an invalid journey row")
    required = set(journey.get("required_tools") or [])
    if required.intersection(legacy_names):
        raise SystemExit("primary_chat export contains a forbidden legacy journey")
    if journey.get("journey_id") == "kb_sync" and not canonical_sync_tools.issubset(required):
        raise SystemExit("kb_sync journey does not require canonical prepare/status/resume")

source_digest = source.pop("digest", None)
body = {
    **source,
    "engine_source_revision": sys.argv[3],
    "source_export_digest": source_digest,
}
packet = {**body, "digest": digest(body)}
output = Path(sys.argv[2])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(
    json.dumps(packet, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
