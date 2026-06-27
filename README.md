# Hermes KB Journeys Plugin

Out-of-tree Hermes plugin for Anthony's KB guided review journeys.

This repository packages the `kb_journeys` Hermes plugin as a standard user
plugin installed under `$HERMES_HOME/plugins/kb_journeys`. Hermes Agent
v2026.6.19 does not contain a bundled `plugins/kb_journeys` implementation.
Removing this plugin is therefore an uninstall, not a rollback, and leaves no
Hermes KB journey.

## Boundaries

- `kb-engine` owns durable KB semantics, preview leases, confirmed envelopes,
  receipts, provenance, restore/undo, and stale handling.
- Hermes owns Telegram/runtime rendering over backend packets.
- NOC owns production placement, install refs, route validation, canaries, and
  rollback.
- Skills guide wording and operator posture only.

## Rollback

NOC records the exact previous verified plugin ref before an install. Rollback
means reinstalling that `previous_ref`, verifying its installed digest, loading
it, and running the Telegram/dashboard canaries. Removing or renaming the
plugin directory is only an uninstall.

The host-owned install receipt is outside this repository and has exactly these
fields: `current_ref`, `previous_ref`, `installed_digest`,
`descriptor_digest`, `installed_at`, and `noc_plan_digest`. NOC writes the
receipt; the plugin only validates and reports it. The recorded previous ref is
the sole rollback source of truth.
The renderer never treats caller-supplied, self-digested evidence as proof of
installation. Missing live evidence is `not_observed`; any caller-supplied
evidence is `unverified`, including malformed, future, expired, or mismatched
packets. A future `verified` posture requires an authenticated, NOC-owned
observation channel that is not part of this plugin contract.

## Generated contracts

`generated/kb-engine-descriptors.json` is a deterministic, digest-bound subset
of the kb-engine `journey_first_strict` export. Regenerate it with:

```bash
KB_ENGINE_SOURCE=/path/to/kb-engine scripts/refresh-descriptors.sh
```

The loader admits at most 12 tools, requires concrete input and output schemas,
and rejects deprecated sync routes. Missing or invalid descriptors fail closed;
the plugin does not recreate the MCP catalog or supply compatibility aliases.

The committed export is pinned to the kb-engine 0.41.3 safety candidate at
revision `9d4a5856b2e0412e6edc83451fbb2b47356420d1`, which owns the exact
`primary_chat` selection and concrete output schemas. No Hermes compatibility
schema, tool re-selection, or hand-written alias is permitted. The CI
descriptor job remains intentionally blocked until that exact revision is
published and remotely reachable; local test results do not count as a green
GitHub workflow.

## Gate S migration note

Version 0.5.0 deliberately makes `/kb sync` return
`status: temporarily_unavailable` plus the explicit
`generated_kb_sync_contract_missing` integration blocker, without dispatching
an MCP tool. The target remains one canonical `/kb sync` journey, but the
generated primary profile does not yet expose `kb.sync.prepare` and
`kb.sync.commit`; Hermes will not fabricate those semantics. The old `/kbsync`
and `update_kb` entrypoints are
removed and return migration guidance only. Evidence capture/write likewise remains unavailable
until `evidence.remember.preview/confirmed` is exported. A confirmed evidence
receipt is rendered as “Evidence remembered”; it never implies a semantic
object update or publication. Durable wording requires confirmed identity and
digest readback and a generated completion binding to the selected request.

## Local Test

Set `HERMES_AGENT_REPO` to either a Hermes Agent v2026.6.19 checkout or a
current-upstream checkout:

```bash
uv run --with pytest --with pyyaml pytest tests/test_external_plugin_contract.py -q
```
