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

## Generated contracts

`generated/kb-engine-descriptors.json` is a deterministic, digest-bound subset
of the kb-engine `journey_first_strict` export. Regenerate it with:

```bash
KB_ENGINE_SOURCE=/path/to/kb-engine scripts/refresh-descriptors.sh
```

The loader admits at most 12 tools, requires concrete input and output schemas,
and rejects deprecated sync routes. Missing or invalid descriptors fail closed;
the plugin does not recreate the MCP catalog or supply compatibility aliases.

Current integration blocker: kb-engine revision
`3e39d7fcce7e4c5b195901daf640019069f32fff` still exports unconstrained generic
object output schemas. The committed export records that upstream truth, but
the plugin rejects it at load and reports descriptor readiness as blocked.
Once kb-engine publishes concrete output schemas, regenerate this file; no
Hermes compatibility schema or hand-written alias is permitted.

## Gate S migration note

Version 0.5.0 deliberately makes `/kb sync` return
`status: temporarily_unavailable` without dispatching an MCP tool. It will be
restored only when kb-engine publishes canonical `kb.sync.prepare` and
`kb.sync.commit` contracts. Evidence capture/write likewise remains unavailable
until `evidence.remember.preview/confirmed` is exported. A confirmed evidence
receipt is rendered as “Evidence remembered”; it never implies a semantic
object update or publication. Durable wording requires confirmed identity and
digest readback.

## Local Test

Set `HERMES_AGENT_REPO` to either a Hermes Agent v2026.6.19 checkout or a
current-upstream checkout:

```bash
uv run --with pytest --with pyyaml pytest tests/test_external_plugin_contract.py -q
```
