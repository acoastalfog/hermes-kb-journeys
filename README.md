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
revision `47ef70cb7e5986882018a479385b1cafcdedc13b`, which owns the exact
`primary_chat` selection and concrete output schemas. No Hermes compatibility
schema, tool re-selection, or hand-written alias is permitted. The CI
descriptor job checks out that exact private revision with the repository's
read-only `KB_ENGINE_DEPLOY_KEY` Actions secret and disables persisted Git
credentials. A missing secret or unreachable revision fails the workflow;
local test results do not count as a green GitHub workflow.

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

## Gate S H1 owner evidence

`scripts/h1-owner-evidence.py` is a non-packaged evidence generator for the
released plugin at `9772526c543cec30ee3aee71be952f95dbaf8301`. It runs the
four H1 contract groups against immutable upstream Hermes Agent commit
`2bd1977d8fad185c9b4be47884f7e87f1add0ce3` (`v2026.6.19`). Local tags and
tracked, untracked, or ignored fixture additions are rejected before execution.
It then consumes NOC's root-custodied final plugin deployment receipt
and exact relay cutover receipt plus a separate post-cutover semantic
confirmed-write/readback canary receipt. Every group loads the plugin through
the pinned Hermes fixture; missing or wrong fixtures fail the group.

It creates `h1-test-report.json` and `h1-candidate.json` together in a fresh
mode-0700 directory, with both files mode 0600. Missing, stale, pre-cutover,
secret-bearing, request-lifecycle-only, or digest-mismatched evidence creates
neither file. The semantic handoff binds the canonical NOC producer revision,
`hermes-relay` system-service identity, cutover receipt and plan, and final
plugin deployment receipt. The script never calls Hermes, writes to the KB, or
admits the candidate into NOC.

Candidate freshness is inherited rather than reset: generation uses only the
semantic canary's remaining TTL, and emits nothing once that original lifetime
expires.

The exact NOC handoff schema and invocation are documented in
[`docs/gate-s-h1-owner-evidence.md`](docs/gate-s-h1-owner-evidence.md). NOC
must implement that semantic canary producer before a real H1 candidate can be
emitted.
