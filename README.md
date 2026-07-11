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
- `kb-source-access` owns live provider search/gather dispatch, opaque refs,
  connector isolation, and private-spool custody.
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

The loader admits at most 13 generated tools, requires concrete input and output schemas,
and rejects deprecated sync routes. Missing or invalid descriptors fail closed;
the plugin does not recreate the MCP catalog or supply compatibility aliases.

The committed export is pinned to kb-engine 0.46.2 at revision
`fb78531ea994d9f4a5e8e961fd41deb0768b6ba2`, which owns the exact
`primary_chat` selection and concrete output schemas. No Hermes compatibility
schema, tool re-selection, or hand-written alias is permitted. The CI
descriptor job checks out that exact private revision with the repository's
read-only `KB_ENGINE_DEPLOY_KEY` Actions secret and disables persisted Git
credentials. A missing secret or unreachable revision fails the workflow;
local test results do not count as a green GitHub workflow.

The Phase F consumer seam pins two once-built artifacts from that same source
revision:

- `kb_engine-0.46.2-py3-none-any.whl` —
  `f38500fee7c9e1f5fe5ff398203328ad47c57f68c4753b38b8e73dd46fc83244`
- `kb_source_access-0.46.2-py3-none-any.whl` —
  `2def0ebb9b0b8b7d6a0b1de2da2f82b3648a8711dacce577073095a6e973da0d`

The machine-readable pins live in `.github/candidate-artifacts/`. Candidate CI
builds both distributions from the exact Git commit, installs both wheels into
an isolated interpreter, and rejects sibling-checkout imports. Runtime Source
Access search also requires the NOC-placed configuration directory through
`HERMES_KB_SOURCE_CONFIG_ROOT`; missing installed owners or placement fails
closed with remediation and does not restore local provider dispatch.

## User contract

Ordinary language stays with the Hermes harness so it can gather sources,
resolve references, ask one focused question when needed, and draft typed
changes. The plugin does not duplicate that judgment with a synonym parser.
The explicit prose forms `kb status`, `kb review`, `kb sync`, and `kb publish`
remain deterministic shortcuts.

Normal cards show at most five items in about eight lines and omit private
paths, integrity digests, MCP names, source bodies, and workflow internals.
`kb publish` previews and stores one exact path/head/digest binding. A separate
`kb publish confirm` call revalidates that binding and asks kb-engine to commit
and push it. Hermes receives no Git, shell, SSH, NOC, filesystem, or publication
credential capability; the engine performs the governed effect and returns the
readback receipt.

Version 0.8.1 also exposes aggregate model-call, kb-engine-call, and context-size
metrics only to an isolated NOC probe that supplies a valid inherited pipe and
run id. The isolated one-shot emits exactly one packet after its completed LLM
turn. Provider-attempt hooks count model calls and canonical UTF-8 context size;
identified kb-engine tool hooks are deduplicated, while a missing tool-call id
makes the packet incomplete. Normal Hermes sessions register no telemetry
observers, and the packet contains no prompts, responses, tool names, errors,
or correlation identifiers. The plugin stores nothing; missing, incomplete, or
malformed probe telemetry remains unobserved rather than inferred.

## Canonical sync and change surface

Version 0.8.0 makes `/kb sync` and command-like `kb sync` call the generated
`kb.sync.prepare` contract. Hermes records the run id privately and renders the
engine's next harness action; the harness gathers evidence and exercises
judgment. `/kb sync status` reads the same durable run, and `/kb sync apply`
calls `kb.sync.resume` with standing safe-write authorization—no digest-copy
ceremony. Hermes claims success only after a separate
`kb.sync.status` readback reports the same run in the same successful terminal
state, including truthful completion with degradation.
Publication remains a separate action and is never implied by sync.

The same generated primary profile exposes only the two-step
`change.preview` and `change.apply` write surface. Hermes does not
restore the retired overloaded `control.*` wrappers.

The old `/kbsync`, `update_kb`, and `/kb run sync` entrypoints remain hard
breaks with migration guidance. Missing canonical descriptors fail closed.

Version 0.9.0 keeps one narrow transport tool for complete source packets that
exceed model-context limits. `kb-sync-gather` already writes the exact packet
to a private mode-0600 spool; `kb_integration_transport(operation=resume_packet)` verifies that file is
inside the Hermes state spool, validates its owner, mode, schema, and
content-bound filename, and forwards it through the existing generated
`kb.sync.resume` MCP tool. It returns only compact run state. This is not a
source executor or second sync path: the connector still gathers, kb-engine
still validates and owns the run, and Hermes Agent remains exact upstream.

The same single tool's `daily_integration_closeout` operation composes the
completed-run readback, the protected local `calendar.live` socket, and the two
generated clean-publication calls. The plugin never receives a Graph credential
or connector path and never claims per-run human confirmation. It returns only
compact stage truth and a six-line morning brief; full calendar and publication
receipts remain bound to the engine run. With thirteen generated engine tools plus
this one local transport, Hermes stays at the fourteen-tool cap.

Version 0.9.1 adds `semantic_batch` to that same transport tool. It forwards
one exact evidence or target selection through `kb.sync.status`, preserves the
review token, source content, current candidate state, target dossiers, and
response schema, and removes only redundant run-wide status fields. Requests
may contain up to ten refs; the transport deterministically halves an oversized
prefix until the serialized result fits below the upstream persistence bound.
The durable semantic frontier, judgment, and accepted response remain owned by
kb-engine and the Hermes harness.

Version 0.9.2 keeps an individually oversized target dossier fail-closed but
usable. The first bounded response contains the exact target, object and dossier
digests, full evidence-ref set, current object context, and a deterministic
prefix of the exact evidence. When `has_more` is true, the harness repeats the
same one-target request with the returned `next_evidence_offset` until every
evidence item has been read. The plugin holds no semantic state and never
summarizes or drops source evidence.

Version 0.9.3 applies the same lossless rule to an individually oversized
source-evidence body. A byte-identical duplicate `transcript` field is omitted
while the canonical `semantic_text` remains intact. If that canonical text is
still too large, the response contains a deterministic character page and the
harness repeats the same one-evidence request with the returned
`next_text_offset` until the full body has been read. Review tokens, evidence
identity, revision metadata, and all non-duplicate fields remain on every page.

Version 0.9.4 reuses that exact text-page contract when one evidence row inside
a target dossier is itself oversized. The harness keeps the same target and
`target_evidence_offset`, follows `evidence_text_page.next_text_offset` until
that body is complete, then proceeds to the next evidence row. Current-object
context, target and dossier digests, the full evidence-ref set, and review token
remain bound on every page; the plugin still holds no semantic state.

Version 0.9.5 keeps the full response schema, current-object context, and full
evidence-ref set on page one, then omits those already-read invariants from
continuation pages. Every continuation still carries the exact target, object,
dossier, and evidence bindings plus deterministic page offsets. This prevents
large schemas and object context from being re-injected into the model context
for every page without dropping evidence or adding plugin state.

Version 0.9.6 refreshes the generated contracts to kb-engine 0.45.38. When an
oversized target reports `evidence_summary_required`, the harness reads the
exact raw rows in batches of at most ten and checkpoints concise summaries
bound to the target, evidence ref, and raw-item digest through the existing
`kb.sync.resume` path. After every row is checkpointed, the engine returns one
compact `evidence_summaries` dossier for the existing single net target result.
The plugin adds no model, state, scheduler, or alternate sync path.

Version 0.9.7 lets Daily Integration continue from a fully accounted degraded
run only when every degradation is non-retryable item-level source content
insufficiency, every source is current, semantic review is complete, and
lifecycle work is at a fixed point. Source-level and retryable failures remain
held before calendar or Git closeout.

Version 0.10.0 adds one read-only `context_search` operation to the existing
`kb_integration_transport` tool for ordinary meeting prep, event planning,
schedule work, account refreshes, email drafting, and travel reconciliation.
The operation accepts bounded terms, declared sources, an exact time window,
and a small result limit. It reads Calendar, Outlook mail, Slack, TripIt, and
resolved past-meeting artifacts through the relay's isolated source-read
identity; it cannot write the KB or start an external effect. Calendar's
date-only connector bounds are filtered back to the requested UTC interval,
Slack uses one complete window of at most seven days, TripIt returns a current
snapshot without confirmation details, and every source reports its own typed
degradation. Source content is clipped before entering model context, and the
whole result remains under the existing transport result bound.

Version 0.10.2 makes the complete Source Access `packet_transport` object the
preferred `resume_packet` contract. The caller passes `kind`, absolute private
path, full canonical SHA-256 digest, and actual byte count unchanged. The
plugin opens the confined spool and every in-spool parent without following
links, validates owner and private modes, keeps the verified file descriptor
open through the existing `kb.sync.resume` call, and deletes only that exact
inode after an accepted engine response. Invalid and retryable responses retain
the packet with compact cleanup state; the private packet body and its transport
path and digest never appear in the result. The old bare `packet_path` input
remains an explicitly deprecated compatibility branch for the current
`kb-sync-gather` guidance and must be removed after those callers migrate to the
descriptor.

Version 0.10.3 resolves generated engine tools with the canonical MCP name
builder exported by the running Hermes release. This follows Hermes 0.18.2's
`mcp__server__tool` registry convention while retaining the older
`mcp_server_tool` fallback for v2026.6.19. Failed host dispatches expose only a
bounded reason code; they never return packet contents or raw error text.
Accepted packet resumes retain the same exact-inode cleanup contract.

Version 0.10.4 handles the case where exact target review invariants fit under
the transport ceiling but leave no room for even one evidence-text character.
The first response becomes a bounded context-only proof page: it retains the
current object context, complete evidence-ref set, review token, and exact
object and dossier digests while returning no evidence body. The harness then
continues at the returned `next_evidence_offset`, which may be zero. Direct
evidence pages omit only those already-read page-one invariants and retain the
target, object, dossier, evidence, and item digests plus every evidence field.
Semantic text remains losslessly character-paged when needed; the plugin adds
no hidden state and never summarizes or truncates source content. A
`context_only` page is proof and context, not sufficient input for judgment;
the harness must continue until `has_more` is false before resuming the engine.
If the exact context-only proof page or one evidence row's non-text metadata is
itself larger than the ceiling, the transport still fails closed instead of
dropping a field. General metadata paging remains a separate future extension.

Version 0.10.5 bounds private-spool retry custody: accepted and terminal
non-retryable handoffs delete only the exact verified inode and packet directory,
while retryable transport or engine failures retain the packet for replay.

Version 0.10.6 lets the existing `daily_integration_closeout` operation accept
either the compatible single `calendar_envelope` or a `calendar_envelopes`
array of one to fifty single-entity managed plans. The array is canonical even
for one Event entity; the singular input remains compatibility-only. Every
non-empty plan must declare `desired_set_complete: true`, bind the same
exact completed run and source reads, and canonical Event identities must be
distinct even when active and archive paths differ. The plugin recomputes every
plan digest and submits one digest-bound batch through the declared protected
transport; Hermes never calls NOC directly. These pre-preparation envelopes are
harness-attested and engine-routed; kb-engine then stages and authorizes the exact intent. The owned
calendar connector performs one complete owned-set read, enforces the aggregate
delete floor, and executes plans serially with idempotent progress recovery. NOC
relays the typed result and records engine writeback without owning calendar
semantics. Only after every compact receipt proves balanced counts, readback,
durable recording, and no held work does the plugin aggregate the existing
engine closeout shape, retaining the batch digest and every ordered plan/child
receipt digest when work was planned (or the canonical empty-list digest for a
true no-op), and perform one publication preview/apply pair. Publication
acknowledgement then removes private recovery material while retaining an
idempotent compact tombstone for lost acknowledgements. Any refused, partial, or
uncertain batch prevents publication.

Version 0.10.7 carries the connector's one batch-wide terminal calendar
observation through the aggregate publication receipt and final morning brief.
The pre-execution safety count remains distinct from the complete final owned
count and privacy-safe digest; attendee and Graph event-type violations are
reported only as aggregate counts. Exact closeout replay consumes the compact
acknowledged tombstone and performs no additional connector or Graph-bound call.

Version 0.10.8 removes the model-supplied closeout session ID. Hermes injects
the actual runtime session into every tool handler; the plugin now binds that
value to publication provenance, fails closed when it is absent, and returns a
privacy-safe SHA-256 `execution_session_binding` for operational verification.
The nested `publication.session_binding` separately attests the session stored
in kb-engine's durable publication receipt. A fresh publication must return the
current execution session; an idempotent replay may retain the original
publication session while a later Hermes session completes recovery cleanup.
Neither binding exposes a raw session ID, and a model argument can neither
invent nor override the execution binding.

Version 0.11.0 makes those installed packages authoritative for the integration
transport. A v2 Source Access transport descriptor is passed unchanged to
`kb.sync.resume`; kb-engine validates its recipe/session binding and packet,
then kb-source-access performs connector-owned cleanup only after accepted or
terminal non-retryable handoff. The released v1 descriptor and bare-path branch
remain isolated compatibility paths for the rollback window.

Semantic review requests now return the `kb.sync.status` packet intact. Hermes
may reduce only the selected-ref prefix to satisfy its response budget; it no
longer removes engine fields or normalizes duplicate source fields. The old
offset pager remains a named v1 compatibility path for individually oversized
packets until engine/consumer soak permits retirement.

Daily Integration now follows the engine's durable closeout state machine.
Hermes routes the protected calendar executor, asks the installed calendar
contract to prepare/validate/aggregate the result, records that aggregate with
`kb.sync.resume` as `kb.integration.effect_results`, routes governed Git
publication, records its exact readback as
`kb.integration.publication_result`, and renders only the resulting
`kb.integration.final_receipt` plus final summary. Runtime-session attestation
and connector recovery acknowledgement remain Hermes delivery concerns. Exact
terminal replay performs no calendar effect or Git publication again.

The `context_search` operation now calls the installed Source Access facade for
Calendar, mail, Slack, meeting artifacts, and the declared TripIt capability.
Hermes only aggregates opaque refs and bounded connector summaries. A source
that does not advertise search (currently TripIt) returns its typed degraded
status instead of falling back to `kb-sync-gather` or a provider CLI.

Before these plans are authored, an unbound TripIt anchor group is merged into
the unique existing bound Event when the provider source ID matches exactly and
the anchor date window is contained. That case must never mint a synthetic Event
path; all of its calendar artifacts remain consolidated in the bound Event's one
single-entity envelope.

## Local Test

Set `HERMES_AGENT_REPO` to either a Hermes Agent v2026.6.19 checkout or a
current-upstream checkout:

```bash
python -m venv .owner-venv
.owner-venv/bin/pip install \
  /path/to/kb_engine-0.46.2-py3-none-any.whl \
  /path/to/kb_source_access-0.46.2-py3-none-any.whl \
  pytest pyyaml
env -u PYTHONPATH .owner-venv/bin/python -I -m pytest \
  tests/test_external_plugin_contract.py -q
```
