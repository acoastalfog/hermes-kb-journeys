# Gate S H1 owner evidence

This repository owns H1's plugin-side test report and candidate generation.
NOC owns deployment, the post-cutover semantic canary, and later trusted-
operator admission. The evidence generator performs no live mutation and no
admission.

## Required inputs

Run from a checkout whose plugin runtime files still equal release commit
`9772526c543cec30ee3aee71be952f95dbaf8301`.

1. An exact clean checkout of `NousResearch/hermes-agent` at annotated tag
   `v2026.6.19`.
2. NOC's final root-custodied `hermes_plugin_deployment_receipt`. Its nested
   install receipt must bind:
   - `current_ref` to `9772526c543cec30ee3aee71be952f95dbaf8301`;
   - `previous_ref` and `rollback_ref` to the same different 40-character ref;
   - the installed tracked-tree digest to this release;
   - the descriptor digest to the committed generated descriptor bundle;
   - an aware install timestamp and non-placeholder NOC plan digest.
3. A separate root-custodied NOC semantic canary receipt and its root-custodied
   artifact. NOC does not currently produce this exact packet; implementing
   the producer is the remaining external blocker.

Input receipt and artifact files must be regular, single-link, root-owned,
non-writable by group/other, and mode 0600 or 0640. Symlinks and oversized
inputs are rejected.

## Exact semantic canary receipt

The canary receipt is strict: missing or extra fields fail. Its canonical JSON
digest excludes only `receipt_digest`.

```json
{
  "schema_version": 1,
  "kind": "hermes_semantic_confirmed_write_canary_receipt",
  "status": "pass",
  "semantic_canary_id": "h1-post-cutover-<id>",
  "run_id": "<terminal-run-id>",
  "plan_digest": "sha256:<64 lowercase hex>",
  "confirmed_digest": "sha256:<same 64 lowercase hex>",
  "resource_id": "canary:<disposable-resource-id>",
  "workspace": "kb_engine_prod",
  "before_observation_digest": "sha256:<64 lowercase hex>",
  "after_observation_digest": "sha256:<different 64 lowercase hex>",
  "mutation_performed": true,
  "durable_readback": true,
  "terminal_state": "completed",
  "observer_host": "helix",
  "observed_at": "<aware UTC timestamp after plugin installed_at>",
  "source_revision": "9772526c543cec30ee3aee71be952f95dbaf8301",
  "artifact": {
    "path": "/absolute/root-custodied/canary-artifact.json",
    "sha256": "sha256:<digest of the exact artifact bytes>"
  },
  "secret_values_exposed": false,
  "receipt_digest": "<canonical receipt digest>"
}
```

`confirmed_digest` must equal `plan_digest`; `workflow_running` and every other
request-lifecycle state are rejected. The before and after observation digests
must differ. The receipt must be no more than 24 hours old, no more than five
minutes in the future, and observed after the final plugin install receipt.

The bound artifact is also strict:

```json
{
  "schema_version": 1,
  "kind": "hermes_semantic_confirmed_write_canary_artifact",
  "semantic_canary_id": "<same canary id>",
  "run_id": "<same run id>",
  "resource_id": "<same canary resource>",
  "workspace": "kb_engine_prod",
  "before_observation_digest": "<same before digest>",
  "after_observation_digest": "<same after digest>",
  "secret_values_exposed": false
}
```

NOC must produce this only after its controlled post-cutover canary has applied
a confirmed write to a disposable canary resource and independently read the
durable state back. A request receipt, optimistic tool response, declared
configuration, or `workflow_running` state is not sufficient.

## Generate, review, and hand off

The output parent must already exist, be owned by the invoking operator, and
be mode 0700. The output directory itself must not exist.

```bash
uv run --with pytest --with pyyaml \
  scripts/h1-owner-evidence.py \
  --hermes-fixture /absolute/path/to/hermes-agent-v2026.6.19 \
  --plugin-deployment-receipt /absolute/path/to/noc-final-plugin-receipt.json \
  --semantic-canary-receipt /absolute/path/to/noc-semantic-canary-receipt.json \
  --output-directory /absolute/mode-0700-parent/h1-owner-evidence \
  --json
```

On success, review:

- `h1-test-report.json`: deterministic check identities, counts, fixture ref,
  descriptor digest, and receipt/artifact digests;
- `h1-candidate.json`: the schema-v1 `knowledge_system_gate_s_receipt` for H1.

Generation does not admit the candidate. A trusted operator separately uses
NOC's `bin/helix knowledge gate-admit` plan/apply flow with the report as the
`test_report_sha256` artifact source. CI's JUnit artifact contains test results
only and is intentionally not an admissible H1 candidate.
