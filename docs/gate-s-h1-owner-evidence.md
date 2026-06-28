# Gate S H1 owner evidence

This repository owns H1's plugin-side test report and candidate generation.
NOC owns deployment, the post-cutover semantic canary, and later trusted-
operator admission. The evidence generator performs no live mutation and no
admission.

## Required inputs

Run from a checkout whose plugin runtime files still equal release commit
`e8bc5f536a61dafaf45f884dbb50177781437992`.
The generator also compares every actual tracked source-checkout file and its
executable bit with `HEAD`, then compares the committed runtime paths with the
release tree. These checks use Git tree plumbing and direct file reads rather
than index status hints. Every Git identity and tree command disables
replacement objects, removes inherited `GIT_*` configuration, ignores
system/global Git configuration, and applies controlled worktree settings.
Local or custom-base replacement refs therefore cannot substitute another
commit tree while retaining a pinned ref name.

1. An exact checkout of canonical origin `NousResearch/hermes-agent` at commit
   `2bd1977d8fad185c9b4be47884f7e87f1add0ce3` (the immutable commit behind
   `v2026.6.19`). A local tag is not identity evidence. The tracked tree and
   every untracked or ignored path must be empty of local additions; the
   generator rejects all such paths before executing the fixture. It compares
   every actual tracked file's Git blob identity and executable bit directly
   with the immutable commit tree, so `assume-unchanged` and `skip-worktree`
   index flags cannot conceal modified executed code. Replacement objects,
   custom `GIT_REPLACE_REF_BASE` values, and environment-injected URL rewrites
   are disabled before commit and canonical-origin validation.
2. NOC's final root-custodied `hermes_plugin_deployment_receipt`. Its nested
   install receipt must bind:
   - `current_ref` to `e8bc5f536a61dafaf45f884dbb50177781437992`;
   - `previous_ref` and `rollback_ref` to the same different 40-character ref;
   - the NOC builder tracked-tree digest to
     `sha256:f05120f7a04180bfdd059aff1cc04f2ee77ebcbaba1d24accf73bb5b11d4923d`;
   - the descriptor digest to the committed generated descriptor bundle;
   - an aware install timestamp and non-placeholder NOC plan digest.
3. The separate root-custodied NOC `hermes_relay_deployment_receipt` produced
   by the successful controlled `cutover` apply. Every NOC cutover check must
   be true, including `service_identity`, the target/legacy unit state,
   authority denial, dashboard and Telegram canaries, and rollback canary.
4. A separate root-custodied NOC semantic canary receipt and its root-custodied
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
  "ttl_seconds": 86400,
  "source_revision": "e8bc5f536a61dafaf45f884dbb50177781437992",
  "producer": {
    "source_repository": "acoastalfog/noc",
    "source_revision": "<40 lowercase hex NOC revision>"
  },
  "relay_cutover": {
    "artifact": {
      "path": "/absolute/root-custodied/hermes-relay-cutover-receipt.json",
      "sha256": "sha256:<digest of the exact cutover receipt bytes>"
    },
    "receipt_digest": "<canonical NOC cutover receipt digest>",
    "plan_digest": "<same raw 64-hex plan digest as the cutover receipt>"
  },
  "plugin_deployment_receipt_digest": "<final plugin deployment receipt digest>",
  "service_identity": {
    "os_user": "hermes-relay",
    "service_manager": "systemd",
    "service_scope": "system",
    "unit": "hermes-relay.service"
  },
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
minutes in the future, and observed after both the final plugin install receipt
and the exact bound relay cutover receipt. The canary's NOC producer revision,
system-service identity, relay receipt/plan digests, and final plugin receipt
digest are mandatory. A plugin prepare or deployment receipt by itself cannot
prove relay cutover.

The H1 candidate never resets this lifetime. Its `observed_at` is the evidence
generation time and its `ttl_seconds` is the integer remaining lifetime from
`semantic canary observed_at + semantic canary ttl_seconds`, capped by the
original TTL. At the expiry boundary the generator emits nothing. For example,
a 24-hour canary generated 23 hours and 59 minutes earlier can produce at most
a 60-second H1 candidate, not a new 24-hour receipt.

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
  --relay-cutover-receipt /absolute/path/to/noc-relay-cutover-receipt.json \
  --semantic-canary-receipt /absolute/path/to/noc-semantic-canary-receipt.json \
  --output-directory /absolute/mode-0700-parent/h1-owner-evidence \
  --json
```

On success, review:

- `h1-test-report.json`: deterministic check identities, counts, exact fixture
  repository/ref/revision, service identity, NOC producer, descriptor digest,
  and cutover/plugin/canary receipt and plan digests;
- `h1-candidate.json`: the schema-v1 `knowledge_system_gate_s_receipt` for H1.

Generation does not admit the candidate. A trusted operator separately uses
NOC's `bin/helix knowledge gate-admit` plan/apply flow with the report as the
`test_report_sha256` artifact source. CI's JUnit artifact contains test results
only and is intentionally not an admissible H1 candidate.
