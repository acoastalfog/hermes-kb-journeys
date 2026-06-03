# Hermes KB Journeys Plugin

Out-of-tree Hermes plugin for Anthony's KB guided review journeys.

This repository packages the `kb_journeys` Hermes plugin as a standard user
plugin installed under `$HERMES_HOME/plugins/kb_journeys`. It intentionally
keeps the plugin name/key as `kb_journeys` so a NOC-managed production install
can shadow the bundled Hermes fallback without deleting the fallback.

## Boundaries

- `kb-engine` owns durable KB semantics, preview leases, confirmed envelopes,
  receipts, provenance, restore/undo, and stale handling.
- Hermes owns Telegram/runtime rendering over backend packets.
- NOC owns production placement, install refs, route validation, canaries, and
  rollback.
- Skills guide wording and operator posture only.

## Rollback

Because Hermes resolves plugin sources by key and later sources override earlier
ones, a present user plugin at `$HERMES_HOME/plugins/kb_journeys` shadows the
bundled fallback. Rollback must remove or rename that user-plugin directory,
then restart/reload Hermes so bundled `plugins/kb_journeys` is discovered again.
Disabling the plugin in config is not enough for fallback if the user plugin is
still present.

## Local Test

Set `HERMES_AGENT_REPO` if the Hermes checkout is not at
`/Users/acosta/Knowledge/hermes-agent`:

```bash
python -m pytest -q
```
