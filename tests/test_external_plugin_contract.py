from __future__ import annotations

import os
import shutil
import sys
import json
import importlib.util
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HERMES_REPO = Path("/Users/acosta/Knowledge/hermes-agent")


def _hermes_repo() -> Path:
    repo = Path(os.environ.get("HERMES_AGENT_REPO", DEFAULT_HERMES_REPO))
    if not (repo / "hermes_cli" / "plugins.py").exists():
        pytest.skip(f"Hermes checkout not available at {repo}")
    return repo


def _reset_plugin_modules() -> None:
    for name in list(sys.modules):
        if name == "hermes_plugins" or name.startswith("hermes_plugins."):
            sys.modules.pop(name, None)


def _manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = _hermes_repo()
    monkeypatch.syspath_prepend(str(repo))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    monkeypatch.setenv("HERMES_BUNDLED_PLUGINS", str(repo / "plugins"))
    _reset_plugin_modules()

    from hermes_cli.plugins import PluginManager

    return PluginManager()


def _enable_kb_journeys(hermes_home: Path) -> None:
    hermes_home.mkdir(parents=True, exist_ok=True)
    (hermes_home / "config.yaml").write_text(
        yaml.safe_dump({"plugins": {"enabled": ["kb_journeys"]}}),
        encoding="utf-8",
    )


def _load_plugin_module(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    repo = _hermes_repo()
    monkeypatch.syspath_prepend(str(repo))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    spec = importlib.util.spec_from_file_location("kb_journeys_external_under_test", ROOT / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class FakeContext:
    def __init__(self, results):
        self.results = {key: list(value) for key, value in results.items()}
        self.calls = []

    def dispatch_tool(self, tool_name, args):
        self.calls.append((tool_name, args))
        values = self.results.get(tool_name)
        result = values.pop(0) if values else {"error": f"missing {tool_name}"}
        return json.dumps(result)


def test_user_install_shadows_bundled_kb_journeys(tmp_path, monkeypatch):
    hermes_home = tmp_path / ".hermes"
    user_plugin = hermes_home / "plugins" / "kb_journeys"
    shutil.copytree(ROOT, user_plugin, ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__"))
    _enable_kb_journeys(hermes_home)

    mgr = _manager(tmp_path, monkeypatch)
    mgr.discover_and_load(force=True)

    loaded = mgr._plugins["kb_journeys"]
    assert loaded.enabled is True
    assert loaded.manifest.source == "user"
    assert loaded.manifest.path == str(user_plugin)
    assert "/kb" in [f"/{name}" for name in loaded.commands_registered]


def test_bundled_fallback_loads_when_user_plugin_absent(tmp_path, monkeypatch):
    hermes_home = tmp_path / ".hermes"
    _enable_kb_journeys(hermes_home)

    mgr = _manager(tmp_path, monkeypatch)
    mgr.discover_and_load(force=True)

    loaded = mgr._plugins["kb_journeys"]
    assert loaded.enabled is True
    assert loaded.manifest.source == "bundled"
    assert "plugins/kb_journeys" in loaded.manifest.path


def test_kb_help_exposes_only_three_primary_verbs(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)

    card = plugin._kb_command_help()
    text = card["text"]

    assert "/kb status" in text
    assert "/kb sync" in text
    assert "/kb review" in text
    assert "/kb queue" not in text
    assert "/kb publish" not in text


def test_bare_review_reply_previews_with_confirm_hint(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb-engine-prod")
    state = {
        "proposal_ids": ["act_crowdstrike"],
        "title": "CrowdStrike",
        "choices": ["approve", "reject", "archive", "detail", "skip"],
    }
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_queue_decision_preview": [
                {
                    "result": {
                        "status": "preview",
                        "ok": True,
                        "preview_lease": {
                            "preview_lease_id": "lease_crowdstrike",
                            "review_session_id": "session_crowdstrike",
                            "cursor_id": "cursor_crowdstrike",
                            "decision_scope": "explicit_ids",
                            "proposal_ids": ["act_crowdstrike"],
                        },
                        "review_session": {
                            "review_session_id": "session_crowdstrike",
                            "cursor": {"cursor_id": "cursor_crowdstrike"},
                            "decision_scope": "explicit_ids",
                        },
                    }
                }
            ],
            "mcp_kb_engine_prod_queue_batch_decide_confirmed": [
                {"result": {"status": "applied", "ok": True}},
            ],
        }
    )

    card = plugin._render_iterative_queue_reply_decision(
        ctx,
        "kb_engine_prod",
        session_id="telegram-session",
        state=state,
        decision="reject",
    )

    assert "Review reject preview" in card["text"]
    assert "To apply: /kb review reject 1 confirm" in card["text"]
    assert [call[0] for call in ctx.calls] == ["mcp_kb_engine_prod_queue_decision_preview"]
    preview_args = ctx.calls[-1][1]
    assert preview_args["proposal_ids"] == ["act_crowdstrike"]
    assert preview_args["decision"] == "reject"


def test_kb_review_defaults_to_lifecycle_and_explicit_queue_uses_inbox(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")

    lifecycle_ctx = FakeContext(
        {
            "mcp_kb_engine_prod_lifecycle_review": [
                {
                    "result": {
                        "packet_type": "lifecycle_review.packet",
                        "workflow": "Lifecycle Review",
                        "stewardship_area": "KB Stewardship",
                        "target": "situations",
                        "mutation_performed": False,
                        "candidates": [
                            {
                                "candidate_id": "cand_1",
                                "title": "Review launch lifecycle",
                                "target_ref": "situations/launch-lifecycle",
                                "recommended_action": "review",
                            }
                        ],
                    }
                }
            ]
        }
    )

    lifecycle_card = plugin._card_for_command(lifecycle_ctx, "kb", args="review")

    assert lifecycle_ctx.calls == [
        ("mcp_kb_engine_prod_lifecycle_review", {"target": "situations", "dry_run": True})
    ]
    assert "Lifecycle Review" in lifecycle_card["text"]
    assert "Review launch lifecycle" in lifecycle_card["text"]
    assert plugin._prose_kb_command_from_text("what is in the review queue") == ("kblifecycle", "")

    queue_ctx = FakeContext(
        {
            "mcp_kb_engine_prod_review_inbox": [
                {
                    "result": {
                        "total": 1,
                        "items": [
                            {
                                "title": "Keio University",
                                "kind": "proposal_entity",
                                "entity_path": "accounts/keio-university",
                                "preview": "Admission proposal for a healthcare AI PoC.",
                                "proposal_ids": ["act_keio"],
                            }
                        ],
                    }
                }
            ]
        }
    )

    queue_card = plugin._card_for_command(queue_ctx, "kb", args="review queue")

    assert queue_ctx.calls[0][0] == "mcp_kb_engine_prod_review_inbox"
    assert "KB Review" in queue_card["text"]
    assert "Keio University" in queue_card["text"]


def test_review_queue_refuses_legacy_queue_fallback_without_review_inbox(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)

    queue_ctx = FakeContext(
        {
            "mcp_kb_engine_prod_queue_summary": [
                {
                    "result": {
                        "total": 1,
                        "items": [{"title": "Legacy Queue Item"}],
                    }
                }
            ]
        }
    )

    queue_card = plugin._card_for_command(queue_ctx, "kb", args="review queue")

    assert queue_ctx.calls == [
        ("mcp_kb_engine_prod_review_inbox", {"scope": "proposals", "limit": 5})
    ]
    assert "KB data is not available yet." in queue_card["text"]
    assert "mcp_kb_engine_prod_review_inbox" in queue_card["text"]
    assert "Legacy Queue Item" not in queue_card["text"]
