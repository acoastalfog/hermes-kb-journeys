from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import sys
import json
import importlib.util
from copy import deepcopy
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
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    spec = importlib.util.spec_from_file_location("kb_journeys_external_under_test", ROOT / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _install_conforming_descriptor_fixture(plugin, monkeypatch: pytest.MonkeyPatch):
    packet = _conforming_descriptor_packet(plugin)
    bundle, tools = plugin._validate_descriptor_bundle(packet)
    monkeypatch.setattr(plugin, "_DESCRIPTOR_BUNDLE", bundle)
    monkeypatch.setattr(plugin, "_DESCRIPTOR_TOOLS", tools)
    monkeypatch.setattr(plugin, "_DESCRIPTOR_ERROR", "")
    return bundle


def _conforming_descriptor_packet(plugin):
    packet = json.loads((ROOT / "generated" / "kb-engine-descriptors.json").read_text(encoding="utf-8"))
    body = deepcopy(packet)
    body.pop("digest")
    for descriptor in body["tools"]:
        schema = {
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "ok": {"type": "boolean"},
            },
            "required": ["status"],
            "additionalProperties": True,
        }
        descriptor["output_schema"] = schema
        descriptor["output_schema_digest"] = plugin._descriptor_digest(schema)
        if descriptor["name"] == "workflow.start_confirmed":
            envelope = {
                "type": "object",
                "properties": {
                    "plan_digest": {"type": "string"},
                    "user_confirmation": {
                        "type": "object",
                        "properties": {"confirmed": {"type": "boolean"}},
                        "required": ["confirmed"],
                        "additionalProperties": True,
                    },
                },
                "required": ["plan_digest", "user_confirmation"],
                "additionalProperties": True,
            }
            descriptor["input_schema"]["properties"]["envelope"] = envelope
            descriptor["input_schema_digest"] = plugin._descriptor_digest(descriptor["input_schema"])
    tools = {descriptor["name"]: descriptor for descriptor in body["tools"]}
    for action in body["actions"]:
        action["input_schema_digest"] = tools[action["name"]]["input_schema_digest"]
        action["output_schema_digest"] = tools[action["name"]]["output_schema_digest"]
    return {**body, "digest": plugin._descriptor_digest(body)}


def _future_evidence_descriptors():
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    item_schema = {
        "type": "object",
        "properties": {"external_id": {"type": "string"}},
        "required": ["external_id"],
        "additionalProperties": True,
    }
    packet_schema = {
        "type": "object",
        "properties": {"items": {"type": "array", "items": item_schema}},
        "required": ["items"],
        "additionalProperties": True,
    }
    lease = {
        "type": "object",
        "properties": {
            "lease_id": {"type": "string"},
            "expires_at": {"type": "string"},
        },
        "required": ["lease_id", "expires_at"],
        "additionalProperties": False,
    }
    binding_properties = {
        "target": {"type": "string"},
        "preview_digest": digest,
        "preview_lease": lease,
        "idempotency_key": {"type": "string"},
        "evidence_packet_digest": digest,
    }
    binding_required = sorted(binding_properties)
    return {
        "evidence.remember.preview": {
            "name": "evidence.remember.preview",
            "input_schema": {
                "type": "object",
                "properties": {"evidence_packet": packet_schema},
                "required": ["evidence_packet"],
                "additionalProperties": False,
            },
            "output_schema": {
                "type": "object",
                "properties": binding_properties,
                "required": binding_required,
                "additionalProperties": True,
            },
        },
        "evidence.remember.confirmed": {
            "name": "evidence.remember.confirmed",
            "input_schema": {
                "type": "object",
                "properties": {
                    "envelope": {
                        "type": "object",
                        "properties": {
                            **binding_properties,
                            "evidence_packet": packet_schema,
                            "user_confirmation": {
                                "type": "object",
                                "properties": {"confirmed": {"type": "boolean"}},
                                "required": ["confirmed"],
                                "additionalProperties": True,
                            },
                        },
                        "required": sorted([*binding_required, "evidence_packet", "user_confirmation"]),
                        "additionalProperties": False,
                    }
                },
                "required": ["envelope"],
                "additionalProperties": False,
            },
            "output_schema": {
                "type": "object",
                "properties": {"status": {"type": "string"}},
                "required": ["status"],
                "additionalProperties": True,
            },
        },
    }


class FakeContext:
    def __init__(self, results):
        self.results = {key: list(value) for key, value in results.items()}
        self.calls = []

    def dispatch_tool(self, tool_name, args):
        self.calls.append((tool_name, args))
        values = self.results.get(tool_name)
        result = values.pop(0) if values else {"error": f"missing {tool_name}"}
        return json.dumps(result)


def test_user_plugin_loads_from_standard_plugin_directory(tmp_path, monkeypatch):
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


def test_pinned_upstream_has_no_bundled_kb_journeys_fallback():
    repo = _hermes_repo()
    requested_ref = os.environ.get("HERMES_UPSTREAM_REF", "")
    exact_tag = subprocess.run(
        ["git", "-C", str(repo), "describe", "--tags", "--exact-match"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    if requested_ref != "v2026.6.19" and exact_tag != "v2026.6.19":
        pytest.skip("absence contract is pinned to Hermes Agent v2026.6.19")
    tracked = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "HEAD", "plugins/kb_journeys"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert tracked == []


def test_kb_help_exposes_only_three_primary_verbs(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)

    card = plugin._kb_command_help()
    text = card["text"]

    assert "/kb status" in text
    assert "/kb sync" in text
    assert "/kb review" in text
    assert "/kb queue" not in text
    assert "/kb publish" not in text


def test_kb_sync_starts_canonical_prepare_and_renders_next_action(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    source = type(
        "Source",
        (),
        {"platform": "telegram", "chat_id": "chat-1", "thread_id": "", "user_id": "42"},
    )()
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_kb_sync_prepare": [
                {
                    "result": {
                        "schema_version": 1,
                        "kind": "kb_sync_run",
                        "status": "awaiting_action",
                        "run_id": "kb_sync-test",
                        "next_action": {
                            "kind": "gather_evidence",
                            "action_index": 0,
                            "source_id": "m365.email",
                            "instruction": "Gather this exact bounded window.",
                        },
                        "publication": {
                            "status": "not_attempted",
                            "separate_confirmation_required": True,
                            "sync_publishes": False,
                        },
                    }
                }
            ]
        }
    )

    card = plugin._card_for_command(ctx, "kb", args="sync", source=source)

    assert card["status"] == "awaiting_action"
    assert card["actions"] == []
    assert "evidence gathering" in card["text"]
    assert "kb_sync-test" not in card["text"]
    assert "m365.email" not in card["text"]
    assert len(card["text"].splitlines()) <= 8
    assert "kb_sync." not in json.dumps(card)
    assert "update_kb" not in json.dumps(card)
    assert ctx.calls == [
        (
            "mcp_kb_engine_prod_kb_sync_prepare",
            {"actor": "telegram:42", "session_id": "telegram:chat-1:42"},
        )
    ]


def test_generated_profile_exposes_canonical_kb_sync_contract(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    assert plugin._canonical_sync_contract_ready() is True


@pytest.mark.parametrize(
    "readback_status",
    ["completed", "completed_with_degradation", "failed"],
)
def test_kb_sync_apply_claims_success_only_after_terminal_readback(
    readback_status, tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    source = type(
        "Source",
        (),
        {"platform": "telegram", "chat_id": "chat-1", "thread_id": "", "user_id": "42"},
    )()
    digest = "a" * 64
    prepared = {
        "schema_version": 1,
        "kind": "kb_sync_run",
        "status": "awaiting_action",
        "run_id": "kb_sync-test",
        "next_action": {
            "kind": "gather_evidence",
            "action_index": 0,
            "instruction": "Gather evidence.",
        },
    }
    ready = {
        "schema_version": 1,
        "kind": "kb_sync_run",
        "status": "ready_to_apply",
        "run_id": "kb_sync-test",
        "authorization": {
            "digest": digest,
            "expires_at": "2099-01-01T00:00:00Z",
            "bound_actor": "telegram:42",
            "bound_session_id": "telegram:chat-1:42",
            "mode": "standing_safe_write",
            "human_confirmation_required": False,
        },
        "publication": {
            "status": "not_attempted",
            "separate_confirmation_required": True,
            "sync_publishes": False,
        },
    }
    readback = {
        "schema_version": 1,
        "kind": "kb_sync_run",
        "status": readback_status,
        "terminal_state": readback_status,
        "run_id": "kb_sync-test",
        "publication": {
            "status": "not_attempted",
            "separate_confirmation_required": True,
            "sync_publishes": False,
        },
    }
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_kb_sync_prepare": [{"result": prepared}],
            "mcp_kb_engine_prod_kb_sync_status": [
                {"result": ready},
                {"result": readback},
            ],
                "mcp_kb_engine_prod_kb_sync_resume": [
                    {
                        "result": {
                            "schema_version": 1,
                            "kind": "kb_sync_receipt",
                            "status": (
                                readback_status
                                if readback_status in {"completed", "completed_with_degradation"}
                                else "completed"
                            ),
                            "terminal_state": (
                                readback_status
                                if readback_status in {"completed", "completed_with_degradation"}
                                else "completed"
                            ),
                            "run_id": "kb_sync-test",
                            "publication": {
                                "status": "not_attempted",
                                "separate_confirmation_required": True,
                                "sync_publishes": False,
                            },
                        }
                    }
            ],
        }
    )
    plugin._card_for_command(ctx, "kb", args="sync", source=source)
    card = plugin._card_for_command(ctx, "kb", args="sync apply", source=source)

    assert [name for name, _args in ctx.calls] == [
        "mcp_kb_engine_prod_kb_sync_prepare",
        "mcp_kb_engine_prod_kb_sync_status",
        "mcp_kb_engine_prod_kb_sync_resume",
        "mcp_kb_engine_prod_kb_sync_status",
    ]
    assert ctx.calls[2][1] == {"run_id": "kb_sync-test", "apply": True}
    if readback_status in {"completed", "completed_with_degradation"}:
        assert "Receipt: verified" in card["text"]
        assert "saved" in card["text"]
        if readback_status == "completed_with_degradation":
            assert "completed with gaps" in card["text"].lower()
    else:
        assert "Receipt: verified" not in card["text"]
        assert "no completion is claimed" in card["text"].lower()


def test_kb_sync_apply_rejects_another_actor_or_conversation(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    source = type(
        "Source",
        (),
        {"platform": "telegram", "chat_id": "chat-1", "thread_id": "", "user_id": "42"},
    )()
    prepared = {
        "schema_version": 1,
        "kind": "kb_sync_run",
        "status": "awaiting_action",
        "run_id": "kb_sync-test",
        "next_action": {"kind": "gather_evidence", "action_index": 0, "instruction": "Gather."},
    }
    wrong_owner = {
        "schema_version": 1,
        "kind": "kb_sync_run",
        "status": "ready_to_apply",
        "run_id": "kb_sync-test",
        "authorization": {
            "digest": "a" * 64,
            "expires_at": "2099-01-01T00:00:00Z",
            "bound_actor": "telegram:99",
            "bound_session_id": "telegram:other:99",
            "mode": "standing_safe_write",
            "human_confirmation_required": False,
        },
    }
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_kb_sync_prepare": [{"result": prepared}],
            "mcp_kb_engine_prod_kb_sync_status": [{"result": wrong_owner}],
        }
    )
    plugin._card_for_command(ctx, "kb", args="sync", source=source)
    card = plugin._card_for_command(ctx, "kb", args="sync apply", source=source)
    assert card["status"] == "authorization_owner_mismatch"
    assert "No KB state changed" in card["text"]
    assert all("kb_sync_resume" not in name for name, _args in ctx.calls)


def test_bare_review_reply_previews_with_confirm_hint(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb-engine-prod")
    state = {
        "proposal_ids": ["act_crowdstrike"],
        "title": "CrowdStrike",
        "choices": ["approve", "reject", "archive", "detail", "skip"],
    }
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_review_decision_preview": [
                {
                    "result": {
                        "status": "preview",
                        "ok": True,
                        "decision": "reject",
                        "proposal_ids": ["act_crowdstrike"],
                        "preview_hash": "a" * 64,
                        "plan": {"operations": [{"operation_id": "proposal.reject"}]},
                        "preview_lease": {
                            "preview_lease_id": "lease_crowdstrike",
                            "preview_hash": "a" * 64,
                            "confirm_tool": "review.batch_decide_confirmed",
                            "decision": "reject",
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
            "mcp_kb_engine_prod_review_batch_decide_confirmed": [
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

    assert "not available in the generated Hermes profile" in card["text"]
    assert ctx.calls == []


def test_kb_review_defaults_to_lifecycle_and_explicit_queue_uses_inbox(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")

    cockpit = {
        "schema_version": 1,
        "front_door": "attention_cockpit",
        "status": "ready",
        "summary": {"proposal_queue_count": 1},
        "sections": {
            "situations": {"items": []},
            "queue": {"items": [{"title": "Review launch lifecycle"}]},
        },
    }
    lifecycle_ctx = FakeContext(
        {"mcp_kb_engine_prod_attention_cockpit": [{"result": cockpit}]}
    )

    lifecycle_card = plugin._card_for_command(lifecycle_ctx, "kb", args="review")

    assert lifecycle_ctx.calls[0][0] == "mcp_kb_engine_prod_attention_cockpit"
    assert lifecycle_ctx.calls[0][1]["sections"] == ["situations", "queue"]
    assert lifecycle_card["title"] == "KB Review"
    assert plugin._prose_kb_command_from_text("what is in the review queue") == ("kblifecycle", "")

    queue_ctx = FakeContext(
        {"mcp_kb_engine_prod_attention_cockpit": [{"result": cockpit}]}
    )

    queue_card = plugin._card_for_command(queue_ctx, "kb", args="review queue")

    assert queue_ctx.calls[0][0] == "mcp_kb_engine_prod_attention_cockpit"
    assert queue_card["title"] == "KB Review"


def test_review_queue_refuses_legacy_queue_fallback_without_review_inbox(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)

    queue_ctx = FakeContext(
        {
            "mcp_kb_engine_prod_attention_cockpit": [
                {
                    "result": {
                        "schema_version": 1,
                        "front_door": "attention_cockpit",
                        "status": "ready",
                        "summary": {"proposal_queue_count": 0},
                        "sections": {"situations": {"items": []}, "queue": {"items": []}},
                    }
                }
            ]
        }
    )

    queue_card = plugin._card_for_command(queue_ctx, "kb", args="review queue")

    assert queue_ctx.calls[0][0] == "mcp_kb_engine_prod_attention_cockpit"
    assert "Legacy Queue Item" not in queue_card["text"]


# --- Phase 2 #7: Telegram capture command ---

def test_kb_capture_fails_closed_until_evidence_contract_is_exported(tmp_path, monkeypatch):
    from types import SimpleNamespace
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakeContext({})
    source = SimpleNamespace(chat_id="12345678", platform="telegram", user_id="42", user_name="Anthony")
    event = SimpleNamespace(
        source=source, message_id="100", reply_to_message_id="99",
        reply_to_text="This tweet about a new model is important", raw_message=None, text="/kb capture",
    )
    card = plugin._render_capture_command(ctx, "kb_engine_prod", "", event=event, source=source, session_store=None)
    assert card["status"] == "temporarily_unavailable"
    assert card["actions"] == []
    assert "evidence.remember.preview/confirmed" in card["text"]
    assert ctx.calls == []


def test_evidence_receipt_uses_evidence_only_wording(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    digest = "sha256:" + "a" * 64
    card = plugin._render_evidence_completion(
        {
            "status": "remembered",
            "ok": True,
            "receipt": {"confirmed": True, "receipt_id": "ev-1", "content_digest": digest},
            "readback": {"status": "verified", "receipt_id": "ev-1", "content_digest": digest},
        },
        title="KB Capture",
    )
    assert "Evidence remembered" in card["text"]
    assert "Captured to the KB" not in card["text"]
    assert "Saved to the KB" not in card["text"]


def test_kb_capture_routes_via_root_command(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    assert plugin._kb_root_command("capture") == ("kbcapture", "")
    assert plugin._kb_root_command("capture confirm") == ("kbcapture", "confirm")
    assert plugin._kb_root_command("save") == ("kbcapture", "")


# --- P0: /kb write durable-note verb + readback gate (hermes-kb-journeys#6) ---

def test_kb_write_routes_via_root_command(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    assert plugin._kb_root_command("write events/bio | a note") == ("kbwrite", "events/bio | a note")
    assert plugin._kb_root_command("note just text") == ("kbwrite", "just text")
    assert plugin._kb_root_command("write confirm") == ("kbwrite", "confirm")


def test_kb_write_fails_closed_without_evidence_descriptors(tmp_path, monkeypatch):
    from types import SimpleNamespace
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakeContext({})
    source = SimpleNamespace(chat_id="12345678", platform="telegram", user_id="42", user_name="Anthony")
    event = SimpleNamespace(source=source, message_id="200", reply_to_message_id=None,
                            reply_to_text=None, raw_message=None, text="/kb write events/bio | remember the panel time")
    card = plugin._render_write_command(ctx, "kb_engine_prod", "events/bio | remember the panel time",
                                        event=event, source=source, session_store=None)
    assert card["status"] == "temporarily_unavailable"
    assert card["actions"] == []
    assert ctx.calls == []


def test_optimistic_confirm_without_readback_never_renders_durable_success(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    optimistic = {"status": "applied", "ok": True, "receipt": {"new_count": 1}}
    assert plugin._durable_completion(optimistic)["complete"] is False
    text = plugin._confirmed_text("approve", optimistic, proposal_ids=["p1"])
    assert "Applied" not in text
    assert "saved" not in text.lower()


def test_durable_completion_requires_generated_request_binding_in_addition_to_readback(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    payload = {
        "status": "applied",
        "ok": True,
        "receipt": {
            "confirmed": True,
            "receipt_id": "r-1",
            "object_id": "todo-1",
            "content_digest": "sha256:" + "a" * 64,
        },
        "readback": {
            "status": "verified",
            "receipt_id": "r-1",
            "object_id": "todo-1",
            "content_digest": "sha256:" + "a" * 64,
        },
    }
    assert plugin._durable_completion(payload)["complete"] is True
    text = plugin._confirmed_text("approve", payload, proposal_ids=["p1"])
    assert "Applied" not in text
    assert "generated_completion_contract_missing" in text


def test_unrelated_matching_receipt_never_proves_selected_proposal_completion(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    digest = "sha256:" + "a" * 64
    payload = {
        "status": "applied",
        "ok": True,
        "receipt": {
            "confirmed": True,
            "transaction_id": "tx-unrelated",
            "content_digest": digest,
        },
        "readback": {
            "status": "verified",
            "transaction_id": "tx-unrelated",
            "content_digest": digest,
        },
    }
    text = plugin._confirmed_text("approve", payload, proposal_ids=["p-selected"])
    assert "Applied" not in text
    assert "unverified" in text


def _request_bound_review_fixture(plugin):
    route = "review.batch_decide_confirmed"
    preview_hash = "a" * 64
    args = {
        "proposal_ids": ["p-selected"],
        "decision": "approve",
        "actor": "telegram:operator",
        "source": "Hermes Telegram",
        "session_id": "session-1",
        "user_confirmation": {
            "confirmed": True,
            "surface": "telegram",
            "preview_lease": {
                "preview_lease_id": "lease-1",
                "preview_hash": preview_hash,
            },
        },
    }
    expected = plugin._review_completion_expectation(route, args)
    transaction_id = "tx-1"
    receipt = {
        "route": route,
        "state": "applied",
        "ok": True,
        "saved": True,
        "receipt_id": "receipt-1",
        "transaction_id": transaction_id,
        "affected_ids": ["p-selected"],
    }
    receipt["receipt_digest"] = plugin._descriptor_digest(receipt)
    request_payload = {
        "route": route,
        "affected_ids": ["p-selected"],
        "decision": "approve",
        "target_status": "",
        "source_transaction_id": "",
        "actor": args["actor"],
        "source": args["source"],
        "session_id": args["session_id"],
        "preview_lease": args["user_confirmation"]["preview_lease"],
        "idempotency_key": transaction_id,
    }
    payload = {
        "schema_version": 1,
        "status": "applied",
        "ok": True,
        "completion": {
            "route": route,
            "action": "review_decision",
            "state": "applied",
            "affected_ids": ["p-selected"],
            "decision": "approve",
            "request": {
                "preview_digest": "sha256:" + preview_hash,
                "preview_lease_id": "lease-1",
                "request_digest": plugin._descriptor_digest(request_payload),
                "idempotency_key": transaction_id,
            },
            "confirmation": {
                "confirmed": True,
                "confirmation_digest": plugin._descriptor_digest(args["user_confirmation"]),
            },
            "transaction_id": transaction_id,
        },
        "receipt": receipt,
        "readback": {
            "route": route,
            "state": "applied",
            "ok": True,
            "receipt_id": "receipt-1",
            "receipt_digest": receipt["receipt_digest"],
            "transaction_id": transaction_id,
            "affected_ids": ["p-selected"],
            "content_digest": "sha256:" + "b" * 64,
            "observed_at": plugin._capture_now(),
        },
    }
    return payload, expected


def test_removed_review_completion_contract_is_never_fabricated(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    route = "review.batch_decide_confirmed"
    payload, expected = _request_bound_review_fixture(plugin)
    assert plugin._validate_runtime_output(route, payload) == (
        "capability is not present in the generated descriptor allowlist"
    )
    assert plugin._request_bound_review_completion(payload, expected) == {
        "complete": False,
        "reason": "generated_completion_contract_missing",
    }


def test_durable_completion_rejects_any_joint_identity_mismatch(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    payload = {
        "status": "applied",
        "ok": True,
        "receipt": {
            "confirmed": True,
            "receipt_id": "r-1",
            "object_id": "todo-1",
            "content_digest": "sha256:" + "a" * 64,
        },
        "readback": {
            "status": "verified",
            "receipt_id": "forged-r-2",
            "object_id": "todo-1",
            "content_digest": "sha256:" + "a" * 64,
        },
    }
    proof = plugin._durable_completion(payload)
    assert proof["complete"] is False
    assert proof["reason"] == "identity_mismatch"


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("top", "status", "cancelled"),
        ("top", "ok", False),
        ("top", "mutation_performed", False),
        ("top", "applied", False),
        ("receipt", "status", "failed"),
        ("readback", "status", "blocked"),
        ("receipt", "ok", False),
        ("readback", "mutation_performed", False),
        ("receipt", "saved", False),
        ("readback", "applied", False),
    ],
)
@pytest.mark.parametrize("completion_name", ["_durable_completion", "_evidence_completion"])
def test_completion_truth_rejects_any_contradictory_engine_signal(
    completion_name, section, field, value, tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    digest = "sha256:" + "a" * 64
    payload = {
        "status": "remembered" if completion_name == "_evidence_completion" else "applied",
        "ok": True,
        "receipt": {"confirmed": True, "receipt_id": "r-1", "content_digest": digest},
        "readback": {"status": "verified", "receipt_id": "r-1", "content_digest": digest},
    }
    target = payload if section == "top" else payload[section]
    target[field] = value
    proof = getattr(plugin, completion_name)(payload)
    assert proof["complete"] is False
    assert proof["reason"].startswith("contradictory_")


@pytest.mark.parametrize(
    "nested_failure",
    [
        {"outcome": {"status": "failed"}},
        {"result": {"ok": False}},
        {"transaction": {"state": "cancelled"}},
        {"operations": [{"operation_id": "op-1", "status": "failed"}]},
        {"errors": [{"code": "write_failed"}]},
    ],
)
def test_completion_truth_rejects_nested_failure_signals(nested_failure, tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    digest = "sha256:" + "a" * 64
    payload = {
        "status": "applied",
        "ok": True,
        "receipt": {"confirmed": True, "receipt_id": "r-1", "content_digest": digest},
        "readback": {"status": "verified", "receipt_id": "r-1", "content_digest": digest},
        **nested_failure,
    }
    proof = plugin._durable_completion(payload)
    assert proof["complete"] is False
    assert proof["reason"].startswith("contradictory_")


@pytest.mark.parametrize(
    "nested_failure",
    [
        {"preview": {"isError": True}},
        {"preview": {"status": "failed"}},
        {"publication": {"isError": True}},
        {"publication": {"status": "failed"}},
        {"result": {"isError": True}},
        {"status": "partial"},
    ],
)
def test_completion_truth_scans_preview_publication_result_and_partial(
    nested_failure, tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    proof = plugin._completion_truth(
        {"status": "applied", "ok": True, **nested_failure},
        mutation_required=True,
    )
    assert proof["accepted"] is False
    assert proof["reason"].startswith("contradictory_")


def test_separate_disabled_publication_is_observed_but_not_a_completion_contradiction(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    proof = plugin._completion_truth(
        {
            "status": "applied",
            "ok": True,
            "publication": {"status": "disabled", "ok": False},
            "preview": {"status": "noop", "ok": True},
        },
        mutation_required=True,
    )
    assert proof == {"accepted": True, "reason": "consistent"}


def test_sync_renderer_claims_completion_only_after_engine_readback(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    packet = {
        "status": "completed",
        "terminal_state": "completed",
        "run_id": "kb_sync-1",
        "publication": {
            "status": "not_attempted",
            "separate_confirmation_required": True,
            "sync_publishes": False,
        },
    }
    unverified = plugin._render_sync_packet(packet, readback_verified=False)
    verified = plugin._render_sync_packet(packet, readback_verified=True)
    assert "could not be verified" in unverified["text"]
    assert "Receipt: verified" not in unverified["text"]
    assert "Receipt: verified" in verified["text"]
    assert "saved and verified" in verified["text"]


def test_evidence_completion_requires_digest_bound_readback(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    receipt_id_only = {
        "status": "remembered",
        "ok": True,
        "receipt": {"confirmed": True, "receipt_id": "ev-1"},
        "readback": {"status": "verified", "receipt_id": "ev-1"},
    }
    assert plugin._evidence_completion(receipt_id_only) == {
        "complete": False,
        "reason": "digest_mismatch",
    }


def test_future_evidence_route_requires_confirmed_envelope_schema(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setattr(
        plugin,
        "_DESCRIPTOR_TOOLS",
        {
            "evidence.remember.preview": {"name": "evidence.remember.preview"},
            "evidence.remember.confirmed": {"name": "evidence.remember.confirmed"},
        },
    )
    assert plugin._evidence_contract_ready() is False
    ctx = FakeContext({})
    source = _FakeSource()
    card = plugin._render_capture_command(
        ctx,
        "kb_engine_prod",
        "note",
        event=_FakeEvent(source, text="/kb capture note"),
        source=source,
        session_store=None,
    )
    assert card["status"] == "temporarily_unavailable"
    assert ctx.calls == []


def test_future_evidence_envelope_binds_preview_and_active_target(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setattr(plugin, "_DESCRIPTOR_TOOLS", _future_evidence_descriptors())
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    packet = {"items": [{"external_id": "telegram:1"}]}
    packet_digest = plugin._descriptor_digest(packet)
    preview = {
        "status": "preview_ready",
        "ok": True,
        "target": "kb_engine_prod",
        "preview_digest": "sha256:" + "a" * 64,
        "preview_lease": {"lease_id": "lease-1", "expires_at": "2099-06-27T00:00:00Z"},
        "idempotency_key": "idem-1",
        "evidence_packet_digest": packet_digest,
    }
    binding, reason = plugin._evidence_preview_binding(preview, target="kb_engine_prod", packet=packet)
    assert reason == ""
    state = {"target": "kb_engine_prod", "packet": packet, "preview_binding": binding}
    envelope, reason = plugin._evidence_confirm_envelope(
        state,
        target="kb_engine_prod",
        actor_id="42",
    )
    assert reason == ""
    assert envelope["target"] == "kb_engine_prod"
    assert envelope["preview_digest"] == preview["preview_digest"]
    assert envelope["preview_lease"] == preview["preview_lease"]
    assert envelope["idempotency_key"] == "idem-1"
    assert envelope["evidence_packet_digest"] == packet_digest
    assert envelope["evidence_packet"] == packet
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "other_target")
    assert plugin._evidence_confirm_envelope(state, target="kb_engine_prod", actor_id="42") == (
        None,
        "active_target_mismatch",
    )


def test_future_evidence_confirm_dispatches_only_bound_envelope(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setattr(plugin, "_DESCRIPTOR_TOOLS", _future_evidence_descriptors())
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    source = _FakeSource()
    packet = {"items": [{"external_id": "telegram:1"}]}
    packet_digest = plugin._descriptor_digest(packet)
    preview = {
        "status": "preview_ready",
        "ok": True,
        "target": "kb_engine_prod",
        "preview_digest": "sha256:" + "a" * 64,
        "preview_lease": {"lease_id": "lease-1", "expires_at": "2099-06-27T00:00:00Z"},
        "idempotency_key": "idem-1",
        "evidence_packet_digest": packet_digest,
    }
    binding, _reason = plugin._evidence_preview_binding(preview, target="kb_engine_prod", packet=packet)
    state = {"target": "kb_engine_prod", "packet": packet, "preview_binding": binding}
    monkeypatch.setattr(plugin, "_get_capture_preview_state", lambda *_args: (state, ""))
    cleared: list[str] = []
    monkeypatch.setattr(plugin, "_clear_capture_preview_state", cleared.append)
    result_digest = "sha256:" + "b" * 64
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_evidence_remember_confirmed": [
                {
                    "status": "remembered",
                    "ok": True,
                    "receipt": {"confirmed": True, "receipt_id": "ev-1", "content_digest": result_digest},
                    "readback": {"status": "verified", "receipt_id": "ev-1", "content_digest": result_digest},
                }
            ]
        }
    )
    card = plugin._render_capture_command(
        ctx,
        "kb_engine_prod",
        "confirm",
        event=_FakeEvent(source, text="/kb capture confirm"),
        source=source,
        session_store=None,
    )
    assert "Evidence remembered" in card["text"]
    assert len(ctx.calls) == 1
    tool, args = ctx.calls[0]
    assert tool == "mcp_kb_engine_prod_evidence_remember_confirmed"
    assert set(args) == {"envelope"}
    assert args["envelope"]["preview_digest"] == preview["preview_digest"]
    assert args["envelope"]["preview_lease"] == preview["preview_lease"]
    assert args["envelope"]["idempotency_key"] == "idem-1"
    assert args["envelope"]["target"] == "kb_engine_prod"
    assert cleared


# --- Phase A Task 1: expandable blockquote for long bodies ---

# Verified-live telegram.py _convert_blockquote regex (re.MULTILINE): a SPACE is
# required after the '>'/'**>' prefix; expandable fires when the first matched
# line has a '**>' prefix AND content ending in '||'.
_TELEGRAM_BLOCKQUOTE_RE = re.compile(r'^((?:\*\*)?>{1,3}) (.+)$')


def test_expandable_block_matches_telegram_blockquote_regex(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    body = "line one\nline two\nline three"
    out = plugin._expandable_block(body)
    out_lines = out.splitlines()
    first = _TELEGRAM_BLOCKQUOTE_RE.match(out_lines[0])
    assert first is not None, f"first line does not match blockquote regex: {out_lines[0]!r}"
    assert first.group(1).startswith("**"), "first line must be expandable (**> prefix)"
    assert first.group(2).endswith("||"), "first matched line content must end with || to be expandable"
    # Every interior line must ALSO match the regex (space after '>') so it renders
    # as a quote, not literal text.
    for ln in out_lines:
        assert _TELEGRAM_BLOCKQUOTE_RE.match(ln) is not None, f"line does not match: {ln!r}"
    assert "line one" in out and "line three" in out


def test_expandable_block_passthrough_for_short_body(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    assert plugin._expandable_block("ok") == "ok"
    assert plugin._expandable_block("one\ntwo") == "one\ntwo"  # 2 lines < min


# --- Phase A Task 2: inline MarkdownV2 emphasis (bold headlines) ---

def test_emphasis_headline_bolds_and_preserves_text(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    assert plugin._emphasis_headline("KB Dashboard") == "*KB Dashboard*"  # MarkdownV2 bold


def test_emphasis_headline_does_not_escape(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    assert plugin._emphasis_headline("A_B") == "*A_B*"  # only adds *, no escapes


def test_render_error_headline_is_bold(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    card = plugin._render_error("KB Status", "kb_engine_prod", ["boom"])
    assert card["text"].startswith("*KB Status*")  # bold headline
    assert "Knowledge service unavailable." in card["text"]
    assert "kb_engine_prod" not in card["text"]


def test_render_dashboard_headline_is_bold(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    card = plugin._render_dashboard(
        {"summary": {"readiness_status": "ready", "publication_status": "clean"}},
        ctx=FakeContext({}),
        target="kb_engine_prod",
    )
    assert card["text"].startswith("*Knowledge*")  # bold headline
    assert "Status: ready · publication clean" in card["text"]
    assert len(card["text"].splitlines()) <= 8


# --- Phase B Task 5: enriched _render_status cockpit pilot ---

def _status_proof_packet():
    # Shape verified against _render_status -> _render_status_proof dispatch:
    # kind triggers the proof renderer; these fields populate the long status body.
    return {
        "kind": "kb_status_proof_packet",
        "status": "ready",
        "active_target": {"target": "kb_engine_prod"},
        "runtime": {"version": "v0.36.1"},
        "transport": {"status": "open"},
        "publication": {"status": "clean"},
        "review": {"pending_count": 3},
        "sync": {"status": "idle"},
        "next_action": {"command": "/kb sync"},
    }


def test_render_status_enriched_card_composition(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    card = plugin._render_status(_status_proof_packet(), "kb_engine_prod")
    text = card["text"]
    assert text.startswith("*")                       # bold headline (Task 2)
    assert "Status: ready" in text
    assert "Publication: clean" in text
    assert "Needs attention: 3" in text
    assert "Last sync: idle" in text
    assert "kb_engine_prod" not in text
    assert "v0.36.1" not in text
    assert len(text.splitlines()) <= 7


def test_render_status_simple_card_headline_is_bold(tmp_path, monkeypatch):
    # Non-proof status packet still gets the bold headline; short body stays inline.
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    card = plugin._render_status({"readiness": "ready"}, "kb_engine_prod")
    assert card["text"].startswith("*Knowledge status*")


# ---------------------------------------------------------------------------
# Upstream-environment simulation: fork-only modules absent
# ---------------------------------------------------------------------------

def _load_plugin_module_upstream(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Load the plugin with fork-only modules blocked in sys.modules.

    Setting sys.modules[name] = None makes Python raise ImportError for that
    module, simulating plain upstream hermes-agent where those packages do not
    exist.  monkeypatch restores sys.modules on teardown.
    """
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))

    # Block the two fork-only modules.
    monkeypatch.setitem(sys.modules, "tools.kb_callback_registry", None)  # type: ignore[arg-type]
    monkeypatch.setitem(sys.modules, "gateway.platforms.base", None)  # type: ignore[arg-type]
    # Also block the parent 'tools' and 'gateway.platforms' packages so that
    # a from-package import cannot succeed via the parent path.
    for parent in ("tools", "gateway", "gateway.platforms"):
        if parent not in sys.modules:
            monkeypatch.setitem(sys.modules, parent, None)  # type: ignore[arg-type]

    # Use a distinct module name so exec_module runs the file afresh.
    spec = importlib.util.spec_from_file_location("kb_journeys_upstream_under_test", ROOT / "__init__.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    assert spec and spec.loader
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


class _FakeSource:
    def __init__(self):
        self.chat_id = "12345678"
        self.platform = "telegram"
        self.user_id = "42"
        self.user_name = "Anthony"
        self.thread_id = None


class _FakeEvent:
    def __init__(self, source, *, message_id="100", reply_to_message_id=None, reply_to_text=None, text=""):
        self.source = source
        self.message_id = message_id
        self.reply_to_message_id = reply_to_message_id
        self.reply_to_text = reply_to_text
        self.raw_message = None
        self.text = text


def test_upstream_env_module_loads_cleanly(tmp_path, monkeypatch):
    """The plugin must import without raising when fork modules are absent."""
    plugin = _load_plugin_module_upstream(monkeypatch, tmp_path)
    # _KB_ACTION_AVAILABLE must be False — the stub is in effect.
    assert plugin._KB_ACTION_AVAILABLE is False
    # KbAction is a stub class, not the real one.
    instance = plugin.KbAction(label="x", action_id="x", handler=None, metadata={})
    assert instance.label == "x"


def test_upstream_env_status_renders_plain_text(tmp_path, monkeypatch):
    """_render_status must return a non-empty plain text card and no inline keyboard."""
    plugin = _load_plugin_module_upstream(monkeypatch, tmp_path)
    card = plugin._render_status({"readiness": "ready"}, "kb_engine_prod")
    assert isinstance(card, dict)
    assert card.get("text"), "text field must be non-empty"
    assert "Knowledge status" in card["text"]
    # Stub KbAction instances may appear in actions, but no real callback buttons.
    for action in card.get("actions", []):
        assert not hasattr(action, "callback_data"), "stub actions must not carry callback_data"


def test_upstream_env_today_renders_plain_text(tmp_path, monkeypatch):
    """_render_today must return a non-empty plain text card."""
    plugin = _load_plugin_module_upstream(monkeypatch, tmp_path)
    card = plugin._render_today({
        "readiness": "ready",
        "publication_status": "clean",
        "proposals": {"total": 2},
    })
    assert isinstance(card, dict)
    assert card.get("text"), "text field must be non-empty"
    assert "KB Today" in card["text"]
    for action in card.get("actions", []):
        assert not hasattr(action, "callback_data")


def test_upstream_env_write_fails_closed_without_evidence_contract(tmp_path, monkeypatch):
    """The text-only path must not revive a removed evidence compatibility route."""
    plugin = _load_plugin_module_upstream(monkeypatch, tmp_path)
    ctx = FakeContext({})
    source = _FakeSource()
    ev = _FakeEvent(source, message_id="200", text="/kb write a note")
    card = plugin._render_write_command(
        ctx, "kb_engine_prod", "a note", event=ev, source=source, session_store=None
    )
    assert card["status"] == "temporarily_unavailable"
    assert card["actions"] == []
    assert ctx.calls == []


def test_upstream_env_readiness_reports_text_only_degraded(tmp_path, monkeypatch):
    plugin = _load_plugin_module_upstream(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    readiness = plugin._plugin_readiness()
    assert readiness["status"] == "text_only_degraded"
    assert readiness["buttons"] == "unavailable"


def test_upstream_env_no_inline_keyboard_in_write_cards(tmp_path, monkeypatch):
    """/kb write cards must carry no inline_keyboard structure when stub is active."""
    plugin = _load_plugin_module_upstream(monkeypatch, tmp_path)
    ctx = FakeContext({})
    source = _FakeSource()
    ev = _FakeEvent(source, message_id="200", text="/kb write a note")
    card = plugin._render_write_command(
        ctx, "kb_engine_prod", "a note", event=ev, source=source, session_store=None
    )
    # No real inline keyboard in any field.
    card_json = json.dumps(card)
    assert "inline_keyboard" not in card_json
    assert "callback_data" not in card_json


def test_upstream_env_text_delivery_drops_unavailable_buttons(tmp_path, monkeypatch):
    plugin = _load_plugin_module_upstream(monkeypatch, tmp_path)

    class Adapter:
        def __init__(self):
            self.sent = []

        def send(self, chat_id, text, **kwargs):
            self.sent.append((chat_id, text, kwargs))
            return type("Result", (), {"success": True})()

        def send_kb_actions(self, *_args, **_kwargs):
            raise AssertionError("button transport must not be used")

    adapter = Adapter()
    source = _FakeSource()
    event = _FakeEvent(source, text="/kb review")
    action = plugin.KbAction(label="Review", action_id="review", handler=None, metadata={})
    asyncio.run(
        plugin._send_card(
            adapter,
            event,
            {"title": "KB Review", "text": "Review remains usable as text.", "actions": [action]},
        )
    )
    assert adapter.sent[0][1] == "Review remains usable as text."


def test_generated_descriptor_bundle_is_strict_and_legacy_free(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    source = json.loads((ROOT / "generated" / "kb-engine-descriptors.json").read_text(encoding="utf-8"))
    assert source["schema_version"] == 1
    assert source["profile"] == "journey_first_strict"
    assert source["selection"] == "primary_chat"
    assert source["engine_version"] == "0.45.23"
    assert source["engine_source_revision"] == "1b8032a4db5bde33090a7c363e5c6e0d079acc8c"
    assert source["digest"].startswith("sha256:")
    assert source["engine_version"]
    assert len(source["tools"]) == 10
    serialized = json.dumps(source, sort_keys=True)
    assert "kb_sync.preview" not in serialized
    assert "kb_sync.confirmed" not in serialized
    assert "update_kb" not in serialized
    assert {"kb.sync.prepare", "kb.sync.status", "kb.sync.resume"} <= {
        tool["name"] for tool in source["tools"]
    }
    assert next(
        row for row in source["journeys"] if row["journey_id"] == "kb_sync"
    )["confirmation_required"] is False
    assert plugin._DESCRIPTOR_BUNDLE == source
    assert plugin._DESCRIPTOR_ERROR == ""
    assert len(plugin._descriptor_allowlist()) == 10


def test_descriptor_validation_rejects_arbitrary_untyped_leaf(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    packet = _conforming_descriptor_packet(plugin)
    schema = {
        "type": "object",
        "properties": {"value": {"description": "Unbounded caller payload."}},
        "required": ["value"],
        "additionalProperties": False,
    }
    packet["tools"][0]["output_schema"] = schema
    packet["tools"][0]["output_schema_digest"] = plugin._descriptor_digest(schema)
    body = dict(packet)
    body.pop("digest")
    packet["digest"] = plugin._descriptor_digest(body)
    with pytest.raises(ValueError, match="invalid output schema"):
        plugin._validate_descriptor_bundle(packet)


def test_required_only_anyof_branches_remain_enforced(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    schema = {
        "type": "object",
        "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
        "anyOf": [{"required": ["a"]}, {"required": ["b"]}],
        "additionalProperties": False,
    }
    plugin._validate_schema(schema)
    assert plugin._runtime_schema_error({}, schema) is not None
    assert plugin._runtime_schema_error({"a": "ready"}, schema) is None
    assert plugin._runtime_schema_error({"b": "ready"}, schema) is None


def test_conforming_concrete_output_fixture_loads(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    bundle = _install_conforming_descriptor_fixture(plugin, monkeypatch)
    assert bundle["digest"].startswith("sha256:")
    assert plugin._plugin_readiness()["descriptors"] == "ready"


def test_descriptor_validation_recomputes_schema_digests(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    packet = _conforming_descriptor_packet(plugin)
    packet["tools"][0]["output_schema_digest"] = "sha256:" + "0" * 64
    body = dict(packet)
    body.pop("digest")
    packet["digest"] = plugin._descriptor_digest(body)
    with pytest.raises(ValueError, match="output schema digest does not match"):
        plugin._validate_descriptor_bundle(packet)


def test_descriptor_validation_rejects_empty_composition(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    packet = _conforming_descriptor_packet(plugin)
    empty_schema = {"anyOf": []}
    packet["tools"][0]["output_schema"] = empty_schema
    packet["tools"][0]["output_schema_digest"] = plugin._descriptor_digest(empty_schema)
    body = dict(packet)
    body.pop("digest")
    packet["digest"] = plugin._descriptor_digest(body)
    with pytest.raises(ValueError, match="invalid output schema"):
        plugin._validate_descriptor_bundle(packet)


@pytest.mark.parametrize(
    "schema",
    [
        {"anyOf": [{"type": "object", "additionalProperties": True}, {"type": "string"}]},
        {"oneOf": [{"type": "string"}, {"type": "object", "additionalProperties": True}]},
        {"anyOf": [{"type": "string"}, {"$ref": "#/$defs/unproven"}]},
        {"allOf": [{"type": "string"}, {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]}]},
        {"allOf": [{"type": "string"}, {"not": {"type": "string"}}]},
        {"type": "string", "not": {}},
        {"type": "string", "not": {"type": "string"}},
        {
            "type": "object",
            "properties": {"x": {"type": "string"}},
            "required": ["x"],
            "not": {"required": ["x"]},
        },
        {"type": "string", "enum": [1]},
        {"type": "string", "const": 1},
        {"allOf": [{"type": "string"}, {"enum": [1]}]},
        {"allOf": [{"type": "string"}, {"const": 1}]},
        {"oneOf": [{"type": "string"}, {"type": "string"}]},
        {"allOf": [{"enum": ["a"]}, {"enum": ["b"]}]},
        {"type": "string", "not": {"anyOf": [{"type": "integer"}, {"type": "string"}]}},
        {"type": "string", "minLength": 5, "maxLength": 4},
        {"type": "array", "items": {"type": "string"}, "minItems": 2, "maxItems": 1},
        {"type": "number", "minimum": 10, "maximum": 9},
        {"type": "number", "minimum": 10, "exclusiveMaximum": 10},
        {"allOf": [{"type": "string", "minLength": 5}, {"maxLength": 4}]},
        {
            "allOf": [
                {"type": "array", "items": {"type": "string"}, "minItems": 2},
                {"maxItems": 1},
            ]
        },
        {"allOf": [{"type": "number", "minimum": 10}, {"exclusiveMaximum": 10}]},
    ],
)
def test_descriptor_validation_rejects_smuggled_or_impossible_schema(schema, tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    packet = _conforming_descriptor_packet(plugin)
    packet["tools"][0]["output_schema"] = schema
    packet["tools"][0]["output_schema_digest"] = plugin._descriptor_digest(schema)
    body = dict(packet)
    body.pop("digest")
    packet["digest"] = plugin._descriptor_digest(body)
    with pytest.raises(ValueError, match="invalid output schema|unconstrained output schema"):
        plugin._validate_descriptor_bundle(packet)


def test_descriptor_validation_rejects_unconstrained_executable_envelope(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    packet = _conforming_descriptor_packet(plugin)
    workflow = next(tool for tool in packet["tools"] if tool["name"] == "change.apply")
    workflow["input_schema"]["properties"]["preview"] = {
        "type": "object",
        "additionalProperties": True,
    }
    workflow["input_schema_digest"] = plugin._descriptor_digest(workflow["input_schema"])
    for action in packet["actions"]:
        if action["name"] == workflow["name"]:
            action["input_schema_digest"] = workflow["input_schema_digest"]
    body = dict(packet)
    body.pop("digest")
    packet["digest"] = plugin._descriptor_digest(body)
    with pytest.raises(ValueError, match="executable envelope"):
        plugin._validate_descriptor_bundle(packet)


def test_unconstrained_export_blocks_descriptor_dispatch(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    packet = _conforming_descriptor_packet(plugin)
    generic = {"type": "object", "additionalProperties": True}
    packet["tools"][0]["output_schema"] = generic
    packet["tools"][0]["output_schema_digest"] = plugin._descriptor_digest(generic)
    body = dict(packet)
    body.pop("digest")
    packet["digest"] = plugin._descriptor_digest(body)
    with pytest.raises(ValueError, match="unconstrained output schema"):
        plugin._validate_descriptor_bundle(packet)
    monkeypatch.setattr(plugin, "_DESCRIPTOR_BUNDLE", {})
    monkeypatch.setattr(plugin, "_DESCRIPTOR_TOOLS", {})
    ctx = FakeContext({})
    card = plugin._card_for_command(ctx, "kb", args="review")
    assert card["status"] == "temporarily_unavailable"
    assert card["actions"] == []
    assert ctx.calls == []


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("kb", ""),
        ("kbworkbench", ""),
        ("kbtoday", ""),
        ("kbstatus", ""),
        ("kbruns", ""),
        ("kbreview", ""),
        ("kbpublish", ""),
        ("kbmeeting", ""),
    ],
)
def test_invalid_descriptor_bundle_blocks_every_root_dispatch(command, args, tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setattr(plugin, "_DESCRIPTOR_BUNDLE", {})
    monkeypatch.setattr(plugin, "_DESCRIPTOR_TOOLS", {})
    ctx = FakeContext({})
    plugin._card_for_command(ctx, command, args=args)
    assert ctx.calls == []


def test_dispatch_first_skips_every_non_allowlisted_tool(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_attention_cockpit": [{"status": "ready"}],
            "mcp_kb_engine_prod_dashboard_live": [{"status": "should-not-run"}],
        }
    )
    selected, payload, errors = plugin._dispatch_first(
        ctx,
        "kb_engine_prod",
        [("dashboard.live", {}), ("attention.cockpit", {})],
    )
    assert selected == "mcp_kb_engine_prod_attention_cockpit"
    assert payload == {"status": "ready"}
    assert ctx.calls == [("mcp_kb_engine_prod_attention_cockpit", {})]
    assert errors == ["dashboard.live: not present in generated descriptor allowlist"]


def test_unwrap_rejects_top_level_iserror_even_with_structured_content(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    payload, error = plugin._unwrap_tool_result(
        {
            "isError": True,
            "structuredContent": {"status": "ready"},
            "content": [{"type": "text", "text": "backend failed"}],
        }
    )
    assert payload is None
    assert "isError" in error


@pytest.mark.parametrize(
    "nested",
    [
        {"isError": True, "status": "ready"},
        {"status": "failed", "schema_version": 1},
        {"result": {"isError": True}},
        {"result": {"status": "failed"}},
    ],
)
def test_unwrap_preserves_nested_upstream_failure_envelopes(nested, tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    payload, error = plugin._unwrap_tool_result({"result": nested})
    assert payload is None
    assert error


def test_read_dispatcher_rejects_nested_failed_result_before_rendering(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_attention_cockpit": [
                {"result": {"status": "failed", "schema_version": 1}}
            ]
        }
    )
    selected, payload, errors = plugin._dispatch_first(
        ctx,
        "kb_engine_prod",
        [("attention.cockpit", {})],
    )
    assert selected is None
    assert payload is None
    assert any("upstream tool failure" in error for error in errors)


def test_dispatch_rejects_runtime_output_that_violates_generated_schema(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    ctx = FakeContext({"mcp_kb_engine_prod_attention_cockpit": [{"ok": True}]})
    selected, payload, errors = plugin._dispatch_first(
        ctx,
        "kb_engine_prod",
        [("attention.cockpit", {})],
    )
    assert selected is None
    assert payload is None
    assert any("runtime output violates generated schema" in error for error in errors)


def test_empty_preview_never_enables_confirmation(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    assert plugin._preview_allows_confirmation({}) is False
    assert plugin._preview_allows_confirmation(
        {"status": "preview", "ok": True},
        capability="review.decision_preview",
    ) is False
    assert plugin._preview_allows_confirmation(
        {"status": "noop", "ok": True},
        capability="review.decision_preview",
    ) is False
    assert plugin._preview_allows_confirmation(
        {
            "status": "noop",
            "ok": True,
            "decision": "approve",
            "proposal_ids": ["p1"],
            "preview_hash": "a" * 64,
            "preview_lease": {
                "preview_lease_id": "lease-1",
                "preview_hash": "a" * 64,
                "confirm_tool": "review.batch_decide_confirmed",
                "proposal_ids": ["p1"],
                "decision": "approve",
            },
            "plan": {"operations": [{"operation_id": "proposal.approve"}]},
        },
        capability="review.decision_preview",
    ) is False


def test_generated_primary_action_contracts_are_concrete(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    for capability in (
        "change.preview",
        "change.apply",
        "kb.sync.prepare",
        "kb.sync.status",
        "kb.sync.resume",
    ):
        descriptor = plugin._descriptor(capability)
        assert descriptor is not None
        assert plugin._schema_is_concrete(descriptor["input_schema"])
        assert plugin._schema_is_concrete(
            descriptor["output_schema"], require_required=True
        )


def test_generic_concrete_generated_preview_contract_can_enable_confirmation(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    preview_name = "example.preview"
    confirm_name = "example.confirmed"
    lease_schema = {
        "type": "object",
        "properties": {
            "preview_lease_id": {"type": "string"},
            "preview_hash": {"type": "string"},
            "confirm_tool": {"type": "string", "const": confirm_name},
            "affected_ids": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
            },
        },
        "required": ["preview_lease_id", "preview_hash", "confirm_tool", "affected_ids"],
        "additionalProperties": False,
    }
    plan_schema = {
        "type": "object",
        "properties": {
            "operations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"operation_id": {"type": "string"}},
                    "required": ["operation_id"],
                    "additionalProperties": True,
                },
                "minItems": 1,
            }
        },
        "required": ["operations"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {
            "status": {"type": "string"},
            "ok": {"type": "boolean"},
            "preview_hash": {"type": "string"},
            "preview_lease": lease_schema,
            "plan": plan_schema,
        },
        "required": ["status", "ok", "preview_hash", "preview_lease", "plan"],
        "additionalProperties": False,
    }
    monkeypatch.setattr(
        plugin,
        "_DESCRIPTOR_TOOLS",
        {
            preview_name: {"name": preview_name, "output_schema": output_schema},
            confirm_name: {
                "name": confirm_name,
                "annotations": {"readOnlyHint": False},
            },
        },
    )
    payload = {
        "status": "preview_ready",
        "ok": True,
        "preview_hash": "a" * 64,
        "preview_lease": {
            "preview_lease_id": "lease-1",
            "preview_hash": "a" * 64,
            "confirm_tool": confirm_name,
            "affected_ids": ["object-1"],
        },
        "plan": {"operations": [{"operation_id": "object.update"}]},
    }
    assert plugin._generated_preview_contract_ready(preview_name) is True
    assert plugin._preview_allows_confirmation(payload, capability=preview_name) is True
    payload["status"] = "ready_to_confirm"
    assert plugin._preview_allows_confirmation(payload, capability=preview_name) is True
    for unsafe_status in ("noop", "preview_failed", "not_previewable"):
        payload["status"] = unsafe_status
        assert plugin._preview_allows_confirmation(payload, capability=preview_name) is False


def test_restore_preview_requires_route_bound_lease_ids_and_actionable_plan(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    bare = {"schema_version": 1, "status": "noop", "ok": True}
    assert plugin._preview_allows_confirmation(
        bare,
        capability="review.restore_preview",
    ) is False
    empty_plan = {
        **bare,
        "restorable_ids": ["p1"],
        "preview_hash": "a" * 64,
        "preview_lease": {
            "preview_lease_id": "lease-1",
            "preview_hash": "a" * 64,
            "confirm_tool": "review.restore_confirmed",
            "proposal_ids": ["p1"],
            "decision": "restore",
        },
        "plan": {},
    }
    assert plugin._preview_allows_confirmation(
        empty_plan,
        capability="review.restore_preview",
    ) is False
    actionable = deepcopy(empty_plan)
    actionable["plan"] = {"operations": [{"operation_id": "proposal.restore"}]}
    assert plugin._preview_allows_confirmation(
        actionable,
        capability="review.restore_preview",
    ) is False


def test_bare_successful_restore_preview_never_renders_confirm_action(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_review_restore_preview": [
                {"result": {"schema_version": 1, "status": "noop", "ok": True}}
            ]
        }
    )
    card = plugin._render_restore_preview(
        ctx,
        "kb_engine_prod",
        receipt={
            "restore_hint": {
                "preview_tool": "review.restore_preview",
                "confirm_tool": "review.restore_confirmed",
                "transaction_id": "tx-1",
                "proposal_ids": ["p1"],
            }
        },
        callback_ctx=object(),
    )
    assert card["actions"] == []
    assert "Confirm restore" not in card["text"]


def test_runtime_rejects_more_than_twelve_effective_tools(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setattr(
        plugin,
        "_DESCRIPTOR_TOOLS",
        {f"tool.{index}": {"name": f"tool.{index}"} for index in range(13)},
    )
    ctx = FakeContext({"mcp_kb_engine_prod_tool_0": [{"status": "must-not-run"}]})
    assert plugin._descriptor_allowlist() == frozenset()
    assert plugin._dispatch_first(ctx, "kb_engine_prod", [("tool.0", {})])[1] is None
    assert ctx.calls == []


def test_missing_generated_descriptor_fails_closed(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setattr(plugin, "_DESCRIPTOR_TOOLS", {})
    ctx = FakeContext({})
    receipt = {
        "restore_available": True,
        "receipt_id": "r1",
        "restore_hint": {"transaction_id": "tx1"},
    }
    assert plugin._restore_action_from_receipt(ctx, "kb_engine_prod", receipt) is None
    assert ctx.calls == []


def test_install_receipt_reports_previous_ref_and_rollback_command(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    descriptor_packet = json.loads((ROOT / "generated" / "kb-engine-descriptors.json").read_text(encoding="utf-8"))
    receipt = plugin._parse_install_receipt(
        {
            "current_ref": "v0.5.0",
            "previous_ref": "v0.4.0",
            "installed_digest": "sha256:" + "a" * 64,
            "descriptor_digest": descriptor_packet["digest"],
            "installed_at": "2026-06-27T00:00:00Z",
            "noc_plan_digest": "sha256:" + "b" * 64,
        }
    )
    assert receipt["previous_ref"] == "v0.4.0"
    assert plugin._rollback_ref(receipt) == "v0.4.0"
    rendered = plugin._render_install_receipt(receipt)
    assert rendered["status"] == "not_observed"
    assert "not live verification" in rendered["text"]
    assert "Previous ref: v0.4.0" in rendered["text"]


def test_install_receipt_requires_valid_timezone_timestamp(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="installed_at"):
        plugin._parse_install_receipt(
            {
                "current_ref": "v0.5.0",
                "previous_ref": "v0.4.0",
                "installed_digest": "sha256:" + "a" * 64,
                "descriptor_digest": "sha256:" + "b" * 64,
                "installed_at": "2026-06-27T00:00:00",
                "noc_plan_digest": "sha256:" + "c" * 64,
            }
        )


def test_caller_supplied_install_evidence_can_never_self_attest_as_verified(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    bundle = _install_conforming_descriptor_fixture(plugin, monkeypatch)
    receipt = {
        "current_ref": "v0.5.0",
        "previous_ref": "v0.4.0",
        "installed_digest": "sha256:" + "a" * 64,
        "descriptor_digest": bundle["digest"],
        "installed_at": "2026-06-27T00:00:00Z",
        "noc_plan_digest": "sha256:" + "b" * 64,
    }
    evidence = {
        "owner": "noc",
        "source": "noc.hermes-plugin-install-observation",
        "observed_at": plugin._capture_now(),
        "ttl_seconds": 3600,
        "ref_verified": True,
        "artifact_verified": True,
        "current_ref": "v0.5.0",
        "installed_digest": "sha256:" + "a" * 64,
        "descriptor_digest": bundle["digest"],
    }
    evidence["binding_digest"] = plugin._descriptor_digest(evidence)
    unverified = plugin._render_install_receipt(receipt, installed_evidence=evidence)
    assert unverified["status"] == "unverified"
    assert "authenticated NOC observation channel" in unverified["text"]
    mismatch_evidence = dict(evidence)
    mismatch_evidence["current_ref"] = "different-ref"
    mismatch_evidence["binding_digest"] = plugin._descriptor_digest(mismatch_evidence)
    mismatch = plugin._render_install_receipt(
        receipt,
        installed_evidence=mismatch_evidence,
    )
    assert mismatch["status"] == "unverified"


@pytest.mark.parametrize(
    ("observed_at", "ttl_seconds"),
    [
        ("2099-01-01T00:00:00Z", 3600),
        ("2020-01-01T00:00:00Z", 60),
    ],
)
def test_install_evidence_rejects_future_or_expired_observation(
    observed_at, ttl_seconds, tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    bundle = _install_conforming_descriptor_fixture(plugin, monkeypatch)
    receipt = {
        "current_ref": "v0.5.0",
        "previous_ref": "v0.4.0",
        "installed_digest": "sha256:" + "a" * 64,
        "descriptor_digest": bundle["digest"],
        "installed_at": "2026-06-27T00:00:00Z",
        "noc_plan_digest": "sha256:" + "b" * 64,
    }
    evidence = {
        "owner": "noc",
        "source": "noc.hermes-plugin-install-observation",
        "observed_at": observed_at,
        "ttl_seconds": ttl_seconds,
        "ref_verified": True,
        "artifact_verified": True,
        "current_ref": receipt["current_ref"],
        "installed_digest": receipt["installed_digest"],
        "descriptor_digest": receipt["descriptor_digest"],
    }
    evidence["binding_digest"] = plugin._descriptor_digest(evidence)
    assert plugin._render_install_receipt(receipt, installed_evidence=evidence)["status"] == "unverified"


def test_install_evidence_rejects_unowned_caller_shape(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    bundle = _install_conforming_descriptor_fixture(plugin, monkeypatch)
    receipt = {
        "current_ref": "v0.5.0",
        "previous_ref": "v0.4.0",
        "installed_digest": "sha256:" + "a" * 64,
        "descriptor_digest": bundle["digest"],
        "installed_at": "2026-06-27T00:00:00Z",
        "noc_plan_digest": "sha256:" + "b" * 64,
    }
    caller_shape = {
        "ref_verified": True,
        "artifact_verified": True,
        "current_ref": receipt["current_ref"],
        "installed_digest": receipt["installed_digest"],
        "descriptor_digest": receipt["descriptor_digest"],
    }
    assert plugin._render_install_receipt(receipt, installed_evidence=caller_shape)["status"] == "unverified"


def test_readme_and_manifest_define_real_rollback_contract():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text(encoding="utf-8"))
    assert "reinstalling that `previous_ref`" in readme
    assert "Removing or renaming" in readme
    assert "bundled fallback" not in readme.lower()
    assert manifest["version"] == "0.8.1"
    assert manifest["install_receipt"]["owner"] == "noc"
    assert manifest["install_receipt"]["rollback_ref_field"] == "previous_ref"


def test_legacy_run_sync_entrypoint_returns_migration_guidance(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakeContext({})
    card = plugin._card_for_command(ctx, "kb", args="run sync")
    assert card["status"] == "migration_required"
    assert card["actions"] == []
    assert ctx.calls == []


@pytest.mark.parametrize("text", ["/kbsync", "/update_kb"])
def test_removed_legacy_sync_commands_only_return_migration_guidance(text, tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    assert plugin._command_from_text(text) == "kbmigration"
    ctx = FakeContext({})
    card = plugin._card_for_command(ctx, "kbmigration", args=text)
    assert card["status"] == "migration_required"
    assert "/kb sync" in card["text"]
    assert ctx.calls == []


@pytest.mark.parametrize(
    "args",
    ["run update_kb", "run update_kb anything", "run update kb", "run update kb confirm"],
)
def test_update_kb_workflow_name_is_never_executable(args, tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakeContext({})
    card = plugin._card_for_command(ctx, "kb", args=args)
    assert card["status"] == "migration_required"
    assert ctx.calls == []


def test_transport_error_keeps_evidence_preview_resumable(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setattr(plugin, "_DESCRIPTOR_TOOLS", _future_evidence_descriptors())
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    packet = {"items": [{"external_id": "1"}]}
    preview = {
        "status": "preview_ready",
        "ok": True,
        "target": "kb_engine_prod",
        "preview_digest": "sha256:" + "a" * 64,
        "preview_lease": {"lease_id": "lease-1", "expires_at": "2099-06-27T00:00:00Z"},
        "idempotency_key": "idem-1",
        "evidence_packet_digest": plugin._descriptor_digest(packet),
    }
    binding, _reason = plugin._evidence_preview_binding(preview, target="kb_engine_prod", packet=packet)
    monkeypatch.setattr(
        plugin,
        "_get_capture_preview_state",
        lambda *_args, **_kwargs: (
            {"target": "kb_engine_prod", "packet": packet, "preview_binding": binding},
            "",
        ),
    )
    cleared: list[str] = []
    monkeypatch.setattr(plugin, "_clear_capture_preview_state", cleared.append)
    source = _FakeSource()
    ctx = FakeContext({})
    card = plugin._render_capture_command(
        ctx,
        "kb_engine_prod",
        "confirm",
        event=_FakeEvent(source, text="/kb capture confirm"),
        source=source,
        session_store=None,
    )
    assert "unavailable" in card["text"]
    assert cleared == []


def test_unauthorized_sender_dispatches_no_tool(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakeContext({})
    hook = plugin.build_pre_gateway_dispatch_hook(ctx)
    source = _FakeSource()
    event = _FakeEvent(source, text="/kb sync")
    gateway = type(
        "Gateway",
        (),
        {
            "_is_user_authorized": staticmethod(lambda _source: False),
            "adapters": {"telegram": object()},
        },
    )()
    assert hook(event=event, gateway=gateway, session_store=None) is None
    assert ctx.calls == []


def test_ci_checks_out_exact_private_engine_ref_with_read_only_deploy_key():
    workflow_path = ROOT / ".github" / "workflows" / "test.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)
    assert (
        workflow["jobs"]["contract"]["env"]["KB_ENGINE_DESCRIPTOR_REF"]
        == "1b8032a4db5bde33090a7c363e5c6e0d079acc8c"
    )
    steps = workflow["jobs"]["contract"]["steps"]
    engine_checkouts = [
        step
        for step in steps
        if step.get("uses") == "actions/checkout@v4"
        and step.get("with", {}).get("repository") == "acoastalfog/kb-engine"
    ]

    assert len(engine_checkouts) == 1
    checkout = engine_checkouts[0]["with"]
    assert checkout["ref"] == "${{ env.KB_ENGINE_DESCRIPTOR_REF }}"
    assert checkout["path"] == "kb-engine"
    assert checkout["ssh-key"] == "${{ secrets.KB_ENGINE_DEPLOY_KEY }}"
    assert checkout["persist-credentials"] is False
    assert "https://github.com/acoastalfog/kb-engine.git" not in workflow_text
    assert "git -C kb-engine fetch" not in workflow_text


# --- Milestone 3: Hermes-first free-text user contract ---

_BANNED_USER_MACHINERY = (
    "/home/",
    "/Users/",
    "sha256:",
    "kb_engine_prod",
    "attention.cockpit",
    "kb.sync.",
    "publication.status",
    "MCP",
    "PRIVATE SOURCE BODY",
)


def _assert_compact_user_card(card, *, max_lines=8):
    text = card["text"]
    assert len(text.splitlines()) <= max_lines
    assert len([line for line in text.splitlines() if line.startswith("- ")]) <= 5
    assert re.search(r"\b[0-9a-f]{64}\b", text, re.IGNORECASE) is None
    for forbidden in _BANNED_USER_MACHINERY:
        assert forbidden not in text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Ordinary language stays with Hermes, which can combine KB and live
        # context instead of being reduced to a plugin-only read.
        ("What needs my attention?", None),
        ("What needs my attention today?", None),
        ("kb sync", ("kbsync_run", "")),
        # Natural sync language reaches Hermes so the harness can gather and
        # judge; the deterministic shortcut only prepares/renders a run.
        ("Sync everything.", None),
        ("kb publish", ("kbpublish", "")),
        ("Publish the reviewed changes.", None),
        # Nuanced semantic updates and ambiguous references belong to the LLM
        # harness, not a second regex intent engine in this plugin.
        ("Lilly is waiting on legal until Friday.", None),
        ("This is done; archive it.", None),
    ],
)
def test_m3_free_text_front_doors_preserve_harness_owned_judgment(
    text, expected, tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    assert plugin._prose_kb_command_from_text(text) == expected


def test_m3_attention_mapping_renders_five_compact_user_items(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    packet = {
            "schema_version": 1,
            "front_door": "attention_cockpit",
            "status": "ready",
            "mode": "compact",
            "summary": {
                "active_todo_count": 1,
                "readiness_status": "ready",
                "publication_status": "clean",
            },
            "sections": {
                "situations": {
                    "surface": "attention.cockpit",
                    "items": [
                        {
                            "item_id": "situation-1",
                            "title": "Lilly AI Lab next steps",
                            "detail": "Legal review is due Friday.",
                            "entity_path": "/home/abcosta/Knowledge/kb-anthony/private.md",
                            "target": "situations/lilly-ai-lab",
                            "source_body": "PRIVATE SOURCE BODY",
                        }
                    ],
                },
                "queue": {
                    "surface": "review.inbox",
                    "items": [
                        {
                            "item_id": "todo-1",
                            "title": "Confirm the legal owner",
                            "priority": "P1",
                        }
                    ],
                },
            },
            "next_actions": ["Open Lilly AI Lab"],
            "digest": "sha256:" + "a" * 64,
        }
    ctx = FakeContext(
        {"mcp_kb_engine_prod_attention_cockpit": [{"result": packet}]}
    )
    card = plugin._card_for_command(ctx, "kblifecycle")
    assert "Lilly AI Lab next steps" in card["text"]
    assert "Legal review is due Friday." in card["text"]
    assert "Confirm the legal owner" in card["text"]
    _assert_compact_user_card(card)


def test_m3_publish_is_a_read_only_trusted_operator_handoff(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_publication_status": [
                {
                    "result": {
                        "schema_version": 1,
                        "status": "ready",
                        "ok": True,
                        "git": {"status": "dirty", "clean": False},
                        "scope": {
                            "publication_state": "pending_reviewed_changes",
                            "unrelated_workspace_dirty": False,
                        },
                    }
                }
            ]
        }
    )
    card = plugin._card_for_command(ctx, "kbpublish")
    assert "trusted operator" in card["text"].lower()
    assert "No publication was attempted." in card["text"]
    assert [name for name, _args in ctx.calls] == ["mcp_kb_engine_prod_publication_status"]
    _assert_compact_user_card(card)


def test_m3_degraded_sync_is_success_only_with_terminal_readback(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    packet = {
        "status": "completed_with_degradation",
        "terminal_state": "completed_with_degradation",
        "run_id": "kb_sync-private-id",
        "publication": {
            "status": "not_attempted",
            "separate_confirmation_required": True,
            "sync_publishes": False,
        },
        "digest": "sha256:" + "b" * 64,
    }
    unverified = plugin._render_sync_packet(packet, readback_verified=False)
    assert "Receipt: verified" not in unverified["text"]
    assert "no completion is claimed" in unverified["text"].lower()
    verified = plugin._render_sync_packet(packet, readback_verified=True)
    assert "completed with gaps" in verified["text"].lower()
    assert "Receipt: verified" in verified["text"]
    _assert_compact_user_card(verified)


def test_m3_sync_readback_requires_same_run_and_terminal_state(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    publication = {
        "status": "not_attempted",
        "separate_confirmation_required": True,
        "sync_publishes": False,
    }
    completed = {
        "status": "completed",
        "terminal_state": "completed",
        "run_id": "run-1",
        "publication": publication,
    }
    degraded = {
        "status": "completed_with_degradation",
        "terminal_state": "completed_with_degradation",
        "run_id": "run-1",
        "publication": publication,
    }
    assert plugin._sync_readback_verified(degraded, degraded, "run-1") is True
    assert plugin._sync_readback_verified(completed, degraded, "run-1") is False
    assert plugin._sync_readback_verified(completed, {**completed, "run_id": "run-2"}, "run-1") is False


def test_m3_sync_readback_requires_explicit_terminal_and_publication_separation(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    publication = {
        "status": "not_attempted",
        "separate_confirmation_required": True,
        "sync_publishes": False,
    }
    completed = {
        "status": "completed",
        "terminal_state": "completed",
        "run_id": "run-1",
        "publication": publication,
    }
    assert plugin._sync_readback_verified(completed, completed, "run-1") is True
    assert plugin._sync_readback_verified(
        {key: value for key, value in completed.items() if key != "terminal_state"},
        completed,
        "run-1",
    ) is False
    assert plugin._sync_readback_verified(
        completed,
        {**completed, "publication": {**publication, "sync_publishes": True}},
        "run-1",
    ) is False


def test_m3_all_sources_current_is_a_truthful_verified_noop(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    card = plugin._render_sync_packet(
        {
            "schema_version": 1,
            "kind": "kb_sync_run",
            "status": "completed",
            "terminal_state": "completed",
            "answered_actions": 0,
            "reason": "all_sources_current",
            "publication": {
                "status": "not_attempted",
                "separate_confirmation_required": True,
                "sync_publishes": False,
            },
        },
        readback_verified=False,
    )
    assert card["status"] == "completed"
    assert "already current" in card["text"].lower()
    assert "no knowledge changes were needed" in card["text"].lower()
    assert "Receipt: verified no-op" in card["text"]
    assert "could not be verified" not in card["text"]
    _assert_compact_user_card(card)


def test_m3_verified_sync_fails_closed_on_publication_invariant(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    card = plugin._render_sync_packet(
        {
            "status": "completed",
            "terminal_state": "completed",
            "run_id": "run-1",
            "publication": {
                "status": "attempted",
                "separate_confirmation_required": False,
                "sync_publishes": True,
            },
        },
        readback_verified=True,
    )
    assert card["status"] == "blocked"
    assert "publication separation could not be verified" in card["text"].lower()
    assert "Receipt: verified" not in card["text"]
    assert "no completion is claimed" in card["text"].lower()


def test_m3_sync_shortcut_rewrites_into_harness_visible_context(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")

    prepared = {
        "schema_version": 1,
        "kind": "kb_sync_run",
        "status": "awaiting_action",
        "run_id": "kb_sync-test",
        "next_action": {"kind": "gather_evidence"},
        "publication": {
            "status": "not_attempted",
            "separate_confirmation_required": True,
            "sync_publishes": False,
        },
    }
    ctx = FakeContext(
        {"mcp_kb_engine_prod_kb_sync_prepare": [{"result": prepared}]}
    )

    class Adapter:
        def __init__(self):
            self.sent = []

        def send(self, *args, **kwargs):
            self.sent.append((args, kwargs))
            return type("Result", (), {"success": True})()

    adapter = Adapter()
    source = _FakeSource()
    gateway = type(
        "Gateway",
        (),
        {
            "_is_user_authorized": staticmethod(lambda _source: True),
            "adapters": {"telegram": adapter},
        },
    )()
    result = plugin.build_pre_gateway_dispatch_hook(ctx)(
        event=_FakeEvent(source, text="/kb sync"),
        gateway=gateway,
        session_store=None,
    )

    assert result["action"] == "rewrite"
    assert "kb_sync-test" in result["text"]
    assert "kb.sync.status" in result["text"]
    assert "do not publish" in result["text"].lower()
    assert adapter.sent == []


def test_m3_mapping_sections_preserve_descriptor_actions(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    descriptor = {
        "schema_version": 2,
        "packet_type": "dashboard_action_descriptor",
        "action_id": "archive-situation",
        "label": "Archive",
        "mutation": "handoff_only",
        "target_kind": "situation",
        "target_ref": "situations/lilly-ai-lab",
        "surface": "change.preview",
    }
    card = plugin._render_dashboard(
        {
            "summary": {"readiness_status": "ready", "publication_status": "clean"},
            "sections": {
                "situations": {
                    "cards": [
                        {
                            "id": "lilly-ai-lab",
                            "title": "Lilly AI Lab next steps",
                            "detail": "The outcome is complete.",
                            "action_descriptors": [descriptor],
                        }
                    ]
                }
            },
        },
        ctx=FakeContext({}),
        target="kb_engine_prod",
    )
    assert "Lilly AI Lab next steps" in card["text"]
    assert [action.label for action in card["actions"]] == ["Archive"]
    assert card["actions"][0].metadata["target_ref"] == "situations/lilly-ai-lab"


@pytest.mark.parametrize(
    ("payload", "expected_status", "expected_text"),
    [
        (
            {
                "status": "blocked",
                "ok": False,
                "git": {"status": "ready", "clean": True, "behind": 1, "ahead": 0},
                "scope": {"publication_state": "publication_blocked"},
            },
            "blocked",
            "Publication is blocked",
        ),
        (
            {
                "status": "dirty",
                "ok": True,
                "git": {"status": "ready", "clean": False, "behind": 0, "ahead": 0},
                "scope": {"publication_state": "publication_pending"},
            },
            "dirty",
            "Reviewed changes are ready for publication",
        ),
        (
            {
                "status": "ahead",
                "ok": True,
                "git": {"status": "ready", "clean": True, "behind": 0, "ahead": 1},
                "scope": {"publication_state": "publication_applied"},
            },
            "ahead",
            "has not been pushed",
        ),
        (
            {
                "status": "clean",
                "ok": True,
                "git": {"status": "ready", "clean": True, "behind": 0, "ahead": 0},
                "scope": {"publication_state": "publication_applied"},
            },
            "published",
            "already published",
        ),
    ],
)
def test_m3_publication_handoff_renders_consequence_state(
    payload, expected_status, expected_text, tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    ctx = FakeContext(
        {"mcp_kb_engine_prod_publication_status": [{"result": payload}]}
    )
    card = plugin._render_publish_command(ctx, "kb_engine_prod", "")
    assert card["status"] == expected_status
    assert expected_text in card["text"]
    assert "No publication was attempted." in card["text"]
    _assert_compact_user_card(card)


def test_m3_sync_packet_hides_next_action_machinery_and_source_body(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    card = plugin._render_sync_packet(
        {
            "status": "awaiting_action",
            "run_id": "kb_sync-private-id",
            "next_action": {
                "kind": "gather_evidence",
                "source_id": "private-source",
                "instruction": (
                    "Read PRIVATE SOURCE BODY from "
                    "/home/abcosta/Knowledge/kb-anthony/private.md using kb.sync.resume"
                ),
            },
            "digest": "sha256:" + "c" * 64,
        }
    )
    assert "gather" in card["text"].lower()
    _assert_compact_user_card(card)


def test_m3_disconnected_status_is_compact_and_secret_safe(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    card = plugin._card_for_command(FakeContext({}), "kbstatus")
    assert "unavailable" in card["text"].lower()
    assert "No KB completion is claimed." in card["text"]
    _assert_compact_user_card(card, max_lines=4)


def test_m3_tell_update_never_claims_success_without_readback(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    assert plugin._durable_completion(
        {"status": "applied", "ok": True, "receipt": {"confirmed": True}}
    )["complete"] is False


@pytest.mark.parametrize(
    "text",
    [
        "What needs my attention today?",
        "Sync everything.",
        "Lilly is waiting on legal until Friday.",
        "This is done; archive it.",
    ],
)
def test_m3_ordinary_language_falls_through_to_hermes_without_plugin_calls(
    text, tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakeContext({})
    hook = plugin.build_pre_gateway_dispatch_hook(ctx)
    source = _FakeSource()
    gateway = type(
        "Gateway",
        (),
        {
            "_is_user_authorized": staticmethod(lambda _source: True),
            "adapters": {"telegram": object()},
        },
    )()
    assert hook(
        event=_FakeEvent(source, text=text), gateway=gateway, session_store=None
    ) is None
    assert ctx.calls == []


class _ProbeHookContext(FakeContext):
    def __init__(self, results):
        super().__init__(results)
        self.hooks = {}
        self.commands = {}

    def register_hook(self, name, callback):
        self.hooks.setdefault(name, []).append(callback)

    def register_command(self, name, handler, **metadata):
        self.commands[name] = {"handler": handler, **metadata}


def _configure_probe_pipe(monkeypatch, *, run_id="probe-0123456789abcdef"):
    read_fd, write_fd = os.pipe()
    os.set_inheritable(write_fd, True)
    os.set_blocking(read_fd, False)
    monkeypatch.setenv("NOC_HERMES_PROBE_TELEMETRY_FD", str(write_fd))
    monkeypatch.setenv("NOC_HERMES_PROBE_RUN_ID", run_id)
    return read_fd, write_fd


def _read_probe_packet(read_fd):
    raw = os.read(read_fd, 4096)
    assert raw.endswith(b"\n")
    return json.loads(raw)


def test_m3_probe_telemetry_registers_no_observers_without_private_contract(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("NOC_HERMES_PROBE_TELEMETRY_FD", raising=False)
    monkeypatch.delenv("NOC_HERMES_PROBE_RUN_ID", raising=False)
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = _ProbeHookContext({})

    plugin.register(ctx)

    assert set(ctx.hooks) == {"pre_gateway_dispatch", "post_llm_call"}


def test_m3_probe_telemetry_counts_attempts_context_and_engine_calls_once(
    tmp_path, monkeypatch
):
    read_fd, write_fd = _configure_probe_pipe(monkeypatch)
    try:
        plugin = _load_plugin_module(monkeypatch, tmp_path)
        _install_conforming_descriptor_fixture(plugin, monkeypatch)
        ctx = _ProbeHookContext(
            {
                "mcp_kb_engine_prod_attention_cockpit": [
                    {"result": {"status": "ready"}}
                ]
            }
        )
        plugin.register(ctx)

        assert {"pre_api_request", "post_tool_call"} <= set(ctx.hooks)
        assert "api_request_error" not in ctx.hooks

        small_context = [{"role": "user", "content": "cafe"}]
        large_context = [{"role": "user", "content": "café λλλ"}]
        pre_request = ctx.hooks["pre_api_request"][0]
        pre_request(api_request_id="turn-1:api:1", request_messages=small_context)
        # The same upstream request id may span retries. Each pre-request hook
        # is one outgoing provider attempt.
        pre_request(api_request_id="turn-1:api:1", request_messages=large_context)
        pre_request(api_request_id="turn-1:api:2", request_messages=small_context)

        post_tool = ctx.hooks["post_tool_call"][0]
        post_tool(
            tool_name="mcp_kb_engine_prod_attention_cockpit",
            tool_call_id="tool-1",
        )
        post_tool(
            tool_name="mcp_kb_engine_prod_attention_cockpit",
            tool_call_id="tool-1",
        )
        post_tool(tool_name="web_search", tool_call_id="tool-2")

        for callback in ctx.hooks["post_llm_call"]:
            callback(platform="cli", assistant_response="PRIVATE RESPONSE")

        packet = _read_probe_packet(read_fd)
        expected_context_bytes = len(
            json.dumps(
                large_context,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        assert packet == {
            "schema_version": 1,
            "kind": "hermes_probe_telemetry",
            "run_id": "probe-0123456789abcdef",
            "status": "complete",
            "model_calls": 3,
            "engine_calls": 1,
            "context_bytes": expected_context_bytes,
        }
        assert "PRIVATE" not in json.dumps(packet)

        # A repeated terminal hook cannot emit a second packet.
        for callback in ctx.hooks["post_llm_call"]:
            callback(platform="cli", assistant_response="SECOND PRIVATE RESPONSE")
        with pytest.raises(BlockingIOError):
            os.read(read_fd, 4096)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_m3_probe_telemetry_gateway_dispatch_does_not_emit_or_count(
    tmp_path, monkeypatch
):
    read_fd, write_fd = _configure_probe_pipe(
        monkeypatch, run_id="probe-direct-0123456789"
    )
    try:
        plugin = _load_plugin_module(monkeypatch, tmp_path)
        _install_conforming_descriptor_fixture(plugin, monkeypatch)
        ctx = _ProbeHookContext(
            {
                "mcp_kb_engine_prod_attention_cockpit": [
                    {"result": {"status": "ready"}}
                ]
            }
        )
        plugin.register(ctx)

        class Adapter:
            @staticmethod
            def send(*_args, **_kwargs):
                return type("SendResult", (), {"success": True})()

        source = _FakeSource()
        gateway = type(
            "Gateway",
            (),
            {
                "_is_user_authorized": staticmethod(lambda _source: True),
                "adapters": {"telegram": Adapter()},
            },
        )()
        result = ctx.hooks["pre_gateway_dispatch"][0](
            event=_FakeEvent(source, text="kb status"),
            gateway=gateway,
            session_store=None,
        )

        assert result == {"action": "skip", "reason": "kb_journeys"}
        with pytest.raises(BlockingIOError):
            os.read(read_fd, 4096)

        for callback in ctx.hooks["post_llm_call"]:
            callback(platform="cli", assistant_response="PRIVATE RESPONSE")
        assert _read_probe_packet(read_fd) == {
            "schema_version": 1,
            "kind": "hermes_probe_telemetry",
            "run_id": "probe-direct-0123456789",
            "status": "complete",
            "model_calls": 0,
            "engine_calls": 0,
            "context_bytes": 0,
        }
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_m3_probe_telemetry_missing_engine_call_id_is_incomplete(
    tmp_path, monkeypatch
):
    read_fd, write_fd = _configure_probe_pipe(
        monkeypatch, run_id="probe-incomplete-0123456789"
    )
    try:
        plugin = _load_plugin_module(monkeypatch, tmp_path)
        ctx = _ProbeHookContext({})
        plugin.register(ctx)

        context = [{"role": "user", "content": "status"}]
        ctx.hooks["pre_api_request"][0](
            api_request_id="turn-1:api:1", request_messages=context
        )
        ctx.hooks["post_tool_call"][0](
            tool_name="mcp_kb_engine_prod_attention_cockpit",
            tool_call_id="",
        )
        for callback in ctx.hooks["post_llm_call"]:
            callback(platform="cli", assistant_response="PRIVATE RESPONSE")

        assert _read_probe_packet(read_fd) == {
            "schema_version": 1,
            "kind": "hermes_probe_telemetry",
            "run_id": "probe-incomplete-0123456789",
            "status": "incomplete",
            "model_calls": 1,
            "engine_calls": None,
            "context_bytes": len(
                json.dumps(
                    context,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ),
        }
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_m3_probe_telemetry_rejects_malformed_contract_without_leaking_values(
    tmp_path, monkeypatch, caplog
):
    read_fd, write_fd = _configure_probe_pipe(
        monkeypatch, run_id="invalid run id PRIVATE-NONCE"
    )
    try:
        plugin = _load_plugin_module(monkeypatch, tmp_path)
        ctx = _ProbeHookContext({})
        plugin.register(ctx)

        assert "pre_api_request" not in ctx.hooks
        assert "api_request_error" not in ctx.hooks
        assert "post_tool_call" not in ctx.hooks
        for callback in ctx.hooks["post_llm_call"]:
            callback(platform="cli", assistant_response="PRIVATE RESPONSE")
        with pytest.raises(BlockingIOError):
            os.read(read_fd, 4096)
        assert "PRIVATE-NONCE" not in caplog.text
        assert "PRIVATE RESPONSE" not in caplog.text
    finally:
        os.close(read_fd)
        os.close(write_fd)
