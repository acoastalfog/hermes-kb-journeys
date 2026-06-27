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


def test_kb_sync_is_typed_unavailable_and_dispatches_nothing(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakeContext({})

    card = plugin._card_for_command(ctx, "kb", args="sync confirm")

    assert card["status"] == "temporarily_unavailable"
    assert card["integration_blocker"] == "generated_kb_sync_contract_missing"
    assert card["actions"] == []
    assert "kb.sync.prepare/commit" in card["text"]
    assert "No KB state changed." in card["text"]
    assert "kb_sync." not in json.dumps(card)
    assert "update_kb" not in json.dumps(card)
    assert ctx.calls == []


def test_generated_profile_exposes_canonical_kb_sync_contract(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    if not plugin._canonical_sync_contract_ready():
        pytest.xfail(
            "integration blocker: generated primary_chat does not yet expose "
            "kb.sync.prepare and kb.sync.commit"
        )
    assert plugin._canonical_sync_contract_ready() is True


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

    assert "Review reject preview" in card["text"]
    assert "To apply:" not in card["text"]
    assert [call[0] for call in ctx.calls] == ["mcp_kb_engine_prod_review_decision_preview"]
    preview_args = ctx.calls[-1][1]
    assert preview_args["proposal_ids"] == ["act_crowdstrike"]
    assert preview_args["decision"] == "reject"


def test_kb_review_defaults_to_lifecycle_and_explicit_queue_uses_inbox(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")

    lifecycle_ctx = FakeContext(
        {
            "mcp_kb_engine_prod_lifecycle_review": [
                {
                        "result": {
                            "status": "review",
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
                        "status": "ready",
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
    _install_conforming_descriptor_fixture(plugin, monkeypatch)

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


def test_generated_completion_binding_proves_only_the_exact_selected_request(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    route = "review.batch_decide_confirmed"
    payload, expected = _request_bound_review_fixture(plugin)
    assert plugin._validate_runtime_output(route, payload) is None
    assert plugin._request_bound_review_completion(payload, expected)["complete"] is True
    assert "Applied" in plugin._confirmed_text(
        "approve",
        payload,
        proposal_ids=["p-selected"],
        expected_completion=expected,
    )

    unrelated = deepcopy(payload)
    for section in (unrelated["completion"], unrelated["receipt"], unrelated["readback"]):
        section["affected_ids"] = ["p-unrelated"]
    assert plugin._request_bound_review_completion(unrelated, expected)["reason"] == "affected_ids_mismatch"


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


@pytest.mark.parametrize("observed_at", ["2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z"])
def test_request_bound_completion_rejects_stale_or_future_readback(
    observed_at, tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    payload, expected = _request_bound_review_fixture(plugin)
    payload["readback"]["observed_at"] = observed_at
    proof = plugin._request_bound_review_completion(payload, expected)
    assert proof["complete"] is False
    assert proof["reason"] in {"readback_stale", "readback_future"}


def test_request_bound_completion_rejects_readback_before_confirmation(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    payload, expected = _request_bound_review_fixture(plugin)
    future_confirmation = (
        plugin._parse_aware_timestamp(plugin._capture_now())
        + plugin._dt.timedelta(minutes=2)
    ).isoformat().replace("+00:00", "Z")
    expected["confirmation"]["confirmed_at"] = future_confirmation
    payload["completion"]["confirmation"]["confirmation_digest"] = plugin._descriptor_digest(
        expected["confirmation"]
    )
    proof = plugin._request_bound_review_completion(payload, expected)
    assert proof["complete"] is False
    assert proof["reason"] == "readback_precedes_request_or_receipt"


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
    assert "KB data is not available yet." in card["text"]


def test_render_dashboard_headline_is_bold(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    card = plugin._render_dashboard(
        {"summary": {"readiness_status": "ready", "publication_status": "clean"}},
        ctx=FakeContext({}),
        target="kb_engine_prod",
    )
    assert card["text"].startswith("*KB*")  # bold headline
    assert "kb status:" in card["text"]


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
    assert "**> " in text and "||" in text            # long body collapsed (Task 1)
    # The detail content survives inside the expandable block.
    assert "Outcome: ready" in text
    assert "v0.36.1" in text
    assert "/kb sync" in text
    # Every expandable/quote line must match the verified telegram blockquote regex
    # (space after the prefix) so the body renders as a quote, not literal text.
    for ln in text.splitlines():
        if ln.startswith(">") or ln.startswith("**>"):
            assert _TELEGRAM_BLOCKQUOTE_RE.match(ln) is not None, f"bad quote line: {ln!r}"


def test_render_status_simple_card_headline_is_bold(tmp_path, monkeypatch):
    # Non-proof status packet still gets the bold headline; short body stays inline.
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    card = plugin._render_status({"readiness": "ready"}, "kb_engine_prod")
    assert card["text"].startswith("*KB Status*")


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
    assert "KB Status" in card["text"]
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
    assert source["engine_source_revision"] == "7ce2cc59d9ef7f8076a6e33deedd7feacd84dc16"
    assert source["digest"].startswith("sha256:")
    assert source["engine_version"]
    assert len(source["tools"]) == 12
    serialized = json.dumps(source, sort_keys=True)
    assert "kb_sync" not in serialized
    assert "update_kb" not in serialized
    assert plugin._DESCRIPTOR_BUNDLE == source
    assert plugin._DESCRIPTOR_ERROR == ""
    assert len(plugin._descriptor_allowlist()) == 12


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
    workflow = next(tool for tool in packet["tools"] if tool["name"] == "workflow.start_confirmed")
    workflow["input_schema"]["properties"]["envelope"] = {
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


def test_generated_preview_contracts_are_concrete_enough_for_confirmation(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    missing = [
        capability
        for capability in ("review.decision_preview", "review.restore_preview")
        if not plugin._generated_preview_contract_ready(capability)
    ]
    if missing:
        pytest.xfail(
            "integration blocker: generated preview schemas are not concrete: "
            + ", ".join(missing)
        )
    assert missing == []


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
    assert manifest["version"] == "0.5.0"
    assert manifest["install_receipt"]["owner"] == "noc"
    assert manifest["install_receipt"]["rollback_ref_field"] == "previous_ref"


@pytest.mark.parametrize("args", ["sync", "sync confirm", "run sync"])
def test_all_sync_entrypoints_fail_closed(args, tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakeContext({})
    card = plugin._card_for_command(ctx, "kb", args=args)
    assert card["status"] == "temporarily_unavailable"
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
    assert "temporarily unavailable" in card["text"]
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
    assert "not available" in card["text"]
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
