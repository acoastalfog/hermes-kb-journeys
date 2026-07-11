from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tomllib
import json
import importlib.metadata
import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HERMES_REPO = Path("/Users/acosta/Knowledge/hermes-agent")
CANDIDATE_PIN = ROOT / ".github" / "candidate-artifacts" / "kb-engine.json"
SOURCE_CANDIDATE_PIN = (
    ROOT / ".github" / "candidate-artifacts" / "kb-source-access.json"
)


def _candidate_pin() -> dict:
    return json.loads(CANDIDATE_PIN.read_text(encoding="utf-8"))


def _source_candidate_pin() -> dict:
    return json.loads(SOURCE_CANDIDATE_PIN.read_text(encoding="utf-8"))


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


def _load_plugin_module(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    use_host_mcp_naming: bool = False,
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    # Keep ordinary unit tests deterministic even after an upstream-manager
    # test imports Hermes modules into this pytest process. The dedicated host
    # registry integration test below opts into the running upstream helper.
    if not use_host_mcp_naming:
        monkeypatch.setitem(sys.modules, "tools.mcp_tool", None)  # type: ignore[arg-type]
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


class FakePacketTransportContext:
    def __init__(self, dispatch_result=None):
        self.registered_tools = {}
        self.calls = []
        self.dispatch_result = dispatch_result or {
            "result": {
                "schema_version": 1,
                "kind": "kb_sync_run",
                "status": "awaiting_action",
                "run_id": "hdf-kb_sync-test",
                "next_action": {
                    "kind": "gather_evidence",
                    "action_index": 1,
                    "source_id": "m365.calendar",
                },
                "source_currency": {"target_through": "2026-07-04T00:00:00Z"},
                "publication": {"status": "not_attempted"},
            }
        }

    def register_tool(self, **kwargs):
        self.registered_tools[kwargs["name"]] = kwargs

    def dispatch_tool(self, tool_name, args):
        self.calls.append((tool_name, args))
        return json.dumps(self.dispatch_result)


def _spooled_source_packet(
    root: Path,
    *,
    mode: int = 0o600,
    directory_mode: int = 0o700,
) -> tuple[Path, dict]:
    packet = {
        "schema_version": 1,
        "kind": "kb.source_evidence",
        "source_id": "m365.email",
        "connector_id": "neutral.m365-evidence",
        "harness_id": "hermes-cron",
        "requested_journey": "kb.sync",
        "collected_at": "2026-07-04T00:05:00Z",
        "items": [
            {
                "external_id": "mail-1",
                "revision_id": "revision-1",
                "semantic_text": "private evidence body",
            }
        ],
        "coverage": {
            "requested_window": {
                "start": "2026-07-03T00:00:00Z",
                "end": "2026-07-04T00:00:00Z",
            },
            "observed_intervals": [
                {
                    "start": "2026-07-03T00:00:00Z",
                    "end": "2026-07-04T00:00:00Z",
                }
            ],
            "gaps": [],
            "errors": [],
            "truncated": False,
        },
        "limits": {"max_items": 1, "truncated": False},
        "provenance": {"source_refs": ["source:mail-1"]},
        "privacy": {"classification": "private"},
    }
    canonical = json.dumps(packet, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    prepare = root / "kb-sync" / "prepare"
    prepare.mkdir(parents=True)
    prepare.chmod(0o700)
    spool = prepare / "run-1"
    spool.mkdir()
    spool.chmod(directory_mode)
    path = spool / f"m365.email-{digest[:16]}.json"
    path.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
    path.chmod(mode)
    return path, packet


def _packet_transport(path: Path, packet: dict) -> dict:
    canonical = json.dumps(packet, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "kind": "private_spool",
        "packet_path": str(path),
        "packet_digest": f"sha256:{digest}",
        "byte_count": path.stat().st_size,
    }


def _v2_spooled_source_packet(
    root: Path,
    *,
    recipe_digest: str = "sha256:" + "a" * 64,
    session_id: str = "hermes-session-1",
) -> tuple[Path, dict, dict]:
    packet = {
        "schema_version": 1,
        "kind": "kb.source_evidence",
        "source_id": "m365.email",
        "connector_id": "neutral.m365-evidence",
        "harness_id": "hermes-cron",
        "requested_journey": "kb.sync",
        "collected_at": "2026-07-04T00:05:00Z",
        "items": [{"external_id": "mail-1", "semantic_text": "private evidence body"}],
        "coverage": {
            "requested_window": {
                "start": "2026-07-03T00:00:00Z",
                "end": "2026-07-04T00:00:00Z",
            },
            "observed_intervals": [],
            "gaps": [],
            "errors": [],
            "truncated": False,
        },
        "limits": {"max_items": 1, "truncated": False},
        "provenance": {"source_refs": ["source:mail-1"]},
        "privacy": {"classification": "private"},
    }
    raw = json.dumps(
        packet,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    harness = root / "kb-source-access" / "spool" / ("source-access-" + "1" * 24)
    packet_dir = harness / ("packet-1-" + "2" * 16)
    packet_dir.mkdir(parents=True)
    harness.chmod(0o700)
    packet_dir.chmod(0o700)
    path = packet_dir / f"m365.email-{digest[:16]}.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    transport = {
        "schema_version": 2,
        "kind": "kb.connector.transport",
        "mode": "private_local_spool",
        "packet_path": str(path),
        "packet_digest": "sha256:" + digest,
        "byte_count": len(raw),
        "recipe_digest": recipe_digest,
        "session_id": session_id,
        "cleanup_custody": "connector_owned",
    }
    return path, packet, transport


def test_v2_packet_transport_is_forwarded_unchanged_and_connector_cleans_custody(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet, transport = _v2_spooled_source_packet(state_root)
    packet_dir = packet_path.parent
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": transport,
            }
        )
    )

    assert ctx.calls == [
        (
            "mcp_kb_engine_prod_kb_sync_resume",
            {"run_id": "hdf-kb_sync-test", "response": transport},
        )
    ]
    assert result["accepted"] is True
    assert result["packet_validation_owner"] == "kb-engine"
    assert result["cleanup"] == {
        "status": "cleaned",
        "cleanup_performed": True,
        "custody_owner": "kb-source-access",
    }
    assert not packet_path.exists()
    assert not packet_dir.exists()
    assert "private evidence body" not in json.dumps(result)
    assert str(packet_path) not in json.dumps(result)
    assert transport["packet_digest"] not in json.dumps(result)
    assert packet["source_id"] == "m365.email"


def test_v2_packet_validation_failure_is_engine_owned_and_does_not_echo_packet(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, _packet, transport = _v2_spooled_source_packet(state_root)
    transport["packet_digest"] = "sha256:" + "f" * 64
    ctx = FakePacketTransportContext(
        {
            "result": {
                "status": "invalid_response",
                "run_id": "hdf-kb_sync-test",
                "reason": "connector_transport_invalid",
            }
        }
    )
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": transport,
            }
        )
    )

    assert ctx.calls[0][1]["response"] == transport
    assert result["accepted"] is False
    assert result["packet_validation_owner"] == "kb-engine"
    assert result["cleanup"]["status"] == "blocked"
    assert packet_path.exists()
    assert "private evidence body" not in json.dumps(result)


def test_sync_packet_transport_forwards_verified_descriptor_and_cleans_exact_spool(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    packet_transport = _packet_transport(packet_path, packet)
    spool_dir = packet_path.parent
    ctx = FakePacketTransportContext()

    plugin._register_integration_transport(ctx)

    registered = ctx.registered_tools["kb_integration_transport"]
    result = json.loads(
        registered["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": packet_transport,
            }
        )
    )

    assert ctx.calls == [
        (
            "mcp_kb_engine_prod_kb_sync_resume",
            {"run_id": "hdf-kb_sync-test", "response": packet},
        )
    ]
    assert result["accepted"] is True
    assert result["retryable"] is False
    assert result["run_id"] == "hdf-kb_sync-test"
    assert result["next_action"] == {
        "kind": "gather_evidence",
        "action_index": 1,
        "source_id": "m365.calendar",
    }
    assert result["cleanup"] == {"directory": "removed", "packet": "deleted"}
    assert not packet_path.exists()
    assert not spool_dir.exists()
    assert "private evidence body" not in json.dumps(result)
    assert str(packet_path) not in json.dumps(result)
    assert packet_transport["packet_digest"] not in json.dumps(result)


def test_sync_packet_transport_uses_the_host_canonical_mcp_registry_name(
    tmp_path, monkeypatch
):
    repo = _hermes_repo()
    monkeypatch.syspath_prepend(str(repo))

    from hermes_cli.plugins import PluginContext, PluginManifest
    from tools import registry as registry_module
    from tools import mcp_tool

    plugin = _load_plugin_module(
        monkeypatch,
        tmp_path,
        use_host_mcp_naming=True,
    )
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    transport = _packet_transport(packet_path, packet)

    isolated_registry = registry_module.ToolRegistry()
    monkeypatch.setattr(registry_module, "registry", isolated_registry)
    builder = getattr(mcp_tool, "mcp_prefixed_tool_name", None)
    canonical_name = (
        builder("kb_engine_prod", "kb.sync.resume")
        if builder is not None
        else "mcp_kb_engine_prod_kb_sync_resume"
    )
    assert plugin._mcp_tool_name("kb_engine_prod", "kb.sync.resume") == canonical_name
    isolated_registry.register(
        name=canonical_name,
        toolset="mcp-kb_engine_prod",
        schema={"name": canonical_name, "parameters": {"type": "object"}},
        handler=lambda _args, **_kwargs: json.dumps(
            {
                "result": {
                    "schema_version": 1,
                    "kind": "kb_sync_run",
                    "status": "awaiting_action",
                    "run_id": "hdf-kb_sync-test",
                    "next_action": {
                        "kind": "gather_evidence",
                        "action_index": 1,
                        "source_id": "m365.calendar",
                    },
                    "source_currency": {
                        "target_through": "2026-07-04T00:00:00Z"
                    },
                    "publication": {"status": "not_attempted"},
                }
            }
        ),
    )
    manager = type(
        "Manager",
        (),
        {"_cli_ref": None, "_plugin_tool_names": set()},
    )()
    ctx = PluginContext(
        PluginManifest(name="kb_journeys", source="user"),
        manager,
    )
    plugin._register_integration_transport(ctx)

    registered = isolated_registry.get_entry("kb_integration_transport")
    assert registered is not None
    result = json.loads(
        registered.handler(
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": transport,
            }
        )
    )

    assert result["accepted"] is True
    assert result["cleanup"] == {"directory": "removed", "packet": "deleted"}
    assert not packet_path.exists()


def test_sync_packet_transport_accepts_harness_capacity_sibling_and_removes_only_packet_dir(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    prepare = state_root / "kb-sync" / "prepare"
    harness_root = prepare / "source-access-harness"
    harness_root.mkdir(mode=0o700)
    capacity_lock = harness_root / ".capacity.lock"
    capacity_lock.write_text("", encoding="utf-8")
    capacity_lock.chmod(0o600)
    packet_dir = harness_root / "packet-1"
    packet_path.parent.rename(packet_dir)
    packet_path = packet_dir / packet_path.name
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": _packet_transport(packet_path, packet),
            }
        )
    )

    assert result["accepted"] is True
    assert result["cleanup"] == {"directory": "removed", "packet": "deleted"}
    assert harness_root.is_dir()
    assert capacity_lock.is_file()
    assert not packet_dir.exists()


def test_sync_packet_transport_schema_prefers_exact_descriptor_and_marks_path_deprecated(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)

    parameters = ctx.registered_tools["kb_integration_transport"]["schema"]["parameters"]
    transport = parameters["properties"]["packet_transport"]
    assert len(transport["oneOf"]) == 2
    installed, legacy = transport["oneOf"]
    private_spool = next(
        branch
        for branch in installed["oneOf"]
        if branch["properties"]["mode"].get("const") == "private_local_spool"
    )
    assert private_spool["required"] == [
        "schema_version",
        "kind",
        "mode",
        "packet_path",
        "packet_digest",
        "byte_count",
        "recipe_digest",
        "session_id",
        "cleanup_custody",
    ]
    assert private_spool["additionalProperties"] is False
    assert private_spool["properties"]["kind"] == {
        "const": "kb.connector.transport"
    }
    assert private_spool["properties"]["cleanup_custody"] == {
        "const": "connector_owned"
    }
    assert legacy["properties"]["kind"] == {"const": "private_spool"}
    assert "deprecated" in parameters["properties"]["packet_path"]["description"].lower()


def test_sync_packet_transport_keeps_explicit_deprecated_path_compatibility(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_path": str(packet_path),
            }
        )
    )

    assert ctx.calls == [
        (
            "mcp_kb_engine_prod_kb_sync_resume",
            {"run_id": "hdf-kb_sync-test", "response": packet},
        )
    ]
    assert result["accepted"] is True
    assert result["compatibility"] == "deprecated_packet_path"
    assert result["cleanup"]["packet"] == "deleted"
    assert "private evidence body" not in json.dumps(result)


@pytest.mark.parametrize(
    ("mutation", "error_code"),
    [
        ("wrong_digest", "packet_digest_mismatch"),
        ("prefix_only_digest", "packet_digest_mismatch"),
        ("wrong_byte_count", "packet_byte_count_mismatch"),
        ("wrong_kind", "packet_transport_invalid"),
        ("extra_field", "packet_transport_invalid"),
        ("wrong_source_filename", "packet_filename_invalid"),
    ],
)
def test_sync_packet_transport_rejects_invalid_descriptor_without_dispatch(
    tmp_path, monkeypatch, mutation, error_code
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    transport = _packet_transport(packet_path, packet)
    if mutation == "wrong_digest":
        transport["packet_digest"] = "sha256:" + "f" * 64
    elif mutation == "prefix_only_digest":
        actual = transport["packet_digest"].removeprefix("sha256:")
        transport["packet_digest"] = "sha256:" + actual[:16] + "0" * 48
    elif mutation == "wrong_byte_count":
        transport["byte_count"] += 1
    elif mutation == "wrong_kind":
        transport["kind"] = "inline"
    elif mutation == "extra_field":
        transport["evidence"] = "private evidence body"
    elif mutation == "wrong_source_filename":
        moved = packet_path.with_name(packet_path.name.replace("m365.email", "slack.message"))
        packet_path.rename(moved)
        packet_path = moved
        transport["packet_path"] = str(moved)
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": transport,
            }
        )
    )

    assert result["accepted"] is False
    assert result["retryable"] is False
    assert result["error_code"] == error_code
    assert result["cleanup"]["packet"] == "unmanaged"
    assert packet_path.exists()
    assert ctx.calls == []
    assert "private evidence body" not in json.dumps(result)


@pytest.mark.parametrize(
    ("unsafe", "error_code"),
    [
        ("outside", "packet_path_outside_spool"),
        ("file_mode", "packet_file_unsafe"),
        ("directory_mode", "packet_parent_unsafe"),
        ("spool_root_mode", "packet_parent_unsafe"),
        ("file_symlink", "packet_file_unsafe"),
        ("parent_symlink", "packet_parent_unsafe"),
        ("hardlink", "packet_file_unsafe"),
        ("owner", "packet_parent_unsafe"),
        ("over_limit", "packet_size_invalid"),
    ],
)
def test_sync_packet_transport_rejects_unsafe_descriptor_spool(
    tmp_path, monkeypatch, unsafe, error_code
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_root = tmp_path / "outside" if unsafe == "outside" else state_root
    packet_path, packet = _spooled_source_packet(
        packet_root,
        mode=0o644 if unsafe == "file_mode" else 0o600,
        directory_mode=0o755 if unsafe == "directory_mode" else 0o700,
    )
    transport = _packet_transport(packet_path, packet)
    if unsafe == "file_symlink":
        target = packet_path.with_name("target.json")
        packet_path.rename(target)
        packet_path.symlink_to(target)
    elif unsafe == "spool_root_mode":
        (state_root / "kb-sync" / "prepare").chmod(0o755)
    elif unsafe == "parent_symlink":
        real_parent = packet_path.parent.with_name("real-run")
        packet_path.parent.rename(real_parent)
        packet_path.parent.symlink_to(real_parent, target_is_directory=True)
    elif unsafe == "hardlink":
        os.link(packet_path, packet_path.with_name("second-link.json"))
    elif unsafe == "owner":
        current_uid = os.geteuid()
        monkeypatch.setattr(plugin.os, "geteuid", lambda: current_uid + 1)
    elif unsafe == "over_limit":
        with packet_path.open("r+b") as handle:
            handle.truncate(plugin.SYNC_PACKET_MAX_BYTES + 1)
        transport["byte_count"] = packet_path.stat().st_size
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": transport,
            }
        )
    )

    assert result["accepted"] is False
    assert result["retryable"] is False
    assert result["error_code"] == error_code
    assert ctx.calls == []
    assert "private evidence body" not in json.dumps(result)


@pytest.mark.parametrize(
    ("body", "error_code"),
    [
        (b"\xff", "packet_json_invalid"),
        (b"not-json", "packet_json_invalid"),
        (b"[]", "packet_schema_invalid"),
        (b'{"schema_version":1,"kind":"wrong"}', "packet_schema_invalid"),
        (
            b'{"schema_version":1,"kind":"kb.source_evidence","source_id":"m365.email"}',
            "packet_source_identity_invalid",
        ),
    ],
)
def test_sync_packet_transport_rejects_invalid_packet_body_without_rendering_it(
    tmp_path, monkeypatch, body, error_code
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    packet_path.write_bytes(body)
    packet_path.chmod(0o600)
    transport = _packet_transport(packet_path, packet)
    transport["byte_count"] = len(body)
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": transport,
            }
        )
    )

    assert result["accepted"] is False
    assert result["error_code"] == error_code
    assert ctx.calls == []
    assert body.decode("utf-8", "replace") not in json.dumps(result)


def test_sync_packet_transport_rejects_descriptor_and_legacy_path_together(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": _packet_transport(packet_path, packet),
                "packet_path": str(packet_path),
            }
        )
    )

    assert result["accepted"] is False
    assert result["error_code"] == "packet_transport_invalid"
    assert ctx.calls == []


def test_sync_packet_transport_retains_packet_on_retryable_dispatch_failure(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    transport = _packet_transport(packet_path, packet)

    class RetryContext(FakePacketTransportContext):
        def dispatch_tool(self, tool_name, args):
            self.calls.append((tool_name, args))
            raise RuntimeError("private evidence body must not escape through errors")

    ctx = RetryContext()
    plugin._register_integration_transport(ctx)
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": transport,
            }
        )
    )

    assert result["accepted"] is False
    assert result["retryable"] is True
    assert result["error_code"] == "kb_sync_resume_transport_failed"
    assert result["dispatch_reason_code"] == "dispatch_failed"
    assert result["cleanup"] == {"directory": "retained", "packet": "retained"}
    assert packet_path.exists()
    assert "private evidence body" not in json.dumps(result)


def test_sync_packet_transport_cleans_packet_on_nonretryable_dispatch_failure(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    transport = _packet_transport(packet_path, packet)

    class TerminalContext(FakePacketTransportContext):
        def dispatch_tool(self, tool_name, args):
            self.calls.append((tool_name, args))
            raise RuntimeError("runtime output violates generated schema")

    ctx = TerminalContext()
    plugin._register_integration_transport(ctx)
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": transport,
            }
        )
    )

    assert result == {
        "accepted": False,
        "retryable": False,
        "run_id": "hdf-kb_sync-test",
        "error": "private packet transport was not accepted",
        "error_code": "kb_sync_resume_transport_failed",
        "cleanup": {"directory": "removed", "packet": "deleted"},
        "dispatch_reason_code": "output_contract_invalid",
    }
    assert not packet_path.exists()
    assert "private evidence body" not in json.dumps(result)
    assert str(packet_path) not in json.dumps(result)
    assert transport["packet_digest"] not in json.dumps(result)


def test_sync_packet_transport_classifies_missing_registered_route_without_error_text(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)

    class MissingRouteContext(FakePacketTransportContext):
        def dispatch_tool(self, tool_name, args):
            self.calls.append((tool_name, args))
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

    ctx = MissingRouteContext()
    plugin._register_integration_transport(ctx)
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": _packet_transport(packet_path, packet),
            }
        )
    )

    assert result["accepted"] is False
    assert result["retryable"] is True
    assert result["error_code"] == "kb_sync_resume_transport_failed"
    assert result["dispatch_reason_code"] == "route_not_registered"
    assert result["cleanup"] == {"directory": "retained", "packet": "retained"}
    assert packet_path.exists()
    assert "Unknown tool" not in json.dumps(result)
    assert "private evidence body" not in json.dumps(result)


@pytest.mark.parametrize(
    ("error", "reason_code"),
    [
        ("MCP call timed out after 30s", "route_timeout"),
        ("MCP server transport is down; reconnect requested", "route_unavailable"),
        ("runtime output violates generated schema", "output_contract_invalid"),
        ("upstream tool failure: $.error: rejected", "upstream_rejected"),
    ],
)
def test_sync_packet_dispatch_reason_codes_are_bounded(error, reason_code, tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    assert plugin._sync_packet_dispatch_reason_code([error]) == reason_code


def test_sync_packet_transport_classifies_engine_failed_as_nonretryable(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    ctx = FakePacketTransportContext(
        {"result": {"status": "failed", "run_id": "hdf-kb_sync-test"}}
    )
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": _packet_transport(packet_path, packet),
            }
        )
    )

    assert result["accepted"] is False
    assert result["retryable"] is False
    assert result["error_code"] == "kb_sync_resume_transport_failed"
    assert result["cleanup"] == {"directory": "removed", "packet": "deleted"}
    assert not packet_path.exists()


@pytest.mark.parametrize(
    ("engine_result", "retryable"),
    [
        ({"status": "invalid_response", "run_id": "hdf-kb_sync-test"}, False),
        (
            {
                "status": "temporarily_unavailable",
                "run_id": "hdf-kb_sync-test",
                "retryable": True,
            },
            True,
        ),
        ({"status": "awaiting_action", "run_id": "another-run"}, False),
    ],
)
def test_sync_packet_transport_cleans_terminal_and_retains_retryable_engine_rejection(
    tmp_path, monkeypatch, engine_result, retryable
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    ctx = FakePacketTransportContext({"result": engine_result})
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": _packet_transport(packet_path, packet),
            }
        )
    )

    assert result["accepted"] is False
    assert result["retryable"] is retryable
    assert result["error_code"] == "kb_sync_resume_not_accepted"
    if retryable:
        assert result["cleanup"] == {"directory": "retained", "packet": "retained"}
        assert packet_path.exists()
    else:
        assert result["cleanup"] == {"directory": "removed", "packet": "deleted"}
        assert not packet_path.exists()
    assert "private evidence body" not in json.dumps(result)


def test_sync_packet_transport_does_not_unlink_when_name_changes_inode(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)
    opened_inode_path = packet_path.with_name("opened-inode.json")

    class SwapContext(FakePacketTransportContext):
        def dispatch_tool(self, tool_name, args):
            self.calls.append((tool_name, args))
            packet_path.rename(opened_inode_path)
            packet_path.write_text("replacement", encoding="utf-8")
            packet_path.chmod(0o600)
            return json.dumps(self.dispatch_result)

    ctx = SwapContext()
    plugin._register_integration_transport(ctx)
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": _packet_transport(packet_path, packet),
            }
        )
    )

    assert result["accepted"] is True
    assert result["cleanup"] == {
        "directory": "retained",
        "packet": "retained_inode_changed",
    }
    assert packet_path.exists()
    assert opened_inode_path.exists()
    assert "private evidence body" not in json.dumps(result)


def test_sync_packet_transport_does_not_unlink_when_open_inode_content_changes(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    state_root = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_root))
    packet_path, packet = _spooled_source_packet(state_root)

    class RewriteContext(FakePacketTransportContext):
        def dispatch_tool(self, tool_name, args):
            self.calls.append((tool_name, args))
            packet_path.write_text("replacement content", encoding="utf-8")
            packet_path.chmod(0o600)
            return json.dumps(self.dispatch_result)

    ctx = RewriteContext()
    plugin._register_integration_transport(ctx)
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "resume_packet",
                "run_id": "hdf-kb_sync-test",
                "packet_transport": _packet_transport(packet_path, packet),
            }
        )
    )

    assert result["accepted"] is True
    assert result["cleanup"] == {
        "directory": "retained",
        "packet": "retained_content_changed",
    }
    assert packet_path.read_text(encoding="utf-8") == "replacement content"


def test_context_search_reuses_the_single_transport_without_a_sync_run(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakePacketTransportContext()
    calls = []

    class Facade:
        def dispatch(self, source_id, operation, params):
            calls.append((source_id, operation, params))
            if source_id == "m365.calendar" and operation == "fetch":
                return {"status": "ok", "result": {"item": {"external_id": "event-1"}}}
            if source_id == "m365.email":
                return {"status": "unavailable", "error_code": "mail_unavailable"}
            rows = {
                "m365.calendar": [
                    {
                        "ref": "sar1.calendar",
                        "summary": {
                            "subject": "Acme review",
                            "start": "2026-07-08T10:00:00Z",
                        },
                    }
                ],
                "travel.tripit": [
                    {
                        "ref": "sar1.tripit",
                        "summary": {
                            "title": "Acme trip",
                            "start": "2026-07-07T00:00:00Z",
                        },
                    }
                ],
                "slack.message": [
                    {
                        "ref": "sar1.slack",
                        "summary": {
                            "text": "Acme context",
                            "timestamp": "2026-07-09T00:00:00Z",
                        },
                    }
                ],
                "m365.meeting_artifact": [],
            }[source_id]
            return {
                "status": "ok",
                "result": {"items": rows},
                "continuation": {"complete": True, "cursor": None},
            }

    monkeypatch.setattr(plugin, "_source_access_facade", lambda: Facade())
    plugin._register_integration_transport(ctx)

    registered = ctx.registered_tools["kb_integration_transport"]
    result = json.loads(
        registered["handler"](
            {
                "operation": "context_search",
                "terms": ["Acme", "Thursday"],
                "sources": ["meeting_artifacts", "slack", "mail", "tripit", "calendar"],
                "start": "2026-07-06T00:00:00Z",
                "end": "2026-07-10T00:00:00Z",
                "limit_per_source": 5,
            }
        )
    )

    assert result["accepted"] is True
    assert result["kind"] == "hermes_context_search"
    assert result["source_access_owner"] == "kb-source-access"
    assert result["item_count"] == 3
    assert result["external_effect_started"] is False
    assert result["durable_kb_write_started"] is False
    assert result["requested_sources"] == [
        "meeting_artifacts",
        "slack",
        "mail",
        "tripit",
        "calendar",
    ]
    assert [(row[0], row[1]) for row in calls] == [
        ("m365.calendar", "search"),
        ("travel.tripit", "search"),
        ("m365.email", "search"),
        ("slack.message", "search"),
        ("m365.calendar", "fetch"),
        ("m365.meeting_artifact", "search"),
    ]
    assert calls[-1][2]["query"] == "event-1"
    operation = registered["schema"]["parameters"]["properties"]["operation"]
    assert "context_search" in operation["enum"]
    assert registered["schema"]["parameters"]["required"] == ["operation"]
    assert ctx.calls == []


def test_context_tripit_row_excludes_confirmation_material(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)

    row = plugin._context_tripit_row(
        {
            "external_id": "item-1",
            "type": "flight",
            "title": "Flight to Seoul",
            "trip_name": "ICML",
            "start": "2026-07-05T00:00:00Z",
            "end": "2026-07-06T00:00:00Z",
            "location": {"code": "ICN"},
            "confirmation": "must-not-leave-source-packet",
            "details": "private connector detail",
        }
    )

    assert row["source"] == "tripit"
    assert row["location"] == "ICN"
    assert "confirmation" not in row
    assert "details" not in row


def test_context_search_rejects_an_unsafe_window_before_any_source_read(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    ctx = FakePacketTransportContext()
    monkeypatch.setattr(
        plugin,
        "_source_access_facade",
        lambda: pytest.fail("source read must not start"),
    )
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "context_search",
                "terms": ["Acme"],
                "sources": ["calendar"],
                "start": "2026-01-01T00:00:00Z",
                "end": "2026-07-10T00:00:00Z",
            }
        )
    )

    assert result["accepted"] is False
    assert "45 days" in result["error"]
    assert ctx.calls == []


def test_context_command_rejects_general_shell_execution(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)

    with pytest.raises(ValueError, match="not allowlisted"):
        plugin._run_context_command(["sh", "-c", "echo unsafe"])


def test_context_command_supplies_a_stable_harness_identity(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.delenv("KB_HARNESS_ID", raising=False)
    monkeypatch.setattr(plugin.shutil, "which", lambda _name: "/usr/bin/calendar-cli")
    seen = {}

    def run(argv, **kwargs):
        seen.update(kwargs["env"])
        return type("Result", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()

    monkeypatch.setattr(plugin.subprocess, "run", run)
    plugin._run_context_command(["calendar-cli", "find"])

    assert seen["KB_HARNESS_ID"] == "hermes-context"


def test_context_slack_search_uses_one_bounded_window(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return 75, "", "synthetic source failure"

    monkeypatch.setattr(plugin, "_run_context_command", run)
    status, rows = plugin._search_slack_context(
        start=plugin._context_timestamp("2026-07-06T00:00:00Z", field="start"),
        end=plugin._context_timestamp("2026-07-13T00:00:00Z", field="end"),
        tokens=["acme"],
        limit=5,
    )

    argv = calls[0][0]
    assert argv[argv.index("--window-days") + 1] == "7"
    assert status["status"] == "degraded"
    assert rows == []


def test_context_calendar_search_filters_date_cli_results_to_exact_utc_window(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    calls = []

    def run(argv, **_kwargs):
        calls.append(argv)
        return (
            0,
            json.dumps(
                {
                    "success": True,
                    "data": [
                        {
                            "id": "weak-body-match",
                            "subject": "Weekly sync",
                            "bodyPreview": "SK presentation is one agenda topic",
                            "start": {
                                "dateTime": "2026-07-08T15:30:00",
                                "timeZone": "UTC",
                            },
                            "end": {
                                "dateTime": "2026-07-08T16:00:00",
                                "timeZone": "UTC",
                            },
                        },
                        {
                            "id": "inside",
                            "subject": "SK presentation",
                            "start": {
                                "dateTime": "2026-07-08T16:00:00",
                                "timeZone": "UTC",
                            },
                            "end": {
                                "dateTime": "2026-07-08T17:00:00",
                                "timeZone": "UTC",
                            },
                        },
                        {
                            "id": "outside",
                            "subject": "Outside exact bound",
                            "start": {
                                "dateTime": "2026-07-09T16:00:00",
                                "timeZone": "UTC",
                            },
                            "end": {
                                "dateTime": "2026-07-09T17:00:00",
                                "timeZone": "UTC",
                            },
                        },
                    ],
                }
            ),
            "",
        )

    monkeypatch.setattr(plugin, "_run_context_command", run)
    status, rows = plugin._search_calendar_context(
        start=plugin._context_timestamp("2026-07-08T15:00:00Z", field="start"),
        end=plugin._context_timestamp("2026-07-09T15:00:00Z", field="end"),
        tokens=["sk"],
        limit=5,
    )

    argv = calls[0]
    assert argv[argv.index("--after") + 1] == "2026-07-08"
    assert argv[argv.index("--before") + 1] == "2026-07-10"
    assert status["fetched_count"] == 3
    assert status["observed_count"] == 2
    assert [row["ref"] for row in rows] == ["inside", "weak-body-match"]


def test_context_meeting_search_skips_future_events(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setattr(
        plugin,
        "_run_context_command",
        lambda *_args, **_kwargs: pytest.fail(
            "future event must not trigger transcript lookup"
        ),
    )

    status, rows = plugin._search_meeting_artifacts_context(
        [
            {
                "ref": "future-event",
                "title": "Future meeting",
                "end": {"dateTime": "2099-01-01T01:00:00", "timeZone": "UTC"},
            }
        ],
        limit=5,
    )

    assert status["status"] == "degraded"
    assert status["error"] == "no resolved calendar event was available"
    assert rows == []


def test_semantic_batch_transport_returns_the_exact_engine_packet_without_local_compaction(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    run_id = "hdf-kb_sync-daily"
    evidence_refs = ["sha256:" + character * 64 for character in ("a", "b")]
    status = {
        "schema_version": 1,
        "kind": "kb_sync_run",
        "status": "awaiting_action",
        "run_id": run_id,
        "source_currency": {"private": "irrelevant-to-review"},
        "publication": {"status": "not_attempted"},
        "timing": {"started_at": "2026-07-05T00:00:00Z"},
        "next_action": {
            "kind": "exercise_judgment",
            "action_index": 12,
            "semantic_stage": "evidence_attribution",
            "instruction": "Attribute the selected evidence.",
            "attribution_outcomes": ["integrate", "non_durable"],
            "response_schema": {"type": "object"},
            "evidence_sources": [{"source_id": "m365.email"}],
            "semantic_accounting": {
                "progress": {
                    "stage": "evidence_attribution",
                    "reviewed_ref_count": 10,
                    "unreviewed_count": 20,
                    "remaining_refs": ["sha256:" + "c" * 64],
                    "remaining_refs_truncated": True,
                    "digest": "sha256:" + "d" * 64,
                }
            },
        },
        "selected_evidence": {
            "requested_count": 2,
            "truncated": False,
            "review_token": "sha256:" + "e" * 64,
            "digest": "sha256:" + "f" * 64,
            "items": [
                {
                    "evidence_ref": evidence_ref,
                    "source_id": "m365.email",
                    "item": {"semantic_text": f"evidence body {index}"},
                }
                for index, evidence_ref in enumerate(evidence_refs)
            ],
        },
        "candidate_state": {
            "requested_count": 2,
            "truncated": False,
            "digest": "sha256:" + "1" * 64,
            "rows": [],
        },
    }
    ctx = FakePacketTransportContext()
    ctx.dispatch_result = {"result": status}

    plugin._register_integration_transport(ctx)
    registered = ctx.registered_tools["kb_integration_transport"]
    result = json.loads(
        registered["handler"](
            {
                "operation": "semantic_batch",
                "run_id": run_id,
                "evidence_refs": evidence_refs,
            }
        )
    )

    assert ctx.calls == [
        (
            "mcp_kb_engine_prod_kb_sync_status",
            {"run_id": run_id, "evidence_refs": evidence_refs},
        )
    ]
    assert result["accepted"] is True
    assert result["selected_evidence"] == status["selected_evidence"]
    assert result["candidate_state"] == status["candidate_state"]
    assert result["next_action"]["response_schema"] == {"type": "object"}
    assert result["next_action"]["semantic_accounting"]["progress"]["remaining_refs"] == [
        "sha256:" + "c" * 64
    ]
    assert result["source_currency"] == status["source_currency"]
    assert result["publication"] == status["publication"]
    assert result["timing"] == status["timing"]
    assert result["next_action"]["evidence_sources"] == [
        {"source_id": "m365.email"}
    ]
    assert result["semantic_owner"] == "kb-engine"
    assert "semantic_batch" in registered["schema"]["parameters"]["properties"]["operation"]["enum"]


def test_semantic_batch_transport_reduces_requested_prefix_until_result_is_bounded(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setattr(plugin, "INTEGRATION_TRANSPORT_MAX_RESULT_BYTES", 1_500)
    run_id = "hdf-kb_sync-daily"
    evidence_refs = ["sha256:" + character * 64 for character in ("a", "b", "c", "d")]
    ctx = FakePacketTransportContext()

    def dispatch(tool_name, args):
        ctx.calls.append((tool_name, args))
        selected = args["evidence_refs"]
        payload = {
            "schema_version": 1,
            "status": "awaiting_action",
            "run_id": run_id,
            "next_action": {
                "kind": "exercise_judgment",
                "action_index": 2,
                "semantic_stage": "evidence_attribution",
                "instruction": "Attribute.",
                "response_schema": {"type": "object"},
                "semantic_accounting": {"progress": {"unreviewed_count": 4}},
            },
            "selected_evidence": {
                "requested_count": len(selected),
                "truncated": False,
                "review_token": "sha256:" + "e" * 64,
                "items": [
                    {"evidence_ref": ref, "item": {"semantic_text": "x" * 500}}
                    for ref in selected
                ],
            },
            "candidate_state": {"requested_count": len(selected), "rows": []},
        }
        return json.dumps({"result": payload})

    ctx.dispatch_tool = dispatch
    plugin._register_integration_transport(ctx)
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "semantic_batch",
                "run_id": run_id,
                "evidence_refs": evidence_refs,
            }
        )
    )

    assert [len(args["evidence_refs"]) for _tool, args in ctx.calls] == [4, 2, 1]
    assert result["accepted"] is True
    assert result["requested_count"] == 4
    assert result["selected_count"] == 1
    assert result["reduced"] is True
    assert len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= 1_500


def test_semantic_batch_transport_preserves_owner_packet_duplicate_fields(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    run_id = "hdf-kb_sync-daily"
    evidence_ref = "sha256:" + "a" * 64
    distinct_ref = "sha256:" + "d" * 64
    semantic_text = "speaker: exact transcript body"
    ctx = FakePacketTransportContext()
    ctx.dispatch_result = {
        "result": {
            "status": "awaiting_action",
            "run_id": run_id,
            "next_action": {
                "kind": "exercise_judgment",
                "semantic_stage": "evidence_attribution",
            },
            "selected_evidence": {
                "requested_count": 2,
                "review_token": "sha256:" + "b" * 64,
                "digest": "sha256:" + "c" * 64,
                "items": [
                    {
                        "evidence_ref": evidence_ref,
                        "source_id": "m365.meeting_artifact",
                        "item": {
                            "semantic_text": semantic_text,
                            "transcript": semantic_text,
                            "subject": "Review",
                        },
                    },
                    {
                        "evidence_ref": distinct_ref,
                        "source_id": "m365.meeting_artifact",
                        "item": {
                            "semantic_text": "curated summary",
                            "transcript": "different source transcript",
                        },
                    },
                ],
            },
            "candidate_state": {"requested_count": 2, "rows": []},
        }
    }

    plugin._register_integration_transport(ctx)
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "semantic_batch",
                "run_id": run_id,
                "evidence_refs": [evidence_ref, distinct_ref],
            }
        )
    )

    item = result["selected_evidence"]["items"][0]["item"]
    assert item["semantic_text"] == semantic_text
    assert item["transcript"] == semantic_text
    assert item["subject"] == "Review"
    assert result["selected_evidence"]["items"][1]["item"]["transcript"] == (
        "different source transcript"
    )
    assert "transport_normalization" not in result["selected_evidence"]


def test_semantic_batch_transport_pages_one_oversized_evidence_body_losslessly(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setattr(plugin, "INTEGRATION_TRANSPORT_MAX_RESULT_BYTES", 2_400)
    run_id = "hdf-kb_sync-daily"
    evidence_ref = "sha256:" + "a" * 64
    semantic_text = "alpha βeta 🧬 " * 700
    selected_evidence = {
        "requested_count": 1,
        "truncated": False,
        "review_token": "sha256:" + "b" * 64,
        "digest": "sha256:" + "c" * 64,
        "items": [
            {
                "evidence_ref": evidence_ref,
                "source_id": "m365.meeting_artifact",
                "revision": "meeting-revision-1",
                "item": {
                    "semantic_text": semantic_text,
                    "transcript": semantic_text,
                    "subject": "Long review",
                },
            }
        ],
    }
    ctx = FakePacketTransportContext()
    ctx.dispatch_result = {
        "result": {
            "status": "awaiting_action",
            "run_id": run_id,
            "next_action": {
                "kind": "exercise_judgment",
                "semantic_stage": "evidence_attribution",
                "response_schema": {"type": "object"},
            },
            "selected_evidence": selected_evidence,
            "candidate_state": {"requested_count": 1, "rows": []},
        }
    }

    plugin._register_integration_transport(ctx)
    registered = ctx.registered_tools["kb_integration_transport"]
    offset_schema = registered["schema"]["parameters"]["properties"][
        "evidence_text_offset"
    ]
    assert offset_schema["minimum"] == 0
    handler = registered["handler"]
    offset = 0
    seen = []
    while True:
        request = {
            "operation": "semantic_batch",
            "run_id": run_id,
            "evidence_refs": [evidence_ref],
        }
        if offset:
            request["evidence_text_offset"] = offset
        result = json.loads(handler(request))
        assert result["accepted"] is True
        assert result["selected_evidence"]["review_token"] == selected_evidence["review_token"]
        assert result["selected_evidence"]["digest"] == selected_evidence["digest"]
        row = result["selected_evidence"]["items"][0]
        assert row["evidence_ref"] == evidence_ref
        assert row["revision"] == "meeting-revision-1"
        assert row["item"]["subject"] == "Long review"
        assert "transcript" not in row["item"]
        assert len(
            json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ) <= 2_400
        page = result["selected_evidence"]["page"]
        assert page["field"] == "semantic_text"
        assert page["text_offset"] == offset
        assert page["text_char_count"] == len(row["item"]["semantic_text"])
        assert page["text_total_chars"] == len(semantic_text)
        seen.append(row["item"]["semantic_text"])
        if not page["has_more"]:
            break
        offset = page["next_text_offset"]

    assert "".join(seen) == semantic_text
    assert "".join(seen).encode("utf-8") == semantic_text.encode("utf-8")
    assert ctx.calls == [
        (
            "mcp_kb_engine_prod_kb_sync_status",
            {"run_id": run_id, "evidence_refs": [evidence_ref]},
        )
    ] * len(seen)


@pytest.mark.parametrize(
    ("selector", "offset", "extra"),
    [
        ({"target_refs": ["projects/demo"]}, 0, {}),
        ({"evidence_refs": ["sha256:" + "a" * 64, "sha256:" + "b" * 64]}, 0, {}),
        ({"evidence_refs": ["sha256:" + "a" * 64]}, True, {}),
        ({"evidence_refs": ["sha256:" + "a" * 64]}, -1, {}),
        (
            {"evidence_refs": ["sha256:" + "a" * 64]},
            0,
            {"target_evidence_offset": 0},
        ),
    ],
)
def test_semantic_batch_transport_rejects_invalid_evidence_text_offset(
    tmp_path, monkeypatch, selector, offset, extra
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "semantic_batch",
                "run_id": "hdf-kb_sync-daily",
                **selector,
                "evidence_text_offset": offset,
                **extra,
            }
        )
    )

    assert result["accepted"] is False
    assert ctx.calls == []
    assert "evidence_text_offset" in result["error"]


def test_semantic_batch_transport_returns_exact_target_dossiers(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    run_id = "hdf-kb_sync-daily"
    target_refs = ["accounts/acme", "projects/launch"]
    dossiers = {
        "requested_count": 2,
        "truncated": False,
        "review_token": "sha256:" + "a" * 64,
        "items": [{"target_ref": target_ref} for target_ref in target_refs],
    }
    ctx = FakePacketTransportContext()
    ctx.dispatch_result = {
        "result": {
            "schema_version": 1,
            "status": "awaiting_action",
            "run_id": run_id,
            "next_action": {
                "kind": "exercise_judgment",
                "action_index": 20,
                "semantic_stage": "target_integration",
                "instruction": "Synthesize one net result per target.",
                "response_schema": {"type": "object"},
                "semantic_accounting": {"progress": {"target_remaining_count": 2}},
            },
            "target_dossiers": dossiers,
        }
    }

    plugin._register_integration_transport(ctx)
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "semantic_batch",
                "run_id": run_id,
                "target_refs": target_refs,
            }
        )
    )

    assert ctx.calls == [
        (
            "mcp_kb_engine_prod_kb_sync_status",
            {"run_id": run_id, "target_refs": target_refs},
        )
    ]
    assert result["accepted"] is True
    assert result["target_dossiers"] == dossiers
    assert "selected_evidence" not in result


def test_semantic_batch_transport_pages_one_oversized_target_without_dropping_evidence(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setattr(plugin, "INTEGRATION_TRANSPORT_MAX_RESULT_BYTES", 2_400)
    run_id = "hdf-kb_sync-daily"
    target_ref = "products/platform-bionemo"
    evidence = [
        {
            "evidence_ref": "sha256:" + character * 64,
            "item": {"semantic_text": character * 700},
        }
        for character in ("a", "b", "c", "d")
    ]
    dossier = {
        "target_ref": target_ref,
        "object_digest": "sha256:" + "1" * 64,
        "dossier_digest": "sha256:" + "2" * 64,
        "evidence_refs": [row["evidence_ref"] for row in evidence],
        "evidence": evidence,
        "object_context": {"rendered": "current object context"},
    }
    ctx = FakePacketTransportContext()
    ctx.dispatch_result = {
        "result": {
            "schema_version": 1,
            "status": "awaiting_action",
            "run_id": run_id,
            "next_action": {
                "kind": "exercise_judgment",
                "action_index": 20,
                "semantic_stage": "target_integration",
                "instruction": "Synthesize one net result per target.",
                "response_schema": {"type": "object"},
                "semantic_accounting": {"progress": {"target_remaining_count": 1}},
            },
            "target_dossiers": {
                "requested_count": 1,
                "truncated": False,
                "items": [dossier],
            },
        }
    }

    plugin._register_integration_transport(ctx)
    offset_schema = ctx.registered_tools["kb_integration_transport"]["schema"]["parameters"][
        "properties"
    ]["target_evidence_offset"]
    assert offset_schema["minimum"] == 0
    handler = ctx.registered_tools["kb_integration_transport"]["handler"]
    offset = 0
    seen = []
    page_count = 0
    while True:
        request = {
            "operation": "semantic_batch",
            "run_id": run_id,
            "target_refs": [target_ref],
        }
        if offset:
            request["target_evidence_offset"] = offset
        result = json.loads(handler(request))
        page_count += 1
        assert result["accepted"] is True
        page_dossier = result["target_dossiers"]["items"][0]
        assert page_dossier["object_digest"] == dossier["object_digest"]
        assert page_dossier["dossier_digest"] == dossier["dossier_digest"]
        if offset == 0:
            assert result["next_action"]["response_schema"] == {"type": "object"}
            assert page_dossier["evidence_refs"] == dossier["evidence_refs"]
            assert page_dossier["object_context"] == dossier["object_context"]
        else:
            assert "next_action" not in result
            assert "evidence_refs" not in page_dossier
            assert "object_context" not in page_dossier
            assert result["target_dossiers"]["continuation"] is True
        assert len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= 2_400
        page = result["target_dossiers"]["page"]
        assert page["evidence_offset"] == offset
        page_evidence = result["target_dossiers"]["items"][0]["evidence"]
        assert page["evidence_count"] == len(page_evidence)
        seen.extend(page_evidence)
        if not page["has_more"]:
            break
        offset = page["next_evidence_offset"]

    assert seen == evidence
    assert ctx.calls == [
        (
            "mcp_kb_engine_prod_kb_sync_status",
            {"run_id": run_id, "target_refs": [target_ref]},
        )
    ] * page_count


def test_semantic_batch_transport_pages_one_oversized_target_evidence_body_losslessly(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setattr(plugin, "INTEGRATION_TRANSPORT_MAX_RESULT_BYTES", 2_500)
    run_id = "hdf-kb_sync-daily"
    target_ref = "projects/long-review"
    semantic_text = "target evidence β 🧬 " * 700
    evidence_ref = "sha256:" + "a" * 64
    dossier = {
        "target_ref": target_ref,
        "object_digest": "sha256:" + "1" * 64,
        "dossier_digest": "sha256:" + "2" * 64,
        "evidence_refs": [evidence_ref],
        "evidence": [
            {
                "evidence_ref": evidence_ref,
                "revision": "meeting-revision-1",
                "item": {
                    "semantic_text": semantic_text,
                    "transcript": semantic_text,
                    "subject": "Long target review",
                },
            }
        ],
        "object_context": {"rendered": "current object context"},
    }
    ctx = FakePacketTransportContext()
    ctx.dispatch_result = {
        "result": {
            "status": "awaiting_action",
            "run_id": run_id,
            "next_action": {
                "kind": "exercise_judgment",
                "semantic_stage": "target_integration",
                "response_schema": {"type": "object"},
            },
            "target_dossiers": {
                "requested_count": 1,
                "review_token": "sha256:" + "b" * 64,
                "digest": "sha256:" + "c" * 64,
                "items": [dossier],
            },
        }
    }

    plugin._register_integration_transport(ctx)
    registered = ctx.registered_tools["kb_integration_transport"]
    offset_schema = registered["schema"]["parameters"]["properties"][
        "target_evidence_text_offset"
    ]
    assert offset_schema["minimum"] == 0
    handler = registered["handler"]
    text_offset = 0
    seen = []
    while True:
        request = {
            "operation": "semantic_batch",
            "run_id": run_id,
            "target_refs": [target_ref],
        }
        if text_offset:
            request["target_evidence_offset"] = 0
            request["target_evidence_text_offset"] = text_offset
        result = json.loads(handler(request))
        assert result["accepted"] is True
        target_dossiers = result["target_dossiers"]
        assert target_dossiers["review_token"] == "sha256:" + "b" * 64
        row = target_dossiers["items"][0]
        assert row["object_digest"] == dossier["object_digest"]
        assert row["dossier_digest"] == dossier["dossier_digest"]
        if text_offset == 0:
            assert result["next_action"]["response_schema"] == {"type": "object"}
            assert row["evidence_refs"] == [evidence_ref]
            assert row["object_context"] == dossier["object_context"]
        else:
            assert "next_action" not in result
            assert "evidence_refs" not in row
            assert "object_context" not in row
            assert target_dossiers["continuation"] is True
        evidence = row["evidence"][0]
        assert evidence["evidence_ref"] == evidence_ref
        assert evidence["revision"] == "meeting-revision-1"
        assert evidence["item"]["subject"] == "Long target review"
        assert "transcript" not in evidence["item"]
        assert len(
            json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ) <= 2_500
        page = target_dossiers["page"]
        text_page = page["evidence_text_page"]
        assert page["evidence_offset"] == 0
        assert page["evidence_count"] == 1
        assert text_page["field"] == "semantic_text"
        assert text_page["text_offset"] == text_offset
        assert text_page["text_char_count"] == len(evidence["item"]["semantic_text"])
        assert text_page["text_total_chars"] == len(semantic_text)
        seen.append(evidence["item"]["semantic_text"])
        if not text_page["has_more"]:
            assert page["has_more"] is False
            break
        assert page["has_more"] is True
        assert page["next_evidence_offset"] == 0
        text_offset = text_page["next_text_offset"]

    assert "".join(seen) == semantic_text
    assert ctx.calls == [
        (
            "mcp_kb_engine_prod_kb_sync_status",
            {"run_id": run_id, "target_refs": [target_ref]},
        )
    ] * len(seen)


def test_semantic_batch_transport_pages_target_context_before_direct_evidence(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setattr(plugin, "INTEGRATION_TRANSPORT_MAX_RESULT_BYTES", 5_000)
    run_id = "hdf-kb_sync-daily"
    target_ref = "projects/bounded-review"
    evidence_ref = "sha256:" + "a" * 64
    semantic_text = "lossless evidence beta 🧬 " * 500
    recipient_metadata = [
        {"emailAddress": {"address": f"reviewer-{index}@example.invalid"}}
        for index in range(24)
    ]
    dossier = {
        "target_ref": target_ref,
        "object_digest": "sha256:" + "1" * 64,
        "dossier_digest": "sha256:" + "2" * 64,
        "evidence_refs": [evidence_ref],
        "evidence": [
            {
                "evidence_ref": evidence_ref,
                "item_digest": "sha256:" + "3" * 64,
                "source_id": "m365.email",
                "item": {
                    "semantic_text": semantic_text,
                    "subject": "Bounded review fixture",
                    "toRecipients": recipient_metadata,
                },
            }
        ],
        "object_context": {
            "context": "current target context " * 70,
            "current_state": {"state_summary": "durable state " * 40},
            "allowed_operations": [{"operation_id": "object.yaml.set"}],
        },
    }
    ctx = FakePacketTransportContext()
    ctx.dispatch_result = {
        "result": {
            "status": "awaiting_action",
            "run_id": run_id,
            "next_action": {
                "kind": "exercise_judgment",
                "semantic_stage": "target_integration",
                "response_schema": {"type": "object"},
            },
            "target_dossiers": {
                "requested_count": 1,
                "review_token": "sha256:" + "4" * 64,
                "digest": "sha256:" + "5" * 64,
                "items": [dossier],
            },
        }
    }

    plugin._register_integration_transport(ctx)
    handler = ctx.registered_tools["kb_integration_transport"]["handler"]
    context_page = json.loads(
        handler(
            {
                "operation": "semantic_batch",
                "run_id": run_id,
                "target_refs": [target_ref],
            }
        )
    )

    assert context_page["accepted"] is True
    context_dossiers = context_page["target_dossiers"]
    context_dossier = context_dossiers["items"][0]
    assert context_dossiers["review_token"] == "sha256:" + "4" * 64
    assert context_dossiers["digest"] == "sha256:" + "5" * 64
    assert context_dossier["object_digest"] == dossier["object_digest"]
    assert context_dossier["dossier_digest"] == dossier["dossier_digest"]
    assert context_dossier["evidence_refs"] == [evidence_ref]
    assert context_dossier["object_context"] == dossier["object_context"]
    assert context_dossier["evidence"] == []
    assert context_page["next_action"]["response_schema"] == {"type": "object"}
    assert context_dossiers["page"] == {
        "context_only": True,
        "judgment_ready": False,
        "evidence_offset": 0,
        "evidence_count": 0,
        "evidence_total_count": 1,
        "has_more": True,
        "next_evidence_offset": 0,
    }
    assert len(
        json.dumps(context_page, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    ) <= 5_000

    text_offset = 0
    seen = []
    while True:
        request = {
            "operation": "semantic_batch",
            "run_id": run_id,
            "target_refs": [target_ref],
            "target_evidence_offset": 0,
        }
        if text_offset:
            request["target_evidence_text_offset"] = text_offset
        evidence_page = json.loads(handler(request))
        assert evidence_page["accepted"] is True
        evidence_dossiers = evidence_page["target_dossiers"]
        evidence_dossier = evidence_dossiers["items"][0]
        assert evidence_dossiers["review_token"] == "sha256:" + "4" * 64
        assert evidence_dossiers["digest"] == "sha256:" + "5" * 64
        assert evidence_dossier["object_digest"] == dossier["object_digest"]
        assert evidence_dossier["dossier_digest"] == dossier["dossier_digest"]
        assert "evidence_refs" not in evidence_dossier
        assert "object_context" not in evidence_dossier
        assert "next_action" not in evidence_page
        assert evidence_dossiers["continuation"] is True
        evidence = evidence_dossier["evidence"][0]
        assert evidence["evidence_ref"] == evidence_ref
        assert evidence["item_digest"] == "sha256:" + "3" * 64
        assert evidence["item"]["toRecipients"] == recipient_metadata
        assert evidence["item"]["subject"] == "Bounded review fixture"
        assert len(
            json.dumps(
                evidence_page, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ) <= 5_000
        page = evidence_dossiers["page"]
        text_page = page["evidence_text_page"]
        assert page["evidence_offset"] == 0
        assert page["evidence_count"] == 1
        assert text_page["text_offset"] == text_offset
        assert text_page["text_total_chars"] == len(semantic_text)
        assert text_page["text_char_count"] == len(
            evidence["item"]["semantic_text"]
        )
        seen.append(evidence["item"]["semantic_text"])
        if not text_page["has_more"]:
            assert page["has_more"] is False
            break
        assert page["next_evidence_offset"] == 0
        text_offset = text_page["next_text_offset"]

    assert "".join(seen) == semantic_text
    assert "".join(seen).encode("utf-8") == semantic_text.encode("utf-8")
    assert ctx.calls == [
        (
            "mcp_kb_engine_prod_kb_sync_status",
            {"run_id": run_id, "target_refs": [target_ref]},
        )
    ] * (len(seen) + 1)


def test_semantic_batch_transport_pages_context_before_non_semantic_text_row(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setattr(plugin, "INTEGRATION_TRANSPORT_MAX_RESULT_BYTES", 6_000)
    run_id = "hdf-kb_sync-daily"
    target_ref = "projects/thread-review"
    evidence_ref = "sha256:" + "a" * 64
    second_evidence_ref = "sha256:" + "b" * 64
    evidence = {
        "evidence_ref": evidence_ref,
        "item_digest": "sha256:" + "3" * 64,
        "source_id": "slack.message",
        "item": {
            "text": "root message " * 160,
            "thread_replies": [
                {"text": "reply one " * 40},
                {"text": "reply two " * 40},
            ],
        },
    }
    second_evidence = {
        "evidence_ref": second_evidence_ref,
        "item_digest": "sha256:" + "6" * 64,
        "source_id": "slack.message",
        "item": {"text": "second exact message"},
    }
    dossier = {
        "target_ref": target_ref,
        "object_digest": "sha256:" + "1" * 64,
        "dossier_digest": "sha256:" + "2" * 64,
        "evidence_refs": [evidence_ref, second_evidence_ref],
        "evidence": [evidence, second_evidence],
        "object_context": {"context": "current object state " * 180},
    }
    ctx = FakePacketTransportContext()
    ctx.dispatch_result = {
        "result": {
            "status": "awaiting_action",
            "run_id": run_id,
            "next_action": {
                "kind": "exercise_judgment",
                "semantic_stage": "target_integration",
                "response_schema": {"type": "object"},
            },
            "target_dossiers": {
                "requested_count": 1,
                "review_token": "sha256:" + "4" * 64,
                "digest": "sha256:" + "5" * 64,
                "items": [dossier],
            },
        }
    }

    plugin._register_integration_transport(ctx)
    handler = ctx.registered_tools["kb_integration_transport"]["handler"]
    context_page = json.loads(
        handler(
            {
                "operation": "semantic_batch",
                "run_id": run_id,
                "target_refs": [target_ref],
            }
        )
    )
    assert context_page["accepted"] is True
    assert context_page["target_dossiers"]["page"]["context_only"] is True
    assert context_page["target_dossiers"]["page"]["judgment_ready"] is False
    assert context_page["target_dossiers"]["page"]["next_evidence_offset"] == 0
    assert context_page["target_dossiers"]["items"][0]["evidence"] == []
    assert len(
        json.dumps(context_page, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    ) <= 6_000

    evidence_page = json.loads(
        handler(
            {
                "operation": "semantic_batch",
                "run_id": run_id,
                "target_refs": [target_ref],
                # Presence is meaningful even though the exact offset is zero.
                "target_evidence_offset": 0,
            }
        )
    )
    assert evidence_page["accepted"] is True
    evidence_dossiers = evidence_page["target_dossiers"]
    evidence_dossier = evidence_dossiers["items"][0]
    assert evidence_dossiers["continuation"] is True
    assert evidence_dossier["object_digest"] == dossier["object_digest"]
    assert evidence_dossier["dossier_digest"] == dossier["dossier_digest"]
    assert evidence_dossier["evidence"] == [evidence, second_evidence]
    assert evidence_dossier["evidence"][0]["item_digest"] == evidence["item_digest"]
    assert evidence_dossier["evidence"][1]["item_digest"] == second_evidence[
        "item_digest"
    ]
    assert "object_context" not in evidence_dossier
    assert "evidence_refs" not in evidence_dossier
    assert evidence_dossiers["page"]["has_more"] is False
    assert len(
        json.dumps(evidence_page, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    ) <= 6_000
    assert len(ctx.calls) == 2


def test_semantic_batch_transport_fails_closed_when_target_context_page_is_oversized(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setattr(plugin, "INTEGRATION_TRANSPORT_MAX_RESULT_BYTES", 1_500)
    run_id = "hdf-kb_sync-daily"
    target_ref = "projects/irreducible-context"
    evidence_ref = "sha256:" + "a" * 64
    ctx = FakePacketTransportContext()
    ctx.dispatch_result = {
        "result": {
            "status": "awaiting_action",
            "run_id": run_id,
            "next_action": {
                "kind": "exercise_judgment",
                "semantic_stage": "target_integration",
                "response_schema": {"type": "object"},
            },
            "target_dossiers": {
                "requested_count": 1,
                "review_token": "sha256:" + "4" * 64,
                "items": [
                    {
                        "target_ref": target_ref,
                        "object_digest": "sha256:" + "1" * 64,
                        "dossier_digest": "sha256:" + "2" * 64,
                        "evidence_refs": [evidence_ref],
                        "evidence": [
                            {
                                "evidence_ref": evidence_ref,
                                "item_digest": "sha256:" + "3" * 64,
                                "item": {"semantic_text": "bounded evidence"},
                            }
                        ],
                        "object_context": {"context": "state " * 1_000},
                    }
                ],
            },
        }
    }

    plugin._register_integration_transport(ctx)
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "semantic_batch",
                "run_id": run_id,
                "target_refs": [target_ref],
            }
        )
    )

    assert result == {
        "accepted": False,
        "run_id": run_id,
        "requested_count": 1,
        "selected_count": 1,
        "error": "one target review context page exceeds the bounded transport result",
    }
    assert len(ctx.calls) == 1


@pytest.mark.parametrize(
    ("selector", "target_offset", "text_offset"),
    [
        ({"evidence_refs": ["sha256:" + "a" * 64]}, 0, 0),
        ({"target_refs": ["projects/a", "projects/b"]}, 0, 0),
        ({"target_refs": ["projects/a"]}, None, 1),
        ({"target_refs": ["projects/a"]}, 0, True),
        ({"target_refs": ["projects/a"]}, 0, -1),
    ],
)
def test_semantic_batch_transport_rejects_invalid_target_evidence_text_offset(
    tmp_path, monkeypatch, selector, target_offset, text_offset
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)
    request = {
        "operation": "semantic_batch",
        "run_id": "hdf-kb_sync-daily",
        **selector,
        "target_evidence_text_offset": text_offset,
    }
    if target_offset is not None:
        request["target_evidence_offset"] = target_offset

    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](request)
    )

    assert result["accepted"] is False
    assert ctx.calls == []
    assert "target_evidence_text_offset" in result["error"]


def _managed_calendar_plan(run_id, entity_path):
    return {
        "schema_version": 1,
        "kind": "managed_calendar_plan",
        "policy_scope": "kb_managed_event_travel_v1",
        "run_id": run_id,
        "entity_path": entity_path,
        "desired_set_complete": True,
        "source_reads": {
            "tripit_complete": True,
            "calendar_complete": True,
            "tripit_digest": "sha256:" + "a" * 64,
            "calendar_digest": "sha256:" + "b" * 64,
        },
        "artifacts": [],
    }


def _managed_calendar_closeout(
    plugin,
    run_id,
    *,
    planned=0,
    applied=0,
    kept=0,
):
    closeout = {
        "schema_version": 1,
        "kind": "managed_calendar_closeout",
        "run_id": run_id,
        "status": "not_required" if planned == 0 else "completed",
        "ok": True,
        "source_reads": {"tripit_complete": True, "calendar_complete": True},
        "counts": {
            "planned": planned,
            "applied": applied,
            "kept": kept,
            "read_back": applied,
            "recorded": applied,
            "held": 0,
            "failed": 0,
            "pending": 0,
        },
    }
    closeout["receipt_digest"] = plugin._managed_closeout_digest(closeout)
    return closeout


def _calendar_live_success(envelope, closeout):
    return {
        "schema_version": 1,
        "kind": "calendar_live_executor_receipt",
        "status": "completed",
        "ok": True,
        "run_id": envelope["run_id"],
        "plan_digest": envelope["plan_digest"],
        "closeout": closeout,
    }


@pytest.mark.parametrize(
    ("sync_status", "degradations"),
    [
        ("completed", []),
        (
            "completed_with_degradation",
            [
                {
                    "source_id": "m365.email",
                    "reason_code": "source_content_insufficient",
                    "retryable": False,
                    "source_insufficient_count": 2,
                }
            ],
        ),
    ],
)
def test_daily_integration_closeout_composes_calendar_publication_and_brief(
    sync_status, degradations, tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    run_id = "hdf-kb_sync-daily"
    closeout = _managed_calendar_closeout(
        plugin,
        run_id,
        planned=2,
        applied=1,
        kept=1,
    )

    def calendar_live_request(envelope, mode="execute"):
        assert mode == "execute"
        return _calendar_live_success(envelope, closeout)

    monkeypatch.setattr(plugin, "_calendar_live_request", calendar_live_request)
    sync = {
        "kind": "kb_sync_receipt",
        "status": sync_status,
        "terminal_state": sync_status,
        "run_id": run_id,
        "degradations": degradations,
        "source_currency": {
            "sources": [
                {"source_id": source_id, "state": "current"}
                for source_id in ("mail", "calendar", "slack", "meetings", "tripit")
            ]
        },
        "semantic_accounting": {
            "complete": True,
            "remaining_count": 0,
            "integrated_target_count": 3,
        },
        "lifecycle": {"status": "fixed_point"},
    }
    preview = {
        "ok": True,
        "status": "ready",
        "preview_digest": "sha256:" + "d" * 64,
    }
    publication = {
        "ok": True,
        "status": "published",
        "session_id": "hermes-cron-daily",
        "readback": {"ok": True, "clean": True, "ahead": 0},
    }
    ctx = FakePacketTransportContext()
    ctx.dispatch_result = {"result": sync}
    responses = iter((sync, preview, publication))

    def dispatch(tool_name, args):
        ctx.calls.append((tool_name, args))
        return json.dumps({"result": next(responses)})

    ctx.dispatch_tool = dispatch
    plugin._register_integration_transport(ctx)
    envelope = {
        "schema_version": 1,
        "kind": "managed_calendar_plan",
        "policy_scope": "kb_managed_event_travel_v1",
        "run_id": run_id,
        "entity_path": "events/demo",
        "source_reads": {"tripit_complete": True, "calendar_complete": True},
        "artifacts": [],
    }
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "daily_integration_closeout",
                "run_id": run_id,
                "calendar_envelope": envelope,
            },
            session_id="hermes-cron-daily",
        )
    )

    assert result["accepted"] is True and result["complete"] is True
    assert result["stages"] == {
        "integration": "completed",
        "calendar": "completed",
        "publication": "published",
    }
    assert "Evidence: 5/5 sources current." in result["morning_brief"]
    assert "KB: 3 targets integrated" in result["morning_brief"]
    assert result["execution_session_binding"] == {
        "kind": "hermes_runtime_execution_session_binding",
        "source": "runtime_dispatch",
        "session_sha256": "sha256:"
        + hashlib.sha256(b"hermes-cron-daily").hexdigest(),
    }
    assert result["publication"]["session_binding"] == {
        "kind": "daily_integration_publication_session_binding",
        "source": "kb_engine_publication_receipt",
        "session_sha256": "sha256:"
        + hashlib.sha256(b"hermes-cron-daily").hexdigest(),
        "idempotent_replay": False,
    }
    assert len(plugin._descriptor_allowlist()) + len(ctx.registered_tools) <= 14
    assert [name for name, _args in ctx.calls] == [
        "mcp_kb_engine_prod_kb_sync_status",
        "mcp_kb_engine_prod_publication_daily_integration_preview",
        "mcp_kb_engine_prod_publication_daily_integration_apply",
    ]
    apply_args = ctx.calls[-1][1]
    aggregate = apply_args["calendar_receipt"]
    assert aggregate["counts"] == closeout["counts"]
    prepared_envelope = dict(envelope)
    prepared_envelope["plan_digest"] = plugin._managed_plan_digest(prepared_envelope)
    assert aggregate["batch_digest"] == plugin._calendar_batch_digest(
        [prepared_envelope]
    )
    assert aggregate["child_receipts"] == [
        {
            "plan_digest": prepared_envelope["plan_digest"],
            "receipt_digest": closeout["receipt_digest"],
        }
    ]
    assert aggregate["receipt_digest"] == plugin._managed_closeout_digest(aggregate)
    assert apply_args["session_id"] == "hermes-cron-daily"

    responses = iter((sync, preview, publication))
    fresh_mismatch = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "daily_integration_closeout",
                "run_id": run_id,
                "calendar_envelope": envelope,
            },
            session_id="hermes-cron-other",
        )
    )
    assert fresh_mismatch["accepted"] is False
    assert fresh_mismatch["stage"] == "publication_apply"
    assert fresh_mismatch["error"] == "publication session binding is invalid"
    assert fresh_mismatch["execution_session_binding"] == {
        "kind": "hermes_runtime_execution_session_binding",
        "source": "runtime_dispatch",
        "session_sha256": "sha256:"
        + hashlib.sha256(b"hermes-cron-other").hexdigest(),
    }
    assert "hermes-cron-daily" not in json.dumps(fresh_mismatch)
    assert "hermes-cron-other" not in json.dumps(fresh_mismatch)


def _eligible_daily_sync(run_id):
    return {
        "kind": "kb_sync_receipt",
        "status": "completed",
        "terminal_state": "completed",
        "run_id": run_id,
        "degradations": [],
        "source_currency": {
            "sources": [
                {"source_id": source_id, "state": "current"}
                for source_id in ("mail", "calendar", "slack", "meetings", "tripit")
            ]
        },
        "semantic_accounting": {
            "complete": True,
            "remaining_count": 0,
            "integrated_target_count": 4,
        },
        "lifecycle": {"status": "fixed_point"},
    }


def _noc_batch_success(plugin, envelopes, closeouts):
    observation = {
        "schema_version": 1,
        "kind": "managed_calendar_terminal_observation",
        "pre_execution_owned_count": 3,
        "final_owned_count": 4,
        "final_owned_calendar_digest": "sha256:" + "c" * 64,
        "attendee_violation_count": 0,
        "event_type_violation_count": 0,
    }
    result = {
        "schema_version": 1,
        "kind": "calendar_live_batch_executor_receipt",
        "status": "completed",
        "ok": True,
        "run_id": envelopes[0]["run_id"],
        "batch_digest": plugin._calendar_batch_digest(envelopes),
        "total_count": len(envelopes),
        "completed_count": len(envelopes),
        "receipts": [
            {"plan_digest": envelope["plan_digest"], "closeout": closeout}
            for envelope, closeout in zip(envelopes, closeouts, strict=True)
        ],
        "side_effect_state": "complete",
        "aggregate_safety": {
            "allowed": True,
            "owned_count": 3,
            "pre_execution_owned_count": 3,
        },
        "calendar_observation": observation,
    }
    result["receipt_digest"] = plugin._managed_closeout_digest(result)
    return result


def _noc_batch_ack(plugin, envelopes, *, removed=True, compacted=True):
    result = {
        "schema_version": 1,
        "kind": "calendar_live_batch_acknowledgement",
        "status": "acknowledged",
        "ok": True,
        "run_id": envelopes[0]["run_id"],
        "batch_digest": plugin._calendar_batch_digest(envelopes),
        "connector_progress_removed": removed,
        "recovery_compacted": compacted,
    }
    result["receipt_digest"] = plugin._managed_closeout_digest(result)
    return result


def test_daily_integration_persists_engine_effect_publication_and_final_receipt(
    tmp_path, monkeypatch
):
    from kb_engine.api import integration_run

    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setattr(
        plugin,
        "_legacy_daily_integration_closeout_serial",
        lambda *_args, **_kwargs: pytest.fail("legacy closeout must not run"),
    )
    monkeypatch.setattr(
        plugin,
        "_legacy_aggregate_calendar_closeouts",
        lambda *_args, **_kwargs: pytest.fail("legacy aggregation must not run"),
    )

    run_id = "hdf-kb_sync-engine-owned-closeout"
    recipe = integration_run.compile_recipe(
        [],
        observed_at="2026-07-10T00:00:00Z",
        external_effects=[plugin.CALENDAR_INTEGRATION_EFFECT_ID],
        publication_posture="required",
    )
    run_model = integration_run.new_run(
        run_id,
        recipe,
        actor="hermes-relay",
        session_id="hermes-runtime-session",
    )
    run_model = integration_run.advance(
        run_model,
        recipe=recipe,
        completed_stage="exercise_judgment",
        result={"semantic_accounting_digest": "sha256:" + "a" * 64},
    )
    run_model = integration_run.advance(
        run_model,
        recipe=recipe,
        completed_stage="project_evidence",
        result={"evidence_receipt_digest": "sha256:" + "b" * 64},
    )
    initial = {
        "schema_version": 1,
        "kind": "kb_sync_run",
        "status": "awaiting_action",
        "run_id": run_id,
        "recipe_digest": recipe["digest"],
        "integration_stage": "execute_external_effect",
        "next_action": {
            "kind": "execute_external_effect",
            "integration_stage": "execute_external_effect",
            "run_id": run_id,
            "recipe_digest": recipe["digest"],
            "effect_ids": [plugin.CALENDAR_INTEGRATION_EFFECT_ID],
            "response_kind": "kb.integration.effect_results",
        },
    }
    raw_plan = _managed_calendar_plan(run_id, "events/engine-owned-closeout")
    child_closeout = _managed_calendar_closeout(
        plugin,
        run_id,
        planned=2,
        applied=1,
        kept=1,
    )
    events = []
    terminal_packet = None
    effect_packet = None

    def calendar_batch(envelopes):
        events.append("calendar_batch")
        return _noc_batch_success(plugin, envelopes, [child_closeout])

    monkeypatch.setattr(plugin, "_calendar_live_batch_request", calendar_batch)
    monkeypatch.setattr(
        plugin,
        "_calendar_live_batch_acknowledge",
        lambda envelopes: events.append("calendar_ack")
        or _noc_batch_ack(plugin, envelopes),
    )

    preview = {
        "ok": True,
        "status": "ready",
        "preview_digest": "sha256:" + "d" * 64,
    }
    publication_receipt = {
        "ok": True,
        "status": "published",
        "session_id": "hermes-runtime-session",
        "readback": {"ok": True, "clean": True, "ahead": 0},
    }
    ctx = FakePacketTransportContext()

    def dispatch(tool_name, args):
        nonlocal run_model, terminal_packet, effect_packet
        ctx.calls.append((tool_name, args))
        if tool_name.endswith("kb_sync_status"):
            payload = terminal_packet or initial
        elif tool_name.endswith("publication_daily_integration_preview"):
            payload = preview
        elif tool_name.endswith("publication_daily_integration_apply"):
            payload = publication_receipt
        elif tool_name.endswith("kb_sync_resume"):
            response = args["response"]
            if response.get("kind") == "kb.integration.effect_results":
                assert integration_run.validate_effect_results(
                    response,
                    run=run_model,
                    recipe=recipe,
                )["ok"] is True
                effect_packet = response
                acknowledgement = integration_run.effect_acknowledgement(
                    response,
                    run=run_model,
                    recipe=recipe,
                )
                run_model = integration_run.advance(
                    run_model,
                    recipe=recipe,
                    completed_stage="execute_external_effect",
                    result=response,
                )
                run_model = integration_run.advance(
                    run_model,
                    recipe=recipe,
                    completed_stage="record_effect",
                    result=acknowledgement,
                )
                payload = {
                    "schema_version": 1,
                    "kind": "kb_sync_run",
                    "status": "awaiting_action",
                    "run_id": run_id,
                    "recipe_digest": recipe["digest"],
                    "integration_stage": "publish",
                    "next_action": {
                        "kind": "publish_integration",
                        "integration_stage": "publish",
                        "run_id": run_id,
                        "recipe_digest": recipe["digest"],
                        "publication_posture": "required",
                        "response_kind": "kb.integration.publication_result",
                    },
                }
            else:
                assert integration_run.validate_publication_result(
                    response,
                    run=run_model,
                    recipe=recipe,
                )["ok"] is True
                run_model = integration_run.advance(
                    run_model,
                    recipe=recipe,
                    completed_stage="publish",
                    result=response,
                )
                final_receipt = integration_run.final_receipt(
                    run_model,
                    recipe=recipe,
                    terminal_status="completed",
                )
                terminal_packet = {
                    "schema_version": 1,
                    "kind": "kb_sync_receipt",
                    "status": "completed",
                    "terminal_state": "completed",
                    "run_id": run_id,
                    "degradations": [],
                    "semantic_final_receipt": final_receipt,
                    "external_effects": effect_packet,
                    "publication": response,
                    "source_currency": {"sources": []},
                    "semantic_accounting": {
                        "complete": True,
                        "remaining_count": 0,
                        "integrated_target_count": 4,
                    },
                    "lifecycle": {"status": "fixed_point"},
                }
                payload = terminal_packet
        else:
            raise AssertionError(tool_name)
        return json.dumps({"result": payload})

    ctx.dispatch_tool = dispatch
    plugin._register_integration_transport(ctx)
    handler = ctx.registered_tools["kb_integration_transport"]["handler"]
    request = {
        "operation": "daily_integration_closeout",
        "run_id": run_id,
        "calendar_envelopes": [raw_plan],
    }
    result = json.loads(handler(request, session_id="hermes-runtime-session"))

    assert result["accepted"] is True and result["complete"] is True
    assert result["semantic_owner"] == "kb-engine"
    assert result["integration_receipt"]["kind"] == "kb.integration.final_receipt"
    assert result["integration_summary"]["complete"] is True
    assert result["calendar"]["counts"] == child_closeout["counts"]
    assert effect_packet["results"][0]["result"]["kind"] == "managed_calendar_closeout"
    assert events == ["calendar_batch", "calendar_ack"]
    assert [name for name, _args in ctx.calls] == [
        "mcp_kb_engine_prod_kb_sync_status",
        "mcp_kb_engine_prod_kb_sync_resume",
        "mcp_kb_engine_prod_publication_daily_integration_preview",
        "mcp_kb_engine_prod_publication_daily_integration_apply",
        "mcp_kb_engine_prod_kb_sync_resume",
    ]

    calls_before_replay = len(ctx.calls)
    events.clear()
    replay = json.loads(handler(request, session_id="hermes-runtime-replay"))
    assert replay["accepted"] is True and replay["idempotent_replay"] is True
    assert replay["integration_receipt"] == result["integration_receipt"]
    assert events == ["calendar_ack"]
    assert [name for name, _args in ctx.calls[calls_before_replay:]] == [
        "mcp_kb_engine_prod_kb_sync_status"
    ]


def test_calendar_batch_result_dual_reads_legacy_without_terminal_observation(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    run_id = "hdf-kb_sync-legacy-observation"
    envelope = _managed_calendar_plan(run_id, "events/legacy-observation")
    envelope["plan_digest"] = plugin._managed_plan_digest(envelope)
    closeout = _managed_calendar_closeout(plugin, run_id)
    result = _noc_batch_success(plugin, [envelope], [closeout])
    result.pop("calendar_observation")
    result["aggregate_safety"].pop("pre_execution_owned_count")
    result["receipt_digest"] = plugin._managed_closeout_digest(result)

    closeouts, observation, error = plugin._validated_calendar_batch_result(
        result,
        envelopes=[envelope],
        run_id=run_id,
    )

    assert error == ""
    assert closeouts == [closeout]
    assert observation is None


def test_calendar_batch_result_rejects_new_safety_without_terminal_observation(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    run_id = "hdf-kb_sync-missing-observation"
    envelope = _managed_calendar_plan(run_id, "events/missing-observation")
    envelope["plan_digest"] = plugin._managed_plan_digest(envelope)
    closeout = _managed_calendar_closeout(plugin, run_id)
    result = _noc_batch_success(plugin, [envelope], [closeout])
    result.pop("calendar_observation")
    result["receipt_digest"] = plugin._managed_closeout_digest(result)

    closeouts, observation, error = plugin._validated_calendar_batch_result(
        result,
        envelopes=[envelope],
        run_id=run_id,
    )

    assert closeouts == [] and observation is None
    assert error == "managed calendar terminal observation is missing"


def test_morning_brief_keeps_attendee_and_type_violation_dimensions_separate(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    brief = plugin._daily_integration_morning_brief(
        {
            "source_currency": {"sources": []},
            "semantic_accounting": {},
            "lifecycle": {},
        },
        {
            "counts": {"applied": 0, "kept": 1},
            "calendar_observation": {
                "final_owned_count": 2,
                "attendee_violation_count": 1,
                "event_type_violation_count": 1,
            },
        },
        {"status": "noop"},
    )

    assert "2 managed events verified, 1 attendee / 1 type violations" in brief


def test_daily_integration_multi_envelope_uses_one_protected_batch_and_one_publication(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    run_id = "hdf-kb_sync-multi"
    raw_envelopes = [
        _managed_calendar_plan(run_id, "events/travel-one"),
        _managed_calendar_plan(run_id, "events/archive/travel-two"),
    ]
    envelopes = []
    for raw in raw_envelopes:
        envelope = dict(raw)
        envelope["plan_digest"] = plugin._managed_plan_digest(envelope)
        envelopes.append(envelope)
    closeouts = [
        _managed_calendar_closeout(plugin, run_id, planned=2, applied=1, kept=1),
        _managed_calendar_closeout(plugin, run_id, planned=3, applied=2, kept=1),
    ]
    events = []

    def batch_request(values):
        events.append("calendar_batch")
        assert [value["plan_digest"] for value in values] == [
            value["plan_digest"] for value in envelopes
        ]
        return _noc_batch_success(plugin, values, closeouts)

    monkeypatch.setattr(plugin, "_calendar_live_batch_request", batch_request)
    monkeypatch.setattr(
        plugin,
        "_calendar_live_request",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("single path used")),
    )
    monkeypatch.setattr(
        plugin,
        "_calendar_live_batch_acknowledge",
        lambda values: events.append("calendar_ack") or _noc_batch_ack(plugin, values),
    )
    sync = _eligible_daily_sync(run_id)
    preview = {"ok": True, "status": "ready", "preview_digest": "sha256:" + "d" * 64}
    publication = {
        "ok": True,
        "status": "published",
        "session_id": "hermes-cron-multi",
        "readback": {"ok": True, "clean": True, "ahead": 0},
    }
    responses = iter((sync, preview, publication))
    ctx = FakePacketTransportContext()

    def dispatch(tool_name, args):
        ctx.calls.append((tool_name, args))
        events.append(tool_name)
        return json.dumps({"result": next(responses)})

    ctx.dispatch_tool = dispatch
    plugin._register_integration_transport(ctx)
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "daily_integration_closeout",
                "run_id": run_id,
                "calendar_envelopes": raw_envelopes,
            },
            session_id="hermes-cron-multi",
        )
    )

    assert result["accepted"] is True and result["complete"] is True
    assert result["calendar"]["entity_count"] == 2
    assert result["calendar"]["calendar_observation"] == {
        "schema_version": 1,
        "kind": "managed_calendar_terminal_observation",
        "pre_execution_owned_count": 3,
        "final_owned_count": 4,
        "final_owned_calendar_digest": "sha256:" + "c" * 64,
        "attendee_violation_count": 0,
        "event_type_violation_count": 0,
    }
    assert "4 managed events verified, 0 attendee / 0 type violations" in result["morning_brief"]
    assert result["calendar"]["counts"] == {
        "planned": 5,
        "applied": 3,
        "kept": 2,
        "read_back": 3,
        "recorded": 3,
        "held": 0,
        "failed": 0,
        "pending": 0,
    }
    assert events == [
        "mcp_kb_engine_prod_kb_sync_status",
        "calendar_batch",
        "mcp_kb_engine_prod_publication_daily_integration_preview",
        "mcp_kb_engine_prod_publication_daily_integration_apply",
        "calendar_ack",
    ]
    aggregate = ctx.calls[-1][1]["calendar_receipt"]
    assert aggregate["batch_digest"] == plugin._calendar_batch_digest(envelopes)
    assert aggregate["child_receipts"] == [
        {
            "plan_digest": envelope["plan_digest"],
            "receipt_digest": child["receipt_digest"],
        }
        for envelope, child in zip(envelopes, closeouts, strict=True)
    ]
    assert aggregate["calendar_observation"] == result["calendar"]["calendar_observation"]
    assert aggregate["receipt_digest"] == plugin._managed_closeout_digest(aggregate)

    events.clear()
    replay_publication = {
        **publication,
        "idempotent_replay": True,
    }
    responses = iter((sync, preview, replay_publication))
    replay = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "daily_integration_closeout",
                "run_id": run_id,
                "calendar_envelopes": raw_envelopes,
            },
            session_id="hermes-cron-multi-recovery",
        )
    )

    assert replay["accepted"] is True and replay["complete"] is True
    assert replay["execution_session_binding"] == {
        "kind": "hermes_runtime_execution_session_binding",
        "source": "runtime_dispatch",
        "session_sha256": "sha256:"
        + hashlib.sha256(b"hermes-cron-multi-recovery").hexdigest(),
    }
    assert replay["publication"]["session_binding"] == {
        "kind": "daily_integration_publication_session_binding",
        "source": "kb_engine_publication_receipt",
        "session_sha256": "sha256:"
        + hashlib.sha256(b"hermes-cron-multi").hexdigest(),
        "idempotent_replay": True,
    }
    assert events == [
        "mcp_kb_engine_prod_kb_sync_status",
        "calendar_batch",
        "mcp_kb_engine_prod_publication_daily_integration_preview",
        "mcp_kb_engine_prod_publication_daily_integration_apply",
        "calendar_ack",
    ]
    assert ctx.calls[-1][1]["session_id"] == "hermes-cron-multi-recovery"
    assert "hermes-cron-multi" not in json.dumps(replay)
    assert "hermes-cron-multi-recovery" not in json.dumps(replay)


def test_calendar_aggregate_not_required_binds_canonical_empty_provenance(
    tmp_path, monkeypatch
) -> None:
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    run_id = "hdf-kb_sync-empty"
    envelopes = []
    closeouts = []
    for index in (1, 2):
        envelope = _managed_calendar_plan(run_id, f"events/empty-{index}")
        envelope["plan_digest"] = plugin._managed_plan_digest(envelope)
        envelopes.append(envelope)
        closeouts.append(_managed_calendar_closeout(plugin, run_id))

    aggregate = plugin._aggregate_calendar_closeouts(
        closeouts,
        envelopes=envelopes,
        run_id=run_id,
    )

    assert aggregate["status"] == "not_required"
    assert aggregate["child_receipts"] == []
    assert aggregate["batch_digest"] == (
        plugin._engine_calendar_contracts().calendar_batch_digest(
            [], run_id=run_id
        )
    )
    assert aggregate["receipt_digest"] == plugin._managed_closeout_digest(aggregate)


def test_daily_integration_batch_uncertainty_stops_before_publication(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    run_id = "hdf-kb_sync-multi"
    raw = [
        _managed_calendar_plan(run_id, "events/travel-one"),
        _managed_calendar_plan(run_id, "events/travel-two"),
    ]

    def batch_request(values):
        result = {
            "schema_version": 1,
            "kind": "calendar_live_batch_executor_receipt",
            "status": "partial",
            "ok": False,
            "run_id": run_id,
            "batch_digest": plugin._calendar_batch_digest(values),
            "total_count": 2,
            "completed_count": 0,
            "receipts": [],
            "side_effect_state": "uncertain",
            "reason_code": "graph_execution_failed",
            "reason": "retry exact batch",
            "uncertain_plan_digest": values[1]["plan_digest"],
        }
        result["receipt_digest"] = plugin._managed_closeout_digest(result)
        return result

    monkeypatch.setattr(plugin, "_calendar_live_batch_request", batch_request)
    monkeypatch.setattr(
        plugin,
        "_calendar_live_batch_acknowledge",
        lambda values: (_ for _ in ()).throw(AssertionError("ack must not run")),
    )
    ctx = FakePacketTransportContext()
    ctx.dispatch_result = {"result": _eligible_daily_sync(run_id)}
    plugin._register_integration_transport(ctx)
    result = json.loads(
        ctx.registered_tools["kb_integration_transport"]["handler"](
            {
                "operation": "daily_integration_closeout",
                "run_id": run_id,
                "calendar_envelopes": raw,
            },
            session_id="hermes-cron-multi",
        )
    )

    assert result["accepted"] is False and result["stage"] == "calendar_execution"
    assert result["error"] == "graph_execution_failed"
    assert [name for name, _args in ctx.calls] == ["mcp_kb_engine_prod_kb_sync_status"]


def test_daily_integration_batch_schema_and_identity_gates(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)
    parameters = ctx.registered_tools["kb_integration_transport"]["schema"]["parameters"]
    batch = parameters["properties"]["calendar_envelopes"]
    assert batch["minItems"] == 1 and batch["maxItems"] == 50
    assert "unbound TripIt anchor" in batch["description"]
    assert "never mint a synthetic Event path" in batch["description"]
    closeout_variant = next(
        variant
        for variant in parameters["oneOf"]
        if variant["properties"]["operation"].get("const") == "daily_integration_closeout"
    )
    assert len(closeout_variant["oneOf"]) == 2
    assert "session_id" not in parameters["properties"]
    assert closeout_variant["required"] == ["run_id"]

    run_id = "hdf-kb_sync-multi"
    first = _managed_calendar_plan(run_id, "events/travel-one")
    alias = _managed_calendar_plan(run_id, "events/archive/travel-one")
    envelopes, error = plugin._calendar_closeout_envelopes(
        {"calendar_envelopes": [first, alias]}, run_id=run_id
    )
    assert envelopes == [] and "complete single-entity" in error

    second = _managed_calendar_plan(run_id, "events/travel-two")
    second["source_reads"]["calendar_digest"] = "sha256:" + "c" * 64
    envelopes, error = plugin._calendar_closeout_envelopes(
        {"calendar_envelopes": [first, second]}, run_id=run_id
    )
    assert envelopes == [] and "same complete source reads" in error

    nonempty = _managed_calendar_plan(run_id, "events/travel-three")
    nonempty["artifacts"] = [{"events": []}]
    nonempty.pop("desired_set_complete")
    envelopes, error = plugin._calendar_closeout_envelopes(
        {"calendar_envelopes": [nonempty]}, run_id=run_id
    )
    assert envelopes == [] and "complete single-entity plan" in error


def test_daily_integration_closeout_binds_runtime_session_not_model_argument(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    captured = {}

    def closeout(_ctx, args, *, run_id):
        captured.update(args)
        return {"accepted": True, "complete": True, "run_id": run_id}

    monkeypatch.setattr(plugin, "_daily_integration_closeout", closeout)
    ctx = FakePacketTransportContext()
    plugin._register_integration_transport(ctx)
    handler = ctx.registered_tools["kb_integration_transport"]["handler"]

    missing = json.loads(
        handler(
            {
                "operation": "daily_integration_closeout",
                "run_id": "hdf-kb_sync-runtime",
                "calendar_envelopes": [{}],
            }
        )
    )
    assert missing == {
        "accepted": False,
        "retryable": False,
        "run_id": "hdf-kb_sync-runtime",
        "error": "runtime session id is unavailable",
        "error_code": "runtime_session_unavailable",
    }

    result = json.loads(
        handler(
            {
                "operation": "daily_integration_closeout",
                "run_id": "hdf-kb_sync-runtime",
                "session_id": "model-forged-session",
                "calendar_envelopes": [{}],
            },
            session_id="cron_job-1_20260710_170020",
        )
    )
    assert captured["session_id"] == "cron_job-1_20260710_170020"
    assert result["execution_session_binding"] == {
        "kind": "hermes_runtime_execution_session_binding",
        "source": "runtime_dispatch",
        "session_sha256": "sha256:"
        + hashlib.sha256(b"cron_job-1_20260710_170020").hexdigest(),
    }

@pytest.mark.parametrize(
    "degradation",
    [
        {
            "source_id": "travel.tripit",
            "reason_code": "source_transport_failed",
            "retryable": True,
        },
        {
            "source_id": "m365.email",
            "reason_code": "source_content_insufficient",
            "retryable": True,
            "source_insufficient_count": 1,
        },
        {
            "source_id": "m365.email",
            "reason_code": "source_content_insufficient",
            "retryable": False,
            "source_insufficient_count": "unknown",
        },
    ],
)
def test_daily_integration_closeout_rejects_source_level_degradation(
    degradation, tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    packet = {
        "status": "completed_with_degradation",
        "terminal_state": "completed_with_degradation",
        "degradations": [degradation],
        "source_currency": {"sources": [{"state": "current"}]},
        "semantic_accounting": {"complete": True, "remaining_count": 0},
        "lifecycle": {"status": "fixed_point"},
    }

    assert plugin._daily_integration_closeout_eligible(packet) is False


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


def test_kb_help_exposes_publication_as_a_primary_verb(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)

    card = plugin._kb_command_help()
    text = card["text"]

    assert "/kb status" in text
    assert "/kb sync" in text
    assert "/kb review" in text
    assert "/kb queue" not in text
    assert "/kb publish" in text


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
    assert source["engine_version"] == "0.46.0"
    assert source["engine_source_revision"] == "28caa373f17e2be5a75016862b5119dbf6faca3c"
    assert source["digest"].startswith("sha256:")
    assert source["engine_version"]
    assert len(source["tools"]) == 13
    serialized = json.dumps(source, sort_keys=True)
    assert "kb_sync.preview" not in serialized
    assert "kb_sync.confirmed" not in serialized
    assert "update_kb" not in serialized
    assert {"kb.sync.prepare", "kb.sync.status", "kb.sync.resume"} <= {
        tool["name"] for tool in source["tools"]
    }
    assert {
        "publication.preview_commit",
        "publication.commit_confirmed",
        "publication.daily_integration_preview",
        "publication.daily_integration_apply",
    } <= {tool["name"] for tool in source["tools"]}
    assert next(
        row for row in source["journeys"] if row["journey_id"] == "kb_sync"
    )["confirmation_required"] is False
    assert plugin._DESCRIPTOR_BUNDLE == source
    assert plugin._DESCRIPTOR_ERROR == ""
    assert len(plugin._descriptor_allowlist()) == 13


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


def test_required_property_refinement_anyof_branches_remain_enforced(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    schema = {
        "type": "object",
        "properties": {
            "a": {"type": "array", "items": {"type": "string"}, "maxItems": 2},
            "b": {"type": "array", "items": {"type": "string"}, "maxItems": 2},
        },
        "anyOf": [
            {"properties": {"a": {"minItems": 1}}, "required": ["a"]},
            {"properties": {"b": {"minItems": 1}}, "required": ["b"]},
        ],
        "additionalProperties": False,
    }
    plugin._validate_schema(schema)
    assert plugin._runtime_schema_error({}, schema) is not None
    assert plugin._runtime_schema_error({"a": []}, schema) is not None
    assert plugin._runtime_schema_error({"b": []}, schema) is not None
    assert plugin._runtime_schema_error({"a": ["ready"]}, schema) is None
    assert plugin._runtime_schema_error({"b": ["ready"]}, schema) is None


def test_required_property_refinement_branch_cannot_target_another_field(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    schema = {
        "type": "object",
        "properties": {
            "a": {"type": "array", "items": {"type": "string"}},
            "b": {"type": "array", "items": {"type": "string"}},
        },
        "anyOf": [
            {"properties": {"b": {"minItems": 1}}, "required": ["a"]},
        ],
        "additionalProperties": False,
    }
    with pytest.raises(ValueError, match="invalid|required|unconstrained|no type"):
        plugin._validate_schema(schema)


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


def test_runtime_rejects_more_than_thirteen_generated_tools(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setattr(
        plugin,
        "_DESCRIPTOR_TOOLS",
        {f"tool.{index}": {"name": f"tool.{index}"} for index in range(14)},
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
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "reinstalling that `previous_ref`" in readme
    assert "Removing or renaming" in readme
    assert "bundled fallback" not in readme.lower()
    assert manifest["version"] == "0.11.0"
    assert project["project"]["version"] == manifest["version"]
    assert manifest["migrations"][-1]["version"] == "0.11.0"
    assert "packet_transport" in readme
    assert "deprecated compatibility branch" in readme
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
        == "28caa373f17e2be5a75016862b5119dbf6faca3c"
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

    candidate_job = workflow["jobs"]["engine-candidate-contract"]
    assert (
        candidate_job["env"]["KB_ENGINE_CANDIDATE_REF"]
        == "28caa373f17e2be5a75016862b5119dbf6faca3c"
    )
    candidate_checkouts = [
        step
        for step in candidate_job["steps"]
        if step.get("uses") == "actions/checkout@v4"
        and step.get("with", {}).get("repository") == "acoastalfog/kb-engine"
    ]
    assert len(candidate_checkouts) == 1
    candidate_checkout = candidate_checkouts[0]["with"]
    assert candidate_checkout["ref"] == "${{ env.KB_ENGINE_CANDIDATE_REF }}"
    assert candidate_checkout["path"] == "kb-engine-candidate"
    assert candidate_checkout["ssh-key"] == "${{ secrets.KB_ENGINE_DEPLOY_KEY }}"
    assert candidate_checkout["persist-credentials"] is False
    candidate_commands = "\n".join(
        str(step.get("run") or "") for step in candidate_job["steps"]
    )
    assert "build_release_artifacts.py" in candidate_commands
    assert "build_source_access_artifacts.py" in candidate_commands
    assert "KB_SOURCE_ACCESS_CANDIDATE_WHEEL" in candidate_commands
    assert "-I -m pytest" in candidate_commands


@pytest.mark.skipif(
    os.environ.get("KB_ENGINE_CANDIDATE_REQUIRED") != "1",
    reason="exact candidate wheel is validated by the candidate artifact job",
)
def test_installed_candidate_wheel_is_exact_and_sibling_free():
    pin = _candidate_pin()
    source_pin = _source_candidate_pin()
    assert "PYTHONPATH" not in os.environ
    assert os.environ.get("KB_ENGINE_CANDIDATE_SOURCE_COMMIT") == pin["source_commit"]

    wheel = Path(os.environ["KB_ENGINE_CANDIDATE_WHEEL"]).resolve()
    assert wheel.name == pin["wheel_filename"]
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == pin["wheel_sha256"]
    source_wheel = Path(os.environ["KB_SOURCE_ACCESS_CANDIDATE_WHEEL"]).resolve()
    assert source_wheel.name == source_pin["wheel_filename"]
    assert hashlib.sha256(source_wheel.read_bytes()).hexdigest() == source_pin["wheel_sha256"]
    assert source_pin["source_commit"] == pin["source_commit"]
    assert source_pin["core_wheel_sha256"] == pin["wheel_sha256"]

    import kb_engine  # noqa: PLC0415
    import kb_source_access  # noqa: PLC0415
    from kb_engine.api import contract_fixtures  # noqa: PLC0415

    distribution = importlib.metadata.distribution(pin["distribution"])
    source_distribution = importlib.metadata.distribution(source_pin["distribution"])
    installed_root = Path(distribution.locate_file("")).resolve()
    engine_file = Path(kb_engine.__file__).resolve()
    assert distribution.version == pin["version"]
    assert source_distribution.version == source_pin["version"]
    assert engine_file.is_relative_to(installed_root)
    assert not engine_file.is_relative_to(
        Path(os.environ["KB_ENGINE_CANDIDATE_SOURCE_CHECKOUT"]).resolve()
    )
    assert Path(kb_source_access.__file__).resolve().is_relative_to(
        Path(source_distribution.locate_file("")).resolve()
    )

    manifest = contract_fixtures.manifest()
    assert manifest["kind"] == pin["fixture_manifest_kind"]
    assert manifest["fixture_count"] == pin["fixture_count"]
    assert len(manifest["fixtures"]) == pin["fixture_count"]
    assert all(row["fixture_digest"].startswith("sha256:") for row in manifest["fixtures"])


@pytest.mark.skipif(
    os.environ.get("KB_ENGINE_CANDIDATE_REQUIRED") != "1",
    reason="exact candidate wheel is validated by the candidate artifact job",
)
def test_installed_candidate_goldens_match_hermes_compatibility_reducers(
    tmp_path, monkeypatch
):
    from kb_engine.api import contract_fixtures  # noqa: PLC0415

    plugin = _load_plugin_module(monkeypatch, tmp_path)
    terminal = contract_fixtures.load("terminal-eligibility")
    decisions = {}
    legacy_decisions = {}
    for case in terminal["input"]["cases"]:
        packet = deepcopy(case["receipt"])
        packet["terminal_state"] = case["terminal_state"]
        if packet.get("status") == "completed_with_degradation":
            packet.update(
                {
                    "source_currency": {"sources": [{"state": "current"}]},
                    "semantic_accounting": {"complete": True, "remaining_count": 0},
                    "lifecycle": {"status": "fixed_point"},
                }
            )
        decisions[case["id"]] = plugin._daily_integration_closeout_eligible(packet)
        legacy_decisions[case["id"]] = (
            plugin._legacy_daily_integration_closeout_eligible(packet)
        )
    assert decisions == terminal["expected"]["decisions"]
    assert decisions == legacy_decisions

    closeout = contract_fixtures.load("closeout-replay")
    run_id = closeout["input"]["run_id"]
    envelopes = [
        {"plan_digest": f"sha256:{index:064x}"}
        for index, _entity in enumerate(closeout["input"]["entities"], start=1)
    ]
    children = []
    for counts in closeout["input"]["child_counts"]:
        child = {
            "schema_version": 1,
            "kind": "managed_calendar_closeout",
            "run_id": run_id,
            "status": "not_required" if counts["planned"] == 0 else "completed",
            "ok": True,
            "counts": counts,
            "source_reads": {
                "tripit_complete": True,
                "calendar_complete": True,
            },
        }
        child["receipt_digest"] = plugin._managed_closeout_digest(child)
        children.append(child)
    first = plugin._aggregate_calendar_closeouts(
        children,
        envelopes=envelopes,
        run_id=run_id,
        calendar_observation=closeout["input"]["calendar_observation"],
    )
    replay = plugin._aggregate_calendar_closeouts(
        children,
        envelopes=envelopes,
        run_id=run_id,
        calendar_observation=closeout["input"]["calendar_observation"],
    )
    legacy = plugin._legacy_aggregate_calendar_closeouts(
        children,
        envelopes=envelopes,
        run_id=run_id,
        calendar_observation=closeout["input"]["calendar_observation"],
    )
    assert first == legacy
    actual = {
        "status": first["status"],
        "counts": first["counts"],
        "child_receipt_count": len(first["child_receipts"]),
        "calendar_observation_preserved": (
            first["calendar_observation"]
            == closeout["input"]["calendar_observation"]
        ),
        "exact_replay": first == replay,
    }
    assert actual == closeout["expected"]


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


def test_m3_compact_attention_tool_result_is_rendered_once_before_model_context(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    ctx = _ProbeHookContext({})
    plugin.register(ctx)

    items = [
        {
            "item_id": f"situation-{index}",
            "title": f"Situation {index}",
            "detail": f"Why situation {index} needs attention now.",
            "entity_path": f"/home/abcosta/Knowledge/kb-anthony/situations/{index}.md",
            "source_body": "PRIVATE SOURCE BODY",
        }
        for index in range(7)
    ]
    packet = {
        "schema_version": 1,
        "front_door": "attention_cockpit",
        "status": "degraded",
        "mode": "compact",
        "summary": {
            "active_todo_count": 2,
            "readiness_status": "degraded",
            "publication_status": "not_attempted",
        },
        "sections": {
            "situations": {
                "surface": "attention.cockpit",
                "items": items,
            }
        },
        "next_actions": ["Open the highest-priority situation."],
        "digest": "sha256:" + "a" * 64,
    }
    envelope = json.dumps(
        {
            "result": json.dumps(packet, ensure_ascii=False, sort_keys=True),
            "structuredContent": packet,
        },
        ensure_ascii=False,
    )

    assert "transform_tool_result" in ctx.hooks
    rendered = ctx.hooks["transform_tool_result"][0](
        tool_name="mcp_kb_engine_prod_attention_cockpit",
        args={"attention_limit": 5, "mode": "compact"},
        result=envelope,
    )

    assert isinstance(rendered, str)
    assert len(rendered.encode("utf-8")) < 2_000
    assert len(rendered.encode("utf-8")) < len(envelope.encode("utf-8")) // 10
    _assert_compact_user_card({"text": rendered})
    assert "Status: degraded" in rendered
    assert "Situation 0" in rendered
    assert "Situation 4" in rendered
    assert "Situation 5" not in rendered
    assert "Next:" in rendered


def test_m3_compact_attention_transform_fails_closed_without_exact_generated_packet(
    tmp_path, monkeypatch
):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    packet = {
        "status": "ready",
        "mode": "compact",
        "summary": {},
        "sections": {},
    }

    def envelope(structured, text=None):
        return json.dumps(
            {
                "result": json.dumps(
                    structured if text is None else text,
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                "structuredContent": structured,
            },
            ensure_ascii=False,
        )

    cases = [
        (
            "mcp_kb_engine_prod_attention_cockpit",
            {},
            envelope({**packet, "mode": "full"}),
        ),
        (
            "mcp_kb_engine_prod_attention_cockpit",
            {"mode": "full"},
            envelope(packet),
        ),
        (
            "mcp_kb_engine_prod_attention_cockpit",
            {"detail": True},
            envelope(packet),
        ),
        (
            "mcp_kb_engine_prod_attention_cockpit",
            {},
            envelope(packet, {**packet, "status": "different"}),
        ),
        (
            "mcp_kb_engine_prod_attention_cockpit",
            {},
            envelope({"mode": "compact"}),
        ),
        (
            "mcp_kb_engine_prod_attention_cockpit",
            {},
            json.dumps({"error": "upstream unavailable"}),
        ),
        ("mcp_kb_engine_prod_workspace_readiness", {}, envelope(packet)),
        ("mcp_other_attention_cockpit", {}, envelope(packet)),
        ("web_search", {}, envelope(packet)),
    ]

    for tool_name, args, result in cases:
        assert (
            plugin._compact_attention_tool_result(
                tool_name=tool_name,
                args=args,
                result=result,
            )
            is None
        )


def test_m3_publish_routes_to_governed_preview_without_committing(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    monkeypatch.setenv("HERMES_KB_MCP_TARGET", "kb_engine_prod")
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_publication_preview_commit": [
                {"result": _publication_preview()}
            ]
        }
    )
    source = type(
        "Source",
        (),
        {"platform": "telegram", "chat_id": "chat-1", "thread_id": "", "user_id": "42"},
    )()

    card = plugin._card_for_command(ctx, "kbpublish", source=source)

    assert card["status"] == "ready_to_confirm"
    assert "No publication was attempted" in card["text"]
    assert [tool for tool, _args in ctx.calls] == [
        "mcp_kb_engine_prod_publication_preview_commit"
    ]
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


def _publication_preview(*, digest="a" * 64, paths=None, status="ready"):
    changed_paths = ["accounts/acme/log.md", "todos.jsonl"] if paths is None else paths
    ahead = 1 if status == "push_pending" else 0
    return {
        "schema_version": 1,
        "status": status,
        "ok": True,
        "message": "kb: publish reviewed knowledge changes",
        "changed_paths": changed_paths,
        "change_set_digest": digest,
        "git": {
            "status": "ready",
            "clean": not changed_paths,
            "head": "abcdef12",
            "ahead": ahead,
            "behind": 0,
            "changed_count": len(changed_paths),
        },
        "preflight": {
            "status": "pending_publication" if changed_paths else "ready",
            "ok": True,
            "git_diff_check": "pass",
            "safe_fix_count": 0,
        },
    }


def test_m3_publication_preview_binds_exact_set_without_mutation(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    source = type("Source", (), {"user_id": "42"})()
    ctx = FakeContext(
        {"mcp_kb_engine_prod_publication_preview_commit": [{"result": _publication_preview()}]}
    )

    card = plugin._render_publish_command(
        ctx, "kb_engine_prod", "", session_id="session-1", source=source
    )

    assert card["status"] == "ready_to_confirm"
    assert "2 reviewed paths" in card["text"]
    assert "No publication was attempted" in card["text"]
    assert "/kb publish confirm" in card["text"]
    assert ctx.calls == [
        (
            "mcp_kb_engine_prod_publication_preview_commit",
            {"message": "kb: publish reviewed knowledge changes"},
        )
    ]
    _assert_compact_user_card(card)


def test_m3_publication_confirm_uses_stored_binding_and_pushes(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    source = type("Source", (), {"user_id": "42"})()
    preview = _publication_preview()
    confirmed = {
        "schema_version": 1,
        "status": "committed",
        "ok": True,
        "actor": "telegram:42",
        "source": "Hermes Telegram",
        "session_id": "session-1",
        "publication": {
            "status": "committed",
            "ok": True,
            "commit": "12345678",
            "pushed": True,
            "changed_paths": preview["changed_paths"],
            "git": {"status": "ready", "clean": True, "ahead": 0, "behind": 0},
        },
    }
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_publication_preview_commit": [
                {"result": preview},
                {"result": preview},
            ],
            "mcp_kb_engine_prod_publication_commit_confirmed": [{"result": confirmed}],
        }
    )
    plugin._render_publish_command(
        ctx, "kb_engine_prod", "", session_id="session-1", source=source
    )

    card = plugin._render_publish_command(
        ctx, "kb_engine_prod", "confirm", session_id="session-1", source=source
    )

    assert card["status"] == "published"
    assert "Published 2 reviewed paths" in card["text"]
    tool, args = ctx.calls[-1]
    assert tool == "mcp_kb_engine_prod_publication_commit_confirmed"
    assert args["expected_git_head"] == "abcdef12"
    assert args["expected_changed_paths"] == preview["changed_paths"]
    assert args["expected_change_set_digest"] == "a" * 64
    assert args["push"] is True
    assert args["user_confirmation"]["confirmed"] is True
    _assert_compact_user_card(card)


def test_m3_publication_confirm_fails_closed_when_preview_drifted(tmp_path, monkeypatch):
    plugin = _load_plugin_module(monkeypatch, tmp_path)
    _install_conforming_descriptor_fixture(plugin, monkeypatch)
    source = type("Source", (), {"user_id": "42"})()
    ctx = FakeContext(
        {
            "mcp_kb_engine_prod_publication_preview_commit": [
                {"result": _publication_preview()},
                {"result": _publication_preview(digest="b" * 64)},
            ],
        }
    )
    plugin._render_publish_command(
        ctx, "kb_engine_prod", "", session_id="session-1", source=source
    )

    card = plugin._render_publish_command(
        ctx, "kb_engine_prod", "confirm", session_id="session-1", source=source
    )

    assert card["status"] == "preview_stale"
    assert "changed since the preview" in card["text"]
    assert all("commit_confirmed" not in tool for tool, _args in ctx.calls)
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
        self.registered_tools = {}

    def register_hook(self, name, callback):
        self.hooks.setdefault(name, []).append(callback)

    def register_command(self, name, handler, **metadata):
        self.commands[name] = {"handler": handler, **metadata}

    def register_tool(self, **metadata):
        self.registered_tools[metadata["name"]] = metadata


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

    assert set(ctx.hooks) == {
        "pre_gateway_dispatch",
        "post_llm_call",
        "transform_tool_result",
    }


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
