from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "h1-owner-evidence.py"
EXPECTED_REF = "9772526c543cec30ee3aee71be952f95dbaf8301"
NOW = datetime(2026, 6, 27, 20, 0, tzinfo=UTC)


def _load_module():
    spec = importlib.util.spec_from_file_location("h1_owner_evidence", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _digest(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _write_json(path: Path, payload: dict, *, mode: int = 0o600) -> None:
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(mode)


def _plugin_receipt(module, *, installed_at: datetime | None = None) -> dict:
    descriptor = json.loads(
        (ROOT / "generated" / "kb-engine-descriptors.json").read_text(encoding="utf-8")
    )
    payload = {
        "schema_version": 1,
        "kind": "hermes_plugin_deployment_receipt",
        "plugin": "kb_journeys",
        "status": "pass",
        "load_verified": True,
        "secret_values_exposed": False,
        "install_receipt": {
            "current_ref": EXPECTED_REF,
            "previous_ref": "1" * 40,
            "rollback_ref": "1" * 40,
            "installed_digest": module.expected_plugin_artifact_digest(ROOT),
            "descriptor_digest": descriptor["digest"],
            "installed_at": (installed_at or NOW - timedelta(minutes=5))
            .isoformat()
            .replace("+00:00", "Z"),
            "noc_plan_digest": "sha256:" + "2" * 64,
        },
    }
    return {**payload, "receipt_digest": _digest(payload)}


def _canary_receipt(module, artifact: Path, **overrides) -> dict:
    artifact_payload = {
        "schema_version": 1,
        "kind": "hermes_semantic_confirmed_write_canary_artifact",
        "semantic_canary_id": "h1-post-cutover-001",
        "run_id": "run-h1-001",
        "resource_id": "canary:hermes-kb-journeys-h1",
        "workspace": "kb_engine_prod",
        "before_observation_digest": "sha256:" + "3" * 64,
        "after_observation_digest": "sha256:" + "4" * 64,
        "secret_values_exposed": False,
    }
    _write_json(artifact, artifact_payload)
    artifact_sha = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    payload = {
        "schema_version": 1,
        "kind": "hermes_semantic_confirmed_write_canary_receipt",
        "status": "pass",
        "semantic_canary_id": artifact_payload["semantic_canary_id"],
        "run_id": artifact_payload["run_id"],
        "plan_digest": "sha256:" + "5" * 64,
        "confirmed_digest": "sha256:" + "5" * 64,
        "resource_id": artifact_payload["resource_id"],
        "workspace": artifact_payload["workspace"],
        "before_observation_digest": artifact_payload["before_observation_digest"],
        "after_observation_digest": artifact_payload["after_observation_digest"],
        "mutation_performed": True,
        "durable_readback": True,
        "terminal_state": "completed",
        "observer_host": "helix",
        "observed_at": NOW.isoformat().replace("+00:00", "Z"),
        "source_revision": EXPECTED_REF,
        "artifact": {"path": str(artifact), "sha256": artifact_sha},
        "secret_values_exposed": False,
    }
    payload.update(overrides)
    return {**payload, "receipt_digest": _digest(payload)}


def _inputs(tmp_path: Path, module, *, canary_overrides=None):
    plugin_path = tmp_path / "plugin.json"
    canary_path = tmp_path / "canary.json"
    artifact = tmp_path / "canary-artifact.json"
    _write_json(plugin_path, _plugin_receipt(module))
    _write_json(
        canary_path,
        _canary_receipt(module, artifact, **(canary_overrides or {})),
    )
    return plugin_path, canary_path


def _passing_runner(check_name, selectors, *, hermes_fixture, repo_root):
    assert check_name in {
        "descriptor_contract",
        "durable_readback",
        "strict_profile_compatible",
        "rendering_degradation_safe",
    }
    assert selectors
    assert hermes_fixture.name == "hermes-fixture"
    assert repo_root == ROOT
    return {"status": "pass", "tests": len(selectors)}


def test_success_emits_stable_mode_0600_report_and_schema_valid_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    plugin_path, canary_path = _inputs(tmp_path, module)
    fixture = tmp_path / "hermes-fixture"
    fixture.mkdir()
    output = tmp_path / "out"
    monkeypatch.setattr(module, "validate_source_checkout", lambda _root: None)
    monkeypatch.setattr(
        module,
        "validate_hermes_fixture",
        lambda path: "6" * 40 if path == fixture else "",
    )

    result = module.generate_evidence(
        repo_root=ROOT,
        hermes_fixture=fixture,
        plugin_receipt_path=plugin_path,
        canary_receipt_path=canary_path,
        output_directory=output,
        now=NOW,
        test_runner=_passing_runner,
        trusted_input_uid=os.geteuid(),
    )

    report_path = output / "h1-test-report.json"
    candidate_path = output / "h1-candidate.json"
    assert result == {"report": report_path, "candidate": candidate_path}
    assert oct(report_path.stat().st_mode & 0o777) == "0o600"
    assert oct(candidate_path.stat().st_mode & 0o777) == "0o600"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    assert report["kind"] == "hermes_kb_journeys_h1_test_report"
    assert report["source_revision"] == EXPECTED_REF
    assert report["checks"] == {
        "descriptor_contract": True,
        "durable_readback": True,
        "rendering_degradation_safe": True,
        "strict_profile_compatible": True,
    }
    assert report["secret_values_exposed"] is False
    unsigned_report = {
        key: value for key, value in report.items() if key != "report_digest"
    }
    assert report["report_digest"] == _digest(unsigned_report)
    assert candidate["schema_version"] == 1
    assert candidate["kind"] == "knowledge_system_gate_s_receipt"
    assert candidate["receipt_id"] == "h1"
    assert candidate["status"] == "pass"
    assert candidate["evidence"]["source_revision"] == EXPECTED_REF
    assert candidate["evidence"]["observer_host"] == "helix"
    assert candidate["evidence"]["checks"] == report["checks"]
    assert candidate["evidence"]["artifacts"]["test_report_sha256"] == (
        "sha256:" + hashlib.sha256(report_path.read_bytes()).hexdigest()
    )
    assert candidate["evidence"]["artifacts"][
        "plugin_deployment_receipt"
    ] == json.loads(plugin_path.read_text(encoding="utf-8"))
    unsigned_candidate = {
        key: value for key, value in candidate.items() if key != "receipt_digest"
    }
    assert candidate["receipt_digest"] == _digest(unsigned_candidate)


@pytest.mark.parametrize(
    "overrides",
    [
        {"source_revision": "9" * 40},
        {"confirmed_digest": "sha256:" + "6" * 64},
        {"after_observation_digest": "sha256:" + "3" * 64},
        {"durable_readback": False},
        {"mutation_performed": False},
        {"terminal_state": "workflow_running"},
        {"observer_host": "mac"},
        {"secret_values_exposed": True},
        {"observed_at": (NOW - timedelta(days=2)).isoformat()},
    ],
)
def test_canary_mismatch_or_lifecycle_only_success_emits_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict,
) -> None:
    module = _load_module()
    plugin_path, canary_path = _inputs(tmp_path, module, canary_overrides=overrides)
    fixture = tmp_path / "hermes-fixture"
    fixture.mkdir()
    output = tmp_path / "out"
    monkeypatch.setattr(module, "validate_source_checkout", lambda _root: None)
    monkeypatch.setattr(module, "validate_hermes_fixture", lambda _path: "6" * 40)

    with pytest.raises(module.EvidenceError):
        module.generate_evidence(
            repo_root=ROOT,
            hermes_fixture=fixture,
            plugin_receipt_path=plugin_path,
            canary_receipt_path=canary_path,
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )

    assert not output.exists()


def test_pre_cutover_canary_extra_fields_and_artifact_drift_emit_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    plugin_path = tmp_path / "plugin.json"
    canary_path = tmp_path / "canary.json"
    artifact = tmp_path / "canary-artifact.json"
    _write_json(plugin_path, _plugin_receipt(module, installed_at=NOW))
    canary = _canary_receipt(
        module,
        artifact,
        observed_at=(NOW - timedelta(seconds=1)).isoformat(),
    )
    canary["unexpected"] = True
    canary["receipt_digest"] = _digest(
        {key: value for key, value in canary.items() if key != "receipt_digest"}
    )
    _write_json(canary_path, canary)
    fixture = tmp_path / "hermes-fixture"
    fixture.mkdir()
    output = tmp_path / "out"
    monkeypatch.setattr(module, "validate_source_checkout", lambda _root: None)
    monkeypatch.setattr(module, "validate_hermes_fixture", lambda _path: "6" * 40)

    with pytest.raises(module.EvidenceError):
        module.generate_evidence(
            repo_root=ROOT,
            hermes_fixture=fixture,
            plugin_receipt_path=plugin_path,
            canary_receipt_path=canary_path,
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )
    assert not output.exists()

    canary.pop("unexpected")
    canary["observed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    canary["receipt_digest"] = _digest(
        {key: value for key, value in canary.items() if key != "receipt_digest"}
    )
    _write_json(canary_path, canary)
    artifact.write_text("changed", encoding="utf-8")
    artifact.chmod(0o600)
    with pytest.raises(module.EvidenceError):
        module.generate_evidence(
            repo_root=ROOT,
            hermes_fixture=fixture,
            plugin_receipt_path=plugin_path,
            canary_receipt_path=canary_path,
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )
    assert not output.exists()


def test_failed_contract_check_and_foreign_input_emit_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    plugin_path, canary_path = _inputs(tmp_path, module)
    fixture = tmp_path / "hermes-fixture"
    fixture.mkdir()
    output = tmp_path / "out"
    monkeypatch.setattr(module, "validate_source_checkout", lambda _root: None)
    monkeypatch.setattr(module, "validate_hermes_fixture", lambda _path: "6" * 40)

    def failed_runner(*_args, **_kwargs):
        return {"status": "fail", "tests": 0}

    with pytest.raises(module.EvidenceError):
        module.generate_evidence(
            repo_root=ROOT,
            hermes_fixture=fixture,
            plugin_receipt_path=plugin_path,
            canary_receipt_path=canary_path,
            output_directory=output,
            now=NOW,
            test_runner=failed_runner,
            trusted_input_uid=os.geteuid(),
        )
    assert not output.exists()

    plugin_path.chmod(0o666)
    with pytest.raises(module.EvidenceError):
        module.generate_evidence(
            repo_root=ROOT,
            hermes_fixture=fixture,
            plugin_receipt_path=plugin_path,
            canary_receipt_path=canary_path,
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("current_ref", "9" * 40),
        ("previous_ref", "0" * 40),
        ("rollback_ref", "8" * 40),
        ("installed_digest", "sha256:" + "9" * 64),
        ("descriptor_digest", "sha256:" + "9" * 64),
    ],
)
def test_plugin_deployment_mismatch_emits_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    module = _load_module()
    plugin_path, canary_path = _inputs(tmp_path, module)
    plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
    plugin["install_receipt"][field] = value
    unsigned = {key: item for key, item in plugin.items() if key != "receipt_digest"}
    plugin["receipt_digest"] = _digest(unsigned)
    _write_json(plugin_path, plugin)
    fixture = tmp_path / "hermes-fixture"
    fixture.mkdir()
    output = tmp_path / "out"
    monkeypatch.setattr(module, "validate_source_checkout", lambda _root: None)
    monkeypatch.setattr(module, "validate_hermes_fixture", lambda _path: "6" * 40)

    with pytest.raises(module.EvidenceError):
        module.generate_evidence(
            repo_root=ROOT,
            hermes_fixture=fixture,
            plugin_receipt_path=plugin_path,
            canary_receipt_path=canary_path,
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )
    assert not output.exists()


def test_secret_bearing_canary_artifact_emits_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    plugin_path, canary_path = _inputs(tmp_path, module)
    canary = json.loads(canary_path.read_text(encoding="utf-8"))
    artifact_path = Path(canary["artifact"]["path"])
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["api_key"] = "sk-examplecredential123456"
    _write_json(artifact_path, artifact)
    canary["artifact"]["sha256"] = (
        "sha256:" + hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    )
    unsigned = {key: item for key, item in canary.items() if key != "receipt_digest"}
    canary["receipt_digest"] = _digest(unsigned)
    _write_json(canary_path, canary)
    fixture = tmp_path / "hermes-fixture"
    fixture.mkdir()
    output = tmp_path / "out"
    monkeypatch.setattr(module, "validate_source_checkout", lambda _root: None)
    monkeypatch.setattr(module, "validate_hermes_fixture", lambda _path: "6" * 40)

    with pytest.raises(module.EvidenceError):
        module.generate_evidence(
            repo_root=ROOT,
            hermes_fixture=fixture,
            plugin_receipt_path=plugin_path,
            canary_receipt_path=canary_path,
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )
    assert not output.exists()


def test_missing_inputs_and_existing_output_are_non_mutating(tmp_path: Path) -> None:
    module = _load_module()
    output = tmp_path / "out"
    with pytest.raises(module.EvidenceError):
        module.generate_evidence(
            repo_root=ROOT,
            hermes_fixture=tmp_path / "missing-hermes",
            plugin_receipt_path=tmp_path / "missing-plugin",
            canary_receipt_path=tmp_path / "missing-canary",
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )
    assert not output.exists()

    output.mkdir()
    sentinel = output / "sentinel"
    sentinel.write_text("preserve", encoding="utf-8")
    with pytest.raises(module.EvidenceError):
        module.generate_evidence(
            repo_root=ROOT,
            hermes_fixture=tmp_path / "missing-hermes",
            plugin_receipt_path=tmp_path / "missing-plugin",
            canary_receipt_path=tmp_path / "missing-canary",
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )
    assert sentinel.read_text(encoding="utf-8") == "preserve"
