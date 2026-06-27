from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "h1-owner-evidence.py"
EXPECTED_REF = "9772526c543cec30ee3aee71be952f95dbaf8301"
EXPECTED_HERMES_REVISION = "2bd1977d8fad185c9b4be47884f7e87f1add0ce3"
EXPECTED_NOC_PLUGIN_DIGEST = (
    "sha256:2efb67ed1c201e7e95b64e9868fa5feee06d75cfb9499c6fbd9ca7e267e3436c"
)
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


def _relay_cutover_receipt(path: Path, *, observed_at: datetime | None = None) -> dict:
    payload = {
        "schema_version": 1,
        "kind": "hermes_relay_deployment_receipt",
        "action": "cutover",
        "status": "pass",
        "plan_digest": "6" * 64,
        "observed_at": (observed_at or NOW - timedelta(minutes=10))
        .isoformat()
        .replace("+00:00", "Z"),
        "checks": {
            "service_identity": True,
            "target_unit_enabled": True,
            "legacy_unit_disabled": True,
            "authority_denied": True,
            "namespace_filesystem_boundaries": True,
            "dashboard_canary": True,
            "telegram_canary": True,
            "legacy_service_preserved": True,
            "rollback_canary": True,
            "idmapped_projection": True,
            "source_identity_and_mode_unchanged": True,
            "private_host_projection": True,
            "exact_writable_root_projection": True,
            "safefs_idmap_canary": True,
            "config_restart_fence": True,
        },
        "secret_values_exposed": False,
    }
    receipt = {**payload, "receipt_digest": _digest(payload)}
    _write_json(path, receipt)
    return receipt


def _canary_receipt(
    module,
    artifact: Path,
    *,
    plugin_receipt: dict,
    relay_cutover_path: Path,
    relay_cutover_receipt: dict,
    **overrides,
) -> dict:
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
        "ttl_seconds": 86400,
        "source_revision": EXPECTED_REF,
        "producer": {
            "source_repository": "acoastalfog/noc",
            "source_revision": "7" * 40,
        },
        "relay_cutover": {
            "artifact": {
                "path": str(relay_cutover_path),
                "sha256": "sha256:"
                + hashlib.sha256(relay_cutover_path.read_bytes()).hexdigest(),
            },
            "receipt_digest": relay_cutover_receipt["receipt_digest"],
            "plan_digest": relay_cutover_receipt["plan_digest"],
        },
        "plugin_deployment_receipt_digest": plugin_receipt["receipt_digest"],
        "service_identity": {
            "os_user": "hermes-relay",
            "service_manager": "systemd",
            "service_scope": "system",
            "unit": "hermes-relay.service",
        },
        "artifact": {"path": str(artifact), "sha256": artifact_sha},
        "secret_values_exposed": False,
    }
    payload.update(overrides)
    return {**payload, "receipt_digest": _digest(payload)}


def _inputs(
    tmp_path: Path,
    module,
    *,
    canary_overrides=None,
    plugin_installed_at: datetime | None = None,
):
    plugin_path = tmp_path / "plugin.json"
    relay_cutover_path = tmp_path / "relay-cutover.json"
    canary_path = tmp_path / "canary.json"
    artifact = tmp_path / "canary-artifact.json"
    plugin_receipt = _plugin_receipt(module, installed_at=plugin_installed_at)
    _write_json(plugin_path, plugin_receipt)
    relay_cutover_receipt = _relay_cutover_receipt(relay_cutover_path)
    _write_json(
        canary_path,
        _canary_receipt(
            module,
            artifact,
            plugin_receipt=plugin_receipt,
            relay_cutover_path=relay_cutover_path,
            relay_cutover_receipt=relay_cutover_receipt,
            **(canary_overrides or {}),
        ),
    )
    return plugin_path, relay_cutover_path, canary_path


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


def test_released_plugin_digest_matches_noc_builder_known_vector() -> None:
    module = _load_module()

    assert module.expected_plugin_artifact_digest(ROOT) == EXPECTED_NOC_PLUGIN_DIGEST


def test_h1_ci_checks_out_the_immutable_hermes_revision() -> None:
    workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")

    assert f"ref: {EXPECTED_HERMES_REVISION}" in workflow


def _run_git_fixture(path: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def test_forged_local_tag_and_canonical_origin_cannot_substitute_for_pinned_commit(
    tmp_path: Path,
) -> None:
    module = _load_module()
    fixture = tmp_path / "forged-hermes-agent"
    fixture.mkdir()
    _run_git_fixture(fixture, "init")
    _run_git_fixture(fixture, "config", "user.name", "fixture")
    _run_git_fixture(fixture, "config", "user.email", "fixture@example.invalid")
    (fixture / "hermes_cli").mkdir()
    (fixture / "hermes_cli" / "plugins.py").write_text(
        "class PluginManager: pass\n", encoding="utf-8"
    )
    _run_git_fixture(fixture, "add", "hermes_cli/plugins.py")
    _run_git_fixture(fixture, "commit", "-m", "forged fixture")
    _run_git_fixture(fixture, "tag", "v2026.6.19")
    _run_git_fixture(
        fixture,
        "remote",
        "add",
        "origin",
        "https://github.com/NousResearch/hermes-agent.git",
    )
    assert _run_git_fixture(fixture, "rev-parse", "HEAD") != EXPECTED_HERMES_REVISION

    with pytest.raises(module.EvidenceError, match="hermes_fixture_mismatch"):
        module.validate_hermes_fixture(fixture)


@pytest.mark.parametrize(
    "injected_path",
    [
        "hermes_cli/injected.py",
        "tests/injected_test.py",
        "hermes_cli/__pycache__/plugins.cpython-311.pyc",
        ".env",
    ],
)
def test_untracked_or_ignored_execution_injection_invalidates_exact_fixture(
    tmp_path: Path, injected_path: str
) -> None:
    module = _load_module()
    source_value = os.environ.get("HERMES_AGENT_REPO")
    if not source_value:
        pytest.skip("exact Hermes Agent fixture is supplied by the H1 CI job")
    fixture = tmp_path / "injected-hermes-agent"
    subprocess.run(
        ["git", "clone", "--quiet", "--no-hardlinks", source_value, str(fixture)],
        check=True,
    )
    _run_git_fixture(
        fixture,
        "remote",
        "set-url",
        "origin",
        "https://github.com/NousResearch/hermes-agent.git",
    )
    _run_git_fixture(fixture, "checkout", "--detach", EXPECTED_HERMES_REVISION)
    injection = fixture / injected_path
    injection.parent.mkdir(parents=True, exist_ok=True)
    injection.write_bytes(b"execution-affecting injection\n")

    with pytest.raises(module.EvidenceError, match="hermes_fixture_mismatch"):
        module.validate_hermes_fixture(fixture)


def test_clean_committed_plugin_source_tree_is_accepted(tmp_path: Path) -> None:
    module = _load_module()
    fixture = tmp_path / "plugin-source"
    subprocess.run(
        ["git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(fixture)],
        check=True,
    )

    module.validate_source_checkout(fixture)


@pytest.mark.parametrize(
    ("index_flag", "relative", "mutation"),
    [
        ("--assume-unchanged", "scripts/h1-owner-evidence.py", "content"),
        ("--skip-worktree", "tests/test_external_plugin_contract.py", "content"),
        ("--assume-unchanged", "scripts/h1-owner-evidence.py", "mode"),
        ("--skip-worktree", "tests/test_external_plugin_contract.py", "mode"),
    ],
)
def test_plugin_source_tree_validation_ignores_index_suppression_flags(
    tmp_path: Path, index_flag: str, relative: str, mutation: str
) -> None:
    module = _load_module()
    fixture = tmp_path / "plugin-source"
    subprocess.run(
        ["git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(fixture)],
        check=True,
    )
    _run_git_fixture(fixture, "update-index", index_flag, relative)
    target = fixture / relative
    if mutation == "content":
        target.write_bytes(target.read_bytes() + b"\n# hidden executed injection\n")
    else:
        mode = target.stat().st_mode
        target.chmod(mode & ~0o111 if mode & 0o111 else mode | 0o111)
    assert relative not in _run_git_fixture(
        fixture, "status", "--porcelain", "--untracked-files=all"
    )

    with pytest.raises(module.EvidenceError, match="released_plugin_bytes_changed"):
        module.validate_source_checkout(fixture)


@pytest.mark.parametrize(
    ("index_flag", "mutation"),
    [
        ("--assume-unchanged", "content"),
        ("--skip-worktree", "content"),
        ("--assume-unchanged", "mode"),
        ("--skip-worktree", "mode"),
    ],
)
def test_hermes_tree_validation_ignores_index_suppression_flags(
    tmp_path: Path, index_flag: str, mutation: str
) -> None:
    module = _load_module()
    source_value = os.environ.get("HERMES_AGENT_REPO")
    if not source_value:
        pytest.skip("exact Hermes Agent fixture is supplied by the H1 CI job")
    fixture = tmp_path / "hidden-hermes-agent"
    subprocess.run(
        ["git", "clone", "--quiet", "--no-hardlinks", source_value, str(fixture)],
        check=True,
    )
    _run_git_fixture(
        fixture,
        "remote",
        "set-url",
        "origin",
        "https://github.com/NousResearch/hermes-agent.git",
    )
    _run_git_fixture(fixture, "checkout", "--detach", EXPECTED_HERMES_REVISION)
    relative = "hermes_cli/plugins.py"
    _run_git_fixture(fixture, "update-index", index_flag, relative)
    target = fixture / relative
    if mutation == "content":
        target.write_bytes(target.read_bytes() + b"\n# hidden executed injection\n")
    else:
        mode = target.stat().st_mode
        target.chmod(mode & ~0o111 if mode & 0o111 else mode | 0o111)
    assert relative not in _run_git_fixture(
        fixture,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    )

    with pytest.raises(module.EvidenceError, match="hermes_fixture_mismatch"):
        module.validate_hermes_fixture(fixture)


@pytest.mark.parametrize(
    "check_name",
    [
        "descriptor_contract",
        "durable_readback",
        "strict_profile_compatible",
        "rendering_degradation_safe",
    ],
)
@pytest.mark.parametrize("fixture_kind", ["missing", "wrong"])
def test_every_h1_contract_group_fails_without_the_exact_pinned_hermes_fixture(
    tmp_path: Path, check_name: str, fixture_kind: str
) -> None:
    module = _load_module()
    selectors = module.CHECK_TESTS[check_name]
    fixture = tmp_path / f"{fixture_kind}-hermes-agent"
    if fixture_kind == "wrong":
        (fixture / "hermes_cli").mkdir(parents=True)
        (fixture / "hermes_cli" / "plugins.py").write_text(
            "raise RuntimeError('not the pinned Hermes fixture')\n", encoding="utf-8"
        )

    assert "test_user_plugin_loads_from_standard_plugin_directory" in selectors
    result = module.run_contract_check(
        check_name,
        selectors,
        hermes_fixture=fixture,
        repo_root=ROOT,
    )
    assert result["status"] == "fail"
    assert 0 <= result["tests"] <= len(selectors)


@pytest.mark.parametrize(
    "check_name",
    [
        "descriptor_contract",
        "durable_readback",
        "strict_profile_compatible",
        "rendering_degradation_safe",
    ],
)
def test_every_h1_contract_group_executes_against_the_exact_reported_fixture(
    check_name: str,
) -> None:
    module = _load_module()
    fixture_value = os.environ.get("HERMES_AGENT_REPO")
    if not fixture_value:
        pytest.skip("exact Hermes Agent fixture is supplied by the H1 CI job")
    fixture = Path(fixture_value).resolve()
    revision = module.validate_hermes_fixture(fixture)
    selectors = module.CHECK_TESTS[check_name]

    assert module.EXPECTED_HERMES_REPOSITORY == "NousResearch/hermes-agent"
    assert module.EXPECTED_HERMES_REF == "v2026.6.19"
    assert module.EXPECTED_HERMES_REVISION == EXPECTED_HERMES_REVISION
    assert revision == EXPECTED_HERMES_REVISION
    assert module.run_contract_check(
        check_name,
        selectors,
        hermes_fixture=fixture,
        repo_root=ROOT,
    ) == {"status": "pass", "tests": len(selectors)}


def test_success_emits_stable_mode_0600_report_and_schema_valid_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    plugin_path, relay_cutover_path, canary_path = _inputs(tmp_path, module)
    fixture = tmp_path / "hermes-fixture"
    fixture.mkdir()
    output = tmp_path / "out"
    monkeypatch.setattr(module, "validate_source_checkout", lambda _root: None)
    monkeypatch.setattr(
        module,
        "validate_hermes_fixture",
        lambda path: EXPECTED_HERMES_REVISION if path == fixture else "",
    )

    result = module.generate_evidence(
        repo_root=ROOT,
        hermes_fixture=fixture,
        plugin_receipt_path=plugin_path,
        relay_cutover_receipt_path=relay_cutover_path,
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
    assert report["hermes_fixture"] == {
        "repository": "NousResearch/hermes-agent",
        "ref": "v2026.6.19",
        "revision": EXPECTED_HERMES_REVISION,
    }
    assert (
        report["relay_cutover_receipt_digest"]
        == json.loads(relay_cutover_path.read_text(encoding="utf-8"))["receipt_digest"]
    )
    assert report["relay_cutover_observed_at"] == (
        NOW - timedelta(minutes=10)
    ).isoformat().replace("+00:00", "Z")
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
    assert candidate["observed_at"] == NOW.isoformat().replace("+00:00", "Z")
    assert candidate["ttl_seconds"] == 86400
    unsigned_candidate = {
        key: value for key, value in candidate.items() if key != "receipt_digest"
    }
    assert candidate["receipt_digest"] == _digest(unsigned_candidate)


@pytest.mark.parametrize(
    ("elapsed", "original_ttl", "expected_remaining"),
    [
        (timedelta(hours=23, minutes=59), 86400, 60),
        (timedelta(seconds=60), 120, 60),
        (timedelta(seconds=86399), 86400, 1),
    ],
)
def test_candidate_freshness_uses_only_semantic_canary_remaining_lifetime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    elapsed: timedelta,
    original_ttl: int,
    expected_remaining: int,
) -> None:
    module = _load_module()
    plugin_path, relay_cutover_path, canary_path = _inputs(
        tmp_path,
        module,
        canary_overrides={"ttl_seconds": original_ttl},
    )
    fixture = tmp_path / "hermes-fixture"
    fixture.mkdir()
    output = tmp_path / "out"
    generated_at = NOW + elapsed
    monkeypatch.setattr(module, "validate_source_checkout", lambda _root: None)
    monkeypatch.setattr(module, "validate_hermes_fixture", lambda _path: "6" * 40)

    result = module.generate_evidence(
        repo_root=ROOT,
        hermes_fixture=fixture,
        plugin_receipt_path=plugin_path,
        relay_cutover_receipt_path=relay_cutover_path,
        canary_receipt_path=canary_path,
        output_directory=output,
        now=generated_at,
        test_runner=_passing_runner,
        trusted_input_uid=os.geteuid(),
    )

    report = json.loads(result["report"].read_text(encoding="utf-8"))
    candidate = json.loads(result["candidate"].read_text(encoding="utf-8"))
    candidate_observed = datetime.fromisoformat(
        candidate["observed_at"].replace("Z", "+00:00")
    )
    canary_expires = NOW + timedelta(seconds=original_ttl)
    assert candidate_observed == generated_at
    assert candidate["ttl_seconds"] == expected_remaining
    assert (
        candidate_observed + timedelta(seconds=candidate["ttl_seconds"])
        <= canary_expires
    )
    assert report["semantic_canary_ttl_seconds"] == original_ttl
    assert report["candidate_ttl_seconds"] == expected_remaining
    assert report["semantic_canary_expires_at"] == canary_expires.isoformat().replace(
        "+00:00", "Z"
    )


def test_expired_semantic_canary_cannot_be_replayed_into_a_fresh_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    plugin_path, relay_cutover_path, canary_path = _inputs(tmp_path, module)
    fixture = tmp_path / "hermes-fixture"
    fixture.mkdir()
    output = tmp_path / "out"
    monkeypatch.setattr(module, "validate_source_checkout", lambda _root: None)
    monkeypatch.setattr(module, "validate_hermes_fixture", lambda _path: "6" * 40)

    with pytest.raises(module.EvidenceError, match="semantic_canary_expired"):
        module.generate_evidence(
            repo_root=ROOT,
            hermes_fixture=fixture,
            plugin_receipt_path=plugin_path,
            relay_cutover_receipt_path=relay_cutover_path,
            canary_receipt_path=canary_path,
            output_directory=output,
            now=NOW + timedelta(hours=24),
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )

    assert not output.exists()


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
        {"ttl_seconds": 0},
        {"ttl_seconds": 86401},
        {"ttl_seconds": True},
    ],
)
def test_canary_mismatch_or_lifecycle_only_success_emits_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict,
) -> None:
    module = _load_module()
    plugin_path, relay_cutover_path, canary_path = _inputs(
        tmp_path, module, canary_overrides=overrides
    )
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
            relay_cutover_receipt_path=relay_cutover_path,
            canary_receipt_path=canary_path,
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )

    assert not output.exists()


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        (None, "plugin_deployment_receipt_digest", "8" * 64),
        ("producer", "source_repository", "foreign/noc"),
        ("producer", "source_revision", "0" * 40),
        ("service_identity", "os_user", "anthony"),
        ("service_identity", "service_scope", "user"),
        ("relay_cutover", "receipt_digest", "8" * 64),
        ("relay_cutover", "plan_digest", "8" * 64),
    ],
)
def test_canary_must_bind_exact_cutover_plugin_service_and_noc_producer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    section: str | None,
    field: str,
    value: str,
) -> None:
    module = _load_module()
    plugin_path, relay_cutover_path, canary_path = _inputs(tmp_path, module)
    canary = json.loads(canary_path.read_text(encoding="utf-8"))
    target = canary if section is None else canary[section]
    target[field] = value
    canary["receipt_digest"] = _digest(
        {key: item for key, item in canary.items() if key != "receipt_digest"}
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
            relay_cutover_receipt_path=relay_cutover_path,
            canary_receipt_path=canary_path,
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )

    assert not output.exists()


def test_canary_must_be_observed_after_the_bound_relay_cutover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    plugin_path = tmp_path / "plugin.json"
    relay_cutover_path = tmp_path / "relay-cutover.json"
    canary_path = tmp_path / "canary.json"
    artifact = tmp_path / "canary-artifact.json"
    plugin_receipt = _plugin_receipt(module)
    _write_json(plugin_path, plugin_receipt)
    cutover = _relay_cutover_receipt(
        relay_cutover_path, observed_at=NOW + timedelta(seconds=1)
    )
    _write_json(
        canary_path,
        _canary_receipt(
            module,
            artifact,
            plugin_receipt=plugin_receipt,
            relay_cutover_path=relay_cutover_path,
            relay_cutover_receipt=cutover,
            observed_at=NOW.isoformat().replace("+00:00", "Z"),
        ),
    )
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
            relay_cutover_receipt_path=relay_cutover_path,
            canary_receipt_path=canary_path,
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )

    assert not output.exists()


def test_final_plugin_receipt_without_cutover_evidence_emits_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    plugin_path, relay_cutover_path, canary_path = _inputs(tmp_path, module)
    relay_cutover_path.unlink()
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
            relay_cutover_receipt_path=relay_cutover_path,
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
    relay_cutover_path = tmp_path / "relay-cutover.json"
    canary_path = tmp_path / "canary.json"
    artifact = tmp_path / "canary-artifact.json"
    plugin_receipt = _plugin_receipt(module, installed_at=NOW)
    _write_json(plugin_path, plugin_receipt)
    relay_cutover_receipt = _relay_cutover_receipt(relay_cutover_path)
    canary = _canary_receipt(
        module,
        artifact,
        plugin_receipt=plugin_receipt,
        relay_cutover_path=relay_cutover_path,
        relay_cutover_receipt=relay_cutover_receipt,
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
            relay_cutover_receipt_path=relay_cutover_path,
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
            relay_cutover_receipt_path=relay_cutover_path,
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
    plugin_path, relay_cutover_path, canary_path = _inputs(tmp_path, module)
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
            relay_cutover_receipt_path=relay_cutover_path,
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
            relay_cutover_receipt_path=relay_cutover_path,
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
    plugin_path, relay_cutover_path, canary_path = _inputs(tmp_path, module)
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
            relay_cutover_receipt_path=relay_cutover_path,
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
    plugin_path, relay_cutover_path, canary_path = _inputs(tmp_path, module)
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
            relay_cutover_receipt_path=relay_cutover_path,
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
            relay_cutover_receipt_path=tmp_path / "missing-cutover",
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
            relay_cutover_receipt_path=tmp_path / "missing-cutover",
            canary_receipt_path=tmp_path / "missing-canary",
            output_directory=output,
            now=NOW,
            test_runner=_passing_runner,
            trusted_input_uid=os.geteuid(),
        )
    assert sentinel.read_text(encoding="utf-8") == "preserve"
