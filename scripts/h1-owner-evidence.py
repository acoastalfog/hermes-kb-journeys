#!/usr/bin/env python3
"""Produce the owner-side H1 Gate S evidence packet.

This is a development/operations script, not plugin runtime code.  It consumes
only root-custodied NOC receipts and never calls Hermes, kb-engine, or Gate S
admission mutations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable


EXPECTED_PLUGIN_REF = "9772526c543cec30ee3aee71be952f95dbaf8301"
EXPECTED_HERMES_REF = "v2026.6.19"
EXPECTED_SOURCE_REPOSITORY = "acoastalfog/hermes-kb-journeys"
EXPECTED_HERMES_REPOSITORY = "NousResearch/hermes-agent"
EXPECTED_WORKSPACE = "kb_engine_prod"
MAX_INPUT_BYTES = 1024 * 1024
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
PLUGIN_RUNTIME_PATHS = (
    "__init__.py",
    "generated/kb-engine-descriptors.json",
    "plugin.yaml",
    "pyproject.toml",
    "scripts/refresh-descriptors.sh",
    "tests/test_external_plugin_contract.py",
)
OWNER_EVIDENCE_PATHS = {
    ".github/workflows/test.yml",
    "README.md",
    "docs/gate-s-h1-owner-evidence.md",
    "scripts/h1-owner-evidence.py",
    "tests/test_h1_owner_evidence.py",
}
CHECK_TESTS: dict[str, tuple[str, ...]] = {
    "descriptor_contract": (
        "test_generated_descriptor_bundle_is_strict_and_legacy_free",
        "test_conforming_concrete_output_fixture_loads",
        "test_descriptor_validation_recomputes_schema_digests",
    ),
    "durable_readback": (
        "test_optimistic_confirm_without_readback_never_renders_durable_success",
        "test_durable_completion_requires_generated_request_binding_in_addition_to_readback",
        "test_generated_completion_binding_proves_only_the_exact_selected_request",
        "test_evidence_completion_requires_digest_bound_readback",
    ),
    "strict_profile_compatible": (
        "test_generated_descriptor_bundle_is_strict_and_legacy_free",
        "test_kb_sync_is_typed_unavailable_and_dispatches_nothing",
        "test_dispatch_first_skips_every_non_allowlisted_tool",
        "test_runtime_rejects_more_than_twelve_effective_tools",
    ),
    "rendering_degradation_safe": (
        "test_upstream_env_status_renders_plain_text",
        "test_upstream_env_today_renders_plain_text",
        "test_upstream_env_readiness_reports_text_only_degraded",
        "test_upstream_env_text_delivery_drops_unavailable_buttons",
    ),
}
PLUGIN_RECEIPT_KEYS = {
    "schema_version",
    "kind",
    "plugin",
    "status",
    "load_verified",
    "secret_values_exposed",
    "install_receipt",
    "receipt_digest",
}
INSTALL_RECEIPT_KEYS = {
    "current_ref",
    "previous_ref",
    "rollback_ref",
    "installed_digest",
    "descriptor_digest",
    "installed_at",
    "noc_plan_digest",
}
CANARY_RECEIPT_KEYS = {
    "schema_version",
    "kind",
    "status",
    "semantic_canary_id",
    "run_id",
    "plan_digest",
    "confirmed_digest",
    "resource_id",
    "workspace",
    "before_observation_digest",
    "after_observation_digest",
    "mutation_performed",
    "durable_readback",
    "terminal_state",
    "observer_host",
    "observed_at",
    "source_revision",
    "artifact",
    "secret_values_exposed",
    "receipt_digest",
}
CANARY_ARTIFACT_KEYS = {
    "schema_version",
    "kind",
    "semantic_canary_id",
    "run_id",
    "resource_id",
    "workspace",
    "before_observation_digest",
    "after_observation_digest",
    "secret_values_exposed",
}
SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(api[_-]?key|authorization|credential|password|private[_-]?key|secret|token)(?:$|[_-])",
    re.IGNORECASE,
)
SENSITIVE_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|github_pat_|gh[pousr]_[A-Za-z0-9]|xox[baprs]-|Bearer\s+[A-Za-z0-9]|AKIA[0-9A-Z]{12,}|(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9]{12,})"
)


class EvidenceError(ValueError):
    """A secret-safe, fail-closed owner-evidence error."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _non_placeholder(value: str, *, prefix: str = "") -> bool:
    raw = value.removeprefix(prefix) if prefix else value
    return bool(raw and set(raw) != {"0"})


def _parse_timestamp(value: Any, *, code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError(code) from error
    if parsed.tzinfo is None:
        raise EvidenceError(code)
    return parsed.astimezone(UTC)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _run_git(root: Path, *arguments: str, binary: bool = False) -> str | bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=not binary,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise EvidenceError("source_revision_unavailable")
    return result.stdout


def expected_plugin_artifact_digest(repo_root: Path) -> str:
    """Recompute NOC's installed tracked-tree digest at the released ref."""

    names_raw = _run_git(
        repo_root,
        "ls-tree",
        "-r",
        "--name-only",
        "-z",
        EXPECTED_PLUGIN_REF,
        binary=True,
    )
    assert isinstance(names_raw, bytes)
    artifact = hashlib.sha256()
    for raw_name in sorted(item for item in names_raw.split(b"\0") if item):
        relative = raw_name.decode("utf-8")
        content = _run_git(
            repo_root,
            "show",
            f"{EXPECTED_PLUGIN_REF}:{relative}",
            binary=True,
        )
        assert isinstance(content, bytes)
        artifact.update(raw_name)
        artifact.update(b"\0")
        artifact.update(content)
        artifact.update(b"\0")
    return f"sha256:{artifact.hexdigest()}"


def validate_source_checkout(repo_root: Path) -> None:
    expected = str(
        _run_git(repo_root, "rev-parse", f"{EXPECTED_PLUGIN_REF}^{{commit}}")
    ).strip()
    head = str(_run_git(repo_root, "rev-parse", "HEAD^{commit}")).strip()
    if expected != EXPECTED_PLUGIN_REF or not SHA.fullmatch(head):
        raise EvidenceError("source_revision_mismatch")
    ancestor = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "merge-base",
            "--is-ancestor",
            EXPECTED_PLUGIN_REF,
            head,
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    runtime_diff = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "diff",
            "--quiet",
            EXPECTED_PLUGIN_REF,
            "--",
            *PLUGIN_RUNTIME_PATHS,
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    changed = {
        item
        for item in str(
            _run_git(repo_root, "diff", "--name-only", EXPECTED_PLUGIN_REF, "HEAD")
        ).splitlines()
        if item
    }
    worktree = str(
        _run_git(repo_root, "status", "--porcelain", "--untracked-files=all")
    )
    if (
        ancestor.returncode != 0
        or runtime_diff.returncode != 0
        or not changed <= OWNER_EVIDENCE_PATHS
        or worktree
    ):
        raise EvidenceError("released_plugin_bytes_changed")


def validate_hermes_fixture(path: Path) -> str:
    if not path.is_absolute() or not (path / "hermes_cli" / "plugins.py").is_file():
        raise EvidenceError("hermes_fixture_unavailable")
    head = str(_run_git(path, "rev-parse", "HEAD^{commit}")).strip()
    tag = str(_run_git(path, "rev-parse", f"{EXPECTED_HERMES_REF}^{{commit}}")).strip()
    origin = str(_run_git(path, "remote", "get-url", "origin")).strip()
    dirty = str(_run_git(path, "status", "--porcelain", "--untracked-files=no"))
    canonical_origins = {
        f"https://github.com/{EXPECTED_HERMES_REPOSITORY}",
        f"https://github.com/{EXPECTED_HERMES_REPOSITORY}.git",
        f"git@github.com:{EXPECTED_HERMES_REPOSITORY}.git",
    }
    if head != tag or origin not in canonical_origins or dirty:
        raise EvidenceError("hermes_fixture_mismatch")
    return head


def _read_custodied_bytes(path: Path, *, trusted_uid: int) -> bytes:
    if not path.is_absolute() or path != Path(os.path.normpath(os.fspath(path))):
        raise EvidenceError("input_path_not_canonical")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvidenceError("required_input_unavailable") from error
    allowed_modes = {0o600, 0o640} if trusted_uid == 0 else {0o600}
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != trusted_uid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) not in allowed_modes
        or metadata.st_size > MAX_INPUT_BYTES
    ):
        raise EvidenceError("input_custody_invalid")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise EvidenceError("input_changed_during_read")
        raw = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, MAX_INPUT_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_INPUT_BYTES:
                raise EvidenceError("input_too_large")
        final = os.fstat(descriptor)
        if (
            (final.st_dev, final.st_ino) != (metadata.st_dev, metadata.st_ino)
            or final.st_size != metadata.st_size
            or final.st_mtime_ns != metadata.st_mtime_ns
            or len(raw) != metadata.st_size
        ):
            raise EvidenceError("input_changed_during_read")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _read_custodied_json(
    path: Path, *, trusted_uid: int
) -> tuple[dict[str, Any], bytes]:
    raw = _read_custodied_bytes(path, trusted_uid=trusted_uid)
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("input_json_invalid") from error
    if not isinstance(payload, dict):
        raise EvidenceError("input_json_invalid")
    return payload, raw


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("input_json_duplicate_key")
        result[key] = value
    return result


def _secret_safe(value: Any, *, parent_key: str = "") -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if key != "secret_values_exposed" and SENSITIVE_KEY.search(key):
                return False
            if not _secret_safe(item, parent_key=key):
                return False
        return True
    if isinstance(value, list):
        return all(_secret_safe(item, parent_key=parent_key) for item in value)
    if isinstance(value, str) and parent_key not in {"path"}:
        return SENSITIVE_VALUE.search(value) is None
    return True


def _validate_plugin_receipt(payload: dict[str, Any], *, repo_root: Path) -> datetime:
    if set(payload) != PLUGIN_RECEIPT_KEYS:
        raise EvidenceError("plugin_receipt_schema_invalid")
    claimed = payload.get("receipt_digest")
    unsigned = {key: value for key, value in payload.items() if key != "receipt_digest"}
    install = payload.get("install_receipt")
    if (
        not isinstance(claimed, str)
        or DIGEST.fullmatch(claimed) is None
        or claimed != _digest(unsigned)
        or payload.get("schema_version") != 1
        or payload.get("kind") != "hermes_plugin_deployment_receipt"
        or payload.get("plugin") != "kb_journeys"
        or payload.get("status") != "pass"
        or payload.get("load_verified") is not True
        or payload.get("secret_values_exposed") is not False
        or not isinstance(install, dict)
        or set(install) != INSTALL_RECEIPT_KEYS
        or install.get("current_ref") != EXPECTED_PLUGIN_REF
        or not SHA.fullmatch(str(install.get("previous_ref") or ""))
        or not _non_placeholder(str(install.get("previous_ref") or ""))
        or install.get("previous_ref") != install.get("rollback_ref")
        or install.get("rollback_ref") == EXPECTED_PLUGIN_REF
        or install.get("installed_digest") != expected_plugin_artifact_digest(repo_root)
        or not _non_placeholder(
            str(install.get("installed_digest") or ""), prefix="sha256:"
        )
        or not SHA256.fullmatch(str(install.get("descriptor_digest") or ""))
        or not _non_placeholder(
            str(install.get("descriptor_digest") or ""), prefix="sha256:"
        )
        or not SHA256.fullmatch(str(install.get("noc_plan_digest") or ""))
        or not _non_placeholder(
            str(install.get("noc_plan_digest") or ""), prefix="sha256:"
        )
        or not _secret_safe(payload)
    ):
        raise EvidenceError("plugin_receipt_invalid")
    descriptor = json.loads(
        (repo_root / "generated" / "kb-engine-descriptors.json").read_text(
            encoding="utf-8"
        )
    )
    if install["descriptor_digest"] != descriptor.get("digest"):
        raise EvidenceError("plugin_descriptor_digest_mismatch")
    return _parse_timestamp(
        install.get("installed_at"), code="plugin_timestamp_invalid"
    )


def _validate_identifier(value: Any, *, code: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise EvidenceError(code)
    return value


def _validate_canary_receipt(
    payload: dict[str, Any],
    *,
    installed_at: datetime,
    now: datetime,
    trusted_uid: int,
) -> datetime:
    if set(payload) != CANARY_RECEIPT_KEYS:
        raise EvidenceError("semantic_canary_schema_invalid")
    claimed = payload.get("receipt_digest")
    unsigned = {key: value for key, value in payload.items() if key != "receipt_digest"}
    artifact = payload.get("artifact")
    digests = (
        str(payload.get("plan_digest") or ""),
        str(payload.get("confirmed_digest") or ""),
        str(payload.get("before_observation_digest") or ""),
        str(payload.get("after_observation_digest") or ""),
    )
    if (
        not isinstance(claimed, str)
        or DIGEST.fullmatch(claimed) is None
        or claimed != _digest(unsigned)
        or payload.get("schema_version") != 1
        or payload.get("kind") != "hermes_semantic_confirmed_write_canary_receipt"
        or payload.get("status") != "pass"
        or any(
            SHA256.fullmatch(value) is None
            or not _non_placeholder(value, prefix="sha256:")
            for value in digests
        )
        or payload.get("confirmed_digest") != payload.get("plan_digest")
        or payload.get("before_observation_digest")
        == payload.get("after_observation_digest")
        or payload.get("mutation_performed") is not True
        or payload.get("durable_readback") is not True
        or payload.get("terminal_state") != "completed"
        or payload.get("observer_host") != "helix"
        or payload.get("source_revision") != EXPECTED_PLUGIN_REF
        or payload.get("workspace") != EXPECTED_WORKSPACE
        or payload.get("secret_values_exposed") is not False
        or not isinstance(artifact, dict)
        or set(artifact) != {"path", "sha256"}
        or SHA256.fullmatch(str(artifact.get("sha256") or "")) is None
        or not _secret_safe(payload)
    ):
        raise EvidenceError("semantic_canary_invalid")
    semantic_canary_id = _validate_identifier(
        payload.get("semantic_canary_id"), code="semantic_canary_id_invalid"
    )
    run_id = _validate_identifier(payload.get("run_id"), code="canary_run_id_invalid")
    resource_id = _validate_identifier(
        payload.get("resource_id"), code="canary_resource_id_invalid"
    )
    if not resource_id.startswith("canary:"):
        raise EvidenceError("canary_resource_scope_invalid")
    observed_at = _parse_timestamp(
        payload.get("observed_at"), code="canary_timestamp_invalid"
    )
    if (
        observed_at < installed_at
        or observed_at < now.astimezone(UTC) - timedelta(hours=24)
        or observed_at > now.astimezone(UTC) + timedelta(minutes=5)
    ):
        raise EvidenceError("semantic_canary_not_current_post_cutover")
    artifact_path = Path(str(artifact["path"]))
    artifact_payload, artifact_raw = _read_custodied_json(
        artifact_path, trusted_uid=trusted_uid
    )
    if "sha256:" + hashlib.sha256(artifact_raw).hexdigest() != artifact["sha256"]:
        raise EvidenceError("semantic_canary_artifact_digest_mismatch")
    if (
        set(artifact_payload) != CANARY_ARTIFACT_KEYS
        or artifact_payload.get("schema_version") != 1
        or artifact_payload.get("kind")
        != "hermes_semantic_confirmed_write_canary_artifact"
        or artifact_payload.get("semantic_canary_id") != semantic_canary_id
        or artifact_payload.get("run_id") != run_id
        or artifact_payload.get("resource_id") != resource_id
        or artifact_payload.get("workspace") != EXPECTED_WORKSPACE
        or artifact_payload.get("before_observation_digest")
        != payload.get("before_observation_digest")
        or artifact_payload.get("after_observation_digest")
        != payload.get("after_observation_digest")
        or artifact_payload.get("secret_values_exposed") is not False
        or not _secret_safe(artifact_payload)
    ):
        raise EvidenceError("semantic_canary_artifact_invalid")
    return observed_at


def run_contract_check(
    check_name: str,
    selectors: tuple[str, ...],
    *,
    hermes_fixture: Path,
    repo_root: Path,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix=f"h1-{check_name}-") as temporary:
        junit = Path(temporary) / "junit.xml"
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--disable-warnings",
            "--maxfail=1",
            f"--junitxml={junit}",
            *[
                f"tests/test_external_plugin_contract.py::{selector}"
                for selector in selectors
            ],
        ]
        environment = {
            **os.environ,
            "HERMES_AGENT_REPO": str(hermes_fixture),
            "HERMES_UPSTREAM_REF": EXPECTED_HERMES_REF,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = subprocess.run(
            command,
            cwd=repo_root,
            env=environment,
            capture_output=True,
            timeout=180,
            check=False,
        )
        if result.returncode != 0 or not junit.is_file():
            return {"status": "fail", "tests": 0}
        try:
            root = ET.parse(junit).getroot()
        except (ET.ParseError, OSError):
            return {"status": "fail", "tests": 0}
        suites = list(root.iter("testsuite"))
        executed = sum(int(suite.attrib.get("tests", "0")) for suite in suites)
        failures = sum(
            int(suite.attrib.get("failures", "0"))
            + int(suite.attrib.get("errors", "0"))
            + int(suite.attrib.get("skipped", "0"))
            for suite in suites
        )
        return {
            "status": "pass"
            if executed == len(selectors) and failures == 0
            else "fail",
            "tests": executed,
        }


def _build_report(
    *,
    plugin_receipt: dict[str, Any],
    canary_receipt: dict[str, Any],
    hermes_revision: str,
    generated_at: datetime,
    canary_observed_at: datetime,
    check_results: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    checks = {
        name: result.get("status") == "pass" for name, result in check_results.items()
    }
    payload = {
        "schema_version": 1,
        "kind": "hermes_kb_journeys_h1_test_report",
        "status": "pass",
        "observed_at": _format_timestamp(generated_at),
        "source_repository": EXPECTED_SOURCE_REPOSITORY,
        "source_revision": EXPECTED_PLUGIN_REF,
        "hermes_fixture": {
            "repository": EXPECTED_HERMES_REPOSITORY,
            "ref": EXPECTED_HERMES_REF,
            "revision": hermes_revision,
        },
        "descriptor_digest": plugin_receipt["install_receipt"]["descriptor_digest"],
        "plugin_deployment_receipt_digest": plugin_receipt["receipt_digest"],
        "semantic_canary_receipt_digest": canary_receipt["receipt_digest"],
        "semantic_canary_observed_at": _format_timestamp(canary_observed_at),
        "semantic_canary_artifact_sha256": canary_receipt["artifact"]["sha256"],
        "checks": checks,
        "test_counts": {
            name: result.get("tests", 0) for name, result in check_results.items()
        },
        "secret_values_exposed": False,
    }
    return {**payload, "report_digest": _digest(payload)}


def _build_candidate(
    *, report_raw: bytes, report: dict[str, Any], plugin_receipt: dict[str, Any]
) -> dict[str, Any]:
    checks = dict(report["checks"])
    evidence = {
        "receipt_id": "h1",
        "owner": "hermes-kb-journeys",
        "checks": checks,
        "source_repository": EXPECTED_SOURCE_REPOSITORY,
        "source_revision": EXPECTED_PLUGIN_REF,
        "plan_digest": None,
        "observer_host": "helix",
        "artifacts": {
            "test_report_sha256": "sha256:" + hashlib.sha256(report_raw).hexdigest(),
            "plugin_deployment_receipt": plugin_receipt,
        },
        "supersedes_receipt_digest": None,
        "secret_values_exposed": False,
    }
    payload = {
        "schema_version": 1,
        "kind": "knowledge_system_gate_s_receipt",
        "receipt_id": "h1",
        "status": "pass",
        "observed_at": report["observed_at"],
        "ttl_seconds": 86400,
        "evidence": evidence,
        "evidence_digest": _digest(evidence),
        "secret_values_exposed": False,
    }
    return {**payload, "receipt_digest": _digest(payload)}


def _output_parent_ready(output_directory: Path) -> None:
    absolute = Path(os.path.abspath(output_directory))
    if (
        output_directory != absolute
        or output_directory.exists()
        or output_directory.is_symlink()
    ):
        raise EvidenceError("output_directory_not_fresh")
    parent = absolute.parent
    try:
        metadata = parent.lstat()
    except OSError as error:
        raise EvidenceError("output_parent_unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise EvidenceError("output_parent_custody_invalid")


def _write_create_only(path: Path, raw: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def generate_evidence(
    *,
    repo_root: Path,
    hermes_fixture: Path,
    plugin_receipt_path: Path,
    canary_receipt_path: Path,
    output_directory: Path,
    now: datetime | None = None,
    test_runner: Callable[..., dict[str, Any]] = run_contract_check,
    trusted_input_uid: int = 0,
) -> dict[str, Path]:
    """Validate all owner and NOC evidence, then emit both artifacts or neither."""

    _output_parent_ready(output_directory)
    validate_source_checkout(repo_root)
    hermes_revision = validate_hermes_fixture(hermes_fixture)
    plugin_receipt, _plugin_raw = _read_custodied_json(
        plugin_receipt_path, trusted_uid=trusted_input_uid
    )
    installed_at = _validate_plugin_receipt(plugin_receipt, repo_root=repo_root)
    canary_receipt, _canary_raw = _read_custodied_json(
        canary_receipt_path, trusted_uid=trusted_input_uid
    )
    current = (now or datetime.now(UTC)).astimezone(UTC)
    canary_observed_at = _validate_canary_receipt(
        canary_receipt,
        installed_at=installed_at,
        now=current,
        trusted_uid=trusted_input_uid,
    )
    check_results: dict[str, dict[str, Any]] = {}
    for check_name, selectors in CHECK_TESTS.items():
        result = test_runner(
            check_name,
            selectors,
            hermes_fixture=hermes_fixture,
            repo_root=repo_root,
        )
        if (
            not isinstance(result, dict)
            or result.get("status") != "pass"
            or result.get("tests") != len(selectors)
        ):
            raise EvidenceError(f"{check_name}_failed")
        check_results[check_name] = result
    report = _build_report(
        plugin_receipt=plugin_receipt,
        canary_receipt=canary_receipt,
        hermes_revision=hermes_revision,
        generated_at=current,
        canary_observed_at=canary_observed_at,
        check_results=check_results,
    )
    report_raw = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    candidate = _build_candidate(
        report_raw=report_raw,
        report=report,
        plugin_receipt=plugin_receipt,
    )
    candidate_raw = (
        json.dumps(candidate, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    if not _secret_safe(report) or not _secret_safe(candidate):
        raise EvidenceError("output_secret_safety_failed")
    output_directory.mkdir(mode=0o700)
    output_directory.chmod(0o700)
    report_path = output_directory / "h1-test-report.json"
    candidate_path = output_directory / "h1-candidate.json"
    try:
        _write_create_only(report_path, report_raw, 0o600)
        _write_create_only(candidate_path, candidate_raw, 0o600)
        directory_fd = os.open(
            output_directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        for path in (report_path, candidate_path):
            path.unlink(missing_ok=True)
        output_directory.rmdir()
        raise
    return {"report": report_path, "candidate": candidate_path}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate H1 Gate S owner evidence without admitting it"
    )
    parser.add_argument("--hermes-fixture", type=Path, required=True)
    parser.add_argument("--plugin-deployment-receipt", type=Path, required=True)
    parser.add_argument("--semantic-canary-receipt", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    try:
        result = generate_evidence(
            repo_root=repo_root,
            hermes_fixture=args.hermes_fixture,
            plugin_receipt_path=args.plugin_deployment_receipt,
            canary_receipt_path=args.semantic_canary_receipt,
            output_directory=args.output_directory,
        )
        payload = {
            "status": "pass",
            "source_revision": EXPECTED_PLUGIN_REF,
            "report": str(result["report"]),
            "candidate": str(result["candidate"]),
        }
        print(
            json.dumps(payload, sort_keys=True)
            if args.json
            else "H1 evidence generated"
        )
        return 0
    except (EvidenceError, OSError, subprocess.SubprocessError) as error:
        code = (
            str(error)
            if isinstance(error, EvidenceError)
            else "evidence_runtime_failed"
        )
        payload = {"status": "blocked", "code": code, "artifacts_emitted": False}
        print(
            json.dumps(payload, sort_keys=True) if args.json else f"blocked: {code}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
