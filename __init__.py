"""Telegram KB journey renderer plugin.

Intercepts a small set of Telegram slash commands and renders concise KB
status, review, and confirmed-receipt cards from a generated strict kb-engine
descriptor bundle. Sync uses the canonical prepare/status/resume contract;
Hermes transports and renders the engine-owned run without inventing semantics.
"""

from __future__ import annotations

import asyncio
import copy
import datetime as _dt
import hashlib
import inspect
import json
import logging
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fork-optional imports — degrade gracefully on plain upstream hermes-agent.
#
# tools.kb_callback_registry (KbAction) ships only in the fork.  On upstream
# we replace it with a no-op stub so every card-builder that calls KbAction(…)
# produces an object, but its presence in an ``actions`` list contributes NO
# inline-keyboard buttons (the gateway simply ignores stub instances it can't
# serialise into Telegram button rows).  All function-level guards that used to
# do `try: from tools.kb_callback_registry import KbAction` now reference this
# module-level symbol instead.
# ---------------------------------------------------------------------------

try:
    from tools.kb_callback_registry import KbAction as KbAction  # noqa: F401
    _KB_ACTION_AVAILABLE = True
except Exception:
    _KB_ACTION_AVAILABLE = False

    class KbAction:  # type: ignore[no-redef]
        """No-op stub used when the fork-only tools.kb_callback_registry is absent.

        Instantiation succeeds (accepting the same kwargs as the real class) but
        the stub carries NO callback data, so gateway adapters that inspect the
        type or look for a ``callback_data`` attribute will silently skip it —
        producing plain text-only cards with an empty inline keyboard.
        """

        def __init__(
            self,
            *,
            label: str = "",
            action_id: str = "",
            handler: Any = None,
            metadata: dict[str, Any] | None = None,
        ) -> None:
            self.label = label
            self.action_id = action_id
            self.handler = handler
            self.metadata = metadata or {}

        def __repr__(self) -> str:  # pragma: no cover
            return f"KbAction(stub, label={self.label!r})"


DEFAULT_MCP_TARGET = "kb_engine_prod"
MENU_COMMANDS = {"kb"}
LEGACY_COMMANDS = {"kbtoday", "kbstatus", "kbruns", "kbqueue", "kbreview", "kbrun"}
RETIRED_COMMANDS = {"kbsync", "update_kb"}
SUPPORTED_COMMANDS = MENU_COMMANDS
QUEUE_REPLY_DECISIONS = {"approve", "reject", "archive", "skip", "complete", "keep", "demote", "detail"}
QUEUE_REPLY_TOOL_DECISIONS = {"approve", "reject", "archive", "skip", "complete", "keep", "demote"}
QUEUE_REPLY_STATE_TTL_SECONDS = 15 * 60
QUEUE_SCOPE_STATE_TTL_SECONDS = 15 * 60
MEETING_HANDOFF_STATE_TTL_SECONDS = 15 * 60
SYNC_PREVIEW_STATE_TTL_SECONDS = 15 * 60
PUBLICATION_PREVIEW_STATE_TTL_SECONDS = 15 * 60
SYNC_RUN_STATE_TTL_SECONDS = 7 * 24 * 60 * 60
COMPLETION_READBACK_TTL_SECONDS = 5 * 60
COMPLETION_CLOCK_SKEW_SECONDS = 30
INTEGRATION_TRANSPORT_TOOL = "kb_integration_transport"
CALENDAR_LIVE_SOCKET = "/run/noc-calendar-live/executor.sock"
CALENDAR_LIVE_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
SYNC_PACKET_MAX_BYTES = 64 * 1024 * 1024
INTEGRATION_TRANSPORT_MAX_RESULT_BYTES = 90 * 1024
CONTEXT_SEARCH_MAX_WINDOW_DAYS = 45
CONTEXT_SEARCH_SLACK_MAX_WINDOW_DAYS = 7
CONTEXT_SEARCH_MAX_ITEMS_PER_SOURCE = 12
CONTEXT_SEARCH_DETAIL_LIMIT = 2
CONTEXT_SEARCH_COMMAND_TIMEOUT_SECONDS = 120
CONTEXT_SEARCH_SOURCES = frozenset(
    {"calendar", "mail", "slack", "meeting_artifacts", "tripit"}
)
SYNC_PACKET_RUN_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SEMANTIC_WRITE_RECEIPT_PACKET_TYPES = {
    "semantic_write_receipt",
    "semantic_write_through_receipt",
    "semantic_write_through.receipt",
    "semantic_write.receipt",
    "kb_semantic_write_receipt",
}
SEMANTIC_WRITE_SHADOW_PACKET_TYPES = {
    "semantic_write_through.shadow_preview",
}
SUPPORTED_RESULT_PACKET_TYPES = {
    "durable_graph_validation",
    "lifecycle_proposal_draft.packet",
    "lifecycle_review.packet",
    "lifecycle_update.packet",
    "publication_observation",
    "request.receipt",
    "report_admission_receipt",
    *SEMANTIC_WRITE_RECEIPT_PACKET_TYPES,
    *SEMANTIC_WRITE_SHADOW_PACKET_TYPES,
}
DESCRIPTOR_READONLY_TARGET_KINDS = {
    "closeout",
    "component",
    "dashboard_surface",
    "event",
    "lifecycle_candidate",
    "object_graph",
    "proposal_queue",
    "publication",
    "receipt",
    "report",
    "run",
    "situation",
    "sync",
    "todo",
}
DESCRIPTOR_WRITE_TARGET_KINDS = DESCRIPTOR_READONLY_TARGET_KINDS.difference(
    {"dashboard_surface", "lifecycle_candidate", "run"}
)
DESCRIPTOR_PROFILE = "journey_first_strict"
DESCRIPTOR_PATH = Path(__file__).resolve().parent / "generated" / "kb-engine-descriptors.json"
DESCRIPTOR_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LEGACY_DESCRIPTOR_NAMES = {"kb_sync.preview", "kb_sync.confirmed", "update_kb"}
UNTYPED_JSON_VALUE_DESCRIPTION = (
    "JSON/YAML-compatible value to assign at the field path."
)
INSTALL_RECEIPT_FIELDS = {
    "current_ref",
    "previous_ref",
    "installed_digest",
    "descriptor_digest",
    "installed_at",
    "noc_plan_digest",
}
INSTALL_EVIDENCE_FIELDS = {
    "owner",
    "source",
    "observed_at",
    "ttl_seconds",
    "ref_verified",
    "artifact_verified",
    "current_ref",
    "installed_digest",
    "descriptor_digest",
    "binding_digest",
}
EVIDENCE_BINDING_FIELDS = {
    "target",
    "preview_digest",
    "preview_lease",
    "idempotency_key",
    "evidence_packet_digest",
}
EVIDENCE_ENVELOPE_FIELDS = {
    *EVIDENCE_BINDING_FIELDS,
    "evidence_packet",
    "user_confirmation",
}


def _descriptor_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _utc_now_text() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat().replace("+00:00", "Z")


def _parse_aware_timestamp(value: Any) -> _dt.datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("timestamp is required")
    try:
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp is not ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(_dt.UTC)


def _schema_declared_types(schema: Any) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    found = {schema["type"]} if isinstance(schema.get("type"), str) else set()
    for branch in schema.get("allOf") or []:
        found.update(_schema_declared_types(branch))
    return found


def _schema_denies_type(schema: Any, schema_type: str) -> bool:
    """Return whether a denial schema covers every value of ``schema_type``."""
    if not isinstance(schema, dict):
        return False
    if schema.get("type") == schema_type:
        return True
    branches = schema.get("anyOf")
    if isinstance(branches, list) and any(
        _schema_denies_type(branch, schema_type) for branch in branches
    ):
        return True
    branches = schema.get("oneOf")
    if isinstance(branches, list) and len(branches) == 1:
        return _schema_denies_type(branches[0], schema_type)
    branches = schema.get("allOf")
    return bool(
        isinstance(branches, list)
        and branches
        and all(_schema_denies_type(branch, schema_type) for branch in branches)
    )


def _value_matches_schema_type(value: Any, schema_type: str) -> bool:
    if schema_type == "null":
        return value is None
    if schema_type == "boolean":
        return isinstance(value, bool)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "array":
        return isinstance(value, list)
    if schema_type == "object":
        return isinstance(value, dict)
    return False


def _json_value_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _schema_finite_values(schema: Any) -> set[str] | None:
    """Return a finite allowed-value set when enum/const constraints provide one."""
    if not isinstance(schema, dict):
        return None
    finite: set[str] | None = None
    if "const" in schema:
        finite = {_json_value_key(schema["const"])}
    if "enum" in schema and isinstance(schema.get("enum"), list):
        enum_values = {_json_value_key(value) for value in schema["enum"]}
        finite = enum_values if finite is None else finite.intersection(enum_values)
    for branch in schema.get("allOf") or []:
        branch_values = _schema_finite_values(branch)
        if branch_values is not None:
            finite = branch_values if finite is None else finite.intersection(branch_values)
    return finite


def _schema_constraint_values(schema: Any, key: str) -> list[Any]:
    if not isinstance(schema, dict):
        return []
    values = [schema[key]] if key in schema else []
    for branch in schema.get("allOf") or []:
        values.extend(_schema_constraint_values(branch, key))
    return values


def _validate_schema_ranges(schema: dict[str, Any], *, path: str) -> None:
    for key in ("minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties"):
        for value in _schema_constraint_values(schema, key):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{path}.{key} must be a non-negative integer")
    for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
        for value in _schema_constraint_values(schema, key):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"{path}.{key} must be a number")

    declared_types = _schema_declared_types(schema)
    for schema_type, minimum_key, maximum_key in (
        ("string", "minLength", "maxLength"),
        ("array", "minItems", "maxItems"),
        ("object", "minProperties", "maxProperties"),
    ):
        if schema_type not in declared_types:
            continue
        minimums = _schema_constraint_values(schema, minimum_key)
        maximums = _schema_constraint_values(schema, maximum_key)
        if minimums and maximums and max(minimums) > min(maximums):
            raise ValueError(f"{path} contains impossible {minimum_key}/{maximum_key} constraints")

    if not declared_types.intersection({"integer", "number"}):
        return
    lowers = [
        (value, False) for value in _schema_constraint_values(schema, "minimum")
    ] + [
        (value, True) for value in _schema_constraint_values(schema, "exclusiveMinimum")
    ]
    uppers = [
        (value, False) for value in _schema_constraint_values(schema, "maximum")
    ] + [
        (value, True) for value in _schema_constraint_values(schema, "exclusiveMaximum")
    ]
    if not lowers or not uppers:
        return
    lower_value = max(value for value, _exclusive in lowers)
    upper_value = min(value for value, _exclusive in uppers)
    lower_exclusive = any(exclusive for value, exclusive in lowers if value == lower_value)
    upper_exclusive = any(exclusive for value, exclusive in uppers if value == upper_value)
    if lower_value > upper_value or (
        lower_value == upper_value and (lower_exclusive or upper_exclusive)
    ):
        raise ValueError(f"{path} contains impossible numeric range constraints")


def _schema_required_fields(schema: Any) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    found = {item for item in schema.get("required") or [] if isinstance(item, str)}
    for branch in schema.get("allOf") or []:
        found.update(_schema_required_fields(branch))
    return found


def _schema_forbidden_required_fields(schema: Any) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    found: set[str] = set()
    denied = schema.get("not")
    if isinstance(denied, dict):
        found.update(item for item in denied.get("required") or [] if isinstance(item, str))
    for branch in schema.get("allOf") or []:
        found.update(_schema_forbidden_required_fields(branch))
    return found


def _schema_forbidden_types(schema: Any) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    found: set[str] = set()
    denied = schema.get("not")
    if isinstance(denied, dict):
        found.update(_schema_declared_types(denied))
    for branch in schema.get("allOf") or []:
        found.update(_schema_forbidden_types(branch))
    return found


def _schema_shape_is_concrete(schema: Any, *, require_required: bool) -> bool:
    if not isinstance(schema, dict):
        return False
    if isinstance(schema.get("$ref"), str) and schema["$ref"].strip():
        return True
    for keyword in ("oneOf", "anyOf"):
        if keyword in schema:
            branches = schema.get(keyword)
            return bool(
                isinstance(branches, list)
                and branches
                and all(
                    _schema_shape_is_concrete(branch, require_required=require_required)
                    for branch in branches
                )
            )
    if "allOf" in schema:
        branches = schema.get("allOf")
        return bool(
            isinstance(branches, list)
            and branches
            and any(
                _schema_shape_is_concrete(branch, require_required=require_required)
                for branch in branches
            )
        )
    properties = schema.get("properties")
    if schema.get("type") == "object":
        required = schema.get("required")
        if not isinstance(properties, dict) or not properties:
            return False
        return not require_required or (isinstance(required, list) and bool(required))
    return schema.get("type") in {"array", "boolean", "integer", "number", "string"}


def _required_branch_is_concrete(parent: Any, branch: Any) -> bool:
    if (
        not isinstance(parent, dict)
        or parent.get("type") != "object"
        or not isinstance(branch, dict)
        or set(branch) != {"required"}
    ):
        return False
    properties = parent.get("properties")
    required = branch.get("required")
    return bool(
        isinstance(properties, dict)
        and isinstance(required, list)
        and required
        and all(isinstance(name, str) and name in properties for name in required)
    )


def _validate_schema(schema: Any, *, path: str = "$") -> None:
    if not isinstance(schema, dict) or not schema:
        raise ValueError(f"{path} must be a non-empty schema object")
    has_shape = False
    ref = schema.get("$ref")
    if "$ref" in schema:
        if not isinstance(ref, str) or not ref.strip():
            raise ValueError(f"{path} has an invalid $ref")
        raise ValueError(f"{path} contains an unresolved $ref")
    for keyword in ("oneOf", "anyOf", "allOf"):
        if keyword not in schema:
            continue
        branches = schema[keyword]
        if not isinstance(branches, list) or not branches:
            raise ValueError(f"{path}.{keyword} must contain at least one schema")
        for index, branch in enumerate(branches):
            _validate_schema(branch, path=f"{path}.{keyword}[{index}]")
            if (
                keyword in {"oneOf", "anyOf"}
                and not _schema_shape_is_concrete(branch, require_required=False)
                and not _required_branch_is_concrete(schema, branch)
            ):
                raise ValueError(f"{path}.{keyword}[{index}] is unconstrained")
        if keyword == "oneOf":
            canonical = [_json_value_key(branch) for branch in branches]
            if len(canonical) != len(set(canonical)):
                raise ValueError(f"{path}.oneOf contains duplicate branches")
        has_shape = True
    schema_type = schema.get("type")
    if schema_type is not None:
        if schema_type not in {"array", "boolean", "integer", "null", "number", "object", "string"}:
            raise ValueError(f"{path} has an unsupported type")
        has_shape = True
    if schema_type == "object":
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise ValueError(f"{path}.properties must be an object")
        for name, child in properties.items():
            if not isinstance(name, str) or not name:
                raise ValueError(f"{path}.properties has an invalid name")
            _validate_schema(child, path=f"{path}.properties.{name}")
        required = schema.get("required", [])
        if not isinstance(required, list) or any(not isinstance(item, str) or not item for item in required):
            raise ValueError(f"{path}.required must contain field names")
        if len(required) != len(set(required)) or any(item not in properties for item in required):
            raise ValueError(f"{path}.required must be unique and reference properties")
        additional = schema.get("additionalProperties", True)
        if not isinstance(additional, bool):
            _validate_schema(additional, path=f"{path}.additionalProperties")
    elif "required" in schema:
        required = schema.get("required")
        if not isinstance(required, list) or any(not isinstance(item, str) or not item for item in required):
            raise ValueError(f"{path}.required must contain field names")
        if len(required) != len(set(required)):
            raise ValueError(f"{path}.required must be unique")
        has_shape = True
    if schema_type == "array":
        if "items" not in schema:
            raise ValueError(f"{path}.items is required for arrays")
        _validate_schema(schema["items"], path=f"{path}.items")
    if "enum" in schema:
        if not isinstance(schema["enum"], list) or not schema["enum"]:
            raise ValueError(f"{path}.enum must not be empty")
        if schema_type and any(
            not _value_matches_schema_type(value, schema_type) for value in schema["enum"]
        ):
            raise ValueError(f"{path}.enum contains a value incompatible with its type")
    if "const" in schema and schema_type and not _value_matches_schema_type(schema["const"], schema_type):
        raise ValueError(f"{path}.const is incompatible with its type")
    if "const" in schema or "enum" in schema:
        has_shape = True
    if "not" in schema:
        denied = schema["not"]
        if not isinstance(denied, dict) or not denied:
            raise ValueError(f"{path}.not must be a non-empty schema")
        _validate_schema(denied, path=f"{path}.not")
        has_shape = True
        if schema_type and _schema_denies_type(denied, schema_type):
            raise ValueError(f"{path} excludes its own type")
    if "allOf" in schema:
        declared_types = _schema_declared_types(schema)
        if len(declared_types) > 1:
            raise ValueError(f"{path}.allOf contains impossible type constraints")
        finite_values = _schema_finite_values(schema)
        if finite_values == set():
            raise ValueError(f"{path}.allOf contains disjoint enum/const constraints")
        if len(declared_types) == 1 and finite_values is not None and any(
            not _value_matches_schema_type(json.loads(value), next(iter(declared_types)))
            for value in finite_values
        ):
            raise ValueError(f"{path}.allOf contains enum/const values incompatible with its type")
    required_fields = _schema_required_fields(schema)
    forbidden_fields = _schema_forbidden_required_fields(schema)
    if required_fields.intersection(forbidden_fields):
        raise ValueError(f"{path} contains impossible required/not constraints")
    if _schema_declared_types(schema).intersection(_schema_forbidden_types(schema)):
        raise ValueError(f"{path} contains impossible type/not constraints")
    _validate_schema_ranges(schema, path=path)
    if (
        not has_shape
        and path.endswith(".properties.value")
        and schema == {"description": UNTYPED_JSON_VALUE_DESCRIPTION}
    ):
        return
    if not has_shape:
        raise ValueError(f"{path} has no type, reference, composition, enum, or const")


def _schema_is_concrete(schema: Any, *, require_required: bool = False) -> bool:
    try:
        _validate_schema(schema)
    except ValueError:
        return False
    return _schema_shape_is_concrete(schema, require_required=require_required)


def _runtime_schema_error(value: Any, schema: Any, *, path: str = "$") -> str | None:
    """Validate a runtime packet against the generated schema subset we export."""
    if not isinstance(schema, dict):
        return f"{path}: schema is unavailable"
    for keyword in ("allOf",):
        for index, branch in enumerate(schema.get(keyword) or []):
            error = _runtime_schema_error(value, branch, path=path)
            if error:
                return f"{path}: {keyword}[{index}] failed ({error})"
    if "anyOf" in schema:
        errors = [_runtime_schema_error(value, branch, path=path) for branch in schema["anyOf"]]
        if all(error is not None for error in errors):
            return f"{path}: no anyOf branch matched"
    if "oneOf" in schema:
        matches = sum(
            _runtime_schema_error(value, branch, path=path) is None for branch in schema["oneOf"]
        )
        if matches != 1:
            return f"{path}: expected exactly one oneOf match, got {matches}"
    if "not" in schema and _runtime_schema_error(value, schema["not"], path=path) is None:
        return f"{path}: matched forbidden schema"
    schema_type = schema.get("type")
    if schema_type and not _value_matches_schema_type(value, schema_type):
        return f"{path}: expected {schema_type}"
    if "required" in schema:
        if not isinstance(value, dict):
            return f"{path}: expected object for required properties"
        for name in schema.get("required") or []:
            if name not in value:
                return f"{path}.{name}: required property is missing"
    if "const" in schema and _json_value_key(value) != _json_value_key(schema["const"]):
        return f"{path}: does not match const"
    if "enum" in schema and _json_value_key(value) not in {
        _json_value_key(item) for item in schema["enum"]
    }:
        return f"{path}: is not in enum"
    if schema_type == "object" and isinstance(value, dict):
        properties = schema.get("properties") or {}
        for name, child_value in value.items():
            if name in properties:
                error = _runtime_schema_error(child_value, properties[name], path=f"{path}.{name}")
                if error:
                    return error
                continue
            additional = schema.get("additionalProperties", True)
            if additional is False:
                return f"{path}.{name}: additional property is forbidden"
            if isinstance(additional, dict):
                error = _runtime_schema_error(child_value, additional, path=f"{path}.{name}")
                if error:
                    return error
    if schema_type == "array" and isinstance(value, list):
        if isinstance(schema.get("minItems"), int) and len(value) < schema["minItems"]:
            return f"{path}: has fewer than minItems"
        if isinstance(schema.get("maxItems"), int) and len(value) > schema["maxItems"]:
            return f"{path}: has more than maxItems"
        if schema.get("uniqueItems") is True:
            canonical_items = [_json_value_key(item) for item in value]
            if len(canonical_items) != len(set(canonical_items)):
                return f"{path}: contains duplicate items"
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                error = _runtime_schema_error(item, item_schema, path=f"{path}[{index}]")
                if error:
                    return error
    if schema_type == "string" and isinstance(value, str):
        if isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
            return f"{path}: is shorter than minLength"
        if isinstance(schema.get("maxLength"), int) and len(value) > schema["maxLength"]:
            return f"{path}: is longer than maxLength"
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            return f"{path}: does not match pattern"
    if schema_type in {"integer", "number"} and _value_matches_schema_type(value, schema_type):
        if isinstance(schema.get("minimum"), (int, float)) and value < schema["minimum"]:
            return f"{path}: is below minimum"
        if isinstance(schema.get("maximum"), (int, float)) and value > schema["maximum"]:
            return f"{path}: is above maximum"
    return None


def _validate_descriptor_bundle(value: Any) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if not isinstance(value, dict):
        raise ValueError("descriptor bundle must be an object")
    body = dict(value)
    digest = body.pop("digest", None)
    if not isinstance(digest, str) or not DESCRIPTOR_DIGEST_RE.fullmatch(digest):
        raise ValueError("descriptor bundle digest is missing or invalid")
    if _descriptor_digest(body) != digest:
        raise ValueError("descriptor bundle digest does not match its content")
    if body.get("schema_version") != 1:
        raise ValueError("unsupported descriptor bundle schema")
    if body.get("profile") != DESCRIPTOR_PROFILE:
        raise ValueError("descriptor bundle is not the strict journey profile")
    if body.get("selection") != "primary_chat":
        raise ValueError("descriptor bundle is not the canonical primary_chat selection")
    if not isinstance(body.get("engine_version"), str) or not body["engine_version"].strip():
        raise ValueError("descriptor bundle has no engine version")
    engine_revision = body.get("engine_source_revision")
    if not isinstance(engine_revision, str) or not re.fullmatch(r"[0-9a-f]{40}", engine_revision):
        raise ValueError("descriptor bundle has no pinned engine source revision")
    source_digest = body.get("source_export_digest")
    if not isinstance(source_digest, str) or not DESCRIPTOR_DIGEST_RE.fullmatch(source_digest):
        raise ValueError("descriptor bundle has no valid exporter digest")
    tools = body.get("tools")
    if not isinstance(tools, list) or not tools or len(tools) > 13:
        raise ValueError("descriptor bundle must select between one and thirteen tools")
    tool_map: dict[str, dict[str, Any]] = {}
    for descriptor in tools:
        if not isinstance(descriptor, dict):
            raise ValueError("tool descriptor must be an object")
        name = descriptor.get("name")
        if not isinstance(name, str) or not name.strip() or name in tool_map:
            raise ValueError("tool descriptor names must be non-empty and unique")
        if name in LEGACY_DESCRIPTOR_NAMES or name.startswith("kb_sync."):
            raise ValueError("legacy KB sync descriptors are forbidden")
        input_schema = descriptor.get("input_schema")
        output_schema = descriptor.get("output_schema")
        if not isinstance(input_schema, dict) or not isinstance(output_schema, dict):
            raise ValueError(f"tool descriptor {name} must include concrete schemas")
        for label, schema in (("input", input_schema), ("output", output_schema)):
            try:
                _validate_schema(schema)
            except ValueError as exc:
                raise ValueError(f"tool descriptor {name} has an invalid {label} schema: {exc}") from exc
            if not _schema_is_concrete(schema, require_required=label == "output"):
                raise ValueError(f"tool descriptor {name} has an unconstrained {label} schema")
            digest_key = f"{label}_schema_digest"
            found = descriptor.get(digest_key)
            if not isinstance(found, str) or not DESCRIPTOR_DIGEST_RE.fullmatch(found):
                raise ValueError(f"tool descriptor {name} has an invalid {label} schema digest")
            if found != _descriptor_digest(schema):
                raise ValueError(f"tool descriptor {name} {label} schema digest does not match")
        annotations = descriptor.get("annotations") if isinstance(descriptor.get("annotations"), dict) else {}
        input_properties = input_schema.get("properties") if isinstance(input_schema.get("properties"), dict) else {}
        for executable_field in ("envelope", "preview"):
            executable_envelope = input_properties.get(executable_field)
            if (
                annotations.get("readOnlyHint") is False
                and executable_envelope is not None
                and not _schema_is_concrete(executable_envelope, require_required=True)
            ):
                raise ValueError(
                    f"tool descriptor {name} has an unconstrained executable envelope"
                )
        tool_map[name] = descriptor
    actions = body.get("actions")
    if not isinstance(actions, list):
        raise ValueError("descriptor bundle actions must be a list")
    for action in actions:
        if not isinstance(action, dict) or action.get("name") not in tool_map:
            raise ValueError("descriptor bundle action is not selected")
        selected = tool_map[str(action["name"])]
        if action.get("input_schema_digest") != selected.get("input_schema_digest"):
            raise ValueError("descriptor bundle action input schema digest does not match")
        if action.get("output_schema_digest") != selected.get("output_schema_digest"):
            raise ValueError("descriptor bundle action output schema digest does not match")
    return {**body, "digest": digest}, tool_map


def _load_descriptor_bundle(path: Path = DESCRIPTOR_PATH) -> tuple[dict[str, Any], dict[str, dict[str, Any]], str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        bundle, tool_map = _validate_descriptor_bundle(raw)
        return bundle, tool_map, ""
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        logger.error("kb_journeys: generated descriptor bundle is unavailable: %s", exc)
        return {}, {}, str(exc)


_DESCRIPTOR_BUNDLE, _DESCRIPTOR_TOOLS, _DESCRIPTOR_ERROR = _load_descriptor_bundle()


def _descriptor_allowlist() -> frozenset[str]:
    if not 1 <= len(_DESCRIPTOR_TOOLS) <= 13:
        return frozenset()
    return frozenset(_DESCRIPTOR_TOOLS)


def _descriptor(name: Any) -> dict[str, Any] | None:
    clean = str(name or "").strip()
    if clean not in _descriptor_allowlist():
        return None
    descriptor = _DESCRIPTOR_TOOLS.get(clean)
    return dict(descriptor) if isinstance(descriptor, dict) else None


def _plugin_readiness() -> dict[str, Any]:
    descriptor_status = "ready" if _descriptor_allowlist() else "blocked"
    if not _KB_ACTION_AVAILABLE:
        status = "text_only_degraded" if descriptor_status == "ready" else "blocked"
    else:
        status = descriptor_status
    return {
        "schema_version": 1,
        "status": status,
        "buttons": "ready" if _KB_ACTION_AVAILABLE else "unavailable",
        "descriptors": descriptor_status,
        "descriptor_digest": _DESCRIPTOR_BUNDLE.get("digest"),
    }


def _capability_unavailable(title: str, required: Iterable[str], *, message: str | None = None) -> dict[str, Any]:
    capabilities = [str(item) for item in required if str(item)]
    detail = message or (
        "Required capability " + "/".join(capabilities) + " is not available in the generated Hermes profile."
    )
    return {
        "title": title,
        "status": "temporarily_unavailable",
        "required_capabilities": capabilities,
        "text": f"{title}\n{detail}\nNo KB state changed.",
        "actions": [],
    }


def _sync_temporarily_unavailable() -> dict[str, Any]:
    card = _capability_unavailable(
        "KB Sync",
        ("kb.sync.prepare", "kb.sync.status", "kb.sync.resume"),
        message=(
            "The generated primary_chat profile does not expose the canonical "
            "kb.sync prepare/status/resume contract."
        ),
    )
    card["integration_blocker"] = "generated_kb_sync_contract_missing"
    return card


def _canonical_sync_contract_ready() -> bool:
    return all(
        _descriptor(name) is not None
        for name in ("kb.sync.prepare", "kb.sync.status", "kb.sync.resume")
    )


def _parse_install_receipt(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != INSTALL_RECEIPT_FIELDS:
        raise ValueError("install receipt fields do not match the plugin contract")
    receipt = {key: str(value.get(key) or "").strip() for key in INSTALL_RECEIPT_FIELDS}
    if any(not receipt[key] for key in INSTALL_RECEIPT_FIELDS):
        raise ValueError("install receipt fields must be non-empty")
    for key in ("installed_digest", "descriptor_digest", "noc_plan_digest"):
        if not DESCRIPTOR_DIGEST_RE.fullmatch(receipt[key]):
            raise ValueError(f"install receipt {key} is invalid")
    try:
        _parse_aware_timestamp(receipt["installed_at"])
    except ValueError as exc:
        raise ValueError(f"install receipt installed_at is invalid: {exc}") from exc
    return receipt


def _rollback_ref(receipt: dict[str, str]) -> str:
    return _parse_install_receipt(receipt)["previous_ref"]


def _install_evidence_status(receipt: dict[str, str], value: Any) -> tuple[str, str]:
    if value is None:
        return "not_observed", "no authenticated live NOC installation evidence was supplied"
    if not isinstance(value, dict) or set(value) != INSTALL_EVIDENCE_FIELDS:
        return "unverified", "installation evidence fields do not match the contract"
    evidence = dict(value)
    binding_digest = str(evidence.pop("binding_digest") or "").strip()
    if binding_digest != _descriptor_digest(evidence):
        return "unverified", "installation evidence digest does not match"
    if evidence.get("owner") != "noc" or not str(evidence.get("source") or "").startswith("noc."):
        return "unverified", "caller-asserted installation evidence owner/source is not trusted"
    if evidence.get("ref_verified") is not True or evidence.get("artifact_verified") is not True:
        return "unverified", "installation artifact/ref evidence is not verified"
    try:
        observed_at = _parse_aware_timestamp(evidence.get("observed_at"))
        ttl_seconds = int(evidence.get("ttl_seconds"))
    except (TypeError, ValueError):
        return "unverified", "installation evidence freshness fields are invalid"
    if not 1 <= ttl_seconds <= 86400:
        return "unverified", "installation evidence TTL is outside the allowed range"
    now = _dt.datetime.now(_dt.UTC)
    if observed_at > now + _dt.timedelta(minutes=5):
        return "unverified", "installation evidence is future-dated"
    if now > observed_at + _dt.timedelta(seconds=ttl_seconds):
        return "unverified", "installation evidence is expired"
    if not _DESCRIPTOR_BUNDLE or receipt["descriptor_digest"] != _DESCRIPTOR_BUNDLE.get("digest"):
        return "unverified", "receipt descriptor digest does not match the loaded bundle"
    for key in ("current_ref", "installed_digest", "descriptor_digest"):
        if str(evidence.get(key) or "") != receipt[key]:
            return "unverified", f"installation evidence {key} does not match the receipt"
    return (
        "unverified",
        "caller-supplied evidence is internally consistent but is not an authenticated NOC observation",
    )


def _render_install_receipt(value: Any, *, installed_evidence: Any = None) -> dict[str, Any]:
    try:
        receipt = _parse_install_receipt(value)
    except ValueError as exc:
        return {
            "title": "Hermes KB Plugin Install",
            "status": "unknown",
            "text": f"Hermes KB Plugin Install\nInstall receipt is invalid: {exc}",
            "actions": [],
        }
    status, evidence_reason = _install_evidence_status(receipt, installed_evidence)
    if status == "not_observed":
        posture = "Receipt recorded; this is not live verification of the installed artifact or ref."
    elif status == "unverified":
        posture = (
            f"Caller-supplied evidence remains unverified ({evidence_reason}) until it arrives "
            "through an authenticated NOC observation channel."
        )
    return {
        "title": "Hermes KB Plugin Install",
        "status": status,
        "text": "\n".join(
            [
                "Hermes KB Plugin Install",
                posture,
                f"Current ref: {receipt['current_ref']}",
                f"Previous ref: {receipt['previous_ref']}",
                f"Installed digest: {receipt['installed_digest']}",
                f"Descriptor digest: {receipt['descriptor_digest']}",
                f"Installed at: {receipt['installed_at']}",
                f"NOC plan digest: {receipt['noc_plan_digest']}",
            ]
        ),
        "actions": [],
    }


def _sanitize_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", str(value or ""))


def _mcp_target() -> str:
    return os.getenv("HERMES_KB_MCP_TARGET", DEFAULT_MCP_TARGET).strip() or DEFAULT_MCP_TARGET


def _mcp_tool_name(target: str, tool_name: str) -> str:
    return f"mcp_{_sanitize_component(target)}_{_sanitize_component(tool_name)}"


# ---------------------------------------------------------------------------
# Probe-scoped telemetry
#
# This is deliberately not a general telemetry surface. NOC may give an
# isolated Hermes probe one inherited pipe plus an opaque run id. Only that
# exact process registers observer callbacks, keeps aggregate counters in
# memory, and writes one secret-free packet. Normal Hermes processes pay no
# observer-payload construction cost because they register none of these
# callbacks.
# ---------------------------------------------------------------------------

_PROBE_TELEMETRY_FD_ENV = "NOC_HERMES_PROBE_TELEMETRY_FD"
_PROBE_TELEMETRY_RUN_ID_ENV = "NOC_HERMES_PROBE_RUN_ID"
_PROBE_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class _ProbeTelemetry:
    def __init__(self, *, fd: int, run_id: str) -> None:
        self._fd = fd
        self._run_id = run_id
        self._lock = threading.Lock()
        self._model_calls = 0
        self._engine_tool_call_ids: set[str] = set()
        self._engine_complete = True
        self._context_seen = False
        self._context_complete = True
        self._max_context_bytes = 0
        self._emitted = False

    @staticmethod
    def _canonical_context_bytes(messages: Any) -> int | None:
        if not isinstance(messages, list):
            return None
        try:
            encoded = json.dumps(
                messages,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            return None
        return len(encoded)

    def record_pre_api_request(self, **kwargs: Any) -> None:
        context_bytes = self._canonical_context_bytes(
            kwargs.get("request_messages")
        )
        with self._lock:
            if self._emitted:
                return
            # Hermes fires this hook once immediately before each provider
            # attempt, including retry attempts.
            self._model_calls += 1
            if context_bytes is None:
                self._context_complete = False
            else:
                self._context_seen = True
                self._max_context_bytes = max(
                    self._max_context_bytes, context_bytes
                )

    def _matches_engine_tool(self, tool_name: Any) -> bool:
        prefix = f"mcp_{_sanitize_component(_mcp_target())}_"
        return str(tool_name or "").startswith(prefix)

    def record_observed_tool(self, **kwargs: Any) -> None:
        if not self._matches_engine_tool(kwargs.get("tool_name")):
            return
        tool_call_id = str(kwargs.get("tool_call_id") or "")
        with self._lock:
            if self._emitted:
                return
            if not tool_call_id:
                # Hermes has historically delivered some post-tool hooks more
                # than once. Without an id there is no truthful way to
                # distinguish a duplicate observer event from another call.
                self._engine_complete = False
                return
            self._engine_tool_call_ids.add(
                hashlib.sha256(
                    tool_call_id.encode("utf-8", errors="replace")
                ).hexdigest()
            )

    def emit(self) -> None:
        with self._lock:
            if self._emitted:
                return
            self._emitted = True
            context_complete = self._context_complete and (
                self._model_calls == 0 or self._context_seen
            )
            observation_complete = context_complete and self._engine_complete
            packet = {
                "schema_version": 1,
                "kind": "hermes_probe_telemetry",
                "run_id": self._run_id,
                "status": "complete" if observation_complete else "incomplete",
                "model_calls": self._model_calls,
                "engine_calls": (
                    len(self._engine_tool_call_ids)
                    if self._engine_complete
                    else None
                ),
                "context_bytes": self._max_context_bytes if context_complete else None,
            }
            encoded = (
                json.dumps(
                    packet,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")
        try:
            # The packet is far below POSIX PIPE_BUF, so one write is atomic.
            os.write(self._fd, encoded)
        except OSError:
            # Probe telemetry must never alter the user turn. The NOC caller
            # treats a missing packet as failed observation.
            return


_PROBE_TELEMETRY: _ProbeTelemetry | None = None


def _probe_telemetry_from_env() -> _ProbeTelemetry | None:
    fd_text = os.getenv(_PROBE_TELEMETRY_FD_ENV, "")
    run_id = os.getenv(_PROBE_TELEMETRY_RUN_ID_ENV, "")
    if not fd_text and not run_id:
        return None
    if not fd_text.isascii() or not fd_text.isdecimal():
        return None
    if not _PROBE_RUN_ID_RE.fullmatch(run_id):
        return None
    try:
        fd = int(fd_text)
        if fd <= 2 or fd > 1_048_576 or not os.get_inheritable(fd):
            return None
        import fcntl
        import stat

        descriptor = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if not stat.S_ISFIFO(descriptor.st_mode):
            return None
        if (flags & os.O_ACCMODE) not in {os.O_WRONLY, os.O_RDWR}:
            return None
    except (ImportError, OSError, OverflowError, ValueError):
        return None
    return _ProbeTelemetry(fd=fd, run_id=run_id)


def _activate_probe_telemetry(ctx: Any) -> None:
    global _PROBE_TELEMETRY
    if _PROBE_TELEMETRY is None:
        _PROBE_TELEMETRY = _probe_telemetry_from_env()
    if _PROBE_TELEMETRY is None:
        return
    ctx.register_hook("pre_api_request", _PROBE_TELEMETRY.record_pre_api_request)
    ctx.register_hook("post_tool_call", _PROBE_TELEMETRY.record_observed_tool)


def _emit_probe_telemetry() -> None:
    if _PROBE_TELEMETRY is not None:
        _PROBE_TELEMETRY.emit()


def _hermes_state_path(filename: str) -> Path:
    try:
        from hermes_constants import get_hermes_home

        home = Path(get_hermes_home())
    except (ImportError, ModuleNotFoundError):
        home = Path(os.environ.get("HERMES_HOME", "~/.hermes")).expanduser()
    return home / "state" / filename


def _queue_reply_state_path():
    return _hermes_state_path("kb_queue_reply_state.json")


def _queue_scope_state_path():
    return _hermes_state_path("kb_queue_scope_state.json")


def _meeting_handoff_state_path():
    return _hermes_state_path("kb_meeting_handoff_state.json")


def _sync_preview_state_path():
    return _hermes_state_path("kb_sync_preview_state.json")


def _publication_preview_state_path():
    return _hermes_state_path("kb_publication_preview_state.json")


def _load_queue_reply_states() -> dict[str, Any]:
    path = _queue_reply_state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_queue_reply_states(states: dict[str, Any]) -> None:
    path = _queue_reply_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(states, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        logger.debug("kb_journeys: failed to persist iterative queue state", exc_info=True)


def _load_queue_scope_states() -> dict[str, Any]:
    path = _queue_scope_state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_queue_scope_states(states: dict[str, Any]) -> None:
    path = _queue_scope_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(states, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        logger.debug("kb_journeys: failed to persist queue scope state", exc_info=True)


def _load_meeting_handoff_states() -> dict[str, Any]:
    path = _meeting_handoff_state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _load_sync_preview_states() -> dict[str, Any]:
    path = _sync_preview_state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_meeting_handoff_states(states: dict[str, Any]) -> None:
    path = _meeting_handoff_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(states, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        logger.debug("kb_journeys: failed to persist meeting handoff state", exc_info=True)


def _save_sync_preview_states(states: dict[str, Any]) -> None:
    path = _sync_preview_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(states, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        path.chmod(0o600)
    except OSError:
        logger.debug("kb_journeys: failed to persist sync preview state", exc_info=True)


def _load_publication_preview_states() -> dict[str, Any]:
    path = _publication_preview_state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_publication_preview_states(states: dict[str, Any]) -> None:
    path = _publication_preview_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(states, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        path.chmod(0o600)
    except OSError:
        logger.debug("kb_journeys: failed to persist publication preview state", exc_info=True)


def _clear_publication_preview_state(session_id: str) -> None:
    if not session_id:
        return
    states = _load_publication_preview_states()
    if states.pop(session_id, None) is not None:
        _save_publication_preview_states(states)


def _clear_meeting_handoff_state(session_id: str) -> None:
    if not session_id:
        return
    states = _load_meeting_handoff_states()
    if session_id in states:
        states.pop(session_id, None)
        _save_meeting_handoff_states(states)


def _clear_iterative_queue_reply_state(session_id: str) -> None:
    if not session_id:
        return
    states = _load_queue_reply_states()
    if session_id in states:
        states.pop(session_id, None)
        _save_queue_reply_states(states)


def _platform_name(platform: Any) -> str:
    return str(getattr(platform, "value", platform) or "").lower()


def _command_from_text(text: str) -> str | None:
    stripped = (text or "").strip()
    if not stripped.startswith("/"):
        return None
    token = stripped.split(maxsplit=1)[0][1:]
    command = token.split("@", 1)[0].lower()
    if command in RETIRED_COMMANDS:
        return "kbmigration"
    return command if command in MENU_COMMANDS or command in LEGACY_COMMANDS else None


def _command_args_from_text(text: str) -> str:
    stripped = (text or "").strip()
    if not stripped.startswith("/"):
        return ""
    parts = stripped.split(maxsplit=1)
    return parts[1].strip() if len(parts) > 1 else ""


def _prose_kb_command_from_text(text: str) -> tuple[str, str] | None:
    stripped = (text or "").strip()
    if not stripped or stripped.startswith("/"):
        return None
    normalized = re.sub(r"[?!.,;:]+", "", stripped.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()
    match = re.match(r"^kb\s+(status|sync|review|publish)\b(?:\s+(.*))?$", normalized)
    if match:
        verb = match.group(1)
        rest = (match.group(2) or "").strip()
        return {
            "status": "kbstatus",
            "sync": "kbsync_run",
            "review": "kblifecycle",
            "publish": "kbpublish",
        }[verb], rest
    if re.search(r"\breview queue\b", normalized) and re.search(
        r"\b(?:what(?: is|'s)?|show|list|open|view|display|check|pending|in)\b",
        normalized,
    ):
        return "kblifecycle", ""
    return None


def _short(value: Any, default: str = "unknown") -> str:
    if value is None:
        return default
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value).strip()
    return text if text else default


def _clip(value: Any, limit: int = 220) -> str:
    text = re.sub(r"\s+", " ", _short(value, "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "..."


_PRIVATE_PATH_RE = re.compile(r"(?:(?:/home|/Users|/var|/opt)/[^\s,;]+)")
_DIGEST_RE = re.compile(r"\bsha256:[0-9a-f]{32,}\b", re.IGNORECASE)
_MCP_NAME_RE = re.compile(r"\bmcp_[A-Za-z0-9_]+\b")
_CAPABILITY_NAME_RE = re.compile(
    r"\b(?:attention|change|kb\.sync|policy|publication|search|workspace)\.[A-Za-z0-9_.-]+\b"
)


def _public_clip(value: Any, limit: int = 180) -> str:
    """Bound user-facing text and remove implementation-only identifiers."""
    text = re.sub(r"\s+", " ", _short(value, "")).strip()
    text = _PRIVATE_PATH_RE.sub("an internal location", text)
    text = _DIGEST_RE.sub("an integrity detail", text)
    text = _MCP_NAME_RE.sub("the knowledge service", text)
    text = _CAPABILITY_NAME_RE.sub("the knowledge service", text)
    return _clip(text, limit)


_EXPANDABLE_MIN_LINES = 3  # only collapse genuinely long bodies


def _expandable_block(text: str) -> str:
    """Wrap a multi-line body in a Telegram EXPANDABLE blockquote.

    telegram.py _convert_blockquote regex is r'^((?:\\*\\*)?>{1,3}) (.+)$'
    (a SPACE is required after the '>'/'**>' prefix). The expandable variant
    fires when a matched line has a '**>' prefix AND content ending in '||'.
    We therefore emit:  '**> <first>||'  then  '> <line>' continuations.
    Short bodies pass through unchanged. PLUGIN-DATA-SHAPE-ONLY: no fork-core
    edit; format_message already understands this marker.
    """
    if not text:
        return text
    lines = text.splitlines()
    if len(lines) < _EXPANDABLE_MIN_LINES:
        return text
    first, *rest = lines
    head = f"**> {first}||"           # space after **> ; || marks expandable on this matched line
    tail = [f"> {ln}" for ln in rest]  # space after > on every continuation line
    return "\n".join([head, *tail])


def _emphasis_headline(label: str) -> str:
    """Bold a card headline in MarkdownV2. PLUGIN-DATA-SHAPE-ONLY.

    Assumes ``label`` is plain headline text that the caller's text assembly
    will escape via format_message; we only add the '*' emphasis markers and
    add NO escapes (caller owns escaping). Only bold short, control-char-free
    headline labels (no interpolated user/MCP free-text).
    """
    label = (label or "").strip()
    return f"*{label}*" if label else label


# ----------------------------------------------------------------------------
# RAW-markdown rich-card builders (Bot API 10.1 sendRichMessage).
#
# These emit RAW markdown (NOT format_message/MarkdownV2-escaped) for the
# separate ``rich_markdown`` card field. The adapter passes this verbatim into
# rich_message.markdown, so Telegram parses '#' headings and '|' tables
# server-side. The legacy ``text`` field stays MarkdownV2-escaped for fallback.
# PLUGIN-DATA-SHAPE-ONLY: no fork-core edit.
# ----------------------------------------------------------------------------
_RICH_CELL_RE = re.compile(r"[|\n]")


def _rich_cell(value: Any) -> str:
    """Sanitize a value for a single rich-markdown table cell.

    Pipes and newlines would break the table grammar; collapse them so a stray
    MCP value can never split or escape its cell.
    """
    return _RICH_CELL_RE.sub(" ", _short(value, "")).strip()


def _rich_heading(label: str) -> str:
    """A level-2 rich-markdown heading (Telegram renders it as a SectionHeading).

    The label is run through the same newline/pipe collapse used for table
    cells (``_RICH_CELL_RE``) so a dashboard section title carrying a stray
    newline or pipe can never break the heading line or bleed into the
    following table grammar.
    """
    collapsed = _RICH_CELL_RE.sub(" ", (label or "")).strip()
    return f"## {collapsed}".rstrip()


def _rich_kv_table(title: str, pairs: list[tuple[str, Any]]) -> str:
    """Render ``(key, value)`` pairs as a 2-column rich-markdown table.

    Empty values are kept so the row count is stable and the card reads as a
    complete status sheet. Returns a heading + table block.
    """
    lines = [_rich_heading(title), "", "| Field | Value |", "| --- | --- |"]
    for key, value in pairs:
        lines.append(f"| {_rich_cell(key)} | {_rich_cell(value)} |")
    return "\n".join(lines)


def _rich_bullets(items: Iterable[Any]) -> list[str]:
    """Render values as a rich-markdown bullet list."""
    return [f"- {_rich_cell(item)}" for item in items if _rich_cell(item)]


def _request_receipt(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    receipt = payload.get("receipt") or payload.get("request_receipt")
    if isinstance(receipt, dict):
        return receipt
    if payload.get("packet_type") == "request.receipt":
        return payload
    return {}


def _request_outcome(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    outcome = payload.get("outcome") or payload.get("request_outcome")
    return outcome if isinstance(outcome, dict) else {}


def _request_envelope(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    request = payload.get("request") or payload.get("request_envelope")
    return request if isinstance(request, dict) else {}


def _dedupe_list(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _object_reference_lines(*packets: dict[str, Any], include_report_ref: bool = False) -> list[str]:
    object_family = ""
    report_refs: list[str] = []
    related_refs: list[str] = []
    for packet in packets:
        if not isinstance(packet, dict):
            continue
        if not object_family:
            object_family = _short(packet.get("object_family"), "")
        if include_report_ref:
            report_refs.extend(_id_list(packet.get("report_ref")))
        report_refs.extend(_id_list(packet.get("report_refs")))
        related_refs.extend(_id_list(packet.get("related_object_refs")))
        related_refs.extend(_id_list(packet.get("related_objects")))
    lines: list[str] = []
    if object_family:
        lines.append(f"Object family: {object_family}")
    report_refs = _dedupe_list(report_refs)
    related_refs = _dedupe_list(related_refs)
    if report_refs:
        lines.append(_id_line("Report refs", report_refs))
    if related_refs:
        lines.append(_id_line("Related objects", related_refs))
    return lines


def _receipt_lines(payload: Any, *, include_request: bool = False) -> list[str]:
    receipt = _request_receipt(payload)
    outcome = _request_outcome(payload)
    request = _request_envelope(payload)
    lines: list[str] = []
    if not receipt and not outcome and not request:
        return lines
    if receipt:
        state = _short(receipt.get("state") or receipt.get("status"), "")
        if state:
            lines.append(f"Receipt: {state}")
        effect = _short(receipt.get("durable_effect"), "")
        if effect:
            lines.append(f"Effect: {effect}")
        if receipt.get("llm_invoked_by_read_surface") is not None:
            lines.append(
                "Read-surface LLM: "
                + ("yes" if receipt.get("llm_invoked_by_read_surface") else "no")
            )
        next_step = _short(receipt.get("next_step"), "")
        if next_step:
            lines.append(f"Next: {_clip(next_step, 180)}")
    if outcome:
        family = _short(outcome.get("family") or outcome.get("status"), "")
        if family:
            lines.append(f"Outcome: {family}")
    lines.extend(_object_reference_lines(outcome, receipt))
    if include_request and request:
        kind = _short(request.get("kind") or request.get("request_kind"), "")
        route = _short(request.get("route"), "")
        if kind or route:
            lines.append(f"Request: {kind or 'request'}" + (f" via {route}" if route else ""))
    return lines


def _packet_kind(packet: Any) -> str:
    if not isinstance(packet, dict):
        return ""
    return _short(
        packet.get("packet_type")
        or packet.get("kind")
        or packet.get("packet_kind")
        or packet.get("type"),
        "",
    )


def _first_result_packet(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    if _packet_kind(payload) in SUPPORTED_RESULT_PACKET_TYPES:
        return payload
    for key in (
        "output",
        "result",
        "receipt",
        "packet",
        "preview",
        "shadow_preview",
        "lifecycle_update",
        "semantic_preview",
        "publication_observation",
        "graph_validation",
        "report_admission_receipt",
    ):
        nested = payload.get(key)
        if isinstance(nested, dict) and _packet_kind(nested) in SUPPORTED_RESULT_PACKET_TYPES:
            return nested
    return {}


def _warning_lines(warnings: Any, *, limit: int = 3) -> list[str]:
    if not isinstance(warnings, list) or not warnings:
        return []
    lines = [f"Warnings: {len(warnings)}"]
    for warning in warnings[:limit]:
        if isinstance(warning, dict):
            code = _short(warning.get("code") or warning.get("warning"), "")
            ref = _short(warning.get("ref") or warning.get("path") or warning.get("object_ref"), "")
            detail = _clip(warning.get("message") or warning.get("detail") or warning.get("summary"), 160)
            text = " - ".join(part for part in (code, ref, detail) if part)
            lines.append(f"- {text or 'warning'}")
        else:
            lines.append(f"- {_clip(warning, 180)}")
    return lines


def _render_report_admission_packet(packet: dict[str, Any]) -> dict[str, Any]:
    title = _short(packet.get("title") or packet.get("report_ref"), "Report Admission")
    status = _short(packet.get("status"))
    report_ref = _short(packet.get("report_ref"), "")
    event_ref = _short(packet.get("event_ref"), "")
    event_role = _short(packet.get("event_role"), "")
    situation_ref = _short(packet.get("situation_ref"), "")
    transfers = packet.get("source_transfers") if isinstance(packet.get("source_transfers"), list) else []
    changed_paths = _changed_paths(packet)
    validation = packet.get("graph_validation") if isinstance(packet.get("graph_validation"), dict) else {}
    lines = [
        "Report Admission",
        f"Status: {status}",
        f"Report: {report_ref or title}",
    ]
    if title and title != report_ref:
        lines.append(f"Title: {title}")
    if event_ref:
        lines.append(f"Event: {event_ref}" + (f" ({event_role})" if event_role else ""))
    if situation_ref:
        lines.append(f"Situation: {situation_ref}")
    lines.extend(_object_reference_lines(packet, include_report_ref=True))
    if transfers:
        lines.append(f"Source files: {len(transfers)}")
    if changed_paths:
        lines.append(f"Changed paths: {len(changed_paths)}")
        lines.extend(_format_changed_paths(changed_paths, limit=5))
    if validation:
        lines.append(
            "Graph validation: "
            + _short(validation.get("status") or ("ok" if validation.get("ok") else "warning"))
        )
    lines.extend(_warning_lines(packet.get("warnings")))
    if status == "preview":
        lines.append("No durable write has been made.")
    return {"title": "Report Admission", "text": "\n".join(lines), "actions": []}


def _render_graph_validation_packet(packet: dict[str, Any]) -> dict[str, Any]:
    status = _short(packet.get("status") or ("ok" if packet.get("ok") else "warning"))
    warning_count = packet.get("warning_count")
    error_count = packet.get("error_count")
    lines = [
        "KB Graph Validation",
        f"Status: {status}",
    ]
    if warning_count is not None or error_count is not None:
        lines.append(
            f"Warnings: {_short(warning_count, '0')} · Errors: {_short(error_count, '0')}"
        )
    lines.extend(_warning_lines(packet.get("warnings"), limit=5))
    return {"title": "KB Graph Validation", "text": "\n".join(lines), "actions": []}


def _lifecycle_values(value: Any) -> list[str]:
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if not isinstance(value, list):
        return []
    values: list[str] = []
    for item in value:
        if isinstance(item, dict):
            found = ""
            for key in ("ref", "id", "target_ref", "path", "title", "summary", "message"):
                found = _short(item.get(key), "")
                if found:
                    break
            if found:
                values.append(found)
        else:
            text = str(item).strip()
            if text:
                values.append(text)
    return _dedupe_list(values)


def _lifecycle_signal_lines(signal: Any) -> list[str]:
    if not isinstance(signal, dict):
        return []
    lines: list[str] = []
    source = _short(signal.get("source"), "")
    observed = _short(signal.get("observed_at"), "")
    if source or observed:
        parts = []
        if source:
            parts.append(f"Source: {source}")
        if observed:
            parts.append(f"Observed: {observed}")
        lines.append("   " + " · ".join(parts))
    kind = _short(signal.get("kind"), "")
    polarity = _short(signal.get("polarity"), "")
    confidence = _short(signal.get("confidence"), "")
    signal_parts = [part for part in (kind, polarity) if part]
    if signal_parts or confidence:
        suffix = f" ({confidence})" if confidence else ""
        lines.append(f"   Signal: {' / '.join(signal_parts) or 'lifecycle'}{suffix}")
    evidence_refs = _dedupe_list([
        _short(signal.get("source_ref"), ""),
        *_lifecycle_values(signal.get("evidence_refs")),
    ])
    if evidence_refs:
        lines.append(f"   Signal evidence refs: {len(evidence_refs)}")
        lines.append(_id_line("   Signal evidence", evidence_refs, limit=3))
    summary = _short(signal.get("summary"), "")
    if summary:
        lines.append(f"   Signal summary: {_clip(summary, 220)}")
    return lines


def _is_lifecycle_proposal_descriptor(descriptor: dict[str, Any]) -> bool:
    if not isinstance(descriptor, dict):
        return False
    if descriptor.get("dashboard_owned_write") is True:
        return False
    preview_tool = str(descriptor.get("preview_tool") or descriptor.get("method") or "").strip()
    action_id = str(descriptor.get("action_id") or "").strip()
    target_kind = str(descriptor.get("target_kind") or "").strip()
    return (
        target_kind == "lifecycle_candidate"
        or action_id.startswith("lifecycle.")
        or preview_tool.startswith("lifecycle.proposal_")
    ) and bool(preview_tool)


def _lifecycle_candidate_descriptor(candidate: dict[str, Any]) -> dict[str, Any]:
    descriptor = candidate.get("action_descriptor")
    if isinstance(descriptor, dict) and _is_lifecycle_proposal_descriptor(descriptor):
        return dict(descriptor)
    descriptors = candidate.get("action_descriptors")
    if isinstance(descriptors, list):
        for item in descriptors:
            if isinstance(item, dict) and _is_lifecycle_proposal_descriptor(item):
                return dict(item)
    return {}


def _render_lifecycle_proposal_draft_packet(packet: dict[str, Any]) -> dict[str, Any]:
    workflow = _short(packet.get("workflow"), "Lifecycle Review")
    stewardship = _short(packet.get("stewardship_area"), "")
    proposals = packet.get("proposals") if isinstance(packet.get("proposals"), list) else []
    proposal_count = packet.get("proposal_count")
    if proposal_count is None:
        proposal_count = len(proposals)
    lines = [
        "Lifecycle Proposal Draft",
        f"Workflow: {workflow}",
    ]
    if stewardship:
        lines.append(f"Stewardship: {stewardship}")
    if packet.get("mutation_performed") is not None:
        lines.append("Mutation: " + ("performed" if packet.get("mutation_performed") else "none"))
    lines.append(f"Proposals: {_short(proposal_count, '0')}")
    for index, proposal in enumerate(proposals[:5], start=1):
        if not isinstance(proposal, dict):
            lines.append(f"{index}. {_clip(proposal, 180)}")
            continue
        title = _short(
            proposal.get("proposal_id")
            or proposal.get("id")
            or proposal.get("target_ref")
            or proposal.get("title"),
            "proposal",
        )
        lines.append(f"{index}. {title}")
        action = _short(proposal.get("recommended_action") or proposal.get("action"), "")
        target_ref = _short(proposal.get("target_ref"), "")
        summary = _short(proposal.get("summary") or proposal.get("preview") or proposal.get("description"), "")
        if action:
            lines.append(f"   Action: {action}")
        if target_ref:
            lines.append(f"   Target: {target_ref}")
        if summary:
            lines.append(f"   Summary: {_clip(summary, 180)}")
    if len(proposals) > 5:
        lines.append(f"... {len(proposals) - 5} more proposal(s)")
    lines.append("No durable write has been made.")
    return {"title": "Lifecycle Proposal Draft", "text": "\n".join(lines), "actions": []}


def _render_lifecycle_descriptor_preview(
    ctx: Any,
    target: str,
    *,
    descriptor: dict[str, Any],
    callback_ctx: Any,
) -> dict[str, Any]:
    del callback_ctx
    label = _short(descriptor.get("label") or descriptor.get("action_id") or "Lifecycle proposal", "Lifecycle proposal")
    preview_tool = _descriptor_tool_name(target, descriptor.get("preview_tool") or descriptor.get("method"))
    payload = _dispatch_registry_tool(ctx, target, preview_tool, _descriptor_params(descriptor))
    if isinstance(payload, dict) and payload.get("error"):
        return {"title": label, "text": f"{label}\n{payload['error']}", "actions": []}
    packet_card = _render_supported_result_packet(payload, ctx=ctx, target=target)
    if packet_card is not None:
        packet_card["actions"] = []
        if "No durable write has been made." not in packet_card["text"]:
            packet_card["text"] += "\nNo durable write has been made."
        return packet_card
    if not isinstance(payload, dict):
        return {"title": label, "text": f"{label}\n{_short(payload, 'No proposal preview returned.')}", "actions": []}
    lines = [
        "Lifecycle Proposal Preview",
        f"Status: {_short(payload.get('status') or payload.get('state'), 'preview')}",
    ]
    summary = _short(payload.get("summary") or payload.get("message"), "")
    if summary:
        lines.append("Summary: " + _clip(summary, 260))
    target_ref = _short(payload.get("target_ref") or descriptor.get("target_ref"), "")
    if target_ref:
        lines.append(f"Target: {target_ref}")
    lines.append("No durable write has been made.")
    return {"title": label, "text": "\n".join(lines), "actions": []}


def _lifecycle_descriptor_action(ctx: Any, target: str, descriptor: dict[str, Any]) -> Any | None:
    if not _is_lifecycle_proposal_descriptor(descriptor):
        return None
    label = _short(descriptor.get("label") or descriptor.get("action_id") or "Lifecycle proposal", "Lifecycle proposal")
    action_id = _short(descriptor.get("action_id") or label, label)
    preview_tool = _descriptor_tool_name(target, descriptor.get("preview_tool") or descriptor.get("method"))
    confirm_tool = _descriptor_tool_name(target, descriptor.get("confirm_tool"))
    if not preview_tool or not confirm_tool:
        return None
    return KbAction(
        label=label,
        action_id=f"{action_id}.preview",
        handler=lambda callback_ctx, d=dict(descriptor): _render_generic_descriptor_preview(
            ctx,
            target,
            descriptor=d,
            callback_ctx=callback_ctx,
        ),
        metadata={
            "target_kind": descriptor.get("target_kind") or "lifecycle_candidate",
            "target_ref": descriptor.get("target_ref"),
            "preview_tool": preview_tool,
            "confirm_tool": confirm_tool,
            "preview_required": True,
            "durable_write": False,
        },
    )


def _lifecycle_candidate_actions(ctx: Any | None, target: str, candidates: list[Any]) -> list[Any]:
    if ctx is None or not target:
        return []
    actions: list[Any] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        descriptor = _lifecycle_candidate_descriptor(candidate)
        action = _lifecycle_descriptor_action(ctx, target, descriptor)
        if action is not None:
            actions.append(action)
        if len(actions) >= 4:
            break
    return actions


def _render_lifecycle_review_packet(
    packet: dict[str, Any],
    *,
    ctx: Any | None = None,
    target: str = "",
) -> dict[str, Any]:
    workflow = _short(packet.get("workflow"), "Lifecycle Review")
    stewardship = _short(packet.get("stewardship_area"), "")
    candidates = packet.get("candidates") if isinstance(packet.get("candidates"), list) else []
    lines = [workflow]
    if stewardship:
        lines.append(f"Stewardship: {stewardship}")
    review_target = _short(packet.get("target") or packet.get("target_ref") or packet.get("scope"), "")
    if review_target:
        lines.append(f"Target: {review_target}")
    if packet.get("mutation_performed") is not None:
        lines.append("Mutation: " + ("performed" if packet.get("mutation_performed") else "none"))
    lines.append(f"Candidates: {len(candidates)}")
    for index, candidate in enumerate(candidates[:5], start=1):
        if not isinstance(candidate, dict):
            lines.append(f"{index}. {_clip(candidate, 180)}")
            continue
        title = _short(candidate.get("title") or candidate.get("name") or candidate.get("target_ref"), "candidate")
        lines.append(f"{index}. {title}")
        action = _short(candidate.get("recommended_action"), "")
        target_ref = _short(candidate.get("target_ref") or candidate.get("object_ref"), "")
        if action:
            lines.append(f"   Action: {action}")
        if target_ref:
            lines.append(f"   Target: {target_ref}")
        signals = candidate.get("signals") if isinstance(candidate.get("signals"), dict) else {}
        closure_signal = signals.get("closure_signal") if isinstance(signals, dict) else None
        lines.extend(_lifecycle_signal_lines(closure_signal))
        evidence_refs = _lifecycle_values(candidate.get("evidence_refs"))
        evidence_gaps = _lifecycle_values(candidate.get("evidence_gaps"))
        if evidence_refs:
            lines.append(_id_line("   Evidence", evidence_refs, limit=3))
        if evidence_gaps:
            lines.append(_id_line("   Gaps", evidence_gaps, limit=3))
    if len(candidates) > 5:
        lines.append(f"... {len(candidates) - 5} more candidate(s)")
    if packet.get("mutation_performed") is False:
        lines.append("No durable write has been made.")
    return {
        "title": "Lifecycle Review",
        "text": "\n".join(lines),
        "actions": _lifecycle_candidate_actions(ctx, target, candidates),
    }


def _manifest_items(manifest: Any) -> list[Any]:
    if isinstance(manifest, list):
        return manifest
    if not isinstance(manifest, dict):
        return []
    for key in ("sources", "items", "entries", "source_refs", "source_manifest"):
        value = manifest.get(key)
        if isinstance(value, list):
            return value
    return []


def _manifest_count(manifest: Any, items: list[Any]) -> int | None:
    if isinstance(manifest, dict):
        for key in ("source_count", "sources_count", "count", "total"):
            try:
                return int(manifest.get(key))
            except (TypeError, ValueError):
                continue
    if items:
        return len(items)
    return None


def _source_manifest_lines(manifest: Any, *, limit: int = 4) -> list[str]:
    if not manifest:
        return []
    items = _manifest_items(manifest)
    count = _manifest_count(manifest, items)
    lines = [f"Sources: {_short(count, 'manifest')}"]
    for item in items[:limit]:
        if isinstance(item, dict):
            kind = _receipt_public_value(item.get("kind") or item.get("source_kind") or item.get("type"), limit=60)
            ref = _receipt_public_value(
                item.get("source_ref")
                or item.get("ref")
                or item.get("id")
                or item.get("source_id")
                or item.get("uri"),
                limit=120,
            )
            title = _receipt_public_value(item.get("title") or item.get("label") or item.get("summary"), limit=120)
            status = _receipt_public_value(item.get("status") or item.get("state"), limit=60)
            parts = [part for part in (kind, ref, title) if part]
            suffix = f" ({status})" if status else ""
            lines.append(f"- {' - '.join(parts) or 'source'}{suffix}")
        else:
            value = _receipt_public_value(item, limit=140)
            if value:
                lines.append(f"- {value}")
    if len(items) > limit:
        lines.append(f"- +{len(items) - limit} more source(s)")
    return lines


def _authority_entry(surface: Any, value: Any = None) -> str:
    label = _receipt_public_value(surface, limit=80)
    if isinstance(value, dict):
        authority = _receipt_public_value(
            value.get("authority")
            or value.get("role")
            or value.get("status")
            or value.get("state")
            or value.get("owner"),
            limit=80,
        )
    else:
        authority = _receipt_public_value(value, limit=80)
    if label and authority:
        return f"{label}={authority}"
    return label or authority


def _authority_map_lines(authority_map: Any, *, limit: int = 6) -> list[str]:
    if not authority_map:
        return []
    entries: list[str] = []
    if isinstance(authority_map, list):
        for item in authority_map:
            if isinstance(item, dict):
                entries.append(
                    _authority_entry(
                        item.get("surface") or item.get("name") or item.get("id") or item.get("target"),
                        item,
                    )
                )
            else:
                entries.append(_authority_entry(item))
    elif isinstance(authority_map, dict):
        list_entries = []
        for key in ("surfaces", "entries", "authorities", "surface_authorities"):
            value = authority_map.get(key)
            if isinstance(value, list):
                list_entries = value
                break
        if list_entries:
            return _authority_map_lines(list_entries, limit=limit)
        for key, value in authority_map.items():
            if key in {"raw", "raw_text", "private_source_text", "source_body"}:
                continue
            entries.append(_authority_entry(key, value))
    entries = [entry for entry in _dedupe_list(entries) if entry]
    if not entries:
        return []
    shown = entries[:limit]
    suffix = f"; +{len(entries) - limit} more" if len(entries) > limit else ""
    return ["Authority map: " + "; ".join(shown) + suffix]


def _candidate_action_values(candidate: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("candidate_actions", "safe_actions", "actions", "action_descriptors"):
        actions = candidate.get(key)
        if not isinstance(actions, list):
            continue
        for action in actions:
            if isinstance(action, dict):
                values.append(
                    _short(
                        action.get("label")
                        or action.get("action_id")
                        or action.get("recommended_action")
                        or action.get("method")
                        or action.get("preview_tool"),
                        "",
                    )
                )
            else:
                values.append(_short(action, ""))
    descriptor = candidate.get("action_descriptor")
    if isinstance(descriptor, dict):
        values.append(
            _short(
                descriptor.get("label")
                or descriptor.get("action_id")
                or descriptor.get("method")
                or descriptor.get("preview_tool"),
                "",
            )
        )
    recommended = _short(candidate.get("recommended_action") or candidate.get("action"), "")
    if recommended:
        values.append(recommended)
    return _receipt_public_values(values, limit=120)


def _candidate_action_line(candidate: dict[str, Any], *, indent: str = "   ") -> str:
    actions = _candidate_action_values(candidate)
    return _id_line(f"{indent}Candidate actions", actions, limit=4) if actions else ""


def _render_lifecycle_update_packet(
    packet: dict[str, Any],
    *,
    ctx: Any | None = None,
    target: str = "",
) -> dict[str, Any]:
    workflow = _short(packet.get("workflow") or packet.get("title"), "Lifecycle Update")
    stewardship = _short(packet.get("stewardship_area") or packet.get("domain"), "")
    candidates = packet.get("candidates") if isinstance(packet.get("candidates"), list) else []
    lines = ["Lifecycle Update"]
    if workflow and workflow != "Lifecycle Update":
        lines.append(f"Workflow: {workflow}")
    if stewardship:
        lines.append(f"Stewardship: {stewardship}")
    status = _short(packet.get("status") or packet.get("state"), "")
    if status:
        lines.append(f"Status: {status}")
    review_target = _receipt_public_value(packet.get("target") or packet.get("target_ref") or packet.get("scope"), limit=140)
    if review_target:
        lines.append(f"Target: {review_target}")
    if packet.get("mutation_performed") is not None:
        lines.append("Mutation: " + ("performed" if packet.get("mutation_performed") else "none"))
    if packet.get("raw_private_source_text_copied") is not None:
        lines.append(
            "Raw private source text copied: "
            + ("yes" if packet.get("raw_private_source_text_copied") else "no")
        )
    lines.extend(_source_manifest_lines(packet.get("source_manifest")))
    lines.extend(_authority_map_lines(packet.get("surface_authority_map")))
    lines.append(f"Candidates: {len(candidates)}")
    for index, candidate in enumerate(candidates[:5], start=1):
        if not isinstance(candidate, dict):
            lines.append(f"{index}. {_clip(candidate, 180)}")
            continue
        title = _receipt_public_value(
            candidate.get("title")
            or candidate.get("name")
            or candidate.get("candidate_id")
            or candidate.get("target_ref"),
            limit=140,
        ) or "candidate"
        lines.append(f"{index}. {title}")
        action = _receipt_public_value(candidate.get("recommended_action") or candidate.get("action"), limit=80)
        target_ref = _receipt_public_value(candidate.get("target_ref") or candidate.get("object_ref"), limit=140)
        summary = _receipt_public_value(candidate.get("summary") or candidate.get("preview") or candidate.get("reason"), limit=180)
        if action:
            lines.append(f"   Action: {action}")
        if target_ref:
            lines.append(f"   Target: {target_ref}")
        if summary:
            lines.append(f"   Summary: {_clip(summary, 180)}")
        action_line = _candidate_action_line(candidate)
        if action_line:
            lines.append(action_line)
        evidence_refs = _receipt_public_values(_lifecycle_values(candidate.get("evidence_refs")), limit=120)
        evidence_gaps = _receipt_public_values(_lifecycle_values(candidate.get("evidence_gaps")), limit=120)
        if evidence_refs:
            lines.append(_id_line("   Evidence", evidence_refs, limit=3))
        if evidence_gaps:
            lines.append(_id_line("   Gaps", evidence_gaps, limit=3))
    if len(candidates) > 5:
        lines.append(f"... {len(candidates) - 5} more candidate(s)")
    if packet.get("mutation_performed") is False:
        lines.append("No durable write has been made.")
    return {
        "title": "Lifecycle Update",
        "text": "\n".join(lines),
        "actions": _lifecycle_candidate_actions(ctx, target, candidates),
    }


def _render_publication_observation_packet(packet: dict[str, Any]) -> dict[str, Any]:
    state = _short(packet.get("publication_state") or packet.get("status") or packet.get("state"))
    changed_paths = _changed_paths(packet)
    lines = [
        "Publication Observation",
        f"State: {state}",
    ]
    changed_count = packet.get("changed_count")
    if changed_count is None and changed_paths:
        changed_count = len(changed_paths)
    if changed_count is not None:
        lines.append(f"Changed paths: {_short(changed_count, '0')}")
    if changed_paths:
        lines.extend(_format_changed_paths(changed_paths, limit=5))
    if packet.get("secret_values_exposed") is not None:
        lines.append("Secrets exposed: " + ("yes" if packet.get("secret_values_exposed") else "no"))
    lines.extend(_warning_lines(packet.get("warnings")))
    return {"title": "Publication Observation", "text": "\n".join(lines), "actions": []}


_PRIVATE_RECEIPT_PATTERNS = (
    re.compile(r"https?://", re.I),
    re.compile(r"\bwww\.", re.I),
    re.compile(r"(?i)(?:^|/)(?:Users|home|private|tmp)/"),
    re.compile(r"(?i)(?:^|[_-])(?:token|secret|password|api[_-]?key)(?:[_-]|$)"),
    re.compile(r"(?i)^(?:acct|account|login|user):"),
    re.compile(r"(?i)\b(?:bearer|sk-[A-Za-z0-9])"),
    re.compile(r"\S+@\S+"),
    re.compile(r"^[A-Za-z]:[\\/]"),
)


def _receipt_public_value(value: Any, *, limit: int = 120) -> str:
    text = _clip(value, limit)
    if not text:
        return ""
    if text.startswith(("/", "~/", "~\\")):
        return ""
    if any(pattern.search(text) for pattern in _PRIVATE_RECEIPT_PATTERNS):
        return ""
    return text


def _receipt_public_values(values: Iterable[Any], *, limit: int = 120) -> list[str]:
    return _dedupe_list(
        value
        for raw in values
        if (value := _receipt_public_value(raw, limit=limit))
    )


def _semantic_values_from(packet: dict[str, Any], *keys: str) -> list[Any]:
    values: list[Any] = []
    for key in keys:
        value = packet.get(key)
        if value is None:
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    for nested_key in ("id", "object_id", "object_ref", "path", "ref", "operation_id"):
                        if item.get(nested_key):
                            values.append(item.get(nested_key))
                            break
                else:
                    values.append(item)
        elif isinstance(value, dict):
            for nested_key in ("id", "object_id", "object_ref", "path", "ref", "operation_id"):
                if value.get(nested_key):
                    values.append(value.get(nested_key))
                    break
        else:
            values.append(value)
    return values


def _semantic_status(packet: dict[str, Any]) -> str:
    status = (
        packet.get("prod_write_status")
        or packet.get("prod_write_state")
        or packet.get("prod_status")
        or packet.get("write_status")
        or _get_path(packet, "prod_write", "status")
        or _get_path(packet, "prod_write", "state")
        or packet.get("status")
        or packet.get("state")
    )
    return _receipt_public_value(status, limit=80)


def _semantic_publication_status(packet: dict[str, Any]) -> str:
    status = (
        packet.get("publication_status")
        or packet.get("publication_state")
        or _get_path(packet, "publication", "status")
        or _get_path(packet, "publication", "state")
        or _get_path(packet, "publication", "publication_status")
        or _get_path(packet, "sync", "status")
    )
    return _receipt_public_value(status, limit=80)


def _semantic_reconciliation_status(packet: dict[str, Any]) -> str:
    status = (
        packet.get("reconciliation_status")
        or packet.get("offline_reconciliation_status")
        or packet.get("local_reconciliation_status")
        or _get_path(packet, "reconciliation", "status")
        or _get_path(packet, "reconciliation", "state")
        or _get_path(packet, "local_reconciliation", "status")
        or _get_path(packet, "local_reconciliation", "state")
        or _get_path(packet, "offline_reconciliation", "status")
        or _get_path(packet, "offline", "reconciliation_status")
    )
    return _receipt_public_value(status, limit=80)


def _semantic_transaction_id(packet: dict[str, Any]) -> str:
    transaction = packet.get("transaction")
    transaction_id = packet.get("transaction_id") or packet.get("txid")
    if not transaction_id and isinstance(transaction, dict):
        transaction_id = transaction.get("id") or transaction.get("transaction_id")
    elif not transaction_id:
        transaction_id = transaction
    return _receipt_public_value(transaction_id, limit=120)


def _public_id_values(value: Any, *, limit: int = 120) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        values: list[Any] = []
        for key in (
            "id",
            "object_id",
            "object_ref",
            "target_ref",
            "ref",
            "path",
            "family",
            "name",
            "label",
            "action_id",
            "method",
            "preview_tool",
            "status",
            "state",
        ):
            if value.get(key):
                values.append(value.get(key))
        return _receipt_public_values(values, limit=limit)
    if isinstance(value, list):
        values = []
        for item in value:
            if isinstance(item, dict):
                nested = _public_id_values(item, limit=limit)
                values.extend(nested)
            else:
                values.append(item)
        return _receipt_public_values(values, limit=limit)
    return _receipt_public_values([value], limit=limit)


def _classification_line(classification: Any) -> str:
    if not classification:
        return ""
    if isinstance(classification, dict):
        values = [
            _receipt_public_value(
                classification.get(key),
                limit=80,
            )
            for key in ("family", "intent", "classification", "status", "state", "confidence")
        ]
        values = [value for value in values if value]
        if values:
            return "Classification: " + " / ".join(values)
        summary = _receipt_public_value(classification.get("summary") or classification.get("reason"), limit=180)
        return f"Classification: {summary}" if summary else ""
    value = _receipt_public_value(classification, limit=120)
    return f"Classification: {value}" if value else ""


def _semantic_preview_lines(preview: Any) -> list[str]:
    if not isinstance(preview, dict):
        value = _receipt_public_value(preview, limit=180)
        return [f"Preview: {value}"] if value else []
    lines: list[str] = []
    status = _receipt_public_value(preview.get("status") or preview.get("state"), limit=80)
    summary = _receipt_public_value(preview.get("summary") or preview.get("safe_summary"), limit=220)
    if status:
        lines.append(f"Preview status: {status}")
    if summary:
        lines.append("Preview: " + _clip(summary, 220))
    object_refs = _receipt_public_values(
        _semantic_values_from(preview, "object_ids", "object_id", "object_refs", "object_ref", "objects"),
        limit=140,
    )
    operations = _receipt_public_values(
        _semantic_values_from(preview, "operation_ids", "operation_id", "operations", "operation_receipts"),
        limit=120,
    )
    families = _public_id_values(preview.get("durable_write_families") or preview.get("families"), limit=100)
    if families:
        lines.append(_id_line("Preview families", families, limit=4))
    if object_refs:
        lines.append(_id_line("Preview objects", object_refs, limit=4))
    if operations:
        lines.append(_id_line("Preview operations", operations, limit=4))
    return lines


def _comparison_lines(comparison: Any) -> list[str]:
    if not comparison:
        return []
    if not isinstance(comparison, dict):
        value = _receipt_public_value(comparison, limit=180)
        return [f"Comparison: {value}"] if value else []
    status = _receipt_public_value(
        comparison.get("status")
        or comparison.get("state")
        or comparison.get("result")
        or comparison.get("outcome"),
        limit=80,
    )
    lines = [f"Comparison: {status}"] if status else []
    for label, key in (
        ("Matches", "matches"),
        ("Differences", "differences"),
        ("Missing", "missing"),
        ("Extra", "extra"),
    ):
        value = comparison.get(key)
        if isinstance(value, list) and value:
            lines.append(f"{label}: {len(value)}")
        elif isinstance(value, int):
            lines.append(f"{label}: {value}")
    summary = _receipt_public_value(comparison.get("summary") or comparison.get("safe_summary"), limit=180)
    if summary:
        lines.append("Comparison summary: " + _clip(summary, 180))
    return lines


def _status_value(statuses: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = statuses.get(key)
        if isinstance(value, dict):
            found = _receipt_public_value(
                value.get("status")
                or value.get("state")
                or value.get("result")
                or value.get("reason"),
                limit=80,
            )
        else:
            found = _receipt_public_value(value, limit=80)
        if found:
            return found
    return ""


def _receipt_status_lines(statuses: Any) -> list[str]:
    if not statuses:
        return []
    if not isinstance(statuses, dict):
        value = _receipt_public_value(statuses, limit=120)
        return [f"Receipt status: {value}"] if value else []
    lines: list[str] = []
    for label, keys in (
        ("Prod write", ("prod_write_status", "prod_write", "prod", "durable_write", "write_status")),
        ("Publication", ("publication_status", "publication", "sync_status", "sync")),
        (
            "Reconciliation",
            (
                "reconciliation_status",
                "reconciliation",
                "local_reconciliation",
                "offline_reconciliation",
            ),
        ),
        ("Shadow receipt", ("shadow_receipt_status", "shadow_receipt", "receipt_status", "status", "state")),
    ):
        value = _status_value(statuses, *keys)
        if value:
            lines.append(f"{label}: {value}")
    return _dedupe_list(lines)


def _render_semantic_write_shadow_packet(packet: dict[str, Any]) -> dict[str, Any]:
    lines = ["Semantic Write Shadow Preview"]
    if packet.get("shadow_mode") is not None:
        lines.append("Shadow mode: " + ("yes" if packet.get("shadow_mode") else "no"))
    if packet.get("mutation_performed") is not None:
        lines.append("Mutation: " + ("performed" if packet.get("mutation_performed") else "none"))
    if packet.get("raw_private_source_text_copied") is not None:
        lines.append(
            "Raw private source text copied: "
            + ("yes" if packet.get("raw_private_source_text_copied") else "no")
        )
    families = _public_id_values(packet.get("durable_write_families"), limit=100)
    if families:
        lines.append(_id_line("Durable write families", families, limit=5))
    classification = _classification_line(packet.get("classification"))
    if classification:
        lines.append(classification)
    lines.extend(_source_manifest_lines(packet.get("source_manifest")))
    lines.extend(_authority_map_lines(packet.get("surface_authority_map")))
    lines.extend(_semantic_preview_lines(packet.get("semantic_preview")))
    lines.extend(_comparison_lines(packet.get("comparison")))
    lines.extend(_receipt_status_lines(packet.get("receipt_status")))
    candidate_actions = _receipt_public_values(
        _public_id_values(packet.get("candidate_actions"), limit=120)
        or _public_id_values(packet.get("actions"), limit=120),
        limit=120,
    )
    if candidate_actions:
        lines.append(_id_line("Candidate actions", candidate_actions, limit=5))
    if packet.get("mutation_performed") is False:
        lines.append("No durable write has been made.")
    return {"title": "Semantic Write Shadow Preview", "text": "\n".join(lines), "actions": []}


def _render_semantic_write_receipt_packet(packet: dict[str, Any]) -> dict[str, Any]:
    lines = ["Semantic Write Receipt"]
    prod_status = _semantic_status(packet)
    publication_status = _semantic_publication_status(packet)
    reconciliation_status = _semantic_reconciliation_status(packet)
    transaction_id = _semantic_transaction_id(packet)
    changed_paths = _receipt_public_values(_changed_paths(packet), limit=140)
    object_ids = _receipt_public_values(
        _semantic_values_from(packet, "object_ids", "object_id", "object_refs", "object_ref", "objects"),
        limit=140,
    )
    operation_ids = _receipt_public_values(
        _semantic_values_from(packet, "operation_ids", "operation_id", "operations", "operation_receipts"),
        limit=120,
    )

    if prod_status:
        lines.append(f"Prod write: {prod_status}")
    if publication_status:
        lines.append(f"Publication: {publication_status}")
    if reconciliation_status:
        lines.append(f"Reconciliation: {reconciliation_status}")
    if transaction_id:
        lines.append(f"Transaction: {transaction_id}")
    if changed_paths:
        lines.append(f"Changed paths: {len(changed_paths)}")
        lines.extend(_format_changed_paths(changed_paths, limit=4))
    if object_ids:
        lines.append(_id_line("Objects", object_ids, limit=4))
    if operation_ids:
        lines.append(_id_line("Operations", operation_ids, limit=4))
    return {"title": "Semantic Write Receipt", "text": "\n".join(lines), "actions": []}


def _id_list(value: Any) -> list[str]:
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _id_line(label: str, values: list[str], *, limit: int = 8) -> str:
    shown = ", ".join(values[:limit])
    if len(values) > limit:
        shown += f", +{len(values) - limit} more"
    return f"{label}: {shown}"


def _restore_hint(receipt: dict[str, Any]) -> dict[str, Any]:
    hint = receipt.get("restore_hint")
    return hint if isinstance(hint, dict) else {}


def _restore_args_from_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    hint = _restore_hint(receipt)
    args = hint.get("params") if isinstance(hint.get("params"), dict) else {}
    args = dict(args)
    for key in ("transaction_id", "receipt_id"):
        value = _short(hint.get(key) or receipt.get(key), "")
        if value:
            args.setdefault(key, value)
    proposal_ids = _id_list(hint.get("proposal_ids")) or _id_list(receipt.get("affected_ids"))
    if proposal_ids:
        args.setdefault("proposal_ids", proposal_ids)
    return {key: value for key, value in args.items() if value not in (None, "", [])}


def _restore_tools(target: str, receipt: dict[str, Any]) -> tuple[str, str]:
    hint = _restore_hint(receipt)
    preview_name = hint.get("preview_tool") or hint.get("restore_preview_tool")
    confirm_name = hint.get("confirm_tool") or hint.get("restore_confirm_tool")
    if not preview_name and _descriptor("review.restore_preview"):
        preview_name = "review.restore_preview"
    if not confirm_name and _descriptor("review.restore_confirmed"):
        confirm_name = "review.restore_confirmed"
    preview_tool = _descriptor_tool_name(target, preview_name)
    confirm_tool = _descriptor_tool_name(target, confirm_name)
    return preview_tool, confirm_tool


def _restore_preview_text(payload: Any) -> str:
    if isinstance(payload, dict) and payload.get("error"):
        return f"Review restore preview failed\n{payload['error']}"
    if not isinstance(payload, dict):
        return f"Review restore preview\n{_short(payload, 'No structured response returned.')}"
    lines = [
        "Review restore preview",
        f"Status: {_short(payload.get('status') or payload.get('state'))} · ok: {_short(payload.get('ok'))}",
    ]
    restorable = _id_list(payload.get("restorable_ids"))
    incompatible = _id_list(payload.get("incompatible_ids"))
    already_restored = _id_list(payload.get("already_restored_ids"))
    if restorable:
        lines.append(_id_line("Restorable ids", restorable))
    if incompatible:
        lines.append(_id_line("Blocked ids", incompatible))
    if already_restored:
        lines.append(_id_line("Already restored", already_restored))
    lines.extend(_queue_scope_lines(payload))
    return "\n".join(lines)


def _restore_action_from_receipt(ctx: Any | None, target: str, receipt: dict[str, Any]) -> Any | None:
    if ctx is None or receipt.get("restore_available") is not True or not _restore_hint(receipt):
        return None
    preview_tool, confirm_tool = _restore_tools(target, receipt)
    args = _restore_args_from_receipt(receipt)
    if not preview_tool or not confirm_tool or not args:
        return None
    return KbAction(
        label="Preview Restore",
        action_id="queue.restore.preview",
        handler=lambda callback_ctx, r=dict(receipt): _render_restore_preview(
            ctx,
            target,
            receipt=r,
            callback_ctx=callback_ctx,
        ),
        metadata={
            "target_kind": "proposal_queue",
            "preview_tool": preview_tool,
            "confirm_tool": confirm_tool,
            "preview_required": True,
            "restore_available": True,
        },
    )


def _render_restore_preview(
    ctx: Any,
    target: str,
    *,
    receipt: dict[str, Any],
    callback_ctx: Any,
) -> dict[str, Any]:
    del callback_ctx
    preview_tool, _confirm_tool = _restore_tools(target, receipt)
    preview_payload = _dispatch_registry_tool(ctx, target, preview_tool, _restore_args_from_receipt(receipt))
    text = _restore_preview_text(preview_payload)
    if not _preview_allows_confirmation(
        preview_payload,
        capability=_capability_for_registry_name(target, preview_tool),
    ):
        return {"title": "KB Review Restore", "text": text, "actions": []}
    preview_metadata = _queue_preview_metadata(preview_payload)
    confirm_action = KbAction(
        label="Confirm Restore",
        action_id="queue.restore.confirm",
        handler=lambda confirm_ctx, r=dict(receipt), metadata=dict(preview_metadata): _render_restore_confirm(
            ctx,
            target,
            receipt=r,
            callback_ctx=confirm_ctx,
            preview_metadata=metadata,
        ),
        metadata={
            "target_kind": "proposal_queue",
            "preview_required": True,
            "preview_lease": bool(preview_metadata.get("preview_lease")),
            "review_session_id": _review_session_id(preview_metadata),
        },
    )
    return {
        "title": "KB Review Restore",
        "text": text + "\n\nConfirm restore only if these ids match the receipt you intended to undo.",
        "actions": [confirm_action],
    }


def _render_restore_confirm(
    ctx: Any,
    target: str,
    *,
    receipt: dict[str, Any],
    callback_ctx: Any,
    preview_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    preview_tool, confirm_tool = _restore_tools(target, receipt)
    effective_metadata = dict(preview_metadata or {})
    preview_payload = _dispatch_registry_tool(ctx, target, preview_tool, _restore_args_from_receipt(receipt))
    if not _preview_allows_confirmation(
        preview_payload,
        capability=_capability_for_registry_name(target, preview_tool),
    ):
        return {"title": "KB Review Restore", "text": _restore_preview_text(preview_payload), "actions": []}
    effective_metadata = _queue_preview_metadata(preview_payload)
    args = _restore_args_from_receipt(receipt)
    review_session_id = _review_session_id(effective_metadata)
    cursor_id = _queue_cursor_id(effective_metadata)
    if review_session_id:
        args.setdefault("review_session_id", review_session_id)
    if cursor_id:
        args.setdefault("cursor_id", cursor_id)
    args.setdefault("actor", _queue_callback_actor(callback_ctx))
    args.setdefault("source", "Hermes Telegram Action Card")
    args.setdefault("session_id", review_session_id or f"telegram-kb-restore-{int(time.time())}")
    args["user_confirmation"] = {
        "confirmed": True,
        "confirmed_at": _utc_now_text(),
        "surface": "telegram",
        "action": "queue.restore",
        "preview_required": True,
        "confirmation_text": "Confirm queue restore from Telegram receipt action card.",
        "actor_id": _short(getattr(callback_ctx, "actor_id", ""), ""),
        "actor_name": _short(getattr(callback_ctx, "actor_name", ""), ""),
    }
    _apply_queue_confirmation_preview_metadata(args["user_confirmation"], effective_metadata)
    payload = _dispatch_registry_tool(ctx, target, confirm_tool, args)
    capability = _capability_for_registry_name(target, confirm_tool)
    completion = _request_bound_review_completion(
        payload,
        _review_completion_expectation(capability, args),
    )
    if not completion["complete"]:
        return {
            "title": "KB Review Restore",
            "text": (
                "KB Review Restore\nConfirmation received, but durable restore readback "
                f"is not verified ({completion['reason']}). No restored state is claimed."
            ),
            "actions": [],
        }
    packet_card = _render_supported_result_packet(payload, ctx=ctx, target=target)
    if packet_card is not None:
        return packet_card
    return {"title": "KB Review Restore", "text": _restore_preview_text(payload).replace("preview", "result", 1), "actions": []}


def _render_request_receipt_packet(
    packet: dict[str, Any],
    *,
    ctx: Any | None = None,
    target: str = "",
) -> dict[str, Any]:
    route = _short(packet.get("route"), "")
    title = "KB Review Receipt" if route.startswith("queue.") else "KB Request Receipt"
    lines = [
        title,
        f"State: {_short(packet.get('state') or packet.get('status'))}",
    ]
    if packet.get("saved") is not None:
        lines.append("Saved: " + ("yes" if packet.get("saved") else "no"))
    if route:
        lines.append(f"Route: {route}")
    if packet.get("receipt_id"):
        lines.append(f"Receipt: {_short(packet.get('receipt_id'))}")
    if packet.get("transaction_id"):
        lines.append(f"Transaction: {_short(packet.get('transaction_id'))}")
    count_bits: list[str] = []
    if packet.get("reviewed_count") is not None:
        count_bits.append(f"{_short(packet.get('reviewed_count'), '0')} reviewed")
    if packet.get("confirmed_count") is not None:
        count_bits.append(f"{_short(packet.get('confirmed_count'), '0')} confirmed")
    if count_bits:
        lines.append("Counts: " + " · ".join(count_bits))
    for label, key in (
        ("Affected ids", "affected_ids"),
        ("Restored ids", "restored_ids"),
        ("Skipped ids", "skipped_ids"),
        ("Changed refs", "changed_refs"),
    ):
        ids = _id_list(packet.get(key))
        if ids:
            lines.append(_id_line(label, ids))
    lines.extend(_object_reference_lines(packet))
    message = _short(packet.get("safe_message") or packet.get("message"), "")
    if message:
        lines.append(_clip(message, 260))
    next_step = _short(packet.get("next_step"), "")
    if next_step:
        lines.append("Next: " + _clip(next_step, 220))
    if packet.get("restore_available") is True:
        lines.append("Restore: preview available")
    action = _restore_action_from_receipt(ctx, target, packet)
    next_review = _next_review_packet(packet)
    if next_review:
        status = _short(next_review.get("status"), "")
        if route.startswith("queue.") and status == "ready":
            next_payload = _queue_payload_from_next_review(next_review)
            next_card = _render_queue(
                next_payload,
                ctx=ctx,
                target=target,
                session_id=_review_session_id({"review_session": next_review.get("review_session")})
                or _short(next_review.get("source_review_session_id"), ""),
            )
            actions = list(next_card.get("actions") or [])
            if action and len(actions) < 6:
                actions.append(action)
            return {
                "title": "KB Review",
                "text": "\n".join([*lines, "", "Next review from kb-engine:", next_card["text"]]),
                "actions": actions,
            }
        lines.extend(_next_review_lines(next_review))
    return {"title": title, "text": "\n".join(lines), "actions": [action] if action else []}


def _next_review_packet(packet: dict[str, Any]) -> dict[str, Any]:
    next_review = packet.get("next_review")
    if isinstance(next_review, dict) and next_review.get("packet_type") == "guided_kb_review_next":
        return dict(next_review)
    return {}


def _next_review_lines(next_review: dict[str, Any]) -> list[str]:
    status = _short(next_review.get("status"), "")
    reason = _short(next_review.get("reason"), "")
    if status == "no_more_items":
        return ["Next review: no more proposal items."]
    if status in {"changed_queue", "stale_cursor", "preview_lease_required", "refresh_required"}:
        line = "Next review: refresh required"
        if reason:
            line += f" ({_clip(reason, 160)})"
        return [line]
    if status == "unavailable":
        line = "Next review: unavailable"
        if reason:
            line += f" ({_clip(reason, 160)})"
        return [line]
    if status == "ready":
        target = next_review.get("target") if isinstance(next_review.get("target"), dict) else {}
        title = _short(target.get("title"), "next item")
        proposal_count = len(_id_list(target.get("proposal_ids")))
        suffix = f" · {proposal_count} proposal{'s' if proposal_count != 1 else ''}" if proposal_count else ""
        return [f"Next review: {title}{suffix}"]
    return [f"Next review: {status or 'unknown'}"]


def _queue_payload_from_next_review(next_review: dict[str, Any]) -> dict[str, Any]:
    target = next_review.get("target") if isinstance(next_review.get("target"), dict) else {}
    proposal_ids = _id_list(target.get("proposal_ids"))
    review_session = next_review.get("review_session") if isinstance(next_review.get("review_session"), dict) else {}
    item = {
        "item_id": _short(target.get("target_id"), ""),
        "kind": _short(target.get("kind"), "proposal_entity"),
        "title": _short(target.get("title"), "Next review"),
        "summary": _short(target.get("summary"), ""),
        "status": _short(target.get("status"), ""),
        "entity_path": _short(target.get("entity_path"), ""),
        "safe_actions": target.get("safe_actions") if isinstance(target.get("safe_actions"), list) else [],
        "review_session": review_session,
        "raw": {
            "proposal_ids": proposal_ids,
            "proposal_count": int(target.get("proposal_count") or len(proposal_ids)),
            "sections": target.get("sections") if isinstance(target.get("sections"), list) else [],
            "review_session": review_session,
        },
    }
    return {
        "packet_type": "workbench.queue",
        "schema_version": 1,
        "total": 1,
        "offset": 0,
        "next_offset": None,
        "items": [item],
        "review_session": review_session,
    }


def _render_supported_result_packet(
    payload: Any,
    *,
    ctx: Any | None = None,
    target: str = "",
) -> dict[str, Any] | None:
    packet = _first_result_packet(payload)
    if not packet:
        return None
    packet_type = _packet_kind(packet)
    if packet_type == "report_admission_receipt":
        return _render_report_admission_packet(packet)
    if packet_type == "durable_graph_validation":
        return _render_graph_validation_packet(packet)
    if packet_type == "lifecycle_review.packet":
        return _render_lifecycle_review_packet(packet, ctx=ctx, target=target)
    if packet_type == "lifecycle_update.packet":
        return _render_lifecycle_update_packet(packet, ctx=ctx, target=target)
    if packet_type == "lifecycle_proposal_draft.packet":
        return _render_lifecycle_proposal_draft_packet(packet)
    if packet_type == "publication_observation":
        return _render_publication_observation_packet(packet)
    if packet_type in SEMANTIC_WRITE_SHADOW_PACKET_TYPES:
        return _render_semantic_write_shadow_packet(packet)
    if packet_type in SEMANTIC_WRITE_RECEIPT_PACKET_TYPES:
        return _render_semantic_write_receipt_packet(packet)
    if packet_type == "request.receipt":
        return _render_request_receipt_packet(packet, ctx=ctx, target=target)
    return None


def _maybe_json(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped:
        return value
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return value
    try:
        return json.loads(stripped)
    except Exception:
        return value


def _upstream_envelope_failure(value: Any, *, path: str = "$") -> str | None:
    value = _maybe_json(value)
    if not isinstance(value, dict):
        return None
    if value.get("isError") is True:
        return f"{path}.isError=true"
    for key in ("error", "errors"):
        error_value = value.get(key)
        if error_value not in (None, "", [], {}):
            detail = _clip(error_value, 180) if isinstance(error_value, str) else "non-empty"
            return f"{path}.{key}: {detail}"
    for key in ("status", "state"):
        status = str(value.get(key) or "").strip().lower()
        if status in {"cancelled", "canceled", "error", "failed", "partial", "partially_applied"}:
            return f"{path}.{key}={status}"
    for key in ("result", "structuredContent"):
        if key in value:
            failure = _upstream_envelope_failure(value[key], path=f"{path}.{key}")
            if failure:
                return failure
    return None


def _unwrap_tool_result(raw: Any) -> tuple[Any | None, str | None]:
    parsed = _maybe_json(raw)
    if not isinstance(parsed, dict):
        return parsed, None
    failure = _upstream_envelope_failure(parsed)
    if failure:
        return None, f"upstream tool failure: {failure}"
    payload = parsed.get("structuredContent")
    if payload is None:
        payload = parsed.get("result", parsed)
    payload = _maybe_json(payload)
    return payload, None


def _validate_runtime_output(capability: str, payload: Any) -> str | None:
    descriptor = _descriptor(capability)
    if descriptor is None:
        return "capability is not present in the generated descriptor allowlist"
    schema = descriptor.get("output_schema")
    if not isinstance(schema, dict):
        return "generated output schema is unavailable"
    return _runtime_schema_error(payload, schema)


def _dispatch_selected_tool(
    ctx: Any,
    target: str,
    capability: str,
    args: dict[str, Any],
) -> tuple[str, Any | None, str | None]:
    registry_name = _mcp_tool_name(target, capability)
    if capability not in _descriptor_allowlist():
        return registry_name, None, "not present in generated descriptor allowlist"
    try:
        payload, error = _unwrap_tool_result(ctx.dispatch_tool(registry_name, args))
    except Exception as exc:
        return registry_name, None, str(exc)
    if error:
        return registry_name, None, error
    schema_error = _validate_runtime_output(capability, payload)
    if schema_error:
        return registry_name, None, f"runtime output violates generated schema: {schema_error}"
    return registry_name, payload, None


def _capability_for_registry_name(target: str, registry_name: str) -> str:
    matches = [
        capability
        for capability in _descriptor_allowlist()
        if _mcp_tool_name(target, capability) == registry_name
    ]
    return matches[0] if len(matches) == 1 else ""


def _dispatch_registry_tool(
    ctx: Any,
    target: str,
    registry_name: str,
    args: dict[str, Any],
) -> Any:
    capability = _capability_for_registry_name(target, registry_name)
    if not capability:
        return {"error": "tool is not uniquely present in the generated descriptor allowlist"}
    _selected, payload, error = _dispatch_selected_tool(ctx, target, capability, args)
    return {"error": error} if error else payload


def _dispatch_first(
    ctx: Any,
    target: str,
    candidates: Iterable[tuple[str, dict[str, Any]]],
) -> tuple[str | None, Any | None, list[str]]:
    errors: list[str] = []
    for kb_tool, args in candidates:
        capability = str(kb_tool or "").strip()
        registry_name, payload, error = _dispatch_selected_tool(ctx, target, capability, args)
        if error:
            label = capability if capability not in _descriptor_allowlist() else registry_name
            errors.append(f"{label}: {error}")
            continue
        return registry_name, payload, errors
    return None, None, errors


def _get_path(data: Any, *path: str, default: Any = None) -> Any:
    cur = data
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return cur if cur is not None else default


def _count_from(data: Any, *keys: str) -> Any:
    for key in keys:
        value = _get_path(data, key, "count")
        if value is not None:
            return value
        if isinstance(data, dict) and data.get(key) is not None and not isinstance(data.get(key), dict):
            found = data.get(key)
            return len(found) if isinstance(found, list) else found
    return None


def _readiness_status(data: dict[str, Any]) -> Any:
    return (
        _get_path(data, "summary", "readiness_status")
        or _get_path(data, "sections", "readiness", "summary", "status")
        or _get_path(data, "sections", "readiness", "payload", "status")
        or _get_path(data, "readiness", "status")
        or _get_path(data, "readiness", "state")
        or data.get("readiness")
    )


def _publication_status(data: dict[str, Any]) -> Any:
    return (
        _get_path(data, "summary", "publication_status")
        or _get_path(data, "sections", "publication", "summary", "status")
        or _get_path(data, "sections", "publication", "payload", "status")
        or _get_path(data, "publication", "status")
        or _get_path(data, "publication", "state")
        or data.get("publication")
    )


def _item_title(item: Any) -> str:
    if isinstance(item, dict):
        return _short(
            item.get("title")
            or item.get("name")
            or item.get("summary")
            or item.get("id")
            or item.get("proposal_id"),
            "item",
        )
    return _short(item, "item")


def _summary_count(summary: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = summary.get(key)
        if value is not None:
            return value
    return None


def _proposal_count_from_summary(summary: dict[str, Any]) -> Any:
    proposal_count = _summary_count(
        summary,
        "proposal_queue_count",
        "pending_proposal_count",
        "proposal_count",
        "review_proposal_count",
    )
    if proposal_count is not None:
        return proposal_count
    legacy_queue_count = summary.get("queue_item_count")
    todo_count = _summary_count(summary, "active_todo_count", "triage_todo_count", "task_queue_count")
    if legacy_queue_count is not None and todo_count is not None and legacy_queue_count != todo_count:
        return legacy_queue_count
    return None


def _todo_count_from_summary(summary: dict[str, Any]) -> Any:
    return _summary_count(summary, "active_todo_count", "triage_todo_count", "task_queue_count")


def _display_text(value: Any) -> str:
    text = _short(value, "")
    if text in {
        "Review prioritized queue items through workbench.queue.",
        "Review prioritized review items through workbench.queue.",
    }:
        return "Review prioritized attention items; use /kb review for proposal review."
    return text


def _dashboard_section_title(section: dict[str, Any], summary: dict[str, Any]) -> str:
    title = _short(section.get("title") or section.get("id"), "Section")
    key = title.strip().lower()
    section_id = str(section.get("id") or "").strip().lower()
    if key == "queue" or section_id == "queue":
        proposal_count = _proposal_count_from_summary(summary)
        todo_count = _todo_count_from_summary(summary)
        legacy_queue_count = summary.get("queue_item_count")
        if proposal_count is None or (todo_count is not None and legacy_queue_count == todo_count):
            return "Attention Review"
        return "Proposal Review"
    return title


def _items(data: Any, *paths: tuple[str, ...]) -> list[Any]:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for path in paths:
        found = _get_path(data, *path)
        if isinstance(found, list) and found:
            return found
    for key in ("items", "proposals", "queue", "runs", "recent", "active"):
        found = data.get(key)
        if isinstance(found, list) and found:
            return found
    return []


def _public_error(errors: list[str]) -> str:
    if not errors:
        return "The knowledge service did not return a usable response."
    detail = errors[-1]
    if detail.startswith("mcp_") and ": " in detail:
        detail = detail.split(": ", 1)[1]
    if (
        _PRIVATE_PATH_RE.search(detail)
        or _DIGEST_RE.search(detail)
        or _MCP_NAME_RE.search(detail)
        or _CAPABILITY_NAME_RE.search(detail)
    ):
        return "The knowledge service did not return a usable response."
    return _public_clip(detail) or "The knowledge service did not return a usable response."


def _render_error(title: str, target: str, errors: list[str]) -> dict[str, Any]:
    del target
    detail = _public_error(errors)
    text = (
        f"{_emphasis_headline(title)}\n"
        "Knowledge service unavailable.\n"
        f"{detail}\n"
        "No KB completion is claimed."
    )
    return {"title": title, "text": text, "actions": []}


def _render_today(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        text = f"KB Today\n{_short(data, 'No cockpit details returned.')}"
        return {"title": "KB Today", "text": text, "actions": []}

    readiness = _short(_readiness_status(data))
    publication = _short(_publication_status(data))
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    queue_count = _proposal_count_from_summary(summary)
    if queue_count is None:
        queue_count = _count_from(data, "proposals", "proposal_queue")
    todo_count = _count_from(data, "todo", "todos")
    if todo_count is None:
        todo_count = _todo_count_from_summary(summary)

    active_runs = _items(data, ("runs", "active"), ("active_runs",))
    recent_runs = _items(data, ("runs", "recent"), ("recent_runs",))
    run_bits: list[str] = []
    for run in active_runs[:2]:
        if isinstance(run, dict):
            run_bits.append(f"{_item_title(run)} {_short(run.get('status') or run.get('state'))}")
        else:
            run_bits.append(_short(run))
    for run in recent_runs[:1]:
        if isinstance(run, dict):
            run_bits.append(f"recent {_item_title(run)} {_short(run.get('status') or run.get('state'))}")
        else:
            run_bits.append(f"recent {_short(run)}")

    next_actions = _items(data, ("next_actions",), ("actions",))
    lines = [
        "KB Today",
        f"Readiness: {readiness}",
        f"Publication: {publication}",
    ]
    if queue_count is not None or todo_count is not None:
        count_bits = []
        if queue_count is not None:
            count_bits.append(f"Proposals: {_short(queue_count, 'unknown')}")
        if todo_count is not None:
            count_bits.append(f"TODOs: {_short(todo_count, 'unknown')}")
        lines.append(" · ".join(count_bits))
    if run_bits:
        lines.append("Runs: " + " · ".join(run_bits[:3]))
    if next_actions:
        lines.append("Next: " + "; ".join(_item_title(a) for a in next_actions[:3]))

    # Rich path: a status KV table + native bullet lists for runs / next actions.
    today_pairs: list[tuple[str, Any]] = [
        ("Readiness", readiness),
        ("Publication", publication),
    ]
    if queue_count is not None:
        today_pairs.append(("Proposals", _short(queue_count, "unknown")))
    if todo_count is not None:
        today_pairs.append(("TODOs", _short(todo_count, "unknown")))
    rich_parts = [_rich_kv_table("KB Today", today_pairs)]
    if run_bits:
        rich_parts.append("")
        rich_parts.append(_rich_heading("Runs"))
        rich_parts.append("")
        rich_parts.extend(_rich_bullets(run_bits[:3]))
    if next_actions:
        rich_parts.append("")
        rich_parts.append(_rich_heading("Next"))
        rich_parts.append("")
        rich_parts.extend(_rich_bullets(_item_title(a) for a in next_actions[:3]))
    return {
        "title": "KB Today",
        "text": "\n".join(lines),
        "actions": [],
        "rich_markdown": "\n".join(rich_parts),
    }


def _dashboard_sections(data: dict[str, Any]) -> list[dict[str, Any]]:
    raw = data.get("sections")
    if isinstance(raw, dict):
        return [
            {"id": str(section_id), **section}
            for section_id, section in raw.items()
            if isinstance(section, dict)
        ]
    return [section for section in (raw or []) if isinstance(section, dict)]


def _dashboard_items(sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    preferred = {"situations": 0, "queue": 1, "todos": 2}
    ordered = sorted(
        enumerate(sections),
        key=lambda row: (
            preferred.get(str(row[1].get("id") or "").lower(), 9),
            row[0],
        ),
    )
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _index, section in ordered:
        for field in ("items", "cards", "attention", "standalone_critical"):
            rows = section.get(field)
            if not isinstance(rows, list):
                continue
            for item in rows:
                if not isinstance(item, dict):
                    continue
                identity = str(
                    item.get("target")
                    or item.get("item_id")
                    or item.get("id")
                    or item.get("title")
                    or ""
                )
                if identity and identity in seen:
                    continue
                if identity:
                    seen.add(identity)
                items.append(item)
                if len(items) == 5:
                    return items
    return items


def _dashboard_item_line(item: dict[str, Any]) -> str:
    title = _public_clip(
        item.get("title")
        or item.get("name")
        or item.get("summary")
        or "Attention item",
        120,
    )
    detail = _public_clip(item.get("detail"), 150)
    if not detail:
        context = [
            _public_clip(item.get("priority") or item.get("severity"), 24),
            _public_clip(item.get("due_date"), 48),
        ]
        detail = " · ".join(value for value in context if value)
    return f"- {title}" + (f" — {detail}" if detail else "")


def _render_dashboard(data: Any, *, ctx: Any, target: str) -> dict[str, Any]:
    """Render the normal attention path as one small, user-facing packet."""
    if not isinstance(data, dict):
        return {
            "title": "Knowledge",
            "text": f"{_emphasis_headline('Knowledge')}\n{_public_clip(data, 180) or 'No details returned.'}",
            "actions": [],
        }

    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    readiness = _public_clip(summary.get("readiness_status") or _readiness_status(data), 32)
    publication = _public_clip(summary.get("publication_status") or _publication_status(data), 32)
    sections = _dashboard_sections(data)
    items = _dashboard_items(sections)

    status_bits = [value for value in (readiness, f"publication {publication}" if publication else "") if value]
    lines = [_emphasis_headline("Knowledge")]
    if status_bits:
        lines.append("Status: " + " · ".join(status_bits))
    lines.extend(_dashboard_item_line(item) for item in items)
    if not items:
        lines.append("Nothing currently needs attention.")
    lines.append(
        "Next: ask to open an item or tell me what changed."
        if items
        else "Next: tell me what changed or ask me to sync."
    )
    return {
        "title": "Knowledge",
        "text": "\n".join(lines[:8]),
        "actions": _dashboard_descriptor_actions(ctx, target, sections),
    }


def _compact_attention_tool_result(
    *,
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    **_: Any,
) -> str | None:
    """Replace one duplicated compact cockpit envelope before model reuse."""
    target = _mcp_target()
    capability = _capability_for_registry_name(target, tool_name)
    descriptor = _descriptor(capability)
    annotations = (
        descriptor.get("annotations")
        if isinstance(descriptor, dict) and isinstance(descriptor.get("annotations"), dict)
        else {}
    )
    if capability != "attention.cockpit" or annotations.get("readOnlyHint") is not True:
        return None

    requested = args if isinstance(args, dict) else {}
    if requested.get("detail") is True or str(requested.get("mode") or "").lower() == "full":
        return None

    envelope = _maybe_json(result)
    if not isinstance(envelope, dict) or not isinstance(envelope.get("structuredContent"), dict):
        return None
    payload, error = _unwrap_tool_result(envelope)
    if error or not isinstance(payload, dict) or payload.get("mode") != "compact":
        return None
    if _validate_runtime_output(capability, payload) is not None:
        return None
    if _maybe_json(envelope.get("result")) != payload:
        return None

    rendered = _render_dashboard(payload, ctx=None, target=target).get("text")
    return rendered if isinstance(rendered, str) and rendered.strip() else None


_WORKBENCH_SECTION_IDS = {"closeout", "now", "reports", "situations", "workbench"}


def _dashboard_card_descriptors(card: dict[str, Any]) -> list[dict[str, Any]]:
    descriptors = card.get("action_descriptors") if isinstance(card.get("action_descriptors"), list) else []
    safe: list[dict[str, Any]] = []
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            continue
        if descriptor.get("dashboard_owned_write") is True:
            continue
        if descriptor.get("packet_type") != "dashboard_action_descriptor" or descriptor.get("schema_version") != 2:
            continue
        safe.append(descriptor)
    return safe


def _render_workbench(data: Any, *, ctx: Any, target: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {"title": "KB Review", "text": f"KB Review\n{_short(data, 'No review details returned.')}", "actions": []}

    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    readiness = _short(summary.get("readiness_status") or _readiness_status(data))
    publication = _short(summary.get("publication_status") or _publication_status(data))
    sections = data.get("sections") if isinstance(data.get("sections"), list) else []
    queue_count = _proposal_count_from_summary(summary)
    todo_count = _todo_count_from_summary(summary)
    lines = [
        "KB Review",
        f"Status: runtime {readiness} · publication {publication}",
    ]
    counts: list[str] = []
    if queue_count is not None:
        counts.append(f"Proposals {queue_count}")
    if todo_count is not None:
        counts.append(f"TODOs {todo_count}")
    if counts:
        lines.append(" · ".join(counts))
    lines.extend(_receipt_lines(data))

    decision_cards: list[tuple[str, dict[str, Any], list[dict[str, Any]]]] = []
    for section in sections:
        if not isinstance(section, dict):
            continue
        section_id = str(section.get("id") or "").strip().lower()
        if section_id not in _WORKBENCH_SECTION_IDS:
            continue
        section_title = _dashboard_section_title(section, summary)
        cards = section.get("cards") if isinstance(section.get("cards"), list) else []
        for card in cards:
            if not isinstance(card, dict):
                continue
            descriptors = _dashboard_card_descriptors(card)
            if descriptors:
                decision_cards.append((section_title, card, descriptors))

    lines.append("")
    lines.append("Decision Cards")
    if not decision_cards:
        lines.append("No active kb-engine Decision Cards returned.")
    for index, (section_title, card, descriptors) in enumerate(decision_cards[:5], start=1):
        lines.extend(
            _workbench_compact_card_lines(
                index=index,
                section_title=section_title,
                card=card,
                descriptors=descriptors,
            )
        )
    if len(decision_cards) > 5:
        lines.append(f"... {len(decision_cards) - 5} more Decision Card(s)")

    lines.extend(
        [
            "",
            "Buttons open or preview canonical kb-engine actions; writes still require confirmation.",
            "Fallback: /kb status",
        ]
    )
    return {"title": "KB Review", "text": "\n".join(lines), "actions": _dashboard_descriptor_actions(ctx, target, sections)}


def _workbench_review_kind(card: dict[str, Any], descriptors: list[dict[str, Any]]) -> str:
    kind = str(card.get("kind") or "").strip().lower()
    if kind:
        return kind
    for descriptor in descriptors:
        target_kind = str(descriptor.get("target_kind") or "").strip().lower()
        if target_kind:
            return target_kind
    return "review"


def _workbench_rail_labels(descriptors: list[dict[str, Any]], *, include_skip: bool = True) -> list[str]:
    labels: list[str] = []
    for descriptor in descriptors:
        label = _short(descriptor.get("label") or descriptor.get("action_id") or "", "")
        if label and label not in labels:
            labels.append(label)
    if any(_descriptor_advisory_guidance(descriptor) for descriptor in descriptors) and "Ask LLM" not in labels:
        labels.append("Ask LLM")
    if include_skip and "Skip" not in labels:
        labels.append("Skip")
    return labels


def _workbench_compact_card_lines(
    *,
    index: int,
    section_title: str,
    card: dict[str, Any],
    descriptors: list[dict[str, Any]],
) -> list[str]:
    title = _display_text(card.get("title") or "KB review")
    detail = _display_text(card.get("detail"))
    kind = _workbench_review_kind(card, descriptors)
    target = _short(
        card.get("target")
        or next((descriptor.get("target_ref") for descriptor in descriptors if descriptor.get("target_ref")), ""),
        "",
    )
    labels = _workbench_rail_labels(descriptors)
    lines = [f"{index}. {title}"]
    if kind == "situation":
        lines.append("   Surface: Situation Review")
    elif kind == "lifecycle_candidate":
        lines.append("   Surface: Lifecycle Review")
    elif section_title:
        lines.append(f"   Surface: {section_title}")
    if detail:
        lines.append(f"   Summary: {_clip(detail, 180)}")
    scope_bits = [bit for bit in (target, f"{len(descriptors)} action{'s' if len(descriptors) != 1 else ''}") if bit]
    if scope_bits:
        lines.append("   Scope: " + " · ".join(scope_bits))
    if labels:
        lines.append("   Rail: " + ", ".join(labels[:6]))
    if kind == "situation":
        lines.append("   Writes: handoff-only until kb-engine returns a confirmed workflow.")
    if kind == "lifecycle_candidate":
        lines.append("   Writes: proposal preview only; no Hermes durable write.")
    return lines


def _dashboard_descriptor_actions(ctx: Any, target: str, sections: list[Any]) -> list[Any]:
    actions: list[Any] = []
    guidance_actions: list[Any] = []
    for section in sections:
        if not isinstance(section, dict):
            continue
        if str(section.get("id") or "").strip().lower() not in _WORKBENCH_SECTION_IDS:
            continue
        cards = section.get("cards") if isinstance(section.get("cards"), list) else []
        for card in cards:
            if not isinstance(card, dict):
                continue
            for descriptor in _dashboard_card_descriptors(card):
                descriptor_copy = dict(descriptor)
                label = _short(descriptor.get("label") or descriptor.get("action_id") or "Open", "Open")
                action_id = _short(descriptor.get("action_id") or label, label)
                mutation = _short(descriptor.get("mutation"), "read_only")
                target_kind = str(descriptor.get("target_kind") or "").strip()
                lifecycle_action = _lifecycle_descriptor_action(ctx, target, descriptor_copy)
                if lifecycle_action is not None:
                    actions.append(lifecycle_action)
                elif mutation == "read_only":
                    if target_kind not in DESCRIPTOR_READONLY_TARGET_KINDS:
                        continue
                    if not (descriptor.get("preview_tool") or descriptor.get("method")):
                        continue
                    actions.append(
                        KbAction(
                            label=label,
                            action_id=f"{action_id}.open",
                            handler=lambda callback_ctx, d=descriptor_copy: _render_readonly_descriptor_action(
                                ctx,
                                target,
                                descriptor=d,
                                callback_ctx=callback_ctx,
                            ),
                            metadata={
                                "target_kind": descriptor.get("target_kind"),
                                "target_ref": descriptor.get("target_ref"),
                                "preview_tool": descriptor.get("preview_tool") or descriptor.get("method"),
                            },
                        )
                    )
                elif mutation == "handoff_only":
                    if target_kind not in DESCRIPTOR_READONLY_TARGET_KINDS:
                        continue
                    actions.append(
                        KbAction(
                            label=label,
                            action_id=f"{action_id}.handoff",
                            handler=lambda callback_ctx, d=descriptor_copy: _render_handoff_descriptor_action(
                                d,
                                callback_ctx=callback_ctx,
                            ),
                            metadata={
                                "target_kind": descriptor.get("target_kind"),
                                "target_ref": descriptor.get("target_ref"),
                                "preview_tool": descriptor.get("preview_tool") or descriptor.get("method"),
                                "handoff_only": True,
                            },
                        )
                    )
                else:
                    generic = _generic_descriptor_action(ctx, target, descriptor_copy)
                    if generic is None:
                        continue
                    actions.append(generic)
                guidance = _descriptor_advisory_guidance(descriptor)
                if guidance:
                    guidance_actions.append(
                        KbAction(
                            label="Ask LLM",
                            action_id=f"{action_id}.guidance",
                            handler=lambda callback_ctx, d=descriptor_copy: _render_descriptor_guidance(
                                d,
                                title="KB LLM Guidance",
                            ),
                            metadata={
                                "target_kind": descriptor.get("target_kind"),
                                "target_ref": descriptor.get("target_ref"),
                                "advisory_only": True,
                            },
                        )
                    )
                if len(actions) >= 4:
                    return actions
    return (actions + guidance_actions)[:4]


def _descriptor_advisory_guidance(descriptor: dict[str, Any]) -> dict[str, Any]:
    guidance = descriptor.get("advisory_guidance")
    if not isinstance(guidance, dict):
        return {}
    if guidance.get("packet_type") != "kb_advisory_guidance":
        return {}
    if guidance.get("mutates_state") is True:
        return {}
    return guidance


def _guidance_status(guidance: dict[str, Any]) -> str:
    status = _short(guidance.get("status") or guidance.get("state"), "").strip().lower()
    if status:
        return status
    if guidance.get("stale") is True or _get_path(guidance, "staleness", "stale") is True:
        return "stale"
    return "available"


def _guidance_field(guidance: dict[str, Any], *keys: str, limit: int = 520) -> str:
    for key in keys:
        value = guidance.get(key)
        if isinstance(value, dict):
            value = value.get("summary") or value.get("label") or value.get("text") or value.get("message")
        if isinstance(value, list):
            value = "; ".join(_short(item, "") for item in value[:4])
        text = _redact_guidance_text(value, limit=limit)
        if text:
            return text
    return ""


def _guidance_facet_text(guidance: dict[str, Any], facet: str) -> tuple[str, str]:
    facet_key = str(facet or "summary").strip().lower()
    if facet_key == "why":
        return "Why", _guidance_field(guidance, "why", "why_now", "why_this_matters", "summary")
    if facet_key == "recommend":
        return "Recommendation", _guidance_field(guidance, "recommendation", "recommend", "recommended_action", "next_best_action")
    if facet_key == "evidence":
        return "Evidence", _guidance_field(guidance, "evidence", "evidence_summary", "evidence_refs", "supporting_evidence")
    if facet_key == "missing":
        return "Missing Context", _guidance_field(guidance, "missing_context", "evidence_gaps", "gaps", "missing")
    return "Guidance", _guidance_field(guidance, "summary")


def _descriptor_guidance_actions(descriptor: dict[str, Any], *, title: str) -> list[Any]:
    actions: list[Any] = []
    for facet, label in (
        ("why", "Why"),
        ("recommend", "Recommend"),
        ("evidence", "Evidence"),
        ("missing", "Missing Context"),
    ):
        actions.append(
            KbAction(
                label=label,
                action_id=f"guidance.{facet}",
                handler=lambda callback_ctx, d=dict(descriptor), f=facet: _render_descriptor_guidance(
                    d,
                    title=title,
                    facet=f,
                    include_facet_actions=False,
                ),
                metadata={
                    "target_kind": descriptor.get("target_kind"),
                    "target_ref": descriptor.get("target_ref"),
                    "advisory_only": True,
                    "guidance_facet": facet,
                },
            )
        )
    return actions


def _render_descriptor_guidance(
    descriptor: dict[str, Any],
    *,
    title: str = "KB Guidance",
    facet: str = "summary",
    include_facet_actions: bool = True,
) -> dict[str, Any]:
    guidance = _descriptor_advisory_guidance(descriptor)
    if not guidance:
        return {"title": title, "text": f"{title}\nNo advisory guidance was attached to this action.", "actions": []}
    status = _guidance_status(guidance)
    if status in {"unavailable", "blocked", "error", "failed"}:
        reason = _guidance_field(guidance, "unavailable_reason", "reason", "message", limit=240)
        lines = [
            title,
            _short(descriptor.get("label") or descriptor.get("action_id") or "KB action", "KB action"),
            "",
            f"Guidance unavailable: {reason or status}.",
            "Advisory output never confirms, applies, commits, or publishes.",
        ]
        return {"title": title, "text": "\n".join(lines), "actions": []}
    stale = status in {"stale", "expired"}
    facet_title, facet_text = _guidance_facet_text(guidance, facet)
    lines = [
        title,
        _short(descriptor.get("label") or descriptor.get("action_id") or "KB action", "KB action"),
        "",
        facet_text or "Guidance is advisory only and cannot mutate durable KB state.",
        "",
        f"Prompt: {_short(guidance.get('llm_prompt'), 'kb.review_guidance')}",
        f"Mode: {_short(guidance.get('mode'), 'advisory_only')}",
        f"Authority: {_short(guidance.get('authority'), 'no_mutation_authority')}",
        "Mutates KB: no",
    ]
    if facet != "summary":
        lines.insert(2, facet_title)
    if stale:
        lines.append("Status: stale; refresh the KB review card before relying on this guidance.")
    sequence = guidance.get("recommended_sequence") if isinstance(guidance.get("recommended_sequence"), list) else []
    if sequence and facet == "summary":
        lines.append("")
        lines.append("Suggested sequence:")
        for step in sequence[:4]:
            lines.append(f"- {_redact_guidance_text(step, limit=180)}")
    lines.append("")
    lines.append("Advisory output never confirms, applies, commits, or publishes. Use the preview/confirm button path for writes.")
    return {
        "title": title,
        "text": "\n".join(lines),
        "actions": _descriptor_guidance_actions(descriptor, title=title) if include_facet_actions and not stale else [],
    }


def _render_readonly_descriptor_action(
    ctx: Any,
    target: str,
    *,
    descriptor: dict[str, Any],
    callback_ctx: Any,
) -> dict[str, Any]:
    del callback_ctx
    method = _descriptor_tool_name(target, descriptor.get("preview_tool") or descriptor.get("method"))
    params = descriptor.get("params") if isinstance(descriptor.get("params"), dict) else {}
    payload = _dispatch_registry_tool(ctx, target, method, params)
    label = _short(descriptor.get("label") or descriptor.get("action_id") or "KB Context", "KB Context")
    if isinstance(payload, dict) and payload.get("error"):
        return {"title": label, "text": f"{label}\n{payload['error']}", "actions": []}
    packet_card = _render_supported_result_packet(payload, ctx=ctx, target=target)
    if packet_card is not None:
        return packet_card
    if not isinstance(payload, dict):
        return {"title": label, "text": f"{label}\n{_short(payload, 'No context returned.')}", "actions": []}
    title = _short(payload.get("title") or payload.get("name") or label, label)
    summary = _short(payload.get("summary") or payload.get("description") or payload.get("text"), "")
    target_ref = _short(payload.get("target_ref") or descriptor.get("target_ref"), "")
    status = _short(payload.get("status") or payload.get("state"), "")
    lines = [title]
    if summary:
        lines.append(summary)
    if status:
        lines.append(f"Status: {status}")
    if target_ref:
        lines.append(f"Ref: {target_ref}")
    lines.extend(_receipt_lines(payload, include_request=True))
    return {"title": label, "text": "\n".join(lines), "actions": []}


def _render_handoff_descriptor_action(
    descriptor: dict[str, Any],
    *,
    callback_ctx: Any,
) -> dict[str, Any]:
    del callback_ctx
    label = _short(descriptor.get("label") or descriptor.get("action_id") or "KB handoff", "KB handoff")
    target_ref = _short(descriptor.get("target_ref"), "")
    route = _short(descriptor.get("preview_tool") or descriptor.get("method") or descriptor.get("surface"), "kb-engine")
    required = descriptor.get("required_inputs")
    if isinstance(required, str):
        required_values = [required]
    elif isinstance(required, list):
        required_values = [str(value).strip() for value in required if str(value).strip()]
    else:
        required_values = []
    lines = [
        label,
        "This is a kb-engine handoff action, not a durable write.",
    ]
    description = _short(descriptor.get("description") or descriptor.get("expected_result"), "")
    if description:
        lines.append(_clip(description, 220))
    if target_ref:
        lines.append(f"Target: {target_ref}")
    lines.append(f"Route: {route}")
    if required_values:
        lines.append("Required input: " + ", ".join(required_values))
        lines.append("Send the missing context explicitly, then preview through kb-engine before any confirmation.")
    else:
        lines.append("Preview through kb-engine before any confirmation.")
    lines.append("No KB state changed.")
    return {"title": label, "text": "\n".join(lines), "actions": []}


def _descriptor_params(descriptor: dict[str, Any]) -> dict[str, Any]:
    params = descriptor.get("params") if isinstance(descriptor.get("params"), dict) else {}
    return dict(params)


def _generic_descriptor_action(ctx: Any, target: str, descriptor: dict[str, Any]) -> Any | None:
    if descriptor.get("requires_canonical_tool") is not True:
        return None
    preview_tool = _descriptor_tool_name(target, descriptor.get("preview_tool") or descriptor.get("method"))
    confirm_tool = _descriptor_tool_name(target, descriptor.get("confirm_tool"))
    if not preview_tool or not confirm_tool:
        return None
    if str(descriptor.get("target_kind") or "").strip() not in DESCRIPTOR_WRITE_TARGET_KINDS:
        return None
    label = _short(descriptor.get("label") or descriptor.get("action_id") or "Action", "Action")
    action_id = _short(descriptor.get("action_id") or label, label)
    return KbAction(
        label=f"Preview {label}",
        action_id=f"{action_id}.preview",
        handler=lambda callback_ctx, d=dict(descriptor): _render_generic_descriptor_preview(
            ctx,
            target,
            descriptor=d,
            callback_ctx=callback_ctx,
        ),
        metadata={
            "target_kind": descriptor.get("target_kind"),
            "target_ref": descriptor.get("target_ref"),
            "preview_tool": preview_tool,
            "confirm_tool": confirm_tool,
            "preview_required": True,
        },
    )


def _generic_preview_text(label: str, payload: Any) -> str:
    if isinstance(payload, dict) and payload.get("error"):
        return f"{label} Preview Failed\n{payload['error']}"
    packet_card = _render_supported_result_packet(payload)
    if packet_card is not None:
        return packet_card["text"]
    if isinstance(payload, dict):
        lines = [
            f"{label} Preview",
            f"Status: {_short(payload.get('status') or payload.get('state'))}",
        ]
        lines.extend(_receipt_lines(payload, include_request=True))
        changed_paths = _changed_paths(payload)
        if changed_paths:
            lines.append(f"Changed paths: {len(changed_paths)}")
            lines.extend(_format_changed_paths(changed_paths, limit=5))
        lines.extend(_queue_scope_lines(payload))
        summary = _short(payload.get("summary") or payload.get("message"), "")
        if summary:
            lines.append("Summary: " + _clip(summary, 260))
        return "\n".join(lines)
    return f"{label} Preview\n{_short(payload, 'No structured response returned.')}"


def _render_generic_descriptor_preview(
    ctx: Any,
    target: str,
    *,
    descriptor: dict[str, Any],
    callback_ctx: Any,
) -> dict[str, Any]:
    del callback_ctx
    label = _short(descriptor.get("label") or descriptor.get("action_id") or "KB Action", "KB Action")
    action_id = _short(descriptor.get("action_id") or label, label)
    preview_tool = _descriptor_tool_name(target, descriptor.get("preview_tool") or descriptor.get("method"))
    preview_payload = _dispatch_registry_tool(ctx, target, preview_tool, _descriptor_params(descriptor))
    text = _generic_preview_text(label, preview_payload)
    if not _preview_allows_confirmation(
        preview_payload,
        capability=_capability_for_registry_name(target, preview_tool),
    ):
        return {"title": label, "text": text, "actions": []}
    preview_metadata = _queue_preview_metadata(preview_payload)
    confirm_action = KbAction(
        label=f"Confirm {label}",
        action_id=f"{action_id}.confirm",
        handler=lambda confirm_ctx, d=dict(descriptor), metadata=dict(preview_metadata): _render_generic_descriptor_confirm(
            ctx,
            target,
            descriptor=d,
            callback_ctx=confirm_ctx,
            preview_metadata=metadata,
        ),
        metadata={
            "target_kind": descriptor.get("target_kind"),
            "target_ref": descriptor.get("target_ref"),
            "preview_required": True,
            "preview_lease": bool(preview_metadata.get("preview_lease")),
            "review_session_id": _review_session_id(preview_metadata),
        },
    )
    return {
        "title": label,
        "text": text + "\n\nConfirm with the button below only if the preview matches your intent.",
        "actions": [confirm_action],
    }


def _render_generic_descriptor_confirm(
    ctx: Any,
    target: str,
    *,
    descriptor: dict[str, Any],
    callback_ctx: Any,
    preview_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    label = _short(descriptor.get("label") or descriptor.get("action_id") or "KB Action", "KB Action")
    preview_tool = _descriptor_tool_name(target, descriptor.get("preview_tool") or descriptor.get("method"))
    confirm_tool = _descriptor_tool_name(target, descriptor.get("confirm_tool"))
    effective_metadata = dict(preview_metadata or {})
    preview_payload = _dispatch_registry_tool(ctx, target, preview_tool, _descriptor_params(descriptor))
    if not _preview_allows_confirmation(
        preview_payload,
        capability=_capability_for_registry_name(target, preview_tool),
    ):
        return {"title": label, "text": _generic_preview_text(label, preview_payload), "actions": []}
    effective_metadata = _queue_preview_metadata(preview_payload)
    confirm_args = _descriptor_params(descriptor)
    _apply_queue_preview_metadata(confirm_args, effective_metadata)
    confirm_args["user_confirmation"] = {
        "confirmed": True,
        "confirmed_at": _utc_now_text(),
        "surface": "telegram",
        "action": _short(descriptor.get("action_id") or label, label),
        "preview_required": True,
        "confirmation_text": str(descriptor.get("confirmation_copy") or f"Confirm {label}"),
        "actor_id": _short(getattr(callback_ctx, "actor_id", ""), ""),
        "actor_name": _short(getattr(callback_ctx, "actor_name", ""), ""),
    }
    _apply_queue_confirmation_preview_metadata(confirm_args["user_confirmation"], effective_metadata)
    confirm_args.setdefault("actor", _queue_callback_actor(callback_ctx))
    confirm_args.setdefault("source", "Hermes Telegram Action Card")
    confirm_args.setdefault("session_id", _review_session_id(effective_metadata) or f"telegram-kb-card-{int(time.time())}")
    confirmed_payload = _dispatch_registry_tool(ctx, target, confirm_tool, confirm_args)
    completion = _durable_completion(confirmed_payload)
    if not completion["complete"]:
        return {
            "title": label,
            "text": (
                f"{label}\nConfirmation received, but durable readback is not verified "
                f"({completion['reason']}). No durable completion is claimed."
            ),
            "actions": [],
        }
    packet_card = _render_supported_result_packet(confirmed_payload, ctx=ctx, target=target)
    if packet_card is not None:
        return packet_card
    return {"title": label, "text": _generic_preview_text(label.replace("Preview", "Applied"), confirmed_payload), "actions": []}


def _status_next_action(packet: dict[str, Any]) -> str:
    value = packet.get("next_action")
    if isinstance(value, dict):
        value = value.get("summary") or value.get("label") or value.get("next_safe_action")
    text = _public_clip(value, 120)
    if not text:
        return ""
    if text.startswith("/kb sync"):
        return "Ask me to sync."
    if text.startswith("/kb review"):
        return "Ask what needs attention."
    return text


def _render_status(
    data: Any,
    target: str,
    provider_data: Any | None = None,
    *,
    hermes_reasoning: str | None = None,
) -> dict[str, Any]:
    """Render user status without host, model, path, digest, or tool details."""
    del target, provider_data, hermes_reasoning
    if not isinstance(data, dict):
        return {
            "title": "Knowledge status",
            "text": f"{_emphasis_headline('Knowledge status')}\nUnavailable.\nNo KB completion is claimed.",
            "actions": [],
        }

    status = _public_clip(data.get("status") or data.get("state") or _readiness_status(data), 40)
    publication = _public_clip(_publication_status(data), 48)
    review = _get_path(data, "review", "pending_count")
    sync = _public_clip(
        _get_path(data, "sync", "status")
        or _get_path(data, "sync", "state")
        or _get_path(data, "sync", "last_run_status"),
        48,
    )
    lines = [_emphasis_headline("Knowledge status"), f"Status: {status or 'unknown'}"]
    if publication:
        lines.append("Publication: " + publication.replace("_", " "))
    if review not in (None, ""):
        lines.append(f"Needs attention: {_public_clip(review, 20)}")
    if sync:
        lines.append("Last sync: " + sync.replace("_", " "))
    next_action = _status_next_action(data)
    if next_action:
        lines.append("Next: " + next_action)
    return {
        "title": "Knowledge status",
        "status": status or "unknown",
        "text": "\n".join(lines[:7]),
        "actions": [],
    }


def _render_runs(data: Any) -> dict[str, Any]:
    if isinstance(data, str):
        return {"title": "KB Runs", "text": f"KB Runs\n{data}", "actions": []}
    if isinstance(data, dict):
        runs = []
        for found in (
            _get_path(data, "active"),
            _get_path(data, "runs", "active"),
            _get_path(data, "recent"),
            _get_path(data, "runs", "recent"),
        ):
            if isinstance(found, list):
                runs.extend(found)
        if not runs:
            found = _get_path(data, "runs")
            runs = found if isinstance(found, list) else []
    else:
        runs = []
    lines = ["KB Runs"]
    if not runs:
        lines.append("No active or recent run details returned.")
    for idx, run in enumerate(runs[:6], start=1):
        if isinstance(run, dict):
            status = _short(run.get("status") or run.get("state") or run.get("phase"))
            detail = _short(run.get("summary") or run.get("message") or run.get("updated_at"), "")
            staleness = run.get("staleness") if isinstance(run.get("staleness"), dict) else {}
            if staleness.get("stale"):
                detail = f"stalled {_short(staleness.get('last_trace_age_seconds'), 'unknown')}s"
                action = _short(run.get("recommended_next_action"), "")
                if action:
                    detail += f"; {action}"
            suffix = f" - {detail}" if detail else ""
            title = _short(run.get("run_id") or run.get("workflow_id") or _item_title(run))
            lines.append(f"{idx}. {title}: {status}{suffix}")
        else:
            lines.append(f"{idx}. {_short(run)}")
    return {"title": "KB Runs", "text": "\n".join(lines), "actions": []}


def _proposal_ids_for_item(item: Any) -> list[str]:
    if not isinstance(item, dict):
        return []
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    proposal_ids = raw.get("proposal_ids") or item.get("proposal_ids") or []
    if isinstance(proposal_ids, str):
        proposal_ids = [proposal_ids]
    return [str(pid).strip() for pid in proposal_ids if str(pid).strip()]


def _preview_lease_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return None
    for candidate in (
        payload.get("preview_lease"),
        payload.get("lease"),
        _get_path(payload, "preview", "preview_lease"),
        _get_path(payload, "preview", "lease"),
    ):
        if isinstance(candidate, dict):
            return dict(candidate)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def _review_session_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    for candidate in (
        payload.get("review_session"),
        payload.get("preview_session"),
        _get_path(payload, "preview", "review_session"),
        _get_path(payload, "preview", "preview_session"),
    ):
        if isinstance(candidate, dict):
            return dict(candidate)
    return {}


def _safe_scope_label(value: Any) -> str:
    text = _clip(value, 120)
    if not text:
        return ""
    # Scope text is user-facing; avoid rendering path-like or secret-like blobs
    # from backend metadata. Counts are rendered separately.
    if any(marker in text for marker in ("/", "\\", "~", "$", "://")):
        return ""
    return text


def _redact_guidance_text(value: Any, *, limit: int = 520) -> str:
    text = _clip(value, limit)
    if not text:
        return ""
    text = re.sub(r"(?i)\b(?:token|secret|api[_-]?key|private[_-]?key)\s*[:=]\s*\S+", "[redacted]", text)
    text = re.sub(r"(?i)\b(?:sk|ghp|gho|github_pat|xox[abprs])_[A-Za-z0-9_\-]{12,}", "[redacted]", text)
    text = re.sub(r"(?i)(?:/Users|/home|/private|/tmp|~)/\S+", "[redacted-path]", text)
    text = re.sub(r"(?i)\b\S*(?:\.env|id_rsa|id_ed25519|credentials|token|cache)\S*\b", "[redacted]", text)
    return text


def _queue_count_value(*values: Any) -> int | None:
    for value in values:
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if number >= 0:
            return number
    return None


def _queue_preview_metadata(payload: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    lease = _preview_lease_payload(payload)
    if lease:
        metadata["preview_lease"] = lease
    review_session = _review_session_payload(payload)
    if review_session:
        metadata["review_session"] = review_session
        metadata["preview_session"] = review_session
    if isinstance(payload, dict):
        expected_before_hash = _short(
            payload.get("expected_before_hash")
            or payload.get("expectedBeforeHash")
            or payload.get("before_hash")
            or _get_path(payload, "preview", "expected_before_hash")
            or _get_path(payload, "preview", "before_hash"),
            "",
        )
        if expected_before_hash:
            metadata["expected_before_hash"] = expected_before_hash
    return metadata


def _apply_queue_preview_metadata(args: dict[str, Any], metadata: dict[str, Any]) -> None:
    if not metadata:
        return
    expected_before_hash = _short(metadata.get("expected_before_hash"), "")
    if expected_before_hash:
        args.setdefault("expected_before_hash", expected_before_hash)
    review_session_id = _review_session_id(metadata)
    if review_session_id:
        args.setdefault("review_session_id", review_session_id)
    cursor_id = _queue_cursor_id(metadata)
    if cursor_id:
        args.setdefault("cursor_id", cursor_id)
    decision_scope = _queue_decision_scope(metadata)
    if decision_scope:
        # The confirmed write must follow the backend preview lease, even when a
        # descriptor supplied a conservative default scope.
        args["decision_scope"] = decision_scope


def _apply_queue_confirmation_preview_metadata(user_confirmation: dict[str, Any], metadata: dict[str, Any]) -> None:
    if not metadata:
        return
    lease = metadata.get("preview_lease")
    if isinstance(lease, dict) and lease:
        user_confirmation["preview_lease"] = dict(lease)
    elif isinstance(lease, str) and lease.strip():
        user_confirmation["preview_lease_id"] = lease.strip()
    review_session_id = _review_session_id(metadata)
    if review_session_id:
        user_confirmation["review_session_id"] = review_session_id


def _review_session_id(metadata: dict[str, Any]) -> str:
    review_session = metadata.get("review_session") or metadata.get("preview_session")
    if not isinstance(review_session, dict):
        return ""
    return _short(
        review_session.get("session_id")
        or review_session.get("review_session_id")
        or review_session.get("preview_session_id"),
        "",
    )


def _queue_cursor_id(metadata: dict[str, Any]) -> str:
    lease = metadata.get("preview_lease")
    if isinstance(lease, dict):
        cursor_id = _short(lease.get("cursor_id"), "")
        if cursor_id:
            return cursor_id
    review_session = metadata.get("review_session") or metadata.get("preview_session")
    if isinstance(review_session, dict):
        cursor_id = _short(review_session.get("cursor_id"), "")
        if cursor_id:
            return cursor_id
        cursor = review_session.get("cursor")
        if isinstance(cursor, dict):
            return _short(cursor.get("cursor_id"), "")
    return ""


def _queue_decision_scope(metadata: dict[str, Any]) -> str:
    lease = metadata.get("preview_lease")
    if isinstance(lease, dict):
        scope = _queue_scope_value(lease.get("decision_scope")) or _queue_scope_value(lease.get("scope"))
        if scope:
            return scope
    review_session = metadata.get("review_session") or metadata.get("preview_session")
    if isinstance(review_session, dict):
        return _queue_scope_value(review_session.get("decision_scope")) or _queue_scope_value(review_session.get("scope"))
    return ""


def _queue_scope_value(value: Any) -> str:
    if isinstance(value, str):
        return _short(value, "")
    if isinstance(value, dict):
        return _short(value.get("scope_type") or value.get("scope") or value.get("type"), "")
    return ""


def _queue_scope_display_label(value: Any) -> str:
    scope = _queue_scope_value(value).strip().lower()
    if not scope:
        return ""
    aliases = {
        "all_viewed": "Visible",
        "all_window": "Window",
        "all_filtered": "Filter",
        "explicit_ids": "Selected",
    }
    return aliases.get(scope, _safe_scope_label(scope.replace("_", " ").title()))


def _queue_scope_lines(payload: Any) -> list[str]:
    review_session = _review_session_payload(payload)
    if not review_session:
        return []
    lease = _preview_lease_payload(payload)
    cursor = review_session.get("cursor") if isinstance(review_session.get("cursor"), dict) else {}
    scope = review_session.get("scope") if isinstance(review_session.get("scope"), dict) else {}
    scope_label = _safe_scope_label(
        review_session.get("scope_label")
        or review_session.get("scope_description")
        or scope.get("label")
        or scope.get("description")
        or _queue_scope_display_label(review_session.get("decision_scope"))
        or _queue_scope_display_label(review_session.get("scope"))
    )
    item_count = _queue_count_value(
        review_session.get("item_count"),
        review_session.get("selected_item_count"),
        review_session.get("selected_count"),
        cursor.get("displayed_count"),
        scope.get("item_count"),
        scope.get("selected_count"),
    )
    proposal_count = _queue_count_value(
        review_session.get("proposal_count"),
        review_session.get("selected_proposal_count"),
        len(lease.get("proposal_ids", [])) if isinstance(lease, dict) and isinstance(lease.get("proposal_ids"), list) else None,
        scope.get("proposal_count"),
    )
    lines: list[str] = []
    if scope_label:
        lines.append(f"Scope: {scope_label}")
    count_bits: list[str] = []
    if item_count is not None:
        count_bits.append(f"{item_count} item(s)")
    if proposal_count is not None:
        count_bits.append(f"{proposal_count} proposal(s)")
    if count_bits:
        lines.append("Review session: " + " · ".join(count_bits))
    return lines


def _item_kind(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    return _short(item.get("kind") or item.get("type") or raw.get("kind") or raw.get("type"), "")


def _item_target(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    return _short(
        item.get("entity_path")
        or item.get("target")
        or item.get("item_id")
        or raw.get("entity_path")
        or raw.get("target")
        or raw.get("item_id"),
        "",
    )


def _item_detail(item: Any) -> str:
    if not isinstance(item, dict):
        return _short(item, "")
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    return _short(
        item.get("preview")
        or item.get("why")
        or item.get("summary")
        or item.get("description")
        or item.get("detail")
        or raw.get("preview")
        or raw.get("why")
        or raw.get("summary")
        or raw.get("description")
        or raw.get("detail"),
        "",
    )


def _safe_actions_for_item(item: Any) -> list[dict[str, Any]]:
    if not isinstance(item, dict):
        return []
    actions = item.get("safe_actions")
    if not isinstance(actions, list):
        return []
    return [action for action in actions if isinstance(action, dict)]


def _queue_action_decisions(item: dict[str, Any]) -> list[tuple[str, str]]:
    decisions: list[tuple[str, str]] = []
    seen: set[str] = set()
    for action in _safe_actions_for_item(item):
        params = action.get("params") if isinstance(action.get("params"), dict) else {}
        decision = str(params.get("decision") or "").strip().lower()
        if not decision or decision in seen:
            continue
        label = _short(action.get("label") or decision.replace("_", " ").title(), "")
        if not label:
            continue
        seen.add(decision)
        decisions.append((decision, label))
    if any(decision in {"complete", "keep", "demote"} for decision, _ in decisions):
        order = {"complete": 0, "keep": 1, "demote": 2, "archive": 3, "skip": 4}
    else:
        order = {"approve": 0, "reject": 1, "archive": 2, "skip": 3}
    decisions.sort(key=lambda pair: (order.get(pair[0], 99), pair[0]))
    return decisions


def _queue_descriptor_decisions(item: dict[str, Any]) -> list[tuple[str, str]]:
    descriptor_item = dict(item)
    descriptor_item["safe_actions"] = [
        action
        for action in _safe_actions_for_item(item)
        if action.get("dashboard_owned_write") is not True
        and action.get("preview_tool")
        and action.get("confirm_tool")
    ]
    return _queue_action_decisions(descriptor_item)


def _queue_decision_commands(item: dict[str, Any], *, index: int) -> list[str]:
    decisions = _queue_action_decisions(item)
    if not decisions:
        decisions = [
            ("reject", "Reject"),
            ("archive", "Archive"),
            ("approve", "Approve"),
        ]
    lines: list[str] = []
    for decision, label in decisions:
        if decision == "approve":
            label = "Approve proposal"
        elif decision == "reject":
            label = "Reject proposal"
        elif decision == "archive" and not any(d in {"complete", "keep", "demote"} for d, _ in decisions):
            label = "Archive proposal"
        lines.append(f"- {label}: /kb review {decision} {index}")
    if decisions:
        example_decision = decisions[0][0]
        lines.append(f"Confirm from the preview button; text fallback: /kb review {example_decision} {index} confirm")
    return lines


def _descriptor_tool_name(target: str, tool_name: Any) -> str:
    value = str(tool_name or "").strip()
    if not value:
        return ""
    if value.startswith("mcp_"):
        return ""
    if _descriptor(value) is None:
        return ""
    return _mcp_tool_name(target, value)


def _queue_descriptor_actions(
    ctx: Any,
    target: str,
    item: dict[str, Any],
    *,
    index: int,
    preview_label_prefix: bool = True,
    limit: int | None = 4,
) -> list[Any]:
    actions: list[Any] = []
    guidance_descriptor = next(
        (
            descriptor
            for descriptor in _safe_actions_for_item(item)
            if isinstance(descriptor, dict) and _descriptor_advisory_guidance(descriptor)
        ),
        None,
    )
    for descriptor in _safe_actions_for_item(item):
        if descriptor.get("dashboard_owned_write") is True:
            continue
        params = descriptor.get("params") if isinstance(descriptor.get("params"), dict) else {}
        decision = str(params.get("decision") or "").strip().lower()
        preview_tool = _descriptor_tool_name(target, descriptor.get("preview_tool"))
        confirm_tool = _descriptor_tool_name(target, descriptor.get("confirm_tool"))
        if not decision or not preview_tool or not confirm_tool:
            continue
        label = _short(descriptor.get("label") or decision.replace("_", " ").title(), decision.title())
        action_id = _short(descriptor.get("action_id") or f"queue.{decision}", f"queue.{decision}")
        descriptor_copy = dict(descriptor)
        actions.append(
            KbAction(
                label=f"Preview {label}" if preview_label_prefix else label,
                action_id=f"{action_id}.preview",
                handler=lambda callback_ctx, d=descriptor_copy: _render_queue_descriptor_preview(
                    ctx,
                    target,
                    item,
                    index=index,
                    descriptor=d,
                    callback_ctx=callback_ctx,
                ),
                metadata={
                    "target_kind": "proposal_queue",
                    "target_ref": _item_target(item),
                    "decision": decision,
                    "preview_tool": preview_tool,
                    "confirm_tool": confirm_tool,
                },
            )
        )
    if guidance_descriptor:
        descriptor_copy = dict(guidance_descriptor)
        actions.append(
            KbAction(
                label="Ask LLM",
                action_id="queue.advisory_guidance",
                handler=lambda callback_ctx, d=descriptor_copy: _render_descriptor_guidance(
                    d,
                    title="KB Review LLM Guidance",
                ),
                metadata={
                    "target_kind": "proposal_queue",
                    "target_ref": _item_target(item),
                    "advisory_only": True,
                },
            )
        )
    if limit is None:
        return actions
    return actions[:limit]


def _queue_descriptor_call_args(
    descriptor: dict[str, Any],
    item: dict[str, Any],
    *,
    decision: str,
    actor: str,
    source: str,
    note: str,
) -> dict[str, Any]:
    params = descriptor.get("params") if isinstance(descriptor.get("params"), dict) else {}
    proposal_ids = [str(proposal_id) for proposal_id in (params.get("proposal_ids") or []) if str(proposal_id)]
    if not proposal_ids:
        proposal_ids = _proposal_ids_for_item(item)
    args = dict(params)
    args["proposal_ids"] = proposal_ids
    args["decision"] = decision
    args.setdefault("decision_scope", "explicit_ids")
    args.setdefault("displayed_count", len(proposal_ids))
    args.setdefault("candidate_count", len(proposal_ids))
    args["actor"] = actor
    args["source"] = source
    args["note"] = note
    review_metadata = _queue_item_review_metadata(item)
    _apply_queue_preview_metadata(args, review_metadata)
    review_session_id = _review_session_id(review_metadata)
    if review_session_id:
        args.setdefault("session_id", review_session_id)
    return args


def _queue_item_review_metadata(item: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    for candidate in (item.get("preview_lease"), raw.get("preview_lease")):
        if isinstance(candidate, dict) and candidate:
            metadata["preview_lease"] = dict(candidate)
            break
    for candidate in (item.get("review_session"), raw.get("review_session")):
        if isinstance(candidate, dict) and candidate:
            metadata["review_session"] = dict(candidate)
            metadata["preview_session"] = dict(candidate)
            break
    return metadata


def _review_target_payload(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    for candidate in (item.get("review_target"), raw.get("review_target")):
        if isinstance(candidate, dict) and candidate.get("packet_type") == "guided_kb_review_target":
            return dict(candidate)
    return {}


def _review_target_policy(item: Any) -> dict[str, Any]:
    target = _review_target_payload(item)
    policy = target.get("policy") if isinstance(target.get("policy"), dict) else {}
    return dict(policy)


def _control_actions_for_item(item: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for action in _safe_actions_for_item(item):
        route = action.get("confirmed_write_route")
        if isinstance(route, dict) and route.get("operation_id"):
            result.append(action)
    return result


def _action_required_inputs(action: dict[str, Any]) -> list[str]:
    route = action.get("confirmed_write_route") if isinstance(action.get("confirmed_write_route"), dict) else {}
    values = route.get("required_input")
    if values is None:
        values = action.get("required_inputs")
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []
    return [str(value).strip() for value in values if str(value).strip()]


def _control_action_decisions(item: dict[str, Any]) -> list[tuple[str, str]]:
    decisions: list[tuple[str, str]] = []
    for action in _control_actions_for_item(item):
        route = action.get("confirmed_write_route") if isinstance(action.get("confirmed_write_route"), dict) else {}
        operation_id = _short(route.get("operation_id") or _get_path(action, "params", "operation_id"), "")
        if not operation_id:
            continue
        label = _short(action.get("label") or operation_id.rsplit(".", 1)[-1].title(), "")
        if label:
            decisions.append((operation_id, label))
    order = {"todo.complete": 0, "todo.delegate": 1, "todo.archive": 2}
    decisions.sort(key=lambda pair: (order.get(pair[0], 99), pair[0]))
    return decisions


def _queue_review_action_labels(item: dict[str, Any]) -> list[str]:
    descriptor_labels = [label for _decision, label in _queue_descriptor_decisions(item)]
    if descriptor_labels:
        return descriptor_labels
    control_labels = [label for _operation, label in _control_action_decisions(item)]
    if control_labels:
        return control_labels
    target = _review_target_payload(item)
    action_ids = target.get("action_ids") if isinstance(target.get("action_ids"), list) else []
    labels: list[str] = []
    for action_id in action_ids:
        label = _review_action_label(action_id)
        if label and label not in labels:
            labels.append(label)
    return labels


def _review_action_label(action_id: Any) -> str:
    value = str(action_id or "").strip()
    aliases = {
        "todo.complete": "Complete",
        "todo.archive": "Archive",
        "todo.delegate": "Delegate",
        "open_situation": "Details",
        "propose_situation_update": "Add Update",
        "propose_child_commitment": "Add Commitment",
    }
    if value in aliases:
        return aliases[value]
    tail = value.rsplit(".", 1)[-1].replace("_", " ").strip()
    return tail.title() if tail else ""


def _review_guidance_available(item: dict[str, Any]) -> bool:
    return bool(_descriptor_advisory_guidance_for_item(item) or _review_target_payload(item))


def _render_review_target_guidance(item: dict[str, Any]) -> dict[str, Any]:
    target = _review_target_payload(item)
    if not target:
        return {
            "title": "KB Review Guidance",
            "text": "KB Review Guidance\nNo backend review target metadata was available. Refresh the card before asking for guidance.",
            "actions": [],
        }
    policy = target.get("policy") if isinstance(target.get("policy"), dict) else {}
    scope = target.get("scope") if isinstance(target.get("scope"), dict) else {}
    lines = [
        "KB Review Guidance",
        f"Target: {_short(target.get('title') or _item_title(item))}",
        f"Kind: {_short(target.get('kind') or _item_kind(item), 'review target')}",
        "Advisory only: cannot preview, confirm, or mutate KB state.",
    ]
    affected_count = scope.get("affected_count")
    viewed_count = scope.get("viewed_count")
    if affected_count is not None or viewed_count is not None:
        lines.append(
            "Scope: "
            + " · ".join(
                bit
                for bit in (
                    f"{affected_count} affected" if affected_count is not None else "",
                    f"{viewed_count} viewed" if viewed_count is not None else "",
                )
                if bit
            )
        )
    if policy:
        lines.append(
            "Write posture: "
            + (
                "preview and confirmed envelope required"
                if policy.get("preview_required") or policy.get("confirmed_envelope_required")
                else "read/proposal handoff only"
            )
        )
    summary = _short(target.get("summary") or _item_detail(item), "")
    if summary:
        lines.append("Context: " + _clip(summary, 360))
    return {"title": "KB Review Guidance", "text": "\n".join(lines), "actions": []}


def _control_action_plan(action: dict[str, Any], *, reason: str) -> dict[str, Any]:
    route = action.get("confirmed_write_route") if isinstance(action.get("confirmed_write_route"), dict) else {}
    operation_id = _short(route.get("operation_id") or _get_path(action, "params", "operation_id"), "")
    arguments = route.get("arguments") if isinstance(route.get("arguments"), dict) else {}
    label = _short(action.get("label") or operation_id.rsplit(".", 1)[-1].title(), "Apply")
    return {
        "summary": f"{label} from Telegram KB Review.",
        "operations": [
            {
                "operation_id": operation_id,
                "arguments": dict(arguments),
                "reason": reason,
            }
        ],
        "confirmation": {
            "question": f"Confirm {label}?",
            "operation_ids": [operation_id] if operation_id else [],
        },
    }


def _control_action_object(action: dict[str, Any]) -> dict[str, Any]:
    route = action.get("confirmed_write_route") if isinstance(action.get("confirmed_write_route"), dict) else {}
    obj = route.get("object_ref") if isinstance(route.get("object_ref"), dict) else {}
    return dict(obj)


def _control_preview_text(label: str, item: dict[str, Any], payload: Any) -> str:
    if isinstance(payload, dict) and payload.get("error"):
        return f"KB Control Preview Failed\n{payload['error']}"
    if not isinstance(payload, dict):
        return "KB Control Preview\n" + _short(payload, "No structured response returned.")
    lines = [
        "KB Control Preview",
        f"Action: {label}",
        f"Target: {_item_title(item)}",
        f"Status: {_short(payload.get('status') or payload.get('state'), 'preview')}",
    ]
    results = payload.get("results") if isinstance(payload.get("results"), list) else []
    for result in results[:3]:
        if isinstance(result, dict):
            message = _short(result.get("message") or result.get("status"), "")
            operation = _short(result.get("operation_id"), "")
            if message or operation:
                lines.append("- " + " · ".join(bit for bit in (operation, message) if bit))
    lines.extend(_receipt_lines(payload, include_request=True))
    if _preview_allows_confirmation(payload):
        lines.append("Confirm only if this preview matches the action you intend.")
    return "\n".join(lines)


def _control_result_text(label: str, payload: Any) -> str:
    if isinstance(payload, dict) and payload.get("error"):
        return f"KB Control Result Failed\n{payload['error']}"
    if not isinstance(payload, dict):
        return "KB Control Result\n" + _short(payload, "No structured response returned.")
    lines = [
        "KB Control Result",
        f"Action: {label}",
        f"Status: {_short(payload.get('status') or payload.get('state'), 'unknown')}",
    ]
    lines.extend(_receipt_lines(payload, include_request=True))
    results = payload.get("results") if isinstance(payload.get("results"), list) else []
    for result in results[:3]:
        if isinstance(result, dict):
            message = _short(result.get("message") or result.get("status"), "")
            operation = _short(result.get("operation_id"), "")
            if message or operation:
                lines.append("- " + " · ".join(bit for bit in (operation, message) if bit))
    return "\n".join(lines)


def _render_control_action_confirm(
    ctx: Any,
    target: str,
    item: dict[str, Any],
    action: dict[str, Any],
    *,
    packet: dict[str, Any],
    plan: dict[str, Any],
    preview_payload: dict[str, Any],
    callback_ctx: Any,
) -> dict[str, Any]:
    label = _short(action.get("label") or "Apply", "Apply")
    actor = _queue_callback_actor(callback_ctx)
    source = "Hermes Telegram Action Card"
    session_id = _review_session_id(_queue_item_review_metadata(item)) or f"telegram-kb-control-{int(time.time())}"
    envelope_tool = _descriptor_tool_name(target, "control.build_confirmed_envelope")
    envelope_payload = _dispatch_registry_tool(
        ctx,
        target,
        envelope_tool,
        {
                "packet": packet,
                "plan": plan,
                "actor": actor,
                "source": source,
                "session_id": session_id,
                "user_confirmation": {
                    "confirmed": True,
                    "confirmed_at": _utc_now_text(),
                    "confirmed_by": actor,
                    "confirmation_text": f"Confirmed {label} from Telegram KB Review.",
                    "preview_status": _short(preview_payload.get("status"), ""),
                    "review_session_id": session_id,
                },
        },
    )
    envelope = envelope_payload.get("envelope") if isinstance(envelope_payload, dict) else None
    if not isinstance(envelope, dict):
        return {"title": "KB Control", "text": _control_result_text(label, envelope_payload), "actions": []}
    applied_tool = _descriptor_tool_name(target, "control.apply_confirmed")
    applied = _dispatch_registry_tool(
        ctx,
        target,
        applied_tool,
        {"envelope": envelope},
    )
    return {"title": "KB Control", "text": _control_result_text(label, applied), "actions": []}


def _render_control_action_preview(
    ctx: Any,
    target: str,
    item: dict[str, Any],
    action: dict[str, Any],
    *,
    callback_ctx: Any,
) -> dict[str, Any]:
    label = _short(action.get("label") or "Apply", "Apply")
    missing_inputs = _action_required_inputs(action)
    if missing_inputs:
        return {
            "title": "KB Control",
            "text": (
                f"KB Control\n{label} needs additional input first: "
                + ", ".join(missing_inputs)
                + ". Refresh in a fuller workbench surface."
            ),
            "actions": [],
        }
    actor = _queue_callback_actor(callback_ctx)
    source = "Hermes Telegram Action Card"
    reason = f"{label} previewed from Telegram KB Review for {_item_title(item)}."
    obj = _control_action_object(action)
    context_tool = _descriptor_tool_name(target, "control.context")
    packet = _dispatch_registry_tool(
        ctx,
        target,
        context_tool,
        {"object": obj, "user_input": reason},
    )
    if not isinstance(packet, dict) or packet.get("error"):
        return {"title": "KB Control", "text": _control_preview_text(label, item, packet), "actions": []}
    plan = _control_action_plan(action, reason=reason)
    apply_preview_tool = _descriptor_tool_name(target, "control.apply_preview")
    preview_payload = _dispatch_registry_tool(
        ctx,
        target,
        apply_preview_tool,
        {
                "packet": packet,
                "plan": plan,
                "actor": actor,
                "source": source,
        },
    )
    actions: list[Any] = []
    if isinstance(preview_payload, dict) and _preview_allows_confirmation(
        preview_payload,
        capability=_capability_for_registry_name(target, apply_preview_tool),
    ):
        preview_plan = preview_payload.get("plan") if isinstance(preview_payload.get("plan"), dict) else plan
        actions.append(
            KbAction(
                label=f"Confirm {label}",
                action_id="control.apply_confirmed.confirm",
                handler=lambda confirm_ctx, p=dict(packet), pl=dict(preview_plan), pp=dict(preview_payload), a=dict(action): _render_control_action_confirm(
                    ctx,
                    target,
                    item,
                    a,
                    packet=p,
                    plan=pl,
                    preview_payload=pp,
                    callback_ctx=confirm_ctx,
                ),
                metadata={
                    "target_kind": "todo",
                    "target_ref": _item_target(item),
                    "preview_required": True,
                    "review_session_id": _review_session_id(_queue_item_review_metadata(item)),
                },
            )
        )
    return {"title": "KB Control", "text": _control_preview_text(label, item, preview_payload), "actions": actions}


def _queue_control_actions(
    ctx: Any,
    target: str,
    item: dict[str, Any],
    *,
    limit: int | None = 3,
) -> list[Any]:
    required = (
        "control.context",
        "control.apply_preview",
        "control.build_confirmed_envelope",
        "control.apply_confirmed",
    )
    if any(_descriptor(name) is None for name in required):
        return []
    actions: list[Any] = []
    for action in _control_actions_for_item(item):
        label = _short(action.get("label") or _get_path(action, "confirmed_write_route", "operation_id"), "")
        if not label:
            continue
        action_copy = dict(action)
        actions.append(
            KbAction(
                label=label,
                action_id=f"{_short(_get_path(action, 'confirmed_write_route', 'operation_id'), 'control.action')}.preview",
                handler=lambda callback_ctx, a=action_copy: _render_control_action_preview(
                    ctx,
                    target,
                    item,
                    a,
                    callback_ctx=callback_ctx,
                ),
                metadata={
                    "target_kind": "todo",
                    "target_ref": _item_target(item),
                    "preview_required": True,
                },
            )
        )
    if limit is None:
        return actions
    return actions[:limit]


def _queue_callback_actor(callback_ctx: Any) -> str:
    actor_id = str(getattr(callback_ctx, "actor_id", "") or "").strip()
    return f"telegram:{actor_id}" if actor_id else "telegram:operator"


def _render_queue_descriptor_preview(
    ctx: Any,
    target: str,
    item: dict[str, Any],
    *,
    index: int,
    descriptor: dict[str, Any],
    callback_ctx: Any,
) -> dict[str, Any]:
    params = descriptor.get("params") if isinstance(descriptor.get("params"), dict) else {}
    decision = str(params.get("decision") or "").strip().lower()
    if not decision:
        return {"title": "KB Review", "text": "KB Review\nThis action is missing a proposal decision.", "actions": []}
    proposal_ids = [str(proposal_id) for proposal_id in (params.get("proposal_ids") or []) if str(proposal_id)] or _proposal_ids_for_item(item)
    actor = _queue_callback_actor(callback_ctx)
    source = "Hermes Telegram Action Card"
    preview_tool = _descriptor_tool_name(target, descriptor.get("preview_tool"))
    if not preview_tool:
        return _capability_unavailable("KB Review", (str(descriptor.get("preview_tool") or "review preview"),))
    preview_payload = _dispatch_registry_tool(
        ctx,
        target,
        preview_tool,
        _queue_descriptor_call_args(
                descriptor,
                item,
                decision=decision,
                actor=actor,
                source=source,
                note=f"Previewed from Telegram action card for {_item_title(item)}",
        ),
    )
    selection = [(index, item)]
    text = _preview_text(decision, proposal_ids, preview_payload, selection=selection)
    if not _preview_allows_confirmation(
        preview_payload,
        capability=_capability_for_registry_name(target, preview_tool),
    ):
        return {"title": "KB Review", "text": text, "actions": []}
    preview_metadata = _queue_preview_metadata(preview_payload)
    label = _short(descriptor.get("label") or decision.replace("_", " ").title(), decision.title())
    action_id = _short(descriptor.get("action_id") or f"queue.{decision}", f"queue.{decision}")
    confirm_action = KbAction(
        label=f"Confirm {label}",
        action_id=f"{action_id}.confirm",
        handler=lambda confirm_ctx: _render_queue_descriptor_confirm(
            ctx,
            target,
            item,
            index=index,
            descriptor=descriptor,
            callback_ctx=confirm_ctx,
            preview_metadata=preview_metadata,
        ),
        metadata={
            "target_kind": "proposal_queue",
            "target_ref": _item_target(item),
            "decision": decision,
            "preview_required": True,
            "preview_lease": bool(preview_metadata.get("preview_lease")),
            "review_session_id": _review_session_id(preview_metadata),
        },
    )
    return {
        "title": "KB Review",
        "text": text + "\n\nConfirm with the button below only if the preview matches your intent.",
        "actions": [confirm_action],
    }


def _render_queue_descriptor_confirm(
    ctx: Any,
    target: str,
    item: dict[str, Any],
    *,
    index: int,
    descriptor: dict[str, Any],
    callback_ctx: Any,
    preview_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    params = descriptor.get("params") if isinstance(descriptor.get("params"), dict) else {}
    decision = str(params.get("decision") or "").strip().lower()
    if not decision:
        return {"title": "KB Review", "text": "KB Review\nThis action is missing a proposal decision.", "actions": []}
    proposal_ids = [str(proposal_id) for proposal_id in (params.get("proposal_ids") or []) if str(proposal_id)] or _proposal_ids_for_item(item)
    actor = _queue_callback_actor(callback_ctx)
    source = "Hermes Telegram Action Card"
    preview_tool = _descriptor_tool_name(target, descriptor.get("preview_tool"))
    confirmed_tool = _descriptor_tool_name(target, descriptor.get("confirm_tool"))
    if not preview_tool or not confirmed_tool:
        return _capability_unavailable(
            "KB Review",
            (
                str(descriptor.get("preview_tool") or "review preview"),
                str(descriptor.get("confirm_tool") or "review confirmation"),
            ),
        )
    selection = [(index, item)]
    effective_metadata = dict(preview_metadata or {})
    preview_payload = _dispatch_registry_tool(
        ctx,
        target,
        preview_tool,
        _queue_descriptor_call_args(
            descriptor,
            item,
            decision=decision,
            actor=actor,
            source=source,
            note=f"Re-previewed before Telegram action-card confirmation for {_item_title(item)}",
        ),
    )
    if not _preview_allows_confirmation(
        preview_payload,
        capability=_capability_for_registry_name(target, preview_tool),
    ):
        return {"title": "KB Review", "text": _preview_text(decision, proposal_ids, preview_payload, selection=selection), "actions": []}
    effective_metadata = _queue_preview_metadata(preview_payload)
    confirmed_args = _queue_descriptor_call_args(
        descriptor,
        item,
        decision=decision,
        actor=actor,
        source=source,
        note=f"Confirmed from Telegram action card for {_item_title(item)}",
    )
    _apply_queue_preview_metadata(confirmed_args, effective_metadata)
    confirmed_args["session_id"] = _review_session_id(effective_metadata) or f"telegram-kb-card-{int(time.time())}"
    confirmed_args["user_confirmation"] = {
        "confirmed": True,
        "confirmed_at": _utc_now_text(),
        "surface": "telegram",
        "action": f"queue.{decision}",
        "preview_required": True,
        "confirmation_text": str(descriptor.get("confirmation_copy") or f"Confirm {decision}"),
        "proposal_ids": proposal_ids,
    }
    _apply_queue_confirmation_preview_metadata(confirmed_args["user_confirmation"], effective_metadata)
    confirmed_payload = _dispatch_registry_tool(ctx, target, confirmed_tool, confirmed_args)
    return {
        "title": "KB Review",
        "text": _confirmed_text(
            decision,
            confirmed_payload,
            selection=selection,
            proposal_ids=proposal_ids,
            expected_completion=_review_completion_expectation(
                _capability_for_registry_name(target, confirmed_tool),
                confirmed_args,
            ),
        ),
        "actions": [],
    }


def _queue_item_text(item: dict[str, Any], *, index: int) -> str:
    proposal_ids = _proposal_ids_for_item(item)
    lines = [
        f"Review Item {index}",
        f"Title: {_item_title(item)}",
    ]
    kind = _item_kind(item)
    target = _item_target(item)
    detail = _item_detail(item)
    if kind:
        lines.append(f"Type: {kind}")
    if target:
        lines.append(f"Target: {target}")
    if detail:
        lines.append("")
        lines.append("Summary: " + _clip(detail, 420))
    if proposal_ids:
        lines.append("")
        lines.append(f"Proposal ids: {', '.join(proposal_ids[:5])}")
        descriptor_actions = _queue_descriptor_decisions(item)
        if descriptor_actions:
            labels = [label for _decision, label in descriptor_actions]
            lines.append("Decision rail: " + ", ".join(labels))
            lines.append("Nothing applies until a kb-engine preview returns and you confirm from that preview.")
        else:
            lines.append("Fallback text actions:")
            lines.extend(_queue_decision_commands(item, index=index))
    else:
        control_actions = _control_action_decisions(item)
        lines.append("")
        if control_actions:
            lines.append("Decision rail: " + ", ".join(label for _operation, label in control_actions))
            lines.append("Nothing applies until kb-engine previews the control route and you confirm.")
        elif _review_target_payload(item):
            lines.append("Review target: backend-owned session metadata is available.")
            lines.append("No direct write is available from this card; use Details or Ask LLM.")
        else:
            lines.append(
                "This item did not include backend review metadata, so Telegram cannot apply a decision yet. Refresh the KB workbench."
            )
    return "\n".join(lines)


def _queue_review_text(data: Any, visible_items: list[Any], *, total: int | None, offset: int) -> str:
    item = visible_items[0] if visible_items and isinstance(visible_items[0], dict) else None
    if item is None:
        return "KB Review\nNo proposal previews returned."
    current = offset + 1
    total_label = total if total is not None else len(visible_items)
    title = _item_title(item)
    detail = _item_detail(item)
    target = _item_target(item)
    proposal_ids = _proposal_ids_for_item(item)
    rail_labels = _queue_review_action_labels(item)
    rail_labels.append("Details")
    if _review_guidance_available(item):
        rail_labels.append("Ask LLM")
    if _queue_item_at(data, 2) is not None:
        rail_labels.append("Skip")
    lines = [
        "KB Review",
        f"{current} of {total_label} · Visible scope",
        title,
    ]
    if detail:
        lines.append(_clip(detail, 260))
    scope_bits: list[str] = []
    if target:
        scope_bits.append(target)
    if proposal_ids:
        scope_bits.append(f"{len(proposal_ids)} proposal{'s' if len(proposal_ids) != 1 else ''}")
    elif _review_target_payload(item):
        scope_bits.append("1 review target")
    if visible_items:
        scope_bits.append(f"{len(visible_items)} visible")
    if total is not None and total != len(visible_items):
        scope_bits.append(f"{total} total")
    if scope_bits:
        lines.append("Scope: " + " · ".join(scope_bits))
    if rail_labels:
        lines.append("Rail: " + ", ".join(rail_labels[:6]))
    policy = _review_target_policy(item)
    if proposal_ids:
        lines.append("Nothing applies until kb-engine returns a preview lease and you confirm.")
    elif policy.get("preview_required") or _control_actions_for_item(item):
        lines.append("Nothing applies until kb-engine previews the control route and you confirm.")
    else:
        lines.append("No direct write is available from this card; use Details or Ask LLM.")
    waiting = max(len(visible_items) - 1, 0)
    if waiting:
        lines.append(f"{waiting} more item{'s' if waiting != 1 else ''} waiting in this Telegram window.")
    return "\n".join(lines)


def _descriptor_advisory_guidance_for_item(item: dict[str, Any]) -> dict[str, Any] | None:
    for descriptor in _safe_actions_for_item(item):
        guidance = _descriptor_advisory_guidance(descriptor)
        if guidance:
            return guidance
    return None


def _selection_lines(selection: list[tuple[int, dict[str, Any]]]) -> list[str]:
    lines: list[str] = []
    for index, item in selection:
        lines.append(f"{index}. {_item_title(item)}")
        target = _item_target(item)
        kind = _item_kind(item)
        detail = _item_detail(item)
        if target:
            lines.append(f"   Target: {target}")
        if kind:
            lines.append(f"   Type: {kind}")
        if detail:
            lines.append(f"   Summary: {_clip(detail, 180)}")
    return lines


def _format_indices(indices: list[int]) -> str:
    return ",".join(str(index) for index in indices)


def _proposal_ids_for_selection(selection: list[tuple[int, dict[str, Any]]]) -> list[str]:
    proposal_ids: list[str] = []
    seen: set[str] = set()
    for _, item in selection:
        for proposal_id in _proposal_ids_for_item(item):
            if proposal_id not in seen:
                seen.add(proposal_id)
                proposal_ids.append(proposal_id)
    return proposal_ids


def _queue_selection_snapshot(selection: list[tuple[int, dict[str, Any]]]) -> list[dict[str, Any]]:
    snapshots: list[dict[str, Any]] = []
    for index, item in selection:
        snapshots.append(
            {
                "index": int(index),
                "title": _item_title(item),
                "kind": _item_kind(item),
                "target": _item_target(item),
                "detail": _item_detail(item),
                "proposal_ids": _proposal_ids_for_item(item),
            }
        )
    return snapshots


def _queue_selection_from_snapshot(snapshots: Any) -> list[tuple[int, dict[str, Any]]]:
    selection: list[tuple[int, dict[str, Any]]] = []
    if not isinstance(snapshots, list):
        return selection
    for offset, snapshot in enumerate(snapshots, start=1):
        if not isinstance(snapshot, dict):
            continue
        try:
            index = int(snapshot.get("index") or offset)
        except (TypeError, ValueError):
            index = offset
        proposal_ids = [str(item) for item in (snapshot.get("proposal_ids") or []) if str(item).strip()]
        item = {
            "title": _short(snapshot.get("title"), "Review item"),
            "kind": _short(snapshot.get("kind"), ""),
            "target": _short(snapshot.get("target"), ""),
            "detail": _short(snapshot.get("detail"), ""),
            "raw": {"proposal_ids": proposal_ids},
        }
        selection.append((index, item))
    return selection


def _queue_scope_state(session_id: str, *, create: bool = False) -> tuple[dict[str, Any], dict[str, Any] | None]:
    states = _load_queue_scope_states()
    if not session_id:
        return states, None
    state = states.get(session_id)
    if not isinstance(state, dict):
        if not create:
            return states, None
        state = {"schema_version": 1}
        states[session_id] = state
    return states, state


def _queue_scope_stale(record: Any) -> bool:
    if not isinstance(record, dict):
        return True
    try:
        recorded_at = float(record.get("recorded_at") or 0.0)
    except (TypeError, ValueError):
        return True
    if recorded_at <= 0:
        return True
    return bool(time.time() - recorded_at > QUEUE_SCOPE_STATE_TTL_SECONDS)


def _queue_total(data: Any) -> int | None:
    if not isinstance(data, dict):
        return None
    return _queue_count_value(
        data.get("total"),
        data.get("count"),
        _get_path(data, "counts", "proposals"),
        _get_path(data, "queue", "count"),
    )


def _queue_offset(data: Any) -> int:
    if not isinstance(data, dict):
        return 0
    return _queue_count_value(data.get("offset"), _get_path(data, "page", "offset")) or 0


def _queue_next_offset(data: Any) -> int | None:
    if not isinstance(data, dict):
        return None
    return _queue_count_value(data.get("next_offset"), _get_path(data, "page", "next_offset"))


def _store_visible_queue_scope(
    session_id: str,
    items: list[Any],
    *,
    total: int | None = None,
    offset: int = 0,
    next_offset: int | None = None,
) -> None:
    if not session_id:
        return
    selection = [(idx, item) for idx, item in enumerate(items, start=1) if isinstance(item, dict)]
    states, state = _queue_scope_state(session_id, create=True)
    if state is None:
        return
    state["visible"] = {
        "kind": "visible_queue_window",
        "recorded_at": time.time(),
        "selection": _queue_selection_snapshot(selection),
        "offset": int(offset),
        "displayed_count": len(selection),
    }
    if total is not None:
        state["visible"]["candidate_count"] = int(total)
    if next_offset is not None:
        state["visible"]["next_offset"] = int(next_offset)
    _save_queue_scope_states(states)


def _get_visible_queue_scope_record(session_id: str) -> dict[str, Any]:
    states, state = _queue_scope_state(session_id)
    if state is None:
        return {}
    visible = state.get("visible")
    if _queue_scope_stale(visible):
        state.pop("visible", None)
        _save_queue_scope_states(states)
        return {}
    return dict(visible) if isinstance(visible, dict) else {}


def _get_visible_queue_scope(session_id: str) -> list[tuple[int, dict[str, Any]]]:
    visible = _get_visible_queue_scope_record(session_id)
    if not visible:
        return []
    return _queue_selection_from_snapshot(visible.get("selection"))


def _store_queue_text_preview_scope(
    session_id: str,
    *,
    decision: str,
    indices: list[int],
    selection: list[tuple[int, dict[str, Any]]],
    preview_payload: Any = None,
) -> None:
    if not session_id:
        return
    states, state = _queue_scope_state(session_id, create=True)
    if state is None:
        return
    state["preview"] = {
        "kind": "queue_text_preview",
        "recorded_at": time.time(),
        "decision": str(decision or "").strip().lower(),
        "indices": [int(index) for index in indices],
        "selection": _queue_selection_snapshot(selection),
        "proposal_ids": _proposal_ids_for_selection(selection),
    }
    state["preview"]["preview_metadata"] = _queue_preview_metadata(preview_payload)
    _save_queue_scope_states(states)


def _get_queue_text_preview_scope(
    session_id: str,
    *,
    decision: str,
    indices: list[int],
) -> tuple[list[tuple[int, dict[str, Any]]], dict[str, Any]]:
    states, state = _queue_scope_state(session_id)
    if state is None:
        return [], {}
    preview = state.get("preview")
    if _queue_scope_stale(preview):
        state.pop("preview", None)
        _save_queue_scope_states(states)
        return [], {}
    if str(preview.get("decision") or "").strip().lower() != str(decision or "").strip().lower():
        return [], {}
    try:
        recorded_indices = [int(index) for index in (preview.get("indices") or [])]
    except (TypeError, ValueError):
        recorded_indices = []
    if recorded_indices != [int(index) for index in indices]:
        return [], {}
    preview_metadata = preview.get("preview_metadata") if isinstance(preview.get("preview_metadata"), dict) else {}
    return _queue_selection_from_snapshot(preview.get("selection")), dict(preview_metadata)


def _preview_text(
    decision: str,
    proposal_ids: list[str],
    payload: Any,
    *,
    selection: list[tuple[int, dict[str, Any]]] | None = None,
    item: dict[str, Any] | None = None,
) -> str:
    if selection is None:
        selection = [(0, item)] if isinstance(item, dict) else []
    if isinstance(payload, dict) and payload.get("error"):
        return f"Review {decision} preview failed\n{payload['error']}"
    if isinstance(payload, dict):
        status = _short(payload.get("status"))
        ok = _short(payload.get("ok"))
        preview = payload.get("preview") if isinstance(payload.get("preview"), dict) else {}
        summary = _short(
            preview.get("summary")
            or _get_path(payload, "plan", "summary")
            or f"{decision.title()} {len(proposal_ids)} proposal(s).",
        )
        lines = [f"Review {decision} preview"]
        if selection:
            lines.append(f"Items: {len(selection)}")
            lines.extend(_selection_lines(selection))
        lines.extend(
            [
                f"Status: {status} · ok: {ok}",
                f"Proposal ids: {', '.join(proposal_ids[:5])}",
                "Plan: " + _clip(summary, 260),
                "Confirm only if this item and decision match what you intend.",
            ]
        )
        lines.extend(_queue_scope_lines(payload))
        return "\n".join(lines)
    lines = [f"Review {decision} preview"]
    if selection:
        lines.extend(_selection_lines(selection))
    lines.append(f"Proposal ids: {', '.join(proposal_ids[:5])}")
    return "\n".join(lines)


def _generated_preview_contract_ready(capability: str) -> bool:
    descriptor = _descriptor(capability)
    schema = descriptor.get("output_schema") if isinstance(descriptor, dict) else None
    if not isinstance(schema, dict):
        return False
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    if not {"status", "ok", "preview_hash", "preview_lease", "plan"} <= set(
        schema.get("required") or []
    ):
        return False
    lease_schema = properties.get("preview_lease") if isinstance(properties.get("preview_lease"), dict) else {}
    plan_schema = properties.get("plan") if isinstance(properties.get("plan"), dict) else {}
    if not _schema_is_concrete(lease_schema, require_required=True):
        return False
    if not _schema_is_concrete(plan_schema, require_required=True):
        return False
    lease_properties = lease_schema.get("properties") if isinstance(lease_schema.get("properties"), dict) else {}
    lease_required = set(lease_schema.get("required") or [])
    if not {"preview_lease_id", "preview_hash", "confirm_tool"} <= lease_required:
        return False
    confirm_schema = lease_properties.get("confirm_tool") if isinstance(lease_properties.get("confirm_tool"), dict) else {}
    confirm_tool = str(confirm_schema.get("const") or "").strip()
    confirm_descriptor = _descriptor(confirm_tool)
    confirm_annotations = (
        confirm_descriptor.get("annotations") if isinstance(confirm_descriptor, dict) else {}
    )
    if not confirm_tool or not isinstance(confirm_annotations, dict) or confirm_annotations.get("readOnlyHint") is not False:
        return False
    scope_fields = [
        name
        for name in lease_required
        if name.endswith("_ids")
        and isinstance(lease_properties.get(name), dict)
        and lease_properties[name].get("type") == "array"
        and int(lease_properties[name].get("minItems") or 0) >= 1
    ]
    if not scope_fields:
        return False
    plan_properties = plan_schema.get("properties") if isinstance(plan_schema.get("properties"), dict) else {}
    operations_schema = plan_properties.get("operations") if isinstance(plan_properties.get("operations"), dict) else {}
    operation_schema = operations_schema.get("items") if isinstance(operations_schema.get("items"), dict) else {}
    return bool(
        "operations" in set(plan_schema.get("required") or [])
        and operations_schema.get("type") == "array"
        and int(operations_schema.get("minItems") or 0) >= 1
        and _schema_is_concrete(operation_schema, require_required=True)
        and "operation_id" in set(operation_schema.get("required") or [])
    )


def _preview_allows_confirmation(payload: Any, *, capability: str = "") -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("error") or payload.get("isError"):
        return False
    if payload.get("ok") is not True:
        return False
    status = str(payload.get("status") or payload.get("state") or "").strip().lower()
    if not status:
        return False
    if status in {
        "blocked",
        "error",
        "failed",
        "operator_blocked",
        "preview_lease_expired",
        "preview_lease_missing",
        "preview_lease_mismatch",
        "preview_lease_stale",
        "stale_cursor",
        "stale_preview_lease",
        "validation_failed",
    }:
        return False
    if not _generated_preview_contract_ready(capability):
        return False
    if _validate_runtime_output(capability, payload):
        return False
    if status not in {
        "planned",
        "preview_ready",
        "ready",
        "ready_to_confirm",
        "success",
        "valid",
        "validated",
    }:
        return False
    lease = payload.get("preview_lease") if isinstance(payload.get("preview_lease"), dict) else {}
    preview_digest = _normalized_digest(payload.get("preview_hash"))
    if not preview_digest or _normalized_digest(lease.get("preview_hash")) != preview_digest:
        return False
    confirm_tool = str(lease.get("confirm_tool") or "").strip()
    confirm_descriptor = _descriptor(confirm_tool)
    confirm_annotations = (
        confirm_descriptor.get("annotations") if isinstance(confirm_descriptor, dict) else {}
    )
    if not isinstance(confirm_annotations, dict) or confirm_annotations.get("readOnlyHint") is not False:
        return False
    descriptor = _descriptor(capability) or {}
    output_schema = descriptor.get("output_schema") if isinstance(descriptor.get("output_schema"), dict) else {}
    lease_schema = _get_path(output_schema, "properties", "preview_lease", default={})
    scope_fields = [
        name
        for name in (lease_schema.get("required") or [])
        if isinstance(name, str) and name.endswith("_ids")
    ] if isinstance(lease_schema, dict) else []
    if not any(isinstance(lease.get(name), list) and bool(lease[name]) for name in scope_fields):
        return False
    plan = payload.get("plan") if isinstance(payload.get("plan"), dict) else {}
    operations = plan.get("operations") if isinstance(plan.get("operations"), list) else []
    return bool(
        operations
        and all(
            isinstance(operation, dict)
            and bool(str(operation.get("operation_id") or "").strip())
            for operation in operations
        )
    )


def _git_summary(git_state: dict[str, Any]) -> str:
    after = git_state.get("after") if isinstance(git_state.get("after"), dict) else {}
    before = git_state.get("before") if isinstance(git_state.get("before"), dict) else {}
    branch = _short(after.get("branch") or git_state.get("branch") or before.get("branch"), "")
    changed = after.get("changed_count")
    if changed is None and isinstance(after.get("changes"), list):
        changed = len(after["changes"])
    if changed is None:
        changed = git_state.get("changed_count")
    if changed is not None:
        suffix = f" on {branch}" if branch else ""
        return f"{changed} changed path(s){suffix}"
    return _short(git_state.get("summary") or git_state.get("status"), "")


def _decision_past_tense(decision: str) -> str:
    return {
        "approve": "Approved",
        "reject": "Rejected",
        "archive": "Archived",
        "complete": "Completed",
        "keep": "Kept unchanged",
        "demote": "Demoted",
        "skip": "Skipped",
    }.get(decision, f"{decision.title()}ed")


def _confirmed_text(
    decision: str,
    payload: Any,
    *,
    selection: list[tuple[int, dict[str, Any]]] | None = None,
    proposal_ids: list[str] | None = None,
    expected_completion: dict[str, Any] | None = None,
) -> str:
    if isinstance(payload, dict) and payload.get("error"):
        return f"Review {decision} failed\n{payload['error']}"
    selection = selection or []
    proposal_ids = proposal_ids or []
    past_tense = _decision_past_tense(decision)
    if isinstance(payload, dict):
        status = _short(payload.get("status") or payload.get("state"), "")
        reason = _short(payload.get("reason") or payload.get("message"), "")
        if status.lower() in {"queued", "pending", "proposal_queued"}:
            lines = [
                f"Review {decision.title()} Queued",
                f"Queued {len(proposal_ids) or len(selection)} proposal decision(s); no application is claimed.",
            ]
            lines.extend(_receipt_lines(payload))
            lines.append("Publication: separate and not implied by queueing.")
            lines.append("Next: /kb review")
            return "\n".join(lines)
        if payload.get("ok") is False or status.lower() in {
            "blocked",
            "error",
            "failed",
            "operator_blocked",
            "preview_lease_expired",
            "preview_lease_missing",
            "preview_lease_stale",
            "stale_preview_lease",
            "validation_failed",
        }:
            lines = [
                f"Review {decision.title()} Blocked",
                f"Status: {status or 'blocked'} · ok: {_short(payload.get('ok'))}",
            ]
            if reason:
                lines.append("Reason: " + _clip(reason, 220))
            lines.extend(_receipt_lines(payload))
            lines.append("Next: /kb review")
            return "\n".join(lines)
        completion = (
            _request_bound_review_completion(payload, expected_completion)
            if isinstance(expected_completion, dict)
            else {"complete": False, "reason": "generated_completion_contract_missing"}
        )
        if not completion["complete"]:
            lines = [
                f"Review {decision.title()} Confirmation Received",
                "Durable outcome: unverified; no durable completion is claimed.",
                f"Readback: {completion['reason']}",
            ]
            if reason:
                lines.append("Engine message: " + _clip(reason, 220))
            lines.extend(_receipt_lines(payload))
            lines.append("Publication: separate and not implied by confirmation.")
            lines.append("Next: retry or inspect /kb review")
            return "\n".join(lines)
        publication = payload.get("publication") if isinstance(payload.get("publication"), dict) else {}
        git_state = payload.get("git") if isinstance(payload.get("git"), dict) else {}
        lines = [
            f"Review {decision.title()} Applied",
            f"{past_tense} {len(proposal_ids) or len(selection)} proposal(s).",
        ]
        if selection:
            lines.append("")
            lines.append("Changed:")
            lines.extend(_selection_lines(selection))
        if proposal_ids:
            lines.append("")
            lines.append(f"Proposal ids: {', '.join(proposal_ids[:8])}")
        lines.extend(
            [
                f"Status: {_short(payload.get('status'))} · ok: {_short(payload.get('ok'))}",
            ]
        )
        lines.extend(_receipt_lines(payload))
        if publication:
            lines.append(
                "Publication: "
                + _short(publication.get("status") or publication.get("state") or publication.get("reason"))
            )
        if git_state:
            git_summary = _git_summary(git_state)
            if git_summary:
                lines.append("Git: " + git_summary)
        lines.append("Next: /kb review")
        return "\n".join(lines)
    lines = [
        f"Review {decision.title()} Confirmation Unknown",
        "No structured durable readback was returned; no application is claimed.",
    ]
    if selection:
        lines.extend(["", "Changed:", *_selection_lines(selection)])
    lines.append("Next: /kb review")
    return "\n".join(lines)


def _queue_reply_choices_from_text(text: str) -> list[str]:
    lowered = str(text or "").lower()
    lowered = re.sub(r"\bdetails\b", "detail", lowered)
    ordered = ["complete", "keep", "demote", "archive", "reject", "approve", "detail", "skip"]
    return [decision for decision in ordered if re.search(rf"\b{re.escape(decision)}\b", lowered)]


def _infer_iterative_queue_title(body: str) -> str:
    lines = body.splitlines()
    last_proposal_line = -1
    for idx, line in enumerate(lines):
        if re.search(r"(?i)\bproposal ids?\b", line) and re.search(r"\bact_[A-Za-z0-9]+\b", line):
            last_proposal_line = idx
    search_lines = lines[:last_proposal_line] if last_proposal_line >= 0 else lines
    skip_prefixes = (
        "next item",
        "proposal",
        "todo",
        "summary",
        "created",
        "reply",
        "applied",
        "archived proposal",
        "proposal ids",
        "options",
    )
    for raw_line in reversed(search_lines):
        line = raw_line.strip()
        if not line:
            continue
        line = re.sub(r"^\s*#+\s*", "", line).strip()
        line = re.sub(r"^\s*\d+[\).]\s*", "", line).strip()
        proposal_title_match = re.match(r"(?i)^proposal\s+\d+\s*[—:-]\s*(.+)$", line)
        if proposal_title_match:
            return proposal_title_match.group(1).strip("`*_ ")
        if line.startswith("-"):
            continue
        if line.lower().startswith(skip_prefixes):
            continue
        return line.strip("`*_ ")
    return ""


def _parse_iterative_queue_reply_state(response_text: str) -> dict[str, Any] | None:
    text = str(response_text or "")
    reply_matches = list(
        re.finditer(
            r"(?im)^\s*(?:Reply(?:\s+with)?|Options(?:\s+presented)?)\s*:\s*(.+)$",
            text,
        )
    )
    if not reply_matches:
        return None
    reply_match = reply_matches[-1]
    choices = _queue_reply_choices_from_text(reply_match.group(1))
    if not choices:
        return None
    body = text[: reply_match.start()].rstrip()
    proposal_ids: list[str] = []
    for line in body.splitlines():
        if re.search(r"(?i)\bproposal ids?\b", line):
            ids = re.findall(r"\bact_[A-Za-z0-9]+\b", line)
            if ids:
                proposal_ids = ids
    if not proposal_ids:
        all_ids = re.findall(r"\bact_[A-Za-z0-9]+\b", body)
        proposal_ids = all_ids[-1:] if all_ids else []
    if not proposal_ids:
        return None
    title = _infer_iterative_queue_title(body)
    return {
        "schema_version": 1,
        "proposal_ids": proposal_ids,
        "title": title,
        "choices": choices,
        "recorded_at": time.time(),
    }


def _record_iterative_queue_reply_state(session_id: str, response_text: str) -> dict[str, Any] | None:
    if not session_id:
        return None
    parsed = _parse_iterative_queue_reply_state(response_text)
    states = _load_queue_reply_states()
    if not parsed:
        if session_id in states:
            states.pop(session_id, None)
            _save_queue_reply_states(states)
        return None
    states[session_id] = parsed
    _save_queue_reply_states(states)
    return parsed


def _get_iterative_queue_reply_state(session_id: str) -> dict[str, Any] | None:
    if not session_id:
        return None
    states = _load_queue_reply_states()
    state = states.get(session_id)
    if not isinstance(state, dict):
        return None
    recorded_at = float(state.get("recorded_at") or 0.0)
    if recorded_at and time.time() - recorded_at > QUEUE_REPLY_STATE_TTL_SECONDS:
        states.pop(session_id, None)
        _save_queue_reply_states(states)
        return None
    proposal_ids = [str(item) for item in (state.get("proposal_ids") or []) if str(item).strip()]
    if not proposal_ids:
        return None
    state["proposal_ids"] = proposal_ids
    return state


def _bare_queue_reply_decision(text: str) -> str:
    lowered = str(text or "").strip().lower()
    lowered = {"details": "detail", "show": "detail"}.get(lowered, lowered)
    return lowered if lowered in QUEUE_REPLY_DECISIONS else ""


def _visible_scope_all_decision(text: str) -> str:
    lowered = str(text or "").strip().lower()
    match = re.match(r"^(approve|reject|archive|skip)\b", lowered)
    if not match:
        return ""
    rest = lowered[match.end() :].strip()
    if not rest:
        return ""
    if re.search(r"\b(all|these|shown|visible|listed|everything)\b", rest):
        return match.group(1)
    if re.search(r"\b(?:the\s+)?(?:\d+|five)\b.*\b(showed|shown|presented|listed|visible|items?|proposals?)\b", rest):
        return match.group(1)
    return ""


def scoped_mcp_tool_allowlist_for_message(
    *,
    session_id: str,
    message: str,
    target: str | None = None,
) -> set[str]:
    """Return exact MCP tools allowed by a matched pending queue action.

    This is the stateful bridge between Telegram action cards and the generic
    MCP posture filter.  A bare reply such as ``Reject`` should stay preview
    only.  Confirmed queue tools are reserved for explicit confirm commands or
    action-card confirmation gestures.
    """
    decision = _bare_queue_reply_decision(message)
    if decision not in QUEUE_REPLY_TOOL_DECISIONS:
        decision = _visible_scope_all_decision(message)
        if decision not in QUEUE_REPLY_TOOL_DECISIONS:
            return set()
        if not _get_visible_queue_scope(session_id):
            return set()
    else:
        state = _get_iterative_queue_reply_state(session_id)
        if not state:
            return set()
        choices = {str(choice).strip().lower() for choice in (state.get("choices") or []) if str(choice).strip()}
        if choices and decision not in choices:
            return set()
    mcp_target = target or _mcp_target()
    tool = _descriptor_tool_name(mcp_target, "review.decision_preview")
    return {tool} if tool else set()


def _session_id_for_queue_reply_state(session_store: Any, source: Any) -> str:
    if session_store is None:
        return ""
    try:
        session_store._ensure_loaded()
    except Exception:
        pass
    try:
        session_key = session_store._generate_session_key(source)
        entry = getattr(session_store, "_entries", {}).get(session_key)
        return str(getattr(entry, "session_id", "") or "")
    except Exception:
        logger.debug("kb_journeys: failed to resolve gateway session id", exc_info=True)
        return ""


def _conversation_state_id(session_store: Any, source: Any) -> str:
    session_id = _session_id_for_queue_reply_state(session_store, source)
    if session_id:
        return session_id
    parts = [
        _platform_name(getattr(source, "platform", None)),
        _short(getattr(source, "chat_id", ""), ""),
        _short(getattr(source, "thread_id", ""), ""),
        _short(getattr(source, "user_id", ""), ""),
    ]
    return ":".join(part for part in parts if part)


def _get_meeting_handoff_state(session_id: str) -> dict[str, Any] | None:
    if not session_id:
        return None
    states = _load_meeting_handoff_states()
    state = states.get(session_id)
    if not isinstance(state, dict):
        return None
    recorded_at = float(state.get("recorded_at") or 0.0)
    if recorded_at and time.time() - recorded_at > MEETING_HANDOFF_STATE_TTL_SECONDS:
        states.pop(session_id, None)
        _save_meeting_handoff_states(states)
        return None
    plan = state.get("plan")
    if not isinstance(plan, dict):
        return None
    return state


def _telegram_user_id(source: Any) -> str:
    return _short(getattr(source, "user_id", ""), "")


def _sync_preview_lease(plan: dict[str, Any], *, recorded_at: float | None = None) -> dict[str, Any]:
    preview_lease = plan.get("preview_lease") if isinstance(plan.get("preview_lease"), dict) else {}
    if preview_lease:
        return dict(preview_lease)
    workflow = plan.get("workflow") if isinstance(plan.get("workflow"), dict) else {}
    payload = {
        "workflow_id": str(workflow.get("workflow_id") or ""),
        "request_id": str(plan.get("request_id") or ""),
        "idempotency_key": str(plan.get("idempotency_key") or ""),
        "recorded_at": int(recorded_at or time.time()),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "kind": "telegram_workflow_preview",
        "preview_lease_id": f"sha256:{digest}",
        **{key: value for key, value in payload.items() if value},
    }


def _get_sync_run_state(session_id: str, source: Any) -> tuple[dict[str, Any] | None, str]:
    """Return the conversation-bound canonical sync run, if still current."""
    if not session_id:
        return None, "missing_session"
    states = _load_sync_preview_states()
    state = states.get(session_id)
    if not isinstance(state, dict) or state.get("kind") != "kb_sync_run_state":
        return None, "missing"
    recorded_at = float(state.get("recorded_at") or 0.0)
    if not recorded_at or time.time() - recorded_at > SYNC_RUN_STATE_TTL_SECONDS:
        states.pop(session_id, None)
        _save_sync_preview_states(states)
        return None, "stale"
    actor_id = _short(state.get("actor_id"), "")
    current_actor = _telegram_user_id(source)
    if actor_id and current_actor and actor_id != current_actor:
        return None, "wrong_actor"
    if not _short(state.get("run_id"), ""):
        return None, "invalid"
    return state, ""


def _store_sync_run_state(
    session_id: str,
    *,
    source: Any,
    target: str,
    packet: dict[str, Any],
) -> None:
    if not session_id or not _short(packet.get("run_id"), ""):
        return
    states = _load_sync_preview_states()
    states[session_id] = {
        "schema_version": 2,
        "kind": "kb_sync_run_state",
        "recorded_at": time.time(),
        "actor_id": _telegram_user_id(source),
        "target": target,
        "run_id": _short(packet.get("run_id"), ""),
        "status": _short(packet.get("status"), ""),
        "confirmation": dict(packet.get("confirmation") or {}),
    }
    _save_sync_preview_states(states)


def _store_meeting_handoff_state(
    session_id: str,
    *,
    plan: dict[str, Any],
    meeting_file: str,
    notes_text: str,
) -> None:
    if not session_id:
        return
    states = _load_meeting_handoff_states()
    states[session_id] = {
        "schema_version": 1,
        "recorded_at": time.time(),
        "meeting_file": _short(meeting_file, ""),
        "notes_sha256": "sha256:" + hashlib.sha256(str(notes_text or "").encode("utf-8")).hexdigest(),
        "notes_chars": len(str(notes_text or "")),
        "plan": plan,
    }
    _save_meeting_handoff_states(states)


def _queue_count(data: Any) -> int | None:
    if not isinstance(data, dict):
        return None
    counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    for value in (counts.get("proposals"), data.get("total"), data.get("count"), _count_from(data, "queue", "proposals")):
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
    return None


def _iterative_state_from_item(item: dict[str, Any]) -> dict[str, Any] | None:
    proposal_ids = _proposal_ids_for_item(item)
    if not proposal_ids:
        return None
    decisions = [decision for decision, _ in _queue_action_decisions(item)]
    for fallback in ("detail", "skip"):
        if fallback not in decisions:
            decisions.append(fallback)
    return {
        "schema_version": 1,
        "proposal_ids": proposal_ids,
        "title": _item_title(item),
        "choices": decisions,
        "recorded_at": time.time(),
    }


def _store_iterative_state_from_item(session_id: str, item: dict[str, Any] | None) -> None:
    if not session_id:
        return
    if not isinstance(item, dict):
        _clear_iterative_queue_reply_state(session_id)
        return
    state = _iterative_state_from_item(item)
    if not state:
        _clear_iterative_queue_reply_state(session_id)
        return
    states = _load_queue_reply_states()
    states[session_id] = state
    _save_queue_reply_states(states)


def _iterative_queue_next_text(data: Any, *, session_id: str = "") -> str:
    items = _queue_items_from_payload(data)
    if not items:
        if session_id:
            _clear_iterative_queue_reply_state(session_id)
        return "Review is empty."
    item = items[0] if isinstance(items[0], dict) else {}
    if not item:
        return "Next review item could not be rendered. Use /kb review to refresh."
    _store_iterative_state_from_item(session_id, item)
    count = _queue_count(data)
    proposal_ids = _proposal_ids_for_item(item)
    decisions = [decision for decision, _ in _queue_action_decisions(item)]
    for fallback in ("detail", "skip"):
        if fallback not in decisions:
            decisions.append(fallback)
    lines: list[str] = []
    if count is not None:
        lines.append(f"Review now has {count} proposal(s).")
        lines.append("")
    lines.extend(["Next item:", "", _item_title(item)])
    detail = _item_detail(item)
    if detail:
        lines.append("- Summary: " + _clip(detail, 240))
    target = _item_target(item)
    if target:
        lines.append("- Target: " + target)
    if proposal_ids:
        label = "Proposal ids" if len(proposal_ids) != 1 else "Proposal id"
        lines.append(f"- {label}: {', '.join(proposal_ids[:8])}")
    lines.append("")
    lines.append("Reply: " + ", ".join(decisions) + ".")
    return "\n".join(lines)


def _iterative_selection_from_state(state: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    return [
        (
            1,
            {
                "title": _short(state.get("title"), "Current review item"),
                "raw": {"proposal_ids": list(state.get("proposal_ids") or [])},
            },
        )
    ]


def _render_iterative_queue_reply_decision(
    ctx: Any,
    target: str,
    *,
    session_id: str,
    state: dict[str, Any],
    decision: str,
) -> dict[str, Any]:
    proposal_ids = [str(item) for item in (state.get("proposal_ids") or []) if str(item).strip()]
    title = _short(state.get("title"), "current review item")
    selection = _iterative_selection_from_state(state)
    if decision == "detail":
        lines = [
            "Review Item",
            f"Title: {title}",
            f"Proposal ids: {', '.join(proposal_ids)}",
            "Reply: " + ", ".join(state.get("choices") or sorted(QUEUE_REPLY_DECISIONS)) + ".",
        ]
        return {"title": "KB Review", "text": "\n".join(lines), "actions": []}
    if decision not in QUEUE_REPLY_TOOL_DECISIONS:
        return {"title": "KB Review", "text": "That review reply is not supported. Use /kb review to refresh.", "actions": []}
    actor = "telegram:operator"
    source = "Hermes Telegram iterative queue"
    preview_tool = _descriptor_tool_name(target, "review.decision_preview")
    if not preview_tool:
        return _capability_unavailable("KB Review", ("review.decision_preview",))
    preview_payload = _dispatch_registry_tool(
        ctx,
        target,
        preview_tool,
        {
                "proposal_ids": proposal_ids,
                "decision": decision,
                "actor": actor,
                "source": source,
                "note": f"Previewed from Telegram iterative review reply for {title}",
        },
    )
    text = _preview_text(decision, proposal_ids, preview_payload, selection=selection)
    if _preview_allows_confirmation(
        preview_payload,
        capability=_capability_for_registry_name(target, preview_tool),
    ):
        text += f"\nTo apply: /kb review {decision} 1 confirm"
    return {"title": "KB Review", "text": text, "actions": []}


def _render_visible_scope_all_decision(
    ctx: Any,
    target: str,
    *,
    session_id: str,
    decision: str,
) -> dict[str, Any]:
    visible_record = _get_visible_queue_scope_record(session_id)
    selection = _queue_selection_from_snapshot(visible_record.get("selection")) if visible_record else []
    if not selection:
        return {
            "title": "KB Review",
            "text": (
                "KB Review\n"
                f"I can only {decision} all against the proposals currently shown in this Telegram thread. "
                "Run /kb review first, then ask again."
            ),
            "actions": [],
        }
    proposal_ids = _proposal_ids_for_selection(selection)
    if not proposal_ids:
        return {"title": "KB Review", "text": "KB Review\nThe visible review window did not include proposal ids.", "actions": []}
    actor = "telegram:operator"
    source = "Hermes Telegram visible queue"
    preview_tool = _descriptor_tool_name(target, "review.decision_preview")
    if not preview_tool:
        return _capability_unavailable("KB Review", ("review.decision_preview",))
    candidate_count = _queue_count_value(visible_record.get("candidate_count"), len(selection))
    displayed_count = _queue_count_value(visible_record.get("displayed_count"), len(selection))
    preview_payload = _dispatch_registry_tool(
        ctx,
        target,
        preview_tool,
        {
                "proposal_ids": proposal_ids,
                "decision": decision,
                "decision_scope": "all_viewed",
                "candidate_count": candidate_count,
                "displayed_count": displayed_count,
                "actor": actor,
                "source": source,
                "note": f"Previewed from Telegram visible queue scope for {len(selection)} shown item(s)",
        },
    )
    text = _preview_text(decision, proposal_ids, preview_payload, selection=selection)
    text += "\nScope: visible Telegram review window only, not the full pending review inbox."
    if _preview_allows_confirmation(
        preview_payload,
        capability=_capability_for_registry_name(target, preview_tool),
    ):
        indices = [index for index, _ in selection]
        _store_queue_text_preview_scope(
            session_id,
            decision=decision,
            indices=indices,
            selection=selection,
            preview_payload=preview_payload,
        )
        text += f"\nTo apply: /kb review {decision} {_format_indices(indices)} confirm"
    return {"title": "KB Review", "text": text, "actions": []}


def _queue_summary_payload(
    ctx: Any,
    target: str,
    *,
    scope: str = "proposals",
    limit: int = 5,
    offset: int = 0,
    selected_id: str = "",
) -> tuple[Any | None, list[str]]:
    args = {"scope": _queue_requested_scope(scope), "limit": limit}
    if offset:
        args["offset"] = int(offset)
    if selected_id:
        args["selected_id"] = selected_id
    _, data, errors = _dispatch_first(
        ctx,
        target,
        [("review.inbox", dict(args))],
    )
    return data, errors


def _queue_requested_scope(value: str | None) -> str:
    scope = str(value or "").strip().lower()
    aliases = {
        "task": "tasks",
        "tasks": "tasks",
        "todo": "tasks",
        "todos": "tasks",
        "stale": "stale",
        "delegated": "delegated",
        "done": "done",
        "proposal": "proposals",
        "proposals": "proposals",
        "queue": "proposals",
        "review": "proposals",
    }
    return aliases.get(scope, "proposals")


def _queue_scope_and_args(args: str) -> tuple[str, str]:
    text = (args or "").strip()
    if not text:
        return "proposals", ""
    head, _, tail = text.partition(" ")
    scope = _queue_requested_scope(head)
    if scope != "proposals" or head.strip().lower() in {"proposal", "proposals"}:
        return scope, tail.strip()
    return "proposals", text


def _queue_payload_scope(data: Any) -> str:
    if not isinstance(data, dict):
        return "proposals"
    return _queue_requested_scope(data.get("scope") or data.get("queue_scope"))


def _changed_paths(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    paths = payload.get("changed_paths")
    if paths is None:
        paths = _get_path(payload, "publication", "changed_paths")
    if isinstance(paths, str):
        return [paths]
    if isinstance(paths, list):
        return [str(path).strip() for path in paths if str(path).strip()]
    return []


def _format_changed_paths(paths: list[str], *, limit: int = 10) -> list[str]:
    if not paths:
        return []
    lines = [f"- {path}" for path in paths[:limit]]
    remaining = len(paths) - limit
    if remaining > 0:
        lines.append(f"- ... {remaining} more")
    return lines


def _publication_preview_binding(data: dict[str, Any]) -> dict[str, Any]:
    git_state = data.get("git") if isinstance(data.get("git"), dict) else {}
    return {
        "message": str(data.get("message") or ""),
        "git_head": str(git_state.get("head") or ""),
        "changed_paths": _changed_paths(data),
        "change_set_digest": str(data.get("change_set_digest") or ""),
        "status": str(data.get("status") or ""),
    }


def _store_publication_preview_state(
    session_id: str,
    *,
    source: Any,
    target: str,
    binding: dict[str, Any],
) -> bool:
    if not session_id:
        return False
    states = _load_publication_preview_states()
    states[session_id] = {
        "schema_version": 1,
        "recorded_at": time.time(),
        "actor_id": _short(getattr(source, "user_id", ""), ""),
        "target": target,
        "binding": binding,
    }
    _save_publication_preview_states(states)
    return True


def _get_publication_preview_state(
    session_id: str, *, source: Any, target: str
) -> tuple[dict[str, Any] | None, str]:
    if not session_id:
        return None, "missing_session"
    state = _load_publication_preview_states().get(session_id)
    if not isinstance(state, dict):
        return None, "missing"
    recorded_at = float(state.get("recorded_at") or 0.0)
    if not recorded_at or time.time() - recorded_at > PUBLICATION_PREVIEW_STATE_TTL_SECONDS:
        _clear_publication_preview_state(session_id)
        return None, "stale"
    actor_id = _short(state.get("actor_id"), "")
    current_actor = _short(getattr(source, "user_id", ""), "")
    if actor_id and current_actor and actor_id != current_actor:
        return None, "wrong_actor"
    if state.get("target") != target or not isinstance(state.get("binding"), dict):
        return None, "invalid"
    return state, ""


def _publication_message(args: str) -> tuple[bool, str]:
    text = str(args or "").strip()
    head, _, tail = text.partition(" ")
    confirm = head.lower() in {"confirm", "confirmed", "yes"}
    message = tail.strip() if confirm else text
    return confirm, message or "kb: publish reviewed knowledge changes"


def _render_publication_result(data: dict[str, Any], *, changed_count: int) -> dict[str, Any]:
    publication = data.get("publication") if isinstance(data.get("publication"), dict) else {}
    git_state = publication.get("git") if isinstance(publication.get("git"), dict) else {}
    pushed = publication.get("pushed") is True
    clean = git_state.get("clean") is True
    ahead = int(git_state.get("ahead") or 0)
    if data.get("ok") is True and pushed and clean and ahead == 0:
        commit = _short(publication.get("commit") or git_state.get("head"), "")[:8]
        detail = f" Commit {commit}." if commit else ""
        return {
            "title": "Publication",
            "status": "published",
            "text": (
                f"*Publication*\nPublished {changed_count} reviewed paths.{detail}\n"
                "Git readback is clean and current."
            ),
            "actions": [],
        }
    return {
        "title": "Publication",
        "status": "blocked",
        "text": (
            "*Publication*\nPublication did not complete.\n"
            "No success is claimed; run /kb publish for a fresh exact preview."
        ),
        "actions": [],
    }


def _render_publish_command(
    ctx: Any,
    target: str,
    args: str,
    *,
    session_id: str = "",
    source: Any = None,
) -> dict[str, Any]:
    """Preview and confirm one exact ad hoc publication through kb-engine."""
    required = ("publication.preview_commit", "publication.commit_confirmed")
    if any(_descriptor(name) is None for name in required):
        return _capability_unavailable("Publication", required)

    confirm, message = _publication_message(args)
    state = None
    if confirm:
        state, reason = _get_publication_preview_state(
            session_id, source=source, target=target
        )
        if state is None:
            return {
                "title": "Publication",
                "status": "preview_required",
                "text": (
                    "*Publication*\nNo current exact preview is bound to this conversation.\n"
                    "Run /kb publish, review the count, then confirm."
                ),
                "actions": [],
                "reason": reason,
            }
        message = str(state["binding"].get("message") or message)

    _tool, preview, errors = _dispatch_first(
        ctx, target, [("publication.preview_commit", {"message": message})]
    )
    if not isinstance(preview, dict):
        return _render_error("Publication", target, errors)
    binding = _publication_preview_binding(preview)
    git_state = preview.get("git") if isinstance(preview.get("git"), dict) else {}
    changed_count = int(git_state.get("changed_count") or len(binding["changed_paths"]))
    preview_status = str(preview.get("status") or "")

    if confirm:
        if binding != state["binding"]:
            _clear_publication_preview_state(session_id)
            return {
                "title": "Publication",
                "status": "preview_stale",
                "text": (
                    "*Publication*\nThe publication set changed since the preview.\n"
                    "Nothing was published. Run /kb publish and review the fresh count."
                ),
                "actions": [],
            }
        actor_id = _short(getattr(source, "user_id", ""), "operator")
        _confirmed_tool, confirmed, confirm_errors = _dispatch_first(
            ctx,
            target,
            [
                (
                    "publication.commit_confirmed",
                    {
                        "message": binding["message"],
                        "expected_git_head": binding["git_head"],
                        "expected_changed_paths": binding["changed_paths"],
                        "expected_change_set_digest": binding["change_set_digest"],
                        "push": True,
                        "actor": f"telegram:{actor_id}",
                        "source": "Hermes Telegram",
                        "session_id": session_id,
                        "user_confirmation": {
                            "confirmed": True,
                            "confirmed_by": actor_id,
                            "confirmation_text": "/kb publish confirm",
                            "preview_status": binding["status"],
                        },
                    },
                )
            ],
        )
        _clear_publication_preview_state(session_id)
        if not isinstance(confirmed, dict):
            return _render_error("Publication", target, confirm_errors)
        return _render_publication_result(confirmed, changed_count=changed_count)

    if preview.get("ok") is not True or preview_status == "blocked":
        _clear_publication_preview_state(session_id)
        return {
            "title": "Publication",
            "status": "blocked",
            "text": (
                "*Publication*\nPublication preflight is blocked.\n"
                "No publication was attempted; resolve the reported workspace issue first."
            ),
            "actions": [],
        }
    if preview_status == "noop":
        _clear_publication_preview_state(session_id)
        return {
            "title": "Publication",
            "status": "published",
            "text": "*Publication*\nThe reviewed KB is already published.\nNo action is needed.",
            "actions": [],
        }
    if preview_status not in {"ready", "push_pending"}:
        return _render_error("Publication", target, [f"unexpected preview status: {preview_status}"])
    if not _store_publication_preview_state(
        session_id, source=source, target=target, binding=binding
    ):
        return _render_error("Publication", target, ["conversation binding unavailable"])
    consequence = (
        f"{changed_count} reviewed paths are ready to commit and push."
        if preview_status == "ready"
        else "The reviewed commit is ready to push; no second commit will be created."
    )
    return {
        "title": "Publication",
        "status": "ready_to_confirm",
        "text": (
            f"*Publication*\n{consequence}\nPreflight passed. No publication was attempted.\n"
            "Reply /kb publish confirm to publish this exact set."
        ),
        "actions": [],
    }


def _queue_items_from_payload(data: Any) -> list[Any]:
    return _items(data, ("items",), ("proposals",), ("queue", "items"))


def _queue_item_at(data: Any, index: int) -> dict[str, Any] | None:
    if index < 1:
        return None
    items = _queue_items_from_payload(data)
    if index > len(items):
        return None
    item = items[index - 1]
    return item if isinstance(item, dict) else None


def _parse_queue_indices(tokens: list[str]) -> list[int]:
    text = " ".join(tokens)
    indices: list[int] = []
    seen: set[int] = set()
    for match in re.finditer(r"\d+\s*-\s*\d+|\d+", text):
        token = match.group(0).strip()
        if re.fullmatch(r"\d+\s*-\s*\d+", token):
            start_text, end_text = re.split(r"\s*-\s*", token, maxsplit=1)
            start, end = int(start_text), int(end_text)
            step = 1 if end >= start else -1
            candidates = range(start, end + step, step)
        else:
            candidates = [int(token)]
        for index in candidates:
            if index > 0 and index not in seen:
                seen.add(index)
                indices.append(index)
    return indices


def _queue_items_at(data: Any, indices: list[int]) -> tuple[list[tuple[int, dict[str, Any]]], list[int]]:
    selection: list[tuple[int, dict[str, Any]]] = []
    missing: list[int] = []
    for index in indices:
        item = _queue_item_at(data, index)
        if item is None:
            missing.append(index)
        else:
            selection.append((index, item))
    return selection, missing


def _parse_queue_command_args(args: str, *, command: str) -> tuple[str, list[int], str | None, bool]:
    text = (args or "").strip()
    if not text:
        return "dashboard", [], None, False
    parts = text.split()
    first = parts[0].lower()
    if command == "kbreview":
        if first in {"review", "show", "detail", "details"}:
            indices = _parse_queue_indices(parts[1:])
        else:
            indices = _parse_queue_indices(parts)
        return ("review", indices[:1], None, False) if indices else ("help", [], None, False)
    if first.isdigit():
        return "review", [int(first)], None, False
    if first in {"review", "show", "detail", "details"}:
        indices = _parse_queue_indices(parts[1:])
        return ("review", indices[:1], None, False) if indices else ("help", [], None, False)
    if first in {"approve", "reject", "archive", "skip", "complete", "keep", "demote"}:
        confirm = any(part.lower() in {"confirm", "confirmed", "apply"} for part in parts[1:])
        index_tokens = [part for part in parts[1:] if part.lower() not in {"confirm", "confirmed", "apply"}]
        indices = _parse_queue_indices(index_tokens)
        return ("decision", indices, first, confirm) if indices else ("help", [], None, False)
    return "help", [], None, False


def _queue_command_help() -> dict[str, Any]:
    return {
        "title": "KB Review",
        "text": "\n".join(
            [
                "KB Review",
                "Use /kb review to list proposals.",
                "Use /kb review 1 to inspect one item.",
                "Use /kb review reject 1 to preview a decision.",
                "Use /kb review complete 1 for a TODO-backed proposal.",
                "Confirm from the Telegram preview button when available.",
                "Text fallback: /kb review reject 1 confirm only after that exact Telegram preview.",
                "Reply Reject all to preview only the review items currently shown in Telegram.",
            ]
        ),
        "actions": [],
    }


def _render_queue_item(data: Any, *, index: int, ctx: Any, target: str) -> dict[str, Any]:
    item = _queue_item_at(data, index)
    if item is None:
        total = len(_queue_items_from_payload(data))
        return {
            "title": "KB Review",
            "text": f"KB Review\nNo item {index} in the current review window ({total} shown). Use /kb review to refresh.",
            "actions": [],
        }
    return {
        "title": "KB Review",
        "text": _queue_item_text(item, index=index),
        "actions": _queue_descriptor_actions(
            ctx,
            target,
            item,
            index=index,
            preview_label_prefix=False,
            limit=6,
        )
        or _queue_control_actions(ctx, target, item, limit=6),
    }


def _render_queue_skip(
    data: Any,
    *,
    index: int,
    ctx: Any,
    target: str,
    session_id: str = "",
) -> dict[str, Any]:
    current_item = _queue_item_at(data, index)
    offset = _queue_offset(data)
    scope = _queue_payload_scope(data)
    server_data = None
    if ctx is not None and target:
        server_data, _errors = _queue_summary_payload(
            ctx,
            target,
            scope=scope,
            limit=5,
            offset=offset + index,
        )
    if server_data is not None:
        server_item = _queue_item_at(server_data, 1)
        current_ids = _proposal_ids_for_item(current_item) if isinstance(current_item, dict) else []
        server_ids = _proposal_ids_for_item(server_item) if isinstance(server_item, dict) else []
        if server_item is not None and (not current_ids or server_ids != current_ids):
            _store_iterative_state_from_item(session_id, server_item)
            card = _render_queue_item(server_data, index=1, ctx=ctx, target=target)
            card["text"] = (
                f"Skipped item {offset + index} locally. No KB state changed.\n"
                "Advanced to the next kb-engine review window.\n\n"
                + card["text"]
            )
            return card

    next_index = index + 1
    next_item = _queue_item_at(data, next_index)
    if next_item is None:
        if session_id:
            _clear_iterative_queue_reply_state(session_id)
        return {
            "title": "KB Review",
            "text": "KB Review\nNo more items are visible in this Telegram window. Refresh with /kb review.",
            "actions": [],
        }
    _store_iterative_state_from_item(session_id, next_item)
    card = _render_queue_item(data, index=next_index, ctx=ctx, target=target)
    card["text"] = f"Skipped item {index} locally. No KB state changed.\n\n{card['text']}"
    return card


def _queue_guided_actions(
    ctx: Any | None,
    target: str | None,
    data: Any,
    *,
    session_id: str = "",
) -> list[Any]:
    if ctx is None or not target:
        return []
    item = _queue_item_at(data, 1)
    if item is None:
        return []
    descriptor_actions = _queue_descriptor_actions(
        ctx,
        target,
        item,
        index=1,
        preview_label_prefix=False,
        limit=None,
    )
    guidance_actions = [action for action in descriptor_actions if getattr(action, "label", "") == "Ask LLM"]
    decision_actions = [action for action in descriptor_actions if getattr(action, "label", "") != "Ask LLM"]
    if not decision_actions:
        decision_actions = _queue_control_actions(ctx, target, item, limit=None)
    if not guidance_actions and _review_target_payload(item):
        guidance_actions = [
            KbAction(
                label="Ask LLM",
                action_id="review_target.guidance",
                handler=lambda callback_ctx: _render_review_target_guidance(item),
                metadata={
                    "target_kind": _item_kind(item) or "review_target",
                    "target_ref": _item_target(item),
                    "advisory_only": True,
                },
            )
        ]
    detail_action = KbAction(
        label="Details",
        action_id="queue.details",
        handler=lambda callback_ctx: _render_queue_item(data, index=1, ctx=ctx, target=target),
        metadata={
            "target_kind": "proposal_queue",
            "target_ref": _item_target(item),
            "review_index": 1,
        },
    )
    actions: list[Any] = [*decision_actions, detail_action, *guidance_actions]
    if _queue_item_at(data, 2) is not None:
        actions.append(
            KbAction(
                label="Skip",
                action_id="queue.skip",
                handler=lambda callback_ctx: _render_queue_skip(
                    data,
                    index=1,
                    ctx=ctx,
                    target=target,
                    session_id=session_id,
                ),
                metadata={
                    "target_kind": "proposal_queue",
                    "target_ref": _item_target(item),
                    "review_index": 1,
                    "mutates_state": False,
                },
            )
        )
    return actions[:6]


def _render_queue_text_decision(
    ctx: Any,
    target: str,
    data: Any,
    *,
    indices: list[int],
    decision: str,
    confirm: bool,
    session_id: str = "",
    callback_ctx: Any | None = None,
) -> dict[str, Any]:
    preview_metadata: dict[str, Any] = {}
    if confirm:
        selection, preview_metadata = _get_queue_text_preview_scope(session_id, decision=decision, indices=indices)
        missing: list[int] = []
        if not selection:
            return {
                "title": "KB Review",
                "text": (
                    "KB Review\n"
                    "That confirmation is not tied to a current Telegram preview. "
                    "Preview the exact item(s) again, then confirm from that preview."
                ),
                "actions": [],
            }
    else:
        selection, missing = _queue_items_at(data, indices)
        if not selection:
            total = len(_queue_items_from_payload(data))
            return {
                "title": "KB Review",
                "text": f"KB Review\nNo selected items in the current review window ({total} shown). Use /kb review to refresh.",
                "actions": [],
            }
        if missing:
            # Partial selections can be previewed, but the stored confirmation
            # lease only covers the concrete items that were actually shown.
            pass
    proposal_ids = _proposal_ids_for_selection(selection)
    if not proposal_ids:
        return {"title": "KB Review", "text": "No proposal ids were available for the selected review item(s).", "actions": []}
    selected_titles = ", ".join(_item_title(item) for _, item in selection)
    index_text = _format_indices([index for index, _ in selection])
    preview_tool = _descriptor_tool_name(target, "review.decision_preview")
    confirmed_tool = _descriptor_tool_name(target, "review.batch_decide_confirmed")
    if not preview_tool or not confirmed_tool:
        return _capability_unavailable(
            "KB Review",
            ("review.decision_preview", "review.batch_decide_confirmed"),
        )
    actor = _queue_callback_actor(callback_ctx) if callback_ctx is not None else "telegram:operator"
    source = "Hermes Telegram"
    preview_payload: Any = None
    preview_payload = _dispatch_registry_tool(
            ctx,
            target,
            preview_tool,
            {
                    "proposal_ids": proposal_ids,
                    "decision": decision,
                    "decision_scope": "explicit_ids",
                    "candidate_count": len(proposal_ids),
                    "displayed_count": len(proposal_ids),
                    "actor": actor,
                    "source": source,
                    "note": f"Previewed from Telegram /kb review text command for {selected_titles}",
            },
    )
    if confirm:
        preview_metadata = _queue_preview_metadata(preview_payload)
    if not confirm:
        text = _preview_text(decision, proposal_ids, preview_payload, selection=selection)
        if missing:
            text += "\nMissing review item(s): " + ", ".join(str(index) for index in missing)
        actions: list[Any] = []
        if _preview_allows_confirmation(
            preview_payload,
            capability=_capability_for_registry_name(target, preview_tool),
        ):
            _store_queue_text_preview_scope(
                session_id,
                decision=decision,
                indices=[index for index, _ in selection],
                selection=selection,
                preview_payload=preview_payload,
            )
            text += "\nConfirm with the button below when it matches your intent."
            text += f"\nText fallback: /kb review {decision} {index_text} confirm"
            metadata = _queue_preview_metadata(preview_payload)
            actions = [
                KbAction(
                    label=f"Confirm {decision.title()}",
                    action_id=f"queue.{decision}.confirm",
                    handler=lambda confirm_ctx: _render_queue_text_decision(
                        ctx,
                        target,
                        data,
                        indices=[index for index, _ in selection],
                        decision=decision,
                        confirm=True,
                        session_id=session_id,
                        callback_ctx=confirm_ctx,
                    ),
                    metadata={
                        "target_kind": "proposal_queue",
                        "decision": decision,
                        "preview_required": True,
                        "preview_lease": bool(metadata.get("preview_lease")),
                        "review_session_id": _review_session_id(metadata),
                    },
                )
            ]
        return {"title": "KB Review", "text": text, "actions": actions}
    if not _preview_allows_confirmation(
        preview_payload,
        capability=_capability_for_registry_name(target, preview_tool),
    ):
        return {
            "title": "KB Review",
            "text": _preview_text(decision, proposal_ids, preview_payload, selection=selection),
            "actions": [],
        }
    confirmed_args = {
        "proposal_ids": proposal_ids,
        "decision": decision,
        "actor": actor,
        "source": source,
        "session_id": _review_session_id(preview_metadata) or f"telegram-kb-text-{int(time.time())}",
        "user_confirmation": {
            "confirmed": True,
            "confirmed_at": _utc_now_text(),
            "surface": "telegram",
            "action": f"queue.{decision}",
            "preview_required": True,
            "confirmation_text": f"/kb review {decision} {index_text} confirm",
            "proposal_ids": proposal_ids,
        },
        "note": f"Confirmed from Telegram /kb review text command for {selected_titles}",
    }
    _apply_queue_preview_metadata(confirmed_args, preview_metadata)
    _apply_queue_confirmation_preview_metadata(confirmed_args["user_confirmation"], preview_metadata)
    confirmed_payload = _dispatch_registry_tool(ctx, target, confirmed_tool, confirmed_args)
    text = _confirmed_text(
        decision,
        confirmed_payload,
        selection=selection,
        proposal_ids=proposal_ids,
        expected_completion=_review_completion_expectation(
            "review.batch_decide_confirmed",
            confirmed_args,
        ),
    )
    if missing:
        text += "\nSkipped missing review item(s): " + ", ".join(str(index) for index in missing)
    return {"title": "KB Review", "text": text, "actions": []}


def _is_retired_sync_request(value: Any) -> bool:
    normalized = re.sub(r"\s+", " ", str(value or "").strip().lower())
    return normalized == "update kb" or normalized.startswith("update kb ") or normalized.split(" ", 1)[0] == "update_kb"


def _workflow_id_from_args(args: str) -> tuple[str, str]:
    text = (args or "").strip()
    lowered = text.lower()
    if not text:
        return "", ""
    if lowered in {"sync", "kb sync", "sync kb"}:
        return "sync", text
    if _is_retired_sync_request(lowered):
        return "", text
    if lowered.startswith("meeting"):
        return "meeting_process", text
    return text.split(maxsplit=1)[0], text


def _workflow_args_from_text(args: str) -> tuple[str, str, bool]:
    text = (args or "").strip()
    parts = text.split()
    confirm = bool(parts and parts[-1].lower() in {"confirm", "confirmed", "start", "apply"})
    if confirm:
        text = " ".join(parts[:-1]).strip()
    workflow_id, intent = _workflow_id_from_args(text)
    return workflow_id, intent, confirm


def _workflow_envelope(plan: dict[str, Any], callback_ctx: Any) -> dict[str, Any]:
    workflow = plan.get("workflow") if isinstance(plan.get("workflow"), dict) else {}
    request = plan.get("request") if isinstance(plan.get("request"), dict) else {}
    actor_id = _short(getattr(callback_ctx, "actor_id", ""), "unknown")
    actor_name = _short(getattr(callback_ctx, "actor_name", ""), "")
    confirmed_at = _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat()
    return {
        "schema_version": int(plan.get("schema_version") or 1),
        "tool": plan.get("tool") or (_descriptor("workflow.start_confirmed") or {}).get("name"),
        "plan": {
            "workflow_id": str(workflow.get("workflow_id") or ""),
            "args": dict(request.get("args") or {}),
            "queue_gate_limit": int(request.get("queue_gate_limit") or 0),
            "force": bool(request.get("force", False)),
            "request_id": str(plan.get("request_id") or ""),
            "idempotency_key": str(plan.get("idempotency_key") or ""),
            "preconditions": list(plan.get("preconditions") or []),
        },
        "provenance": dict(plan.get("provenance") or {}),
        "user_confirmation": {
            "confirmed": True,
            "confirmed_by": actor_name or actor_id,
            "confirmed_at": confirmed_at,
            "confirmation_text": "Confirmed by Telegram text command after workflow preview.",
            "preview_required": True,
            "preview_lease": _sync_preview_lease(plan),
            "preview_status": _short(plan.get("status")),
            "surface": "telegram",
            "actor_id": actor_id,
            "actor_name": actor_name,
        },
    }


def _workflow_start_text(
    ctx: Any,
    target: str,
    plan: dict[str, Any],
    *,
    prefix: str = "Workflow start result",
) -> str:
    start_tool = _descriptor_tool_name(target, "workflow.start_confirmed")
    if not start_tool:
        return (
            f"{prefix}\nWorkflow confirmation is temporarily unavailable because "
            "workflow.start_confirmed is not in the generated Hermes profile. No KB state changed."
        )
    callback_ctx = SimpleNamespace(
        callback_id=f"text-{int(time.time())}",
        actor_id="operator",
        actor_name="Telegram",
    )
    envelope = _workflow_envelope(plan, callback_ctx)
    payload = _dispatch_registry_tool(
        ctx,
        target,
        start_tool,
        {"envelope": envelope},
    )
    proof = _request_bound_workflow_completion(payload, envelope)
    if not proof["complete"]:
        return (
            f"{prefix}\nConfirmation received, but workflow start readback is not verified "
            f"({proof['reason']}). No workflow start is claimed."
        )
    text = _workflow_status_text(prefix, payload, include_run_details=False)
    run_id = _workflow_run_id(payload)
    if run_id:
        progress_text = _workflow_initial_progress_text(ctx, target, run_id, include_run_details=False)
        if progress_text:
            text += "\n" + progress_text
        text += "\nDetails: /kb runs"
    return text


def _meeting_handoff_args(args: str) -> dict[str, Any]:
    text = str(args or "").strip()
    if text.lower() in {"confirm", "confirmed", "start", "apply"}:
        return {"confirm_pending": True}
    if not text:
        return {"error": "meeting_file and notes are required"}
    if text.lower().startswith("process "):
        text = text.split(maxsplit=1)[1].strip()
    if " -- " in text:
        meeting_file, notes_text = text.split(" -- ", 1)
    elif "\n" in text:
        first, notes_text = text.split("\n", 1)
        meeting_file = first
    else:
        return {"error": "separate the meeting file from notes with --"}
    meeting_file = _strip_wrapping_quotes(meeting_file.strip())
    notes_text = notes_text.strip()
    if not meeting_file:
        return {"error": "meeting_file is required"}
    if not notes_text:
        return {"error": "notes are required"}
    return {
        "confirm_pending": False,
        "meeting_file": meeting_file,
        "notes_text": notes_text,
    }


def _strip_wrapping_quotes(value: str) -> str:
    text = str(value or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1].strip()
    return text


def _telegram_actor(source: Any) -> str:
    name = _short(getattr(source, "user_name", ""), "")
    user_id = _short(getattr(source, "user_id", ""), "")
    return f"telegram:{name or user_id or 'operator'}"


def _render_meeting_handoff_command(
    ctx: Any,
    target: str,
    args: str,
    *,
    source: Any = None,
    session_store: Any = None,
    adapter: Any = None,
) -> dict[str, Any]:
    required = ("workflow.plan_request", "workflow.start_confirmed")
    if any(_descriptor(name) is None for name in required):
        return _capability_unavailable("Meeting Notes", required)
    parsed = _meeting_handoff_args(args)
    session_id = _conversation_state_id(session_store, source)
    if parsed.get("confirm_pending"):
        state = _get_meeting_handoff_state(session_id)
        if not state:
            return {
                "title": "Meeting Notes",
                "text": "Meeting Notes\nNo pending meeting handoff found for this chat.",
                "actions": [],
            }
        plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
        text = _workflow_start_text(ctx, target, plan)
        _clear_meeting_handoff_state(session_id)
        return {"title": "Meeting Notes", "text": text, "actions": []}
    if parsed.get("error"):
        return {"title": "Meeting Notes", "text": f"Meeting Notes\n{parsed['error']}", "actions": []}

    meeting_file = str(parsed.get("meeting_file") or "")
    notes_text = str(parsed.get("notes_text") or "")
    plan_args = {
        "meeting_file": meeting_file,
        "source_kind": "telegram",
        "source_notes_source": "telegram",
        "source_notes_text": notes_text,
        "harness_id": "telegram-hermes",
        "harness_session_id": session_id,
    }
    _, data, errors = _dispatch_first(
        ctx,
        target,
        [
            (
                "workflow.plan_request",
                {
                    "workflow_id": "meeting_process",
                    "args": plan_args,
                    "actor": _telegram_actor(source),
                    "source": "Hermes Telegram",
                    "session_id": session_id or f"telegram-meeting-{int(time.time())}",
                },
            )
        ],
    )
    if data is None:
        return _render_error("Meeting Notes", target, errors)
    if isinstance(data, dict) and data.get("status") == "confirmation_required":
        _store_meeting_handoff_state(
            session_id,
            plan=data,
            meeting_file=meeting_file,
            notes_text=notes_text,
        )
    card = _render_workflow_plan(
        data,
        ctx=ctx,
        target=target,
        adapter=adapter,
        start_hint="/kb meeting confirm",
    )
    card["title"] = "Meeting Notes"
    return card


def _workflow_initial_progress_text(
    ctx: Any,
    target: str,
    run_id: str,
    *,
    include_run_details: bool = True,
) -> str:
    _tool, payload, _errors = _dispatch_first(
        ctx,
        target,
        [
            (
                "run.summary",
                {
                    "run_id": run_id,
                    "timeline_limit": 5,
                },
            )
        ],
    )
    if isinstance(payload, dict) and payload.get("error"):
        return "Initial progress: unavailable - " + _short(payload.get("error"))
    if not isinstance(payload, dict):
        return ""
    digest = payload.get("progress_digest") if isinstance(payload.get("progress_digest"), dict) else payload
    progress = digest.get("progress") if isinstance(digest.get("progress"), dict) else {}
    stage = digest.get("stage") if isinstance(digest.get("stage"), dict) else {}
    provider = digest.get("provider") if isinstance(digest.get("provider"), dict) else {}
    staleness = digest.get("staleness") if isinstance(digest.get("staleness"), dict) else {}
    phase = _short(progress.get("current_phase") or progress.get("current_step") or digest.get("status"), "")
    detail = _short(progress.get("current_detail") or progress.get("latest_message"), "")
    lines: list[str] = []
    if phase:
        lines.append(
            f"Initial progress: {phase}" + (f" - {detail}" if detail and include_run_details else "")
        )
    if include_run_details:
        stage_id = _short(stage.get("stage_id") or stage.get("call_name"), "")
        total = stage.get("total")
        if stage_id and total not in {None, ""}:
            try:
                failed_count = int(stage.get("failed") or 0)
            except (TypeError, ValueError):
                failed_count = 0
            lines.append(
                f"Stage: {stage_id} {_short(stage.get('completed'), '0')}/{_short(total, '0')}"
                + (f" failed {_short(stage.get('failed'), '0')}" if failed_count else "")
            )
        provider_name = _short(provider.get("provider"), "")
        model = _short(provider.get("model"), "")
        if provider_name or model:
            lines.append(f"Provider: {provider_name or 'unknown'} / {model or 'unknown'}")
    if staleness.get("stale"):
        age = _short(staleness.get("last_trace_age_seconds"), "unknown")
        lines.append(f"Attention: run appears stalled; no trace progress for {age}s")
    if include_run_details:
        if payload.get("terminal") is False:
            lines.append("Watch: still running")
        elif payload.get("terminal") is True:
            lines.append("Watch: terminal")
    return "\n".join(lines)


def _workflow_run_id(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    run = payload.get("run") if isinstance(payload.get("run"), dict) else {}
    completion = payload.get("completion") if isinstance(payload.get("completion"), dict) else {}
    return str(payload.get("run_id") or run.get("run_id") or completion.get("run_id") or "")


def _workflow_status_text(prefix: str, payload: Any, *, include_run_details: bool = True) -> str:
    if isinstance(payload, dict) and payload.get("error"):
        return f"{prefix}\n{payload['error']}"
    if not isinstance(payload, dict):
        return f"{prefix}\n{_short(payload, 'No structured response returned.')}"
    lines = [
        prefix,
        f"Status: {_short(payload.get('status'))}",
    ]
    lines.extend(_receipt_lines(payload))
    run_id = _workflow_run_id(payload)
    if run_id and include_run_details:
        lines.append(f"Run: {run_id}")
    if payload.get("started") is not None:
        lines.append(f"Started: {_short(payload.get('started'))}")
    follow = payload.get("followthrough_contract") if isinstance(payload.get("followthrough_contract"), dict) else {}
    if follow and include_run_details:
        lines.append(f"Next: {_short(follow.get('recommended_next_action'))}")
    if isinstance(payload.get("readiness"), dict):
        lines.append("Readiness: " + _short(payload["readiness"].get("status")))
    return "\n".join(lines)


def _render_workflow_plan(
    data: Any,
    *,
    ctx: Any,
    target: str,
    adapter: Any,
    start_hint: str = "/kb run sync confirm",
    title: str = "Workflow",
    heading: str = "Workflow Preview",
) -> dict[str, Any]:
    if isinstance(data, dict) and data.get("error"):
        return {"title": title, "text": f"{heading} failed\n{data['error']}", "actions": []}
    if not isinstance(data, dict):
        return {"title": title, "text": f"{title}\n{_short(data, 'No plan returned.')}", "actions": []}
    workflow = data.get("workflow") if isinstance(data.get("workflow"), dict) else {}
    request = data.get("request") if isinstance(data.get("request"), dict) else {}
    effect_plan = data.get("effect_plan") if isinstance(data.get("effect_plan"), dict) else {}
    effects = effect_plan.get("effects") if isinstance(effect_plan.get("effects"), list) else []
    lines = [
        heading,
        f"Request: {start_hint.removesuffix(' confirm') if start_hint.endswith(' confirm') else start_hint}",
        f"Workflow: {_short(workflow.get('workflow_id'))}",
        f"Status: {_short(data.get('status'))}",
        f"Risk: {_short(workflow.get('risk') or effect_plan.get('risk'))}",
        f"Force: {_short(request.get('force'))}",
    ]
    if data.get("message"):
        lines.append("Message: " + _short(data.get("message")))
    lines.extend(_receipt_lines(data, include_request=True))
    if isinstance(data.get("readiness"), dict):
        lines.append("Readiness: " + _short(data["readiness"].get("status")))
    if effects:
        lines.append("Effects: " + ", ".join(_short(effect.get("id")) for effect in effects[:4] if isinstance(effect, dict)))
    follow = data.get("followthrough_contract") if isinstance(data.get("followthrough_contract"), dict) else {}
    if follow:
        lines.append("Follow-through: " + _short(follow.get("watch_tool")) + " -> " + _short(follow.get("terminal_summary_tool")))
    if data.get("status") == "confirmation_required":
        lines.append(f"To start: {start_hint}")
    return {"title": title, "text": "\n".join(lines), "actions": []}


_SYNC_SUCCESS_STATES = {"completed", "completed_with_degradation"}


def _sync_success_state(packet: Any) -> str:
    if not isinstance(packet, dict):
        return ""
    terminal = str(packet.get("terminal_state") or "").strip().lower()
    status = str(packet.get("status") or "").strip().lower()
    if terminal in _SYNC_SUCCESS_STATES and status in _SYNC_SUCCESS_STATES:
        return terminal if terminal == status else ""
    return ""


def _daily_integration_closeout_eligible(packet: Any) -> bool:
    """Allow only clean runs or fully-accounted item-level insufficiency."""

    success_state = _sync_success_state(packet)
    if success_state == "completed":
        return True
    if success_state != "completed_with_degradation" or not isinstance(packet, dict):
        return False
    degradations = packet.get("degradations")
    if not isinstance(degradations, list) or not degradations:
        return False
    for row in degradations:
        try:
            insufficient_count = int(row.get("source_insufficient_count") or 0) if isinstance(row, dict) else 0
        except (TypeError, ValueError):
            return False
        if (
            not isinstance(row, dict)
            or row.get("reason_code") != "source_content_insufficient"
            or row.get("retryable") is not False
            or insufficient_count <= 0
        ):
            return False
    source_currency = (
        packet.get("source_currency")
        if isinstance(packet.get("source_currency"), dict)
        else {}
    )
    sources = source_currency.get("sources")
    if not isinstance(sources, list) or not sources or any(
        not isinstance(row, dict) or row.get("state") != "current" for row in sources
    ):
        return False
    accounting = (
        packet.get("semantic_accounting")
        if isinstance(packet.get("semantic_accounting"), dict)
        else {}
    )
    lifecycle = packet.get("lifecycle") if isinstance(packet.get("lifecycle"), dict) else {}
    return bool(
        accounting.get("complete") is True
        and int(accounting.get("remaining_count") or 0) == 0
        and lifecycle.get("status") == "fixed_point"
    )


def _sync_publication_is_separate(packet: Any) -> bool:
    if not isinstance(packet, dict):
        return False
    publication = packet.get("publication")
    return bool(
        isinstance(publication, dict)
        and publication.get("status") == "not_attempted"
        and publication.get("sync_publishes") is False
        and publication.get("separate_confirmation_required") is True
    )


def _sync_noop_verified(packet: Any) -> bool:
    return bool(
        isinstance(packet, dict)
        and packet.get("kind") == "kb_sync_run"
        and _sync_success_state(packet) == "completed"
        and packet.get("reason") == "all_sources_current"
        and packet.get("answered_actions") == 0
        and not packet.get("run_id")
        and _sync_publication_is_separate(packet)
    )


def _sync_readback_verified(resumed: Any, readback: Any, run_id: str) -> bool:
    resumed_state = _sync_success_state(resumed)
    readback_state = _sync_success_state(readback)
    return bool(
        resumed_state
        and resumed_state == readback_state
        and isinstance(resumed, dict)
        and isinstance(readback, dict)
        and resumed.get("run_id") == run_id
        and readback.get("run_id") == run_id
        and _sync_publication_is_separate(resumed)
        and _sync_publication_is_separate(readback)
    )


def _render_sync_packet(packet: Any, *, readback_verified: bool = False) -> dict[str, Any]:
    """Render one compact sync receipt without exposing workflow machinery."""
    if not isinstance(packet, dict):
        return _render_error("Knowledge sync", _mcp_target(), ["sync returned no structured packet"])

    status = str(packet.get("status") or "unknown").strip().lower()
    terminal = str(packet.get("terminal_state") or "").strip().lower()
    success_state = _sync_success_state(packet)
    lines = [_emphasis_headline("Knowledge sync")]

    if packet.get("error"):
        lines.extend(["Sync stopped.", "No completion is claimed.", "Next: ask me to retry."])
        return {"title": "Knowledge sync", "status": "failed", "text": "\n".join(lines), "actions": []}

    if _sync_noop_verified(packet):
        lines.extend(
            [
                "Everything is already current.",
                "No knowledge changes were needed.",
                "Publication was not attempted.",
                "Receipt: verified no-op",
            ]
        )
    elif success_state:
        if not readback_verified:
            lines.extend(
                [
                    "The final result could not be verified.",
                    "No completion is claimed.",
                    "Next: ask me to check sync status.",
                ]
            )
        elif not _sync_publication_is_separate(packet):
            return {
                "title": "Knowledge sync",
                "status": "blocked",
                "text": "\n".join(
                    [
                        _emphasis_headline("Knowledge sync"),
                        "Publication separation could not be verified.",
                        "No completion is claimed.",
                        "Next: inspect the sync receipt on a trusted operator surface.",
                    ]
                ),
                "actions": [],
            }
        elif success_state == "completed_with_degradation":
            lines.extend(
                [
                    "Sync completed with gaps.",
                    "Verified knowledge changes are saved; some evidence was unavailable.",
                    "Publication was not attempted.",
                    "Receipt: verified",
                ]
            )
        else:
            lines.extend(
                [
                    "Sync complete.",
                    "Knowledge changes are saved and verified.",
                    "Publication was not attempted.",
                    "Receipt: verified",
                ]
            )
    elif status == "ready_to_apply":
        summary = _public_clip(_get_path(packet, "preview", "semantic_summary"), 150)
        lines.append("The reviewed internal update is ready.")
        if summary:
            lines.append(summary)
        lines.append("Next: say “apply it” to continue.")
        lines.append("Publication remains separate.")
    elif status in {"awaiting_action", "prepared", "running", "workflow_running"}:
        action = packet.get("next_action") if isinstance(packet.get("next_action"), dict) else {}
        action_kind = str(action.get("kind") or "").strip().lower()
        if action_kind == "gather_evidence":
            lines.append("The comprehensive update is ready for evidence gathering.")
            lines.append("Next: continue here so I can gather and review the evidence.")
        else:
            lines.append("Sync is in progress.")
            lines.append("Next: continue here to complete the review.")
        lines.append("Publication was not attempted.")
    elif terminal in {"failed", "stalled_unobserved"} or status in {"failed", "stalled_unobserved"}:
        state = terminal or status
        lines.extend(
            [
                f"Sync stopped: {state.replace('_', ' ')}.",
                "No completion is claimed.",
                "Next: ask me to inspect the blocker or retry.",
            ]
        )
    elif terminal == "cancelled" or status == "cancelled":
        lines.extend(
            [
                "Sync stopped without applying changes.",
                "No completion is claimed.",
                "Next: ask me to start again when ready.",
            ]
        )
    else:
        lines.extend(
            [
                f"Status: {_public_clip(status, 48) or 'unknown'}.",
                "No completion is claimed.",
                "Next: ask me to check sync status.",
            ]
        )
    return {
        "title": "Knowledge sync",
        "status": status,
        "text": "\n".join(lines[:8]),
        "actions": [],
    }


def _sync_harness_rewrite(run_id: str) -> str:
    """Give the active run to Hermes through the gateway's normal model turn."""
    return (
        f"Continue the canonical KB sync run {run_id}. "
        "Call kb.sync.status for that exact run first, then follow its next_action. "
        "Gather evidence and exercise semantic judgment in the Hermes harness; use "
        "kb.sync.resume for the requested responses and routine standing-safe-write apply. "
        "Do not publish. Return a compact truthful result to the user."
    )


def _sync_tool_call(
    ctx: Any,
    target: str,
    capability: str,
    args: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    _tool, data, errors = _dispatch_first(ctx, target, [(capability, args)])
    return (data if isinstance(data, dict) else None), errors


def _sync_packet_spool_root() -> Path:
    state_root = Path(
        os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")
    ).expanduser()
    return (state_root / "kb-sync" / "prepare").resolve()


def _load_sync_spooled_packet(packet_path: Any) -> dict[str, Any]:
    raw_path = str(packet_path or "").strip()
    if not raw_path or "\x00" in raw_path or "\n" in raw_path or "\r" in raw_path:
        raise ValueError("packet_path is required")
    requested_path = Path(raw_path).expanduser()
    if not requested_path.is_absolute() or requested_path.is_symlink():
        raise ValueError("packet_path must be an absolute regular spool file")
    spool_root = _sync_packet_spool_root()
    resolved_path = requested_path.resolve(strict=True)
    try:
        resolved_path.relative_to(spool_root)
    except ValueError as exc:
        raise ValueError("packet_path is outside the private sync spool") from exc
    info = resolved_path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("packet_path is not a regular file")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("packet_path ownership or mode is unsafe")
    if info.st_size <= 0 or info.st_size > SYNC_PACKET_MAX_BYTES:
        raise ValueError("packet_path size is outside the safe transport bound")
    try:
        packet = json.loads(resolved_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("packet_path does not contain valid UTF-8 JSON") from exc
    if not isinstance(packet, dict):
        raise ValueError("spooled packet must be a JSON object")
    if packet.get("schema_version") != 1 or packet.get("kind") != "kb.source_evidence":
        raise ValueError("spooled packet is not kb.source_evidence schema v1")
    if not all(
        isinstance(packet.get(field), str) and str(packet[field]).strip()
        for field in ("source_id", "connector_id", "harness_id")
    ):
        raise ValueError("spooled packet is missing its source identity")
    canonical = json.dumps(packet, sort_keys=True, ensure_ascii=False)
    digest_prefix = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    if not resolved_path.name.endswith(f"-{digest_prefix}.json"):
        raise ValueError("spooled packet filename does not bind its content digest")
    return packet


def _compact_sync_packet_result(payload: Any, *, run_id: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": "kb.sync.resume returned a non-object response",
        }
    next_action = payload.get("next_action")
    compact_action: dict[str, Any] = {}
    if isinstance(next_action, dict):
        for field in (
            "kind",
            "action_index",
            "source_id",
            "reconciliation_window",
            "apply_required",
        ):
            if field in next_action:
                compact_action[field] = next_action[field]
        evidence_refs = next_action.get("evidence_refs")
        if isinstance(evidence_refs, list):
            compact_action["evidence_ref_count"] = len(evidence_refs)
    return {
        "accepted": True,
        "run_id": str(payload.get("run_id") or run_id),
        "status": payload.get("status"),
        "next_action": compact_action,
        "source_currency": payload.get("source_currency"),
        "publication": payload.get("publication"),
        "instruction": "Continue with kb.sync.status for this exact run.",
    }


def _compact_semantic_status_result(
    payload: Any,
    *,
    run_id: str,
    requested_count: int,
    selected_count: int,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": "kb.sync.status returned a non-object response",
        }
    status = str(payload.get("status") or "")
    if status in {"invalid_request", "not_found", "failed", "cancelled"}:
        return {
            "accepted": False,
            "run_id": str(payload.get("run_id") or run_id),
            "status": status,
            "error": _clip(payload.get("reason"), 240) or "semantic status selection failed",
        }
    next_action = payload.get("next_action")
    compact_action: dict[str, Any] = {}
    if isinstance(next_action, dict):
        for field in (
            "kind",
            "action_index",
            "semantic_stage",
            "instruction",
            "response_schema",
            "attribution_outcomes",
            "allowed_operations",
        ):
            if field in next_action:
                compact_action[field] = next_action[field]
        accounting = next_action.get("semantic_accounting")
        progress = accounting.get("progress") if isinstance(accounting, dict) else None
        if isinstance(progress, dict):
            compact_progress = dict(progress)
            compact_progress.pop("remaining_refs", None)
            compact_action["semantic_accounting"] = {"progress": compact_progress}
    result: dict[str, Any] = {
        "accepted": True,
        "run_id": str(payload.get("run_id") or run_id),
        "status": status,
        "requested_count": requested_count,
        "selected_count": selected_count,
        "reduced": selected_count < requested_count,
        "next_action": compact_action,
    }
    for field in ("selected_evidence", "candidate_state", "target_dossiers"):
        if field in payload:
            value = payload[field]
            if field == "selected_evidence":
                value = _normalize_selected_evidence_for_transport(value)
            elif field == "target_dossiers":
                value = _normalize_target_dossiers_for_transport(value)
            result[field] = value
    return result


def _normalize_selected_evidence_for_transport(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    normalized = copy.deepcopy(payload)
    items = normalized.get("items")
    if not isinstance(items, list):
        return normalized
    omitted = 0
    for row in items:
        item = row.get("item") if isinstance(row, dict) else None
        if not isinstance(item, dict):
            continue
        semantic_text = item.get("semantic_text")
        transcript = item.get("transcript")
        if isinstance(semantic_text, str) and transcript == semantic_text:
            item.pop("transcript", None)
            omitted += 1
    if omitted:
        normalized["transport_normalization"] = {
            "duplicate_transcript_fields_omitted": omitted,
        }
    return normalized


def _normalize_target_dossiers_for_transport(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    normalized = copy.deepcopy(payload)
    dossiers = normalized.get("items")
    if not isinstance(dossiers, list):
        return normalized
    omitted = 0
    for dossier in dossiers:
        evidence = dossier.get("evidence") if isinstance(dossier, dict) else None
        if not isinstance(evidence, list):
            continue
        for row in evidence:
            item = row.get("item") if isinstance(row, dict) else None
            if not isinstance(item, dict):
                continue
            semantic_text = item.get("semantic_text")
            transcript = item.get("transcript")
            if isinstance(semantic_text, str) and transcript == semantic_text:
                item.pop("transcript", None)
                omitted += 1
    if omitted:
        normalized["transport_normalization"] = {
            "duplicate_transcript_fields_omitted": omitted,
        }
    return normalized


def _semantic_batch_transport(
    ctx: Any,
    args: dict[str, Any],
    *,
    run_id: str,
) -> dict[str, Any]:
    evidence_refs = args.get("evidence_refs")
    target_refs = args.get("target_refs")
    if (evidence_refs is None) == (target_refs is None):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": "semantic_batch requires exactly one selector",
        }
    selector = "evidence_refs" if evidence_refs is not None else "target_refs"
    values = evidence_refs if evidence_refs is not None else target_refs
    if not isinstance(values, list) or not 1 <= len(values) <= 10:
        return {
            "accepted": False,
            "run_id": run_id,
            "error": f"{selector} must contain one to ten exact refs",
        }
    selected = [str(value or "").strip() for value in values]
    if len(set(selected)) != len(selected) or any(not value for value in selected):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": f"{selector} must contain unique non-empty refs",
        }
    if selector == "evidence_refs" and any(
        not DESCRIPTOR_DIGEST_RE.fullmatch(value) for value in selected
    ):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": "evidence_refs must be exact sha256 refs",
        }
    raw_target_evidence_offset = args.get("target_evidence_offset")
    raw_evidence_text_offset = args.get("evidence_text_offset")
    raw_target_evidence_text_offset = args.get("target_evidence_text_offset")
    if raw_evidence_text_offset is not None and (
        raw_target_evidence_offset is not None
        or raw_target_evidence_text_offset is not None
    ):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": (
                "evidence_text_offset and target evidence offsets are mutually exclusive"
            ),
        }
    if raw_target_evidence_text_offset is not None and (
        selector != "target_refs"
        or len(selected) != 1
        or raw_target_evidence_offset is None
        or isinstance(raw_target_evidence_offset, bool)
        or not isinstance(raw_target_evidence_offset, int)
        or raw_target_evidence_offset < 0
        or isinstance(raw_target_evidence_text_offset, bool)
        or not isinstance(raw_target_evidence_text_offset, int)
        or raw_target_evidence_text_offset < 0
    ):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": (
                "target_evidence_text_offset requires exactly one target_ref, "
                "target_evidence_offset, and a non-negative integer"
            ),
        }
    if raw_evidence_text_offset is not None and (
        selector != "evidence_refs"
        or len(selected) != 1
        or isinstance(raw_evidence_text_offset, bool)
        or not isinstance(raw_evidence_text_offset, int)
        or raw_evidence_text_offset < 0
    ):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": (
                "evidence_text_offset requires exactly one evidence_ref and a "
                "non-negative integer"
            ),
        }
    if raw_target_evidence_offset is not None and (
        selector != "target_refs"
        or len(selected) != 1
        or isinstance(raw_target_evidence_offset, bool)
        or not isinstance(raw_target_evidence_offset, int)
        or raw_target_evidence_offset < 0
    ):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": (
                "target_evidence_offset requires exactly one target_ref and a "
                "non-negative integer"
            ),
        }
    target_evidence_offset = int(raw_target_evidence_offset or 0)
    evidence_text_offset = int(raw_evidence_text_offset or 0)
    target_evidence_text_offset = (
        int(raw_target_evidence_text_offset)
        if raw_target_evidence_text_offset is not None
        else None
    )
    requested_count = len(selected)
    while selected:
        _tool, payload, errors = _dispatch_first(
            ctx,
            _mcp_target(),
            [("kb.sync.status", {"run_id": run_id, selector: selected})],
        )
        if payload is None:
            return {
                "accepted": False,
                "run_id": run_id,
                "error": _clip("; ".join(errors), 240) or "kb.sync.status failed",
            }
        result = _compact_semantic_status_result(
            payload,
            run_id=run_id,
            requested_count=requested_count,
            selected_count=len(selected),
        )
        required_result = (
            "selected_evidence" if selector == "evidence_refs" else "target_dossiers"
        )
        if result.get("accepted") is not True or not isinstance(
            result.get(required_result), dict
        ):
            return {
                **result,
                "accepted": False,
                "error": str(result.get("error") or f"{required_result} is unavailable"),
            }
        encoded = json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if selector == "target_refs" and len(selected) == 1 and (
            raw_target_evidence_offset is not None
            or raw_target_evidence_text_offset is not None
            or len(encoded) > INTEGRATION_TRANSPORT_MAX_RESULT_BYTES
        ):
            return _page_target_dossier_result(
                result,
                run_id=run_id,
                evidence_offset=target_evidence_offset,
                evidence_text_offset=target_evidence_text_offset,
            )
        if selector == "evidence_refs" and len(selected) == 1 and (
            raw_evidence_text_offset is not None
            or len(encoded) > INTEGRATION_TRANSPORT_MAX_RESULT_BYTES
        ):
            return _page_selected_evidence_result(
                result,
                run_id=run_id,
                text_offset=evidence_text_offset,
            )
        if len(encoded) <= INTEGRATION_TRANSPORT_MAX_RESULT_BYTES:
            return result
        if len(selected) == 1:
            return {
                "accepted": False,
                "run_id": run_id,
                "requested_count": requested_count,
                "selected_count": 1,
                "error": "one semantic review item exceeds the bounded transport result",
            }
        selected = selected[: max(1, len(selected) // 2)]
    raise AssertionError("semantic batch selector unexpectedly became empty")


def _page_selected_evidence_result(
    result: dict[str, Any],
    *,
    run_id: str,
    text_offset: int,
) -> dict[str, Any]:
    selected_evidence = result.get("selected_evidence")
    items = (
        selected_evidence.get("items")
        if isinstance(selected_evidence, dict)
        else None
    )
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": "one exact evidence item is required for text paging",
        }
    item = items[0].get("item")
    semantic_text = item.get("semantic_text") if isinstance(item, dict) else None
    if not isinstance(semantic_text, str) or text_offset >= len(semantic_text):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": "evidence_text_offset is outside the exact evidence body",
        }
    text_char_count = len(semantic_text) - text_offset
    while text_char_count:
        paged = copy.deepcopy(result)
        paged_evidence = paged["selected_evidence"]
        paged_item = paged_evidence["items"][0]["item"]
        page_end = text_offset + text_char_count
        paged_item["semantic_text"] = semantic_text[text_offset:page_end]
        has_more = page_end < len(semantic_text)
        paged_evidence["page"] = {
            "field": "semantic_text",
            "text_offset": text_offset,
            "text_char_count": text_char_count,
            "text_total_chars": len(semantic_text),
            "has_more": has_more,
            "next_text_offset": page_end if has_more else None,
        }
        encoded = json.dumps(
            paged,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) <= INTEGRATION_TRANSPORT_MAX_RESULT_BYTES:
            return paged
        if text_char_count == 1:
            return {
                "accepted": False,
                "run_id": run_id,
                "requested_count": int(result.get("requested_count") or 1),
                "selected_count": 1,
                "error": "one evidence text page exceeds the bounded transport result",
            }
        text_char_count = max(1, text_char_count // 2)
    raise AssertionError("evidence text page unexpectedly became empty")


def _page_target_dossier_result(
    result: dict[str, Any],
    *,
    run_id: str,
    evidence_offset: int,
    evidence_text_offset: int | None = None,
) -> dict[str, Any]:
    dossiers = result.get("target_dossiers")
    items = dossiers.get("items") if isinstance(dossiers, dict) else None
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": "one exact target dossier is required for evidence paging",
        }
    evidence = items[0].get("evidence")
    if not isinstance(evidence, list) or evidence_offset >= len(evidence):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": "target_evidence_offset is outside the exact target dossier",
        }
    if evidence_text_offset is not None:
        return _page_target_dossier_evidence_text_result(
            result,
            run_id=run_id,
            evidence_offset=evidence_offset,
            text_offset=evidence_text_offset,
        )
    evidence_count = len(evidence) - evidence_offset
    while evidence_count:
        paged = copy.deepcopy(result)
        paged_dossiers = paged["target_dossiers"]
        paged_item = paged_dossiers["items"][0]
        page_end = evidence_offset + evidence_count
        paged_item["evidence"] = evidence[evidence_offset:page_end]
        has_more = page_end < len(evidence)
        paged_dossiers["page"] = {
            "evidence_offset": evidence_offset,
            "evidence_count": evidence_count,
            "evidence_total_count": len(evidence),
            "has_more": has_more,
            "next_evidence_offset": page_end if has_more else None,
        }
        if evidence_offset > 0:
            _compact_target_dossier_continuation(paged)
        encoded = json.dumps(
            paged,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) <= INTEGRATION_TRANSPORT_MAX_RESULT_BYTES:
            return paged
        if evidence_count == 1:
            return _page_target_dossier_evidence_text_result(
                result,
                run_id=run_id,
                evidence_offset=evidence_offset,
                text_offset=0,
            )
        evidence_count = max(1, evidence_count // 2)
    raise AssertionError("target dossier page unexpectedly became empty")


def _page_target_dossier_evidence_text_result(
    result: dict[str, Any],
    *,
    run_id: str,
    evidence_offset: int,
    text_offset: int,
) -> dict[str, Any]:
    dossiers = result.get("target_dossiers")
    items = dossiers.get("items") if isinstance(dossiers, dict) else None
    dossier = items[0] if isinstance(items, list) and len(items) == 1 else None
    evidence = dossier.get("evidence") if isinstance(dossier, dict) else None
    row = (
        evidence[evidence_offset]
        if isinstance(evidence, list) and evidence_offset < len(evidence)
        else None
    )
    item = row.get("item") if isinstance(row, dict) else None
    semantic_text = item.get("semantic_text") if isinstance(item, dict) else None
    if not isinstance(semantic_text, str) or text_offset >= len(semantic_text):
        return {
            "accepted": False,
            "run_id": run_id,
            "error": (
                "target_evidence_text_offset is outside the exact target evidence body"
            ),
        }
    text_char_count = len(semantic_text) - text_offset
    while text_char_count:
        paged = copy.deepcopy(result)
        paged_dossiers = paged["target_dossiers"]
        paged_dossier = paged_dossiers["items"][0]
        paged_row = copy.deepcopy(evidence[evidence_offset])
        page_end = text_offset + text_char_count
        paged_row["item"]["semantic_text"] = semantic_text[text_offset:page_end]
        paged_dossier["evidence"] = [paged_row]
        text_has_more = page_end < len(semantic_text)
        evidence_has_more = evidence_offset + 1 < len(evidence)
        has_more = text_has_more or evidence_has_more
        paged_dossiers["page"] = {
            "evidence_offset": evidence_offset,
            "evidence_count": 1,
            "evidence_total_count": len(evidence),
            "has_more": has_more,
            "next_evidence_offset": (
                evidence_offset
                if text_has_more
                else evidence_offset + 1
                if evidence_has_more
                else None
            ),
            "evidence_text_page": {
                "field": "semantic_text",
                "text_offset": text_offset,
                "text_char_count": text_char_count,
                "text_total_chars": len(semantic_text),
                "has_more": text_has_more,
                "next_text_offset": page_end if text_has_more else None,
            },
        }
        if evidence_offset > 0 or text_offset > 0:
            _compact_target_dossier_continuation(paged)
        encoded = json.dumps(
            paged,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) <= INTEGRATION_TRANSPORT_MAX_RESULT_BYTES:
            return paged
        if text_char_count == 1:
            return {
                "accepted": False,
                "run_id": run_id,
                "requested_count": int(result.get("requested_count") or 1),
                "selected_count": 1,
                "error": "one target evidence text page exceeds the bounded transport result",
            }
        text_char_count = max(1, text_char_count // 2)
    raise AssertionError("target evidence text page unexpectedly became empty")


def _compact_target_dossier_continuation(result: dict[str, Any]) -> None:
    """Keep continuation pages exact without repeating page-one invariants."""

    result.pop("next_action", None)
    dossiers = result.get("target_dossiers")
    if not isinstance(dossiers, dict):
        return
    dossiers["continuation"] = True
    items = dossiers.get("items")
    if not isinstance(items, list):
        return
    for dossier in items:
        if not isinstance(dossier, dict):
            continue
        dossier.pop("object_context", None)
        dossier.pop("evidence_refs", None)


_CONTEXT_STOPWORDS = frozenset(
    {
        "about", "after", "before", "calendar", "context", "event", "from",
        "meeting", "meetings", "prep", "schedule", "this", "through", "with", "work",
    }
)


def _context_timestamp(value: Any, *, field: str) -> _dt.datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    try:
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(_dt.timezone.utc)


def _context_terms(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 12:
        raise ValueError("terms must contain one to twelve search anchors")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        term = str(item or "").strip()
        if not term or len(term) > 80 or "\x00" in term:
            raise ValueError("terms must be non-empty and at most 80 characters")
        folded = term.casefold()
        if folded not in seen:
            seen.add(folded)
            result.append(term)
    return result


def _context_sources(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= len(CONTEXT_SEARCH_SOURCES):
        raise ValueError("sources must select one to five declared read sources")
    result = [str(item or "").strip() for item in value]
    if len(set(result)) != len(result) or any(item not in CONTEXT_SEARCH_SOURCES for item in result):
        raise ValueError("sources contain an unknown or duplicate read source")
    return result


def _context_query_tokens(terms: list[str]) -> list[str]:
    tokens: list[str] = []
    for term in terms:
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]+", term.casefold()):
            if token not in _CONTEXT_STOPWORDS and token not in tokens:
                tokens.append(token)
    return tokens


def _context_score(value: Any, tokens: list[str]) -> int:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True).casefold()
    return sum(1 for token in tokens if token in text)


def _context_cli_payload(value: Any) -> tuple[bool, Any, str]:
    if not isinstance(value, dict):
        return False, None, "connector returned a non-object response"
    if value.get("success") is not True:
        error = value.get("error")
        message = (
            error.get("message") or error.get("code")
            if isinstance(error, dict)
            else error
        )
        return False, None, _clip(message, 240) or "connector reported failure"
    return True, value.get("data"), ""


def _run_context_command(
    argv: list[str],
    *,
    timeout: int = CONTEXT_SEARCH_COMMAND_TIMEOUT_SECONDS,
    discard_stdout: bool = False,
) -> tuple[int, str, str]:
    allowed = {"calendar-cli", "outlook-cli", "meeting-cli", "kb-sync-gather"}
    if not argv or argv[0] not in allowed:
        raise ValueError("context command is not allowlisted")
    executable = shutil.which(argv[0])
    if not executable:
        return 127, "", f"{argv[0]} is unavailable"
    env = dict(os.environ)
    env["AI_PIM_UTILS_SKILL_SYNC_DISABLED"] = "1"
    env["AI_PIM_UTILS_TELEMETRY_DISABLED"] = "1"
    env.setdefault("KB_HARNESS_ID", "hermes-context")
    try:
        result = subprocess.run(
            [executable, *argv[1:]],
            text=True,
            stdout=subprocess.DEVNULL if discard_stdout else subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]} timed out"
    return result.returncode, "" if discard_stdout else result.stdout, result.stderr


def _context_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        for key in ("items", "messages", "events", "results"):
            rows = value.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
    return []


def _context_email_address(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    address = value.get("emailAddress") if isinstance(value.get("emailAddress"), dict) else value
    return str(address.get("name") or address.get("address") or "").strip()


def _context_event_datetime(value: Any) -> _dt.datetime | None:
    timezone_name = ""
    if isinstance(value, dict):
        timezone_name = str(value.get("timeZone") or "").upper()
        value = value.get("dateTime")
    try:
        parsed = _dt.datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        if timezone_name not in {"UTC", "ETC/UTC"}:
            return None
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


def _context_calendar_row(row: dict[str, Any]) -> dict[str, Any]:
    location = row.get("location")
    if isinstance(location, dict):
        location = location.get("displayName") or location.get("address")
    return {
        "source": "calendar",
        "ref": str(row.get("id") or ""),
        "title": _clip(row.get("subject"), 240),
        "start": row.get("start"),
        "end": row.get("end"),
        "location": _clip(location, 180),
        "organizer": _context_email_address(row.get("organizer")),
        "preview": _clip(row.get("bodyPreview"), 1200),
        "is_cancelled": row.get("isCancelled") is True,
        "is_online": row.get("isOnlineMeeting") is True,
    }


def _context_mail_row(row: dict[str, Any], *, body: Any = "") -> dict[str, Any]:
    return {
        "source": "mail",
        "ref": str(row.get("id") or ""),
        "conversation_ref": str(row.get("conversationId") or ""),
        "title": _clip(row.get("subject"), 240),
        "from": _context_email_address(row.get("from") or row.get("sender")),
        "received_at": str(row.get("receivedDateTime") or row.get("sentDateTime") or ""),
        "preview": _clip(row.get("bodyPreview"), 1200),
        "body": _clip(body, 3500),
        "has_attachments": row.get("hasAttachments") is True,
    }


def _context_slack_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "slack",
        "ref": str(row.get("external_id") or row.get("ts") or ""),
        "channel": str(row.get("channel") or row.get("channel_id") or ""),
        "author": str(row.get("user_name") or row.get("user") or ""),
        "observed_at": str(row.get("date") or row.get("ts") or ""),
        "text": _clip(row.get("text"), 3000),
        "reply_count": int(row.get("reply_count") or 0),
    }


def _context_tripit_row(row: dict[str, Any]) -> dict[str, Any]:
    location = row.get("location")
    if isinstance(location, dict):
        location = location.get("name") or location.get("address") or location.get("code")
    return {
        "source": "tripit",
        "ref": str(row.get("external_id") or ""),
        "kind": str(row.get("type") or ""),
        "title": _clip(row.get("title"), 240),
        "trip_name": _clip(row.get("trip_name"), 240),
        "start": row.get("start"),
        "end": row.get("end"),
        "trip_start": row.get("trip_start"),
        "trip_end": row.get("trip_end"),
        "location": _clip(location, 240),
    }


def _search_calendar_context(
    *, start: _dt.datetime, end: _dt.datetime, tokens: list[str], limit: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    code, stdout, stderr = _run_context_command(
        [
            "calendar-cli", "find",
            "--after", start.date().isoformat(),
            # calendar-cli accepts dates, not timestamps. Expand the connector
            # read by one date and filter the returned rows to the exact UTC
            # interval below so travel timezones cannot drop boundary events.
            "--before", (end.date() + _dt.timedelta(days=1)).isoformat(),
            "--limit", "200", "--utc", "--json",
        ]
    )
    if code != 0:
        return {"source": "calendar", "status": "degraded", "error": _clip(stderr, 240)}, []
    try:
        raw = json.loads(stdout)
    except json.JSONDecodeError:
        return {"source": "calendar", "status": "degraded", "error": "invalid connector response"}, []
    ok, data, error = _context_cli_payload(raw)
    if not ok:
        return {"source": "calendar", "status": "degraded", "error": error}, []
    fetched = _context_rows(data)
    rows = [
        row
        for row in fetched
        if (
            (event_start := _context_event_datetime(row.get("start"))) is not None
            and start <= event_start < end
        )
    ]
    def score(row: dict[str, Any]) -> int:
        # The user's account/event words in the subject are stronger identity
        # evidence than a generic mention buried in an invite body.
        return 4 * _context_score(row.get("subject"), tokens) + _context_score(row, tokens)

    scored = sorted(rows, key=score, reverse=True)
    positive = [row for row in scored if score(row) > 0]
    selected = (positive or scored)[:limit]
    return {
        "source": "calendar",
        "status": "ready",
        "observed_count": len(rows),
        "fetched_count": len(fetched),
        "selected_count": len(selected),
        "bounded": len(rows) >= 200,
    }, [_context_calendar_row(row) for row in selected]


def _context_kql(terms: list[str]) -> str:
    return " OR ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms)


def _search_mail_context(
    *, start: _dt.datetime, end: _dt.datetime, terms: list[str], tokens: list[str], limit: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    fetch_limit = max(limit * 3, 20)
    code, stdout, stderr = _run_context_command(
        [
            "outlook-cli", "message", "find", "--query", _context_kql(terms),
            "--after", start.isoformat().replace("+00:00", "Z"),
            "--before", end.isoformat().replace("+00:00", "Z"),
            "--all-folders", "--limit", str(fetch_limit), "--json",
        ]
    )
    if code != 0:
        return {"source": "mail", "status": "degraded", "error": _clip(stderr, 240)}, []
    try:
        raw = json.loads(stdout)
    except json.JSONDecodeError:
        return {"source": "mail", "status": "degraded", "error": "invalid connector response"}, []
    ok, data, error = _context_cli_payload(raw)
    if not ok:
        return {"source": "mail", "status": "degraded", "error": error}, []
    observed = _context_rows(data)
    rows = sorted(observed, key=lambda row: _context_score(row, tokens), reverse=True)[:limit]
    normalized: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        body: Any = ""
        ref = str(row.get("id") or "")
        if ref and index < CONTEXT_SEARCH_DETAIL_LIMIT:
            detail_code, detail_stdout, _detail_stderr = _run_context_command(
                ["outlook-cli", "message", "read", ref, "--json"], timeout=45
            )
            if detail_code == 0:
                try:
                    detail_raw = json.loads(detail_stdout)
                    detail_ok, detail, _detail_error = _context_cli_payload(detail_raw)
                    if detail_ok and isinstance(detail, dict):
                        raw_body = detail.get("body")
                        body = (
                            raw_body.get("content") or raw_body.get("text") or ""
                            if isinstance(raw_body, dict)
                            else raw_body
                        )
                except json.JSONDecodeError:
                    pass
        normalized.append(_context_mail_row(row, body=body))
    return {
        "source": "mail",
        "status": "ready",
        "observed_count": len(observed),
        "selected_count": len(normalized),
        "bounded": len(observed) >= fetch_limit,
    }, normalized


def _search_slack_context(
    *, start: _dt.datetime, end: _dt.datetime, tokens: list[str], limit: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    requested_start = start
    max_start = end - _dt.timedelta(days=CONTEXT_SEARCH_SLACK_MAX_WINDOW_DAYS)
    warning = ""
    if start < max_start:
        start = max_start
        warning = f"Slack search bounded to the latest {CONTEXT_SEARCH_SLACK_MAX_WINDOW_DAYS} days"
    state_root = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
    temp_root = state_root / "kb-sync" / "context"
    temp_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=temp_root,
        prefix="slack-", suffix=".yaml", delete=False,
    ) as handle:
        handle.write("channels: {}\n")
        config_path = Path(handle.name)
    config_path.chmod(0o600)
    try:
        window_seconds = (end - start).total_seconds()
        window_days = max(1, min(
            CONTEXT_SEARCH_SLACK_MAX_WINDOW_DAYS,
            int(window_seconds + 86399) // 86400,
        ))
        code, _stdout, stderr = _run_context_command(
            [
                "kb-sync-gather", "--source", "slack", "--workspace", str(Path.home()),
                "--since", start.isoformat().replace("+00:00", "Z"),
                "--until", end.isoformat().replace("+00:00", "Z"),
                "--source-config", str(config_path), "--window-days", str(window_days),
                "--max-items", "5000",
            ],
            discard_stdout=True,
        )
    finally:
        config_path.unlink(missing_ok=True)
    if code != 0:
        return {"source": "slack", "status": "degraded", "error": _clip(stderr, 240)}, []
    match = re.search(r"spooled exact response:\s+(\S+\.json)\s+\(no durable KB write\)", stderr)
    if not match:
        return {"source": "slack", "status": "degraded", "error": "connector returned no private spool"}, []
    spool = Path(match.group(1))
    try:
        packet = _load_sync_spooled_packet(spool)
    except (OSError, ValueError) as exc:
        return {"source": "slack", "status": "degraded", "error": _clip(str(exc), 240)}, []
    finally:
        spool.unlink(missing_ok=True)
    rows = _context_rows(packet.get("items") if isinstance(packet, dict) else None)
    selected = [row for row in rows if _context_score(row, tokens) > 0][:limit]
    status: dict[str, Any] = {
        "source": "slack", "status": "ready", "observed_count": len(rows),
        "selected_count": len(selected), "bounded": False,
        "requested_start": requested_start.isoformat().replace("+00:00", "Z"),
        "observed_start": start.isoformat().replace("+00:00", "Z"),
    }
    if warning:
        status["warning"] = warning
    return status, [_context_slack_row(row) for row in selected]


def _search_tripit_context(
    *, observed_at: _dt.datetime, tokens: list[str], limit: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    boundary = observed_at.isoformat().replace("+00:00", "Z")
    code, _stdout, stderr = _run_context_command(
        [
            "kb-sync-gather", "--source", "tripit", "--workspace", str(Path.home()),
            "--since", boundary, "--until", boundary, "--max-items", "1000",
        ],
        discard_stdout=True,
    )
    if code != 0:
        return {"source": "tripit", "status": "degraded", "error": _clip(stderr, 240)}, []
    match = re.search(r"spooled exact response:\s+(\S+\.json)\s+\(no durable KB write\)", stderr)
    if not match:
        return {"source": "tripit", "status": "degraded", "error": "connector returned no private spool"}, []
    spool = Path(match.group(1))
    try:
        packet = _load_sync_spooled_packet(spool)
    except (OSError, ValueError) as exc:
        return {"source": "tripit", "status": "degraded", "error": _clip(str(exc), 240)}, []
    finally:
        spool.unlink(missing_ok=True)
    rows = _context_rows(packet.get("items") if isinstance(packet, dict) else None)
    scored = sorted(rows, key=lambda row: _context_score(row, tokens), reverse=True)
    positive = [row for row in scored if _context_score(row, tokens) > 0]
    selected = (positive or scored)[:limit]
    return {
        "source": "tripit", "status": "ready", "observed_count": len(rows),
        "selected_count": len(selected), "snapshot_complete": True,
    }, [_context_tripit_row(row) for row in selected]


def _search_meeting_artifacts_context(
    calendar_rows: list[dict[str, Any]], *, limit: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    now = _dt.datetime.now(_dt.timezone.utc)

    def ended(row: dict[str, Any]) -> bool:
        parsed = _context_event_datetime(row.get("end"))
        return parsed is not None and parsed <= now

    candidates = [row for row in calendar_rows if row.get("ref") and ended(row)][:1]
    if not candidates:
        return {
            "source": "meeting_artifacts", "status": "degraded",
            "error": "no resolved calendar event was available",
        }, []
    items: list[dict[str, Any]] = []
    for event in candidates:
        code, stdout, _stderr = _run_context_command(
            ["meeting-cli", "transcript", "read", "--event-id", str(event["ref"]), "--json"],
            timeout=60,
        )
        if code != 0:
            continue
        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            continue
        ok, data, _error = _context_cli_payload(raw)
        if ok and data not in (None, [], {}):
            items.append(
                {
                    "source": "meeting_artifacts", "event_ref": event["ref"],
                    "title": event.get("title"),
                    "content": _clip(json.dumps(data, ensure_ascii=False), 8000),
                }
            )
    return {
        "source": "meeting_artifacts",
        "status": "ready" if items else "empty",
        "checked_count": len(candidates), "selected_count": len(items),
    }, items


def _context_search(args: dict[str, Any]) -> dict[str, Any]:
    terms = _context_terms(args.get("terms"))
    requested_sources = _context_sources(args.get("sources"))
    start = _context_timestamp(args.get("start"), field="start")
    end = _context_timestamp(args.get("end"), field="end")
    if end <= start:
        raise ValueError("end must be after start")
    if end - start > _dt.timedelta(days=CONTEXT_SEARCH_MAX_WINDOW_DAYS):
        raise ValueError(f"context search window cannot exceed {CONTEXT_SEARCH_MAX_WINDOW_DAYS} days")
    limit = args.get("limit_per_source", 5)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= CONTEXT_SEARCH_MAX_ITEMS_PER_SOURCE:
        raise ValueError(f"limit_per_source must be between 1 and {CONTEXT_SEARCH_MAX_ITEMS_PER_SOURCE}")
    tokens = _context_query_tokens(terms)
    statuses: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    calendar_items: list[dict[str, Any]] = []
    # Calendar anchors meeting-artifact lookup. Keep execution deterministic even
    # when the model presents the declared sources in a different order.
    sources = [
        source
        for source in ("calendar", "tripit", "mail", "slack", "meeting_artifacts")
        if source in requested_sources
    ]
    for source in sources:
        if source == "calendar":
            status, rows = _search_calendar_context(start=start, end=end, tokens=tokens, limit=limit)
            calendar_items = rows
        elif source == "tripit":
            status, rows = _search_tripit_context(observed_at=end, tokens=tokens, limit=limit)
        elif source == "mail":
            status, rows = _search_mail_context(
                start=start, end=end, terms=terms, tokens=tokens, limit=limit
            )
        elif source == "slack":
            status, rows = _search_slack_context(start=start, end=end, tokens=tokens, limit=limit)
        else:
            status, rows = _search_meeting_artifacts_context(calendar_items, limit=limit)
        statuses.append(status)
        items.extend(rows)
    result = {
        "accepted": True,
        "kind": "hermes_context_search",
        "terms": terms,
        "window": {
            "start": start.isoformat().replace("+00:00", "Z"),
            "end": end.isoformat().replace("+00:00", "Z"),
        },
        "sources": statuses,
        "requested_sources": requested_sources,
        "items": items,
        "item_count": len(items),
        "external_effect_started": False,
        "durable_kb_write_started": False,
    }
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > INTEGRATION_TRANSPORT_MAX_RESULT_BYTES:
        for item in items:
            for field in ("body", "content", "text", "preview"):
                if field in item:
                    item[field] = _clip(item[field], 800)
        result["transport_reduced"] = True
    return result


def _managed_plan_digest(envelope: dict[str, Any]) -> str:
    material = {key: value for key, value in envelope.items() if key != "plan_digest"}
    canonical = json.dumps(
        material,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _calendar_live_request(envelope: dict[str, Any], *, mode: str = "execute") -> dict[str, Any]:
    path = os.getenv("HERMES_CALENDAR_LIVE_SOCKET", CALENDAR_LIVE_SOCKET).strip() or CALENDAR_LIVE_SOCKET
    request = {
        "schema_version": 1,
        "kind": "calendar_live_managed_request",
        "mode": mode,
        "envelope": envelope,
    }
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(240)
    chunks: list[bytes] = []
    size = 0
    try:
        client.connect(path)
        client.sendall(json.dumps(request, sort_keys=True).encode("utf-8"))
        client.shutdown(socket.SHUT_WR)
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > CALENDAR_LIVE_MAX_RESPONSE_BYTES:
                raise ValueError("calendar.live response exceeded the bounded size")
            chunks.append(chunk)
    finally:
        client.close()
    try:
        payload = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("calendar.live returned an invalid response") from exc
    if not isinstance(payload, dict):
        raise ValueError("calendar.live returned a non-object response")
    return payload


def _daily_integration_morning_brief(
    sync: dict[str, Any],
    calendar: dict[str, Any],
    publication: dict[str, Any],
) -> str:
    source_currency = sync.get("source_currency") if isinstance(sync.get("source_currency"), dict) else {}
    sources = source_currency.get("sources") if isinstance(source_currency.get("sources"), list) else []
    source_current = sum(
        1 for row in sources if isinstance(row, dict) and row.get("state") == "current"
    )
    accounting = sync.get("semantic_accounting") if isinstance(sync.get("semantic_accounting"), dict) else {}
    lifecycle = sync.get("lifecycle") if isinstance(sync.get("lifecycle"), dict) else {}
    counts = calendar.get("counts") if isinstance(calendar.get("counts"), dict) else {}
    targets = int(accounting.get("integrated_target_count") or 0)
    changed = int(counts.get("applied") or 0)
    kept = int(counts.get("kept") or 0)
    git_status = str(publication.get("status") or "unknown")
    return "\n".join(
        (
            "Daily Integration complete",
            f"Evidence: {source_current}/5 sources current.",
            f"KB: {targets} targets integrated; lifecycle {lifecycle.get('status') or 'verified'}.",
            f"Calendar: {changed} applied, {kept} already current.",
            f"Git: {git_status} with clean readback.",
            "Next: open /kb review for the current decision queue.",
        )
    )


def _daily_integration_closeout(ctx: Any, args: dict[str, Any], *, run_id: str) -> dict[str, Any]:
    target = _mcp_target()
    _tool, sync, errors = _dispatch_first(
        ctx, target, [("kb.sync.status", {"run_id": run_id})]
    )
    if not _daily_integration_closeout_eligible(sync):
        return {
            "accepted": False,
            "complete": False,
            "run_id": run_id,
            "stage": "integration_readback",
            "error": _clip("; ".join(errors), 240)
            or "kb.sync run is not eligible for Daily Integration closeout",
        }
    envelope = args.get("calendar_envelope")
    if not isinstance(envelope, dict) or str(envelope.get("run_id") or "") != run_id:
        return {
            "accepted": False,
            "complete": False,
            "run_id": run_id,
            "stage": "calendar_plan",
            "error": "calendar envelope must bind the exact completed run",
        }
    envelope = dict(envelope)
    envelope["plan_digest"] = _managed_plan_digest(envelope)
    try:
        calendar_result = _calendar_live_request(envelope, mode="execute")
    except (OSError, ValueError) as exc:
        return {
            "accepted": False,
            "complete": False,
            "run_id": run_id,
            "stage": "calendar_execution",
            "error": _clip(str(exc), 240),
        }
    closeout = calendar_result.get("closeout") if isinstance(calendar_result, dict) else None
    if calendar_result.get("ok") is not True or not isinstance(closeout, dict) or closeout.get("ok") is not True:
        return {
            "accepted": False,
            "complete": False,
            "run_id": run_id,
            "stage": "calendar_execution",
            "error": _clip(calendar_result.get("reason"), 240) or "managed calendar execution failed",
        }
    _tool, preview, errors = _dispatch_first(
        ctx,
        target,
        [("publication.daily_integration_preview", {"run_id": run_id, "calendar_receipt": closeout})],
    )
    if not isinstance(preview, dict) or preview.get("ok") is not True:
        return {
            "accepted": False,
            "complete": False,
            "run_id": run_id,
            "stage": "publication_preview",
            "calendar": {"status": closeout.get("status"), "counts": closeout.get("counts")},
            "error": _clip("; ".join(errors), 240) or "Git publication is held",
        }
    preview_digest = str(preview.get("preview_digest") or "")
    if not DESCRIPTOR_DIGEST_RE.fullmatch(preview_digest):
        return {
            "accepted": False,
            "complete": False,
            "run_id": run_id,
            "stage": "publication_preview",
            "error": "publication preview did not return an exact digest",
        }
    _tool, publication, errors = _dispatch_first(
        ctx,
        target,
        [(
            "publication.daily_integration_apply",
            {
                "run_id": run_id,
                "calendar_receipt": closeout,
                "preview_digest": preview_digest,
                "actor": "hermes-relay",
                "source": "kb_journeys.daily_integration",
                "session_id": str(args.get("session_id") or ""),
            },
        )],
    )
    if not isinstance(publication, dict) or publication.get("ok") is not True \
       or publication.get("status") not in {"published", "noop"}:
        return {
            "accepted": False,
            "complete": False,
            "run_id": run_id,
            "stage": "publication_apply",
            "calendar": {"status": closeout.get("status"), "counts": closeout.get("counts")},
            "error": _clip("; ".join(errors), 240) or "Git publication did not pass readback",
        }
    return {
        "accepted": True,
        "complete": True,
        "run_id": run_id,
        "status": "completed",
        "stages": {
            "integration": "completed",
            "calendar": str(closeout.get("status") or "completed"),
            "publication": str(publication.get("status") or "published"),
        },
        "source_currency": sync.get("source_currency"),
        "semantic_accounting": sync.get("semantic_accounting"),
        "lifecycle": sync.get("lifecycle"),
        "calendar": {"status": closeout.get("status"), "counts": closeout.get("counts")},
        "publication": {
            "status": publication.get("status"),
            "readback": publication.get("readback"),
        },
        "morning_brief": _daily_integration_morning_brief(sync, closeout, publication),
    }


def _register_integration_transport(ctx: Any) -> None:
    if len(_descriptor_allowlist()) > 13:
        logger.error("kb_journeys: integration transport would exceed the 14-tool cap")
        return
    schema = {
        "name": INTEGRATION_TRANSPORT_TOOL,
        "description": (
            "Perform one bounded Daily Integration transport action: forward an exact "
            "private source packet, return one compact semantic review batch, or close "
            "a completed run through the protected managed-calendar and clean Git "
            "publication contracts. Also perform one explicitly requested, read-only "
            "Calendar, Outlook, Slack, TripIt, and meeting-context search for ordinary prep and planning."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": [
                        "resume_packet",
                        "semantic_batch",
                        "daily_integration_closeout",
                        "context_search",
                    ],
                },
                "run_id": {
                    "type": "string",
                    "description": "The exact active kb.sync run id.",
                },
                "packet_path": {
                    "type": "string",
                    "description": (
                        "Absolute mode-0600 file beneath the private "
                        "XDG_STATE_HOME/kb-sync/prepare spool."
                    ),
                },
                "calendar_envelope": {
                    "type": "object",
                    "description": "Exact kb_managed_event_travel_v1 envelope for this run.",
                },
                "session_id": {
                    "type": "string",
                    "description": "Stable Hermes execution session id for publication provenance.",
                },
                "evidence_refs": {
                    "type": "array",
                    "description": "One to ten exact adequate evidence refs to inspect.",
                    "items": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                    "minItems": 1,
                    "maxItems": 10,
                    "uniqueItems": True,
                },
                "target_refs": {
                    "type": "array",
                    "description": "One to ten exact current KB targets to synthesize.",
                    "items": {"type": "string", "minLength": 1},
                    "minItems": 1,
                    "maxItems": 10,
                    "uniqueItems": True,
                },
                "target_evidence_offset": {
                    "type": "integer",
                    "minimum": 0,
                    "description": (
                        "For one paged target dossier only, continue at the exact "
                        "next_evidence_offset returned by the previous page."
                    ),
                },
                "evidence_text_offset": {
                    "type": "integer",
                    "minimum": 0,
                    "description": (
                        "For one paged evidence item only, continue at the exact "
                        "next_text_offset returned by the previous page."
                    ),
                },
                "target_evidence_text_offset": {
                    "type": "integer",
                    "minimum": 0,
                    "description": (
                        "For one oversized evidence body inside one target dossier, "
                        "continue at the exact next_text_offset while retaining the "
                        "same target_evidence_offset."
                    ),
                },
                "terms": {
                    "type": "array",
                    "description": "One to twelve concrete names, topics, or event anchors to find.",
                    "items": {"type": "string", "minLength": 1, "maxLength": 80},
                    "minItems": 1,
                    "maxItems": 12,
                    "uniqueItems": True,
                },
                "sources": {
                    "type": "array",
                    "description": "Declared read-only context sources.",
                    "items": {
                        "type": "string",
                        "enum": ["calendar", "mail", "slack", "meeting_artifacts", "tripit"],
                    },
                    "minItems": 1,
                    "maxItems": 5,
                    "uniqueItems": True,
                },
                "start": {
                    "type": "string",
                    "description": "Timezone-aware ISO-8601 lower bound for context search.",
                },
                "end": {
                    "type": "string",
                    "description": "Timezone-aware ISO-8601 upper bound for context search.",
                },
                "limit_per_source": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 12,
                    "default": 5,
                },
            },
            "required": ["operation"],
            "oneOf": [
                {
                    "properties": {"operation": {"const": "resume_packet"}},
                    "required": ["run_id", "packet_path"],
                },
                {
                    "properties": {"operation": {"const": "daily_integration_closeout"}},
                    "required": ["run_id", "calendar_envelope", "session_id"],
                },
                {
                    "properties": {"operation": {"const": "semantic_batch"}},
                    "required": ["run_id"],
                    "oneOf": [
                        {
                            "required": ["evidence_refs"],
                            "not": {"required": ["target_refs"]},
                        },
                        {
                            "required": ["target_refs"],
                            "not": {"required": ["evidence_refs"]},
                        },
                    ],
                },
                {
                    "properties": {"operation": {"const": "context_search"}},
                    "required": ["terms", "sources", "start", "end"],
                    "not": {
                        "anyOf": [
                            {"required": ["packet_path"]},
                            {"required": ["calendar_envelope"]},
                            {"required": ["evidence_refs"]},
                            {"required": ["target_refs"]}
                        ]
                    }
                },
            ],
            "additionalProperties": False,
        },
    }

    def _handler(args: dict[str, Any], **_: Any) -> str:
        operation = str(args.get("operation") or "").strip()
        if operation == "context_search":
            try:
                payload = _context_search(args)
            except (OSError, ValueError) as exc:
                payload = {"accepted": False, "error": _clip(str(exc), 240)}
            return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        run_id = str(args.get("run_id") or "").strip()
        if not SYNC_PACKET_RUN_ID_RE.fullmatch(run_id):
            return json.dumps(
                {"accepted": False, "error": "run_id is invalid"},
                separators=(",", ":"),
            )
        if operation == "daily_integration_closeout":
            return json.dumps(
                _daily_integration_closeout(ctx, args, run_id=run_id),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        if operation == "semantic_batch":
            return json.dumps(
                _semantic_batch_transport(ctx, args, run_id=run_id),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        if operation != "resume_packet":
            return json.dumps(
                {"accepted": False, "run_id": run_id, "error": "operation is invalid"},
                separators=(",", ":"),
            )
        try:
            packet = _load_sync_spooled_packet(args.get("packet_path"))
        except (OSError, ValueError) as exc:
            return json.dumps(
                {"accepted": False, "run_id": run_id, "error": str(exc)},
                separators=(",", ":"),
            )
        _tool, payload, errors = _dispatch_first(
            ctx,
            _mcp_target(),
            [("kb.sync.resume", {"run_id": run_id, "response": packet})],
        )
        if payload is None:
            return json.dumps(
                {
                    "accepted": False,
                    "run_id": run_id,
                    "error": _clip("; ".join(errors), 240) or "kb.sync.resume failed",
                },
                separators=(",", ":"),
            )
        return json.dumps(
            _compact_sync_packet_result(payload, run_id=run_id),
            ensure_ascii=False,
            separators=(",", ":"),
        )

    ctx.register_tool(
        name=INTEGRATION_TRANSPORT_TOOL,
        toolset="kb_journeys",
        schema=schema,
        handler=_handler,
        description=(
            "Bounded read-only context, source-packet, semantic-review, and Daily Integration closeout transport."
        ),
        emoji="📦",
    )


def _render_sync_command(
    ctx: Any,
    target: str,
    args: str,
    *,
    source: Any,
    session_store: Any,
) -> dict[str, Any]:
    """Run the canonical prepare/status/resume protocol from Telegram."""
    if not _canonical_sync_contract_ready():
        return _sync_temporarily_unavailable()
    session_id = _conversation_state_id(session_store, source)
    if not session_id:
        return {
            "title": "KB Sync",
            "status": "blocked",
            "text": "KB Sync\nA stable Hermes conversation id is required. No KB state changed.",
            "actions": [],
        }
    state, _state_reason = _get_sync_run_state(session_id, source)
    tokens = (args or "").strip().split()
    verb = tokens[0].lower() if tokens else ""

    if verb in {"status", "apply"} or (not tokens and state):
        run_id = ""
        if verb in {"status", "apply"} and len(tokens) > 1:
            run_id = tokens[1]
        if not run_id and state:
            run_id = _short(state.get("run_id"), "")
        if not run_id:
            return {
                "title": "KB Sync",
                "status": "not_found",
                "text": "KB Sync\nNo current run is recorded. Start one with /kb sync.",
                "actions": [],
            }
        current, errors = _sync_tool_call(ctx, target, "kb.sync.status", {"run_id": run_id})
        if current is None:
            return _render_error("KB Sync", target, errors)
        _store_sync_run_state(session_id, source=source, target=target, packet=current)
        if verb != "apply":
            terminal = _short(current.get("terminal_state"), "")
            if not tokens and terminal in {
                "completed",
                "completed_with_degradation",
                "failed",
                "cancelled",
            }:
                state = None
            else:
                card = _render_sync_packet(
                    current,
                    readback_verified=bool(
                        _sync_success_state(current)
                        and _sync_publication_is_separate(current)
                    ),
                )
                if not tokens and run_id and not _sync_success_state(current):
                    card["_gateway_rewrite"] = _sync_harness_rewrite(run_id)
                return card
        else:
            if current.get("status") != "ready_to_apply":
                return _render_sync_packet(current, readback_verified=False)
            authorization = current.get("authorization") if isinstance(current.get("authorization"), dict) else {}
            expected_actor = f"telegram:{_telegram_user_id(source) or 'operator'}"
            if (
                _short(authorization.get("bound_actor"), "") != expected_actor
                or _short(authorization.get("bound_session_id"), "") != session_id
                or authorization.get("mode") != "standing_safe_write"
                or authorization.get("human_confirmation_required") is not False
            ):
                return {
                    "title": "KB Sync",
                    "status": "authorization_owner_mismatch",
                    "text": (
                        "KB Sync\nThis preview is not bound to the current Hermes actor and "
                        "conversation. No KB state changed."
                    ),
                    "actions": [],
                }
            resumed, errors = _sync_tool_call(
                ctx,
                target,
                "kb.sync.resume",
                {"run_id": run_id, "apply": True},
            )
            if resumed is None:
                return _render_error("KB Sync", target, errors)
            readback, errors = _sync_tool_call(ctx, target, "kb.sync.status", {"run_id": run_id})
            if readback is None:
                return _render_sync_packet(resumed, readback_verified=False)
            _store_sync_run_state(session_id, source=source, target=target, packet=readback)
            verified = _sync_readback_verified(resumed, readback, run_id)
            return _render_sync_packet(readback, readback_verified=verified)

    if tokens and verb not in {"prepare"}:
        return {
            "title": "KB Sync",
            "status": "invalid_request",
            "text": "KB Sync\nUse /kb sync, /kb sync status, or /kb sync apply.",
            "actions": [],
        }
    actor_id = _telegram_user_id(source) or "operator"
    prepared, errors = _sync_tool_call(
        ctx,
        target,
        "kb.sync.prepare",
        {"actor": f"telegram:{actor_id}", "session_id": session_id},
    )
    if prepared is None:
        return _render_error("KB Sync", target, errors)
    _store_sync_run_state(session_id, source=source, target=target, packet=prepared)
    card = _render_sync_packet(
        prepared,
        readback_verified=_sync_noop_verified(prepared),
    )
    run_id = _short(prepared.get("run_id"), "")
    if run_id and not _sync_success_state(prepared):
        card["_gateway_rewrite"] = _sync_harness_rewrite(run_id)
    return card


def _render_queue(
    data: Any,
    *,
    ctx: Any | None = None,
    target: str | None = None,
    session_id: str = "",
) -> dict[str, Any]:
    if isinstance(data, str):
        return {"title": "KB Review", "text": f"KB Review\n{data}", "actions": []}
    count = None
    if isinstance(data, dict):
        count = data.get("total") or data.get("count") or _count_from(data, "queue", "proposals")
    items = _items(data, ("items",), ("proposals",), ("queue", "items"))
    visible_items = items[:5]
    total = _queue_total(data)
    offset = _queue_offset(data)
    next_offset = _queue_next_offset(data)
    _store_visible_queue_scope(session_id, visible_items, total=total, offset=offset, next_offset=next_offset)
    if visible_items and isinstance(visible_items[0], dict):
        _store_iterative_state_from_item(session_id, visible_items[0])
    elif session_id:
        _clear_iterative_queue_reply_state(session_id)
    if not items:
        lines = ["KB Review"]
        if count is not None:
            lines.append(f"{count} pending")
        lines.append("No proposal previews returned.")
        return {"title": "KB Review", "text": "\n".join(lines), "actions": []}
    return {
        "title": "KB Review",
        "text": _queue_review_text(data, visible_items, total=total, offset=offset),
        "actions": _queue_guided_actions(ctx, target, data, session_id=session_id),
    }


def _lifecycle_review_args(args: str) -> dict[str, Any]:
    text = str(args or "").strip()
    if text.lower().startswith("lifecycle "):
        text = text.split(maxsplit=1)[1].strip()
    if text.lower().startswith("for "):
        text = text.split(maxsplit=1)[1].strip()
    return {
        "target": text or "situations",
        "dry_run": True,
    }


def _render_lifecycle_review_command(ctx: Any, target: str, args: str) -> dict[str, Any]:
    if _descriptor("lifecycle.review") is None:
        if _descriptor("attention.cockpit") is None:
            return _capability_unavailable("KB Review", ("attention.cockpit",))
        _, data, errors = _dispatch_first(
            ctx,
            target,
            [
                (
                    "attention.cockpit",
                    {
                        "attention_limit": 5,
                        "run_limit": 1,
                        "include_publication": False,
                        "include_readiness": False,
                        "mode": "compact",
                        "sections": ["situations", "queue"],
                    },
                )
            ],
        )
        if data is None:
            return _render_error("KB Review", target, errors)
        card = _render_dashboard(data, ctx=ctx, target=target)
        card["title"] = "KB Review"
        return card
    _, data, errors = _dispatch_first(
        ctx,
        target,
        [("lifecycle.review", _lifecycle_review_args(args))],
    )
    if data is None:
        return _render_error("Lifecycle Review", target, errors)
    packet_card = _render_supported_result_packet(data, ctx=ctx, target=target)
    if packet_card is not None:
        return packet_card
    return _render_lifecycle_review_packet(
        {
            "packet_type": "lifecycle_review.packet",
            "workflow": "Lifecycle Review",
            "mutation_performed": False,
            "candidates": [],
            "summary": data,
        },
        ctx=ctx,
        target=target,
    )


def _kb_root_command(args: str) -> tuple[str, str]:
    text = (args or "").strip()
    if not text:
        return "kb", ""
    head, _, tail = text.partition(" ")
    key = head.strip().lower()
    rest = tail.strip()
    if key in {"dashboard", "home"}:
        return "kb", rest
    if key in {"workbench", "wb", "cards", "decision-cards"}:
        return "kbworkbench", rest
    if key in {"help", "commands"}:
        return "kbhelp", rest
    if key == "today":
        return "kbtoday", rest
    if key in {"status", "info"}:
        return "kbstatus", rest
    if key in {"runs", "runlog", "history"}:
        return "kbruns", rest
    if key in {"queue", "q"}:
        return "kbqueue", rest
    if key == "review":
        review_head, _, review_tail = rest.partition(" ")
        review_mode = review_head.strip().lower()
        if not review_mode:
            return "kblifecycle", ""
        if review_mode in {"lifecycle", "stewardship"}:
            return "kblifecycle", review_tail.strip()
        if review_mode in {"proposal", "proposals", "queue", "inbox"}:
            return "kbqueue", review_tail.strip()
        if review_mode.isdigit() or review_mode in QUEUE_REPLY_DECISIONS:
            return "kbqueue", rest
        if "," in review_mode and all(part.strip().isdigit() for part in review_mode.split(",")):
            return "kbqueue", rest
        return "kbqueue", rest
    if key in {"lifecycle", "stewardship"}:
        return "kblifecycle", rest
    if key in {"publish", "publication"}:
        return "kbpublish", rest
    if key in {"run", "workflow"}:
        return "kbrun", rest
    if key in {"meeting", "meetings", "notes"}:
        return "kbmeeting", rest
    if key == "sync":
        return "kbsync_run", rest
    if key in {"capture", "save", "keep"}:
        return "kbcapture", rest
    if key in {"write", "note", "jot"}:
        return "kbwrite", rest
    return "kbhelp", text


def _kb_command_help() -> dict[str, Any]:
    return {
        "title": "KB",
        "text": "\n".join(
            [
                "KB Commands",
                "/kb status - prove lane, runtime, transport, publication, review, sync, dirtiness, and next action",
                "/kb sync - start or resume the canonical harness-driven knowledge update",
                "/kb review - lifecycle and proposal judgment inbox",
                "/kb publish - preview an exact KB publication; add confirm only after review",
                "Retired sync aliases return migration guidance only; they never dispatch a tool.",
            ]
        ),
        "actions": [],
    }


def _card_for_command(
    ctx: Any,
    command: str,
    *,
    args: str = "",
    adapter: Any = None,
    gateway: Any = None,
    source: Any = None,
    session_store: Any = None,
    event: Any = None,
) -> dict[str, Any]:
    target = _mcp_target()
    queue_session_id = _conversation_state_id(session_store, source)
    cockpit_args = {
        "attention_limit": 5,
        "include_publication": True,
        "include_readiness": True,
        "run_limit": 3,
    }
    if command == "kb":
        routed_command, routed_args = _kb_root_command(args)
        if routed_command == "kbhelp":
            return _kb_command_help()
        if routed_command != "kb":
            return _card_for_command(
                ctx,
                routed_command,
                args=routed_args,
                adapter=adapter,
                gateway=gateway,
                source=source,
                session_store=session_store,
                event=event,
            )
        _, data, errors = _dispatch_first(
            ctx,
            target,
            [
                (
                    "dashboard.live",
                    {
                        "limit": 5,
                        "include_feedback": True,
                        "include_publication": True,
                        "include_readiness": True,
                    },
                ),
                ("attention.cockpit", cockpit_args),
            ],
        )
        return _render_error("KB Dashboard", target, errors) if data is None else _render_dashboard(data, ctx=ctx, target=target)
    if command == "kbhelp":
        return _kb_command_help()
    if command == "kbworkbench":
        _, data, errors = _dispatch_first(
            ctx,
            target,
            [
                (
                    "dashboard.live",
                    {
                        "limit": 5,
                        "include_feedback": True,
                        "include_publication": True,
                        "include_readiness": True,
                    },
                ),
                ("attention.cockpit", cockpit_args),
            ],
        )
        return _render_error("KB Workbench", target, errors) if data is None else _render_workbench(data, ctx=ctx, target=target)
    if command == "kbtoday":
        _, data, errors = _dispatch_first(ctx, target, [("attention.cockpit", cockpit_args)])
        return _render_error("KB Today", target, errors) if data is None else _render_today(data)
    if command == "kbstatus":
        _, data, errors = _dispatch_first(
            ctx,
            target,
            [
                ("status.proof", {}),
                ("attention.cockpit", cockpit_args),
            ],
        )
        if data is None:
            return _render_error("Knowledge status", target, errors)
        return _render_status(data, target)
    if command == "kbruns":
        _, data, errors = _dispatch_first(
            ctx,
            target,
            [
                ("run.health", {}),
                ("run.watch", {"mode": "progress_digest"}),
                ("progress_digest", {}),
            ],
        )
        return _render_error("KB Runs", target, errors) if data is None else _render_runs(data)
    if command == "kbreview" and not (args or "").strip():
        return _render_lifecycle_review_command(ctx, target, "")
    if command in {"kbqueue", "kbreview"}:
        if _descriptor("review.inbox") is None:
            return _render_lifecycle_review_command(ctx, target, args)
        queue_scope, queue_args = _queue_scope_and_args(args)
        mode, indices, decision, confirm = _parse_queue_command_args(queue_args, command=command)
        if mode == "help":
            return _queue_command_help()
        data, errors = _queue_summary_payload(ctx, target, scope=queue_scope, limit=5)
        if data is None:
            return _render_error("KB Review", target, errors)
        packet_card = _render_supported_result_packet(data, ctx=ctx, target=target)
        if packet_card is not None:
            return packet_card
        if mode == "review" and indices:
            return _render_queue_item(data, index=indices[0], ctx=ctx, target=target)
        if mode == "decision" and indices and decision:
            return _render_queue_text_decision(
                ctx,
                target,
                data,
                indices=indices,
                decision=decision,
                confirm=confirm,
                session_id=queue_session_id,
            )
        return _render_queue(data, ctx=ctx, target=target, session_id=queue_session_id)
    if command == "kblifecycle":
        return _render_lifecycle_review_command(ctx, target, args)
    if command == "kbpublish":
        return _render_publish_command(
            ctx,
            target,
            args,
            session_id=queue_session_id,
            source=source,
        )
    if command == "kbsync_run":
        return _render_sync_command(
            ctx,
            target,
            args,
            source=source,
            session_store=session_store,
        )
    if command == "kbmeeting":
        return _render_meeting_handoff_command(
            ctx,
            target,
            args,
            source=source,
            session_store=session_store,
            adapter=adapter,
        )
    if command == "kbcapture":
        return _render_capture_command(
            ctx, target, args, event=event, source=source, session_store=session_store
        )
    if command == "kbwrite":
        return _render_write_command(
            ctx, target, args, event=event, source=source, session_store=session_store
        )
    if command == "kbmigration":
        return {
            "title": "KB Sync Migration",
            "status": "migration_required",
            "text": (
                "KB Sync Migration\nThis legacy sync command was removed. Use /kb sync. "
                "No KB state changed."
            ),
            "actions": [],
        }
    if command == "sync_unavailable":
        return _sync_temporarily_unavailable()
    if command == "kbrun":
        if _is_retired_sync_request(args):
            return _card_for_command(ctx, "kbmigration", args=args)
        workflow_id, intent, confirm = _workflow_args_from_text(args)
        if workflow_id in {"sync", "kb_sync"}:
            return _card_for_command(
                ctx,
                "kbmigration",
                args="/kb run sync",
                adapter=adapter,
                gateway=gateway,
                source=source,
                session_store=session_store,
                event=event,
            )
        required = ("workflow.plan_request", "workflow.start_confirmed")
        if any(_descriptor(name) is None for name in required):
            return _capability_unavailable("Workflow", required)
        if not workflow_id:
            return {
                "title": "Workflow",
                "text": "Workflow\nSend /kb run sync or /kb run <workflow_id>.",
                "actions": [],
            }
        _, data, errors = _dispatch_first(
            ctx,
            target,
            [
                (
                    "workflow.plan_request",
                    {
                        "workflow_id": workflow_id,
                        "intent": intent,
                        "actor": "telegram:operator",
                        "source": "Hermes Telegram",
                        "session_id": f"telegram-kb-{int(time.time())}",
                    },
                )
            ],
        )
        if data is None:
            return _render_error("Workflow", target, errors)
        if confirm and isinstance(data, dict) and data.get("status") == "confirmation_required":
            return {
                "title": "Workflow",
                "text": _workflow_start_text(
                    ctx,
                    target,
                    data,
                    prefix="Workflow start result",
                ),
                "actions": [],
            }
        hint_args = (args or "sync").strip()
        hint_parts = hint_args.split()
        if hint_parts and hint_parts[-1].lower() in {"confirm", "confirmed", "start", "apply"}:
            hint_args = " ".join(hint_parts[:-1]).strip()
        return _render_workflow_plan(
            data,
            ctx=ctx,
            target=target,
            adapter=adapter,
            start_hint=f"/kb run {hint_args or 'sync'} confirm",
            title="Workflow",
            heading="Workflow Preview",
        )
    return {"title": "KB", "text": "Unsupported KB command.", "actions": []}


def _adapter_for(gateway: Any, source: Any) -> Any | None:
    adapters = getattr(gateway, "adapters", {}) or {}
    platform = getattr(source, "platform", None)
    return (
        adapters.get(platform)
        or adapters.get(_platform_name(platform))
        or adapters.get("telegram")
    )


def _authorized_for_gateway(gateway: Any, source: Any) -> bool:
    checker = getattr(gateway, "_is_user_authorized", None)
    if checker is None:
        return True
    try:
        return bool(checker(source))
    except Exception:
        logger.debug("kb_journeys: authorization check failed", exc_info=True)
        return False


def _reply_anchor_and_metadata(event: Any) -> tuple[str | None, dict[str, Any] | None]:
    source = getattr(event, "source", None)
    try:
        from gateway.platforms.base import _reply_anchor_for_event, _thread_metadata_for_source

        return _reply_anchor_for_event(event), _thread_metadata_for_source(source)
    except Exception:
        metadata = None
        if getattr(source, "thread_id", None):
            metadata = {"thread_id": getattr(source, "thread_id")}
        return getattr(event, "message_id", None), metadata


def _send_kb_actions_accepts_rich(adapter: Any) -> bool:
    """True when ``adapter.send_kb_actions`` accepts a ``rich_markdown`` kwarg.

    Defends plugin/core version skew: this plugin ships from its own repo while
    the adapter ships in Hermes core. If a
    card emits ``rich_markdown`` but the bound adapter predates the rich-card
    param, forwarding it would raise ``TypeError``; this guard keeps the legacy
    text/actions path intact in that case.
    """
    return _callable_accepts_rich(getattr(adapter, "send_kb_actions", None))

def _send_accepts_rich(adapter: Any) -> bool:
    """True when ``adapter.send`` accepts a ``rich_markdown`` kwarg.

    Mirrors :func:`_send_kb_actions_accepts_rich` for the action-LESS path. The
    status/today/proof cards carry a ``rich_markdown`` payload but NO actions,
    so they go through plain ``adapter.send``; only telegram's ``send`` was
    extended with the rich param. Other transports (and any pre-rich telegram
    build, given the dual-source skew) keep the legacy two-arg ``send``, so we
    must NOT forward ``rich_markdown`` to them (it would raise ``TypeError``).
    """
    return _callable_accepts_rich(getattr(adapter, "send", None))

def _callable_accepts_rich(fn: Any) -> bool:
    """Shared signature probe: does ``fn`` accept a ``rich_markdown`` kwarg?"""
    if fn is None:
        return False
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    params = sig.parameters
    if "rich_markdown" in params:
        return True
    return any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())

async def _send_card(adapter: Any, event: Any, card: dict[str, Any]) -> None:
    source = getattr(event, "source", None)
    chat_id = getattr(source, "chat_id", None)
    if not chat_id:
        return
    reply_to, metadata = _reply_anchor_and_metadata(event)
    actions = card.get("actions", []) or []
    if not _KB_ACTION_AVAILABLE:
        actions = []
    rich_markdown = card.get("rich_markdown")
    if actions and hasattr(adapter, "send_kb_actions"):
        kb_kwargs: dict[str, Any] = {"reply_to": reply_to, "metadata": metadata}
        # Only forward rich_markdown when the bound adapter's send_kb_actions
        # actually accepts it; an older core adapter may lack the parameter.
        if rich_markdown and _send_kb_actions_accepts_rich(adapter):
            kb_kwargs["rich_markdown"] = rich_markdown
        result = adapter.send_kb_actions(
            chat_id,
            card["text"],
            actions,
            **kb_kwargs,
        )
    else:
        # Action-LESS cards (status / today / status-proof) carry their rich
        # payload here. Forward rich_markdown to adapter.send so the
        # status/today cards actually render rich — but only when the bound
        # send signature accepts it (same dual-source-skew guard as the
        # actions path; legacy / non-telegram adapters keep the plain send).
        send_kwargs: dict[str, Any] = {"reply_to": reply_to, "metadata": metadata}
        if rich_markdown and _send_accepts_rich(adapter):
            send_kwargs["rich_markdown"] = rich_markdown
        result = adapter.send(chat_id, card["text"], **send_kwargs)
    if inspect.isawaitable(result):
        result = await result
    if actions and not getattr(result, "success", True):
        labels = []
        for action in actions:
            label = getattr(action, "label", None)
            if label is None and isinstance(action, dict):
                label = action.get("label")
            if label:
                labels.append(str(label))
        fallback_text = card["text"]
        if labels:
            fallback_text = f"{card['text']}\n\nActions: {', '.join(labels)}"
        fallback = adapter.send(chat_id, fallback_text, reply_to=reply_to, metadata=metadata)
        if inspect.isawaitable(fallback):
            await fallback


def _run_delivery(coro: Any) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(coro)
        return
    loop.create_task(coro)


# --- Telegram capture (Phase 2 #7): save a message as kb.source_evidence ---
CAPTURE_CONNECTOR_ID = "hermes.plugin.telegram_capture"
CAPTURE_SOURCE_ID = "telegram.capture"


def _capture_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _capture_preview_state_path():
    from hermes_constants import get_hermes_home

    return get_hermes_home() / "state" / "kb_capture_preview_state.json"


def _load_capture_states() -> dict[str, Any]:
    path = _capture_preview_state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_capture_states(states: dict[str, Any]) -> None:
    path = _capture_preview_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(states, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        logger.debug("kb_journeys: failed to persist capture preview state", exc_info=True)


def _store_capture_preview_state(
    session_id: str,
    *,
    source: Any,
    target: str,
    packet: dict[str, Any],
    preview_binding: dict[str, Any],
) -> None:
    if not session_id:
        return
    states = _load_capture_states()
    states[session_id] = {
        "schema_version": 2,
        "recorded_at": time.time(),
        "actor_id": _telegram_user_id(source),
        "target": target,
        "packet": packet,
        "preview_binding": preview_binding,
    }
    _save_capture_states(states)


def _get_capture_preview_state(session_id: str, source: Any) -> tuple[dict[str, Any] | None, str]:
    if not session_id:
        return None, "missing_session"
    state = _load_capture_states().get(session_id)
    if not isinstance(state, dict):
        return None, "missing"
    recorded_at = float(state.get("recorded_at") or 0.0)
    if not recorded_at or time.time() - recorded_at > SYNC_PREVIEW_STATE_TTL_SECONDS:
        _clear_capture_preview_state(session_id)
        return None, "stale"
    actor_id = _short(state.get("actor_id"), "")
    current_actor = _telegram_user_id(source)
    if actor_id and current_actor and actor_id != current_actor:
        return None, "wrong_actor"
    if state.get("schema_version") != 2:
        return None, "invalid"
    if not isinstance(state.get("packet"), dict) or not isinstance(state.get("preview_binding"), dict):
        return None, "invalid"
    return state, ""


def _clear_capture_preview_state(session_id: str) -> None:
    if not session_id:
        return
    states = _load_capture_states()
    if states.pop(session_id, None) is not None:
        _save_capture_states(states)


def _capture_target_from_event(event: Any, inline: str) -> tuple[str, str, str, dict[str, Any]]:
    """(chat_id, message_id, text, meta). Reply -> the replied-to message; else inline text."""
    source = getattr(event, "source", None)
    chat_id = _short(getattr(source, "chat_id", ""), "")
    meta: dict[str, Any] = {}
    raw = getattr(event, "raw_message", None)
    fwd = getattr(raw, "forward_origin", None)
    if fwd is not None:
        meta["forwarded"] = True
        meta["forward_origin_type"] = _short(getattr(fwd, "type", ""), "")
    reply_id = getattr(event, "reply_to_message_id", None)
    reply_text = getattr(event, "reply_to_text", None)
    if reply_id and reply_text:
        return chat_id, _short(reply_id, ""), str(reply_text), meta
    if (inline or "").strip():
        return chat_id, _short(getattr(event, "message_id", ""), ""), inline.strip(), meta
    return chat_id, _short(getattr(event, "message_id", ""), ""), "", meta


def _build_telegram_capture_packet(
    chat_id: str, message_id: str, text: str, meta: dict[str, Any], *, harness_id: str = "hermes"
) -> dict[str, Any]:
    external_id = f"{chat_id}:{message_id}" if chat_id and message_id else (message_id or "")
    item: dict[str, Any] = {
        "external_id": external_id,
        "text": str(text or ""),
        "chat_id": chat_id,
        "message_id": message_id,
        "captured_at": _capture_now(),
    }
    item.update(meta or {})
    return {
        "schema_version": 1,
        "kind": "kb.source_evidence",
        "source_id": CAPTURE_SOURCE_ID,
        "connector_id": CAPTURE_CONNECTOR_ID,
        "harness_id": harness_id,
        "collected_at": _capture_now(),
        "requested_journey": "evidence_remember",
        "items": [item],
        "provenance": {
            "source_refs": [f"telegram://chat/{chat_id}/message/{message_id}"],
            "external_ids": [external_id] if external_id else [],
            "retrieval_method": "telegram_capture",
        },
        "privacy": {"classification": "internal", "redactions_applied": []},
        "limits": {"max_items": 1, "truncated": False},
    }


def _evidence_contract_ready() -> bool:
    preview = _descriptor("evidence.remember.preview")
    confirmed = _descriptor("evidence.remember.confirmed")
    if preview is None or confirmed is None:
        return False
    preview_output = preview.get("output_schema")
    confirmed_input = confirmed.get("input_schema")
    if not isinstance(preview_output, dict) or not isinstance(confirmed_input, dict):
        return False
    preview_properties = preview_output.get("properties")
    preview_required = preview_output.get("required")
    if not isinstance(preview_properties, dict) or not isinstance(preview_required, list):
        return False
    if not EVIDENCE_BINDING_FIELDS.issubset(preview_properties) or not EVIDENCE_BINDING_FIELDS.issubset(
        set(preview_required)
    ):
        return False
    input_properties = confirmed_input.get("properties")
    input_required = confirmed_input.get("required")
    if not isinstance(input_properties, dict) or not isinstance(input_required, list) or "envelope" not in input_required:
        return False
    envelope = input_properties.get("envelope")
    if not isinstance(envelope, dict):
        return False
    envelope_properties = envelope.get("properties")
    envelope_required = envelope.get("required")
    return bool(
        isinstance(envelope_properties, dict)
        and isinstance(envelope_required, list)
        and EVIDENCE_ENVELOPE_FIELDS.issubset(envelope_properties)
        and EVIDENCE_ENVELOPE_FIELDS.issubset(set(envelope_required))
    )


def _evidence_preview_binding(
    preview: Any,
    *,
    target: str,
    packet: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    if not isinstance(preview, dict) or preview.get("ok") is not True:
        return None, "preview_not_ready"
    if str(preview.get("status") or "").strip().lower() not in {"confirmation_required", "preview_ready"}:
        return None, "preview_not_ready"
    observed_target = str(preview.get("target") or "").strip()
    if not observed_target or observed_target != target:
        return None, "preview_target_mismatch"
    preview_digest = str(preview.get("preview_digest") or "").strip()
    packet_digest = str(preview.get("evidence_packet_digest") or "").strip()
    if not DESCRIPTOR_DIGEST_RE.fullmatch(preview_digest):
        return None, "invalid_preview_digest"
    if packet_digest != _descriptor_digest(packet):
        return None, "evidence_packet_digest_mismatch"
    idempotency_key = str(preview.get("idempotency_key") or "").strip()
    if not idempotency_key:
        return None, "missing_idempotency_key"
    lease = preview.get("preview_lease")
    if not isinstance(lease, dict) or not str(lease.get("lease_id") or "").strip():
        return None, "invalid_preview_lease"
    try:
        expires_at = _parse_aware_timestamp(lease.get("expires_at"))
    except ValueError:
        return None, "invalid_preview_lease"
    if expires_at <= _dt.datetime.now(_dt.UTC):
        return None, "expired_preview_lease"
    safe_lease = json.loads(json.dumps(lease, ensure_ascii=False, sort_keys=True))
    return {
        "target": target,
        "preview_digest": preview_digest,
        "preview_lease": safe_lease,
        "idempotency_key": idempotency_key,
        "evidence_packet_digest": packet_digest,
    }, ""


def _evidence_confirm_envelope(
    state: Any,
    *,
    target: str,
    actor_id: str,
) -> tuple[dict[str, Any] | None, str]:
    if not _evidence_contract_ready():
        return None, "confirmed_envelope_unavailable"
    if target != _mcp_target():
        return None, "active_target_mismatch"
    if not isinstance(state, dict) or str(state.get("target") or "") != target:
        return None, "stored_target_mismatch"
    packet = state.get("packet")
    binding = state.get("preview_binding")
    if not isinstance(packet, dict) or not isinstance(binding, dict):
        return None, "invalid_preview_state"
    rebound, reason = _evidence_preview_binding(
        {"ok": True, "status": "preview_ready", **binding},
        target=target,
        packet=packet,
    )
    if rebound is None:
        return None, reason
    return {
        **rebound,
        "evidence_packet": packet,
        "user_confirmation": {
            "confirmed": True,
            "confirmed_at": _utc_now_text(),
            "surface": "telegram",
            "actor_id": str(actor_id or "").strip(),
        },
    }, ""


def _render_capture_command(
    ctx: Any, target: str, args: str, *, event: Any = None, source: Any = None, session_store: Any = None
) -> dict[str, Any]:
    preview_tool = _descriptor_tool_name(target, "evidence.remember.preview")
    confirmed_tool = _descriptor_tool_name(target, "evidence.remember.confirmed")
    if not preview_tool or not confirmed_tool or not _evidence_contract_ready():
        return _capability_unavailable(
            "KB Capture",
            ("evidence.remember.preview", "evidence.remember.confirmed"),
            message="Evidence capture is temporarily unavailable until evidence.remember.preview/confirmed is released.",
        )
    session_id = _conversation_state_id(session_store, source)
    text = (args or "").strip()
    if text.lower() == "cancel":
        _clear_capture_preview_state(session_id)
        return {"title": "KB Capture", "status": "cancelled", "text": "KB Capture\nPending evidence preview cancelled.", "actions": []}
    if text.lower() == "confirm":
        state, reason = _get_capture_preview_state(session_id, source)
        if state is None:
            return {"title": "KB Capture", "text": f"KB Capture\nNothing to confirm ({reason}). Reply /kb capture to a message first.", "actions": []}
        envelope, reason = _evidence_confirm_envelope(
            state,
            target=target,
            actor_id=_telegram_user_id(source),
        )
        if envelope is None:
            return {
                "title": "KB Capture",
                "status": "blocked",
                "text": f"KB Capture\nConfirmation blocked ({reason}). No KB state changed.",
                "actions": [],
            }
        _, data, errors = _dispatch_first(
            ctx, target,
            [("evidence.remember.confirmed", {"envelope": envelope})],
        )
        if data is None:
            return _render_error("KB Capture", target, errors)
        card = _render_evidence_completion(data, title="KB Capture")
        if card["completion"]["complete"]:
            _clear_capture_preview_state(session_id)
        return card
    chat_id, message_id, captured_text, meta = _capture_target_from_event(event, text)
    if not captured_text:
        return {"title": "KB Capture", "text": "KB Capture\nReply /kb capture to a message, or send /kb capture <text>.", "actions": []}
    packet = _build_telegram_capture_packet(chat_id, message_id, captured_text, meta)
    _, data, errors = _dispatch_first(ctx, target, [("evidence.remember.preview", {"evidence_packet": packet})])
    if data is None:
        return _render_error("KB Capture", target, errors)
    binding, reason = _evidence_preview_binding(data, target=target, packet=packet)
    if binding is None:
        return {
            "title": "KB Capture",
            "status": "blocked",
            "text": f"KB Capture\nPreview binding is invalid ({reason}). No KB state changed.",
            "actions": [],
        }
    _store_capture_preview_state(
        session_id,
        source=source,
        target=target,
        packet=packet,
        preview_binding=binding,
    )
    preview = _short(captured_text, "")[:160]
    lines = ["KB Capture - preview", f"Will capture as {CAPTURE_SOURCE_ID} (id {chat_id}:{message_id})."]
    if preview:
        lines.append(f"“{preview}”")
    lines.append("Confirm: /kb capture confirm")
    return {"title": "KB Capture", "text": "\n".join(lines), "actions": []}


def _matching_readback_identity(receipt: dict[str, Any], readback: dict[str, Any]) -> dict[str, str] | None:
    shared: dict[str, str] = {}
    for key in ("object_id", "ledger_id", "transaction_id", "receipt_id", "operation_id"):
        expected = str(receipt.get(key) or "").strip()
        observed = str(readback.get(key) or "").strip()
        if not expected or not observed:
            continue
        if expected != observed:
            return None
        shared[key] = expected
    return shared or None


def _matching_readback_digest(receipt: dict[str, Any], readback: dict[str, Any]) -> dict[str, str] | None:
    shared: dict[str, str] = {}
    for key in ("content_digest", "state_digest", "ledger_digest", "object_digest", "receipt_digest"):
        expected = str(receipt.get(key) or "").strip()
        observed = str(readback.get(key) or "").strip()
        if not expected or not observed:
            continue
        if expected != observed or not DESCRIPTOR_DIGEST_RE.fullmatch(expected):
            return None
        shared[key] = expected
    return shared or None


def _normalized_digest(value: Any) -> str:
    text = str(value or "").strip().lower()
    if DESCRIPTOR_DIGEST_RE.fullmatch(text):
        return text
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return f"sha256:{text}"
    return ""


def _generated_completion_contract_ready(capability: str) -> bool:
    descriptor = _descriptor(capability)
    schema = descriptor.get("output_schema") if isinstance(descriptor, dict) else None
    if not isinstance(schema, dict):
        return False
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = set(schema.get("required") or [])
    if not {"completion", "receipt", "readback"} <= required:
        return False
    completion = properties.get("completion") if isinstance(properties.get("completion"), dict) else {}
    receipt = properties.get("receipt") if isinstance(properties.get("receipt"), dict) else {}
    readback = properties.get("readback") if isinstance(properties.get("readback"), dict) else {}
    for section in (completion, receipt, readback):
        section_properties = section.get("properties") if isinstance(section.get("properties"), dict) else {}
        route = section_properties.get("route") if isinstance(section_properties.get("route"), dict) else {}
        if route.get("const") != capability:
            return False
    completion_required = set(completion.get("required") or [])
    return {"route", "action", "affected_ids", "request", "confirmation", "transaction_id"} <= completion_required


def _review_completion_expectation(
    capability: str,
    args: dict[str, Any],
) -> dict[str, Any]:
    confirmation = args.get("user_confirmation") if isinstance(args.get("user_confirmation"), dict) else {}
    preview_lease = confirmation.get("preview_lease") if isinstance(confirmation.get("preview_lease"), dict) else {}
    requested_ids = [str(item) for item in (args.get("proposal_ids") or []) if str(item)]
    lease_ids = [str(item) for item in (preview_lease.get("proposal_ids") or []) if str(item)]
    is_restore = capability.endswith("restore_confirmed")
    affected_ids = lease_ids if is_restore and lease_ids else requested_ids
    return {
        "route": capability,
        "action": "review_restore" if is_restore else "review_decision",
        "affected_ids": affected_ids,
        "decision": str(args.get("decision") or ("restore" if is_restore else "")),
        "target_status": str(args.get("target_status") or ("pending_approval" if is_restore else "")),
        "source_transaction_id": str(args.get("transaction_id") or args.get("source_transaction_id") or ""),
        "actor": str(args.get("actor") or ""),
        "source": str(args.get("source") or ""),
        "session_id": str(args.get("session_id") or ""),
        "preview_lease": dict(preview_lease),
        "confirmation": dict(confirmation),
    }


def _completion_readback_freshness(
    readback: dict[str, Any],
    *,
    receipt: dict[str, Any],
    confirmation: dict[str, Any],
) -> str | None:
    try:
        observed_at = _parse_aware_timestamp(readback.get("observed_at"))
    except ValueError:
        return "readback_timestamp_invalid"
    now = _dt.datetime.now(_dt.UTC)
    if observed_at > now + _dt.timedelta(seconds=COMPLETION_CLOCK_SKEW_SECONDS):
        return "readback_future"
    if observed_at < now - _dt.timedelta(seconds=COMPLETION_READBACK_TTL_SECONDS):
        return "readback_stale"
    related_times: list[_dt.datetime] = []
    for value in (
        confirmation.get("confirmed_at"),
        receipt.get("generated_at"),
        receipt.get("created_at"),
        receipt.get("committed_at"),
    ):
        if value in (None, ""):
            continue
        try:
            related_times.append(_parse_aware_timestamp(value))
        except ValueError:
            return "request_receipt_timestamp_invalid"
    if any(
        observed_at + _dt.timedelta(seconds=COMPLETION_CLOCK_SKEW_SECONDS) < related_at
        for related_at in related_times
    ):
        return "readback_precedes_request_or_receipt"
    return None


def _request_bound_review_completion(data: Any, expected: dict[str, Any]) -> dict[str, Any]:
    capability = str(expected.get("route") or "")
    if not _generated_completion_contract_ready(capability):
        return {"complete": False, "reason": "generated_completion_contract_missing"}
    truth = _completion_truth(data, mutation_required=True)
    if not truth["accepted"]:
        return {"complete": False, **{key: value for key, value in truth.items() if key != "accepted"}}
    if not isinstance(data, dict) or data.get("ok") is not True:
        return {"complete": False, "reason": "invalid_response"}
    completion = data.get("completion") if isinstance(data.get("completion"), dict) else {}
    receipt = data.get("receipt") if isinstance(data.get("receipt"), dict) else {}
    readback = data.get("readback") if isinstance(data.get("readback"), dict) else {}
    if any(section.get("route") != capability for section in (completion, receipt, readback)):
        return {"complete": False, "reason": "route_mismatch"}
    if completion.get("action") != expected.get("action"):
        return {"complete": False, "reason": "action_mismatch"}
    expected_ids = list(expected.get("affected_ids") or [])
    if not expected_ids or any(
        section.get("affected_ids") != expected_ids for section in (completion, receipt, readback)
    ):
        return {"complete": False, "reason": "affected_ids_mismatch"}
    if expected.get("action") == "review_decision" and completion.get("decision") != expected.get("decision"):
        return {"complete": False, "reason": "decision_mismatch"}
    if expected.get("action") == "review_restore":
        if completion.get("target_status") != expected.get("target_status"):
            return {"complete": False, "reason": "target_status_mismatch"}
        if completion.get("source_transaction_id") != expected.get("source_transaction_id"):
            return {"complete": False, "reason": "source_transaction_mismatch"}
    if any(str(section.get("state") or "").lower() != "applied" for section in (completion, receipt, readback)):
        return {"complete": False, "reason": "non_terminal_status"}
    if receipt.get("ok") is not True or receipt.get("saved") is not True or readback.get("ok") is not True:
        return {"complete": False, "reason": "unverified_receipt"}
    transaction_id = str(completion.get("transaction_id") or "")
    receipt_id = str(receipt.get("receipt_id") or "")
    if not transaction_id or any(str(section.get("transaction_id") or "") != transaction_id for section in (receipt, readback)):
        return {"complete": False, "reason": "transaction_mismatch"}
    if not receipt_id or str(readback.get("receipt_id") or "") != receipt_id:
        return {"complete": False, "reason": "identity_mismatch"}
    receipt_digest = _normalized_digest(receipt.get("receipt_digest"))
    if not receipt_digest or _normalized_digest(readback.get("receipt_digest")) != receipt_digest:
        return {"complete": False, "reason": "digest_mismatch"}
    digest_body = dict(receipt)
    digest_body.pop("receipt_digest", None)
    if _descriptor_digest(digest_body) != receipt_digest:
        return {"complete": False, "reason": "receipt_digest_mismatch"}
    if not _normalized_digest(readback.get("content_digest")):
        return {"complete": False, "reason": "readback_digest_missing"}
    confirmation = completion.get("confirmation") if isinstance(completion.get("confirmation"), dict) else {}
    expected_confirmation = expected.get("confirmation") if isinstance(expected.get("confirmation"), dict) else {}
    if confirmation.get("confirmed") is not True or confirmation.get("confirmation_digest") != _descriptor_digest(expected_confirmation):
        return {"complete": False, "reason": "confirmation_mismatch"}
    freshness_error = _completion_readback_freshness(
        readback,
        receipt=receipt,
        confirmation=expected_confirmation,
    )
    if freshness_error:
        return {"complete": False, "reason": freshness_error}
    request = completion.get("request") if isinstance(completion.get("request"), dict) else {}
    lease = expected.get("preview_lease") if isinstance(expected.get("preview_lease"), dict) else {}
    preview_digest = _normalized_digest(lease.get("preview_hash"))
    preview_lease_id = str(lease.get("preview_lease_id") or "")
    if not preview_digest or request.get("preview_digest") != preview_digest:
        return {"complete": False, "reason": "preview_digest_mismatch"}
    if not preview_lease_id or request.get("preview_lease_id") != preview_lease_id:
        return {"complete": False, "reason": "preview_lease_mismatch"}
    if request.get("idempotency_key") != transaction_id:
        return {"complete": False, "reason": "idempotency_mismatch"}
    request_payload = {
        "route": capability,
        "affected_ids": expected_ids,
        "decision": str(expected.get("decision") or ""),
        "target_status": str(expected.get("target_status") or ""),
        "source_transaction_id": str(expected.get("source_transaction_id") or ""),
        "actor": str(expected.get("actor") or ""),
        "source": str(expected.get("source") or ""),
        "session_id": str(expected.get("session_id") or ""),
        "preview_lease": lease,
        "idempotency_key": transaction_id,
    }
    if request.get("request_digest") != _descriptor_digest(request_payload):
        return {"complete": False, "reason": "request_digest_mismatch"}
    return {
        "complete": True,
        "reason": "verified",
        "status": "applied",
        "identity": {"transaction_id": transaction_id, "receipt_id": receipt_id},
        "digest": str(readback.get("content_digest")),
    }


def _request_bound_workflow_completion(data: Any, envelope: dict[str, Any]) -> dict[str, Any]:
    capability = "workflow.start_confirmed"
    if not _generated_completion_contract_ready(capability):
        return {"complete": False, "reason": "generated_completion_contract_missing"}
    truth = _completion_truth(data, mutation_required=True)
    if not truth["accepted"]:
        return {"complete": False, **{key: value for key, value in truth.items() if key != "accepted"}}
    if not isinstance(data, dict) or data.get("ok") is not True:
        return {"complete": False, "reason": "invalid_response"}
    completion = data.get("completion") if isinstance(data.get("completion"), dict) else {}
    receipt = data.get("receipt") if isinstance(data.get("receipt"), dict) else {}
    readback = data.get("readback") if isinstance(data.get("readback"), dict) else {}
    if any(section.get("route") != capability for section in (completion, receipt, readback)):
        return {"complete": False, "reason": "route_mismatch"}
    if completion.get("action") != "workflow_start":
        return {"complete": False, "reason": "action_mismatch"}
    plan = envelope.get("plan") if isinstance(envelope.get("plan"), dict) else {}
    confirmation_packet = envelope.get("user_confirmation") if isinstance(envelope.get("user_confirmation"), dict) else {}
    workflow_id = str(plan.get("workflow_id") or "")
    transaction_id = str(plan.get("idempotency_key") or "")
    run_id = str(completion.get("run_id") or "")
    if not workflow_id or completion.get("workflow_id") != workflow_id or not run_id:
        return {"complete": False, "reason": "workflow_identity_mismatch"}
    if completion.get("transaction_id") != transaction_id or any(
        section.get("transaction_id") != transaction_id for section in (receipt, readback)
    ):
        return {"complete": False, "reason": "transaction_mismatch"}
    affected_ids = [run_id]
    if any(section.get("affected_ids") != affected_ids for section in (completion, receipt, readback)):
        return {"complete": False, "reason": "affected_ids_mismatch"}
    state = str(completion.get("state") or "").lower()
    if state not in {"started", "replayed"} or any(
        str(section.get("state") or "").lower() != state for section in (receipt, readback)
    ):
        return {"complete": False, "reason": "non_terminal_status"}
    if receipt.get("ok") is not True or receipt.get("saved") is not True or readback.get("ok") is not True:
        return {"complete": False, "reason": "unverified_receipt"}
    receipt_id = str(receipt.get("receipt_id") or "")
    if not receipt_id or readback.get("receipt_id") != receipt_id:
        return {"complete": False, "reason": "identity_mismatch"}
    receipt_digest = _normalized_digest(receipt.get("receipt_digest"))
    if not receipt_digest or _normalized_digest(readback.get("receipt_digest")) != receipt_digest:
        return {"complete": False, "reason": "digest_mismatch"}
    digest_body = dict(receipt)
    digest_body.pop("receipt_digest", None)
    if _descriptor_digest(digest_body) != receipt_digest:
        return {"complete": False, "reason": "receipt_digest_mismatch"}
    if not _normalized_digest(readback.get("content_digest")):
        return {"complete": False, "reason": "readback_digest_missing"}
    confirmation = completion.get("confirmation") if isinstance(completion.get("confirmation"), dict) else {}
    if confirmation.get("confirmed") is not True or confirmation.get("confirmation_digest") != _descriptor_digest(confirmation_packet):
        return {"complete": False, "reason": "confirmation_mismatch"}
    freshness_error = _completion_readback_freshness(
        readback,
        receipt=receipt,
        confirmation=confirmation_packet,
    )
    if freshness_error:
        return {"complete": False, "reason": freshness_error}
    request = completion.get("request") if isinstance(completion.get("request"), dict) else {}
    expected_request = {
        "preview_digest": _descriptor_digest(plan),
        "preview_lease_id": str(plan.get("request_id") or transaction_id),
        "request_digest": _descriptor_digest(envelope),
        "idempotency_key": transaction_id,
    }
    if request != expected_request:
        return {"complete": False, "reason": "request_binding_mismatch"}
    return {
        "complete": True,
        "reason": "verified",
        "status": state,
        "identity": {"transaction_id": transaction_id, "receipt_id": receipt_id, "run_id": run_id},
        "digest": str(readback.get("content_digest")),
    }


def _completion_truth(data: Any, *, mutation_required: bool) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {"accepted": False, "reason": "contradictory_invalid_response"}
    failed_statuses = {
        "blocked",
        "cancelled",
        "canceled",
        "error",
        "failed",
        "partial",
        "partially_applied",
        "completed_with_errors",
        "rejected",
    }

    def inspect_value(value: Any, path: str) -> dict[str, Any] | None:
        if isinstance(value, list):
            for index, item in enumerate(value):
                failure = inspect_value(item, f"{path}_{index}")
                if failure:
                    return failure
            return None
        if not isinstance(value, dict):
            return None
        diagnostic_branch = "_preview" in path or "_publication" in path
        if value.get("isError") is True:
            return {"accepted": False, "reason": f"contradictory_{path}_isError"}
        for key in ("error", "errors"):
            error_value = value.get(key)
            if error_value not in (None, "", [], {}):
                return {"accepted": False, "reason": f"contradictory_{path}_{key}"}
        for key in ("status", "state"):
            status = str(value.get(key) or "").strip().lower()
            if status in failed_statuses:
                return {
                    "accepted": False,
                    "reason": f"contradictory_{path}_{key}",
                    "status": status,
                }
        for key in ("ok", "success"):
            if value.get(key) is False and not diagnostic_branch:
                return {"accepted": False, "reason": f"contradictory_{path}_{key}"}
        if mutation_required and value.get("mutation_performed") is False and not diagnostic_branch:
            return {
                "accepted": False,
                "reason": f"contradictory_{path}_mutation_performed",
            }
        for key in ("saved", "applied"):
            if value.get(key) is False and not diagnostic_branch:
                return {"accepted": False, "reason": f"contradictory_{path}_{key}"}
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                clean_key = re.sub(r"[^A-Za-z0-9]+", "_", str(key)).strip("_") or "nested"
                failure = inspect_value(child, f"{path}_{clean_key}")
                if failure:
                    return failure
        return None

    failure = inspect_value(data, "top")
    if failure:
        return failure
    return {"accepted": True, "reason": "consistent"}


def _durable_completion(data: Any) -> dict[str, Any]:
    """Return fail-closed proof for wording that claims a durable mutation.

    Transport success and an optimistic ``ok`` flag are never sufficient. The
    engine must return an explicitly confirmed receipt, a verified post-write
    readback of the same durable identity, and an agreeing content/state digest.
    """
    truth = _completion_truth(data, mutation_required=True)
    if not truth["accepted"]:
        return {"complete": False, **{key: value for key, value in truth.items() if key != "accepted"}}
    if not isinstance(data, dict) or data.get("ok") is not True:
        return {"complete": False, "reason": "invalid_response"}
    status = str(data.get("status") or data.get("state") or "").strip().lower()
    if status not in {"applied", "committed", "completed", "confirmed"}:
        return {"complete": False, "reason": "non_terminal_status", "status": status}
    receipt = data.get("receipt") if isinstance(data.get("receipt"), dict) else {}
    if receipt.get("confirmed") is not True:
        return {"complete": False, "reason": "unconfirmed_receipt", "status": status}
    readback = data.get("readback") if isinstance(data.get("readback"), dict) else {}
    readback_status = str(readback.get("status") or readback.get("state") or "").strip().lower()
    if readback_status not in {"current", "matched", "verified"}:
        return {"complete": False, "reason": "missing_readback", "status": status}
    identity = _matching_readback_identity(receipt, readback)
    if identity is None:
        return {"complete": False, "reason": "identity_mismatch", "status": status}
    digest = _matching_readback_digest(receipt, readback)
    if digest is None:
        return {"complete": False, "reason": "digest_mismatch", "status": status}
    return {
        "complete": True,
        "reason": "verified",
        "status": status,
        "identity": identity,
        "digest": next(iter(digest.values())),
        "digests": digest,
    }


def _evidence_completion(data: Any) -> dict[str, Any]:
    truth = _completion_truth(data, mutation_required=True)
    if not truth["accepted"]:
        return {"complete": False, **{key: value for key, value in truth.items() if key != "accepted"}}
    if not isinstance(data, dict) or data.get("ok") is not True:
        return {"complete": False, "reason": "invalid_response"}
    if str(data.get("status") or "").strip().lower() not in {"remembered", "completed", "confirmed"}:
        return {"complete": False, "reason": "non_terminal_status"}
    receipt = data.get("receipt") if isinstance(data.get("receipt"), dict) else {}
    readback = data.get("readback") if isinstance(data.get("readback"), dict) else {}
    if receipt.get("confirmed") is not True:
        return {"complete": False, "reason": "unconfirmed_receipt"}
    if str(readback.get("status") or "").strip().lower() not in {"current", "matched", "verified"}:
        return {"complete": False, "reason": "missing_readback"}
    identity = _matching_readback_identity(receipt, readback)
    if identity is None:
        return {"complete": False, "reason": "identity_mismatch"}
    digest = _matching_readback_digest(receipt, readback)
    if digest is None:
        return {"complete": False, "reason": "digest_mismatch"}
    return {
        "complete": True,
        "reason": "verified",
        "identity": identity,
        "digest": next(iter(digest.values())),
        "digests": digest,
    }


def _render_evidence_completion(data: Any, *, title: str) -> dict[str, Any]:
    proof = _evidence_completion(data)
    if proof["complete"]:
        text = f"{title}\nEvidence remembered. No semantic object update or publication was claimed."
    else:
        text = (
            f"{title}\nEvidence outcome is not yet verified ({proof['reason']}). "
            "The confirmation remains resumable; no durable success is claimed."
        )
    return {"title": title, "text": text, "actions": [], "completion": proof}


def _write_landed(data: Any) -> bool:
    return bool(_durable_completion(data)["complete"])


def _render_write_command(
    ctx: Any, target: str, args: str, *, event: Any = None, source: Any = None, session_store: Any = None
) -> dict[str, Any]:
    """Remember a freeform evidence note through a digest-bound preview envelope."""
    preview_tool = _descriptor_tool_name(target, "evidence.remember.preview")
    confirmed_tool = _descriptor_tool_name(target, "evidence.remember.confirmed")
    if not preview_tool or not confirmed_tool or not _evidence_contract_ready():
        return _capability_unavailable(
            "KB Write",
            ("evidence.remember.preview", "evidence.remember.confirmed"),
            message="Evidence remembering is temporarily unavailable until evidence.remember.preview/confirmed is released.",
        )
    session_id = _conversation_state_id(session_store, source)
    write_session = f"{session_id}:write" if session_id else ""
    text = (args or "").strip()
    if text.lower() == "cancel":
        _clear_capture_preview_state(write_session)
        return {"title": "KB Write", "status": "cancelled", "text": "KB Write\nPending evidence preview cancelled.", "actions": []}
    if text.lower() == "confirm":
        state, reason = _get_capture_preview_state(write_session, source)
        if state is None:
            return {"title": "KB Write", "text": f"KB Write\nNothing to confirm ({reason}). Send /kb write <note> first.", "actions": []}
        envelope, reason = _evidence_confirm_envelope(
            state,
            target=target,
            actor_id=_telegram_user_id(source),
        )
        if envelope is None:
            return {
                "title": "KB Write",
                "status": "blocked",
                "text": f"KB Write\nConfirmation blocked ({reason}). No KB state changed.",
                "actions": [],
            }
        _, data, errors = _dispatch_first(
            ctx, target,
            [("evidence.remember.confirmed", {"envelope": envelope})],
        )
        if data is None:
            return _render_error("KB Write", target, errors)
        card = _render_evidence_completion(data, title="KB Write")
        if card["completion"]["complete"]:
            _clear_capture_preview_state(write_session)
        return card
    anchor = ""
    body = text
    if " | " in text:
        anchor_part, _, body_part = text.partition(" | ")
        anchor = anchor_part.strip()
        body = body_part.strip()
    if not body:
        return {"title": "KB Write", "text": "KB Write\nSend /kb write <note>, or /kb write <object> | <note> to anchor it.", "actions": []}
    chat_id = _short(getattr(source, "chat_id", ""), "")
    message_id = _short(getattr(event, "message_id", ""), "")
    meta: dict[str, Any] = {"note": True}
    if anchor:
        meta["anchor"] = anchor
    packet = _build_telegram_capture_packet(chat_id, message_id, body, meta)
    _, data, errors = _dispatch_first(ctx, target, [("evidence.remember.preview", {"evidence_packet": packet})])
    if data is None:
        return _render_error("KB Write", target, errors)
    binding, reason = _evidence_preview_binding(data, target=target, packet=packet)
    if binding is None:
        return {
            "title": "KB Write",
            "status": "blocked",
            "text": f"KB Write\nPreview binding is invalid ({reason}). No KB state changed.",
            "actions": [],
        }
    _store_capture_preview_state(
        write_session,
        source=source,
        target=target,
        packet=packet,
        preview_binding=binding,
    )
    preview = _short(body, "")[:160]
    lines = ["KB Write - preview", f"Will remember as evidence ({CAPTURE_SOURCE_ID}); no semantic write is implied."]
    if anchor:
        lines.append(f"Anchor: {anchor}")
    if preview:
        lines.append(f"“{preview}”")
    lines.append("Confirm: /kb write confirm")
    return {"title": "KB Write", "text": "\n".join(lines), "actions": []}


def build_pre_gateway_dispatch_hook(ctx: Any) -> Callable[..., dict[str, str] | None]:
    def _hook(event: Any = None, gateway: Any = None, session_store: Any = None, **_: Any) -> dict[str, str] | None:
        source = getattr(event, "source", None)
        if _platform_name(getattr(source, "platform", None)) != "telegram":
            return None
        text = getattr(event, "text", "")
        command = _command_from_text(text)
        prose_command = _prose_kb_command_from_text(text) if command is None else None
        bare_decision = _bare_queue_reply_decision(text)
        visible_all_decision = _visible_scope_all_decision(text)
        if command is None and prose_command is None and not bare_decision and not visible_all_decision:
            return None
        if not _authorized_for_gateway(gateway, source):
            return None
        adapter = _adapter_for(gateway, source)
        if adapter is None:
            logger.debug("kb_journeys: no Telegram adapter available")
            return None
        if visible_all_decision:
            session_id = _conversation_state_id(session_store, source)
            card = _render_visible_scope_all_decision(
                ctx,
                _mcp_target(),
                session_id=session_id,
                decision=visible_all_decision,
            )
        elif bare_decision:
            session_id = _session_id_for_queue_reply_state(session_store, source)
            state = _get_iterative_queue_reply_state(session_id)
            if not state:
                return None
            card = _render_iterative_queue_reply_decision(
                ctx,
                _mcp_target(),
                session_id=session_id,
                state=state,
                decision=bare_decision,
            )
        else:
            if prose_command is not None:
                command, args = prose_command
            else:
                args = _command_args_from_text(text)
            card = _card_for_command(
                ctx,
                command,
                args=args,
                adapter=adapter,
                gateway=gateway,
                source=source,
                session_store=session_store,
                event=event,
            )
        gateway_rewrite = card.pop("_gateway_rewrite", "")
        if gateway_rewrite:
            return {"action": "rewrite", "text": str(gateway_rewrite)}
        _run_delivery(_send_card(adapter, event, card))
        return {"action": "skip", "reason": "kb_journeys"}

    return _hook


def _on_post_llm_call(
    *,
    session_id: str = "",
    assistant_response: str = "",
    platform: str = "",
    **_: Any,
) -> None:
    _emit_probe_telemetry()
    if str(platform or "").lower() != "telegram":
        return
    _record_iterative_queue_reply_state(session_id, assistant_response)


def register(ctx: Any) -> None:
    def _command_help(_: str = "") -> str:
        return "Use /kb in Telegram. Try: /kb status, /kb sync, or /kb review."

    for command in sorted(MENU_COMMANDS):
        try:
            ctx.register_command(
                command,
                _command_help,
                description="KB status, sync, and review.",
            )
        except Exception:
            logger.debug("kb_journeys: failed to register /%s", command, exc_info=True)
    _register_integration_transport(ctx)
    _activate_probe_telemetry(ctx)
    ctx.register_hook("transform_tool_result", _compact_attention_tool_result)
    ctx.register_hook("pre_gateway_dispatch", build_pre_gateway_dispatch_hook(ctx))
    ctx.register_hook("post_llm_call", _on_post_llm_call)
