#!/usr/bin/env python3
"""Validate Daily Skill Friction ledger cases without modifying the repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schema" / "case.schema.json"
CASES_ROOT = REPO_ROOT / "cases"
ALLOWED_CASE_AUXILIARY = PurePosixPath("cases/.gitkeep")
MAX_CASE_BYTES = 256 * 1024

CASE_ID_RE = re.compile(
    r"^DSF-([0-9a-f]{8})-([0-9a-f]{4})-"
    r"(7[0-9a-f]{3})-([89ab][0-9a-f]{3})-([0-9a-f]{12})$"
)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PR_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[1-9][0-9]*$"
)
STABLE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$")
REPAIR_ID_RE = re.compile(r"^R[1-9][0-9]*$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)

STATUS_VALUES = {
    "watching",
    "proposed",
    "approved",
    "implemented",
    "observing",
    "closed",
    "dormant",
    "superseded",
}
CLASSIFICATION_VALUES = {"repo-local", "cross-workflow", "global-invariant"}
SOURCE_KIND_VALUES = {"human-root", "automation-derived", "legacy-migration"}
SUPPORT_VALUES = {"novel", "repeated"}
URGENCY_LEVEL_VALUES = {"normal", "high-signal"}
HIGH_SIGNAL_REASON_VALUES = {
    "data-loss-or-corruption",
    "recovery-boundary-failure",
    "credential-or-private-data-exposure",
    "unauthorized-access",
    "unauthorized-irreversible-external-side-effect",
    "material-authority-boundary-breach",
}
SIGNAL_TYPE_VALUES = {
    "explicit-human-correction",
    "repeated-retry",
    "manual-workaround",
    "blocked-operation",
    "unexpected-result",
    "policy-mismatch",
    "validation-failure",
}
APPLICABILITY_VALUES = {"present", "changed", "absent", "unknown"}
REPAIR_ACTION_VALUES = {"install", "amend", "remove-forward"}
REPAIR_STATE_VALUES = {"planned", "open", "merged", "superseded"}
EFFECTIVENESS_METHOD_VALUES = {"none", "deterministic", "behavioral", "both"}
EFFECTIVENESS_STATE_VALUES = {"not-started", "monitoring", "passed", "failed"}
DETERMINISTIC_RESULT_VALUES = {"pending", "passed", "failed"}
STATUS_TRANSITIONS = {
    "watching": {"watching", "proposed", "dormant", "superseded"},
    "proposed": {"proposed", "approved", "dormant", "superseded"},
    "approved": {"approved", "implemented", "superseded"},
    "implemented": {"implemented", "observing", "superseded"},
    "observing": {"observing", "closed", "superseded"},
    "closed": {"closed", "proposed", "superseded"},
    "dormant": {"dormant", "watching", "proposed", "superseded"},
    "superseded": {"superseded"},
}
REPAIR_STATE_TRANSITIONS = {
    "planned": {"planned", "open", "merged", "superseded"},
    "open": {"open", "merged", "superseded"},
    "merged": {"merged", "superseded"},
    "superseded": {"superseded"},
}

FORBIDDEN_FIELD_WORDS = {
    "secret",
    "secrets",
    "password",
    "passwords",
    "passwd",
    "credential",
    "credentials",
    "token",
    "tokens",
    "auth",
    "authentication",
    "authorization",
    "cookie",
    "cookies",
    "raw",
    "excerpt",
    "excerpts",
    "transcript",
    "transcripts",
    "rollout",
    "rollouts",
    "prompt",
    "prompts",
    "payload",
    "payloads",
    "log",
    "logs",
    "conversation",
    "conversations",
}
FORBIDDEN_FIELD_COMBINATIONS = {
    frozenset(("api", "key")),
    frozenset(("access", "key")),
    frozenset(("private", "key")),
    frozenset(("access", "token")),
    frozenset(("refresh", "token")),
    frozenset(("bearer", "token")),
}
SENSITIVE_VALUE_MARKERS = (
    "-----begin private key-----",
    "-----begin rsa private key-----",
    "authorization: bearer ",
    "password=",
    "passwd=",
    "api_key=",
    "access_token=",
    "refresh_token=",
)
RAW_SOURCE_MARKERS = (
    "rollout-",
    "/sessions/",
    "/archived_sessions/",
    "/.codex/",
)
FILE_URI_RE = re.compile(r"(?:^|[\s\"'])file:", re.IGNORECASE)
CREDENTIAL_VALUE_PATTERNS = (
    re.compile(r"\bbearer\s+[A-Za-z0-9._~-]{8,}", re.IGNORECASE),
    re.compile(
        r"\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd)"
        r"\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
)
BARE_CREDENTIAL_VALUE_PATTERNS = (
    re.compile(
        r"\bcodex_synth_v[0-9]+_(?:access|refresh|id|api_key|bearer)_"
        r"[A-Za-z0-9][A-Za-z0-9_-]*\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", re.IGNORECASE),
    re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
        r"[A-Za-z0-9_-]{10,}\b"
    ),
)

TOP_LEVEL_FIELDS = {
    "schema_version",
    "revision",
    "id",
    "title",
    "status",
    "support",
    "classification",
    "source_kind",
    "urgency",
    "causal",
    "evidence",
    "evidence_last_seen",
    "applicability",
    "currentness_checked_at",
    "scope",
    "lifecycle",
    "lifecycle_changed_at",
    "repairs",
    "effectiveness",
}


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a key."""


@dataclass(frozen=True)
class EvidenceStats:
    first_observed_at: datetime | None
    last_observed_at: datetime | None
    occurrence_count: int
    root_task_count: int
    workflow_count: int
    repository_count: int
    opportunity_count: int
    causal_signature_count: int
    has_human_correction: bool
    has_repeated_signature: bool
    source_event_ids: frozenset[str]


def _object_pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _field_words(name: str) -> set[str]:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return {word.lower() for word in re.split(r"[^A-Za-z0-9]+", separated) if word}


def _contains_raw_source_locator(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in RAW_SOURCE_MARKERS) or bool(
        FILE_URI_RE.search(value)
    )


def _scan_prohibited_content(value: Any, where: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            words = _field_words(key)
            if words & FORBIDDEN_FIELD_WORDS or any(
                combination <= words for combination in FORBIDDEN_FIELD_COMBINATIONS
            ):
                errors.append(
                    f"{where}.{key}: prohibited raw-evidence or credential-shaped field name"
                )
            _scan_prohibited_content(child, f"{where}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_prohibited_content(child, f"{where}[{index}]", errors)
    elif isinstance(value, str):
        lowered = value.lower()
        if any(marker in lowered for marker in SENSITIVE_VALUE_MARKERS):
            errors.append(f"{where}: contains credential-shaped material")
        if any(pattern.search(value) for pattern in CREDENTIAL_VALUE_PATTERNS):
            errors.append(f"{where}: contains credential-shaped material")
        if any(pattern.search(value) for pattern in BARE_CREDENTIAL_VALUE_PATTERNS):
            errors.append(f"{where}: contains a bare credential-shaped value")
        if _contains_raw_source_locator(value):
            errors.append(f"{where}: contains a raw rollout or local session locator")


def _require_object(
    value: Any,
    where: str,
    required: set[str],
    allowed: set[str],
    errors: list[str],
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{where}: expected object")
        return None
    for key in sorted(required - value.keys()):
        errors.append(f"{where}.{key}: required field is missing")
    for key in sorted(value.keys() - allowed):
        errors.append(f"{where}.{key}: unknown field")
    return value


def _require_array(
    value: Any,
    where: str,
    errors: list[str],
    *,
    minimum: int = 0,
    maximum: int,
) -> list[Any] | None:
    if not isinstance(value, list):
        errors.append(f"{where}: expected array")
        return None
    if len(value) < minimum:
        errors.append(f"{where}: expected at least {minimum} item(s)")
    if len(value) > maximum:
        errors.append(f"{where}: exceeds the {maximum}-item bound")
    return value


def _string(
    value: Any,
    where: str,
    errors: list[str],
    *,
    minimum: int,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str | None:
    if not isinstance(value, str):
        errors.append(f"{where}: expected string")
        return None
    if len(value) < minimum or len(value) > maximum:
        errors.append(f"{where}: expected {minimum}..{maximum} characters")
    if "\n" in value or "\r" in value:
        errors.append(f"{where}: multiline text is not allowed")
    if pattern is not None and pattern.fullmatch(value) is None:
        errors.append(f"{where}: invalid format")
    return value


def _nullable_string(
    value: Any,
    where: str,
    errors: list[str],
    *,
    minimum: int,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str | None:
    if value is None:
        return None
    return _string(
        value,
        where,
        errors,
        minimum=minimum,
        maximum=maximum,
        pattern=pattern,
    )


def _enum(value: Any, where: str, allowed: set[str], errors: list[str]) -> str | None:
    if not isinstance(value, str) or value not in allowed:
        errors.append(f"{where}: expected one of {', '.join(sorted(allowed))}")
        return None
    return value


def _integer(
    value: Any,
    where: str,
    errors: list[str],
    *,
    minimum: int,
    maximum: int,
) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(f"{where}: expected integer")
        return None
    if value < minimum or value > maximum:
        errors.append(f"{where}: expected value in {minimum}..{maximum}")
    return value


def _date(
    value: Any, where: str, errors: list[str], *, nullable: bool = False
) -> date | None:
    if value is None and nullable:
        return None
    text = _string(value, where, errors, minimum=10, maximum=10)
    if text is None:
        return None
    try:
        parsed = date.fromisoformat(text)
    except ValueError:
        errors.append(f"{where}: expected an ISO calendar date")
        return None
    if parsed.isoformat() != text:
        errors.append(f"{where}: expected canonical YYYY-MM-DD form")
        return None
    return parsed


def _timestamp(
    value: Any, where: str, errors: list[str], *, nullable: bool = False
) -> datetime | None:
    if value is None and nullable:
        return None
    text = _string(value, where, errors, minimum=20, maximum=27)
    if text is None:
        return None
    if TIMESTAMP_RE.fullmatch(text) is None:
        errors.append(f"{where}: expected canonical UTC RFC 3339 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        errors.append(f"{where}: expected a valid UTC RFC 3339 timestamp")
        return None
    if parsed.tzinfo != timezone.utc:
        errors.append(f"{where}: timestamp must use UTC Z suffix")
        return None
    return parsed


def _case_id(value: Any, where: str, errors: list[str]) -> str | None:
    text = _string(value, where, errors, minimum=40, maximum=40)
    if text is None:
        return None
    if CASE_ID_RE.fullmatch(text) is None:
        errors.append(f"{where}: expected DSF- followed by a lowercase UUIDv7")
        return None
    return text


def _uuid7_year(case_id: str, where: str, errors: list[str]) -> int | None:
    match = CASE_ID_RE.fullmatch(case_id)
    if match is None:
        return None
    timestamp_ms = int(match.group(1) + match.group(2), 16)
    try:
        return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc).year
    except (OverflowError, OSError, ValueError):
        errors.append(f"{where}: UUIDv7 contains an invalid Unix timestamp")
        return None


def _validate_case_path(
    relative_path: PurePosixPath, case_id: str | None, errors: list[str]
) -> None:
    parts = relative_path.parts
    if (
        len(parts) != 3
        or parts[0] != "cases"
        or re.fullmatch(r"[0-9]{4}", parts[1]) is None
        or not parts[2].endswith(".json")
    ):
        errors.append(
            "$path: expected cases/<UUIDv7 UTC year>/DSF-<lowercase UUIDv7>.json"
        )
        return
    if case_id is None:
        return
    if parts[2] != f"{case_id}.json":
        errors.append("$path: filename must equal the case id plus .json")
    embedded_year = _uuid7_year(case_id, "$.id", errors)
    if embedded_year is not None and int(parts[1]) != embedded_year:
        errors.append(
            f"$path: directory year {parts[1]} does not match UUIDv7 UTC year {embedded_year}"
        )


def _validate_urgency(
    value: Any, errors: list[str]
) -> tuple[dict[str, Any] | None, set[str]]:
    fields = {"level", "reason", "source_event_ids"}
    obj = _require_object(value, "$.urgency", fields, fields, errors)
    if obj is None:
        return None, set()
    level = _enum(obj.get("level"), "$.urgency.level", URGENCY_LEVEL_VALUES, errors)
    reason = obj.get("reason")
    if reason is not None:
        _enum(reason, "$.urgency.reason", HIGH_SIGNAL_REASON_VALUES, errors)
    event_values = _require_array(
        obj.get("source_event_ids"),
        "$.urgency.source_event_ids",
        errors,
        maximum=16,
    )
    source_event_ids: set[str] = set()
    if event_values is not None:
        for index, value_item in enumerate(event_values):
            where = f"$.urgency.source_event_ids[{index}]"
            event_id = _string(
                value_item,
                where,
                errors,
                minimum=3,
                maximum=200,
                pattern=STABLE_ID_RE,
            )
            if event_id is None:
                continue
            if event_id in source_event_ids:
                errors.append(f"{where}: duplicate urgency evidence source")
            source_event_ids.add(event_id)
    if level == "normal":
        if reason is not None:
            errors.append("$.urgency.reason: normal urgency requires null")
        if source_event_ids:
            errors.append(
                "$.urgency.source_event_ids: normal urgency requires an empty array"
            )
    elif level == "high-signal":
        if reason not in HIGH_SIGNAL_REASON_VALUES:
            errors.append("$.urgency.reason: high-signal requires a closed reason")
        if not source_event_ids:
            errors.append(
                "$.urgency.source_event_ids: high-signal requires current evidence"
            )
    return obj, source_event_ids


def _validate_causal(value: Any, errors: list[str]) -> dict[str, Any] | None:
    fields = {
        "summary",
        "first_observed_at",
        "occurrence_count",
        "root_task_count",
        "workflow_count",
        "repository_count",
        "opportunity_count",
        "causal_signature_count",
    }
    obj = _require_object(value, "$.causal", fields, fields, errors)
    if obj is None:
        return None
    _string(obj.get("summary"), "$.causal.summary", errors, minimum=16, maximum=800)
    _timestamp(obj.get("first_observed_at"), "$.causal.first_observed_at", errors)
    _integer(
        obj.get("occurrence_count"),
        "$.causal.occurrence_count",
        errors,
        minimum=1,
        maximum=256,
    )
    for field in (
        "root_task_count",
        "workflow_count",
        "opportunity_count",
        "causal_signature_count",
    ):
        _integer(
            obj.get(field),
            f"$.causal.{field}",
            errors,
            minimum=1,
            maximum=256,
        )
    _integer(
        obj.get("repository_count"),
        "$.causal.repository_count",
        errors,
        minimum=0,
        maximum=256,
    )
    return obj


def _validate_evidence(value: Any, errors: list[str]) -> EvidenceStats:
    items = _require_array(value, "$.evidence", errors, minimum=1, maximum=256)
    if items is None:
        return EvidenceStats(None, None, 0, 0, 0, 0, 0, 0, False, False, frozenset())

    fields = {
        "root_task_id",
        "workflow_id",
        "opportunity_id",
        "causal_signature",
        "observed_at",
        "signal_type",
        "source_event_ids",
        "source_digest",
        "summary",
        "repository",
    }
    observed_timestamps: list[datetime] = []
    root_ids: set[str] = set()
    workflow_ids: set[str] = set()
    repositories: set[str] = set()
    opportunity_ids: set[str] = set()
    causal_signatures: dict[str, int] = {}
    source_event_ids: set[str] = set()
    seen_entries: set[tuple[Any, ...]] = set()
    has_human_correction = False

    for index, item in enumerate(items):
        where = f"$.evidence[{index}]"
        obj = _require_object(item, where, fields, fields, errors)
        if obj is None:
            continue
        root_id = _string(
            obj.get("root_task_id"),
            f"{where}.root_task_id",
            errors,
            minimum=3,
            maximum=200,
            pattern=STABLE_ID_RE,
        )
        if root_id is not None:
            if _contains_raw_source_locator(root_id):
                errors.append(
                    f"{where}.root_task_id: raw rollout or local session paths are prohibited"
                )
            root_ids.add(root_id)
        workflow_id = _string(
            obj.get("workflow_id"),
            f"{where}.workflow_id",
            errors,
            minimum=3,
            maximum=200,
            pattern=STABLE_ID_RE,
        )
        if workflow_id is not None:
            if _contains_raw_source_locator(workflow_id):
                errors.append(
                    f"{where}.workflow_id: raw rollout or local session paths are prohibited"
                )
            workflow_ids.add(workflow_id)
        opportunity_id = _string(
            obj.get("opportunity_id"),
            f"{where}.opportunity_id",
            errors,
            minimum=3,
            maximum=200,
            pattern=STABLE_ID_RE,
        )
        if opportunity_id is not None:
            if _contains_raw_source_locator(opportunity_id):
                errors.append(
                    f"{where}.opportunity_id: raw rollout or local session paths are prohibited"
                )
            if opportunity_id in opportunity_ids:
                errors.append(f"{where}.opportunity_id: duplicate opportunity")
            opportunity_ids.add(opportunity_id)
        causal_signature = _string(
            obj.get("causal_signature"),
            f"{where}.causal_signature",
            errors,
            minimum=71,
            maximum=71,
            pattern=DIGEST_RE,
        )
        if causal_signature is not None:
            causal_signatures[causal_signature] = (
                causal_signatures.get(causal_signature, 0) + 1
            )
        observed_at = _timestamp(obj.get("observed_at"), f"{where}.observed_at", errors)
        if observed_at is not None:
            observed_timestamps.append(observed_at)
        signal_type = _enum(
            obj.get("signal_type"), f"{where}.signal_type", SIGNAL_TYPE_VALUES, errors
        )
        has_human_correction = (
            has_human_correction or signal_type == "explicit-human-correction"
        )
        event_items = _require_array(
            obj.get("source_event_ids"),
            f"{where}.source_event_ids",
            errors,
            minimum=1,
            maximum=16,
        )
        local_event_ids: set[str] = set()
        if event_items is not None:
            for event_index, event_value in enumerate(event_items):
                event_where = f"{where}.source_event_ids[{event_index}]"
                event_id = _string(
                    event_value,
                    event_where,
                    errors,
                    minimum=3,
                    maximum=200,
                    pattern=STABLE_ID_RE,
                )
                if event_id is None:
                    continue
                if _contains_raw_source_locator(event_id):
                    errors.append(
                        f"{event_where}: raw rollout or local paths are prohibited"
                    )
                if event_id in local_event_ids:
                    errors.append(
                        f"{event_where}: duplicate source event in occurrence"
                    )
                if event_id in source_event_ids:
                    errors.append(
                        f"{event_where}: source event is reused by another occurrence"
                    )
                local_event_ids.add(event_id)
                source_event_ids.add(event_id)
        _string(
            obj.get("source_digest"),
            f"{where}.source_digest",
            errors,
            minimum=71,
            maximum=71,
            pattern=DIGEST_RE,
        )
        _string(obj.get("summary"), f"{where}.summary", errors, minimum=8, maximum=400)
        repository = obj.get("repository")
        if repository is not None:
            validated_repository = _string(
                repository,
                f"{where}.repository",
                errors,
                minimum=3,
                maximum=160,
                pattern=REPOSITORY_RE,
            )
            if validated_repository is not None:
                repositories.add(validated_repository)
        identity = (
            root_id,
            workflow_id,
            opportunity_id,
            causal_signature,
            observed_at,
            signal_type,
        )
        if identity in seen_entries:
            errors.append(f"{where}: duplicate evidence occurrence")
        seen_entries.add(identity)

    return EvidenceStats(
        min(observed_timestamps) if observed_timestamps else None,
        max(observed_timestamps) if observed_timestamps else None,
        len(items),
        len(root_ids),
        len(workflow_ids),
        len(repositories),
        len(opportunity_ids),
        len(causal_signatures),
        has_human_correction,
        any(count >= 2 for count in causal_signatures.values()),
        frozenset(source_event_ids),
    )


def _validate_applicability(value: Any, errors: list[str]) -> dict[str, Any] | None:
    fields = {"state", "summary"}
    obj = _require_object(value, "$.applicability", fields, fields, errors)
    if obj is None:
        return None
    _enum(obj.get("state"), "$.applicability.state", APPLICABILITY_VALUES, errors)
    _string(
        obj.get("summary"), "$.applicability.summary", errors, minimum=8, maximum=500
    )
    return obj


def _validate_scope(value: Any, errors: list[str]) -> dict[str, Any] | None:
    fields = {"target_repository", "global_rationale", "global_invariant_kind"}
    obj = _require_object(value, "$.scope", fields, fields, errors)
    if obj is None:
        return None
    if obj.get("target_repository") is not None:
        _string(
            obj.get("target_repository"),
            "$.scope.target_repository",
            errors,
            minimum=3,
            maximum=160,
            pattern=REPOSITORY_RE,
        )
    if obj.get("global_rationale") is not None:
        _string(
            obj.get("global_rationale"),
            "$.scope.global_rationale",
            errors,
            minimum=16,
            maximum=800,
        )
    if obj.get("global_invariant_kind") is not None:
        _enum(
            obj.get("global_invariant_kind"),
            "$.scope.global_invariant_kind",
            {"authorization", "data-integrity"},
            errors,
        )
    return obj


def _validate_lifecycle(value: Any, errors: list[str]) -> dict[str, Any] | None:
    fields = {
        "created_at",
        "dormant_since",
        "dormant_from_status",
        "superseded_by",
        "revisit_when",
    }
    obj = _require_object(value, "$.lifecycle", fields, fields, errors)
    if obj is None:
        return None
    _timestamp(obj.get("created_at"), "$.lifecycle.created_at", errors)
    _timestamp(
        obj.get("dormant_since"), "$.lifecycle.dormant_since", errors, nullable=True
    )
    dormant_from = obj.get("dormant_from_status")
    if dormant_from is not None:
        _enum(
            dormant_from,
            "$.lifecycle.dormant_from_status",
            {"watching", "proposed"},
            errors,
        )
    if obj.get("superseded_by") is not None:
        _case_id(obj.get("superseded_by"), "$.lifecycle.superseded_by", errors)
    revisit = _require_array(
        obj.get("revisit_when"), "$.lifecycle.revisit_when", errors, maximum=12
    )
    if revisit is not None:
        seen: set[str] = set()
        for index, condition in enumerate(revisit):
            text = _string(
                condition,
                f"$.lifecycle.revisit_when[{index}]",
                errors,
                minimum=8,
                maximum=240,
            )
            if text is not None and text in seen:
                errors.append(f"$.lifecycle.revisit_when[{index}]: duplicate condition")
            if text is not None:
                seen.add(text)
    return obj


def _validate_repairs(
    value: Any, case_id: str | None, errors: list[str]
) -> list[dict[str, Any]]:
    items = _require_array(value, "$.repairs", errors, maximum=64)
    if items is None:
        return []
    fields = {
        "id",
        "repository",
        "action",
        "state",
        "problem_statement",
        "change_summary",
        "pull_request_url",
        "commit",
        "commit_trailer",
        "installed_on",
        "removed_on",
        "replaces_repair_id",
    }
    result: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    repairs_by_id: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(items):
        where = f"$.repairs[{index}]"
        obj = _require_object(item, where, fields, fields, errors)
        if obj is None:
            continue
        repair_id = _string(
            obj.get("id"),
            f"{where}.id",
            errors,
            minimum=2,
            maximum=12,
            pattern=REPAIR_ID_RE,
        )
        if repair_id is not None:
            if repair_id in seen_ids:
                errors.append(f"{where}.id: duplicate repair id")
            seen_ids.add(repair_id)
        repair_repository = _string(
            obj.get("repository"),
            f"{where}.repository",
            errors,
            minimum=3,
            maximum=160,
            pattern=REPOSITORY_RE,
        )
        action = _enum(
            obj.get("action"), f"{where}.action", REPAIR_ACTION_VALUES, errors
        )
        repair_state = _enum(
            obj.get("state"), f"{where}.state", REPAIR_STATE_VALUES, errors
        )
        _string(
            obj.get("problem_statement"),
            f"{where}.problem_statement",
            errors,
            minimum=16,
            maximum=800,
        )
        _string(
            obj.get("change_summary"),
            f"{where}.change_summary",
            errors,
            minimum=8,
            maximum=500,
        )
        pr_url = _nullable_string(
            obj.get("pull_request_url"),
            f"{where}.pull_request_url",
            errors,
            minimum=20,
            maximum=240,
            pattern=PR_URL_RE,
        )
        if (
            pr_url is not None
            and repair_repository is not None
            and not pr_url.startswith(f"https://github.com/{repair_repository}/pull/")
        ):
            errors.append(
                f"{where}.pull_request_url: owner/repository must match repair.repository"
            )
        commit = _nullable_string(
            obj.get("commit"),
            f"{where}.commit",
            errors,
            minimum=40,
            maximum=64,
            pattern=COMMIT_RE,
        )
        trailer = _string(
            obj.get("commit_trailer"),
            f"{where}.commit_trailer",
            errors,
            minimum=55,
            maximum=55,
        )
        if trailer is not None and case_id is not None:
            expected = f"Friction-Case: {case_id}"
            if trailer != expected:
                errors.append(f"{where}.commit_trailer: must equal {expected!r}")
        installed_on = _date(
            obj.get("installed_on"), f"{where}.installed_on", errors, nullable=True
        )
        removed_on = _date(
            obj.get("removed_on"), f"{where}.removed_on", errors, nullable=True
        )
        replaces = obj.get("replaces_repair_id")
        if replaces is not None:
            replaces = _string(
                replaces,
                f"{where}.replaces_repair_id",
                errors,
                minimum=2,
                maximum=12,
                pattern=REPAIR_ID_RE,
            )

        if repair_state == "planned" and any(
            item is not None for item in (pr_url, commit, installed_on, removed_on)
        ):
            errors.append(
                f"{where}: planned repair must not carry publication or install data"
            )
        if repair_state == "open":
            if pr_url is None:
                errors.append(f"{where}.pull_request_url: required for open repair")
            if any(item is not None for item in (commit, installed_on, removed_on)):
                errors.append(
                    f"{where}: open repair must not carry commit or completion dates"
                )
        completed_repair = repair_state == "merged" or (
            repair_state == "superseded" and commit is not None
        )
        if completed_repair:
            if pr_url is None:
                errors.append(
                    f"{where}.pull_request_url: required for completed {repair_state} repair"
                )
            if commit is None:
                errors.append(
                    f"{where}.commit: required for completed {repair_state} repair"
                )
            if action == "remove-forward":
                if removed_on is None:
                    errors.append(
                        f"{where}.removed_on: required for completed forward removal"
                    )
                if installed_on is not None:
                    errors.append(
                        f"{where}.installed_on: must be null for forward removal"
                    )
            else:
                if installed_on is None:
                    errors.append(
                        f"{where}.installed_on: required for installed repair"
                    )
                if removed_on is not None:
                    errors.append(
                        f"{where}.removed_on: allowed only for forward removal"
                    )
        elif repair_state == "superseded" and any(
            item is not None for item in (installed_on, removed_on)
        ):
            errors.append(
                f"{where}: unmerged superseded repair must not carry completion dates"
            )
        if action == "remove-forward":
            if commit is not None and any(
                prior_repair.get("commit") == commit
                for prior_repair in repairs_by_id.values()
            ):
                errors.append(
                    f"{where}.commit: forward removal must use a new commit that "
                    "does not appear earlier in the case repair history"
                )
            if replaces is None:
                errors.append(
                    f"{where}.replaces_repair_id: required for forward removal"
                )
            elif replaces not in seen_ids - ({repair_id} if repair_id else set()):
                errors.append(
                    f"{where}.replaces_repair_id: must name an earlier repair"
                )
            else:
                replaced_repair = repairs_by_id.get(replaces)
                if replaced_repair is not None:
                    replaced_installed_on = replaced_repair.get("installed_on")
                    if (
                        replaced_repair.get("action") not in {"install", "amend"}
                        or replaced_repair.get("state") != "superseded"
                        or replaced_repair.get("commit") is None
                        or not isinstance(replaced_installed_on, str)
                    ):
                        errors.append(
                            f"{where}.replaces_repair_id: forward removal must replace "
                            "a completed superseded install or amend repair"
                        )
                    if replaced_repair.get("repository") != obj.get("repository"):
                        errors.append(
                            f"{where}.repository: forward removal must use the "
                            "replaced repair repository"
                        )
                    if removed_on is not None and isinstance(
                        replaced_installed_on, str
                    ):
                        try:
                            if removed_on < date.fromisoformat(replaced_installed_on):
                                errors.append(
                                    f"{where}.removed_on: forward removal must not "
                                    "predate the replaced repair installation"
                                )
                        except ValueError:
                            pass
                    prior_installed: list[tuple[date, int, str]] = []
                    for prior_index, (prior_id, prior_repair) in enumerate(
                        repairs_by_id.items()
                    ):
                        if (
                            prior_repair.get("repository") != obj.get("repository")
                            or prior_repair.get("action") not in {"install", "amend"}
                            or prior_repair.get("state") != "superseded"
                            or prior_repair.get("commit") is None
                        ):
                            continue
                        prior_installed_on = _date(
                            prior_repair.get("installed_on"),
                            f"{where}.prior_repair.installed_on",
                            [],
                        )
                        if prior_installed_on is not None:
                            prior_installed.append(
                                (prior_installed_on, prior_index, prior_id)
                            )
                    if prior_installed:
                        latest_installed_on, _, latest_repair_id = max(prior_installed)
                        if replaces != latest_repair_id:
                            errors.append(
                                f"{where}.replaces_repair_id: forward removal must "
                                "replace the latest installed repair in its repository"
                            )
                        if removed_on is not None and removed_on < latest_installed_on:
                            errors.append(
                                f"{where}.removed_on: forward removal must not predate "
                                "the latest installed repair in its repository"
                            )
        elif replaces is not None:
            errors.append(
                f"{where}.replaces_repair_id: allowed only for forward removal"
            )

        result.append(obj)
        if repair_id is not None:
            repairs_by_id[repair_id] = obj
    return result


def _validate_effectiveness(value: Any, errors: list[str]) -> dict[str, Any] | None:
    fields = {"method", "state", "checked_on", "summary", "deterministic", "behavioral"}
    obj = _require_object(value, "$.effectiveness", fields, fields, errors)
    if obj is None:
        return None
    method = _enum(
        obj.get("method"), "$.effectiveness.method", EFFECTIVENESS_METHOD_VALUES, errors
    )
    state_value = _enum(
        obj.get("state"), "$.effectiveness.state", EFFECTIVENESS_STATE_VALUES, errors
    )
    checked_on = _date(
        obj.get("checked_on"), "$.effectiveness.checked_on", errors, nullable=True
    )
    summary = _nullable_string(
        obj.get("summary"), "$.effectiveness.summary", errors, minimum=8, maximum=500
    )
    deterministic = obj.get("deterministic")
    behavioral = obj.get("behavioral")

    deterministic_obj: dict[str, Any] | None = None
    if deterministic is not None:
        deterministic_fields = {"test_ref", "result", "commit"}
        deterministic_obj = _require_object(
            deterministic,
            "$.effectiveness.deterministic",
            deterministic_fields,
            deterministic_fields,
            errors,
        )
        if deterministic_obj is not None:
            _string(
                deterministic_obj.get("test_ref"),
                "$.effectiveness.deterministic.test_ref",
                errors,
                minimum=5,
                maximum=300,
            )
            _enum(
                deterministic_obj.get("result"),
                "$.effectiveness.deterministic.result",
                DETERMINISTIC_RESULT_VALUES,
                errors,
            )
            _string(
                deterministic_obj.get("commit"),
                "$.effectiveness.deterministic.commit",
                errors,
                minimum=40,
                maximum=64,
                pattern=COMMIT_RE,
            )

    behavioral_obj: dict[str, Any] | None = None
    behavioral_started: date | None = None
    behavioral_ended: date | None = None
    behavioral_opportunities: int | None = None
    behavioral_recurrences: int | None = None
    if behavioral is not None:
        behavioral_fields = {
            "started_on",
            "ended_on",
            "relevant_opportunities",
            "recurrences",
        }
        behavioral_obj = _require_object(
            behavioral,
            "$.effectiveness.behavioral",
            behavioral_fields,
            behavioral_fields,
            errors,
        )
        if behavioral_obj is not None:
            behavioral_started = _date(
                behavioral_obj.get("started_on"),
                "$.effectiveness.behavioral.started_on",
                errors,
            )
            behavioral_ended = _date(
                behavioral_obj.get("ended_on"),
                "$.effectiveness.behavioral.ended_on",
                errors,
                nullable=True,
            )
            behavioral_opportunities = _integer(
                behavioral_obj.get("relevant_opportunities"),
                "$.effectiveness.behavioral.relevant_opportunities",
                errors,
                minimum=0,
                maximum=1_000_000,
            )
            behavioral_recurrences = _integer(
                behavioral_obj.get("recurrences"),
                "$.effectiveness.behavioral.recurrences",
                errors,
                minimum=0,
                maximum=1_000_000,
            )
            if (
                behavioral_started is not None
                and behavioral_ended is not None
                and behavioral_started > behavioral_ended
            ):
                errors.append(
                    "$.effectiveness.behavioral: started_on must not follow ended_on"
                )
            if (
                checked_on is not None
                and behavioral_ended is not None
                and checked_on < behavioral_ended
            ):
                errors.append(
                    "$.effectiveness.checked_on must not precede behavioral ended_on"
                )
            if (
                checked_on is not None
                and behavioral_started is not None
                and checked_on < behavioral_started
            ):
                errors.append(
                    "$.effectiveness.checked_on must not precede behavioral started_on"
                )
            if (
                behavioral_opportunities is not None
                and behavioral_recurrences is not None
                and behavioral_recurrences > behavioral_opportunities
            ):
                errors.append(
                    "$.effectiveness.behavioral.recurrences must not exceed "
                    "relevant_opportunities"
                )

    if method == "none":
        if state_value != "not-started":
            errors.append("$.effectiveness.state: method none requires not-started")
        if any(
            item is not None
            for item in (checked_on, summary, deterministic, behavioral)
        ):
            errors.append("$.effectiveness: method none must not carry evaluation data")
    elif state_value == "not-started":
        if any(
            item is not None
            for item in (checked_on, summary, deterministic, behavioral)
        ):
            errors.append("$.effectiveness: not-started must not carry evaluation data")
    else:
        uses_deterministic = method in {"deterministic", "both"}
        uses_behavioral = method in {"behavioral", "both"}
        if uses_deterministic and deterministic_obj is None:
            errors.append("$.effectiveness.deterministic: required for selected method")
        if not uses_deterministic and deterministic is not None:
            errors.append(
                "$.effectiveness.deterministic: must be null for selected method"
            )
        if uses_behavioral and behavioral_obj is None:
            errors.append("$.effectiveness.behavioral: required for selected method")
        if not uses_behavioral and behavioral is not None:
            errors.append(
                "$.effectiveness.behavioral: must be null for selected method"
            )
        if uses_behavioral and behavioral_obj is not None:
            if state_value == "monitoring" and behavioral_ended is not None:
                errors.append(
                    "$.effectiveness.behavioral.ended_on: must be null while monitoring"
                )
            if state_value == "monitoring" and behavioral_obj.get("recurrences") != 0:
                errors.append(
                    "$.effectiveness.behavioral.recurrences: monitoring requires zero; "
                    "a recurrence is failed evidence"
                )
            if state_value in {"passed", "failed"} and behavioral_ended is None:
                errors.append(
                    "$.effectiveness.behavioral.ended_on: required for completed evaluation"
                )

        if state_value == "monitoring" and deterministic_obj is not None:
            expected_result = "pending" if method == "deterministic" else "passed"
            if deterministic_obj.get("result") != expected_result:
                errors.append(
                    "$.effectiveness.deterministic.result: "
                    f"{method} monitoring requires {expected_result!r}"
                )

        if state_value == "passed":
            if uses_deterministic and deterministic_obj is not None:
                if deterministic_obj.get("result") != "passed":
                    errors.append(
                        "$.effectiveness.deterministic.result: passed effectiveness requires a passed deterministic gate"
                    )
            if uses_behavioral and behavioral_obj is not None:
                opportunities = behavioral_obj.get("relevant_opportunities")
                recurrences = behavioral_obj.get("recurrences")
                if (
                    not isinstance(opportunities, int)
                    or isinstance(opportunities, bool)
                    or opportunities < 3
                ):
                    errors.append(
                        "$.effectiveness.behavioral.relevant_opportunities: passed requires at least 3"
                    )
                if recurrences != 0:
                    errors.append(
                        "$.effectiveness.behavioral.recurrences: passed requires zero"
                    )
                if behavioral_started is not None and behavioral_ended is not None:
                    if (behavioral_ended - behavioral_started).days < 7:
                        errors.append(
                            "$.effectiveness.behavioral: passed requires a window of at least 7 days"
                        )
        elif (
            state_value == "failed"
            and method == "deterministic"
            and deterministic_obj is not None
        ):
            if deterministic_obj.get("result") != "failed":
                errors.append(
                    "$.effectiveness.deterministic.result: failed deterministic effectiveness requires a failed test"
                )
        elif (
            state_value == "failed"
            and method == "behavioral"
            and behavioral_obj is not None
        ):
            recurrences = behavioral_obj.get("recurrences")
            if (
                not isinstance(recurrences, int)
                or isinstance(recurrences, bool)
                or recurrences <= 0
            ):
                errors.append(
                    "$.effectiveness.state: behavioral evidence without a recurrence "
                    "cannot be failed; insufficient observation remains monitoring"
                )
        elif state_value == "failed" and method == "both":
            deterministic_complete = (
                deterministic_obj is not None
                and deterministic_obj.get("result") in {"passed", "failed"}
            )
            deterministic_failed = (
                deterministic_obj is not None
                and deterministic_obj.get("result") == "failed"
            )
            behavioral_failed = False
            if behavioral_obj is not None:
                recurrences = behavioral_obj.get("recurrences")
                behavioral_failed = (
                    isinstance(recurrences, int)
                    and not isinstance(recurrences, bool)
                    and recurrences > 0
                )
            if not deterministic_complete:
                errors.append(
                    "$.effectiveness.deterministic.result: completed both-method "
                    "evaluation cannot remain pending"
                )
            elif not deterministic_failed and not behavioral_failed:
                errors.append(
                    "$.effectiveness: failed both-method result needs a failed gate"
                )

    if state_value in {"monitoring", "passed", "failed"}:
        if summary is None:
            errors.append(f"$.effectiveness.summary: required for {state_value}")
    if state_value in {"monitoring", "passed", "failed"} and checked_on is None:
        errors.append(f"$.effectiveness.checked_on: required for {state_value}")
    return obj


def validate_case(data: Any, relative_path: PurePosixPath) -> list[str]:
    """Return all validation errors for one parsed case document."""

    errors: list[str] = []
    _scan_prohibited_content(data, "$", errors)
    obj = _require_object(data, "$", TOP_LEVEL_FIELDS, TOP_LEVEL_FIELDS, errors)
    if obj is None:
        return errors

    version = obj.get("schema_version")
    if isinstance(version, bool) or version != 1:
        errors.append("$.schema_version: expected integer constant 1")
    _integer(obj.get("revision"), "$.revision", errors, minimum=1, maximum=1_000_000)
    case_id = _case_id(obj.get("id"), "$.id", errors)
    _validate_case_path(relative_path, case_id, errors)
    _string(obj.get("title"), "$.title", errors, minimum=8, maximum=160)
    status_value = _enum(obj.get("status"), "$.status", STATUS_VALUES, errors)
    support = _enum(obj.get("support"), "$.support", SUPPORT_VALUES, errors)
    classification = _enum(
        obj.get("classification"), "$.classification", CLASSIFICATION_VALUES, errors
    )
    source_kind = _enum(
        obj.get("source_kind"), "$.source_kind", SOURCE_KIND_VALUES, errors
    )
    urgency, urgency_source_event_ids = _validate_urgency(obj.get("urgency"), errors)

    causal = _validate_causal(obj.get("causal"), errors)
    evidence_stats = _validate_evidence(obj.get("evidence"), errors)
    evidence_last_seen = _timestamp(
        obj.get("evidence_last_seen"), "$.evidence_last_seen", errors
    )
    applicability = _validate_applicability(obj.get("applicability"), errors)
    currentness_checked_at = _timestamp(
        obj.get("currentness_checked_at"), "$.currentness_checked_at", errors
    )
    scope = _validate_scope(obj.get("scope"), errors)
    lifecycle = _validate_lifecycle(obj.get("lifecycle"), errors)
    lifecycle_changed_at = _timestamp(
        obj.get("lifecycle_changed_at"), "$.lifecycle_changed_at", errors
    )
    repairs = _validate_repairs(obj.get("repairs"), case_id, errors)
    effectiveness = _validate_effectiveness(obj.get("effectiveness"), errors)

    if causal is not None:
        if causal.get("occurrence_count") != evidence_stats.occurrence_count:
            errors.append("$.causal.occurrence_count: must equal evidence item count")
        if causal.get("root_task_count") != evidence_stats.root_task_count:
            errors.append(
                "$.causal.root_task_count: must equal distinct evidence root_task_id count"
            )
        if causal.get("workflow_count") != evidence_stats.workflow_count:
            errors.append(
                "$.causal.workflow_count: must equal distinct evidence workflow_id count"
            )
        if causal.get("repository_count") != evidence_stats.repository_count:
            errors.append(
                "$.causal.repository_count: must equal distinct non-null evidence repository count"
            )
        if causal.get("opportunity_count") != evidence_stats.opportunity_count:
            errors.append(
                "$.causal.opportunity_count: must equal distinct evidence opportunity_id count"
            )
        if (
            causal.get("causal_signature_count")
            != evidence_stats.causal_signature_count
        ):
            errors.append(
                "$.causal.causal_signature_count: must equal distinct evidence causal_signature count"
            )
        causal_first = _timestamp(
            causal.get("first_observed_at"), "$.causal.first_observed_at", []
        )
        if (
            causal_first is not None
            and evidence_stats.first_observed_at is not None
            and causal_first != evidence_stats.first_observed_at
        ):
            errors.append(
                "$.causal.first_observed_at: must equal earliest evidence timestamp"
            )

    if (
        evidence_last_seen is not None
        and evidence_stats.last_observed_at is not None
        and evidence_last_seen != evidence_stats.last_observed_at
    ):
        errors.append("$.evidence_last_seen: must equal latest evidence timestamp")
    if (
        currentness_checked_at is not None
        and evidence_last_seen is not None
        and currentness_checked_at < evidence_last_seen
    ):
        errors.append("$.currentness_checked_at: must not precede evidence_last_seen")

    if support == "novel" and evidence_stats.occurrence_count != 1:
        errors.append(
            "$.support: novel requires exactly one qualifying evidence occurrence"
        )
    if support == "repeated":
        if evidence_stats.occurrence_count < 2:
            errors.append(
                "$.support: repeated requires at least two evidence occurrences"
            )
        if not evidence_stats.has_repeated_signature:
            errors.append(
                "$.support: repeated requires a causal signature observed more than once"
            )

    if urgency is not None and urgency.get("level") == "high-signal":
        missing_sources = urgency_source_event_ids - evidence_stats.source_event_ids
        if missing_sources:
            errors.append(
                "$.urgency.source_event_ids: every urgency source must identify current case evidence"
            )

    if source_kind == "automation-derived" and not evidence_stats.has_human_correction:
        errors.append(
            "$.evidence: automation-derived cases require an explicit-human-correction signal"
        )

    if scope is not None:
        target_repository = scope.get("target_repository")
        global_rationale = scope.get("global_rationale")
        global_invariant_kind = scope.get("global_invariant_kind")
        if classification == "repo-local":
            if target_repository is None:
                errors.append(
                    "$.scope.target_repository: required for repo-local classification"
                )
            if global_rationale is not None:
                errors.append(
                    "$.scope.global_rationale: must be null for repo-local classification"
                )
            if global_invariant_kind is not None:
                errors.append(
                    "$.scope.global_invariant_kind: must be null for repo-local classification"
                )
            evidence_repositories = {
                item.get("repository")
                for item in obj.get("evidence", [])
                if isinstance(item, dict) and item.get("repository") is not None
            }
            missing_repository = any(
                isinstance(item, dict) and item.get("repository") is None
                for item in obj.get("evidence", [])
            )
            if missing_repository:
                errors.append(
                    "$.evidence: repo-local classification requires repository on every occurrence"
                )
            if target_repository is not None and evidence_repositories - {
                target_repository
            }:
                errors.append(
                    "$.scope.target_repository: repo-local evidence must name only the target repository"
                )
            if target_repository is not None and any(
                repair.get("repository") != target_repository for repair in repairs
            ):
                errors.append(
                    "$.repairs: repo-local repairs must use scope.target_repository"
                )
        elif classification == "cross-workflow":
            if global_rationale is None:
                errors.append(
                    "$.scope.global_rationale: required when the repair is not repository-local"
                )
            if global_invariant_kind is not None:
                errors.append(
                    "$.scope.global_invariant_kind: must be null for cross-workflow classification"
                )
            if evidence_stats.root_task_count < 2:
                errors.append(
                    "$.classification: cross-workflow requires at least two independent human root tasks"
                )
            if (
                evidence_stats.workflow_count < 2
                and evidence_stats.repository_count < 2
            ):
                errors.append(
                    "$.classification: cross-workflow requires distinct workflows or repositories"
                )
        elif classification == "global-invariant":
            if global_rationale is None:
                errors.append(
                    "$.scope.global_rationale: required for repository-independent global invariant"
                )
            if global_invariant_kind not in {"authorization", "data-integrity"}:
                errors.append(
                    "$.scope.global_invariant_kind: global invariant must be authorization or data-integrity"
                )

    if lifecycle is not None:
        created_at = _timestamp(
            lifecycle.get("created_at"), "$.lifecycle.created_at", []
        )
        dormant_since = _timestamp(
            lifecycle.get("dormant_since"),
            "$.lifecycle.dormant_since",
            [],
            nullable=True,
        )
        if (
            created_at is not None
            and evidence_stats.first_observed_at is not None
            and created_at < evidence_stats.first_observed_at
        ):
            errors.append("$.lifecycle.created_at: must not precede first observation")
        if (
            created_at is not None
            and lifecycle_changed_at is not None
            and created_at > lifecycle_changed_at
        ):
            errors.append("$.lifecycle_changed_at: must not precede case creation")
        revisit_when = lifecycle.get("revisit_when")
        if status_value == "dormant":
            if dormant_since is None:
                errors.append("$.lifecycle.dormant_since: required for dormant case")
            if lifecycle.get("dormant_from_status") not in {"watching", "proposed"}:
                errors.append(
                    "$.lifecycle.dormant_from_status: dormant cases may come only from watching or proposed"
                )
            if not isinstance(revisit_when, list) or not revisit_when:
                errors.append(
                    "$.lifecycle.revisit_when: dormant case requires a revisit condition"
                )
            if (
                dormant_since is not None
                and lifecycle_changed_at is not None
                and dormant_since != lifecycle_changed_at
            ):
                errors.append(
                    "$.lifecycle.dormant_since: must equal lifecycle_changed_at for dormant state"
                )
        elif (
            lifecycle.get("dormant_since") is not None
            or lifecycle.get("dormant_from_status") is not None
        ):
            errors.append(
                "$.lifecycle: dormancy fields must be null unless status is dormant"
            )
        if case_id is not None and lifecycle.get("superseded_by") == case_id:
            errors.append("$.lifecycle.superseded_by: case cannot supersede itself")
        if status_value != "superseded" and lifecycle.get("superseded_by") is not None:
            errors.append(
                "$.lifecycle.superseded_by: allowed only when status is superseded"
            )
        if (
            status_value in {"closed", "superseded"}
            and lifecycle_changed_at is not None
            and effectiveness is not None
            and effectiveness.get("state") in {"passed", "failed"}
        ):
            checked_on = effectiveness.get("checked_on")
            if isinstance(checked_on, str):
                try:
                    if lifecycle_changed_at.date() < date.fromisoformat(checked_on):
                        errors.append(
                            "$.lifecycle_changed_at: terminal state must not predate "
                            "effectiveness check"
                        )
                except ValueError:
                    pass
        if (
            status_value == "closed"
            and lifecycle_changed_at is not None
            and effectiveness is not None
            and effectiveness.get("state") == "passed"
        ):
            checked_on = effectiveness.get("checked_on")
            if (
                evidence_last_seen is not None
                and evidence_last_seen > lifecycle_changed_at
            ):
                errors.append(
                    "$.evidence_last_seen: closed case cannot retain post-closure recurrence"
                )
            if isinstance(checked_on, str) and evidence_last_seen is not None:
                try:
                    if evidence_last_seen.date() > date.fromisoformat(checked_on):
                        errors.append(
                            "$.evidence_last_seen: closed case cannot retain evidence "
                            "observed after its passed effectiveness check"
                        )
                except ValueError:
                    pass

    active_repairs = [
        repair for repair in repairs if repair.get("state") != "superseded"
    ]
    completed_repair_history = [
        repair
        for repair in repairs
        if repair.get("state") == "merged"
        or (repair.get("state") == "superseded" and repair.get("commit") is not None)
    ]
    installed_change_history = [
        repair
        for repair in completed_repair_history
        if repair.get("action") in {"install", "amend"}
        and repair.get("installed_on") is not None
    ]
    dated_installed_changes: list[tuple[date, int, dict[str, Any]]] = []
    for index, repair in enumerate(installed_change_history):
        installed_on = _date(
            repair.get("installed_on"),
            "$.repairs.installed_on",
            [],
        )
        if installed_on is not None:
            dated_installed_changes.append((installed_on, index, repair))
    latest_installed_change = (
        max(dated_installed_changes, key=lambda item: (item[0], item[1]))
        if dated_installed_changes
        else None
    )
    effectiveness_checked_on = (
        _date(
            effectiveness.get("checked_on"),
            "$.effectiveness.checked_on",
            [],
            nullable=True,
        )
        if effectiveness is not None
        else None
    )
    forward_removals = [
        repair for repair in repairs if repair.get("action") == "remove-forward"
    ]
    if (
        status_value in {"approved", "implemented", "observing", "closed"}
        and not repairs
    ):
        errors.append(f"$.repairs: status {status_value} requires at least one repair")
    if (
        repairs or status_value in {"approved", "implemented", "observing", "closed"}
    ) and (effectiveness is None or effectiveness.get("method") == "none"):
        errors.append(
            "$.effectiveness.method: selected repair requires deterministic, behavioral, or both"
        )
    if (
        not repairs
        and effectiveness is not None
        and effectiveness.get("method") != "none"
    ):
        errors.append("$.effectiveness.method: no repair selected requires none")
    if status_value == "watching" and repairs:
        errors.append("$.repairs: watching status must not contain repair proposals")
    if status_value == "proposed":
        if len(active_repairs) != 1 or active_repairs[0].get("state") != "planned":
            errors.append(
                "$.repairs: proposed status requires exactly one current planned repair"
            )
    if status_value == "approved":
        if len(active_repairs) != 1 or active_repairs[0].get("state") not in {
            "planned",
            "open",
        }:
            errors.append(
                "$.repairs: approved status requires exactly one current planned or open repair"
            )
    if status_value in {"implemented", "observing", "closed"}:
        if (
            len(active_repairs) != 1
            or active_repairs[0].get("state") != "merged"
            or active_repairs[0].get("action") not in {"install", "amend"}
        ):
            errors.append(
                f"$.repairs: status {status_value} requires exactly one current "
                "merged install or amend repair"
            )
        elif lifecycle_changed_at is not None:
            if status_value == "implemented":
                installed_dates = [
                    _date(
                        repair.get("installed_on"),
                        "$.repairs.installed_on",
                        [],
                    )
                    for repair in installed_change_history
                ]
                installed_on = min(
                    (item for item in installed_dates if item is not None),
                    default=None,
                )
            else:
                installed_on = _date(
                    active_repairs[0].get("installed_on"),
                    "$.repairs.current.installed_on",
                    [],
                )
            if installed_on is not None and lifecycle_changed_at.date() < installed_on:
                subject = (
                    "the first repair installation"
                    if status_value == "implemented"
                    else "the current repair installation"
                )
                errors.append(
                    "$.lifecycle_changed_at: installed lifecycle state must not "
                    f"predate {subject}"
                )
    if status_value in {
        "watching",
        "proposed",
        "approved",
        "dormant",
        "implemented",
    } and (effectiveness is None or effectiveness.get("state") != "not-started"):
        errors.append(
            f"$.effectiveness.state: status {status_value} requires not-started"
        )
    if status_value == "observing" and (
        effectiveness is None or effectiveness.get("state") != "monitoring"
    ):
        errors.append("$.effectiveness.state: observing status requires monitoring")
    if status_value == "closed" and (
        effectiveness is None or effectiveness.get("state") != "passed"
    ):
        errors.append(
            "$.effectiveness.state: closed status requires passed effectiveness"
        )
    if (
        effectiveness is not None
        and effectiveness.get("state") == "failed"
        and status_value != "superseded"
    ):
        errors.append(
            "$.effectiveness.state: failed evidence requires superseded status"
        )
    if status_value == "dormant":
        dormant_origin = (
            lifecycle.get("dormant_from_status") if lifecycle is not None else None
        )
        expected_current = (
            not active_repairs
            if dormant_origin == "watching"
            else len(active_repairs) == 1
            and active_repairs[0].get("state") == "planned"
        )
        if not expected_current:
            errors.append(
                "$.repairs: dormant current repair must match its watching or proposed origin"
            )
        if completed_repair_history:
            errors.append(
                "$.repairs: dormant is not allowed after a repair was implemented"
            )
    if status_value == "superseded":
        superseded_by = (
            lifecycle.get("superseded_by") if lifecycle is not None else None
        )
        completed_removals = [
            repair
            for repair in active_repairs
            if repair.get("action") == "remove-forward"
            and repair.get("state") == "merged"
            and repair.get("commit") is not None
            and repair.get("removed_on") is not None
        ]
        completed_removal = bool(completed_removals)
        if superseded_by is not None and active_repairs:
            errors.append(
                "$.repairs: replacement-case supersession must not retain a current repair"
            )
        if superseded_by is None and (
            len(active_repairs) != 1 or len(completed_removals) != 1
        ):
            errors.append(
                "$.repairs: forward-removal supersession requires exactly one current "
                "merged removal"
            )
        if superseded_by is None and not completed_removal:
            errors.append(
                "$.lifecycle.superseded_by: superseded status needs a replacement case or completed forward removal"
            )
        if completed_removal and lifecycle_changed_at is not None:
            removed_on = _date(
                completed_removals[0].get("removed_on"),
                "$.repairs.current.removed_on",
                [],
            )
            if removed_on is not None and lifecycle_changed_at.date() < removed_on:
                errors.append(
                    "$.lifecycle_changed_at: superseded lifecycle state must not "
                    "predate the forward removal"
                )
    if forward_removals:
        revisit_when = lifecycle.get("revisit_when") if lifecycle is not None else None
        if not isinstance(revisit_when, list) or not revisit_when:
            errors.append(
                "$.lifecycle.revisit_when: forward removal requires a revisit condition"
            )
        if applicability is not None and applicability.get("state") not in {
            "changed",
            "absent",
        }:
            errors.append(
                "$.applicability.state: forward removal requires changed or absent applicability"
            )

    if effectiveness is not None and effectiveness.get("state") in {"passed", "failed"}:
        if not installed_change_history:
            errors.append(
                "$.effectiveness: completed result requires installed repair history"
            )
        elif (
            effectiveness_checked_on is not None
            and latest_installed_change is not None
            and effectiveness_checked_on < latest_installed_change[0]
        ):
            errors.append(
                "$.effectiveness.checked_on: terminal evaluation must not predate "
                "the latest applicable installed repair"
            )
    if effectiveness is not None and effectiveness.get("method") in {
        "deterministic",
        "both",
    }:
        deterministic = effectiveness.get("deterministic")
        if isinstance(deterministic, dict):
            tested_commit = deterministic.get("commit")
            allowed_commits = {
                repair.get("commit") for repair in installed_change_history
            }
            if status_value in {"observing", "closed"} and len(active_repairs) == 1:
                allowed_commits = {active_repairs[0].get("commit")}
            elif (
                effectiveness.get("state") in {"passed", "failed"}
                and latest_installed_change is not None
            ):
                allowed_commits = {latest_installed_change[2].get("commit")}
            if tested_commit not in allowed_commits:
                errors.append(
                    "$.effectiveness.deterministic.commit: must identify the applicable "
                    "installed repair"
                )
            elif effectiveness_checked_on is not None:
                matching_install_dates: list[date] = []
                for repair in installed_change_history:
                    if repair.get("commit") != tested_commit:
                        continue
                    installed_on = _date(
                        repair.get("installed_on"),
                        "$.repairs.installed_on",
                        [],
                    )
                    if installed_on is not None:
                        matching_install_dates.append(installed_on)
                if matching_install_dates and effectiveness_checked_on < max(
                    matching_install_dates
                ):
                    errors.append(
                        "$.effectiveness.checked_on: deterministic evaluation must "
                        "not predate its installed repair"
                    )

    if effectiveness is not None and effectiveness.get("method") in {
        "behavioral",
        "both",
    }:
        behavioral = effectiveness.get("behavioral")
        start_text = (
            behavioral.get("started_on") if isinstance(behavioral, dict) else None
        )
        installed_dates = [
            repair.get("installed_on")
            for repair in installed_change_history
            if isinstance(repair.get("installed_on"), str)
        ]
        if isinstance(start_text, str) and installed_dates:
            try:
                if date.fromisoformat(start_text) < max(
                    date.fromisoformat(item) for item in installed_dates
                ):
                    errors.append(
                        "$.effectiveness.behavioral.started_on: must not predate "
                        "the latest applicable installed repair"
                    )
            except ValueError:
                pass

    return errors


def _relative_to_repo(path: Path) -> PurePosixPath | None:
    try:
        return PurePosixPath(
            path.resolve(strict=False).relative_to(REPO_ROOT).as_posix()
        )
    except ValueError:
        return None


def _collect_case_files(arguments: Sequence[str]) -> tuple[list[Path], list[str]]:
    discovery_errors: list[str] = []
    candidates: list[Path] = []
    requested = (
        [Path(argument) for argument in arguments] if arguments else [CASES_ROOT]
    )
    for requested_path in requested:
        path = (
            requested_path
            if requested_path.is_absolute()
            else REPO_ROOT / requested_path
        )
        if path.is_symlink():
            discovery_errors.append(f"{path}: symlinks are not accepted")
            continue
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_symlink():
                    discovery_errors.append(f"{candidate}: symlinks are not accepted")
                elif candidate.is_file():
                    relative = _relative_to_repo(candidate)
                    if relative == ALLOWED_CASE_AUXILIARY:
                        continue
                    if candidate.suffix != ".json":
                        discovery_errors.append(
                            f"{candidate}: only case JSON files and cases/.gitkeep are allowed"
                        )
                        continue
                    candidates.append(candidate)
        elif path.is_file():
            relative = _relative_to_repo(path)
            if relative == ALLOWED_CASE_AUXILIARY:
                continue
            if path.suffix != ".json":
                discovery_errors.append(
                    f"{path}: only case JSON files and cases/.gitkeep are allowed"
                )
            else:
                candidates.append(path)
        else:
            discovery_errors.append(
                f"{path}: path does not exist or is not a regular file"
            )

    unique: dict[Path, None] = {}
    for candidate in candidates:
        relative = _relative_to_repo(candidate)
        if relative is None or not relative.parts or relative.parts[0] != "cases":
            discovery_errors.append(
                f"{candidate}: case files must be beneath {CASES_ROOT}"
            )
            continue
        unique[candidate] = None
    return sorted(unique), discovery_errors


def _load_case(path: Path) -> tuple[Any | None, list[str]]:
    errors: list[str] = []
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode):
            return None, [f"{path}: expected a regular file"]
        if path.stat().st_size > MAX_CASE_BYTES:
            return None, [f"{path}: exceeds the {MAX_CASE_BYTES}-byte case bound"]
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle, object_pairs_hook=_object_pairs_no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError) as exc:
        errors.append(f"{path}: cannot load JSON: {exc}")
        return None, errors
    return value, errors


def semantic_case_digest(value: dict[str, Any]) -> str:
    """Return the canonical digest used by control-plane selection receipts."""

    projection = {
        key: child
        for key, child in value.items()
        if key not in {"revision", "currentness_checked_at"}
    }
    encoded = json.dumps(
        projection,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _git(
    arguments: Sequence[str], *, text_mode: bool = False
) -> subprocess.CompletedProcess[Any]:
    environment = dict(os.environ)
    environment.update({"GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"})
    return subprocess.run(
        ["git", *arguments],
        cwd=REPO_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text_mode,
        check=False,
    )


def _load_base_case(
    base_commit: str, relative_path: PurePosixPath
) -> tuple[Any | None, str | None]:
    result = _git(["show", f"{base_commit}:{relative_path.as_posix()}"])
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        return None, f"cannot read base case: {detail or 'git show failed'}"
    try:
        value = json.loads(
            result.stdout.decode("utf-8"), object_pairs_hook=_object_pairs_no_duplicates
        )
    except (UnicodeError, json.JSONDecodeError, DuplicateKeyError) as exc:
        return None, f"cannot parse base case: {exc}"
    return value, None


def _validate_closed_reopen_transition(
    base_case: dict[str, Any],
    current_case: dict[str, Any],
    relative_path: PurePosixPath,
) -> tuple[bool, list[str]]:
    """Validate the only transition that may replace terminal evaluation state."""

    if base_case.get("status") != "closed" or current_case.get("status") != "proposed":
        return False, []

    errors: list[str] = []
    base_effectiveness = base_case.get("effectiveness")
    if (
        not isinstance(base_effectiveness, dict)
        or base_effectiveness.get("state") != "passed"
    ):
        errors.append(
            f"{relative_path}: closed reopen requires a prior passed effectiveness snapshot"
        )

    base_evidence = base_case.get("evidence")
    current_evidence = current_case.get("evidence")
    appended_evidence: list[Any] = []
    if isinstance(base_evidence, list) and isinstance(current_evidence, list):
        appended_evidence = current_evidence[len(base_evidence) :]
    if not appended_evidence:
        errors.append(
            f"{relative_path}: closed reopen requires newly appended recurrence evidence"
        )

    base_closed_at = _timestamp(
        base_case.get("lifecycle_changed_at"),
        "$.lifecycle_changed_at",
        [],
    )
    reopened_at = _timestamp(
        current_case.get("lifecycle_changed_at"),
        "$.lifecycle_changed_at",
        [],
    )
    base_checked_on = (
        _date(
            base_effectiveness.get("checked_on"),
            "$.effectiveness.checked_on",
            [],
        )
        if isinstance(base_effectiveness, dict)
        else None
    )
    base_signatures = {
        occurrence.get("causal_signature")
        for occurrence in base_evidence or []
        if isinstance(occurrence, dict)
        and isinstance(occurrence.get("causal_signature"), str)
    }
    repeated_prior_cause = False
    for index, occurrence in enumerate(appended_evidence):
        if not isinstance(occurrence, dict):
            errors.append(
                f"{relative_path}: closed reopen evidence {index} must be an object"
            )
            continue
        observed_at = _timestamp(
            occurrence.get("observed_at"),
            "$.evidence.observed_at",
            [],
        )
        if (
            observed_at is None
            or base_closed_at is None
            or observed_at <= base_closed_at
            or base_checked_on is None
            or observed_at.date() <= base_checked_on
        ):
            errors.append(
                f"{relative_path}: closed reopen evidence must be strictly later than "
                "the prior effectiveness check and closure"
            )
        if observed_at is None or reopened_at is None or reopened_at < observed_at:
            errors.append(
                f"{relative_path}: closed reopen lifecycle_changed_at must not "
                "predate appended recurrence evidence"
            )
        if occurrence.get("causal_signature") in base_signatures:
            repeated_prior_cause = True
    if not repeated_prior_cause:
        errors.append(
            f"{relative_path}: closed reopen requires recurrence of a prior causal signature"
        )
    if current_case.get("support") != "repeated":
        errors.append(f"{relative_path}: closed reopen requires repeated support")

    base_repairs = base_case.get("repairs")
    current_repairs = current_case.get("repairs")
    base_repair_items = base_repairs if isinstance(base_repairs, list) else []
    current_repair_items = current_repairs if isinstance(current_repairs, list) else []
    if len(current_repair_items) != len(base_repair_items) + 1:
        errors.append(
            f"{relative_path}: closed reopen must append exactly one planned repair"
        )
    base_current = [
        (index, repair)
        for index, repair in enumerate(base_repair_items)
        if isinstance(repair, dict) and repair.get("state") != "superseded"
    ]
    if len(base_current) != 1:
        errors.append(
            f"{relative_path}: closed reopen requires exactly one prior current repair"
        )
    else:
        index, old_repair = base_current[0]
        changed_old = (
            current_repair_items[index] if index < len(current_repair_items) else None
        )
        if (
            not isinstance(changed_old, dict)
            or changed_old.get("id") != old_repair.get("id")
            or changed_old.get("state") != "superseded"
        ):
            errors.append(
                f"{relative_path}: closed reopen must supersede the prior current repair"
            )
    if len(current_repair_items) == len(base_repair_items) + 1:
        new_repair = current_repair_items[-1]
        if (
            not isinstance(new_repair, dict)
            or new_repair.get("state") != "planned"
            or new_repair.get("action") not in {"install", "amend"}
        ):
            errors.append(
                f"{relative_path}: closed reopen must append one planned install or amend repair"
            )

    current_effectiveness = current_case.get("effectiveness")
    if not isinstance(current_effectiveness, dict):
        errors.append(
            f"{relative_path}: closed reopen requires reset effectiveness state"
        )
    else:
        base_method = (
            base_effectiveness.get("method")
            if isinstance(base_effectiveness, dict)
            else None
        )
        reset_shape = (
            base_method in {"deterministic", "behavioral", "both"}
            and current_effectiveness.get("method") == base_method
            and current_effectiveness.get("state") == "not-started"
            and all(
                current_effectiveness.get(field) is None
                for field in ("checked_on", "summary", "deterministic", "behavioral")
            )
        )
        if not reset_shape:
            errors.append(
                f"{relative_path}: closed reopen must preserve the prior effectiveness "
                "method and reset it to not-started with no evaluation evidence"
            )

    return not errors, errors


def _validate_effectiveness_history(
    base_effectiveness: Any,
    current_effectiveness: Any,
    relative_path: PurePosixPath,
    *,
    allow_terminal_reset: bool = False,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(base_effectiveness, dict):
        return errors
    if not isinstance(current_effectiveness, dict):
        return [f"{relative_path}: existing effectiveness history must not be erased"]
    if allow_terminal_reset:
        return errors

    base_checked_raw = base_effectiveness.get("checked_on")
    current_checked_raw = current_effectiveness.get("checked_on")
    if base_checked_raw is not None:
        if current_checked_raw is None:
            errors.append(
                f"{relative_path}: effectiveness.checked_on must not be erased"
            )
        else:
            base_checked = _date(base_checked_raw, "$.effectiveness.checked_on", [])
            current_checked = _date(
                current_checked_raw, "$.effectiveness.checked_on", []
            )
            if (
                base_checked is not None
                and current_checked is not None
                and current_checked < base_checked
            ):
                errors.append(
                    f"{relative_path}: effectiveness.checked_on must not move backward"
                )

    base_behavioral = base_effectiveness.get("behavioral")
    current_behavioral = current_effectiveness.get("behavioral")
    if isinstance(base_behavioral, dict):
        if not isinstance(current_behavioral, dict):
            errors.append(
                f"{relative_path}: behavioral effectiveness history must not be erased"
            )
        else:
            if current_behavioral.get("started_on") != base_behavioral.get(
                "started_on"
            ):
                errors.append(
                    f"{relative_path}: behavioral started_on is immutable once observation begins"
                )
            base_ended_raw = base_behavioral.get("ended_on")
            current_ended_raw = current_behavioral.get("ended_on")
            if base_ended_raw is not None:
                if current_ended_raw is None:
                    errors.append(
                        f"{relative_path}: behavioral ended_on must not be erased"
                    )
                else:
                    base_ended = _date(
                        base_ended_raw, "$.effectiveness.behavioral.ended_on", []
                    )
                    current_ended = _date(
                        current_ended_raw,
                        "$.effectiveness.behavioral.ended_on",
                        [],
                    )
                    if (
                        base_ended is not None
                        and current_ended is not None
                        and current_ended < base_ended
                    ):
                        errors.append(
                            f"{relative_path}: behavioral ended_on must not move backward"
                        )
            for field in ("relevant_opportunities", "recurrences"):
                base_count = base_behavioral.get(field)
                current_count = current_behavioral.get(field)
                if (
                    isinstance(base_count, int)
                    and not isinstance(base_count, bool)
                    and (
                        not isinstance(current_count, int)
                        or isinstance(current_count, bool)
                        or current_count < base_count
                    )
                ):
                    errors.append(
                        f"{relative_path}: behavioral {field} must not decrease or be erased"
                    )

    base_deterministic = base_effectiveness.get("deterministic")
    current_deterministic = current_effectiveness.get("deterministic")
    if isinstance(base_deterministic, dict):
        if not isinstance(current_deterministic, dict):
            errors.append(
                f"{relative_path}: deterministic effectiveness evidence must not be erased"
            )
        else:
            for field in ("test_ref", "commit"):
                if current_deterministic.get(field) != base_deterministic.get(field):
                    errors.append(
                        f"{relative_path}: deterministic {field} is immutable once "
                        "evaluation begins"
                    )
            base_result = base_deterministic.get("result")
            current_result = current_deterministic.get("result")
            if base_result == "pending" and current_result not in {
                "pending",
                "passed",
                "failed",
            }:
                errors.append(
                    f"{relative_path}: deterministic pending result has an invalid transition"
                )
            if (
                base_result in {"passed", "failed"}
                and current_deterministic != base_deterministic
            ):
                errors.append(
                    f"{relative_path}: terminal deterministic effectiveness evidence is immutable"
                )

    if base_effectiveness.get("state") == "passed":
        if current_effectiveness.get("state") != "passed":
            errors.append(
                f"{relative_path}: passed effectiveness state must not regress"
            )
        if (
            base_effectiveness.get("method") in {"behavioral", "both"}
            and current_behavioral != base_behavioral
        ):
            errors.append(
                f"{relative_path}: passed behavioral effectiveness evidence is immutable"
            )
    if (
        base_effectiveness.get("state") in {"passed", "failed"}
        and current_effectiveness != base_effectiveness
    ):
        errors.append(f"{relative_path}: terminal effectiveness snapshot is immutable")
    return errors


def _validate_history_transition(
    base_case: dict[str, Any],
    current_case: dict[str, Any],
    relative_path: PurePosixPath,
) -> list[str]:
    errors: list[str] = []
    base_status = base_case.get("status")
    current_status = current_case.get("status")
    closed_reopen, closed_reopen_errors = _validate_closed_reopen_transition(
        base_case,
        current_case,
        relative_path,
    )
    errors.extend(closed_reopen_errors)
    base_currentness = _timestamp(
        base_case.get("currentness_checked_at"),
        "$.currentness_checked_at",
        [],
    )
    current_currentness = _timestamp(
        current_case.get("currentness_checked_at"),
        "$.currentness_checked_at",
        [],
    )
    if (
        base_currentness is not None
        and current_currentness is not None
        and current_currentness < base_currentness
    ):
        errors.append(
            f"{relative_path}: currentness_checked_at must not move backward from "
            f"{base_case.get('currentness_checked_at')!r}"
        )

    base_lifecycle = base_case.get("lifecycle")
    current_lifecycle = current_case.get("lifecycle")
    if isinstance(base_lifecycle, dict) and isinstance(current_lifecycle, dict):
        if current_lifecycle.get("created_at") != base_lifecycle.get("created_at"):
            errors.append(f"{relative_path}: lifecycle.created_at is immutable")
        base_changed_at = _timestamp(
            base_case.get("lifecycle_changed_at"),
            "$.lifecycle_changed_at",
            [],
        )
        current_changed_at = _timestamp(
            current_case.get("lifecycle_changed_at"),
            "$.lifecycle_changed_at",
            [],
        )
        lifecycle_changed = current_status != base_status
        if base_changed_at is not None and current_changed_at is not None:
            if lifecycle_changed and current_changed_at <= base_changed_at:
                errors.append(
                    f"{relative_path}: lifecycle_changed_at must move forward when "
                    "status changes"
                )
            if not lifecycle_changed and current_changed_at != base_changed_at:
                errors.append(
                    f"{relative_path}: lifecycle_changed_at must remain unchanged "
                    "without a status change"
                )

    base_evidence = base_case.get("evidence")
    current_evidence = current_case.get("evidence")
    if not isinstance(base_evidence, list) or not isinstance(current_evidence, list):
        errors.append(f"{relative_path}: evidence history must remain an array")
    else:
        if len(current_evidence) < len(base_evidence):
            errors.append(
                f"{relative_path}: persisted evidence occurrences must not be removed"
            )
        for index, base_occurrence in enumerate(base_evidence):
            if index >= len(current_evidence):
                break
            if current_evidence[index] != base_occurrence:
                errors.append(
                    f"{relative_path}: persisted evidence occurrence {index} must be "
                    "preserved exactly and in order"
                )

        persisted_source_event_ids = {
            source_event_id
            for occurrence in base_evidence
            if isinstance(occurrence, dict)
            for source_event_id in occurrence.get("source_event_ids", [])
            if isinstance(source_event_id, str)
        }
        for index, occurrence in enumerate(
            current_evidence[len(base_evidence) :], start=len(base_evidence)
        ):
            if not isinstance(occurrence, dict):
                continue
            source_event_ids = occurrence.get("source_event_ids")
            if not isinstance(source_event_ids, list):
                continue
            reused = sorted(
                source_event_id
                for source_event_id in source_event_ids
                if isinstance(source_event_id, str)
                and source_event_id in persisted_source_event_ids
            )
            if reused:
                errors.append(
                    f"{relative_path}: appended evidence occurrence {index} reuses "
                    "persisted source_event_id(s)"
                )

    errors.extend(
        _validate_effectiveness_history(
            base_case.get("effectiveness"),
            current_case.get("effectiveness"),
            relative_path,
            allow_terminal_reset=closed_reopen,
        )
    )

    if isinstance(base_status, str) and isinstance(current_status, str):
        allowed = STATUS_TRANSITIONS.get(base_status, set())
        if current_status not in allowed:
            errors.append(
                f"{relative_path}: invalid lifecycle transition {base_status!r} -> {current_status!r}"
            )
        if current_status == "implemented" and base_status != "implemented":
            current_repairs = current_case.get("repairs")
            repair_items = current_repairs if isinstance(current_repairs, list) else []
            installed_dates: list[date] = []
            for repair in repair_items:
                if (
                    not isinstance(repair, dict)
                    or repair.get("state") != "merged"
                    or repair.get("action") not in {"install", "amend"}
                ):
                    continue
                installed_on = _date(
                    repair.get("installed_on"),
                    "$.repairs.current.installed_on",
                    [],
                )
                if installed_on is not None:
                    installed_dates.append(installed_on)
            implemented_at = _timestamp(
                current_case.get("lifecycle_changed_at"),
                "$.lifecycle_changed_at",
                [],
            )
            if (
                installed_dates
                and implemented_at is not None
                and implemented_at.date() < max(installed_dates)
            ):
                errors.append(
                    f"{relative_path}: implemented status transition must not "
                    "predate repair installation"
                )
        current_lifecycle = current_case.get("lifecycle")
        if (
            current_status == "dormant"
            and base_status != "dormant"
            and isinstance(current_lifecycle, dict)
        ):
            if base_status not in {"watching", "proposed"}:
                errors.append(
                    f"{relative_path}: dormant transition is allowed only from watching or proposed"
                )
            if current_lifecycle.get("dormant_from_status") != base_status:
                errors.append(
                    f"{relative_path}: dormant_from_status must equal base status {base_status!r}"
                )
        if base_status == "dormant" and current_status in {"watching", "proposed"}:
            base_lifecycle = base_case.get("lifecycle")
            dormant_origin = (
                base_lifecycle.get("dormant_from_status")
                if isinstance(base_lifecycle, dict)
                else None
            )
            if current_status != dormant_origin:
                errors.append(
                    f"{relative_path}: dormant case may reactivate only to {dormant_origin!r}"
                )
        if (
            base_status == "dormant"
            and current_status == "dormant"
            and isinstance(base_lifecycle, dict)
            and isinstance(current_lifecycle, dict)
        ):
            for field in ("dormant_since", "dormant_from_status"):
                if current_lifecycle.get(field) != base_lifecycle.get(field):
                    errors.append(
                        f"{relative_path}: lifecycle.{field} is immutable while dormant"
                    )
        if (
            base_status == "superseded"
            and isinstance(base_lifecycle, dict)
            and isinstance(current_lifecycle, dict)
            and base_lifecycle.get("superseded_by") is not None
            and current_lifecycle.get("superseded_by")
            != base_lifecycle.get("superseded_by")
        ):
            errors.append(
                f"{relative_path}: lifecycle.superseded_by is immutable once recorded"
            )

    base_repairs = base_case.get("repairs")
    current_repairs = current_case.get("repairs")
    if not isinstance(base_repairs, list) or not isinstance(current_repairs, list):
        return errors
    if len(current_repairs) < len(base_repairs):
        errors.append(f"{relative_path}: existing repair history must not be removed")

    immutable_fields = {
        "id",
        "repository",
        "action",
        "problem_statement",
        "change_summary",
        "commit_trailer",
        "replaces_repair_id",
    }
    durable_fields = {"pull_request_url", "commit", "installed_on", "removed_on"}
    for index, base_repair in enumerate(base_repairs):
        if index >= len(current_repairs):
            break
        current_repair = current_repairs[index]
        if not isinstance(base_repair, dict) or not isinstance(current_repair, dict):
            errors.append(
                f"{relative_path}: repair history entries must remain objects"
            )
            continue
        base_id = base_repair.get("id")
        if current_repair.get("id") != base_id:
            errors.append(
                f"{relative_path}: existing repair history must not be reordered or replaced"
            )
            continue
        for field in immutable_fields:
            if current_repair.get(field) != base_repair.get(field):
                errors.append(
                    f"{relative_path}: repair {base_id} field {field} is immutable"
                )
        base_repair_state = base_repair.get("state")
        current_repair_state = current_repair.get("state")
        if isinstance(
            base_repair_state, str
        ) and current_repair_state not in REPAIR_STATE_TRANSITIONS.get(
            base_repair_state, set()
        ):
            errors.append(
                f"{relative_path}: repair {base_id} has invalid state transition "
                f"{base_repair_state!r} -> {current_repair_state!r}"
            )
        for field in durable_fields:
            base_value = base_repair.get(field)
            if base_value is not None and current_repair.get(field) != base_value:
                errors.append(
                    f"{relative_path}: repair {base_id} durable field {field} must be preserved"
                )
    base_effectiveness = base_case.get("effectiveness")
    current_effectiveness = current_case.get("effectiveness")
    if (
        not closed_reopen
        and base_repairs
        and isinstance(base_effectiveness, dict)
        and isinstance(current_effectiveness, dict)
    ):
        base_method = base_effectiveness.get("method")
        if (
            base_method in {"deterministic", "behavioral", "both"}
            and current_effectiveness.get("method") != base_method
        ):
            errors.append(
                f"{relative_path}: selected effectiveness method {base_method!r} is immutable"
            )
    return errors


def _validate_one_case_change_scope(
    changed_cases: Sequence[tuple[str, PurePosixPath]],
    other_changed_paths: set[PurePosixPath],
) -> list[str]:
    errors: list[str] = []
    if len(changed_cases) > 1:
        errors.append(
            "$base: one-case-one-PR permits at most one changed case JSON file"
        )
    if len(changed_cases) == 1 and other_changed_paths:
        examples = ", ".join(
            path.as_posix() for path in sorted(other_changed_paths)[:5]
        )
        suffix = " ..." if len(other_changed_paths) > 5 else ""
        errors.append(
            f"$base: a one-case PR must not change non-case paths: {examples}{suffix}"
        )
    return errors


def _validate_case_graph(
    loaded_cases: dict[PurePosixPath, dict[str, Any]],
) -> list[str]:
    """Validate repository-wide replacement references without mutating the ledger."""

    errors: list[str] = []
    paths_by_id: dict[str, PurePosixPath] = {}
    successors: dict[str, str] = {}
    for path, case in loaded_cases.items():
        case_id = case.get("id")
        if not isinstance(case_id, str):
            continue
        prior_path = paths_by_id.get(case_id)
        if prior_path is not None:
            errors.append(f"{path}: duplicate case id also appears at {prior_path}")
            continue
        paths_by_id[case_id] = path
        lifecycle = case.get("lifecycle")
        successor = (
            lifecycle.get("superseded_by") if isinstance(lifecycle, dict) else None
        )
        if isinstance(successor, str):
            successors[case_id] = successor

    for case_id, successor in sorted(successors.items()):
        if successor not in paths_by_id:
            errors.append(
                f"{paths_by_id[case_id]}: lifecycle.superseded_by references "
                f"missing case {successor}"
            )

    completed: set[str] = set()
    reported_cycles: set[tuple[str, ...]] = set()
    for start in sorted(paths_by_id):
        if start in completed:
            continue
        chain: list[str] = []
        positions: dict[str, int] = {}
        current = start
        while current in paths_by_id and current not in completed:
            if current in positions:
                cycle = chain[positions[current] :]
                signature = tuple(sorted(cycle))
                if signature not in reported_cycles:
                    reported_cycles.add(signature)
                    errors.append(
                        f"{paths_by_id[current]}: lifecycle.superseded_by cycle: "
                        + " -> ".join([*cycle, current])
                    )
                break
            positions[current] = len(chain)
            chain.append(current)
            successor = successors.get(current)
            if successor is None:
                break
            current = successor
        completed.update(chain)
    return errors


def _validate_base_revisions(
    base: str, loaded_cases: dict[PurePosixPath, dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    resolved = _git(["rev-parse", "--verify", f"{base}^{{commit}}"], text_mode=True)
    if resolved.returncode != 0:
        detail = resolved.stderr.strip()
        return [
            f"$base: cannot resolve local commit {base!r}: {detail or 'git rev-parse failed'}"
        ]
    base_commit = resolved.stdout.strip()

    diff = _git(["diff", "--name-status", "-z", "--no-renames", base_commit, "--", "."])
    if diff.returncode != 0:
        detail = diff.stderr.decode("utf-8", errors="replace").strip()
        return [f"$base: cannot inspect case changes: {detail or 'git diff failed'}"]
    tokens = diff.stdout.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    if len(tokens) % 2 != 0:
        return ["$base: malformed git diff name-status output"]

    changed_cases: list[tuple[str, PurePosixPath]] = []
    other_changed_paths: set[PurePosixPath] = set()
    for index in range(0, len(tokens), 2):
        status_value = tokens[index].decode("ascii", errors="replace")
        path_text = tokens[index + 1].decode("utf-8", errors="surrogateescape")
        path = PurePosixPath(path_text)
        beneath_cases = bool(path.parts) and path.parts[0] == "cases"
        if not beneath_cases:
            other_changed_paths.add(path)
            continue
        if path == ALLOWED_CASE_AUXILIARY:
            other_changed_paths.add(path)
            continue
        if path.suffix != ".json":
            if status_value != "D":
                errors.append(
                    f"{path}: only case JSON files and cases/.gitkeep are allowed"
                )
            other_changed_paths.add(path)
            continue
        changed_cases.append((status_value, path))
        if status_value == "D":
            errors.append(
                f"{path}: case deletion is prohibited; use dormant or superseded"
            )
        elif status_value not in {"A", "M"}:
            errors.append(f"{path}: unsupported case path change status {status_value}")

    untracked = _git(["ls-files", "--others", "--exclude-standard", "-z", "--", "."])
    if untracked.returncode != 0:
        detail = untracked.stderr.decode("utf-8", errors="replace").strip()
        errors.append(
            f"$base: cannot inspect untracked paths: {detail or 'git ls-files failed'}"
        )
    else:
        for raw_path in untracked.stdout.split(b"\0"):
            if not raw_path:
                continue
            path = PurePosixPath(raw_path.decode("utf-8", errors="surrogateescape"))
            beneath_cases = bool(path.parts) and path.parts[0] == "cases"
            if beneath_cases and path.suffix == ".json":
                if all(existing_path != path for _, existing_path in changed_cases):
                    changed_cases.append(("A", path))
            else:
                if beneath_cases and path != ALLOWED_CASE_AUXILIARY:
                    errors.append(
                        f"{path}: only case JSON files and cases/.gitkeep are allowed"
                    )
                other_changed_paths.add(path)

    changed_paths = {path for _, path in changed_cases}
    for path in loaded_cases:
        if path in changed_paths:
            continue
        exists_at_base = _git(["ls-tree", "-z", base_commit, "--", path.as_posix()])
        if exists_at_base.returncode != 0:
            detail = exists_at_base.stderr.decode("utf-8", errors="replace").strip()
            errors.append(
                f"{path}: cannot determine base-path existence: {detail or 'git ls-tree failed'}"
            )
            continue
        if not exists_at_base.stdout:
            changed_cases.append(("A", path))

    errors.extend(_validate_one_case_change_scope(changed_cases, other_changed_paths))

    for status_value, path in changed_cases:
        current = loaded_cases.get(path)
        if current is None or status_value == "D":
            continue
        revision = current.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int):
            continue
        if status_value == "A":
            if revision != 1:
                errors.append(f"{path}: a new case must start at revision 1")
            continue
        base_case, load_error = _load_base_case(base_commit, path)
        if load_error is not None:
            errors.append(f"{path}: {load_error}")
            continue
        if not isinstance(base_case, dict):
            errors.append(f"{path}: base case must be an object")
            continue
        base_revision = base_case.get("revision")
        if isinstance(base_revision, bool) or not isinstance(base_revision, int):
            errors.append(f"{path}: base case has invalid revision")
            continue
        if current.get("id") != base_case.get("id"):
            errors.append(f"{path}: existing case id is immutable")
        errors.extend(_validate_history_transition(base_case, current, path))
        semantic_change = semantic_case_digest(current) != semantic_case_digest(
            base_case
        )
        expected_revision = base_revision + 1 if semantic_change else base_revision
        if revision != expected_revision:
            reason = "semantic change" if semantic_change else "currentness-only change"
            errors.append(
                f"{path}: {reason} requires revision {expected_revision}, found {revision}"
            )
    return errors


def _validate_schema_file() -> list[str]:
    try:
        with SCHEMA_PATH.open("r", encoding="utf-8") as handle:
            schema = json.load(handle, object_pairs_hook=_object_pairs_no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError) as exc:
        return [f"{SCHEMA_PATH}: cannot load schema JSON: {exc}"]
    if (
        not isinstance(schema, dict)
        or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
    ):
        return [f"{SCHEMA_PATH}: expected a JSON Schema 2020-12 document"]
    return []


def _print_errors(errors: Iterable[str]) -> None:
    for error in errors:
        print(error, file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only validation for Daily Skill Friction ledger cases."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Case JSON files or directories (default: cases/).",
    )
    parser.add_argument(
        "--base",
        help=(
            "Optional local base commit for one-case change and monotonic revision checks; "
            "the validator never fetches."
        ),
    )
    args = parser.parse_args(argv)
    if args.base and args.paths:
        parser.error(
            "--base audits the complete cases/ tree and cannot be combined with paths"
        )

    errors = _validate_schema_file()
    files, discovery_errors = _collect_case_files(args.paths)
    errors.extend(discovery_errors)
    validated = 0
    loaded_cases: dict[PurePosixPath, dict[str, Any]] = {}
    for path in files:
        value, load_errors = _load_case(path)
        errors.extend(load_errors)
        if value is None:
            continue
        relative = _relative_to_repo(path)
        if relative is None:
            errors.append(f"{path}: case file is outside the repository")
            continue
        case_errors = validate_case(value, relative)
        errors.extend(f"{relative}: {error}" for error in case_errors)
        if isinstance(value, dict):
            loaded_cases[relative] = value
        validated += 1

    if not args.paths:
        errors.extend(_validate_case_graph(loaded_cases))

    if args.base:
        errors.extend(_validate_base_revisions(args.base, loaded_cases))

    if errors:
        _print_errors(errors)
        print(
            f"Validation failed: {len(errors)} error(s) across {validated} case file(s).",
            file=sys.stderr,
        )
        return 1
    print(f"Validated {validated} case file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
