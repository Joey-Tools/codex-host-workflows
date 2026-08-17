#!/usr/bin/env python3
"""Fail-closed local state transitions for Daily Skill Friction.

The helper is intentionally limited to JSON and local filesystem operations.  It
does not import a Git or network client and it never invokes a subprocess.
"""

from __future__ import annotations

import argparse
import contextvars
import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, Literal, NoReturn, overload

VERSION = 1
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_CASE_JSON_BYTES = 256 * 1024
MAX_PUBLICATION_JSON_BYTES = 32 * 1024 * 1024
MAX_WAL_JSON_BYTES = 64 * 1024 * 1024
MAX_PREPARED_COMMANDS = 8
MAX_PREPARED_COMMAND_CHARS = 512
MAX_PREPARED_SIGNER_CHARS = 256
# Publication v1 bounds every non-case plan/active field (UUID, safe ID,
# revision, digest, timestamp, repository, branch, and derived case path).  The
# per-case reservations exceed their maximum canonical encodings, while the
# fixed reservations cover top-level objects, the fixed automation output path,
# the external parent binding, and WAL framing.  Weekly planning and finalization
# still measure their actual artifacts and intents against the approved
# projections before writing, so a future schema expansion cannot silently
# consume this headroom.
PUBLICATION_FIXED_BUDGET_BYTES = 1 * 1024 * 1024
PUBLICATION_PER_CASE_OVERHEAD_BYTES = 32 * 1024
WEEKLY_WAL_FIXED_BUDGET_BYTES = 2 * 1024 * 1024
WEEKLY_WAL_PER_CASE_OVERHEAD_BYTES = 8 * 1024
FINALIZE_WAL_FIXED_BUDGET_BYTES = 4 * 1024 * 1024
STATE_MARKER = ".state-root.json"
LOCK_FILE = ".state.lock"
LIVE_POINTER = "last-completed-daily.json"
LEDGER_REPOSITORY = "Joey-Tools/codex-skill-friction-ledger"
LEDGER_BASE_BRANCH = "master"
TRANSACTION_OPERATIONS = {
    "stage",
    "dormancy",
    "complete-audit",
    "selection-preflight",
    "weekly-plan",
    "finalize-publication",
    "close-publication",
}
AUDIT_SUMMARY_COUNT_FIELDS = {
    "candidates_considered",
    "cases_created",
    "cases_updated",
    "cases_unchanged",
    "cases_dormant",
    "no_issue_observations",
    "blocked_actions",
}

CASE_ID_RE = re.compile(
    r"^DSF-([0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
)
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SAFE_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
SAFE_OBJECT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
WAL_LEAF_RE = re.compile(r"^[0-9a-f]{64}\.(?:intent|commit)\.json$")
WAL_TEMP_RE = re.compile(
    r"^\.(?P<leaf>[0-9a-f]{64}\.(?:intent|commit)\.json)"
    r"\.tmp-(?P<pid>[1-9][0-9]{0,19})-(?P<nonce>[0-9a-f]{16})$"
)

STATUSES = {
    "watching",
    "proposed",
    "approved",
    "implemented",
    "observing",
    "closed",
    "superseded",
    "dormant",
}
INITIAL_CASE_STATUSES = {"watching", "proposed"}
SUPPORT_RESULTS = {"novel", "repeated"}
URGENCIES = {"normal", "high-signal"}
SCOPES = {"repo-local", "cross-workflow", "global-invariant"}
APPLICABILITY_STATES = {"present", "changed", "absent", "unknown"}
SOURCE_KINDS = {"human-root", "automation-derived", "legacy-migration"}
SIGNAL_TYPES = {
    "explicit-human-correction",
    "repeated-retry",
    "manual-workaround",
    "blocked-operation",
    "unexpected-result",
    "policy-mismatch",
    "validation-failure",
}
HIGH_SIGNAL_REASONS = {
    "data-loss-or-corruption",
    "recovery-boundary-failure",
    "credential-or-private-data-exposure",
    "unauthorized-access",
    "unauthorized-irreversible-external-side-effect",
    "material-authority-boundary-breach",
}
STABLE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
FORBIDDEN_SOURCE_FAMILIES = {
    "daily-skill-friction",
    "weekly-skill-friction",
    "automation-descendant",
    "historical-replay",
}
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
PR_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[1-9][0-9]*$")
REPAIR_ID_RE = re.compile(r"^R[1-9][0-9]*$")
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
RAW_SOURCE_MARKERS = ("rollout-", "/sessions/", "/archived_sessions/", "/.codex/")
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


class StateError(RuntimeError):
    """A validation or state transition failure with a stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> NoReturn:
    raise StateError(code, message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate-json-key", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _json_from_bytes(raw: bytes, source: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        _fail("invalid-json", f"cannot load JSON from {source}: {exc}")
    if not isinstance(value, dict):
        _fail("invalid-json-root", f"JSON root must be an object: {source}")
    return value


def _read_fd_stable(
    fd: int,
    source: str,
    *,
    private: bool,
    max_bytes: int = MAX_JSON_BYTES,
    expected_parent_fd: int | None = None,
    expected_name: str | None = None,
) -> tuple[bytes, str]:
    """Read bounded bytes twice from one object and bind identity and policy.

    Identity is the open object's device/inode plus the parent entry that names it.
    Content stability is an equal second read, not mtime/ctime equality.  Access
    policy is regular, current-user-owned, private, single-link state when
    ``private`` is true.
    """

    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        _fail("unsafe-file", f"expected a regular non-symlink file: {source}")
    if before.st_size > max_bytes:
        _fail("input-too-large", f"JSON input exceeds {max_bytes} bytes: {source}")
    if private:
        if before.st_uid != os.geteuid():
            _fail("unsafe-owner", f"state file is not owned by the current user: {source}")
        if stat.S_IMODE(before.st_mode) & 0o077:
            _fail("unsafe-permissions", f"state file permits group or other access: {source}")
        if before.st_nlink != 1:
            _fail("unsafe-link-count", f"state file must have exactly one link: {source}")

    def read_once() -> bytes:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(128 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            _fail("input-too-large", f"JSON input exceeds {max_bytes} bytes: {source}")
        return payload

    first = read_once()
    second = read_once()
    after = os.fstat(fd)
    identity_before = (before.st_dev, before.st_ino, before.st_nlink)
    identity_after = (after.st_dev, after.st_ino, after.st_nlink)
    if identity_before != identity_after:
        _fail("object-identity-changed", f"file identity changed while reading: {source}")
    if first != second or len(second) != after.st_size:
        _fail("content-changed", f"file content changed while reading: {source}")
    if private and (
        after.st_uid != before.st_uid
        or stat.S_IMODE(after.st_mode) & 0o077
        or not stat.S_ISREG(after.st_mode)
    ):
        _fail("access-policy-changed", f"state file access policy changed: {source}")
    if expected_parent_fd is not None and expected_name is not None:
        try:
            named = os.stat(expected_name, dir_fd=expected_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            _fail("object-replaced", f"file name disappeared while reading: {source}")
        if stat.S_ISLNK(named.st_mode) or (named.st_dev, named.st_ino) != (
            after.st_dev,
            after.st_ino,
        ):
            _fail("object-replaced", f"file name was rebound while reading: {source}")
    return second, hashlib.sha256(second).hexdigest()


def _open_external_stable(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> tuple[bytes, str]:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        _fail("missing-file", f"required file is missing: {path}")
    except OSError as exc:
        _fail("unsafe-file", f"cannot open JSON input {path}: {exc}")
    try:
        return _read_fd_stable(fd, str(path), private=False, max_bytes=max_bytes)
    finally:
        os.close(fd)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_digest(path: Path) -> str:
    store = _active_store_for_path(path)
    if store is not None:
        return store.read_bytes(store.relative(path))[1]
    return _open_external_stable(path)[1]


def _load_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> dict[str, Any]:
    store = _active_store_for_path(path)
    if store is not None:
        raw, _ = store.read_bytes(store.relative(path))
    else:
        raw, _ = _open_external_stable(path, max_bytes=max_bytes)
    return _json_from_bytes(raw, str(path))


def _load_json_with_digest(
    path: Path, *, max_bytes: int = MAX_JSON_BYTES
) -> tuple[dict[str, Any], str]:
    store = _active_store_for_path(path)
    if store is not None:
        raw, digest = store.read_bytes(store.relative(path))
    else:
        raw, digest = _open_external_stable(path, max_bytes=max_bytes)
    return _json_from_bytes(raw, str(path)), digest


def _require_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("invalid-field", f"{field} must be an object")
    return value


def _require_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        _fail("invalid-field", f"{field} must be an array")
    return value


def _require_string(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        _fail("invalid-field", f"{field} must be a non-empty string")
    return value


def _require_int(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail("invalid-field", f"{field} must be an integer >= {minimum}")
    return value


def _parse_time(value: Any, field: str) -> dt.datetime:
    text = _require_string(value, field)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except (ValueError, OverflowError):
        _fail("invalid-timestamp", f"{field} is not an ISO-8601 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("invalid-timestamp", f"{field} must include a timezone")
    try:
        return parsed.astimezone(dt.UTC)
    except (ValueError, OverflowError):
        _fail("invalid-timestamp", f"{field} cannot be normalized to UTC")


def _timestamp(value: Any, field: str) -> str:
    text = _require_string(value, field)
    if TIMESTAMP_RE.fullmatch(text) is None:
        _fail("invalid-timestamp", f"{field} must use canonical UTC RFC 3339 Z form")
    parsed = _parse_time(text, field)
    del parsed
    return text


def _bounded_string(value: Any, field: str, minimum: int, maximum: int) -> str:
    text = _require_string(value, field)
    if not minimum <= len(text) <= maximum or "\n" in text or "\r" in text:
        _fail("invalid-text", f"{field} must be single-line text of {minimum}..{maximum} chars")
    return text


@overload
def _date(value: Any, field: str, *, nullable: Literal[False] = False) -> dt.date: ...


@overload
def _date(value: Any, field: str, *, nullable: Literal[True]) -> dt.date | None: ...


def _date(value: Any, field: str, *, nullable: bool = False) -> dt.date | None:
    if value is None and nullable:
        return None
    text = _require_string(value, field)
    try:
        parsed = dt.date.fromisoformat(text)
    except ValueError:
        _fail("invalid-date", f"{field} must be YYYY-MM-DD")
    if parsed.isoformat() != text:
        _fail("invalid-date", f"{field} must be canonical YYYY-MM-DD")
    return parsed


def _field_words(name: str) -> set[str]:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return {word.lower() for word in re.split(r"[^A-Za-z0-9]+", separated) if word}


def _scan_prohibited_content(value: Any, field: str = "candidate") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            words = _field_words(key)
            if words & FORBIDDEN_FIELD_WORDS or any(
                combination <= words for combination in FORBIDDEN_FIELD_COMBINATIONS
            ):
                _fail("prohibited-field", f"{field}.{key} is a prohibited evidence field")
            _scan_prohibited_content(child, f"{field}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_prohibited_content(child, f"{field}[{index}]")
    elif isinstance(value, str):
        lowered = value.lower()
        if (
            any(marker in lowered for marker in SENSITIVE_VALUE_MARKERS)
            or any(pattern.search(value) for pattern in CREDENTIAL_VALUE_PATTERNS)
            or any(pattern.search(value) for pattern in BARE_CREDENTIAL_VALUE_PATTERNS)
        ):
            _fail("credential-shaped-content", f"{field} contains credential-shaped material")
        if any(marker in lowered for marker in RAW_SOURCE_MARKERS) or FILE_URI_RE.search(value):
            _fail("raw-source-locator", f"{field} contains a raw rollout or session locator")


def _validate_case_id(value: Any, field: str = "case_id") -> str:
    case_id = _require_string(value, field)
    match = CASE_ID_RE.fullmatch(case_id)
    if match is None:
        _fail("invalid-case-id", f"{field} must be DSF-<UUIDv7>")
    parsed = uuid.UUID(match.group(1))
    if parsed.version != 7 or parsed.variant != uuid.RFC_4122:
        _fail("invalid-case-id", f"{field} must contain an RFC 4122 UUIDv7")
    return case_id


def _safe_object_id(value: Any, field: str) -> str:
    result = _require_string(value, field)
    if SAFE_OBJECT_ID_RE.fullmatch(result) is None or result in {".", ".."}:
        _fail("unsafe-object-id", f"{field} must be a closed safe basename")
    return result


def new_case_id(now: str) -> str:
    """Return a UUIDv7 case ID whose timestamp is derived from ``now``."""

    instant = _parse_time(now, "now")
    unix_ms = int(instant.timestamp() * 1000)
    if not 0 <= unix_ms < 1 << 48:
        _fail("timestamp-out-of-range", "now is outside the UUIDv7 timestamp range")
    value = unix_ms << 80
    value |= 0x7 << 76
    value |= secrets.randbits(12) << 64
    value |= 0b10 << 62
    value |= secrets.randbits(62)
    return f"DSF-{uuid.UUID(int=value)}"


def _semantic_projection(case: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: child
        for key, child in case.items()
        if key not in {"revision", "currentness_checked_at"}
    }


def semantic_digest(case: Mapping[str, Any]) -> str:
    """Match the ledger's ``semantic_case_digest`` byte for byte."""

    encoded = json.dumps(
        _semantic_projection(case),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _exact_fields(value: Mapping[str, Any], field: str, expected: set[str]) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        _fail("invalid-fields", f"{field} fields mismatch; missing={missing}, extra={extra}")


def _stable_id(value: Any, field: str) -> str:
    result = _require_string(value, field)
    if not 3 <= len(result) <= 200 or STABLE_ID_RE.fullmatch(result) is None:
        _fail("invalid-stable-id", f"{field} must be a namespaced stable ID")
    return result


def _sha_digest(value: Any, field: str) -> str:
    result = _require_string(value, field)
    if DIGEST_RE.fullmatch(result) is None:
        _fail("invalid-digest", f"{field} must be sha256:<64 lowercase hex>")
    return result


def _repository(value: Any, field: str) -> str:
    result = _require_string(value, field)
    if not 3 <= len(result) <= 160 or REPOSITORY_RE.fullmatch(result) is None:
        _fail("invalid-repository", f"{field} must be owner/repository")
    return result


def _validate_evidence(case: Mapping[str, Any]) -> dict[str, Any]:
    values = _require_list(case.get("evidence"), "case.evidence")
    if not values or len(values) > 256:
        _fail("invalid-evidence-count", "case.evidence must contain 1..256 occurrences")
    required = {
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
    evidence: list[dict[str, Any]] = []
    roots: set[str] = set()
    workflows: set[str] = set()
    opportunities: set[str] = set()
    signatures: dict[str, int] = {}
    repositories: set[str] = set()
    all_events: set[str] = set()
    observed: list[dt.datetime] = []
    for index, value in enumerate(values):
        item = _require_object(value, f"case.evidence[{index}]")
        _exact_fields(item, f"case.evidence[{index}]", required)
        root = _stable_id(item["root_task_id"], f"case.evidence[{index}].root_task_id")
        workflow = _stable_id(item["workflow_id"], f"case.evidence[{index}].workflow_id")
        opportunity = _stable_id(item["opportunity_id"], f"case.evidence[{index}].opportunity_id")
        signature = _sha_digest(
            item["causal_signature"], f"case.evidence[{index}].causal_signature"
        )
        if opportunity in opportunities:
            _fail("duplicate-opportunity", f"duplicate opportunity ID: {opportunity}")
        roots.add(root)
        workflows.add(workflow)
        opportunities.add(opportunity)
        signatures[signature] = signatures.get(signature, 0) + 1
        observed_text = _timestamp(item["observed_at"], f"case.evidence[{index}].observed_at")
        observed.append(_parse_time(observed_text, f"case.evidence[{index}].observed_at"))
        signal = _require_string(item["signal_type"], f"case.evidence[{index}].signal_type")
        if signal not in SIGNAL_TYPES:
            _fail("invalid-signal-type", f"unsupported signal type: {signal}")
        events = _require_list(item["source_event_ids"], "source_event_ids")
        if not 1 <= len(events) <= 16:
            _fail("invalid-source-events", "source_event_ids must contain 1..16 IDs")
        local_events: set[str] = set()
        for event in events:
            event_id = _stable_id(event, "source_event_id")
            if event_id in local_events or event_id in all_events:
                _fail("duplicate-source-event", f"source event is reused: {event_id}")
            local_events.add(event_id)
            all_events.add(event_id)
        _sha_digest(item["source_digest"], f"case.evidence[{index}].source_digest")
        _bounded_string(item["summary"], f"case.evidence[{index}].summary", 8, 400)
        if item["repository"] is not None:
            repositories.add(_repository(item["repository"], f"case.evidence[{index}].repository"))
        evidence.append(item)
    first = min(observed).isoformat().replace("+00:00", "Z")
    last = max(observed).isoformat().replace("+00:00", "Z")
    return {
        "items": evidence,
        "roots": roots,
        "workflows": workflows,
        "opportunities": opportunities,
        "signatures": signatures,
        "repositories": repositories,
        "source_event_ids": all_events,
        "first": first,
        "last": last,
    }


def _validate_control(
    control: Mapping[str, Any], case: Mapping[str, Any], stats: Mapping[str, Any]
) -> str:
    required = {
        "semantic_digest",
        "source_lineage",
        "explicit_human_root_task_id",
        "origin_case_id",
    }
    _exact_fields(control, "control", required)
    digest = _sha_digest(control["semantic_digest"], "control.semantic_digest")
    expected_digest = semantic_digest(case)
    if digest != expected_digest:
        _fail("semantic-digest-mismatch", f"expected control.semantic_digest {expected_digest}")
    lineage_values = _require_list(control["source_lineage"], "control.source_lineage")
    lineage_by_opportunity: dict[str, dict[str, Any]] = {}
    lineage_fields = {
        "opportunity_id",
        "source_family",
        "is_automation_descendant",
        "is_replay",
        "chronology",
    }
    for index, value in enumerate(lineage_values):
        item = _require_object(value, f"control.source_lineage[{index}]")
        _exact_fields(item, f"control.source_lineage[{index}]", lineage_fields)
        opportunity = _stable_id(item["opportunity_id"], "lineage.opportunity_id")
        if opportunity in lineage_by_opportunity:
            _fail("duplicate-lineage", f"duplicate lineage for {opportunity}")
        family = _require_string(item["source_family"], "lineage.source_family")
        if not isinstance(item["is_automation_descendant"], bool) or not isinstance(
            item["is_replay"], bool
        ):
            _fail("invalid-lineage", "lineage descendant/replay flags must be boolean")
        if (
            family in FORBIDDEN_SOURCE_FAMILIES
            or item["is_automation_descendant"] is not False
            or item["is_replay"] is not False
        ):
            _fail(
                "automation-family-evidence",
                "Daily/Weekly families, descendants, and replays cannot supply case evidence",
            )
        if family not in {"human-root", "explicit-human-correction", "legacy-migration"}:
            _fail("invalid-source-family", f"unsupported source family: {family}")
        _require_string(item["chronology"], "lineage.chronology")
        lineage_by_opportunity[opportunity] = item
    if set(lineage_by_opportunity) != stats["opportunities"]:
        _fail("lineage-mismatch", "control.source_lineage must bind every evidence opportunity")
    expected_lineage_order = [item["opportunity_id"] for item in stats["items"]]
    actual_lineage_order = [item["opportunity_id"] for item in lineage_values]
    if actual_lineage_order != expected_lineage_order:
        _fail("lineage-order", "control.source_lineage must follow exact evidence order")

    source_kind = case["source_kind"]
    human_root = control["explicit_human_root_task_id"]
    origin_case = control["origin_case_id"]
    if source_kind == "automation-derived":
        human_root = _stable_id(human_root, "control.explicit_human_root_task_id")
        origin_case = _validate_case_id(origin_case, "control.origin_case_id")
        if origin_case == case["id"]:
            _fail(
                "self-reinforcing-automation",
                "automation-derived evidence cannot reinforce its origin",
            )
        corrections = {
            item["root_task_id"]
            for item in stats["items"]
            if item["signal_type"] == "explicit-human-correction"
        }
        if human_root not in corrections:
            _fail(
                "missing-human-root",
                "automation-derived case requires its explicit correction root",
            )
    elif human_root is not None or origin_case is not None:
        _fail("unexpected-origin", "only automation-derived cases may bind automation origin")
    return digest


def _validate_repairs(value: Any, case_id: str) -> list[dict[str, Any]]:
    repairs = _require_list(value, "case.repairs")
    if len(repairs) > 64:
        _fail("too-many-repairs", "case.repairs exceeds 64 entries")
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
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for index, value_item in enumerate(repairs):
        item = _require_object(value_item, f"case.repairs[{index}]")
        _exact_fields(item, f"case.repairs[{index}]", fields)
        repair_id = _bounded_string(item["id"], f"case.repairs[{index}].id", 2, 12)
        if REPAIR_ID_RE.fullmatch(repair_id) is None or repair_id in seen:
            _fail("invalid-repair-id", f"invalid or duplicate repair ID: {repair_id}")
        repair_repository = _repository(item["repository"], f"case.repairs[{index}].repository")
        action = _require_string(item["action"], f"case.repairs[{index}].action")
        repair_state = _require_string(item["state"], f"case.repairs[{index}].state")
        if action not in {"install", "amend", "remove-forward"}:
            _fail("invalid-repair-action", f"unsupported repair action: {action}")
        if repair_state not in {"planned", "open", "merged", "superseded"}:
            _fail("invalid-repair-state", f"unsupported repair state: {repair_state}")
        _bounded_string(item["problem_statement"], "repair.problem_statement", 16, 800)
        _bounded_string(item["change_summary"], "repair.change_summary", 8, 500)
        pr_url = item["pull_request_url"]
        if pr_url is not None:
            pr_url = _bounded_string(pr_url, f"repair {repair_id} pull_request_url", 20, 240)
            if PR_URL_RE.fullmatch(pr_url) is None:
                _fail("invalid-pull-request", f"invalid pull request URL for {repair_id}")
            if not pr_url.startswith(f"https://github.com/{repair_repository}/pull/"):
                _fail("invalid-pull-request", "repair PR owner/repository must match repair")
        commit = item["commit"]
        if commit is not None and (
            not isinstance(commit, str) or COMMIT_RE.fullmatch(commit) is None
        ):
            _fail("invalid-commit", f"invalid commit for {repair_id}")
        if item["commit_trailer"] != f"Friction-Case: {case_id}":
            _fail("invalid-repair-trailer", f"repair {repair_id} trailer must bind {case_id}")
        installed = _date(item["installed_on"], "repair.installed_on", nullable=True)
        removed = _date(item["removed_on"], "repair.removed_on", nullable=True)
        replaces = item["replaces_repair_id"]
        if replaces is not None:
            replaces = _bounded_string(replaces, "repair.replaces_repair_id", 2, 12)
            if REPAIR_ID_RE.fullmatch(replaces) is None:
                _fail("invalid-repair-reference", f"invalid replaces_repair_id for {repair_id}")
        if repair_state == "planned" and any(
            child is not None for child in (pr_url, commit, installed, removed)
        ):
            _fail("invalid-planned-repair", f"planned repair {repair_id} carries durable data")
        if repair_state == "open" and (
            pr_url is None or any(child is not None for child in (commit, installed, removed))
        ):
            _fail("invalid-open-repair", f"open repair {repair_id} has invalid durable data")
        completed_repair = repair_state == "merged" or (
            repair_state == "superseded" and commit is not None
        )
        if completed_repair:
            if pr_url is None or commit is None:
                _fail("incomplete-repair", f"{repair_state} repair {repair_id} needs PR and commit")
            if action == "remove-forward":
                if removed is None or installed is not None:
                    _fail("invalid-forward-removal", f"repair {repair_id} needs removed_on only")
            elif installed is None or removed is not None:
                _fail("invalid-installed-repair", f"repair {repair_id} needs installed_on only")
        elif repair_state == "superseded" and any(
            child is not None for child in (installed, removed)
        ):
            _fail("incomplete-repair", "unmerged superseded repair cannot carry completion dates")
        if action == "remove-forward":
            if replaces is None or replaces not in seen:
                _fail(
                    "invalid-forward-removal", f"repair {repair_id} must replace an earlier repair"
                )
            if commit is not None and any(prior["commit"] == commit for prior in result):
                _fail(
                    "invalid-forward-removal",
                    "forward removal commit must differ from every earlier repair commit",
                )
            replaced = next((prior for prior in result if prior["id"] == replaces), None)
            if replaced is not None:
                if (
                    replaced["action"] not in {"install", "amend"}
                    or replaced["state"] != "superseded"
                    or replaced["commit"] is None
                    or replaced["installed_on"] is None
                ):
                    _fail(
                        "invalid-forward-removal",
                        "forward removal must replace completed superseded install/amend",
                    )
                if replaced["repository"] != repair_repository:
                    _fail("invalid-forward-removal", "forward removal repository must match")
                if commit is not None and commit == replaced["commit"]:
                    _fail("invalid-forward-removal", "removal commit must differ from install")
                replaced_date = _date(replaced["installed_on"], "replaced.installed_on")
                if removed is not None and replaced_date is not None and removed < replaced_date:
                    _fail("invalid-forward-removal", "removal cannot predate installation")
                eligible_prior = [
                    prior
                    for prior in result
                    if prior["repository"] == repair_repository
                    and prior["action"] in {"install", "amend"}
                    and prior["state"] == "superseded"
                    and prior["commit"] is not None
                    and prior["installed_on"] is not None
                ]
                if eligible_prior:
                    latest = max(
                        eligible_prior,
                        key=lambda prior: (
                            _date(prior["installed_on"], "prior.installed_on"),
                            result.index(prior),
                        ),
                    )
                    if replaces != latest["id"]:
                        _fail("invalid-forward-removal", "removal must replace latest installation")
        elif replaces is not None:
            _fail("invalid-repair-reference", "only forward removal may replace a repair")
        seen.add(repair_id)
        result.append(item)
    return result


def _validate_effectiveness(value: Any) -> dict[str, Any]:
    obj = _require_object(value, "case.effectiveness")
    fields = {"method", "state", "checked_on", "summary", "deterministic", "behavioral"}
    _exact_fields(obj, "case.effectiveness", fields)
    method = _require_string(obj["method"], "case.effectiveness.method")
    state = _require_string(obj["state"], "case.effectiveness.state")
    if method not in {"none", "deterministic", "behavioral", "both"}:
        _fail("invalid-effectiveness", f"unsupported effectiveness method: {method}")
    if state not in {"not-started", "monitoring", "passed", "failed"}:
        _fail("invalid-effectiveness", f"unsupported effectiveness state: {state}")
    checked = _date(obj["checked_on"], "case.effectiveness.checked_on", nullable=True)
    summary = obj["summary"]
    if summary is not None:
        _bounded_string(summary, "case.effectiveness.summary", 8, 500)

    deterministic = obj["deterministic"]
    if deterministic is not None:
        deterministic = _require_object(deterministic, "case.effectiveness.deterministic")
        _exact_fields(
            deterministic, "case.effectiveness.deterministic", {"test_ref", "result", "commit"}
        )
        _bounded_string(deterministic["test_ref"], "effectiveness.deterministic.test_ref", 5, 300)
        if deterministic["result"] not in {"pending", "passed", "failed"}:
            _fail(
                "invalid-deterministic-result",
                "deterministic result must be pending, passed, or failed",
            )
        if (
            not isinstance(deterministic["commit"], str)
            or COMMIT_RE.fullmatch(deterministic["commit"]) is None
        ):
            _fail("invalid-commit", "deterministic commit must be a Git object ID")

    behavioral = obj["behavioral"]
    started: dt.date | None = None
    ended: dt.date | None = None
    if behavioral is not None:
        behavioral = _require_object(behavioral, "case.effectiveness.behavioral")
        _exact_fields(
            behavioral,
            "case.effectiveness.behavioral",
            {"started_on", "ended_on", "relevant_opportunities", "recurrences"},
        )
        started = _date(behavioral["started_on"], "behavioral.started_on")
        ended = _date(behavioral["ended_on"], "behavioral.ended_on", nullable=True)
        opportunities = _require_int(
            behavioral["relevant_opportunities"], "behavioral.relevant_opportunities", minimum=0
        )
        recurrences = _require_int(behavioral["recurrences"], "behavioral.recurrences", minimum=0)
        if opportunities > 1_000_000 or recurrences > 1_000_000:
            _fail("invalid-behavioral-count", "behavioral counts exceed the ledger bound")
        if ended is not None and started is not None and ended < started:
            _fail("invalid-behavioral-window", "behavioral ended_on precedes started_on")
        if checked is not None and ended is not None and checked < ended:
            _fail("invalid-effectiveness-date", "checked_on precedes behavioral ended_on")
        if checked is not None and started is not None and checked < started:
            _fail("invalid-effectiveness-date", "checked_on precedes behavioral started_on")
        if recurrences > opportunities:
            _fail("invalid-behavioral-count", "recurrences cannot exceed opportunities")

    if method == "none":
        if state != "not-started" or any(
            child is not None for child in (checked, summary, deterministic, behavioral)
        ):
            _fail("invalid-effectiveness", "method none requires an empty not-started state")
        return obj
    if state == "not-started":
        if any(child is not None for child in (checked, summary, deterministic, behavioral)):
            _fail("invalid-effectiveness", "not-started effectiveness must carry no results")
        return obj

    uses_deterministic = method in {"deterministic", "both"}
    uses_behavioral = method in {"behavioral", "both"}
    if uses_deterministic != (deterministic is not None):
        _fail("invalid-effectiveness", "deterministic result presence must match method")
    if uses_behavioral != (behavioral is not None):
        _fail("invalid-effectiveness", "behavioral result presence must match method")
    if checked is None or summary is None:
        _fail("invalid-effectiveness", "active or completed effectiveness needs date and summary")
    if state == "monitoring":
        if behavioral is not None and ended is not None:
            _fail("invalid-effectiveness", "behavioral monitoring cannot have ended_on")
        if behavioral is not None and behavioral["recurrences"] != 0:
            _fail("invalid-effectiveness", "monitoring behavioral evidence requires no recurrence")
        if deterministic is not None:
            expected = "pending" if method == "deterministic" else "passed"
            if deterministic["result"] != expected:
                _fail(
                    "invalid-effectiveness",
                    f"{method} monitoring requires deterministic {expected}",
                )
    if state in {"passed", "failed"} and behavioral is not None and ended is None:
        _fail("invalid-effectiveness", "completed behavioral evaluation needs ended_on")
    if state == "passed":
        if deterministic is not None and deterministic["result"] != "passed":
            _fail("invalid-effectiveness", "passed effectiveness needs deterministic pass")
        if behavioral is not None:
            if behavioral["relevant_opportunities"] < 3 or behavioral["recurrences"] != 0:
                _fail(
                    "invalid-effectiveness",
                    "behavioral pass needs 3 opportunities and no recurrence",
                )
            assert started is not None and ended is not None
            if (ended - started).days < 7:
                _fail("invalid-effectiveness", "behavioral pass needs at least seven days")
    if state == "failed":
        if method == "deterministic" and deterministic is not None:
            if deterministic["result"] != "failed":
                _fail("invalid-effectiveness", "failed deterministic needs failed test")
        elif method == "behavioral" and behavioral is not None:
            if behavioral["recurrences"] <= 0:
                _fail("invalid-effectiveness", "failed behavioral gate needs recurrence")
        elif method == "both":
            assert deterministic is not None and behavioral is not None
            if deterministic["result"] == "pending":
                _fail("invalid-effectiveness", "completed both gate cannot remain pending")
            if deterministic["result"] != "failed" and behavioral["recurrences"] <= 0:
                _fail("invalid-effectiveness", "failed both gate needs a failed component")
    return obj


def _validate_status_repair_contract(
    case: Mapping[str, Any], repairs: Sequence[Mapping[str, Any]], effectiveness: Mapping[str, Any]
) -> None:
    status = case["status"]
    active = [repair for repair in repairs if repair["state"] != "superseded"]
    completed = [
        repair
        for repair in repairs
        if repair["state"] == "merged"
        or (repair["state"] == "superseded" and repair["commit"] is not None)
    ]
    installed = [
        repair
        for repair in completed
        if repair["action"] in {"install", "amend"} and repair["installed_on"] is not None
    ]
    dated_installed = [
        (
            _date(repair["installed_on"], "repair.installed_on"),
            index,
            repair,
        )
        for index, repair in enumerate(installed)
    ]
    latest_installed = (
        max(dated_installed, key=lambda item: (item[0], item[1]))[2] if dated_installed else None
    )
    forward = [repair for repair in repairs if repair["action"] == "remove-forward"]
    if status in {"approved", "implemented", "observing", "closed"} and not repairs:
        _fail("missing-repair", f"status {status} requires a repair")
    if (repairs or status in {"approved", "implemented", "observing", "closed"}) and effectiveness[
        "method"
    ] == "none":
        _fail("missing-effectiveness-method", "a selected repair requires an effectiveness method")
    if not repairs and effectiveness["method"] != "none":
        _fail("invalid-effectiveness", "no repair selected requires method none")
    if status == "watching" and repairs:
        _fail("premature-repair", "watching cases cannot contain repairs")
    if status == "proposed" and not (len(active) == 1 and active[0]["state"] == "planned"):
        _fail("premature-repair", "proposed requires exactly one active planned repair")
    if status == "approved" and not (
        len(active) == 1 and active[0]["state"] in {"planned", "open"}
    ):
        _fail("premature-installation", "approved requires one active planned/open repair")
    if status in {"implemented", "observing", "closed"} and not (
        len(active) == 1
        and active[0]["state"] == "merged"
        and active[0]["action"] in {"install", "amend"}
    ):
        _fail("missing-merged-repair", f"status {status} requires one active merged install")
    required_state = {
        "watching": "not-started",
        "proposed": "not-started",
        "approved": "not-started",
        "dormant": "not-started",
        "implemented": "not-started",
        "observing": "monitoring",
        "closed": "passed",
    }
    if status in required_state and effectiveness["state"] != required_state[status]:
        _fail("effectiveness-status-mismatch", f"status {status} requires {required_state[status]}")
    if status in {"closed", "superseded"} and effectiveness["checked_on"] is not None:
        checked = _date(effectiveness["checked_on"], "case.effectiveness.checked_on")
        changed = _parse_time(case["lifecycle_changed_at"], "case.lifecycle_changed_at").date()
        if checked is not None and changed < checked:
            _fail("clock-order", "terminal lifecycle change cannot predate effectiveness check")
    if status == "closed":
        evidence_last_seen = _parse_time(case["evidence_last_seen"], "evidence_last_seen")
        if evidence_last_seen > _parse_time(case["lifecycle_changed_at"], "lifecycle_changed_at"):
            _fail("clock-order", "closed case cannot retain post-closure recurrence")
        checked = _date(effectiveness["checked_on"], "case.effectiveness.checked_on")
        if checked is not None and evidence_last_seen.date() > checked:
            _fail(
                "clock-order",
                "closed case cannot retain evidence observed after its passed check",
            )
    if effectiveness["state"] == "failed" and status != "superseded":
        _fail("effectiveness-status-mismatch", "failed effectiveness requires superseded")
    if status == "dormant":
        origin = case["lifecycle"]["dormant_from_status"]
        valid_active = (
            not active
            if origin == "watching"
            else (len(active) == 1 and active[0]["state"] == "planned")
        )
        if not valid_active or completed or effectiveness["state"] != "not-started":
            _fail("invalid-dormant-repair", "dormant repair state must match its origin")
    if status == "superseded":
        replacement = case["lifecycle"]["superseded_by"]
        completed_removals = [
            repair
            for repair in active
            if repair["action"] == "remove-forward"
            and repair["state"] == "merged"
            and repair["commit"] is not None
            and repair["removed_on"] is not None
        ]
        if replacement is not None and active:
            _fail("invalid-supersession", "replacement supersession cannot retain active repair")
        if replacement is None and not (len(active) == 1 and len(completed_removals) == 1):
            _fail("invalid-supersession", "forward supersession requires one merged removal")
        if completed_removals:
            removed = _date(completed_removals[0]["removed_on"], "repair.removed_on")
            if _parse_time(case["lifecycle_changed_at"], "lifecycle_changed_at").date() < removed:
                _fail("clock-order", "superseded lifecycle predates forward removal")
    if forward:
        if not case["lifecycle"]["revisit_when"]:
            _fail("invalid-forward-removal", "forward removal needs revisit_when")
        if case["applicability"]["state"] not in {"changed", "absent"}:
            _fail(
                "invalid-forward-removal", "forward removal needs changed or absent applicability"
            )
    if effectiveness["state"] in {"passed", "failed"}:
        if latest_installed is None:
            _fail(
                "invalid-effectiveness",
                "completed effectiveness requires installed repair history",
            )
        latest_installed_on = _date(latest_installed["installed_on"], "repair.installed_on")
        checked_on = _date(effectiveness["checked_on"], "effectiveness.checked_on")
        if checked_on is None or latest_installed_on is None or checked_on < latest_installed_on:
            _fail(
                "invalid-effectiveness",
                "terminal evaluation cannot predate latest installed repair",
            )
    if status in {"implemented", "observing", "closed"} and len(active) == 1:
        if status == "implemented":
            installed_dates = [
                _date(repair["installed_on"], "repair.installed_on") for repair in installed
            ]
            installed_on = min(installed_dates) if installed_dates else None
        else:
            installed_on = _date(active[0]["installed_on"], "current.installed_on")
        if installed_on is None:
            _fail("clock-order", "installed lifecycle state needs installed repair history")
        if _parse_time(case["lifecycle_changed_at"], "lifecycle_changed_at").date() < installed_on:
            _fail("clock-order", "installed lifecycle state predates current repair")
    if (
        effectiveness["method"] in {"deterministic", "both"}
        and effectiveness["deterministic"] is not None
    ):
        tested = effectiveness["deterministic"]["commit"]
        allowed = {repair["commit"] for repair in installed}
        if status in {"observing", "closed"} and len(active) == 1:
            allowed = {active[0]["commit"]}
        if tested not in allowed:
            _fail("invalid-effectiveness", "deterministic commit must bind installed repair")
        if (
            effectiveness["state"] in {"passed", "failed"}
            and latest_installed is not None
            and tested != latest_installed["commit"]
        ):
            _fail(
                "invalid-effectiveness",
                "terminal deterministic result must bind latest installed repair",
            )
        checked = _date(effectiveness["checked_on"], "effectiveness.checked_on", nullable=True)
        matching = [
            _date(repair["installed_on"], "repair.installed_on")
            for repair in installed
            if repair["commit"] == tested
        ]
        if checked is not None and matching and checked < max(matching):
            _fail("invalid-effectiveness", "deterministic check predates installation")
    if (
        effectiveness["method"] in {"behavioral", "both"}
        and effectiveness["behavioral"] is not None
    ):
        started = _date(effectiveness["behavioral"]["started_on"], "behavioral.started_on")
        installed_dates = [
            _date(repair["installed_on"], "repair.installed_on") for repair in installed
        ]
        if installed_dates and started < max(installed_dates):
            _fail("invalid-effectiveness", "behavioral window predates latest installation")
    if case["classification"] == "repo-local":
        target = case["scope"]["target_repository"]
        if any(repair["repository"] != target for repair in repairs):
            _fail("repair-scope-mismatch", "repo-local repairs must target case repository")


def validate_candidate(candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the control wrapper and its exact ledger-compatible ``case`` object."""

    _scan_prohibited_content(candidate)
    _exact_fields(candidate, "candidate", {"version", "case", "control"})
    if type(candidate.get("version")) is not int or candidate.get("version") != VERSION:
        _fail("unsupported-version", f"candidate.version must be {VERSION}")
    case = _require_object(candidate.get("case"), "case")
    control = _require_object(candidate.get("control"), "control")
    top_fields = {
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
    _exact_fields(case, "case", top_fields)
    if len(_canonical_bytes(case)) > MAX_CASE_JSON_BYTES:
        _fail(
            "case-too-large",
            f"canonical ledger case exceeds {MAX_CASE_JSON_BYTES} bytes",
        )
    if type(case["schema_version"]) is not int or case["schema_version"] != 1:
        _fail("unsupported-case-version", "case.schema_version must be 1")
    revision = _require_int(case["revision"], "case.revision", minimum=1)
    if revision > 1_000_000:
        _fail("invalid-revision", "case.revision exceeds 1,000,000")
    case_id = _validate_case_id(case["id"], "case.id")
    _bounded_string(case["title"], "case.title", 8, 160)
    status = _require_string(case["status"], "case.status")
    if status not in STATUSES:
        _fail("invalid-status", f"unsupported case.status: {status}")
    support = _require_string(case["support"], "case.support")
    if support == "no_issue":
        _fail(
            "unsupported-no-issue", "no_issue findings are not durable cases and cannot be staged"
        )
    if support not in SUPPORT_RESULTS:
        _fail("invalid-support", f"unsupported case.support: {support}")
    classification = _require_string(case["classification"], "case.classification")
    if classification not in SCOPES:
        _fail("invalid-classification", f"unsupported classification: {classification}")
    source_kind = _require_string(case["source_kind"], "case.source_kind")
    if source_kind not in SOURCE_KINDS:
        _fail("invalid-source-kind", f"unsupported source kind: {source_kind}")

    urgency = _require_object(case["urgency"], "case.urgency")
    _exact_fields(urgency, "case.urgency", {"level", "reason", "source_event_ids"})
    urgency_level = _require_string(urgency["level"], "case.urgency.level")
    if urgency_level not in URGENCIES:
        _fail("invalid-urgency", f"unsupported urgency: {urgency_level}")
    urgency_sources = _require_list(urgency["source_event_ids"], "case.urgency.source_event_ids")
    if len(urgency_sources) > 16:
        _fail("too-many-urgency-sources", "urgency source_event_ids exceeds 16")
    for event in urgency_sources:
        _stable_id(event, "case.urgency.source_event_ids[]")
    if len(urgency_sources) != len(set(urgency_sources)):
        _fail("duplicate-urgency-source", "urgency source_event_ids must be unique")
    urgency_reason = urgency["reason"]
    if urgency_reason is not None and not isinstance(urgency_reason, str):
        _fail("invalid-urgency-reason", "urgency.reason must be a string or null")
    if urgency_level == "high-signal":
        if urgency_reason not in HIGH_SIGNAL_REASONS or not urgency_sources:
            _fail(
                "unsupported-high-signal", "high-signal requires a closed reason and evidence IDs"
            )
    elif urgency["reason"] is not None or urgency_sources:
        _fail("invalid-normal-urgency", "normal urgency cannot carry high-signal evidence")

    stats = _validate_evidence(case)
    if not set(urgency_sources) <= stats["source_event_ids"]:
        _fail("urgency-evidence-mismatch", "urgency source IDs must exist in case evidence")
    if support == "novel" and len(stats["items"]) != 1:
        _fail("invalid-novel", "novel support requires exactly one occurrence")
    if support == "repeated" and (len(stats["items"]) < 2 or max(stats["signatures"].values()) < 2):
        _fail("insufficient-recurrence", "repeated support requires one causal signature twice")

    causal = _require_object(case["causal"], "case.causal")
    causal_fields = {
        "summary",
        "first_observed_at",
        "occurrence_count",
        "root_task_count",
        "workflow_count",
        "repository_count",
        "opportunity_count",
        "causal_signature_count",
    }
    _exact_fields(causal, "case.causal", causal_fields)
    _bounded_string(causal["summary"], "case.causal.summary", 16, 800)
    if _timestamp(causal["first_observed_at"], "case.causal.first_observed_at") != stats["first"]:
        _fail("causal-count-mismatch", "causal.first_observed_at must match earliest evidence")
    expected_counts = {
        "occurrence_count": len(stats["items"]),
        "root_task_count": len(stats["roots"]),
        "workflow_count": len(stats["workflows"]),
        "repository_count": len(stats["repositories"]),
        "opportunity_count": len(stats["opportunities"]),
        "causal_signature_count": len(stats["signatures"]),
    }
    for field, expected in expected_counts.items():
        value = _require_int(causal[field], f"case.causal.{field}", minimum=0)
        if value > 256:
            _fail("causal-count-mismatch", f"case.causal.{field} exceeds 256")
        if causal[field] != expected:
            _fail("causal-count-mismatch", f"case.causal.{field} must equal {expected}")
    if _timestamp(case["evidence_last_seen"], "case.evidence_last_seen") != stats["last"]:
        _fail("clock-mismatch", "evidence_last_seen must match latest evidence")
    currentness_checked_at = _timestamp(
        case["currentness_checked_at"], "case.currentness_checked_at"
    )
    if _parse_time(currentness_checked_at, "case.currentness_checked_at") < _parse_time(
        stats["last"], "evidence_last_seen"
    ):
        _fail("clock-order", "currentness_checked_at cannot precede evidence_last_seen")

    applicability = _require_object(case["applicability"], "case.applicability")
    _exact_fields(applicability, "case.applicability", {"state", "summary"})
    applicability_state = _require_string(applicability["state"], "case.applicability.state")
    if applicability_state not in APPLICABILITY_STATES:
        _fail("invalid-applicability", "unsupported applicability state")
    _bounded_string(applicability["summary"], "case.applicability.summary", 8, 500)

    scope = _require_object(case["scope"], "case.scope")
    _exact_fields(
        scope, "case.scope", {"target_repository", "global_rationale", "global_invariant_kind"}
    )
    target = scope["target_repository"]
    if target is not None:
        target = _repository(target, "case.scope.target_repository")
    if classification == "repo-local":
        if (
            target is None
            or scope["global_rationale"] is not None
            or scope["global_invariant_kind"] is not None
        ):
            _fail("invalid-repo-local-scope", "repo-local scope requires only target_repository")
        evidence_repositories = {item["repository"] for item in stats["items"]}
        if None in evidence_repositories or evidence_repositories != {target}:
            _fail("repo-local-evidence", "repo-local evidence must all match target_repository")
    elif classification == "cross-workflow":
        _bounded_string(scope["global_rationale"], "case.scope.global_rationale", 16, 800)
        if scope["global_invariant_kind"] is not None:
            _fail("invalid-cross-workflow-scope", "cross-workflow cannot claim a global invariant")
        if len(stats["roots"]) < 2 or (
            len(stats["workflows"]) < 2 and len(stats["repositories"]) < 2
        ):
            _fail(
                "insufficient-breadth",
                "cross-workflow requires two roots and workflows or repositories",
            )
    else:
        _bounded_string(scope["global_rationale"], "case.scope.global_rationale", 16, 800)
        if scope["global_invariant_kind"] not in {"authorization", "data-integrity"}:
            _fail(
                "unsealed-global-invariant",
                "global invariant must be authorization or data-integrity",
            )

    lifecycle = _require_object(case["lifecycle"], "case.lifecycle")
    lifecycle_fields = {
        "created_at",
        "dormant_since",
        "dormant_from_status",
        "superseded_by",
        "revisit_when",
    }
    _exact_fields(lifecycle, "case.lifecycle", lifecycle_fields)
    created = _timestamp(lifecycle["created_at"], "case.lifecycle.created_at")
    changed = _timestamp(case["lifecycle_changed_at"], "case.lifecycle_changed_at")
    if _parse_time(changed, "lifecycle_changed_at") < _parse_time(created, "created_at"):
        _fail("clock-order", "lifecycle_changed_at cannot precede created_at")
    if _parse_time(created, "created_at") < _parse_time(stats["first"], "first evidence"):
        _fail("clock-order", "lifecycle.created_at cannot precede first evidence")
    if lifecycle["superseded_by"] is not None:
        superseded_by = _validate_case_id(
            lifecycle["superseded_by"], "case.lifecycle.superseded_by"
        )
        if superseded_by == case_id:
            _fail("self-supersession", "a case cannot supersede itself")
        if status != "superseded":
            _fail("invalid-supersession", "superseded_by is allowed only for superseded status")
    revisit = _require_list(lifecycle["revisit_when"], "case.lifecycle.revisit_when")
    if len(revisit) > 12:
        _fail("too-many-revisit-conditions", "lifecycle.revisit_when exceeds 12")
    for condition in revisit:
        _bounded_string(condition, "case.lifecycle.revisit_when[]", 8, 240)
    if len(revisit) != len(set(revisit)):
        _fail("duplicate-revisit-condition", "lifecycle.revisit_when must be unique")
    if status == "dormant":
        dormant_since = _timestamp(lifecycle["dormant_since"], "case.lifecycle.dormant_since")
        if lifecycle["dormant_from_status"] not in {"watching", "proposed"} or not revisit:
            _fail("invalid-dormancy", "dormant cases require origin status and revisit conditions")
        if dormant_since != changed:
            _fail("invalid-dormancy", "dormant_since must equal lifecycle_changed_at")
    elif lifecycle["dormant_since"] is not None or lifecycle["dormant_from_status"] is not None:
        _fail("invalid-dormancy", "non-dormant cases cannot carry dormancy fields")

    repairs = _validate_repairs(case["repairs"], case_id)
    effectiveness = _validate_effectiveness(case["effectiveness"])
    _validate_status_repair_contract(case, repairs, effectiveness)

    digest = _validate_control(control, case, stats)
    return {
        "case_id": case_id,
        "revision": revision,
        "semantic_digest": digest,
        "status": status,
        "support": support,
        "urgency": urgency_level,
        "classification": classification,
        "occurrence_count": len(stats["items"]),
        "root_count": len(stats["roots"]),
        "workflow_count": len(stats["workflows"]),
    }


def _validate_private_stat(info: os.stat_result, path: Path, *, directory: bool) -> None:
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or stat.S_ISLNK(info.st_mode):
        _fail(
            "unsafe-path", f"expected a non-symlink {'directory' if directory else 'file'}: {path}"
        )
    if info.st_uid != os.geteuid():
        _fail("unsafe-owner", f"path is not owned by the current user: {path}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        _fail("unsafe-permissions", f"path permits group or other access: {path}")
    if not directory and info.st_nlink != 1:
        _fail("unsafe-link-count", f"private state file must have one link: {path}")


def _validate_helper_temp_stat(info: os.stat_result, path: Path, *, expected_links: int) -> None:
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        _fail("unsafe-helper-temp", f"helper temporary is not a regular file: {path}")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        _fail("unsafe-helper-temp", f"helper temporary has unsafe owner or mode: {path}")
    if info.st_nlink != expected_links:
        _fail("unsafe-helper-temp", f"helper temporary has an invalid link count: {path}")
    if info.st_size > MAX_WAL_JSON_BYTES:
        _fail("unsafe-helper-temp", f"helper temporary exceeds the WAL bound: {path}")


def _safe_relative_parts(relative: Path | str) -> tuple[str, ...]:
    value = Path(relative)
    if value.is_absolute() or not value.parts:
        _fail("unsafe-relative-path", f"state path must be non-empty and relative: {value}")
    parts = tuple(value.parts)
    if any(part in {"", ".", ".."} or "/" in part or "\x00" in part for part in parts):
        _fail("unsafe-relative-path", f"unsafe state path component: {value}")
    return parts


def _json_limit_for_parts(parts: Sequence[str]) -> int:
    if parts and parts[0] == "wal":
        return MAX_WAL_JSON_BYTES
    if parts and parts[0] == "publication":
        return MAX_PUBLICATION_JSON_BYTES
    return MAX_JSON_BYTES


class _ImmutablePublicationCapture:
    """Record proof that one write linked a new immutable final leaf."""

    def __init__(self, relative: Path, expected_digest: str) -> None:
        self.relative = relative
        self.expected_digest = expected_digest
        self.published_digest: str | None = None
        self.identity: tuple[int, int] | None = None


class StateStore:
    """Descriptor-rooted owner-private state storage.

    The retained directory descriptors protect the complete path from the
    filesystem root through the selected state root.  Every path component is
    bound to its object identity, type, access policy, and parent-visible name.
    Timestamps and directory link counts are deliberately excluded because
    ordinary child-entry churn can change them without replacing the protected
    object or its access policy.  Every child lookup is relative to a validated
    directory fd with ``O_NOFOLLOW``.  Reads bind content by a repeated bounded
    read, while writes fsync both the file and every newly changed parent
    directory entry.
    """

    def __init__(self, root: Path, *, create: bool = True) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        if self.root == Path(self.root.anchor):
            _fail("unsafe-state-root", "state root cannot be a filesystem root")
        self._ancestor_fds: list[int] = []
        self._chain_names: list[str | None] = []
        self._chain_signals: list[tuple[int, int, int, int, int, int]] = []
        self.root_fd = -1
        self.lock_fd = -1
        self.lock_identity: tuple[int, int, int] | None = None
        self._immutable_publication_capture: _ImmutablePublicationCapture | None = None
        try:
            self._open_root(create=create)
        except Exception:
            self.close()
            raise

    def _open_root(self, *, create: bool) -> None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        current = os.open(self.root.anchor, flags)
        self._ancestor_fds.append(current)
        self._chain_names.append(None)
        self._chain_signals.append(self._directory_signal(os.fstat(current), self.root.anchor))
        parts = self.root.parts[1:]
        for index, component in enumerate(parts):
            final = index == len(parts) - 1
            try:
                child = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    _fail("missing-state-root", f"state root is not initialized: {self.root}")
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                    os.fsync(current)
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=current)
            child_signal = self._directory_signal(
                os.fstat(child), Path(self.root.anchor, *parts[: index + 1])
            )
            self._chain_names.append(component)
            self._chain_signals.append(child_signal)
            if final:
                self.root_fd = child
            else:
                self._ancestor_fds.append(child)
                current = child
        if self.root_fd < 0:
            _fail("unsafe-state-root", f"could not open state root: {self.root}")
        root_stat = os.fstat(self.root_fd)
        _validate_private_stat(root_stat, self.root, directory=True)
        self._bind_state_chain("opening")

    def close(self) -> None:
        if self.lock_fd >= 0:
            os.close(self.lock_fd)
            self.lock_fd = -1
        if self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1
        seen: set[int] = set()
        for fd in reversed(self._ancestor_fds):
            if fd not in seen and fd >= 0:
                os.close(fd)
                seen.add(fd)
        self._ancestor_fds.clear()
        self._chain_names.clear()
        self._chain_signals.clear()

    @staticmethod
    def _directory_signal(
        info: os.stat_result, path: Path | str
    ) -> tuple[int, int, int, int, int, int]:
        """Return only object-identity, type, and access-policy signals."""

        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            _fail("unsafe-state-chain", f"state path component is not a directory: {path}")
        permissions = stat.S_IMODE(info.st_mode)
        group_bits = (permissions & stat.S_IRWXG) >> 3
        other_bits = permissions & stat.S_IRWXO
        # Group identity changes no mode-based access when the group and other
        # permission classes are identical, so normalize that non-policy signal.
        policy_group = info.st_gid if group_bits != other_bits else -1
        return (
            info.st_dev,
            info.st_ino,
            stat.S_IFMT(info.st_mode),
            info.st_uid,
            policy_group,
            permissions,
        )

    def _bind_state_chain(self, phase: str) -> None:
        """Revalidate every retained directory and its parent-visible name."""

        chain_fds = [*self._ancestor_fds, self.root_fd]
        if not (
            len(chain_fds) == len(self._chain_names) == len(self._chain_signals)
            and self.root_fd >= 0
        ):
            _fail("invalid-state-chain", "state directory binding is incomplete")
        for index, (fd, name, expected) in enumerate(
            zip(chain_fds, self._chain_names, self._chain_signals, strict=True)
        ):
            component_path = Path(self.root.anchor, *self.root.parts[1 : index + 1])
            try:
                opened = os.fstat(fd)
            except OSError as exc:
                _fail(
                    "state-chain-revalidation-failed",
                    f"could not inspect retained state path component during {phase}: "
                    f"{component_path}: {exc}",
                )
            opened_signal = self._directory_signal(opened, component_path)
            if opened_signal[:3] != expected[:3]:
                _fail(
                    "state-chain-replaced",
                    f"state path component identity changed during {phase}: {component_path}",
                )
            if opened_signal[3:] != expected[3:]:
                _fail(
                    "state-chain-policy-changed",
                    f"state path component access policy changed during {phase}: {component_path}",
                )
            if index == 0:
                continue
            assert name is not None
            try:
                named = os.stat(name, dir_fd=chain_fds[index - 1], follow_symlinks=False)
            except (FileNotFoundError, NotADirectoryError):
                _fail(
                    "state-chain-replaced",
                    f"state path component disappeared during {phase}: {component_path}",
                )
            except PermissionError as exc:
                _fail(
                    "state-chain-unreadable",
                    f"state path component became unreadable during {phase}: "
                    f"{component_path}: {exc}",
                )
            except OSError as exc:
                _fail(
                    "state-chain-revalidation-failed",
                    f"could not revalidate state path component during {phase}: "
                    f"{component_path}: {exc}",
                )
            named_signal = self._directory_signal(named, component_path)
            if named_signal[:3] != expected[:3]:
                _fail(
                    "state-chain-replaced",
                    f"state path component name was rebound during {phase}: {component_path}",
                )
            if named_signal[3:] != expected[3:]:
                _fail(
                    "state-chain-policy-changed",
                    f"state path component name policy changed during {phase}: {component_path}",
                )
        try:
            final_root = os.fstat(self.root_fd)
        except OSError as exc:
            _fail(
                "state-chain-revalidation-failed",
                f"could not inspect state root during {phase}: {self.root}: {exc}",
            )
        _validate_private_stat(final_root, self.root, directory=True)

    def acquire_lock(self, *, create: bool = True) -> None:
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        if create:
            flags |= os.O_CREAT
        self._bind_state_chain("lock preflight")
        try:
            self.lock_fd = os.open(LOCK_FILE, flags, 0o600, dir_fd=self.root_fd)
        except FileNotFoundError:
            _fail("uninitialized-state", "state root has no trusted lock object")
        except OSError as exc:
            _fail("unsafe-lock", f"cannot open state lock: {exc}")
        before = os.fstat(self.lock_fd)
        _validate_private_stat(before, self.root / LOCK_FILE, directory=False)
        self.lock_identity = (before.st_dev, before.st_ino, before.st_nlink)
        self._bind_lock("before acquisition")
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
        self._bind_state_chain("after lock acquisition")
        self._bind_lock("after acquisition")

    def _bind_lock(self, phase: str) -> None:
        assert self.lock_identity is not None and self.lock_fd >= 0
        opened = os.fstat(self.lock_fd)
        try:
            named = os.stat(LOCK_FILE, dir_fd=self.root_fd, follow_symlinks=False)
        except FileNotFoundError:
            _fail("lock-replaced", f"state lock disappeared {phase}")
        for info in (opened, named):
            _validate_private_stat(info, self.root / LOCK_FILE, directory=False)
        expected = self.lock_identity
        if (opened.st_dev, opened.st_ino, opened.st_nlink) != expected or (
            named.st_dev,
            named.st_ino,
            named.st_nlink,
        ) != expected:
            _fail("lock-replaced", f"state lock identity changed {phase}")

    def finish(self) -> None:
        self._bind_state_chain("transaction completion")
        self._bind_lock("at transaction completion")

    def relative(self, path: Path) -> Path:
        absolute = Path(os.path.abspath(os.fspath(path)))
        try:
            return absolute.relative_to(self.root)
        except ValueError:
            _fail("outside-state-root", f"path is outside state root: {path}")

    @contextmanager
    def open_dir(self, relative: Path | str, *, create: bool = False) -> Iterator[int]:
        parts = _safe_relative_parts(relative)
        current = os.dup(self.root_fd)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            for component in parts:
                try:
                    child = os.open(component, flags, dir_fd=current)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(component, 0o700, dir_fd=current)
                        os.fsync(current)
                    except FileExistsError:
                        pass
                    child = os.open(component, flags, dir_fd=current)
                info = os.fstat(child)
                _validate_private_stat(info, self.root / Path(*parts), directory=True)
                os.close(current)
                current = child
            yield current
        finally:
            os.close(current)

    def exists(self, relative: Path | str) -> bool:
        parts = _safe_relative_parts(relative)
        context = None
        if len(parts) == 1:
            parent_fd = self.root_fd
        else:
            try:
                context = self.open_dir(Path(*parts[:-1]))
                parent_fd = context.__enter__()
            except FileNotFoundError:
                return False
        try:
            try:
                info = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if stat.S_ISLNK(info.st_mode):
                _fail("unsafe-path", f"state entry is a symlink: {Path(*parts)}")
            return True
        finally:
            if context is not None:
                context.__exit__(None, None, None)

    def read_bytes(
        self, relative: Path | str, *, max_bytes: int | None = None
    ) -> tuple[bytes, str]:
        parts = _safe_relative_parts(relative)
        if len(parts) == 1:
            parent_fd = self.root_fd
            context = None
        else:
            context = self.open_dir(Path(*parts[:-1]))
            try:
                parent_fd = context.__enter__()
            except FileNotFoundError:
                _fail("missing-file", f"required state file is missing: {Path(*parts)}")
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            try:
                fd = os.open(parts[-1], flags, dir_fd=parent_fd)
            except FileNotFoundError:
                _fail("missing-file", f"required state file is missing: {Path(*parts)}")
            try:
                self._recover_link_publication(parent_fd, parts[-1], fd)
                return _read_fd_stable(
                    fd,
                    str(self.root / Path(*parts)),
                    private=True,
                    max_bytes=(_json_limit_for_parts(parts) if max_bytes is None else max_bytes),
                    expected_parent_fd=parent_fd,
                    expected_name=parts[-1],
                )
            finally:
                os.close(fd)
        finally:
            if context is not None:
                context.__exit__(None, None, None)

    def unlink_exact(
        self,
        relative: Path | str,
        expected_digest: str,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        """Remove one exact helper-owned leaf without following a rebound name.

        Device/inode equality protects object identity, the digest protects the
        expected immutable content, and the ordinary stable private-file read
        protects type and access policy.  Timestamps are deliberately excluded;
        the one recoverable helper temp alias is cleaned before the required
        single-link check because it is publication churn, not object mutation.
        """

        parts = _safe_relative_parts(relative)
        if len(parts) == 1:
            parent_fd = self.root_fd
            context = None
        else:
            context = self.open_dir(Path(*parts[:-1]), create=False)
            try:
                parent_fd = context.__enter__()
            except FileNotFoundError:
                _fail("rollback-target-missing", f"rollback parent is missing: {Path(*parts)}")
        try:
            current = self._read_named(
                parent_fd,
                parts[-1],
                Path(*parts),
                max_bytes=_json_limit_for_parts(parts),
                expected_identity=expected_identity,
            )
            if hashlib.sha256(current).hexdigest() != expected_digest:
                _fail("rollback-target-drift", f"rollback target changed: {Path(*parts)}")
            self._bind_state_chain("before exact rollback")
            if self.lock_fd >= 0:
                self._bind_lock("before exact rollback")
            try:
                named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                _fail("rollback-target-missing", f"rollback target is missing: {Path(*parts)}")
            _validate_private_stat(named, self.root / Path(*parts), directory=False)
            if expected_identity is not None and (named.st_dev, named.st_ino) != expected_identity:
                _fail("rollback-target-replaced", f"rollback target was rebound: {Path(*parts)}")
            os.unlink(parts[-1], dir_fd=parent_fd)
            os.fsync(parent_fd)
            self._bind_state_chain("after exact rollback")
        finally:
            if context is not None:
                context.__exit__(None, None, None)

    def read_json(self, relative: Path | str) -> tuple[dict[str, Any], str]:
        raw, digest = self.read_bytes(relative)
        return _json_from_bytes(raw, str(self.root / Path(relative))), digest

    def list_names(self, relative: Path | str) -> list[str]:
        try:
            with self.open_dir(relative) as directory_fd:
                names = os.listdir(directory_fd)
        except FileNotFoundError:
            return []
        return sorted(names, key=os.fsencode)

    def _read_named(
        self,
        parent_fd: int,
        name: str,
        relative: Path,
        *,
        max_bytes: int | None = None,
        expected_identity: tuple[int, int] | None = None,
    ) -> bytes:
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            self._recover_link_publication(parent_fd, name, fd)
            opened = os.fstat(fd)
            if (
                expected_identity is not None
                and (opened.st_dev, opened.st_ino) != expected_identity
            ):
                _fail("rollback-target-replaced", f"rollback target was rebound: {relative}")
            return _read_fd_stable(
                fd,
                str(self.root / relative),
                private=True,
                max_bytes=(
                    _json_limit_for_parts(relative.parts) if max_bytes is None else max_bytes
                ),
                expected_parent_fd=parent_fd,
                expected_name=name,
            )[0]
        finally:
            os.close(fd)

    def _recover_link_publication(self, parent_fd: int, name: str, fd: int) -> None:
        """Finish the only safe link-then-unlink crash state.

        A no-replace publication can be interrupted after linking the final name
        but before removing its private temp name.  Only one same-inode helper
        temp with the exact closed prefix is accepted and removed; every other
        multi-link state remains an access-policy failure.
        """

        info = os.fstat(fd)
        if info.st_nlink == 1:
            return
        prefix = f".{name}.tmp-"
        pattern = re.compile(rf"^{re.escape(prefix)}[1-9][0-9]{{0,19}}-[0-9a-f]{{16}}$")
        aliases: list[str] = []
        for child in os.listdir(parent_fd):
            if not child.startswith(prefix):
                continue
            if pattern.fullmatch(child) is None:
                _fail("unsafe-helper-temp", f"malformed helper temporary: {child}")
            candidate = os.stat(child, dir_fd=parent_fd, follow_symlinks=False)
            _validate_helper_temp_stat(
                candidate,
                self.root / child,
                expected_links=2,
            )
            if (candidate.st_dev, candidate.st_ino) == (info.st_dev, info.st_ino):
                aliases.append(child)
        if info.st_nlink != 2 or len(aliases) != 1:
            _fail("unsafe-link-count", f"private state file has untrusted links: {name}")
        os.unlink(aliases[0], dir_fd=parent_fd)
        os.fsync(parent_fd)

    def recover_wal_temporaries(self, relative: Path | str) -> None:
        """Remove only unambiguous pre-publication WAL temporaries."""

        relative_path = Path(*_safe_relative_parts(relative))
        with self.open_dir(relative_path) as directory_fd:
            # A linked final/temp pair is a post-publication crash.  Reading the
            # final through the ordinary fixed-fd path validates both names and
            # removes only its exact same-inode helper alias.
            for name in sorted(os.listdir(directory_fd), key=os.fsencode):
                if WAL_LEAF_RE.fullmatch(name) is None:
                    continue
                try:
                    fd = os.open(
                        name,
                        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory_fd,
                    )
                except OSError as exc:
                    _fail(
                        "invalid-wal-layout",
                        f"WAL leaf is not a readable private regular file: {name}: {exc}",
                    )
                try:
                    self._recover_link_publication(directory_fd, name, fd)
                    _read_fd_stable(
                        fd,
                        str(self.root / relative_path / name),
                        private=True,
                        max_bytes=MAX_WAL_JSON_BYTES,
                        expected_parent_fd=directory_fd,
                        expected_name=name,
                    )
                finally:
                    os.close(fd)

            temporaries: dict[str, str] = {}
            for name in sorted(os.listdir(directory_fd), key=os.fsencode):
                if not name.startswith("."):
                    continue
                match = WAL_TEMP_RE.fullmatch(name)
                if match is None:
                    _fail("unsafe-helper-temp", f"foreign WAL temporary entry: {name}")
                leaf = match.group("leaf")
                if leaf in temporaries:
                    _fail("unsafe-helper-temp", f"ambiguous WAL temporaries for {leaf}")
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                _validate_helper_temp_stat(
                    info,
                    self.root / relative_path / name,
                    expected_links=1,
                )
                temporaries[leaf] = name

            for leaf, temporary in sorted(temporaries.items()):
                try:
                    os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    os.unlink(temporary, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                    continue
                _fail(
                    "unsafe-helper-temp",
                    f"WAL temporary remains beside an existing final leaf: {leaf}",
                )

    @contextmanager
    def capture_immutable_publication(
        self, relative: Path | str, expected_digest: str
    ) -> Iterator[_ImmutablePublicationCapture]:
        """Capture only a new final link published by the enclosed write."""

        path = Path(*_safe_relative_parts(relative))
        if HEX64_RE.fullmatch(expected_digest) is None:
            _fail("invalid-publication-capture", "publication digest must be raw SHA-256")
        if self._immutable_publication_capture is not None:
            _fail("invalid-publication-capture", "immutable publication capture is nested")
        capture = _ImmutablePublicationCapture(path, expected_digest)
        self._immutable_publication_capture = capture
        try:
            yield capture
        finally:
            self._immutable_publication_capture = None

    def write_json(
        self,
        relative: Path | str,
        value: Mapping[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        parts = _safe_relative_parts(relative)
        payload = _canonical_bytes(value)
        limit = _json_limit_for_parts(parts) if max_bytes is None else max_bytes
        if len(payload) > limit:
            _fail("output-too-large", f"JSON output exceeds {limit} bytes: {Path(*parts)}")
        digest = hashlib.sha256(payload).hexdigest()
        parent_parts = parts[:-1]
        if parent_parts:
            context = self.open_dir(Path(*parent_parts), create=True)
            parent_fd = context.__enter__()
        else:
            context = None
            parent_fd = self.root_fd
        name = parts[-1]
        temporary = f".{name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            try:
                existing = self._read_named(parent_fd, name, Path(*parts), max_bytes=limit)
            except FileNotFoundError:
                existing = None
            if immutable and existing is not None:
                if existing == payload:
                    return digest
                _fail(
                    "immutable-output-exists",
                    "immutable output already exists with other content: "
                    f"{self.root / Path(*parts)}",
                )
            fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
            try:
                offset = 0
                while offset < len(payload):
                    offset += os.write(fd, payload[offset:])
                os.fsync(fd)
                temp_info = os.fstat(fd)
                self._bind_state_chain("before publication")
                if self.lock_fd >= 0:
                    self._bind_lock("before publication")
                named_temp = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(named_temp.st_mode) or (
                    named_temp.st_dev,
                    named_temp.st_ino,
                    named_temp.st_nlink,
                ) != (temp_info.st_dev, temp_info.st_ino, temp_info.st_nlink):
                    _fail("temporary-replaced", "publication temporary object was rebound")
                if immutable:
                    try:
                        os.link(
                            temporary,
                            name,
                            src_dir_fd=parent_fd,
                            dst_dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                    except FileExistsError:
                        existing = self._read_named(parent_fd, name, Path(*parts), max_bytes=limit)
                        if existing != payload:
                            _fail(
                                "immutable-output-exists",
                                "another writer won immutable publication with different content",
                            )
                    else:
                        capture = self._immutable_publication_capture
                        if capture is not None and capture.relative == Path(*parts):
                            capture.published_digest = digest
                            capture.identity = (temp_info.st_dev, temp_info.st_ino)
                    os.fsync(parent_fd)
                else:
                    os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    os.fsync(parent_fd)
            finally:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.fsync(parent_fd)
            final = self._read_named(parent_fd, name, Path(*parts), max_bytes=limit)
            if final != payload:
                _fail("write-verification-failed", f"stored bytes differ: {Path(*parts)}")
            return digest
        finally:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            if context is not None:
                context.__exit__(None, None, None)


_ACTIVE_STORE: contextvars.ContextVar[StateStore | None] = contextvars.ContextVar(
    "daily_skill_friction_state_store", default=None
)


def _active_store_for_path(path: Path) -> StateStore | None:
    store = _ACTIVE_STORE.get()
    if store is None:
        return None
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        absolute.relative_to(store.root)
    except ValueError:
        return None
    return store


def _ensure_private_dir(path: Path) -> None:
    store = _active_store_for_path(path)
    if store is not None:
        relative = store.relative(path)
        if relative == Path("."):
            store._bind_state_chain("directory validation")
        else:
            with store.open_dir(relative, create=True):
                pass
        return
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_private_stat(path.lstat(), path, directory=True)


def _validate_existing_output(path: Path) -> None:
    store = _active_store_for_path(path)
    if store is not None:
        if store.exists(store.relative(path)):
            store.read_bytes(store.relative(path))
        return
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    _validate_private_stat(info, path, directory=False)


def _atomic_write(path: Path, value: Mapping[str, Any], *, immutable: bool = False) -> str:
    store = _active_store_for_path(path)
    if store is not None:
        return store.write_json(store.relative(path), value, immutable=immutable)

    # External immutable outputs use the same no-replace primitive in a private
    # parent.  Mutable state writes are always routed through ``StateStore``.
    _ensure_private_dir(path.parent)
    temporary_root = StateStore(path.parent)
    try:
        return temporary_root.write_json(Path(path.name), value, immutable=immutable)
    finally:
        temporary_root.close()


@contextmanager
def _state_lock(state_root: Path, *, create: bool = True) -> Iterator[StateStore]:
    store: StateStore | None = None
    token: contextvars.Token[StateStore | None] | None = None
    try:
        store = StateStore(state_root, create=create)
        store.acquire_lock(create=create)
        token = _ACTIVE_STORE.set(store)
        yield store
    finally:
        try:
            if store is not None and token is not None:
                store.finish()
        finally:
            if token is not None:
                _ACTIVE_STORE.reset(token)
            if store is not None:
                if store.lock_fd >= 0:
                    try:
                        fcntl.flock(store.lock_fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                store.close()


def _wal_key(operation: str, natural_key: str) -> str:
    return hashlib.sha256(f"{operation}\x00{natural_key}".encode()).hexdigest()


def _wal_paths(operation: str, natural_key: str) -> tuple[Path, Path]:
    key = _wal_key(operation, natural_key)
    base = Path("wal") / operation
    return base / f"{key}.intent.json", base / f"{key}.commit.json"


def _read_optional_state(store: StateStore, relative: Path) -> tuple[bytes, str] | None:
    if not store.exists(relative):
        return None
    return store.read_bytes(relative)


def _planned_write(
    store: StateStore,
    relative: Path,
    value: Mapping[str, Any],
    *,
    immutable: bool,
) -> dict[str, Any]:
    relative = Path(*_safe_relative_parts(relative))
    current = _read_optional_state(store, relative)
    payload = _canonical_bytes(value)
    limit = _json_limit_for_parts(relative.parts)
    if len(payload) > limit:
        _fail("output-too-large", f"planned JSON exceeds {limit} bytes: {relative}")
    return {
        "scope": "state",
        "path": relative.as_posix(),
        "before_sha256": current[1] if current is not None else None,
        "after_sha256": hashlib.sha256(payload).hexdigest(),
        "after": dict(value),
        "immutable": immutable,
    }


def _external_parent_binding(store: StateStore) -> list[dict[str, Any]]:
    """Serialize the protected name, identity, and POSIX policy chain.

    Device, inode, and file type identify each directory object.  Owner and
    permission bits define its coarse POSIX access policy.  Group identity is
    material only when the group and other permission classes differ.  Directory
    timestamps, sizes, and link counts are intentionally absent because ordinary
    child-entry churn can change them without replacing a directory or changing
    the selected access policy.
    """

    names = [store.root.anchor if name is None else name for name in store._chain_names]
    result: list[dict[str, Any]] = []
    for name, signal in zip(names, store._chain_signals, strict=True):
        device, inode, file_type, owner, group, permissions = signal
        group_bits = (permissions & stat.S_IRWXG) >> 3
        other_bits = permissions & stat.S_IRWXO
        result.append(
            {
                "name": name,
                "device": device,
                "inode": inode,
                "file_type": file_type,
                "owner": owner,
                "group": group if group_bits != other_bits else None,
                "permissions": permissions,
            }
        )
    return result


def _validate_external_parent_binding(value: Any, path: Path) -> list[dict[str, Any]]:
    entries = _require_list(value, "wal.external_parent_binding")
    absolute = Path(os.path.abspath(os.fspath(path)))
    expected_names = [absolute.parent.anchor, *absolute.parent.parts[1:]]
    if len(entries) != len(expected_names):
        _fail("invalid-wal", "external parent binding has the wrong path depth")
    normalized: list[dict[str, Any]] = []
    fields = {
        "name",
        "device",
        "inode",
        "file_type",
        "owner",
        "group",
        "permissions",
    }
    for index, (raw, expected_name) in enumerate(zip(entries, expected_names, strict=True)):
        entry = _require_object(raw, f"wal.external_parent_binding[{index}]")
        _exact_fields(entry, f"wal.external_parent_binding[{index}]", fields)
        if entry["name"] != expected_name:
            _fail("invalid-wal", "external parent binding does not match the output path")
        device = _require_int(entry["device"], "wal.parent.device")
        inode = _require_int(entry["inode"], "wal.parent.inode")
        file_type = _require_int(entry["file_type"], "wal.parent.file_type")
        owner = _require_int(entry["owner"], "wal.parent.owner")
        permissions = _require_int(entry["permissions"], "wal.parent.permissions")
        if file_type != stat.S_IFDIR or permissions > 0o7777:
            _fail("invalid-wal", "external parent binding has an invalid directory policy")
        group = entry["group"]
        group_bits = (permissions & stat.S_IRWXG) >> 3
        other_bits = permissions & stat.S_IRWXO
        if group_bits == other_bits:
            if group is not None:
                _fail("invalid-wal", "irrelevant parent group identity must be null")
        else:
            group = _require_int(group, "wal.parent.group")
        normalized.append(
            {
                "name": expected_name,
                "device": device,
                "inode": inode,
                "file_type": file_type,
                "owner": owner,
                "group": group,
                "permissions": permissions,
            }
        )
    final = normalized[-1]
    if final["owner"] != os.geteuid() or final["permissions"] & 0o077:
        _fail("invalid-wal", "external output parent binding is not owner-private")
    return normalized


@contextmanager
def _bound_external_parent(
    path: Path, expected_binding: Any | None = None
) -> Iterator[tuple[StateStore, list[dict[str, Any]]]]:
    """Open an existing external parent without ever recreating its path."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        store = StateStore(absolute.parent, create=False)
    except StateError as exc:
        if exc.code in {"missing-state-root", "missing-state-chain"}:
            _fail(
                "external-parent-missing",
                f"bound external output parent disappeared: {absolute.parent}",
            )
        if exc.code in {"unsafe-owner", "unsafe-permissions"}:
            _fail(
                "external-parent-policy-changed",
                f"bound external output parent policy changed: {absolute.parent}",
            )
        if exc.code in {"unsafe-path", "unsafe-state-chain"}:
            _fail(
                "external-parent-replaced",
                f"bound external output parent is no longer a directory: {absolute.parent}",
            )
        raise
    except OSError as exc:
        if exc.errno in {errno.ENOENT}:
            _fail(
                "external-parent-missing",
                f"bound external output parent disappeared: {absolute.parent}",
            )
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            _fail(
                "external-parent-replaced",
                f"bound external output parent is no longer the directory chain: {absolute.parent}",
            )
        if exc.errno in {errno.EACCES, errno.EPERM}:
            _fail(
                "external-parent-unreadable",
                f"bound external output parent became unreadable: {absolute.parent}",
            )
        _fail(
            "external-parent-revalidation-failed",
            f"could not open bound external output parent {absolute.parent}: {exc}",
        )
    try:
        actual = _external_parent_binding(store)
        if expected_binding is not None:
            expected = _validate_external_parent_binding(expected_binding, absolute)
            for expected_entry, actual_entry in zip(expected, actual, strict=True):
                if any(
                    expected_entry[field] != actual_entry[field]
                    for field in ("name", "device", "inode", "file_type")
                ):
                    _fail(
                        "external-parent-replaced",
                        f"external output parent identity/name chain changed: {absolute.parent}",
                    )
                if any(
                    expected_entry[field] != actual_entry[field]
                    for field in ("owner", "group", "permissions")
                ):
                    _fail(
                        "external-parent-policy-changed",
                        f"external output parent access policy changed: {absolute.parent}",
                    )
        yield store, actual
        store._bind_state_chain("external output completion")
    finally:
        store.close()


def _read_optional_external(parent: StateStore, target: Path) -> tuple[bytes, str] | None:
    leaf = Path(target.name)
    if not parent.exists(leaf):
        return None
    return parent.read_bytes(leaf, max_bytes=MAX_PUBLICATION_JSON_BYTES)


def _planned_external_write(
    path: Path, value: Mapping[str, Any], *, immutable: bool
) -> dict[str, Any]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    payload = _canonical_bytes(value)
    if len(payload) > MAX_PUBLICATION_JSON_BYTES:
        _fail(
            "output-too-large",
            f"planned external JSON exceeds {MAX_PUBLICATION_JSON_BYTES} bytes",
        )
    after_digest = hashlib.sha256(payload).hexdigest()
    with _bound_external_parent(absolute) as (parent, parent_binding):
        current = _read_optional_external(parent, absolute)
        if immutable and current is not None and current[1] != after_digest:
            _fail("immutable-output-exists", f"immutable output already conflicts: {absolute}")
    return {
        "scope": "external",
        "path": str(absolute),
        "parent_binding": parent_binding,
        "before_sha256": current[1] if current is not None else None,
        "after_sha256": after_digest,
        "after": dict(value),
        "immutable": immutable,
    }


def _validate_wal_intent(
    intent: Mapping[str, Any],
    expected_operation: str,
    *,
    allow_committed_legacy_external: bool = False,
) -> bool:
    """Validate an intent and report whether it has an unbound legacy output.

    The original version-1 external schema did not persist parent identity.
    Such an intent is safe only after a matching commit already exists, where it
    can be checked read-only.  It is never eligible for replay.
    """

    _exact_fields(
        intent,
        "wal.intent",
        {
            "version",
            "kind",
            "operation",
            "natural_key",
            "request_digest",
            "captured_at",
            "writes",
            "result",
            "intent_digest",
        },
    )
    if type(intent["version"]) is not int or intent["version"] != VERSION:
        _fail("invalid-wal", "WAL intent has an unsupported version")
    if intent["kind"] != "state-transaction-intent" or intent["operation"] != expected_operation:
        _fail("invalid-wal", "WAL intent kind or operation is invalid")
    if expected_operation not in TRANSACTION_OPERATIONS:
        _fail("invalid-wal", "WAL operation is not supported")
    _safe_object_id(intent["operation"], "wal.operation")
    _require_string(intent["natural_key"], "wal.natural_key")
    if HEX64_RE.fullmatch(_require_string(intent["request_digest"], "wal.request_digest")) is None:
        _fail("invalid-wal", "WAL request_digest must be raw SHA-256")
    _timestamp(intent["captured_at"], "wal.captured_at")
    writes = _require_list(intent["writes"], "wal.writes")
    seen: set[str] = set()
    legacy_external = False
    bound_external = False
    for index, raw_write in enumerate(writes):
        write = _require_object(raw_write, f"wal.writes[{index}]")
        scope = write.get("scope")
        expected_fields = {
            "scope",
            "path",
            "before_sha256",
            "after_sha256",
            "after",
            "immutable",
        }
        if scope == "external" and "parent_binding" in write:
            expected_fields.add("parent_binding")
            bound_external = True
        elif scope == "external":
            if not allow_committed_legacy_external:
                _fail(
                    "legacy-external-wal-unbound",
                    "pending legacy external WAL has no recoverable parent identity binding",
                )
            legacy_external = True
        _exact_fields(
            write,
            f"wal.writes[{index}]",
            expected_fields,
        )
        if scope not in {"state", "external"}:
            _fail("invalid-wal", "WAL write scope is invalid")
        if scope == "external" and expected_operation not in {
            "weekly-plan",
            "finalize-publication",
        }:
            _fail("invalid-wal", "this WAL operation cannot write an external output")
        path = _require_string(write["path"], "wal.path")
        if scope == "state":
            _safe_relative_parts(Path(path))
        else:
            absolute = Path(os.path.abspath(os.fspath(path)))
            if not Path(path).is_absolute() or str(absolute) != path:
                _fail("invalid-wal", "external WAL path must be canonical and absolute")
            _safe_relative_parts(Path(absolute.name))
            if "parent_binding" in write:
                _validate_external_parent_binding(write["parent_binding"], absolute)
        if path in seen:
            _fail("invalid-wal", f"WAL repeats a target: {path}")
        seen.add(path)
        before = write["before_sha256"]
        if before is not None and (
            not isinstance(before, str) or HEX64_RE.fullmatch(before) is None
        ):
            _fail("invalid-wal", "WAL before_sha256 must be null or raw SHA-256")
        after = _require_string(write["after_sha256"], "wal.after_sha256")
        if (
            HEX64_RE.fullmatch(after) is None
            or after
            != hashlib.sha256(
                _canonical_bytes(_require_object(write["after"], "wal.after"))
            ).hexdigest()
        ):
            _fail("invalid-wal", "WAL after-image digest mismatch")
        if not isinstance(write["immutable"], bool):
            _fail("invalid-wal", "WAL immutable flag must be boolean")
        if scope == "external" and write["immutable"] is not True:
            _fail("invalid-wal", "external WAL outputs must be immutable")
    if legacy_external and bound_external:
        _fail("invalid-wal", "WAL cannot mix bound and legacy external outputs")
    _require_object(intent["result"], "wal.result")
    body = {key: value for key, value in intent.items() if key != "intent_digest"}
    if intent["intent_digest"] != _digest(body):
        _fail("invalid-wal", "WAL intent digest mismatch")
    return legacy_external


def _validate_wal_commit(commit: Mapping[str, Any], intent: Mapping[str, Any]) -> None:
    _exact_fields(
        commit,
        "wal.commit",
        {"version", "kind", "operation", "natural_key", "intent_digest", "commit_digest"},
    )
    body = {key: value for key, value in commit.items() if key != "commit_digest"}
    if (
        type(commit["version"]) is not int
        or commit["version"] != VERSION
        or commit["kind"] != "state-transaction-commit"
        or commit["operation"] != intent["operation"]
        or commit["natural_key"] != intent["natural_key"]
        or commit["intent_digest"] != intent["intent_digest"]
        or commit["commit_digest"] != _digest(body)
    ):
        _fail("invalid-wal", "WAL commit does not bind its exact intent")


def _preflight_external_writes(intent: Mapping[str, Any], *, require_after: bool = False) -> None:
    """Reject rebound external destinations before applying any state after-image."""

    for raw_write in intent["writes"]:
        write = _require_object(raw_write, "wal.write")
        if write["scope"] != "external":
            continue
        target = Path(write["path"])
        with _bound_external_parent(target, write["parent_binding"]) as (parent, _):
            current = _read_optional_external(parent, target)
            current_digest = current[1] if current is not None else None
            allowed = (
                {write["after_sha256"]}
                if require_after
                else {write["before_sha256"], write["after_sha256"]}
            )
            if current_digest not in allowed:
                _fail(
                    "wal-target-drift",
                    (
                        f"WAL target is not its exact after-image: {target}"
                        if require_after
                        else f"WAL target is neither its before nor after image: {target}"
                    ),
                )


@contextmanager
def _external_after_image_custody(intent: Mapping[str, Any]) -> Iterator[None]:
    """Hold each bound parent and exact after-image leaf across commit publication."""

    with ExitStack() as stack:
        held: list[tuple[StateStore, Path, int, str]] = []
        for raw_write in intent["writes"]:
            write = _require_object(raw_write, "wal.write")
            if write["scope"] != "external":
                continue
            if "parent_binding" not in write:
                _fail(
                    "legacy-external-wal-unbound",
                    "legacy external WAL cannot acquire commit custody",
                )
            target = Path(write["path"])
            parent, _ = stack.enter_context(_bound_external_parent(target, write["parent_binding"]))
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                fd = os.open(target.name, flags, dir_fd=parent.root_fd)
            except FileNotFoundError:
                _fail("wal-after-image-missing", f"external after-image is missing: {target}")
            except OSError as exc:
                _fail(
                    "wal-after-image-unreadable",
                    f"cannot open external after-image {target}: {exc}",
                )
            stack.callback(os.close, fd)
            _, digest = _read_fd_stable(
                fd,
                str(target),
                private=True,
                max_bytes=MAX_PUBLICATION_JSON_BYTES,
                expected_parent_fd=parent.root_fd,
                expected_name=target.name,
            )
            if digest != write["after_sha256"]:
                _fail("wal-target-drift", f"external target is not its after-image: {target}")
            held.append((parent, target, fd, write["after_sha256"]))
        yield
        for parent, target, fd, expected_digest in held:
            parent._bind_state_chain("after transaction commit")
            _, digest = _read_fd_stable(
                fd,
                str(target),
                private=True,
                max_bytes=MAX_PUBLICATION_JSON_BYTES,
                expected_parent_fd=parent.root_fd,
                expected_name=target.name,
            )
            if digest != expected_digest:
                _fail(
                    "wal-target-drift",
                    f"external after-image changed across transaction commit: {target}",
                )


def _verify_committed_legacy_external_after_images(intent: Mapping[str, Any]) -> None:
    """Read-only check for committed v1 outputs that predate parent bindings."""

    for raw_write in intent["writes"]:
        write = _require_object(raw_write, "wal.write")
        if write["scope"] != "external" or "parent_binding" in write:
            continue
        target = Path(write["path"])
        with _bound_external_parent(target) as (parent, _):
            current = _read_optional_external(parent, target)
            if current is None or current[1] != write["after_sha256"]:
                _fail(
                    "legacy-external-wal-unbound",
                    "committed legacy external WAL after-image is missing or changed; "
                    "automatic replay is unsafe without its original parent identity",
                )


def _apply_wal_intent(store: StateStore, intent: Mapping[str, Any]) -> None:
    if intent["operation"] == "complete-audit":
        _validate_complete_audit_intent_receipts(store, intent)
    _preflight_external_writes(intent)
    for raw_write in intent["writes"]:
        write = _require_object(raw_write, "wal.write")
        target = Path(write["path"])
        if write["scope"] == "state":
            current = _read_optional_state(store, target)
            current_digest = current[1] if current is not None else None
            if current_digest == write["after_sha256"]:
                continue
            if current_digest != write["before_sha256"]:
                _fail(
                    "wal-target-drift",
                    f"WAL target is neither its before nor after image: {target}",
                )
            store.write_json(target, write["after"], immutable=write["immutable"])
            final_digest = store.read_bytes(target)[1]
        else:
            with _bound_external_parent(target, write["parent_binding"]) as (parent, _):
                current = _read_optional_external(parent, target)
                current_digest = current[1] if current is not None else None
                if current_digest == write["after_sha256"]:
                    continue
                if current_digest != write["before_sha256"]:
                    _fail(
                        "wal-target-drift",
                        f"WAL target is neither its before nor after image: {target}",
                    )
                parent.write_json(
                    Path(target.name),
                    write["after"],
                    immutable=write["immutable"],
                    max_bytes=MAX_PUBLICATION_JSON_BYTES,
                )
                final_digest = parent.read_bytes(
                    Path(target.name), max_bytes=MAX_PUBLICATION_JSON_BYTES
                )[1]
        if final_digest != write["after_sha256"]:
            _fail("wal-write-failed", f"WAL target did not reach after-image: {target}")


def _repair_committed_external_after_images(intent: Mapping[str, Any]) -> None:
    """Repair only immutable external leaves from a committed bound intent.

    State after-images may have advanced through later valid transactions and
    must never be replayed merely because an older committed WAL is scanned.
    """

    for raw_write in intent["writes"]:
        write = _require_object(raw_write, "wal.write")
        if write["scope"] != "external":
            continue
        target = Path(write["path"])
        with _bound_external_parent(target, write["parent_binding"]) as (parent, _):
            current = _read_optional_external(parent, target)
            current_digest = current[1] if current is not None else None
            if current_digest == write["after_sha256"]:
                continue
            if current_digest != write["before_sha256"]:
                _fail(
                    "wal-target-drift",
                    f"committed external target is not repairable: {target}",
                )
            parent.write_json(
                Path(target.name),
                write["after"],
                immutable=write["immutable"],
                max_bytes=MAX_PUBLICATION_JSON_BYTES,
            )
            if (
                parent.read_bytes(Path(target.name), max_bytes=MAX_PUBLICATION_JSON_BYTES)[1]
                != write["after_sha256"]
            ):
                _fail("wal-write-failed", f"external repair did not reach after-image: {target}")


def _commit_wal(store: StateStore, intent: Mapping[str, Any]) -> None:
    _, commit_path = _wal_paths(intent["operation"], intent["natural_key"])
    body = {
        "version": VERSION,
        "kind": "state-transaction-commit",
        "operation": intent["operation"],
        "natural_key": intent["natural_key"],
        "intent_digest": intent["intent_digest"],
    }
    commit = {**body, "commit_digest": _digest(body)}
    expected_file_digest = _digest(commit)
    with store.capture_immutable_publication(commit_path, expected_file_digest) as publication:
        try:
            with _external_after_image_custody(intent):
                store._bind_state_chain("before transaction commit")
                stored_digest = store.write_json(commit_path, commit, immutable=True)
                if stored_digest != expected_file_digest:
                    _fail("wal-commit-write-failed", "WAL commit write returned the wrong digest")
        except Exception:
            # Roll back only when this exact write won the no-replace link.  An
            # identical pre-existing or concurrent winner has no capture and is
            # therefore never mistaken for an object owned by this invocation.
            if publication.identity is None:
                raise
            if publication.published_digest != publication.expected_digest:
                _fail(
                    "wal-commit-rollback-failed",
                    "the newly published WAL commit has an unexpected captured digest",
                )
            try:
                store.unlink_exact(
                    commit_path,
                    publication.expected_digest,
                    expected_identity=publication.identity,
                )
            except FileNotFoundError:
                pass
            except Exception as rollback_exc:
                raise StateError(
                    "wal-commit-rollback-failed",
                    "the failed transaction's newly published WAL commit could not "
                    "be removed safely",
                ) from rollback_exc
            raise


def _run_transaction(
    store: StateStore,
    *,
    operation: str,
    natural_key: str,
    request: Mapping[str, Any],
    captured_at: str,
    writes: list[dict[str, Any]],
    result: Mapping[str, Any],
    approved_intent_upper_bound: int | None = None,
) -> dict[str, Any]:
    """Create or replay a deterministic after-image transaction."""

    captured_at = _timestamp(captured_at, "transaction.captured_at")
    request_digest = _digest(request)
    intent_path, commit_path = _wal_paths(operation, natural_key)
    legacy_external = False
    committed = store.exists(commit_path)
    if store.exists(intent_path):
        intent, _ = store.read_json(intent_path)
        legacy_external = _validate_wal_intent(
            intent,
            operation,
            allow_committed_legacy_external=committed,
        )
        if intent["natural_key"] != natural_key or intent["request_digest"] != request_digest:
            _fail("wal-request-conflict", "transaction key already binds a different request")
    else:
        if committed:
            _fail("invalid-wal-layout", "WAL commit exists without its intent")
        body = {
            "version": VERSION,
            "kind": "state-transaction-intent",
            "operation": operation,
            "natural_key": natural_key,
            "request_digest": request_digest,
            "captured_at": captured_at,
            "writes": writes,
            "result": dict(result),
        }
        intent = {**body, "intent_digest": _digest(body)}
        intent_bytes = _canonical_bytes(intent)
        if (
            approved_intent_upper_bound is not None
            and len(intent_bytes) > approved_intent_upper_bound
        ):
            _fail(
                "invalid-selection-preflight",
                "actual publication WAL exceeds its approved upper bound",
            )
        if len(intent_bytes) > MAX_WAL_JSON_BYTES:
            _fail(
                "wal-intent-too-large",
                f"WAL intent exceeds {MAX_WAL_JSON_BYTES} bytes",
            )
        store.write_json(intent_path, intent, immutable=True)
    if (
        approved_intent_upper_bound is not None
        and len(_canonical_bytes(intent)) > approved_intent_upper_bound
    ):
        _fail(
            "invalid-selection-preflight",
            "persisted publication WAL exceeds its approved upper bound",
        )
    if legacy_external:
        _verify_committed_legacy_external_after_images(intent)
        commit, _ = store.read_json(commit_path)
        _validate_wal_commit(commit, intent)
    elif committed:
        commit, _ = store.read_json(commit_path)
        _validate_wal_commit(commit, intent)
        _repair_committed_external_after_images(intent)
        _preflight_external_writes(intent, require_after=True)
    else:
        _apply_wal_intent(store, intent)
        _commit_wal(store, intent)
    return dict(_require_object(intent["result"], "wal.result"))


def _recover_pending_wal(store: StateStore) -> None:
    validated: list[tuple[str, Path, Path | None, str, str | None, bool]] = []
    try:
        operations = store.list_names(Path("wal"))
    except OSError as exc:
        _fail("invalid-wal-layout", f"WAL root is not a private directory: {exc}")
    for operation in operations:
        if (
            SAFE_OBJECT_ID_RE.fullmatch(operation) is None
            or operation not in TRANSACTION_OPERATIONS
        ):
            _fail("invalid-wal-layout", f"unsafe WAL operation directory: {operation}")
        directory = Path("wal") / operation
        try:
            store.recover_wal_temporaries(directory)
            names = store.list_names(directory)
        except OSError as exc:
            _fail(
                "invalid-wal-layout",
                f"WAL operation entry is not a private directory: {operation}: {exc}",
            )

        intent_paths: dict[str, Path] = {}
        commit_paths: dict[str, Path] = {}
        for name in names:
            if WAL_LEAF_RE.fullmatch(name) is None:
                _fail("invalid-wal-layout", f"unexpected WAL entry: {name}")
            key = name[:64]
            target = intent_paths if name.endswith(".intent.json") else commit_paths
            target[key] = directory / name
        orphan_commits = sorted(commit_paths.keys() - intent_paths.keys())
        if orphan_commits:
            _fail(
                "invalid-wal-layout",
                f"WAL commit exists without its intent: {commit_paths[orphan_commits[0]]}",
            )

        for key, intent_path in sorted(intent_paths.items()):
            try:
                intent, intent_file_digest = store.read_json(intent_path)
            except OSError as exc:
                _fail(
                    "invalid-wal-layout",
                    f"WAL intent is not a private regular JSON file: {intent_path}: {exc}",
                )
            candidate_commit = commit_paths.get(key)
            candidate_committed = candidate_commit is not None
            legacy_external = _validate_wal_intent(
                intent,
                operation,
                allow_committed_legacy_external=candidate_committed,
            )
            expected_intent, commit_path = _wal_paths(operation, intent["natural_key"])
            if expected_intent != intent_path:
                _fail("invalid-wal-layout", "WAL filename does not bind its natural key")
            if candidate_commit is not None and candidate_commit != commit_path:
                _fail("invalid-wal-layout", "WAL commit filename does not bind its intent")
            commit_file_digest: str | None = None
            if candidate_commit is not None:
                try:
                    commit, commit_file_digest = store.read_json(candidate_commit)
                except OSError as exc:
                    _fail(
                        "invalid-wal-layout",
                        f"WAL commit is not a private regular JSON file: {candidate_commit}: {exc}",
                    )
                _validate_wal_commit(commit, intent)
            validated.append(
                (
                    operation,
                    intent_path,
                    candidate_commit,
                    intent_file_digest,
                    commit_file_digest,
                    legacy_external,
                )
            )

    # Only replay or repair after the complete WAL namespace and every existing
    # pair have passed canonical-name, private-file, JSON, and exact-binding
    # validation.  Re-read each leaf and compare its content digest so the
    # validation-to-use boundary does not rely on timestamp metadata.
    for (
        operation,
        intent_path,
        commit_path,
        intent_file_digest,
        commit_file_digest,
        legacy_external,
    ) in validated:
        current_intent, current_intent_digest = store.read_json(intent_path)
        if current_intent_digest != intent_file_digest:
            _fail("wal-layout-changed", f"WAL intent changed during recovery: {intent_path}")
        intent = current_intent
        _validate_wal_intent(
            intent,
            operation,
            allow_committed_legacy_external=commit_path is not None,
        )
        if commit_path is not None:
            commit, current_commit_digest = store.read_json(commit_path)
            if current_commit_digest != commit_file_digest:
                _fail("wal-layout-changed", f"WAL commit changed during recovery: {commit_path}")
            _validate_wal_commit(commit, intent)
            if legacy_external:
                _verify_committed_legacy_external_after_images(intent)
            else:
                _repair_committed_external_after_images(intent)
                _preflight_external_writes(intent, require_after=True)
            continue
        _apply_wal_intent(store, intent)
        _commit_wal(store, intent)


def _require_committed_transaction(
    store: StateStore, operation: str, natural_key: str
) -> dict[str, Any]:
    intent_path, commit_path = _wal_paths(operation, natural_key)
    if not store.exists(intent_path) or not store.exists(commit_path):
        _fail("missing-authority-transaction", f"{operation} has no committed control transaction")
    intent, _ = store.read_json(intent_path)
    commit, _ = store.read_json(commit_path)
    legacy_external = _validate_wal_intent(intent, operation, allow_committed_legacy_external=True)
    _validate_wal_commit(commit, intent)
    if legacy_external:
        _verify_committed_legacy_external_after_images(intent)
    else:
        _preflight_external_writes(intent, require_after=True)
    return intent


def _marker_path(root: Path) -> Path:
    return root / STATE_MARKER


def _state_exists(path: Path) -> bool:
    store = _active_store_for_path(path)
    if store is None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(info.st_mode):
            _fail("unsafe-path", f"state entry is a symlink: {path}")
        return True
    return store.exists(store.relative(path))


def _state_list_names(path: Path) -> list[str]:
    store = _active_store_for_path(path)
    if store is None:
        return sorted((item.name for item in path.iterdir()), key=os.fsencode)
    relative = store.relative(path)
    return store.list_names(relative)


def _read_marker(root: Path) -> dict[str, Any] | None:
    path = _marker_path(root)
    if not _state_exists(path):
        return None
    marker = _load_json(path)
    mode = marker.get("mode")
    fields = {"version", "kind", "mode", "state_id", "created_at"}
    if mode in {"live", "historical-replay"}:
        fields.add("bound_at")
    _exact_fields(marker, "state_marker", fields)
    if (
        type(marker.get("version")) is not int
        or marker.get("version") != VERSION
        or marker.get("kind") != "daily-skill-friction-state"
    ):
        _fail("invalid-state-marker", f"invalid state marker: {path}")
    if mode not in {"unbound", "live", "historical-replay"}:
        _fail("invalid-state-marker", f"unsupported state marker mode: {marker.get('mode')}")
    try:
        uuid.UUID(_require_string(marker["state_id"], "state_marker.state_id"))
    except ValueError:
        _fail("invalid-state-marker", "state marker state_id must be UUID")
    created = _parse_time(_timestamp(marker["created_at"], "state_marker.created_at"), "created")
    if mode != "unbound":
        bound = _parse_time(_timestamp(marker["bound_at"], "state_marker.bound_at"), "bound")
        if bound < created:
            _fail("clock-order", "state marker bound_at cannot predate creation")
    return marker


def _ensure_marker(root: Path, now: str) -> dict[str, Any]:
    marker = _read_marker(root)
    if marker is not None:
        return marker
    marker = {
        "version": VERSION,
        "kind": "daily-skill-friction-state",
        "mode": "unbound",
        "state_id": str(uuid.uuid4()),
        "created_at": _timestamp(now, "now"),
    }
    _atomic_write(_marker_path(root), marker, immutable=True)
    return marker


def _bind_marker(root: Path, marker: Mapping[str, Any], mode: str, now: str) -> dict[str, Any]:
    current = marker.get("mode")
    if current not in {"unbound", mode}:
        _fail("state-mode-mismatch", f"state root is {current}, not {mode}")
    if current == mode:
        return dict(marker)
    bound = dict(marker)
    bound["mode"] = mode
    bound["bound_at"] = _timestamp(now, "now")
    _atomic_write(_marker_path(root), bound)
    return bound


def _case_paths(root: Path) -> list[Path]:
    cases = root / "cases"
    if not _state_exists(cases):
        return []
    paths: list[Path] = []
    for year_name in _state_list_names(cases):
        if re.fullmatch(r"[0-9]{4}", year_name) is None:
            _fail("unsafe-case-layout", f"unexpected entry under cases: {year_name}")
        year = cases / year_name
        store = _active_store_for_path(year)
        if store is not None:
            with store.open_dir(store.relative(year)):
                pass
        for name in _state_list_names(year):
            if not name.endswith(".json") or SAFE_OBJECT_ID_RE.fullmatch(name[:-5]) is None:
                _fail("unsafe-case-layout", f"unexpected entry under case year: {name}")
            path = year / name
            # A fixed-fd read validates the entry type, identity and policy.
            _load_json(path)
            paths.append(path)
    return sorted(paths, key=lambda path: os.fsencode(str(path.relative_to(root))))


def _find_case(root: Path, case_id: str) -> Path | None:
    matches = [path for path in _case_paths(root) if path.stem == case_id]
    if len(matches) > 1:
        _fail("duplicate-case", f"case identity exists at multiple paths: {case_id}")
    return matches[0] if matches else None


def _validate_case_graph(root: Path, candidate: Mapping[str, Any]) -> None:
    """Validate replacement references across the post-stage case set."""

    cases: dict[str, Mapping[str, Any]] = {}
    for path in _case_paths(root):
        wrapper = _load_json(path)
        summary = validate_candidate(wrapper)
        case_id = summary["case_id"]
        if case_id in cases:
            _fail("duplicate-case", f"case identity exists at multiple paths: {case_id}")
        cases[case_id] = wrapper["case"]

    candidate_case = candidate["case"]
    cases[candidate_case["id"]] = candidate_case
    successors = {
        case_id: case["lifecycle"]["superseded_by"]
        for case_id, case in cases.items()
        if case["lifecycle"]["superseded_by"] is not None
    }
    for case_id, successor in sorted(successors.items()):
        if successor not in cases:
            _fail(
                "missing-successor",
                f"case {case_id} references missing successor {successor}",
            )

    completed: set[str] = set()
    for start in sorted(cases):
        if start in completed:
            continue
        chain: list[str] = []
        positions: dict[str, int] = {}
        current = start
        while current in cases and current not in completed:
            if current in positions:
                cycle = chain[positions[current] :]
                _fail(
                    "supersession-cycle",
                    "lifecycle.superseded_by cycle: " + " -> ".join([*cycle, current]),
                )
            positions[current] = len(chain)
            chain.append(current)
            successor = successors.get(current)
            if successor is None:
                break
            current = successor
        completed.update(chain)


def _case_year(case_id: str) -> int:
    parsed = uuid.UUID(case_id.removeprefix("DSF-"))
    unix_ms = parsed.int >> 80
    return dt.datetime.fromtimestamp(unix_ms / 1000, tz=dt.UTC).year


def _case_relative_path(candidate: Mapping[str, Any]) -> Path:
    case_id = candidate["case"]["id"]
    return Path("cases") / f"{_case_year(case_id):04d}" / f"{case_id}.json"


def _last_pointer_digest(root: Path) -> str | None:
    path = root / LIVE_POINTER
    if not _state_exists(path):
        return None
    pointer = _load_json(path)
    _validate_completed_snapshot(pointer)
    if pointer["mode"] != "live":
        _fail("invalid-live-pointer", "live pointer cannot reference historical replay")
    history = root / "completed" / f"{pointer['audit_id']}.json"
    if not _state_exists(history) or _load_json(history) != pointer:
        _fail("invalid-live-pointer", "live pointer does not exactly match immutable history")
    digest = pointer.get("snapshot_digest")
    if not isinstance(digest, str) or HEX64_RE.fullmatch(digest) is None:
        _fail("invalid-live-pointer", f"completed snapshot has no valid digest: {path}")
    return digest


def _receipt_ref(receipt: Mapping[str, Any]) -> dict[str, str]:
    return {
        "receipt_id": _safe_object_id(receipt.get("receipt_id"), "receipt_id"),
        "digest": _digest({key: value for key, value in receipt.items() if key != "digest"}),
    }


def _write_receipt(root: Path, category: str, receipt: dict[str, Any]) -> dict[str, Any]:
    receipt_id = _safe_object_id(receipt.get("receipt_id"), "receipt_id")
    body = {key: value for key, value in receipt.items() if key != "digest"}
    receipt["digest"] = _digest(body)
    path = root / "receipts" / category / f"{receipt_id}.json"
    _atomic_write(path, receipt, immutable=True)
    receipt["path"] = str(path)
    return receipt


def _validate_closed_reopen(old_case: Mapping[str, Any], new_case: Mapping[str, Any]) -> bool:
    if old_case["status"] != "closed" or new_case["status"] != "proposed":
        return False
    old_effectiveness = old_case["effectiveness"]
    if old_effectiveness["state"] != "passed":
        _fail("invalid-closed-reopen", "closed reopen requires prior passed effectiveness")
    old_evidence = old_case["evidence"]
    appended = new_case["evidence"][len(old_evidence) :]
    if not appended:
        _fail("invalid-closed-reopen", "closed reopen requires appended recurrence evidence")
    closed_at = _parse_time(old_case["lifecycle_changed_at"], "old.lifecycle_changed_at")
    checked_on = _date(old_effectiveness["checked_on"], "old.effectiveness.checked_on")
    reopened_at = _parse_time(new_case["lifecycle_changed_at"], "new.lifecycle_changed_at")
    old_signatures = {item["causal_signature"] for item in old_evidence}
    repeated_prior = False
    for item in appended:
        observed = _parse_time(item["observed_at"], "reopen.observed_at")
        if observed <= closed_at or observed.date() <= checked_on:
            _fail(
                "invalid-closed-reopen",
                "reopen evidence must strictly follow prior check date and closure timestamp",
            )
        if reopened_at < observed:
            _fail(
                "invalid-closed-reopen",
                "reopen lifecycle_changed_at cannot predate recurrence evidence",
            )
        if item["causal_signature"] in old_signatures:
            repeated_prior = True
    if not repeated_prior or new_case["support"] != "repeated":
        _fail("invalid-closed-reopen", "reopen requires repeated prior-cause support")
    old_repairs = old_case["repairs"]
    new_repairs = new_case["repairs"]
    if len(new_repairs) != len(old_repairs) + 1:
        _fail("invalid-closed-reopen", "reopen must append exactly one planned repair")
    old_active = [
        (index, repair)
        for index, repair in enumerate(old_repairs)
        if repair["state"] != "superseded"
    ]
    if len(old_active) != 1:
        _fail("invalid-closed-reopen", "reopen requires exactly one prior current repair")
    index, old_repair = old_active[0]
    changed_old = new_repairs[index]
    if changed_old["id"] != old_repair["id"] or changed_old["state"] != "superseded":
        _fail("invalid-closed-reopen", "reopen must supersede prior current repair")
    appended_repair = new_repairs[-1]
    if appended_repair["state"] != "planned" or appended_repair["action"] not in {
        "install",
        "amend",
    }:
        _fail("invalid-closed-reopen", "reopen needs one planned install/amend repair")
    new_effectiveness = new_case["effectiveness"]
    if not (
        new_effectiveness["method"] == old_effectiveness["method"]
        and new_effectiveness["method"] in {"deterministic", "behavioral", "both"}
        and new_effectiveness["state"] == "not-started"
        and all(
            new_effectiveness[field] is None
            for field in ("checked_on", "summary", "deterministic", "behavioral")
        )
    ):
        _fail("invalid-closed-reopen", "reopen must reset same selected effectiveness method")
    return True


def _validate_case_delta(existing: Mapping[str, Any], candidate: Mapping[str, Any]) -> str:
    old_case = existing["case"]
    new_case = candidate["case"]
    if old_case["id"] != new_case["id"]:
        _fail("identity-change", "a case identity cannot change")
    closed_reopen = _validate_closed_reopen(old_case, new_case)
    old_evidence = old_case["evidence"]
    new_evidence = new_case["evidence"]
    if len(new_evidence) < len(old_evidence):
        _fail("evidence-removal", "staging cannot remove an existing occurrence")
    if new_evidence[: len(old_evidence)] != old_evidence:
        _fail("evidence-mutation", "staging evidence is exact-prefix append-only")
    old_sources = {source for item in old_case["evidence"] for source in item["source_event_ids"]}
    for item in new_evidence[len(old_evidence) :]:
        overlap = old_sources.intersection(item["source_event_ids"])
        if overlap:
            _fail(
                "duplicate-source-event",
                f"new occurrence reuses existing source events: {sorted(overlap)}",
            )

    old_revision = old_case["revision"]
    new_revision = new_case["revision"]
    old_digest = existing["control"]["semantic_digest"]
    new_digest = candidate["control"]["semantic_digest"]
    semantic_changed = old_digest != new_digest
    if semantic_changed and new_revision != old_revision + 1:
        _fail("revision-order", "a semantic change must increment revision by exactly one")
    if not semantic_changed and new_revision != old_revision:
        _fail("revision-order", "a non-semantic currentness update cannot increment revision")

    if old_case["lifecycle"]["created_at"] != new_case["lifecycle"]["created_at"]:
        _fail("clock-mutation", "lifecycle.created_at is immutable")
    new_occurrence = len(new_evidence) != len(old_evidence)
    if not new_occurrence and old_case["evidence_last_seen"] != new_case["evidence_last_seen"]:
        _fail("clock-mutation", "evidence_last_seen changes only for a new occurrence")
    status_changed = old_case["status"] != new_case["status"]
    if new_case["status"] not in STATUS_TRANSITIONS.get(old_case["status"], set()):
        _fail(
            "invalid-lifecycle-transition",
            f"invalid lifecycle transition {old_case['status']} -> {new_case['status']}",
        )
    if old_case["status"] == "dormant" and new_case["status"] in {"watching", "proposed"}:
        if new_case["status"] != old_case["lifecycle"]["dormant_from_status"]:
            _fail("invalid-reactivation", "dormant case may reactivate only to its origin status")
    if old_case["status"] == new_case["status"] == "dormant":
        for field in ("dormant_since", "dormant_from_status"):
            if old_case["lifecycle"][field] != new_case["lifecycle"][field]:
                _fail("clock-mutation", f"lifecycle.{field} is immutable while dormant")
    if (
        old_case["status"] == "superseded"
        and old_case["lifecycle"]["superseded_by"] is not None
        and old_case["lifecycle"]["superseded_by"] != new_case["lifecycle"]["superseded_by"]
    ):
        _fail("clock-mutation", "lifecycle.superseded_by is immutable once recorded")
    if not status_changed and old_case["lifecycle_changed_at"] != new_case["lifecycle_changed_at"]:
        _fail("clock-mutation", "lifecycle_changed_at changes only when status changes")
    if status_changed and not semantic_changed:
        _fail("semantic-digest-mismatch", "a lifecycle transition must be semantic")
    if new_case["status"] == "implemented" and old_case["status"] != "implemented":
        installed_dates = [
            _date(repair["installed_on"], "repair.installed_on")
            for repair in new_case["repairs"]
            if repair["state"] == "merged"
            and repair["action"] in {"install", "amend"}
            and repair["installed_on"] is not None
        ]
        if installed_dates and _parse_time(
            new_case["lifecycle_changed_at"], "lifecycle_changed_at"
        ).date() < max(installed_dates):
            _fail(
                "clock-order",
                "implemented transition cannot predate the latest repair installation",
            )
    if _parse_time(new_case["currentness_checked_at"], "currentness") < _parse_time(
        old_case["currentness_checked_at"], "currentness"
    ):
        _fail("clock-regression", "currentness_checked_at cannot move backwards")
    if not semantic_changed and existing["control"] != candidate["control"]:
        _fail(
            "control-mutation",
            "control provenance changes require a corresponding semantic case change",
        )
    if old_case["source_kind"] != new_case["source_kind"]:
        _fail("source-kind-mutation", "case source_kind is immutable")
    for field in ("origin_case_id", "explicit_human_root_task_id"):
        if existing["control"][field] != candidate["control"][field]:
            _fail("origin-mutation", f"control.{field} is immutable")
    old_lineage = existing["control"]["source_lineage"]
    new_lineage = candidate["control"]["source_lineage"]
    if len(new_lineage) < len(old_lineage) or new_lineage[: len(old_lineage)] != old_lineage:
        _fail("lineage-mutation", "control.source_lineage is exact-prefix append-only")
    old_repairs = old_case["repairs"]
    new_repairs = new_case["repairs"]
    if len(new_repairs) < len(old_repairs):
        _fail("repair-history-removal", "existing repair history cannot be removed")
    immutable = {
        "id",
        "repository",
        "action",
        "problem_statement",
        "change_summary",
        "commit_trailer",
        "replaces_repair_id",
    }
    durable = {"pull_request_url", "commit", "installed_on", "removed_on"}
    for index, old_repair in enumerate(old_repairs):
        new_repair = new_repairs[index]
        if new_repair["id"] != old_repair["id"]:
            _fail("repair-history-reorder", "repair history cannot be reordered or replaced")
        for field in immutable:
            if new_repair[field] != old_repair[field]:
                _fail("repair-field-mutation", f"repair {old_repair['id']} {field} is immutable")
        if new_repair["state"] not in REPAIR_STATE_TRANSITIONS[old_repair["state"]]:
            _fail("invalid-repair-transition", f"invalid transition for repair {old_repair['id']}")
        for field in durable:
            if old_repair[field] is not None and new_repair[field] != old_repair[field]:
                _fail("repair-field-mutation", f"repair {old_repair['id']} {field} is durable")
    if old_repairs and not closed_reopen:
        old_method = old_case["effectiveness"]["method"]
        if (
            old_method in {"deterministic", "behavioral", "both"}
            and new_case["effectiveness"]["method"] != old_method
        ):
            _fail("effectiveness-method-mutation", "selected effectiveness method is immutable")
    _validate_effectiveness_delta(old_case, new_case)
    return "updated" if semantic_changed or candidate != existing else "unchanged"


def _validate_effectiveness_delta(old_case: Mapping[str, Any], new_case: Mapping[str, Any]) -> None:
    old = old_case["effectiveness"]
    new = new_case["effectiveness"]
    reopening = old_case["status"] == "closed" and new_case["status"] == "proposed"
    old_checked = _date(old["checked_on"], "old.checked_on", nullable=True)
    new_checked = _date(new["checked_on"], "new.checked_on", nullable=True)
    if old_checked is not None and not reopening:
        if new_checked is None or new_checked < old_checked:
            _fail("effectiveness-history", "effectiveness.checked_on cannot be erased/regressed")
    old_behavioral = old["behavioral"]
    new_behavioral = new["behavioral"]
    if isinstance(old_behavioral, dict) and not reopening:
        if not isinstance(new_behavioral, dict):
            _fail("effectiveness-history", "behavioral evidence cannot be erased")
        if new_behavioral["started_on"] != old_behavioral["started_on"]:
            _fail("effectiveness-history", "behavioral started_on is immutable")
        old_ended = _date(old_behavioral["ended_on"], "old.ended", nullable=True)
        new_ended = _date(new_behavioral["ended_on"], "new.ended", nullable=True)
        if old_ended is not None and (new_ended is None or new_ended < old_ended):
            _fail("effectiveness-history", "behavioral ended_on cannot be erased/regressed")
        for field in ("relevant_opportunities", "recurrences"):
            if new_behavioral[field] < old_behavioral[field]:
                _fail("effectiveness-history", f"behavioral {field} cannot decrease")
    old_deterministic = old["deterministic"]
    new_deterministic = new["deterministic"]
    if isinstance(old_deterministic, dict) and not reopening:
        if not isinstance(new_deterministic, dict):
            _fail("effectiveness-history", "deterministic evidence cannot be erased")
        for field in ("test_ref", "commit"):
            if new_deterministic[field] != old_deterministic[field]:
                _fail("effectiveness-history", f"deterministic {field} is immutable")
        if old_deterministic["result"] in {"passed", "failed"} and (
            new_deterministic != old_deterministic
        ):
            _fail("effectiveness-history", "terminal deterministic evidence is immutable")
    if old["state"] in {"passed", "failed"} and not reopening and new != old:
        _fail("effectiveness-history", "terminal effectiveness snapshot is immutable")


def _validate_candidate_at_now(candidate: Mapping[str, Any], now_value: str) -> None:
    case = candidate["case"]
    now_instant = _parse_time(now_value, "now")
    clock_values = [
        (case["evidence_last_seen"], "case.evidence_last_seen"),
        (case["currentness_checked_at"], "case.currentness_checked_at"),
        (case["lifecycle"]["created_at"], "case.lifecycle.created_at"),
        (case["lifecycle_changed_at"], "case.lifecycle_changed_at"),
    ]
    clock_values.extend(
        (item["observed_at"], "case.evidence[].observed_at") for item in case["evidence"]
    )
    if case["lifecycle"]["dormant_since"] is not None:
        clock_values.append((case["lifecycle"]["dormant_since"], "case.lifecycle.dormant_since"))
    for value, field in clock_values:
        if _parse_time(_timestamp(value, field), field) > now_instant:
            _fail("future-state", f"{field} cannot be after --now")
    case_uuid_ms = uuid.UUID(case["id"].removeprefix("DSF-")).int >> 80
    if dt.datetime.fromtimestamp(case_uuid_ms / 1000, tz=dt.UTC) > now_instant:
        _fail("future-state", "case UUIDv7 timestamp cannot be after --now")
    for repair in case["repairs"]:
        for field in ("installed_on", "removed_on"):
            if (
                repair[field] is not None
                and _date(repair[field], f"repair.{field}") > now_instant.date()
            ):
                _fail("future-state", f"repair.{field} cannot be after --now")
    effectiveness = case["effectiveness"]
    if (
        effectiveness["checked_on"] is not None
        and _date(effectiveness["checked_on"], "effectiveness.checked_on") > now_instant.date()
    ):
        _fail("future-state", "effectiveness.checked_on cannot be after --now")
    behavioral = effectiveness["behavioral"]
    if behavioral is not None:
        for field in ("started_on", "ended_on"):
            if (
                behavioral[field] is not None
                and _date(behavioral[field], f"behavioral.{field}") > now_instant.date()
            ):
                _fail("future-state", f"behavioral.{field} cannot be after --now")


def _validate_automation_origin(state_root: Path, candidate: Mapping[str, Any]) -> None:
    case = candidate["case"]
    if case["source_kind"] != "automation-derived":
        return
    control = candidate["control"]
    origin_id = control["origin_case_id"]
    origin_path = _find_case(state_root, origin_id)
    if origin_path is None:
        _fail("missing-origin-case", "automation-derived origin case does not exist")
    origin = _load_json(origin_path)
    validate_candidate(origin)
    origin_case = origin["case"]
    correction_items = [
        item
        for item in case["evidence"]
        if item["signal_type"] == "explicit-human-correction"
        and item["root_task_id"] == control["explicit_human_root_task_id"]
    ]
    if not correction_items:
        _fail("missing-human-root", "automation-derived case has no bound correction evidence")
    origin_created = _parse_time(origin_case["lifecycle"]["created_at"], "origin.created_at")
    if any(
        _parse_time(item["observed_at"], "correction.observed_at") <= origin_created
        for item in correction_items
    ):
        _fail("invalid-origin-chronology", "human correction must strictly follow origin creation")
    origin_roots = {item["root_task_id"] for item in origin_case["evidence"]}
    origin_events = {
        event for item in origin_case["evidence"] for event in item["source_event_ids"]
    }
    if any(
        item["root_task_id"] in origin_roots
        or bool(origin_events.intersection(item["source_event_ids"]))
        for item in case["evidence"]
    ):
        _fail("self-reinforcing-automation", "automation-derived evidence must be independent")


def stage_candidate(candidate_path: Path, state_root: Path, now: str) -> dict[str, Any]:
    now_value = _timestamp(now, "now")
    candidate, candidate_file_sha = _load_json_with_digest(candidate_path)
    summary = validate_candidate(candidate)
    _validate_candidate_at_now(candidate, now_value)
    if _parse_time(candidate["case"]["currentness_checked_at"], "currentness") > _parse_time(
        now_value, "now"
    ):
        _fail("future-state", "candidate currentness check cannot be later than --now")
    with _state_lock(state_root) as store:
        _recover_pending_wal(store)
        marker = _read_marker(state_root)
        marker_write: dict[str, Any] | None = None
        if marker is None:
            marker = {
                "version": VERSION,
                "kind": "daily-skill-friction-state",
                "mode": "unbound",
                "state_id": str(uuid.uuid4()),
                "created_at": now_value,
            }
            marker_write = _planned_write(store, Path(STATE_MARKER), marker, immutable=True)
        if marker["mode"] == "historical-replay" and state_root.name == "control-state":
            _fail("historical-live-root", "historical state cannot use the canonical live root")
        _validate_automation_origin(state_root, candidate)
        existing_path = _find_case(state_root, summary["case_id"])
        if existing_path is None:
            if summary["status"] not in INITIAL_CASE_STATUSES:
                _fail(
                    "invalid-initial-lifecycle",
                    "a new case must start at watching or proposed; source_kind does not "
                    "authorize a lifecycle import",
                )
            if summary["revision"] != 1:
                _fail("revision-order", "a new case must start at revision 1")
            destination = state_root / _case_relative_path(candidate)
            action = "created"
        else:
            existing = _load_json(existing_path)
            validate_candidate(existing)
            action = _validate_case_delta(existing, candidate)
            if existing["case"]["status"] != candidate["case"]["status"] and not (
                _parse_time(existing["case"]["lifecycle_changed_at"], "old.lifecycle")
                < _parse_time(candidate["case"]["lifecycle_changed_at"], "new.lifecycle")
                <= _parse_time(now_value, "now")
            ):
                _fail(
                    "clock-order",
                    "status transition lifecycle_changed_at must strictly advance and be <= --now",
                )
            destination = existing_path
            if destination.relative_to(state_root) != _case_relative_path(candidate):
                _fail("case-path-drift", "case first_seen would move its durable path")
        _validate_case_graph(state_root, candidate)
        before_wrapper_sha = (
            store.read_bytes(destination.relative_to(state_root))[1]
            if store.exists(destination.relative_to(state_root))
            else None
        )
        anchor = _last_pointer_digest(state_root)
        natural_key = f"{anchor or 'none'}:{summary['case_id']}:{candidate_file_sha}"
        receipt_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"dsf-stage:{natural_key}"))
        receipt_body = {
            "version": VERSION,
            "kind": "stage",
            "receipt_id": receipt_id,
            "created_at": now_value,
            "anchor_snapshot_digest": anchor,
            "case_id": summary["case_id"],
            "case_path": str(destination.relative_to(state_root)),
            "revision": summary["revision"],
            "semantic_digest": summary["semantic_digest"],
            "before_wrapper_file_sha256": before_wrapper_sha,
            "wrapper_file_sha256": hashlib.sha256(_canonical_bytes(candidate)).hexdigest(),
            "case_sha256": hashlib.sha256(_canonical_bytes(candidate["case"])).hexdigest(),
            "action": action,
        }
        receipt = {**receipt_body, "digest": _digest(receipt_body)}
        receipt_path = Path("receipts") / "stage" / f"{receipt_id}.json"
        writes = []
        if marker_write is not None:
            writes.append(marker_write)
        writes.extend(
            [
                _planned_write(
                    store, destination.relative_to(state_root), candidate, immutable=False
                ),
                _planned_write(store, receipt_path, receipt, immutable=True),
            ]
        )
        result = {**receipt, "path": str(state_root / receipt_path)}
        return _run_transaction(
            store,
            operation="stage",
            natural_key=natural_key,
            request={"candidate_file_sha256": candidate_file_sha, "anchor": anchor},
            captured_at=now_value,
            writes=writes,
            result=result,
        )


def _pending_case_ids(root: Path) -> set[str]:
    pending: set[str] = set()
    registry = root / "publication" / "active"
    if not _state_exists(registry):
        return pending
    for name in _state_list_names(registry):
        if not name.endswith(".json") or CASE_ID_RE.fullmatch(name[:-5]) is None:
            _fail("unsafe-publication-layout", f"unexpected publication plan entry: {name}")
        path = registry / name
        record = _load_json(path)
        _validate_pending_record(record, name[:-5])
        if record.get("status") == "active":
            pending.add(_validate_case_id(record.get("case_id")))
        elif record.get("status") != "closed":
            _fail("invalid-pending-record", f"invalid pending status: {path}")
    return pending


def _validate_pending_record(record: Mapping[str, Any], filename_case_id: str) -> None:
    fields = {
        "version",
        "kind",
        "status",
        "case_id",
        "revision",
        "semantic_digest",
        "selection_id",
        "plan_digest",
        "activated_at",
        "previous_closure_digest",
        "closure_id",
        "closure_digest",
        "closure_reason",
        "closed_at",
        "record_digest",
    }
    _exact_fields(record, "publication.active", fields)
    if (
        type(record["version"]) is not int
        or record["version"] != VERSION
        or record["kind"] != "publication-pending"
    ):
        _fail("invalid-pending-record", "publication active record has invalid version/kind")
    case_id = _validate_case_id(record["case_id"])
    if case_id != filename_case_id:
        _fail("invalid-pending-record", "active filename does not bind case_id")
    _require_int(record["revision"], "active.revision", minimum=1)
    _sha_digest(record["semantic_digest"], "active.semantic_digest")
    _safe_object_id(record["selection_id"], "active.selection_id")
    if HEX64_RE.fullmatch(_require_string(record["plan_digest"], "active.plan_digest")) is None:
        _fail("invalid-pending-record", "active plan_digest must be raw SHA-256")
    _timestamp(record["activated_at"], "active.activated_at")
    _validate_raw_sha_or_none(record["previous_closure_digest"], "active.previous_closure")
    if record["status"] == "active":
        if any(
            record[field] is not None
            for field in ("closure_id", "closure_digest", "closure_reason", "closed_at")
        ):
            _fail("invalid-pending-record", "active record cannot carry closure fields")
    elif record["status"] == "closed":
        _safe_object_id(record["closure_id"], "active.closure_id")
        if _validate_raw_sha_or_none(record["closure_digest"], "active.closure_digest") is None:
            _fail("invalid-pending-record", "closed active needs closure_digest")
        if record["closure_reason"] not in {"published", "cancelled", "stale"}:
            _fail("invalid-pending-record", "closed active reason is invalid")
        closed_at = _parse_time(_timestamp(record["closed_at"], "active.closed_at"), "closed")
        if closed_at < _parse_time(record["activated_at"], "active.activated_at"):
            _fail("clock-order", "publication cannot close before activation")
    else:
        _fail("invalid-pending-record", "publication active status is invalid")
    body = {key: value for key, value in record.items() if key != "record_digest"}
    if record["record_digest"] != _digest(body):
        _fail("invalid-pending-record", "publication active record digest mismatch")


def _activate_publication_entries(state_root: Path, plan: Mapping[str, Any], now: str) -> None:
    for entry in plan["entries"]:
        path = state_root / "publication" / "active" / f"{entry['case_id']}.json"
        previous_closure_digest: str | None = None
        if _state_exists(path):
            current = _load_json(path)
            if current.get("status") == "active":
                expected = {
                    "selection_id": plan["selection_id"],
                    "plan_digest": plan["plan_digest"],
                    "revision": entry["revision"],
                    "semantic_digest": entry["semantic_digest"],
                }
                if any(current.get(key) != value for key, value in expected.items()):
                    _fail(
                        "publication-already-pending",
                        f"case already has another active publication: {entry['case_id']}",
                    )
                continue
            if current.get("status") != "closed":
                _fail("invalid-pending-record", f"invalid prior pending record: {path}")
            previous_closure_digest = current.get("closure_digest")
        record = {
            "version": VERSION,
            "kind": "publication-pending",
            "status": "active",
            "case_id": entry["case_id"],
            "revision": entry["revision"],
            "semantic_digest": entry["semantic_digest"],
            "selection_id": plan["selection_id"],
            "plan_digest": plan["plan_digest"],
            "activated_at": now,
            "previous_closure_digest": previous_closure_digest,
            "closure_id": None,
            "closure_digest": None,
            "closure_reason": None,
            "closed_at": None,
        }
        _atomic_write(path, record)


def transition_dormant(state_root: Path, now: str) -> dict[str, Any]:
    now_value = _timestamp(now, "now")
    now_instant = _parse_time(now_value, "now")
    with _state_lock(state_root) as store:
        _recover_pending_wal(store)
        marker = _read_marker(state_root)
        marker_write: dict[str, Any] | None = None
        if marker is None:
            marker = {
                "version": VERSION,
                "kind": "daily-skill-friction-state",
                "mode": "unbound",
                "state_id": str(uuid.uuid4()),
                "created_at": now_value,
            }
            marker_write = _planned_write(store, Path(STATE_MARKER), marker, immutable=True)
        anchor = _last_pointer_digest(state_root)
        pending = _pending_case_ids(state_root)
        pending_digest = _digest(sorted(pending))
        natural_key = f"{anchor or 'initial'}:{pending_digest}"
        intent_path, _ = _wal_paths("dormancy", natural_key)
        if store.exists(intent_path):
            intent, _ = store.read_json(intent_path)
            _validate_wal_intent(intent, "dormancy")
            return _run_transaction(
                store,
                operation="dormancy",
                natural_key=natural_key,
                request={"anchor": anchor, "pending_digest": pending_digest},
                captured_at=now_value,
                writes=[],
                result={},
            )
        changed: list[dict[str, Any]] = []
        case_writes: list[dict[str, Any]] = []
        for path in _case_paths(state_root):
            wrapper = _load_json(path)
            before_wrapper_sha = store.read_bytes(path.relative_to(state_root))[1]
            validate_candidate(wrapper)
            case = wrapper["case"]
            if case["status"] not in {"watching", "proposed"}:
                continue
            if case["id"] in pending:
                continue
            changed_at = _parse_time(case["lifecycle_changed_at"], "lifecycle")
            if now_instant - changed_at < dt.timedelta(days=30):
                continue
            previous_status = case["status"]
            case["status"] = "dormant"
            case["lifecycle_changed_at"] = now_value
            case["lifecycle"]["dormant_since"] = now_value
            case["lifecycle"]["dormant_from_status"] = previous_status
            case["revision"] += 1
            digest = semantic_digest(case)
            wrapper["control"]["semantic_digest"] = digest
            validate_candidate(wrapper)
            changed.append(
                {
                    "case_id": case["id"],
                    "case_path": str(path.relative_to(state_root)),
                    "revision": case["revision"],
                    "semantic_digest": digest,
                    "before_wrapper_file_sha256": before_wrapper_sha,
                    "wrapper_file_sha256": hashlib.sha256(_canonical_bytes(wrapper)).hexdigest(),
                    "case_sha256": hashlib.sha256(_canonical_bytes(case)).hexdigest(),
                }
            )
            case_writes.append(
                _planned_write(store, path.relative_to(state_root), wrapper, immutable=False)
            )
        changed.sort(key=lambda item: item["case_id"])
        receipt_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"dsf-dormancy:{natural_key}"))
        receipt_body = {
            "version": VERSION,
            "kind": "dormancy",
            "receipt_id": receipt_id,
            "created_at": now_value,
            "anchor_snapshot_digest": anchor,
            "changed": changed,
        }
        receipt = {**receipt_body, "digest": _digest(receipt_body)}
        receipt_path = Path("receipts") / "dormancy" / f"{receipt_id}.json"
        writes: list[dict[str, Any]] = []
        if marker_write is not None:
            writes.append(marker_write)
        writes.extend(case_writes)
        writes.append(_planned_write(store, receipt_path, receipt, immutable=True))
        result = {**receipt, "path": str(state_root / receipt_path)}
        return _run_transaction(
            store,
            operation="dormancy",
            natural_key=natural_key,
            request={"anchor": anchor, "pending_digest": pending_digest},
            captured_at=now_value,
            writes=writes,
            result=result,
        )


def _normalize_receipt_refs(values: Any, field: str) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, value in enumerate(_require_list(values, field)):
        item = _require_object(value, f"{field}[{index}]")
        _exact_fields(item, f"{field}[{index}]", {"receipt_id", "digest"})
        receipt_id = _safe_object_id(item.get("receipt_id"), f"{field}[{index}].receipt_id")
        digest = _require_string(item.get("digest"), f"{field}[{index}].digest")
        if HEX64_RE.fullmatch(digest) is None:
            _fail("invalid-digest", f"{field}[{index}].digest must be SHA-256")
        if receipt_id in seen:
            _fail("duplicate-receipt", f"duplicate receipt reference: {receipt_id}")
        seen.add(receipt_id)
        refs.append({"receipt_id": receipt_id, "digest": digest})
    return sorted(refs, key=lambda item: item["receipt_id"])


def _validate_audit_summary(value: Any, field: str) -> dict[str, Any]:
    summary = _require_object(value, field)
    _exact_fields(summary, field, AUDIT_SUMMARY_COUNT_FIELDS | {"next_watchpoint"})
    for name in sorted(AUDIT_SUMMARY_COUNT_FIELDS):
        count = _require_int(summary[name], f"{field}.{name}", minimum=0)
        if count > 1_000_000:
            _fail("invalid-audit-summary", f"{field}.{name} exceeds 1,000,000")
    watchpoint = summary["next_watchpoint"]
    if watchpoint is not None:
        _bounded_string(watchpoint, f"{field}.next_watchpoint", 1, 240)
    return summary


def _validate_receipt_backed_audit_counts(
    summary: Mapping[str, Any],
    stage_receipts: Sequence[Mapping[str, Any]],
    dormancy_receipts: Sequence[Mapping[str, Any]],
) -> None:
    """Bind immutable case counts to the exact validated audit receipts."""

    expected = {
        "cases_created": sum(receipt["action"] == "created" for receipt in stage_receipts),
        "cases_updated": sum(receipt["action"] == "updated" for receipt in stage_receipts),
        "cases_unchanged": sum(receipt["action"] == "unchanged" for receipt in stage_receipts),
        "cases_dormant": sum(len(receipt["changed"]) for receipt in dormancy_receipts),
    }
    mismatches = [
        f"{field}={summary[field]} (expected {count})"
        for field, count in expected.items()
        if summary[field] != count
    ]
    if mismatches:
        _fail(
            "audit-summary-mismatch",
            "audit summary does not match its exact receipts: " + ", ".join(mismatches),
        )


def _receipt_files(root: Path, category: str, anchor: str | None) -> list[dict[str, str]]:
    directory = root / "receipts" / category
    if not _state_exists(directory):
        return []
    refs: list[dict[str, str]] = []
    for name in _state_list_names(directory):
        if not name.endswith(".json") or SAFE_OBJECT_ID_RE.fullmatch(name[:-5]) is None:
            _fail("unsafe-receipt-layout", f"unexpected receipt entry: {name}")
        path = directory / name
        receipt = _load_json(path)
        _validate_persisted_receipt(receipt, category, path.stem)
        if receipt.get("anchor_snapshot_digest") == anchor:
            body = {key: value for key, value in receipt.items() if key not in {"digest", "path"}}
            digest = _digest(body)
            if receipt.get("digest") != digest:
                _fail("receipt-digest-mismatch", f"receipt content changed: {path}")
            refs.append({"receipt_id": receipt["receipt_id"], "digest": digest})
    return sorted(refs, key=lambda item: item["receipt_id"])


def _validate_raw_sha_or_none(value: Any, field: str) -> str | None:
    if value is None:
        return None
    text = _require_string(value, field)
    if HEX64_RE.fullmatch(text) is None:
        _fail("invalid-digest", f"{field} must be null or raw SHA-256")
    return text


def _validate_persisted_receipt(
    receipt: Mapping[str, Any], category: str, filename_id: str
) -> None:
    common = {"version", "kind", "receipt_id", "created_at", "anchor_snapshot_digest", "digest"}
    if category == "stage":
        expected = common | {
            "case_id",
            "case_path",
            "revision",
            "semantic_digest",
            "before_wrapper_file_sha256",
            "wrapper_file_sha256",
            "case_sha256",
            "action",
        }
    elif category == "dormancy":
        expected = common | {"changed"}
    else:
        _fail("invalid-receipt-category", f"unsupported receipt category: {category}")
    _exact_fields(receipt, f"receipt.{category}", expected)
    if type(receipt["version"]) is not int or receipt["version"] != VERSION:
        _fail("invalid-receipt", "receipt version is invalid")
    if receipt["kind"] != category:
        _fail("invalid-receipt", "receipt kind is invalid")
    receipt_id = _safe_object_id(receipt["receipt_id"], "receipt.receipt_id")
    if receipt_id != filename_id:
        _fail("invalid-receipt", "receipt filename does not bind receipt_id")
    _timestamp(receipt["created_at"], "receipt.created_at")
    _validate_raw_sha_or_none(receipt["anchor_snapshot_digest"], "receipt.anchor")
    body = {key: value for key, value in receipt.items() if key != "digest"}
    if receipt["digest"] != _digest(body):
        _fail("receipt-digest-mismatch", "receipt body no longer matches its digest")
    if category == "stage":
        case_id = _validate_case_id(receipt["case_id"])
        expected_path = Path("cases") / f"{_case_year(case_id):04d}" / f"{case_id}.json"
        if Path(receipt["case_path"]) != expected_path:
            _fail("invalid-receipt", "stage receipt case_path does not bind case_id")
        _require_int(receipt["revision"], "receipt.revision", minimum=1)
        _sha_digest(receipt["semantic_digest"], "receipt.semantic_digest")
        _validate_raw_sha_or_none(
            receipt["before_wrapper_file_sha256"], "receipt.before_wrapper_file_sha256"
        )
        for field in ("wrapper_file_sha256", "case_sha256"):
            _validate_raw_sha_or_none(receipt[field], f"receipt.{field}")
        if receipt["action"] not in {"created", "updated", "unchanged"}:
            _fail("invalid-receipt", "stage receipt action is invalid")
    else:
        seen: set[str] = set()
        for index, value in enumerate(_require_list(receipt["changed"], "receipt.changed")):
            item = _require_object(value, f"receipt.changed[{index}]")
            _exact_fields(
                item,
                f"receipt.changed[{index}]",
                {
                    "case_id",
                    "case_path",
                    "revision",
                    "semantic_digest",
                    "before_wrapper_file_sha256",
                    "wrapper_file_sha256",
                    "case_sha256",
                },
            )
            case_id = _validate_case_id(item["case_id"])
            if case_id in seen:
                _fail("invalid-receipt", "dormancy receipt repeats a case")
            seen.add(case_id)
            expected_path = Path("cases") / f"{_case_year(case_id):04d}" / f"{case_id}.json"
            if Path(item["case_path"]) != expected_path:
                _fail("invalid-receipt", "dormancy case_path does not bind case_id")
            _require_int(item["revision"], "receipt.changed.revision", minimum=1)
            _sha_digest(item["semantic_digest"], "receipt.changed.semantic_digest")
            for field in (
                "before_wrapper_file_sha256",
                "wrapper_file_sha256",
                "case_sha256",
            ):
                if _validate_raw_sha_or_none(item[field], f"receipt.changed.{field}") is None:
                    _fail("invalid-receipt", f"dormancy {field} cannot be null")


def _snapshot_cases(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in _case_paths(root):
        wrapper = _load_json(path)
        summary = validate_candidate(wrapper)
        case = wrapper["case"]
        entries.append(
            {
                "case_id": summary["case_id"],
                "case_path": str(path.relative_to(root)),
                "revision": summary["revision"],
                "semantic_digest": summary["semantic_digest"],
                "status": summary["status"],
                "wrapper_file_sha256": _file_digest(path),
                "case_sha256": hashlib.sha256(_canonical_bytes(case)).hexdigest(),
            }
        )
    return sorted(entries, key=lambda item: item["case_id"])


def _validate_completed_snapshot(snapshot: Mapping[str, Any]) -> None:
    _exact_fields(
        snapshot,
        "snapshot",
        {
            "version",
            "kind",
            "mode",
            "audit_id",
            "started_at",
            "ended_at",
            "completed_at",
            "previous_snapshot_digest",
            "stage_receipts",
            "dormancy_receipts",
            "cases",
            "audit_summary",
            "snapshot_digest",
        },
    )
    if type(snapshot["version"]) is not int or snapshot["version"] != VERSION:
        _fail("invalid-snapshot", "completed snapshot version is invalid")
    if snapshot["kind"] != "daily-completed-snapshot" or snapshot["mode"] not in {
        "live",
        "historical-replay",
    }:
        _fail("invalid-snapshot", "completed snapshot kind or mode is invalid")
    _safe_object_id(snapshot["audit_id"], "snapshot.audit_id")
    started = _parse_time(_timestamp(snapshot["started_at"], "snapshot.started_at"), "started")
    ended = _parse_time(_timestamp(snapshot["ended_at"], "snapshot.ended_at"), "ended")
    completed = _parse_time(
        _timestamp(snapshot["completed_at"], "snapshot.completed_at"), "completed"
    )
    if not started <= ended <= completed:
        _fail("clock-order", "snapshot clocks are not ordered")
    _validate_raw_sha_or_none(snapshot["previous_snapshot_digest"], "snapshot.previous")
    _normalize_receipt_refs(snapshot["stage_receipts"], "snapshot.stage_receipts")
    _normalize_receipt_refs(snapshot["dormancy_receipts"], "snapshot.dormancy_receipts")
    seen: set[str] = set()
    prior_id = ""
    for index, raw in enumerate(_require_list(snapshot["cases"], "snapshot.cases")):
        item = _require_object(raw, f"snapshot.cases[{index}]")
        _exact_fields(
            item,
            f"snapshot.cases[{index}]",
            {
                "case_id",
                "case_path",
                "revision",
                "semantic_digest",
                "status",
                "wrapper_file_sha256",
                "case_sha256",
            },
        )
        case_id = _validate_case_id(item["case_id"])
        if case_id in seen or case_id <= prior_id:
            _fail("invalid-snapshot", "snapshot cases must be unique and sorted")
        seen.add(case_id)
        prior_id = case_id
        expected_path = Path("cases") / f"{_case_year(case_id):04d}" / f"{case_id}.json"
        if Path(item["case_path"]) != expected_path:
            _fail("invalid-snapshot", "snapshot case_path does not bind case_id")
        _require_int(item["revision"], "snapshot.case.revision", minimum=1)
        _sha_digest(item["semantic_digest"], "snapshot.case.semantic_digest")
        for field in ("wrapper_file_sha256", "case_sha256"):
            if _validate_raw_sha_or_none(item[field], f"snapshot.case.{field}") is None:
                _fail("invalid-snapshot", f"snapshot {field} cannot be null")
        if item["status"] not in STATUSES:
            _fail("invalid-snapshot", "snapshot case status is invalid")
    _validate_audit_summary(snapshot["audit_summary"], "snapshot.audit_summary")
    body = {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
    if snapshot["snapshot_digest"] != _digest(body):
        _fail("snapshot-digest-mismatch", "snapshot body no longer matches snapshot_digest")


def _receipt_objects(root: Path, category: str, anchor: str | None) -> list[dict[str, Any]]:
    directory = root / "receipts" / category
    if not _state_exists(directory):
        return []
    result: list[dict[str, Any]] = []
    for name in _state_list_names(directory):
        if not name.endswith(".json"):
            _fail("unsafe-receipt-layout", f"unexpected receipt entry: {name}")
        receipt = _load_json(directory / name)
        _validate_persisted_receipt(receipt, category, name[:-5])
        if receipt["anchor_snapshot_digest"] == anchor:
            result.append(receipt)
    return result


def _validate_complete_audit_intent_receipts(store: StateStore, intent: Mapping[str, Any]) -> None:
    """Reject a persisted completion intent whose snapshot misstates its receipts."""

    snapshots: list[dict[str, Any]] = []
    for index, raw_write in enumerate(_require_list(intent["writes"], "wal.writes")):
        write = _require_object(raw_write, f"wal.writes[{index}]")
        after = _require_object(write["after"], f"wal.writes[{index}].after")
        if after.get("kind") != "daily-completed-snapshot":
            continue
        if write["scope"] != "state":
            _fail("invalid-wal", "complete-audit snapshot writes must remain in state")
        _validate_completed_snapshot(after)
        snapshots.append(after)
    if not snapshots:
        _fail("invalid-wal", "complete-audit intent has no completed snapshot after-image")
    snapshot = snapshots[0]
    if any(item != snapshot for item in snapshots[1:]):
        _fail("invalid-wal", "complete-audit intent has conflicting snapshot after-images")

    anchor = snapshot["previous_snapshot_digest"]
    stage_refs = _normalize_receipt_refs(snapshot["stage_receipts"], "snapshot.stage_receipts")
    dormancy_refs = _normalize_receipt_refs(
        snapshot["dormancy_receipts"], "snapshot.dormancy_receipts"
    )
    if stage_refs != _receipt_files(store.root, "stage", anchor):
        _fail("invalid-wal", "complete-audit snapshot does not bind every stage receipt")
    if dormancy_refs != _receipt_files(store.root, "dormancy", anchor):
        _fail("invalid-wal", "complete-audit snapshot does not bind every dormancy receipt")
    receipt_objects = {
        category: _receipt_objects(store.root, category, anchor)
        for category in ("stage", "dormancy")
    }
    started = _parse_time(snapshot["started_at"], "snapshot.started_at")
    ended = _parse_time(snapshot["ended_at"], "snapshot.ended_at")
    for category in ("stage", "dormancy"):
        for receipt in receipt_objects[category]:
            created = _parse_time(receipt["created_at"], "receipt.created_at")
            if not started <= created <= ended:
                _fail("invalid-wal", "complete-audit receipt falls outside its snapshot window")
    _validate_receipt_backed_audit_counts(
        _require_object(snapshot["audit_summary"], "snapshot.audit_summary"),
        receipt_objects["stage"],
        receipt_objects["dormancy"],
    )


def _verify_receipt_delta_coverage(root: Path, anchor: str | None) -> None:
    if anchor is None:
        simulated: dict[str, str] = {}
    else:
        pointer = _load_json(root / LIVE_POINTER)
        _validate_completed_snapshot(pointer)
        if pointer["snapshot_digest"] != anchor:
            _fail("audit-anchor-drift", "live pointer does not bind the audit anchor")
        simulated = {item["case_id"]: item["wrapper_file_sha256"] for item in pointer["cases"]}
    transitions: list[tuple[str, str | None, str]] = []
    for receipt in _receipt_objects(root, "stage", anchor):
        before = receipt["before_wrapper_file_sha256"]
        if receipt["action"] == "created" and before is not None:
            _fail("invalid-receipt", "created stage receipt must have an absent before-image")
        if receipt["action"] != "created" and before is None:
            _fail("invalid-receipt", "updated stage receipt must bind a before-image")
        transitions.append((receipt["case_id"], before, receipt["wrapper_file_sha256"]))
    for receipt in _receipt_objects(root, "dormancy", anchor):
        for item in receipt["changed"]:
            transitions.append(
                (
                    item["case_id"],
                    item["before_wrapper_file_sha256"],
                    item["wrapper_file_sha256"],
                )
            )
    pending = list(transitions)
    while pending:
        progressed = False
        remaining: list[tuple[str, str | None, str]] = []
        for case_id, before, after in pending:
            current = simulated.get(case_id)
            if current == before:
                simulated[case_id] = after
                progressed = True
            else:
                remaining.append((case_id, before, after))
        if not progressed:
            _fail("incomplete-audit", "receipt chain does not cover an exact case transition")
        pending = remaining
    current = {item["case_id"]: item["wrapper_file_sha256"] for item in _snapshot_cases(root)}
    if current != simulated:
        _fail("incomplete-audit", "case set or content has a change not covered by receipts")


def complete_audit(
    state_root: Path, receipt_path: Path, now: str, *, historical_replay: bool
) -> dict[str, Any]:
    now_value = _timestamp(now, "now")
    audit = _load_json(receipt_path)
    _scan_prohibited_content(audit, "audit")
    expected_audit_fields = {
        "version",
        "kind",
        "audit_id",
        "started_at",
        "ended_at",
        "previous_snapshot_digest",
        "stage_receipts",
        "dormancy_receipts",
        "summary",
    }
    _exact_fields(audit, "audit", expected_audit_fields)
    if (
        type(audit.get("version")) is not int
        or audit.get("version") != VERSION
        or audit.get("kind") != "daily-audit"
    ):
        _fail("invalid-audit-receipt", "receipt must be a version 1 daily-audit object")
    audit_id = _safe_object_id(audit.get("audit_id"), "audit_id")
    started_at = _timestamp(audit.get("started_at"), "started_at")
    ended_at = _timestamp(audit.get("ended_at"), "ended_at")
    if (
        not _parse_time(started_at, "started_at")
        <= _parse_time(ended_at, "ended_at")
        <= _parse_time(now_value, "now")
    ):
        _fail("clock-order", "audit requires started_at <= ended_at <= --now")
    provided_stage = _normalize_receipt_refs(audit.get("stage_receipts"), "stage_receipts")
    provided_dormancy = _normalize_receipt_refs(audit.get("dormancy_receipts"), "dormancy_receipts")
    anchor = audit.get("previous_snapshot_digest")
    if anchor is not None and (not isinstance(anchor, str) or HEX64_RE.fullmatch(anchor) is None):
        _fail("invalid-digest", "previous_snapshot_digest must be null or SHA-256")
    summary = _validate_audit_summary(audit["summary"], "audit.summary")
    mode = "historical-replay" if historical_replay else "live"
    natural_key = f"{mode}:{audit_id}"
    request = {"audit": audit, "mode": mode}
    with _state_lock(state_root) as store:
        intent_path, _ = _wal_paths("complete-audit", natural_key)

        def validate_audit_receipts() -> None:
            actual_stage = _receipt_files(state_root, "stage", anchor)
            actual_dormancy = _receipt_files(state_root, "dormancy", anchor)
            if provided_stage != actual_stage:
                _fail("incomplete-audit", "audit receipt does not include every stage receipt")
            if provided_dormancy != actual_dormancy:
                _fail("incomplete-audit", "audit receipt does not include every dormancy receipt")
            receipt_objects = {
                category: _receipt_objects(state_root, category, anchor)
                for category in ("stage", "dormancy")
            }
            for category in ("stage", "dormancy"):
                for persisted_receipt in receipt_objects[category]:
                    created_at = _parse_time(persisted_receipt["created_at"], "receipt.created_at")
                    if (
                        not _parse_time(started_at, "started_at")
                        <= created_at
                        <= _parse_time(ended_at, "ended_at")
                    ):
                        _fail("clock-order", "audit receipts must fall within audit start/end")
            _validate_receipt_backed_audit_counts(
                summary,
                receipt_objects["stage"],
                receipt_objects["dormancy"],
            )

        if store.exists(intent_path):
            validate_audit_receipts()
            _recover_pending_wal(store)
            return _run_transaction(
                store,
                operation="complete-audit",
                natural_key=natural_key,
                request=request,
                captured_at=now_value,
                writes=[],
                result={},
            )
        _recover_pending_wal(store)
        validate_audit_receipts()
        immutable_history = (
            Path("historical") / "completed" / f"{audit_id}.json"
            if historical_replay
            else Path("completed") / f"{audit_id}.json"
        )
        if store.exists(immutable_history):
            _fail(
                "orphan-completed-snapshot",
                "completed history exists without its committed control transaction",
            )
        marker = _read_marker(state_root)
        marker_created = False
        if marker is None:
            marker_created = True
            marker = {
                "version": VERSION,
                "kind": "daily-skill-friction-state",
                "mode": "unbound",
                "state_id": str(uuid.uuid4()),
                "created_at": now_value,
            }
        current_anchor = _last_pointer_digest(state_root)
        if anchor != current_anchor:
            _fail(
                "audit-anchor-drift", "audit receipt does not bind the current completed snapshot"
            )
        if anchor is not None:
            previous = _load_json(state_root / LIVE_POINTER)
            _validate_completed_snapshot(previous)
            if _parse_time(previous["completed_at"], "previous.completed_at") > _parse_time(
                started_at, "started_at"
            ):
                _fail("clock-order", "new audit cannot start before prior completion")
        _verify_receipt_delta_coverage(state_root, anchor)
        if historical_replay and state_root.name == "control-state":
            _fail("historical-live-root", "historical replay cannot use the canonical live root")
        if marker.get("mode") not in {"unbound", mode}:
            _fail("state-mode-mismatch", f"state root is {marker.get('mode')}, not {mode}")
        bound_marker = dict(marker)
        if bound_marker["mode"] == "unbound":
            bound_marker["mode"] = mode
            bound_marker["bound_at"] = now_value
        snapshot_body = {
            "version": VERSION,
            "kind": "daily-completed-snapshot",
            "mode": mode,
            "audit_id": audit_id,
            "started_at": started_at,
            "ended_at": ended_at,
            "completed_at": now_value,
            "previous_snapshot_digest": anchor,
            "stage_receipts": provided_stage,
            "dormancy_receipts": provided_dormancy,
            "cases": _snapshot_cases(state_root),
            "audit_summary": summary,
        }
        body_digest = _digest(snapshot_body)
        snapshot = {**snapshot_body, "snapshot_digest": body_digest}
        writes: list[dict[str, Any]] = []
        if historical_replay:
            output_relative = immutable_history
            writes.append(_planned_write(store, output_relative, snapshot, immutable=True))
        else:
            history_relative = immutable_history
            output_relative = Path(LIVE_POINTER)
            writes.append(_planned_write(store, history_relative, snapshot, immutable=True))
        marker_relative = Path(STATE_MARKER)
        if marker_created or bound_marker != marker:
            writes.append(
                _planned_write(store, marker_relative, bound_marker, immutable=marker_created)
            )
        if not historical_replay:
            writes.append(_planned_write(store, output_relative, snapshot, immutable=False))
        result = {
            "version": VERSION,
            "status": "completed",
            "mode": mode,
            "audit_id": audit_id,
            "snapshot_path": str(state_root / output_relative),
            "snapshot_digest": body_digest,
            "case_count": len(snapshot["cases"]),
        }
        return _run_transaction(
            store,
            operation="complete-audit",
            natural_key=natural_key,
            request=request,
            captured_at=now_value,
            writes=writes,
            result=result,
        )


SELECTION_BASIS_FIELDS = {
    "version",
    "kind",
    "selection_id",
    "daily_snapshot_digest",
    "base_intent",
    "cases",
}


def _validate_selection_basis(
    selection: Mapping[str, Any],
) -> tuple[str, list[dict[str, Any]]]:
    _scan_prohibited_content(selection, "selection")
    _exact_fields(
        selection,
        "selection",
        SELECTION_BASIS_FIELDS,
    )
    if (
        type(selection.get("version")) is not int
        or selection.get("version") != VERSION
        or selection.get("kind") != "publication-selection"
    ):
        _fail("invalid-selection", "selection must be a version 1 publication-selection")
    selection_id = _safe_object_id(selection.get("selection_id"), "selection_id")
    snapshot_digest = _require_string(selection["daily_snapshot_digest"], "daily_snapshot_digest")
    if HEX64_RE.fullmatch(snapshot_digest) is None:
        _fail("invalid-digest", "daily_snapshot_digest must be raw SHA-256")
    base = _require_object(selection["base_intent"], "base_intent")
    _exact_fields(base, "selection.base_intent", {"repository", "base_branch", "base_sha"})
    if base["repository"] != LEDGER_REPOSITORY or base["base_branch"] != LEDGER_BASE_BRANCH:
        _fail("invalid-publication-target", "selection must target the fixed ledger master branch")
    if GIT_SHA_RE.fullmatch(_require_string(base["base_sha"], "base_intent.base_sha")) is None:
        _fail("invalid-git-sha", "base_intent.base_sha must be a Git object ID")
    selected = _require_list(selection.get("cases"), "cases")
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, value in enumerate(selected):
        item = _require_object(value, f"cases[{index}]")
        case_id = _validate_case_id(item.get("case_id"), f"cases[{index}].case_id")
        if case_id in seen:
            _fail("duplicate-selection", f"selection repeats {case_id}")
        seen.add(case_id)
        _exact_fields(item, f"cases[{index}]", {"case_id", "revision", "semantic_digest"})
        number = _require_int(item.get("revision"), "revision", minimum=1)
        digest = _sha_digest(item.get("semantic_digest"), "semantic_digest")
        entries.append({"case_id": case_id, "revision": number, "semantic_digest": digest})
    return selection_id, sorted(entries, key=lambda item: item["case_id"])


def _publication_case_bytes_upper_bound(case: Mapping[str, Any]) -> int:
    """Bound the only semantic-digest-excluded case field at its longest form."""

    candidate = dict(case)
    candidate["currentness_checked_at"] = "9999-12-31T23:59:59.999999Z"
    return min(MAX_CASE_JSON_BYTES, len(_canonical_bytes(candidate)))


def _selection_resource_preflight(
    basis: Mapping[str, Any], case_bytes_upper_bound: int
) -> dict[str, Any]:
    selected = _require_list(basis.get("cases"), "cases")
    selected_count = len(selected)
    basis_bytes = len(_canonical_bytes(basis))
    publication_upper_bound = (
        PUBLICATION_FIXED_BUDGET_BYTES
        + case_bytes_upper_bound
        + selected_count * PUBLICATION_PER_CASE_OVERHEAD_BYTES
    )
    weekly_wal_upper_bound = (
        WEEKLY_WAL_FIXED_BUDGET_BYTES
        + basis_bytes
        + 2 * publication_upper_bound
        + selected_count * WEEKLY_WAL_PER_CASE_OVERHEAD_BYTES
    )
    # Finalization retains the plan and prepared receipt in its request, writes
    # the prepared receipt once, and writes the case-bearing manifest twice
    # (control registry plus external output).  Five publication-sized objects
    # plus fixed WAL/path framing is therefore a conservative full-schema bound.
    finalize_wal_upper_bound = FINALIZE_WAL_FIXED_BUDGET_BYTES + 5 * publication_upper_bound
    return {
        "method": "publication-workflow-upper-bound-v1",
        "selection_basis_digest": _digest(basis),
        "selection_basis_bytes": basis_bytes,
        "selected_count": selected_count,
        "case_bytes_upper_bound": case_bytes_upper_bound,
        "publication_fixed_budget_bytes": PUBLICATION_FIXED_BUDGET_BYTES,
        "publication_per_case_overhead_bytes": PUBLICATION_PER_CASE_OVERHEAD_BYTES,
        "publication_upper_bound_bytes": publication_upper_bound,
        "publication_limit_bytes": MAX_PUBLICATION_JSON_BYTES,
        "weekly_fixed_budget_bytes": WEEKLY_WAL_FIXED_BUDGET_BYTES,
        "weekly_per_case_overhead_bytes": WEEKLY_WAL_PER_CASE_OVERHEAD_BYTES,
        "weekly_wal_upper_bound_bytes": weekly_wal_upper_bound,
        "finalize_fixed_budget_bytes": FINALIZE_WAL_FIXED_BUDGET_BYTES,
        "finalize_wal_upper_bound_bytes": finalize_wal_upper_bound,
        "wal_limit_bytes": MAX_WAL_JSON_BYTES,
    }


def _validate_selection_resource(
    resource: Mapping[str, Any], basis: Mapping[str, Any]
) -> dict[str, Any]:
    _exact_fields(
        resource,
        "selection.resource_preflight",
        {
            "method",
            "selection_basis_digest",
            "selection_basis_bytes",
            "selected_count",
            "case_bytes_upper_bound",
            "publication_fixed_budget_bytes",
            "publication_per_case_overhead_bytes",
            "publication_upper_bound_bytes",
            "publication_limit_bytes",
            "weekly_fixed_budget_bytes",
            "weekly_per_case_overhead_bytes",
            "weekly_wal_upper_bound_bytes",
            "finalize_fixed_budget_bytes",
            "finalize_wal_upper_bound_bytes",
            "wal_limit_bytes",
        },
    )
    selected_count = len(_require_list(basis.get("cases"), "cases"))
    case_bytes_upper_bound = _require_int(
        resource["case_bytes_upper_bound"],
        "selection.resource_preflight.case_bytes_upper_bound",
    )
    if case_bytes_upper_bound > selected_count * MAX_CASE_JSON_BYTES:
        _fail("invalid-selection-preflight", "selection case byte bound exceeds schema maximum")
    expected = _selection_resource_preflight(basis, case_bytes_upper_bound)
    if resource != expected:
        _fail(
            "invalid-selection-preflight",
            "selection resource preflight does not bind its exact basis and constants",
        )
    if expected["publication_upper_bound_bytes"] > MAX_PUBLICATION_JSON_BYTES:
        _fail(
            "selection-resource-limit",
            "selection cannot fit the bounded publication artifact",
        )
    if (
        max(
            expected["weekly_wal_upper_bound_bytes"],
            expected["finalize_wal_upper_bound_bytes"],
        )
        > MAX_WAL_JSON_BYTES
    ):
        _fail(
            "selection-resource-limit",
            "selection cannot fit the bounded publication WAL transactions",
        )
    return expected


def _validate_selection(selection: Mapping[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    _scan_prohibited_content(selection, "selection")
    _exact_fields(
        selection,
        "selection",
        {
            *SELECTION_BASIS_FIELDS,
            "resource_preflight",
            "preflight_receipt_id",
            "preflight_receipt_digest",
            "interaction",
        },
    )
    basis = {key: selection[key] for key in SELECTION_BASIS_FIELDS}
    selection_id, entries = _validate_selection_basis(basis)
    resource = _require_object(selection["resource_preflight"], "selection.resource_preflight")
    expected = _validate_selection_resource(resource, basis)
    receipt_id = _require_string(
        selection["preflight_receipt_id"], "selection.preflight_receipt_id"
    )
    expected_receipt_id = str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"dsf-selection-preflight:{selection_id}")
    )
    if receipt_id != expected_receipt_id:
        _fail("invalid-selection-preflight", "preflight receipt ID does not bind selection ID")
    receipt_digest = _require_string(
        selection["preflight_receipt_digest"], "selection.preflight_receipt_digest"
    )
    if HEX64_RE.fullmatch(receipt_digest) is None:
        _fail("invalid-selection-preflight", "preflight receipt digest must be raw SHA-256")
    interaction = _require_object(selection["interaction"], "selection.interaction")
    _exact_fields(
        interaction,
        "selection.interaction",
        {
            "interactive",
            "actor",
            "approved_at",
            "selection_basis_digest",
            "preflight_receipt_id",
            "preflight_receipt_digest",
        },
    )
    if interaction["interactive"] is not True or interaction["actor"] != "Joey":
        _fail("untrusted-selection", "selection approval must be interactive Joey input")
    _timestamp(interaction["approved_at"], "selection.interaction.approved_at")
    if (
        interaction["selection_basis_digest"] != expected["selection_basis_digest"]
        or interaction["preflight_receipt_id"] != receipt_id
        or interaction["preflight_receipt_digest"] != receipt_digest
    ):
        _fail(
            "untrusted-selection",
            "selection approval must bind the exact basis and helper preflight receipt",
        )
    return selection_id, entries


def _deterministic_branch(case_id: str) -> str:
    return f"codex/dsf/{case_id.lower()}"


def _completed_snapshot_by_digest(root: Path, digest: str) -> dict[str, Any] | None:
    pointer = root / LIVE_POINTER
    if not _state_exists(pointer):
        return None
    live = _load_json(pointer)
    _validate_completed_snapshot(live)
    if live["mode"] != "live":
        _fail("invalid-live-pointer", "live pointer contains a non-live snapshot")

    snapshots: dict[str, dict[str, Any]] = {}
    history = root / "completed"
    if _state_exists(history):
        for name in _state_list_names(history):
            if not name.endswith(".json") or SAFE_OBJECT_ID_RE.fullmatch(name[:-5]) is None:
                _fail("unsafe-snapshot-layout", f"unexpected completed snapshot: {name}")
            snapshot = _load_json(history / name)
            _validate_completed_snapshot(snapshot)
            if snapshot["mode"] != "live" or snapshot["audit_id"] != name[:-5]:
                _fail("invalid-snapshot-history", "completed history filename/mode is invalid")
            snapshot_digest = snapshot["snapshot_digest"]
            if snapshot_digest in snapshots and snapshots[snapshot_digest] != snapshot:
                _fail(
                    "snapshot-digest-collision",
                    "different completed snapshots share a digest",
                )
            snapshots[snapshot_digest] = snapshot
    if snapshots.get(live["snapshot_digest"]) != live:
        _fail("invalid-live-pointer", "live pointer does not match immutable completed history")

    chain: list[dict[str, Any]] = []
    seen: set[str] = set()
    current = live
    while True:
        current_digest = current["snapshot_digest"]
        if current_digest in seen:
            _fail("snapshot-ancestry-cycle", "completed snapshot ancestry contains a cycle")
        seen.add(current_digest)
        chain.append(current)
        previous = current["previous_snapshot_digest"]
        if previous is None:
            break
        prior = snapshots.get(previous)
        if prior is None:
            _fail("broken-snapshot-ancestry", "completed snapshot ancestry is incomplete")
        current = prior
    if seen != set(snapshots):
        _fail("orphan-completed-snapshot", "completed history is outside the live ancestry")
    return next((snapshot for snapshot in chain if snapshot["snapshot_digest"] == digest), None)


def _validate_selection_preflight_receipt(
    receipt: Mapping[str, Any],
    basis: Mapping[str, Any],
    resource: Mapping[str, Any],
) -> str:
    _exact_fields(
        receipt,
        "selection.preflight_receipt",
        {
            "version",
            "kind",
            "status",
            "selection_id",
            "receipt_id",
            "checked_at",
            "selection_basis_digest",
            "resource_preflight",
            "receipt_digest",
        },
    )
    if (
        type(receipt["version"]) is not int
        or receipt["version"] != VERSION
        or receipt["kind"] != "selection-preflight-receipt"
        or receipt["status"] != "ready"
    ):
        _fail("invalid-selection-preflight", "selection preflight receipt kind/status is invalid")
    if receipt["selection_id"] != basis["selection_id"]:
        _fail("invalid-selection-preflight", "selection preflight receipt binds another selection")
    expected_receipt_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"dsf-selection-preflight:{basis['selection_id']}",
        )
    )
    if receipt["receipt_id"] != expected_receipt_id:
        _fail("invalid-selection-preflight", "selection preflight receipt ID is invalid")
    _timestamp(receipt["checked_at"], "selection.preflight_receipt.checked_at")
    if (
        receipt["selection_basis_digest"] != _digest(basis)
        or receipt["resource_preflight"] != resource
    ):
        _fail("invalid-selection-preflight", "selection preflight receipt binding changed")
    body = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    digest = _digest(body)
    if receipt["receipt_digest"] != digest:
        _fail("invalid-selection-preflight", "selection preflight receipt digest mismatch")
    return digest


def preflight_selection(state_root: Path, selection_draft_path: Path, now: str) -> dict[str, Any]:
    """Validate and persist an exact preapproval selection resource receipt."""

    now_value = _timestamp(now, "now")
    basis = _load_json(selection_draft_path, max_bytes=MAX_PUBLICATION_JSON_BYTES)
    selection_id, selected = _validate_selection_basis(basis)
    with _state_lock(state_root, create=False) as store:
        _recover_pending_wal(store)
        marker = _read_marker(state_root)
        if marker is None or marker.get("mode") != "live":
            _fail("not-live-state", "selection preflight requires completed live state")
        pointer = _load_json(state_root / LIVE_POINTER)
        _validate_completed_snapshot(pointer)
        pointer_digest = pointer["snapshot_digest"]
        if _receipt_files(state_root, "stage", pointer_digest) or _receipt_files(
            state_root, "dormancy", pointer_digest
        ):
            _fail(
                "daily-incomplete",
                "selection preflight cannot consume an incomplete Daily audit",
            )
        selected_snapshot = _completed_snapshot_by_digest(
            state_root, basis["daily_snapshot_digest"]
        )
        if selected_snapshot is None or selected_snapshot["mode"] != "live":
            _fail(
                "unknown-selection-snapshot",
                "selection snapshot is not a completed live snapshot",
            )
        if _parse_time(selected_snapshot["completed_at"], "snapshot.completed_at") > _parse_time(
            now_value, "preflight.checked_at"
        ):
            _fail("clock-order", "selection preflight cannot predate its completed Daily snapshot")
        selected_snapshot_cases = {
            item["case_id"]: item for item in selected_snapshot.get("cases", [])
        }
        current_by_id = {item["case_id"]: item for item in _snapshot_cases(state_root)}
        case_bytes_upper_bound = 0
        for selected_item in selected:
            case_id = selected_item["case_id"]
            selected_snapshot_case = selected_snapshot_cases.get(case_id)
            current = current_by_id.get(case_id)
            if selected_snapshot_case is None or current is None:
                _fail(
                    "selection-preflight-stale",
                    f"selection preflight cannot bind missing case: {case_id}",
                )
            if any(
                selected_snapshot_case.get(field) != selected_item[field]
                or current[field] != selected_item[field]
                for field in ("revision", "semantic_digest")
            ):
                _fail(
                    "selection-preflight-stale",
                    f"selection preflight tuple is stale: {case_id}",
                )
            wrapper, wrapper_sha = _load_json_with_digest(state_root / current["case_path"])
            validate_candidate(wrapper)
            if wrapper_sha != current["wrapper_file_sha256"]:
                _fail("case-drift", f"case bytes changed during preflight: {case_id}")
            case = _require_object(wrapper["case"], "candidate.case")
            if case["status"] not in {"watching", "proposed"}:
                _fail(
                    "selection-preflight-ineligible",
                    f"selection preflight case is not publication eligible: {case_id}",
                )
            active_relative = Path("publication") / "active" / f"{case_id}.json"
            if store.exists(active_relative):
                active, _ = store.read_json(active_relative)
                _validate_pending_record(active, case_id)
                if active["status"] == "active":
                    _fail(
                        "selection-preflight-ineligible",
                        f"selection preflight case already has an active publication: {case_id}",
                    )
                if (
                    selected_item["revision"] <= active["revision"]
                    or selected_item["semantic_digest"] == active["semantic_digest"]
                ):
                    _fail(
                        "selection-preflight-ineligible",
                        f"selection preflight case cannot reopen its closed tuple: {case_id}",
                    )
            case_bytes_upper_bound += _publication_case_bytes_upper_bound(case)
        resource = _selection_resource_preflight(basis, case_bytes_upper_bound)
        _validate_selection_resource(resource, basis)
        receipt_body = {
            "version": VERSION,
            "kind": "selection-preflight-receipt",
            "status": "ready",
            "selection_id": selection_id,
            "receipt_id": str(
                uuid.uuid5(uuid.NAMESPACE_URL, f"dsf-selection-preflight:{selection_id}")
            ),
            "checked_at": now_value,
            "selection_basis_digest": resource["selection_basis_digest"],
            "resource_preflight": resource,
        }
        receipt = {**receipt_body, "receipt_digest": _digest(receipt_body)}
        receipt_relative = Path("publication") / "preflights" / f"{selection_id}.json"
        if store.exists(receipt_relative):
            intent_relative, commit_relative = _wal_paths("selection-preflight", selection_id)
            if not store.exists(intent_relative) or not store.exists(commit_relative):
                _fail(
                    "orphan-selection-preflight",
                    "preflight receipt exists without its committed helper transaction",
                )
            existing, _ = store.read_json(receipt_relative)
            _validate_selection_preflight_receipt(existing, basis, resource)
            return _run_transaction(
                store,
                operation="selection-preflight",
                natural_key=selection_id,
                request={"selection_basis": basis},
                captured_at=now_value,
                writes=[],
                result={},
            )
        return _run_transaction(
            store,
            operation="selection-preflight",
            natural_key=selection_id,
            request={"selection_basis": basis},
            captured_at=now_value,
            writes=[_planned_write(store, receipt_relative, receipt, immutable=True)],
            result=receipt,
        )


def weekly_plan(state_root: Path, selection_path: Path, output: Path, now: str) -> dict[str, Any]:
    now_value = _timestamp(now, "now")
    selection = _load_json(selection_path, max_bytes=MAX_PUBLICATION_JSON_BYTES)
    selection_id, selected = _validate_selection(selection)
    snapshot_digest = selection["daily_snapshot_digest"]
    base = selection["base_intent"]
    repository = base["repository"]
    base_branch = base["base_branch"]
    base_sha = base["base_sha"]
    approved_at = _parse_time(selection["interaction"]["approved_at"], "approved_at")
    if approved_at > _parse_time(now_value, "now"):
        _fail("future-state", "selection approval time cannot be after --now")
    request = {
        "selection": selection,
        "output": str(Path(os.path.abspath(os.fspath(output)))),
    }
    with _state_lock(state_root, create=False) as store:
        _recover_pending_wal(store)
        preflight_intent = _require_committed_transaction(
            store, "selection-preflight", selection_id
        )
        receipt_relative = Path("publication") / "preflights" / f"{selection_id}.json"
        if not store.exists(receipt_relative):
            _fail(
                "missing-selection-preflight",
                "approved selection has no durable helper preflight receipt",
            )
        preflight_receipt, _ = store.read_json(receipt_relative)
        basis = {key: selection[key] for key in SELECTION_BASIS_FIELDS}
        receipt_digest = _validate_selection_preflight_receipt(
            preflight_receipt,
            basis,
            selection["resource_preflight"],
        )
        if (
            preflight_intent["result"] != preflight_receipt
            or preflight_receipt["receipt_id"] != selection["preflight_receipt_id"]
            or receipt_digest != selection["preflight_receipt_digest"]
        ):
            _fail(
                "invalid-selection-preflight",
                "approved selection does not bind the durable helper preflight receipt",
            )
        if approved_at <= _parse_time(preflight_receipt["checked_at"], "preflight.checked_at"):
            _fail("clock-order", "selection approval must be after helper preflight")
        intent_path, _ = _wal_paths("weekly-plan", selection_id)
        if store.exists(intent_path):
            return _run_transaction(
                store,
                operation="weekly-plan",
                natural_key=selection_id,
                request=request,
                captured_at=now_value,
                writes=[],
                result={},
                approved_intent_upper_bound=selection["resource_preflight"][
                    "weekly_wal_upper_bound_bytes"
                ],
            )
        marker = _read_marker(state_root)
        if marker is None or marker.get("mode") != "live":
            _fail("not-live-state", "weekly planning requires a completed live state root")
        pointer = _load_json(state_root / LIVE_POINTER)
        _validate_completed_snapshot(pointer)
        pointer_digest = pointer.get("snapshot_digest")
        if _receipt_files(state_root, "stage", pointer_digest) or _receipt_files(
            state_root, "dormancy", pointer_digest
        ):
            _fail("daily-incomplete", "weekly planning cannot consume an incomplete Daily audit")
        selected_snapshot = _completed_snapshot_by_digest(state_root, snapshot_digest)
        if selected_snapshot is None:
            _fail(
                "unknown-selection-snapshot", "selection snapshot is not a completed live snapshot"
            )
        if selected_snapshot["mode"] != "live":
            _fail("unknown-selection-snapshot", "selection snapshot is not live")
        if _parse_time(selected_snapshot["completed_at"], "snapshot.completed_at") >= approved_at:
            _fail("clock-order", "selection approval must follow its completed Daily snapshot")
        selected_snapshot_cases = {
            item["case_id"]: item for item in selected_snapshot.get("cases", [])
        }
        current_by_id = {item["case_id"]: item for item in _snapshot_cases(state_root)}
        entries: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        current_case_bytes_upper_bound = 0
        for selected_item in selected:
            case_id = selected_item["case_id"]
            selected_snapshot_case = selected_snapshot_cases.get(case_id)
            if selected_snapshot_case is None or any(
                selected_snapshot_case.get(field) != selected_item[field]
                for field in ("revision", "semantic_digest")
            ):
                skipped.append({"case_id": case_id, "reason": "stale-selection"})
                continue
            current = current_by_id.get(case_id)
            if current is None:
                skipped.append({"case_id": case_id, "reason": "missing-case"})
                continue
            if any(
                current[field] != selected_item[field] for field in ("revision", "semantic_digest")
            ):
                skipped.append({"case_id": case_id, "reason": "stale-selection"})
                continue
            wrapper, wrapper_sha = _load_json_with_digest(state_root / current["case_path"])
            validate_candidate(wrapper)
            case = wrapper["case"]
            if wrapper_sha != current["wrapper_file_sha256"]:
                _fail("case-drift", f"case bytes changed during planning: {case_id}")
            if case["status"] not in {"watching", "proposed"}:
                skipped.append({"case_id": case_id, "reason": "ineligible-lifecycle"})
                continue
            current_case_bytes_upper_bound += _publication_case_bytes_upper_bound(case)
            ledger_case_path = str(Path("cases") / f"{_case_year(case_id):04d}" / f"{case_id}.json")
            entries.append(
                {
                    "case_id": case_id,
                    "state_case_path": current["case_path"],
                    "ledger_case_path": ledger_case_path,
                    "revision": current["revision"],
                    "semantic_digest": current["semantic_digest"],
                    "case_sha256": current["case_sha256"],
                    "case": case,
                    "branch": _deterministic_branch(case_id),
                    "base_sha": base_sha,
                    "changed_paths": [ledger_case_path],
                }
            )
        entries.sort(key=lambda item: item["case_id"])
        skipped.sort(key=lambda item: item["case_id"])
        recorded_case_bound = _require_int(
            selection["resource_preflight"]["case_bytes_upper_bound"],
            "selection.resource_preflight.case_bytes_upper_bound",
        )
        if current_case_bytes_upper_bound > recorded_case_bound:
            _fail(
                "selection-preflight-stale",
                "current selected cases exceed the approved resource preflight",
            )
        plan_body = {
            "version": VERSION,
            "kind": "weekly-publication-plan",
            "plan_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"dsf-plan:{selection_id}")),
            "selection_id": selection_id,
            "selection_digest": _digest(selection),
            "selection_preflight_receipt_digest": selection["preflight_receipt_digest"],
            "resource_preflight": selection["resource_preflight"],
            "created_at": now_value,
            "selected_daily_snapshot_digest": snapshot_digest,
            "planned_from_current_snapshot_digest": pointer["snapshot_digest"],
            "base_intent": {
                "repository": repository,
                "base_branch": base_branch,
                "base_sha": base_sha,
            },
            "entries": entries,
            "skipped": skipped,
        }
        plan = dict(plan_body)
        plan["plan_digest"] = _digest(plan_body)
        _validate_plan(plan)
        if (
            len(_canonical_bytes(plan))
            > selection["resource_preflight"]["publication_upper_bound_bytes"]
        ):
            _fail(
                "invalid-selection-preflight",
                "actual publication plan exceeds its approved upper bound",
            )
        registry_relative = Path("publication") / "plans" / f"{selection_id}.json"

        # Full conflict and output preflight precedes every persistent write.
        if store.exists(registry_relative):
            _fail(
                "orphan-publication-plan",
                "registered plan exists without its committed weekly transaction",
            )
        active_writes: list[dict[str, Any]] = []
        for entry in entries:
            active_relative = Path("publication") / "active" / f"{entry['case_id']}.json"
            previous_closure_digest: str | None = None
            if store.exists(active_relative):
                active, _ = store.read_json(active_relative)
                _validate_pending_record(active, entry["case_id"])
                if active["status"] == "closed":
                    if (
                        entry["revision"] <= active["revision"]
                        or entry["semantic_digest"] == active["semantic_digest"]
                    ):
                        _fail(
                            "publication-already-closed",
                            f"closed publication tuple cannot be reopened: {entry['case_id']}",
                        )
                    previous_closure_digest = active["closure_digest"]
                else:
                    _fail(
                        "publication-already-pending",
                        f"case already has another active publication: {entry['case_id']}",
                    )
            active_body = {
                "version": VERSION,
                "kind": "publication-pending",
                "status": "active",
                "case_id": entry["case_id"],
                "revision": entry["revision"],
                "semantic_digest": entry["semantic_digest"],
                "selection_id": selection_id,
                "plan_digest": plan["plan_digest"],
                "activated_at": now_value,
                "previous_closure_digest": previous_closure_digest,
                "closure_id": None,
                "closure_digest": None,
                "closure_reason": None,
                "closed_at": None,
            }
            active = {**active_body, "record_digest": _digest(active_body)}
            active_writes.append(_planned_write(store, active_relative, active, immutable=False))
        output_write = _planned_external_write(output, plan, immutable=True)
        writes = [_planned_write(store, registry_relative, plan, immutable=True)]
        writes.extend(active_writes)
        writes.append(output_write)
        result = {
            "version": VERSION,
            "status": "planned",
            "plan_path": str(Path(os.path.abspath(os.fspath(output)))),
            "plan_digest": plan["plan_digest"],
            "selected_count": len(entries),
            "skipped": skipped,
        }
        return _run_transaction(
            store,
            operation="weekly-plan",
            natural_key=selection_id,
            request=request,
            captured_at=now_value,
            writes=writes,
            result=result,
            approved_intent_upper_bound=selection["resource_preflight"][
                "weekly_wal_upper_bound_bytes"
            ],
        )


def _validate_plan_resource(resource: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "method",
        "selection_basis_digest",
        "selection_basis_bytes",
        "selected_count",
        "case_bytes_upper_bound",
        "publication_fixed_budget_bytes",
        "publication_per_case_overhead_bytes",
        "publication_upper_bound_bytes",
        "publication_limit_bytes",
        "weekly_fixed_budget_bytes",
        "weekly_per_case_overhead_bytes",
        "weekly_wal_upper_bound_bytes",
        "finalize_fixed_budget_bytes",
        "finalize_wal_upper_bound_bytes",
        "wal_limit_bytes",
    }
    _exact_fields(resource, "plan.resource_preflight", fields)
    if (
        resource["method"] != "publication-workflow-upper-bound-v1"
        or HEX64_RE.fullmatch(
            _require_string(resource["selection_basis_digest"], "resource.selection_basis_digest")
        )
        is None
    ):
        _fail("invalid-plan", "plan resource preflight method/digest is invalid")
    selected_count = _require_int(resource["selected_count"], "resource.selected_count")
    basis_bytes = _require_int(resource["selection_basis_bytes"], "resource.selection_basis_bytes")
    case_bytes = _require_int(resource["case_bytes_upper_bound"], "resource.case_bytes_upper_bound")
    if case_bytes > selected_count * MAX_CASE_JSON_BYTES:
        _fail("invalid-plan", "plan resource case-byte bound exceeds the schema maximum")
    expected_publication = (
        PUBLICATION_FIXED_BUDGET_BYTES
        + case_bytes
        + selected_count * PUBLICATION_PER_CASE_OVERHEAD_BYTES
    )
    expected_weekly = (
        WEEKLY_WAL_FIXED_BUDGET_BYTES
        + basis_bytes
        + 2 * expected_publication
        + selected_count * WEEKLY_WAL_PER_CASE_OVERHEAD_BYTES
    )
    expected_finalize = FINALIZE_WAL_FIXED_BUDGET_BYTES + 5 * expected_publication
    exact_numbers = {
        "publication_fixed_budget_bytes": PUBLICATION_FIXED_BUDGET_BYTES,
        "publication_per_case_overhead_bytes": PUBLICATION_PER_CASE_OVERHEAD_BYTES,
        "publication_upper_bound_bytes": expected_publication,
        "publication_limit_bytes": MAX_PUBLICATION_JSON_BYTES,
        "weekly_fixed_budget_bytes": WEEKLY_WAL_FIXED_BUDGET_BYTES,
        "weekly_per_case_overhead_bytes": WEEKLY_WAL_PER_CASE_OVERHEAD_BYTES,
        "weekly_wal_upper_bound_bytes": expected_weekly,
        "finalize_fixed_budget_bytes": FINALIZE_WAL_FIXED_BUDGET_BYTES,
        "finalize_wal_upper_bound_bytes": expected_finalize,
        "wal_limit_bytes": MAX_WAL_JSON_BYTES,
    }
    if any(resource[field] != value for field, value in exact_numbers.items()):
        _fail("invalid-plan", "plan resource preflight constants or arithmetic changed")
    if (
        expected_publication > MAX_PUBLICATION_JSON_BYTES
        or max(expected_weekly, expected_finalize) > MAX_WAL_JSON_BYTES
    ):
        _fail("invalid-plan", "plan resource preflight exceeds its declared envelopes")
    return dict(resource)


def _validate_plan(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    _scan_prohibited_content(plan, "plan")
    _exact_fields(
        plan,
        "plan",
        {
            "version",
            "kind",
            "plan_id",
            "selection_id",
            "selection_digest",
            "selection_preflight_receipt_digest",
            "resource_preflight",
            "created_at",
            "selected_daily_snapshot_digest",
            "planned_from_current_snapshot_digest",
            "base_intent",
            "entries",
            "skipped",
            "plan_digest",
        },
    )
    if (
        type(plan["version"]) is not int
        or plan["version"] != VERSION
        or plan["kind"] != "weekly-publication-plan"
    ):
        _fail("invalid-plan", "plan must be a version 1 weekly-publication-plan")
    selection_id = _safe_object_id(plan["selection_id"], "plan.selection_id")
    expected_plan_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"dsf-plan:{selection_id}"))
    if plan["plan_id"] != expected_plan_id:
        _fail("invalid-plan", "plan_id does not bind selection_id")
    for field in (
        "selection_digest",
        "selection_preflight_receipt_digest",
        "selected_daily_snapshot_digest",
        "planned_from_current_snapshot_digest",
    ):
        if HEX64_RE.fullmatch(_require_string(plan[field], f"plan.{field}")) is None:
            _fail("invalid-plan", f"plan.{field} must be raw SHA-256")
    resource = _validate_plan_resource(
        _require_object(plan["resource_preflight"], "plan.resource_preflight")
    )
    _timestamp(plan["created_at"], "plan.created_at")
    base = _require_object(plan["base_intent"], "plan.base_intent")
    _exact_fields(base, "plan.base_intent", {"repository", "base_branch", "base_sha"})
    if base["repository"] != LEDGER_REPOSITORY or base["base_branch"] != LEDGER_BASE_BRANCH:
        _fail("invalid-publication-target", "plan must target the fixed ledger master branch")
    if GIT_SHA_RE.fullmatch(_require_string(base["base_sha"], "plan.base_sha")) is None:
        _fail("invalid-git-sha", "plan base_sha is invalid")
    entries: list[dict[str, Any]] = []
    prior = ""
    for index, raw in enumerate(_require_list(plan["entries"], "plan.entries")):
        entry = _require_object(raw, f"plan.entries[{index}]")
        _exact_fields(
            entry,
            f"plan.entries[{index}]",
            {
                "case_id",
                "state_case_path",
                "ledger_case_path",
                "revision",
                "semantic_digest",
                "case_sha256",
                "case",
                "branch",
                "base_sha",
                "changed_paths",
            },
        )
        case_id = _validate_case_id(entry["case_id"])
        if case_id <= prior:
            _fail("plan-order", "plan entries must be unique and sorted")
        prior = case_id
        expected_case_path = Path("cases") / f"{_case_year(case_id):04d}" / f"{case_id}.json"
        if (
            Path(entry["state_case_path"]) != expected_case_path
            or Path(entry["ledger_case_path"]) != expected_case_path
        ):
            _fail("invalid-plan", "plan case path does not bind case ID/year")
        revision = _require_int(entry["revision"], "plan.entry.revision", minimum=1)
        digest = _sha_digest(entry["semantic_digest"], "plan.entry.semantic_digest")
        case = _require_object(entry["case"], "plan.entry.case")
        if (
            case.get("id") != case_id
            or case.get("revision") != revision
            or semantic_digest(case) != digest
        ):
            _fail("invalid-plan", "plan case body does not bind its semantic tuple")
        case_sha = _validate_raw_sha_or_none(entry["case_sha256"], "plan.entry.case_sha256")
        if case_sha != hashlib.sha256(_canonical_bytes(case)).hexdigest():
            _fail("invalid-plan", "plan case content digest mismatch")
        if entry["branch"] != _deterministic_branch(case_id):
            _fail("invalid-plan", "plan branch is not deterministic")
        if entry["base_sha"] != base["base_sha"]:
            _fail("invalid-plan", "plan entry base_sha differs from base intent")
        if entry["changed_paths"] != [expected_case_path.as_posix()]:
            _fail("invalid-plan", "plan changed_paths must contain the exact ledger case")
        entries.append(entry)
    prior = ""
    for index, raw in enumerate(_require_list(plan["skipped"], "plan.skipped")):
        item = _require_object(raw, f"plan.skipped[{index}]")
        _exact_fields(item, f"plan.skipped[{index}]", {"case_id", "reason"})
        case_id = _validate_case_id(item["case_id"])
        if case_id <= prior or item["reason"] not in {
            "stale-selection",
            "missing-case",
            "ineligible-lifecycle",
        }:
            _fail("invalid-plan", "plan skipped entries must be sorted with a closed reason")
        prior = case_id
    if resource["selected_count"] != len(entries) + len(plan["skipped"]):
        _fail("invalid-plan", "plan resource preflight selected_count does not match the plan")
    if (
        sum(_publication_case_bytes_upper_bound(entry["case"]) for entry in entries)
        > resource["case_bytes_upper_bound"]
    ):
        _fail("invalid-plan", "plan case bodies exceed the approved case-byte bound")
    body = {key: value for key, value in plan.items() if key != "plan_digest"}
    if plan["plan_digest"] != _digest(body):
        _fail("plan-digest-mismatch", "plan content no longer matches plan_digest")
    if len(_canonical_bytes(plan)) > resource["publication_upper_bound_bytes"]:
        _fail("invalid-plan", "plan exceeds its approved publication envelope")
    return entries


def _validate_prepared_entry(
    value: Any,
    index: int,
    plan_entry: Mapping[str, Any],
    *,
    plan_created_at: str,
    now: str,
) -> dict[str, Any]:
    entry = _require_object(value, f"prepared.entries[{index}]")
    _exact_fields(
        entry,
        f"prepared.entries[{index}]",
        {
            "case_id",
            "revision",
            "semantic_digest",
            "case_sha256",
            "branch",
            "base_sha",
            "commit_sha",
            "changed_paths",
            "validation",
            "signature",
        },
    )
    case_id = _validate_case_id(entry.get("case_id"), f"prepared.entries[{index}].case_id")
    if case_id != plan_entry["case_id"]:
        _fail("prepared-drift", f"prepared entry case does not match plan: {case_id}")
    for field in (
        "revision",
        "semantic_digest",
        "case_sha256",
        "branch",
        "base_sha",
        "changed_paths",
    ):
        if entry.get(field) != plan_entry[field]:
            _fail("prepared-drift", f"prepared {field} does not match plan for {case_id}")
    if SAFE_BRANCH_RE.fullmatch(entry["branch"]) is None or ".." in entry["branch"]:
        _fail("invalid-branch", f"invalid branch for {case_id}")
    commit_sha = _require_string(entry.get("commit_sha"), "commit_sha")
    if GIT_SHA_RE.fullmatch(commit_sha) is None:
        _fail("invalid-git-sha", f"invalid commit SHA for {case_id}")
    validation = _require_object(entry.get("validation"), "validation")
    _exact_fields(validation, "prepared.validation", {"status", "commands", "validated_at"})
    if validation.get("status") != "passed":
        _fail("validation-failed", f"local validation did not pass for {case_id}")
    commands = _require_list(validation.get("commands"), "validation.commands")
    if not commands:
        _fail("validation-missing", f"validation commands are missing for {case_id}")
    if len(commands) > MAX_PREPARED_COMMANDS:
        _fail(
            "validation-too-large",
            f"validation commands exceed {MAX_PREPARED_COMMANDS} entries for {case_id}",
        )
    for command in commands:
        _bounded_string(
            command,
            "validation command",
            1,
            MAX_PREPARED_COMMAND_CHARS,
        )
    validated_at = _timestamp(validation.get("validated_at"), "validation.validated_at")
    signature = _require_object(entry.get("signature"), "signature")
    _exact_fields(
        signature,
        "prepared.signature",
        {"status", "commit_sha", "signer", "verified_at"},
    )
    if signature.get("status") != "verified" or signature.get("commit_sha") != commit_sha:
        _fail("signature-unverified", f"commit signature is not verified for {case_id}")
    _bounded_string(
        signature.get("signer"),
        "signature.signer",
        1,
        MAX_PREPARED_SIGNER_CHARS,
    )
    verified_at = _timestamp(signature.get("verified_at"), "signature.verified_at")
    if not (
        _parse_time(plan_created_at, "plan.created_at")
        <= _parse_time(validated_at, "validated_at")
        <= _parse_time(verified_at, "verified_at")
        <= _parse_time(now, "now")
    ):
        _fail("clock-order", "plan, validation, signature, and finalize clocks are unordered")
    return entry


def _validate_prepared_receipt(
    prepared: Mapping[str, Any], plan: Mapping[str, Any], *, now: str
) -> dict[str, dict[str, Any]]:
    _scan_prohibited_content(prepared, "prepared")
    _exact_fields(prepared, "prepared", {"version", "kind", "plan_digest", "entries"})
    if (
        type(prepared.get("version")) is not int
        or prepared.get("version") != VERSION
        or prepared.get("kind") != "prepared-commits"
    ):
        _fail("invalid-prepared", "prepared receipt must be a version 1 prepared-commits object")
    if prepared.get("plan_digest") != plan["plan_digest"]:
        _fail("prepared-plan-mismatch", "prepared receipt does not bind the exact plan")
    plan_entries = _validate_plan(plan)
    plan_by_id = {item["case_id"]: item for item in plan_entries}
    prepared_by_id: dict[str, dict[str, Any]] = {}
    prior = ""
    for index, raw in enumerate(_require_list(prepared.get("entries"), "prepared.entries")):
        item = _require_object(raw, f"prepared.entries[{index}]")
        case_id = _validate_case_id(item.get("case_id"), f"prepared.entries[{index}].case_id")
        if case_id <= prior:
            _fail("duplicate-prepared-entry", "prepared entries must be unique and sorted")
        prior = case_id
        plan_entry = plan_by_id.get(case_id)
        if plan_entry is None:
            _fail("prepared-set-mismatch", "prepared entry is not present in the plan")
        prepared_by_id[case_id] = _validate_prepared_entry(
            item,
            index,
            plan_entry,
            plan_created_at=plan["created_at"],
            now=now,
        )
    if set(prepared_by_id) != set(plan_by_id):
        _fail("prepared-set-mismatch", "prepared entries must exactly match every plan entry")
    resource = _validate_plan_resource(
        _require_object(plan["resource_preflight"], "plan.resource_preflight")
    )
    if len(_canonical_bytes(prepared)) > resource["publication_upper_bound_bytes"]:
        _fail("invalid-prepared", "prepared receipt exceeds the approved publication envelope")
    return prepared_by_id


def _validate_manifest(
    manifest: Mapping[str, Any], plan: Mapping[str, Any], prepared: Mapping[str, Any]
) -> list[dict[str, Any]]:
    _scan_prohibited_content(manifest, "manifest")
    _exact_fields(
        manifest,
        "manifest",
        {
            "version",
            "kind",
            "plan_id",
            "plan_digest",
            "selection_id",
            "selected_daily_snapshot_digest",
            "planned_from_current_snapshot_digest",
            "finalized_against_current_snapshot_digest",
            "created_at",
            "base_intent",
            "prepared_digest",
            "entries",
            "manifest_digest",
        },
    )
    if (
        type(manifest["version"]) is not int
        or manifest["version"] != VERSION
        or manifest["kind"] != "publication-manifest"
    ):
        _fail("invalid-manifest", "manifest version or kind is invalid")
    for field in (
        "plan_id",
        "plan_digest",
        "selection_id",
        "selected_daily_snapshot_digest",
        "planned_from_current_snapshot_digest",
        "base_intent",
    ):
        if manifest[field] != plan[field]:
            _fail("invalid-manifest", f"manifest {field} does not bind registered plan")
    if (
        HEX64_RE.fullmatch(
            _require_string(
                manifest["finalized_against_current_snapshot_digest"],
                "manifest.finalized_snapshot",
            )
        )
        is None
    ):
        _fail("invalid-manifest", "finalized snapshot digest must be raw SHA-256")
    manifest_created_at = _timestamp(manifest["created_at"], "manifest.created_at")
    if _parse_time(manifest_created_at, "manifest.created_at") < _parse_time(
        plan["created_at"], "plan.created_at"
    ):
        _fail("clock-order", "manifest creation cannot predate its plan")
    if manifest["prepared_digest"] != _digest(prepared):
        _fail("invalid-manifest", "manifest does not bind exact prepared receipt")
    plan_by_id = {entry["case_id"]: entry for entry in _validate_plan(plan)}
    prepared_by_id = _validate_prepared_receipt(prepared, plan, now=manifest_created_at)
    entries: list[dict[str, Any]] = []
    prior = ""
    expected_fields = {
        "case_id",
        "revision",
        "semantic_digest",
        "case_sha256",
        "ledger_case_path",
        "case",
        "branch",
        "base_sha",
        "commit_sha",
        "changed_paths",
        "validation",
        "signature",
    }
    for index, raw in enumerate(_require_list(manifest["entries"], "manifest.entries")):
        entry = _require_object(raw, f"manifest.entries[{index}]")
        _exact_fields(entry, f"manifest.entries[{index}]", expected_fields)
        case_id = _validate_case_id(entry["case_id"])
        if case_id <= prior or case_id not in plan_by_id or case_id not in prepared_by_id:
            _fail("invalid-manifest", "manifest entry set/order differs from plan/prepared")
        prior = case_id
        plan_entry = plan_by_id[case_id]
        prepared_entry = prepared_by_id[case_id]
        expected = {
            "case_id": case_id,
            "revision": plan_entry["revision"],
            "semantic_digest": plan_entry["semantic_digest"],
            "case_sha256": plan_entry["case_sha256"],
            "ledger_case_path": plan_entry["ledger_case_path"],
            "case": plan_entry["case"],
            **prepared_entry,
        }
        if entry != expected:
            _fail("invalid-manifest", f"manifest entry does not bind plan/prepared: {case_id}")
        entries.append(entry)
    if set(plan_by_id) != {entry["case_id"] for entry in entries}:
        _fail("invalid-manifest", "manifest must include every planned entry")
    body = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if manifest["manifest_digest"] != _digest(body):
        _fail("manifest-digest-mismatch", "manifest body no longer matches digest")
    resource = _validate_plan_resource(
        _require_object(plan["resource_preflight"], "plan.resource_preflight")
    )
    if len(_canonical_bytes(manifest)) > resource["publication_upper_bound_bytes"]:
        _fail("invalid-manifest", "manifest exceeds the approved publication envelope")
    return entries


def finalize_publication(
    state_root: Path, plan_path: Path, prepared_path: Path, output: Path, now: str
) -> dict[str, Any]:
    now_value = _timestamp(now, "now")
    plan = _load_json(plan_path, max_bytes=MAX_PUBLICATION_JSON_BYTES)
    plan_entries = _validate_plan(plan)
    plan_by_id = {item["case_id"]: item for item in plan_entries}

    prepared = _load_json(prepared_path, max_bytes=MAX_PUBLICATION_JSON_BYTES)
    prepared_by_id = _validate_prepared_receipt(prepared, plan, now=now_value)
    resource = _validate_plan_resource(
        _require_object(plan["resource_preflight"], "plan.resource_preflight")
    )
    publication_upper_bound = resource["publication_upper_bound_bytes"]
    finalize_wal_upper_bound = resource["finalize_wal_upper_bound_bytes"]
    if len(_canonical_bytes(prepared)) > publication_upper_bound:
        _fail(
            "invalid-plan-resource-envelope",
            "prepared receipt exceeds the preapproved publication envelope",
        )
    absolute_output = str(Path(os.path.abspath(os.fspath(output))))
    request = {
        "plan": plan,
        "prepared": prepared,
        "output": absolute_output,
    }
    natural_key = f"{plan['selection_id']}:{plan['plan_digest']}"

    with _state_lock(state_root, create=False) as store:
        _recover_pending_wal(store)
        intent_path, _ = _wal_paths("finalize-publication", natural_key)
        existing_finalize_intent: dict[str, Any] | None = None
        if store.exists(intent_path):
            existing_finalize_intent = _require_committed_transaction(
                store, "finalize-publication", natural_key
            )
            if len(_canonical_bytes(existing_finalize_intent)) > finalize_wal_upper_bound:
                _fail(
                    "invalid-plan-resource-envelope",
                    "persisted finalize WAL exceeds the selection envelope",
                )
            if existing_finalize_intent["request_digest"] != _digest(request):
                _fail(
                    "wal-request-conflict",
                    "finalize key binds a different plan/prepared/output request",
                )
        marker = _read_marker(state_root)
        if marker is None or marker.get("mode") != "live":
            _fail("not-live-state", "publication finalization requires live state")
        weekly_intent = _require_committed_transaction(store, "weekly-plan", plan["selection_id"])
        if weekly_intent["result"].get("plan_digest") != plan["plan_digest"]:
            _fail("unregistered-plan", "weekly transaction does not bind this plan digest")
        registry_relative = Path("publication") / "plans" / f"{plan['selection_id']}.json"
        if not store.exists(registry_relative) or store.read_json(registry_relative)[0] != plan:
            _fail("unregistered-plan", "plan is not the immutable registered weekly plan")
        snapshot = _load_json(state_root / LIVE_POINTER)
        _validate_completed_snapshot(snapshot)
        current = {item["case_id"]: item for item in _snapshot_cases(state_root)}
        finalized_entries: list[dict[str, Any]] = []
        for case_id in sorted(plan_by_id):
            plan_entry = plan_by_id[case_id]
            active = _load_json(state_root / "publication" / "active" / f"{case_id}.json")
            _validate_pending_record(active, case_id)
            if active.get("status") != "active" or any(
                active.get(field) != expected
                for field, expected in {
                    "revision": plan_entry["revision"],
                    "semantic_digest": plan_entry["semantic_digest"],
                    "selection_id": plan["selection_id"],
                    "plan_digest": plan["plan_digest"],
                }.items()
            ):
                _fail("publication-not-active", f"publication is no longer active: {case_id}")
            current_entry = current.get(case_id)
            if current_entry is None:
                _fail("case-drift", f"selected case disappeared: {case_id}")
            for field in ("revision", "semantic_digest"):
                if current_entry[field] != plan_entry[field]:
                    _fail("case-drift", f"selected case {field} changed: {case_id}")
            if current_entry["status"] not in {"watching", "proposed"}:
                _fail("case-drift", f"selected case lifecycle is no longer eligible: {case_id}")
            prepared_entry = prepared_by_id[case_id]
            finalized_entries.append(
                {
                    "case_id": case_id,
                    "revision": plan_entry["revision"],
                    "semantic_digest": plan_entry["semantic_digest"],
                    "case_sha256": plan_entry["case_sha256"],
                    "ledger_case_path": plan_entry["ledger_case_path"],
                    "case": plan_entry["case"],
                    **prepared_entry,
                }
            )
        registry_output = Path("publication") / "manifests" / f"{plan['selection_id']}.json"
        prepared_digest = _digest(prepared)
        if store.exists(registry_output):
            if existing_finalize_intent is None:
                _fail(
                    "orphan-manifest", "manifest exists without its committed finalize transaction"
                )
            stored_prepared = store.read_json(
                Path("publication") / "prepared" / f"{plan['selection_id']}.json"
            )[0]
            if stored_prepared != prepared:
                _fail("immutable-manifest-conflict", "stored prepared receipt differs")
            existing_manifest = store.read_json(registry_output)[0]
            _validate_manifest(existing_manifest, plan, prepared)
            assert existing_finalize_intent is not None
            _apply_wal_intent(store, existing_finalize_intent)
            return {
                "version": VERSION,
                "status": "finalized",
                "manifest_path": absolute_output,
                "manifest_digest": existing_manifest["manifest_digest"],
                "entry_count": len(existing_manifest["entries"]),
            }
        manifest_body = {
            "version": VERSION,
            "kind": "publication-manifest",
            "plan_id": plan["plan_id"],
            "plan_digest": plan["plan_digest"],
            "selection_id": plan["selection_id"],
            "selected_daily_snapshot_digest": plan["selected_daily_snapshot_digest"],
            "planned_from_current_snapshot_digest": plan["planned_from_current_snapshot_digest"],
            "finalized_against_current_snapshot_digest": snapshot["snapshot_digest"],
            "created_at": now_value,
            "base_intent": plan["base_intent"],
            "prepared_digest": prepared_digest,
            "entries": finalized_entries,
        }
        manifest = dict(manifest_body)
        manifest["manifest_digest"] = _digest(manifest_body)
        _validate_manifest(manifest, plan, prepared)
        if len(_canonical_bytes(manifest)) > publication_upper_bound:
            _fail(
                "invalid-plan-resource-envelope",
                "manifest exceeds the preapproved publication envelope",
            )
        output_write = _planned_external_write(output, manifest, immutable=True)
        prepared_relative = Path("publication") / "prepared" / f"{plan['selection_id']}.json"
        result = {
            "version": VERSION,
            "status": "finalized",
            "manifest_path": absolute_output,
            "manifest_digest": manifest["manifest_digest"],
            "entry_count": len(finalized_entries),
        }
        return _run_transaction(
            store,
            operation="finalize-publication",
            natural_key=natural_key,
            request=request,
            captured_at=now_value,
            writes=[
                _planned_write(store, prepared_relative, prepared, immutable=True),
                _planned_write(store, registry_output, manifest, immutable=True),
                output_write,
            ],
            result=result,
            approved_intent_upper_bound=finalize_wal_upper_bound,
        )


def _validate_publication_approval(
    approval: Mapping[str, Any], closure_entries: Sequence[Mapping[str, Any]]
) -> tuple[str, str]:
    _scan_prohibited_content(approval, "publication_approval")
    _exact_fields(
        approval,
        "publication_approval",
        {
            "version",
            "kind",
            "approval_id",
            "interaction",
            "selection_id",
            "plan_digest",
            "manifest_digest",
            "entries",
        },
    )
    if (
        type(approval["version"]) is not int
        or approval["version"] != VERSION
        or approval["kind"] != "publication-approval"
    ):
        _fail("invalid-publication-approval", "approval version or kind is invalid")
    _safe_object_id(approval["approval_id"], "approval.approval_id")
    interaction = _require_object(approval["interaction"], "approval.interaction")
    _exact_fields(interaction, "approval.interaction", {"interactive", "actor", "approved_at"})
    if interaction["interactive"] is not True or interaction["actor"] != "Joey":
        _fail("untrusted-publication-approval", "publish approval must be interactive Joey input")
    approved_at = _timestamp(interaction["approved_at"], "approval.approved_at")
    _safe_object_id(approval["selection_id"], "approval.selection_id")
    for field in ("plan_digest", "manifest_digest"):
        if HEX64_RE.fullmatch(_require_string(approval[field], f"approval.{field}")) is None:
            _fail("invalid-publication-approval", f"approval.{field} must be raw SHA-256")
    normalized: list[dict[str, Any]] = []
    prior = ""
    for index, raw in enumerate(_require_list(approval["entries"], "approval.entries")):
        item = _require_object(raw, f"approval.entries[{index}]")
        _exact_fields(
            item, f"approval.entries[{index}]", {"case_id", "revision", "semantic_digest"}
        )
        case_id = _validate_case_id(item["case_id"])
        if case_id <= prior:
            _fail("invalid-publication-approval", "approval entries must be unique and sorted")
        prior = case_id
        _require_int(item["revision"], "approval.revision", minimum=1)
        _sha_digest(item["semantic_digest"], "approval.semantic_digest")
        normalized.append(item)
    expected = [
        {
            "case_id": item["case_id"],
            "revision": item["revision"],
            "semantic_digest": item["semantic_digest"],
        }
        for item in closure_entries
    ]
    if normalized != expected:
        _fail("publication-approval-mismatch", "approval must bind the exact closure subset")
    return approved_at, _digest(approval)


def close_publication(
    state_root: Path,
    receipt_path: Path,
    now: str,
    publish_receipt_path: Path | None = None,
) -> dict[str, Any]:
    """Close active pending entries without deleting their immutable history."""

    now_value = _timestamp(now, "now")
    receipt = _load_json(receipt_path)
    _scan_prohibited_content(receipt, "closure")
    _exact_fields(
        receipt,
        "closure",
        {"version", "kind", "closure_id", "interaction", "reason", "summary", "entries"},
    )
    if (
        type(receipt["version"]) is not int
        or receipt["version"] != VERSION
        or receipt["kind"] != "publication-closure"
    ):
        _fail("invalid-closure", "closure must be a version 1 publication-closure")
    closure_id = _safe_object_id(receipt["closure_id"], "closure.closure_id")
    interaction = _require_object(receipt["interaction"], "closure.interaction")
    _exact_fields(interaction, "closure.interaction", {"interactive", "actor", "closed_at"})
    if interaction["interactive"] is not True or interaction["actor"] != "Joey":
        _fail("untrusted-closure", "publication closure must be an interactive Joey decision")
    closed_at = _timestamp(interaction["closed_at"], "closure.interaction.closed_at")
    if _parse_time(closed_at, "closed_at") > _parse_time(now_value, "now"):
        _fail("future-state", "closure time cannot be after --now")
    reason = _require_string(receipt["reason"], "closure.reason")
    if reason not in {"published", "cancelled", "stale"}:
        _fail("invalid-closure-reason", "closure reason must be published, cancelled, or stale")
    _bounded_string(receipt["summary"], "closure.summary", 8, 500)
    entry_fields = {
        "case_id",
        "revision",
        "semantic_digest",
        "selection_id",
        "plan_digest",
        "manifest_digest",
        "pull_request_url",
        "ledger_commit",
        "merged_at",
    }
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, value in enumerate(_require_list(receipt["entries"], "closure.entries")):
        item = _require_object(value, f"closure.entries[{index}]")
        _exact_fields(item, f"closure.entries[{index}]", entry_fields)
        case_id = _validate_case_id(item["case_id"])
        if case_id in seen:
            _fail("duplicate-closure-entry", f"closure repeats {case_id}")
        seen.add(case_id)
        _require_int(item["revision"], "closure.revision", minimum=1)
        _sha_digest(item["semantic_digest"], "closure.semantic_digest")
        _safe_object_id(item["selection_id"], "closure.selection_id")
        for field in ("plan_digest",):
            if not isinstance(item[field], str) or HEX64_RE.fullmatch(item[field]) is None:
                _fail("invalid-digest", f"closure.{field} must be raw SHA-256")
        for field in ("manifest_digest",):
            if item[field] is not None and (
                not isinstance(item[field], str) or HEX64_RE.fullmatch(item[field]) is None
            ):
                _fail("invalid-digest", f"closure.{field} must be raw SHA-256")
        if reason == "published":
            if item["manifest_digest"] is None:
                _fail("missing-publication-evidence", "published closure needs manifest_digest")
            if (
                not isinstance(item["pull_request_url"], str)
                or PR_URL_RE.fullmatch(item["pull_request_url"]) is None
            ):
                _fail("missing-publication-evidence", "published closure needs a GitHub PR URL")
            if (
                not isinstance(item["ledger_commit"], str)
                or COMMIT_RE.fullmatch(item["ledger_commit"]) is None
            ):
                _fail("missing-publication-evidence", "published closure needs ledger commit")
            _timestamp(item["merged_at"], "closure.merged_at")
            if not item["pull_request_url"].startswith(
                f"https://github.com/{LEDGER_REPOSITORY}/pull/"
            ):
                _fail("invalid-publication-target", "published PR must belong to the ledger")
        elif any(
            item[field] is not None
            for field in ("manifest_digest", "pull_request_url", "ledger_commit", "merged_at")
        ):
            _fail("unexpected-publication-evidence", f"{reason} closure cannot claim publication")
        normalized.append(item)
    normalized.sort(key=lambda item: item["case_id"])
    if not normalized:
        _fail("empty-closure", "publication closure must contain at least one active case")
    approval: dict[str, Any] | None = None
    approved_at: str | None = None
    approval_digest: str | None = None
    if reason == "published":
        if publish_receipt_path is None:
            _fail("missing-publication-approval", "published closure needs explicit Joey approval")
        approval = _load_json(publish_receipt_path)
        approved_at, approval_digest = _validate_publication_approval(approval, normalized)
    elif publish_receipt_path is not None:
        _fail("unexpected-publication-approval", f"{reason} closure cannot carry publish approval")
    canonical = dict(receipt)
    canonical["entries"] = normalized
    closure_body = {
        **canonical,
        "publication_approval_digest": approval_digest,
        "recorded_at": closed_at,
    }
    closure_digest = _digest(closure_body)
    closure_record = {**closure_body, "closure_digest": closure_digest}
    request = {"closure": canonical, "publication_approval": approval}

    with _state_lock(state_root, create=False) as store:
        _recover_pending_wal(store)
        intent_path, _ = _wal_paths("close-publication", closure_id)
        if store.exists(intent_path):
            return _run_transaction(
                store,
                operation="close-publication",
                natural_key=closure_id,
                request=request,
                captured_at=now_value,
                writes=[],
                result={},
            )
        marker = _read_marker(state_root)
        if marker is None or marker.get("mode") != "live":
            _fail("not-live-state", "publication closure requires live state")
        history = Path("publication") / "closures" / f"{closure_id}.json"
        if store.exists(history):
            _fail(
                "orphan-publication-closure",
                "closure history exists without its committed control transaction",
            )
        updates: list[dict[str, Any]] = []
        current_cases = {item["case_id"]: item for item in _snapshot_cases(state_root)}
        for item in normalized:
            relative = Path("publication") / "active" / f"{item['case_id']}.json"
            active = store.read_json(relative)[0]
            _validate_pending_record(active, item["case_id"])
            if active["status"] == "closed":
                _fail("publication-not-active", f"case is already closed: {item['case_id']}")
            expected = {
                "case_id": item["case_id"],
                "revision": item["revision"],
                "semantic_digest": item["semantic_digest"],
                "selection_id": item["selection_id"],
                "plan_digest": item["plan_digest"],
            }
            if active["status"] != "active" or any(
                active.get(field) != expected_value for field, expected_value in expected.items()
            ):
                _fail(
                    "publication-receipt-mismatch",
                    f"closure does not bind active {item['case_id']}",
                )
            if _parse_time(active["activated_at"], "active.activated_at") > _parse_time(
                closed_at, "closed_at"
            ):
                _fail("clock-order", "publication closure cannot predate activation")
            current = current_cases.get(item["case_id"])
            drift = current is None or any(
                current[field] != item[field] for field in ("revision", "semantic_digest")
            )
            if current is not None and current["status"] not in {"watching", "proposed"}:
                drift = True
            if reason == "stale" and not drift:
                _fail(
                    "false-stale-closure", "stale closure requires actual semantic/lifecycle drift"
                )
            if reason == "published" and drift:
                _fail("case-drift", "published closure cannot close a stale case")
            if reason == "published":
                assert approval is not None and approved_at is not None
                if (
                    approval["selection_id"] != item["selection_id"]
                    or approval["plan_digest"] != item["plan_digest"]
                    or approval["manifest_digest"] != item["manifest_digest"]
                ):
                    _fail("publication-approval-mismatch", "approval does not bind closure scope")
                plan_relative = Path("publication") / "plans" / f"{item['selection_id']}.json"
                prepared_relative = (
                    Path("publication") / "prepared" / f"{item['selection_id']}.json"
                )
                manifest_relative = (
                    Path("publication") / "manifests" / f"{item['selection_id']}.json"
                )
                plan = store.read_json(plan_relative)[0]
                prepared = store.read_json(prepared_relative)[0]
                manifest = store.read_json(manifest_relative)[0]
                _validate_manifest(manifest, plan, prepared)
                weekly_intent = _require_committed_transaction(
                    store, "weekly-plan", item["selection_id"]
                )
                if weekly_intent["result"].get("plan_digest") != item["plan_digest"]:
                    _fail("unregistered-plan", "weekly transaction does not bind closure plan")
                finalize_intent = _require_committed_transaction(
                    store,
                    "finalize-publication",
                    f"{item['selection_id']}:{item['plan_digest']}",
                )
                external_paths = [
                    write["path"]
                    for write in finalize_intent["writes"]
                    if write["scope"] == "external"
                ]
                if len(external_paths) != 1:
                    _fail(
                        "missing-authority-transaction",
                        "finalize transaction does not bind one external manifest",
                    )
                expected_finalize_request = _digest(
                    {
                        "plan": plan,
                        "prepared": prepared,
                        "output": external_paths[0],
                    }
                )
                if (
                    finalize_intent["request_digest"] != expected_finalize_request
                    or finalize_intent["result"].get("manifest_digest")
                    != manifest["manifest_digest"]
                ):
                    _fail(
                        "missing-authority-transaction",
                        "finalize transaction does not bind exact plan, prepared, and manifest",
                    )
                if manifest["manifest_digest"] != item["manifest_digest"]:
                    _fail("publication-receipt-mismatch", "closure manifest digest mismatch")
                manifest_entry = next(
                    (entry for entry in manifest["entries"] if entry["case_id"] == item["case_id"]),
                    None,
                )
                if manifest_entry is None or any(
                    manifest_entry[field] != item[field]
                    for field in ("revision", "semantic_digest")
                ):
                    _fail("publication-receipt-mismatch", "closure does not bind manifest case")
                merged_at = _parse_time(item["merged_at"], "merged_at")
                if not (
                    _parse_time(manifest["created_at"], "manifest.created_at")
                    <= _parse_time(approved_at, "approved_at")
                    <= merged_at
                    <= _parse_time(closed_at, "closed_at")
                    <= _parse_time(now_value, "now")
                ):
                    _fail("clock-order", "manifest, approval, merge, and closure clocks unordered")
            updated = dict(active)
            updated.update(
                {
                    "status": "closed",
                    "closure_id": closure_id,
                    "closure_digest": closure_digest,
                    "closure_reason": reason,
                    "closed_at": closed_at,
                }
            )
            updated_body = {key: value for key, value in updated.items() if key != "record_digest"}
            updated["record_digest"] = _digest(updated_body)
            updates.append(_planned_write(store, relative, updated, immutable=False))
        writes = [_planned_write(store, history, closure_record, immutable=True), *updates]
        result = {
            "version": VERSION,
            "status": "closed",
            "closure_id": closure_id,
            "closure_digest": closure_digest,
            "closed_count": len(normalized),
        }
        return _run_transaction(
            store,
            operation="close-publication",
            natural_key=closure_id,
            request=request,
            captured_at=now_value,
            writes=writes,
            result=result,
        )


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        _fail("invalid-command-line", message)


def _parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    new_id = subparsers.add_parser("new-id", help="generate a DSF UUIDv7 case ID")
    new_id.add_argument("--now", required=True)

    validate = subparsers.add_parser("validate", help="validate a candidate JSON file")
    validate.add_argument("--candidate", type=Path, required=True)

    digest = subparsers.add_parser(
        "digest", help="calculate and validate the ledger-compatible semantic digest"
    )
    digest.add_argument("--candidate", type=Path, required=True)

    stage = subparsers.add_parser("stage", help="stage a validated candidate")
    stage.add_argument("--candidate", type=Path, required=True)
    stage.add_argument("--state-root", type=Path, required=True)
    stage.add_argument("--now", required=True)

    dormant = subparsers.add_parser("transition-dormant", help="apply eligible dormancy")
    dormant.add_argument("--state-root", type=Path, required=True)
    dormant.add_argument("--now", required=True)

    complete = subparsers.add_parser("complete-audit", help="write a completed Daily snapshot")
    complete.add_argument("--state-root", type=Path, required=True)
    complete.add_argument("--receipt", type=Path, required=True)
    complete.add_argument("--now", required=True)
    complete.add_argument("--historical-replay", action="store_true")

    selection_preflight = subparsers.add_parser(
        "selection-preflight",
        help="validate and persist an exact preapproval Weekly selection receipt",
    )
    selection_preflight.add_argument("--state-root", type=Path, required=True)
    selection_preflight.add_argument("--selection-draft", type=Path, required=True)
    selection_preflight.add_argument("--now", required=True)

    plan = subparsers.add_parser("weekly-plan", help="freeze a trusted weekly selection")
    plan.add_argument("--state-root", type=Path, required=True)
    plan.add_argument("--selection", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("--now", required=True)

    finalize = subparsers.add_parser(
        "finalize-publication", help="finalize exact prepared commit receipts"
    )
    finalize.add_argument("--state-root", type=Path, required=True)
    finalize.add_argument("--plan", type=Path, required=True)
    finalize.add_argument("--prepared", type=Path, required=True)
    finalize.add_argument("--output", type=Path, required=True)
    finalize.add_argument("--now", required=True)

    close = subparsers.add_parser(
        "close-publication", help="close exact active publication entries by receipt"
    )
    close.add_argument("--state-root", type=Path, required=True)
    close.add_argument("--receipt", type=Path, required=True)
    close.add_argument("--publish-receipt", type=Path)
    close.add_argument("--now", required=True)
    return parser


def _run(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "new-id":
        now = _timestamp(args.now, "now")
        return {"version": VERSION, "case_id": new_case_id(now), "generated_at": now}
    if args.command == "validate":
        summary = validate_candidate(_load_json(args.candidate))
        return {"version": VERSION, "status": "valid", **summary}
    if args.command == "digest":
        candidate = _load_json(args.candidate)
        case = _require_object(candidate.get("case"), "case")
        _require_object(candidate.get("control"), "control")
        expected = semantic_digest(case)
        normalized = json.loads(json.dumps(candidate, ensure_ascii=False))
        normalized["control"]["semantic_digest"] = expected
        validate_candidate(normalized)
        return {"version": VERSION, "status": "valid", "semantic_digest": expected}
    if args.command == "stage":
        return stage_candidate(args.candidate, Path(os.path.abspath(args.state_root)), args.now)
    if args.command == "transition-dormant":
        return transition_dormant(Path(os.path.abspath(args.state_root)), args.now)
    if args.command == "complete-audit":
        return complete_audit(
            Path(os.path.abspath(args.state_root)),
            args.receipt,
            args.now,
            historical_replay=args.historical_replay,
        )
    if args.command == "selection-preflight":
        return preflight_selection(
            Path(os.path.abspath(args.state_root)), args.selection_draft, args.now
        )
    if args.command == "weekly-plan":
        return weekly_plan(
            Path(os.path.abspath(args.state_root)), args.selection, args.output, args.now
        )
    if args.command == "finalize-publication":
        return finalize_publication(
            Path(os.path.abspath(args.state_root)),
            args.plan,
            args.prepared,
            args.output,
            args.now,
        )
    if args.command == "close-publication":
        return close_publication(
            Path(os.path.abspath(args.state_root)),
            args.receipt,
            args.now,
            args.publish_receipt,
        )
    _fail("unsupported-command", f"unsupported command: {args.command}")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        result = _run(args)
        sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
        return 0
    except (
        StateError,
        OSError,
        TypeError,
        ValueError,
        KeyError,
        UnicodeError,
        OverflowError,
    ) as exc:
        if isinstance(exc, StateError):
            code = exc.code
        else:
            code = "invalid-input-or-state"
        sys.stdout.write(
            json.dumps(
                {"version": VERSION, "status": "error", "code": code, "message": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
