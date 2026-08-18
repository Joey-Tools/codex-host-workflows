#!/usr/bin/env python3
"""Fail-closed local state transitions for Daily Skill Friction.

The helper is intentionally limited to JSON and local filesystem operations.  It
does not import a Git or network client and it never invokes a subprocess.
"""

from __future__ import annotations

import argparse
import contextvars
import ctypes
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
ACL_POLICY_VERSION = 1
DARWIN_ACL_TYPE_EXTENDED = 0x00000100
DARWIN_ACL_FIRST_ENTRY = 0
DARWIN_ACL_NEXT_ENTRY = -1
DARWIN_ACL_EXTENDED_ALLOW = 1
DARWIN_ACL_EXTENDED_DENY = 2
DARWIN_ACL_FLAG_BITS = 32
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_CASE_JSON_BYTES = 256 * 1024
MAX_PUBLICATION_JSON_BYTES = 32 * 1024 * 1024
MAX_WAL_JSON_BYTES = 64 * 1024 * 1024
MAX_ACTIVE_WAL_TRANSACTIONS = 32
MAX_ACTIVE_WAL_BYTES = 128 * 1024 * 1024
MAX_WAL_HISTORY_RECORD_BYTES = 8 * 1024 * 1024
MAX_WAL_HISTORY_RECORDS = 100_000
MAX_WAL_HISTORY_BYTES = 256 * 1024 * 1024
MAX_PREPARED_COMMANDS = 8
MAX_PREPARED_COMMAND_CHARS = 512
MAX_PREPARED_SIGNER_CHARS = 256
MAX_RETAINED_STATE_DIRECTORIES = 128
DARWIN_RENAME_EXCL = 0x00000004
LINUX_RENAME_NOREPLACE = 0x00000001
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
REPAIR_APPROVAL_MAX_AGE = dt.timedelta(days=7)
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
    "approve-repair",
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
WAL_HISTORY_LEAF_RE = re.compile(r"^[0-9a-f]{64}\.json$")
WAL_HISTORY_ANY_TEMP_RE = re.compile(
    r"^\.(?:usage\.json|[0-9a-f]{64}\.json)"
    r"\.tmp-[1-9][0-9]{0,19}-[0-9a-f]{16}$"
)
WAL_HISTORY_FIXED_TEMP_PID = "1"
WAL_HISTORY_FIXED_TEMP_NONCE = "0" * 16
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
APPROVAL_BOUND_CASE_STATUSES = {"approved", "implemented", "observing", "closed"}
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
REPAIR_IDENTITY_FIELDS = (
    "id",
    "repository",
    "action",
    "problem_statement",
    "change_summary",
    "commit_trailer",
    "replaces_repair_id",
)
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


_DARWIN_ACL_LIBC: ctypes.CDLL | None = None


def _darwin_acl_libc() -> ctypes.CDLL:
    """Return the process libc with the FD-native extended ACL API bound."""

    global _DARWIN_ACL_LIBC
    if _DARWIN_ACL_LIBC is None:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
        libc.acl_get_fd_np.restype = ctypes.c_void_p
        libc.acl_get_entry.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        libc.acl_get_entry.restype = ctypes.c_int
        libc.acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        libc.acl_get_tag_type.restype = ctypes.c_int
        libc.acl_get_qualifier.argtypes = [ctypes.c_void_p]
        libc.acl_get_qualifier.restype = ctypes.c_void_p
        libc.acl_get_permset_mask_np.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint64),
        ]
        libc.acl_get_permset_mask_np.restype = ctypes.c_int
        libc.acl_get_flagset_np.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        libc.acl_get_flagset_np.restype = ctypes.c_int
        libc.acl_get_flag_np.argtypes = [ctypes.c_void_p, ctypes.c_int]
        libc.acl_get_flag_np.restype = ctypes.c_int
        libc.acl_free.argtypes = [ctypes.c_void_p]
        libc.acl_free.restype = ctypes.c_int
        _DARWIN_ACL_LIBC = libc
    return _DARWIN_ACL_LIBC


def _darwin_acl_entries(libc: ctypes.CDLL, acl: int, source: str) -> list[dict[str, Any]]:
    """Enumerate stable ACL authority fields, preserving kernel entry order."""

    entries: list[dict[str, Any]] = []
    selector = DARWIN_ACL_FIRST_ENTRY
    while True:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        status = libc.acl_get_entry(acl, selector, ctypes.byref(entry))
        if status == -1 and not entry.value and ctypes.get_errno() == errno.EINVAL:
            break
        if status != 0 or not entry.value:
            _fail(
                "acl-revalidation-failed",
                f"could not enumerate extended ACL for {source}: errno {ctypes.get_errno()}",
            )
        selector = DARWIN_ACL_NEXT_ENTRY
        tag_value = ctypes.c_int()
        if libc.acl_get_tag_type(entry, ctypes.byref(tag_value)) != 0:
            _fail("acl-revalidation-failed", f"could not read ACL tag for {source}")
        tag = {
            DARWIN_ACL_EXTENDED_ALLOW: "allow",
            DARWIN_ACL_EXTENDED_DENY: "deny",
        }.get(tag_value.value)
        if tag is None:
            _fail("acl-revalidation-failed", f"ACL tag is unsupported for {source}")
        qualifier_pointer = libc.acl_get_qualifier(entry)
        if not qualifier_pointer:
            _fail("acl-revalidation-failed", f"could not read ACL qualifier for {source}")
        try:
            qualifier = ctypes.string_at(qualifier_pointer, 16).hex()
        finally:
            libc.acl_free(qualifier_pointer)
        permissions = ctypes.c_uint64()
        if libc.acl_get_permset_mask_np(entry, ctypes.byref(permissions)) != 0:
            _fail("acl-revalidation-failed", f"could not read ACL permissions for {source}")
        flagset = ctypes.c_void_p()
        if libc.acl_get_flagset_np(entry, ctypes.byref(flagset)) != 0 or not flagset.value:
            _fail("acl-revalidation-failed", f"could not read ACL flags for {source}")
        flags = 0
        for bit in range(DARWIN_ACL_FLAG_BITS):
            ctypes.set_errno(0)
            present = libc.acl_get_flag_np(flagset, 1 << bit)
            if present == 1:
                flags |= 1 << bit
            elif present == 0:
                continue
            elif ctypes.get_errno() != errno.EINVAL:
                _fail("acl-revalidation-failed", f"could not inspect ACL flags for {source}")
        entries.append(
            {
                "index": len(entries),
                "tag": tag,
                "qualifier": qualifier,
                "permissions": permissions.value,
                "flags": flags,
            }
        )
    return entries


def _acl_snapshot(fd: int, source: str) -> dict[str, Any]:
    """Read an access-policy snapshot through the retained object descriptor."""

    if sys.platform != "darwin":
        body: dict[str, Any] = {
            "version": ACL_POLICY_VERSION,
            "model": "posix-mode-only-v1",
            "entries": [],
        }
        return {**body, "digest": _digest(body)}

    libc = _darwin_acl_libc()
    ctypes.set_errno(0)
    acl = libc.acl_get_fd_np(fd, DARWIN_ACL_TYPE_EXTENDED)
    if not acl:
        error = ctypes.get_errno()
        if error == errno.ENOENT:
            entries: list[dict[str, Any]] = []
        else:
            _fail(
                "acl-revalidation-failed",
                f"could not read extended ACL for {source}: errno {error}",
            )
    else:
        try:
            entries = _darwin_acl_entries(libc, acl, source)
        finally:
            libc.acl_free(acl)
    body = {
        "version": ACL_POLICY_VERSION,
        "model": "darwin-extended-v1",
        "entries": entries,
    }
    return {**body, "digest": _digest(body)}


def _enforce_acl_policy(snapshot: Mapping[str, Any], source: str, *, sensitive: bool) -> None:
    entries = _require_list(snapshot.get("entries"), "acl.entries")
    if sensitive and entries:
        _fail("state-acl-present", f"sensitive state object has an extended ACL: {source}")
    if not sensitive and any(
        _require_object(entry, "acl.entry").get("tag") == "allow" for entry in entries
    ):
        _fail(
            "custody-acl-allows-access",
            f"state custody ancestor has an allow ACL entry: {source}",
        )


def _acl_digest(fd: int, source: str, *, sensitive: bool) -> str:
    snapshot = _acl_snapshot(fd, source)
    _enforce_acl_policy(snapshot, source, sensitive=sensitive)
    return _require_string(snapshot.get("digest"), "acl.digest")


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
    expected_links: int = 1,
) -> tuple[bytes, str]:
    """Read bounded bytes twice from one object and bind identity and policy.

    Identity is the open object's device/inode plus the parent entry that names it.
    Content stability is an equal second read, not mtime/ctime equality.  Access
    policy is regular, current-user-owned, private state with the caller-selected
    namespace link count and no Darwin extended ACL when ``private`` is true.
    Two links are accepted only while a caller separately validates the
    final/helper publication pair.  Timestamps are not mutation evidence and
    are deliberately excluded.
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
        if before.st_nlink != expected_links:
            expected_text = "one" if expected_links == 1 else str(expected_links)
            _fail(
                "unsafe-link-count",
                f"state file must have exactly {expected_text} link(s): {source}",
            )
        before_acl_digest = _acl_digest(fd, source, sensitive=True)
    else:
        before_acl_digest = None

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
    if private:
        after_acl_digest = _acl_digest(fd, source, sensitive=True)
        if after_acl_digest != before_acl_digest:
            _fail("access-policy-changed", f"state file ACL changed while reading: {source}")
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
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
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


def _raw_sha256(value: Any, field: str) -> str:
    result = _require_string(value, field)
    if HEX64_RE.fullmatch(result) is None:
        _fail("invalid-digest", f"{field} must be raw SHA-256")
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
    first = min(observed)
    last = max(observed)
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
    if (
        _parse_time(
            _timestamp(causal["first_observed_at"], "case.causal.first_observed_at"),
            "case.causal.first_observed_at",
        )
        != stats["first"]
    ):
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
    evidence_last_seen = _parse_time(
        _timestamp(case["evidence_last_seen"], "case.evidence_last_seen"),
        "case.evidence_last_seen",
    )
    if evidence_last_seen != stats["last"]:
        _fail("clock-mismatch", "evidence_last_seen must match latest evidence")
    currentness_checked_at = _timestamp(
        case["currentness_checked_at"], "case.currentness_checked_at"
    )
    if _parse_time(currentness_checked_at, "case.currentness_checked_at") < stats["last"]:
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
    if _parse_time(created, "created_at") < stats["first"]:
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
        if _parse_time(dormant_since, "case.lifecycle.dormant_since") != _parse_time(
            changed, "case.lifecycle_changed_at"
        ):
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


def _validate_helper_temp_stat(
    info: os.stat_result,
    path: Path,
    *,
    expected_links: int,
    max_bytes: int = MAX_WAL_JSON_BYTES,
) -> None:
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        _fail("unsafe-helper-temp", f"helper temporary is not a regular file: {path}")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        _fail("unsafe-helper-temp", f"helper temporary has unsafe owner or mode: {path}")
    if info.st_nlink != expected_links:
        _fail("unsafe-helper-temp", f"helper temporary has an invalid link count: {path}")
    if info.st_size > max_bytes:
        _fail("unsafe-helper-temp", f"helper temporary exceeds its byte bound: {path}")


def _wal_history_fixed_temp_name(leaf: str) -> str:
    """Return the one closed temporary name for an exact history leaf."""

    if leaf != "usage.json" and WAL_HISTORY_LEAF_RE.fullmatch(leaf) is None:
        _fail("invalid-wal-history-layout", f"invalid WAL history leaf: {leaf}")
    return f".{leaf}.tmp-{WAL_HISTORY_FIXED_TEMP_PID}-{WAL_HISTORY_FIXED_TEMP_NONCE}"


def _fail_foreign_wal_history_temp(name: str) -> NoReturn:
    if ".tmp-" in name and WAL_HISTORY_ANY_TEMP_RE.fullmatch(name) is None:
        _fail("malformed-helper-temp", f"malformed WAL history temporary entry: {name}")
    _fail("foreign-helper-temp", f"foreign WAL history temporary entry: {name}")


def _safe_relative_parts(relative: Path | str) -> tuple[str, ...]:
    value = Path(relative)
    if value.is_absolute() or not value.parts:
        _fail("unsafe-relative-path", f"state path must be non-empty and relative: {value}")
    parts = tuple(value.parts)
    if any(part in {"", ".", ".."} or "/" in part or "\x00" in part for part in parts):
        _fail("unsafe-relative-path", f"unsafe state path component: {value}")
    return parts


def _rename_state_directory_noreplace(
    parent_fd: int,
    source_name: str,
    target_name: str,
    path: Path,
) -> None:
    """Atomically publish a bound directory without replacing any target."""

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        try:
            rename = libc.renameatx_np
        except AttributeError:
            _fail(
                "state-directory-publication-unavailable",
                "Darwin renameatx_np is unavailable for no-replace directory publication",
            )
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        flags = DARWIN_RENAME_EXCL
    elif sys.platform.startswith("linux"):
        try:
            rename = libc.renameat2
        except AttributeError:
            _fail(
                "state-directory-publication-unavailable",
                "Linux renameat2 is unavailable for no-replace directory publication",
            )
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        flags = LINUX_RENAME_NOREPLACE
    else:
        _fail(
            "state-directory-publication-unavailable",
            f"no atomic no-replace directory publication primitive for {sys.platform}",
        )
    ctypes.set_errno(0)
    status = rename(
        parent_fd,
        os.fsencode(source_name),
        parent_fd,
        os.fsencode(target_name),
        flags,
    )
    if status == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, os.strerror(error), target_name)
    if error == errno.ENOENT:
        _fail(
            "state-directory-missing",
            f"temporary state directory disappeared before publication: {path}",
        )
    if error in {errno.EACCES, errno.EPERM}:
        _fail(
            "state-directory-unreadable",
            f"cannot publish state directory {path}: {os.strerror(error)}",
        )
    if error in {errno.ELOOP, errno.ENOTDIR}:
        _fail(
            "state-directory-replaced",
            f"state directory parent was replaced during publication: {path}",
        )
    _fail(
        "state-directory-revalidation-failed",
        f"could not publish state directory {path}: {os.strerror(error)}",
    )


def _json_limit_for_parts(parts: Sequence[str]) -> int:
    if parts and parts[0] == "wal":
        return MAX_WAL_JSON_BYTES
    if parts and parts[0] == "wal-history":
        return MAX_WAL_HISTORY_RECORD_BYTES
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


class _StateDirectoryBinding:
    """Retained proof for one root-relative state directory component."""

    def __init__(
        self,
        parts: tuple[str, ...],
        fd: int,
        parent_fd: int,
        signal: tuple[int, int, int, int, int, int, str],
    ) -> None:
        self.parts = parts
        self.fd = fd
        self.parent_fd = parent_fd
        self.name = parts[-1]
        self.signal = signal


class StateStore:
    """Descriptor-rooted owner-private state storage.

    The retained directory descriptors protect the complete path from the
    filesystem root through the selected state root and every root-relative
    directory used by the transaction.  Every path component is bound to its
    object identity, type, access policy, and parent-visible name.
    Timestamps and directory link counts are deliberately excluded because
    ordinary child-entry churn can change them without replacing the protected
    object or its access policy.  Every child lookup is relative to a validated
    directory fd with ``O_NOFOLLOW``.  Reads bind content by a repeated bounded
    read, while writes fsync both the file and every newly changed parent
    directory entry.
    """

    def __init__(
        self,
        root: Path,
        *,
        create: bool = True,
        sensitive_root: bool = True,
    ) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        if self.root == Path(self.root.anchor):
            _fail("unsafe-state-root", "state root cannot be a filesystem root")
        self._ancestor_fds: list[int] = []
        self._chain_names: list[str | None] = []
        self._chain_signals: list[tuple[int, int, int, int, int, int, str]] = []
        self.root_fd = -1
        self.lock_fd = -1
        self.lock_identity: tuple[int, int, int] | None = None
        self._sensitive_root = sensitive_root
        self._created_root = False
        self._directory_bindings: dict[tuple[str, ...], _StateDirectoryBinding] = {}
        self._immutable_publication_capture: _ImmutablePublicationCapture | None = None
        self._fixed_publication_temporary: tuple[Path, str] | None = None
        try:
            self._open_root(create=create)
        except Exception:
            self.close()
            raise

    @staticmethod
    def _open_chain_component(
        name: str,
        flags: int,
        path: Path | str,
        *,
        dir_fd: int | None = None,
    ) -> int:
        """Open one custody directory and classify pathname failures."""

        try:
            return os.open(name, flags, dir_fd=dir_fd)
        except FileNotFoundError:
            raise
        except PermissionError as exc:
            _fail(
                "state-chain-unreadable",
                f"state custody component is unreadable: {path}: {exc}",
            )
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                _fail(
                    "state-chain-replaced",
                    f"state custody component is no longer a directory: {path}",
                )
            _fail(
                "state-chain-revalidation-failed",
                f"could not open state custody component {path}: {exc}",
            )

    def _open_root(self, *, create: bool) -> None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            current = self._open_chain_component(
                self.root.anchor,
                flags,
                self.root.anchor,
            )
        except FileNotFoundError:
            _fail("missing-state-root", f"state custody root is missing: {self.root.anchor}")
        self._ancestor_fds.append(current)
        self._chain_names.append(None)
        self._chain_signals.append(
            self._directory_signal(
                current,
                os.fstat(current),
                self.root.anchor,
                sensitive=False,
                custody_error_code="unsafe-state-chain-policy",
            )
        )
        parts = self.root.parts[1:]
        for index, component in enumerate(parts):
            final = index == len(parts) - 1
            component_path = Path(self.root.anchor, *parts[: index + 1])
            try:
                child = self._open_chain_component(
                    component,
                    flags,
                    component_path,
                    dir_fd=current,
                )
            except FileNotFoundError:
                if not create:
                    _fail("missing-state-root", f"state root is not initialized: {self.root}")
                created_component = False
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                    os.fsync(current)
                    created_component = True
                except FileExistsError:
                    pass
                except PermissionError as exc:
                    _fail(
                        "state-chain-unreadable",
                        f"cannot create state custody component {component_path}: {exc}",
                    )
                except OSError as exc:
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                        _fail(
                            "state-chain-replaced",
                            f"state custody component was rebound during creation: "
                            f"{component_path}",
                        )
                    _fail(
                        "state-chain-revalidation-failed",
                        f"could not create state custody component {component_path}: {exc}",
                    )
                try:
                    child = self._open_chain_component(
                        component,
                        flags,
                        component_path,
                        dir_fd=current,
                    )
                except FileNotFoundError:
                    _fail(
                        "state-chain-replaced",
                        f"state custody component disappeared during creation: {component_path}",
                    )
                if final and created_component:
                    self._created_root = True
            try:
                child_signal = self._directory_signal(
                    child,
                    os.fstat(child),
                    component_path,
                    sensitive=final and self._sensitive_root,
                    custody_error_code="unsafe-state-chain-policy",
                )
            except Exception:
                os.close(child)
                raise
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
        for parts in sorted(self._directory_bindings, key=len, reverse=True):
            os.close(self._directory_bindings[parts].fd)
        self._directory_bindings.clear()
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
        fd: int,
        info: os.stat_result,
        path: Path | str,
        *,
        sensitive: bool,
        custody_error_code: str,
    ) -> tuple[int, int, int, int, int, int, str]:
        """Return only object-identity, type, and access-policy signals."""

        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            _fail("unsafe-state-chain", f"state path component is not a directory: {path}")
        permissions = stat.S_IMODE(info.st_mode)
        if info.st_uid not in {0, os.geteuid()}:
            _fail(
                custody_error_code,
                f"state custody ancestor has an untrusted owner: {path}",
            )
        writable_by_others = bool(permissions & (stat.S_IWGRP | stat.S_IWOTH))
        root_owned_sticky = info.st_uid == 0 and bool(permissions & stat.S_ISVTX)
        if writable_by_others and not root_owned_sticky:
            _fail(
                custody_error_code,
                "state custody ancestor is group/world writable without root-owned "
                f"sticky protection: {path}",
            )
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
            _acl_digest(fd, str(path), sensitive=sensitive),
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
            opened_signal = self._directory_signal(
                fd,
                opened,
                component_path,
                sensitive=(index == len(chain_fds) - 1 and self._sensitive_root),
                custody_error_code="state-chain-policy-changed",
            )
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
            permissions = stat.S_IMODE(named.st_mode)
            group_bits = (permissions & stat.S_IRWXG) >> 3
            other_bits = permissions & stat.S_IRWXO
            named_signal = (
                named.st_dev,
                named.st_ino,
                stat.S_IFMT(named.st_mode),
                named.st_uid,
                named.st_gid if group_bits != other_bits else -1,
                permissions,
                opened_signal[6],
            )
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
        _acl_digest(self.root_fd, str(self.root), sensitive=self._sensitive_root)

    def acquire_lock(self, *, create: bool = True) -> None:
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        create_lock = create and self._created_root
        if create_lock:
            flags |= os.O_CREAT | os.O_EXCL
        self._bind_state_chain("lock preflight")
        try:
            self.lock_fd = os.open(LOCK_FILE, flags, 0o600, dir_fd=self.root_fd)
        except FileNotFoundError:
            code = "initialization-in-progress" if create else "uninitialized-state"
            _fail(code, "existing state root has no trusted lock object")
        except FileExistsError:
            _fail(
                "initialization-race",
                "new state root unexpectedly acquired another lock initializer",
            )
        except OSError as exc:
            _fail("unsafe-lock", f"cannot open state lock: {exc}")
        if create_lock:
            os.fsync(self.lock_fd)
            os.fsync(self.root_fd)
        before = os.fstat(self.lock_fd)
        _validate_private_stat(before, self.root / LOCK_FILE, directory=False)
        _acl_digest(self.lock_fd, str(self.root / LOCK_FILE), sensitive=True)
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
        _acl_digest(self.lock_fd, str(self.root / LOCK_FILE), sensitive=True)
        expected = self.lock_identity
        if (opened.st_dev, opened.st_ino, opened.st_nlink) != expected or (
            named.st_dev,
            named.st_ino,
            named.st_nlink,
        ) != expected:
            _fail("lock-replaced", f"state lock identity changed {phase}")

    def finish(self) -> None:
        self._bind_state_namespace("transaction completion")
        self._bind_lock("at transaction completion")

    def relative(self, path: Path) -> Path:
        absolute = Path(os.path.abspath(os.fspath(path)))
        try:
            return absolute.relative_to(self.root)
        except ValueError:
            _fail("outside-state-root", f"path is outside state root: {path}")

    @staticmethod
    def _state_directory_stat_signal(
        info: os.stat_result,
        path: Path,
    ) -> tuple[int, int, int, int, int, int]:
        """Return nested-directory identity and POSIX access-policy signals."""

        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            _fail("state-directory-replaced", f"state directory is not a directory: {path}")
        permissions = stat.S_IMODE(info.st_mode)
        if info.st_uid != os.geteuid() or permissions & 0o077:
            _fail(
                "state-directory-policy-changed",
                f"state directory owner or mode is unsafe: {path}",
            )
        group_bits = (permissions & stat.S_IRWXG) >> 3
        other_bits = permissions & stat.S_IRWXO
        return (
            info.st_dev,
            info.st_ino,
            stat.S_IFMT(info.st_mode),
            info.st_uid,
            info.st_gid if group_bits != other_bits else -1,
            permissions,
        )

    def _state_directory_signal(
        self,
        fd: int,
        parts: tuple[str, ...],
    ) -> tuple[int, int, int, int, int, int, str]:
        path = self.root / Path(*parts)
        try:
            info = os.fstat(fd)
        except OSError as exc:
            _fail(
                "state-directory-revalidation-failed",
                f"could not inspect retained state directory {path}: {exc}",
            )
        signal = self._state_directory_stat_signal(info, path)
        try:
            acl_digest = _acl_digest(fd, str(path), sensitive=True)
        except StateError as exc:
            if exc.code in {"state-acl-present", "custody-acl-allows-access"}:
                _fail(
                    "state-directory-policy-changed",
                    f"state directory ACL is unsafe: {path}",
                )
            if exc.code == "acl-revalidation-failed":
                _fail(
                    "state-directory-revalidation-failed",
                    f"could not revalidate state directory ACL: {path}",
                )
            raise
        return (*signal, acl_digest)

    @staticmethod
    def _open_state_directory_component(
        parent_fd: int,
        name: str,
        path: Path,
    ) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            return os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            raise
        except PermissionError as exc:
            _fail(
                "state-directory-unreadable",
                f"state directory is unreadable: {path}: {exc}",
            )
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                _fail(
                    "state-directory-replaced",
                    f"state directory is no longer a directory: {path}",
                )
            _fail(
                "state-directory-revalidation-failed",
                f"could not open state directory {path}: {exc}",
            )

    def _validate_state_directory_binding(
        self,
        binding: _StateDirectoryBinding,
        phase: str,
    ) -> None:
        path = self.root / Path(*binding.parts)
        opened = self._state_directory_signal(binding.fd, binding.parts)
        if opened[:3] != binding.signal[:3]:
            _fail(
                "state-directory-replaced",
                f"retained state directory identity changed during {phase}: {path}",
            )
        if opened[3:] != binding.signal[3:]:
            _fail(
                "state-directory-policy-changed",
                f"retained state directory policy changed during {phase}: {path}",
            )
        try:
            named = os.stat(binding.name, dir_fd=binding.parent_fd, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            _fail(
                "state-directory-missing",
                f"state directory name disappeared during {phase}: {path}",
            )
        except PermissionError as exc:
            _fail(
                "state-directory-unreadable",
                f"state directory name became unreadable during {phase}: {path}: {exc}",
            )
        except OSError as exc:
            _fail(
                "state-directory-revalidation-failed",
                f"could not inspect state directory name during {phase}: {path}: {exc}",
            )
        named_signal = (*self._state_directory_stat_signal(named, path), opened[6])
        if named_signal[:3] != binding.signal[:3]:
            _fail(
                "state-directory-replaced",
                f"state directory name was rebound during {phase}: {path}",
            )
        if named_signal[3:] != binding.signal[3:]:
            _fail(
                "state-directory-policy-changed",
                f"state directory name policy changed during {phase}: {path}",
            )

    def _bind_state_namespace(self, phase: str) -> None:
        """Revalidate the absolute root and every retained root-relative directory."""

        self._bind_state_chain(phase)
        for parts in sorted(self._directory_bindings, key=lambda item: (len(item), item)):
            binding = self._directory_bindings[parts]
            parent_fd = self.root_fd if len(parts) == 1 else self._directory_bindings[parts[:-1]].fd
            if binding.parent_fd != parent_fd:
                _fail(
                    "invalid-state-directory-binding",
                    f"state directory parent binding is inconsistent: {Path(*parts)}",
                )
            self._validate_state_directory_binding(binding, phase)

    def _retain_state_directory(
        self,
        parts: tuple[str, ...],
        parent_fd: int,
        fd: int,
    ) -> _StateDirectoryBinding:
        if len(self._directory_bindings) >= MAX_RETAINED_STATE_DIRECTORIES:
            os.close(fd)
            _fail(
                "state-directory-binding-limit",
                "retained state directory binding limit exceeded",
            )
        try:
            signal = self._state_directory_signal(fd, parts)
            binding = _StateDirectoryBinding(parts, fd, parent_fd, signal)
            self._validate_state_directory_binding(binding, "initial binding")
        except Exception:
            os.close(fd)
            raise
        self._directory_bindings[parts] = binding
        return binding

    def _create_state_directory(
        self,
        parts: tuple[str, ...],
        parent_fd: int,
    ) -> _StateDirectoryBinding:
        path = self.root / Path(*parts)
        name = parts[-1]
        temporary = f".{name}.dir-{os.getpid()}-{secrets.token_hex(8)}"
        if len(self._directory_bindings) >= MAX_RETAINED_STATE_DIRECTORIES:
            _fail(
                "state-directory-binding-limit",
                "retained state directory binding limit exceeded",
            )
        self._bind_state_namespace("before state directory creation")
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except PermissionError as exc:
            _fail(
                "state-directory-unreadable",
                f"state directory creation target is unreadable: {path}: {exc}",
            )
        except OSError as exc:
            _fail(
                "state-directory-revalidation-failed",
                f"could not inspect state directory creation target {path}: {exc}",
            )
        else:
            _fail(
                "state-directory-replaced",
                f"state directory appeared during creation: {path}",
            )
        fd = -1
        temporary_binding: _StateDirectoryBinding | None = None
        published = False
        try:
            os.mkdir(temporary, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            _fail(
                "state-directory-replaced",
                f"state directory temporary unexpectedly exists: {path}",
            )
        except PermissionError as exc:
            _fail(
                "state-directory-unreadable",
                f"cannot create state directory {path}: {exc}",
            )
        except OSError as exc:
            _fail(
                "state-directory-revalidation-failed",
                f"could not create state directory {path}: {exc}",
            )
        try:
            try:
                fd = self._open_state_directory_component(parent_fd, temporary, path)
            except FileNotFoundError:
                _fail(
                    "state-directory-missing",
                    f"new state directory disappeared before binding: {path}",
                )
            signal = self._state_directory_signal(fd, parts)
            temporary_binding = _StateDirectoryBinding(parts, fd, parent_fd, signal)
            temporary_binding.name = temporary
            self._validate_state_directory_binding(
                temporary_binding,
                "initial temporary directory binding",
            )
            self._bind_state_namespace("before state directory publication")
            self._validate_state_directory_binding(
                temporary_binding,
                "before state directory publication",
            )
            try:
                _rename_state_directory_noreplace(parent_fd, temporary, name, path)
            except FileExistsError:
                _fail(
                    "state-directory-replaced",
                    f"state directory creation lost a no-replace race: {path}",
                )
            published = True
            os.fsync(parent_fd)
            binding = _StateDirectoryBinding(parts, fd, parent_fd, signal)
            self._validate_state_directory_binding(binding, "after directory publication")
            self._directory_bindings[parts] = binding
            fd = -1
            self._bind_state_namespace("after state directory creation")
            return binding
        except Exception:
            if not published and temporary_binding is not None:
                try:
                    try:
                        os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        self._validate_state_directory_binding(
                            temporary_binding,
                            "failed directory publication cleanup",
                        )
                        os.rmdir(temporary, dir_fd=parent_fd)
                        os.fsync(parent_fd)
                except Exception as cleanup_exc:
                    raise StateError(
                        "state-directory-cleanup-failed",
                        f"failed to remove the exact temporary state directory: {path}",
                    ) from cleanup_exc
            raise
        finally:
            if fd >= 0:
                os.close(fd)

    @contextmanager
    def open_dir(self, relative: Path | str, *, create: bool = False) -> Iterator[int]:
        parts = _safe_relative_parts(relative)
        self._bind_state_namespace("before root-relative directory open")
        parent_fd = self.root_fd
        binding: _StateDirectoryBinding | None = None
        prefix: list[str] = []
        for component in parts:
            prefix.append(component)
            key = tuple(prefix)
            binding = self._directory_bindings.get(key)
            if binding is None:
                path = self.root / Path(*key)
                try:
                    fd = self._open_state_directory_component(parent_fd, component, path)
                except FileNotFoundError:
                    if not create:
                        raise
                    binding = self._create_state_directory(key, parent_fd)
                else:
                    binding = self._retain_state_directory(key, parent_fd, fd)
                    self._bind_state_namespace("after state directory binding")
            elif binding.parent_fd != parent_fd:
                _fail(
                    "invalid-state-directory-binding",
                    f"state directory parent binding is inconsistent: {Path(*key)}",
                )
            self._validate_state_directory_binding(binding, "before directory traversal")
            parent_fd = binding.fd
        assert binding is not None
        self._bind_state_namespace("before root-relative directory use")
        current = os.dup(binding.fd)
        try:
            yield current
        finally:
            os.close(current)
            self._bind_state_namespace("after root-relative directory use")

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
        raw, digest, _ = self.read_bytes_with_identity(relative, max_bytes=max_bytes)
        return raw, digest

    def read_bytes_with_identity(
        self, relative: Path | str, *, max_bytes: int | None = None
    ) -> tuple[bytes, str, tuple[int, int]]:
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
                opened = os.fstat(fd)
                raw, digest = _read_fd_stable(
                    fd,
                    str(self.root / Path(*parts)),
                    private=True,
                    max_bytes=(_json_limit_for_parts(parts) if max_bytes is None else max_bytes),
                    expected_parent_fd=parent_fd,
                    expected_name=parts[-1],
                )
                return raw, digest, (opened.st_dev, opened.st_ino)
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
            self._bind_state_namespace("before exact rollback")
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
            self._bind_state_namespace("after exact rollback")
        finally:
            if context is not None:
                context.__exit__(None, None, None)

    def sync_exact(
        self,
        relative: Path | str,
        expected_digest: str,
        *,
        expected_identity: tuple[int, int] | None = None,
        max_bytes: int | None = None,
    ) -> tuple[int, int]:
        """Fsync one exact private leaf and close the post-sync mutation window.

        Object identity is the retained descriptor plus its still-bound parent
        name, content stability is the caller's exact digest, and access policy
        is the private-file policy checked by ``_read_fd_stable``.  All three
        properties are revalidated after both fsync calls; timestamps remain
        irrelevant signals.
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
                _fail("missing-file", f"required state parent is missing: {Path(*parts)}")
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            try:
                fd = os.open(parts[-1], flags, dir_fd=parent_fd)
            except FileNotFoundError:
                _fail("missing-file", f"required state file is missing: {Path(*parts)}")
            try:
                self._recover_link_publication(parent_fd, parts[-1], fd)
                opened = os.fstat(fd)
                identity = (opened.st_dev, opened.st_ino)
                if expected_identity is not None and identity != expected_identity:
                    _fail("object-replaced", f"state leaf was rebound: {Path(*parts)}")
                _, digest = _read_fd_stable(
                    fd,
                    str(self.root / Path(*parts)),
                    private=True,
                    max_bytes=(_json_limit_for_parts(parts) if max_bytes is None else max_bytes),
                    expected_parent_fd=parent_fd,
                    expected_name=parts[-1],
                )
                if digest != expected_digest:
                    _fail("object-changed", f"state leaf content changed: {Path(*parts)}")
                os.fsync(fd)
                os.fsync(parent_fd)
                _, synced_digest = _read_fd_stable(
                    fd,
                    str(self.root / Path(*parts)),
                    private=True,
                    max_bytes=(_json_limit_for_parts(parts) if max_bytes is None else max_bytes),
                    expected_parent_fd=parent_fd,
                    expected_name=parts[-1],
                )
                if synced_digest != expected_digest:
                    _fail(
                        "object-changed-after-sync",
                        f"state leaf content changed during exact sync: {Path(*parts)}",
                    )
                self._bind_state_namespace("after exact leaf sync")
                return identity
            finally:
                os.close(fd)
        finally:
            if context is not None:
                context.__exit__(None, None, None)

    def read_json(self, relative: Path | str) -> tuple[dict[str, Any], str]:
        raw, digest = self.read_bytes(relative)
        return _json_from_bytes(raw, str(self.root / Path(relative))), digest

    def read_bytes_without_publication_recovery_with_identity(
        self,
        relative: Path | str,
        *,
        max_bytes: int | None = None,
        fixed_helper_name: str | None = None,
    ) -> tuple[bytes, str, tuple[int, int], int]:
        """Read one private leaf without changing a recoverable link pair.

        This is the first-writer conflict probe.  Object identity is the
        retained final descriptor plus its parent name; content stability is
        the bounded equal reread; access policy is the private-file and ACL
        policy.  A two-link state is accepted only when the sole closed-name
        helper alias is opened, independently rebound to the same object, and
        yields the same bytes.  Link count distinguishes the publication phase
        here; timestamps are deliberately ignored and no alias is unlinked.
        """

        parts = _safe_relative_parts(relative)
        path = Path(*parts)
        limit = _json_limit_for_parts(parts) if max_bytes is None else max_bytes
        if len(parts) == 1:
            parent_fd = self.root_fd
            context = None
        else:
            context = self.open_dir(Path(*parts[:-1]), create=False)
            try:
                parent_fd = context.__enter__()
            except FileNotFoundError:
                _fail("missing-file", f"required state file is missing: {path}")
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        final_fd = -1
        helper_fd = -1
        try:
            try:
                final_fd = os.open(parts[-1], flags, dir_fd=parent_fd)
            except FileNotFoundError:
                _fail("missing-file", f"required state file is missing: {path}")
            opened = os.fstat(final_fd)
            identity = (opened.st_dev, opened.st_ino)
            expected_links = 1
            helper_digest: str | None = None
            if opened.st_nlink != 1:
                aliases: list[str] = []
                if fixed_helper_name is not None:
                    try:
                        candidate = os.stat(
                            fixed_helper_name,
                            dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        candidate = None
                    except PermissionError as exc:
                        _fail(
                            "helper-temp-unreadable",
                            f"helper temporary is unreadable: {fixed_helper_name}: {exc}",
                        )
                    if candidate is not None:
                        _validate_helper_temp_stat(
                            candidate,
                            self.root / Path(*parts[:-1]) / fixed_helper_name,
                            expected_links=2,
                            max_bytes=limit,
                        )
                        if (candidate.st_dev, candidate.st_ino) == identity:
                            aliases.append(fixed_helper_name)
                else:
                    prefix = f".{parts[-1]}.tmp-"
                    pattern = re.compile(rf"^{re.escape(prefix)}[1-9][0-9]{{0,19}}-[0-9a-f]{{16}}$")
                    for child in os.listdir(parent_fd):
                        if not child.startswith(prefix):
                            continue
                        if pattern.fullmatch(child) is None:
                            _fail("unsafe-helper-temp", f"malformed helper temporary: {child}")
                        candidate = os.stat(child, dir_fd=parent_fd, follow_symlinks=False)
                        _validate_helper_temp_stat(
                            candidate,
                            self.root / Path(*parts[:-1]) / child,
                            expected_links=2,
                            max_bytes=limit,
                        )
                        if (candidate.st_dev, candidate.st_ino) == identity:
                            aliases.append(child)
                if opened.st_nlink != 2 or len(aliases) != 1:
                    _fail(
                        "unsafe-link-count",
                        f"private state file has untrusted links: {parts[-1]}",
                    )
                expected_links = 2
                alias = aliases[0]
                try:
                    helper_fd = os.open(alias, flags, dir_fd=parent_fd)
                except PermissionError as exc:
                    code = (
                        "helper-temp-unreadable"
                        if fixed_helper_name is not None
                        else "unsafe-helper-temp"
                    )
                    _fail(code, f"helper temporary is unreadable: {alias}: {exc}")
                helper_opened = os.fstat(helper_fd)
                if (helper_opened.st_dev, helper_opened.st_ino) != identity:
                    _fail("unsafe-helper-temp", f"helper temporary was rebound: {alias}")
                _, helper_digest = _read_fd_stable(
                    helper_fd,
                    str(self.root / Path(*parts[:-1]) / alias),
                    private=True,
                    max_bytes=limit,
                    expected_parent_fd=parent_fd,
                    expected_name=alias,
                    expected_links=2,
                )
            raw, digest = _read_fd_stable(
                final_fd,
                str(self.root / path),
                private=True,
                max_bytes=limit,
                expected_parent_fd=parent_fd,
                expected_name=parts[-1],
                expected_links=expected_links,
            )
            if helper_digest is not None and helper_digest != digest:
                _fail("unsafe-helper-temp", f"linked helper temporary differs: {path}")
            self._bind_state_namespace("after read-only publication inspection")
            return raw, digest, identity, len(raw)
        finally:
            if helper_fd >= 0:
                os.close(helper_fd)
            if final_fd >= 0:
                os.close(final_fd)
            if context is not None:
                context.__exit__(*sys.exc_info())

    def read_json_without_publication_recovery_with_identity(
        self,
        relative: Path | str,
        *,
        max_bytes: int | None = None,
        fixed_helper_name: str | None = None,
    ) -> tuple[dict[str, Any], str, tuple[int, int], int]:
        raw, digest, identity, size = self.read_bytes_without_publication_recovery_with_identity(
            relative,
            max_bytes=max_bytes,
            fixed_helper_name=fixed_helper_name,
        )
        return _json_from_bytes(raw, str(self.root / Path(relative))), digest, identity, size

    def read_bytes_without_publication_recovery(
        self,
        relative: Path | str,
        *,
        max_bytes: int | None = None,
        fixed_helper_name: str | None = None,
    ) -> tuple[bytes, str]:
        raw, digest, _, _ = self.read_bytes_without_publication_recovery_with_identity(
            relative,
            max_bytes=max_bytes,
            fixed_helper_name=fixed_helper_name,
        )
        return raw, digest

    def read_json_without_publication_recovery(
        self,
        relative: Path | str,
        *,
        max_bytes: int | None = None,
        fixed_helper_name: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        value, digest, _, _ = self.read_json_without_publication_recovery_with_identity(
            relative,
            max_bytes=max_bytes,
            fixed_helper_name=fixed_helper_name,
        )
        return value, digest

    def read_json_with_identity(
        self, relative: Path | str, *, max_bytes: int | None = None
    ) -> tuple[dict[str, Any], str, tuple[int, int], int]:
        raw, digest, identity = self.read_bytes_with_identity(relative, max_bytes=max_bytes)
        return _json_from_bytes(raw, str(self.root / Path(relative))), digest, identity, len(raw)

    def private_file_size(self, relative: Path | str) -> int:
        """Return a private regular leaf size through its retained parent."""

        parts = _safe_relative_parts(relative)
        if len(parts) == 1:
            parent_fd = self.root_fd
            context = None
        else:
            context = self.open_dir(Path(*parts[:-1]), create=False)
            try:
                parent_fd = context.__enter__()
            except FileNotFoundError:
                _fail("missing-file", f"required state parent is missing: {Path(*parts)}")
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            try:
                fd = os.open(parts[-1], flags, dir_fd=parent_fd)
            except FileNotFoundError:
                _fail("missing-file", f"required state file is missing: {Path(*parts)}")
            try:
                self._recover_link_publication(parent_fd, parts[-1], fd)
                info = os.fstat(fd)
                _validate_private_stat(info, self.root / Path(*parts), directory=False)
                _acl_digest(fd, str(self.root / Path(*parts)), sensitive=True)
                named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(named.st_mode) or (named.st_dev, named.st_ino) != (
                    info.st_dev,
                    info.st_ino,
                ):
                    _fail("object-replaced", f"state leaf was rebound: {Path(*parts)}")
                return info.st_size
            finally:
                os.close(fd)
        finally:
            if context is not None:
                context.__exit__(None, None, None)

    def list_names(self, relative: Path | str) -> list[str]:
        try:
            with self.open_dir(relative) as directory_fd:
                names = os.listdir(directory_fd)
        except FileNotFoundError:
            return []
        return sorted(names, key=os.fsencode)

    def iter_names(self, relative: Path | str) -> Iterator[str]:
        """Yield retained-directory names without first materializing them."""

        try:
            with self.open_dir(relative) as directory_fd:
                with os.scandir(directory_fd) as entries:
                    for entry in entries:
                        yield entry.name
        except FileNotFoundError:
            return

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

    def recover_wal_temporaries(
        self,
        relative: Path | str,
        *,
        names: Sequence[str] | None = None,
        recover: bool = True,
    ) -> None:
        """Validate or remove only unambiguous WAL publication temporaries."""

        relative_path = Path(*_safe_relative_parts(relative))
        with self.open_dir(relative_path) as directory_fd:
            ordered_names = (
                sorted(os.listdir(directory_fd), key=os.fsencode)
                if names is None
                else sorted(names, key=os.fsencode)
            )
            # A linked final/temp pair is a post-publication crash.  Reading the
            # final through the ordinary fixed-fd path validates both names and
            # removes only its exact same-inode helper alias.
            for name in ordered_names:
                if WAL_LEAF_RE.fullmatch(name) is None:
                    continue
                if not recover:
                    self.read_bytes_without_publication_recovery(
                        relative_path / name,
                        max_bytes=MAX_WAL_JSON_BYTES,
                    )
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

            if not recover:
                temporaries: dict[str, str] = {}
                for name in ordered_names:
                    if not name.startswith("."):
                        continue
                    match = WAL_TEMP_RE.fullmatch(name)
                    if match is None:
                        _fail("unsafe-helper-temp", f"foreign WAL temporary entry: {name}")
                    leaf = match.group("leaf")
                    if leaf in temporaries:
                        _fail("unsafe-helper-temp", f"ambiguous WAL temporaries for {leaf}")
                    try:
                        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError as exc:
                        _fail(
                            "unsafe-helper-temp", f"could not inspect WAL temporary: {name}: {exc}"
                        )
                    try:
                        final_info = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        final_info = None
                    expected_links = 1
                    if final_info is not None:
                        same_object = (info.st_dev, info.st_ino) == (
                            final_info.st_dev,
                            final_info.st_ino,
                        )
                        if not same_object or info.st_nlink != 2 or final_info.st_nlink != 2:
                            _fail(
                                "unsafe-helper-temp",
                                f"WAL temporary remains beside an existing final leaf: {leaf}",
                            )
                        expected_links = 2
                    _validate_helper_temp_stat(
                        info,
                        self.root / relative_path / name,
                        expected_links=expected_links,
                    )
                    temp_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory_fd,
                    )
                    try:
                        opened = os.fstat(temp_fd)
                        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                            _fail("unsafe-helper-temp", f"helper temporary was rebound: {name}")
                        _read_fd_stable(
                            temp_fd,
                            str(self.root / relative_path / name),
                            private=True,
                            max_bytes=MAX_WAL_JSON_BYTES,
                            expected_parent_fd=directory_fd,
                            expected_name=name,
                            expected_links=expected_links,
                        )
                    finally:
                        os.close(temp_fd)
                    temporaries[leaf] = name
                return

            temporaries: dict[str, str] = {}
            for name in ordered_names:
                if not name.startswith("."):
                    continue
                match = WAL_TEMP_RE.fullmatch(name)
                if match is None:
                    _fail("unsafe-helper-temp", f"foreign WAL temporary entry: {name}")
                leaf = match.group("leaf")
                if leaf in temporaries:
                    _fail("unsafe-helper-temp", f"ambiguous WAL temporaries for {leaf}")
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    # The final-leaf pass already removed the exact post-link
                    # alias captured by the bounded preflight inventory.
                    continue
                _validate_helper_temp_stat(
                    info,
                    self.root / relative_path / name,
                    expected_links=1,
                )
                temp_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(temp_fd)
                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        _fail("unsafe-helper-temp", f"helper temporary was rebound: {name}")
                    _acl_digest(
                        temp_fd,
                        str(self.root / relative_path / name),
                        sensitive=True,
                    )
                finally:
                    os.close(temp_fd)
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

    @staticmethod
    def _wal_history_leaf_kind(relative: Path | str) -> tuple[Path, bool]:
        path = Path(*_safe_relative_parts(relative))
        parts = path.parts
        if parts == ("wal-history", "usage.json"):
            return path, True
        if (
            len(parts) == 3
            and parts[0] == "wal-history"
            and parts[1] in TRANSACTION_OPERATIONS
            and WAL_HISTORY_LEAF_RE.fullmatch(parts[2]) is not None
        ):
            return path, False
        _fail("invalid-wal-history-layout", f"invalid WAL history leaf path: {path}")

    def recover_wal_history_temporary(
        self,
        relative: Path | str,
        *,
        recover: bool = True,
    ) -> None:
        """Recover one fixed-name history publication without scanning history.

        A single-link temporary is a pre-publication non-authority and can be
        discarded only after retained-FD content, identity, private policy, and
        parent/name validation.  A two-link final/temporary pair is accepted
        only when both names bind the same stable object; the final is reread
        after removing the alias.  Timestamps are deliberately irrelevant.
        """

        path, mutable = self._wal_history_leaf_kind(relative)
        parent_path = Path(*path.parts[:-1])
        try:
            context = self.open_dir(parent_path, create=False)
            parent_fd = context.__enter__()
        except FileNotFoundError:
            return
        name = path.name
        temporary = _wal_history_fixed_temp_name(name)
        limit = _json_limit_for_parts(path.parts)

        def named_stat(child: str, *, helper: bool) -> os.stat_result | None:
            try:
                return os.stat(child, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except PermissionError as exc:
                code = "helper-temp-unreadable" if helper else "invalid-wal-history-layout"
                _fail(
                    code,
                    f"WAL history leaf is unreadable: {self.root / parent_path / child}: {exc}",
                )
            except OSError as exc:
                code = "unsafe-helper-temp" if helper else "invalid-wal-history-layout"
                _fail(code, f"could not inspect WAL history leaf {child}: {exc}")

        def open_stable(
            child: str,
            *,
            helper: bool,
            expected_links: int,
        ) -> tuple[int, bytes, str, tuple[int, int]]:
            flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                fd = os.open(child, flags, dir_fd=parent_fd)
            except PermissionError as exc:
                code = "helper-temp-unreadable" if helper else "invalid-wal-history-layout"
                _fail(code, f"WAL history leaf is unreadable: {child}: {exc}")
            except OSError as exc:
                code = "unsafe-helper-temp" if helper else "invalid-wal-history-layout"
                _fail(code, f"could not open WAL history leaf {child}: {exc}")
            try:
                opened = os.fstat(fd)
                if helper:
                    _validate_helper_temp_stat(
                        opened,
                        self.root / parent_path / child,
                        expected_links=expected_links,
                        max_bytes=limit,
                    )
                raw, digest = _read_fd_stable(
                    fd,
                    str(self.root / parent_path / child),
                    private=True,
                    max_bytes=limit,
                    expected_parent_fd=parent_fd,
                    expected_name=child,
                    expected_links=expected_links,
                )
                return fd, raw, digest, (opened.st_dev, opened.st_ino)
            except Exception:
                os.close(fd)
                raise

        def unlink_exact_temp(fd: int, identity: tuple[int, int], expected_links: int) -> None:
            # POSIX unlink is name-based rather than FD-conditional.  The
            # retained-FD checks below protect cooperative writers serialized
            # by the state lock; a non-cooperating same-UID rebind is diagnosed
            # when observable but is outside the prevention boundary.
            try:
                current = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                _fail("unsafe-helper-temp", f"helper temporary disappeared: {temporary}")
            except PermissionError as exc:
                _fail("helper-temp-unreadable", f"helper temporary became unreadable: {exc}")
            _validate_helper_temp_stat(
                current,
                self.root / parent_path / temporary,
                expected_links=expected_links,
                max_bytes=limit,
            )
            if (current.st_dev, current.st_ino) != identity:
                _fail("unsafe-helper-temp", f"helper temporary was rebound: {temporary}")
            os.unlink(temporary, dir_fd=parent_fd)
            os.fsync(parent_fd)
            if os.fstat(fd).st_nlink != expected_links - 1:
                _fail("unsafe-helper-temp", f"helper temporary unlink was not exact: {temporary}")

        final_fd = -1
        temp_fd = -1
        try:
            self._bind_state_namespace("before WAL history temporary recovery")
            temp_info = named_stat(temporary, helper=True)
            if temp_info is None:
                final_info = named_stat(name, helper=False)
                if final_info is not None and final_info.st_nlink != 1:
                    _fail(
                        "unsafe-link-count",
                        f"WAL history final has no exact helper alias: {path}",
                    )
                return
            if temp_info.st_nlink not in {1, 2}:
                _fail("unsafe-helper-temp", f"helper temporary has untrusted links: {temporary}")
            final_info = named_stat(name, helper=False)
            if final_info is None:
                if temp_info.st_nlink != 1:
                    _fail(
                        "unsafe-helper-temp",
                        f"orphan helper temporary has extra links: {temporary}",
                    )
                temp_fd, _, _, temp_identity = open_stable(
                    temporary,
                    helper=True,
                    expected_links=1,
                )
                if not recover:
                    return
                unlink_exact_temp(temp_fd, temp_identity, 1)
                self._bind_state_namespace("after pre-link WAL history recovery")
                return

            same_object = (temp_info.st_dev, temp_info.st_ino) == (
                final_info.st_dev,
                final_info.st_ino,
            )
            expected_links = 2 if same_object else 1
            if temp_info.st_nlink != expected_links or final_info.st_nlink != expected_links:
                _fail("unsafe-helper-temp", f"WAL history publication links are invalid: {path}")
            final_fd, _, final_digest, final_identity = open_stable(
                name,
                helper=False,
                expected_links=expected_links,
            )
            temp_fd, _, temp_digest, temp_identity = open_stable(
                temporary,
                helper=True,
                expected_links=expected_links,
            )
            if same_object:
                if temp_identity != final_identity or temp_digest != final_digest:
                    _fail("unsafe-helper-temp", f"linked history temporary differs: {temporary}")
            elif not mutable:
                _fail(
                    "unsafe-helper-temp",
                    f"immutable history temporary is not the final object: {temporary}",
                )
            if not recover:
                return
            unlink_exact_temp(temp_fd, temp_identity, expected_links)
            _, recovered_digest = _read_fd_stable(
                final_fd,
                str(self.root / path),
                private=True,
                max_bytes=limit,
                expected_parent_fd=parent_fd,
                expected_name=name,
            )
            if recovered_digest != final_digest:
                _fail("unsafe-helper-temp", f"history final changed during recovery: {path}")
            self._bind_state_namespace("after post-link WAL history recovery")
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
            if final_fd >= 0:
                os.close(final_fd)
            context.__exit__(*sys.exc_info())

    def recover_all_wal_history_temporaries(self, *, recover: bool = True) -> None:
        """Explicitly recover valid fixed temps and reject every foreign temp."""

        _, _, temporary_targets = _enumerate_wal_history_namespace(self)
        for target in temporary_targets:
            self.recover_wal_history_temporary(target, recover=recover)

    def write_wal_history_json(
        self,
        relative: Path | str,
        value: Mapping[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        """Write one history leaf through its deterministic recoverable temp."""

        path, mutable = self._wal_history_leaf_kind(relative)
        if mutable == immutable:
            _fail("invalid-wal-history-layout", "history leaf mutability does not match its kind")
        self.recover_wal_history_temporary(path)
        if self._fixed_publication_temporary is not None:
            _fail("invalid-publication-capture", "fixed publication temporary is nested")
        self._fixed_publication_temporary = (path, _wal_history_fixed_temp_name(path.name))
        try:
            return self.write_json(path, value, immutable=immutable)
        finally:
            self._fixed_publication_temporary = None

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

    def _unlink_created_publication_temporary(
        self,
        parent_fd: int,
        temporary: str,
        fd: int,
        expected_identity: tuple[int, int],
        *,
        max_bytes: int,
    ) -> None:
        """Clean this invocation's helper under the cooperative-writer lock."""

        try:
            named = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except PermissionError as exc:
            _fail("temporary-unreadable", f"publication temporary is unreadable: {exc}")
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != expected_identity or (
            named.st_dev,
            named.st_ino,
        ) != expected_identity:
            _fail("temporary-replaced", "publication temporary object was rebound")
        if opened.st_nlink not in {1, 2}:
            _fail("unsafe-helper-temp", "publication temporary has untrusted links")
        _validate_helper_temp_stat(
            named,
            self.root / temporary,
            expected_links=opened.st_nlink,
            max_bytes=max_bytes,
        )
        os.unlink(temporary, dir_fd=parent_fd)
        os.fsync(parent_fd)
        if os.fstat(fd).st_nlink != opened.st_nlink - 1:
            _fail("temporary-replaced", "publication temporary unlink was not exact")

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
        publication_path = Path(*parts)
        fixed_temporary = self._fixed_publication_temporary
        if fixed_temporary is not None and fixed_temporary[0] != publication_path:
            _fail("invalid-publication-capture", "fixed temporary does not bind this write")
        temporary = (
            fixed_temporary[1]
            if fixed_temporary is not None and fixed_temporary[0] == publication_path
            else f".{name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = -1
        created_identity: tuple[int, int] | None = None
        cleanup_attempted = False
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
            opened = os.fstat(fd)
            created_identity = (opened.st_dev, opened.st_ino)
            try:
                _acl_digest(fd, str(self.root / Path(*parts)), sensitive=True)
                offset = 0
                while offset < len(payload):
                    offset += os.write(fd, payload[offset:])
                os.fsync(fd)
                temp_info = os.fstat(fd)
                self._bind_state_namespace("before publication")
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
                self._bind_state_namespace("after publication")
            finally:
                assert created_identity is not None
                cleanup_attempted = True
                try:
                    self._unlink_created_publication_temporary(
                        parent_fd,
                        temporary,
                        fd,
                        created_identity,
                        max_bytes=limit,
                    )
                finally:
                    os.close(fd)
                    fd = -1
            final = self._read_named(parent_fd, name, Path(*parts), max_bytes=limit)
            if final != payload:
                _fail("write-verification-failed", f"stored bytes differ: {Path(*parts)}")
            self._bind_state_namespace("after publication verification")
            return digest
        finally:
            try:
                if fd >= 0:
                    if created_identity is not None and not cleanup_attempted:
                        self._unlink_created_publication_temporary(
                            parent_fd,
                            temporary,
                            fd,
                            created_identity,
                            max_bytes=limit,
                        )
                    os.close(fd)
            finally:
                if context is not None:
                    context.__exit__(*sys.exc_info())


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
    temporary_root = StateStore(path.parent, sensitive_root=False)
    try:
        return temporary_root.write_json(Path(path.name), value, immutable=immutable)
    finally:
        temporary_root.close()


@contextmanager
def _state_lock(
    state_root: Path,
    *,
    create: bool = True,
    recover_marker_publication: bool = True,
) -> Iterator[StateStore]:
    store: StateStore | None = None
    token: contextvars.Token[StateStore | None] | None = None
    try:
        store = StateStore(state_root, create=create)
        store.acquire_lock(create=create)
        token = _ACTIVE_STORE.set(store)
        if store.exists(Path(STATE_MARKER)):
            # Validate the persisted ACL chain before any caller can recover or
            # apply a WAL after-image.  Exact public transaction entrypoints
            # may defer helper cleanup until their first-writer probe accepts
            # the request, but still validate the same object, bytes, and
            # access policy through retained descriptors here.
            _read_marker(
                state_root,
                recover_publication=recover_marker_publication,
            )
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


def _wal_history_path(operation: str, natural_key: str) -> Path:
    return Path("wal-history") / operation / f"{_wal_key(operation, natural_key)}.json"


def _transaction_record_exists(store: StateStore, operation: str, natural_key: str) -> bool:
    intent_path, commit_path = _wal_paths(operation, natural_key)
    history_path = _wal_history_path(operation, natural_key)
    return store.exists(intent_path) or store.exists(commit_path) or store.exists(history_path)


def _wal_checkpoint_authorities(intent: Mapping[str, Any]) -> list[dict[str, str]]:
    prefixes: dict[str, tuple[tuple[str, ...], ...]] = {
        "stage": (("receipts", "stage"), ("repairs", "consumptions")),
        "dormancy": (("receipts", "dormancy"),),
        "complete-audit": (("completed",), ("historical", "completed")),
        "selection-preflight": (("publication", "preflights"),),
        "weekly-plan": (("publication", "plans"),),
        "finalize-publication": (
            ("publication", "prepared"),
            ("publication", "manifests"),
        ),
        "close-publication": (("publication", "closures"),),
        "approve-repair": (("repairs", "approvals"), ("repairs", "approval-index")),
    }
    allowed = prefixes[intent["operation"]]
    authorities = [
        {"path": write["path"], "sha256": write["after_sha256"]}
        for raw_write in intent["writes"]
        if (write := _require_object(raw_write, "wal.write"))["scope"] == "state"
        and write["immutable"] is True
        and any(Path(write["path"]).parts[: len(prefix)] == prefix for prefix in allowed)
    ]
    authorities.sort(key=lambda item: os.fsencode(item["path"]))
    if not authorities:
        _fail(
            "wal-checkpoint-without-authority",
            "committed transaction has no immutable domain authority for retirement",
        )
    return authorities


def _validate_wal_authority_projection(
    operation: str, authorities: Sequence[Mapping[str, str]]
) -> None:
    paths = [Path(item["path"]).parts for item in authorities]

    def count(prefix: tuple[str, ...]) -> int:
        return sum(parts[: len(prefix)] == prefix for parts in paths)

    valid = {
        "stage": count(("receipts", "stage")) == 1,
        "dormancy": count(("receipts", "dormancy")) == 1,
        "complete-audit": (count(("completed",)) + count(("historical", "completed")) == 1),
        "selection-preflight": count(("publication", "preflights")) == 1,
        "weekly-plan": count(("publication", "plans")) == 1,
        "finalize-publication": count(("publication", "manifests")) == 1,
        "close-publication": count(("publication", "closures")) == 1,
        "approve-repair": (
            count(("repairs", "approvals")) == 1 and count(("repairs", "approval-index")) == 1
        ),
    }
    if valid.get(operation) is not True:
        _fail(
            "wal-checkpoint-without-authority",
            f"{operation} lacks its deterministic immutable domain authority",
        )


def _wal_checkpoint_after_images(intent: Mapping[str, Any]) -> list[dict[str, Any]]:
    state_replicas: dict[str, list[str]] = {}
    for raw_write in intent["writes"]:
        write = _require_object(raw_write, "wal.write")
        if write["scope"] == "state" and write["immutable"] is True:
            state_replicas.setdefault(write["after_sha256"], []).append(write["path"])
    result: list[dict[str, Any]] = []
    for raw_write in intent["writes"]:
        write = _require_object(raw_write, "wal.write")
        item: dict[str, Any] = {
            "scope": write["scope"],
            "path": write["path"],
            "before_sha256": write["before_sha256"],
            "after_sha256": write["after_sha256"],
            "immutable": write["immutable"],
        }
        if write["scope"] == "external":
            replicas = sorted(state_replicas.get(write["after_sha256"], []), key=os.fsencode)
            if len(replicas) != 1:
                _fail(
                    "wal-external-replica-missing",
                    "external WAL after-image must have one exact immutable state replica",
                )
            item["replica_path"] = replicas[0]
            if "parent_binding" in write:
                item["parent_binding"] = write["parent_binding"]
                item["legacy_external"] = False
            else:
                item["legacy_external"] = True
        result.append(item)
    return result


def _build_wal_checkpoint(
    intent: Mapping[str, Any],
    commit: Mapping[str, Any],
    *,
    sequence: int,
    previous_usage_digest: str,
) -> dict[str, Any]:
    authorities = _wal_checkpoint_authorities(intent)
    _validate_wal_authority_projection(intent["operation"], authorities)
    body = {
        "version": VERSION,
        "kind": "state-transaction-checkpoint",
        "operation": intent["operation"],
        "natural_key": intent["natural_key"],
        "request_digest": intent["request_digest"],
        "captured_at": intent["captured_at"],
        "intent_digest": intent["intent_digest"],
        "intent_bytes": len(_canonical_bytes(intent)),
        "commit_digest": commit["commit_digest"],
        "result_digest": _digest(_require_object(intent["result"], "wal.result")),
        "sequence": sequence,
        "previous_usage_digest": previous_usage_digest,
        "authorities": authorities,
        "after_images": _wal_checkpoint_after_images(intent),
    }
    checkpoint = {**body, "checkpoint_digest": _digest(body)}
    if len(_canonical_bytes(checkpoint)) > MAX_WAL_HISTORY_RECORD_BYTES:
        _fail(
            "wal-checkpoint-too-large",
            f"compact WAL checkpoint exceeds {MAX_WAL_HISTORY_RECORD_BYTES} bytes",
        )
    return checkpoint


def _validate_wal_checkpoint(
    store: StateStore,
    checkpoint: Mapping[str, Any],
    expected_operation: str,
    *,
    expected_natural_key: str | None = None,
) -> dict[str, Any]:
    _exact_fields(
        checkpoint,
        "wal.checkpoint",
        {
            "version",
            "kind",
            "operation",
            "natural_key",
            "request_digest",
            "captured_at",
            "intent_digest",
            "intent_bytes",
            "commit_digest",
            "result_digest",
            "sequence",
            "previous_usage_digest",
            "authorities",
            "after_images",
            "checkpoint_digest",
        },
    )
    if (
        type(checkpoint["version"]) is not int
        or checkpoint["version"] != VERSION
        or checkpoint["kind"] != "state-transaction-checkpoint"
        or checkpoint["operation"] != expected_operation
        or expected_operation not in TRANSACTION_OPERATIONS
    ):
        _fail("invalid-wal-history", "WAL checkpoint kind or operation is invalid")
    natural_key = _require_string(checkpoint["natural_key"], "wal.checkpoint.natural_key")
    if expected_natural_key is not None and natural_key != expected_natural_key:
        _fail("invalid-wal-history", "WAL checkpoint binds another natural key")
    for field in (
        "request_digest",
        "intent_digest",
        "commit_digest",
        "result_digest",
        "checkpoint_digest",
        "previous_usage_digest",
    ):
        if (
            HEX64_RE.fullmatch(_require_string(checkpoint[field], f"wal.checkpoint.{field}"))
            is None
        ):
            _fail("invalid-wal-history", f"WAL checkpoint {field} must be raw SHA-256")
    sequence = _require_int(checkpoint["sequence"], "wal.checkpoint.sequence", minimum=1)
    if sequence > MAX_WAL_HISTORY_RECORDS:
        _fail("wal-history-count-limit", "WAL checkpoint sequence exceeds history count limit")
    intent_bytes = _require_int(
        checkpoint["intent_bytes"], "wal.checkpoint.intent_bytes", minimum=1
    )
    if intent_bytes > MAX_WAL_JSON_BYTES:
        _fail("invalid-wal-history", "checkpoint intent size exceeds WAL envelope")
    _timestamp(checkpoint["captured_at"], "wal.checkpoint.captured_at")
    authorities = _require_list(checkpoint["authorities"], "wal.checkpoint.authorities")
    if not authorities:
        _fail("invalid-wal-history", "WAL checkpoint has no immutable domain authority")
    seen_authorities: set[str] = set()
    normalized_authorities: list[dict[str, str]] = []
    for index, raw in enumerate(authorities):
        item = _require_object(raw, f"wal.checkpoint.authorities[{index}]")
        _exact_fields(item, "wal.checkpoint.authority", {"path", "sha256"})
        path = _require_string(item["path"], "wal.checkpoint.authority.path")
        _safe_relative_parts(Path(path))
        digest = _require_string(item["sha256"], "wal.checkpoint.authority.sha256")
        if HEX64_RE.fullmatch(digest) is None or path in seen_authorities:
            _fail("invalid-wal-history", "WAL checkpoint authority is invalid or repeated")
        seen_authorities.add(path)
        normalized_authorities.append({"path": path, "sha256": digest})
    if normalized_authorities != sorted(
        normalized_authorities, key=lambda item: os.fsencode(item["path"])
    ):
        _fail("invalid-wal-history", "WAL checkpoint authorities are not canonical")
    _validate_wal_authority_projection(expected_operation, normalized_authorities)
    after_images = _require_list(checkpoint["after_images"], "wal.checkpoint.after_images")
    seen_targets: set[str] = set()
    normalized_images: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(after_images):
        item = _require_object(raw, f"wal.checkpoint.after_images[{index}]")
        scope = item.get("scope")
        expected = {"scope", "path", "before_sha256", "after_sha256", "immutable"}
        if scope == "external":
            expected.update({"replica_path", "legacy_external"})
            if item.get("legacy_external") is False:
                expected.add("parent_binding")
        _exact_fields(item, f"wal.checkpoint.after_images[{index}]", expected)
        if scope not in {"state", "external"}:
            _fail("invalid-wal-history", "WAL checkpoint after-image scope is invalid")
        path = _require_string(item["path"], "wal.checkpoint.after_image.path")
        if path in seen_targets:
            _fail("invalid-wal-history", "WAL checkpoint repeats an after-image target")
        seen_targets.add(path)
        if scope == "state":
            _safe_relative_parts(Path(path))
        else:
            if expected_operation not in {"weekly-plan", "finalize-publication"}:
                _fail("invalid-wal-history", "this checkpoint operation cannot write externally")
            absolute = Path(os.path.abspath(os.fspath(path)))
            if not Path(path).is_absolute() or str(absolute) != path:
                _fail("invalid-wal-history", "external checkpoint path is not canonical")
            _normalize_external_output_outside_state_root(store.root, absolute)
            replica = _require_string(item["replica_path"], "wal.checkpoint.replica_path")
            _safe_relative_parts(Path(replica))
            if replica not in seen_authorities:
                _fail("invalid-wal-history", "external replica is not an immutable authority")
            legacy = item["legacy_external"]
            if not isinstance(legacy, bool):
                _fail("invalid-wal-history", "legacy_external must be boolean")
            if legacy:
                if "parent_binding" in item:
                    _fail("invalid-wal-history", "legacy external checkpoint has a parent binding")
            else:
                _validate_external_parent_binding(item["parent_binding"], absolute)
        before = item["before_sha256"]
        if before is not None and (
            not isinstance(before, str) or HEX64_RE.fullmatch(before) is None
        ):
            _fail("invalid-wal-history", "checkpoint before_sha256 is invalid")
        if HEX64_RE.fullmatch(
            _require_string(item["after_sha256"], "wal.checkpoint.after_sha256")
        ) is None or not isinstance(item["immutable"], bool):
            _fail("invalid-wal-history", "checkpoint after-image digest/flag is invalid")
        if scope == "external" and item["immutable"] is not True:
            _fail("invalid-wal-history", "external checkpoint output must be immutable")
        normalized_images[path] = item
    for authority in normalized_authorities:
        image = normalized_images.get(authority["path"])
        if (
            image is None
            or image["scope"] != "state"
            or image["immutable"] is not True
            or image["after_sha256"] != authority["sha256"]
        ):
            _fail(
                "invalid-wal-history",
                "checkpoint authority does not bind its immutable state after-image",
            )
    body = {key: value for key, value in checkpoint.items() if key != "checkpoint_digest"}
    if checkpoint["checkpoint_digest"] != _digest(body):
        _fail("invalid-wal-history", "WAL checkpoint digest mismatch")
    return dict(checkpoint)


WAL_HISTORY_USAGE = Path("wal-history") / "usage.json"


def _new_wal_history_usage() -> dict[str, Any]:
    body = {
        "version": VERSION,
        "kind": "wal-history-usage",
        "record_count": 0,
        "total_bytes": 0,
        "last_checkpoint_digest": None,
    }
    return {**body, "usage_digest": _digest(body)}


def _validate_wal_history_usage(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_fields(
        value,
        "wal.history_usage",
        {
            "version",
            "kind",
            "record_count",
            "total_bytes",
            "last_checkpoint_digest",
            "usage_digest",
        },
    )
    count = _require_int(value["record_count"], "wal.history_usage.record_count")
    total = _require_int(value["total_bytes"], "wal.history_usage.total_bytes")
    last = value["last_checkpoint_digest"]
    if (
        type(value["version"]) is not int
        or value["version"] != VERSION
        or value["kind"] != "wal-history-usage"
        or count > MAX_WAL_HISTORY_RECORDS
        or total > MAX_WAL_HISTORY_BYTES
        or ((count == 0) != (last is None))
        or (last is not None and (not isinstance(last, str) or HEX64_RE.fullmatch(last) is None))
    ):
        _fail("invalid-wal-history-usage", "WAL history usage record is invalid")
    body = {key: item for key, item in value.items() if key != "usage_digest"}
    if value["usage_digest"] != _digest(body):
        _fail("invalid-wal-history-usage", "WAL history usage digest mismatch")
    return dict(value)


def _read_wal_history_usage(
    store: StateStore,
    *,
    recover: bool = True,
) -> dict[str, Any]:
    store.recover_wal_history_temporary(WAL_HISTORY_USAGE, recover=recover)
    if not store.exists(WAL_HISTORY_USAGE):
        return _new_wal_history_usage()
    if recover:
        value, _ = store.read_json(WAL_HISTORY_USAGE)
    else:
        value, _ = store.read_json_without_publication_recovery(
            WAL_HISTORY_USAGE,
            fixed_helper_name=_wal_history_fixed_temp_name(WAL_HISTORY_USAGE.name),
        )
    return _validate_wal_history_usage(value)


def _read_wal_history_usage_binding_read_only(
    store: StateStore,
) -> tuple[dict[str, Any], str | None, tuple[int, int] | None, int]:
    """Read usage without cleanup and retain its exact file binding."""

    if not store.exists(WAL_HISTORY_USAGE):
        return _new_wal_history_usage(), None, None, 0
    value, digest, identity, size = store.read_json_without_publication_recovery_with_identity(
        WAL_HISTORY_USAGE,
        fixed_helper_name=_wal_history_fixed_temp_name(WAL_HISTORY_USAGE.name),
    )
    return _validate_wal_history_usage(value), digest, identity, size


def _project_wal_history_usage(
    usage: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    checkpoint_size: int,
) -> dict[str, Any]:
    """Project one exact checkpoint onto usage without changing state."""

    usage = _validate_wal_history_usage(usage)
    count = usage["record_count"]
    total = usage["total_bytes"]
    if checkpoint["sequence"] == count:
        if usage["last_checkpoint_digest"] != checkpoint["checkpoint_digest"]:
            _fail("invalid-wal-history-usage", "history usage does not bind its last checkpoint")
        return dict(usage)
    if (
        checkpoint["sequence"] != count + 1
        or checkpoint["previous_usage_digest"] != usage["usage_digest"]
    ):
        _fail("invalid-wal-history-usage", "checkpoint is not the next usage-chain record")
    if count + 1 > MAX_WAL_HISTORY_RECORDS:
        _fail("wal-history-count-limit", "WAL history record count limit reached")
    if total + checkpoint_size > MAX_WAL_HISTORY_BYTES:
        _fail("wal-history-byte-limit", "WAL history aggregate byte limit reached")
    body = {
        "version": VERSION,
        "kind": "wal-history-usage",
        "record_count": count + 1,
        "total_bytes": total + checkpoint_size,
        "last_checkpoint_digest": checkpoint["checkpoint_digest"],
    }
    return {**body, "usage_digest": _digest(body)}


def _advance_wal_history_usage(
    store: StateStore,
    usage: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    checkpoint_size: int,
) -> dict[str, Any]:
    usage = _validate_wal_history_usage(usage)
    checkpoint = _validate_wal_checkpoint(store, checkpoint, checkpoint["operation"])
    advanced = _project_wal_history_usage(usage, checkpoint, checkpoint_size)
    if advanced == usage:
        return dict(usage)
    store.write_wal_history_json(WAL_HISTORY_USAGE, advanced)
    return advanced


def _checkpoint_authority_objects(
    store: StateStore,
    checkpoint: Mapping[str, Any],
    *,
    recover_publication: bool = True,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in checkpoint["authorities"]:
        authority = _require_object(raw, "wal.checkpoint.authority")
        path = authority["path"]
        if recover_publication:
            value, digest = store.read_json(Path(path))
        else:
            value, digest = store.read_json_without_publication_recovery(Path(path))
        if digest != authority["sha256"]:
            _fail("wal-history-authority-drift", f"checkpoint authority changed: {path}")
        result[path] = value
    return result


def _one_checkpoint_authority(
    authorities: Mapping[str, dict[str, Any]],
    *,
    prefix: tuple[str, ...],
) -> tuple[str, dict[str, Any]]:
    matches = [
        (path, value)
        for path, value in authorities.items()
        if Path(path).parts[: len(prefix)] == prefix
    ]
    if len(matches) != 1:
        _fail(
            "invalid-wal-history",
            f"checkpoint must bind one {'/'.join(prefix)} authority",
        )
    return matches[0]


def _checkpoint_external_outputs(checkpoint: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        _require_object(raw, "wal.checkpoint.after_image")
        for raw in checkpoint["after_images"]
        if _require_object(raw, "wal.checkpoint.after_image")["scope"] == "external"
    ]


def _checkpoint_state_after_images(
    checkpoint: Mapping[str, Any],
    operation: str,
) -> dict[str, dict[str, Any]]:
    """Return the closed state-write projection for one retired transaction."""

    result: dict[str, dict[str, Any]] = {}
    for raw in _require_list(checkpoint["after_images"], "wal.checkpoint.after_images"):
        image = _require_object(raw, "wal.checkpoint.after_image")
        if image.get("scope") != "state":
            _fail(
                "invalid-wal-history",
                f"{operation} checkpoint cannot contain external after-images",
            )
        path = _require_string(image.get("path"), "wal.checkpoint.after_image.path")
        if path in result:
            _fail(
                "invalid-wal-history",
                f"{operation} checkpoint repeats a state after-image",
            )
        result[path] = image
    return result


def _validate_approve_repair_checkpoint_projection(
    checkpoint: Mapping[str, Any],
    approval_path: str,
    approval_record: Mapping[str, Any],
    index_path: str,
    index_record: Mapping[str, Any],
) -> None:
    """Bind a retired approval checkpoint to exactly its two authorities."""

    images = _checkpoint_state_after_images(checkpoint, "approve-repair")
    expected = {
        approval_path: hashlib.sha256(_canonical_bytes(approval_record)).hexdigest(),
        index_path: hashlib.sha256(_canonical_bytes(index_record)).hexdigest(),
    }
    if set(images) != set(expected):
        _fail(
            "invalid-wal-history",
            "approve-repair checkpoint state after-images differ from its authorities",
        )
    for path, after_sha256 in expected.items():
        image = images[path]
        if (
            image.get("before_sha256") is not None
            or image.get("after_sha256") != after_sha256
            or image.get("immutable") is not True
        ):
            _fail(
                "invalid-wal-history",
                "approve-repair checkpoint authority projection is invalid",
            )


def _validate_close_publication_checkpoint_projection(
    checkpoint: Mapping[str, Any],
    closure_path: str,
    closure: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
) -> None:
    """Bind a retired closure checkpoint to its closed state target set."""

    images = _checkpoint_state_after_images(checkpoint, "close-publication")
    active_paths = {f"publication/active/{entry['case_id']}.json" for entry in entries}
    expected_paths = {closure_path, *active_paths}
    if set(images) != expected_paths:
        _fail(
            "invalid-wal-history",
            "close-publication checkpoint state after-images differ from its closure",
        )
    closure_image = images[closure_path]
    closure_digest = hashlib.sha256(_canonical_bytes(closure)).hexdigest()
    if (
        closure_image.get("before_sha256") is not None
        or closure_image.get("after_sha256") != closure_digest
        or closure_image.get("immutable") is not True
    ):
        _fail(
            "invalid-wal-history",
            "close-publication checkpoint closure projection is invalid",
        )
    for path in active_paths:
        image = images[path]
        if image.get("before_sha256") is None or image.get("immutable") is not False:
            _fail(
                "invalid-wal-history",
                "close-publication checkpoint active projection is invalid",
            )


def _verify_checkpoint_external_outputs(
    store: StateStore,
    checkpoint: Mapping[str, Any],
    authorities: Mapping[str, dict[str, Any]],
    *,
    recover_publication: bool = True,
    allow_repairable: bool = False,
    usage_committed: bool = True,
) -> None:
    for image in _checkpoint_external_outputs(checkpoint):
        replica_path = image["replica_path"]
        if replica_path not in authorities:
            _fail("invalid-wal-history", "external replica authority is missing")
        replica_digest = hashlib.sha256(_canonical_bytes(authorities[replica_path])).hexdigest()
        if replica_digest != image["after_sha256"]:
            _fail("wal-history-authority-drift", "external replica digest changed")
        target = Path(image["path"])
        binding = None if image["legacy_external"] else image["parent_binding"]
        with _bound_external_parent(target, binding) as (parent, _):
            current = _read_optional_external(
                parent,
                target,
                recover_publication=recover_publication,
            )
            current_digest = current[1] if current is not None else None
            if current_digest == image["after_sha256"]:
                continue
            if (
                allow_repairable
                and not image["legacy_external"]
                and current_digest == image["before_sha256"]
            ):
                repair_intent = _active_wal_binds_checkpoint_read_only(
                    store,
                    checkpoint,
                    required=False,
                    require_commit=not usage_committed,
                )
                if repair_intent is not None:
                    continue
            code = (
                "legacy-external-wal-unbound"
                if image["legacy_external"]
                else "wal-history-external-drift"
            )
            _fail(
                code,
                "retired external after-image is missing or changed; automatic repair requires "
                "the exact retained full WAL",
            )


def _reconstruct_checkpoint_result(
    store: StateStore,
    checkpoint: Mapping[str, Any],
    *,
    verify_external: bool = True,
    recover_publication: bool = True,
    allow_repairable_external: bool = False,
    usage_committed: bool = True,
) -> dict[str, Any]:
    checkpoint = _validate_wal_checkpoint(
        store,
        checkpoint,
        checkpoint["operation"],
        expected_natural_key=checkpoint["natural_key"],
    )
    authorities = _checkpoint_authority_objects(
        store,
        checkpoint,
        recover_publication=recover_publication,
    )
    operation = checkpoint["operation"]
    if operation == "stage":
        path, receipt = _one_checkpoint_authority(authorities, prefix=("receipts", "stage"))
        receipt_id = _safe_object_id(receipt.get("receipt_id"), "receipt.receipt_id")
        if path != f"receipts/stage/{receipt_id}.json":
            _fail("invalid-wal-history", "stage checkpoint receipt path is invalid")
        _validate_persisted_receipt(receipt, "stage", receipt_id)
        consumption_authorities = [
            (authority_path, value)
            for authority_path, value in authorities.items()
            if Path(authority_path).parts[:2] == ("repairs", "consumptions")
        ]
        if len(consumption_authorities) > 1:
            _fail("invalid-wal-history", "stage checkpoint has multiple repair consumptions")
        if consumption_authorities:
            consumption_path, consumption = consumption_authorities[0]
            approval_id = _safe_object_id(
                consumption.get("approval_id"),
                "repair_consumption.approval_id",
            )
            consumption_body = {
                key: value for key, value in consumption.items() if key != "consumption_digest"
            }
            if (
                consumption_path != f"repairs/consumptions/{approval_id}.json"
                or consumption.get("kind") != "repair-approval-consumption"
                or consumption.get("stage_receipt_id") != receipt_id
                or consumption.get("consumption_digest") != _digest(consumption_body)
                or receipt.get("repair_approval")
                != {
                    "approval_id": approval_id,
                    "approval_digest": consumption.get("approval_digest"),
                }
            ):
                _fail("invalid-wal-history", "stage checkpoint repair consumption is invalid")
        result = {**receipt, "path": str(store.root / path)}
    elif operation == "dormancy":
        path, receipt = _one_checkpoint_authority(authorities, prefix=("receipts", "dormancy"))
        result = {**receipt, "path": str(store.root / path)}
    elif operation == "complete-audit":
        completed = [
            (path, value)
            for path, value in authorities.items()
            if Path(path).parts[:1] == ("completed",)
            or Path(path).parts[:2] == ("historical", "completed")
        ]
        if len(completed) != 1:
            _fail("invalid-wal-history", "checkpoint must bind one completed snapshot")
        path, snapshot = completed[0]
        historical = snapshot.get("mode") == "historical-replay"
        result = {
            "version": VERSION,
            "status": "completed",
            "mode": snapshot["mode"],
            "audit_id": snapshot["audit_id"],
            "snapshot_path": str(store.root / (Path(path) if historical else Path(LIVE_POINTER))),
            "snapshot_digest": snapshot["snapshot_digest"],
            "case_count": len(_require_list(snapshot["cases"], "snapshot.cases")),
        }
    elif operation == "selection-preflight":
        _, result = _one_checkpoint_authority(authorities, prefix=("publication", "preflights"))
    elif operation == "weekly-plan":
        _, plan = _one_checkpoint_authority(authorities, prefix=("publication", "plans"))
        outputs = _checkpoint_external_outputs(checkpoint)
        if len(outputs) != 1:
            _fail("invalid-wal-history", "weekly checkpoint must bind one external plan")
        result = {
            "version": VERSION,
            "status": "planned",
            "plan_path": outputs[0]["path"],
            "plan_digest": plan["plan_digest"],
            "selected_count": len(_require_list(plan["entries"], "plan.entries")),
            "skipped": _require_list(plan["skipped"], "plan.skipped"),
        }
    elif operation == "finalize-publication":
        _, prepared = _one_checkpoint_authority(
            authorities,
            prefix=("publication", "prepared"),
        )
        _, manifest = _one_checkpoint_authority(
            authorities,
            prefix=("publication", "manifests"),
        )
        outputs = _checkpoint_external_outputs(checkpoint)
        if len(outputs) != 1:
            _fail("invalid-wal-history", "finalize checkpoint must bind one external manifest")
        result = {
            "version": VERSION,
            "status": "finalized",
            "manifest_path": outputs[0]["path"],
            "manifest_digest": manifest["manifest_digest"],
            "entry_count": len(_require_list(manifest["entries"], "manifest.entries")),
        }
        selection_id = _safe_object_id(manifest.get("selection_id"), "manifest.selection_id")
        plan = _read_state_json(
            store,
            Path("publication") / "plans" / f"{selection_id}.json",
            recover_publication=recover_publication,
        )
        _validate_manifest(manifest, plan, prepared)
        _validate_finalize_transaction_authority(
            {
                "kind": "retired-state-transaction",
                "operation": operation,
                "natural_key": checkpoint["natural_key"],
                "request_digest": checkpoint["request_digest"],
                "writes": checkpoint["after_images"],
                "result": result,
            },
            plan,
            prepared,
            manifest,
        )
    elif operation == "close-publication":
        closure_path, closure = _one_checkpoint_authority(
            authorities,
            prefix=("publication", "closures"),
        )
        _validate_persisted_closure_record(closure)
        if (
            checkpoint["natural_key"] != closure["closure_id"]
            or closure_path != f"publication/closures/{closure['closure_id']}.json"
        ):
            _fail(
                "invalid-wal-history",
                "close checkpoint key or authority path does not bind closure_id",
            )
        entries = [
            _require_object(raw, "closure.entry")
            for raw in _require_list(closure["entries"], "closure.entries")
        ]
        if closure.get("reason") == "published":
            _validate_published_closure_entries_against_plans(
                store,
                entries,
                recover_publication=recover_publication,
            )
        _validate_close_publication_checkpoint_projection(
            checkpoint,
            closure_path,
            closure,
            entries,
        )
        result = {
            "version": VERSION,
            "status": "closed",
            "closure_id": closure["closure_id"],
            "closure_digest": closure["closure_digest"],
            "closed_count": len(entries),
        }
    elif operation == "approve-repair":
        approval_path, approval_record = _one_checkpoint_authority(
            authorities,
            prefix=("repairs", "approvals"),
        )
        index_path, index = _one_checkpoint_authority(
            authorities,
            prefix=("repairs", "approval-index"),
        )
        approval_digest = _raw_sha256(
            approval_record.get("approval_digest"),
            "repair_approval.approval_digest",
        )
        approval_body = {
            key: value for key, value in approval_record.items() if key != "approval_digest"
        }
        approval = _normalize_repair_approval(approval_body)
        if approval_digest != _digest(approval):
            _fail("invalid-repair-approval", "checkpoint repair approval digest is invalid")
        approval_key = _repair_approval_index_key(approval["source"], approval["target"])
        if (
            checkpoint["natural_key"] != approval["approval_id"]
            or approval_path != f"repairs/approvals/{approval['approval_id']}.json"
            or index_path != f"repairs/approval-index/{approval_key}.json"
        ):
            _fail(
                "invalid-wal-history",
                "repair approval checkpoint authority paths or key are invalid",
            )
        _exact_fields(
            index,
            "repair_approval_index",
            {
                "version",
                "kind",
                "approval_key",
                "approval_id",
                "approval_digest",
                "source",
                "target",
                "index_digest",
            },
        )
        index_body = {key: value for key, value in index.items() if key != "index_digest"}
        if (
            index.get("version") != VERSION
            or index.get("kind") != "repair-approval-index"
            or index.get("approval_key") != approval_key
            or index.get("approval_id") != approval["approval_id"]
            or index.get("approval_digest") != approval_digest
            or index.get("source") != approval["source"]
            or index.get("target") != approval["target"]
            or index.get("index_digest") != _digest(index_body)
        ):
            _fail("invalid-repair-approval-index", "checkpoint repair approval index is invalid")
        legacy_result = {
            "version": VERSION,
            "status": "approved",
            "approval_id": approval["approval_id"],
            "approval_digest": approval_digest,
            "approval_key": approval_key,
            "expires_at": approval["expires_at"],
        }
        current_result = {
            **legacy_result,
            "target_lifecycle_changed_at": approval["interaction"]["approved_at"],
        }
        matching_results = [
            candidate
            for candidate in (legacy_result, current_result)
            if _digest(candidate) == checkpoint["result_digest"]
        ]
        if len(matching_results) != 1:
            _fail(
                "wal-history-result-drift",
                "repair approval authority matches neither legacy nor current WAL result",
            )
        result = matching_results[0]
        _validate_published_closure_authority(
            store,
            approval["publication"],
            approval["source"],
            recover_publication=recover_publication,
        )
        _validate_approve_repair_checkpoint_projection(
            checkpoint,
            approval_path,
            approval_record,
            index_path,
            index,
        )
    else:
        _fail("invalid-wal-history", f"unsupported checkpoint operation: {operation}")
    if _digest(result) != checkpoint["result_digest"]:
        _fail("wal-history-result-drift", "domain authority cannot reconstruct exact WAL result")
    if verify_external:
        _verify_checkpoint_external_outputs(
            store,
            checkpoint,
            authorities,
            recover_publication=recover_publication,
            allow_repairable=allow_repairable_external,
            usage_committed=usage_committed,
        )
    return dict(result)


def _active_wal_binds_checkpoint_read_only(
    store: StateStore,
    checkpoint: Mapping[str, Any],
    *,
    required: bool = True,
    require_commit: bool = True,
) -> dict[str, Any] | None:
    """Prove a checkpoint still has its exact retained full intent."""

    operation = checkpoint["operation"]
    natural_key = checkpoint["natural_key"]
    intent_path, commit_path = _wal_paths(operation, natural_key)
    if not store.exists(intent_path):
        if not required:
            return None
        _fail(
            "invalid-wal-history-usage",
            "repairable history checkpoint has no retained active intent",
        )
    intent, _ = store.read_json_without_publication_recovery(
        intent_path,
        max_bytes=MAX_WAL_JSON_BYTES,
    )
    _validate_wal_intent(
        store,
        intent,
        operation,
        allow_committed_legacy_external=True,
    )
    if store.exists(commit_path):
        commit, _ = store.read_json_without_publication_recovery(
            commit_path,
            max_bytes=MAX_WAL_JSON_BYTES,
        )
        _validate_wal_commit(commit, intent)
    else:
        if require_commit:
            _fail(
                "invalid-wal-history-usage",
                "uncommitted history tail has no retained commit",
            )
        commit_body = {
            "version": VERSION,
            "kind": "state-transaction-commit",
            "operation": operation,
            "natural_key": natural_key,
            "intent_digest": intent["intent_digest"],
        }
        commit = {**commit_body, "commit_digest": _digest(commit_body)}
    expected = _build_wal_checkpoint(
        intent,
        commit,
        sequence=checkpoint["sequence"],
        previous_usage_digest=checkpoint["previous_usage_digest"],
    )
    if checkpoint != expected:
        _fail("wal-history-conflict", "uncommitted history tail differs from active WAL")
    return intent


def _enumerate_wal_history_namespace(
    store: StateStore,
) -> tuple[
    tuple[tuple[str, ...], tuple[tuple[str, tuple[str, ...]], ...]],
    tuple[Path, ...],
    tuple[Path, ...],
]:
    """Stream, classify, and bound the complete history namespace first."""

    root = Path("wal-history")
    usage_temp = _wal_history_fixed_temp_name(WAL_HISTORY_USAGE.name)
    root_names: list[str] = []
    operations: list[str] = []
    try:
        for name in store.iter_names(root):
            root_names.append(name)
            if name in {WAL_HISTORY_USAGE.name, usage_temp}:
                continue
            if name.startswith("."):
                _fail_foreign_wal_history_temp(name)
            if SAFE_OBJECT_ID_RE.fullmatch(name) is None or name not in TRANSACTION_OPERATIONS:
                _fail("invalid-wal-history-layout", f"unexpected WAL history entry: {name}")
            operations.append(name)
    except OSError as exc:
        _fail("invalid-wal-history-layout", f"WAL history root is invalid: {exc}")

    checkpoint_paths: list[Path] = []
    temporary_targets: list[Path] = []
    checkpoint_temporary_count = 0
    operation_signatures: list[tuple[str, tuple[str, ...]]] = []
    if usage_temp in root_names:
        temporary_targets.append(WAL_HISTORY_USAGE)
    suffix = f".tmp-{WAL_HISTORY_FIXED_TEMP_PID}-{WAL_HISTORY_FIXED_TEMP_NONCE}"
    for operation in sorted(operations, key=os.fsencode):
        directory = root / operation
        children: list[str] = []
        try:
            for name in store.iter_names(directory):
                children.append(name)
                if name.startswith("."):
                    leaf = name[1 : -len(suffix)] if name.endswith(suffix) else ""
                    if (
                        not name.endswith(suffix)
                        or WAL_HISTORY_LEAF_RE.fullmatch(leaf) is None
                        or name != _wal_history_fixed_temp_name(leaf)
                    ):
                        _fail_foreign_wal_history_temp(name)
                    if checkpoint_temporary_count >= MAX_WAL_HISTORY_RECORDS:
                        _fail(
                            "wal-history-count-limit",
                            "WAL history temporary entry limit exceeded",
                        )
                    temporary_targets.append(directory / leaf)
                    checkpoint_temporary_count += 1
                    continue
                if WAL_HISTORY_LEAF_RE.fullmatch(name) is None:
                    _fail("invalid-wal-history-layout", f"unexpected history leaf: {name}")
                if len(checkpoint_paths) >= MAX_WAL_HISTORY_RECORDS:
                    _fail("wal-history-count-limit", "WAL history record count limit exceeded")
                checkpoint_paths.append(directory / name)
        except OSError as exc:
            _fail(
                "invalid-wal-history-layout",
                f"WAL history operation entry is invalid: {operation}: {exc}",
            )
        operation_signatures.append((operation, tuple(sorted(children, key=os.fsencode))))

    signature = (
        tuple(sorted(root_names, key=os.fsencode)),
        tuple(operation_signatures),
    )
    return (
        signature,
        tuple(sorted(checkpoint_paths, key=lambda path: os.fsencode(str(path)))),
        tuple(sorted(temporary_targets, key=lambda path: os.fsencode(str(path)))),
    )


def _read_wal_history_chain(
    store: StateStore,
    *,
    recover_temporaries: bool,
    allow_adjacent_uncommitted: bool,
    target_path: Path | None = None,
) -> tuple[list[tuple[Path, dict[str, Any], str, tuple[int, int], int]], dict[str, Any]]:
    """Boundedly verify the complete history chain and optional exact member.

    Old-key retry is intentionally the exceptional bounded path: it scans at
    most ``MAX_WAL_HISTORY_RECORDS`` leaves and ``MAX_WAL_HISTORY_BYTES`` bytes.
    New-key and active-key paths never call it.  The selected target must be the
    committed member discovered only after the namespace bound has passed.
    """

    # Validate every fixed helper only after a complete streaming namespace
    # inventory has proved the entry-count bound.  This pass never unlinks.
    store.recover_all_wal_history_temporaries(recover=False)
    baseline_namespace, checkpoint_paths, _ = _enumerate_wal_history_namespace(store)

    records: list[tuple[Path, dict[str, Any], str, tuple[int, int], int]] = []
    total_bytes = 0
    for path in checkpoint_paths:
        operation = path.parts[1]
        name = path.name
        checkpoint, file_digest, identity, size = (
            store.read_json_without_publication_recovery_with_identity(
                path,
                max_bytes=MAX_WAL_HISTORY_RECORD_BYTES,
                fixed_helper_name=_wal_history_fixed_temp_name(name),
            )
        )
        checkpoint = _validate_wal_checkpoint(store, checkpoint, operation)
        if name != f"{_wal_key(operation, checkpoint['natural_key'])}.json":
            _fail("invalid-wal-history-layout", "checkpoint filename does not bind its key")
        records.append((path, checkpoint, file_digest, identity, size))
        total_bytes += size
        if total_bytes > MAX_WAL_HISTORY_BYTES:
            _fail("wal-history-byte-limit", "WAL history aggregate byte limit exceeded")

    records.sort(key=lambda item: item[1]["sequence"])
    usage_states = [_new_wal_history_usage()]
    seen_sequences: set[int] = set()
    for _, checkpoint, _, _, size in records:
        sequence = checkpoint["sequence"]
        expected_usage = usage_states[-1]
        if sequence in seen_sequences or sequence != expected_usage["record_count"] + 1:
            _fail("invalid-wal-history-usage", "WAL history sequence is missing or repeated")
        seen_sequences.add(sequence)
        if checkpoint["previous_usage_digest"] != expected_usage["usage_digest"]:
            _fail("invalid-wal-history-usage", "WAL history usage chain is broken")
        usage_states.append(_project_wal_history_usage(expected_usage, checkpoint, size))

    actual_usage, usage_digest, usage_identity, usage_size = (
        _read_wal_history_usage_binding_read_only(store)
    )
    committed_count = actual_usage["record_count"]
    if committed_count >= len(usage_states) or actual_usage != usage_states[committed_count]:
        _fail("invalid-wal-history-usage", "WAL history usage does not match its prefix")
    uncommitted = records[committed_count:]
    if uncommitted:
        if not allow_adjacent_uncommitted or len(uncommitted) != 1:
            _fail("invalid-wal-history-usage", "WAL history has an uncommitted record tail")
        _active_wal_binds_checkpoint_read_only(store, uncommitted[0][1])
    elif actual_usage != usage_states[-1] or total_bytes != actual_usage["total_bytes"]:
        _fail("invalid-wal-history-usage", "WAL history usage does not match its records")

    terminal_namespace, terminal_paths, _ = _enumerate_wal_history_namespace(store)
    if terminal_namespace != baseline_namespace or terminal_paths != checkpoint_paths:
        _fail("wal-history-changed", "WAL history namespace changed during chain verification")
    for path, checkpoint, file_digest, identity, size in records:
        rebound, rebound_digest, rebound_identity, rebound_size = (
            store.read_json_without_publication_recovery_with_identity(
                path,
                max_bytes=MAX_WAL_HISTORY_RECORD_BYTES,
                fixed_helper_name=_wal_history_fixed_temp_name(path.name),
            )
        )
        if (
            rebound != checkpoint
            or rebound_digest != file_digest
            or rebound_identity != identity
            or rebound_size != size
        ):
            _fail("wal-history-changed", f"checkpoint changed during chain verification: {path}")
    rebound_usage, rebound_usage_digest, rebound_usage_identity, rebound_usage_size = (
        _read_wal_history_usage_binding_read_only(store)
    )
    if (
        rebound_usage != actual_usage
        or rebound_usage_digest != usage_digest
        or rebound_usage_identity != usage_identity
        or rebound_usage_size != usage_size
    ):
        _fail("wal-history-changed", "WAL history usage changed during chain verification")
    final_namespace, final_paths, _ = _enumerate_wal_history_namespace(store)
    if final_namespace != baseline_namespace or final_paths != checkpoint_paths:
        _fail("wal-history-changed", "WAL history namespace changed during chain verification")

    if target_path is not None:
        member = next((record for record in records if record[0] == target_path), None)
        if member is None or member[1]["sequence"] > committed_count:
            _fail("invalid-wal-history-membership", "checkpoint is not a committed chain member")
    if recover_temporaries:
        # Recovery is history-specific and begins only after the entire fixed
        # namespace, chain, usage, and every leaf binding have passed the
        # read-only proof.  Re-read the resulting namespace strictly.
        store.recover_all_wal_history_temporaries()
        return _read_wal_history_chain(
            store,
            recover_temporaries=False,
            allow_adjacent_uncommitted=allow_adjacent_uncommitted,
            target_path=target_path,
        )
    return records, actual_usage


def audit_wal_history(state_root: Path) -> dict[str, Any]:
    """Explicitly validate, converge, and revalidate the compact history."""

    with _state_lock(state_root, create=False) as store:
        # Phase one is wholly read-only.  Validate every helper name/object and
        # the complete bounded chain before cleanup or pending-WAL recovery can
        # alter persistent state.
        store.recover_all_wal_history_temporaries(recover=False)
        preflight_records, preflight_usage = _read_wal_history_chain(
            store,
            recover_temporaries=False,
            allow_adjacent_uncommitted=True,
        )
        for _, checkpoint, _, _, _ in preflight_records:
            _reconstruct_checkpoint_result(
                store,
                checkpoint,
                recover_publication=False,
                allow_repairable_external=True,
                usage_committed=(checkpoint["sequence"] <= preflight_usage["record_count"]),
            )

        # Only a fully valid namespace may converge.  A checkpoint/usage crash
        # tail retains its active intent until this pass commits the usage state.
        store.recover_all_wal_history_temporaries()
        _recover_pending_wal(store, compact_committed=False)

        # Phase one proved every authority and any retained-WAL repair path.
        # Normal reads may now converge valid domain/external helper aliases.
        converged_records, _ = _read_wal_history_chain(
            store,
            recover_temporaries=False,
            allow_adjacent_uncommitted=False,
        )
        for _, checkpoint, _, _, _ in converged_records:
            _reconstruct_checkpoint_result(store, checkpoint)

        # The terminal audit is strict and read-only: no helper or uncommitted
        # tail may remain, and every domain authority is checked again.
        store.recover_all_wal_history_temporaries(recover=False)
        records, actual_usage = _read_wal_history_chain(
            store,
            recover_temporaries=False,
            allow_adjacent_uncommitted=False,
        )
        for _, checkpoint, _, _, _ in records:
            _reconstruct_checkpoint_result(
                store,
                checkpoint,
                recover_publication=False,
            )
        return {
            "version": VERSION,
            "status": "clean",
            "record_count": len(records),
            "total_bytes": actual_usage["total_bytes"],
            "usage_digest": actual_usage["usage_digest"],
        }


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
    """Serialize the protected name, identity, POSIX policy, and ACL chain.

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
        device, inode, file_type, owner, group, permissions, acl_digest = signal
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
                "acl_digest": acl_digest,
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
        "acl_digest",
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
        acl_digest = _require_string(entry["acl_digest"], "wal.parent.acl_digest")
        if HEX64_RE.fullmatch(acl_digest) is None:
            _fail("invalid-wal", "external parent ACL digest must be raw SHA-256")
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
                "acl_digest": acl_digest,
            }
        )
    final = normalized[-1]
    if final["owner"] != os.geteuid() or final["permissions"] & 0o077:
        _fail("invalid-wal", "external output parent binding is not owner-private")
    return normalized


def _normalize_external_output_outside_state_root(state_root: Path, path: Path) -> Path:
    """Return one canonical output path only when it is outside managed state.

    The protected property is the managed state root's object identity and
    namespace layout: an external after-image must never name the root itself or
    any entry beneath it.  This lexical check handles canonical ``..`` paths;
    descriptor-bound identity is checked separately once the state root is open.
    """

    root = Path(os.path.abspath(os.fspath(state_root)))
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        absolute.relative_to(root)
    except ValueError:
        return absolute
    _fail(
        "output-inside-state-root",
        f"external output must be outside the managed state root: {absolute}",
    )


@contextmanager
def _bound_external_parent(
    path: Path, expected_binding: Any | None = None
) -> Iterator[tuple[StateStore, list[dict[str, Any]]]]:
    """Open an existing external parent without ever recreating its path."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        store = StateStore(absolute.parent, create=False, sensitive_root=False)
    except StateError as exc:
        if exc.code in {"missing-state-root", "missing-state-chain"}:
            _fail(
                "external-parent-missing",
                f"bound external output parent disappeared: {absolute.parent}",
            )
        if exc.code in {
            "unsafe-owner",
            "unsafe-permissions",
            "unsafe-state-chain-policy",
            "state-chain-policy-changed",
            "custody-acl-allows-access",
            "state-acl-present",
        }:
            _fail(
                "external-parent-policy-changed",
                f"bound external output parent policy changed: {absolute.parent}",
            )
        if exc.code in {"unsafe-path", "unsafe-state-chain", "state-chain-replaced"}:
            _fail(
                "external-parent-replaced",
                f"bound external output parent is no longer the directory chain: {absolute.parent}",
            )
        if exc.code == "state-chain-unreadable":
            _fail(
                "external-parent-unreadable",
                f"bound external output parent became unreadable: {absolute.parent}",
            )
        if exc.code in {"state-chain-revalidation-failed", "acl-revalidation-failed"}:
            _fail(
                "external-parent-revalidation-failed",
                f"could not open bound external output parent: {absolute.parent}",
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
                    for field in ("owner", "group", "permissions", "acl_digest")
                ):
                    _fail(
                        "external-parent-policy-changed",
                        f"external output parent access policy changed: {absolute.parent}",
                    )
        yield store, actual
        store._bind_state_chain("external output completion")
    finally:
        store.close()


def _validate_external_output_target(
    store: StateStore,
    path: Path,
    *,
    parent: StateStore | None = None,
) -> Path:
    """Reject lexical descendants and descriptor aliases of managed state.

    Device, inode, and file type are the only compared signals because they
    define object identity.  Directory timestamps, sizes, and link counts are
    intentionally irrelevant: ordinary child-entry churn may change them
    without moving an external output into managed state.
    """

    absolute = _normalize_external_output_outside_state_root(store.root, path)
    store._bind_state_chain("external output boundary validation")
    root_info = os.fstat(store.root_fd)
    root_identity = (
        root_info.st_dev,
        root_info.st_ino,
        stat.S_IFMT(root_info.st_mode),
    )

    def reject_descriptor_alias(bound_parent: StateStore) -> None:
        parent_binding = _external_parent_binding(bound_parent)
        if any(
            (
                entry["device"],
                entry["inode"],
                entry["file_type"],
            )
            == root_identity
            for entry in parent_binding
        ):
            _fail(
                "output-inside-state-root",
                f"external output parent resolves inside the managed state root: {absolute}",
            )
        try:
            target_info = os.stat(
                absolute.name,
                dir_fd=bound_parent.root_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        except OSError as exc:
            _fail(
                "external-output-revalidation-failed",
                f"could not inspect external output target {absolute}: {exc}",
            )
        target_identity = (
            target_info.st_dev,
            target_info.st_ino,
            stat.S_IFMT(target_info.st_mode),
        )
        if target_identity == root_identity:
            _fail(
                "output-inside-state-root",
                f"external output resolves to the managed state root: {absolute}",
            )

    if parent is not None:
        reject_descriptor_alias(parent)
    else:
        with _bound_external_parent(absolute) as (bound_parent, _):
            reject_descriptor_alias(bound_parent)
    return absolute


def _read_optional_external(
    parent: StateStore,
    target: Path,
    *,
    recover_publication: bool = True,
) -> tuple[bytes, str] | None:
    leaf = Path(target.name)
    if not parent.exists(leaf):
        return None
    if recover_publication:
        return parent.read_bytes(leaf, max_bytes=MAX_PUBLICATION_JSON_BYTES)
    return parent.read_bytes_without_publication_recovery(
        leaf,
        max_bytes=MAX_PUBLICATION_JSON_BYTES,
    )


def _read_state_json(
    store: StateStore,
    relative: Path | str,
    *,
    recover_publication: bool,
) -> dict[str, Any]:
    if recover_publication:
        return store.read_json(relative)[0]
    return store.read_json_without_publication_recovery(relative)[0]


def _planned_external_write(
    store: StateStore, path: Path, value: Mapping[str, Any], *, immutable: bool
) -> dict[str, Any]:
    absolute = _normalize_external_output_outside_state_root(store.root, path)
    payload = _canonical_bytes(value)
    if len(payload) > MAX_PUBLICATION_JSON_BYTES:
        _fail(
            "output-too-large",
            f"planned external JSON exceeds {MAX_PUBLICATION_JSON_BYTES} bytes",
        )
    after_digest = hashlib.sha256(payload).hexdigest()
    with _bound_external_parent(absolute) as (parent, parent_binding):
        _validate_external_output_target(store, absolute, parent=parent)
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
    store: StateStore,
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
    for raw_write in writes:
        write = _require_object(raw_write, "wal.write")
        if write["scope"] == "external":
            _validate_external_output_target(store, Path(write["path"]))
    if legacy_external and not allow_committed_legacy_external:
        _fail(
            "legacy-external-wal-unbound",
            "pending legacy external WAL has no recoverable parent identity binding",
        )
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


def _preflight_external_writes(
    intent: Mapping[str, Any],
    *,
    require_after: bool = False,
    recover_publication: bool = True,
) -> None:
    """Reject rebound external destinations before applying any state after-image."""

    for raw_write in intent["writes"]:
        write = _require_object(raw_write, "wal.write")
        if write["scope"] != "external":
            continue
        target = Path(write["path"])
        with _bound_external_parent(target, write["parent_binding"]) as (parent, _):
            current = _read_optional_external(
                parent,
                target,
                recover_publication=recover_publication,
            )
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


def _preflight_state_writes(
    store: StateStore,
    intent: Mapping[str, Any],
    *,
    committed: bool,
    recover_publication: bool = True,
) -> None:
    """Validate every state target before any transaction after-image is applied."""

    for raw_write in intent["writes"]:
        write = _require_object(raw_write, "wal.write")
        if write["scope"] != "state":
            continue
        target = Path(write["path"])
        if store.exists(target):
            current = (
                store.read_bytes(target)
                if recover_publication
                else store.read_bytes_without_publication_recovery(target)
            )
            current_digest = current[1]
        else:
            current_digest = None
        if committed and write["immutable"] is not True:
            # A later committed transaction may legitimately advance a mutable
            # case, pointer, or active publication record, but cannot erase it.
            if current_digest is None:
                _fail(
                    "wal-target-drift",
                    f"committed mutable WAL target is missing: {target}",
                )
            continue
        allowed = (
            {write["after_sha256"]}
            if committed
            else {write["before_sha256"], write["after_sha256"]}
        )
        if current_digest not in allowed:
            _fail(
                "wal-target-drift",
                (
                    f"committed immutable WAL target is not its exact after-image: {target}"
                    if committed
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


def _verify_committed_legacy_external_after_images(
    intent: Mapping[str, Any],
    *,
    recover_publication: bool = True,
) -> None:
    """Read-only check for committed v1 outputs that predate parent bindings."""

    for raw_write in intent["writes"]:
        write = _require_object(raw_write, "wal.write")
        if write["scope"] != "external" or "parent_binding" in write:
            continue
        target = Path(write["path"])
        with _bound_external_parent(target) as (parent, _):
            current = _read_optional_external(
                parent,
                target,
                recover_publication=recover_publication,
            )
            if current is None or current[1] != write["after_sha256"]:
                _fail(
                    "legacy-external-wal-unbound",
                    "committed legacy external WAL after-image is missing or changed; "
                    "automatic replay is unsafe without its original parent identity",
                )


def _validate_wal_intent_domain(
    store: StateStore,
    intent: Mapping[str, Any],
    *,
    committed: bool,
    recover_publication: bool,
) -> None:
    if intent["operation"] == "stage":
        _validate_stage_intent_domain(
            store,
            intent,
            recover_publication=recover_publication,
        )
    elif intent["operation"] == "approve-repair":
        _validate_approve_repair_intent_lifecycle(
            store,
            intent,
            allow_legacy_result=committed,
            recover_publication=recover_publication,
        )
    elif intent["operation"] == "complete-audit":
        _validate_complete_audit_intent_receipts(
            store,
            intent,
            recover_publication=recover_publication,
        )
    elif intent["operation"] == "finalize-publication":
        _validate_finalize_publication_intent(
            store,
            intent,
            recover_publication=recover_publication,
        )
    elif intent["operation"] == "close-publication":
        _validate_close_publication_intent_commits(
            store,
            intent,
            recover_publication=recover_publication,
        )


def _apply_wal_intent(store: StateStore, intent: Mapping[str, Any]) -> None:
    store._bind_state_namespace("before WAL after-image application")
    _validate_wal_intent_domain(
        store,
        intent,
        committed=False,
        recover_publication=True,
    )
    _preflight_state_writes(store, intent, committed=False)
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
    store._bind_state_namespace("after WAL after-image application")


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


def _sync_retirement_after_images(store: StateStore, intent: Mapping[str, Any]) -> None:
    """Durably validate compacted outcomes while the full intent is still present."""

    for raw_write in intent["writes"]:
        write = _require_object(raw_write, "wal.write")
        target = Path(write["path"])
        if write["scope"] == "state":
            try:
                _, digest, identity, _ = store.read_json_with_identity(target)
            except StateError as exc:
                if exc.code == "missing-file":
                    _fail("wal-retirement-state-missing", f"WAL state target is missing: {target}")
                raise
            if digest == write["after_sha256"]:
                store.sync_exact(target, digest, expected_identity=identity)
            elif write["immutable"] is True:
                _fail(
                    "wal-retirement-authority-drift",
                    f"immutable WAL authority changed before retirement: {target}",
                )
            # Mutable state can legitimately carry a later committed after-image.
            # Its original digest remains in the checkpoint and its immutable
            # transaction receipt is validated separately.
            continue
        binding = write.get("parent_binding")
        with _bound_external_parent(target, binding) as (parent, _):
            current = _read_optional_external(parent, target)
            if current is None or current[1] != write["after_sha256"]:
                if binding is None:
                    _fail(
                        "legacy-external-wal-unbound",
                        "legacy external WAL cannot retire after its exact output changed",
                    )
                _fail(
                    "wal-retirement-external-drift",
                    f"external WAL after-image changed before retirement: {target}",
                )
            parent.sync_exact(
                Path(target.name),
                write["after_sha256"],
                max_bytes=MAX_PUBLICATION_JSON_BYTES,
            )


def _load_wal_checkpoint(
    store: StateStore, operation: str, natural_key: str
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    path = _wal_history_path(operation, natural_key)
    if not store.exists(path):
        return None
    records, _ = _read_wal_history_chain(
        store,
        recover_temporaries=True,
        allow_adjacent_uncommitted=False,
        target_path=path,
    )
    member = next((record for record in records if record[0] == path), None)
    if member is None:
        _fail("invalid-wal-history-membership", "checkpoint is not a committed chain member")
    checkpoint = member[1]
    checkpoint = _validate_wal_checkpoint(
        store,
        checkpoint,
        operation,
        expected_natural_key=natural_key,
    )
    if path.name != f"{_wal_key(operation, natural_key)}.json":
        _fail("invalid-wal-history", "WAL checkpoint filename does not bind its key")
    result = _reconstruct_checkpoint_result(store, checkpoint)
    return checkpoint, result


def _load_wal_checkpoint_binding_read_only(
    store: StateStore,
    operation: str,
    natural_key: str,
) -> dict[str, Any] | None:
    """Read only the exact retired first-writer binding.

    Usage-chain recovery and result reconstruction intentionally happen only
    after the request digest is known not to conflict.  A linked checkpoint
    helper is validated in place by the read-only publication reader, so even
    a rejected retry leaves every persistent name, object, and byte unchanged.
    """

    path = _wal_history_path(operation, natural_key)
    if not store.exists(path):
        return None
    records, _ = _read_wal_history_chain(
        store,
        recover_temporaries=False,
        allow_adjacent_uncommitted=True,
        target_path=path,
    )
    member = next((record for record in records if record[0] == path), None)
    if member is None:
        _fail("invalid-wal-history-membership", "checkpoint is not a committed chain member")
    checkpoint = member[1]
    checkpoint = _validate_wal_checkpoint(
        store,
        checkpoint,
        operation,
        expected_natural_key=natural_key,
    )
    if path.name != f"{_wal_key(operation, natural_key)}.json":
        _fail("invalid-wal-history", "WAL checkpoint filename does not bind its key")
    return checkpoint


def _preflight_wal_checkpoint_capacity(store: StateStore, intent: Mapping[str, Any]) -> None:
    """Prove retirement capacity before an intent or any after-image is published."""

    commit_body = {
        "version": VERSION,
        "kind": "state-transaction-commit",
        "operation": intent["operation"],
        "natural_key": intent["natural_key"],
        "intent_digest": intent["intent_digest"],
    }
    commit = {**commit_body, "commit_digest": _digest(commit_body)}
    usage = _read_wal_history_usage(store)
    checkpoint = _build_wal_checkpoint(
        intent,
        commit,
        sequence=usage["record_count"] + 1,
        previous_usage_digest=usage["usage_digest"],
    )
    checkpoint_size = len(_canonical_bytes(checkpoint))
    if checkpoint["sequence"] > MAX_WAL_HISTORY_RECORDS:
        _fail("wal-history-count-limit", "WAL history record count limit reached")
    if usage["total_bytes"] + checkpoint_size > MAX_WAL_HISTORY_BYTES:
        _fail("wal-history-byte-limit", "WAL history aggregate byte limit reached")


def _retire_committed_wal(
    store: StateStore,
    intent: Mapping[str, Any],
    commit: Mapping[str, Any],
    *,
    intent_path: Path,
    commit_path: Path | None,
    intent_file_digest: str,
    commit_file_digest: str | None,
    intent_identity: tuple[int, int],
    commit_identity: tuple[int, int] | None,
) -> dict[str, Any]:
    """Replace one full committed WAL pair with a compact chained checkpoint."""

    usage = _read_wal_history_usage(store)
    history_path = _wal_history_path(intent["operation"], intent["natural_key"])
    store.recover_wal_history_temporary(history_path)
    checkpoint_file_digest: str | None = None
    checkpoint_identity: tuple[int, int] | None = None
    checkpoint_exists = store.exists(history_path)
    if checkpoint_exists:
        checkpoint, checkpoint_file_digest, checkpoint_identity, checkpoint_size = (
            store.read_json_with_identity(
                history_path,
                max_bytes=MAX_WAL_HISTORY_RECORD_BYTES,
            )
        )
        checkpoint = _validate_wal_checkpoint(
            store,
            checkpoint,
            intent["operation"],
            expected_natural_key=intent["natural_key"],
        )
        expected = _build_wal_checkpoint(
            intent,
            commit,
            sequence=checkpoint["sequence"],
            previous_usage_digest=checkpoint["previous_usage_digest"],
        )
        if checkpoint != expected:
            _fail("wal-history-conflict", "existing checkpoint differs from active WAL")
    else:
        checkpoint = _build_wal_checkpoint(
            intent,
            commit,
            sequence=usage["record_count"] + 1,
            previous_usage_digest=usage["usage_digest"],
        )
        checkpoint_size = len(_canonical_bytes(checkpoint))
        if checkpoint["sequence"] > MAX_WAL_HISTORY_RECORDS:
            _fail("wal-history-count-limit", "WAL history record count limit reached")
        if usage["total_bytes"] + checkpoint_size > MAX_WAL_HISTORY_BYTES:
            _fail("wal-history-byte-limit", "WAL history aggregate byte limit reached")

    # Validate every permanent authority and durably sync every after-image
    # before publishing a new compact checkpoint or completing an interrupted
    # retirement.  Until publication, the full intent remains the only recovery
    # authority for an external leaf; it is also retained until both checks pass.
    _reconstruct_checkpoint_result(store, checkpoint)
    _sync_retirement_after_images(store, intent)
    if not checkpoint_exists:
        checkpoint_file_digest = store.write_wal_history_json(
            history_path,
            checkpoint,
            immutable=True,
        )
        _, stored_digest, checkpoint_identity, stored_size = store.read_json_with_identity(
            history_path,
            max_bytes=MAX_WAL_HISTORY_RECORD_BYTES,
        )
        if stored_digest != checkpoint_file_digest or stored_size != checkpoint_size:
            _fail("wal-history-write-failed", "stored checkpoint bytes differ")
    assert checkpoint_file_digest is not None and checkpoint_identity is not None
    store.sync_exact(
        history_path,
        checkpoint_file_digest,
        expected_identity=checkpoint_identity,
        max_bytes=MAX_WAL_HISTORY_RECORD_BYTES,
    )
    _advance_wal_history_usage(store, usage, checkpoint, checkpoint_size)
    # Commit-first cleanup can only leave either a complete pair or an intent
    # beside the authoritative checkpoint.  It never creates an orphan commit.
    if commit_path is not None:
        assert commit_file_digest is not None and commit_identity is not None
        store.unlink_exact(
            commit_path,
            commit_file_digest,
            expected_identity=commit_identity,
        )
    store.unlink_exact(
        intent_path,
        intent_file_digest,
        expected_identity=intent_identity,
    )
    return checkpoint


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
                store._bind_state_namespace("before transaction commit")
                stored_digest = store.write_json(commit_path, commit, immutable=True)
                if stored_digest != expected_file_digest:
                    _fail("wal-commit-write-failed", "WAL commit write returned the wrong digest")
                store._bind_state_namespace("after transaction commit")
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


def _preflight_transaction_binding_read_only(
    store: StateStore,
    *,
    operation: str,
    natural_key: str,
    request: Mapping[str, Any],
    approved_intent_upper_bound: int | None = None,
) -> None:
    """Reject an exact first-writer conflict without persistent mutation."""

    request_digest = _digest(request)
    intent_path, commit_path = _wal_paths(operation, natural_key)
    history_path = _wal_history_path(operation, natural_key)
    committed = store.exists(commit_path)
    if store.exists(intent_path):
        intent, _ = store.read_json_without_publication_recovery(
            intent_path,
            max_bytes=MAX_WAL_JSON_BYTES,
        )
        _validate_wal_intent(
            store,
            intent,
            operation,
            allow_committed_legacy_external=(committed or store.exists(history_path)),
        )
        if intent["natural_key"] != natural_key or intent["request_digest"] != request_digest:
            _fail("wal-request-conflict", "transaction key already binds a different request")
        if (
            approved_intent_upper_bound is not None
            and len(_canonical_bytes(intent)) > approved_intent_upper_bound
        ):
            _fail(
                "invalid-selection-preflight",
                "persisted publication WAL exceeds its approved upper bound",
            )
        return
    if committed:
        return
    checkpoint = _load_wal_checkpoint_binding_read_only(store, operation, natural_key)
    if checkpoint is None:
        return
    if checkpoint["request_digest"] != request_digest:
        _fail("wal-request-conflict", "transaction key already binds a different request")
    if (
        approved_intent_upper_bound is not None
        and checkpoint["intent_bytes"] > approved_intent_upper_bound
    ):
        _fail(
            "invalid-selection-preflight",
            "retired publication WAL exceeded its approved upper bound",
        )


def _preflight_existing_transaction_domain_read_only(
    store: StateStore,
    *,
    operation: str,
    natural_key: str,
) -> None:
    """Validate an existing active or retired domain authority without mutation."""

    intent_path, commit_path = _wal_paths(operation, natural_key)
    history_path = _wal_history_path(operation, natural_key)
    has_intent = store.exists(intent_path)
    has_commit = store.exists(commit_path)
    has_history = store.exists(history_path)
    if not has_intent:
        if has_commit:
            _fail("invalid-wal-layout", "WAL commit exists without its intent")
        if not has_history:
            return
        checkpoint = _load_wal_checkpoint_binding_read_only(store, operation, natural_key)
        assert checkpoint is not None
        _reconstruct_checkpoint_result(
            store,
            checkpoint,
            recover_publication=False,
        )
        return
    intent = store.read_json_without_publication_recovery(
        intent_path,
        max_bytes=MAX_WAL_JSON_BYTES,
    )[0]
    legacy_external = _validate_wal_intent(
        store,
        intent,
        operation,
        allow_committed_legacy_external=(has_commit or has_history),
    )
    if intent.get("natural_key") != natural_key:
        _fail("invalid-wal-layout", "WAL intent natural key differs from its lookup key")
    if has_commit:
        commit = store.read_json_without_publication_recovery(
            commit_path,
            max_bytes=MAX_WAL_JSON_BYTES,
        )[0]
        _validate_wal_commit(commit, intent)
    _validate_wal_intent_domain(
        store,
        intent,
        committed=(has_commit or has_history),
        recover_publication=False,
    )
    _preflight_state_writes(
        store,
        intent,
        committed=(has_commit or has_history),
        recover_publication=False,
    )
    if legacy_external:
        _verify_committed_legacy_external_after_images(
            intent,
            recover_publication=False,
        )
    else:
        _preflight_external_writes(
            intent,
            recover_publication=False,
        )
    if has_history:
        checkpoint = _load_wal_checkpoint_binding_read_only(store, operation, natural_key)
        assert checkpoint is not None
        _reconstruct_checkpoint_result(
            store,
            checkpoint,
            recover_publication=False,
        )


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

    store._bind_state_namespace("before transaction binding preflight")
    captured_at = _timestamp(captured_at, "transaction.captured_at")
    request_digest = _digest(request)
    intent_path, commit_path = _wal_paths(operation, natural_key)

    # First-writer binding is checked before recovery can compact any other
    # transaction or advance history usage.  A request conflict is therefore a
    # strictly read-only failure for persistent state.
    _preflight_transaction_binding_read_only(
        store,
        operation=operation,
        natural_key=natural_key,
        request=request,
        approved_intent_upper_bound=approved_intent_upper_bound,
    )

    # Callers perform operation-specific validation before entering this
    # function.  Once the exact key is known not to conflict, recover pending
    # work and compact prior committed WAL while retaining this transaction.
    _recover_pending_wal(
        store,
        compact_committed=True,
        retain_transaction=(operation, natural_key),
    )
    store._bind_state_namespace("before transaction")
    retired = _load_wal_checkpoint(store, operation, natural_key)
    if retired is not None:
        checkpoint, retired_result = retired
        if checkpoint["request_digest"] != request_digest:
            _fail("wal-request-conflict", "transaction key already binds a different request")
        if (
            approved_intent_upper_bound is not None
            and checkpoint["intent_bytes"] > approved_intent_upper_bound
        ):
            _fail(
                "invalid-selection-preflight",
                "retired publication WAL exceeded its approved upper bound",
            )
        store._bind_state_namespace("after retired transaction lookup")
        return retired_result
    legacy_external = False
    committed = store.exists(commit_path)
    if store.exists(intent_path):
        intent, _ = store.read_json(intent_path)
        legacy_external = _validate_wal_intent(
            store,
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
        _validate_wal_intent(store, intent, operation)
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
        _preflight_wal_checkpoint_capacity(store, intent)
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
    store._bind_state_namespace("after transaction")
    return dict(_require_object(intent["result"], "wal.result"))


def _preflight_active_wal_namespace(
    store: StateStore,
) -> list[tuple[str, tuple[str, ...]]]:
    """Stream and cap every active WAL name/object before payload recovery."""

    operations: list[str] = []
    try:
        for operation in store.iter_names(Path("wal")):
            if (
                SAFE_OBJECT_ID_RE.fullmatch(operation) is None
                or operation not in TRANSACTION_OPERATIONS
            ):
                _fail("invalid-wal-layout", f"unsafe WAL operation directory: {operation}")
            operations.append(operation)
    except OSError as exc:
        _fail("invalid-wal-layout", f"WAL root is not a private directory: {exc}")

    transaction_keys: set[tuple[str, str]] = set()
    object_sizes: dict[tuple[int, int], int] = {}
    bindings: dict[tuple[str, str], tuple[int, int, int, int, int, int, int]] = {}
    inventory: list[tuple[str, tuple[str, ...]]] = []
    entry_count = 0
    aggregate_bytes = 0
    maximum_entries = MAX_ACTIVE_WAL_TRANSACTIONS * 4
    for operation in sorted(operations, key=os.fsencode):
        directory = Path("wal") / operation
        names: list[str] = []
        try:
            with store.open_dir(directory) as directory_fd:
                with os.scandir(directory_fd) as entries:
                    for entry in entries:
                        name = entry.name
                        leaf = name
                        if name.startswith("."):
                            match = WAL_TEMP_RE.fullmatch(name)
                            if match is None:
                                _fail(
                                    "unsafe-helper-temp",
                                    f"foreign WAL temporary entry: {name}",
                                )
                            leaf = match.group("leaf")
                        elif WAL_LEAF_RE.fullmatch(name) is None:
                            _fail("invalid-wal-layout", f"unexpected WAL entry: {name}")
                        entry_count += 1
                        if entry_count > maximum_entries:
                            _fail(
                                "active-wal-count-limit",
                                "active WAL namespace entry limit exceeded",
                            )
                        transaction_keys.add((operation, leaf[:64]))
                        if len(transaction_keys) > MAX_ACTIVE_WAL_TRANSACTIONS:
                            _fail(
                                "active-wal-count-limit",
                                f"active WAL exceeds {MAX_ACTIVE_WAL_TRANSACTIONS} transactions",
                            )
                        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        if (
                            not stat.S_ISREG(info.st_mode)
                            or stat.S_ISLNK(info.st_mode)
                            or info.st_uid != os.geteuid()
                            or stat.S_IMODE(info.st_mode) != 0o600
                            or info.st_nlink not in {1, 2}
                        ):
                            _fail(
                                "invalid-wal-layout",
                                f"WAL entry is not a private regular file: {directory / name}",
                            )
                        if info.st_size > MAX_WAL_JSON_BYTES:
                            _fail(
                                "active-wal-byte-limit",
                                f"active WAL leaf is too large: {directory / name}",
                            )
                        identity = (info.st_dev, info.st_ino)
                        prior_size = object_sizes.get(identity)
                        if prior_size is None:
                            object_sizes[identity] = info.st_size
                            aggregate_bytes += info.st_size
                            if aggregate_bytes > MAX_ACTIVE_WAL_BYTES:
                                _fail(
                                    "active-wal-byte-limit",
                                    f"active WAL exceeds {MAX_ACTIVE_WAL_BYTES} aggregate bytes",
                                )
                        elif prior_size != info.st_size:
                            _fail(
                                "wal-layout-changed",
                                "active WAL alias size changed during inventory: "
                                f"{directory / name}",
                            )
                        bindings[(operation, name)] = (
                            info.st_dev,
                            info.st_ino,
                            stat.S_IFMT(info.st_mode),
                            info.st_uid,
                            stat.S_IMODE(info.st_mode),
                            info.st_nlink,
                            info.st_size,
                        )
                        names.append(name)
        except OSError as exc:
            _fail(
                "invalid-wal-layout",
                f"WAL operation entry is not a private directory: {operation}: {exc}",
            )
        inventory.append((operation, tuple(sorted(names, key=os.fsencode))))

    # The count/byte caps now hold for the complete namespace.  Open every
    # captured name without reading payload bytes to bind object identity and
    # ACL policy before any helper cleanup may occur.
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    for operation, captured_names in inventory:
        directory = Path("wal") / operation
        with store.open_dir(directory) as directory_fd:
            for name in captured_names:
                try:
                    fd = os.open(name, flags, dir_fd=directory_fd)
                except OSError as exc:
                    _fail("invalid-wal-layout", f"cannot open active WAL entry {name}: {exc}")
                try:
                    opened = os.fstat(fd)
                    opened_binding = (
                        opened.st_dev,
                        opened.st_ino,
                        stat.S_IFMT(opened.st_mode),
                        opened.st_uid,
                        stat.S_IMODE(opened.st_mode),
                        opened.st_nlink,
                        opened.st_size,
                    )
                    if opened_binding != bindings[(operation, name)]:
                        _fail(
                            "wal-layout-changed",
                            f"active WAL entry changed after inventory: {directory / name}",
                        )
                    try:
                        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError as exc:
                        _fail(
                            "wal-layout-changed",
                            f"active WAL entry could not be rebound: {directory / name}: {exc}",
                        )
                    named_binding = (
                        named.st_dev,
                        named.st_ino,
                        stat.S_IFMT(named.st_mode),
                        named.st_uid,
                        stat.S_IMODE(named.st_mode),
                        named.st_nlink,
                        named.st_size,
                    )
                    if named_binding != bindings[(operation, name)]:
                        _fail(
                            "wal-layout-changed",
                            f"active WAL name changed after inventory: {directory / name}",
                        )
                    _acl_digest(fd, str(store.root / directory / name), sensitive=True)
                finally:
                    os.close(fd)
    return inventory


def _recover_pending_wal(
    store: StateStore,
    *,
    compact_committed: bool = False,
    retain_transaction: tuple[str, str] | None = None,
) -> None:
    store._bind_state_namespace("before WAL recovery")
    validated: list[dict[str, Any]] = []
    inventory = _preflight_active_wal_namespace(store)
    for operation, inventory_names in inventory:
        directory = Path("wal") / operation
        try:
            store.recover_wal_temporaries(
                directory,
                names=inventory_names,
                recover=False,
            )
        except OSError as exc:
            _fail(
                "invalid-wal-layout",
                f"WAL operation entry is not a private directory: {operation}: {exc}",
            )
        names = [name for name in inventory_names if WAL_LEAF_RE.fullmatch(name) is not None]

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
                intent, intent_file_digest, intent_identity, _ = (
                    store.read_json_without_publication_recovery_with_identity(
                        intent_path,
                        max_bytes=MAX_WAL_JSON_BYTES,
                    )
                )
            except OSError as exc:
                _fail(
                    "invalid-wal-layout",
                    f"WAL intent is not a private regular JSON file: {intent_path}: {exc}",
                )
            candidate_commit = commit_paths.get(key)
            candidate_committed = candidate_commit is not None
            history_path: Path | None = None
            checkpoint: dict[str, Any] | None = None
            checkpoint_size: int | None = None
            legacy_external = _validate_wal_intent(
                store,
                intent,
                operation,
                allow_committed_legacy_external=(
                    candidate_committed
                    or store.exists(_wal_history_path(operation, intent["natural_key"]))
                ),
            )
            expected_intent, commit_path = _wal_paths(operation, intent["natural_key"])
            if expected_intent != intent_path:
                _fail("invalid-wal-layout", "WAL filename does not bind its natural key")
            if candidate_commit is not None and candidate_commit != commit_path:
                _fail("invalid-wal-layout", "WAL commit filename does not bind its intent")
            commit_file_digest: str | None = None
            commit_identity: tuple[int, int] | None = None
            commit: dict[str, Any] | None = None
            if candidate_commit is not None:
                try:
                    commit, commit_file_digest, commit_identity, _ = (
                        store.read_json_without_publication_recovery_with_identity(
                            candidate_commit,
                            max_bytes=MAX_WAL_JSON_BYTES,
                        )
                    )
                except OSError as exc:
                    _fail(
                        "invalid-wal-layout",
                        f"WAL commit is not a private regular JSON file: {candidate_commit}: {exc}",
                    )
                _validate_wal_commit(commit, intent)
            history_candidate = _wal_history_path(operation, intent["natural_key"])
            store.recover_wal_history_temporary(history_candidate, recover=False)
            if store.exists(history_candidate):
                history_path = history_candidate
                checkpoint, _, _, checkpoint_size = (
                    store.read_json_without_publication_recovery_with_identity(
                        history_path,
                        max_bytes=MAX_WAL_HISTORY_RECORD_BYTES,
                        fixed_helper_name=_wal_history_fixed_temp_name(history_path.name),
                    )
                )
                checkpoint = _validate_wal_checkpoint(
                    store,
                    checkpoint,
                    operation,
                    expected_natural_key=intent["natural_key"],
                )
                if commit is None:
                    commit_body = {
                        "version": VERSION,
                        "kind": "state-transaction-commit",
                        "operation": operation,
                        "natural_key": intent["natural_key"],
                        "intent_digest": intent["intent_digest"],
                    }
                    commit = {**commit_body, "commit_digest": _digest(commit_body)}
                expected_checkpoint = _build_wal_checkpoint(
                    intent,
                    commit,
                    sequence=checkpoint["sequence"],
                    previous_usage_digest=checkpoint["previous_usage_digest"],
                )
                if checkpoint != expected_checkpoint:
                    _fail("wal-history-conflict", "checkpoint differs from active WAL")
                _reconstruct_checkpoint_result(
                    store,
                    checkpoint,
                    verify_external=False,
                    recover_publication=False,
                )
            if commit is None and checkpoint is None and candidate_commit is None:
                # This is the sole replayable state: a full bound intent without
                # either commit or checkpoint.
                pass
            elif commit is None:
                _fail("invalid-wal-layout", "committed WAL state has no reconstructable commit")
            logically_committed = candidate_committed or checkpoint is not None
            _validate_wal_intent_domain(
                store,
                intent,
                committed=logically_committed,
                recover_publication=False,
            )
            _preflight_state_writes(
                store,
                intent,
                committed=logically_committed,
                recover_publication=False,
            )
            if legacy_external:
                _verify_committed_legacy_external_after_images(
                    intent,
                    recover_publication=False,
                )
            else:
                _preflight_external_writes(
                    intent,
                    recover_publication=False,
                )
            validated.append(
                {
                    "operation": operation,
                    "intent_path": intent_path,
                    "commit_path": candidate_commit,
                    "intent_file_digest": intent_file_digest,
                    "commit_file_digest": commit_file_digest,
                    "intent_identity": intent_identity,
                    "commit_identity": commit_identity,
                    "legacy_external": legacy_external,
                    "history_candidate": history_candidate,
                    "checkpoint": checkpoint,
                    "checkpoint_size": checkpoint_size,
                    "commit": commit,
                    "intent": intent,
                    "natural_key": intent["natural_key"],
                }
            )

    # Prove the complete recovery order and capacity before replay, repair, or
    # cleanup mutates anything.  Existing checkpoints are the authoritative
    # prefix of the usage chain, so interrupted retirement must converge in
    # sequence order before a checkpoint-free legacy backlog can allocate a new
    # sequence.  Canonical operation/key ordering breaks otherwise-equal ties.
    checkpoint_records = sorted(
        (record for record in validated if record["checkpoint"] is not None),
        key=lambda record: (
            record["checkpoint"]["sequence"],
            os.fsencode(record["operation"]),
            os.fsencode(record["natural_key"]),
        ),
    )
    checkpoint_free_records = sorted(
        (record for record in validated if record["checkpoint"] is None),
        key=lambda record: (
            os.fsencode(record["operation"]),
            os.fsencode(record["natural_key"]),
        ),
    )
    projected_usage = _read_wal_history_usage(store, recover=False)
    for record in checkpoint_records:
        checkpoint = record["checkpoint"]
        checkpoint_size = record["checkpoint_size"]
        assert checkpoint is not None and checkpoint_size is not None
        advanced_usage = _project_wal_history_usage(
            projected_usage,
            checkpoint,
            checkpoint_size,
        )
        usage_committed = advanced_usage == projected_usage
        if not usage_committed and record["commit_path"] is None:
            _fail(
                "invalid-wal-history-usage",
                "uncommitted history tail has no retained commit",
            )
        record["checkpoint_usage_committed"] = usage_committed
        projected_usage = advanced_usage
    for record in checkpoint_free_records:
        if not compact_committed or retain_transaction == (
            record["operation"],
            record["natural_key"],
        ):
            continue
        intent = record["intent"]
        commit = record["commit"]
        if commit is None:
            commit_body = {
                "version": VERSION,
                "kind": "state-transaction-commit",
                "operation": record["operation"],
                "natural_key": record["natural_key"],
                "intent_digest": intent["intent_digest"],
            }
            commit = {**commit_body, "commit_digest": _digest(commit_body)}
        projected_checkpoint = _build_wal_checkpoint(
            intent,
            commit,
            sequence=projected_usage["record_count"] + 1,
            previous_usage_digest=projected_usage["usage_digest"],
        )
        projected_checkpoint = _validate_wal_checkpoint(
            store,
            projected_checkpoint,
            record["operation"],
            expected_natural_key=record["natural_key"],
        )
        projected_usage = _project_wal_history_usage(
            projected_usage,
            projected_checkpoint,
            len(_canonical_bytes(projected_checkpoint)),
        )
    validated = [*checkpoint_records, *checkpoint_free_records]

    # Re-read and domain-validate every bounded active record before any helper
    # cleanup, replay, external repair, commit, or retirement can mutate state.
    for record in validated:
        operation = record["operation"]
        intent_path = record["intent_path"]
        current_intent, current_intent_digest, current_intent_identity, _ = (
            store.read_json_without_publication_recovery_with_identity(
                intent_path,
                max_bytes=MAX_WAL_JSON_BYTES,
            )
        )
        if (
            current_intent_digest != record["intent_file_digest"]
            or current_intent_identity != record["intent_identity"]
        ):
            _fail("wal-layout-changed", f"WAL intent changed during recovery: {intent_path}")
        intent = current_intent
        _validate_wal_intent(
            store,
            intent,
            operation,
            allow_committed_legacy_external=(
                record["commit_path"] is not None or record["checkpoint"] is not None
            ),
        )
        commit = record["commit"]
        if record["commit_path"] is not None:
            commit, current_commit_digest, current_commit_identity, _ = (
                store.read_json_without_publication_recovery_with_identity(
                    record["commit_path"],
                    max_bytes=MAX_WAL_JSON_BYTES,
                )
            )
            if (
                current_commit_digest != record["commit_file_digest"]
                or current_commit_identity != record["commit_identity"]
            ):
                _fail(
                    "wal-layout-changed",
                    f"WAL commit changed during recovery: {record['commit_path']}",
                )
            _validate_wal_commit(commit, intent)
        logically_committed = commit is not None or record["checkpoint"] is not None
        _validate_wal_intent_domain(
            store,
            intent,
            committed=logically_committed,
            recover_publication=False,
        )
        _preflight_state_writes(
            store,
            intent,
            committed=logically_committed,
            recover_publication=False,
        )
        if record["legacy_external"]:
            _verify_committed_legacy_external_after_images(
                intent,
                recover_publication=False,
            )
        else:
            _preflight_external_writes(
                intent,
                recover_publication=False,
            )
        record["intent"] = intent
        record["commit"] = commit

    # Domain-valid helper churn is benign metadata.  Converge it only after the
    # complete active set has passed the protected semantic/content checks.
    for operation, inventory_names in inventory:
        store.recover_wal_temporaries(
            Path("wal") / operation,
            names=inventory_names,
        )
    store.recover_wal_history_temporary(WAL_HISTORY_USAGE)
    for history_candidate in sorted(
        {record["history_candidate"] for record in validated},
        key=lambda path: os.fsencode(str(path)),
    ):
        store.recover_wal_history_temporary(history_candidate)

    # Helper cleanup does not change the selected final objects or bytes.  Bind
    # every active leaf once more before the mutation phase begins.
    for record in validated:
        intent, intent_digest, intent_identity, _ = (
            store.read_json_without_publication_recovery_with_identity(
                record["intent_path"],
                max_bytes=MAX_WAL_JSON_BYTES,
            )
        )
        if (
            intent_digest != record["intent_file_digest"]
            or intent_identity != record["intent_identity"]
            or intent != record["intent"]
        ):
            _fail(
                "wal-layout-changed",
                f"WAL intent changed during helper recovery: {record['intent_path']}",
            )
        if record["commit_path"] is not None:
            commit, commit_digest, commit_identity, _ = (
                store.read_json_without_publication_recovery_with_identity(
                    record["commit_path"],
                    max_bytes=MAX_WAL_JSON_BYTES,
                )
            )
            if (
                commit_digest != record["commit_file_digest"]
                or commit_identity != record["commit_identity"]
                or commit != record["commit"]
            ):
                _fail(
                    "wal-layout-changed",
                    f"WAL commit changed during helper recovery: {record['commit_path']}",
                )

    for record in validated:
        operation = record["operation"]
        intent_path = record["intent_path"]
        intent = record["intent"]
        commit = record["commit"]
        if commit is not None:
            if record["legacy_external"]:
                _verify_committed_legacy_external_after_images(intent)
            else:
                _repair_committed_external_after_images(intent)
                _preflight_external_writes(intent, require_after=True)
        else:
            _apply_wal_intent(store, intent)
            _commit_wal(store, intent)
            _, new_commit_path = _wal_paths(operation, intent["natural_key"])
            commit, commit_file_digest, commit_identity, _ = store.read_json_with_identity(
                new_commit_path,
                max_bytes=MAX_WAL_JSON_BYTES,
            )
            _validate_wal_commit(commit, intent)
            record["commit_path"] = new_commit_path
            record["commit_file_digest"] = commit_file_digest
            record["commit_identity"] = commit_identity
        assert commit is not None
        if record["checkpoint"] is None and (
            not compact_committed or retain_transaction == (operation, intent["natural_key"])
        ):
            continue
        _retire_committed_wal(
            store,
            intent,
            commit,
            intent_path=intent_path,
            commit_path=record["commit_path"],
            intent_file_digest=record["intent_file_digest"],
            commit_file_digest=record["commit_file_digest"],
            intent_identity=record["intent_identity"],
            commit_identity=record["commit_identity"],
        )
    store._bind_state_namespace("after WAL recovery")


def _require_committed_transaction(
    store: StateStore,
    operation: str,
    natural_key: str,
    *,
    recover_publication: bool = True,
) -> dict[str, Any]:
    intent_path, commit_path = _wal_paths(operation, natural_key)
    if not store.exists(intent_path) and not store.exists(commit_path):
        if recover_publication:
            retired = _load_wal_checkpoint(store, operation, natural_key)
        else:
            checkpoint = _load_wal_checkpoint_binding_read_only(store, operation, natural_key)
            retired = (
                None
                if checkpoint is None
                else (
                    checkpoint,
                    _reconstruct_checkpoint_result(
                        store,
                        checkpoint,
                        recover_publication=False,
                    ),
                )
            )
        if retired is None:
            _fail(
                "missing-authority-transaction",
                f"{operation} has no committed control transaction",
            )
        checkpoint, result = retired
        return {
            "version": VERSION,
            "kind": "retired-state-transaction",
            "operation": operation,
            "natural_key": natural_key,
            "request_digest": checkpoint["request_digest"],
            "captured_at": checkpoint["captured_at"],
            "writes": checkpoint["after_images"],
            "result": result,
            "intent_digest": checkpoint["intent_digest"],
            "intent_bytes": checkpoint["intent_bytes"],
        }
    if not store.exists(intent_path) or not store.exists(commit_path):
        _fail("missing-authority-transaction", f"{operation} has no committed control transaction")
    intent = _read_state_json(
        store,
        intent_path,
        recover_publication=recover_publication,
    )
    commit = _read_state_json(
        store,
        commit_path,
        recover_publication=recover_publication,
    )
    legacy_external = _validate_wal_intent(
        store,
        intent,
        operation,
        allow_committed_legacy_external=True,
    )
    _validate_wal_commit(commit, intent)
    _validate_wal_intent_domain(
        store,
        intent,
        committed=True,
        recover_publication=recover_publication,
    )
    _preflight_state_writes(
        store,
        intent,
        committed=True,
        recover_publication=recover_publication,
    )
    if legacy_external:
        _verify_committed_legacy_external_after_images(
            intent,
            recover_publication=recover_publication,
        )
    else:
        _preflight_external_writes(
            intent,
            require_after=True,
            recover_publication=recover_publication,
        )
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


def _state_access_policy_binding(store: StateStore) -> dict[str, Any]:
    names = [store.root.anchor if name is None else name for name in store._chain_names]
    return {
        "version": ACL_POLICY_VERSION,
        "model": "darwin-extended-v1" if sys.platform == "darwin" else "posix-mode-only-v1",
        "chain": [
            {"name": name, "acl_digest": signal[6]}
            for name, signal in zip(names, store._chain_signals, strict=True)
        ],
    }


def _validate_state_access_policy_binding(value: Any, store: StateStore) -> None:
    binding = _require_object(value, "state_marker.access_policy")
    _exact_fields(binding, "state_marker.access_policy", {"version", "model", "chain"})
    if binding["version"] != ACL_POLICY_VERSION:
        _fail("unsupported-state-access-policy", "state ACL policy version is unsupported")
    expected = _state_access_policy_binding(store)
    if binding["model"] != expected["model"]:
        _fail("unsupported-state-access-policy", "state ACL policy model is unsupported")
    raw_chain = _require_list(binding["chain"], "state_marker.access_policy.chain")
    normalized: list[dict[str, str]] = []
    for index, raw in enumerate(raw_chain):
        entry = _require_object(raw, f"state_marker.access_policy.chain[{index}]")
        _exact_fields(entry, "state_marker.access_policy.chain[]", {"name", "acl_digest"})
        name = _require_string(entry["name"], "state_marker.access_policy.name")
        digest = _require_string(entry["acl_digest"], "state_marker.access_policy.acl_digest")
        if HEX64_RE.fullmatch(digest) is None:
            _fail("invalid-state-marker", "state ACL digest must be raw SHA-256")
        normalized.append({"name": name, "acl_digest": digest})
    if normalized != expected["chain"]:
        _fail("state-chain-policy-changed", "persisted state ACL chain no longer matches")


def _new_state_marker(store: StateStore, now: str) -> dict[str, Any]:
    return {
        "version": VERSION,
        "kind": "daily-skill-friction-state",
        "mode": "unbound",
        "state_id": str(uuid.uuid4()),
        "created_at": _timestamp(now, "now"),
        "access_policy": _state_access_policy_binding(store),
    }


def _read_marker(
    root: Path,
    *,
    recover_publication: bool = True,
) -> dict[str, Any] | None:
    path = _marker_path(root)
    if not _state_exists(path):
        return None
    store = _active_store_for_path(path)
    if store is None:
        _fail("unbound-state-marker-read", "state marker requires descriptor-bound validation")
    if recover_publication:
        marker = _load_json(path)
    else:
        marker = store.read_json_without_publication_recovery(Path(STATE_MARKER))[0]
    mode = marker.get("mode")
    if "access_policy" not in marker:
        _fail(
            "unsupported-state-access-policy",
            "legacy state marker has no persisted ACL policy binding",
        )
    fields = {"version", "kind", "mode", "state_id", "created_at", "access_policy"}
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
    _validate_state_access_policy_binding(marker["access_policy"], store)
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
    store = _active_store_for_path(root)
    if store is None:
        _fail("unbound-state-marker-write", "state marker requires active custody")
    marker = _new_state_marker(store, now)
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
    index, _ = old_active[0]
    for repair_index, prior_repair in enumerate(old_repairs):
        expected_repair = dict(prior_repair)
        if repair_index == index:
            expected_repair["state"] = "superseded"
        if new_repairs[repair_index] != expected_repair:
            _fail(
                "invalid-closed-reopen",
                "reopen must preserve every prior repair and only supersede the current state",
            )
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


def _repair_identity_projection(repairs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Project the ordered repair identities that one approval selected."""

    return [{field: repair[field] for field in REPAIR_IDENTITY_FIELDS} for repair in repairs]


def _repair_binding_projection(case: Mapping[str, Any]) -> dict[str, Any]:
    """Bind one exact active repair and the immutable ordered repair list."""

    repairs = _require_list(case.get("repairs"), "case.repairs")
    normalized = [_require_object(repair, "case.repair") for repair in repairs]
    active = [repair for repair in normalized if repair.get("state") != "superseded"]
    if len(active) != 1:
        _fail(
            "invalid-repair-binding",
            "an approval-bound case must have exactly one active repair",
        )
    repair_ids = [_bounded_string(repair.get("id"), "repair.id", 2, 12) for repair in normalized]
    identity_projection = _repair_identity_projection(normalized)
    return {
        "active_repair_id": active[0]["id"],
        "repair_ids": repair_ids,
        "repair_identity_digest": _digest({"repairs": identity_projection}),
    }


def _validate_approval_bound_repair_delta(
    old_case: Mapping[str, Any],
    new_case: Mapping[str, Any],
    *,
    closed_reopen: bool,
) -> None:
    """Keep the consumed repair selection fixed until a sealed reopen."""

    if old_case["status"] not in APPROVAL_BOUND_CASE_STATUSES or closed_reopen:
        return
    old_repairs = _require_list(old_case["repairs"], "old.repairs")
    new_repairs = _require_list(new_case["repairs"], "new.repairs")
    if len(new_repairs) != len(old_repairs):
        _fail(
            "consumed-repair-binding-change",
            "consumed repair approval freezes the repair list until a sealed proposed transition",
        )
    old_normalized = [_require_object(repair, "old.repair") for repair in old_repairs]
    new_normalized = [_require_object(repair, "new.repair") for repair in new_repairs]
    if _repair_identity_projection(new_normalized) != _repair_identity_projection(old_normalized):
        _fail(
            "consumed-repair-binding-change",
            "consumed repair approval freezes every ordered repair identity",
        )
    old_active = [
        (index, repair)
        for index, repair in enumerate(old_normalized)
        if repair["state"] != "superseded"
    ]
    new_active = [
        (index, repair)
        for index, repair in enumerate(new_normalized)
        if repair["state"] != "superseded"
    ]
    if (
        len(old_active) != 1
        or len(new_active) != 1
        or new_active[0][0] != old_active[0][0]
        or new_active[0][1]["id"] != old_active[0][1]["id"]
    ):
        _fail(
            "consumed-repair-binding-change",
            "the repair selected by consumed approval cannot be superseded or replaced",
        )
    active_index = old_active[0][0]
    for index, old_repair in enumerate(old_normalized):
        if index != active_index and new_normalized[index] != old_repair:
            _fail(
                "consumed-repair-binding-change",
                "prior repair history is frozen while a consumed approval remains active",
            )


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
    if old_case["status"] == "superseded" and semantic_changed:
        _fail(
            "terminal-semantic-mutation",
            "superseded case semantic history is immutable; only currentness may refresh",
        )
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
    if status_changed and new_case["status"] == "proposed" and new_case["support"] != "repeated":
        _fail(
            "insufficient-proposed-support",
            "entering proposed requires repeated support",
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
    _validate_approval_bound_repair_delta(
        old_case,
        new_case,
        closed_reopen=closed_reopen,
    )
    if len(new_repairs) < len(old_repairs):
        _fail("repair-history-removal", "existing repair history cannot be removed")
    durable = {"pull_request_url", "commit", "installed_on", "removed_on"}
    for index, old_repair in enumerate(old_repairs):
        new_repair = new_repairs[index]
        if new_repair["id"] != old_repair["id"]:
            _fail("repair-history-reorder", "repair history cannot be reordered or replaced")
        for field in REPAIR_IDENTITY_FIELDS:
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


def _case_tuple(wrapper: Mapping[str, Any]) -> dict[str, Any]:
    case = _require_object(wrapper.get("case"), "case")
    control = _require_object(wrapper.get("control"), "control")
    return {
        "case_id": _validate_case_id(case.get("id")),
        "revision": _require_int(case.get("revision"), "case.revision", minimum=1),
        "semantic_digest": _sha_digest(control.get("semantic_digest"), "control.semantic_digest"),
    }


def _normalize_case_tuple_value(value: Any, field: str) -> dict[str, Any]:
    item = _require_object(value, field)
    _exact_fields(item, field, {"case_id", "revision", "semantic_digest"})
    return {
        "case_id": _validate_case_id(item.get("case_id"), f"{field}.case_id"),
        "revision": _require_int(item.get("revision"), f"{field}.revision", minimum=1),
        "semantic_digest": _sha_digest(item.get("semantic_digest"), f"{field}.semantic_digest"),
    }


def _validate_repair_approval_delta(source: Mapping[str, Any], target: Mapping[str, Any]) -> None:
    """Allow approval to authorize only the exact repair/lifecycle transition."""

    source_case = _require_object(source.get("case"), "source.case")
    target_case = _require_object(target.get("case"), "target.case")
    if source_case["status"] != "proposed" or target_case["status"] != "approved":
        _fail("repair-approval-scope", "repair approval requires proposed -> approved")
    if target_case["revision"] != source_case["revision"] + 1:
        _fail("repair-approval-scope", "approved revision must be exactly source revision + 1")
    source_repairs = _require_list(source_case["repairs"], "source.repairs")
    target_repairs = _require_list(target_case["repairs"], "target.repairs")
    if len(source_repairs) != len(target_repairs):
        _fail("repair-approval-scope", "repair approval cannot add or remove repair history")
    active_indexes = [
        index
        for index, repair in enumerate(source_repairs)
        if _require_object(repair, "source.repair").get("state") != "superseded"
    ]
    if len(active_indexes) != 1:
        _fail("repair-approval-scope", "source must have exactly one active planned repair")
    active_index = active_indexes[0]
    for index, (source_repair_raw, target_repair_raw) in enumerate(
        zip(source_repairs, target_repairs, strict=True)
    ):
        source_repair = _require_object(source_repair_raw, "source.repair")
        target_repair = _require_object(target_repair_raw, "target.repair")
        if index != active_index:
            if target_repair != source_repair:
                _fail("repair-approval-scope", "prior repair history cannot change at approval")
            continue
        normalized = dict(target_repair)
        target_state = normalized.get("state")
        if target_state not in {"planned", "open"}:
            _fail("repair-approval-scope", "approved repair must remain planned or become open")
        normalized["state"] = source_repair["state"]
        normalized["pull_request_url"] = source_repair["pull_request_url"]
        if normalized != source_repair:
            _fail(
                "repair-approval-scope",
                "approval may change only active repair state and pull request URL",
            )

    normalized_target = json.loads(json.dumps(target, ensure_ascii=False))
    normalized_case = normalized_target["case"]
    normalized_case["revision"] = source_case["revision"]
    normalized_case["status"] = source_case["status"]
    normalized_case["lifecycle_changed_at"] = source_case["lifecycle_changed_at"]
    normalized_case["currentness_checked_at"] = source_case["currentness_checked_at"]
    normalized_case["repairs"] = json.loads(json.dumps(source_repairs, ensure_ascii=False))
    normalized_target["control"]["semantic_digest"] = source["control"]["semantic_digest"]
    if normalized_target != source:
        _fail(
            "repair-approval-scope",
            "repair approval cannot change evidence, scope, lineage, or unrelated case fields",
        )


def _normalize_repair_approval(value: Mapping[str, Any]) -> dict[str, Any]:
    _scan_prohibited_content(value, "repair_approval")
    if value.get("version") != VERSION or value.get("kind") != "repair-approval":
        _fail("invalid-repair-approval", "repair approval version or kind is invalid")
    _exact_fields(
        value,
        "repair_approval",
        {
            "version",
            "kind",
            "approval_id",
            "interaction",
            "expires_at",
            "source",
            "target",
            "publication",
        },
    )
    approval_id = _safe_object_id(value.get("approval_id"), "repair_approval.approval_id")
    interaction = _require_object(value.get("interaction"), "repair_approval.interaction")
    _exact_fields(
        interaction,
        "repair_approval.interaction",
        {"interactive", "actor", "approved_at"},
    )
    if interaction.get("interactive") is not True or interaction.get("actor") != "Joey":
        _fail("untrusted-repair-approval", "repair approval must be interactive Joey input")
    approved_at = _timestamp(interaction.get("approved_at"), "repair_approval.approved_at")
    expires_at = _timestamp(value.get("expires_at"), "repair_approval.expires_at")

    source = _normalize_case_tuple_value(value.get("source"), "repair_approval.source")
    target = _normalize_case_tuple_value(value.get("target"), "repair_approval.target")
    if source["case_id"] != target["case_id"] or target["revision"] != source["revision"] + 1:
        _fail("invalid-repair-approval", "repair approval source/target tuple is inconsistent")
    publication = _require_object(value.get("publication"), "repair_approval.publication")
    publication_fields = {
        "closure_id",
        "closure_digest",
        "selection_id",
        "plan_digest",
        "manifest_digest",
        "pull_request_url",
        "ledger_commit",
        "merged_at",
    }
    _exact_fields(publication, "repair_approval.publication", publication_fields)
    normalized_publication = {
        "closure_id": _safe_object_id(
            publication.get("closure_id"), "repair_approval.publication.closure_id"
        ),
        "closure_digest": _require_string(
            publication.get("closure_digest"), "repair_approval.publication.closure_digest"
        ),
        "selection_id": _safe_object_id(
            publication.get("selection_id"), "repair_approval.publication.selection_id"
        ),
        "plan_digest": _require_string(
            publication.get("plan_digest"), "repair_approval.publication.plan_digest"
        ),
        "manifest_digest": _require_string(
            publication.get("manifest_digest"), "repair_approval.publication.manifest_digest"
        ),
        "pull_request_url": _require_string(
            publication.get("pull_request_url"), "repair_approval.publication.pull_request_url"
        ),
        "ledger_commit": _require_string(
            publication.get("ledger_commit"), "repair_approval.publication.ledger_commit"
        ),
        "merged_at": _timestamp(
            publication.get("merged_at"), "repair_approval.publication.merged_at"
        ),
    }
    for field in ("closure_digest", "plan_digest", "manifest_digest"):
        if HEX64_RE.fullmatch(normalized_publication[field]) is None:
            _fail("invalid-repair-approval", f"publication.{field} must be raw SHA-256")
    if (
        PR_URL_RE.fullmatch(normalized_publication["pull_request_url"]) is None
        or not normalized_publication["pull_request_url"].startswith(
            f"https://github.com/{LEDGER_REPOSITORY}/pull/"
        )
        or COMMIT_RE.fullmatch(normalized_publication["ledger_commit"]) is None
    ):
        _fail("invalid-repair-approval", "repair approval publication provenance is invalid")
    return {
        "version": VERSION,
        "kind": "repair-approval",
        "approval_id": approval_id,
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "approved_at": approved_at,
        },
        "expires_at": expires_at,
        "source": source,
        "target": target,
        "publication": normalized_publication,
    }


def _repair_approval_index_key(
    source_tuple: Mapping[str, Any], target_tuple: Mapping[str, Any]
) -> str:
    return _digest({"source": dict(source_tuple), "target": dict(target_tuple)})


def _validate_published_closure_authority(
    store: StateStore,
    publication: Mapping[str, Any],
    source_tuple: Mapping[str, Any],
    *,
    recover_publication: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    plan, _, manifest, _ = _validate_registered_finalized_publication_authority(
        store,
        selection_id=publication["selection_id"],
        plan_digest=publication["plan_digest"],
        manifest_digest=publication["manifest_digest"],
        recover_publication=recover_publication,
    )
    closure_id = publication["closure_id"]
    closure_relative = Path("publication") / "closures" / f"{closure_id}.json"
    closure = _read_state_json(
        store,
        closure_relative,
        recover_publication=recover_publication,
    )
    _validate_persisted_closure_record(closure)
    body = {key: value for key, value in closure.items() if key != "closure_digest"}
    if (
        closure.get("kind") != "publication-closure"
        or closure.get("reason") != "published"
        or closure.get("closure_digest") != _digest(body)
        or closure.get("closure_digest") != publication["closure_digest"]
    ):
        _fail("invalid-repair-publication", "repair approval does not bind a published closure")
    entries = _require_list(closure.get("entries"), "closure.entries")
    matches = [
        _require_object(entry, "closure.entry")
        for entry in entries
        if isinstance(entry, dict) and entry.get("case_id") == source_tuple["case_id"]
    ]
    if len(matches) != 1:
        _fail("invalid-repair-publication", "published closure has no unique matching case")
    entry = matches[0]
    expected = {
        **dict(source_tuple),
        "selection_id": publication["selection_id"],
        "plan_digest": publication["plan_digest"],
        "manifest_digest": publication["manifest_digest"],
        "pull_request_url": publication["pull_request_url"],
        "ledger_commit": publication["ledger_commit"],
        "merged_at": publication["merged_at"],
    }
    if any(entry.get(field) != expected_value for field, expected_value in expected.items()):
        _fail("invalid-repair-publication", "published closure provenance does not match")
    _validate_manifest_closure_entry(manifest, entry)
    _validate_published_ledger_commit(entry, plan)
    intent = _require_committed_transaction(
        store,
        "close-publication",
        closure_id,
        recover_publication=recover_publication,
    )
    if intent["result"].get("closure_digest") != publication["closure_digest"]:
        _fail("missing-authority-transaction", "closure WAL does not bind repair publication")
    active_relative = Path("publication") / "active" / f"{source_tuple['case_id']}.json"
    active = _read_state_json(
        store,
        active_relative,
        recover_publication=recover_publication,
    )
    _validate_pending_record(active, source_tuple["case_id"])
    if any(
        active.get(field) != expected_value
        for field, expected_value in {
            **dict(source_tuple),
            "status": "closed",
            "closure_id": closure_id,
            "closure_digest": publication["closure_digest"],
            "closure_reason": "published",
        }.items()
    ):
        _fail("invalid-repair-publication", "published active record does not match approval")
    return closure, entry


def _validate_repair_approval_times(
    approval: Mapping[str, Any], closure: Mapping[str, Any], now_value: str
) -> None:
    approved = _parse_time(approval["interaction"]["approved_at"], "approved_at")
    expires = _parse_time(approval["expires_at"], "expires_at")
    merged = _parse_time(approval["publication"]["merged_at"], "merged_at")
    closed = _parse_time(closure["interaction"]["closed_at"], "closed_at")
    now_instant = _parse_time(now_value, "now")
    if not (merged < approved and closed < approved <= now_instant < expires):
        _fail(
            "repair-approval-clock-order",
            "repair approval must follow merge/closure and remain unexpired at --now",
        )
    if expires - approved > REPAIR_APPROVAL_MAX_AGE:
        _fail("repair-approval-too-long", "repair approval validity cannot exceed seven days")


def _validate_repair_approval_lifecycle_time(
    approval: Mapping[str, Any], target: Mapping[str, Any]
) -> None:
    target_case = _require_object(target.get("case"), "target.case")
    if target_case.get("lifecycle_changed_at") != approval["interaction"]["approved_at"]:
        _fail(
            "repair-approval-lifecycle-mismatch",
            "approved target lifecycle_changed_at must equal repair approved_at",
        )


def _validate_approve_repair_intent_lifecycle(
    store: StateStore,
    intent: Mapping[str, Any],
    *,
    allow_legacy_result: bool = False,
    recover_publication: bool = True,
) -> None:
    """Validate approval/index, lifecycle witness, and publication authority."""

    approvals: list[tuple[dict[str, Any], dict[str, Any]]] = []
    indexes: list[tuple[dict[str, Any], dict[str, Any]]] = []
    writes = _require_list(intent["writes"], "wal.writes")
    if len(writes) != 2:
        _fail("invalid-wal", "approve-repair intent must contain exactly two authority writes")
    for index, raw_write in enumerate(writes):
        write = _require_object(raw_write, f"wal.writes[{index}]")
        if write.get("scope") != "state":
            continue
        after = _require_object(write.get("after"), f"wal.writes[{index}].after")
        if after.get("kind") == "repair-approval":
            approvals.append((write, after))
        elif after.get("kind") == "repair-approval-index":
            indexes.append((write, after))
    if len(approvals) != 1 or len(indexes) != 1:
        _fail(
            "invalid-wal",
            "approve-repair intent must contain one approval and one index record",
        )
    approval_write, record = approvals[0]
    approval_digest = _raw_sha256(
        record.get("approval_digest"), "wal.repair_approval.approval_digest"
    )
    approval_body = {key: value for key, value in record.items() if key != "approval_digest"}
    approval = _normalize_repair_approval(approval_body)
    if approval_digest != _digest(approval):
        _fail("invalid-repair-approval", "approve-repair WAL approval digest is invalid")
    approval_key = _repair_approval_index_key(approval["source"], approval["target"])
    index_write, index_record = indexes[0]
    _exact_fields(
        index_record,
        "wal.repair_approval_index",
        {
            "version",
            "kind",
            "approval_key",
            "approval_id",
            "approval_digest",
            "source",
            "target",
            "index_digest",
        },
    )
    index_body = {key: value for key, value in index_record.items() if key != "index_digest"}
    if (
        index_record.get("version") != VERSION
        or index_record.get("kind") != "repair-approval-index"
        or index_record.get("approval_key") != approval_key
        or index_record.get("approval_id") != approval["approval_id"]
        or index_record.get("approval_digest") != approval_digest
        or index_record.get("source") != approval["source"]
        or index_record.get("target") != approval["target"]
        or index_record.get("index_digest") != _digest(index_body)
    ):
        _fail("invalid-repair-approval-index", "approve-repair WAL index is invalid")
    if (
        intent.get("natural_key") != approval["approval_id"]
        or approval_write.get("path") != f"repairs/approvals/{approval['approval_id']}.json"
        or index_write.get("path") != f"repairs/approval-index/{approval_key}.json"
        or approval_write.get("immutable") is not True
        or index_write.get("immutable") is not True
    ):
        _fail("invalid-wal", "approve-repair WAL authority paths or mutability are invalid")
    result = _require_object(intent.get("result"), "wal.result")
    legacy_fields = {
        "version",
        "status",
        "approval_id",
        "approval_digest",
        "approval_key",
        "expires_at",
    }
    has_lifecycle_witness = "target_lifecycle_changed_at" in result
    _exact_fields(
        result,
        "wal.result",
        legacy_fields | ({"target_lifecycle_changed_at"} if has_lifecycle_witness else set()),
    )
    expected = {
        "version": VERSION,
        "status": "approved",
        "approval_id": approval["approval_id"],
        "approval_digest": approval_digest,
        "approval_key": approval_key,
        "expires_at": approval["expires_at"],
    }
    if any(result.get(field) != value for field, value in expected.items()):
        _fail("invalid-repair-approval", "approve-repair WAL result is invalid")
    if not has_lifecycle_witness:
        if not allow_legacy_result:
            _fail(
                "repair-approval-lifecycle-mismatch",
                "pending approve-repair WAL lacks its target lifecycle decision-time witness",
            )
    else:
        target_lifecycle_changed_at = _timestamp(
            result["target_lifecycle_changed_at"],
            "wal.result.target_lifecycle_changed_at",
        )
        if target_lifecycle_changed_at != approval["interaction"]["approved_at"]:
            _fail(
                "repair-approval-lifecycle-mismatch",
                "approve-repair WAL target lifecycle_changed_at must equal repair approved_at",
            )
    _validate_published_closure_authority(
        store,
        approval["publication"],
        approval["source"],
        recover_publication=recover_publication,
    )


def _validate_stage_intent_repair_approval_lifecycle(
    store: StateStore,
    intent: Mapping[str, Any],
    *,
    recover_publication: bool = True,
) -> None:
    """Revalidate the approved lifecycle timestamp before replaying a stage WAL."""

    consumptions: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    for index, raw_write in enumerate(_require_list(intent["writes"], "wal.writes")):
        write = _require_object(raw_write, f"wal.writes[{index}]")
        if write.get("scope") != "state":
            continue
        after = _require_object(write.get("after"), f"wal.writes[{index}].after")
        if after.get("kind") == "repair-approval-consumption":
            consumptions.append(after)
        elif isinstance(after.get("case"), dict) and isinstance(after.get("control"), dict):
            candidates.append(after)
    if not consumptions:
        return
    if len(consumptions) != 1:
        _fail("invalid-wal", "approval-bound stage intent must contain one consumption")
    consumption = consumptions[0]
    _exact_fields(
        consumption,
        "wal.repair_approval_consumption",
        {
            "version",
            "kind",
            "approval_id",
            "approval_digest",
            "case_id",
            "revision",
            "semantic_digest",
            "repair_binding",
            "consumed_at",
            "stage_receipt_id",
            "consumption_digest",
        },
    )
    consumption_body = {
        key: value for key, value in consumption.items() if key != "consumption_digest"
    }
    if (
        consumption.get("version") != VERSION
        or consumption.get("kind") != "repair-approval-consumption"
        or consumption.get("consumption_digest") != _digest(consumption_body)
    ):
        _fail("invalid-repair-consumption", "stage WAL repair consumption is invalid")
    approval_id = _safe_object_id(consumption.get("approval_id"), "wal.consumption.approval_id")
    approval_digest = _raw_sha256(
        consumption.get("approval_digest"), "wal.consumption.approval_digest"
    )
    case_id = _validate_case_id(consumption.get("case_id"), "wal.consumption.case_id")
    matching_candidates = [
        candidate
        for candidate in candidates
        if _require_object(candidate.get("case"), "wal.candidate.case").get("id") == case_id
    ]
    if len(matching_candidates) != 1:
        _fail("invalid-wal", "approval-bound stage intent must contain one target case")
    target = matching_candidates[0]
    validate_candidate(target)
    target_tuple = _case_tuple(target)
    if any(
        consumption.get(field) != target_tuple[field]
        for field in ("case_id", "revision", "semantic_digest")
    ):
        _fail("invalid-wal", "stage consumption does not bind its target case")

    approval_relative = Path("repairs") / "approvals" / f"{approval_id}.json"
    record = _read_state_json(
        store,
        approval_relative,
        recover_publication=recover_publication,
    )
    persisted_digest = _raw_sha256(record.get("approval_digest"), "repair_approval.approval_digest")
    approval_body = {key: value for key, value in record.items() if key != "approval_digest"}
    approval = _normalize_repair_approval(approval_body)
    if (
        persisted_digest != _digest(approval)
        or persisted_digest != approval_digest
        or approval["approval_id"] != approval_id
        or approval["target"] != target_tuple
    ):
        _fail("invalid-repair-approval", "stage WAL repair approval binding is invalid")
    approval_key = _repair_approval_index_key(approval["source"], approval["target"])
    authority_intent = _require_committed_transaction(
        store,
        "approve-repair",
        approval_id,
        recover_publication=recover_publication,
    )
    if (
        authority_intent["result"].get("approval_digest") != approval_digest
        or authority_intent["result"].get("approval_key") != approval_key
    ):
        _fail("missing-authority-transaction", "stage WAL has no exact approval authority")
    authority_lifecycle = authority_intent["result"].get("target_lifecycle_changed_at")
    if (
        authority_lifecycle is not None
        and authority_lifecycle != approval["interaction"]["approved_at"]
    ):
        _fail(
            "repair-approval-lifecycle-mismatch",
            "approve-repair WAL target lifecycle_changed_at must equal repair approved_at",
        )
    closure, _ = _validate_published_closure_authority(
        store,
        approval["publication"],
        approval["source"],
        recover_publication=recover_publication,
    )
    _validate_repair_approval_times(approval, closure, intent["captured_at"])
    _validate_repair_approval_lifecycle_time(approval, target)


def _validate_stage_intent_domain(
    store: StateStore,
    intent: Mapping[str, Any],
    *,
    recover_publication: bool = True,
) -> None:
    receipts: list[tuple[dict[str, Any], dict[str, Any]]] = []
    candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for index, raw_write in enumerate(_require_list(intent["writes"], "wal.writes")):
        write = _require_object(raw_write, f"wal.writes[{index}]")
        if write.get("scope") != "state":
            continue
        after = _require_object(write.get("after"), f"wal.writes[{index}].after")
        if after.get("kind") == "stage":
            receipts.append((write, after))
        elif isinstance(after.get("case"), dict) and isinstance(after.get("control"), dict):
            candidates.append((write, after))
    if len(receipts) != 1:
        _fail("invalid-wal", "stage intent must contain one immutable stage receipt")
    receipt_write, receipt = receipts[0]
    receipt_id = _safe_object_id(receipt.get("receipt_id"), "receipt.receipt_id")
    _validate_persisted_receipt(receipt, "stage", receipt_id)
    expected_receipt_path = f"receipts/stage/{receipt_id}.json"
    if (
        receipt_write.get("path") != expected_receipt_path
        or receipt_write.get("immutable") is not True
    ):
        _fail("invalid-wal", "stage receipt after-image path or mutability is invalid")
    matching_candidates = [
        (write, candidate)
        for write, candidate in candidates
        if _require_object(candidate.get("case"), "wal.candidate.case").get("id")
        == receipt["case_id"]
    ]
    if len(matching_candidates) != 1:
        _fail("invalid-wal", "stage intent must contain one case after-image for its receipt")
    candidate_write, candidate = matching_candidates[0]
    summary = validate_candidate(candidate)
    if (
        candidate_write.get("path") != receipt["case_path"]
        or summary["revision"] != receipt["revision"]
        or summary["semantic_digest"] != receipt["semantic_digest"]
        or hashlib.sha256(_canonical_bytes(candidate)).hexdigest() != receipt["wrapper_file_sha256"]
        or hashlib.sha256(_canonical_bytes(candidate["case"])).hexdigest() != receipt["case_sha256"]
    ):
        _fail("invalid-wal", "stage case after-image differs from its receipt")
    expected_result = {**receipt, "path": str(store.root / expected_receipt_path)}
    if intent.get("result") != expected_result:
        _fail("invalid-wal", "stage WAL result differs from its receipt")
    _validate_stage_intent_repair_approval_lifecycle(
        store,
        intent,
        recover_publication=recover_publication,
    )


def approve_repair(
    state_root: Path,
    candidate_path: Path,
    approval_path: Path,
    now: str,
    *,
    interactive_confirmed: bool,
) -> dict[str, Any]:
    """Persist one independent, interactive, single-use repair authority."""

    if not interactive_confirmed:
        _fail(
            "interactive-confirmation-required",
            "approve-repair requires explicit interactive Joey confirmation",
        )
    now_value = _timestamp(now, "now")
    candidate = _load_json(candidate_path)
    validate_candidate(candidate)
    _validate_candidate_at_now(candidate, now_value)
    approval = _normalize_repair_approval(_load_json(approval_path))
    target_tuple = _case_tuple(candidate)
    if approval["target"] != target_tuple:
        _fail("repair-approval-mismatch", "approval does not bind the exact target tuple")
    _validate_repair_approval_lifecycle_time(approval, candidate)
    request = {"approval": approval, "target": target_tuple}
    approval_id = approval["approval_id"]
    with _state_lock(
        state_root,
        create=False,
        recover_marker_publication=False,
    ) as store:
        _preflight_transaction_binding_read_only(
            store,
            operation="approve-repair",
            natural_key=approval_id,
            request=request,
        )
        preflight_closure, _ = _validate_published_closure_authority(
            store,
            approval["publication"],
            approval["source"],
            recover_publication=False,
        )
        _validate_repair_approval_times(approval, preflight_closure, now_value)
        _preflight_existing_transaction_domain_read_only(
            store,
            operation="approve-repair",
            natural_key=approval_id,
        )
        _read_marker(state_root)
        _recover_pending_wal(store)
        if _transaction_record_exists(store, "approve-repair", approval_id):
            return _run_transaction(
                store,
                operation="approve-repair",
                natural_key=approval_id,
                request=request,
                captured_at=now_value,
                writes=[],
                result={},
            )
        marker = _read_marker(state_root)
        if marker is None or marker.get("mode") != "live":
            _fail("not-live-state", "repair approval requires live state")
        source_path = _find_case(state_root, approval["source"]["case_id"])
        if source_path is None:
            _fail("missing-repair-source", "repair approval source case does not exist")
        source = _load_json(source_path)
        validate_candidate(source)
        if _case_tuple(source) != approval["source"]:
            _fail("repair-approval-stale", "current proposed case does not match approval source")
        _validate_case_delta(source, candidate)
        _validate_repair_approval_delta(source, candidate)
        closure, _ = _validate_published_closure_authority(
            store, approval["publication"], approval["source"]
        )
        _validate_repair_approval_times(approval, closure, now_value)
        approval_digest = _digest(approval)
        record = {**approval, "approval_digest": approval_digest}
        approval_key = _repair_approval_index_key(approval["source"], approval["target"])
        index_body = {
            "version": VERSION,
            "kind": "repair-approval-index",
            "approval_key": approval_key,
            "approval_id": approval_id,
            "approval_digest": approval_digest,
            "source": approval["source"],
            "target": approval["target"],
        }
        index = {**index_body, "index_digest": _digest(index_body)}
        approval_relative = Path("repairs") / "approvals" / f"{approval_id}.json"
        index_relative = Path("repairs") / "approval-index" / f"{approval_key}.json"
        if store.exists(approval_relative):
            _fail(
                "orphan-repair-approval",
                "repair approval exists without its committed approve-repair transaction",
            )
        if store.exists(index_relative):
            _fail(
                "repair-approval-conflict",
                "the exact repair tuple already has a different approval authority",
            )
        result = {
            "version": VERSION,
            "status": "approved",
            "approval_id": approval_id,
            "approval_digest": approval_digest,
            "approval_key": approval_key,
            "expires_at": approval["expires_at"],
            "target_lifecycle_changed_at": candidate["case"]["lifecycle_changed_at"],
        }
        return _run_transaction(
            store,
            operation="approve-repair",
            natural_key=approval_id,
            request=request,
            captured_at=now_value,
            writes=[
                _planned_write(store, approval_relative, record, immutable=True),
                _planned_write(store, index_relative, index, immutable=True),
            ],
            result=result,
        )


def _load_unconsumed_repair_approval(
    store: StateStore,
    source: Mapping[str, Any],
    target: Mapping[str, Any],
    now_value: str,
) -> tuple[dict[str, Any], Path]:
    source_tuple = _case_tuple(source)
    target_tuple = _case_tuple(target)
    approval_key = _repair_approval_index_key(source_tuple, target_tuple)
    index_relative = Path("repairs") / "approval-index" / f"{approval_key}.json"
    if not store.exists(index_relative):
        _fail("missing-repair-approval", "proposed -> approved needs exact repair approval")
    index = store.read_json(index_relative)[0]
    _exact_fields(
        index,
        "repair_approval_index",
        {
            "version",
            "kind",
            "approval_key",
            "approval_id",
            "approval_digest",
            "source",
            "target",
            "index_digest",
        },
    )
    index_body = {key: value for key, value in index.items() if key != "index_digest"}
    if (
        index.get("version") != VERSION
        or index.get("kind") != "repair-approval-index"
        or index.get("approval_key") != approval_key
        or index.get("source") != source_tuple
        or index.get("target") != target_tuple
        or index.get("index_digest") != _digest(index_body)
    ):
        _fail("invalid-repair-approval-index", "repair approval index is invalid")
    approval_id = _safe_object_id(index.get("approval_id"), "approval_index.approval_id")
    approval_relative = Path("repairs") / "approvals" / f"{approval_id}.json"
    record = store.read_json(approval_relative)[0]
    approval_digest = _require_string(
        record.get("approval_digest"), "repair_approval.approval_digest"
    )
    approval_body = {key: value for key, value in record.items() if key != "approval_digest"}
    approval = _normalize_repair_approval(approval_body)
    if (
        approval_digest != _digest(approval)
        or approval_digest != index.get("approval_digest")
        or approval["approval_id"] != approval_id
        or approval["source"] != source_tuple
        or approval["target"] != target_tuple
    ):
        _fail("invalid-repair-approval", "persisted repair approval binding is invalid")
    _validate_repair_approval_lifecycle_time(approval, target)
    authority_intent = _require_committed_transaction(store, "approve-repair", approval_id)
    if (
        authority_intent["result"].get("approval_digest") != approval_digest
        or authority_intent["result"].get("approval_key") != approval_key
    ):
        _fail("missing-authority-transaction", "approve-repair WAL does not bind authority")
    authority_lifecycle = authority_intent["result"].get("target_lifecycle_changed_at")
    if (
        authority_lifecycle is not None
        and authority_lifecycle != approval["interaction"]["approved_at"]
    ):
        _fail(
            "repair-approval-lifecycle-mismatch",
            "approve-repair WAL target lifecycle_changed_at must equal repair approved_at",
        )
    closure, _ = _validate_published_closure_authority(store, approval["publication"], source_tuple)
    _validate_repair_approval_times(approval, closure, now_value)
    consumption_relative = Path("repairs") / "consumptions" / f"{approval_id}.json"
    if store.exists(consumption_relative):
        _fail("repair-approval-used", "repair approval was already consumed")
    return {**approval, "approval_digest": approval_digest}, consumption_relative


def _normalize_repair_binding_projection(value: Any, field: str) -> dict[str, Any]:
    binding = _require_object(value, field)
    _exact_fields(
        binding,
        field,
        {"active_repair_id", "repair_ids", "repair_identity_digest"},
    )
    active_repair_id = _bounded_string(
        binding.get("active_repair_id"), f"{field}.active_repair_id", 2, 12
    )
    if REPAIR_ID_RE.fullmatch(active_repair_id) is None:
        _fail("invalid-repair-binding", "active repair binding has an invalid repair ID")
    repair_ids = [
        _bounded_string(repair_id, f"{field}.repair_ids[]", 2, 12)
        for repair_id in _require_list(binding.get("repair_ids"), f"{field}.repair_ids")
    ]
    if (
        not repair_ids
        or len(repair_ids) > 64
        or len(repair_ids) != len(set(repair_ids))
        or any(REPAIR_ID_RE.fullmatch(repair_id) is None for repair_id in repair_ids)
        or active_repair_id not in repair_ids
    ):
        _fail("invalid-repair-binding", "repair binding has an invalid ordered repair list")
    identity_digest = _raw_sha256(
        binding.get("repair_identity_digest"), f"{field}.repair_identity_digest"
    )
    return {
        "active_repair_id": active_repair_id,
        "repair_ids": repair_ids,
        "repair_identity_digest": identity_digest,
    }


def _repair_binding_relative(case_id: str) -> Path:
    return Path("repairs") / "bindings" / f"{_validate_case_id(case_id)}.json"


def _load_repair_approval_consumption(store: StateStore, approval_id: str) -> dict[str, Any]:
    relative = Path("repairs") / "consumptions" / f"{approval_id}.json"
    consumption = store.read_json(relative)[0]
    _exact_fields(
        consumption,
        "repair_approval_consumption",
        {
            "version",
            "kind",
            "approval_id",
            "approval_digest",
            "case_id",
            "revision",
            "semantic_digest",
            "repair_binding",
            "consumed_at",
            "stage_receipt_id",
            "consumption_digest",
        },
    )
    body = {key: value for key, value in consumption.items() if key != "consumption_digest"}
    normalized = {
        "version": consumption.get("version"),
        "kind": consumption.get("kind"),
        "approval_id": _safe_object_id(
            consumption.get("approval_id"), "repair_consumption.approval_id"
        ),
        "approval_digest": _raw_sha256(
            consumption.get("approval_digest"), "repair_consumption.approval_digest"
        ),
        "case_id": _validate_case_id(consumption.get("case_id"), "repair_consumption.case_id"),
        "revision": _require_int(
            consumption.get("revision"), "repair_consumption.revision", minimum=1
        ),
        "semantic_digest": _sha_digest(
            consumption.get("semantic_digest"), "repair_consumption.semantic_digest"
        ),
        "repair_binding": _normalize_repair_binding_projection(
            consumption.get("repair_binding"), "repair_consumption.repair_binding"
        ),
        "consumed_at": _timestamp(consumption.get("consumed_at"), "repair_consumption.consumed_at"),
        "stage_receipt_id": _safe_object_id(
            consumption.get("stage_receipt_id"), "repair_consumption.stage_receipt_id"
        ),
        "consumption_digest": _raw_sha256(
            consumption.get("consumption_digest"), "repair_consumption.consumption_digest"
        ),
    }
    if (
        normalized["version"] != VERSION
        or normalized["kind"] != "repair-approval-consumption"
        or normalized["approval_id"] != approval_id
        or normalized["consumption_digest"] != _digest(body)
    ):
        _fail("invalid-repair-consumption", "repair approval consumption is invalid")
    return normalized


def _load_active_repair_binding(store: StateStore, case_id: str) -> dict[str, Any] | None:
    relative = _repair_binding_relative(case_id)
    if not store.exists(relative):
        return None
    binding = store.read_json(relative)[0]
    _exact_fields(
        binding,
        "active_repair_binding",
        {
            "version",
            "kind",
            "case_id",
            "approval_id",
            "approval_digest",
            "target",
            "repair_binding",
            "consumption_digest",
            "binding_digest",
        },
    )
    body = {key: value for key, value in binding.items() if key != "binding_digest"}
    normalized = {
        "version": binding.get("version"),
        "kind": binding.get("kind"),
        "case_id": _validate_case_id(binding.get("case_id"), "repair_binding.case_id"),
        "approval_id": _safe_object_id(binding.get("approval_id"), "repair_binding.approval_id"),
        "approval_digest": _raw_sha256(
            binding.get("approval_digest"), "repair_binding.approval_digest"
        ),
        "target": _normalize_case_tuple_value(binding.get("target"), "repair_binding.target"),
        "repair_binding": _normalize_repair_binding_projection(
            binding.get("repair_binding"), "repair_binding.repair_binding"
        ),
        "consumption_digest": _raw_sha256(
            binding.get("consumption_digest"), "repair_binding.consumption_digest"
        ),
        "binding_digest": _raw_sha256(
            binding.get("binding_digest"), "repair_binding.binding_digest"
        ),
    }
    if (
        normalized["version"] != VERSION
        or normalized["kind"] != "active-repair-approval-binding"
        or normalized["case_id"] != case_id
        or normalized["target"]["case_id"] != case_id
        or normalized["binding_digest"] != _digest(body)
    ):
        _fail("invalid-repair-binding", "active repair approval binding is invalid")

    approval_relative = Path("repairs") / "approvals" / f"{normalized['approval_id']}.json"
    approval_record = store.read_json(approval_relative)[0]
    approval_digest = _raw_sha256(
        approval_record.get("approval_digest"), "repair_binding.approval_record_digest"
    )
    approval_body = {
        key: value for key, value in approval_record.items() if key != "approval_digest"
    }
    approval = _normalize_repair_approval(approval_body)
    if (
        approval_digest != _digest(approval)
        or approval_digest != normalized["approval_digest"]
        or approval["approval_id"] != normalized["approval_id"]
        or approval["target"] != normalized["target"]
    ):
        _fail("invalid-repair-binding", "active binding does not match its repair approval")
    authority_intent = _require_committed_transaction(
        store, "approve-repair", normalized["approval_id"]
    )
    if authority_intent["result"].get("approval_digest") != normalized["approval_digest"]:
        _fail("missing-authority-transaction", "active binding has no exact approval WAL")

    consumption = _load_repair_approval_consumption(store, normalized["approval_id"])
    consumption_target = {
        "case_id": consumption["case_id"],
        "revision": consumption["revision"],
        "semantic_digest": consumption["semantic_digest"],
    }
    if (
        consumption["approval_digest"] != normalized["approval_digest"]
        or consumption_target != normalized["target"]
        or consumption["repair_binding"] != normalized["repair_binding"]
        or consumption["consumption_digest"] != normalized["consumption_digest"]
    ):
        _fail("invalid-repair-binding", "active binding does not match its consumption")
    receipt_relative = Path("receipts") / "stage" / f"{consumption['stage_receipt_id']}.json"
    receipt = store.read_json(receipt_relative)[0]
    _validate_persisted_receipt(receipt, "stage", consumption["stage_receipt_id"])
    if (
        receipt["case_id"] != case_id
        or receipt["revision"] != normalized["target"]["revision"]
        or receipt["semantic_digest"] != normalized["target"]["semantic_digest"]
        or receipt["repair_approval"]
        != {
            "approval_id": normalized["approval_id"],
            "approval_digest": normalized["approval_digest"],
        }
    ):
        _fail("invalid-repair-binding", "active binding does not match its stage receipt")
    return normalized


def _validate_persisted_repair_binding(
    store: StateStore,
    existing: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> None:
    old_case = _require_object(existing.get("case"), "existing.case")
    case_id = _validate_case_id(old_case.get("id"))
    binding = _load_active_repair_binding(store, case_id)
    if old_case["status"] not in APPROVAL_BOUND_CASE_STATUSES:
        return
    if binding is None:
        _fail(
            "missing-repair-binding",
            "approval-bound case has no durable consumed repair binding",
        )
    if _repair_binding_projection(old_case) != binding["repair_binding"]:
        _fail(
            "consumed-repair-binding-change",
            "current repair history no longer matches its consumed approval binding",
        )
    if not (old_case["status"] == "closed" and candidate["case"]["status"] == "proposed"):
        if _repair_binding_projection(candidate["case"]) != binding["repair_binding"]:
            _fail(
                "consumed-repair-binding-change",
                "candidate repair history no longer matches its consumed approval binding",
            )


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
            marker = _new_state_marker(store, now_value)
            marker_write = _planned_write(store, Path(STATE_MARKER), marker, immutable=True)
        if marker["mode"] == "historical-replay" and state_root.name == "control-state":
            _fail("historical-live-root", "historical state cannot use the canonical live root")
        _validate_automation_origin(state_root, candidate)
        existing_path = _find_case(state_root, summary["case_id"])
        repair_approval: dict[str, Any] | None = None
        consumption_relative: Path | None = None
        active_binding_relative: Path | None = None
        if existing_path is None:
            if summary["status"] not in INITIAL_CASE_STATUSES:
                _fail(
                    "invalid-initial-lifecycle",
                    "a new case must start at watching or proposed; source_kind does not "
                    "authorize a lifecycle import",
                )
            if summary["status"] == "proposed" and summary["support"] != "repeated":
                _fail(
                    "insufficient-proposed-support",
                    "entering proposed requires repeated support",
                )
            if summary["revision"] != 1:
                _fail("revision-order", "a new case must start at revision 1")
            destination = state_root / _case_relative_path(candidate)
            action = "created"
        else:
            existing = _load_json(existing_path)
            validate_candidate(existing)
            action = _validate_case_delta(existing, candidate)
            _validate_persisted_repair_binding(store, existing, candidate)
            if (
                existing["case"]["status"] == "proposed"
                and candidate["case"]["status"] == "approved"
            ):
                _validate_repair_approval_delta(existing, candidate)
                repair_approval, consumption_relative = _load_unconsumed_repair_approval(
                    store, existing, candidate, now_value
                )
                active_binding_relative = _repair_binding_relative(summary["case_id"])
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
        receipt_path = Path("receipts") / "stage" / f"{receipt_id}.json"
        approval_ref: dict[str, str] | None = (
            None
            if repair_approval is None
            else {
                "approval_id": repair_approval["approval_id"],
                "approval_digest": repair_approval["approval_digest"],
            }
        )
        if approval_ref is None and store.exists(receipt_path):
            persisted_receipt = store.read_json(receipt_path)[0]
            _validate_persisted_receipt(persisted_receipt, "stage", receipt_id)
            persisted_ref = persisted_receipt.get("repair_approval")
            if isinstance(persisted_ref, dict):
                approval_ref = dict(persisted_ref)
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
            "repair_approval": approval_ref,
        }
        receipt = {**receipt_body, "digest": _digest(receipt_body)}
        writes = []
        if marker_write is not None:
            writes.append(marker_write)
        if repair_approval is not None:
            assert consumption_relative is not None
            assert active_binding_relative is not None
            repair_binding = _repair_binding_projection(candidate["case"])
            consumption_body = {
                "version": VERSION,
                "kind": "repair-approval-consumption",
                "approval_id": repair_approval["approval_id"],
                "approval_digest": repair_approval["approval_digest"],
                "case_id": summary["case_id"],
                "revision": summary["revision"],
                "semantic_digest": summary["semantic_digest"],
                "repair_binding": repair_binding,
                "consumed_at": now_value,
                "stage_receipt_id": receipt_id,
            }
            consumption = {**consumption_body, "consumption_digest": _digest(consumption_body)}
            writes.append(_planned_write(store, consumption_relative, consumption, immutable=True))
            binding_body = {
                "version": VERSION,
                "kind": "active-repair-approval-binding",
                "case_id": summary["case_id"],
                "approval_id": repair_approval["approval_id"],
                "approval_digest": repair_approval["approval_digest"],
                "target": _case_tuple(candidate),
                "repair_binding": repair_binding,
                "consumption_digest": consumption["consumption_digest"],
            }
            binding = {**binding_body, "binding_digest": _digest(binding_body)}
            writes.append(_planned_write(store, active_binding_relative, binding, immutable=False))
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
            request={
                "candidate_file_sha256": candidate_file_sha,
                "anchor": anchor,
                "repair_approval": receipt_body["repair_approval"],
            },
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
            marker = _new_state_marker(store, now_value)
            marker_write = _planned_write(store, Path(STATE_MARKER), marker, immutable=True)
        anchor = _last_pointer_digest(state_root)
        pending = _pending_case_ids(state_root)
        pending_digest = _digest(sorted(pending))
        natural_key = f"{anchor or 'initial'}:{pending_digest}"
        if _transaction_record_exists(store, "dormancy", natural_key):
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
            "repair_approval",
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
        repair_approval = receipt["repair_approval"]
        if repair_approval is not None:
            approval_ref = _require_object(repair_approval, "receipt.repair_approval")
            _exact_fields(
                approval_ref,
                "receipt.repair_approval",
                {"approval_id", "approval_digest"},
            )
            _safe_object_id(approval_ref["approval_id"], "receipt.repair_approval.approval_id")
            if (
                HEX64_RE.fullmatch(
                    _require_string(
                        approval_ref["approval_digest"],
                        "receipt.repair_approval.approval_digest",
                    )
                )
                is None
            ):
                _fail("invalid-receipt", "repair approval digest must be raw SHA-256")
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


def _validate_complete_audit_intent_receipts(
    store: StateStore,
    intent: Mapping[str, Any],
    *,
    recover_publication: bool = True,
) -> None:
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
    if recover_publication:
        receipt_objects = {
            category: _receipt_objects(store.root, category, anchor)
            for category in ("stage", "dormancy")
        }
    else:
        receipt_objects: dict[str, list[dict[str, Any]]] = {}
        for category in ("stage", "dormancy"):
            directory = Path("receipts") / category
            objects: list[dict[str, Any]] = []
            for name in store.list_names(directory):
                if not name.endswith(".json") or SAFE_OBJECT_ID_RE.fullmatch(name[:-5]) is None:
                    _fail("unsafe-receipt-layout", f"unexpected receipt entry: {name}")
                receipt = _read_state_json(
                    store,
                    directory / name,
                    recover_publication=False,
                )
                _validate_persisted_receipt(receipt, category, name[:-5])
                if receipt.get("anchor_snapshot_digest") == anchor:
                    objects.append(receipt)
            receipt_objects[category] = sorted(
                objects,
                key=lambda receipt: receipt["receipt_id"],
            )
    expected_stage_refs = [
        {"receipt_id": receipt["receipt_id"], "digest": receipt["digest"]}
        for receipt in receipt_objects["stage"]
    ]
    expected_dormancy_refs = [
        {"receipt_id": receipt["receipt_id"], "digest": receipt["digest"]}
        for receipt in receipt_objects["dormancy"]
    ]
    if stage_refs != expected_stage_refs:
        _fail("invalid-wal", "complete-audit snapshot does not bind every stage receipt")
    if dormancy_refs != expected_dormancy_refs:
        _fail("invalid-wal", "complete-audit snapshot does not bind every dormancy receipt")
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
    with _state_lock(state_root, recover_marker_publication=False) as store:
        _preflight_transaction_binding_read_only(
            store,
            operation="complete-audit",
            natural_key=natural_key,
            request=request,
        )
        _read_marker(state_root)

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

        if _transaction_record_exists(store, "complete-audit", natural_key):
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
            marker = _new_state_marker(store, now_value)
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
    with _state_lock(
        state_root,
        create=False,
        recover_marker_publication=False,
    ) as store:
        _preflight_transaction_binding_read_only(
            store,
            operation="selection-preflight",
            natural_key=selection_id,
            request={"selection_basis": basis},
        )
        _read_marker(state_root)
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
            if not _transaction_record_exists(store, "selection-preflight", selection_id):
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
    output = _normalize_external_output_outside_state_root(state_root, output)
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
    with _state_lock(
        state_root,
        create=False,
        recover_marker_publication=False,
    ) as store:
        _preflight_transaction_binding_read_only(
            store,
            operation="weekly-plan",
            natural_key=selection_id,
            request=request,
            approved_intent_upper_bound=selection["resource_preflight"][
                "weekly_wal_upper_bound_bytes"
            ],
        )
        _read_marker(state_root)
        _validate_external_output_target(store, output)
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
        if _transaction_record_exists(store, "weekly-plan", selection_id):
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
        output_write = _planned_external_write(store, output, plan, immutable=True)
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
    if len(commit_sha) != len(entry["base_sha"]):
        _fail(
            "prepared-commit-format",
            f"prepared commit must use the bound base SHA object-ID width for {case_id}",
        )
    if commit_sha == entry["base_sha"]:
        _fail(
            "prepared-base-commit",
            f"prepared commit must differ from the bound base SHA for {case_id}",
        )
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


def _validate_finalize_transaction_authority(
    transaction: Mapping[str, Any],
    plan: Mapping[str, Any],
    prepared: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> None:
    selection_id = _safe_object_id(plan.get("selection_id"), "plan.selection_id")
    plan_digest = _raw_sha256(plan.get("plan_digest"), "plan.plan_digest")
    natural_key = f"{selection_id}:{plan_digest}"
    if (
        transaction.get("operation") != "finalize-publication"
        or transaction.get("natural_key") != natural_key
    ):
        _fail("missing-authority-transaction", "finalize transaction key is invalid")
    writes = [
        _require_object(raw, f"finalize.writes[{index}]")
        for index, raw in enumerate(_require_list(transaction.get("writes"), "finalize.writes"))
    ]
    prepared_path = f"publication/prepared/{selection_id}.json"
    manifest_path = f"publication/manifests/{selection_id}.json"
    prepared_sha = hashlib.sha256(_canonical_bytes(prepared)).hexdigest()
    manifest_sha = hashlib.sha256(_canonical_bytes(manifest)).hexdigest()

    def matches(write: Mapping[str, Any], *, scope: str, path: str, digest: str) -> bool:
        return (
            write.get("scope") == scope
            and write.get("path") == path
            and write.get("after_sha256") == digest
            and write.get("immutable") is True
        )

    prepared_writes = [
        write
        for write in writes
        if matches(write, scope="state", path=prepared_path, digest=prepared_sha)
    ]
    manifest_writes = [
        write
        for write in writes
        if matches(write, scope="state", path=manifest_path, digest=manifest_sha)
    ]
    external_writes = [
        write
        for write in writes
        if write.get("scope") == "external"
        and write.get("after_sha256") == manifest_sha
        and write.get("immutable") is True
    ]
    if (
        len(writes) != 3
        or len(prepared_writes) != 1
        or len(manifest_writes) != 1
        or len(external_writes) != 1
    ):
        _fail(
            "missing-authority-transaction",
            "finalize transaction does not bind exact prepared, manifest, and external output",
        )
    full_intent = transaction.get("kind") == "state-transaction-intent"
    if full_intent:
        if (
            prepared_writes[0].get("after") != prepared
            or manifest_writes[0].get("after") != manifest
            or external_writes[0].get("after") != manifest
        ):
            _fail(
                "missing-authority-transaction",
                "finalize transaction after-images do not match immutable authorities",
            )
    elif transaction.get("kind") != "retired-state-transaction":
        _fail("missing-authority-transaction", "finalize transaction kind is invalid")
    external_path = _require_string(external_writes[0].get("path"), "finalize.output")
    if not full_intent and external_writes[0].get("replica_path") != manifest_path:
        _fail(
            "missing-authority-transaction",
            "retired finalize transaction does not bind its manifest replica",
        )
    expected_request_digest = _digest(
        {"plan": dict(plan), "prepared": dict(prepared), "output": external_path}
    )
    expected_result = {
        "version": VERSION,
        "status": "finalized",
        "manifest_path": external_path,
        "manifest_digest": manifest["manifest_digest"],
        "entry_count": len(_require_list(manifest["entries"], "manifest.entries")),
    }
    if (
        transaction.get("request_digest") != expected_request_digest
        or transaction.get("result") != expected_result
    ):
        _fail(
            "missing-authority-transaction",
            "finalize transaction does not bind exact request and result",
        )


def _validate_finalize_publication_intent(
    store: StateStore,
    intent: Mapping[str, Any],
    *,
    recover_publication: bool = True,
) -> None:
    """Revalidate prepared and manifest after-images for a full finalize WAL."""

    if intent.get("kind") == "retired-state-transaction":
        _fail("invalid-wal", "full finalize intent validation received a checkpoint projection")
    prepared_receipts: list[dict[str, Any]] = []
    state_manifests: list[dict[str, Any]] = []
    external_manifests: list[dict[str, Any]] = []
    for index, raw_write in enumerate(_require_list(intent["writes"], "wal.writes")):
        write = _require_object(raw_write, f"wal.writes[{index}]")
        after = _require_object(write.get("after"), f"wal.writes[{index}].after")
        if after.get("kind") == "prepared-commits" and write.get("scope") == "state":
            prepared_receipts.append(after)
        elif after.get("kind") == "publication-manifest":
            target = state_manifests if write.get("scope") == "state" else external_manifests
            target.append(after)
    if (
        len(prepared_receipts) != 1
        or len(state_manifests) != 1
        or len(external_manifests) != 1
        or state_manifests[0] != external_manifests[0]
    ):
        _fail(
            "invalid-wal",
            "finalize-publication intent must bind one prepared receipt and identical manifests",
        )
    prepared = prepared_receipts[0]
    manifest = state_manifests[0]
    selection_id = _safe_object_id(manifest.get("selection_id"), "manifest.selection_id")
    plan_relative = Path("publication") / "plans" / f"{selection_id}.json"
    plan = _read_state_json(
        store,
        plan_relative,
        recover_publication=recover_publication,
    )
    _validate_manifest(manifest, plan, prepared)
    _validate_finalize_transaction_authority(intent, plan, prepared, manifest)


def _validate_registered_finalized_publication_authority(
    store: StateStore,
    *,
    selection_id: str,
    plan_digest: str,
    manifest_digest: str,
    recover_publication: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    plan_relative = Path("publication") / "plans" / f"{selection_id}.json"
    prepared_relative = Path("publication") / "prepared" / f"{selection_id}.json"
    manifest_relative = Path("publication") / "manifests" / f"{selection_id}.json"
    plan = _read_state_json(
        store,
        plan_relative,
        recover_publication=recover_publication,
    )
    prepared = _read_state_json(
        store,
        prepared_relative,
        recover_publication=recover_publication,
    )
    manifest = _read_state_json(
        store,
        manifest_relative,
        recover_publication=recover_publication,
    )
    _validate_plan(plan)
    if plan.get("selection_id") != selection_id or plan.get("plan_digest") != plan_digest:
        _fail("unregistered-plan", "registered publication plan binding is invalid")
    _validate_manifest(manifest, plan, prepared)
    if manifest.get("manifest_digest") != manifest_digest:
        _fail("publication-receipt-mismatch", "registered manifest digest mismatch")
    weekly_intent = _require_committed_transaction(
        store,
        "weekly-plan",
        selection_id,
        recover_publication=recover_publication,
    )
    if weekly_intent["result"].get("plan_digest") != plan_digest:
        _fail("unregistered-plan", "weekly transaction does not bind registered plan")
    finalize_intent = _require_committed_transaction(
        store,
        "finalize-publication",
        f"{selection_id}:{plan_digest}",
        recover_publication=recover_publication,
    )
    _validate_finalize_transaction_authority(finalize_intent, plan, prepared, manifest)
    return plan, prepared, manifest, finalize_intent


def finalize_publication(
    state_root: Path, plan_path: Path, prepared_path: Path, output: Path, now: str
) -> dict[str, Any]:
    output = _normalize_external_output_outside_state_root(state_root, output)
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

    with _state_lock(
        state_root,
        create=False,
        recover_marker_publication=False,
    ) as store:
        _preflight_transaction_binding_read_only(
            store,
            operation="finalize-publication",
            natural_key=natural_key,
            request=request,
            approved_intent_upper_bound=finalize_wal_upper_bound,
        )
        _read_marker(state_root)
        _validate_external_output_target(store, output)
        _recover_pending_wal(store)
        existing_finalize_intent: dict[str, Any] | None = None
        if _transaction_record_exists(store, "finalize-publication", natural_key):
            existing_finalize_intent = _require_committed_transaction(
                store, "finalize-publication", natural_key
            )
            persisted_intent_bytes = existing_finalize_intent.get("intent_bytes")
            if persisted_intent_bytes is None:
                persisted_intent_bytes = len(_canonical_bytes(existing_finalize_intent))
            if persisted_intent_bytes > finalize_wal_upper_bound:
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
            if existing_finalize_intent.get("kind") == "state-transaction-intent":
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
        output_write = _planned_external_write(store, output, manifest, immutable=True)
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


def _validate_published_ledger_commit(item: Mapping[str, Any], plan: Mapping[str, Any]) -> None:
    case_id = _validate_case_id(item.get("case_id"), "closure.case_id")
    base_intent = _require_object(plan.get("base_intent"), "plan.base_intent")
    base_sha = _require_string(base_intent.get("base_sha"), "plan.base_sha")
    ledger_commit = _require_string(item.get("ledger_commit"), "closure.ledger_commit")
    if GIT_SHA_RE.fullmatch(base_sha) is None or COMMIT_RE.fullmatch(ledger_commit) is None:
        _fail("invalid-git-sha", f"publication commit binding is invalid for {case_id}")
    if len(ledger_commit) != len(base_sha):
        _fail(
            "ledger-commit-format",
            f"published ledger commit must use the plan base SHA object-ID width for {case_id}",
        )
    if ledger_commit == base_sha:
        _fail(
            "ledger-commit-base",
            f"published ledger commit must differ from the plan base SHA for {case_id}",
        )


def _validate_manifest_closure_entry(manifest: Mapping[str, Any], item: Mapping[str, Any]) -> None:
    if manifest.get("manifest_digest") != item.get("manifest_digest"):
        _fail("publication-receipt-mismatch", "closure manifest digest mismatch")
    case_id = _validate_case_id(item.get("case_id"), "closure.case_id")
    matches = [
        _require_object(raw, "manifest.entry")
        for raw in _require_list(manifest.get("entries"), "manifest.entries")
        if isinstance(raw, dict) and raw.get("case_id") == case_id
    ]
    if len(matches) != 1 or any(
        matches[0].get(field) != item.get(field) for field in ("revision", "semantic_digest")
    ):
        _fail(
            "publication-receipt-mismatch",
            "closure case tuple is not an exact finalized manifest entry",
        )


def _validate_persisted_closure_record(closure: Mapping[str, Any]) -> None:
    _exact_fields(
        closure,
        "publication_closure",
        {
            "version",
            "kind",
            "closure_id",
            "interaction",
            "reason",
            "summary",
            "entries",
            "publication_approval_digest",
            "recorded_at",
            "closure_digest",
        },
    )
    if (
        closure.get("version") != VERSION
        or closure.get("kind") != "publication-closure"
        or closure.get("reason") not in {"published", "cancelled", "stale"}
    ):
        _fail("invalid-closure", "persisted publication closure is invalid")
    _safe_object_id(closure.get("closure_id"), "closure.closure_id")
    interaction = _require_object(closure.get("interaction"), "closure.interaction")
    _exact_fields(interaction, "closure.interaction", {"interactive", "actor", "closed_at"})
    if interaction.get("interactive") is not True or interaction.get("actor") != "Joey":
        _fail("untrusted-closure", "persisted closure is not an interactive Joey decision")
    closed_at = _timestamp(interaction.get("closed_at"), "closure.closed_at")
    if closure.get("recorded_at") != closed_at:
        _fail("invalid-closure", "persisted closure recorded_at differs from its decision time")
    _bounded_string(closure.get("summary"), "closure.summary", 8, 500)
    entries = _require_list(closure.get("entries"), "closure.entries")
    if not entries:
        _fail("empty-closure", "persisted publication closure has no entries")
    prior = ""
    for raw_entry in entries:
        entry = _require_object(raw_entry, "closure.entry")
        case_id = _validate_case_id(entry.get("case_id"), "closure.case_id")
        if case_id <= prior:
            _fail("duplicate-closure-entry", "persisted closure entries are not unique and sorted")
        prior = case_id
        _require_int(entry.get("revision"), "closure.revision", minimum=1)
        _sha_digest(entry.get("semantic_digest"), "closure.semantic_digest")
        _safe_object_id(entry.get("selection_id"), "closure.selection_id")
        _raw_sha256(entry.get("plan_digest"), "closure.plan_digest")
    body = {key: value for key, value in closure.items() if key != "closure_digest"}
    if closure.get("closure_digest") != _digest(body):
        _fail("invalid-closure", "persisted publication closure digest mismatch")


def _validate_published_closure_entries_against_plans(
    store: StateStore,
    entries: Sequence[Mapping[str, Any]],
    *,
    recover_publication: bool,
) -> None:
    for raw_entry in entries:
        item = _require_object(raw_entry, "closure.entry")
        selection_id = _safe_object_id(item.get("selection_id"), "closure.selection_id")
        plan_digest = _raw_sha256(item.get("plan_digest"), "closure.plan_digest")
        manifest_digest = _raw_sha256(
            item.get("manifest_digest"),
            "closure.manifest_digest",
        )
        plan, _, manifest, _ = _validate_registered_finalized_publication_authority(
            store,
            selection_id=selection_id,
            plan_digest=plan_digest,
            manifest_digest=manifest_digest,
            recover_publication=recover_publication,
        )
        _validate_manifest_closure_entry(manifest, item)
        _validate_published_ledger_commit(item, plan)


def _validate_close_publication_intent_commits(
    store: StateStore,
    intent: Mapping[str, Any],
    *,
    recover_publication: bool = True,
) -> None:
    """Revalidate closure after-images and published commit bindings."""

    writes = _require_list(intent["writes"], "wal.writes")
    closures: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for index, raw_write in enumerate(writes):
        write = _require_object(raw_write, f"wal.writes[{index}]")
        if write.get("scope") != "state":
            continue
        after = _require_object(write.get("after"), f"wal.writes[{index}].after")
        if after.get("kind") == "publication-closure":
            closures.append((write, after))
    if len(closures) != 1:
        _fail("invalid-wal", "close-publication intent must contain one closure record")
    closure_write, closure = closures[0]
    _validate_persisted_closure_record(closure)
    if (
        intent.get("natural_key") != closure["closure_id"]
        or closure_write.get("path") != f"publication/closures/{closure['closure_id']}.json"
        or closure_write.get("immutable") is not True
    ):
        _fail(
            "invalid-wal",
            "close-publication intent key, closure path, or mutability is invalid",
        )
    entries = [
        _require_object(raw, "closure.entry")
        for raw in _require_list(closure["entries"], "closure.entries")
    ]
    if len(writes) != len(entries) + 1:
        _fail("invalid-wal", "close-publication intent has unexpected extra writes")
    active_after_images: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for index, raw_write in enumerate(writes):
        write = _require_object(raw_write, f"wal.writes[{index}]")
        if write.get("scope") != "state":
            continue
        after = _require_object(write.get("after"), f"wal.writes[{index}].after")
        if after.get("kind") != "publication-pending":
            continue
        case_id = _validate_case_id(after.get("case_id"), "publication.active.case_id")
        _validate_pending_record(after, case_id)
        if case_id in active_after_images:
            _fail("invalid-wal", "close-publication intent repeats an active after-image")
        active_after_images[case_id] = (write, after)
    if set(active_after_images) != {entry["case_id"] for entry in entries}:
        _fail("invalid-wal", "close-publication intent active after-images differ from closure")
    for entry in entries:
        active_write, active = active_after_images[entry["case_id"]]
        if (
            active_write.get("path") != f"publication/active/{entry['case_id']}.json"
            or active_write.get("immutable") is not False
        ):
            _fail(
                "invalid-wal",
                "close-publication active after-image path or mutability is invalid",
            )
        expected = {
            "case_id": entry["case_id"],
            "revision": entry["revision"],
            "semantic_digest": entry["semantic_digest"],
            "selection_id": entry["selection_id"],
            "plan_digest": entry["plan_digest"],
            "status": "closed",
            "closure_id": closure["closure_id"],
            "closure_digest": closure["closure_digest"],
            "closure_reason": closure["reason"],
            "closed_at": closure["recorded_at"],
        }
        if any(active.get(field) != value for field, value in expected.items()):
            _fail("invalid-wal", "close-publication active after-image differs from closure")
    expected_result = {
        "version": VERSION,
        "status": "closed",
        "closure_id": closure["closure_id"],
        "closure_digest": closure["closure_digest"],
        "closed_count": len(entries),
    }
    if intent.get("result") != expected_result:
        _fail("invalid-wal", "close-publication WAL result differs from closure")
    if closure.get("reason") == "published":
        _validate_published_closure_entries_against_plans(
            store,
            entries,
            recover_publication=recover_publication,
        )


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

    with _state_lock(
        state_root,
        create=False,
        recover_marker_publication=False,
    ) as store:
        _preflight_transaction_binding_read_only(
            store,
            operation="close-publication",
            natural_key=closure_id,
            request=request,
        )
        if reason == "published":
            _validate_published_closure_entries_against_plans(
                store,
                normalized,
                recover_publication=False,
            )
        _preflight_existing_transaction_domain_read_only(
            store,
            operation="close-publication",
            natural_key=closure_id,
        )
        _read_marker(state_root)
        _recover_pending_wal(store)
        if _transaction_record_exists(store, "close-publication", closure_id):
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
                _validate_published_ledger_commit(item, plan)
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

    approve = subparsers.add_parser(
        "approve-repair",
        help="persist one exact interactive Joey repair authority",
    )
    approve.add_argument("--state-root", type=Path, required=True)
    approve.add_argument("--candidate", type=Path, required=True)
    approve.add_argument("--approval", type=Path, required=True)
    approve.add_argument("--now", required=True)
    approve.add_argument(
        "--confirm-interactive-joey-decision",
        action="store_true",
        required=True,
        help="attest that this invocation consumes Joey's current interactive decision",
    )

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

    wal_audit = subparsers.add_parser(
        "audit-wal-history",
        help="explicitly audit compact WAL history and usage accounting",
    )
    wal_audit.add_argument("--state-root", type=Path, required=True)
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
    if args.command == "approve-repair":
        return approve_repair(
            Path(os.path.abspath(args.state_root)),
            args.candidate,
            args.approval,
            args.now,
            interactive_confirmed=args.confirm_interactive_joey_decision,
        )
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
    if args.command == "audit-wal-history":
        return audit_wal_history(Path(os.path.abspath(args.state_root)))
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
