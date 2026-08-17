#!/usr/bin/env python3
"""Bootstrap and verify the host-local Daily Skill Friction control plane.

Filesystem guards protect object identity (device/inode), exact bounded content,
and access policy (type, owner, group, and mode). Timestamp-only changes are not
treated as mutation. Managed replacement uses a same-directory kernel exchange
or no-replace rename, retains the previous object until commit, and fsyncs both
the file and parent directory.
"""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import datetime as dt
import errno
import hashlib
import json
import os
import plistlib
import re
import secrets
import signal
import stat
import subprocess
import sys
import tomllib
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any


class SetupError(RuntimeError):
    """Raised when bootstrap state cannot be proved safe and complete."""


MANAGED_PLIST_MARKER = b"Managed by Joey-Tools/codex-host-workflows:scripts/host_setup.py"
EXCLUDE_BEGIN = "# >>> codex-host-workflows daily-skill-friction >>>"
EXCLUDE_ENTRY = "/.agents/skills/daily-skill-friction"
EXCLUDE_END = "# <<< codex-host-workflows daily-skill-friction <<<"
STAMP_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
REPO_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
LAUNCH_AGENT_LABEL_PATTERN = re.compile(
    r"(?=.{3,128}\Z)(?:[A-Za-z0-9][A-Za-z0-9-]*\.){2,}"
    r"[A-Za-z0-9][A-Za-z0-9-]*\Z"
)
MAX_CONFIG_BYTES = 1024 * 1024
MAX_STAMP_BYTES = 1024 * 1024
MAX_COMMAND_DETAIL = 2000
GIT_TIMEOUT_SECONDS = 20
COMMAND_TIMEOUT_SECONDS = 120
COMMAND_TERM_GRACE_SECONDS = 2
COMMAND_KILL_GRACE_SECONDS = 2


@dataclasses.dataclass(frozen=True)
class Binding:
    dev: int
    ino: int
    uid: int
    gid: int
    mode: int
    size: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> Binding:
        return cls(
            dev=metadata.st_dev,
            ino=metadata.st_ino,
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            mode=metadata.st_mode,
            size=metadata.st_size,
        )


@dataclasses.dataclass(frozen=True)
class FileSnapshot:
    binding: Binding
    data: bytes

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclasses.dataclass(frozen=True)
class RepoSpec:
    name: str
    url: str
    default_branch: str
    visibility: str


@dataclasses.dataclass(frozen=True)
class WorkspaceManifest:
    path: Path
    cache_root: Path
    repos: tuple[RepoSpec, ...]
    snapshot: FileSnapshot

    @property
    def digest(self) -> str:
        return self.snapshot.digest

    @property
    def root(self) -> Path:
        return self.path.parent

    def repo_path(self, repo: RepoSpec) -> Path:
        return self.cache_root / "repos" / repo.name


@dataclasses.dataclass(frozen=True)
class HostConfig:
    path: Path
    manifest_snapshot: FileSnapshot
    repo_root: Path
    workspace_root: Path
    cache_root: Path
    python_executable: Path
    control_repo: RepoSpec
    skill_relative_path: Path
    locator_relative_path: Path
    launch_agent_label: str
    launch_agent_source_relative_path: Path
    weekly_launch_agent_label: str
    weekly_launch_agent_source_relative_path: Path
    control_stamp: str
    main_stamp: str
    weekly_pair_receipt: str
    prefetch_hour: int
    prefetch_minute: int
    weekly_prefetch_weekday: int
    weekly_prefetch_hour: int
    weekly_prefetch_minute: int
    default_max_age_minutes: int

    @property
    def workspace_helper(self) -> Path:
        return self.workspace_root / "scripts" / "codex_workspace.py"

    @property
    def main_manifest(self) -> Path:
        return self.workspace_root / "workspace.toml"

    @property
    def control_mirror(self) -> Path:
        return self.cache_root / "repos" / self.control_repo.name

    @property
    def control_mirror_manifest(self) -> Path:
        return self.control_mirror / "config" / self.path.name

    @property
    def control_mirror_script(self) -> Path:
        return self.control_mirror / "scripts" / "host_setup.py"

    @property
    def skill_source(self) -> Path:
        return self.control_mirror / self.skill_relative_path

    @property
    def skill_locator(self) -> Path:
        return self.workspace_root / self.locator_relative_path

    @property
    def launch_agent_source(self) -> Path:
        return self.repo_root / self.launch_agent_source_relative_path

    @property
    def weekly_launch_agent_source(self) -> Path:
        return self.repo_root / self.weekly_launch_agent_source_relative_path

    @property
    def log_root(self) -> Path:
        return self.cache_root / "logs"

    @property
    def state_root(self) -> Path:
        return self.cache_root / "state"

    @property
    def reload_receipt(self) -> Path:
        return self.state_root / "launch-agent-reload-required.json"

    @property
    def weekly_receipt(self) -> Path:
        return self.cache_root / "freshness" / f"{self.weekly_pair_receipt}.json"


@dataclasses.dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class LaunchAgentSpec:
    key: str
    label: str
    source: Path
    destination: Path
    expected: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class PlannedLaunchAgent:
    spec: LaunchAgentSpec
    source: FileSnapshot
    installed: FileSnapshot | None
    changed: bool


@dataclasses.dataclass(frozen=True)
class ServiceState:
    label: str
    loaded: bool
    plist_snapshot: FileSnapshot | None = None


class CommandRunner:
    """Injectable subprocess boundary for helper and launchctl operations."""

    def __init__(
        self,
        *,
        timeout_seconds: float = COMMAND_TIMEOUT_SECONDS,
        term_grace_seconds: float = COMMAND_TERM_GRACE_SECONDS,
        kill_grace_seconds: float = COMMAND_KILL_GRACE_SECONDS,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.term_grace_seconds = term_grace_seconds
        self.kill_grace_seconds = kill_grace_seconds

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        process: subprocess.Popen[str] | None = None
        try:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(env) if env is not None else None,
                start_new_session=True,
            )
            stdout, stderr = process.communicate(timeout=self.timeout_seconds)
            return subprocess.CompletedProcess(list(argv), process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired as error:
            assert process is not None
            self._terminate_process_group(process)
            raise SetupError(f"command timed out: {argv[0]}") from error
        except OSError as error:
            raise SetupError(
                f"could not start {argv[0]}: {error.strerror or type(error).__name__}"
            ) from error

    def _terminate_process_group(self, process: subprocess.Popen[str]) -> None:
        """Terminate the complete command process group and bound pipe draining."""

        process_group = process.pid
        try:
            os.killpg(process_group, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=self.term_grace_seconds)
            try:
                os.killpg(process_group, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=self.kill_grace_seconds)
        except subprocess.TimeoutExpired as error:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            try:
                process.wait(timeout=self.kill_grace_seconds)
            except subprocess.TimeoutExpired as wait_error:
                raise SetupError(
                    "timed-out command process group could not be reaped"
                ) from wait_error
            raise SetupError("timed-out command pipes could not be drained") from error


def _binding_tuple(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    binding = Binding.from_stat(metadata)
    return (
        binding.dev,
        binding.ino,
        binding.uid,
        binding.gid,
        binding.mode,
        binding.size,
    )


def _directory_binding_tuple(binding: Binding) -> tuple[int, int, int, int, int]:
    """Bind directory identity/access policy without child-entry-derived size."""

    return (binding.dev, binding.ino, binding.uid, binding.gid, binding.mode)


def _validate_directory_metadata(
    metadata: os.stat_result,
    *,
    label: str,
    require_current_owner: bool,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise SetupError(f"{label} is not a real directory")
    allowed_owners = {0, os.getuid()}
    if metadata.st_uid not in allowed_owners:
        raise SetupError(f"{label} is not owned by root or uid {os.getuid()}")
    if require_current_owner and metadata.st_uid != os.getuid():
        raise SetupError(f"{label} is not owned by uid {os.getuid()}")
    if metadata.st_mode & 0o022:
        sticky_root = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
        if not sticky_root:
            raise SetupError(f"{label} is group- or world-writable")


def _normalized_absolute(path: Path, *, field: str) -> Path:
    if not path.is_absolute():
        raise SetupError(f"{field} must be an absolute path")
    normalized = Path(os.path.normpath(str(path)))
    if normalized != path or ".." in path.parts:
        raise SetupError(f"{field} must be a normalized absolute path")
    return path


def _open_real_directory(
    path: Path,
    *,
    label: str,
    require_current_owner: bool = False,
) -> tuple[int, Binding]:
    path = _normalized_absolute(path, field=label)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open("/", flags)
    try:
        root_metadata = os.fstat(descriptor)
        _validate_directory_metadata(
            root_metadata, label=f"{label} root", require_current_owner=False
        )
        current = Path("/")
        for component in path.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                problem = (
                    "a missing component"
                    if error.errno == errno.ENOENT
                    else "a symlinked or unreadable component"
                )
                raise SetupError(
                    f"{label} has {problem} at "
                    f"{current / component}: {error.strerror or type(error).__name__}"
                ) from error
            os.close(descriptor)
            descriptor = child
            current /= component
            metadata = os.fstat(descriptor)
            _validate_directory_metadata(
                metadata,
                label=f"{label} component {current}",
                require_current_owner=require_current_owner and current == path,
            )
        return descriptor, Binding.from_stat(os.fstat(descriptor))
    except BaseException:
        os.close(descriptor)
        raise


def _directory_path_matches(path: Path, expected: Binding, *, label: str) -> None:
    descriptor, current = _open_real_directory(path, label=label)
    try:
        if _directory_binding_tuple(current) != _directory_binding_tuple(expected):
            raise SetupError(f"{label} directory identity or access policy changed: {path}")
    finally:
        os.close(descriptor)


def _read_bounded_descriptor(descriptor: int, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    retained = 0
    while retained <= max_bytes:
        chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - retained))
        if not chunk:
            break
        chunks.append(chunk)
        retained += len(chunk)
    return b"".join(chunks)


def _snapshot_at(
    parent_fd: int,
    name: str,
    *,
    max_bytes: int,
    label: str,
    missing_ok: bool = False,
) -> FileSnapshot | None:
    if "/" in name or name in {"", ".", ".."}:
        raise SetupError(f"{label} has an invalid leaf name")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise SetupError(f"{label} is missing") from None
    except OSError as error:
        raise SetupError(
            f"{label} could not be opened without following links: "
            f"{error.strerror or type(error).__name__}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SetupError(f"{label} must be a regular file and not a symlink")
        if metadata.st_uid != os.getuid():
            raise SetupError(f"{label} is not owned by uid {os.getuid()}")
        if metadata.st_mode & 0o022:
            raise SetupError(f"{label} is group- or world-writable")
        if metadata.st_size > max_bytes:
            raise SetupError(f"{label} exceeds the {max_bytes}-byte limit")
        first = _read_bounded_descriptor(descriptor, max_bytes)
        if len(first) != metadata.st_size:
            raise SetupError(f"{label} changed while it was being read")
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_bounded_descriptor(descriptor, max_bytes)
        rebound = os.fstat(descriptor)
        if first != second or _binding_tuple(rebound) != _binding_tuple(metadata):
            raise SetupError(f"{label} content or access policy changed while reading")
        path_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _binding_tuple(path_metadata) != _binding_tuple(metadata):
            raise SetupError(f"{label} object was replaced while reading")
        return FileSnapshot(binding=Binding.from_stat(metadata), data=first)
    finally:
        os.close(descriptor)


def _read_owned_regular_file(path: Path, *, max_bytes: int, label: str) -> FileSnapshot:
    path = _normalized_absolute(path, field=label)
    parent_fd, parent_binding = _open_real_directory(path.parent, label=f"{label} parent")
    try:
        snapshot = _snapshot_at(parent_fd, path.name, max_bytes=max_bytes, label=label)
        assert snapshot is not None
        _directory_path_matches(path.parent, parent_binding, label=f"{label} parent")
        return snapshot
    finally:
        os.close(parent_fd)


def _optional_owned_file(path: Path, *, max_bytes: int, label: str) -> FileSnapshot | None:
    path = _normalized_absolute(path, field=label)
    parent_fd, parent_binding = _open_real_directory(path.parent, label=f"{label} parent")
    try:
        snapshot = _snapshot_at(
            parent_fd,
            path.name,
            max_bytes=max_bytes,
            label=label,
            missing_ok=True,
        )
        _directory_path_matches(path.parent, parent_binding, label=f"{label} parent")
        return snapshot
    finally:
        os.close(parent_fd)


def _require_string(table: dict[str, Any], key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise SetupError(f"host_setup.{key} must be a non-empty string")
    return value


def _require_int(table: dict[str, Any], key: str) -> int:
    value = table.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise SetupError(f"host_setup.{key} must be an integer")
    return value


def _absolute_path(raw: str, *, field: str) -> Path:
    return _normalized_absolute(Path(raw), field=field)


def _safe_relative_path(raw: str, *, field: str) -> Path:
    path = Path(raw)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise SetupError(f"{field} must be a normalized relative path")
    if Path(os.path.normpath(raw)) != path:
        raise SetupError(f"{field} must be a normalized relative path")
    return path


def _stamp_name(raw: str, *, field: str) -> str:
    if not STAMP_NAME_PATTERN.fullmatch(raw):
        raise SetupError(f"{field} must be 1-80 characters of letters, numbers, '.', '_', or '-'")
    return raw


def _launch_agent_label(raw: str, *, field: str) -> str:
    if not LAUNCH_AGENT_LABEL_PATTERN.fullmatch(raw):
        raise SetupError(
            f"{field} must be a 3-128 character reverse-DNS label using only "
            "letters, numbers, and hyphens in each component"
        )
    return raw


def _parse_repo_specs(raw: Any, *, label: str) -> tuple[RepoSpec, ...]:
    if not isinstance(raw, list) or not raw:
        raise SetupError(f"{label} must define at least one repository")
    repos: list[RepoSpec] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {
            "name",
            "url",
            "default_branch",
            "visibility",
        }:
            raise SetupError(f"{label} repository entries must use the exact supported fields")
        if not all(isinstance(item[key], str) and item[key] for key in item):
            raise SetupError(f"{label} repository fields must be non-empty strings")
        if not REPO_NAME_PATTERN.fullmatch(item["name"]):
            raise SetupError(f"{label} repository names must be safe single path components")
        if item["visibility"] not in {"private", "public"}:
            raise SetupError(f"{label} repository visibility is invalid")
        repos.append(
            RepoSpec(
                name=item["name"],
                url=item["url"],
                default_branch=item["default_branch"],
                visibility=item["visibility"],
            )
        )
    names = [repo.name for repo in repos]
    if len(set(names)) != len(names):
        raise SetupError(f"{label} has duplicate repository names")
    return tuple(repos)


def _workspace_manifest_from_snapshot(
    path: Path,
    snapshot: FileSnapshot,
    *,
    label: str,
    expected_cache_root: Path | None = None,
) -> tuple[WorkspaceManifest, dict[str, Any]]:
    try:
        data = tomllib.loads(snapshot.data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise SetupError(f"{label} is invalid TOML: {error}") from error
    if data.get("version") != 1:
        raise SetupError(f"{label} must use version = 1")
    cache_root = _absolute_path(str(data.get("cache_root", "")), field=f"{label}.cache_root")
    if expected_cache_root is not None and cache_root != expected_cache_root:
        raise SetupError(f"{label} cache_root does not match the host cache root")
    repos = _parse_repo_specs(data.get("repos"), label=label)
    return WorkspaceManifest(path=path, cache_root=cache_root, repos=repos, snapshot=snapshot), data


def load_workspace_manifest(
    path: Path,
    *,
    label: str,
    expected_cache_root: Path | None = None,
) -> WorkspaceManifest:
    path = path.absolute()
    snapshot = _read_owned_regular_file(path, max_bytes=MAX_CONFIG_BYTES, label=label)
    manifest, _data = _workspace_manifest_from_snapshot(
        path,
        snapshot,
        label=label,
        expected_cache_root=expected_cache_root,
    )
    return manifest


def load_config(path: Path) -> HostConfig:
    path = path.absolute()
    snapshot = _read_owned_regular_file(path, max_bytes=MAX_CONFIG_BYTES, label="host manifest")
    manifest, data = _workspace_manifest_from_snapshot(path, snapshot, label="host manifest")
    if len(manifest.repos) != 1 or manifest.repos[0].name != "codex-host-workflows":
        raise SetupError("host manifest must list only codex-host-workflows")
    host = data.get("host_setup")
    if not isinstance(host, dict):
        raise SetupError("host manifest must define [host_setup]")
    if _require_string(host, "control_repo") != manifest.repos[0].name:
        raise SetupError("host_setup.control_repo must match the sole repository")
    prefetch_hour = _require_int(host, "prefetch_hour")
    prefetch_minute = _require_int(host, "prefetch_minute")
    weekly_weekday = _require_int(host, "weekly_prefetch_weekday")
    weekly_hour = _require_int(host, "weekly_prefetch_hour")
    weekly_minute = _require_int(host, "weekly_prefetch_minute")
    max_age = _require_int(host, "default_max_age_minutes")
    if (prefetch_hour, prefetch_minute) != (2, 45):
        raise SetupError("host_setup control prefetch must remain at 02:45")
    if (weekly_weekday, weekly_hour, weekly_minute) != (5, 6, 30):
        raise SetupError("host_setup weekly prefetch must remain at Friday 06:30")
    if max_age < 1:
        raise SetupError("host_setup.default_max_age_minutes must be positive")
    workspace_root = _absolute_path(
        _require_string(host, "workspace_root"), field="host_setup.workspace_root"
    )
    expected_cache_root = workspace_root / ".codex-local" / "daily-skill-friction"
    if manifest.cache_root != expected_cache_root:
        raise SetupError(
            "host manifest cache_root must be the workspace .codex-local/daily-skill-friction root"
        )
    skill_relative_path = _safe_relative_path(
        _require_string(host, "skill_relative_path"), field="host_setup.skill_relative_path"
    )
    locator_relative_path = _safe_relative_path(
        _require_string(host, "locator_relative_path"),
        field="host_setup.locator_relative_path",
    )
    canonical_skill = Path(".agents/skills/daily-skill-friction")
    if skill_relative_path != canonical_skill or locator_relative_path != canonical_skill:
        raise SetupError("host skill source and locator must use the canonical .agents path")
    launch_agent_label = _launch_agent_label(
        _require_string(host, "launch_agent_label"), field="host_setup.launch_agent_label"
    )
    weekly_launch_agent_label = _launch_agent_label(
        _require_string(host, "weekly_launch_agent_label"),
        field="host_setup.weekly_launch_agent_label",
    )
    if launch_agent_label == weekly_launch_agent_label:
        raise SetupError("host LaunchAgent labels must be distinct")
    return HostConfig(
        path=path,
        manifest_snapshot=snapshot,
        repo_root=path.parent.parent,
        workspace_root=workspace_root,
        cache_root=manifest.cache_root,
        python_executable=_absolute_path(
            _require_string(host, "python_executable"), field="host_setup.python_executable"
        ),
        control_repo=manifest.repos[0],
        skill_relative_path=skill_relative_path,
        locator_relative_path=locator_relative_path,
        launch_agent_label=launch_agent_label,
        launch_agent_source_relative_path=_safe_relative_path(
            _require_string(host, "launch_agent_source"), field="host_setup.launch_agent_source"
        ),
        weekly_launch_agent_label=weekly_launch_agent_label,
        weekly_launch_agent_source_relative_path=_safe_relative_path(
            _require_string(host, "weekly_launch_agent_source"),
            field="host_setup.weekly_launch_agent_source",
        ),
        control_stamp=_stamp_name(
            _require_string(host, "control_stamp"), field="host_setup.control_stamp"
        ),
        main_stamp=_stamp_name(_require_string(host, "main_stamp"), field="host_setup.main_stamp"),
        weekly_pair_receipt=_stamp_name(
            _require_string(host, "weekly_pair_receipt"),
            field="host_setup.weekly_pair_receipt",
        ),
        prefetch_hour=prefetch_hour,
        prefetch_minute=prefetch_minute,
        weekly_prefetch_weekday=weekly_weekday,
        weekly_prefetch_hour=weekly_hour,
        weekly_prefetch_minute=weekly_minute,
        default_max_age_minutes=max_age,
    )


def _config_identity(config: HostConfig) -> tuple[Any, ...]:
    return (
        config.workspace_root,
        config.manifest_snapshot.digest,
        config.cache_root,
        config.python_executable,
        config.control_repo,
        config.skill_relative_path,
        config.locator_relative_path,
        config.launch_agent_label,
        config.launch_agent_source_relative_path,
        config.weekly_launch_agent_label,
        config.weekly_launch_agent_source_relative_path,
        config.control_stamp,
        config.main_stamp,
        config.weekly_pair_receipt,
        config.prefetch_hour,
        config.prefetch_minute,
        config.weekly_prefetch_weekday,
        config.weekly_prefetch_hour,
        config.weekly_prefetch_minute,
        config.default_max_age_minutes,
    )


class AtomicRenamer:
    """Kernel no-replace/exchange adapter for Darwin and Linux."""

    def __init__(self, before: Callable[[str, int, str, int, str], None] | None = None) -> None:
        self.before = before
        self.library = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            function = getattr(self.library, "renameatx_np", None)
            self.no_replace_flag = 0x00000004
            self.exchange_flag = 0x00000002
        elif sys.platform.startswith("linux"):
            function = getattr(self.library, "renameat2", None)
            self.no_replace_flag = 1
            self.exchange_flag = 2
        else:
            function = None
            self.no_replace_flag = 0
            self.exchange_flag = 0
        if function is None:
            raise SetupError("atomic no-replace/exchange rename is unavailable on this platform")
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        self.function = function

    def _call(
        self,
        operation: str,
        source_fd: int,
        source: str,
        target_fd: int,
        target: str,
        flag: int,
    ) -> None:
        if self.before is not None:
            self.before(operation, source_fd, source, target_fd, target)
        result = self.function(
            source_fd,
            os.fsencode(source),
            target_fd,
            os.fsencode(target),
            flag,
        )
        if result != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))

    def no_replace(self, parent_fd: int, source: str, target: str) -> None:
        self._call("no-replace", parent_fd, source, parent_fd, target, self.no_replace_flag)

    def exchange(self, parent_fd: int, source: str, target: str) -> None:
        self._call("exchange", parent_fd, source, parent_fd, target, self.exchange_flag)

    def retire(self, parent_fd: int, source: str, target: str) -> None:
        self._call("retire", parent_fd, source, parent_fd, target, self.no_replace_flag)


def _quarantine_leaf(name: str) -> str:
    return f".{name}.retire-{os.getpid()}-{secrets.token_hex(8)}"


def _restore_quarantined_leaf(
    parent_fd: int,
    *,
    parent_path: Path,
    quarantine: str,
    target: str,
    renamer: AtomicRenamer,
) -> str:
    """Best-effort restore of a mismatched object without overwriting either leaf."""

    try:
        renamer.no_replace(parent_fd, quarantine, target)
    except OSError as error:
        if error.errno in {errno.EEXIST, errno.ENOTEMPTY}:
            return str(parent_path / quarantine)
        return f"{parent_path / quarantine} (restore failed: {error})"
    os.fsync(parent_fd)
    return str(parent_path / target)


def _move_leaf_to_quarantine(
    parent_fd: int,
    *,
    parent_path: Path,
    target: str,
    renamer: AtomicRenamer,
    label: str,
) -> str:
    quarantine = _quarantine_leaf(target)
    try:
        renamer.retire(parent_fd, target, quarantine)
    except OSError as error:
        raise SetupError(
            f"{label} could not move the expected object to private quarantine: "
            f"{parent_path / target}: {error}"
        ) from error
    os.fsync(parent_fd)
    return quarantine


def _retire_regular_leaf(
    parent_fd: int,
    *,
    parent_path: Path,
    parent_binding: Binding,
    target: str,
    expected: FileSnapshot,
    max_bytes: int,
    renamer: AtomicRenamer,
    label: str,
) -> None:
    """Delete an exact regular file only after moving it off its canonical leaf."""

    quarantine = _move_leaf_to_quarantine(
        parent_fd,
        parent_path=parent_path,
        target=target,
        renamer=renamer,
        label=label,
    )
    try:
        moved = _snapshot_at(
            parent_fd,
            quarantine,
            max_bytes=max_bytes,
            label=f"{label} quarantined object",
        )
        if moved != expected:
            raise SetupError(f"{label} quarantined object does not match the expected file")
        rebound = _snapshot_at(
            parent_fd,
            quarantine,
            max_bytes=max_bytes,
            label=f"{label} quarantined object",
        )
        if rebound != expected:
            raise SetupError(f"{label} quarantined object changed before retirement")
    except BaseException as error:
        retained = _restore_quarantined_leaf(
            parent_fd,
            parent_path=parent_path,
            quarantine=quarantine,
            target=target,
            renamer=renamer,
        )
        raise SetupError(f"{label} retained an untrusted object at {retained}: {error}") from error
    os.unlink(quarantine, dir_fd=parent_fd)
    os.fsync(parent_fd)
    _directory_path_matches(parent_path, parent_binding, label=f"{label} parent")


def _retire_symlink_leaf(
    parent_fd: int,
    *,
    parent_path: Path,
    parent_binding: Binding,
    target: str,
    expected_binding: Binding,
    expected_target: str,
    renamer: AtomicRenamer,
    label: str,
) -> None:
    """Delete an exact symlink via a private quarantine name."""

    quarantine = _move_leaf_to_quarantine(
        parent_fd,
        parent_path=parent_path,
        target=target,
        renamer=renamer,
        label=label,
    )
    try:
        metadata = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        current_target = os.readlink(quarantine, dir_fd=parent_fd)
        if Binding.from_stat(metadata) != expected_binding or current_target != expected_target:
            raise SetupError(f"{label} quarantined symlink does not match the expected object")
    except BaseException as error:
        retained = _restore_quarantined_leaf(
            parent_fd,
            parent_path=parent_path,
            quarantine=quarantine,
            target=target,
            renamer=renamer,
        )
        raise SetupError(f"{label} retained an untrusted object at {retained}: {error}") from error
    os.unlink(quarantine, dir_fd=parent_fd)
    os.fsync(parent_fd)
    _directory_path_matches(parent_path, parent_binding, label=f"{label} parent")


def _retire_directory_leaf(
    parent_fd: int,
    *,
    parent_path: Path,
    parent_binding: Binding,
    target: str,
    expected_binding: Binding,
    renamer: AtomicRenamer,
    label: str,
) -> None:
    """Remove an exact empty directory via a private quarantine name."""

    quarantine = _move_leaf_to_quarantine(
        parent_fd,
        parent_path=parent_path,
        target=target,
        renamer=renamer,
        label=label,
    )
    try:
        metadata = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode) or _directory_binding_tuple(
            Binding.from_stat(metadata)
        ) != _directory_binding_tuple(expected_binding):
            raise SetupError(f"{label} quarantined directory does not match the expected object")
        os.rmdir(quarantine, dir_fd=parent_fd)
    except BaseException as error:
        retained = _restore_quarantined_leaf(
            parent_fd,
            parent_path=parent_path,
            quarantine=quarantine,
            target=target,
            renamer=renamer,
        )
        raise SetupError(
            f"{label} retained a non-empty or untrusted object at {retained}: {error}"
        ) from error
    os.fsync(parent_fd)
    _directory_path_matches(parent_path, parent_binding, label=f"{label} parent")


@dataclasses.dataclass
class ReplacementTransaction:
    path: Path
    parent_fd: int
    parent_binding: Binding
    target_name: str
    backup_name: str | None
    old_snapshot: FileSnapshot | None
    new_snapshot: FileSnapshot
    renamer: AtomicRenamer
    commit_snapshot: FileSnapshot | None = None
    active: bool = True

    def _verify_parent(self) -> None:
        _directory_path_matches(self.path.parent, self.parent_binding, label="replacement parent")

    def commit(self) -> None:
        if not self.active:
            return
        try:
            self._verify_parent()
            current = _snapshot_at(
                self.parent_fd,
                self.target_name,
                max_bytes=max(MAX_CONFIG_BYTES, MAX_STAMP_BYTES),
                label="replacement target",
            )
            expected_target = self.commit_snapshot or self.new_snapshot
            if current != expected_target:
                raise SetupError(f"replacement target changed before commit: {self.path}")
            if self.backup_name is not None:
                backup = _snapshot_at(
                    self.parent_fd,
                    self.backup_name,
                    max_bytes=max(MAX_CONFIG_BYTES, MAX_STAMP_BYTES),
                    label="replacement backup",
                )
                if backup != self.old_snapshot:
                    raise SetupError(f"replacement backup changed before commit: {self.path}")
                assert backup is not None
                _retire_regular_leaf(
                    self.parent_fd,
                    parent_path=self.path.parent,
                    parent_binding=self.parent_binding,
                    target=self.backup_name,
                    expected=backup,
                    max_bytes=max(MAX_CONFIG_BYTES, MAX_STAMP_BYTES),
                    renamer=self.renamer,
                    label="replacement backup commit",
                )
            os.fsync(self.parent_fd)
        finally:
            self.active = False
            os.close(self.parent_fd)

    def rollback(self) -> None:
        if not self.active:
            return
        try:
            self._verify_parent()
            current = _snapshot_at(
                self.parent_fd,
                self.target_name,
                max_bytes=max(MAX_CONFIG_BYTES, MAX_STAMP_BYTES),
                label="rollback target",
            )
            if current != self.new_snapshot:
                raise SetupError(f"rollback refused to overwrite a replaced target: {self.path}")
            if self.old_snapshot is None:
                _retire_regular_leaf(
                    self.parent_fd,
                    parent_path=self.path.parent,
                    parent_binding=self.parent_binding,
                    target=self.target_name,
                    expected=self.new_snapshot,
                    max_bytes=max(MAX_CONFIG_BYTES, MAX_STAMP_BYTES),
                    renamer=self.renamer,
                    label="replacement target rollback",
                )
            else:
                assert self.backup_name is not None
                backup = _snapshot_at(
                    self.parent_fd,
                    self.backup_name,
                    max_bytes=max(MAX_CONFIG_BYTES, MAX_STAMP_BYTES),
                    label="rollback backup",
                )
                if backup != self.old_snapshot:
                    raise SetupError(f"rollback backup changed: {self.path}")
                self.renamer.exchange(self.parent_fd, self.backup_name, self.target_name)
                restored = _snapshot_at(
                    self.parent_fd,
                    self.target_name,
                    max_bytes=max(MAX_CONFIG_BYTES, MAX_STAMP_BYTES),
                    label="restored target",
                )
                displaced = _snapshot_at(
                    self.parent_fd,
                    self.backup_name,
                    max_bytes=max(MAX_CONFIG_BYTES, MAX_STAMP_BYTES),
                    label="rollback displaced managed target",
                )
                if restored != self.old_snapshot or displaced != self.new_snapshot:
                    raise SetupError(
                        "rollback exchange encountered a concurrent replacement; retained both "
                        f"objects at {self.path} and {self.path.parent / self.backup_name}"
                    )
                assert displaced is not None
                _retire_regular_leaf(
                    self.parent_fd,
                    parent_path=self.path.parent,
                    parent_binding=self.parent_binding,
                    target=self.backup_name,
                    expected=displaced,
                    max_bytes=max(MAX_CONFIG_BYTES, MAX_STAMP_BYTES),
                    renamer=self.renamer,
                    label="replacement displaced target rollback",
                )
            os.fsync(self.parent_fd)
        finally:
            self.active = False
            os.close(self.parent_fd)


class FileOps:
    def __init__(self, renamer: AtomicRenamer | None = None) -> None:
        self.renamer = renamer or AtomicRenamer()

    def begin_replace(
        self,
        path: Path,
        data: bytes,
        *,
        mode: int,
        expected: FileSnapshot | None,
        max_bytes: int,
    ) -> ReplacementTransaction:
        if len(data) > max_bytes:
            raise SetupError(f"replacement data exceeds the byte limit: {path}")
        parent_fd, parent_binding = _open_real_directory(
            path.parent, label="replacement parent", require_current_owner=True
        )
        stage = f".{path.name}.stage-{os.getpid()}-{secrets.token_hex(8)}"
        stage_fd: int | None = None
        stage_created = False
        moved = False
        backup_name: str | None = None
        staged: FileSnapshot | None = None
        current: FileSnapshot | None = None
        preserve_swapped_objects = False
        try:
            current = _snapshot_at(
                parent_fd,
                path.name,
                max_bytes=max_bytes,
                label="replacement current target",
                missing_ok=True,
            )
            if current != expected:
                raise SetupError(f"replacement target changed since preflight: {path}")
            stage_fd = os.open(
                stage,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                mode,
                dir_fd=parent_fd,
            )
            stage_created = True
            with os.fdopen(stage_fd, "wb", closefd=True) as stream:
                stage_fd = None
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            staged = _snapshot_at(
                parent_fd,
                stage,
                max_bytes=max_bytes,
                label="replacement staged file",
            )
            assert staged is not None
            if current is None:
                try:
                    self.renamer.no_replace(parent_fd, stage, path.name)
                except OSError as error:
                    if error.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                        raise SetupError(
                            f"foreign target appeared during no-replace install: {path}"
                        ) from error
                    raise
                moved = True
            else:
                backup_name = stage
                self.renamer.exchange(parent_fd, stage, path.name)
                moved = True
                displaced = _snapshot_at(
                    parent_fd,
                    stage,
                    max_bytes=max_bytes,
                    label="replacement displaced target",
                )
                if displaced != current:
                    new_current = _snapshot_at(
                        parent_fd,
                        path.name,
                        max_bytes=max_bytes,
                        label="replacement new target",
                    )
                    preserve_swapped_objects = True
                    if new_current != staged:
                        raise SetupError(
                            "replacement race retained recovery objects at "
                            f"{path} and {path.parent / stage}"
                        )
                    raise SetupError(
                        "foreign replacement was retained instead of overwritten; "
                        f"recovery objects: {path}, {path.parent / stage}"
                    )
            installed = _snapshot_at(
                parent_fd,
                path.name,
                max_bytes=max_bytes,
                label="replacement installed target",
            )
            if installed != staged:
                raise SetupError(f"replacement installed target did not verify: {path}")
            os.fsync(parent_fd)
            _directory_path_matches(path.parent, parent_binding, label="replacement parent")
            return ReplacementTransaction(
                path=path,
                parent_fd=parent_fd,
                parent_binding=parent_binding,
                target_name=path.name,
                backup_name=backup_name,
                old_snapshot=current,
                new_snapshot=staged,
                renamer=self.renamer,
            )
        except BaseException as original_error:
            if stage_fd is not None:
                os.close(stage_fd)
            if preserve_swapped_objects:
                os.fsync(parent_fd)
                os.close(parent_fd)
                raise SetupError(str(original_error)) from original_error
            recovery_error: BaseException | None = None
            if moved and staged is not None:
                try:
                    installed = _snapshot_at(
                        parent_fd,
                        path.name,
                        max_bytes=max_bytes,
                        label="failed replacement target",
                    )
                    if installed != staged:
                        raise SetupError(
                            f"failed replacement target was changed before recovery: {path}"
                        )
                    if current is None:
                        _retire_regular_leaf(
                            parent_fd,
                            parent_path=path.parent,
                            parent_binding=parent_binding,
                            target=path.name,
                            expected=staged,
                            max_bytes=max_bytes,
                            renamer=self.renamer,
                            label="failed replacement target recovery",
                        )
                    else:
                        assert backup_name is not None
                        backup = _snapshot_at(
                            parent_fd,
                            backup_name,
                            max_bytes=max_bytes,
                            label="failed replacement backup",
                        )
                        if backup != current:
                            raise SetupError(
                                f"failed replacement backup changed before recovery: {path}"
                            )
                        self.renamer.exchange(parent_fd, backup_name, path.name)
                        restored = _snapshot_at(
                            parent_fd,
                            path.name,
                            max_bytes=max_bytes,
                            label="failed replacement restored target",
                        )
                        displaced = _snapshot_at(
                            parent_fd,
                            backup_name,
                            max_bytes=max_bytes,
                            label="failed replacement displaced managed target",
                        )
                        if restored != current or displaced != staged:
                            raise SetupError(
                                "failed replacement recovery encountered a concurrent "
                                f"replacement; retained both objects at {path} and "
                                f"{path.parent / backup_name}"
                            )
                        assert displaced is not None
                        _retire_regular_leaf(
                            parent_fd,
                            parent_path=path.parent,
                            parent_binding=parent_binding,
                            target=backup_name,
                            expected=displaced,
                            max_bytes=max_bytes,
                            renamer=self.renamer,
                            label="failed replacement displaced target recovery",
                        )
                    os.fsync(parent_fd)
                except BaseException as error:
                    recovery_error = error
            elif stage_created and not moved and staged is not None:
                try:
                    _retire_regular_leaf(
                        parent_fd,
                        parent_path=path.parent,
                        parent_binding=parent_binding,
                        target=stage,
                        expected=staged,
                        max_bytes=max_bytes,
                        renamer=self.renamer,
                        label="failed replacement staged file cleanup",
                    )
                except BaseException as error:
                    recovery_error = error
            elif stage_created and not moved:
                recovery_error = SetupError(
                    f"unverified staged file retained for recovery: {path.parent / stage}"
                )
            os.close(parent_fd)
            if recovery_error is not None:
                raise SetupError(
                    f"replacement failed ({original_error}); recovery failed ({recovery_error})"
                ) from original_error
            raise


@dataclasses.dataclass(frozen=True)
class CreatedDirectory:
    path: Path
    binding: Binding


@dataclasses.dataclass(frozen=True)
class CreatedSymlink:
    path: Path
    binding: Binding
    target: str


class MutationJournal:
    def __init__(self, renamer: AtomicRenamer | None = None) -> None:
        self.files: list[ReplacementTransaction] = []
        self.directories: list[CreatedDirectory] = []
        self.symlinks: list[CreatedSymlink] = []
        self.renamer = renamer or AtomicRenamer()

    def add_file(self, transaction: ReplacementTransaction) -> None:
        chain = [
            existing
            for existing in self.files
            if existing.path == transaction.path and existing.active
        ]
        if chain:
            previous = chain[-1]
            if transaction.old_snapshot != previous.new_snapshot:
                try:
                    transaction.rollback()
                except BaseException as rollback_error:
                    raise SetupError(
                        "chained replacement lost its prior binding and could not restore "
                        f"the new transaction: {transaction.path}: {rollback_error}"
                    ) from rollback_error
                raise SetupError(
                    f"chained replacement does not bind the prior managed state: {transaction.path}"
                )
            for existing in chain:
                existing.commit_snapshot = transaction.new_snapshot
        self.files.append(transaction)

    def rollback(self) -> list[str]:
        errors: list[str] = []
        for transaction in reversed(self.files):
            try:
                transaction.rollback()
            except (OSError, SetupError) as error:
                errors.append(str(error))
        for created in reversed(self.symlinks):
            try:
                parent_fd, parent_binding = _open_real_directory(
                    created.path.parent,
                    label="rollback symlink parent",
                    require_current_owner=True,
                )
                try:
                    _retire_symlink_leaf(
                        parent_fd,
                        parent_path=created.path.parent,
                        parent_binding=parent_binding,
                        target=created.path.name,
                        expected_binding=created.binding,
                        expected_target=created.target,
                        renamer=self.renamer,
                        label="rollback created symlink",
                    )
                finally:
                    os.close(parent_fd)
            except (OSError, SetupError) as error:
                errors.append(str(error))
        for created in reversed(self.directories):
            try:
                parent_fd, parent_binding = _open_real_directory(
                    created.path.parent,
                    label="rollback directory parent",
                    require_current_owner=True,
                )
                try:
                    _retire_directory_leaf(
                        parent_fd,
                        parent_path=created.path.parent,
                        parent_binding=parent_binding,
                        target=created.path.name,
                        expected_binding=created.binding,
                        renamer=self.renamer,
                        label="rollback created directory",
                    )
                finally:
                    os.close(parent_fd)
            except (OSError, SetupError) as error:
                errors.append(str(error))
        return errors

    def commit(self) -> None:
        errors: list[str] = []
        for transaction in self.files:
            try:
                transaction.commit()
            except SetupError as error:
                errors.append(str(error))
        if errors:
            raise SetupError("transaction commit cleanup incomplete: " + "; ".join(errors))


def _ensure_directory_children(
    base: Path,
    children: Sequence[str],
    journal: MutationJournal,
    *,
    label: str,
) -> Path:
    current_path = base
    descriptor, _ = _open_real_directory(base, label=f"{label} base", require_current_owner=True)
    try:
        for child_name in children:
            if "/" in child_name or child_name in {"", ".", ".."}:
                raise SetupError(f"{label} has an invalid directory component")
            created = False
            try:
                child_fd = os.open(
                    child_name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(child_name, mode=0o700, dir_fd=descriptor)
                except FileExistsError as error:
                    raise SetupError(
                        f"foreign object appeared while creating {current_path / child_name}"
                    ) from error
                try:
                    child_fd = os.open(
                        child_name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                except OSError as error:
                    raise SetupError(
                        "created directory could not be rebound and was retained for "
                        f"inspection: {current_path / child_name}"
                    ) from error
                metadata = os.fstat(child_fd)
                journal.directories.append(
                    CreatedDirectory(
                        current_path / child_name,
                        Binding.from_stat(metadata),
                    )
                )
                created = True
            try:
                metadata = os.fstat(child_fd)
                _validate_directory_metadata(
                    metadata,
                    label=f"{label} {current_path / child_name}",
                    require_current_owner=True,
                )
                rebound = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
                if _directory_binding_tuple(Binding.from_stat(rebound)) != _directory_binding_tuple(
                    Binding.from_stat(metadata)
                ):
                    raise SetupError(
                        f"directory was replaced while opening: {current_path / child_name}"
                    )
                if created:
                    os.fsync(descriptor)
            except BaseException:
                os.close(child_fd)
                raise
            os.close(descriptor)
            descriptor = child_fd
            current_path /= child_name
        return current_path
    finally:
        os.close(descriptor)


def _directory_check(
    path: Path,
    *,
    name: str,
    missing_status: str = "needs-apply",
) -> Check:
    try:
        descriptor, _ = _open_real_directory(path, label=name, require_current_owner=True)
    except SetupError as error:
        message = str(error)
        if "missing" in message:
            return Check(name, missing_status, message)
        return Check(name, "blocked", message)
    else:
        os.close(descriptor)
        return Check(name, "ready", str(path))


def _regular_file_check(
    path: Path,
    *,
    name: str,
    missing_status: str = "blocked",
) -> Check:
    try:
        snapshot = _optional_owned_file(path, max_bytes=MAX_CONFIG_BYTES, label=name)
    except SetupError as error:
        return Check(name, "blocked", str(error))
    if snapshot is None:
        return Check(name, missing_status, f"missing file: {path}")
    return Check(name, "ready", f"{path}; sha256={snapshot.digest}")


def _git_admin_path_checks(repository: Path, *, prefix: str) -> list[Check]:
    """Validate the Git worktree/admin boundary without invoking Git."""

    git_dir = repository / ".git"
    checks = [
        _directory_check(repository, name=f"{prefix}-worktree", missing_status="blocked"),
        _directory_check(git_dir, name=f"{prefix}-git", missing_status="blocked"),
    ]
    for relative in (
        "objects",
        "objects/info",
        "objects/pack",
        "refs",
        "refs/heads",
        "refs/remotes",
        "hooks",
        "info",
        "logs",
    ):
        checks.append(
            _directory_check(
                git_dir / relative,
                name=f"{prefix}-{relative.replace('/', '-')}",
                missing_status="ready",
            )
        )
    checks.extend(
        [
            _regular_file_check(git_dir / "config", name=f"{prefix}-config"),
            _regular_file_check(git_dir / "HEAD", name=f"{prefix}-head"),
            _regular_file_check(git_dir / "index", name=f"{prefix}-index", missing_status="ready"),
            _regular_file_check(
                git_dir / "packed-refs",
                name=f"{prefix}-packed-refs",
                missing_status="ready",
            ),
        ]
    )
    return checks


def _git_environment(*, disable_hooks: bool = True) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_") and key not in {"SSH_ASKPASS", "GIT_ASKPASS"}
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_LAZY_FETCH": "1",
        }
    )
    overrides = [("core.fsmonitor", "false")]
    if disable_hooks:
        overrides.append(("core.hooksPath", "/dev/null"))
    environment["GIT_CONFIG_COUNT"] = str(len(overrides))
    for index, (key, value) in enumerate(overrides):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    return environment


def _run_git(
    repository: Path,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    descriptor, binding = _open_real_directory(
        repository, label="Git repository", require_current_owner=True
    )
    os.close(descriptor)
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=False,
            text=True,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=_git_environment(disable_hooks=True),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SetupError(
            f"Git command could not complete in {repository}: {type(error).__name__}"
        ) from error
    _directory_path_matches(repository, binding, label="Git repository")
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:MAX_COMMAND_DETAIL]
        raise SetupError(f"git {' '.join(arguments)} failed in {repository}: {detail}")
    return result


def _workspace_status_argv(
    config: HostConfig,
    manifest: WorkspaceManifest,
    repo: RepoSpec | None = None,
) -> list[str]:
    argv = [
        str(config.python_executable),
        str(config.workspace_helper),
        "--config",
        str(manifest.path),
        "status",
    ]
    if repo is not None:
        argv.extend(["--repo", repo.name])
    argv.append("--strict")
    return argv


def _run_workspace_status(
    config: HostConfig,
    manifest: WorkspaceManifest,
    runner: CommandRunner,
    *,
    repo: RepoSpec | None = None,
) -> None:
    result = runner.run(
        _workspace_status_argv(config, manifest, repo),
        cwd=config.workspace_root,
        env=_git_environment(disable_hooks=False),
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:MAX_COMMAND_DETAIL]
        target = repo.name if repo is not None else "all repositories"
        raise SetupError(
            f"workspace helper strict status failed for {target} with exit "
            f"{result.returncode}: {detail}"
        )


def _git_output(repository: Path, *arguments: str) -> str:
    return _run_git(repository, *arguments).stdout.strip()


def mirror_snapshot(
    config: HostConfig,
    manifest: WorkspaceManifest,
    repo: RepoSpec,
    runner: CommandRunner,
) -> dict[str, str]:
    _run_workspace_status(config, manifest, runner, repo=repo)
    mirror = manifest.repo_path(repo)
    top = Path(_git_output(mirror, "rev-parse", "--show-toplevel"))
    if top != mirror:
        raise SetupError(f"{repo.name} top-level path does not match its manifest mirror")
    common = _git_output(mirror, "rev-parse", "--git-common-dir")
    git_dir = _git_output(mirror, "rev-parse", "--git-dir")
    if common != ".git" or git_dir != ".git":
        raise SetupError(f"{repo.name} mirror must be a standalone Git checkout")
    if _git_output(mirror, "rev-parse", "--is-shallow-repository") != "false":
        raise SetupError(f"{repo.name} mirror must not be shallow")
    remotes = [line for line in _git_output(mirror, "remote").splitlines() if line]
    if remotes != ["origin"]:
        raise SetupError(f"{repo.name} mirror must have exactly the origin remote")
    remote_url = _git_output(mirror, "remote", "get-url", "origin")
    if remote_url != repo.url:
        raise SetupError(f"{repo.name} origin URL does not match the manifest")
    refspecs = [
        line
        for line in _git_output(
            mirror, "config", "--local", "--get-all", "remote.origin.fetch"
        ).splitlines()
        if line
    ]
    if refspecs != ["+refs/heads/*:refs/remotes/origin/*"]:
        raise SetupError(f"{repo.name} origin fetch refspec is not the expected clone refspec")
    branch = _git_output(mirror, "branch", "--show-current")
    if branch != repo.default_branch:
        raise SetupError(
            f"{repo.name} branch is {branch or 'detached'}, expected {repo.default_branch}"
        )
    dirty = _git_output(mirror, "status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise SetupError(f"{repo.name} mirror is dirty")
    upstream = _git_output(mirror, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    expected_upstream = f"origin/{repo.default_branch}"
    if upstream != expected_upstream:
        raise SetupError(f"{repo.name} upstream is {upstream}, expected {expected_upstream}")
    head = _git_output(mirror, "rev-parse", "HEAD")
    upstream_head = _git_output(mirror, "rev-parse", "@{u}")
    counts = _git_output(mirror, "rev-list", "--left-right", "--count", "HEAD...@{u}")
    pieces = counts.split()
    if len(pieces) != 2 or not all(piece.isdigit() for piece in pieces):
        raise SetupError(f"{repo.name} ahead/behind output is malformed")
    if pieces != ["0", "0"] or head != upstream_head:
        raise SetupError(f"{repo.name} mirror is not exactly synchronized with upstream")
    return {
        "name": repo.name,
        "remote": "origin",
        "branch": branch,
        "upstream": upstream,
        "head": head,
        "upstream_head": upstream_head,
        "ahead": pieces[0],
        "behind": pieces[1],
    }


def _ensure_mirror_precheck(manifest: WorkspaceManifest, repo: RepoSpec) -> Check:
    """Prove an existing mirror is safe for helper guard installation.

    A clean mirror may be behind because the later explicit prefetch performs the
    fast-forward. It may never be ahead or diverged when ensure is authorized.
    """

    mirror = manifest.repo_path(repo)
    if not mirror.exists():
        return Check(
            f"ensure-mirror-{repo.name}",
            "needs-apply",
            f"missing mirror may be cloned by explicit ensure: {mirror}",
        )
    try:
        top = Path(_git_output(mirror, "rev-parse", "--show-toplevel"))
        common = _git_output(mirror, "rev-parse", "--git-common-dir")
        git_dir = _git_output(mirror, "rev-parse", "--git-dir")
        if top != mirror or common != ".git" or git_dir != ".git":
            raise SetupError(f"{repo.name} must be the expected standalone mirror")
        if _git_output(mirror, "rev-parse", "--is-shallow-repository") != "false":
            raise SetupError(f"{repo.name} mirror must not be shallow")
        remotes = [line for line in _git_output(mirror, "remote").splitlines() if line]
        if remotes != ["origin"]:
            raise SetupError(f"{repo.name} mirror must have exactly the origin remote")
        if _git_output(mirror, "remote", "get-url", "origin") != repo.url:
            raise SetupError(f"{repo.name} origin URL does not match the manifest")
        refspecs = [
            line
            for line in _git_output(
                mirror, "config", "--local", "--get-all", "remote.origin.fetch"
            ).splitlines()
            if line
        ]
        if refspecs != ["+refs/heads/*:refs/remotes/origin/*"]:
            raise SetupError(f"{repo.name} origin fetch refspec is not the expected clone refspec")
        branch = _git_output(mirror, "branch", "--show-current")
        if branch != repo.default_branch:
            raise SetupError(
                f"{repo.name} branch is {branch or 'detached'}, expected {repo.default_branch}"
            )
        if _git_output(mirror, "status", "--porcelain=v1", "--untracked-files=all"):
            raise SetupError(f"{repo.name} mirror is dirty")
        upstream = _git_output(mirror, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
        expected_upstream = f"origin/{repo.default_branch}"
        if upstream != expected_upstream:
            raise SetupError(f"{repo.name} upstream is {upstream}, expected {expected_upstream}")
        if _git_output(mirror, "config", "--local", "--get", f"branch.{branch}.remote") != "origin":
            raise SetupError(f"{repo.name} branch remote is not origin")
        expected_merge = f"refs/heads/{repo.default_branch}"
        if (
            _git_output(mirror, "config", "--local", "--get", f"branch.{branch}.merge")
            != expected_merge
        ):
            raise SetupError(f"{repo.name} branch merge ref is not {expected_merge}")
        pieces = _git_output(mirror, "rev-list", "--left-right", "--count", "HEAD...@{u}").split()
        if len(pieces) != 2 or not all(piece.isdigit() for piece in pieces):
            raise SetupError(f"{repo.name} ahead/behind output is malformed")
        if pieces[0] != "0":
            raise SetupError(
                f"{repo.name} mirror is ahead or diverged: ahead={pieces[0]} behind={pieces[1]}"
            )
    except SetupError as error:
        return Check(f"ensure-mirror-{repo.name}", "blocked", str(error))
    return Check(
        f"ensure-mirror-{repo.name}",
        "ready",
        f"clean expected mirror; ahead=0 behind={pieces[1]}",
    )


def manifest_snapshots(
    config: HostConfig,
    manifest: WorkspaceManifest,
    runner: CommandRunner,
) -> dict[str, dict[str, str]]:
    _run_workspace_status(config, manifest, runner)
    return {repo.name: mirror_snapshot(config, manifest, repo, runner) for repo in manifest.repos}


def _check_python(config: HostConfig, runner: CommandRunner) -> Check:
    try:
        snapshot = _read_owned_regular_file(
            config.python_executable,
            max_bytes=256 * 1024 * 1024,
            label="Python executable",
        )
        if not snapshot.binding.mode & 0o111:
            raise SetupError("Python executable has no executable bit")
        result = runner.run([str(config.python_executable), "--version"])
        version = (result.stdout or result.stderr).strip()
        match = re.fullmatch(r"Python ([0-9]+)\.([0-9]+)(?:\.([0-9]+))?", version)
        if result.returncode != 0 or match is None:
            raise SetupError("Python executable version probe failed")
        if (int(match.group(1)), int(match.group(2))) < (3, 12):
            raise SetupError("Python executable must be version 3.12 or newer")
        rebound = _read_owned_regular_file(
            config.python_executable,
            max_bytes=256 * 1024 * 1024,
            label="Python executable",
        )
        if rebound != snapshot:
            raise SetupError("Python executable changed during its version probe")
    except SetupError as error:
        return Check("python-executable", "blocked", str(error))
    return Check("python-executable", "ready", f"{config.python_executable}: {version}")


def _check_workspace_helper(config: HostConfig) -> Check:
    try:
        _read_owned_regular_file(
            config.workspace_helper,
            max_bytes=MAX_CONFIG_BYTES,
            label="workspace helper",
        )
    except SetupError as error:
        return Check("workspace-helper", "blocked", str(error))
    return Check("workspace-helper", "ready", str(config.workspace_helper))


def _load_control_mirror_config(config: HostConfig) -> HostConfig:
    mirror = load_config(config.control_mirror_manifest)
    if _config_identity(mirror) != _config_identity(config):
        raise SetupError("control mirror manifest does not match the bootstrap manifest identity")
    return mirror


def _check_control_mirror_manifest(config: HostConfig) -> Check:
    try:
        _load_control_mirror_config(config)
    except SetupError as error:
        message = str(error)
        status = "needs-apply" if "missing" in message else "blocked"
        return Check("control-mirror-manifest", status, message)
    return Check("control-mirror-manifest", "ready", str(config.control_mirror_manifest))


def _load_main_manifest(config: HostConfig) -> WorkspaceManifest:
    return load_workspace_manifest(
        config.main_manifest,
        label="main workspace manifest",
        expected_cache_root=config.cache_root,
    )


def _desired_control_launch_agent(config: HostConfig) -> dict[str, Any]:
    return {
        "Label": config.launch_agent_label,
        "ProgramArguments": [
            str(config.python_executable),
            str(config.control_mirror_script),
            "prefetch-control",
        ],
        "WorkingDirectory": str(config.workspace_root),
        "StartCalendarInterval": {
            "Hour": config.prefetch_hour,
            "Minute": config.prefetch_minute,
        },
        "StandardOutPath": str(config.log_root / "daily-skill-friction-control-prefetch.out.log"),
        "StandardErrorPath": str(config.log_root / "daily-skill-friction-control-prefetch.err.log"),
        "EnvironmentVariables": {
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        },
    }


def _desired_weekly_launch_agent(config: HostConfig) -> dict[str, Any]:
    return {
        "Label": config.weekly_launch_agent_label,
        "ProgramArguments": [
            str(config.python_executable),
            str(config.control_mirror_script),
            "prefetch-weekly",
        ],
        "WorkingDirectory": str(config.workspace_root),
        "StartCalendarInterval": {
            "Weekday": config.weekly_prefetch_weekday,
            "Hour": config.weekly_prefetch_hour,
            "Minute": config.weekly_prefetch_minute,
        },
        "StandardOutPath": str(config.log_root / "daily-skill-friction-weekly-prefetch.out.log"),
        "StandardErrorPath": str(config.log_root / "daily-skill-friction-weekly-prefetch.err.log"),
        "EnvironmentVariables": {
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        },
    }


def desired_launch_agent(config: HostConfig, key: str = "control") -> dict[str, Any]:
    if key == "control":
        return _desired_control_launch_agent(config)
    if key == "weekly":
        return _desired_weekly_launch_agent(config)
    raise SetupError(f"unknown LaunchAgent key: {key}")


def _launch_agent_specs(config: HostConfig, home: Path) -> tuple[LaunchAgentSpec, ...]:
    launch_agents = _normalized_absolute(
        home / "Library" / "LaunchAgents", field="user LaunchAgents"
    )
    specs = (
        LaunchAgentSpec(
            key="control",
            label=config.launch_agent_label,
            source=config.launch_agent_source,
            destination=launch_agents / f"{config.launch_agent_label}.plist",
            expected=_desired_control_launch_agent(config),
        ),
        LaunchAgentSpec(
            key="weekly",
            label=config.weekly_launch_agent_label,
            source=config.weekly_launch_agent_source,
            destination=launch_agents / f"{config.weekly_launch_agent_label}.plist",
            expected=_desired_weekly_launch_agent(config),
        ),
    )
    for spec in specs:
        if (
            spec.destination.parent != launch_agents
            or spec.destination.name != f"{spec.label}.plist"
        ):
            raise SetupError(f"{spec.key} LaunchAgent target escapes {launch_agents}")
    return specs


def _load_plist(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        parsed = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise SetupError(f"{label} is not a valid plist") from error
    if not isinstance(parsed, dict):
        raise SetupError(f"{label} must contain a dictionary")
    return parsed


def _source_plist(spec: LaunchAgentSpec) -> tuple[FileSnapshot, Check]:
    try:
        snapshot = _read_owned_regular_file(
            spec.source,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"{spec.key} LaunchAgent source",
        )
        parsed = _load_plist(snapshot.data, label=f"{spec.key} LaunchAgent source")
        if MANAGED_PLIST_MARKER not in snapshot.data:
            raise SetupError(f"{spec.key} LaunchAgent source lacks the ownership marker")
        if parsed != spec.expected:
            raise SetupError(f"{spec.key} LaunchAgent source does not match the host manifest")
    except SetupError as error:
        return FileSnapshot(Binding(0, 0, 0, 0, 0, 0), b""), Check(
            f"launch-agent-source-{spec.key}", "blocked", str(error)
        )
    return snapshot, Check(f"launch-agent-source-{spec.key}", "ready", str(spec.source))


def _managed_plist(snapshot: FileSnapshot, spec: LaunchAgentSpec) -> bool:
    if MANAGED_PLIST_MARKER not in snapshot.data:
        return False
    try:
        parsed = _load_plist(snapshot.data, label="installed LaunchAgent")
    except SetupError:
        return False
    return parsed.get("Label") == spec.label


def _check_launch_agent_file(spec: LaunchAgentSpec) -> Check:
    source, source_check = _source_plist(spec)
    if source_check.status != "ready":
        return source_check
    try:
        installed = _optional_owned_file(
            spec.destination,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"installed {spec.key} LaunchAgent",
        )
    except SetupError as error:
        message = str(error)
        if "missing" in message and "parent" in message:
            return Check(f"launch-agent-file-{spec.key}", "needs-apply", message)
        return Check(f"launch-agent-file-{spec.key}", "blocked", message)
    if installed is None:
        return Check(
            f"launch-agent-file-{spec.key}",
            "needs-apply",
            f"missing file: {spec.destination}",
        )
    if installed.data == source.data:
        return Check(f"launch-agent-file-{spec.key}", "ready", str(spec.destination))
    if not _managed_plist(installed, spec):
        return Check(
            f"launch-agent-file-{spec.key}",
            "blocked",
            f"foreign LaunchAgent occupies {spec.destination}",
        )
    return Check(
        f"launch-agent-file-{spec.key}",
        "needs-apply",
        f"managed LaunchAgent needs an update: {spec.destination}",
    )


def _check_skill_source(config: HostConfig) -> Check:
    check = _directory_check(config.skill_source, name="control-skill-source")
    if check.status == "needs-apply":
        return Check(
            check.name,
            check.status,
            f"{check.detail}; run apply --ensure only after explicitly authorizing "
            "the initial clone",
        )
    return check


def desired_locator_target(config: HostConfig) -> str:
    return Path(os.path.relpath(config.skill_source, start=config.skill_locator.parent)).as_posix()


def _check_locator(config: HostConfig) -> Check:
    parent_check = _directory_check(config.skill_locator.parent, name="skill-locator-parent")
    if parent_check.status != "ready":
        return Check("skill-locator", parent_check.status, parent_check.detail)
    source_check = _check_skill_source(config)
    if source_check.status != "ready":
        return Check(
            "skill-locator", "blocked", f"locator target is not ready: {source_check.detail}"
        )
    parent_fd, parent_binding = _open_real_directory(
        config.skill_locator.parent,
        label="skill locator parent",
        require_current_owner=True,
    )
    try:
        try:
            metadata = os.stat(config.skill_locator.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return Check("skill-locator", "needs-apply", f"missing symlink: {config.skill_locator}")
        if not stat.S_ISLNK(metadata.st_mode):
            return Check(
                "skill-locator", "blocked", f"foreign non-symlink occupies {config.skill_locator}"
            )
        if metadata.st_uid != os.getuid():
            return Check(
                "skill-locator",
                "blocked",
                f"symlink is not owned by uid {os.getuid()}: {config.skill_locator}",
            )
        target = os.readlink(config.skill_locator.name, dir_fd=parent_fd)
        if target != desired_locator_target(config):
            return Check(
                "skill-locator",
                "blocked",
                f"foreign symlink target at {config.skill_locator}: {target!r}",
            )
        source_fd, source_binding = _open_real_directory(
            config.skill_source,
            label="skill source",
            require_current_owner=True,
        )
        os.close(source_fd)
        followed = os.stat(config.skill_locator.name, dir_fd=parent_fd, follow_symlinks=True)
        if _directory_binding_tuple(Binding.from_stat(followed)) != _directory_binding_tuple(
            source_binding
        ):
            return Check(
                "skill-locator",
                "blocked",
                "locator does not resolve to the exact intended skill directory",
            )
        rebound = os.stat(config.skill_locator.name, dir_fd=parent_fd, follow_symlinks=False)
        if _binding_tuple(rebound) != _binding_tuple(metadata):
            return Check("skill-locator", "blocked", "locator changed while being validated")
        _directory_path_matches(
            config.skill_locator.parent, parent_binding, label="skill locator parent"
        )
        return Check("skill-locator", "ready", f"{config.skill_locator} -> {target}")
    finally:
        os.close(parent_fd)


def _exclude_path(config: HostConfig) -> Path:
    return config.workspace_root / ".git" / "info" / "exclude"


def _validate_workspace_git_root(config: HostConfig) -> None:
    workspace_fd, _ = _open_real_directory(
        config.workspace_root,
        label="workspace root",
        require_current_owner=True,
    )
    os.close(workspace_fd)
    git_fd, _ = _open_real_directory(
        config.workspace_root / ".git",
        label="workspace Git directory",
        require_current_owner=True,
    )
    os.close(git_fd)
    top = Path(_git_output(config.workspace_root, "rev-parse", "--show-toplevel"))
    git_dir = _git_output(config.workspace_root, "rev-parse", "--git-dir")
    if top != config.workspace_root or git_dir != ".git":
        raise SetupError("workspace must be the expected standalone Git repository")


def _exclude_block() -> str:
    return f"{EXCLUDE_BEGIN}\n{EXCLUDE_ENTRY}\n{EXCLUDE_END}\n"


def _check_exclude(config: HostConfig) -> Check:
    try:
        _validate_workspace_git_root(config)
        info_fd, _ = _open_real_directory(
            config.workspace_root / ".git" / "info",
            label="workspace Git info directory",
            require_current_owner=True,
        )
        os.close(info_fd)
        snapshot = _optional_owned_file(
            _exclude_path(config), max_bytes=MAX_CONFIG_BYTES, label="Git exclude file"
        )
    except SetupError as error:
        return Check("git-exclude", "blocked", str(error))
    if snapshot is None:
        return Check("git-exclude", "needs-apply", f"missing file: {_exclude_path(config)}")
    try:
        content = snapshot.data.decode("utf-8")
    except UnicodeDecodeError:
        return Check("git-exclude", "blocked", "Git exclude file is not UTF-8")
    if content.count(EXCLUDE_BEGIN) == 0 and content.count(EXCLUDE_END) == 0:
        return Check("git-exclude", "needs-apply", "managed locator exclusion is missing")
    if (
        content.count(EXCLUDE_BEGIN) != 1
        or content.count(EXCLUDE_END) != 1
        or _exclude_block() not in content
    ):
        return Check("git-exclude", "blocked", "managed exclusion block is malformed")
    effective = _run_git(
        config.workspace_root,
        "check-ignore",
        "-q",
        "--no-index",
        "--",
        config.locator_relative_path.as_posix(),
        check=False,
    )
    if effective.returncode != 0:
        return Check(
            "git-exclude",
            "blocked",
            "later exclude rules negate the managed locator exclusion",
        )
    return Check("git-exclude", "ready", f"{_exclude_path(config)}: {EXCLUDE_ENTRY}")


def _reload_receipt_payload(config: HostConfig, labels: dict[str, str]) -> bytes:
    payload = {"version": 1, "labels": dict(sorted(labels.items()))}
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()


def _load_reload_receipt(config: HostConfig) -> tuple[FileSnapshot | None, dict[str, str]]:
    try:
        snapshot = _optional_owned_file(
            config.reload_receipt,
            max_bytes=MAX_CONFIG_BYTES,
            label="LaunchAgent reload receipt",
        )
    except SetupError as error:
        if "missing" in str(error) and "parent" in str(error):
            return None, {}
        raise
    if snapshot is None:
        return None, {}
    try:
        parsed = json.loads(snapshot.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SetupError("LaunchAgent reload receipt is invalid JSON") from error
    if not isinstance(parsed, dict) or parsed.get("version") != 1:
        raise SetupError("LaunchAgent reload receipt has an invalid version")
    labels = parsed.get("labels")
    if not isinstance(labels, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in labels.items()
    ):
        raise SetupError("LaunchAgent reload receipt labels are invalid")
    expected_labels = {config.launch_agent_label, config.weekly_launch_agent_label}
    if not set(labels).issubset(expected_labels):
        raise SetupError("LaunchAgent reload receipt contains a foreign label")
    return snapshot, dict(labels)


def _check_reload_receipt(config: HostConfig, specs: Sequence[LaunchAgentSpec]) -> Check:
    state_check = _directory_check(config.state_root, name="host-state-root")
    if state_check.status != "ready":
        return state_check
    try:
        _snapshot, labels = _load_reload_receipt(config)
    except SetupError as error:
        return Check("launchctl-reload", "blocked", str(error))
    if not labels:
        return Check("launchctl-reload", "ready", "no pending LaunchAgent reload")
    sources: dict[str, str] = {}
    for spec in specs:
        source, source_check = _source_plist(spec)
        if source_check.status != "ready":
            return Check("launchctl-reload", "blocked", source_check.detail)
        sources[spec.label] = source.digest
    for label, digest in labels.items():
        if sources.get(label) != digest:
            return Check(
                "launchctl-reload",
                "needs-apply",
                f"reload receipt must be advanced to the current source digest: {label}",
            )
    return Check(
        "launchctl-reload",
        "needs-apply",
        "LaunchAgent reload required: " + ",".join(sorted(labels)),
    )


def _launchctl_service(label: str) -> str:
    return f"gui/{os.getuid()}/{label}"


def _known_launchctl_not_found(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode == 0:
        return False
    detail = (result.stderr or result.stdout).lower()
    return result.returncode in {3, 113} and (
        "could not find service" in detail or "service not found" in detail
    )


def _query_service(label: str, runner: CommandRunner) -> ServiceState:
    result = runner.run(["launchctl", "print", _launchctl_service(label)])
    if result.returncode == 0:
        return ServiceState(label=label, loaded=True)
    if _known_launchctl_not_found(result):
        return ServiceState(label=label, loaded=False)
    detail = (result.stderr or result.stdout).strip()[:MAX_COMMAND_DETAIL]
    raise SetupError(f"launchctl print failed for {label} with exit {result.returncode}: {detail}")


def _check_launchctl(spec: LaunchAgentSpec, runner: CommandRunner, *, no_launchctl: bool) -> Check:
    if no_launchctl:
        return Check(
            f"launchctl-{spec.key}",
            "skipped",
            "GUI launchctl query disabled by --no-launchctl",
        )
    try:
        state = _query_service(spec.label, runner)
    except SetupError as error:
        return Check(f"launchctl-{spec.key}", "blocked", str(error))
    if not state.loaded:
        return Check(
            f"launchctl-{spec.key}",
            "needs-apply",
            f"service is not loaded: {spec.label}",
        )
    return Check(f"launchctl-{spec.key}", "ready", _launchctl_service(spec.label))


def _check_manifest_mirrors(
    config: HostConfig,
    manifest: WorkspaceManifest,
    runner: CommandRunner,
    *,
    name: str,
) -> Check:
    try:
        snapshots = manifest_snapshots(config, manifest, runner)
    except SetupError as error:
        return Check(f"mirrors-{name}", "blocked", str(error))
    return Check(
        f"mirrors-{name}",
        "ready",
        f"manifest={manifest.digest}; repos={','.join(sorted(snapshots))}",
    )


def _prefetch_path_checks(
    manifests: Sequence[WorkspaceManifest],
) -> list[Check]:
    checks: list[Check] = []
    for manifest in manifests:
        for repo in manifest.repos:
            mirror = manifest.repo_path(repo)
            checks.extend(_git_admin_path_checks(mirror, prefix=f"prefetch-{repo.name}"))
    return checks


def _ensure_path_checks(
    config: HostConfig,
    manifests: Sequence[WorkspaceManifest],
) -> list[Check]:
    """Validate existing mirrors and safe creation paths before explicit ensure."""

    checks: list[Check] = []
    for manifest in manifests:
        for repo in manifest.repos:
            mirror = manifest.repo_path(repo)
            occupancy = _directory_check(
                mirror,
                name=f"ensure-mirror-path-{repo.name}",
                missing_status="needs-apply",
            )
            checks.append(occupancy)
            if occupancy.status == "ready":
                checks.extend(_git_admin_path_checks(mirror, prefix=f"ensure-{repo.name}"))
                continue
            if occupancy.status == "needs-apply":
                try:
                    relative = mirror.relative_to(config.workspace_root)
                except ValueError:
                    checks.append(
                        Check(
                            f"ensure-mirror-create-{repo.name}",
                            "blocked",
                            f"mirror creation target escapes workspace: {mirror}",
                        )
                    )
                else:
                    checks.append(
                        _preflight_creation_path(
                            config.workspace_root,
                            relative.parts,
                            label=f"ensure mirror creation {repo.name}",
                        )
                    )
    return checks


def collect_core_checks(
    config: HostConfig,
    home: Path,
    runner: CommandRunner,
    *,
    no_launchctl: bool,
    include_mirrors: bool = True,
) -> list[Check]:
    specs = _launch_agent_specs(config, home)
    control_manifest: WorkspaceManifest | None = None
    main_manifest: WorkspaceManifest | None = None
    manifest_errors: list[SetupError] = []
    if include_mirrors:
        try:
            control_manifest = load_workspace_manifest(
                config.control_mirror_manifest,
                label="control mirror manifest",
                expected_cache_root=config.cache_root,
            )
        except SetupError as error:
            manifest_errors.append(error)
        try:
            main_manifest = _load_main_manifest(config)
        except SetupError as error:
            manifest_errors.append(error)
    path_checks = _git_admin_path_checks(config.workspace_root, prefix="workspace")
    loaded_manifests = tuple(
        manifest for manifest in (control_manifest, main_manifest) if manifest is not None
    )
    if include_mirrors:
        path_checks.extend(_prefetch_path_checks(loaded_manifests))
    git_paths_ready = (
        not manifest_errors
        and (not include_mirrors or len(loaded_manifests) == 2)
        and not any(check.status == "blocked" for check in path_checks)
    )
    checks = [*path_checks]
    for error in manifest_errors:
        checks.append(Check("manifests", "blocked", str(error)))
    checks.extend(
        [
            _check_python(config, runner),
            _check_workspace_helper(config),
            _check_control_mirror_manifest(config),
            _check_skill_source(config),
            _check_locator(config),
            (
                _check_exclude(config)
                if git_paths_ready
                else Check(
                    "git-exclude",
                    "blocked",
                    "Git checks skipped because filesystem path preflight is blocked",
                )
            ),
            _directory_check(config.log_root, name="host-log-root"),
            _directory_check(config.state_root, name="host-state-root"),
        ]
    )
    for spec in specs:
        checks.append(_source_plist(spec)[1])
        checks.append(_check_launch_agent_file(spec))
    checks.append(_check_reload_receipt(config, specs))
    for spec in specs:
        checks.append(_check_launchctl(spec, runner, no_launchctl=no_launchctl))
    if include_mirrors and git_paths_ready:
        assert control_manifest is not None and main_manifest is not None
        checks.extend(
            [
                _check_manifest_mirrors(config, control_manifest, runner, name="control"),
                _check_manifest_mirrors(config, main_manifest, runner, name="main"),
            ]
        )
    return checks


def _preflight_creation_path(base: Path, children: Sequence[str], *, label: str) -> Check:
    try:
        descriptor, _ = _open_real_directory(
            base, label=f"{label} base", require_current_owner=True
        )
        try:
            current = base
            missing = False
            for child in children:
                current /= child
                if missing:
                    continue
                try:
                    next_fd = os.open(
                        child,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    missing = True
                    continue
                metadata = os.fstat(next_fd)
                _validate_directory_metadata(
                    metadata,
                    label=f"{label} {current}",
                    require_current_owner=True,
                )
                os.close(descriptor)
                descriptor = next_fd
        finally:
            os.close(descriptor)
    except (OSError, SetupError) as error:
        return Check(label, "blocked", str(error))
    status = "needs-apply" if missing else "ready"
    detail = f"directory creation required: {current}" if missing else str(current)
    return Check(label, status, detail)


def _build_exclude_content(config: HostConfig) -> tuple[FileSnapshot | None, bytes, int]:
    _validate_workspace_git_root(config)
    path = _exclude_path(config)
    snapshot = _optional_owned_file(path, max_bytes=MAX_CONFIG_BYTES, label="Git exclude file")
    if snapshot is None:
        content = ""
        mode = 0o644
    else:
        try:
            content = snapshot.data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SetupError("Git exclude file is not UTF-8") from error
        mode = stat.S_IMODE(snapshot.binding.mode)
    if content.count(EXCLUDE_BEGIN) or content.count(EXCLUDE_END):
        if (
            content.count(EXCLUDE_BEGIN) != 1
            or content.count(EXCLUDE_END) != 1
            or _exclude_block() not in content
        ):
            raise SetupError("managed exclusion block is malformed")
        return snapshot, snapshot.data if snapshot is not None else b"", mode
    separator = "" if not content or content.endswith("\n") else "\n"
    if content and not content.endswith("\n\n"):
        separator += "\n"
    return snapshot, f"{content}{separator}{_exclude_block()}".encode(), mode


def _install_exclude(
    config: HostConfig,
    file_ops: FileOps,
    journal: MutationJournal,
) -> bool:
    snapshot, desired, mode = _build_exclude_content(config)
    if snapshot is not None and snapshot.data == desired:
        return False
    transaction = file_ops.begin_replace(
        _exclude_path(config),
        desired,
        mode=mode,
        expected=snapshot,
        max_bytes=MAX_CONFIG_BYTES,
    )
    journal.add_file(transaction)
    if _check_exclude(config).status != "ready":
        raise SetupError("managed Git exclusion did not become effective")
    return True


def _install_locator(config: HostConfig, journal: MutationJournal) -> bool:
    check = _check_locator(config)
    if check.status == "ready":
        return False
    if check.status == "blocked" and "locator target is not ready" not in check.detail:
        raise SetupError(check.detail)
    if _check_skill_source(config).status != "ready":
        raise SetupError(_check_skill_source(config).detail)
    parent_fd, _ = _open_real_directory(
        config.skill_locator.parent,
        label="skill locator parent",
        require_current_owner=True,
    )
    target = desired_locator_target(config)
    try:
        try:
            os.symlink(target, config.skill_locator.name, dir_fd=parent_fd)
        except FileExistsError as error:
            raise SetupError(f"foreign object appeared at {config.skill_locator}") from error
        try:
            metadata = os.stat(config.skill_locator.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            raise SetupError(
                f"created skill locator could not be rebound and was retained: "
                f"{config.skill_locator}"
            ) from error
        binding = Binding.from_stat(metadata)
        journal.symlinks.append(CreatedSymlink(config.skill_locator, binding, target))
        if (
            not stat.S_ISLNK(metadata.st_mode)
            or os.readlink(config.skill_locator.name, dir_fd=parent_fd) != target
        ):
            raise SetupError("created skill locator did not verify")
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    if _check_locator(config).status != "ready":
        raise SetupError("created skill locator did not resolve to the intended skill")
    return True


def _plan_launch_agent(spec: LaunchAgentSpec) -> PlannedLaunchAgent:
    source, source_check = _source_plist(spec)
    if source_check.status != "ready":
        raise SetupError(source_check.detail)
    try:
        installed = _optional_owned_file(
            spec.destination,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"installed {spec.key} LaunchAgent",
        )
    except SetupError as error:
        detail = str(error)
        if "missing" in detail and "parent" in detail:
            installed = None
        else:
            raise
    if (
        installed is not None
        and installed.data != source.data
        and not _managed_plist(installed, spec)
    ):
        raise SetupError(f"foreign LaunchAgent occupies {spec.destination}")
    return PlannedLaunchAgent(
        spec=spec,
        source=source,
        installed=installed,
        changed=installed is None or installed.data != source.data,
    )


def _revalidate_launch_agent_plans(
    plans: Sequence[PlannedLaunchAgent],
    expected_destinations: dict[str, FileSnapshot],
) -> None:
    for plan in plans:
        source = _read_owned_regular_file(
            plan.spec.source,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"{plan.spec.key} LaunchAgent source",
        )
        if source != plan.source:
            raise SetupError(
                f"{plan.spec.key} LaunchAgent source changed after the apply plan was frozen"
            )
        installed = _read_owned_regular_file(
            plan.spec.destination,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"installed {plan.spec.key} LaunchAgent",
        )
        if installed != expected_destinations[plan.spec.label]:
            raise SetupError(
                f"installed {plan.spec.key} LaunchAgent no longer matches the frozen source"
            )


def _install_plist(
    plan: PlannedLaunchAgent,
    file_ops: FileOps,
    journal: MutationJournal,
) -> FileSnapshot:
    spec = plan.spec
    if not plan.changed:
        assert plan.installed is not None
        return plan.installed
    transaction = file_ops.begin_replace(
        spec.destination,
        plan.source.data,
        mode=0o644,
        expected=plan.installed,
        max_bytes=MAX_CONFIG_BYTES,
    )
    journal.add_file(transaction)
    installed = _read_owned_regular_file(
        spec.destination,
        max_bytes=MAX_CONFIG_BYTES,
        label=f"installed {spec.key} LaunchAgent",
    )
    if installed != transaction.new_snapshot or installed.data != plan.source.data:
        raise SetupError(f"installed {spec.key} LaunchAgent did not match the frozen source")
    return transaction.new_snapshot


def _write_reload_receipt(
    config: HostConfig,
    labels: dict[str, str],
    file_ops: FileOps,
    journal: MutationJournal,
    *,
    expected: FileSnapshot | None,
) -> FileSnapshot:
    desired = _reload_receipt_payload(config, labels)
    if expected is not None and expected.data == desired:
        current = _read_owned_regular_file(
            config.reload_receipt,
            max_bytes=MAX_CONFIG_BYTES,
            label="LaunchAgent reload receipt",
        )
        if current != expected:
            raise SetupError("LaunchAgent reload receipt changed since preflight")
        return expected
    transaction = file_ops.begin_replace(
        config.reload_receipt,
        desired,
        mode=0o600,
        expected=expected,
        max_bytes=MAX_CONFIG_BYTES,
    )
    journal.add_file(transaction)
    return transaction.new_snapshot


def _run_helper(
    config: HostConfig,
    manifest: Path,
    arguments: Sequence[str],
    runner: CommandRunner,
) -> subprocess.CompletedProcess[str]:
    argv = [
        str(config.python_executable),
        str(config.workspace_helper),
        "--config",
        str(manifest),
        *arguments,
    ]
    return runner.run(
        argv,
        cwd=config.workspace_root,
        env=_git_environment(disable_hooks=False),
    )


def _run_ensure(config: HostConfig, runner: CommandRunner) -> None:
    control_manifest = WorkspaceManifest(
        path=config.path,
        cache_root=config.cache_root,
        repos=(config.control_repo,),
        snapshot=config.manifest_snapshot,
    )
    main_manifest = _load_main_manifest(config)
    manifests = (control_manifest, main_manifest)
    checks = _ensure_path_checks(config, manifests)
    if not any(check.status == "blocked" for check in checks):
        for manifest in manifests:
            for repo in manifest.repos:
                checks.append(_ensure_mirror_precheck(manifest, repo))
    _raise_if_blocked(checks, phase="ensure revalidation")
    for manifest in manifests:
        rebound = _read_owned_regular_file(
            manifest.path,
            max_bytes=MAX_CONFIG_BYTES,
            label="ensure workspace manifest",
        )
        if rebound != manifest.snapshot:
            raise SetupError(f"ensure manifest changed before helper invocation: {manifest.path}")
        for repo in manifest.repos:
            precheck = _ensure_mirror_precheck(manifest, repo)
            if precheck.status == "blocked":
                raise SetupError(f"ensure mirror revalidation blocked: {precheck.detail}")
        result = _run_helper(config, manifest.path, ["ensure"], runner)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[:MAX_COMMAND_DETAIL]
            raise SetupError(
                f"workspace helper ensure failed for {manifest.path} with exit "
                f"{result.returncode}: {detail}"
            )


def _prefetch_arguments(stamp: str, repo: str | None = None) -> list[str]:
    arguments = ["prefetch"]
    if repo is not None:
        arguments.extend(["--repo", repo])
    arguments.extend(["--stamp", stamp])
    if "ensure" in arguments or "clone" in arguments:
        raise AssertionError("scheduled prefetch must never include ensure or clone")
    return arguments


def _parse_utc_timestamp(raw: Any, *, field: str) -> dt.datetime:
    if not isinstance(raw, str):
        raise SetupError(f"{field} must be a timestamp string")
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (OverflowError, ValueError) as error:
        raise SetupError(f"{field} is not a valid timestamp") from error
    if parsed.tzinfo is None:
        raise SetupError(f"{field} must include a timezone")
    try:
        return parsed.astimezone(dt.UTC)
    except (OverflowError, ValueError) as error:
        raise SetupError(f"{field} is outside the supported timestamp range") from error


@dataclasses.dataclass(frozen=True)
class StampEvidence:
    path: Path
    snapshot: FileSnapshot
    ended_at: dt.datetime
    oldest_ended_at: dt.datetime
    manifest: WorkspaceManifest
    repos: tuple[str, ...]
    mirror_snapshots: dict[str, dict[str, str]]


@dataclasses.dataclass(frozen=True)
class CapturedPrefetch:
    canonical_stamp: str
    temporary_stamp: str
    evidence: StampEvidence
    canonical_payload: bytes


def _blocked_stamp_checks(stamp: str, detail: str, *, historical: bool) -> list[Check]:
    age_status = "skipped" if historical else "blocked"
    age_detail = (
        "historical replay skips age only; integrity failed"
        if historical
        else "age not evaluated because integrity failed"
    )
    return [
        Check(f"freshness-{stamp}-integrity", "blocked", detail),
        Check(f"freshness-{stamp}-snapshot", "blocked", "snapshot not evaluated"),
        Check(f"freshness-{stamp}-age", age_status, age_detail),
    ]


def validate_freshness_stamp(
    config: HostConfig,
    *,
    stamp_name: str,
    manifest_path: Path,
    max_age_minutes: int,
    now: dt.datetime,
    historical: bool,
    runner: CommandRunner,
) -> tuple[list[Check], StampEvidence | None]:
    try:
        manifest = load_workspace_manifest(
            manifest_path,
            label=f"{stamp_name} manifest",
            expected_cache_root=config.cache_root,
        )
        if (
            manifest.path == config.control_mirror_manifest
            and manifest.snapshot != config.manifest_snapshot
        ):
            raise SetupError("control manifest changed after the active config was loaded")
        before = manifest_snapshots(config, manifest, runner)
        path = config.cache_root / "freshness" / f"{stamp_name}.json"
        stamp_snapshot = _read_owned_regular_file(
            path, max_bytes=MAX_STAMP_BYTES, label=f"{stamp_name} stamp"
        )
        try:
            parsed = json.loads(stamp_snapshot.data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SetupError(f"{stamp_name} stamp is not valid UTF-8 JSON") from error
        if not isinstance(parsed, dict):
            raise SetupError("stamp root must be an object")
        if parsed.get("version") != 1 or parsed.get("stamp") != stamp_name:
            raise SetupError("stamp identity does not match the requested version/name")
        if parsed.get("cache_root") != str(manifest.cache_root):
            raise SetupError("stamp cache_root does not match the manifest")
        if parsed.get("workspace_root") != str(manifest.root):
            raise SetupError("stamp workspace_root does not match the manifest directory")
        repos = parsed.get("repos")
        expected_names = {repo.name for repo in manifest.repos}
        if not isinstance(repos, dict) or set(repos) != expected_names:
            raise SetupError("stamp repo entries do not exactly match the manifest")
        started_at = _parse_utc_timestamp(
            parsed.get("started_at"), field=f"{stamp_name}.started_at"
        )
        ended_at = _parse_utc_timestamp(parsed.get("ended_at"), field=f"{stamp_name}.ended_at")
        if started_at > ended_at:
            raise SetupError("stamp started_at is after ended_at")
        if now.astimezone(dt.UTC) - ended_at < -dt.timedelta(minutes=5):
            raise SetupError("stamp timestamp is more than five minutes in the future")
        ended_times = [ended_at]
        ages: list[tuple[str, dt.timedelta]] = [("stamp", now.astimezone(dt.UTC) - ended_at)]
        for repo in manifest.repos:
            entry = repos[repo.name]
            if not isinstance(entry, dict) or entry.get("status") != "ready":
                raise SetupError(f"repository entry is not ready: {repo.name}")
            entry_started = _parse_utc_timestamp(
                entry.get("started_at"), field=f"{stamp_name}.{repo.name}.started_at"
            )
            entry_ended = _parse_utc_timestamp(
                entry.get("ended_at"), field=f"{stamp_name}.{repo.name}.ended_at"
            )
            if entry_started > entry_ended:
                raise SetupError(f"repository entry started_at is after ended_at: {repo.name}")
            if entry_started < started_at or entry_ended > ended_at:
                raise SetupError(
                    f"repository entry timestamps are outside the stamp window: {repo.name}"
                )
            entry_age = now.astimezone(dt.UTC) - entry_ended
            if entry_age < -dt.timedelta(minutes=5):
                raise SetupError(f"repository entry timestamp is in the future: {repo.name}")
            ages.append((repo.name, entry_age))
            ended_times.append(entry_ended)
            expected_snapshot = before[repo.name]
            for key, expected_value in expected_snapshot.items():
                if entry.get(key) != expected_value:
                    raise SetupError(
                        f"stamp snapshot mismatch for {repo.name}.{key}: "
                        f"stamp={entry.get(key)!r} current={expected_value!r}"
                    )
        after = manifest_snapshots(config, manifest, runner)
        if after != before:
            raise SetupError("mirror snapshot changed while validating the stamp")
        rebound_manifest = _read_owned_regular_file(
            manifest.path,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"{stamp_name} manifest",
        )
        if rebound_manifest != manifest.snapshot:
            raise SetupError("manifest identity or content changed while validating the stamp")
    except SetupError as error:
        return _blocked_stamp_checks(stamp_name, str(error), historical=historical), None
    age_problems = [
        f"{name}={int(age.total_seconds() // 60)}m"
        for name, age in ages
        if age > dt.timedelta(minutes=max_age_minutes)
    ]
    if historical:
        age_check = Check(
            f"freshness-{stamp_name}-age",
            "skipped",
            "explicit historical replay skips maximum age only",
        )
    elif age_problems:
        age_check = Check(
            f"freshness-{stamp_name}-age",
            "blocked",
            f"freshness exceeds {max_age_minutes}m: {','.join(age_problems)}",
        )
    else:
        age_check = Check(
            f"freshness-{stamp_name}-age",
            "ready",
            f"all timestamps are within {max_age_minutes}m",
        )
    checks = [
        Check(
            f"freshness-{stamp_name}-integrity",
            "ready",
            f"manifest={manifest.digest}; repos={','.join(sorted(expected_names))}",
        ),
        Check(
            f"freshness-{stamp_name}-snapshot",
            "ready",
            "stamp snapshot matches stable current mirrors",
        ),
        age_check,
    ]
    return checks, StampEvidence(
        path=path,
        snapshot=stamp_snapshot,
        ended_at=ended_at,
        oldest_ended_at=min(ended_times),
        manifest=manifest,
        repos=tuple(sorted(expected_names)),
        mirror_snapshots=before,
    )


def _decision_age_check(
    stamp_name: str,
    evidence: StampEvidence,
    *,
    max_age_minutes: int,
    now: dt.datetime,
) -> Check:
    age = now.astimezone(dt.UTC) - evidence.oldest_ended_at
    if age > dt.timedelta(minutes=max_age_minutes):
        return Check(
            f"freshness-{stamp_name}-age",
            "blocked",
            f"freshness exceeded {max_age_minutes}m before the final decision: "
            f"oldest={int(age.total_seconds() // 60)}m",
        )
    return Check(
        f"freshness-{stamp_name}-age",
        "ready",
        f"all timestamps are within {max_age_minutes}m at the final decision",
    )


def _replace_check(checks: list[Check], replacement: Check) -> None:
    for index, check in enumerate(checks):
        if check.name == replacement.name:
            checks[index] = replacement
            return
    checks.append(replacement)


def _weekly_receipt_payload(
    config: HostConfig,
    control: StampEvidence,
    main: StampEvidence,
    *,
    created_at: dt.datetime,
) -> bytes:
    payload = {
        "version": 1,
        "receipt": config.weekly_pair_receipt,
        "created_at": created_at.astimezone(dt.UTC).isoformat().replace("+00:00", "Z"),
        "stamps": {
            config.control_stamp: {
                "sha256": control.snapshot.digest,
                "ended_at": control.ended_at.isoformat().replace("+00:00", "Z"),
                "manifest_sha256": control.manifest.digest,
                "repos": list(control.repos),
            },
            config.main_stamp: {
                "sha256": main.snapshot.digest,
                "ended_at": main.ended_at.isoformat().replace("+00:00", "Z"),
                "manifest_sha256": main.manifest.digest,
                "repos": list(main.repos),
            },
        },
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()


def _validate_weekly_receipt(
    config: HostConfig,
    control: StampEvidence | None,
    main: StampEvidence | None,
    *,
    max_age_minutes: int,
    now: dt.datetime,
) -> Check:
    if control is None or main is None:
        return Check("weekly-pair-receipt", "blocked", "stamp evidence is incomplete")
    try:
        receipt = _read_owned_regular_file(
            config.weekly_receipt,
            max_bytes=MAX_STAMP_BYTES,
            label="weekly pair receipt",
        )
        try:
            parsed = json.loads(receipt.data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SetupError("weekly pair receipt is not valid UTF-8 JSON") from error
        if (
            not isinstance(parsed, dict)
            or parsed.get("version") != 1
            or parsed.get("receipt") != config.weekly_pair_receipt
        ):
            raise SetupError("weekly pair receipt identity is invalid")
        created_at = _parse_utc_timestamp(parsed.get("created_at"), field="weekly.created_at")
        age = now.astimezone(dt.UTC) - created_at
        if age < -dt.timedelta(minutes=5):
            raise SetupError("weekly pair receipt is in the future")
        if age > dt.timedelta(minutes=max_age_minutes):
            raise SetupError("weekly pair receipt is stale")
        if created_at < max(control.ended_at, main.ended_at):
            raise SetupError("weekly pair receipt predates one of its bound stamps")
        stamps = parsed.get("stamps")
        if not isinstance(stamps, dict) or set(stamps) != {
            config.control_stamp,
            config.main_stamp,
        }:
            raise SetupError("weekly pair receipt stamp set is invalid")
        for stamp_name, evidence in (
            (config.control_stamp, control),
            (config.main_stamp, main),
        ):
            entry = stamps[stamp_name]
            expected = {
                "sha256": evidence.snapshot.digest,
                "ended_at": evidence.ended_at.isoformat().replace("+00:00", "Z"),
                "manifest_sha256": evidence.manifest.digest,
                "repos": list(evidence.repos),
            }
            if entry != expected:
                raise SetupError(
                    f"weekly pair receipt no longer matches current {stamp_name} evidence"
                )
    except SetupError as error:
        return Check("weekly-pair-receipt", "blocked", str(error))
    return Check(
        "weekly-pair-receipt",
        "ready",
        f"{config.weekly_receipt}; max_age={max_age_minutes}m",
    )


def _revalidate_pair_evidence(
    config: HostConfig,
    control: StampEvidence,
    main: StampEvidence,
    runner: CommandRunner,
) -> None:
    evidence_set = (control, main)
    for evidence in evidence_set:
        stamp = _read_owned_regular_file(
            evidence.path,
            max_bytes=MAX_STAMP_BYTES,
            label=f"{evidence.path.stem} stamp",
        )
        manifest = _read_owned_regular_file(
            evidence.manifest.path,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"{evidence.path.stem} manifest",
        )
        if stamp != evidence.snapshot or manifest != evidence.manifest.snapshot:
            raise SetupError("weekly pair input changed before final snapshot validation")
    for evidence in evidence_set:
        current = manifest_snapshots(config, evidence.manifest, runner)
        if current != evidence.mirror_snapshots:
            raise SetupError("weekly pair mirror changed before final snapshot validation")
    for evidence in evidence_set:
        stamp = _read_owned_regular_file(
            evidence.path,
            max_bytes=MAX_STAMP_BYTES,
            label=f"{evidence.path.stem} stamp",
        )
        manifest = _read_owned_regular_file(
            evidence.manifest.path,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"{evidence.path.stem} manifest",
        )
        if stamp != evidence.snapshot or manifest != evidence.manifest.snapshot:
            raise SetupError("weekly pair input changed during final snapshot validation")


def _validate_stable_weekly_pair(
    config: HostConfig,
    control: StampEvidence | None,
    main: StampEvidence | None,
    *,
    max_age_minutes: int,
    now: dt.datetime,
    runner: CommandRunner,
) -> Check:
    if control is None or main is None:
        return Check("weekly-pair-receipt", "blocked", "stamp evidence is incomplete")
    try:
        receipt_before = _read_owned_regular_file(
            config.weekly_receipt,
            max_bytes=MAX_STAMP_BYTES,
            label="weekly pair receipt",
        )
        receipt_check = _validate_weekly_receipt(
            config,
            control,
            main,
            max_age_minutes=max_age_minutes,
            now=now,
        )
        if receipt_check.status != "ready":
            return receipt_check
        _revalidate_pair_evidence(config, control, main, runner)
        receipt_after = _read_owned_regular_file(
            config.weekly_receipt,
            max_bytes=MAX_STAMP_BYTES,
            label="weekly pair receipt",
        )
        if receipt_after != receipt_before:
            raise SetupError("weekly pair receipt changed during final snapshot validation")
    except SetupError as error:
        return Check("weekly-pair-receipt", "blocked", str(error))
    return receipt_check


def _existing_weekly_receipt(config: HostConfig) -> FileSnapshot | None:
    snapshot = _optional_owned_file(
        config.weekly_receipt,
        max_bytes=MAX_STAMP_BYTES,
        label="weekly pair receipt",
    )
    if snapshot is None:
        return None
    try:
        parsed = json.loads(snapshot.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SetupError("foreign or invalid weekly pair receipt exists") from error
    if (
        not isinstance(parsed, dict)
        or parsed.get("version") != 1
        or parsed.get("receipt") != config.weekly_pair_receipt
    ):
        raise SetupError("foreign or invalid weekly pair receipt exists")
    return snapshot


def _control_workspace_manifest(config: HostConfig) -> WorkspaceManifest:
    manifest = load_workspace_manifest(
        config.control_mirror_manifest,
        label="control mirror manifest",
        expected_cache_root=config.cache_root,
    )
    if manifest.repos != (config.control_repo,):
        raise SetupError("control mirror manifest repository entry changed")
    if manifest.snapshot != config.manifest_snapshot:
        raise SetupError("control mirror manifest changed after config load")
    return manifest


def _allocate_temporary_stamp(config: HostConfig, canonical_stamp: str) -> str:
    parent_fd, _parent_binding = _open_real_directory(
        config.cache_root / "freshness",
        label="freshness state directory",
        require_current_owner=True,
    )
    try:
        for _attempt in range(4):
            prefix = canonical_stamp[:52]
            candidate = _stamp_name(
                f"{prefix}-run-{secrets.token_hex(8)}",
                field="temporary freshness stamp",
            )
            leaves = (f"{candidate}.json", f"{candidate}.json.tmp")
            occupied = False
            for leaf in leaves:
                snapshot = _snapshot_at(
                    parent_fd,
                    leaf,
                    max_bytes=MAX_STAMP_BYTES,
                    label="temporary freshness stamp leaf",
                    missing_ok=True,
                )
                occupied = occupied or snapshot is not None
            if not occupied:
                return candidate
    finally:
        os.close(parent_fd)
    raise SetupError("could not allocate an unused private freshness stamp name")


def _cleanup_temporary_stamp_name(
    config: HostConfig,
    temporary_stamp: str,
    operations: FileOps,
) -> list[str]:
    errors: list[str] = []
    parent = config.cache_root / "freshness"
    for leaf in (f"{temporary_stamp}.json", f"{temporary_stamp}.json.tmp"):
        try:
            snapshot = _optional_owned_file(
                parent / leaf,
                max_bytes=MAX_STAMP_BYTES,
                label="one-shot freshness artifact",
            )
            if snapshot is None:
                continue
            parent_fd, parent_binding = _open_real_directory(
                parent,
                label="one-shot freshness parent",
                require_current_owner=True,
            )
            try:
                _retire_regular_leaf(
                    parent_fd,
                    parent_path=parent,
                    parent_binding=parent_binding,
                    target=leaf,
                    expected=snapshot,
                    max_bytes=MAX_STAMP_BYTES,
                    renamer=operations.renamer,
                    label="one-shot freshness artifact cleanup",
                )
            finally:
                os.close(parent_fd)
        except SetupError as error:
            errors.append(str(error))
    return errors


def _capture_prefetch_step(
    config: HostConfig,
    runner: CommandRunner,
    *,
    name: str,
    canonical_stamp: str,
    manifest_loader: Callable[[], WorkspaceManifest],
    repo: str | None,
    now: dt.datetime | None,
    operations: FileOps,
) -> tuple[dict[str, Any], CapturedPrefetch | None]:
    temporary_stamp: str | None = None
    try:
        manifest = manifest_loader()
        path_checks = _prefetch_path_checks((manifest,))
        path_checks.append(
            _directory_check(
                config.cache_root / "freshness",
                name=f"prefetch-freshness-{name}",
                missing_status="blocked",
            )
        )
        _raise_if_blocked(path_checks, phase=f"{name} prefetch path preflight")
        temporary_stamp = _allocate_temporary_stamp(config, canonical_stamp)
        rebound = _read_owned_regular_file(
            manifest.path,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"{name} prefetch manifest",
        )
        if rebound != manifest.snapshot:
            raise SetupError(f"{name} prefetch manifest changed before helper invocation")
    except SetupError as error:
        cleanup_errors = (
            _cleanup_temporary_stamp_name(config, temporary_stamp, operations)
            if temporary_stamp is not None
            else []
        )
        detail = str(error)
        if cleanup_errors:
            detail += "; cleanup incomplete: " + "; ".join(cleanup_errors)
        return (
            {"name": name, "returncode": None, "detail": detail[:MAX_COMMAND_DETAIL]},
            None,
        )
    assert temporary_stamp is not None
    try:
        result = _run_helper(
            config,
            manifest.path,
            _prefetch_arguments(temporary_stamp, repo),
            runner,
        )
    except SetupError as error:
        cleanup_errors = _cleanup_temporary_stamp_name(config, temporary_stamp, operations)
        detail = str(error)
        if cleanup_errors:
            detail += "; cleanup incomplete: " + "; ".join(cleanup_errors)
        return (
            {"name": name, "returncode": None, "detail": detail[:MAX_COMMAND_DETAIL]},
            None,
        )
    detail = (result.stderr or result.stdout).strip()[:MAX_COMMAND_DETAIL]
    step = {"name": name, "returncode": result.returncode, "detail": detail}
    if result.returncode != 0:
        cleanup_errors = _cleanup_temporary_stamp_name(config, temporary_stamp, operations)
        if cleanup_errors:
            step["detail"] = (f"{detail}; cleanup incomplete: " + "; ".join(cleanup_errors))[
                :MAX_COMMAND_DETAIL
            ]
        return step, None
    validation_now = now or dt.datetime.now(dt.UTC)
    validation_config = config
    if manifest.path == config.control_mirror_manifest:
        try:
            validation_config = load_config(manifest.path)
        except SetupError as error:
            cleanup_errors = _cleanup_temporary_stamp_name(config, temporary_stamp, operations)
            detail = str(error)
            if cleanup_errors:
                detail += "; cleanup incomplete: " + "; ".join(cleanup_errors)
            step["detail"] = detail[:MAX_COMMAND_DETAIL]
            return step, None
        if _config_identity(validation_config) != _config_identity(config):
            cleanup_errors = _cleanup_temporary_stamp_name(config, temporary_stamp, operations)
            step["detail"] = "control config identity changed during helper prefetch"
            if cleanup_errors:
                step["detail"] += "; cleanup incomplete: " + "; ".join(cleanup_errors)
                step["detail"] = step["detail"][:MAX_COMMAND_DETAIL]
            return step, None
    checks, evidence = validate_freshness_stamp(
        validation_config,
        stamp_name=temporary_stamp,
        manifest_path=manifest.path,
        max_age_minutes=config.default_max_age_minutes,
        now=validation_now,
        historical=False,
        runner=runner,
    )
    blocked = [check for check in checks if check.status != "ready"]
    if evidence is None or blocked:
        step["detail"] = "; ".join(f"{check.name}: {check.detail}" for check in blocked)[
            :MAX_COMMAND_DETAIL
        ]
        cleanup_errors = _cleanup_temporary_stamp_name(config, temporary_stamp, operations)
        if cleanup_errors:
            step["detail"] = (
                f"{step['detail']}; cleanup incomplete: " + "; ".join(cleanup_errors)
            )[:MAX_COMMAND_DETAIL]
        return step, None
    try:
        parsed = json.loads(evidence.snapshot.data.decode("utf-8"))
        if not isinstance(parsed, dict) or parsed.get("stamp") != temporary_stamp:
            raise SetupError("temporary helper stamp identity changed")
        parsed["stamp"] = canonical_stamp
        payload = (json.dumps(parsed, indent=2, sort_keys=True) + "\n").encode()
        temp_path = evidence.path.with_suffix(evidence.path.suffix + ".tmp")
        if (
            _optional_owned_file(
                temp_path,
                max_bytes=MAX_STAMP_BYTES,
                label=f"{name} helper temporary file",
            )
            is not None
        ):
            raise SetupError(f"{name} helper left an incomplete temporary stamp")
    except (UnicodeDecodeError, json.JSONDecodeError, SetupError) as error:
        cleanup_errors = _cleanup_temporary_stamp_name(config, temporary_stamp, operations)
        detail = str(error)
        if cleanup_errors:
            detail += "; cleanup incomplete: " + "; ".join(cleanup_errors)
        step["detail"] = detail[:MAX_COMMAND_DETAIL]
        return step, None
    return (
        step,
        CapturedPrefetch(
            canonical_stamp=canonical_stamp,
            temporary_stamp=temporary_stamp,
            evidence=evidence,
            canonical_payload=payload,
        ),
    )


def _existing_canonical_stamp(config: HostConfig, stamp_name: str) -> FileSnapshot | None:
    path = config.cache_root / "freshness" / f"{stamp_name}.json"
    snapshot = _optional_owned_file(path, max_bytes=MAX_STAMP_BYTES, label=f"{stamp_name} stamp")
    if snapshot is None:
        return None
    try:
        parsed = json.loads(snapshot.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SetupError(f"foreign or invalid canonical stamp exists: {path}") from error
    if (
        not isinstance(parsed, dict)
        or parsed.get("version") != 1
        or parsed.get("stamp") != stamp_name
    ):
        raise SetupError(f"foreign or invalid canonical stamp exists: {path}")
    return snapshot


def _publish_captured_stamp(
    config: HostConfig,
    captured: CapturedPrefetch,
    operations: FileOps,
    journal: MutationJournal,
) -> None:
    path = config.cache_root / "freshness" / f"{captured.canonical_stamp}.json"
    previous = _existing_canonical_stamp(config, captured.canonical_stamp)
    transaction = operations.begin_replace(
        path,
        captured.canonical_payload,
        mode=0o600,
        expected=previous,
        max_bytes=MAX_STAMP_BYTES,
    )
    journal.add_file(transaction)


def _cleanup_captured_stamp(
    captured: CapturedPrefetch,
    operations: FileOps,
) -> None:
    path = captured.evidence.path
    parent_fd, parent_binding = _open_real_directory(
        path.parent,
        label="captured freshness parent",
        require_current_owner=True,
    )
    try:
        _retire_regular_leaf(
            parent_fd,
            parent_path=path.parent,
            parent_binding=parent_binding,
            target=path.name,
            expected=captured.evidence.snapshot,
            max_bytes=MAX_STAMP_BYTES,
            renamer=operations.renamer,
            label="captured temporary freshness stamp cleanup",
        )
    finally:
        os.close(parent_fd)


def _cleanup_captured_stamp_if_present(
    captured: CapturedPrefetch,
    operations: FileOps,
) -> None:
    current = _optional_owned_file(
        captured.evidence.path,
        max_bytes=MAX_STAMP_BYTES,
        label="captured temporary freshness stamp",
    )
    if current is None:
        return
    if current != captured.evidence.snapshot:
        raise SetupError(
            f"captured temporary freshness stamp changed and was retained: {captured.evidence.path}"
        )
    _cleanup_captured_stamp(captured, operations)


def _begin_freshness_directory(
    config: HostConfig,
    operations: FileOps,
) -> MutationJournal:
    journal = MutationJournal(operations.renamer)
    try:
        _ensure_directory_children(
            config.cache_root,
            ("freshness",),
            journal,
            label="host freshness state",
        )
    except BaseException as original_error:
        rollback_errors = journal.rollback()
        if rollback_errors:
            raise SetupError(
                f"freshness directory setup failed ({original_error}); rollback incomplete: "
                + "; ".join(rollback_errors)
            ) from original_error
        raise
    return journal


def prefetch_control(
    config: HostConfig,
    runner: CommandRunner,
    *,
    file_ops: FileOps | None = None,
    now: dt.datetime | None = None,
) -> tuple[dict[str, Any], HostConfig]:
    operations = file_ops or FileOps()
    global_checks = [_check_python(config, runner), _check_workspace_helper(config)]
    _raise_if_blocked(global_checks, phase="control prefetch preflight")
    freshness_journal = _begin_freshness_directory(config, operations)
    step, captured = _capture_prefetch_step(
        config,
        runner,
        name="control",
        canonical_stamp=config.control_stamp,
        manifest_loader=lambda: _control_workspace_manifest(config),
        repo=config.control_repo.name,
        now=now,
        operations=operations,
    )
    if captured is None:
        rollback_errors = freshness_journal.rollback()
        if rollback_errors:
            step["detail"] = (
                f"{step['detail']}; freshness rollback incomplete: " + "; ".join(rollback_errors)
            )[:MAX_COMMAND_DETAIL]
        return (
            make_report(
                "prefetch-control",
                [Check("control-prefetch", "blocked", step["detail"])],
                steps=[step],
                stamp_updated=False,
            ),
            config,
        )
    try:
        refreshed = load_config(config.control_mirror_manifest)
        if _config_identity(refreshed) != _config_identity(config):
            raise SetupError(
                "control config identity changed during control prefetch; rerun from the "
                "refreshed mirror"
            )
    except BaseException as original_error:
        cleanup_errors: list[str] = []
        try:
            _cleanup_captured_stamp_if_present(captured, operations)
        except SetupError as error:
            cleanup_errors.append(str(error))
        cleanup_errors.extend(freshness_journal.rollback())
        if cleanup_errors:
            raise SetupError(
                f"control prefetch refresh failed ({original_error}); cleanup incomplete: "
                + "; ".join(cleanup_errors)
            ) from original_error
        raise
    journal = MutationJournal(operations.renamer)
    try:
        _publish_captured_stamp(refreshed, captured, operations, journal)
        current = now or dt.datetime.now(dt.UTC)
        checks, evidence = validate_freshness_stamp(
            refreshed,
            stamp_name=refreshed.control_stamp,
            manifest_path=refreshed.control_mirror_manifest,
            max_age_minutes=refreshed.default_max_age_minutes,
            now=current,
            historical=False,
            runner=runner,
        )
        if evidence is None or any(check.status != "ready" for check in checks):
            raise SetupError("published control freshness stamp did not validate")
        decision_age = _decision_age_check(
            refreshed.control_stamp,
            evidence,
            max_age_minutes=refreshed.default_max_age_minutes,
            now=now or dt.datetime.now(dt.UTC),
        )
        _replace_check(checks, decision_age)
        if decision_age.status != "ready":
            raise SetupError(decision_age.detail)
        _cleanup_captured_stamp(captured, operations)
        journal.commit()
    except BaseException as original_error:
        rollback_errors = journal.rollback()
        try:
            _cleanup_captured_stamp_if_present(captured, operations)
        except SetupError as error:
            rollback_errors.append(str(error))
        rollback_errors.extend(freshness_journal.rollback())
        if rollback_errors:
            raise SetupError(
                f"control prefetch failed ({original_error}); rollback incomplete: "
                + "; ".join(rollback_errors)
            ) from original_error
        raise
    return (
        make_report(
            "prefetch-control",
            checks,
            steps=[step],
            stamp_updated=True,
        ),
        refreshed,
    )


def prefetch_weekly(
    config: HostConfig,
    runner: CommandRunner,
    *,
    file_ops: FileOps | None = None,
    now: dt.datetime | None = None,
) -> tuple[dict[str, Any], HostConfig]:
    operations = file_ops or FileOps()
    prechecks = [_check_python(config, runner), _check_workspace_helper(config)]
    _raise_if_blocked(prechecks, phase="weekly prefetch preflight")
    freshness_journal = _begin_freshness_directory(config, operations)
    steps: list[dict[str, Any]] = []
    captures: list[CapturedPrefetch] = []
    requests = (
        (
            "control",
            config.control_stamp,
            lambda: _control_workspace_manifest(config),
            config.control_repo.name,
        ),
        ("main", config.main_stamp, lambda: _load_main_manifest(config), None),
    )
    for name, stamp, loader, repo in requests:
        step, captured = _capture_prefetch_step(
            config,
            runner,
            name=name,
            canonical_stamp=stamp,
            manifest_loader=loader,
            repo=repo,
            now=now,
            operations=operations,
        )
        steps.append(step)
        if captured is not None:
            captures.append(captured)
    if len(captures) != 2:
        cleanup_errors: list[str] = []
        for captured in captures:
            try:
                _cleanup_captured_stamp(captured, operations)
            except SetupError as error:
                cleanup_errors.append(str(error))
        cleanup_errors.extend(freshness_journal.rollback())
        if cleanup_errors:
            steps.append(
                {
                    "name": "cleanup",
                    "returncode": None,
                    "detail": "; ".join(cleanup_errors)[:MAX_COMMAND_DETAIL],
                }
            )
        return (
            {
                "version": 1,
                "command": "prefetch-weekly",
                "status": "blocked",
                "steps": steps,
                "receipt_updated": False,
            },
            config,
        )
    current = now or dt.datetime.now(dt.UTC)
    try:
        refreshed = load_config(config.control_mirror_manifest)
        if _config_identity(refreshed) != _config_identity(config):
            raise SetupError(
                "control config identity changed during pair prefetch; rerun from the "
                "refreshed mirror"
            )
    except BaseException as original_error:
        cleanup_errors = []
        for captured in captures:
            try:
                _cleanup_captured_stamp_if_present(captured, operations)
            except SetupError as error:
                cleanup_errors.append(str(error))
        cleanup_errors.extend(freshness_journal.rollback())
        if cleanup_errors:
            raise SetupError(
                f"weekly prefetch refresh failed ({original_error}); cleanup incomplete: "
                + "; ".join(cleanup_errors)
            ) from original_error
        raise
    journal = MutationJournal(operations.renamer)
    try:
        for captured in captures:
            _publish_captured_stamp(refreshed, captured, operations, journal)
        control_checks, control_evidence = validate_freshness_stamp(
            refreshed,
            stamp_name=refreshed.control_stamp,
            manifest_path=refreshed.control_mirror_manifest,
            max_age_minutes=refreshed.default_max_age_minutes,
            now=current,
            historical=False,
            runner=runner,
        )
        main_checks, main_evidence = validate_freshness_stamp(
            refreshed,
            stamp_name=refreshed.main_stamp,
            manifest_path=refreshed.main_manifest,
            max_age_minutes=refreshed.default_max_age_minutes,
            now=current,
            historical=False,
            runner=runner,
        )
        evidence_checks = [*control_checks, *main_checks]
        if any(check.status != "ready" for check in evidence_checks):
            raise SetupError("published weekly prefetch stamps did not validate")
        assert control_evidence is not None and main_evidence is not None
        _revalidate_pair_evidence(refreshed, control_evidence, main_evidence, runner)
        receipt_time = now or dt.datetime.now(dt.UTC)
        for stamp_name, evidence in (
            (refreshed.control_stamp, control_evidence),
            (refreshed.main_stamp, main_evidence),
        ):
            decision_age = _decision_age_check(
                stamp_name,
                evidence,
                max_age_minutes=refreshed.default_max_age_minutes,
                now=receipt_time,
            )
            _replace_check(evidence_checks, decision_age)
            if decision_age.status != "ready":
                raise SetupError(decision_age.detail)
        previous = _existing_weekly_receipt(refreshed)
        payload = _weekly_receipt_payload(
            refreshed,
            control_evidence,
            main_evidence,
            created_at=receipt_time,
        )
        transaction = operations.begin_replace(
            refreshed.weekly_receipt,
            payload,
            mode=0o600,
            expected=previous,
            max_bytes=MAX_STAMP_BYTES,
        )
        journal.add_file(transaction)
        receipt_check = _validate_stable_weekly_pair(
            refreshed,
            control_evidence,
            main_evidence,
            max_age_minutes=refreshed.default_max_age_minutes,
            now=receipt_time,
            runner=runner,
        )
        if receipt_check.status != "ready":
            raise SetupError(receipt_check.detail)
        final_decision = now or dt.datetime.now(dt.UTC)
        for stamp_name, evidence in (
            (refreshed.control_stamp, control_evidence),
            (refreshed.main_stamp, main_evidence),
        ):
            decision_age = _decision_age_check(
                stamp_name,
                evidence,
                max_age_minutes=refreshed.default_max_age_minutes,
                now=final_decision,
            )
            _replace_check(evidence_checks, decision_age)
            if decision_age.status != "ready":
                raise SetupError(decision_age.detail)
        receipt_check = _validate_weekly_receipt(
            refreshed,
            control_evidence,
            main_evidence,
            max_age_minutes=refreshed.default_max_age_minutes,
            now=final_decision,
        )
        if receipt_check.status != "ready":
            raise SetupError(receipt_check.detail)
        for captured in captures:
            _cleanup_captured_stamp(captured, operations)
        journal.commit()
    except BaseException as original_error:
        rollback_errors = journal.rollback()
        for captured in captures:
            try:
                _cleanup_captured_stamp_if_present(captured, operations)
            except SetupError as error:
                rollback_errors.append(str(error))
        rollback_errors.extend(freshness_journal.rollback())
        if rollback_errors:
            raise SetupError(
                f"weekly prefetch failed ({original_error}); rollback incomplete: "
                + "; ".join(rollback_errors)
            ) from original_error
        raise
    return (
        make_report(
            "prefetch-weekly",
            [*evidence_checks, receipt_check],
            steps=steps,
            receipt_updated=True,
        ),
        refreshed,
    )


def _launchctl_command(
    runner: CommandRunner,
    argv: Sequence[str],
    *,
    action: str,
) -> None:
    result = runner.run(argv)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:MAX_COMMAND_DETAIL]
        raise SetupError(f"{action} failed with exit {result.returncode}: {detail}")


def _reload_services(
    specs: Sequence[LaunchAgentSpec],
    original: dict[str, ServiceState],
    required_labels: set[str],
    runner: CommandRunner,
    touched: set[str],
) -> None:
    for spec in specs:
        state = original[spec.label]
        must_reload = spec.label in required_labels
        if state.loaded and not must_reload:
            continue
        if state.loaded:
            touched.add(spec.label)
            _launchctl_command(
                runner,
                ["launchctl", "bootout", _launchctl_service(spec.label)],
                action=f"launchctl bootout {spec.label}",
            )
        touched.add(spec.label)
        _launchctl_command(
            runner,
            [
                "launchctl",
                "bootstrap",
                f"gui/{os.getuid()}",
                str(spec.destination),
            ],
            action=f"launchctl bootstrap {spec.label}",
        )
        verified = _query_service(spec.label, runner)
        if not verified.loaded:
            raise SetupError(f"launchctl did not load {spec.label}")


def _restore_services(
    specs: Sequence[LaunchAgentSpec],
    original: dict[str, ServiceState],
    touched: set[str],
    runner: CommandRunner,
) -> list[str]:
    errors: list[str] = []
    blocked_labels: set[str] = set()
    for spec in specs:
        if spec.label not in touched or not original[spec.label].loaded:
            continue
        try:
            installed = _read_owned_regular_file(
                spec.destination,
                max_bytes=MAX_CONFIG_BYTES,
                label=f"rollback {spec.key} LaunchAgent",
            )
            if installed != original[spec.label].plist_snapshot:
                raise SetupError(f"rollback refused to bootstrap an unverified plist: {spec.label}")
        except SetupError as error:
            errors.append(str(error))
            blocked_labels.add(spec.label)
    for spec in specs:
        if spec.label not in touched or spec.label in blocked_labels:
            continue
        try:
            current = _query_service(spec.label, runner)
            if current.loaded:
                _launchctl_command(
                    runner,
                    ["launchctl", "bootout", _launchctl_service(spec.label)],
                    action=f"rollback bootout {spec.label}",
                )
            if original[spec.label].loaded:
                _launchctl_command(
                    runner,
                    [
                        "launchctl",
                        "bootstrap",
                        f"gui/{os.getuid()}",
                        str(spec.destination),
                    ],
                    action=f"rollback bootstrap {spec.label}",
                )
                if not _query_service(spec.label, runner).loaded:
                    raise SetupError(f"rollback service verification failed: {spec.label}")
        except SetupError as error:
            errors.append(str(error))
    return errors


def _overall_status(checks: Sequence[Check]) -> str:
    if any(check.status == "blocked" for check in checks):
        return "blocked"
    if any(check.status == "needs-apply" for check in checks):
        return "changes-required"
    return "ready"


def make_report(command: str, checks: Sequence[Check], **extra: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "version": 1,
        "command": command,
        "status": _overall_status(checks),
        "checks": [check.as_dict() for check in checks],
    }
    report.update(extra)
    return report


def _locator_occupancy_check(config: HostConfig) -> Check:
    """Check only whether an existing locator is safe to retain before ensure."""

    parent = _preflight_creation_path(
        config.workspace_root,
        config.locator_relative_path.parent.parts,
        label="skill locator parent",
    )
    if parent.status != "ready":
        return Check("skill-locator-occupancy", parent.status, parent.detail)
    parent_fd, _ = _open_real_directory(
        config.skill_locator.parent,
        label="skill locator parent",
        require_current_owner=True,
    )
    try:
        try:
            metadata = os.stat(config.skill_locator.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return Check(
                "skill-locator-occupancy",
                "needs-apply",
                f"missing symlink: {config.skill_locator}",
            )
        if not stat.S_ISLNK(metadata.st_mode):
            raise SetupError(f"foreign non-symlink occupies {config.skill_locator}")
        if metadata.st_uid != os.getuid():
            raise SetupError(f"locator is not owned by uid {os.getuid()}")
        target = os.readlink(config.skill_locator.name, dir_fd=parent_fd)
        if target != desired_locator_target(config):
            raise SetupError(f"foreign locator target: {target!r}")
    except SetupError as error:
        return Check("skill-locator-occupancy", "blocked", str(error))
    finally:
        os.close(parent_fd)
    return Check("skill-locator-occupancy", "ready", str(config.skill_locator))


def _initial_preflight_checks(
    config: HostConfig,
    home: Path,
    runner: CommandRunner,
) -> list[Check]:
    """Checks that must pass before an explicitly authorized ensure can run."""

    cache_parts = config.cache_root.relative_to(config.workspace_root).parts
    checks: list[Check] = [
        _check_python(config, runner),
        _check_workspace_helper(config),
        _preflight_creation_path(
            config.workspace_root,
            config.locator_relative_path.parent.parts,
            label="skill locator parent",
        ),
        _preflight_creation_path(
            home,
            ("Library", "LaunchAgents"),
            label="user LaunchAgents",
        ),
        _preflight_creation_path(
            config.workspace_root,
            (*cache_parts, "repos", config.control_repo.name),
            label="control mirror",
        ),
        _preflight_creation_path(
            config.workspace_root,
            (*cache_parts, "freshness"),
            label="host freshness state",
        ),
        _preflight_creation_path(
            config.workspace_root,
            (*cache_parts, "logs"),
            label="host logs",
        ),
        _preflight_creation_path(
            config.workspace_root,
            (*cache_parts, "state"),
            label="host state",
        ),
        _locator_occupancy_check(config),
    ]
    control_manifest = WorkspaceManifest(
        path=config.path,
        cache_root=config.cache_root,
        repos=(config.control_repo,),
        snapshot=config.manifest_snapshot,
    )
    try:
        main_manifest = _load_main_manifest(config)
    except SetupError as error:
        checks.append(Check("main-workspace-manifest", "blocked", str(error)))
        main_manifest = None
    else:
        checks.append(
            Check(
                "main-workspace-manifest",
                "ready",
                f"manifest={main_manifest.digest}; repos="
                + ",".join(repo.name for repo in main_manifest.repos),
            )
        )
    manifests = (control_manifest,) if main_manifest is None else (control_manifest, main_manifest)
    path_checks = _git_admin_path_checks(config.workspace_root, prefix="workspace")
    path_checks.extend(_ensure_path_checks(config, manifests))
    checks.extend(path_checks)
    paths_ready = main_manifest is not None and not any(
        check.status == "blocked" for check in path_checks
    )
    if paths_ready:
        checks.append(_check_exclude(config))
        for manifest in manifests:
            for repo in manifest.repos:
                checks.append(_ensure_mirror_precheck(manifest, repo))
    else:
        checks.append(
            Check(
                "git-exclude",
                "blocked",
                "Git checks skipped because filesystem path preflight is blocked",
            )
        )
        for manifest in manifests:
            for repo in manifest.repos:
                checks.append(
                    Check(
                        f"ensure-mirror-{repo.name}",
                        "blocked",
                        "ensure semantic precheck skipped because filesystem path preflight "
                        "is blocked",
                    )
                )
    for spec in _launch_agent_specs(config, home):
        checks.append(_source_plist(spec)[1])
        checks.append(_check_launch_agent_file(spec))
    return checks


def _apply_preflight_checks(
    config: HostConfig,
    home: Path,
    runner: CommandRunner,
) -> list[Check]:
    checks = collect_core_checks(
        config,
        home,
        runner,
        no_launchctl=True,
        include_mirrors=True,
    )
    checks.extend(
        [
            _preflight_creation_path(
                config.workspace_root,
                config.locator_relative_path.parent.parts,
                label="skill locator parent",
            ),
            _preflight_creation_path(
                home,
                ("Library", "LaunchAgents"),
                label="user LaunchAgents",
            ),
            _preflight_creation_path(config.cache_root, ("logs",), label="host logs"),
            _preflight_creation_path(config.cache_root, ("state",), label="host state"),
        ]
    )
    return checks


def _raise_if_blocked(checks: Sequence[Check], *, phase: str) -> None:
    blocked = [check for check in checks if check.status == "blocked"]
    if blocked:
        detail = "; ".join(f"{check.name}: {check.detail}" for check in blocked)
        raise SetupError(f"{phase} blocked: {detail}")


def _active_config(config: HostConfig) -> HostConfig:
    """Return the steady-state config from the control mirror when available."""

    return _load_control_mirror_config(config)


def plan_setup(
    config: HostConfig,
    home: Path,
    runner: CommandRunner,
    *,
    no_launchctl: bool,
) -> dict[str, Any]:
    try:
        active = _active_config(config)
    except SetupError:
        active = config
    checks = collect_core_checks(
        active,
        home,
        runner,
        no_launchctl=no_launchctl,
        include_mirrors=True,
    )
    actions = [check.name for check in checks if check.status in {"needs-apply", "blocked"}]
    return make_report("plan", checks, actions=actions)


def status_setup(
    config: HostConfig,
    home: Path,
    runner: CommandRunner,
    *,
    no_launchctl: bool,
) -> dict[str, Any]:
    try:
        active = _active_config(config)
    except SetupError:
        active = config
    return make_report(
        "status",
        collect_core_checks(
            active,
            home,
            runner,
            no_launchctl=no_launchctl,
            include_mirrors=True,
        ),
    )


def doctor_setup(
    config: HostConfig,
    home: Path,
    runner: CommandRunner,
    *,
    no_launchctl: bool,
    max_age_minutes: int,
    historical: bool = False,
    weekly: bool = False,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    if max_age_minutes < 1:
        raise SetupError("--max-age-minutes must be a positive integer")
    if historical and weekly:
        raise SetupError("--historical and --weekly cannot be combined")
    current = now or dt.datetime.now(dt.UTC)
    try:
        active = _active_config(config)
    except SetupError:
        active = config
    checks = collect_core_checks(
        active,
        home,
        runner,
        no_launchctl=no_launchctl,
        include_mirrors=True,
    )
    control_checks, control_evidence = validate_freshness_stamp(
        active,
        stamp_name=active.control_stamp,
        manifest_path=active.control_mirror_manifest,
        max_age_minutes=max_age_minutes,
        now=current,
        historical=historical,
        runner=runner,
    )
    main_checks, main_evidence = validate_freshness_stamp(
        active,
        stamp_name=active.main_stamp,
        manifest_path=active.main_manifest,
        max_age_minutes=max_age_minutes,
        now=current,
        historical=historical,
        runner=runner,
    )
    checks.extend(control_checks)
    checks.extend(main_checks)
    if control_evidence is None or main_evidence is None:
        checks.append(
            Check(
                "freshness-final-rebind",
                "blocked",
                "both stamp evidence sets are required for final revalidation",
            )
        )
    else:
        try:
            _revalidate_pair_evidence(active, control_evidence, main_evidence, runner)
        except SetupError as error:
            checks.append(Check("freshness-final-rebind", "blocked", str(error)))
        else:
            checks.append(
                Check(
                    "freshness-final-rebind",
                    "ready",
                    "both stamps, manifests, and mirror snapshots remained exact",
                )
            )
    if weekly:
        checks.append(
            _validate_stable_weekly_pair(
                active,
                control_evidence,
                main_evidence,
                max_age_minutes=max_age_minutes,
                now=current,
                runner=runner,
            )
        )
    decision_now = now or dt.datetime.now(dt.UTC)
    if not historical:
        for stamp_name, evidence in (
            (active.control_stamp, control_evidence),
            (active.main_stamp, main_evidence),
        ):
            if evidence is not None:
                _replace_check(
                    checks,
                    _decision_age_check(
                        stamp_name,
                        evidence,
                        max_age_minutes=max_age_minutes,
                        now=decision_now,
                    ),
                )
    if weekly and control_evidence is not None and main_evidence is not None:
        pair_check = next(check for check in checks if check.name == "weekly-pair-receipt")
        if pair_check.status == "ready":
            _replace_check(
                checks,
                _validate_weekly_receipt(
                    active,
                    control_evidence,
                    main_evidence,
                    max_age_minutes=max_age_minutes,
                    now=decision_now,
                ),
            )
    return make_report(
        "doctor",
        checks,
        freshness_mode="historical-age-only" if historical else "live",
        weekly=weekly,
        max_age_minutes=max_age_minutes,
    )


def _service_preflight(
    plans: Sequence[PlannedLaunchAgent],
    runner: CommandRunner,
) -> dict[str, ServiceState]:
    specs = tuple(plan.spec for plan in plans)
    original = {spec.label: _query_service(spec.label, runner) for spec in specs}
    for plan in plans:
        spec = plan.spec
        if not original[spec.label].loaded:
            continue
        if plan.installed is None:
            raise SetupError(
                f"cannot safely restore loaded service without its plist: {spec.label}"
            )
        installed = _read_owned_regular_file(
            spec.destination,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"installed {spec.key} LaunchAgent",
        )
        if installed != plan.installed:
            raise SetupError(
                f"cannot safely restore loaded service after plist drift: {spec.label}"
            )
        original[spec.label] = dataclasses.replace(
            original[spec.label], plist_snapshot=plan.installed
        )
    return original


def apply_setup(
    config: HostConfig,
    home: Path,
    runner: CommandRunner,
    *,
    ensure: bool,
    no_launchctl: bool,
    file_ops: FileOps | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    operations = file_ops or FileOps()
    initial_checks = _initial_preflight_checks(config, home, runner)
    _raise_if_blocked(initial_checks, phase="initial preflight")
    if ensure:
        _run_ensure(config, runner)
    try:
        active = _active_config(config)
    except SetupError as error:
        if not ensure:
            raise SetupError(
                f"control mirror is not ready; rerun with explicitly authorized --ensure: {error}"
            ) from error
        raise

    pair_report: dict[str, Any] | None = None
    if ensure:
        freshness_journal = _begin_freshness_directory(active, operations)
        try:
            pair_report, active = prefetch_weekly(
                active,
                runner,
                file_ops=operations,
                now=now,
            )
            if pair_report["status"] != "ready":
                raise SetupError("initial control/main prefetch pair did not become ready")
        except BaseException as original_error:
            rollback_errors = freshness_journal.rollback()
            if rollback_errors:
                raise SetupError(
                    f"initial prefetch failed ({original_error}); freshness directory rollback "
                    "incomplete: " + "; ".join(rollback_errors)
                ) from original_error
            raise

    preflight_checks = _apply_preflight_checks(active, home, runner)
    _raise_if_blocked(preflight_checks, phase="mutation preflight")
    specs = _launch_agent_specs(active, home)
    plans = tuple(_plan_launch_agent(spec) for spec in specs)
    receipt_snapshot, original_pending_labels = _load_reload_receipt(active)
    pending_labels = dict(original_pending_labels)
    for plan in plans:
        if plan.changed or plan.spec.label in pending_labels:
            pending_labels[plan.spec.label] = plan.source.digest
    original_services: dict[str, ServiceState] = {}
    if not no_launchctl:
        original_services = _service_preflight(plans, runner)

    journal = MutationJournal(operations.renamer)
    touched_services: set[str] = set()
    changes: list[str] = []
    commit_started = False
    try:
        _ensure_directory_children(
            active.workspace_root,
            active.locator_relative_path.parent.parts,
            journal,
            label="skill locator parent",
        )
        _ensure_directory_children(
            home,
            ("Library", "LaunchAgents"),
            journal,
            label="user LaunchAgents",
        )
        _ensure_directory_children(active.cache_root, ("logs",), journal, label="host logs")
        _ensure_directory_children(active.cache_root, ("state",), journal, label="host state")
        if _install_exclude(active, operations, journal):
            changes.append("git-exclude")
        if _install_locator(active, journal):
            changes.append("skill-locator")

        if pending_labels != original_pending_labels:
            receipt_snapshot = _write_reload_receipt(
                active,
                pending_labels,
                operations,
                journal,
                expected=receipt_snapshot,
            )
        expected_destinations: dict[str, FileSnapshot] = {}
        for plan in plans:
            expected_destinations[plan.spec.label] = _install_plist(plan, operations, journal)
            if plan.changed:
                changes.append(f"launch-agent-{plan.spec.key}")

        _revalidate_launch_agent_plans(plans, expected_destinations)

        if not no_launchctl:
            required_labels = set(pending_labels)
            _reload_services(
                specs,
                original_services,
                required_labels,
                runner,
                touched_services,
            )
            _revalidate_launch_agent_plans(plans, expected_destinations)
            if required_labels:
                receipt_snapshot = _write_reload_receipt(
                    active,
                    {},
                    operations,
                    journal,
                    expected=receipt_snapshot,
                )
                changes.append("launchctl-reload")

        if ensure:
            final_report = doctor_setup(
                active,
                home,
                runner,
                no_launchctl=no_launchctl,
                max_age_minutes=active.default_max_age_minutes,
                now=now,
            )
        else:
            final_report = status_setup(
                active,
                home,
                runner,
                no_launchctl=no_launchctl,
            )
        if final_report["status"] == "blocked":
            raise SetupError("post-apply validation is blocked")
        if not no_launchctl and final_report["status"] != "ready":
            raise SetupError("post-apply validation did not become ready")
        _revalidate_launch_agent_plans(plans, expected_destinations)
        active_manifest = _read_owned_regular_file(
            active.path,
            max_bytes=MAX_CONFIG_BYTES,
            label="active host manifest",
        )
        if active_manifest != active.manifest_snapshot:
            raise SetupError("active host manifest changed before apply commit")
        commit_started = True
        journal.commit()
    except BaseException as original_error:
        if commit_started:
            raise SetupError(
                "apply reached validated installed state but transaction backup cleanup "
                f"did not complete: {original_error}"
            ) from original_error
        rollback_errors = journal.rollback()
        if not no_launchctl and original_services:
            rollback_errors.extend(
                _restore_services(specs, original_services, touched_services, runner)
            )
        if rollback_errors:
            raise SetupError(
                f"apply failed ({original_error}); rollback incomplete: "
                + "; ".join(rollback_errors)
            ) from original_error
        raise

    final_report["command"] = "apply"
    final_report["changes"] = changes
    final_report["ensured"] = ensure
    if pair_report is not None:
        final_report["initial_prefetch"] = pair_report
    return final_report


def _add_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--home",
        type=Path,
        default=Path.home(),
        help="Home directory containing Library/LaunchAgents (default: current home)",
    )
    parser.add_argument(
        "--no-launchctl",
        action="store_true",
        help="Skip GUI launchctl queries; plist and reload-receipt checks still run",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bootstrap and validate Daily Skill Friction host control state."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).absolute().parent.parent / "config" / "host-workspace.toml",
        help="Host repository-management manifest",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "status"):
        command = commands.add_parser(name)
        _add_runtime_arguments(command)
    apply = commands.add_parser("apply")
    _add_runtime_arguments(apply)
    apply.add_argument(
        "--ensure",
        action="store_true",
        help="Explicitly authorize the workspace helper's initial ensure/clone path",
    )
    doctor = commands.add_parser("doctor")
    _add_runtime_arguments(doctor)
    doctor.add_argument(
        "--max-age-minutes",
        type=int,
        default=None,
        help="Maximum stamp and entry age (default: manifest value)",
    )
    doctor.add_argument(
        "--historical",
        action="store_true",
        help="Skip only stamp age; all identity, Git, and snapshot checks still run",
    )
    doctor.add_argument(
        "--weekly",
        action="store_true",
        help="Also require a fresh pair receipt matching both current stamps",
    )
    commands.add_parser(
        "prefetch-control",
        help="Refresh the control stamp without ensure/clone through a private staging name",
    )
    commands.add_parser(
        "prefetch-weekly",
        help="Refresh control then main stamps without ensure/clone and write a pair receipt",
    )
    return parser


def _error_report(command: str, error: BaseException) -> dict[str, Any]:
    return {
        "version": 1,
        "command": command,
        "status": "blocked",
        "error": str(error),
        "checks": [],
    }


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    command = str(arguments.command)
    runner = CommandRunner()
    try:
        config = load_config(arguments.config)
        if command == "plan":
            report = plan_setup(
                config,
                arguments.home.absolute(),
                runner,
                no_launchctl=arguments.no_launchctl,
            )
        elif command == "status":
            report = status_setup(
                config,
                arguments.home.absolute(),
                runner,
                no_launchctl=arguments.no_launchctl,
            )
        elif command == "apply":
            report = apply_setup(
                config,
                arguments.home.absolute(),
                runner,
                ensure=arguments.ensure,
                no_launchctl=arguments.no_launchctl,
            )
        elif command == "doctor":
            max_age = (
                config.default_max_age_minutes
                if arguments.max_age_minutes is None
                else arguments.max_age_minutes
            )
            report = doctor_setup(
                config,
                arguments.home.absolute(),
                runner,
                no_launchctl=arguments.no_launchctl,
                max_age_minutes=max_age,
                historical=arguments.historical,
                weekly=arguments.weekly,
            )
        elif command == "prefetch-control":
            report, _refreshed = prefetch_control(config, runner)
        elif command == "prefetch-weekly":
            report, _refreshed = prefetch_weekly(config, runner)
        else:  # pragma: no cover - argparse owns the command set
            raise AssertionError(command)
    except (OSError, SetupError, ValueError) as error:
        report = _error_report(command, error)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("status") == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
