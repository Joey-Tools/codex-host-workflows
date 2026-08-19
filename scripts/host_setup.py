#!/usr/bin/env python3
"""Bootstrap and verify the host-local Daily Skill Friction control plane.

Filesystem guards protect object identity (device/inode), exact bounded content,
and access policy (type, owner, group, and mode). Timestamp-only changes are not
treated as mutation. Managed replacement uses a same-directory kernel exchange
or no-replace rename, retains the previous object until commit, and fsyncs both
the file and parent directory.

Subprocess guards protect executable-selection integrity: host commands use
audited absolute executables, delegated helpers receive a system-only PATH, and
every child starts from a closed environment allowlist. This does not attest the
publisher identity of the fixed executables or the behavior of remote services.

The already-running isolated Python interpreter and the OS loader that created it
are an explicit startup trust root. This process can prove its current version,
isolation flags, and the identity/content/access policy of its nominal executable
path, but it cannot retrospectively prove which vnode the loader consumed before
Python started. Delegated helper code is therefore never reopened by pathname:
one stable owned-file snapshot is compiled and executed from its exact in-memory
bytes in a forked child of this interpreter. The fixed system shell, `/usr/bin/env`,
and the OS loader stages that start a LaunchAgent environment trampoline are the
same kind of pre-execution trust root; the closed environment applies only after
`env -i` has taken effect for the Python child.
"""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import datetime as dt
import errno
import functools
import hashlib
import json
import locale
import os
import plistlib
import pwd
import re
import secrets
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import threading
import time
import tomllib
import traceback
import types
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, BinaryIO, Protocol, cast


class SetupError(RuntimeError):
    """Raised when bootstrap state cannot be proved safe and complete."""


MANAGED_PLIST_MARKER = b"Managed by Joey-Tools/codex-host-workflows:scripts/host_setup.py"
EXCLUDE_BEGIN = "# >>> codex-host-workflows daily-skill-friction >>>"
EXCLUDE_ENTRY = "/.agents/skills/daily-skill-friction"
EXCLUDE_END = "# <<< codex-host-workflows daily-skill-friction <<<"
STAMP_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
REPO_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
RETIRED_REPO_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
LAUNCH_AGENT_LABEL_PATTERN = re.compile(
    r"(?=.{3,128}\Z)(?:[A-Za-z0-9][A-Za-z0-9-]*\.){2,}"
    r"[A-Za-z0-9][A-Za-z0-9-]*\Z"
)
GIT_CONFIG_SECTION_PATTERN = re.compile(
    r"^\[\s*([A-Za-z0-9][A-Za-z0-9.-]*)"
    r'(?:\s+"((?:[^"\\]|\\["\\])*)")?\s*\](?:\s*[#;].*)?$'
)
GIT_CONFIG_VARIABLE_PATTERN = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)(?:\s*=\s*(.*))?$")
MANAGED_MIRROR_GUARD_HOOKS = (
    "pre-commit",
    "prepare-commit-msg",
    "pre-merge-commit",
    "applypatch-msg",
    "pre-applypatch",
)
MAX_CONFIG_BYTES = 1024 * 1024
MAX_STAMP_BYTES = 1024 * 1024
MAX_COMMAND_DETAIL = 2000
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
COMMAND_OUTPUT_READ_BYTES = 64 * 1024
GIT_TIMEOUT_SECONDS = 20
COMMAND_TIMEOUT_SECONDS = 120
COMMAND_TERM_GRACE_SECONDS = 2
COMMAND_KILL_GRACE_SECONDS = 2
LAUNCH_AGENT_MODE = 0o644
ACL_TYPE_EXTENDED = 0x00000100
ACL_FIRST_ENTRY = 0
ACL_NEXT_ENTRY = -1
ACL_EXTENDED_ALLOW = 1
ACL_EXTENDED_DENY = 2
ACL_FLAG_SCAN_BITS = 32
GIT_EXECUTABLE = "/usr/bin/git"
LAUNCHCTL_EXECUTABLE = "/bin/launchctl"
SSH_EXECUTABLE = "/usr/bin/ssh"
ENV_EXECUTABLE = "/usr/bin/env"
SHELL_EXECUTABLE = "/bin/sh"
SHELL_PRIVILEGED_FLAG = "-p"
TRUSTED_SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
TRUSTED_LOCALE = "en_US.UTF-8"
TRUSTED_TMPDIR = "/tmp"
PYTHON_ISOLATION_FLAGS = ("-I", "-B", "-S")
LAUNCH_ENV_ARG0 = "daily-skill-friction-clean-env"
LAUNCH_ENV_COMMAND = (
    "account_home=$1; shift; "
    'if [ -n "${SSH_AUTH_SOCK-}" ]; then '
    f'exec {ENV_EXECUTABLE} -i PATH={TRUSTED_SYSTEM_PATH} "HOME=$account_home" '
    f"LANG={TRUSTED_LOCALE} TMPDIR={TRUSTED_TMPDIR} "
    '"SSH_AUTH_SOCK=$SSH_AUTH_SOCK" "$@"; '
    "fi; "
    f'exec {ENV_EXECUTABLE} -i PATH={TRUSTED_SYSTEM_PATH} "HOME=$account_home" '
    f'LANG={TRUSTED_LOCALE} TMPDIR={TRUSTED_TMPDIR} "$@"'
)
PRESERVED_PROCESS_ENVIRONMENT = (
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "SSH_AUTH_SOCK",
    "TEMP",
    "TMP",
)


def _bounded_command_output_diagnostic(stdout: bytearray, stderr: bytearray) -> str:
    """Decode one useful output stream without retaining another large copy."""

    stream_name, source = ("stderr", stderr) if stderr else ("stdout", stdout)
    if not source:
        return ""
    raw = bytes(source[:MAX_COMMAND_DETAIL])
    decoded = raw.decode(locale.getpreferredencoding(False), errors="replace")
    return f"{stream_name}={decoded.strip()[:MAX_COMMAND_DETAIL]}"


class CommandOutputLimitError(SetupError):
    """Raised after bounded output capture terminates and reaps the command group."""

    def __init__(
        self,
        executable: str,
        output_limit_bytes: int,
        stdout: bytearray,
        stderr: bytearray,
    ) -> None:
        self.output_limit_bytes = output_limit_bytes
        self.captured_stdout_bytes = len(stdout)
        self.captured_stderr_bytes = len(stderr)
        self.captured_total_bytes = len(stdout) + len(stderr)
        self.diagnostic = _bounded_command_output_diagnostic(stdout, stderr)
        message = (
            f"command output limit exceeded: {executable}; "
            f"limit={output_limit_bytes}; captured={self.captured_total_bytes}"
        )
        if self.diagnostic:
            message = f"{message}; {self.diagnostic}"
        super().__init__(message)


class _CommandOutputExceeded(Exception):
    """Carry the already bounded raw capture into process-group cleanup."""

    def __init__(self, stdout: bytearray, stderr: bytearray) -> None:
        self.stdout = stdout
        self.stderr = stderr


def _trusted_account_home() -> str:
    """Resolve HOME from the kernel account identity, not ambient input."""

    try:
        raw = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError as error:
        raise SetupError(f"uid {os.getuid()} has no account home") from error
    home = Path(raw)
    if not home.is_absolute() or home != Path(os.path.normpath(str(home))):
        raise SetupError("account home must be a normalized absolute path")
    return str(home)


def _trusted_process_environment() -> dict[str, str]:
    """Build the minimal inherited environment for every child process."""

    environment = {
        "PATH": TRUSTED_SYSTEM_PATH,
        "HOME": _trusted_account_home(),
        "LANG": os.environ.get("LANG", TRUSTED_LOCALE),
        "TMPDIR": os.environ.get("TMPDIR", TRUSTED_TMPDIR),
    }
    for key in PRESERVED_PROCESS_ENVIRONMENT:
        value = os.environ.get(key)
        if value is not None:
            environment[key] = value
    return environment


@dataclasses.dataclass(frozen=True)
class Binding:
    dev: int
    ino: int
    uid: int
    gid: int
    mode: int
    size: int
    acl_digest: str | None = None

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
class AclEntry:
    """One Darwin extended ACL entry in stable kernel order."""

    tag: int
    qualifier: bytes
    permissions: int
    flags: int


@dataclasses.dataclass(frozen=True)
class FileSnapshot:
    binding: Binding
    data: bytes

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclasses.dataclass(frozen=True)
class CurrentInterpreterBinding:
    """Evidence available after the current interpreter has already started.

    ``nominal_snapshot`` binds the current object at the manifest pathname. The
    running image itself is an explicit trust root: neither ``sys.executable``
    nor a post-start pathname snapshot proves which vnode the OS loader opened.
    """

    executable: Path
    version: tuple[int, int, int]
    nominal_snapshot: FileSnapshot


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
    retired_repo_names: tuple[str, ...]
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
class GitTopologyGuard:
    """Bind the administrative and object-source boundaries used by Git."""

    repository: Path
    repository_binding: Binding | None
    git_dir_binding: Binding | None
    objects_binding: Binding | None
    objects_info_binding: Binding | None
    refs_binding: Binding | None
    info_binding: Binding | None
    hooks_binding: Binding | None
    managed_hook_snapshots: tuple[tuple[str, FileSnapshot], ...] | None
    local_config_snapshot: FileSnapshot | None
    worktree_config_absent: bool | None
    alternate_object_sources_absent: bool | None


@dataclasses.dataclass(frozen=True)
class HostConfig:
    path: Path
    manifest_snapshot: FileSnapshot
    repo_root: Path
    workspace_root: Path
    account_home: Path
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
    definition: LoadedLaunchAgent | None = None


@dataclasses.dataclass(frozen=True)
class LoadedLaunchAgent:
    source_path: str
    program: str
    program_arguments: tuple[str, ...]
    working_directory: str
    standard_out_path: str
    standard_error_path: str
    environment_variables: dict[str, str]
    calendar_intervals: tuple[tuple[tuple[str, int], ...], ...]
    minimum_runtime: int
    base_minimum_runtime: int | None
    exit_timeout: int
    spawn_type: str
    properties: frozenset[str]


class _SupervisedProcess(Protocol):
    pid: int
    args: Any
    stdout: Any
    stderr: Any
    returncode: int | None

    def wait(self, timeout: float | None = None) -> int: ...


class _ForkedPythonProcess:
    """Minimal waitable process wrapper for one Python ``fork`` child."""

    def __init__(
        self,
        pid: int,
        args: Sequence[str],
        stdout_descriptor: int,
        stderr_descriptor: int,
    ) -> None:
        self.pid = pid
        self.args = tuple(args)
        self.stdout: BinaryIO | None = os.fdopen(stdout_descriptor, "rb", buffering=0)
        self.stderr: BinaryIO | None = os.fdopen(stderr_descriptor, "rb", buffering=0)
        self.returncode: int | None = None

    def _collect(self, *, nohang: bool) -> int | None:
        if self.returncode is not None:
            return self.returncode
        options = os.WNOHANG if nohang else 0
        try:
            waited_pid, status = os.waitpid(self.pid, options)
        except ChildProcessError as error:
            raise OSError(errno.ECHILD, "forked Python child was reaped externally") from error
        if waited_pid == 0:
            return None
        if waited_pid != self.pid:
            raise OSError(errno.ECHILD, "waitpid returned an unexpected child")
        self.returncode = os.waitstatus_to_exitcode(status)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if timeout is None:
            result = self._collect(nohang=False)
            assert result is not None
            return result
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            result = self._collect(nohang=True)
            if result is not None:
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(self.args, timeout)
            time.sleep(min(0.01, remaining))


class CommandRunner:
    """Injectable, byte-bounded subprocess boundary for delegated operations.

    The protected property is that retained stdout and stderr payload bytes share
    one deterministic ``output_limit_bytes`` ceiling. A timeout or the first byte
    beyond that ceiling enters the same TERM/KILL process-group cleanup path, and
    the direct child is reaped before control returns to the caller.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = COMMAND_TIMEOUT_SECONDS,
        term_grace_seconds: float = COMMAND_TERM_GRACE_SECONDS,
        kill_grace_seconds: float = COMMAND_KILL_GRACE_SECONDS,
        output_limit_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
    ) -> None:
        if not 1 <= output_limit_bytes <= MAX_COMMAND_OUTPUT_BYTES:
            raise ValueError(
                f"command output limit must be between 1 and {MAX_COMMAND_OUTPUT_BYTES} bytes"
            )
        self.timeout_seconds = timeout_seconds
        self.term_grace_seconds = term_grace_seconds
        self.kill_grace_seconds = kill_grace_seconds
        self.output_limit_bytes = output_limit_bytes
        self._interpreter_baseline: CurrentInterpreterBinding | None = None
        self._workspace_helper_baselines: dict[Path, FileSnapshot] = {}

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                env=(dict(env) if env is not None else _trusted_process_environment()),
                start_new_session=True,
            )
        except OSError as error:
            raise SetupError(
                f"could not start {argv[0]}: {error.strerror or type(error).__name__}"
            ) from error
        return self._supervise(process, argv)

    def bind_current_interpreter(self, config: HostConfig) -> CurrentInterpreterBinding:
        """Enforce the production interpreter trust-root policy.

        Test runners may override this method as an injection seam. The CLI and
        every ordinary ``CommandRunner`` instance always use the strict policy.
        """

        return self._remember_current_interpreter(_bind_current_interpreter(config))

    def _remember_current_interpreter(
        self,
        candidate: CurrentInterpreterBinding,
    ) -> CurrentInterpreterBinding:
        baseline = self._interpreter_baseline
        if baseline is None:
            self._interpreter_baseline = candidate
            return candidate
        if candidate != baseline:
            raise SetupError("Python executable changed from this operation's trusted baseline")
        return baseline

    def bind_workspace_helper(self, config: HostConfig) -> FileSnapshot:
        """Bind one exact helper object/content/access policy per operation."""

        candidate = _read_owned_regular_file(
            config.workspace_helper,
            max_bytes=MAX_CONFIG_BYTES,
            label="workspace helper",
        )
        baseline = self._workspace_helper_baselines.get(config.workspace_helper)
        if baseline is None:
            self._workspace_helper_baselines[config.workspace_helper] = candidate
            return candidate
        if candidate != baseline:
            raise SetupError("workspace helper changed from this operation's trusted baseline")
        return baseline

    def revalidate_helper_runtime(self, config: HostConfig) -> None:
        """Prove nominal Python/helper paths still match operation baselines."""

        self.bind_current_interpreter(config)
        self.bind_workspace_helper(config)

    def run_python_source(
        self,
        argv: Sequence[str],
        *,
        source: FileSnapshot,
        source_path: Path,
        cwd: Path,
        env: Mapping[str, str],
        workspace_manifest: WorkspaceManifest | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Fork this interpreter and execute exact validated source bytes.

        No manifest-controlled executable or helper pathname is resolved in the
        child. The fork inherits the already-running isolated interpreter, then
        closes every inherited non-stdio descriptor before executing ``source``.
        """

        try:
            process = self._fork_python_source(
                argv,
                source=source,
                source_path=source_path,
                cwd=cwd,
                env=env,
                workspace_manifest=workspace_manifest,
            )
        except OSError as error:
            raise SetupError(
                f"could not fork {source_path}: {error.strerror or type(error).__name__}"
            ) from error
        return self._supervise(process, argv)

    def _supervise(
        self,
        process: _SupervisedProcess,
        argv: Sequence[str],
    ) -> subprocess.CompletedProcess[str]:
        try:
            stdout, stderr = self._capture_output(process)
            assert process.returncode is not None
            return subprocess.CompletedProcess(list(argv), process.returncode, stdout, stderr)
        except _CommandOutputExceeded as error:
            self._terminate_process_group(process)
            limit_error = CommandOutputLimitError(
                str(argv[0]),
                self.output_limit_bytes,
                error.stdout,
                error.stderr,
            )
            error.stdout.clear()
            error.stderr.clear()
            raise limit_error from None
        except subprocess.TimeoutExpired as error:
            self._terminate_process_group(process)
            raise SetupError(f"command timed out: {argv[0]}") from error
        except OSError as error:
            self._terminate_process_group(process)
            raise SetupError(
                f"command output capture failed: {argv[0]}: "
                f"{error.strerror or type(error).__name__}"
            ) from error

    @staticmethod
    def _maximum_child_descriptor() -> int:
        try:
            maximum = os.sysconf("SC_OPEN_MAX")
        except (OSError, ValueError) as error:
            raise SetupError("could not determine the child descriptor ceiling") from error
        if not isinstance(maximum, int) or maximum < 4:
            raise SetupError("child descriptor ceiling is invalid")
        return maximum

    @staticmethod
    def _require_fork_safe_thread_state() -> None:
        if (
            threading.current_thread() is not threading.main_thread()
            or threading.active_count() != 1
        ):
            raise SetupError("delegated helper fork requires one active main Python thread")

    def _fork_python_source(
        self,
        argv: Sequence[str],
        *,
        source: FileSnapshot,
        source_path: Path,
        cwd: Path,
        env: Mapping[str, str],
        workspace_manifest: WorkspaceManifest | None,
    ) -> _ForkedPythonProcess:
        if len(argv) < 5 or tuple(argv[1:4]) != PYTHON_ISOLATION_FLAGS:
            raise SetupError("delegated helper argv lost the required Python isolation flags")
        if Path(argv[4]) != source_path:
            raise SetupError("delegated helper argv does not match its validated source path")
        self._require_fork_safe_thread_state()
        maximum_descriptor = self._maximum_child_descriptor()
        environment = dict(env)
        child_argv = [str(source_path), *argv[5:]]
        stdout_read, stdout_write = self._noninheritable_pipe()
        try:
            stderr_read, stderr_write = self._noninheritable_pipe()
        except BaseException:
            os.close(stdout_read)
            os.close(stdout_write)
            raise
        try:
            pid = os.fork()
        except BaseException:
            for descriptor in (stdout_read, stdout_write, stderr_read, stderr_write):
                os.close(descriptor)
            raise
        if pid == 0:
            self._execute_python_source_child(
                argv,
                child_argv=child_argv,
                source=source,
                source_path=source_path,
                cwd=cwd,
                environment=environment,
                workspace_manifest=workspace_manifest,
                stdout_read=stdout_read,
                stdout_write=stdout_write,
                stderr_read=stderr_read,
                stderr_write=stderr_write,
                maximum_descriptor=maximum_descriptor,
            )
            os._exit(127)
        os.close(stdout_write)
        os.close(stderr_write)
        try:
            return _ForkedPythonProcess(pid, argv, stdout_read, stderr_read)
        except BaseException:
            os.close(stdout_read)
            os.close(stderr_read)
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            raise

    @staticmethod
    def _noninheritable_pipe() -> tuple[int, int]:
        descriptors = os.pipe()
        if any(os.get_inheritable(descriptor) for descriptor in descriptors):
            for descriptor in descriptors:
                os.close(descriptor)
            raise SetupError("Python pipe descriptors must be close-on-exec")
        return descriptors

    @staticmethod
    def _execute_python_source_child(
        display_argv: Sequence[str],
        *,
        child_argv: list[str],
        source: FileSnapshot,
        source_path: Path,
        cwd: Path,
        environment: dict[str, str],
        workspace_manifest: WorkspaceManifest | None,
        stdout_read: int,
        stdout_write: int,
        stderr_read: int,
        stderr_write: int,
        maximum_descriptor: int,
    ) -> None:
        try:
            os.dup2(stdout_write, 1)
            os.dup2(stderr_write, 2)
            os.closerange(3, maximum_descriptor)
            encoding = locale.getpreferredencoding(False)
            sys.stdout = open(1, "w", encoding=encoding, errors="backslashreplace", closefd=False)
            sys.stderr = open(2, "w", encoding=encoding, errors="backslashreplace", closefd=False)
            os.setsid()
            os.chdir(cwd)
            os.environ.clear()
            os.environ.update(environment)
            signal.signal(signal.SIGINT, signal.default_int_handler)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGHUP, signal.SIG_DFL)
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
            sys.argv = child_argv
            sys.orig_argv = list(display_argv)
            module_name = (
                "__main__" if workspace_manifest is None else "_codex_workspace_bound_helper"
            )
            main_module = types.ModuleType(module_name)
            namespace = main_module.__dict__
            namespace.update(
                {
                    "__name__": module_name,
                    "__file__": str(source_path),
                    "__package__": None,
                    "__cached__": None,
                    "__loader__": None,
                    "__spec__": None,
                }
            )
            sys.modules[module_name] = main_module
            code = compile(source.data, str(source_path), "exec", dont_inherit=True)
            exec(code, namespace)
            if workspace_manifest is not None:
                CommandRunner._run_bound_workspace_helper(
                    namespace,
                    child_argv=child_argv,
                    manifest=workspace_manifest,
                )
        except SystemExit as error:
            if error.code is None:
                exit_code = 0
            elif isinstance(error.code, int):
                exit_code = error.code
            else:
                print(error.code, file=sys.stderr)
                exit_code = 1
        except BaseException:
            traceback.print_exc()
            exit_code = 1
        else:
            exit_code = 0
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(exit_code)

    @staticmethod
    def _run_bound_workspace_helper(
        namespace: dict[str, Any],
        *,
        child_argv: Sequence[str],
        manifest: WorkspaceManifest,
    ) -> None:
        """Call the trusted helper with an exact inherited manifest object."""

        main = namespace.get("main")
        original_load_config = namespace.get("load_config")
        repo_type = namespace.get("RepoSpec")
        config_type = namespace.get("WorkspaceConfig")
        workspace_error = namespace.get("WorkspaceError")
        expected_callables = {
            "main": main,
            "load_config": original_load_config,
            "git_common_dir": namespace.get("git_common_dir"),
            "mirror_guard_hook": namespace.get("mirror_guard_hook"),
            "mirror_guard_path": namespace.get("mirror_guard_path"),
            "install_mirror_guard": namespace.get("install_mirror_guard"),
        }
        missing = [name for name, value in expected_callables.items() if not callable(value)]
        if missing:
            raise SetupError(
                "workspace helper API drifted; missing callables: " + ", ".join(missing)
            )
        if not isinstance(repo_type, type) or not dataclasses.is_dataclass(repo_type):
            raise SetupError("workspace helper RepoSpec API drifted")
        if not isinstance(config_type, type) or not dataclasses.is_dataclass(config_type):
            raise SetupError("workspace helper WorkspaceConfig API drifted")
        if not isinstance(workspace_error, type) or not issubclass(workspace_error, Exception):
            raise SetupError("workspace helper WorkspaceError API drifted")
        repo_fields = tuple(field.name for field in dataclasses.fields(repo_type))
        config_fields = tuple(field.name for field in dataclasses.fields(config_type))
        if repo_fields != ("name", "url", "default_branch", "visibility"):
            raise SetupError("workspace helper RepoSpec constructor fields drifted")
        legacy_config_fields = ("root", "cache_root", "repos")
        current_config_fields = (*legacy_config_fields, "retired_repo_names")
        if config_fields == legacy_config_fields:
            if manifest.retired_repo_names:
                raise SetupError(
                    "workspace helper legacy WorkspaceConfig cannot preserve non-empty "
                    "retired_repo_names"
                )
        elif config_fields != current_config_fields:
            raise SetupError("workspace helper WorkspaceConfig constructor fields drifted")

        repo_factory = cast(Any, repo_type)
        config_factory = cast(Any, config_type)
        error_factory = cast(Any, workspace_error)
        main_callable = cast(Callable[[list[str]], int], main)
        git_common_dir_callable = cast(Callable[[Path], Path], expected_callables["git_common_dir"])
        mirror_guard_hook_callable = cast(
            Callable[[Path], str], expected_callables["mirror_guard_hook"]
        )
        repos = tuple(
            repo_factory(
                name=repo.name,
                url=repo.url,
                default_branch=repo.default_branch,
                visibility=repo.visibility,
            )
            for repo in manifest.repos
        )
        config_arguments: dict[str, object] = {
            "root": manifest.root,
            "cache_root": manifest.cache_root,
            "repos": repos,
        }
        if config_fields == current_config_fields:
            config_arguments["retired_repo_names"] = manifest.retired_repo_names
        bound_config = config_factory(**config_arguments)

        def bound_load_config(requested: object) -> object:
            try:
                requested_path = Path(requested)  # type: ignore[arg-type]
            except TypeError as error:
                raise error_factory("bound manifest path has an invalid type") from error
            if requested_path != manifest.path:
                raise error_factory(
                    "bound manifest path does not match the inherited logical origin: "
                    f"{requested_path} != {manifest.path}"
                )
            return bound_config

        guard_hooks = namespace.get("MIRROR_GUARD_HOOKS")
        if (
            not isinstance(guard_hooks, tuple)
            or not guard_hooks
            or not all(isinstance(hook, str) and hook for hook in guard_hooks)
        ):
            raise SetupError("workspace helper MIRROR_GUARD_HOOKS API drifted")

        def bound_mirror_guard_path(mirror: Path, hook_name: str) -> Path:
            if hook_name not in guard_hooks:
                raise error_factory(f"unsupported mirror guard hook: {hook_name}")
            common_dir = git_common_dir_callable(mirror)
            return common_dir / "hooks" / hook_name

        def bound_install_mirror_guard(config: Any, repo: Any) -> None:
            mirror = config.repo_path(repo)
            expected = mirror_guard_hook_callable(mirror)
            common_dir = git_common_dir_callable(mirror)
            for hook_name in guard_hooks:
                hook = bound_mirror_guard_path(mirror, hook_name)
                expected_hook = common_dir / "hooks" / hook_name
                if hook != expected_hook:
                    raise error_factory(
                        f"effective {hook_name} hook path is not the exact managed leaf: {hook}"
                    )
            try:
                _install_managed_mirror_guard_hooks(
                    common_dir,
                    guard_hooks,
                    expected.encode("utf-8"),
                )
            except (OSError, SetupError) as error:
                raise error_factory(
                    f"{repo.name} mirror guard installation blocked: {error}"
                ) from error

        namespace["load_config"] = bound_load_config
        namespace["mirror_guard_path"] = bound_mirror_guard_path
        namespace["install_mirror_guard"] = bound_install_mirror_guard
        result = main_callable(list(child_argv[1:]))
        if not isinstance(result, int) or isinstance(result, bool):
            raise SetupError("workspace helper main returned a non-integer status")
        raise SystemExit(result)

    def _capture_output(self, process: _SupervisedProcess) -> tuple[str, str]:
        """Stream both pipes through one retained-byte budget until exit."""

        stdout = bytearray()
        stderr = bytearray()
        captured_bytes = 0
        deadline = time.monotonic() + self.timeout_seconds
        streams = (
            ("stdout", process.stdout),
            ("stderr", process.stderr),
        )
        selector = selectors.DefaultSelector()
        open_streams: dict[int, Any] = {}
        for stream_name, stream in streams:
            assert stream is not None
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            open_streams[descriptor] = stream
            selector.register(descriptor, selectors.EVENT_READ, stream_name)
        try:
            while selector.get_map():
                remaining_seconds = deadline - time.monotonic()
                if remaining_seconds <= 0:
                    raise subprocess.TimeoutExpired(process.args, self.timeout_seconds)
                events = selector.select(remaining_seconds)
                if not events:
                    raise subprocess.TimeoutExpired(process.args, self.timeout_seconds)
                for key, _mask in events:
                    remaining_bytes = self.output_limit_bytes - captured_bytes
                    read_bytes = min(COMMAND_OUTPUT_READ_BYTES, remaining_bytes + 1)
                    try:
                        chunk = os.read(key.fd, read_bytes)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fd)
                        open_streams.pop(key.fd).close()
                        continue
                    retained = chunk if len(chunk) <= remaining_bytes else chunk[:remaining_bytes]
                    target = stdout if key.data == "stdout" else stderr
                    target.extend(retained)
                    captured_bytes += len(retained)
                    if len(chunk) > len(retained):
                        raise _CommandOutputExceeded(stdout, stderr)
        finally:
            selector.close()

        remaining_seconds = deadline - time.monotonic()
        process.wait(timeout=max(0.0, remaining_seconds))
        encoding = locale.getpreferredencoding(False)
        return stdout.decode(encoding), stderr.decode(encoding)

    @staticmethod
    def _drain_process_pipes(process: _SupervisedProcess, timeout_seconds: float) -> bool:
        """Discard pipe data with fixed per-read memory until EOF or deadline."""

        deadline = time.monotonic() + max(0.0, timeout_seconds)
        selector = selectors.DefaultSelector()
        open_streams: dict[int, Any] = {}
        for stream in (process.stdout, process.stderr):
            if stream is None or stream.closed:
                continue
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            open_streams[descriptor] = stream
            selector.register(descriptor, selectors.EVENT_READ)
        try:
            while selector.get_map():
                remaining_seconds = deadline - time.monotonic()
                if remaining_seconds <= 0:
                    return False
                events = selector.select(remaining_seconds)
                if not events:
                    return False
                for key, _mask in events:
                    try:
                        chunk = os.read(key.fd, COMMAND_OUTPUT_READ_BYTES)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fd)
                        open_streams.pop(key.fd).close()
            return True
        finally:
            selector.close()

    @staticmethod
    def _close_process_pipes(process: _SupervisedProcess) -> OSError | None:
        """Close every still-owned pipe while retaining the first close failure."""

        first_error: OSError | None = None
        for stream in (process.stdout, process.stderr):
            if stream is None or stream.closed:
                continue
            try:
                stream.close()
            except OSError as error:
                if first_error is None:
                    first_error = error
        return first_error

    def _terminate_process_group(self, process: _SupervisedProcess) -> None:
        """Terminate the complete command process group and bound pipe draining."""

        process_group = process.pid
        signal_error: OSError | None = self._signal_process_group_with_pid_fallback(
            process, signal.SIGTERM
        )
        pipe_error: OSError | None = None
        try:
            self._drain_process_pipes(process, self.term_grace_seconds)
        except OSError as error:
            pipe_error = error
        kill_error = self._signal_process_group_with_pid_fallback(process, signal.SIGKILL)
        if signal_error is None:
            signal_error = kill_error
        try:
            drained = self._drain_process_pipes(process, self.kill_grace_seconds)
        except OSError as error:
            drained = False
            if pipe_error is None:
                pipe_error = error
        close_error = self._close_process_pipes(process)
        if pipe_error is None:
            pipe_error = close_error
        try:
            process.wait(timeout=self.kill_grace_seconds)
        except subprocess.TimeoutExpired as error:
            raise SetupError("command process group could not be reaped") from error
        if signal_error is not None:
            try:
                os.killpg(process_group, 0)
            except ProcessLookupError:
                signal_error = None
            except OSError:
                pass
        if signal_error is not None:
            raise SetupError("command process group could not be terminated") from signal_error
        if pipe_error is not None:
            raise SetupError("command process pipes could not be drained") from pipe_error
        if not drained:
            raise SetupError("command process pipes could not be drained")

    @staticmethod
    def _signal_process_group_with_pid_fallback(
        process: _SupervisedProcess,
        requested_signal: int,
    ) -> OSError | None:
        """Signal the session, retaining uncertainty until its PGID disappears."""

        try:
            os.killpg(process.pid, requested_signal)
            return None
        except ProcessLookupError as group_error:
            try:
                os.kill(process.pid, requested_signal)
            except ProcessLookupError:
                return None
            except OSError:
                pass
            return group_error
        except OSError as group_error:
            try:
                os.kill(process.pid, requested_signal)
            except ProcessLookupError:
                pass
            except OSError:
                pass
            return group_error


@functools.cache
def _darwin_acl_api() -> tuple[Any, ...]:
    """Resolve and type the Darwin ACL ABI once per process."""

    library = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = library.acl_get_fd_np
    acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_get_entry = library.acl_get_entry
    acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    acl_get_entry.restype = ctypes.c_int
    acl_get_tag_type = library.acl_get_tag_type
    acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    acl_get_tag_type.restype = ctypes.c_int
    acl_get_qualifier = library.acl_get_qualifier
    acl_get_qualifier.argtypes = [ctypes.c_void_p]
    acl_get_qualifier.restype = ctypes.c_void_p
    acl_get_permset_mask_np = library.acl_get_permset_mask_np
    acl_get_permset_mask_np.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
    acl_get_permset_mask_np.restype = ctypes.c_int
    acl_get_flagset_np = library.acl_get_flagset_np
    acl_get_flagset_np.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    acl_get_flagset_np.restype = ctypes.c_int
    acl_get_flag_np = library.acl_get_flag_np
    acl_get_flag_np.argtypes = [ctypes.c_void_p, ctypes.c_int]
    acl_get_flag_np.restype = ctypes.c_int
    acl_free = library.acl_free
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int
    return (
        acl_get_fd_np,
        acl_get_entry,
        acl_get_tag_type,
        acl_get_qualifier,
        acl_get_permset_mask_np,
        acl_get_flagset_np,
        acl_get_flag_np,
        acl_free,
    )


def _read_darwin_acl_entries(descriptor: int) -> tuple[AclEntry, ...]:
    """Read one extended ACL from an already-retained descriptor."""

    (
        acl_get_fd_np,
        acl_get_entry,
        acl_get_tag_type,
        acl_get_qualifier,
        acl_get_permset_mask_np,
        acl_get_flagset_np,
        acl_get_flag_np,
        acl_free,
    ) = _darwin_acl_api()

    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED)
    if not acl:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return ()
        raise SetupError(
            "extended ACL could not be read from retained descriptor: "
            f"{os.strerror(error_number) if error_number else 'unknown error'}"
        )
    entries: list[AclEntry] = []
    try:
        entry = ctypes.c_void_p()
        selector = ACL_FIRST_ENTRY
        while True:
            ctypes.set_errno(0)
            status = acl_get_entry(acl, selector, ctypes.byref(entry))
            if status == -1 and ctypes.get_errno() == errno.EINVAL and entries:
                break
            if status != 0 or not entry.value:
                error_number = ctypes.get_errno()
                raise SetupError(
                    "extended ACL entry enumeration failed: "
                    f"{os.strerror(error_number) if error_number else 'invalid entry'}"
                )
            selector = ACL_NEXT_ENTRY
            tag = ctypes.c_int()
            if acl_get_tag_type(entry, ctypes.byref(tag)) != 0:
                error_number = ctypes.get_errno()
                raise SetupError(
                    "extended ACL tag could not be read: "
                    f"{os.strerror(error_number) if error_number else 'unknown error'}"
                )
            qualifier_pointer = acl_get_qualifier(entry)
            if not qualifier_pointer:
                error_number = ctypes.get_errno()
                raise SetupError(
                    "extended ACL qualifier could not be read: "
                    f"{os.strerror(error_number) if error_number else 'unknown error'}"
                )
            try:
                qualifier = ctypes.string_at(qualifier_pointer, 16)
            finally:
                if acl_free(qualifier_pointer) != 0:
                    raise SetupError("extended ACL qualifier could not be released")
            permissions = ctypes.c_uint64()
            if acl_get_permset_mask_np(entry, ctypes.byref(permissions)) != 0:
                error_number = ctypes.get_errno()
                raise SetupError(
                    "extended ACL permissions could not be read: "
                    f"{os.strerror(error_number) if error_number else 'unknown error'}"
                )
            flagset = ctypes.c_void_p()
            if acl_get_flagset_np(entry, ctypes.byref(flagset)) != 0 or not flagset.value:
                error_number = ctypes.get_errno()
                raise SetupError(
                    "extended ACL flags could not be read: "
                    f"{os.strerror(error_number) if error_number else 'unknown error'}"
                )
            flags = 0
            for bit_index in range(ACL_FLAG_SCAN_BITS):
                flag = 1 << bit_index
                ctypes.set_errno(0)
                present = acl_get_flag_np(flagset, flag)
                if present == 1:
                    flags |= flag
                elif present == -1 and ctypes.get_errno() not in {0, errno.EINVAL}:
                    error_number = ctypes.get_errno()
                    raise SetupError(
                        f"extended ACL flag could not be read: {os.strerror(error_number)}"
                    )
            entries.append(
                AclEntry(
                    tag=tag.value,
                    qualifier=qualifier,
                    permissions=permissions.value,
                    flags=flags,
                )
            )
    finally:
        if acl_free(acl) != 0:
            raise SetupError("extended ACL could not be released")
    return tuple(entries)


def _canonical_acl_payload(entries: Sequence[AclEntry], *, platform_name: str) -> bytes:
    payload = {
        "entries": [
            {
                "flags": entry.flags,
                "permissions": entry.permissions,
                "qualifier": entry.qualifier.hex(),
                "tag": entry.tag,
            }
            for entry in entries
        ],
        "platform": platform_name,
        "version": 1,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def _acl_digest_from_fd(
    descriptor: int,
    *,
    label: str,
    sensitive_leaf: bool,
) -> str:
    """Bind ACL access policy without a pathname re-open.

    Darwin extended ACLs are enforced. Other platforms record an explicit
    sentinel so equality remains meaningful without claiming ACL enforcement.
    """

    if sys.platform == "darwin":
        entries = _read_darwin_acl_entries(descriptor)
        if sensitive_leaf and entries:
            raise SetupError(f"{label} has an extended ACL")
        if not sensitive_leaf:
            unsupported = [entry.tag for entry in entries if entry.tag != ACL_EXTENDED_DENY]
            if unsupported:
                raise SetupError(f"{label} has a non-deny extended ACL entry")
        platform_name = "darwin-extended-acl"
    else:
        entries = ()
        platform_name = "non-darwin-acl-unavailable"
    return hashlib.sha256(_canonical_acl_payload(entries, platform_name=platform_name)).hexdigest()


def _binding_from_fd(
    descriptor: int,
    *,
    label: str,
    sensitive_leaf: bool,
) -> Binding:
    metadata = os.fstat(descriptor)
    return dataclasses.replace(
        Binding.from_stat(metadata),
        acl_digest=_acl_digest_from_fd(
            descriptor,
            label=label,
            sensitive_leaf=sensitive_leaf,
        ),
    )


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


def _directory_binding_tuple(binding: Binding) -> tuple[int, int, int, int, int, str | None]:
    """Bind directory identity/access policy without child-entry-derived size."""

    return (
        binding.dev,
        binding.ino,
        binding.uid,
        binding.gid,
        binding.mode,
        binding.acl_digest,
    )


def _directory_stat_tuple(binding: Binding) -> tuple[int, int, int, int, int]:
    """Compare path metadata to a retained FD without pretending it carries ACL state."""

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
    sensitive_leaf: bool = True,
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
        current_binding = _binding_from_fd(
            descriptor,
            label=f"{label} root",
            sensitive_leaf=sensitive_leaf and path == current,
        )
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
            current_binding = _binding_from_fd(
                descriptor,
                label=f"{label} component {current}",
                sensitive_leaf=sensitive_leaf and current == path,
            )
        return descriptor, current_binding
    except BaseException:
        os.close(descriptor)
        raise


def _directory_path_matches(path: Path, expected: Binding, *, label: str) -> None:
    descriptor, current = _open_real_directory(path, label=label, sensitive_leaf=False)
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
        binding = _binding_from_fd(
            descriptor,
            label=label,
            sensitive_leaf=True,
        )
        first = _read_bounded_descriptor(descriptor, max_bytes)
        if len(first) != metadata.st_size:
            raise SetupError(f"{label} changed while it was being read")
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_bounded_descriptor(descriptor, max_bytes)
        rebound_binding = _binding_from_fd(
            descriptor,
            label=label,
            sensitive_leaf=True,
        )
        if first != second or rebound_binding != binding:
            raise SetupError(f"{label} content or access policy changed while reading")
        path_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _binding_tuple(path_metadata) != _binding_tuple(metadata):
            raise SetupError(f"{label} object was replaced while reading")
        return FileSnapshot(binding=binding, data=first)
    finally:
        os.close(descriptor)


def _read_owned_regular_file(path: Path, *, max_bytes: int, label: str) -> FileSnapshot:
    path = _normalized_absolute(path, field=label)
    parent_fd, parent_binding = _open_real_directory(
        path.parent,
        label=f"{label} parent",
        sensitive_leaf=False,
    )
    try:
        snapshot = _snapshot_at(parent_fd, path.name, max_bytes=max_bytes, label=label)
        assert snapshot is not None
        _directory_path_matches(path.parent, parent_binding, label=f"{label} parent")
        return snapshot
    finally:
        os.close(parent_fd)


def _optional_owned_file(path: Path, *, max_bytes: int, label: str) -> FileSnapshot | None:
    path = _normalized_absolute(path, field=label)
    parent_fd, parent_binding = _open_real_directory(
        path.parent,
        label=f"{label} parent",
        sensitive_leaf=False,
    )
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
    raw_retired_repo_names = data.get("retired_repo_names", [])
    if not isinstance(raw_retired_repo_names, list) or any(
        not isinstance(name, str) for name in raw_retired_repo_names
    ):
        raise SetupError(f"{label} retired_repo_names must be an array of strings")
    retired_repo_names = tuple(raw_retired_repo_names)
    invalid_retired_names = [
        name for name in retired_repo_names if not RETIRED_REPO_NAME_PATTERN.fullmatch(name)
    ]
    if invalid_retired_names:
        raise SetupError(
            f"{label} retired_repo_names contains invalid names: "
            + ", ".join(repr(name) for name in invalid_retired_names)
        )
    if len(set(retired_repo_names)) != len(retired_repo_names):
        raise SetupError(f"{label} retired_repo_names must not contain duplicates")
    active_names = {repo.name for repo in repos}
    overlap = sorted(active_names.intersection(retired_repo_names))
    if overlap:
        raise SetupError(
            f"{label} repositories cannot be both active and retired: " + ", ".join(overlap)
        )
    return (
        WorkspaceManifest(
            path=path,
            cache_root=cache_root,
            repos=repos,
            retired_repo_names=retired_repo_names,
            snapshot=snapshot,
        ),
        data,
    )


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
    if manifest.retired_repo_names:
        raise SetupError("host manifest retired_repo_names must be empty")
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
        account_home=_absolute_path(
            _require_string(host, "account_home"), field="host_setup.account_home"
        ),
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
        config.account_home,
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
        quarantine_fd = os.open(
            quarantine,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            current_binding = _binding_from_fd(
                quarantine_fd,
                label=f"{label} quarantined directory",
                sensitive_leaf=True,
            )
        finally:
            os.close(quarantine_fd)
        if not stat.S_ISDIR(metadata.st_mode) or _directory_binding_tuple(
            current_binding
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


def _managed_mirror_guard_data(mirror: Path) -> bytes:
    """Return the workspace helper's exact managed-mirror hook payload."""

    mirror_literal = shlex.quote(str(mirror))
    return f"""#!/bin/sh
# Generated by codex-workspace. Do not edit.
mirror_path={mirror_literal}
top_level=$(git rev-parse --show-toplevel 2>/dev/null || exit 0)
if [ "$top_level" = "$mirror_path" ]; then
  echo "error: this checkout is a codex-workspace default-branch mirror: $mirror_path" >&2
  echo "create a run worktree with scripts/codex_workspace.py prepare-run before editing" >&2
  exit 1
fi
exit 0
""".encode()


def _managed_mirror_guard_snapshot(
    hooks_fd: int,
    hooks_path: Path,
    hook_name: str,
    expected_data: bytes,
) -> FileSnapshot | None:
    """Read one hook leaf without following it and accept only managed state."""

    hook_path = hooks_path / hook_name
    try:
        metadata = os.stat(hook_name, dir_fd=hooks_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SetupError(
            f"mirror guard hook leaf could not be inspected: {hook_path}: "
            f"{error.strerror or type(error).__name__}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode):
        raise SetupError(f"mirror guard hook leaf is a symlink: {hook_path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise SetupError(f"mirror guard hook leaf is not a regular file: {hook_path}")
    snapshot = _snapshot_at(
        hooks_fd,
        hook_name,
        max_bytes=MAX_CONFIG_BYTES,
        label=f"mirror guard hook {hook_path}",
    )
    assert snapshot is not None
    if snapshot.data != expected_data:
        raise SetupError(f"existing mirror guard hook has non-managed content: {hook_path}")
    if stat.S_IMODE(snapshot.binding.mode) != 0o755:
        raise SetupError(f"existing mirror guard hook has non-managed access policy: {hook_path}")
    return snapshot


def _revalidate_managed_hooks_directory(
    common_fd: int,
    common_path: Path,
    common_binding: Binding,
    hooks_fd: int,
    hooks_path: Path,
    hooks_binding: Binding,
) -> None:
    """Rebind the retained hook directory without treating child churn as mutation."""

    current = _binding_from_fd(
        hooks_fd,
        label="mirror guard hooks directory",
        sensitive_leaf=True,
    )
    if _directory_binding_tuple(current) != _directory_binding_tuple(hooks_binding):
        raise SetupError(
            f"mirror guard hooks directory identity or access policy changed: {hooks_path}"
        )
    try:
        linked = os.stat("hooks", dir_fd=common_fd, follow_symlinks=False)
    except OSError as error:
        raise SetupError(
            f"mirror guard hooks directory link could not be rebound: {hooks_path}: "
            f"{error.strerror or type(error).__name__}"
        ) from error
    if not stat.S_ISDIR(linked.st_mode) or _directory_stat_tuple(
        Binding.from_stat(linked)
    ) != _directory_stat_tuple(hooks_binding):
        raise SetupError(f"mirror guard hooks directory was replaced: {hooks_path}")
    _directory_path_matches(common_path, common_binding, label="mirror guard Git common dir")
    _directory_path_matches(hooks_path, hooks_binding, label="mirror guard hooks directory")


def _publish_missing_mirror_guard_hook(
    *,
    common_fd: int,
    common_path: Path,
    common_binding: Binding,
    hooks_fd: int,
    hooks_path: Path,
    hooks_binding: Binding,
    hook_name: str,
    expected_data: bytes,
    renamer: AtomicRenamer,
) -> FileSnapshot:
    """Publish one missing hook through a private-named prevalidated stage."""

    hook_path = hooks_path / hook_name
    stage = f".{hook_name}.stage-{os.getpid()}-{secrets.token_hex(8)}"
    stage_fd: int | None = None
    stage_created = False
    moved = False
    owned_snapshot: FileSnapshot | None = None
    try:
        _revalidate_managed_hooks_directory(
            common_fd,
            common_path,
            common_binding,
            hooks_fd,
            hooks_path,
            hooks_binding,
        )
        if (
            _managed_mirror_guard_snapshot(
                hooks_fd,
                hooks_path,
                hook_name,
                expected_data,
            )
            is not None
        ):
            raise SetupError(f"mirror guard hook appeared after preflight: {hook_path}")
        stage_fd = os.open(
            stage,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=hooks_fd,
        )
        stage_created = True
        os.fchmod(stage_fd, 0o755)
        remaining = memoryview(expected_data)
        while remaining:
            written = os.write(stage_fd, remaining)
            if written <= 0:
                raise OSError(errno.EIO, "mirror guard stage write made no progress")
            remaining = remaining[written:]
        os.fsync(stage_fd)
        staged = _snapshot_at(
            hooks_fd,
            stage,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"mirror guard private stage {hooks_path / stage}",
        )
        assert staged is not None
        if staged.data != expected_data or stat.S_IMODE(staged.binding.mode) != 0o755:
            raise SetupError(f"mirror guard private stage did not verify: {hooks_path / stage}")
        owned_snapshot = staged
        if (
            _managed_mirror_guard_snapshot(
                hooks_fd,
                hooks_path,
                hook_name,
                expected_data,
            )
            is not None
        ):
            raise SetupError(f"mirror guard hook appeared before publish: {hook_path}")
        try:
            renamer.no_replace(hooks_fd, stage, hook_name)
        except OSError as error:
            if error.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                raise SetupError(
                    f"foreign mirror guard hook appeared during no-replace publish: {hook_path}"
                ) from error
            raise
        moved = True
        os.fsync(stage_fd)
        published_binding = _binding_from_fd(
            stage_fd,
            label=f"published mirror guard hook {hook_path}",
            sensitive_leaf=True,
        )
        if published_binding != staged.binding:
            raise SetupError(
                f"mirror guard hook identity or access policy changed during publish: {hook_path}"
            )
        owned_snapshot = FileSnapshot(binding=published_binding, data=expected_data)
        if stat.S_IMODE(owned_snapshot.binding.mode) != 0o755:
            raise SetupError(f"published mirror guard hook mode did not verify: {hook_path}")
        installed = _snapshot_at(
            hooks_fd,
            hook_name,
            max_bytes=MAX_CONFIG_BYTES,
            label=f"published mirror guard hook {hook_path}",
        )
        assert installed is not None
        if installed != owned_snapshot:
            raise SetupError(f"published mirror guard hook identity did not verify: {hook_path}")
        os.fsync(hooks_fd)
        _revalidate_managed_hooks_directory(
            common_fd,
            common_path,
            common_binding,
            hooks_fd,
            hooks_path,
            hooks_binding,
        )
        return installed
    except BaseException as original_error:
        recovery_error: BaseException | None = None
        try:
            if moved and owned_snapshot is not None:
                current = _snapshot_at(
                    hooks_fd,
                    hook_name,
                    max_bytes=MAX_CONFIG_BYTES,
                    label="failed mirror guard publish target",
                )
                if current != owned_snapshot:
                    raise SetupError(
                        f"failed mirror guard publish retained recovery object: {hook_path}"
                    )
                _retire_regular_leaf(
                    hooks_fd,
                    parent_path=hooks_path,
                    parent_binding=hooks_binding,
                    target=hook_name,
                    expected=owned_snapshot,
                    max_bytes=MAX_CONFIG_BYTES,
                    renamer=renamer,
                    label="failed mirror guard publish recovery",
                )
            elif stage_created and owned_snapshot is not None:
                _retire_regular_leaf(
                    hooks_fd,
                    parent_path=hooks_path,
                    parent_binding=hooks_binding,
                    target=stage,
                    expected=owned_snapshot,
                    max_bytes=MAX_CONFIG_BYTES,
                    renamer=renamer,
                    label="failed mirror guard stage recovery",
                )
            elif stage_created:
                raise SetupError(
                    f"unverified mirror guard stage retained for recovery: {hooks_path / stage}"
                )
        except BaseException as error:
            recovery_error = error
        if recovery_error is not None:
            raise SetupError(
                f"mirror guard publish failed ({original_error}); recovery failed "
                f"({recovery_error})"
            ) from original_error
        raise
    finally:
        if stage_fd is not None:
            os.close(stage_fd)


def _install_managed_mirror_guard_hooks(
    common_dir: Path,
    hook_names: Sequence[str],
    expected_data: bytes,
    *,
    renamer: AtomicRenamer | None = None,
) -> tuple[FileSnapshot, ...]:
    """Install exact guard hooks without following or overwriting a hook leaf."""

    common_dir = _normalized_absolute(common_dir, field="mirror guard Git common dir")
    if len(expected_data) > MAX_CONFIG_BYTES:
        raise SetupError("mirror guard hook content exceeds the byte limit")
    names = tuple(hook_names)
    if (
        not names
        or len(set(names)) != len(names)
        or any(not name or "/" in name or "\0" in name or name in {".", ".."} for name in names)
    ):
        raise SetupError("mirror guard hook names are not unique safe leaf names")

    common_fd, common_binding = _open_real_directory(
        common_dir,
        label="mirror guard Git common dir",
        require_current_owner=True,
    )
    hooks_path = common_dir / "hooks"
    hooks_fd: int | None = None
    hooks_binding: Binding | None = None
    hooks_created = False
    active_renamer = renamer
    installed: dict[str, FileSnapshot] = {}
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        directory_flags |= getattr(os, "O_NONBLOCK", 0)
        try:
            hooks_fd = os.open("hooks", directory_flags, dir_fd=common_fd)
        except FileNotFoundError:
            try:
                os.mkdir("hooks", mode=0o700, dir_fd=common_fd)
            except FileExistsError as error:
                raise SetupError(
                    f"foreign object appeared while creating mirror guard hooks directory: "
                    f"{hooks_path}"
                ) from error
            hooks_created = True
            os.fsync(common_fd)
            try:
                hooks_fd = os.open("hooks", directory_flags, dir_fd=common_fd)
            except OSError as error:
                raise SetupError(
                    f"created mirror guard hooks directory could not be rebound and was "
                    f"retained for inspection: {hooks_path}"
                ) from error
        except OSError as error:
            raise SetupError(
                f"mirror guard hooks directory could not be opened without following links: "
                f"{hooks_path}: {error.strerror or type(error).__name__}"
            ) from error

        metadata = os.fstat(hooks_fd)
        _validate_directory_metadata(
            metadata,
            label="mirror guard hooks directory",
            require_current_owner=True,
        )
        hooks_binding = _binding_from_fd(
            hooks_fd,
            label="mirror guard hooks directory",
            sensitive_leaf=True,
        )
        linked = os.stat("hooks", dir_fd=common_fd, follow_symlinks=False)
        if not stat.S_ISDIR(linked.st_mode) or _directory_stat_tuple(
            Binding.from_stat(linked)
        ) != _directory_stat_tuple(hooks_binding):
            raise SetupError(
                f"mirror guard hooks directory was replaced while opening: {hooks_path}"
            )
        _revalidate_managed_hooks_directory(
            common_fd,
            common_dir,
            common_binding,
            hooks_fd,
            hooks_path,
            hooks_binding,
        )

        preflight = {
            name: _managed_mirror_guard_snapshot(
                hooks_fd,
                hooks_path,
                name,
                expected_data,
            )
            for name in names
        }
        if hooks_created:
            active_renamer = active_renamer or AtomicRenamer()
        for name in names:
            expected = preflight[name]
            current = _managed_mirror_guard_snapshot(
                hooks_fd,
                hooks_path,
                name,
                expected_data,
            )
            if current != expected:
                raise SetupError(f"mirror guard hook changed after preflight: {hooks_path / name}")
            if current is not None:
                continue
            active_renamer = active_renamer or AtomicRenamer()
            installed[name] = _publish_missing_mirror_guard_hook(
                common_fd=common_fd,
                common_path=common_dir,
                common_binding=common_binding,
                hooks_fd=hooks_fd,
                hooks_path=hooks_path,
                hooks_binding=hooks_binding,
                hook_name=name,
                expected_data=expected_data,
                renamer=active_renamer,
            )
            preflight[name] = installed[name]

        final: list[FileSnapshot] = []
        for name in names:
            current = _managed_mirror_guard_snapshot(
                hooks_fd,
                hooks_path,
                name,
                expected_data,
            )
            if current != preflight[name] or current is None:
                raise SetupError(
                    f"mirror guard hook identity or access policy changed: {hooks_path / name}"
                )
            final.append(current)
        os.fsync(hooks_fd)
        _revalidate_managed_hooks_directory(
            common_fd,
            common_dir,
            common_binding,
            hooks_fd,
            hooks_path,
            hooks_binding,
        )
        return tuple(final)
    except BaseException as original_error:
        recovery_errors: list[str] = []
        if hooks_fd is not None and hooks_binding is not None:
            if installed:
                try:
                    active_renamer = active_renamer or AtomicRenamer()
                except SetupError as error:
                    recovery_errors.append(str(error))
                else:
                    for name, expected in reversed(tuple(installed.items())):
                        try:
                            current = _snapshot_at(
                                hooks_fd,
                                name,
                                max_bytes=MAX_CONFIG_BYTES,
                                label="mirror guard transaction rollback target",
                            )
                            if current != expected:
                                raise SetupError(
                                    f"mirror guard rollback refused a replaced target: "
                                    f"{hooks_path / name}"
                                )
                            _retire_regular_leaf(
                                hooks_fd,
                                parent_path=hooks_path,
                                parent_binding=hooks_binding,
                                target=name,
                                expected=expected,
                                max_bytes=MAX_CONFIG_BYTES,
                                renamer=active_renamer,
                                label="mirror guard transaction rollback",
                            )
                        except (OSError, SetupError) as error:
                            recovery_errors.append(str(error))
            if hooks_created:
                try:
                    active_renamer = active_renamer or AtomicRenamer()
                    _retire_directory_leaf(
                        common_fd,
                        parent_path=common_dir,
                        parent_binding=common_binding,
                        target="hooks",
                        expected_binding=hooks_binding,
                        renamer=active_renamer,
                        label="mirror guard hooks directory rollback",
                    )
                except (OSError, SetupError) as error:
                    recovery_errors.append(str(error))
        if recovery_errors:
            raise SetupError(
                f"mirror guard installation failed ({original_error}); recovery incomplete: "
                + "; ".join(recovery_errors)
            ) from original_error
        raise
    finally:
        if hooks_fd is not None:
            os.close(hooks_fd)
        os.close(common_fd)


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
                try:
                    os.fchmod(stream.fileno(), mode)
                except OSError as error:
                    raise SetupError(f"could not set replacement mode: {path}") from error
                actual_mode = stat.S_IMODE(os.fstat(stream.fileno()).st_mode)
                if actual_mode != mode:
                    raise SetupError(
                        f"replacement staged mode did not match the requested mode: {path}"
                    )
                os.fsync(stream.fileno())
            staged = _snapshot_at(
                parent_fd,
                stage,
                max_bytes=max_bytes,
                label="replacement staged file",
            )
            assert staged is not None
            if staged.data != data:
                raise SetupError(
                    f"replacement staged content did not match the requested data: {path}"
                )
            if stat.S_IMODE(staged.binding.mode) != mode:
                raise SetupError(
                    f"replacement staged mode changed after descriptor validation: {path}"
                )
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
    descriptor, _ = _open_real_directory(
        base,
        label=f"{label} base",
        require_current_owner=True,
        sensitive_leaf=False,
    )
    try:
        for index, child_name in enumerate(children):
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
                        _binding_from_fd(
                            child_fd,
                            label=f"{label} {current_path / child_name}",
                            sensitive_leaf=index == len(children) - 1,
                        ),
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
                child_binding = _binding_from_fd(
                    child_fd,
                    label=f"{label} {current_path / child_name}",
                    sensitive_leaf=index == len(children) - 1,
                )
                rebound = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
                if _directory_stat_tuple(Binding.from_stat(rebound)) != _directory_stat_tuple(
                    child_binding
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


def _open_optional_child_directory(
    parent_fd: int,
    parent_path: Path,
    name: str,
    *,
    label: str,
) -> tuple[int, Binding] | None:
    """Open one administrative child without following or accepting replacement."""

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SetupError(
            f"{label} could not be opened without following links: "
            f"{error.strerror or type(error).__name__}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        _validate_directory_metadata(
            metadata,
            label=label,
            require_current_owner=True,
        )
        path_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        binding = _binding_from_fd(
            descriptor,
            label=label,
            sensitive_leaf=True,
        )
        if _directory_stat_tuple(Binding.from_stat(path_metadata)) != _directory_stat_tuple(
            binding
        ):
            raise SetupError(f"{label} was replaced while opening: {parent_path / name}")
        return descriptor, binding
    except BaseException:
        os.close(descriptor)
        raise


def _require_missing_git_admin_entry(parent_fd: int, name: str, *, label: str) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise SetupError(
            f"{label} absence could not be verified: {error.strerror or type(error).__name__}"
        ) from error
    raise SetupError(f"{label} is present")


def _require_missing_git_worktree_config(parent_fd: int, git_dir: Path) -> bool:
    """Bind ``config.worktree`` absence without following a hostile leaf."""

    name = "config.worktree"
    path = git_dir / name
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except PermissionError as error:
        raise SetupError(f"Git worktree config absence is unreadable: {path}") from error
    except OSError as error:
        raise SetupError(
            f"Git worktree config absence could not be inspected: {path}: "
            f"{error.strerror or type(error).__name__}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode):
        raise SetupError(f"Git worktree config leaf is a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise SetupError(f"Git worktree config leaf is not a regular file: {path}")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except PermissionError as error:
        raise SetupError(f"Git worktree config regular file is unreadable: {path}") from error
    except FileNotFoundError as error:
        raise SetupError(
            f"Git worktree config leaf changed while being inspected: {path}"
        ) from error
    except OSError as error:
        raise SetupError(
            f"Git worktree config regular file could not be opened without following links: "
            f"{path}: {error.strerror or type(error).__name__}"
        ) from error
    try:
        rebound = os.fstat(descriptor)
        if not stat.S_ISREG(rebound.st_mode) or _binding_tuple(rebound) != _binding_tuple(metadata):
            raise SetupError(f"Git worktree config leaf changed while being opened: {path}")
    finally:
        os.close(descriptor)
    raise SetupError(f"Git worktree config regular file is present: {path}")


def _require_missing_git_external_source_leaf(
    parent_fd: int,
    name: str,
    *,
    parent_path: Path,
    label: str,
) -> None:
    """Reject an external Git source redirect without following its leaf."""

    path = parent_path / name
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except PermissionError as error:
        raise SetupError(f"{label} absence is unreadable: {path}") from error
    except OSError as error:
        raise SetupError(
            f"{label} absence could not be inspected: {path}: "
            f"{error.strerror or type(error).__name__}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode):
        raise SetupError(f"{label} leaf is a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise SetupError(f"{label} leaf is not a regular file: {path}")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except PermissionError as error:
        raise SetupError(f"{label} regular file is unreadable: {path}") from error
    except FileNotFoundError as error:
        raise SetupError(f"{label} leaf changed while being inspected: {path}") from error
    except OSError as error:
        raise SetupError(
            f"{label} regular file could not be opened without following links: "
            f"{path}: {error.strerror or type(error).__name__}"
        ) from error
    try:
        rebound = os.fstat(descriptor)
        if not stat.S_ISREG(rebound.st_mode) or _binding_tuple(rebound) != _binding_tuple(metadata):
            raise SetupError(f"{label} leaf changed while being opened: {path}")
    finally:
        os.close(descriptor)
    raise SetupError(f"{label} regular file is present: {path}")


def _require_missing_git_object_sources(parent_fd: int, parent_path: Path) -> bool:
    for name, label in (
        ("alternates", "Git object alternates"),
        ("http-alternates", "Git HTTP object alternates"),
    ):
        _require_missing_git_external_source_leaf(
            parent_fd,
            name,
            parent_path=parent_path,
            label=label,
        )
    return True


def _packed_refs_contains_replace_ref(data: bytes) -> bool:
    for line in data.splitlines():
        if not line or line.startswith((b"#", b"^")):
            continue
        fields = line.split(b" ", 1)
        if len(fields) == 2 and fields[1].startswith(b"refs/replace/"):
            return True
    return False


def _git_local_config_entries(
    data: bytes,
    *,
    label: str,
) -> tuple[tuple[str, str | None], ...]:
    """Parse the closed key grammar needed to reject executable Git config.

    The parser intentionally accepts less than Git. Unsupported syntax fails
    closed before any repository-aware Git command is started.
    """

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SetupError(f"{label} is not UTF-8") from error
    if "\0" in text:
        raise SetupError(f"{label} contains a NUL byte")
    section: str | None = None
    entries: list[tuple[str, str | None]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if raw_line.rstrip().endswith("\\"):
            raise SetupError(f"{label} uses an unsupported continuation at line {line_number}")
        if stripped.startswith("["):
            match = GIT_CONFIG_SECTION_PATTERN.fullmatch(stripped)
            if match is None:
                raise SetupError(f"{label} has unsupported section syntax at line {line_number}")
            section_name = match.group(1).lower()
            subsection = match.group(2)
            if subsection is not None:
                subsection = subsection.replace(r"\"", '"').replace(r"\\", "\\")
                section = f"{section_name}.{subsection.lower()}"
            else:
                section = section_name
            continue
        if section is None:
            raise SetupError(f"{label} has a variable outside a section at line {line_number}")
        match = GIT_CONFIG_VARIABLE_PATTERN.fullmatch(stripped)
        if match is None:
            raise SetupError(f"{label} has unsupported variable syntax at line {line_number}")
        entries.append((f"{section}.{match.group(1).lower()}", match.group(2)))
    return tuple(entries)


def _git_config_key_is_unsafe(key: str) -> bool:
    parts = key.split(".")
    section = parts[0]
    leaf = parts[-1]
    if section in {"include", "includeif", "alias", "pager"}:
        return True
    if section == "filter" and leaf in {"clean", "smudge", "process"}:
        return True
    if section == "core" and leaf in {
        "alternaterefscommand",
        "askpass",
        "attributesfile",
        "editor",
        "fsmonitor",
        "gitproxy",
        "hookspath",
        "pager",
        "sshcommand",
        "worktree",
    }:
        return True
    if section == "extensions" and leaf == "worktreeconfig":
        return True
    if section == "diff" and leaf in {"command", "external", "textconv"}:
        return True
    if section == "merge" and leaf in {"driver", "tool"}:
        return True
    if section in {"difftool", "mergetool"} and leaf in {"cmd", "path"}:
        return True
    if section == "interactive" and leaf == "difffilter":
        return True
    if section == "url" and leaf in {"insteadof", "pushinsteadof"}:
        return True
    if section == "credential" and leaf in {"askpass", "helper"}:
        return True
    if section == "remote" and leaf in {
        "proxy",
        "pushurl",
        "receivepack",
        "uploadpack",
        "vcs",
    }:
        return True
    if section in {"http", "https"} and leaf == "proxy":
        return True
    if section == "protocol" and leaf == "allow":
        return True
    return False


def _validate_git_local_config(
    snapshot: FileSnapshot,
    *,
    repository: Path,
    label: str,
    allow_managed_hooks_path: bool,
    allow_worktree_config: bool,
) -> bool:
    """Reject executable Git config except for two exact host-owned shapes.

    Managed mirrors may name only their own absolute ``.git/hooks`` directory;
    every delegated Git boundary still overrides ``core.hooksPath`` to
    ``/dev/null``.  The standalone workspace root may additionally retain the
    one exact ``extensions.worktreeConfig = true`` setting used by its local
    worktree management.  Mirrors never receive that allowance, and
    ``config.worktree`` remains required absent before and after every child.
    """

    entries = _git_local_config_entries(snapshot.data, label=label)
    unsafe = {key for key, _value in entries if _git_config_key_is_unsafe(key)}
    hooks_path_values = [value for key, value in entries if key == "core.hookspath"]
    expected_hooks_path = str(repository / ".git" / "hooks")
    managed_hooks_path = bool(hooks_path_values)
    if allow_managed_hooks_path and hooks_path_values == [expected_hooks_path]:
        unsafe.discard("core.hookspath")
    worktree_config_values = [value for key, value in entries if key == "extensions.worktreeconfig"]
    if allow_worktree_config and worktree_config_values == ["true"]:
        unsafe.discard("extensions.worktreeconfig")
    core_bare_values = [value for key, value in entries if key == "core.bare"]
    if core_bare_values and core_bare_values != ["false"]:
        unsafe.add("core.bare")
    if unsafe:
        raise SetupError(
            f"{label} selects executable or redirected Git behavior: {', '.join(sorted(unsafe))}"
        )
    return managed_hooks_path


def _inspect_git_topology_replacements(
    repository: Path,
    *,
    expected: GitTopologyGuard | None = None,
    allow_managed_hooks_path: bool = False,
    allow_worktree_config: bool = False,
) -> GitTopologyGuard:
    """Reject Git topology substitution and bind its administrative parents.

    Object identity and access policy are protected for the repository, ``.git``,
    the common object directory, and any existing object/ref metadata parents.
    Ordinary loose/pack object and ref churn is allowed. The complete external
    object-source set and replacement topology must remain absent.
    """

    repository_fd, repository_binding = _open_real_directory(
        repository,
        label="Git topology repository",
        require_current_owner=True,
    )
    git_dir_opened: tuple[int, Binding] | None = None
    hooks_opened: tuple[int, Binding] | None = None
    objects_opened: tuple[int, Binding] | None = None
    objects_info_opened: tuple[int, Binding] | None = None
    refs_opened: tuple[int, Binding] | None = None
    info_opened: tuple[int, Binding] | None = None
    try:
        if expected is not None and expected.repository_binding is not None:
            if _directory_binding_tuple(repository_binding) != _directory_binding_tuple(
                expected.repository_binding
            ):
                raise SetupError(
                    f"Git topology repository identity or access policy changed: {repository}"
                )
        git_dir_opened = _open_optional_child_directory(
            repository_fd,
            repository,
            ".git",
            label="Git topology .git directory",
        )
        if git_dir_opened is None:
            raise SetupError(f"Git topology .git directory is missing: {repository / '.git'}")
        git_fd, git_dir_binding = git_dir_opened
        if expected is not None and expected.git_dir_binding is not None:
            if _directory_binding_tuple(git_dir_binding) != _directory_binding_tuple(
                expected.git_dir_binding
            ):
                raise SetupError(
                    f"Git topology .git identity or access policy changed: {repository / '.git'}"
                )
        _require_missing_git_external_source_leaf(
            git_fd,
            "commondir",
            parent_path=repository / ".git",
            label="Git common-directory redirect",
        )
        local_config = _snapshot_at(
            git_fd,
            "config",
            max_bytes=MAX_CONFIG_BYTES,
            label=f"Git local config {repository / '.git' / 'config'}",
        )
        assert local_config is not None
        managed_hooks_path = _validate_git_local_config(
            local_config,
            repository=repository,
            label=f"Git local config {repository / '.git' / 'config'}",
            allow_managed_hooks_path=allow_managed_hooks_path,
            allow_worktree_config=allow_worktree_config,
        )
        if expected is not None and expected.local_config_snapshot is not None:
            if local_config != expected.local_config_snapshot:
                raise SetupError(
                    f"Git local config changed during delegated operation: "
                    f"{repository / '.git' / 'config'}"
                )
        worktree_config_absent = _require_missing_git_worktree_config(
            git_fd,
            repository / ".git",
        )
        if expected is not None and expected.worktree_config_absent is not True:
            raise SetupError("Git worktree config absence baseline is invalid")

        managed_hook_snapshots: tuple[tuple[str, FileSnapshot], ...] | None = None
        if managed_hooks_path:
            hooks_opened = _open_optional_child_directory(
                git_fd,
                repository / ".git",
                "hooks",
                label="managed mirror hooks directory",
            )
            if hooks_opened is None:
                raise SetupError(
                    f"managed mirror hooks directory is missing: {repository / '.git' / 'hooks'}"
                )
            expected_hook_data = _managed_mirror_guard_data(repository)
            snapshots: list[tuple[str, FileSnapshot]] = []
            for hook_name in MANAGED_MIRROR_GUARD_HOOKS:
                snapshot = _managed_mirror_guard_snapshot(
                    hooks_opened[0],
                    repository / ".git" / "hooks",
                    hook_name,
                    expected_hook_data,
                )
                if snapshot is None:
                    raise SetupError(
                        f"managed mirror guard hook is missing: "
                        f"{repository / '.git' / 'hooks' / hook_name}"
                    )
                snapshots.append((hook_name, snapshot))
            managed_hook_snapshots = tuple(snapshots)
            if expected is not None:
                if expected.hooks_binding is None or _directory_binding_tuple(
                    hooks_opened[1]
                ) != _directory_binding_tuple(expected.hooks_binding):
                    raise SetupError(
                        f"managed mirror hooks directory identity or access policy changed: "
                        f"{repository / '.git' / 'hooks'}"
                    )
                if expected.managed_hook_snapshots != managed_hook_snapshots:
                    raise SetupError(
                        f"managed mirror guard hooks changed during delegated operation: "
                        f"{repository / '.git' / 'hooks'}"
                    )
        elif expected is not None and (
            expected.hooks_binding is not None or expected.managed_hook_snapshots is not None
        ):
            raise SetupError("managed mirror hook baseline is invalid")

        objects_opened = _open_optional_child_directory(
            git_fd,
            repository / ".git",
            "objects",
            label="Git common object directory",
        )
        if objects_opened is None:
            raise SetupError(
                f"Git common object directory is missing: {repository / '.git' / 'objects'}"
            )
        objects_fd, objects_binding = objects_opened
        if expected is not None:
            if expected.objects_binding is None or _directory_binding_tuple(
                objects_binding
            ) != _directory_binding_tuple(expected.objects_binding):
                raise SetupError(
                    f"Git common object directory identity or access policy changed: "
                    f"{repository / '.git' / 'objects'}"
                )
        objects_info_opened = _open_optional_child_directory(
            objects_fd,
            repository / ".git" / "objects",
            "info",
            label="Git object info directory",
        )
        objects_info_binding = objects_info_opened[1] if objects_info_opened is not None else None
        if expected is not None and expected.objects_info_binding is not None:
            if objects_info_binding is None or _directory_binding_tuple(
                objects_info_binding
            ) != _directory_binding_tuple(expected.objects_info_binding):
                raise SetupError(
                    f"Git object info directory identity or access policy changed: "
                    f"{repository / '.git' / 'objects' / 'info'}"
                )
        alternate_object_sources_absent = True
        if objects_info_opened is not None:
            alternate_object_sources_absent = _require_missing_git_object_sources(
                objects_info_opened[0],
                repository / ".git" / "objects" / "info",
            )
        if expected is not None and expected.alternate_object_sources_absent is not True:
            raise SetupError("Git alternate object source absence baseline is invalid")

        refs_opened = _open_optional_child_directory(
            git_fd,
            repository / ".git",
            "refs",
            label="Git topology refs directory",
        )
        info_opened = _open_optional_child_directory(
            git_fd,
            repository / ".git",
            "info",
            label="Git topology info directory",
        )
        refs_binding = refs_opened[1] if refs_opened is not None else None
        info_binding = info_opened[1] if info_opened is not None else None
        if expected is not None and expected.refs_binding is not None:
            if refs_binding is None or _directory_binding_tuple(
                refs_binding
            ) != _directory_binding_tuple(expected.refs_binding):
                raise SetupError(
                    f"Git topology refs identity or access policy changed: "
                    f"{repository / '.git' / 'refs'}"
                )
        if expected is not None and expected.info_binding is not None:
            if info_binding is None or _directory_binding_tuple(
                info_binding
            ) != _directory_binding_tuple(expected.info_binding):
                raise SetupError(
                    f"Git topology info identity or access policy changed: "
                    f"{repository / '.git' / 'info'}"
                )

        if refs_opened is not None:
            _require_missing_git_admin_entry(
                refs_opened[0],
                "replace",
                label=f"Git loose replacement refs path {repository / '.git' / 'refs' / 'replace'}",
            )
        if info_opened is not None:
            _require_missing_git_admin_entry(
                info_opened[0],
                "grafts",
                label=f"Git graft file {repository / '.git' / 'info' / 'grafts'}",
            )
        packed_refs = _snapshot_at(
            git_fd,
            "packed-refs",
            max_bytes=MAX_CONFIG_BYTES,
            label=f"Git packed refs {repository / '.git' / 'packed-refs'}",
            missing_ok=True,
        )
        if packed_refs is not None and _packed_refs_contains_replace_ref(packed_refs.data):
            raise SetupError(
                f"Git packed replacement ref is present: {repository / '.git' / 'packed-refs'}"
            )

        _directory_path_matches(
            repository,
            repository_binding,
            label="Git topology repository",
        )
        _directory_path_matches(
            repository / ".git",
            git_dir_binding,
            label="Git topology .git directory",
        )
        _directory_path_matches(
            repository / ".git" / "objects",
            objects_binding,
            label="Git common object directory",
        )
        if objects_info_opened is not None:
            _directory_path_matches(
                repository / ".git" / "objects" / "info",
                objects_info_opened[1],
                label="Git object info directory",
            )
            _require_missing_git_object_sources(
                objects_info_opened[0],
                repository / ".git" / "objects" / "info",
            )
        else:
            rebound_objects_info = _open_optional_child_directory(
                objects_fd,
                repository / ".git" / "objects",
                "info",
                label="Git object info directory revalidation",
            )
            if rebound_objects_info is not None:
                os.close(rebound_objects_info[0])
                raise SetupError(
                    f"Git object info directory appeared while it was being inspected: "
                    f"{repository / '.git' / 'objects' / 'info'}"
                )
        if refs_opened is not None:
            _directory_path_matches(
                repository / ".git" / "refs",
                refs_opened[1],
                label="Git topology refs directory",
            )
            _require_missing_git_admin_entry(
                refs_opened[0],
                "replace",
                label=f"Git loose replacement refs path {repository / '.git' / 'refs' / 'replace'}",
            )
        if info_opened is not None:
            _directory_path_matches(
                repository / ".git" / "info",
                info_opened[1],
                label="Git topology info directory",
            )
            _require_missing_git_admin_entry(
                info_opened[0],
                "grafts",
                label=f"Git graft file {repository / '.git' / 'info' / 'grafts'}",
            )
        packed_refs_rebound = _snapshot_at(
            git_fd,
            "packed-refs",
            max_bytes=MAX_CONFIG_BYTES,
            label=f"Git packed refs {repository / '.git' / 'packed-refs'}",
            missing_ok=True,
        )
        if packed_refs_rebound is not None and _packed_refs_contains_replace_ref(
            packed_refs_rebound.data
        ):
            raise SetupError(
                f"Git packed replacement ref is present: {repository / '.git' / 'packed-refs'}"
            )
        local_config_rebound = _snapshot_at(
            git_fd,
            "config",
            max_bytes=MAX_CONFIG_BYTES,
            label=f"Git local config {repository / '.git' / 'config'}",
        )
        if local_config_rebound != local_config:
            raise SetupError(
                f"Git local config changed while it was being inspected: "
                f"{repository / '.git' / 'config'}"
            )
        _require_missing_git_external_source_leaf(
            git_fd,
            "commondir",
            parent_path=repository / ".git",
            label="Git common-directory redirect",
        )
        if not _require_missing_git_worktree_config(git_fd, repository / ".git"):
            raise SetupError("Git worktree config absence revalidation failed")
        if hooks_opened is not None:
            _revalidate_managed_hooks_directory(
                git_fd,
                repository / ".git",
                git_dir_binding,
                hooks_opened[0],
                repository / ".git" / "hooks",
                hooks_opened[1],
            )
            assert managed_hook_snapshots is not None
            expected_hook_data = _managed_mirror_guard_data(repository)
            for hook_name, snapshot in managed_hook_snapshots:
                rebound = _managed_mirror_guard_snapshot(
                    hooks_opened[0],
                    repository / ".git" / "hooks",
                    hook_name,
                    expected_hook_data,
                )
                if rebound != snapshot:
                    raise SetupError(
                        f"managed mirror guard hook changed while it was being inspected: "
                        f"{repository / '.git' / 'hooks' / hook_name}"
                    )
            _revalidate_managed_hooks_directory(
                git_fd,
                repository / ".git",
                git_dir_binding,
                hooks_opened[0],
                repository / ".git" / "hooks",
                hooks_opened[1],
            )
        return GitTopologyGuard(
            repository=repository,
            repository_binding=repository_binding,
            git_dir_binding=git_dir_binding,
            objects_binding=objects_binding,
            objects_info_binding=objects_info_binding,
            refs_binding=refs_binding,
            info_binding=info_binding,
            hooks_binding=hooks_opened[1] if hooks_opened is not None else None,
            managed_hook_snapshots=managed_hook_snapshots,
            local_config_snapshot=local_config,
            worktree_config_absent=worktree_config_absent,
            alternate_object_sources_absent=alternate_object_sources_absent,
        )
    finally:
        if info_opened is not None:
            os.close(info_opened[0])
        if refs_opened is not None:
            os.close(refs_opened[0])
        if objects_info_opened is not None:
            os.close(objects_info_opened[0])
        if objects_opened is not None:
            os.close(objects_opened[0])
        if hooks_opened is not None:
            os.close(hooks_opened[0])
        if git_dir_opened is not None:
            os.close(git_dir_opened[0])
        os.close(repository_fd)


def _git_topology_replacement_check(
    repository: Path,
    *,
    prefix: str,
    allow_managed_hooks_path: bool = False,
    allow_worktree_config: bool = False,
) -> Check:
    try:
        _inspect_git_topology_replacements(
            repository,
            allow_managed_hooks_path=allow_managed_hooks_path,
            allow_worktree_config=allow_worktree_config,
        )
    except SetupError as error:
        return Check(f"{prefix}-topology-replacements", "blocked", str(error))
    return Check(
        f"{prefix}-topology-replacements",
        "ready",
        f"no Git replace refs, graft file, or alternate object source: {repository}",
    )


def _git_admin_path_checks(
    repository: Path,
    *,
    prefix: str,
    allow_managed_hooks_path: bool = False,
    allow_worktree_config: bool = False,
) -> list[Check]:
    """Validate Git admin paths before any optional managed-mirror Git probe."""

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
    checks.append(
        _git_topology_replacement_check(
            repository,
            prefix=prefix,
            allow_managed_hooks_path=allow_managed_hooks_path,
            allow_worktree_config=allow_worktree_config,
        )
    )
    if allow_managed_hooks_path:
        if any(check.status == "blocked" for check in checks):
            checks.append(
                Check(
                    f"{prefix}-index-flags",
                    "blocked",
                    "index flag validation was not started because a Git admin "
                    "prerequisite is blocked",
                )
            )
        else:
            checks.append(_mirror_index_flags_check(repository, prefix=prefix))
    return checks


def _git_environment(*, disable_hooks: bool = True) -> dict[str, str]:
    environment = _trusted_process_environment()
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_GRAFT_FILE": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_ASKPASS": "/usr/bin/false",
            "SSH_ASKPASS": "/usr/bin/false",
            "GIT_SSH": SSH_EXECUTABLE,
            "GIT_SSH_VARIANT": "ssh",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
        }
    )
    overrides = [
        ("core.attributesFile", "/dev/null"),
        ("core.checkStat", "default"),
        ("core.fileMode", "true"),
        ("core.fsmonitor", "false"),
        ("core.hooksPath", "/dev/null"),
        ("core.ignoreStat", "false"),
        ("core.sshCommand", SSH_EXECUTABLE),
        ("core.trustCtime", "true"),
        ("credential.helper", ""),
        ("protocol.ext.allow", "never"),
    ]
    del disable_hooks  # Hooks are disabled at every Git boundary, including delegated helpers.
    environment["GIT_CONFIG_COUNT"] = str(len(overrides))
    for index, (key, value) in enumerate(overrides):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    return environment


def _run_git(
    repository: Path,
    *arguments: str,
    check: bool = True,
    allow_managed_hooks_path: bool = False,
    allow_worktree_config: bool = False,
) -> subprocess.CompletedProcess[str]:
    topology = _inspect_git_topology_replacements(
        repository,
        allow_managed_hooks_path=allow_managed_hooks_path,
        allow_worktree_config=allow_worktree_config,
    )
    try:
        result = CommandRunner(
            timeout_seconds=GIT_TIMEOUT_SECONDS,
            term_grace_seconds=COMMAND_TERM_GRACE_SECONDS,
            kill_grace_seconds=COMMAND_KILL_GRACE_SECONDS,
        ).run(
            [GIT_EXECUTABLE, *arguments],
            cwd=repository,
            env=_git_environment(disable_hooks=True),
        )
    except SetupError:
        _inspect_git_topology_replacements(
            repository,
            expected=topology,
            allow_managed_hooks_path=allow_managed_hooks_path,
            allow_worktree_config=allow_worktree_config,
        )
        raise
    _inspect_git_topology_replacements(
        repository,
        expected=topology,
        allow_managed_hooks_path=allow_managed_hooks_path,
        allow_worktree_config=allow_worktree_config,
    )
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
        *PYTHON_ISOLATION_FLAGS,
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
    arguments = ["status"]
    if repo is not None:
        arguments.extend(["--repo", repo.name])
    arguments.append("--strict")
    result = _run_helper(config, manifest, arguments, runner)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[:MAX_COMMAND_DETAIL]
        target = repo.name if repo is not None else "all repositories"
        raise SetupError(
            f"workspace helper strict status failed for {target} with exit "
            f"{result.returncode}: {detail}"
        )


def _git_output(
    repository: Path,
    *arguments: str,
    allow_managed_hooks_path: bool = False,
    allow_worktree_config: bool = False,
) -> str:
    return _run_git(
        repository,
        *arguments,
        allow_managed_hooks_path=allow_managed_hooks_path,
        allow_worktree_config=allow_worktree_config,
    ).stdout.strip()


def _managed_mirror_git_output(repository: Path, *arguments: str) -> str:
    return _git_output(
        repository,
        *arguments,
        allow_managed_hooks_path=True,
    )


def _default_mirror_index_snapshot(repository: Path) -> str:
    """Require the index shape that makes worktree cleanliness observable.

    The protected property is that status can observe tracked worktree drift at
    each validation checkpoint. A lowercase ``h`` (assume-unchanged), ``S``
    (skip-worktree), or any other non-``H`` ``git ls-files -v`` tag can suppress
    or invalidate an ordinary status signal, so managed mirrors accept only
    cached ``H`` entries. This intentionally does not claim to expose the
    separate fsmonitor-valid bit. The command runs under the repository-safe Git
    boundary, with hooks, filters, attributes, and executable extensions
    disabled, and its aggregate output is byte-bounded by ``CommandRunner``.
    Object identity and access policy are separate topology and filesystem
    properties.
    """

    index_check = _regular_file_check(
        repository / ".git" / "index",
        name="managed mirror index",
    )
    if index_check.status != "ready":
        raise SetupError(f"managed mirror index prerequisite is blocked: {index_check.detail}")
    output = _run_git(
        repository,
        "ls-files",
        "--cached",
        "-v",
        "-z",
        "--",
        allow_managed_hooks_path=True,
    ).stdout
    if output and not output.endswith("\0"):
        raise SetupError("managed mirror index flag output is malformed")
    records = output.split("\0")
    if records and records[-1] == "":
        records.pop()
    unexpected_tags: dict[str, int] = {}
    for record in records:
        if len(record) < 3 or record[1] != " ":
            raise SetupError("managed mirror index flag output is malformed")
        tag = record[0]
        if tag != "H":
            unexpected_tags[tag] = unexpected_tags.get(tag, 0) + 1
    if unexpected_tags:
        summary = ",".join(f"{tag}={count}" for tag, count in sorted(unexpected_tags.items()))
        raise SetupError(
            "managed mirror index has status-suppressing flags or non-default "
            f"stages that can hide tracked worktree drift: {summary}"
        )
    return output


def _mirror_index_flags_check(repository: Path, *, prefix: str) -> Check:
    try:
        _default_mirror_index_snapshot(repository)
    except SetupError as error:
        return Check(f"{prefix}-index-flags", "blocked", str(error))
    return Check(
        f"{prefix}-index-flags",
        "ready",
        f"no status-suppressing index tags or non-default stages: {repository}",
    )


def _mirror_cleanliness_snapshot(repository: Path, *, repo_name: str) -> str:
    baseline = _default_mirror_index_snapshot(repository)
    dirty = _managed_mirror_git_output(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    rebound = _default_mirror_index_snapshot(repository)
    if rebound != baseline:
        raise SetupError(f"{repo_name} mirror index changed during cleanliness validation")
    if dirty:
        raise SetupError(f"{repo_name} mirror is dirty")
    return baseline


def _revalidate_mirror_cleanliness_snapshot(
    repository: Path,
    *,
    repo_name: str,
    expected: str,
) -> None:
    rebound = _mirror_cleanliness_snapshot(repository, repo_name=repo_name)
    if rebound != expected:
        raise SetupError(f"{repo_name} mirror index changed during semantic validation")


def mirror_snapshot(
    config: HostConfig,
    manifest: WorkspaceManifest,
    repo: RepoSpec,
    runner: CommandRunner,
) -> dict[str, str]:
    _run_workspace_status(config, manifest, runner, repo=repo)
    mirror = manifest.repo_path(repo)
    top = Path(_managed_mirror_git_output(mirror, "rev-parse", "--show-toplevel"))
    if top != mirror:
        raise SetupError(f"{repo.name} top-level path does not match its manifest mirror")
    common = _managed_mirror_git_output(mirror, "rev-parse", "--git-common-dir")
    git_dir = _managed_mirror_git_output(mirror, "rev-parse", "--git-dir")
    if common != ".git" or git_dir != ".git":
        raise SetupError(f"{repo.name} mirror must be a standalone Git checkout")
    if _managed_mirror_git_output(mirror, "rev-parse", "--is-shallow-repository") != "false":
        raise SetupError(f"{repo.name} mirror must not be shallow")
    remotes = [line for line in _managed_mirror_git_output(mirror, "remote").splitlines() if line]
    if remotes != ["origin"]:
        raise SetupError(f"{repo.name} mirror must have exactly the origin remote")
    remote_url = _managed_mirror_git_output(mirror, "remote", "get-url", "origin")
    if remote_url != repo.url:
        raise SetupError(f"{repo.name} origin URL does not match the manifest")
    refspecs = [
        line
        for line in _managed_mirror_git_output(
            mirror, "config", "--local", "--get-all", "remote.origin.fetch"
        ).splitlines()
        if line
    ]
    if refspecs != ["+refs/heads/*:refs/remotes/origin/*"]:
        raise SetupError(f"{repo.name} origin fetch refspec is not the expected clone refspec")
    branch = _managed_mirror_git_output(mirror, "branch", "--show-current")
    if branch != repo.default_branch:
        raise SetupError(
            f"{repo.name} branch is {branch or 'detached'}, expected {repo.default_branch}"
        )
    clean_index = _mirror_cleanliness_snapshot(mirror, repo_name=repo.name)
    upstream = _managed_mirror_git_output(
        mirror, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"
    )
    expected_upstream = f"origin/{repo.default_branch}"
    if upstream != expected_upstream:
        raise SetupError(f"{repo.name} upstream is {upstream}, expected {expected_upstream}")
    head = _managed_mirror_git_output(mirror, "rev-parse", "HEAD")
    upstream_head = _managed_mirror_git_output(mirror, "rev-parse", "@{u}")
    counts = _managed_mirror_git_output(
        mirror, "rev-list", "--left-right", "--count", "HEAD...@{u}"
    )
    pieces = counts.split()
    if len(pieces) != 2 or not all(piece.isdigit() for piece in pieces):
        raise SetupError(f"{repo.name} ahead/behind output is malformed")
    if pieces != ["0", "0"] or head != upstream_head:
        raise SetupError(f"{repo.name} mirror is not exactly synchronized with upstream")
    _revalidate_mirror_cleanliness_snapshot(
        mirror,
        repo_name=repo.name,
        expected=clean_index,
    )
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
        top = Path(_managed_mirror_git_output(mirror, "rev-parse", "--show-toplevel"))
        common = _managed_mirror_git_output(mirror, "rev-parse", "--git-common-dir")
        git_dir = _managed_mirror_git_output(mirror, "rev-parse", "--git-dir")
        if top != mirror or common != ".git" or git_dir != ".git":
            raise SetupError(f"{repo.name} must be the expected standalone mirror")
        if _managed_mirror_git_output(mirror, "rev-parse", "--is-shallow-repository") != "false":
            raise SetupError(f"{repo.name} mirror must not be shallow")
        remotes = [
            line for line in _managed_mirror_git_output(mirror, "remote").splitlines() if line
        ]
        if remotes != ["origin"]:
            raise SetupError(f"{repo.name} mirror must have exactly the origin remote")
        if _managed_mirror_git_output(mirror, "remote", "get-url", "origin") != repo.url:
            raise SetupError(f"{repo.name} origin URL does not match the manifest")
        refspecs = [
            line
            for line in _managed_mirror_git_output(
                mirror, "config", "--local", "--get-all", "remote.origin.fetch"
            ).splitlines()
            if line
        ]
        if refspecs != ["+refs/heads/*:refs/remotes/origin/*"]:
            raise SetupError(f"{repo.name} origin fetch refspec is not the expected clone refspec")
        branch = _managed_mirror_git_output(mirror, "branch", "--show-current")
        if branch != repo.default_branch:
            raise SetupError(
                f"{repo.name} branch is {branch or 'detached'}, expected {repo.default_branch}"
            )
        clean_index = _mirror_cleanliness_snapshot(mirror, repo_name=repo.name)
        upstream = _managed_mirror_git_output(
            mirror, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"
        )
        expected_upstream = f"origin/{repo.default_branch}"
        if upstream != expected_upstream:
            raise SetupError(f"{repo.name} upstream is {upstream}, expected {expected_upstream}")
        if (
            _managed_mirror_git_output(
                mirror, "config", "--local", "--get", f"branch.{branch}.remote"
            )
            != "origin"
        ):
            raise SetupError(f"{repo.name} branch remote is not origin")
        expected_merge = f"refs/heads/{repo.default_branch}"
        if (
            _managed_mirror_git_output(
                mirror, "config", "--local", "--get", f"branch.{branch}.merge"
            )
            != expected_merge
        ):
            raise SetupError(f"{repo.name} branch merge ref is not {expected_merge}")
        pieces = _managed_mirror_git_output(
            mirror, "rev-list", "--left-right", "--count", "HEAD...@{u}"
        ).split()
        if len(pieces) != 2 or not all(piece.isdigit() for piece in pieces):
            raise SetupError(f"{repo.name} ahead/behind output is malformed")
        if pieces[0] != "0":
            raise SetupError(
                f"{repo.name} mirror is ahead or diverged: ahead={pieces[0]} behind={pieces[1]}"
            )
        _revalidate_mirror_cleanliness_snapshot(
            mirror,
            repo_name=repo.name,
            expected=clean_index,
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


def _bind_current_interpreter(config: HostConfig) -> CurrentInterpreterBinding:
    """Validate the already-running interpreter and its nominal path policy.

    The protected runtime object is the current process image, which fork will
    inherit without a new pathname lookup. ``sys.executable`` and the stable
    snapshot below prove that the manifest names the current safe pathname and
    that its present object has stable content and access policy. They do not
    retrospectively identify the vnode opened by the OS loader at process start.
    """

    executable = _normalized_absolute(Path(sys.executable), field="current Python executable")
    if executable != config.python_executable:
        raise SetupError(
            "current Python executable does not match host_setup.python_executable: "
            f"{executable} != {config.python_executable}"
        )
    snapshot = _read_owned_regular_file(
        config.python_executable,
        max_bytes=256 * 1024 * 1024,
        label="Python executable",
    )
    if not snapshot.binding.mode & 0o111:
        raise SetupError("Python executable has no executable bit")
    version = (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)
    if version < (3, 12, 0):
        raise SetupError("current Python interpreter must be version 3.12 or newer")
    required_flags = {
        "isolated": sys.flags.isolated,
        "no_site": sys.flags.no_site,
        "no_user_site": sys.flags.no_user_site,
        "dont_write_bytecode": sys.flags.dont_write_bytecode,
    }
    missing = [name for name, value in required_flags.items() if value != 1]
    if missing:
        raise SetupError(
            "current Python interpreter lacks required -I -B -S isolation: " + ", ".join(missing)
        )
    return CurrentInterpreterBinding(
        executable=executable,
        version=version,
        nominal_snapshot=snapshot,
    )


def _check_python(config: HostConfig, runner: CommandRunner) -> Check:
    try:
        binding = runner.bind_current_interpreter(config)
    except SetupError as error:
        return Check("python-executable", "blocked", str(error))
    version = ".".join(str(part) for part in binding.version)
    return Check(
        "python-executable",
        "ready",
        f"current isolated interpreter {binding.executable}: Python {version}",
    )


def _check_workspace_helper(config: HostConfig, runner: CommandRunner) -> Check:
    try:
        runner.bind_workspace_helper(config)
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
            SHELL_EXECUTABLE,
            SHELL_PRIVILEGED_FLAG,
            "-c",
            LAUNCH_ENV_COMMAND,
            LAUNCH_ENV_ARG0,
            str(config.account_home),
            str(config.python_executable),
            *PYTHON_ISOLATION_FLAGS,
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
        "EnvironmentVariables": {"PATH": TRUSTED_SYSTEM_PATH},
    }


def _desired_weekly_launch_agent(config: HostConfig) -> dict[str, Any]:
    return {
        "Label": config.weekly_launch_agent_label,
        "ProgramArguments": [
            SHELL_EXECUTABLE,
            SHELL_PRIVILEGED_FLAG,
            "-c",
            LAUNCH_ENV_COMMAND,
            LAUNCH_ENV_ARG0,
            str(config.account_home),
            str(config.python_executable),
            *PYTHON_ISOLATION_FLAGS,
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
        "EnvironmentVariables": {"PATH": TRUSTED_SYSTEM_PATH},
    }


def desired_launch_agent(config: HostConfig, key: str = "control") -> dict[str, Any]:
    if key == "control":
        return _desired_control_launch_agent(config)
    if key == "weekly":
        return _desired_weekly_launch_agent(config)
    raise SetupError(f"unknown LaunchAgent key: {key}")


def _launch_agent_specs(config: HostConfig, home: Path) -> tuple[LaunchAgentSpec, ...]:
    home = _normalized_absolute(home, field="user home")
    if home != config.account_home:
        raise SetupError(
            f"user home does not match host_setup.account_home: {home} != {config.account_home}"
        )
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
    installed_mode = stat.S_IMODE(installed.binding.mode)
    if installed.data == source.data and installed_mode != LAUNCH_AGENT_MODE:
        return Check(
            f"launch-agent-file-{spec.key}",
            "needs-apply",
            f"managed LaunchAgent access policy needs mode {LAUNCH_AGENT_MODE:#06o}, "
            f"found {installed_mode:#06o}: {spec.destination}",
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
        if _directory_stat_tuple(Binding.from_stat(followed)) != _directory_stat_tuple(
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
    top = Path(
        _git_output(
            config.workspace_root,
            "rev-parse",
            "--show-toplevel",
            allow_worktree_config=True,
        )
    )
    git_dir = _git_output(
        config.workspace_root,
        "rev-parse",
        "--git-dir",
        allow_worktree_config=True,
    )
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
        allow_worktree_config=True,
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


_LAUNCHCTL_REQUIRED_SCALARS = frozenset(
    {
        "path",
        "type",
        "program",
        "working directory",
        "stdout path",
        "stderr path",
    }
)
_LAUNCHCTL_BEHAVIOR_SCALARS = frozenset(
    {"minimum runtime", "base minimum runtime", "exit timeout", "spawn type", "properties"}
)
_LAUNCHCTL_REQUIRED_BEHAVIOR_SCALARS = frozenset(
    {"minimum runtime", "exit timeout", "spawn type", "properties"}
)
_LAUNCHCTL_RUNTIME_SCALARS = frozenset(
    {
        "active count",
        "state",
        "domain",
        "asid",
        "runs",
        "pid",
        "immediate reason",
        "forks",
        "execs",
        "initialized",
        "trampolined",
        "started suspended",
        "proxy started suspended",
        "checked allocations",
        "checked allocations reason",
        "checked allocations flags",
        "last exit code",
        "job state",
        "jetsam priority",
        "jetsam memory limit (active, soft)",
        "jetsam memory limit (inactive, soft)",
        "jetsam memory limit (active)",
        "jetsam memory limit (inactive)",
        "jetsamproperties category",
        "jetsam thread limit",
        "cpumon",
        "exponential throttling grace limit",
    }
)
_LAUNCHCTL_REQUIRED_BLOCKS = frozenset(
    {"arguments", "environment", "event triggers", "event channels"}
)
_LAUNCHCTL_RUNTIME_BLOCKS = frozenset(
    {
        "inherited environment",
        "default environment",
        "dynamic endpoints",
        "pid-local endpoints",
        "resource coalition",
        "jetsam coalition",
    }
)
_LAUNCHCTL_RUNTIME_FLAGS = frozenset({"submitted job. ignore execute allowed"})
_LAUNCHCTL_NEUTRAL_PROPERTIES = frozenset(
    {"inferred program", "needs LWCR update", "managed LWCR", "has LWCR"}
)
_LAUNCHCTL_DEFAULT_MINIMUM_RUNTIME = 10
_LAUNCHCTL_DEFAULT_EXIT_TIMEOUT = 5
_LAUNCHCTL_DEFAULT_SPAWN_TYPE = "daemon (3)"
_LAUNCH_AGENT_PLIST_KEYS = frozenset(
    {
        "Label",
        "ProgramArguments",
        "WorkingDirectory",
        "StartCalendarInterval",
        "StandardOutPath",
        "StandardErrorPath",
        "EnvironmentVariables",
    }
)


def _launchctl_opens_block(line: str) -> bool:
    stripped = line.lstrip("\t")
    return stripped.endswith(" = {") or stripped.endswith(" => {")


def _launchctl_top_level_fields(
    lines: Sequence[str],
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    scalars: dict[str, str] = {}
    blocks: dict[str, tuple[str, ...]] = {}
    index = 1
    while index < len(lines) - 1:
        line = lines[index]
        if not line:
            index += 1
            continue
        if not line.startswith("\t") or line.startswith("\t\t"):
            raise SetupError("launchctl print has an invalid top-level field")
        field = line.removeprefix("\t")
        key, separator, value = field.partition(" = ")
        if not separator:
            if field not in _LAUNCHCTL_RUNTIME_FLAGS:
                raise SetupError(f"launchctl print has an unsupported top-level field: {field}")
            index += 1
            continue
        if not key or not value or key in scalars or key in blocks:
            raise SetupError("launchctl print has a duplicate or invalid top-level field")
        if value != "{":
            scalars[key] = value
            index += 1
            continue

        depth = 1
        end = index + 1
        while end < len(lines) - 1:
            nested = lines[end].lstrip("\t")
            if _launchctl_opens_block(lines[end]):
                depth += 1
            elif nested == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        if depth != 0:
            raise SetupError(f"launchctl print has an unterminated {key} block")
        blocks[key] = tuple(lines[index + 1 : end])
        index = end + 1

    allowed_scalars = (
        _LAUNCHCTL_REQUIRED_SCALARS | _LAUNCHCTL_BEHAVIOR_SCALARS | _LAUNCHCTL_RUNTIME_SCALARS
    )
    unknown_scalars = sorted(set(scalars) - allowed_scalars)
    unknown_blocks = sorted(set(blocks) - _LAUNCHCTL_REQUIRED_BLOCKS - _LAUNCHCTL_RUNTIME_BLOCKS)
    if unknown_scalars or unknown_blocks:
        fields = ",".join(unknown_scalars + unknown_blocks)
        raise SetupError(f"launchctl print has unsupported fields: {fields}")
    missing_scalars = sorted(
        (_LAUNCHCTL_REQUIRED_SCALARS | _LAUNCHCTL_REQUIRED_BEHAVIOR_SCALARS) - set(scalars)
    )
    missing_blocks = sorted(_LAUNCHCTL_REQUIRED_BLOCKS - set(blocks))
    if missing_scalars or missing_blocks:
        fields = ",".join(missing_scalars + missing_blocks)
        raise SetupError(f"launchctl print is missing required fields: {fields}")
    return scalars, blocks


def _launchctl_scalar(scalars: Mapping[str, str], key: str) -> str:
    value = scalars.get(key)
    if value is None or not value or value == "{":
        raise SetupError(f"launchctl print has an invalid {key} field")
    return value


def _parse_launchctl_arguments(lines: Sequence[str]) -> tuple[str, ...]:
    arguments: list[str] = []
    for line in lines:
        if not line.startswith("\t\t") or line.startswith("\t\t\t"):
            raise SetupError("launchctl print has an invalid arguments entry")
        value = line.removeprefix("\t\t")
        if not value:
            raise SetupError("launchctl print has an empty arguments entry")
        arguments.append(value)
    if not arguments:
        raise SetupError("launchctl print has no program arguments")
    return tuple(arguments)


def _parse_launchctl_environment(lines: Sequence[str]) -> dict[str, str]:
    environment: dict[str, str] = {}
    for line in lines:
        if not line.startswith("\t\t") or line.startswith("\t\t\t"):
            raise SetupError("launchctl print has an invalid environment entry")
        key, separator, value = line.removeprefix("\t\t").partition(" => ")
        if not separator or not key or not value or key in environment:
            raise SetupError("launchctl print has an invalid environment entry")
        environment[key] = value
    return environment


def _launchctl_direct_fields(
    lines: Sequence[str],
    *,
    indent: int,
    context: str,
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    prefix = "\t" * indent
    scalars: dict[str, str] = {}
    blocks: dict[str, tuple[str, ...]] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line:
            index += 1
            continue
        if not line.startswith(prefix) or line.startswith(prefix + "\t"):
            raise SetupError(f"launchctl print has an invalid {context} field")
        field = line.removeprefix(prefix)
        key, separator, value = field.partition(" = ")
        if not separator or not key or not value or key in scalars or key in blocks:
            raise SetupError(f"launchctl print has an invalid {context} field")
        if value != "{":
            scalars[key] = value
            index += 1
            continue
        depth = 1
        end = index + 1
        while end < len(lines):
            nested = lines[end].lstrip("\t")
            if _launchctl_opens_block(lines[end]):
                depth += 1
            elif nested == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        if depth != 0:
            raise SetupError(f"launchctl print has an unterminated {context} field")
        blocks[key] = tuple(lines[index + 1 : end])
        index = end + 1
    return scalars, blocks


def _parse_launchctl_event_channels(channels: Sequence[str]) -> None:
    index = 0
    seen = False
    while index < len(channels):
        line = channels[index]
        if not line:
            index += 1
            continue
        if seen or line != '\t\t"com.apple.launchd.calendarinterval" = {':
            raise SetupError("launchctl print has an unexpected event channel")
        seen = True
        depth = 1
        end = index + 1
        while end < len(channels):
            nested = channels[end].lstrip("\t")
            if _launchctl_opens_block(channels[end]):
                depth += 1
            elif nested == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        if depth != 0:
            raise SetupError("launchctl print has an unterminated event channel")
        scalars, blocks = _launchctl_direct_fields(
            channels[index + 1 : end],
            indent=3,
            context="event channel",
        )
        expected_fields = {"port", "active", "managed", "reset", "hide", "watching"}
        if set(scalars) != expected_fields or blocks:
            fields = sorted(set(scalars) ^ expected_fields)
            fields.extend(sorted(blocks))
            raise SetupError(
                "launchctl print has unsupported event channel fields: " + ",".join(fields)
            )
        if re.fullmatch(r"0x[0-9a-f]+", scalars["port"]) is None:
            raise SetupError("launchctl print has an invalid event channel port")
        if scalars["active"] not in {"0", "1"}:
            raise SetupError("launchctl print has an invalid event channel active state")
        if (
            scalars["managed"] != "1"
            or scalars["reset"] != "0"
            or scalars["hide"] != "0"
            or scalars["watching"] != "1"
        ):
            raise SetupError("launchctl print has an unexpected event channel behavior")
        index = end + 1
    if not seen:
        raise SetupError("launchctl print has no calendar event channel")


def _parse_launchctl_calendar_intervals(
    triggers: Sequence[str],
    *,
    expected_service: str,
) -> tuple[tuple[tuple[str, int], ...], ...]:
    intervals: list[tuple[tuple[str, int], ...]] = []
    trigger_names: set[str] = set()
    index = 0
    while index < len(triggers):
        line = triggers[index]
        if not line:
            index += 1
            continue
        match = re.fullmatch(r"\t\t(.+) => \{", line)
        if (
            match is None
            or re.fullmatch(rf"{re.escape(expected_service)}\.[0-9]+", match.group(1)) is None
            or match.group(1) in trigger_names
        ):
            raise SetupError("launchctl print has an invalid event trigger")
        trigger_names.add(match.group(1))
        depth = 1
        end = index + 1
        while end < len(triggers):
            nested = triggers[end].lstrip("\t")
            if _launchctl_opens_block(triggers[end]):
                depth += 1
            elif nested == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        if depth != 0:
            raise SetupError("launchctl print has an unterminated event trigger")
        scalars, blocks = _launchctl_direct_fields(
            triggers[index + 1 : end],
            indent=3,
            context="event trigger",
        )
        expected_scalars = {"service", "stream", "monitor", "keepalive"}
        expected_blocks = {"descriptor"}
        scalar_delta = sorted(set(scalars) ^ expected_scalars)
        block_delta = sorted(set(blocks) ^ expected_blocks)
        if scalar_delta or block_delta:
            fields = ",".join(scalar_delta + block_delta)
            raise SetupError(f"launchctl print has unsupported event trigger fields: {fields}")
        if scalars.get("service") != expected_service:
            raise SetupError("launchctl print event trigger targets an unexpected service")
        if scalars.get("stream") != "com.apple.launchd.calendarinterval":
            raise SetupError("launchctl print has an unexpected event trigger kind")
        if scalars["monitor"] != "com.apple.UserEventAgent-Aqua":
            raise SetupError("launchctl print has an unexpected event trigger monitor")
        if scalars["keepalive"] != "0":
            raise SetupError("launchctl print event trigger enables unexpected KeepAlive behavior")
        descriptor_lines = blocks["descriptor"]
        descriptor: dict[str, int] = {}
        for entry in descriptor_lines:
            if not entry.startswith("\t\t\t\t") or entry.startswith("\t\t\t\t\t"):
                raise SetupError("launchctl print has an invalid calendar descriptor entry")
            match = re.fullmatch(
                r'"([A-Za-z]+)" => (-?[0-9]+)',
                entry.removeprefix("\t\t\t\t"),
            )
            if match is None or match.group(1) in descriptor:
                raise SetupError("launchctl print has an invalid calendar descriptor entry")
            descriptor[match.group(1)] = int(match.group(2))
        if not descriptor:
            raise SetupError("launchctl print has an empty calendar descriptor")
        intervals.append(tuple(sorted(descriptor.items())))
        index = end + 1
    if not intervals:
        raise SetupError("launchctl print has no calendar interval")
    return tuple(sorted(intervals))


def _parse_launchctl_definition(
    service: str,
    output: str,
) -> LoadedLaunchAgent:
    if len(output.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise SetupError("launchctl print output exceeds the size limit")
    lines = output.splitlines()
    if not lines or lines[0] != f"{service} = {{" or lines[-1] != "}":
        raise SetupError("launchctl print does not describe the requested service")
    scalars, blocks = _launchctl_top_level_fields(lines)
    if _launchctl_scalar(scalars, "type") != "LaunchAgent":
        raise SetupError("launchctl print does not describe a LaunchAgent")

    minimum_runtime = scalars.get("minimum runtime")
    base_minimum_runtime = scalars.get("base minimum runtime")
    for key, value in (
        ("minimum runtime", minimum_runtime),
        ("base minimum runtime", base_minimum_runtime),
        ("exit timeout", scalars.get("exit timeout")),
    ):
        if value is not None and re.fullmatch(r"[0-9]+", value) is None:
            raise SetupError(f"launchctl print has an invalid {key} field")

    properties_value = scalars.get("properties")
    properties: frozenset[str]
    if properties_value is None:
        properties = frozenset()
    else:
        values = properties_value.split(" | ")
        if any(not value for value in values) or len(values) != len(set(values)):
            raise SetupError("launchctl print has an invalid properties field")
        properties = frozenset(values)
        configured_behavior = sorted(properties & {"keepalive", "runatload"})
        if configured_behavior:
            names = [
                {"keepalive": "KeepAlive", "runatload": "RunAtLoad"}[value]
                for value in configured_behavior
            ]
            raise SetupError(
                "launchctl print enables unsupported behavior properties: " + ",".join(names)
            )
        unsupported = sorted(properties - _LAUNCHCTL_NEUTRAL_PROPERTIES)
        if unsupported:
            raise SetupError(
                "launchctl print has unsupported behavior properties: " + ",".join(unsupported)
            )
        if "inferred program" not in properties:
            raise SetupError("launchctl print properties do not bind the inferred program")
    _parse_launchctl_event_channels(blocks["event channels"])
    assert minimum_runtime is not None
    exit_timeout = scalars["exit timeout"]
    spawn_type = scalars["spawn type"]
    return LoadedLaunchAgent(
        source_path=_launchctl_scalar(scalars, "path"),
        program=_launchctl_scalar(scalars, "program"),
        program_arguments=_parse_launchctl_arguments(blocks["arguments"]),
        working_directory=_launchctl_scalar(scalars, "working directory"),
        standard_out_path=_launchctl_scalar(scalars, "stdout path"),
        standard_error_path=_launchctl_scalar(scalars, "stderr path"),
        environment_variables=_parse_launchctl_environment(blocks["environment"]),
        calendar_intervals=_parse_launchctl_calendar_intervals(
            blocks["event triggers"],
            expected_service=service.rsplit("/", 1)[-1],
        ),
        minimum_runtime=int(minimum_runtime),
        base_minimum_runtime=(
            int(base_minimum_runtime) if base_minimum_runtime is not None else None
        ),
        exit_timeout=int(exit_timeout),
        spawn_type=spawn_type,
        properties=properties,
    )


def _expected_calendar_intervals(
    expected: Mapping[str, Any],
) -> tuple[tuple[tuple[str, int], ...], ...]:
    configured = expected.get("StartCalendarInterval")
    entries = [configured] if isinstance(configured, dict) else configured
    if not isinstance(entries, list) or not entries:
        raise SetupError("verified LaunchAgent has invalid StartCalendarInterval")
    intervals: list[tuple[tuple[str, int], ...]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry:
            raise SetupError("verified LaunchAgent has invalid StartCalendarInterval")
        normalized: list[tuple[str, int]] = []
        for key, value in entry.items():
            if not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool):
                raise SetupError("verified LaunchAgent has invalid StartCalendarInterval")
            normalized.append((key, value))
        intervals.append(tuple(sorted(normalized)))
    return tuple(sorted(intervals))


def _loaded_definition_mismatches(
    spec: LaunchAgentSpec,
    definition: LoadedLaunchAgent | None,
    expected: Mapping[str, Any],
) -> tuple[str, ...]:
    """Bind behavior-affecting loaded configuration to the verified plist.

    The source path, execution inputs, working directory, output paths, explicit
    environment, and schedule define what launchd will run and when. Volatile
    runtime fields such as state, counters, PIDs, and exit status are deliberately
    ignored because they do not change that protected configuration property.
    """
    if definition is None:
        return ("definition",)
    if set(expected) != _LAUNCH_AGENT_PLIST_KEYS:
        unsupported = sorted(set(expected) - _LAUNCH_AGENT_PLIST_KEYS)
        missing = sorted(_LAUNCH_AGENT_PLIST_KEYS - set(expected))
        fields = ",".join(unsupported + missing)
        raise SetupError(
            f"verified {spec.key} LaunchAgent does not use the closed behavior schema: {fields}"
        )
    label = expected.get("Label")
    arguments = expected.get("ProgramArguments")
    working_directory = expected.get("WorkingDirectory")
    stdout_path = expected.get("StandardOutPath")
    stderr_path = expected.get("StandardErrorPath")
    environment = expected.get("EnvironmentVariables")
    if (
        label != spec.label
        or not isinstance(arguments, list)
        or not arguments
        or not all(isinstance(value, str) and value for value in arguments)
        or not isinstance(working_directory, str)
        or not isinstance(stdout_path, str)
        or not isinstance(stderr_path, str)
        or not isinstance(environment, dict)
        or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in environment.items()
        )
    ):
        raise SetupError(f"verified {spec.key} LaunchAgent definition is invalid")

    mismatches: list[str] = []
    if definition.source_path != str(spec.destination):
        mismatches.append("path")
    if definition.program != arguments[0]:
        mismatches.append("program")
    if definition.program_arguments != tuple(arguments):
        mismatches.append("ProgramArguments")
    if definition.working_directory != working_directory:
        mismatches.append("WorkingDirectory")
    if definition.standard_out_path != stdout_path:
        mismatches.append("StandardOutPath")
    if definition.standard_error_path != stderr_path:
        mismatches.append("StandardErrorPath")

    observed_environment = dict(definition.environment_variables)
    service_name = observed_environment.pop("XPC_SERVICE_NAME", spec.label)
    observed_environment.pop("OSLogRateLimit", None)
    if service_name != spec.label or observed_environment != environment:
        mismatches.append("EnvironmentVariables")
    if definition.calendar_intervals != _expected_calendar_intervals(expected):
        mismatches.append("StartCalendarInterval")
    if definition.minimum_runtime != _LAUNCHCTL_DEFAULT_MINIMUM_RUNTIME or (
        definition.base_minimum_runtime is not None
        and definition.base_minimum_runtime != _LAUNCHCTL_DEFAULT_MINIMUM_RUNTIME
    ):
        mismatches.append("ThrottleInterval")
    if definition.exit_timeout != _LAUNCHCTL_DEFAULT_EXIT_TIMEOUT:
        mismatches.append("ExitTimeOut")
    if definition.spawn_type != _LAUNCHCTL_DEFAULT_SPAWN_TYPE:
        mismatches.append("ProcessType")
    return tuple(mismatches)


def _require_loaded_definition(
    spec: LaunchAgentSpec,
    state: ServiceState,
    expected: Mapping[str, Any],
    *,
    action: str,
) -> None:
    if not state.loaded:
        raise SetupError(f"{action} did not load {spec.label}")
    mismatches = _loaded_definition_mismatches(spec, state.definition, expected)
    if mismatches:
        raise SetupError(
            f"{action} loaded an unexpected definition for {spec.label}: "
            f"fields={','.join(mismatches)}"
        )


def _query_service(label: str, runner: CommandRunner) -> ServiceState:
    service = _launchctl_service(label)
    result = runner.run(
        [LAUNCHCTL_EXECUTABLE, "print", service],
        env=_trusted_process_environment(),
    )
    if result.returncode == 0:
        definition = _parse_launchctl_definition(service, result.stdout)
        return ServiceState(label=label, loaded=True, definition=definition)
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
    try:
        _require_loaded_definition(
            spec,
            state,
            spec.expected,
            action="launchctl print",
        )
    except SetupError as error:
        return Check(f"launchctl-{spec.key}", "blocked", str(error))
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
            checks.extend(
                _git_admin_path_checks(
                    mirror,
                    prefix=f"prefetch-{repo.name}",
                    allow_managed_hooks_path=True,
                )
            )
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
                checks.extend(
                    _git_admin_path_checks(
                        mirror,
                        prefix=f"ensure-{repo.name}",
                        allow_managed_hooks_path=True,
                    )
                )
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
    path_checks = _git_admin_path_checks(
        config.workspace_root,
        prefix="workspace",
        allow_worktree_config=True,
    )
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
            _check_workspace_helper(config, runner),
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
            base,
            label=f"{label} base",
            require_current_owner=True,
            sensitive_leaf=False,
        )
        try:
            current = base
            missing = False
            for index, child in enumerate(children):
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
                try:
                    metadata = os.fstat(next_fd)
                    _validate_directory_metadata(
                        metadata,
                        label=f"{label} {current}",
                        require_current_owner=True,
                    )
                    _binding_from_fd(
                        next_fd,
                        label=f"{label} {current}",
                        sensitive_leaf=index == len(children) - 1,
                    )
                except BaseException:
                    os.close(next_fd)
                    raise
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


def _verify_exact_replacement(
    transaction: ReplacementTransaction,
    *,
    expected_data: bytes,
    expected_mode: int,
    max_bytes: int,
    label: str,
) -> FileSnapshot:
    installed = _read_owned_regular_file(
        transaction.path,
        max_bytes=max_bytes,
        label=label,
    )
    if installed != transaction.new_snapshot:
        raise SetupError(f"{label} changed after atomic replacement")
    if installed.data != expected_data:
        raise SetupError(f"{label} did not match the exact requested payload")
    if stat.S_IMODE(installed.binding.mode) != expected_mode:
        raise SetupError(f"{label} did not retain the exact requested access mode")
    return installed


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
    _verify_exact_replacement(
        transaction,
        expected_data=desired,
        expected_mode=mode,
        max_bytes=MAX_CONFIG_BYTES,
        label="managed Git exclusion",
    )
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
        changed=(
            installed is None
            or installed.data != source.data
            or stat.S_IMODE(installed.binding.mode) != LAUNCH_AGENT_MODE
        ),
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
        if stat.S_IMODE(installed.binding.mode) != LAUNCH_AGENT_MODE:
            raise SetupError(
                f"installed {plan.spec.key} LaunchAgent no longer has mode {LAUNCH_AGENT_MODE:#06o}"
            )


def _install_plist(
    plan: PlannedLaunchAgent,
    file_ops: FileOps,
    journal: MutationJournal,
) -> FileSnapshot:
    spec = plan.spec
    if not plan.changed:
        assert plan.installed is not None
        if stat.S_IMODE(plan.installed.binding.mode) != LAUNCH_AGENT_MODE:
            raise SetupError(
                f"unchanged {spec.key} LaunchAgent lacks mode {LAUNCH_AGENT_MODE:#06o}"
            )
        return plan.installed
    transaction = file_ops.begin_replace(
        spec.destination,
        plan.source.data,
        mode=LAUNCH_AGENT_MODE,
        expected=plan.installed,
        max_bytes=MAX_CONFIG_BYTES,
    )
    journal.add_file(transaction)
    installed = _read_owned_regular_file(
        spec.destination,
        max_bytes=MAX_CONFIG_BYTES,
        label=f"installed {spec.key} LaunchAgent",
    )
    if (
        installed != transaction.new_snapshot
        or installed.data != plan.source.data
        or stat.S_IMODE(installed.binding.mode) != LAUNCH_AGENT_MODE
    ):
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
    return _verify_exact_replacement(
        transaction,
        expected_data=desired,
        expected_mode=0o600,
        max_bytes=MAX_CONFIG_BYTES,
        label="LaunchAgent reload receipt",
    )


def _bind_helper_git_topology(
    manifest: WorkspaceManifest,
    *,
    allow_missing: bool,
) -> tuple[GitTopologyGuard, ...]:
    guards: list[GitTopologyGuard] = []
    for repo in manifest.repos:
        repository = manifest.repo_path(repo)
        occupancy = _directory_check(
            repository,
            name=f"helper topology repository {repo.name}",
            missing_status="missing",
        )
        if occupancy.status == "ready":
            guard = _inspect_git_topology_replacements(
                repository,
                allow_managed_hooks_path=True,
            )
            _default_mirror_index_snapshot(repository)
            guards.append(guard)
            continue
        if occupancy.status == "missing" and allow_missing:
            guards.append(
                GitTopologyGuard(
                    repository=repository,
                    repository_binding=None,
                    git_dir_binding=None,
                    objects_binding=None,
                    objects_info_binding=None,
                    refs_binding=None,
                    info_binding=None,
                    hooks_binding=None,
                    managed_hook_snapshots=None,
                    local_config_snapshot=None,
                    worktree_config_absent=None,
                    alternate_object_sources_absent=None,
                )
            )
            continue
        raise SetupError(occupancy.detail)
    return tuple(guards)


def _revalidate_helper_git_topology(guards: Sequence[GitTopologyGuard]) -> None:
    for guard in guards:
        occupancy = _directory_check(
            guard.repository,
            name="helper topology repository revalidation",
            missing_status="missing",
        )
        if guard.repository_binding is None:
            if occupancy.status == "missing":
                continue
            if occupancy.status != "ready":
                raise SetupError(occupancy.detail)
            _inspect_git_topology_replacements(
                guard.repository,
                allow_managed_hooks_path=True,
            )
            _default_mirror_index_snapshot(guard.repository)
            continue
        if occupancy.status != "ready":
            raise SetupError(
                f"Git topology repository changed during helper invocation: {guard.repository}; "
                f"{occupancy.detail}"
            )
        _inspect_git_topology_replacements(
            guard.repository,
            expected=guard,
            allow_managed_hooks_path=True,
        )
        _default_mirror_index_snapshot(guard.repository)


def _revalidate_workspace_manifest(manifest: WorkspaceManifest, *, phase: str) -> None:
    current = _read_owned_regular_file(
        manifest.path,
        max_bytes=MAX_CONFIG_BYTES,
        label=f"{phase} workspace manifest",
    )
    if current != manifest.snapshot:
        raise SetupError(f"workspace manifest changed {phase}: {manifest.path}")


def _run_helper(
    config: HostConfig,
    manifest: WorkspaceManifest,
    arguments: Sequence[str],
    runner: CommandRunner,
) -> subprocess.CompletedProcess[str]:
    _revalidate_workspace_manifest(manifest, phase="before delegated helper")
    topology_guards = _bind_helper_git_topology(
        manifest,
        allow_missing=bool(arguments) and arguments[0] == "ensure",
    )
    try:
        runner.bind_current_interpreter(config)
        helper_snapshot = runner.bind_workspace_helper(config)
        argv = [
            str(config.python_executable),
            *PYTHON_ISOLATION_FLAGS,
            str(config.workspace_helper),
            "--config",
            str(manifest.path),
            *arguments,
        ]
        return runner.run_python_source(
            argv,
            source=helper_snapshot,
            source_path=config.workspace_helper,
            cwd=config.workspace_root,
            env=_git_environment(disable_hooks=True),
            workspace_manifest=manifest,
        )
    finally:
        try:
            _revalidate_workspace_manifest(manifest, phase="after delegated helper")
        finally:
            try:
                runner.revalidate_helper_runtime(config)
            finally:
                _revalidate_helper_git_topology(topology_guards)


def _run_ensure(config: HostConfig, runner: CommandRunner) -> None:
    control_manifest = WorkspaceManifest(
        path=config.path,
        cache_root=config.cache_root,
        repos=(config.control_repo,),
        retired_repo_names=(),
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
        result = _run_helper(config, manifest, ["ensure"], runner)
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
            manifest,
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
    _verify_exact_replacement(
        transaction,
        expected_data=captured.canonical_payload,
        expected_mode=0o600,
        max_bytes=MAX_STAMP_BYTES,
        label=f"{captured.canonical_stamp} canonical stamp",
    )


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
    global_checks = [_check_python(config, runner), _check_workspace_helper(config, runner)]
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
    prechecks = [_check_python(config, runner), _check_workspace_helper(config, runner)]
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
        _verify_exact_replacement(
            transaction,
            expected_data=payload,
            expected_mode=0o600,
            max_bytes=MAX_STAMP_BYTES,
            label="weekly pair receipt",
        )
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
    result = runner.run(argv, env=_trusted_process_environment())
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
                [LAUNCHCTL_EXECUTABLE, "bootout", _launchctl_service(spec.label)],
                action=f"launchctl bootout {spec.label}",
            )
        touched.add(spec.label)
        _launchctl_command(
            runner,
            [
                LAUNCHCTL_EXECUTABLE,
                "bootstrap",
                f"gui/{os.getuid()}",
                str(spec.destination),
            ],
            action=f"launchctl bootstrap {spec.label}",
        )
        verified = _query_service(spec.label, runner)
        _require_loaded_definition(
            spec,
            verified,
            spec.expected,
            action="launchctl bootstrap",
        )


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
                    [LAUNCHCTL_EXECUTABLE, "bootout", _launchctl_service(spec.label)],
                    action=f"rollback bootout {spec.label}",
                )
            if original[spec.label].loaded:
                _launchctl_command(
                    runner,
                    [
                        LAUNCHCTL_EXECUTABLE,
                        "bootstrap",
                        f"gui/{os.getuid()}",
                        str(spec.destination),
                    ],
                    action=f"rollback bootstrap {spec.label}",
                )
                snapshot = original[spec.label].plist_snapshot
                if snapshot is None:
                    raise SetupError(f"rollback lacks the prior plist: {spec.label}")
                expected = _load_plist(snapshot.data, label="rollback LaunchAgent")
                _require_loaded_definition(
                    spec,
                    _query_service(spec.label, runner),
                    expected,
                    action="rollback bootstrap",
                )
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
        _check_workspace_helper(config, runner),
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
        retired_repo_names=(),
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
    path_checks = _git_admin_path_checks(
        config.workspace_root,
        prefix="workspace",
        allow_worktree_config=True,
    )
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
        installed_definition = _load_plist(
            installed.data,
            label=f"installed {spec.key} LaunchAgent",
        )
        try:
            _require_loaded_definition(
                spec,
                original[spec.label],
                installed_definition,
                action="launchctl preflight",
            )
        except SetupError as error:
            raise SetupError(
                f"cannot safely restore loaded service with a foreign definition: "
                f"{spec.label}; {error}"
            ) from error
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
