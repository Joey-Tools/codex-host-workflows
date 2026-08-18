from __future__ import annotations

import datetime as dt
import errno
import hashlib
import json
import os
import plistlib
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts import host_setup as hs  # noqa: E402


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    )
    return result.stdout.strip()


def _init_bare(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "--bare", str(path)],
        check=True,
        text=True,
        capture_output=True,
    )


def _commit_and_push(repository: Path, remote: Path, message: str = "fixture") -> None:
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Host Setup Test",
        "-c",
        "user.email=host-setup@example.invalid",
        "commit",
        "-m",
        message,
    )
    if not _git(repository, "remote"):
        _git(repository, "remote", "add", "origin", str(remote))
    _git(repository, "push", "-u", "origin", "master")


def _init_mirror(path: Path, remote: Path, files: dict[str, bytes]) -> None:
    path.mkdir(parents=True)
    _git(path, "init", "-b", "master")
    for relative, data in files.items():
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        if relative.endswith(".py"):
            target.chmod(0o755)
    _commit_and_push(path, remote)


def _forge_divergence_as_behind(
    mirror: Path,
    remote: Path,
    updater: Path,
    mechanism: str,
) -> tuple[str, str]:
    mirror.joinpath("local-only.txt").write_text("local\n", encoding="utf-8")
    _git(mirror, "add", "local-only.txt")
    _git(
        mirror,
        "-c",
        "user.name=Host Setup Test",
        "-c",
        "user.email=host-setup@example.invalid",
        "commit",
        "-m",
        "local divergence",
    )
    subprocess.run(
        ["git", "clone", str(remote), str(updater)],
        check=True,
        text=True,
        capture_output=True,
    )
    updater.joinpath("remote-only.txt").write_text("remote\n", encoding="utf-8")
    _commit_and_push(updater, remote, "remote divergence")
    _git(mirror, "fetch", "origin")
    local_head = _git(mirror, "rev-parse", "HEAD")
    remote_head = _git(mirror, "rev-parse", "@{u}")

    if mechanism == "graft":
        mirror.joinpath(".git", "info", "grafts").write_text(
            f"{remote_head} {local_head}\n",
            encoding="ascii",
        )
    else:
        remote_tree = _git(mirror, "rev-parse", f"{remote_head}^{{tree}}")
        replacement = _git(
            mirror,
            "-c",
            "user.name=Host Setup Test",
            "-c",
            "user.email=host-setup@example.invalid",
            "commit-tree",
            remote_tree,
            "-p",
            local_head,
            "-m",
            "forged replacement topology",
        )
        _git(mirror, "replace", remote_head, replacement)
        if mechanism == "packed-replace":
            _git(mirror, "pack-refs", "--all", "--prune")
            replace_dir = mirror / ".git" / "refs" / "replace"
            if replace_dir.is_dir():
                replace_dir.rmdir()

    assert _git(mirror, "rev-list", "--left-right", "--count", "HEAD...@{u}").split() == [
        "0",
        "1",
    ]
    return local_head, remote_head


class FakeRunner(hs.CommandRunner):
    def __init__(
        self,
        *,
        on_helper: Callable[[list[str]], None] | None = None,
        helper_failures: dict[str, int] | None = None,
        launch_failures: dict[tuple[str, str], list[int]] | None = None,
        print_error: int | None = None,
    ) -> None:
        super().__init__()
        self.calls: list[tuple[list[str], Path | None]] = []
        self.environments: list[dict[str, str] | None] = []
        self.on_helper = on_helper
        self.helper_failures = helper_failures or {}
        self.launch_failures = launch_failures or {}
        self.loaded: dict[str, bool] = {}
        self.loaded_definitions: dict[str, tuple[Path, dict[str, Any]]] = {}
        self.print_error = print_error
        self.extra_print_scalars: list[str] = []
        self.extra_event_triggers: list[str] = []
        self.minimum_runtime = 10
        self.exit_timeout = 5
        self.spawn_type = "daemon (3)"
        self.properties = "inferred program | needs LWCR update | managed LWCR"
        self.trigger_keepalive = "0"

    def load_plist(self, path: Path) -> None:
        parsed = plistlib.loads(path.read_bytes())
        assert isinstance(parsed, dict)
        label = parsed["Label"]
        assert isinstance(label, str)
        self.loaded[label] = True
        self.loaded_definitions[label] = (path, parsed)

    def _print_definition(self, label: str) -> str:
        path, definition = self.loaded_definitions[label]
        arguments = definition["ProgramArguments"]
        environment = definition["EnvironmentVariables"]
        configured_intervals = definition["StartCalendarInterval"]
        intervals = (
            configured_intervals
            if isinstance(configured_intervals, list)
            else [configured_intervals]
        )
        lines = [
            f"gui/{os.getuid()}/{label} = {{",
            "\tactive count = 0",
            f"\tpath = {path}",
            "\ttype = LaunchAgent",
            "\tstate = not running",
            "",
            f"\tprogram = {arguments[0]}",
            "\targuments = {",
            *(f"\t\t{argument}" for argument in arguments),
            "\t}",
            "",
            f"\tworking directory = {definition['WorkingDirectory']}",
            "",
            f"\tstdout path = {definition['StandardOutPath']}",
            f"\tstderr path = {definition['StandardErrorPath']}",
            "\tenvironment = {",
            "\t\tOSLogRateLimit => 64",
            *(f"\t\t{key} => {value}" for key, value in environment.items()),
            f"\t\tXPC_SERVICE_NAME => {label}",
            "\t}",
            "",
            f"\tminimum runtime = {self.minimum_runtime}",
            f"\texit timeout = {self.exit_timeout}",
            *self.extra_print_scalars,
            "",
            "\tevent triggers = {",
        ]
        for index, interval in enumerate(intervals, start=1):
            lines.extend(
                [
                    f"\t\t{label}.{index} => {{",
                    f"\t\t\tkeepalive = {self.trigger_keepalive}",
                    f"\t\t\tservice = {label}",
                    "\t\t\tstream = com.apple.launchd.calendarinterval",
                    "\t\t\tmonitor = com.apple.UserEventAgent-Aqua",
                    "\t\t\tdescriptor = {",
                    *(f'\t\t\t\t"{key}" => {value}' for key, value in interval.items()),
                    "\t\t\t}",
                    "\t\t}",
                ]
            )
        lines.extend(
            [
                *self.extra_event_triggers,
                "\t}",
                "",
                "\tevent channels = {",
                '\t\t"com.apple.launchd.calendarinterval" = {',
                "\t\t\tport = 0x0",
                "\t\t\tactive = 0",
                "\t\t\tmanaged = 1",
                "\t\t\treset = 0",
                "\t\t\thide = 0",
                "\t\t\twatching = 1",
                "\t\t}",
                "\t}",
                "",
                f"\tspawn type = {self.spawn_type}",
                "\tjetsam priority = 40",
                "\tjetsam memory limit (active) = (unlimited)",
                "\tjetsam memory limit (inactive) = (unlimited)",
                "\tjetsamproperties category = daemon",
                "\tjetsam thread limit = 32",
                "\tcpumon = default",
                "",
                f"\tproperties = {self.properties}",
                "}",
            ]
        )
        return "\n".join(lines) + "\n"

    def _launch_result(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        action = args[1]
        if action == "print":
            label = args[2].rsplit("/", 1)[-1]
            if self.print_error is not None:
                return subprocess.CompletedProcess(
                    args, self.print_error, "", "launchctl transport failure"
                )
            if self.loaded.get(label, False):
                output = self._print_definition(label)
                return subprocess.CompletedProcess(args, 0, output, "")
            return subprocess.CompletedProcess(args, 113, "", "Could not find service")
        label = Path(args[-1]).stem if action == "bootstrap" else args[2].rsplit("/", 1)[-1]
        failures = self.launch_failures.get((action, label), [])
        if failures:
            code = failures.pop(0)
            if code:
                return subprocess.CompletedProcess(args, code, "", f"{action} failed")
        if action == "bootstrap":
            self.load_plist(Path(args[-1]))
        else:
            self.loaded[label] = False
        return subprocess.CompletedProcess(args, 0, "", "")

    def bind_current_interpreter(self, config: hs.HostConfig) -> hs.CurrentInterpreterBinding:
        snapshot = hs._read_owned_regular_file(
            config.python_executable,
            max_bytes=256 * 1024 * 1024,
            label="Python executable",
        )
        if not snapshot.binding.mode & 0o111:
            raise hs.SetupError("Python executable has no executable bit")
        return self._remember_current_interpreter(
            hs.CurrentInterpreterBinding(
                executable=config.python_executable,
                version=(3, 14, 2),
                nominal_snapshot=snapshot,
            )
        )

    def run_python_source(
        self,
        argv: Sequence[str],
        *,
        source: hs.FileSnapshot,
        source_path: Path,
        cwd: Path,
        env: Mapping[str, str],
        workspace_manifest: hs.WorkspaceManifest | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = list(argv)
        assert Path(args[4]) == source_path
        assert source.data
        assert workspace_manifest is not None
        self.calls.append((args, cwd))
        self.environments.append(dict(env))
        command = next((name for name in ("ensure", "prefetch", "status") if name in args), None)
        assert command is not None
        if self.on_helper is not None:
            self.on_helper(args)
        code = self.helper_failures.get(command, 0)
        if command == "prefetch" and "--stamp" in args:
            stamp = args[args.index("--stamp") + 1]
            for configured_stamp, configured_code in self.helper_failures.items():
                if stamp == configured_stamp or stamp.startswith(f"{configured_stamp}-run-"):
                    code = configured_code
                    break
        return subprocess.CompletedProcess(args, code, "", "helper failed" if code else "")

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = list(argv)
        self.calls.append((args, cwd))
        self.environments.append(dict(env) if env is not None else None)
        if args[1:] == [*hs.PYTHON_ISOLATION_FLAGS, "--version"]:
            return subprocess.CompletedProcess(args, 0, "Python 3.14.2\n", "")
        if args and args[0] == hs.LAUNCHCTL_EXECUTABLE:
            return self._launch_result(args)
        command = next((name for name in ("ensure", "prefetch", "status") if name in args), None)
        if command is not None:
            if self.on_helper is not None:
                self.on_helper(args)
            code = self.helper_failures.get(command, 0)
            if command == "prefetch" and "--stamp" in args:
                stamp = args[args.index("--stamp") + 1]
                for configured_stamp, configured_code in self.helper_failures.items():
                    if stamp == configured_stamp or stamp.startswith(f"{configured_stamp}-run-"):
                        code = configured_code
                        break
            return subprocess.CompletedProcess(args, code, "", "helper failed" if code else "")
        return subprocess.CompletedProcess(args, 0, "", "")


class ForkTestRunner(hs.CommandRunner):
    """Exercise the real fork supervisor from this non-isolated pytest process."""

    def bind_current_interpreter(self, config: hs.HostConfig) -> hs.CurrentInterpreterBinding:
        snapshot = hs._read_owned_regular_file(
            config.python_executable,
            max_bytes=256 * 1024 * 1024,
            label="Python executable",
        )
        if not snapshot.binding.mode & 0o111:
            raise hs.SetupError("Python executable has no executable bit")
        return self._remember_current_interpreter(
            hs.CurrentInterpreterBinding(
                executable=config.python_executable,
                version=(sys.version_info.major, sys.version_info.minor, sys.version_info.micro),
                nominal_snapshot=snapshot,
            )
        )


def _manifest_text(
    workspace: Path,
    cache_root: Path,
    python: Path,
    control_remote: Path,
    *,
    weekly_source: str = "launchd/com.hoteng.codex.daily-skill-friction-weekly-prefetch.plist",
) -> str:
    return f'''version = 1
cache_root = "{cache_root}"

[host_setup]
workspace_root = "{workspace}"
account_home = "{workspace.parent / "home"}"
python_executable = "{python}"
control_repo = "codex-host-workflows"
skill_relative_path = ".agents/skills/daily-skill-friction"
locator_relative_path = ".agents/skills/daily-skill-friction"
launch_agent_label = "com.hoteng.codex.daily-skill-friction-control-prefetch"
launch_agent_source = "launchd/com.hoteng.codex.daily-skill-friction-control-prefetch.plist"
weekly_launch_agent_label = "com.hoteng.codex.daily-skill-friction-weekly-prefetch"
weekly_launch_agent_source = "{weekly_source}"
control_stamp = "daily-skill-friction-control"
main_stamp = "daily-skill-friction"
weekly_pair_receipt = "daily-skill-friction-weekly-pair"
prefetch_hour = 2
prefetch_minute = 45
weekly_prefetch_weekday = 5
weekly_prefetch_hour = 6
weekly_prefetch_minute = 30
default_max_age_minutes = 60

[[repos]]
name = "codex-host-workflows"
url = "{control_remote}"
default_branch = "master"
visibility = "private"
'''


def _plist_bytes(config: hs.HostConfig, key: str) -> bytes:
    raw = plistlib.dumps(hs.desired_launch_agent(config, key), sort_keys=False)
    marker = b"<!-- " + hs.MANAGED_PLIST_MARKER + b" -->\n"
    return raw.replace(b'<plist version="1.0">\n', marker + b'<plist version="1.0">\n', 1)


@dataclass
class HostFixture:
    config: hs.HostConfig
    home: Path
    workspace: Path
    control_source: Path
    control_remote: Path


def _build_host(tmp_path: Path, *, empty_host: bool = True) -> HostFixture:
    control_source = tmp_path / "control-source"
    workspace = tmp_path / "workspace"
    home = tmp_path / "home"
    cache_root = workspace / ".codex-local" / "daily-skill-friction"
    control_remote = tmp_path / "remotes" / "codex-host-workflows.git"
    python = tmp_path / "runtime" / "python3.14"
    python.parent.mkdir(parents=True)
    python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    python.chmod(0o755)
    home.mkdir()
    if not empty_host:
        (home / "Library" / "LaunchAgents").mkdir(parents=True)

    workspace.mkdir()
    _git(workspace, "init", "-b", "master")
    (workspace / "scripts").mkdir()
    helper = workspace / "scripts" / "codex_workspace.py"
    helper.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    helper.chmod(0o755)
    (workspace / ".gitignore").write_text(".codex-local/\n", encoding="utf-8")

    main_specs: list[str] = []
    for name in ("alpha", "beta"):
        remote = tmp_path / "remotes" / f"{name}.git"
        _init_bare(remote)
        _init_mirror(
            cache_root / "repos" / name,
            remote,
            {"README.md": f"# {name}\n".encode()},
        )
        main_specs.append(
            f'''[[repos]]
name = "{name}"
url = "{remote}"
default_branch = "master"
visibility = "private"
'''
        )
    (workspace / "workspace.toml").write_text(
        f'''version = 1
cache_root = "{cache_root}"

{"".join(main_specs)}''',
        encoding="utf-8",
    )
    _git(workspace, "add", ".")
    _git(
        workspace,
        "-c",
        "user.name=Host Setup Test",
        "-c",
        "user.email=host-setup@example.invalid",
        "commit",
        "-m",
        "workspace fixture",
    )

    _init_bare(control_remote)
    manifest = control_source / "config" / "host-workspace.toml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        _manifest_text(workspace, cache_root, python, control_remote), encoding="utf-8"
    )
    config = hs.load_config(manifest)
    control_files = {
        "config/host-workspace.toml": manifest.read_bytes(),
        ".agents/skills/daily-skill-friction/SKILL.md": b"---\nname: daily-skill-friction\n---\n",
        "scripts/host_setup.py": b"#!/usr/bin/env python3\n",
        str(config.launch_agent_source_relative_path): _plist_bytes(config, "control"),
        str(config.weekly_launch_agent_source_relative_path): _plist_bytes(config, "weekly"),
    }
    for relative, data in control_files.items():
        target = control_source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    _init_mirror(config.control_mirror, control_remote, control_files)
    return HostFixture(config, home, workspace, control_source, control_remote)


def _active(fixture: HostFixture) -> hs.HostConfig:
    return hs.load_config(fixture.config.control_mirror_manifest)


def _write_bound_helper_fixture(path: Path, *, loaded_marker: Path | None = None) -> None:
    marker_statement = (
        f"    Path({str(loaded_marker)!r}).write_text('loaded', encoding='utf-8')\n"
        if loaded_marker is not None
        else ""
    )
    path.write_text(
        "from __future__ import annotations\n"
        "import dataclasses\n"
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        "class WorkspaceError(RuntimeError):\n"
        "    pass\n"
        "MIRROR_GUARD_HOOKS = ('pre-commit',)\n"
        "@dataclasses.dataclass(frozen=True)\n"
        "class RepoSpec:\n"
        "    name: str\n"
        "    url: str\n"
        "    default_branch: str\n"
        "    visibility: str\n"
        "@dataclasses.dataclass(frozen=True)\n"
        "class WorkspaceConfig:\n"
        "    root: Path\n"
        "    cache_root: Path\n"
        "    repos: tuple[RepoSpec, ...]\n"
        "    def repo_path(self, repo: RepoSpec) -> Path:\n"
        "        return self.cache_root / 'repos' / repo.name\n"
        "def load_config(path: Path) -> WorkspaceConfig:\n"
        "    raise AssertionError(f'disk manifest loader ran: {path}')\n"
        "def git_common_dir(mirror: Path) -> Path:\n"
        "    return mirror / '.git'\n"
        "def mirror_guard_hook(mirror: Path) -> str:\n"
        "    return f'guard:{mirror}\\n'\n"
        "def mirror_guard_path(mirror: Path, hook_name: str) -> Path:\n"
        "    return mirror / '.git' / 'hooks' / hook_name\n"
        "def install_mirror_guard(config: WorkspaceConfig, repo: RepoSpec) -> None:\n"
        "    raise AssertionError('unbound installer ran')\n"
        "def main(argv: list[str] | None = None) -> int:\n"
        "    args = list(sys.argv[1:] if argv is None else argv)\n"
        "    config_path = Path(args[args.index('--config') + 1])\n"
        "    config = load_config(config_path)\n"
        f"{marker_statement}"
        "    if 'ensure' in args:\n"
        "        for repo in config.repos:\n"
        "            install_mirror_guard(config, repo)\n"
        "    print(json.dumps({\n"
        "        'root': str(config.root),\n"
        "        'cache_root': str(config.cache_root),\n"
        "        'repos': [dataclasses.asdict(repo) for repo in config.repos],\n"
        "    }, sort_keys=True))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n"
        "    raise SystemExit(main())\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _apply_ready(fixture: HostFixture, runner: FakeRunner | None = None) -> dict[str, object]:
    return hs.apply_setup(
        fixture.config,
        fixture.home,
        runner or FakeRunner(),
        ensure=False,
        no_launchctl=False,
    )


def _load_installed_services(
    runner: FakeRunner,
    config: hs.HostConfig,
    home: Path,
) -> None:
    for spec in hs._launch_agent_specs(config, home):
        runner.load_plist(spec.destination)


def _write_stamp(
    config: hs.HostConfig,
    runner: FakeRunner,
    *,
    stamp_name: str,
    manifest_path: Path,
    now: dt.datetime,
    age_minutes: int = 5,
    failed_repo: str | None = None,
) -> Path:
    manifest = hs.load_workspace_manifest(
        manifest_path,
        label=f"{stamp_name} test manifest",
        expected_cache_root=config.cache_root,
    )
    snapshots = hs.manifest_snapshots(config, manifest, runner)
    ended = now - dt.timedelta(minutes=age_minutes)
    started = ended - dt.timedelta(minutes=2)
    entries = {
        repo.name: {
            "name": repo.name,
            "status": "blocked" if repo.name == failed_repo else "ready",
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "ended_at": ended.isoformat().replace("+00:00", "Z"),
            **snapshots[repo.name],
        }
        for repo in manifest.repos
    }
    payload = {
        "version": 1,
        "stamp": stamp_name,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "ended_at": ended.isoformat().replace("+00:00", "Z"),
        "workspace_root": str(manifest.path.parent),
        "cache_root": str(config.cache_root),
        "repos": entries,
    }
    path = config.cache_root / "freshness" / f"{stamp_name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _write_both_stamps(
    config: hs.HostConfig,
    runner: FakeRunner,
    now: dt.datetime,
    *,
    age_minutes: int = 5,
) -> tuple[Path, Path]:
    return (
        _write_stamp(
            config,
            runner,
            stamp_name=config.control_stamp,
            manifest_path=config.control_mirror_manifest,
            now=now,
            age_minutes=age_minutes,
        ),
        _write_stamp(
            config,
            runner,
            stamp_name=config.main_stamp,
            manifest_path=config.main_manifest,
            now=now,
            age_minutes=age_minutes,
        ),
    )


def _prefetch_writer(config: hs.HostConfig, runner: FakeRunner, now: dt.datetime) -> None:
    def write(args: list[str]) -> None:
        if "prefetch" not in args:
            return
        _write_stamp(
            config,
            runner,
            stamp_name=args[args.index("--stamp") + 1],
            manifest_path=Path(args[args.index("--config") + 1]),
            now=now,
            age_minutes=0,
        )

    runner.on_helper = write


def _check(report: dict[str, object], name: str) -> dict[str, str]:
    return next(item for item in report["checks"] if item["name"] == name)  # type: ignore[index,return-value]


def test_production_manifest_and_both_launch_agents_are_exact() -> None:
    config = hs.load_config(REPO_ROOT / "config" / "host-workspace.toml")
    assert config.cache_root == Path(
        "/Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction"
    )
    assert config.account_home == Path("/Users/hoteng")
    assert config.skill_relative_path == Path(".agents/skills/daily-skill-friction")
    assert config.python_executable == Path(
        "/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14"
    )
    assert config.weekly_prefetch_weekday == 5
    assert (config.weekly_prefetch_hour, config.weekly_prefetch_minute) == (6, 30)
    for key, source in (
        ("control", config.launch_agent_source),
        ("weekly", config.weekly_launch_agent_source),
    ):
        parsed = plistlib.loads(source.read_bytes())
        assert parsed == hs.desired_launch_agent(config, key)
        assert "ensure" not in parsed["ProgramArguments"]
        assert "clone" not in parsed["ProgramArguments"]
        assert parsed["EnvironmentVariables"] == {"PATH": hs.TRUSTED_SYSTEM_PATH}
        assert parsed["ProgramArguments"][:6] == [
            hs.SHELL_EXECUTABLE,
            hs.SHELL_PRIVILEGED_FLAG,
            "-c",
            hs.LAUNCH_ENV_COMMAND,
            hs.LAUNCH_ENV_ARG0,
            str(config.account_home),
        ]
        assert list(hs.PYTHON_ISOLATION_FLAGS) == parsed["ProgramArguments"][7:10]
    weekly = hs.desired_launch_agent(config, "weekly")
    control = hs.desired_launch_agent(config, "control")
    assert control["ProgramArguments"][-1] == "prefetch-control"
    assert weekly["ProgramArguments"][-1] == "prefetch-weekly"
    assert weekly["StartCalendarInterval"] == {"Weekday": 5, "Hour": 6, "Minute": 30}


def test_empty_host_apply_is_idempotent_and_preserves_shared_prefetch(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    fixture.home.joinpath("Library", "LaunchAgents").mkdir(parents=True)
    shared = fixture.home / "Library" / "LaunchAgents" / "shared-0250.plist"
    shared.write_bytes(b"shared\n")
    first = _apply_ready(fixture)
    active = _active(fixture)
    before = {
        "locator": (active.skill_locator.lstat().st_ino, os.readlink(active.skill_locator)),
        "exclude": (hs._exclude_path(active).stat().st_ino, hs._exclude_path(active).read_bytes()),
        "plists": {
            spec.key: (spec.destination.stat().st_ino, spec.destination.read_bytes())
            for spec in hs._launch_agent_specs(active, fixture.home)
        },
        "shared": (shared.stat().st_ino, shared.read_bytes()),
    }
    second = _apply_ready(fixture)
    assert first["status"] == second["status"] == "ready"
    assert second["changes"] == []
    assert (active.skill_locator.lstat().st_ino, os.readlink(active.skill_locator)) == before[
        "locator"
    ]
    assert (
        hs._exclude_path(active).stat().st_ino,
        hs._exclude_path(active).read_bytes(),
    ) == before["exclude"]
    assert (shared.stat().st_ino, shared.read_bytes()) == before["shared"]
    for spec in hs._launch_agent_specs(active, fixture.home):
        assert (spec.destination.stat().st_ino, spec.destination.read_bytes()) == before["plists"][
            spec.key
        ]


def test_launch_agent_clean_launcher_drops_inherited_tool_control_environment(
    tmp_path: Path,
) -> None:
    config = hs.load_config(REPO_ROOT / "config" / "host-workspace.toml")
    launch_arguments = hs.desired_launch_agent(config, "control")["ProgramArguments"]
    python_index = launch_arguments.index(str(config.python_executable))
    startup_marker = tmp_path / "shell-startup-ran"
    hostile_startup = tmp_path / "hostile-shell-startup"
    hostile_startup.write_text(
        f'#!/bin/sh\n/usr/bin/touch "{startup_marker}"\n',
        encoding="utf-8",
    )
    hostile_environment = {
        **os.environ,
        "PATH": "/tmp/hostile-path",
        "HOME": "/tmp/hostile-home",
        "SSH_AUTH_SOCK": "/tmp/test-agent.sock",
        "PYTHONHOME": "/tmp/hostile-python-home",
        "PYTHONPATH": "/tmp/hostile-python-path",
        "DYLD_INSERT_LIBRARIES": "/tmp/hostile-inject.dylib",
        "GIT_EXEC_PATH": "/tmp/hostile-git-exec",
        "BASH_ENV": str(hostile_startup),
        "ENV": str(hostile_startup),
        "BASH_FUNC_[%%": f'() {{ /usr/bin/touch "{startup_marker}"; return 1; }}',
    }
    probe = (
        "import json, os, sys; "
        "print(json.dumps({'environment': dict(os.environ), "
        "'isolated': sys.flags.isolated, 'no_site': sys.flags.no_site, "
        "'no_user_site': sys.flags.no_user_site}))"
    )
    result = subprocess.run(
        [
            *launch_arguments[:python_index],
            sys.executable,
            *hs.PYTHON_ISOLATION_FLAGS,
            "-c",
            probe,
        ],
        check=True,
        text=True,
        capture_output=True,
        env=hostile_environment,
    )
    observed = json.loads(result.stdout)
    environment = observed["environment"]
    assert environment["PATH"] == hs.TRUSTED_SYSTEM_PATH
    assert environment["HOME"] == str(config.account_home)
    assert environment["LANG"] == hs.TRUSTED_LOCALE
    assert environment["TMPDIR"] == hs.TRUSTED_TMPDIR
    assert environment["SSH_AUTH_SOCK"] == "/tmp/test-agent.sock"
    assert not startup_marker.exists()
    assert observed["isolated"] == 1
    assert observed["no_site"] == 1
    assert observed["no_user_site"] == 1
    for hostile_key in (
        "PYTHONHOME",
        "PYTHONPATH",
        "DYLD_INSERT_LIBRARIES",
        "GIT_EXEC_PATH",
        "BASH_ENV",
        "ENV",
    ):
        assert hostile_key not in environment


def test_foreign_locator_and_launch_agent_fail_closed(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    active.skill_locator.unlink()
    active.skill_locator.symlink_to("../../foreign")
    with pytest.raises(hs.SetupError, match="foreign locator|foreign symlink"):
        _apply_ready(fixture)
    active.skill_locator.unlink()
    active.skill_locator.symlink_to(hs.desired_locator_target(active))
    spec = hs._launch_agent_specs(active, fixture.home)[0]
    spec.destination.write_text("foreign\n", encoding="utf-8")
    with pytest.raises(hs.SetupError, match="foreign LaunchAgent"):
        _apply_ready(fixture)


def test_no_ensure_fails_and_explicit_ensure_prefetches_immediately(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    shutil.rmtree(fixture.config.control_mirror)
    with pytest.raises(hs.SetupError, match="--ensure"):
        _apply_ready(fixture)
    now = dt.datetime(2026, 8, 17, 6, 30, tzinfo=dt.UTC)
    runner = FakeRunner()

    def helper(args: list[str]) -> None:
        if "ensure" in args and not fixture.config.control_mirror.exists():
            subprocess.run(
                ["git", "clone", str(fixture.control_remote), str(fixture.config.control_mirror)],
                check=True,
                text=True,
                capture_output=True,
            )
        elif "prefetch" in args:
            active = _active(fixture)
            _write_stamp(
                active,
                runner,
                stamp_name=args[args.index("--stamp") + 1],
                manifest_path=Path(args[args.index("--config") + 1]),
                now=now,
                age_minutes=0,
            )

    runner.on_helper = helper
    report = hs.apply_setup(
        fixture.config,
        fixture.home,
        runner,
        ensure=True,
        no_launchctl=False,
        now=now,
    )
    assert report["status"] == "ready"
    assert report["initial_prefetch"]["receipt_updated"] is True
    prefetch_calls = [args for args, _cwd in runner.calls if "prefetch" in args]
    assert len(prefetch_calls) == 2


def test_explicit_ensure_prefetches_a_clean_behind_main_mirror(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    main_manifest = hs._load_main_manifest(active)
    alpha = main_manifest.repos[0]
    updater = tmp_path / "alpha-updater"
    subprocess.run(
        ["git", "clone", alpha.url, str(updater)],
        check=True,
        text=True,
        capture_output=True,
    )
    updater.joinpath("README.md").write_text("# alpha updated\n", encoding="utf-8")
    _git(updater, "add", "README.md")
    _git(
        updater,
        "-c",
        "user.name=Host Setup Test",
        "-c",
        "user.email=host-setup@example.invalid",
        "commit",
        "-m",
        "remote update",
    )
    _git(updater, "push", "origin", "master")
    now = dt.datetime(2026, 8, 17, 6, 30, tzinfo=dt.UTC)
    runner = FakeRunner()

    def helper(args: list[str]) -> None:
        if "prefetch" not in args:
            return
        manifest_path = Path(args[args.index("--config") + 1])
        manifest = hs.load_workspace_manifest(
            manifest_path,
            label="prefetch fixture manifest",
            expected_cache_root=active.cache_root,
        )
        for repo in manifest.repos:
            mirror = manifest.repo_path(repo)
            _git(mirror, "fetch", "origin")
            _git(mirror, "merge", "--ff-only", "@{u}")
        _write_stamp(
            active,
            runner,
            stamp_name=args[args.index("--stamp") + 1],
            manifest_path=manifest_path,
            now=now,
            age_minutes=0,
        )

    runner.on_helper = helper
    report = hs.apply_setup(
        fixture.config,
        fixture.home,
        runner,
        ensure=True,
        no_launchctl=False,
        now=now,
    )
    assert report["status"] == "ready"
    assert _git(main_manifest.repo_path(alpha), "rev-parse", "HEAD") == _git(
        updater, "rev-parse", "HEAD"
    )


@pytest.mark.parametrize(
    "failure", ["stale", "missing", "failed-entry", "repo-set", "non-utf8", "swapped"]
)
def test_doctor_validates_stamp_integrity_snapshot_and_age(tmp_path: Path, failure: str) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    runner = FakeRunner()
    now = dt.datetime(2026, 8, 17, 7, 0, tzinfo=dt.UTC)
    control = _write_stamp(
        active,
        runner,
        stamp_name=active.control_stamp,
        manifest_path=active.control_mirror_manifest,
        now=now,
        age_minutes=90 if failure == "stale" else 5,
        failed_repo="codex-host-workflows" if failure == "failed-entry" else None,
    )
    _write_stamp(
        active,
        runner,
        stamp_name=active.main_stamp,
        manifest_path=active.main_manifest,
        now=now,
    )
    if failure == "missing":
        control.unlink()
    elif failure == "repo-set":
        payload = json.loads(control.read_text())
        payload["repos"]["extra"] = payload["repos"]["codex-host-workflows"]
        control.write_text(json.dumps(payload), encoding="utf-8")
    elif failure == "non-utf8":
        control.write_bytes(b"\xff\xfe")
    elif failure == "swapped":
        payload = json.loads(control.read_text())
        payload["stamp"] = active.main_stamp
        control.write_text(json.dumps(payload), encoding="utf-8")
    report = hs.doctor_setup(
        active,
        fixture.home,
        runner,
        no_launchctl=True,
        max_age_minutes=60,
        now=now,
    )
    assert report["status"] == "blocked"
    assert report["freshness_mode"] == "live"


def test_historical_skips_only_two_age_checks(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    runner = FakeRunner()
    now = dt.datetime(2026, 8, 17, 7, 0, tzinfo=dt.UTC)
    _write_both_stamps(active, runner, now, age_minutes=900)
    report = hs.doctor_setup(
        active,
        fixture.home,
        runner,
        no_launchctl=True,
        max_age_minutes=60,
        historical=True,
        now=now,
    )
    assert report["status"] == "ready"
    assert report["freshness_mode"] == "historical-age-only"
    skipped = [item for item in report["checks"] if item["status"] == "skipped"]
    assert (
        len(
            [
                item
                for item in skipped
                if item["name"].startswith("freshness-") and item["name"].endswith("-age")
            ]
        )
        == 2
    )
    _git(active.control_mirror, "checkout", "--detach", "HEAD")
    blocked = hs.doctor_setup(
        active,
        fixture.home,
        runner,
        no_launchctl=True,
        max_age_minutes=60,
        historical=True,
        now=now,
    )
    assert blocked["status"] == "blocked"


def test_weekly_pair_receipt_binds_current_stamps(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    pair_time = dt.datetime(2026, 8, 21, 6, 30, tzinfo=dt.UTC)
    runner = FakeRunner()
    _prefetch_writer(active, runner, pair_time)
    prefetch, refreshed = hs.prefetch_weekly(active, runner, now=pair_time)
    assert prefetch["status"] == "ready", prefetch
    weekly = hs.doctor_setup(
        refreshed,
        fixture.home,
        runner,
        no_launchctl=True,
        max_age_minutes=60,
        weekly=True,
        now=pair_time + dt.timedelta(minutes=30),
    )
    assert weekly["status"] == "ready"
    assert _check(weekly, "weekly-pair-receipt")["status"] == "ready"
    assert refreshed.weekly_receipt.stat().st_mode & 0o077 == 0
    main_stamp = refreshed.cache_root / "freshness" / f"{refreshed.main_stamp}.json"
    main_stamp.write_bytes(main_stamp.read_bytes() + b"\n")
    replaced = hs.doctor_setup(
        refreshed,
        fixture.home,
        runner,
        no_launchctl=True,
        max_age_minutes=60,
        weekly=True,
        now=pair_time + dt.timedelta(minutes=30),
    )
    assert _check(replaced, "weekly-pair-receipt")["status"] == "blocked"


def test_weekly_prefetch_attempts_both_without_receipt_on_failure(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    runner = FakeRunner(helper_failures={active.control_stamp: 17})
    report, _ = hs.prefetch_weekly(active, runner)
    assert report["status"] == "blocked"
    assert len([args for args, _cwd in runner.calls if "prefetch" in args]) == 2
    assert not active.weekly_receipt.exists()


def test_failed_weekly_steps_retire_one_shot_stamp_artifacts(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    now = dt.datetime(2026, 8, 21, 6, 30, tzinfo=dt.UTC)
    runner = FakeRunner(helper_failures={active.control_stamp: 17})
    _prefetch_writer(active, runner, now)
    report, _refreshed = hs.prefetch_weekly(active, runner, now=now)
    assert report["status"] == "blocked"
    assert list((active.cache_root / "freshness").glob("*-run-*")) == []


def test_weekly_prefetch_attempts_main_after_control_start_error(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    runner = FakeRunner()

    def fail_control(args: list[str]) -> None:
        if "prefetch" in args and any(
            value.startswith(f"{active.control_stamp}-run-") for value in args
        ):
            raise hs.SetupError("control helper could not start")

    runner.on_helper = fail_control
    report, _ = hs.prefetch_weekly(active, runner)
    assert report["status"] == "blocked"
    assert len([args for args, _cwd in runner.calls if "prefetch" in args]) == 2
    assert report["steps"][0]["returncode"] is None


def test_weekly_prefetch_rejects_stamp_changed_during_receipt_install(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    now = dt.datetime(2026, 8, 21, 6, 30, tzinfo=dt.UTC)
    runner = FakeRunner()
    _prefetch_writer(active, runner, now)
    main_stamp = active.cache_root / "freshness" / f"{active.main_stamp}.json"
    fired = False

    def replace_stamp(operation: str, _sfd: int, _source: str, _target_fd: int, _name: str) -> None:
        nonlocal fired
        if operation == "no-replace" and _name == active.weekly_receipt.name and not fired:
            fired = True
            main_stamp.write_bytes(main_stamp.read_bytes() + b"\n")

    with pytest.raises(hs.SetupError, match="weekly pair input changed"):
        hs.prefetch_weekly(
            active,
            runner,
            file_ops=hs.FileOps(hs.AtomicRenamer(replace_stamp)),
            now=now,
        )
    assert not active.weekly_receipt.exists()


def test_stamp_validation_rebinds_manifest_content(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    now = dt.datetime(2026, 8, 17, 7, 0, tzinfo=dt.UTC)
    writer = FakeRunner()
    _write_stamp(
        active,
        writer,
        stamp_name=active.main_stamp,
        manifest_path=active.main_manifest,
        now=now,
    )
    changed = False

    def change_manifest(args: list[str]) -> None:
        nonlocal changed
        if "status" in args and not changed:
            changed = True
            active.main_manifest.write_bytes(active.main_manifest.read_bytes() + b"\n")

    checks, evidence = hs.validate_freshness_stamp(
        active,
        stamp_name=active.main_stamp,
        manifest_path=active.main_manifest,
        max_age_minutes=60,
        now=now,
        historical=False,
        runner=FakeRunner(on_helper=change_manifest),
    )
    assert evidence is None
    assert any(
        check.status == "blocked"
        and (
            "manifest identity or content changed" in check.detail
            or "workspace manifest changed after delegated helper" in check.detail
        )
        for check in checks
    )


def test_doctor_final_rebind_detects_control_drift_during_main_validation(
    tmp_path: Path,
) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    now = dt.datetime(2026, 8, 17, 7, 0, tzinfo=dt.UTC)
    writer = FakeRunner()
    _write_both_stamps(active, writer, now)
    calls = 0

    def drift_during_main(args: list[str]) -> None:
        nonlocal calls
        if "status" not in args:
            return
        calls += 1
        if calls == 5:
            replacement = active.control_mirror_manifest.with_name("host-workspace.drift.toml")
            replacement.write_bytes(active.control_mirror_manifest.read_bytes())
            os.replace(replacement, active.control_mirror_manifest)

    report = hs.doctor_setup(
        active,
        fixture.home,
        FakeRunner(on_helper=drift_during_main),
        no_launchctl=True,
        max_age_minutes=60,
        now=now,
    )
    assert report["status"] == "blocked"
    assert _check(report, "freshness-final-rebind")["status"] == "blocked"


def test_doctor_rechecks_age_at_final_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    base = dt.datetime(2026, 8, 17, 6, 0, tzinfo=dt.UTC)
    writer = FakeRunner()
    _write_both_stamps(active, writer, base)
    real_datetime = dt.datetime
    moments = iter(
        (
            base + dt.timedelta(minutes=59),
            base + dt.timedelta(minutes=61),
        )
    )

    class AdvancingDateTime(real_datetime):
        @classmethod
        def now(cls, tz: dt.tzinfo | None = None) -> dt.datetime:
            value = next(moments)
            return value if tz is not None else value.replace(tzinfo=None)

    monkeypatch.setattr(hs.dt, "datetime", AdvancingDateTime)
    report = hs.doctor_setup(
        active,
        fixture.home,
        FakeRunner(),
        no_launchctl=True,
        max_age_minutes=60,
    )
    assert report["status"] == "blocked"
    assert _check(report, f"freshness-{active.control_stamp}-age")["status"] == "blocked"


@pytest.mark.parametrize("mutation", ["dirty", "wrong-head", "replaced-directory"])
def test_doctor_rejects_invalid_git_mirror(tmp_path: Path, mutation: str) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    runner = FakeRunner()
    now = dt.datetime(2026, 8, 17, 7, 0, tzinfo=dt.UTC)
    _write_both_stamps(active, runner, now)
    mirror = active.control_mirror
    if mutation == "dirty":
        (mirror / "dirty.txt").write_text("dirty\n", encoding="utf-8")
    elif mutation == "wrong-head":
        (mirror / "new.txt").write_text("ahead\n", encoding="utf-8")
        _git(mirror, "add", "new.txt")
        _git(
            mirror,
            "-c",
            "user.name=Host Setup Test",
            "-c",
            "user.email=host-setup@example.invalid",
            "commit",
            "-m",
            "ahead",
        )
    else:
        mirror.rename(mirror.with_name("control-backup"))
        mirror.mkdir()
    report = hs.doctor_setup(
        active,
        fixture.home,
        runner,
        no_launchctl=True,
        max_age_minutes=60,
        now=now,
    )
    assert report["status"] == "blocked"


@pytest.mark.parametrize("target", ["agents", "library", "git-info", "cache-logs"])
def test_apply_rejects_symlinked_intermediate_components(tmp_path: Path, target: str) -> None:
    fixture = _build_host(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    if target == "agents":
        fixture.workspace.joinpath(".agents").symlink_to(outside)
    elif target == "library":
        fixture.home.joinpath("Library").symlink_to(outside)
    elif target == "git-info":
        info = fixture.workspace / ".git" / "info"
        shutil.rmtree(info)
        info.symlink_to(outside)
    else:
        fixture.config.cache_root.joinpath("logs").symlink_to(outside)
    with pytest.raises(hs.SetupError, match="symlink|blocked|real directory"):
        _apply_ready(fixture)


def test_created_directory_and_locator_are_journaled_before_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    real_fsync = os.fsync
    failed = False

    def fail_once(descriptor: int) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("injected fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(hs.os, "fsync", fail_once)
    with pytest.raises(OSError, match="injected fsync failure"):
        hs._begin_freshness_directory(active, hs.FileOps())
    assert not (active.cache_root / "freshness").exists()

    setup_journal = hs.MutationJournal()
    hs._ensure_directory_children(
        active.workspace_root,
        active.locator_relative_path.parent.parts,
        setup_journal,
        label="locator parent fixture",
    )
    failed = False
    locator_journal = hs.MutationJournal()
    with pytest.raises(OSError, match="injected fsync failure"):
        hs._install_locator(active, locator_journal)
    assert locator_journal.rollback() == []
    assert not active.skill_locator.exists()


def test_directory_child_churn_is_not_treated_as_object_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    real_stat = os.stat
    churned = False

    def churn_before_followed_stat(
        path: os.PathLike[str] | str | int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal churned
        if (
            path == active.skill_locator.name
            and dir_fd is not None
            and follow_symlinks
            and not churned
        ):
            churned = True
            (active.skill_source / "benign-child").write_text("churn\n", encoding="utf-8")
        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(hs.os, "stat", churn_before_followed_stat)
    assert hs._check_locator(active).status == "ready"
    assert churned


def test_acl_policy_canonicalizes_entries_and_rejects_allow_on_custody_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    deny = hs.AclEntry(
        tag=hs.ACL_EXTENDED_DENY,
        qualifier=bytes.fromhex("abcdefabcdefabcdefabcdef0000000c"),
        permissions=1 << 4,
        flags=0,
    )
    allow = hs.AclEntry(
        tag=hs.ACL_EXTENDED_ALLOW,
        qualifier=bytes.fromhex("abcdefabcdefabcdefabcdef0000000c"),
        permissions=1 << 1,
        flags=0,
    )
    monkeypatch.setattr(hs.sys, "platform", "darwin")
    try:
        monkeypatch.setattr(hs, "_read_darwin_acl_entries", lambda _fd: (deny,))
        first = hs._acl_digest_from_fd(
            descriptor,
            label="custody ancestor",
            sensitive_leaf=False,
        )
        second = hs._acl_digest_from_fd(
            descriptor,
            label="custody ancestor",
            sensitive_leaf=False,
        )
        assert first == second
        with pytest.raises(hs.SetupError, match="has an extended ACL"):
            hs._acl_digest_from_fd(
                descriptor,
                label="sensitive leaf",
                sensitive_leaf=True,
            )
        monkeypatch.setattr(hs, "_read_darwin_acl_entries", lambda _fd: (allow,))
        with pytest.raises(hs.SetupError, match="non-deny"):
            hs._acl_digest_from_fd(
                descriptor,
                label="custody ancestor",
                sensitive_leaf=False,
            )
    finally:
        os.close(descriptor)


def test_acl_digest_preserves_semantic_entry_order_and_non_darwin_is_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    first = hs.AclEntry(hs.ACL_EXTENDED_DENY, b"a" * 16, 1 << 4, 0)
    second = hs.AclEntry(hs.ACL_EXTENDED_DENY, b"b" * 16, 1 << 6, 1 << 5)
    try:
        monkeypatch.setattr(hs.sys, "platform", "darwin")
        monkeypatch.setattr(hs, "_read_darwin_acl_entries", lambda _fd: (first, second))
        forward = hs._acl_digest_from_fd(
            descriptor,
            label="custody ancestor",
            sensitive_leaf=False,
        )
        monkeypatch.setattr(hs, "_read_darwin_acl_entries", lambda _fd: (second, first))
        reverse = hs._acl_digest_from_fd(
            descriptor,
            label="custody ancestor",
            sensitive_leaf=False,
        )
        assert forward != reverse

        monkeypatch.setattr(hs.sys, "platform", "linux")
        monkeypatch.setattr(
            hs,
            "_read_darwin_acl_entries",
            lambda _fd: pytest.fail("Darwin ACL reader must not run on non-Darwin"),
        )
        unsupported = hs._acl_digest_from_fd(
            descriptor,
            label="portable leaf",
            sensitive_leaf=True,
        )
        assert (
            unsupported
            == hashlib.sha256(
                hs._canonical_acl_payload((), platform_name="non-darwin-acl-unavailable")
            ).hexdigest()
        )
    finally:
        os.close(descriptor)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL API")
def test_darwin_acl_reader_accepts_home_style_deny_only_on_custody_ancestor(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "acl-custody"
    directory.mkdir()
    added = subprocess.run(
        ["chmod", "+a", "everyone deny delete", str(directory)],
        check=False,
        text=True,
        capture_output=True,
    )
    if added.returncode != 0:
        pytest.skip(f"temporary volume does not support extended ACLs: {added.stderr.strip()}")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        entries = hs._read_darwin_acl_entries(descriptor)
        assert entries
        assert all(entry.tag == hs.ACL_EXTENDED_DENY for entry in entries)
        hs._acl_digest_from_fd(
            descriptor,
            label="custody ancestor",
            sensitive_leaf=False,
        )
        with pytest.raises(hs.SetupError, match="has an extended ACL"):
            hs._acl_digest_from_fd(
                descriptor,
                label="sensitive leaf",
                sensitive_leaf=True,
            )
    finally:
        os.close(descriptor)
        subprocess.run(
            ["chmod", "-N", str(directory)],
            check=False,
            text=True,
            capture_output=True,
        )


def test_ensure_preflight_rejects_cache_symlink_before_helper_mutation(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    fixture.config.cache_root.joinpath("freshness").symlink_to(outside)
    runner = FakeRunner()
    with pytest.raises(hs.SetupError, match="initial preflight"):
        hs.apply_setup(
            fixture.config,
            fixture.home,
            runner,
            ensure=True,
            no_launchctl=True,
        )
    assert not any("ensure" in args for args, _cwd in runner.calls)


@pytest.mark.parametrize("entrypoint", ["ensure", "weekly"])
@pytest.mark.parametrize("git_target", ["objects", "config"])
def test_prefetch_rejects_unsafe_main_mirror_before_that_helper_step(
    tmp_path: Path, entrypoint: str, git_target: str
) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    main = hs._load_main_manifest(active)
    target = main.repo_path(main.repos[0]) / ".git" / git_target
    outside = tmp_path / f"foreign-{git_target}"
    if target.is_dir():
        outside.mkdir()
        shutil.rmtree(target)
    else:
        outside.write_text("foreign\n", encoding="utf-8")
        target.unlink()
    target.symlink_to(outside)
    runner = FakeRunner()
    if entrypoint == "ensure":
        with pytest.raises(hs.SetupError, match="initial preflight"):
            hs.apply_setup(
                fixture.config,
                fixture.home,
                runner,
                ensure=True,
                no_launchctl=True,
            )
        assert not any("ensure" in args for args, _cwd in runner.calls)
    else:
        report, _refreshed = hs.prefetch_weekly(active, runner)
        assert report["status"] == "blocked"
        assert not any(
            "prefetch" in args
            and "--config" in args
            and Path(args[args.index("--config") + 1]) == active.main_manifest
            for args, _cwd in runner.calls
        )


def test_later_git_exclude_negation_is_blocked(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    with hs._exclude_path(active).open("a", encoding="utf-8") as stream:
        stream.write("!/.agents/skills/daily-skill-friction\n")
    report = hs.status_setup(active, fixture.home, FakeRunner(), no_launchctl=True)
    assert report["status"] == "blocked"
    assert "negate" in _check(report, "git-exclude")["detail"]


def test_no_launchctl_persists_reload_until_ordinary_apply(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    first = hs.apply_setup(
        fixture.config,
        fixture.home,
        FakeRunner(),
        ensure=False,
        no_launchctl=True,
    )
    active = _active(fixture)
    assert first["status"] == "changes-required"
    assert set(hs._load_reload_receipt(active)[1]) == {
        active.launch_agent_label,
        active.weekly_launch_agent_label,
    }
    now = dt.datetime(2026, 8, 17, 7, 0, tzinfo=dt.UTC)
    stamp_runner = FakeRunner()
    _write_both_stamps(active, stamp_runner, now)
    doctor = hs.doctor_setup(
        active,
        fixture.home,
        stamp_runner,
        no_launchctl=True,
        max_age_minutes=60,
        now=now,
    )
    assert doctor["status"] == "changes-required"
    assert _check(doctor, "launchctl-reload")["status"] == "needs-apply"
    assert _apply_ready(fixture)["status"] == "ready"
    assert hs._load_reload_receipt(active)[1] == {}


def test_stale_reload_digest_advances_then_reloads_current_plist(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    source = active.launch_agent_source
    source.write_bytes(source.read_bytes().replace(b"<dict>\n", b"<dict>\n  <!-- one -->\n", 1))
    _commit_and_push(active.control_mirror, fixture.control_remote, "first plist revision")
    first = hs.apply_setup(
        fixture.config,
        fixture.home,
        FakeRunner(),
        ensure=False,
        no_launchctl=True,
    )
    assert first["status"] == "changes-required"
    old_digest = hs._load_reload_receipt(active)[1][active.launch_agent_label]

    source.write_bytes(source.read_bytes().replace(b"<dict>\n", b"<dict>\n  <!-- two -->\n", 1))
    _commit_and_push(active.control_mirror, fixture.control_remote, "second plist revision")
    runner = FakeRunner()
    report = _apply_ready(fixture, runner)
    assert report["status"] == "ready"
    assert hs._load_reload_receipt(active)[1] == {}
    assert old_digest != hs._source_plist(hs._launch_agent_specs(active, fixture.home)[0])[0].digest
    assert any(args[:2] == [hs.LAUNCHCTL_EXECUTABLE, "bootstrap"] for args, _cwd in runner.calls)


def test_reload_receipt_write_rejects_concurrent_valid_replacement(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    hs.apply_setup(
        fixture.config,
        fixture.home,
        FakeRunner(),
        ensure=False,
        no_launchctl=True,
    )
    active = _active(fixture)
    before, labels = hs._load_reload_receipt(active)
    assert before is not None
    replacement_labels = dict(labels)
    replacement_labels[active.launch_agent_label] = "f" * 64
    replacement = hs._reload_receipt_payload(active, replacement_labels)
    active.reload_receipt.write_bytes(replacement)
    journal = hs.MutationJournal()
    with pytest.raises(hs.SetupError, match="changed since preflight"):
        hs._write_reload_receipt(
            active,
            labels,
            hs.FileOps(),
            journal,
            expected=before,
        )
    assert active.reload_receipt.read_bytes() == replacement


def test_plist_source_drift_after_plan_fails_before_service_reload(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    control_spec = hs._launch_agent_specs(active, fixture.home)[0]
    installed_before = control_spec.destination.read_bytes()

    class DriftRunner(FakeRunner):
        changed = False

        def run(
            self,
            argv: Sequence[str],
            *,
            cwd: Path | None = None,
            env: Mapping[str, str] | None = None,
        ) -> subprocess.CompletedProcess[str]:
            args = list(argv)
            if args[:2] == [hs.LAUNCHCTL_EXECUTABLE, "print"] and not self.changed:
                self.changed = True
                active.launch_agent_source.write_bytes(
                    active.launch_agent_source.read_bytes().replace(
                        b"<dict>\n", b"<dict>\n  <!-- raced -->\n", 1
                    )
                )
            return super().run(args, cwd=cwd, env=env)

    runner = DriftRunner()
    _load_installed_services(runner, active, fixture.home)
    with pytest.raises(hs.SetupError, match="source changed"):
        _apply_ready(fixture, runner)
    assert control_spec.destination.read_bytes() == installed_before
    assert not any(
        args[:2]
        in (
            [hs.LAUNCHCTL_EXECUTABLE, "bootout"],
            [hs.LAUNCHCTL_EXECUTABLE, "bootstrap"],
        )
        for args, _cwd in runner.calls
    )


def test_launchctl_unknown_print_error_blocks_without_mutation(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    before = hs._exclude_path(fixture.config).read_bytes()
    with pytest.raises(hs.SetupError, match="launchctl print failed"):
        _apply_ready(fixture, FakeRunner(print_error=5))
    assert hs._exclude_path(fixture.config).read_bytes() == before
    assert not fixture.config.skill_locator.exists()


def test_launchctl_exact_loaded_definition_is_ready(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    runner = FakeRunner()
    _apply_ready(fixture, runner)
    active = _active(fixture)
    runner.extra_print_scalars = [
        "\tbase minimum runtime = 10",
        "\truns = 8",
        "\tpid = 1234",
        "\tlast exit code = 0",
    ]

    report = hs.status_setup(active, fixture.home, runner, no_launchctl=False)

    assert report["status"] == "ready"
    assert _check(report, "launchctl-control")["status"] == "ready"
    assert _check(report, "launchctl-weekly")["status"] == "ready"


@pytest.mark.parametrize(
    ("attribute", "value", "expected_field"),
    [
        ("properties", "inferred program | keepalive", "KeepAlive"),
        ("properties", "inferred program | runatload", "RunAtLoad"),
        ("minimum_runtime", 30, "ThrottleInterval"),
        ("exit_timeout", 30, "ExitTimeOut"),
        ("spawn_type", "interactive (4)", "ProcessType"),
    ],
)
def test_launchctl_same_path_and_arguments_with_extra_behavior_is_blocked(
    tmp_path: Path,
    attribute: str,
    value: str | int,
    expected_field: str,
) -> None:
    fixture = _build_host(tmp_path)
    runner = FakeRunner()
    _apply_ready(fixture, runner)
    active = _active(fixture)
    setattr(runner, attribute, value)
    calls_before_status = len(runner.calls)

    report = hs.status_setup(active, fixture.home, runner, no_launchctl=False)

    check = _check(report, "launchctl-control")
    assert report["status"] == "blocked"
    assert check["status"] == "blocked"
    assert expected_field in check["detail"]
    assert not any(
        args[:2]
        in (
            [hs.LAUNCHCTL_EXECUTABLE, "bootout"],
            [hs.LAUNCHCTL_EXECUTABLE, "bootstrap"],
        )
        for args, _cwd in runner.calls[calls_before_status:]
    )


def test_launchctl_conditional_keepalive_block_is_blocked(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    runner = FakeRunner()
    _apply_ready(fixture, runner)
    active = _active(fixture)
    runner.extra_print_scalars = [
        "\tsemaphores = {",
        "\t\tsuccessful exit => 0",
        "\t}",
    ]

    report = hs.status_setup(active, fixture.home, runner, no_launchctl=False)

    check = _check(report, "launchctl-control")
    assert report["status"] == "blocked"
    assert check["status"] == "blocked"
    assert "semaphores" in check["detail"]


def test_launchctl_calendar_trigger_keepalive_is_blocked(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    runner = FakeRunner()
    _apply_ready(fixture, runner)
    active = _active(fixture)
    runner.trigger_keepalive = "1"

    report = hs.status_setup(active, fixture.home, runner, no_launchctl=False)

    check = _check(report, "launchctl-control")
    assert report["status"] == "blocked"
    assert check["status"] == "blocked"
    assert "KeepAlive" in check["detail"]


def test_launchctl_foreign_calendar_trigger_name_is_blocked(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    runner = FakeRunner()
    _apply_ready(fixture, runner)
    active = _active(fixture)
    runner.extra_event_triggers = [
        "\t\tforeign.999999999 => {",
        "\t\t\tkeepalive = 0",
        f"\t\t\tservice = {active.launch_agent_label}",
        "\t\t\tstream = com.apple.launchd.calendarinterval",
        "\t\t\tmonitor = com.apple.UserEventAgent-Aqua",
        "\t\t\tdescriptor = {",
        '\t\t\t\t"Hour" => 2',
        '\t\t\t\t"Minute" => 45',
        "\t\t\t}",
        "\t\t}",
    ]

    report = hs.status_setup(active, fixture.home, runner, no_launchctl=False)

    check = _check(report, "launchctl-control")
    assert report["status"] == "blocked"
    assert check["status"] == "blocked"
    assert "invalid event trigger" in check["detail"]


def test_launchctl_additional_unknown_trigger_kind_is_blocked(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    runner = FakeRunner()
    _apply_ready(fixture, runner)
    active = _active(fixture)
    runner.extra_event_triggers = [
        f"\t\t{active.launch_agent_label}.999999999 => {{",
        "\t\t\tkeepalive = 0",
        f"\t\t\tservice = {active.launch_agent_label}",
        "\t\t\tstream = com.apple.launchd.watchpaths",
        "\t\t\tmonitor = com.apple.UserEventAgent-Aqua",
        "\t\t\tdescriptor = {",
        '\t\t\t\t"Path" => 1',
        "\t\t\t}",
        "\t\t}",
    ]

    report = hs.status_setup(active, fixture.home, runner, no_launchctl=False)

    check = _check(report, "launchctl-control")
    assert report["status"] == "blocked"
    assert check["status"] == "blocked"
    assert "unexpected event trigger kind" in check["detail"]


def test_launchctl_expected_trigger_with_unknown_behavior_field_is_blocked(
    tmp_path: Path,
) -> None:
    fixture = _build_host(tmp_path)
    runner = FakeRunner()
    _apply_ready(fixture, runner)
    active = _active(fixture)
    runner.extra_event_triggers = [
        f"\t\t{active.launch_agent_label}.999999999 => {{",
        "\t\t\tkeepalive = 0",
        f"\t\t\tservice = {active.launch_agent_label}",
        "\t\t\tstream = com.apple.launchd.calendarinterval",
        "\t\t\tmonitor = com.apple.UserEventAgent-Aqua",
        "\t\t\twatch path = /tmp/foreign",
        "\t\t\tdescriptor = {",
        '\t\t\t\t"Hour" => 2',
        '\t\t\t\t"Minute" => 45',
        "\t\t\t}",
        "\t\t}",
    ]

    report = hs.status_setup(active, fixture.home, runner, no_launchctl=False)

    check = _check(report, "launchctl-control")
    assert report["status"] == "blocked"
    assert check["status"] == "blocked"
    assert "unsupported event trigger fields" in check["detail"]


def test_launchctl_same_label_foreign_definition_is_blocked(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    runner = FakeRunner()
    _apply_ready(fixture, runner)
    active = _active(fixture)
    label = active.launch_agent_label
    path, expected = runner.loaded_definitions[label]
    foreign = plistlib.loads(plistlib.dumps(expected))
    foreign["ProgramArguments"] = ["/usr/bin/false", "foreign"]
    runner.loaded_definitions[label] = (path, foreign)
    calls_before_status = len(runner.calls)

    report = hs.status_setup(active, fixture.home, runner, no_launchctl=False)

    check = _check(report, "launchctl-control")
    assert report["status"] == "blocked"
    assert check["status"] == "blocked"
    assert "unexpected definition" in check["detail"]
    assert "ProgramArguments" in check["detail"]
    assert not any(
        args[:2]
        in (
            [hs.LAUNCHCTL_EXECUTABLE, "bootout"],
            [hs.LAUNCHCTL_EXECUTABLE, "bootstrap"],
        )
        for args, _cwd in runner.calls[calls_before_status:]
    )


def test_bootstrap_failure_rolls_back_owned_state(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    runner = FakeRunner(
        launch_failures={
            (
                "bootstrap",
                "com.hoteng.codex.daily-skill-friction-control-prefetch",
            ): [9]
        }
    )
    exclude = hs._exclude_path(fixture.config)
    before = exclude.read_bytes()
    with pytest.raises(hs.SetupError, match="bootstrap"):
        _apply_ready(fixture, runner)
    assert exclude.read_bytes() == before
    assert not fixture.config.skill_locator.exists()
    assert not (fixture.home / "Library").exists()


def test_bootout_failure_restores_prior_plist_and_loaded_service(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    control_spec = hs._launch_agent_specs(active, fixture.home)[0]
    prior = control_spec.destination.read_bytes()
    source = active.launch_agent_source
    source.write_bytes(
        source.read_bytes().replace(b"<dict>\n", b"<dict>\n    <!-- revision -->\n", 1)
    )
    _commit_and_push(active.control_mirror, fixture.control_remote, "plist revision")
    runner = FakeRunner(launch_failures={("bootout", active.launch_agent_label): [7]})
    _load_installed_services(runner, active, fixture.home)
    with pytest.raises(hs.SetupError, match="bootout"):
        _apply_ready(fixture, runner)
    assert control_spec.destination.read_bytes() == prior
    assert runner.loaded[active.launch_agent_label] is True
    assert runner.loaded[active.weekly_launch_agent_label] is True


@pytest.mark.parametrize("other_was_loaded", [False, True])
def test_service_restore_is_gated_per_label(tmp_path: Path, other_was_loaded: bool) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    control, weekly = hs._launch_agent_specs(active, fixture.home)
    control_before = hs._read_owned_regular_file(
        control.destination, max_bytes=hs.MAX_CONFIG_BYTES, label="control before"
    )
    weekly_before = hs._read_owned_regular_file(
        weekly.destination, max_bytes=hs.MAX_CONFIG_BYTES, label="weekly before"
    )
    control.destination.write_bytes(control.destination.read_bytes() + b"\n")
    original = {
        control.label: hs.ServiceState(control.label, True, control_before),
        weekly.label: hs.ServiceState(weekly.label, other_was_loaded, weekly_before),
    }
    runner = FakeRunner()
    runner.load_plist(control.destination)
    runner.load_plist(weekly.destination)
    errors = hs._restore_services(
        (control, weekly), original, {control.label, weekly.label}, runner
    )
    assert any(control.label in error for error in errors)
    assert runner.loaded[control.label] is True
    assert runner.loaded[weekly.label] is other_was_loaded
    assert any(
        args[:2] == [hs.LAUNCHCTL_EXECUTABLE, "bootout"] and args[2].endswith(weekly.label)
        for args, _cwd in runner.calls
    )
    if other_was_loaded:
        assert any(
            args[:2] == [hs.LAUNCHCTL_EXECUTABLE, "bootstrap"]
            and Path(args[-1]).name == weekly.destination.name
            for args, _cwd in runner.calls
        )


def test_atomic_replacement_preserves_foreign_race_targets(tmp_path: Path) -> None:
    parent = tmp_path / "atomic"
    parent.mkdir()
    target = parent / "managed.json"

    def appear(operation: str, _sfd: int, _source: str, target_fd: int, name: str) -> None:
        if operation == "no-replace":
            descriptor = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=target_fd
            )
            os.write(descriptor, b"foreign")
            os.close(descriptor)

    with pytest.raises(hs.SetupError, match="foreign target appeared"):
        hs.FileOps(hs.AtomicRenamer(appear)).begin_replace(
            target, b"managed", mode=0o600, expected=None, max_bytes=100
        )
    assert target.read_bytes() == b"foreign"

    original = hs._read_owned_regular_file(target, max_bytes=100, label="race target")
    fired = False

    def replace(operation: str, _sfd: int, _source: str, target_fd: int, name: str) -> None:
        nonlocal fired
        if operation == "exchange" and not fired:
            fired = True
            os.unlink(name, dir_fd=target_fd)
            descriptor = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=target_fd
            )
            os.write(descriptor, b"replacement")
            os.close(descriptor)

    with pytest.raises(hs.SetupError, match="foreign replacement"):
        hs.FileOps(hs.AtomicRenamer(replace)).begin_replace(
            target, b"new-managed", mode=0o600, expected=original, max_bytes=100
        )
    assert target.read_bytes() == b"new-managed"
    retained = list(parent.glob(".managed.json.stage-*"))
    assert len(retained) == 1
    assert retained[0].read_bytes() == b"replacement"


def test_rollback_exchange_retains_a_second_foreign_replacement(tmp_path: Path) -> None:
    parent = tmp_path / "rollback-race"
    parent.mkdir()
    target = parent / "managed.json"
    target.write_bytes(b"old")
    original = hs._read_owned_regular_file(target, max_bytes=100, label="rollback target")
    transaction = hs.FileOps().begin_replace(
        target, b"new", mode=0o600, expected=original, max_bytes=100
    )
    fired = False

    def replace(operation: str, _sfd: int, _source: str, target_fd: int, name: str) -> None:
        nonlocal fired
        if operation == "exchange" and not fired:
            fired = True
            os.unlink(name, dir_fd=target_fd)
            descriptor = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=target_fd
            )
            os.write(descriptor, b"foreign-second")
            os.close(descriptor)

    transaction.renamer = hs.AtomicRenamer(replace)
    with pytest.raises(hs.SetupError, match="retained both objects"):
        transaction.rollback()
    assert target.read_bytes() == b"old"
    assert transaction.backup_name is not None
    assert (parent / transaction.backup_name).read_bytes() == b"foreign-second"


def test_chained_replacements_remain_fully_rollbackable(tmp_path: Path) -> None:
    parent = tmp_path / "replacement-chain"
    parent.mkdir()
    target = parent / "receipt.json"
    target.write_bytes(b"original")
    original = hs._read_owned_regular_file(target, max_bytes=100, label="original receipt")
    operations = hs.FileOps()
    journal = hs.MutationJournal(operations.renamer)
    first = operations.begin_replace(target, b"first", mode=0o600, expected=original, max_bytes=100)
    journal.add_file(first)
    second = operations.begin_replace(
        target, b"second", mode=0o600, expected=first.new_snapshot, max_bytes=100
    )
    journal.add_file(second)
    assert target.read_bytes() == b"second"
    assert journal.rollback() == []
    assert target.read_bytes() == b"original"
    assert list(parent.glob(".receipt.json.stage-*")) == []


def test_retirement_restores_foreign_replacement_and_stage_collision_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "retire-race"
    parent.mkdir()
    target = parent / "managed.json"
    transaction = hs.FileOps().begin_replace(
        target, b"managed", mode=0o600, expected=None, max_bytes=100
    )
    fired = False

    def replace(operation: str, _sfd: int, _source: str, target_fd: int, name: str) -> None:
        nonlocal fired
        if operation == "retire" and name.startswith(".managed.json.retire-") and not fired:
            fired = True
            os.unlink("managed.json", dir_fd=target_fd)
            descriptor = os.open(
                "managed.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=target_fd
            )
            os.write(descriptor, b"foreign")
            os.close(descriptor)

    transaction.renamer = hs.AtomicRenamer(replace)
    with pytest.raises(hs.SetupError, match="retained an untrusted object"):
        transaction.rollback()
    assert target.read_bytes() == b"foreign"

    monkeypatch.setattr(hs.secrets, "token_hex", lambda _size: "fixed-stage")
    stage = parent / f".other.json.stage-{os.getpid()}-fixed-stage"
    stage.write_bytes(b"foreign-stage")
    with pytest.raises(FileExistsError):
        hs.FileOps().begin_replace(
            parent / "other.json", b"managed", mode=0o600, expected=None, max_bytes=100
        )
    assert stage.read_bytes() == b"foreign-stage"


def test_mirror_guard_install_is_atomic_idempotent_and_allows_child_churn(
    tmp_path: Path,
) -> None:
    common_dir = tmp_path / "mirror" / ".git"
    hooks_dir = common_dir / "hooks"
    common_dir.mkdir(parents=True)
    expected = b"#!/bin/sh\nexit 1\n"
    churned = False

    def churn(
        operation: str,
        _source_fd: int,
        _source: str,
        target_fd: int,
        _target: str,
    ) -> None:
        nonlocal churned
        if operation == "no-replace" and not churned:
            churned = True
            descriptor = os.open(
                "benign-sibling",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=target_fd,
            )
            try:
                os.write(descriptor, b"benign")
            finally:
                os.close(descriptor)

    names = ("pre-commit", "prepare-commit-msg")
    first = hs._install_managed_mirror_guard_hooks(
        common_dir,
        names,
        expected,
        renamer=hs.AtomicRenamer(churn),
    )

    assert churned
    assert hooks_dir.joinpath("benign-sibling").read_bytes() == b"benign"
    for name, snapshot in zip(names, first, strict=True):
        hook = hooks_dir / name
        metadata = hook.lstat()
        assert stat.S_ISREG(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o755
        assert hook.read_bytes() == expected
        assert snapshot.binding.dev == metadata.st_dev
        assert snapshot.binding.ino == metadata.st_ino
    identities = {name: (hooks_dir / name).lstat().st_ino for name in names}

    second = hs._install_managed_mirror_guard_hooks(common_dir, names, expected)

    assert second == first
    assert {name: (hooks_dir / name).lstat().st_ino for name in names} == identities
    assert list(hooks_dir.glob(".*.stage-*")) == []


def test_mirror_guard_hook_is_executable_at_atomic_publish_boundary(tmp_path: Path) -> None:
    common_dir = tmp_path / "mirror" / ".git"
    hooks_dir = common_dir / "hooks"
    hooks_dir.mkdir(parents=True)
    observed: list[tuple[os.stat_result, os.stat_result]] = []

    class ObservingRenamer(hs.AtomicRenamer):
        def no_replace(self, parent_fd: int, source: str, target: str) -> None:
            staged = os.stat(source, dir_fd=parent_fd, follow_symlinks=False)
            assert stat.S_ISREG(staged.st_mode)
            assert stat.S_IMODE(staged.st_mode) == 0o755
            assert staged.st_mode & 0o111 == 0o111
            super().no_replace(parent_fd, source, target)
            published = os.stat(target, dir_fd=parent_fd, follow_symlinks=False)
            observed.append((staged, published))

    (snapshot,) = hs._install_managed_mirror_guard_hooks(
        common_dir,
        ("pre-commit",),
        b"#!/bin/sh\nexit 1\n",
        renamer=ObservingRenamer(),
    )

    assert len(observed) == 1
    staged, published = observed[0]
    assert (published.st_dev, published.st_ino) == (staged.st_dev, staged.st_ino)
    assert stat.S_IMODE(published.st_mode) == 0o755
    assert published.st_mode & 0o111 == 0o111
    assert (snapshot.binding.dev, snapshot.binding.ino) == (
        published.st_dev,
        published.st_ino,
    )


@pytest.mark.parametrize(
    "hostile_kind",
    ["directory", "foreign-content", "foreign-access-policy"],
)
def test_mirror_guard_preflight_rejects_nonmanaged_leaves_before_any_write(
    tmp_path: Path,
    hostile_kind: str,
) -> None:
    common_dir = tmp_path / "mirror" / ".git"
    hooks_dir = common_dir / "hooks"
    hooks_dir.mkdir(parents=True)
    missing = hooks_dir / "pre-commit"
    hostile = hooks_dir / "prepare-commit-msg"
    managed = b"#!/bin/sh\nexit 1\n"
    if hostile_kind == "directory":
        hostile.mkdir()
        expected_error = "not a regular file"
    elif hostile_kind == "foreign-content":
        hostile.write_bytes(b"foreign")
        hostile.chmod(0o711)
        expected_error = "non-managed content"
    else:
        hostile.write_bytes(managed)
        hostile.chmod(0o644)
        expected_error = "non-managed access policy"
    hostile_binding = hs.Binding.from_stat(hostile.lstat())

    with pytest.raises(hs.SetupError, match=expected_error):
        hs._install_managed_mirror_guard_hooks(
            common_dir,
            (missing.name, hostile.name),
            managed,
        )

    assert not missing.exists()
    assert hs.Binding.from_stat(hostile.lstat()) == hostile_binding
    if hostile_kind == "directory":
        assert hostile.is_dir()
    elif hostile_kind == "foreign-content":
        assert hostile.read_bytes() == b"foreign"
        assert stat.S_IMODE(hostile.stat().st_mode) == 0o711
    else:
        assert hostile.read_bytes() == managed
        assert stat.S_IMODE(hostile.stat().st_mode) == 0o644
    assert list(hooks_dir.glob(".*.stage-*")) == []


def test_mirror_guard_transaction_rolls_back_owned_hooks_after_publish_race(
    tmp_path: Path,
) -> None:
    common_dir = tmp_path / "mirror" / ".git"
    hooks_dir = common_dir / "hooks"
    hooks_dir.mkdir(parents=True)
    collided = False

    def collide(
        operation: str,
        _source_fd: int,
        _source: str,
        target_fd: int,
        target: str,
    ) -> None:
        nonlocal collided
        if operation == "no-replace" and target == "prepare-commit-msg" and not collided:
            collided = True
            os.mkdir(target, mode=0o700, dir_fd=target_fd)

    with pytest.raises(hs.SetupError, match="foreign mirror guard hook appeared"):
        hs._install_managed_mirror_guard_hooks(
            common_dir,
            ("pre-commit", "prepare-commit-msg"),
            b"#!/bin/sh\nexit 1\n",
            renamer=hs.AtomicRenamer(collide),
        )

    assert collided
    assert not hooks_dir.joinpath("pre-commit").exists()
    assert hooks_dir.joinpath("prepare-commit-msg").is_dir()
    assert list(hooks_dir.glob(".*.stage-*")) == []
    assert list(hooks_dir.glob(".*.retire-*")) == []


def test_apply_ensure_rejects_symlinked_guard_without_touching_external_target(
    tmp_path: Path,
) -> None:
    fixture = _build_host(tmp_path)
    _write_bound_helper_fixture(fixture.config.workspace_helper)
    hook = fixture.config.control_mirror / ".git" / "hooks" / "pre-commit"
    external = tmp_path / "owner-writable-external-hook"
    external.write_bytes(b"external\n")
    external.chmod(0o640)
    external_before = (external.read_bytes(), stat.S_IMODE(external.stat().st_mode))
    hook.symlink_to(external)

    with pytest.raises(hs.SetupError, match="mirror guard hook leaf is a symlink"):
        hs.apply_setup(
            fixture.config,
            fixture.home,
            ForkTestRunner(timeout_seconds=10),
            ensure=True,
            no_launchctl=True,
        )

    assert hook.is_symlink()
    assert Path(os.readlink(hook)) == external
    assert (external.read_bytes(), stat.S_IMODE(external.stat().st_mode)) == external_before


def test_bound_helper_installs_and_reuses_exact_managed_guard_hooks(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    _write_bound_helper_fixture(active.workspace_helper)
    manifest = hs._load_main_manifest(active)
    runner = ForkTestRunner(timeout_seconds=10)

    first = hs._run_helper(active, manifest, ["ensure"], runner)

    assert first.returncode == 0, first.stderr
    identities: dict[Path, tuple[int, int]] = {}
    for repo in manifest.repos:
        mirror = manifest.repo_path(repo)
        hook = mirror / ".git" / "hooks" / "pre-commit"
        metadata = hook.lstat()
        assert stat.S_ISREG(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o755
        assert hook.read_bytes() == f"guard:{mirror}\n".encode()
        identities[hook] = (metadata.st_dev, metadata.st_ino)

    second = hs._run_helper(active, manifest, ["ensure"], runner)

    assert second.returncode == 0, second.stderr
    assert {hook: (hook.lstat().st_dev, hook.lstat().st_ino) for hook in identities} == identities


def test_manifest_identity_stamp_names_python_and_zero_age_guards(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    alternate = fixture.control_source / "config" / "alternate.toml"
    alternate.write_text(
        _manifest_text(
            fixture.workspace,
            fixture.config.cache_root,
            fixture.config.python_executable,
            fixture.control_remote,
            weekly_source="launchd/other.plist",
        ),
        encoding="utf-8",
    )
    assert hs._config_identity(hs.load_config(alternate)) != hs._config_identity(fixture.config)
    alternate_control = fixture.control_source / "config" / "alternate-control.toml"
    alternate_control.write_text(
        fixture.config.path.read_text().replace(
            "launchd/com.hoteng.codex.daily-skill-friction-control-prefetch.plist",
            "launchd/other-control.plist",
        ),
        encoding="utf-8",
    )
    assert hs._config_identity(hs.load_config(alternate_control)) != hs._config_identity(
        fixture.config
    )
    invalid = fixture.control_source / "config" / "invalid.toml"
    invalid.write_text(
        fixture.config.path.read_text().replace(
            'control_stamp = "daily-skill-friction-control"',
            'control_stamp = "../escape"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(hs.SetupError, match="1-80 characters"):
        hs.load_config(invalid)
    link = fixture.config.python_executable.with_name("python-link")
    link.symlink_to(fixture.config.python_executable.name)
    symlink_manifest = fixture.control_source / "config" / "python-link.toml"
    symlink_manifest.write_text(
        fixture.config.path.read_text().replace(str(fixture.config.python_executable), str(link)),
        encoding="utf-8",
    )
    report = hs.status_setup(
        hs.load_config(symlink_manifest), fixture.home, FakeRunner(), no_launchctl=True
    )
    assert _check(report, "python-executable")["status"] == "blocked"
    with pytest.raises(hs.SetupError, match="positive integer"):
        hs.doctor_setup(
            fixture.config,
            fixture.home,
            FakeRunner(),
            no_launchctl=True,
            max_age_minutes=0,
        )
    with pytest.raises(hs.SetupError, match="cannot be combined"):
        hs.doctor_setup(
            fixture.config,
            fixture.home,
            FakeRunner(),
            no_launchctl=True,
            max_age_minutes=60,
            historical=True,
            weekly=True,
        )
    with pytest.raises(hs.SetupError, match="does not match host_setup.account_home"):
        hs.status_setup(
            fixture.config,
            tmp_path / "other-home",
            FakeRunner(),
            no_launchctl=True,
        )
    unsafe_repo = fixture.control_source / "config" / "unsafe-repo.toml"
    unsafe_repo.write_text(
        fixture.config.path.read_text().replace(
            'name = "codex-host-workflows"', 'name = "../outside"'
        ),
        encoding="utf-8",
    )
    with pytest.raises(hs.SetupError, match="safe single path components"):
        hs.load_config(unsafe_repo)


def test_stamp_validation_binds_exact_active_control_manifest(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    active = _active(fixture)
    runner = FakeRunner()
    now = dt.datetime(2026, 8, 17, 7, 0, tzinfo=dt.UTC)
    _write_stamp(
        active,
        runner,
        stamp_name=active.control_stamp,
        manifest_path=active.control_mirror_manifest,
        now=now,
    )
    replacement = active.control_mirror_manifest.with_name("host-workspace.replacement.toml")
    replacement.write_bytes(active.control_mirror_manifest.read_bytes())
    os.replace(replacement, active.control_mirror_manifest)
    checks, evidence = hs.validate_freshness_stamp(
        active,
        stamp_name=active.control_stamp,
        manifest_path=active.control_mirror_manifest,
        max_age_minutes=60,
        now=now,
        historical=False,
        runner=runner,
    )
    assert evidence is None
    assert any(item.status == "blocked" and "active config" in item.detail for item in checks)


def test_doctor_cli_is_json_and_nonzero_for_missing_stamps(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _build_host(tmp_path)
    _apply_ready(fixture)
    exit_code = hs.main(
        [
            "--config",
            str(fixture.config.path),
            "doctor",
            "--home",
            str(fixture.home),
            "--no-launchctl",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert report["command"] == "doctor"
    assert report["status"] == "blocked"


def test_status_rejects_symlinked_git_admin_before_helper(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    alpha = active.cache_root / "repos" / "alpha"
    git_dir = alpha / ".git"
    displaced = alpha / ".git-displaced"
    git_dir.rename(displaced)
    git_dir.symlink_to(displaced.name)
    runner = FakeRunner()

    report = hs.status_setup(active, fixture.home, runner, no_launchctl=True)

    assert report["status"] == "blocked"
    assert _check(report, "prefetch-alpha-git")["status"] == "blocked"
    assert not any("status" in args for args, _cwd in runner.calls)


def test_git_and_helper_environments_disable_executable_fsmonitor(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    mirror = active.cache_root / "repos" / "alpha"
    marker = tmp_path / "fsmonitor-invoked"
    hook = tmp_path / "fsmonitor.sh"
    hook.write_text(f"#!/bin/sh\nprintf invoked > {marker}\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    _git(mirror, "config", "--local", "core.fsmonitor", str(hook))
    _git(mirror, "status", "--porcelain=v1")
    assert marker.read_text(encoding="utf-8") == "invoked"
    marker.unlink()

    with pytest.raises(hs.SetupError, match="core.fsmonitor"):
        hs._run_git(mirror, "status", "--porcelain=v1")
    assert not marker.exists()
    _git(mirror, "config", "--local", "--unset", "core.fsmonitor")

    runner = FakeRunner()
    manifest = hs._load_main_manifest(active)
    hs._run_workspace_status(active, manifest, runner)
    helper_environment = runner.environments[-1]
    assert helper_environment is not None
    overrides = {
        helper_environment[f"GIT_CONFIG_KEY_{index}"]: helper_environment[
            f"GIT_CONFIG_VALUE_{index}"
        ]
        for index in range(int(helper_environment["GIT_CONFIG_COUNT"]))
    }
    assert overrides["core.attributesFile"] == "/dev/null"
    assert overrides["core.fsmonitor"] == "false"
    assert overrides["core.hooksPath"] == "/dev/null"
    assert overrides["core.sshCommand"] == hs.SSH_EXECUTABLE
    assert overrides["credential.helper"] == ""
    assert overrides["protocol.ext.allow"] == "never"
    assert helper_environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert helper_environment["GIT_GRAFT_FILE"] == "/dev/null"


@pytest.mark.parametrize(
    ("section", "setting"),
    [
        ('includeIf "gitdir:**"', "path = /tmp/hostile.gitconfig"),
        ('filter "hostile"', "process = /tmp/hostile-filter"),
        ("core", "hooksPath = /tmp/hostile-hooks"),
        ('diff "hostile"', "textconv = /tmp/hostile-textconv"),
        ('merge "hostile"', "driver = /tmp/hostile-merge %O %A %B"),
        ('url "ssh://attacker.invalid/"', "insteadOf = git@github.com:"),
        ("credential", "helper = /tmp/hostile-credential"),
        ('remote "origin"', "uploadpack = /tmp/hostile-upload-pack"),
        ("extensions", "worktreeConfig = true"),
        ("core", "worktree = /tmp/hostile-worktree"),
        ("core", "bare = true"),
        ("core", "bare"),
        ("core", "bare = false\n\tbare = false"),
    ],
)
def test_git_local_config_rejects_executable_or_redirected_behavior_before_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    section: str,
    setting: str,
) -> None:
    fixture = _build_host(tmp_path)
    mirror = fixture.config.cache_root / "repos" / "alpha"
    local_config = mirror / ".git" / "config"
    local_config.write_text(
        local_config.read_text(encoding="utf-8") + f"\n[{section}]\n\t{setting}\n",
        encoding="utf-8",
    )
    started = False

    def forbidden_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal started
        started = True
        raise AssertionError("Git must not start after hostile local config is found")

    monkeypatch.setattr(hs.CommandRunner, "run", forbidden_run)
    with pytest.raises(hs.SetupError, match="executable or redirected Git behavior"):
        hs._run_git(mirror, "status", "--porcelain=v1")
    assert started is False


def test_standalone_git_accepts_ordinary_config_with_bound_worktree_config_absence(
    tmp_path: Path,
) -> None:
    fixture = _build_host(tmp_path)
    mirror = fixture.config.cache_root / "repos" / "alpha"

    guard = hs._inspect_git_topology_replacements(mirror)
    result = hs._run_git(mirror, "rev-parse", "--git-dir")

    assert guard.worktree_config_absent is True
    assert result.stdout.strip() == ".git"


@pytest.mark.parametrize(
    ("leaf_kind", "expected_error"),
    [
        ("symlink", "leaf is a symlink"),
        ("directory", "leaf is not a regular file"),
        ("regular", "regular file is present"),
        ("unreadable", "regular file is unreadable"),
    ],
)
def test_git_worktree_config_leaf_is_rejected_without_following(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    leaf_kind: str,
    expected_error: str,
) -> None:
    fixture = _build_host(tmp_path)
    mirror = fixture.config.cache_root / "repos" / "alpha"
    worktree_config = mirror / ".git" / "config.worktree"
    external = tmp_path / "external-worktree-config"
    external.write_text("[core]\n\tbare = true\n", encoding="utf-8")
    if leaf_kind == "symlink":
        worktree_config.symlink_to(external)
    elif leaf_kind == "directory":
        worktree_config.mkdir()
    else:
        worktree_config.write_text("[core]\n\tbare = true\n", encoding="utf-8")

    if leaf_kind == "unreadable":
        real_open = hs.os.open

        def deny_worktree_config_open(
            path: os.PathLike[str] | str,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if path == "config.worktree" and dir_fd is not None:
                raise PermissionError(errno.EACCES, "injected unreadable worktree config")
            if dir_fd is None:
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(hs.os, "open", deny_worktree_config_open)

    started = False

    def forbidden_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal started
        started = True
        raise AssertionError("Git must not start when config.worktree exists")

    monkeypatch.setattr(hs.CommandRunner, "run", forbidden_run)
    with pytest.raises(hs.SetupError, match=expected_error):
        hs._run_git(mirror, "status", "--porcelain=v1")

    assert started is False
    if leaf_kind == "symlink":
        assert worktree_config.is_symlink()
        assert external.read_text(encoding="utf-8") == "[core]\n\tbare = true\n"


def test_enabled_worktree_config_filter_is_blocked_before_git_or_helper_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    manifest = hs._load_main_manifest(active)
    repo = manifest.repos[0]
    mirror = manifest.repo_path(repo)
    attack_probe = tmp_path / "attack-probe"
    updater = tmp_path / "alpha-updater"
    for destination in (attack_probe, updater):
        subprocess.run(
            [hs.GIT_EXECUTABLE, "clone", repo.url, str(destination)],
            check=True,
            text=True,
            capture_output=True,
        )
    updater.joinpath(".gitattributes").write_text(
        "tracked.txt filter=hostile\n",
        encoding="utf-8",
    )
    updater.joinpath("tracked.txt").write_text("remote update\n", encoding="utf-8")
    _commit_and_push(updater, Path(repo.url), "tracked hostile filter fixture")

    marker = tmp_path / "worktree-filter-invoked"
    process = tmp_path / "hostile-filter-process"
    process.write_text(
        f"#!/bin/sh\nprintf invoked > {shlex.quote(str(marker))}\nexit 1\n",
        encoding="utf-8",
    )
    process.chmod(0o755)

    def install_hostile_worktree_config(repository: Path) -> None:
        local_config = repository / ".git" / "config"
        local_config.write_text(
            local_config.read_text(encoding="utf-8") + "\n[extensions]\n\tworktreeConfig = true\n",
            encoding="utf-8",
        )
        repository.joinpath(".git", "config.worktree").write_text(
            f'[filter "hostile"]\n\tprocess = "{process}"\n'
            f'\tsmudge = "{process}"\n\trequired = true\n',
            encoding="utf-8",
        )

    install_hostile_worktree_config(attack_probe)
    _git(attack_probe, "fetch", "origin")
    unguarded = subprocess.run(
        [hs.GIT_EXECUTABLE, "merge", "--ff-only", "@{u}"],
        cwd=attack_probe,
        check=False,
        text=True,
        capture_output=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"},
    )
    assert unguarded.returncode != 0, unguarded
    assert marker.read_text(encoding="utf-8") == "invoked"
    marker.unlink()

    install_hostile_worktree_config(mirror)
    git_started = False

    def forbidden_git_start(
        _runner: hs.CommandRunner,
        argv: Sequence[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal git_started
        git_started = True
        raise AssertionError(f"protected Git child started: {argv}")

    monkeypatch.setattr(hs.CommandRunner, "run", forbidden_git_start)
    with pytest.raises(hs.SetupError, match="extensions.worktreeconfig"):
        hs._run_git(mirror, "fetch", "origin")
    runner = FakeRunner()
    with pytest.raises(hs.SetupError, match="extensions.worktreeconfig"):
        hs._run_helper(
            active,
            manifest,
            ["prefetch", "--repo", repo.name, "--stamp", "hostile-worktree-config"],
            runner,
        )

    assert not marker.exists()
    assert git_started is False
    assert runner.calls == []


def test_git_worktree_config_creation_during_command_fails_post_revalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_host(tmp_path)
    mirror = fixture.config.cache_root / "repos" / "alpha"
    worktree_config = mirror / ".git" / "config.worktree"
    started = False

    def create_during_git(
        _runner: hs.CommandRunner,
        argv: Sequence[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal started
        started = True
        worktree_config.write_text("[core]\n\tbare = true\n", encoding="utf-8")
        return subprocess.CompletedProcess(list(argv), 0, "", "")

    monkeypatch.setattr(hs.CommandRunner, "run", create_during_git)
    with pytest.raises(hs.SetupError, match="regular file is present"):
        hs._run_git(mirror, "status", "--porcelain=v1")

    assert started


def test_helper_rejects_local_config_drift_after_child_without_executing_marker(
    tmp_path: Path,
) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    manifest = hs._load_main_manifest(active)
    mirror = manifest.repo_path(manifest.repos[0])
    config_path = mirror / ".git" / "config"
    marker = tmp_path / "hostile-filter-ran"

    def mutate_config(_args: list[str]) -> None:
        config_path.write_text(
            config_path.read_text(encoding="utf-8")
            + '\n[filter "hostile"]\n'
            + f"\tprocess = {marker}\n",
            encoding="utf-8",
        )

    with pytest.raises(hs.SetupError, match="executable or redirected Git behavior"):
        hs._run_helper(
            active,
            manifest,
            ["status", "--repo", manifest.repos[0].name],
            FakeRunner(on_helper=mutate_config),
        )
    assert not marker.exists()


def test_command_boundaries_use_fixed_executables_and_closed_environments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    hostile = str(tmp_path / "hostile-tools")
    monkeypatch.setenv("PATH", f"{hostile}:/usr/bin:/bin")
    monkeypatch.setenv("HOME", str(tmp_path / "preserved-home"))
    monkeypatch.setenv("LANG", "en_GB.UTF-8")
    monkeypatch.setenv("TMPDIR", str(tmp_path / "preserved-tmp"))
    monkeypatch.setenv("GIT_EXEC_PATH", hostile)
    monkeypatch.setenv("GIT_SSH_COMMAND", f"{hostile}/ssh")
    monkeypatch.setenv("PYTHONPATH", hostile)
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", f"{hostile}/inject.dylib")
    monkeypatch.setenv("SSH_ASKPASS", f"{hostile}/askpass")
    runner = FakeRunner()

    assert hs._check_python(active, runner).status == "ready"
    assert not hs._query_service(active.launch_agent_label, runner).loaded
    helper_result = hs._run_helper(
        active,
        hs._load_main_manifest(active),
        ["status", "--repo", "alpha"],
        runner,
    )
    assert helper_result.returncode == 0

    assert not any("--version" in args for args, _cwd in runner.calls)
    launchctl_index = next(
        index
        for index, (args, _cwd) in enumerate(runner.calls)
        if args[:2] == [hs.LAUNCHCTL_EXECUTABLE, "print"]
    )
    helper_index = next(
        index
        for index, (args, _cwd) in enumerate(runner.calls)
        if str(active.workspace_helper) in args
    )
    assert runner.calls[launchctl_index][0][0] == hs.LAUNCHCTL_EXECUTABLE
    assert runner.calls[helper_index][0][:5] == [
        str(active.python_executable),
        *hs.PYTHON_ISOLATION_FLAGS,
        str(active.workspace_helper),
    ]
    base_environment = hs._trusted_process_environment()
    assert runner.environments[launchctl_index] == base_environment
    helper_environment = runner.environments[helper_index]
    assert helper_environment == hs._git_environment(disable_hooks=False)
    assert helper_environment is not None
    assert helper_environment["PATH"] == hs.TRUSTED_SYSTEM_PATH
    assert helper_environment["HOME"] == hs._trusted_account_home()
    assert helper_environment["HOME"] != str(tmp_path / "preserved-home")
    assert helper_environment["LANG"] == "en_GB.UTF-8"
    assert helper_environment["TMPDIR"] == str(tmp_path / "preserved-tmp")
    assert helper_environment["GIT_SSH"] == hs.SSH_EXECUTABLE
    assert helper_environment["SSH_ASKPASS"] == "/usr/bin/false"
    for hostile_key in (
        "GIT_EXEC_PATH",
        "GIT_SSH_COMMAND",
        "PYTHONPATH",
        "DYLD_INSERT_LIBRARIES",
    ):
        assert hostile_key not in helper_environment


def test_direct_git_uses_absolute_binary_and_closed_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_host(tmp_path)
    mirror = fixture.config.cache_root / "repos" / "alpha"
    captured: dict[str, Any] = {}

    def capture_run(
        _runner: hs.CommandRunner,
        argv: Sequence[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        captured["argv"] = list(argv)
        captured["env"] = dict(kwargs["env"])
        return subprocess.CompletedProcess(list(argv), 0, ".git\n", "")

    monkeypatch.setattr(hs.CommandRunner, "run", capture_run)
    result = hs._run_git(mirror, "rev-parse", "--git-dir")

    assert result.stdout == ".git\n"
    assert captured["argv"] == [hs.GIT_EXECUTABLE, "rev-parse", "--git-dir"]
    assert captured["env"] == hs._git_environment(disable_hooks=True)


def test_direct_git_output_cap_kills_descendant_group_and_prevents_late_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_host(tmp_path)
    mirror = fixture.config.cache_root / "repos" / "alpha"
    late_write = tmp_path / "git-output-limit-late-write"
    grandchild_ready = tmp_path / "git-output-limit-grandchild.json"
    grandchild = tmp_path / "git-output-limit-grandchild.py"
    grandchild.write_text(
        """import json, os, pathlib, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
ready = pathlib.Path(sys.argv[2])
temporary = ready.with_suffix('.tmp')
temporary.write_text(json.dumps({'pid': os.getpid(), 'pgid': os.getpgrp()}), encoding='utf-8')
temporary.replace(ready)
time.sleep(0.6)
pathlib.Path(sys.argv[1]).write_text('late', encoding='utf-8')
""",
        encoding="utf-8",
    )
    fake_git = tmp_path / "git-output-limit"
    fake_git.write_text(
        f"""#!{sys.executable}
import os, pathlib, signal, subprocess, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
subprocess.Popen([
    sys.executable,
    {str(grandchild)!r},
    {str(late_write)!r},
    {str(grandchild_ready)!r},
])
deadline = time.monotonic() + 5
while not pathlib.Path({str(grandchild_ready)!r}).is_file():
    if time.monotonic() >= deadline:
        sys.exit(91)
    time.sleep(0.01)
for _ in range(2048):
    os.write(1, b'x' * 1024)
time.sleep(5)
""",
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    monkeypatch.setattr(hs, "GIT_EXECUTABLE", str(fake_git))
    monkeypatch.setattr(hs, "COMMAND_TERM_GRACE_SECONDS", 0.1)
    monkeypatch.setattr(hs, "COMMAND_KILL_GRACE_SECONDS", 1)

    with pytest.raises(hs.CommandOutputLimitError) as captured:
        hs._run_git(mirror, "status", "--porcelain=v1", "--untracked-files=all")

    error = captured.value
    assert error.output_limit_bytes == hs.MAX_COMMAND_OUTPUT_BYTES
    assert error.captured_total_bytes == hs.MAX_COMMAND_OUTPUT_BYTES
    readiness = json.loads(grandchild_ready.read_text(encoding="utf-8"))
    pid = readiness["pid"]
    process_group = readiness["pgid"]
    assert isinstance(pid, int)
    assert isinstance(process_group, int)
    assert pid != process_group
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail(f"Git output-limit grandchild {pid} survived cleanup")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail(f"Git output-limit process group {process_group} survived cleanup")
    time.sleep(0.65)
    assert not late_write.exists()


def test_hostile_path_shim_cannot_intercept_direct_or_delegated_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper_source = Path(
        "/Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/scripts/codex_workspace.py"
    )
    if not helper_source.is_file():
        pytest.skip("host workspace helper is unavailable")
    fixture = _build_host(tmp_path)
    shutil.copy2(helper_source, fixture.config.workspace_helper)
    shutil.copy2(Path(sys.executable).resolve(), fixture.config.python_executable)
    active = _active(fixture)
    hostile_root = tmp_path / "hostile-path"
    hostile_root.mkdir()
    marker = tmp_path / "hostile-git-invoked"
    shim = hostile_root / "git"
    shim.write_text(
        f'#!/bin/sh\nprintf invoked > "{marker}"\nexit 97\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{hostile_root}:{os.environ['PATH']}")
    monkeypatch.setenv("GIT_EXEC_PATH", str(hostile_root))

    mirror = active.cache_root / "repos" / "alpha"
    direct = hs._run_git(mirror, "rev-parse", "--git-dir")
    delegated = hs._run_helper(
        active,
        hs._load_main_manifest(active),
        ["status", "--repo", "alpha"],
        ForkTestRunner(timeout_seconds=10),
    )

    assert direct.stdout.strip() == ".git"
    assert delegated.returncode == 0
    assert not marker.exists()


@pytest.mark.parametrize("unsafe_state", ["dirty", "wrong-branch", "wrong-remote", "diverged"])
def test_real_helper_ensure_precheck_preserves_invalid_mirror_admin(
    tmp_path: Path, unsafe_state: str
) -> None:
    helper_source = Path(
        "/Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/scripts/codex_workspace.py"
    )
    if not helper_source.is_file():
        pytest.skip("host workspace helper is unavailable")
    fixture = _build_host(tmp_path)
    shutil.copy2(helper_source, fixture.config.workspace_helper)
    shutil.copy2(sys.executable, fixture.config.python_executable)
    mirror = fixture.config.control_mirror
    if unsafe_state == "dirty":
        mirror.joinpath("untracked.txt").write_text("dirty\n", encoding="utf-8")
    elif unsafe_state == "wrong-branch":
        _git(mirror, "switch", "-c", "wrong")
    elif unsafe_state == "wrong-remote":
        _git(mirror, "remote", "set-url", "origin", str(tmp_path / "wrong.git"))
    else:
        updater = tmp_path / "control-updater"
        subprocess.run(
            ["git", "clone", str(fixture.control_remote), str(updater)],
            check=True,
            text=True,
            capture_output=True,
        )
        updater.joinpath("remote.txt").write_text("remote\n", encoding="utf-8")
        _commit_and_push(updater, fixture.control_remote, "remote divergence")
        mirror.joinpath("local.txt").write_text("local\n", encoding="utf-8")
        _git(mirror, "add", "local.txt")
        _git(
            mirror,
            "-c",
            "user.name=Host Setup Test",
            "-c",
            "user.email=host-setup@example.invalid",
            "commit",
            "-m",
            "local divergence",
        )
        _git(mirror, "fetch", "origin")
    config_before = mirror.joinpath(".git", "config").read_bytes()
    hooks_before = {
        path.name: (path.read_bytes(), path.stat().st_mode)
        for path in mirror.joinpath(".git", "hooks").iterdir()
        if path.is_file()
    }

    with pytest.raises(hs.SetupError, match="initial preflight blocked"):
        hs.apply_setup(
            fixture.config,
            fixture.home,
            ForkTestRunner(timeout_seconds=10),
            ensure=True,
            no_launchctl=True,
        )

    assert mirror.joinpath(".git", "config").read_bytes() == config_before
    assert {
        path.name: (path.read_bytes(), path.stat().st_mode)
        for path in mirror.joinpath(".git", "hooks").iterdir()
        if path.is_file()
    } == hooks_before


@pytest.mark.parametrize("unsafe_state", ["dirty", "wrong-remote"])
def test_real_helper_ensure_precheck_covers_every_main_mirror(
    tmp_path: Path, unsafe_state: str
) -> None:
    helper_source = Path(
        "/Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/scripts/codex_workspace.py"
    )
    if not helper_source.is_file():
        pytest.skip("host workspace helper is unavailable")
    fixture = _build_host(tmp_path)
    shutil.copy2(helper_source, fixture.config.workspace_helper)
    shutil.copy2(sys.executable, fixture.config.python_executable)
    main = fixture.config.cache_root / "repos" / "alpha"
    if unsafe_state == "dirty":
        main.joinpath("untracked.txt").write_text("dirty\n", encoding="utf-8")
    else:
        _git(main, "remote", "set-url", "origin", str(tmp_path / "wrong-main.git"))
    mirrors = (fixture.config.control_mirror, main)
    before = {
        mirror: (
            mirror.joinpath(".git", "config").read_bytes(),
            {
                path.name: (path.read_bytes(), path.stat().st_mode)
                for path in mirror.joinpath(".git", "hooks").iterdir()
                if path.is_file()
            },
        )
        for mirror in mirrors
    }

    with pytest.raises(hs.SetupError, match="initial preflight blocked"):
        hs.apply_setup(
            fixture.config,
            fixture.home,
            ForkTestRunner(timeout_seconds=10),
            ensure=True,
            no_launchctl=True,
        )

    for mirror in mirrors:
        config_before, hooks_before = before[mirror]
        assert mirror.joinpath(".git", "config").read_bytes() == config_before
        assert {
            path.name: (path.read_bytes(), path.stat().st_mode)
            for path in mirror.joinpath(".git", "hooks").iterdir()
            if path.is_file()
        } == hooks_before


def test_ensure_semantic_precheck_allows_clean_behind_mirror(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    manifest = hs._load_main_manifest(active)
    alpha = manifest.repos[0]
    mirror = manifest.repo_path(alpha)
    updater = tmp_path / "alpha-behind-updater"
    subprocess.run(
        ["git", "clone", alpha.url, str(updater)],
        check=True,
        text=True,
        capture_output=True,
    )
    updater.joinpath("behind.txt").write_text("remote\n", encoding="utf-8")
    _commit_and_push(updater, Path(alpha.url), "behind update")
    _git(mirror, "fetch", "origin")

    check = hs._ensure_mirror_precheck(manifest, alpha)

    assert check.status == "ready"
    assert "ahead=0 behind=1" in check.detail


@pytest.mark.parametrize("mechanism", ["loose-replace", "packed-replace", "graft"])
def test_ensure_rejects_topology_replacement_that_masks_divergence(
    tmp_path: Path,
    mechanism: str,
) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    manifest = hs._load_main_manifest(active)
    alpha = manifest.repos[0]
    mirror = manifest.repo_path(alpha)
    _forge_divergence_as_behind(
        mirror,
        Path(alpha.url),
        tmp_path / f"{mechanism}-updater",
        mechanism,
    )

    topology = next(
        check
        for check in hs._git_admin_path_checks(mirror, prefix="test")
        if check.name == "test-topology-replacements"
    )
    assert topology.status == "blocked"
    expected_detail = {
        "loose-replace": "loose replacement refs",
        "packed-replace": "packed replacement ref",
        "graft": "graft file",
    }[mechanism]
    assert expected_detail in topology.detail
    semantic = hs._ensure_mirror_precheck(manifest, alpha)
    assert semantic.status == "blocked"
    assert expected_detail in semantic.detail

    runner = FakeRunner()
    with pytest.raises(hs.SetupError, match="initial preflight blocked"):
        hs.apply_setup(
            fixture.config,
            fixture.home,
            runner,
            ensure=True,
            no_launchctl=True,
        )

    assert not any(
        any(command in args for command in ("ensure", "prefetch", "status"))
        for args, _cwd in runner.calls
    )


@pytest.mark.parametrize("entrypoint", ["status", "prefetch"])
def test_status_and_prefetch_reject_grafts_before_helper_mutation(
    tmp_path: Path,
    entrypoint: str,
) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    manifests = (
        hs.load_workspace_manifest(
            active.control_mirror_manifest,
            label="control test manifest",
            expected_cache_root=active.cache_root,
        ),
        hs._load_main_manifest(active),
    )
    for manifest in manifests:
        for repo in manifest.repos:
            manifest.repo_path(repo).joinpath(".git", "info", "grafts").write_text(
                f"{_git(manifest.repo_path(repo), 'rev-parse', 'HEAD')}\n",
                encoding="ascii",
            )
    runner = FakeRunner()

    if entrypoint == "status":
        report = hs.status_setup(active, fixture.home, runner, no_launchctl=True)
        assert report["status"] == "blocked"
    else:
        report, _refreshed = hs.prefetch_weekly(active, runner)
        assert report["status"] == "blocked"

    assert not any(
        any(command in args for command in ("ensure", "prefetch", "status"))
        for args, _cwd in runner.calls
    )


def test_helper_revalidates_replacement_absence_after_invocation(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    manifest = hs._load_main_manifest(active)
    mirror = manifest.repo_path(manifest.repos[0])

    def install_graft(_args: list[str]) -> None:
        head = _git(mirror, "rev-parse", "HEAD")
        mirror.joinpath(".git", "info", "grafts").write_text(
            f"{head}\n",
            encoding="ascii",
        )

    runner = FakeRunner(on_helper=install_graft)
    with pytest.raises(hs.SetupError, match="Git graft file .* is present"):
        hs._run_workspace_status(active, manifest, runner)

    assert any("status" in args for args, _cwd in runner.calls)
    helper_environment = runner.environments[-1]
    assert helper_environment is not None
    assert helper_environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert helper_environment["GIT_GRAFT_FILE"] == "/dev/null"


def test_production_interpreter_policy_requires_exact_isolated_runtime(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    cache_root = workspace / ".codex-local" / "daily-skill-friction"
    config_path = tmp_path / "config" / "host-workspace.toml"
    config_path.parent.mkdir()
    executable = Path(sys.executable).resolve()
    config_path.write_text(
        _manifest_text(workspace, cache_root, executable, tmp_path / "control.git"),
        encoding="utf-8",
    )
    config = hs.load_config(config_path)
    module_path = REPO_ROOT / "scripts" / "host_setup.py"
    probe = (
        "import importlib.util, pathlib, sys; "
        f"path=pathlib.Path({str(module_path)!r}); "
        "spec=importlib.util.spec_from_file_location('host_setup_probe', path); "
        "module=importlib.util.module_from_spec(spec); "
        "sys.modules[spec.name]=module; "
        "spec.loader.exec_module(module); "
        f"config=module.load_config(pathlib.Path({str(config_path)!r})); "
        "binding=module._bind_current_interpreter(config); "
        "print('.'.join(str(part) for part in binding.version))"
    )

    isolated = subprocess.run(
        [str(config.python_executable), *hs.PYTHON_ISOLATION_FLAGS, "-c", probe],
        check=False,
        text=True,
        capture_output=True,
        env=hs._trusted_process_environment(),
    )
    assert isolated.returncode == 0, isolated.stderr
    observed_version = tuple(int(part) for part in isolated.stdout.strip().split("."))
    assert observed_version >= (3, 12, 0)

    unisolated = subprocess.run(
        [str(config.python_executable), "-c", probe],
        check=False,
        text=True,
        capture_output=True,
        env=hs._trusted_process_environment(),
    )
    assert unisolated.returncode != 0
    assert "lacks required -I -B -S isolation" in unisolated.stderr


@pytest.mark.parametrize("replacement_target", ["python", "helper"])
def test_helper_fork_consumes_snapshot_after_manifest_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_target: str,
) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    original_marker = tmp_path / "original-helper-ran"
    malicious_marker = tmp_path / "malicious-replacement-ran"
    active.workspace_helper.write_text(
        "import pathlib\n"
        f"pathlib.Path({str(original_marker)!r}).write_text('original', encoding='utf-8')\n"
        "print('original-helper')\n",
        encoding="utf-8",
    )
    active.workspace_helper.chmod(0o755)
    if replacement_target == "python":
        target = active.python_executable
        replacement = target.with_name("python-malicious-replacement")
        replacement.write_text(
            f'#!/bin/sh\nprintf malicious > "{malicious_marker}"\nexit 91\n',
            encoding="utf-8",
        )
    else:
        target = active.workspace_helper
        replacement = target.with_name("codex_workspace-malicious.py")
        replacement.write_text(
            "import pathlib\n"
            f"pathlib.Path({str(malicious_marker)!r}).write_text('malicious', encoding='utf-8')\n"
            "print('malicious-helper')\n",
            encoding="utf-8",
        )
    replacement.chmod(0o755)
    real_fork = hs.os.fork
    swapped = False

    def replace_after_snapshots() -> int:
        nonlocal swapped
        assert not swapped
        swapped = True
        os.replace(replacement, target)
        return real_fork()

    # _run_helper reaches os.fork only after both interpreter and helper snapshots.
    monkeypatch.setattr(hs.os, "fork", replace_after_snapshots)
    runner = ForkTestRunner(timeout_seconds=5)
    with pytest.raises(hs.SetupError, match="changed from this operation's trusted baseline"):
        hs._run_helper(
            active,
            hs._load_main_manifest(active),
            ["status"],
            runner,
        )
    with pytest.raises(hs.SetupError, match="changed from this operation's trusted baseline"):
        hs._run_helper(
            active,
            hs._load_main_manifest(active),
            ["status"],
            runner,
        )

    assert swapped is True
    assert original_marker.read_text(encoding="utf-8") == "original"
    assert not malicious_marker.exists()


def test_helper_preflight_baseline_blocks_replacement_before_first_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    malicious_marker = tmp_path / "preflight-replacement-ran"
    runner = ForkTestRunner(timeout_seconds=5)
    assert hs._check_workspace_helper(active, runner).status == "ready"
    replacement = active.workspace_helper.with_name("preflight-malicious.py")
    replacement.write_text(
        "import pathlib\n"
        f"pathlib.Path({str(malicious_marker)!r}).write_text('malicious', encoding='utf-8')\n",
        encoding="utf-8",
    )
    replacement.chmod(0o755)
    os.replace(replacement, active.workspace_helper)

    def forbidden_fork() -> int:
        raise AssertionError("helper replacement must be rejected before fork")

    monkeypatch.setattr(hs.os, "fork", forbidden_fork)
    with pytest.raises(hs.SetupError, match="workspace helper changed from"):
        hs._run_helper(
            active,
            hs._load_main_manifest(active),
            ["status"],
            runner,
        )

    assert not malicious_marker.exists()


def test_bound_helper_consumes_inherited_manifest_during_replace_restore_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    loaded_marker = tmp_path / "bound-manifest-loaded"
    _write_bound_helper_fixture(active.workspace_helper, loaded_marker=loaded_marker)
    manifest = hs._load_main_manifest(active)
    original_backup = manifest.path.with_name("workspace.original.toml")
    malicious = manifest.path.with_name("workspace.malicious.toml")
    displaced = manifest.path.with_name("workspace.displaced.toml")
    malicious_marker = tmp_path / "malicious-repo-consumed"
    malicious.write_text(
        "version = 1\n"
        f'cache_root = "{manifest.cache_root}"\n\n'
        "[[repos]]\n"
        'name = "malicious"\n'
        f'url = "{malicious_marker}"\n'
        'default_branch = "master"\n'
        'visibility = "private"\n',
        encoding="utf-8",
    )
    real_fork = hs.os.fork
    swapped = False

    def replace_and_restore_after_fork() -> int:
        nonlocal swapped
        pid = real_fork()
        if pid <= 0:
            return pid
        os.replace(manifest.path, original_backup)
        os.replace(malicious, manifest.path)
        deadline = time.monotonic() + 2
        while not loaded_marker.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert loaded_marker.exists()
        os.replace(manifest.path, displaced)
        os.replace(original_backup, manifest.path)
        swapped = True
        return pid

    monkeypatch.setattr(hs.os, "fork", replace_and_restore_after_fork)
    result = hs._run_helper(
        active,
        manifest,
        ["status"],
        ForkTestRunner(timeout_seconds=5),
    )

    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed == {
        "cache_root": str(manifest.cache_root),
        "repos": [
            {
                "default_branch": repo.default_branch,
                "name": repo.name,
                "url": repo.url,
                "visibility": repo.visibility,
            }
            for repo in manifest.repos
        ],
        "root": str(manifest.root),
    }
    assert swapped is True
    assert not malicious_marker.exists()


def test_bound_helper_fails_closed_when_expected_api_drifts(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    _write_bound_helper_fixture(active.workspace_helper)
    source = active.workspace_helper.read_text(encoding="utf-8")
    active.workspace_helper.write_text(
        source.replace("    visibility: str\n", "    visibility: str\n    extra: str = ''\n"),
        encoding="utf-8",
    )
    active.workspace_helper.chmod(0o755)

    result = hs._run_helper(
        active,
        hs._load_main_manifest(active),
        ["status"],
        ForkTestRunner(timeout_seconds=5),
    )

    assert result.returncode == 1
    assert "RepoSpec constructor fields drifted" in result.stderr


def test_forked_python_source_uses_os_pipe_closes_fds_and_preserves_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "fork-source.py"
    source_path.write_text(
        "import json, os, sys\n"
        "try:\n"
        "    os.fstat(int(sys.argv[2]))\n"
        "except OSError:\n"
        "    inherited_fd_closed = True\n"
        "else:\n"
        "    inherited_fd_closed = False\n"
        "print(json.dumps({\n"
        "    'argv': sys.argv,\n"
        "    'cwd': os.getcwd(),\n"
        "    'environment': dict(os.environ),\n"
        "    'inherited_fd_closed': inherited_fd_closed,\n"
        "}, sort_keys=True))\n",
        encoding="utf-8",
    )
    source_path.chmod(0o700)
    snapshot = hs._read_owned_regular_file(
        source_path,
        max_bytes=hs.MAX_CONFIG_BYTES,
        label="fork source",
    )
    inherited_fd = os.open(source_path, os.O_RDONLY)
    environment = {
        "PATH": hs.TRUSTED_SYSTEM_PATH,
        "HOME": str(tmp_path),
        "LANG": hs.TRUSTED_LOCALE,
        "TMPDIR": str(tmp_path),
        "SSH_AUTH_SOCK": str(tmp_path / "agent.sock"),
    }
    monkeypatch.delattr(hs.os, "pipe2", raising=False)
    try:
        result = hs.CommandRunner(timeout_seconds=2).run_python_source(
            [
                sys.executable,
                *hs.PYTHON_ISOLATION_FLAGS,
                str(source_path),
                "payload",
                str(inherited_fd),
            ],
            source=snapshot,
            source_path=source_path,
            cwd=tmp_path,
            env=environment,
        )
    finally:
        os.close(inherited_fd)

    assert result.returncode == 0
    observed = json.loads(result.stdout)
    assert observed == {
        "argv": [str(source_path), "payload", str(inherited_fd)],
        "cwd": str(tmp_path),
        "environment": environment,
        "inherited_fd_closed": True,
    }
    assert result.stderr == ""


def test_forked_python_source_reports_signal_returncode(tmp_path: Path) -> None:
    source_path = tmp_path / "signal-source.py"
    source_path.write_text(
        "import os, signal\nos.kill(os.getpid(), signal.SIGUSR1)\n",
        encoding="utf-8",
    )
    snapshot = hs._read_owned_regular_file(
        source_path,
        max_bytes=hs.MAX_CONFIG_BYTES,
        label="signal source",
    )

    result = hs.CommandRunner(timeout_seconds=2).run_python_source(
        [sys.executable, *hs.PYTHON_ISOLATION_FLAGS, str(source_path)],
        source=snapshot,
        source_path=source_path,
        cwd=tmp_path,
        env=hs._trusted_process_environment(),
    )

    assert result.returncode == -signal.SIGUSR1


def test_forked_python_source_timeout_before_setsid_kills_and_reaps_pid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "pre-setsid-timeout.py"
    source_path.write_text("raise AssertionError('source must not run')\n", encoding="utf-8")
    snapshot = hs._read_owned_regular_file(
        source_path,
        max_bytes=hs.MAX_CONFIG_BYTES,
        label="pre-setsid timeout source",
    )
    real_fork = hs.os.fork
    real_setsid = hs.os.setsid
    started: dict[str, int] = {}

    def record_fork() -> int:
        pid = real_fork()
        if pid > 0:
            started["pid"] = pid
        return pid

    def delayed_setsid() -> None:
        time.sleep(0.5)
        real_setsid()

    monkeypatch.setattr(hs.os, "fork", record_fork)
    monkeypatch.setattr(hs.os, "setsid", delayed_setsid)
    runner = hs.CommandRunner(
        timeout_seconds=0.05,
        term_grace_seconds=0.05,
        kill_grace_seconds=1,
    )

    with pytest.raises(hs.SetupError, match="command timed out"):
        runner.run_python_source(
            [sys.executable, *hs.PYTHON_ISOLATION_FLAGS, str(source_path)],
            source=snapshot,
            source_path=source_path,
            cwd=tmp_path,
            env=hs._trusted_process_environment(),
        )

    pid = started["pid"]
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def _fork_supervision_fixture(
    tmp_path: Path,
    *,
    output_bytes: int,
) -> tuple[Path, hs.FileSnapshot, Path, Path]:
    late_write = tmp_path / "fork-late-write"
    readiness = tmp_path / "fork-grandchild-ready.json"
    grandchild = tmp_path / "fork-grandchild.py"
    grandchild.write_text(
        "import pathlib, signal, sys, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(0.8)\n"
        "pathlib.Path(sys.argv[1]).write_text('late', encoding='utf-8')\n",
        encoding="utf-8",
    )
    source_path = tmp_path / "fork-supervised-source.py"
    source_path.write_text(
        "import json, os, pathlib, signal, subprocess, sys, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"process = subprocess.Popen([sys.executable, {str(grandchild)!r}, "
        f"{str(late_write)!r}])\n"
        f"pathlib.Path({str(readiness)!r}).write_text("
        "json.dumps({'pid': process.pid, 'pgid': os.getpgrp()}), encoding='utf-8')\n"
        f"output_bytes = {output_bytes}\n"
        "if output_bytes:\n"
        "    os.write(1, b'x' * output_bytes)\n"
        "time.sleep(5)\n",
        encoding="utf-8",
    )
    snapshot = hs._read_owned_regular_file(
        source_path,
        max_bytes=hs.MAX_CONFIG_BYTES,
        label="fork supervision source",
    )
    return source_path, snapshot, readiness, late_write


def _assert_fork_descendant_cleaned(readiness: Path, late_write: Path) -> None:
    observed = json.loads(readiness.read_text(encoding="utf-8"))
    pid = observed["pid"]
    process_group = observed["pgid"]
    assert isinstance(pid, int)
    assert isinstance(process_group, int)
    assert pid != process_group
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail(f"forked helper descendant {pid} survived cleanup")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail(f"forked helper process group {process_group} survived cleanup")
    time.sleep(0.85)
    assert not late_write.exists()


def test_forked_python_source_timeout_kills_descendant_group(tmp_path: Path) -> None:
    source_path, snapshot, readiness, late_write = _fork_supervision_fixture(
        tmp_path,
        output_bytes=0,
    )
    runner = hs.CommandRunner(
        timeout_seconds=0.3,
        term_grace_seconds=0.1,
        kill_grace_seconds=1,
    )

    with pytest.raises(hs.SetupError, match="command timed out"):
        runner.run_python_source(
            [sys.executable, *hs.PYTHON_ISOLATION_FLAGS, str(source_path)],
            source=snapshot,
            source_path=source_path,
            cwd=tmp_path,
            env=hs._trusted_process_environment(),
        )

    _assert_fork_descendant_cleaned(readiness, late_write)


def test_forked_python_source_output_cap_kills_descendant_group(tmp_path: Path) -> None:
    output_limit = 4096
    source_path, snapshot, readiness, late_write = _fork_supervision_fixture(
        tmp_path,
        output_bytes=output_limit * 2,
    )
    runner = hs.CommandRunner(
        timeout_seconds=5,
        term_grace_seconds=0.1,
        kill_grace_seconds=1,
        output_limit_bytes=output_limit,
    )

    with pytest.raises(hs.CommandOutputLimitError) as captured:
        runner.run_python_source(
            [sys.executable, *hs.PYTHON_ISOLATION_FLAGS, str(source_path)],
            source=snapshot,
            source_path=source_path,
            cwd=tmp_path,
            env=hs._trusted_process_environment(),
        )

    assert captured.value.captured_total_bytes == output_limit
    _assert_fork_descendant_cleaned(readiness, late_write)


@pytest.mark.parametrize("returncode", [0, 17])
def test_command_runner_captures_split_output_under_limit(returncode: int) -> None:
    runner = hs.CommandRunner(timeout_seconds=2, output_limit_bytes=128)

    result = runner.run(
        [
            sys.executable,
            "-c",
            (
                "import os, sys; "
                "os.write(1, b'stdout-one\\n'); "
                "os.write(2, b'stderr-two\\n'); "
                f"sys.exit({returncode})"
            ),
        ]
    )

    assert result.returncode == returncode
    assert result.stdout == "stdout-one\n"
    assert result.stderr == "stderr-two\n"


def test_command_runner_output_limit_kills_group_and_bounds_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_limit = 4096
    late_write = tmp_path / "output-limit-late-stamp.json"
    grandchild_ready = tmp_path / "output-limit-grandchild-ready.json"
    grandchild = tmp_path / "output-limit-grandchild.py"
    grandchild.write_text(
        """import json, os, pathlib, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
ready = pathlib.Path(sys.argv[2])
temporary = ready.with_suffix('.tmp')
temporary.write_text(json.dumps({'pid': os.getpid(), 'pgid': os.getpgrp()}), encoding='utf-8')
temporary.replace(ready)
os.write(1, b'stdout-marker\\n')
os.write(2, b'stderr-marker\\n')
for _ in range(128):
    os.write(1, b'o' * 1024)
    os.write(2, b'e' * 1024)
time.sleep(0.6)
pathlib.Path(sys.argv[1]).write_text('late', encoding='utf-8')
""",
        encoding="utf-8",
    )
    parent = tmp_path / "output-limit-parent.py"
    parent.write_text(
        """import signal, subprocess, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2], sys.argv[3]])
time.sleep(5)
""",
        encoding="utf-8",
    )
    runner = hs.CommandRunner(
        timeout_seconds=5,
        term_grace_seconds=0.1,
        kill_grace_seconds=1,
        output_limit_bytes=output_limit,
    )
    real_popen = hs.subprocess.Popen
    started: dict[str, int] = {}

    def wait_for_grandchild_ready(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process = cast("subprocess.Popen[bytes]", real_popen(*args, **kwargs))
        started["leader_pid"] = process.pid
        deadline = time.monotonic() + 5
        while not grandchild_ready.is_file():
            if process.poll() is not None:
                pytest.fail("output-limit fixture leader exited before grandchild readiness")
            if time.monotonic() >= deadline:
                runner._terminate_process_group(process)
                pytest.fail("output-limit fixture grandchild did not publish readiness")
            time.sleep(0.01)
        return process

    monkeypatch.setattr(hs.subprocess, "Popen", wait_for_grandchild_ready)
    with pytest.raises(hs.CommandOutputLimitError) as captured:
        runner.run(
            [sys.executable, str(parent), str(grandchild), str(late_write), str(grandchild_ready)]
        )

    error = captured.value
    assert str(error).startswith("command output limit exceeded:")
    assert error.output_limit_bytes == output_limit
    assert error.captured_total_bytes == output_limit
    assert error.captured_stdout_bytes + error.captured_stderr_bytes == output_limit
    assert "marker" in error.diagnostic
    assert len(error.diagnostic) <= hs.MAX_COMMAND_DETAIL + len("stderr=")
    readiness = json.loads(grandchild_ready.read_text(encoding="utf-8"))
    pid = readiness["pid"]
    assert isinstance(pid, int)
    assert readiness == {"pid": pid, "pgid": started["leader_pid"]}
    assert pid != started["leader_pid"]
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail(f"output-limit grandchild {pid} survived cleanup")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.killpg(started["leader_pid"], 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail(f"output-limit process group {started['leader_pid']} survived cleanup")
    time.sleep(0.65)
    assert not late_write.exists()


def test_command_runner_timeout_kills_descendant_tree_and_prevents_late_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    late_write = tmp_path / "late-stamp.json"
    grandchild_ready = tmp_path / "grandchild-ready.json"
    grandchild = tmp_path / "grandchild.py"
    grandchild.write_text(
        """import json, os, pathlib, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
ready = pathlib.Path(sys.argv[2])
temporary = ready.with_suffix('.tmp')
temporary.write_text(json.dumps({'pid': os.getpid(), 'pgid': os.getpgrp()}), encoding='utf-8')
temporary.replace(ready)
time.sleep(0.6)
pathlib.Path(sys.argv[1]).write_text('late', encoding='utf-8')
""",
        encoding="utf-8",
    )
    parent = tmp_path / "parent.py"
    parent.write_text(
        """import signal, subprocess, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2], sys.argv[3]])
time.sleep(5)
""",
        encoding="utf-8",
    )
    runner = hs.CommandRunner(
        timeout_seconds=0.15,
        term_grace_seconds=0.1,
        kill_grace_seconds=1,
    )
    real_popen = hs.subprocess.Popen
    started: dict[str, int] = {}

    def wait_for_grandchild_ready(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process = cast("subprocess.Popen[bytes]", real_popen(*args, **kwargs))
        started["leader_pid"] = process.pid
        deadline = time.monotonic() + 5
        while not grandchild_ready.is_file():
            if process.poll() is not None:
                pytest.fail("timeout fixture leader exited before grandchild readiness")
            if time.monotonic() >= deadline:
                runner._terminate_process_group(process)
                pytest.fail("timeout fixture grandchild did not publish readiness")
            time.sleep(0.01)
        return process

    monkeypatch.setattr(hs.subprocess, "Popen", wait_for_grandchild_ready)
    with pytest.raises(hs.SetupError, match="command timed out") as captured:
        runner.run(
            [sys.executable, str(parent), str(grandchild), str(late_write), str(grandchild_ready)]
        )
    assert type(captured.value) is hs.SetupError
    readiness = json.loads(grandchild_ready.read_text(encoding="utf-8"))
    pid = readiness["pid"]
    assert isinstance(pid, int)
    assert readiness == {"pid": pid, "pgid": started["leader_pid"]}
    assert pid != started["leader_pid"]
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail(f"grandchild process {pid} survived timeout cleanup")
    time.sleep(0.65)
    assert not late_write.exists()


@pytest.mark.parametrize(
    "invalid_label",
    ["/tmp/escape", "../escape", "com.hoteng/escape", "."],
)
def test_launch_agent_labels_reject_path_escape(tmp_path: Path, invalid_label: str) -> None:
    fixture = _build_host(tmp_path)
    manifest = fixture.control_source / "config" / f"invalid-label-{len(invalid_label)}.toml"
    manifest.write_text(
        fixture.config.path.read_text(encoding="utf-8").replace(
            fixture.config.launch_agent_label, invalid_label, 1
        ),
        encoding="utf-8",
    )
    with pytest.raises(hs.SetupError, match="reverse-DNS label"):
        hs.load_config(manifest)


def test_launch_agent_labels_must_be_distinct_and_targets_are_contained(tmp_path: Path) -> None:
    fixture = _build_host(tmp_path)
    manifest = fixture.control_source / "config" / "duplicate-label.toml"
    manifest.write_text(
        fixture.config.path.read_text(encoding="utf-8").replace(
            fixture.config.weekly_launch_agent_label, fixture.config.launch_agent_label, 1
        ),
        encoding="utf-8",
    )
    with pytest.raises(hs.SetupError, match="must be distinct"):
        hs.load_config(manifest)
    launch_agents = fixture.home / "Library" / "LaunchAgents"
    for spec in hs._launch_agent_specs(fixture.config, fixture.home):
        assert spec.destination.parent == launch_agents
        assert spec.destination.name == f"{spec.label}.plist"


def test_apply_ensure_resamples_final_doctor_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _build_host(tmp_path)
    active = _active(fixture)
    stamp_time = dt.datetime(2026, 8, 17, 6, 0, tzinfo=dt.UTC)
    runner = FakeRunner()
    _prefetch_writer(active, runner, stamp_time)
    phase = {"doctor": False}
    real_datetime = hs.dt.datetime

    class AdvancingDateTime(real_datetime):
        @classmethod
        def now(cls, tz: dt.tzinfo | None = None) -> AdvancingDateTime:
            minutes = 61 if phase["doctor"] else 59
            value = stamp_time + dt.timedelta(minutes=minutes)
            return cls.fromtimestamp(value.timestamp(), tz=tz)

    original_doctor = hs.doctor_setup
    observed_now: list[dt.datetime | None] = []

    def recording_doctor(*args: object, **kwargs: object) -> dict[str, object]:
        observed_now.append(kwargs.get("now"))  # type: ignore[arg-type]
        phase["doctor"] = True
        return original_doctor(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(hs.dt, "datetime", AdvancingDateTime)
    monkeypatch.setattr(hs, "doctor_setup", recording_doctor)
    with pytest.raises(hs.SetupError, match="post-apply validation is blocked"):
        hs.apply_setup(
            fixture.config,
            fixture.home,
            runner,
            ensure=True,
            no_launchctl=True,
            now=None,
        )
    assert observed_now == [None]


def test_setup_ci_force_round_trip_keeps_exact_fixture_exclusions(tmp_path: Path) -> None:
    for relative in (".gitignore", "package.json"):
        shutil.copy2(REPO_ROOT / relative, tmp_path / relative)
    command = [
        "node",
        str(REPO_ROOT / "scripts" / "setup-ci.mjs"),
        "--tool",
        "python",
        "--tool",
        "bash",
        "--tool",
        "github-actions",
        "--tool",
        "markdown",
        "--force",
    ]
    subprocess.run(command, cwd=tmp_path, check=True, text=True, capture_output=True)
    for relative in (
        ".github/workflows/ci.yml",
        ".gitignore",
        ".editorconfig",
        "package.json",
        "prettier.config.mjs",
        ".prettierignore",
        ".markdownlint-cli2.jsonc",
        "pyproject.toml",
    ):
        assert tmp_path.joinpath(relative).read_bytes() == REPO_ROOT.joinpath(relative).read_bytes()
    dry_run = subprocess.run(
        [*command, "--dry-run"],
        cwd=tmp_path,
        check=True,
        text=True,
        capture_output=True,
    )
    assert "Planned 0 file change(s)" in dry_run.stdout
