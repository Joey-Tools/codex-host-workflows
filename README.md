# Codex Host Workflows

Private, host-scoped control-plane assets for Codex workflows that should run on one workstation rather than every machine using the private overlay.

## Boundaries

This repository does **not** aggregate or replace the private overlay installation manifest. The global private overlay continues to be installed by its existing mechanism. `config/host-workspace.toml` is a separate repository-management manifest for `codex-workspace/scripts/codex_workspace.py`; it lists only `codex-host-workflows` and deliberately shares the existing Daily Skill Friction cache root.

The evidence repository is also separate. This repository owns control code, prompts, schedules, tests, and project journals. The evidence repository stores case data and does not adopt project journalling.

## Host bootstrap

The bootstrap is explicit, inspectable, and idempotent:

```bash
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 scripts/host_setup.py plan --no-launchctl
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 scripts/host_setup.py apply --ensure
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 scripts/host_setup.py status
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 scripts/host_setup.py doctor
```

`apply --ensure` is the only bootstrap path that may invoke the workspace helper's `ensure` command. It is intended for a first, explicitly authorized installation. Before `ensure`, bootstrap validates every existing workspace, cache, locator, Git-info, and LaunchAgents ancestor that the helper or installer may touch. It then performs the initial control and main prefetch pair, which may safely fast-forward a clean-behind mirror, proves the resulting manifests and mirrors with strict helper status, installs host state, and runs `doctor`; a successful first bootstrap is immediately ready. Plain `apply` never clones. Scheduled wrappers invoke only the helper's `prefetch` command and fail closed when a mirror is missing or unsafe.

The bootstrap manages the following host-local state:

- A relative `.agents/skills/daily-skill-friction` locator in `codex-workspace`, with a dedicated managed entry in `.git/info/exclude`.
- `com.hoteng.codex.daily-skill-friction-control-prefetch`, a 02:45 LaunchAgent that runs `host_setup.py prefetch-control`, refreshes only the control repository, and publishes the `daily-skill-friction-control` freshness stamp.
- `com.hoteng.codex.daily-skill-friction-weekly-prefetch`, a Friday 06:30 LaunchAgent that sequentially refreshes the control and main manifests without `ensure` or clone. It writes `daily-skill-friction-weekly-pair.json` only after both calls and both resulting stamps validate.
- Machine-readable state for pending LaunchAgent reloads and the weekly pair receipt. A normal `doctor` requires both `daily-skill-friction-control` and the existing main `daily-skill-friction` stamp to be no more than 60 minutes old. Each exact manifest repository entry must be `ready`, and every stamped `head`, `upstream_head`, `branch`, `upstream`, remote, and ahead/behind value must match a stable, clean current mirror snapshot.

The bootstrap never edits or unloads the existing 02:50 shared prefetch LaunchAgent.

Explicit historical replays may use `doctor --historical`. That flag skips only the maximum-age check for each stamp and records the two `freshness-*-age` checks as `skipped`; stamp parsing, manifest identity, exact repository set, `ready` entries, mirror Git state, and stamped snapshot binding still run. It does not skip helper, locator, ownership, permission, plist, or reload-state checks. `--historical` and `--weekly` are mutually exclusive, and scheduled Daily or Weekly runs must never pass the historical flag.

For a non-interactive validation environment, pass `--no-launchctl`. This skips only the GUI-domain service query while still validating both plist files, reload state, manifests, mirrors, and stamps. If `apply --no-launchctl` changes a plist, it returns `changes-required` and leaves an explicit digest-bound reload receipt; a later ordinary `apply` must load or reload the service and clear that receipt. Disk-only validation never claims the service was reloaded.

The Daily automation is `automations/daily-skill-friction/automation.toml` with ID `daily-skill-friction`. It calls the stable mirror path:

```bash
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/scripts/host_setup.py doctor --no-launchctl
```

The Weekly automation is `automations/weekly-skill-friction-publication/automation.toml` with ID `weekly-skill-friction-publication`. Its Friday 07:00 gate additionally binds the two current stamps to the receipt written by the 06:30 pair prefetch:

```bash
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/scripts/host_setup.py doctor --weekly --no-launchctl
```

`doctor --weekly` requires `weekly-pair-receipt` to match the exact SHA-256, `ended_at`, manifest SHA-256, and repository set of both current stamps, and requires the receipt to be within the same 60-minute window. Each scheduled helper call writes to an unpredictable one-shot stamp name. The wrapper validates that exact output, publishes the two canonical stamps transactionally, writes the receipt only after both publications validate, and retires one-shot files on both success and failure. Production freshness age is sampled again after the final evidence rebind, so a slow validation cannot cross the 60-minute boundary and still report ready. A partial, failed, concurrent, or later single-stamp refresh therefore cannot receive an old pair's endorsement.

## Filesystem and service safety

All managed paths are walked without following intermediate symlinks. Existing directories must be owned by the current user at their managed boundary and must not be group- or world-writable; the pinned Python runtime is a real executable file under similarly protected ancestry. Before helper mutation, each mirror's Git administration directories and `.git/config` must also be real, current-user-owned, and non-writable by group or world. The locator must resolve to the exact intended skill directory, and `git check-ignore --no-index` proves that later exclude rules do not negate the managed entry.

Managed file replacement protects the target's device/inode identity, exact bounded content, file type, owner/group, and mode. It uses a same-directory no-replace or exchange operation, retains the prior object until final validation, and fsyncs the new file and parent. Cleanup first moves the exact candidate to an unpredictable quarantine leaf and validates it there; a mismatch is restored to its canonical leaf when still vacant or retained with both recovery paths reported. It does not claim an unavailable inode-conditional rename primitive. Directory child-entry churn may change directory size and is not itself treated as mutation; directory device/inode identity and access policy remain bound. If later validation or `launchctl` activation fails, owned file/directory changes and each prior managed service state are restored only when that service's protected plist identity can still be proved. A service with an unverified plist is skipped without preventing independently safe restoration of another service.

The shared helper never receives a canonical stamp name from either host-owned scheduled wrapper. It receives an unpredictable one-shot name under a prevalidated current-user-owned freshness directory that is not writable by group or world; the host wrapper alone validates and publishes canonical evidence. This protects pre-existing leaf targets and ordinary cooperative concurrency. It does not claim protection from a continuously malicious same-UID process that discovers a random leaf and swaps it after the final revalidation.

Freshness, manifest, mirror, receipt, and managed-file checks are point-in-time proofs. Weekly validation rebinds both manifests, both stamps, all mirror snapshots, and the receipt around its final decision, but it does not claim to prevent a same-UID process from mutating state after the last successful revalidation.

## Repository layout

- `automations/`: canonical Daily and Weekly task definitions.
- `.agents/skills/`: repository-local workflow skills exposed through the host locator.
- `config/host-workspace.toml`: one-repository manifest used by the shared workspace helper.
- `launchd/`: canonical host LaunchAgent source.
- `scripts/host_setup.py`: plan/apply/status/doctor plus safe control/weekly prefetch wrappers.
- `docs/project_journal/`: durable control-plane workstream state.

## Validation

```bash
uv sync --group dev
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest
pnpm install
pnpm run format:check
pnpm run lint
```
