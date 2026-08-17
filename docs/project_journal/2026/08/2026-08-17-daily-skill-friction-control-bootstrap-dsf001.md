---
id: 20260817-dsf001
title: Daily Skill Friction Control Bootstrap
status: active
created: 2026-08-17
updated: 2026-08-17
branch: codex/daily-skill-friction-control
pr:
supersedes: []
superseded_by:
---

# Daily Skill Friction Control Bootstrap

## Summary

- Establish the single-host Daily Skill Friction control plane without distributing it through the global private overlay.
- Replace the old automation's ambiguous `repeated` / `high-signal` escalation language, which could overreact to a small number of observations and produce too much authoring work.
- Stop treating a local or unpublished repair as covered: the old flow had no push or PR path, so it could not demonstrate adoption or effectiveness.

## Current State

- The control repository owns its host manifest, repo-local skill, scheduled task definitions, bootstrap, and validation.
- The case ledger remains a separate data repository with no project-journal workflow.
- Initial mirror creation and LaunchAgent activation remain explicit host bootstrap actions; scheduled prefetch paths cannot ensure or clone.
- Bootstrap installs independent 02:45 control and Friday 06:30 paired-prefetch LaunchAgents without changing the existing 02:50 main prefetch.
- Daily doctor binds both freshness stamps to clean current Git mirrors. Weekly doctor additionally requires the current digest-bound pair receipt.
- Managed filesystem replacement, reload receipts, and service rollback fail closed on foreign targets or unsafe path ancestry.
- LaunchAgent readiness binds the loaded service's behavior-defining configuration to the verified installed plist; a foreign service reusing the managed label is blocked.
- Control-state transactions bind every directory from the filesystem root through the state root by object identity, access policy, and parent-visible name before publishing a WAL commit.
- Daily completion derives its created, updated, unchanged, and dormant case counts from the exact validated stage and dormancy receipts, including WAL recovery.
- The redesigned Daily path is evidence-only. Publication and repair happen in the explicit Weekly path, with separate approval boundaries for creating changes, pushing, and opening a PR.
- The existing private overlay remains independently installed and is not absorbed into this host manifest. Host-only control can be removed without changing overlay installation; each later squash commit must describe the concrete friction it addresses so a no-longer-needed repair can be identified and reverted.

## Next Steps

- Run the explicit first-host bootstrap after Joey authorizes the helper `ensure`, then complete the read-only replay and live-run pilot before enabling the paused Daily and Weekly schedules.

## Evidence

- `config/host-workspace.toml`
- `scripts/host_setup.py`
- `tests/test_host_setup.py`
- `.agents/skills/daily-skill-friction/scripts/friction_state.py`
- `.agents/skills/daily-skill-friction/references/daily-audit.md`
- `tests/test_friction_state.py`
- `launchd/com.hoteng.codex.daily-skill-friction-control-prefetch.plist`
- `launchd/com.hoteng.codex.daily-skill-friction-weekly-prefetch.plist`
