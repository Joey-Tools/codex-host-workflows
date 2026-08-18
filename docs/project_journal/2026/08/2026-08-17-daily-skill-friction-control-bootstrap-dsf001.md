---
id: 20260817-dsf001
title: Daily Skill Friction Control Bootstrap
status: active
created: 2026-08-17
updated: 2026-08-18
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
- Host control subprocesses use fixed system executables, isolated Python startup, and a manifest-bound account home under a rebuilt environment; writable `PATH` entries cannot substitute Git, SSH, launchctl, or Python startup behavior.
- LaunchAgent readiness uses a closed behavior schema for the loaded service, including every calendar trigger, event channel, scheduling default, process type, and launch property; a foreign or behavior-augmented service reusing the managed label is blocked.
- Control-state transactions bind every directory from the filesystem root through the state root by object identity, access policy, and parent-visible name before publishing a WAL commit.
- External Weekly WAL outputs retain the original destination-parent identity and access-policy chain across recovery; missing, rebound, or unsafe parents are never recreated or silently adopted.
- A failed WAL commit publication rolls back only the exact leaf linked by that invocation, including failures after link publication but before `write_json` returns; global recovery validates canonical intent/commit pairing and every WAL leaf before replaying any transaction.
- Delegated helper and launchctl stdout/stderr share a 1 MiB retained-output ceiling; overflow and timeout both terminate, drain, kill, and reap the complete managed process group before returning a bounded diagnostic.
- Delegated workspace helpers are compiled and executed from exact stable in-memory source bytes in a fork of the already-running isolated interpreter; no post-preflight Python or helper pathname is executed. The current interpreter and OS loader are explicit startup trust roots, and this process does not claim to retrospectively prove a pre-start vnode.
- Delegated helpers receive the exact parent-validated manifest as an inherited in-memory configuration object and cannot reopen a replacement `--config` path; the nominal manifest is revalidated before and after every helper call.
- Local Git configuration is read and screened before any Git probe, safety-relevant executable and redirecting configuration is rejected, and helper Git runs force hooks and other executable extension points off. Exact local configuration is revalidated afterward; the control does not claim kernel-level prevention of a same-UID process that changes and restores configuration entirely between those checks.
- Mirror guard hooks are installed through retained directory descriptors: every existing hook leaf must already be the exact managed regular file, while missing hooks use private same-directory staging and no-replace publication. A symlink, foreign file, or partial multi-hook race blocks without following or overwriting the external target.
- Direct Git topology checks use the same bounded process supervisor, disable replacement-object and graft semantics, and reject loose or packed replacement refs plus `info/grafts` before and after workspace-helper execution.
- Daily completion derives its created, updated, unchanged, and dormant case counts from the exact validated stage and dormancy receipts, including WAL recovery.
- A case absent from control state can enter only as `watching` or `proposed`; `source_kind`, including `legacy-migration`, cannot import an approval, implementation, terminal state, or other lifecycle authority.
- A repair can enter `approved` only through a separate interactive Joey authority created after the exact ledger publication is squash-merged. The authority binds the published closure and a source-to-source-plus-one semantic delta, expires within seven days, and is consumed exactly once in the same WAL transaction that stages the approved case.
- Darwin access policy is bound from retained file descriptors as ordered ACL semantics in addition to owner/group/mode: sensitive state leaves reject every extended ACL, custody ancestors permit deny-only entries, and any allow entry or later ACL drift fails closed. Non-Darwin state records an explicit POSIX-only sentinel rather than implying ACL coverage.
- State and external-output ancestry also requires root/current-user ownership without group/world write; only a root-owned sticky directory receives the writable-ancestor exception. Benign child-entry churn remains outside the access-policy signal.
- A dedicated pinned-action `macos-15` CI lane runs the complete host bootstrap and state-engine suites plus native LaunchAgent plist validation so Darwin rename, fork, process-group, ACL, WAL, and launchd behavior is exercised on the deployment platform rather than inferred from Linux-only coverage.
- Weekly selection has no count-based candidate cap, but an immutable helper-generated preflight receipt must prove the exact draft fits the publication and WAL byte envelopes before a later Joey approval can bind it; the old implicit 4 MiB post-approval failure is not retained.
- Weekly plan and manifest outputs must remain outside the managed state-root namespace during normal execution and persisted WAL recovery; non-regular external JSON inputs, including FIFOs without writers, are opened non-blockingly and rejected before they can stall the control path.
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
