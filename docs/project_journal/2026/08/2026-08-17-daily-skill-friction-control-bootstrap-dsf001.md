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
- Atomic file replacement writes staged content under a private temporary name, then applies and verifies the exact requested permission mode on the retained descriptor before fsync and publication; caller `umask` cannot silently narrow a managed Git exclude or LaunchAgent file.
- Host control subprocesses use fixed system executables, isolated Python startup, and a manifest-bound account home under a rebuilt environment; writable `PATH` entries cannot substitute Git, SSH, launchctl, or Python startup behavior.
- LaunchAgent readiness uses a closed behavior schema for the loaded service, including every calendar trigger, event channel, scheduling default, process type, and launch property; a foreign or behavior-augmented service reusing the managed label is blocked.
- Control-state transactions bind every directory from the filesystem root through the state root, plus every retained root-relative directory component used by cases, receipts, and WAL operations, by object identity, access policy, and parent-visible name before publication and recovery. Transaction and case file leaves are not retained as directory bindings, and benign child-entry churn is not treated as replacement.
- External Weekly WAL outputs retain the original destination-parent identity and access-policy chain across recovery; missing, rebound, or unsafe parents are never recreated or silently adopted.
- A failed WAL commit publication rolls back only the exact leaf linked by that invocation, including failures after link publication but before `write_json` returns; global recovery validates canonical intent/commit pairing and every WAL leaf before replaying any transaction.
- Delegated helper and launchctl stdout/stderr share a 1 MiB retained-output ceiling; overflow and timeout both terminate, drain, kill, and reap the complete managed process group before returning a bounded diagnostic.
- Delegated workspace helpers are compiled and executed from exact stable in-memory source bytes in a fork of the already-running isolated interpreter; no post-preflight Python or helper pathname is executed. The current interpreter and OS loader are explicit startup trust roots, and this process does not claim to retrospectively prove a pre-start vnode.
- Delegated helpers receive the exact parent-validated manifest as an inherited in-memory configuration object and cannot reopen a replacement `--config` path; the nominal manifest is revalidated before and after every helper call.
- Local Git configuration is read and screened before any Git probe, safety-relevant executable and redirecting configuration is rejected, and helper Git runs force hooks and other executable extension points off. Standalone mirrors reject worktree-config activation and bind the absence of `.git/config.worktree`; exact configuration sources are revalidated afterward. The control does not claim kernel-level prevention of a same-UID process that changes and restores configuration entirely between those checks.
- Bootstrap compatibility is profile-scoped rather than globally relaxed: the stable workspace may carry one exact `extensions.worktreeConfig=true` only while `.git/config.worktree` remains absent, and a managed mirror may carry one exact absolute `core.hooksPath` to its own bound `.git/hooks` directory and exact managed hook leaves. This records and fixes the real first-host plan failure without admitting foreign paths, duplicate values, subsection lookalikes, or worktree config in mirrors. Remove the exceptions if the workspace stops using worktree-local config or the shared helper stops installing explicit mirror hook paths.
- Mirror guard hooks are installed through retained directory descriptors: every existing hook leaf must already be the exact managed regular file, while missing hooks use private same-directory staging that is verified at its final executable mode before no-replace publication. A symlink, foreign file, partial multi-hook race, or canonical non-executable window blocks without following or overwriting the external target.
- Direct Git topology checks use the same bounded process supervisor, disable replacement-object and graft semantics, and reject loose or packed replacement refs plus `info/grafts` before and after workspace-helper execution. Standalone mirrors also reject `commondir`, `core.alternateRefsCommand`, and both local object-alternates leaves while retaining and revalidating the `.git/objects/info` chain; ordinary object and pack churn remains outside this source-set signal.
- Managed mirror cleanliness rejects status-suppressing assume-unchanged and skip-worktree entries plus unmerged or other non-`H` index stages before and after delegated helper operations. Each decision checkpoint runs bounded status with fixed safe stat settings between two exact index listings, requires that status to be empty, and the final semantic decision repeats that complete sequence. This proves tracked worktree drift is observable and absent at those checkpoints; it does not inspect the separate fsmonitor-valid bit or claim continuous exclusion of same-UID change-and-restore races. Mirror object identity and access policy remain separate signals, and the already-started control interpreter remains the documented startup trust boundary.
- Installed LaunchAgent content and access policy are independent readiness signals. A managed content-identical plist at any mode other than exact `0644`, including a legacy `0600` file, requires atomic republication; benign timestamp changes alone remain ready.
- Daily completion derives its created, updated, unchanged, and dormant case counts from the exact validated stage and dormancy receipts, including WAL recovery.
- A case absent from control state can enter only as `watching` or `proposed`; `source_kind`, including `legacy-migration`, cannot import an approval, implementation, terminal state, or other lifecycle authority.
- A repair can enter `approved` only through a separate interactive Joey authority created after the exact ledger publication is squash-merged. The authority binds the published closure and a source-to-source-plus-one semantic delta, expires within seven days, and is consumed exactly once in the same WAL transaction that stages the approved case.
- Darwin access policy is bound from retained file descriptors as ordered ACL semantics in addition to owner/group/mode: sensitive state leaves reject every extended ACL, custody ancestors permit deny-only entries, and any allow entry or later ACL drift fails closed. Non-Darwin state records an explicit POSIX-only sentinel rather than implying ACL coverage.
- State and external-output ancestry also requires root/current-user ownership without group/world write; only a root-owned sticky directory receives the writable-ancestor exception. Benign child-entry churn remains outside the access-policy signal.
- A dedicated pinned-action `macos-15` CI lane runs the complete host bootstrap and state-engine suites plus native LaunchAgent plist validation so Darwin rename, fork, process-group, ACL, WAL, and launchd behavior is exercised on the deployment platform rather than inferred from Linux-only coverage.
- Weekly selection has no count-based candidate cap, but an immutable helper-generated preflight receipt must prove the exact draft fits the publication and WAL byte envelopes before a later Joey approval can bind it; the old implicit 4 MiB post-approval failure is not retained.
- Weekly plan and manifest outputs must remain outside the managed state-root namespace during normal execution and persisted WAL recovery; non-regular external JSON inputs, including FIFOs without writers, are opened non-blockingly and rejected before they can stall the control path.
- Equivalent legal UTC timestamp spellings are compared as parsed instants rather than formatter output, so whole seconds and 1–6 fractional digits remain compatible with the frozen ledger schema.
- Completed full WAL pairs retire into bounded compact checkpoints that contain only digests, locators, and immutable-authority bindings. New-key and active-key operations scan only the bounded active set; retired exact-key lookup and the explicit full-history audit validate the complete bounded usage chain. Revert this layout only if another reviewed bounded transaction index replaces its first-writer, crash-recovery, and external-output guarantees.
- Compact-history publication uses fixed helper-owned temporary leaves that can be recovered only after exact identity, content, private-access, name, and link-shape validation; foreign or malformed leaves remain blocked. Retired exact-key lookup proves membership through a bounded read-only replay of the current global usage chain, while new-key and active paths do not scan permanent history. A conflicting natural-key request is rejected before any history maintenance so failed input cannot advance usage or retire another transaction. Final temp cleanup relies on the cooperative state lock and does not claim impossible protection from an uncooperative same-UID writer. Revert these guards only when a replacement preserves authenticated membership, crash convergence, and rejected-input non-mutation.
- Generated CI pins every third-party Action to a full commit SHA, disables persisted checkout credentials, and selects exact Node, Python, uv, Go, Rust, actionlint, and shfmt versions. Change those pins only through the authoritative generator and its round-trip contract when a reviewed dependency update requires it.
- Generated Python CI uses `uv sync --locked` whenever `uv.lock` exists, and the Node tooling job executes the committed setup-ci contract tests when present. This keeps the tested dependency graph and generated workflow pins identical to the reviewed repository state.
- The forked-helper descendant timeout regression begins its supervisor deadline only after an atomically published readiness receipt proves that the descendant exists. A separate test retains coverage for timeout before `setsid`; this avoids treating slow descriptor closure under full-suite load as a process-group cleanup failure.
- The redesigned Daily path is evidence-only. Publication and repair happen in the explicit Weekly path, with separate approval boundaries for creating changes, pushing, and opening a PR.
- The existing private overlay remains independently installed and is not absorbed into this host manifest. Host-only control can be removed without changing overlay installation; each later squash commit must describe the concrete friction it addresses so a no-longer-needed repair can be identified and reverted.
- Daily and Weekly run from the stable local `codex-workspace` project, not an app-generated worktree: the host-only skill locator is intentionally untracked and points into that workspace's `.codex-local` mirror, so it would be absent or broken in a generated worktree. Their skill contracts prohibit workspace writes; this local-mode choice can be revisited only if skill discovery gains a verified host-wide or per-worktree locator.

## Next Steps

- Run the explicit first-host bootstrap after Joey authorizes the helper `ensure`, then complete the read-only replay and live-run pilot before enabling the paused Daily and Weekly schedules.

## Evidence

- `config/host-workspace.toml`
- `scripts/host_setup.py`
- `tests/test_host_setup.py`
- `.agents/skills/daily-skill-friction/scripts/friction_state.py`
- `.agents/skills/daily-skill-friction/references/daily-audit.md`
- `.agents/skills/daily-skill-friction/references/weekly-publication.md`
- `tests/test_friction_state.py`
- `.github/workflows/ci.yml`
- `scripts/setup-ci.mjs`
- `test/setup-ci.node-test.mjs`
- `launchd/com.hoteng.codex.daily-skill-friction-control-prefetch.plist`
- `launchd/com.hoteng.codex.daily-skill-friction-weekly-prefetch.plist`
