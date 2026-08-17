# Daily Audit And Pilot Replay

## Inputs

Record the actual audit start time before reading evidence. Use the last completed
Daily audit end time that is strictly earlier than that start as the lower bound.
If it cannot be recovered, report the gap and use a bounded 24-hour fallback.
Never use the current incomplete run as its own lower bound.

Historical pilot replays use an explicit frozen time range and write to an
isolated pilot staging namespace. They must not alter live case state or generate
publication artifacts.

For a scheduled run, first run:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/scripts/host_setup.py doctor --no-launchctl
```

The weekday 03:10 run depends on the host-owned 02:45 `prefetch-control`; do not
invoke, replace, or retry that prefetch from the audit.

Require top-level JSON `status: ready`, every control and main
`freshness-<stamp>-integrity`, `freshness-<stamp>-snapshot`, and
`freshness-<stamp>-age` check to be `ready`, and every repository entry to be
`ready`. Also require `freshness-final-rebind` to be `ready` so the final decision
binds the same stable freshness evidence. `--no-launchctl` skips only GUI service
load inspection; it still validates both managed plists and reload receipts,
mirror and manifest identity, locator, ownership, permissions, and both freshness
stamps. A missing, stale, failed, mismatched, or non-ready result is a blocker. Do
not fetch, call `ensure`, or create a control worktree. A scheduled run must never
add `--historical`.

For a manually requested replay explicitly labelled `historical`, run:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/scripts/host_setup.py doctor --historical --no-launchctl
```

Require `freshness_mode: historical-age-only`, every core, integrity, snapshot,
Git, and final-rebind check to be ready, and only
`freshness-daily-skill-friction-control-age` and
`freshness-daily-skill-friction-age` to be skipped. Freeze its time range and place
any replay receipts under a distinct pilot state root outside the live
`control-state`; never let the helper accept or generate live case state from that
replay.

## Procedure

Invoke every state-helper subcommand below through this exact pinned prefix; append
the shown subcommand and arguments, and never execute the script directly:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/.agents/skills/daily-skill-friction/scripts/friction_state.py
```

1. After the scheduled preflight, append `--help` and verify the live interface.
   Use `new-id --now <ISO>` for a new case. Call `digest --candidate <FILE>`, put
   its returned semantic digest into the candidate's helper-defined control field,
   then call `validate --candidate <FILE>` before staging. Never implement the
   digest projection in the prompt. Stop on an ambiguous or incompatible schema.
   Treat nonzero exit or JSON `status: error` as blocked and report its stable
   error code.
2. Use `$codex-session-mining` to enumerate, parse, and deduplicate active and
   archived rollouts since the lower bound.
3. Reconstruct substantive human root tasks without injected system, developer,
   skill, repository-guidance, reviewer, or automation wrapper text.
4. Detect skill-trigger, workflow, command-shape, approval/authentication,
   review-lane, and automation/runtime friction.
5. Apply [signal-policy.md](signal-policy.md), then reconcile each supported
   causal cluster with existing cases by stable identity and cause.
6. Run the narrow currentness check. Record unavailable validation separately
   from an absent or reproduced problem.
7. Call `stage --candidate <FILE> --state-root <DIR> --now <ISO>` for every
   validated case delta. Then call
   `transition-dormant --state-root <DIR> --now <ISO>` with that same absolute
   state root and run timestamp. Verify every JSON receipt emitted on stdout.
8. Write a version 1 `daily-audit` receipt with an `audit_id`, start/end times,
   previous snapshot digest, and the complete `receipt_id`/digest references for
   every stage and dormancy receipt anchored to that prior snapshot. Its `summary`
   object must contain exactly the following shape, replacing the example values
   with actual counts:

   ```json
   {
     "candidates_considered": 0,
     "cases_created": 0,
     "cases_updated": 0,
     "cases_unchanged": 0,
     "cases_dormant": 0,
     "no_issue_observations": 0,
     "blocked_actions": 0,
     "next_watchpoint": null
   }
   ```

   Every count is a nonnegative integer within the helper's bound. The helper
   derives `cases_created`, `cases_updated`, and `cases_unchanged` from the exact
   validated stage receipts and derives `cases_dormant` from the changed entries
   in the exact validated dormancy receipts; any supplied mismatch blocks
   completion before a completion WAL intent is written.
   `next_watchpoint` is either `null` or a 1–240 character string. Do not add
   summary fields. Then call
   `complete-audit --state-root <DIR> --receipt <FILE> --now <ISO>`. For an
   explicit replay, use the isolated pilot state root and add
   `--historical-replay`. Record the completed snapshot only after stdout reports
   JSON `status: completed` and its snapshot digest.

Do not edit or commit the control repository, evidence ledger, repair target, or
private overlay. Do not fetch, clone, push, open pull requests, or send messages.
The audit may recommend a placement but may not implement it.

## Output

Lead with supported new or changed cases. Include:

- audit start, lower bound, end time, and whether fallback was used;
- active, archived, and union candidate/parsed/accepted counts;
- duplicate groups, duplicate rollouts collapsed, and replayed-prefix counts;
- new, changed, dormant, awakened, and still-observing case summaries;
- currentness result and proposed repo-local or global scope for each changed case;
- exact staging receipt or exact blocker.

Keep diagnostic corpus and deduplication counts in the human-readable report, not
as extra fields in the helper's closed `summary` object.

For an unchanged run, emit a compact receipt with counts and the next watchpoint.
Do not expand dormant cases by default. Never claim a completed snapshot when the
staging write or its deterministic post-write verification failed.

## Pilot Gate

Keep the scheduled Daily automation paused while completing two read-only
historical replays and three live runs. Historical replays may write only their
isolated pilot state. The live runs may write the normal host-local staging and
completed snapshot, but all five runs remain read-only with respect to Git,
GitHub, canonical repositories, and the evidence ledger. Joey reviews their
evidence, false-positive rate, and staging diffs before activating the schedule.
Keep the Weekly publisher paused throughout the pilot.
