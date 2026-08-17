# Weekly Publication Preparation

## Inputs

First run:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/scripts/host_setup.py doctor --weekly --no-launchctl
```

Require top-level JSON `status: ready`; every control and main stamp integrity,
snapshot, and age check to be `ready`; every repository entry to be `ready`; and
both `freshness-final-rebind` and `weekly-pair-receipt` to be `ready`. The pair
receipt must be no more than 60 minutes old and must bind the current two stamp
digests, their completion time, manifest digests, and exact repository sets.
`--no-launchctl` skips only GUI service load inspection; it still validates both
managed plists and reload receipts, mirror and manifest identity, locator,
ownership, permissions, and freshness evidence. A missing, stale, failed,
mismatched, or non-ready result blocks the run. Do not fetch, call `ensure`, create
a control worktree, or add `--historical`. The Friday 07:00 run requires the
host-owned combined prefetch at 06:30, which invokes
`prefetch-weekly` sequentially for control then main and updates the pair receipt
only when both succeed. If it did not complete, report blocked; do not widen the
age limit or fall back to the older Daily stamps.

Use the latest completed Daily state available when the Weekly run starts. Do not
wait for, trigger, or synthesize another Daily run. Before planning, inspect the
control-state registry for the receipt's selection ID. If it already has an exact
immutable plan, active entry, or finalized manifest, verify and report that state
without recreating, advancing, or retrying it automatically.

For a new trusted selection ID, run:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/.agents/skills/daily-skill-friction/scripts/friction_state.py weekly-plan --state-root <DIR> --selection <FILE> --output <FILE> --now <ISO>
```

Use the same absolute live state root. Require JSON `status: planned` and retain
its plan digest. The helper's validated JSON and schema are the field-level
authority. The plan freezes selection input but authorizes no push, pull request,
merge, or repair. Treat `selected_daily_snapshot_digest` as selection provenance
and `planned_from_current_snapshot_digest` as planning provenance; neither replaces
the per-case semantic selection binding.

Only cases bound by a trusted version 1 `publication-selection` receipt are
eligible. It must bind a stable selection ID, `interaction.interactive: true`,
`interaction.actor: Joey`, selection time, the completed Daily snapshot used for
selection as provenance, ledger repository/base branch/base SHA intent, and every
selected case's exact ID, integer revision, and canonical semantic digest. A newer
completed snapshot does not stale the receipt when those per-case semantic
bindings remain current. An urgency label, prior discussion, or broad approval
does not substitute for that receipt. Selection approval authorizes only local
preparation; a separate later publication approval authorizes the interactive
publisher to push and open the bound PR subset.

Require the receipt's repository, base branch, and base SHA to match the exact
configured `codex-skill-friction-ledger` mirror identity and default-branch state.
Do not honor a receipt that redirects preparation to another repository.

The scheduled run must never create, edit, or infer the selection receipt. It may
only consume the exact host-local artifact produced by the prior interactive Joey
decision. The helper validates the receipt's structure and bindings, not the human
actor's identity by itself; if provenance cannot be established from that
interactive handoff, report blocked as untrusted selection.

## Prepare One Case At A Time

For each selected case returned in the validated Weekly plan:

1. Recheck currentness, lifecycle, and exact semantic revision against the
   selection receipt. Bind validity to case ID, integer revision, and canonical
   semantic digest. A changed applicability, currentness outcome, lifecycle, or
   other semantic value is `stale-selection`; skip it unchanged and preserve the
   reason without manufacturing a repair. A same-outcome check that changes only
   `currentness_checked_at`, a newer snapshot, or a changed full-file digest alone
   does not stale the selection.
2. Require a clean, configured local ledger mirror and a repository-owned
   per-run worktree. Run target-specific strict status from the stable workspace:

   ```text
   /Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/scripts/codex_workspace.py status --repo codex-skill-friction-ledger --strict
   ```

   Require the mirror's configured base branch to be at the plan's exact base SHA
   before creating a branch. Before calling `prepare-run`, inspect the plan's
   deterministic branch ref and run path without mutation. If either already
   exists and an exact immutable prepared receipt binds its case, selection, base,
   branch, and commit, verify and preserve it, then stop that entry without
   advancing or retrying it. Any pre-existing ref or path without that exact
   binding is a collision and blocks the entry. A plan, active entry, or manifest
   that predated this run follows the earlier stop-and-report rule even if no ref
   exists.

3. Only when both the deterministic branch ref and run path are absent, run this
   command with the Weekly run date, the lowercase case ID as its deterministic
   topic, and the exact branch from the plan:

   ```text
   /Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/scripts/codex_workspace.py prepare-run --repo codex-skill-friction-ledger --date <YYYY-MM-DD> --topic <lowercase-case-id> --branch <plan-branch> --offline --fresh-stamp daily-skill-friction --fresh-within-minutes 60
   ```

   Before any file or commit write, recheck that the returned worktree has the
   plan's exact branch and base SHA. Any mismatch blocks the entry without creating
   an immutable commit. Do not clone or fetch during the unattended run.

4. Write the exact ledger case object and path frozen in the plan. Do not rebuild
   it from a later timestamp or add journal, control-state, or unrelated index
   changes to the data-only evidence repository.
5. Run the ledger's lightweight schema and formatting validation.
6. Create one signed local commit whose subject names the concrete case problem.
   Do not mix cases or control-plane changes.
7. Freeze a publication entry binding case ID/revision, branch, commit SHA, base
   SHA, changed paths, validation result, and verified signature evidence.

A signing failure is a blocker. Do not try alternate identities, unsigned commits,
or a replacement branch. An already prepared exact commit is immutable.

## Publication Manifest

Write a version 1 `prepared-commits` receipt only after direct Git verification is
complete. Bind the exact plan digest and every planned entry's case ID, integer
revision, canonical semantic digest, plan-provided case-content digest,
deterministic branch, base SHA, and changed paths, plus its commit SHA, passed
local validation commands/time, and verified signature evidence binding that
commit SHA, signer, and verification time. Then call:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/.agents/skills/daily-skill-friction/scripts/friction_state.py finalize-publication --state-root <DIR> --plan <FILE> --prepared <FILE> --output <FILE> --now <ISO>
```

Require JSON `status: finalized`, manifest path, and manifest digest. The helper
must revalidate the registered immutable plan, the selected cases' unchanged
integer revisions and canonical semantic digests, the exact prepared set, branch,
base, changed paths, local validation, and signature evidence before atomically
writing the final batch manifest. A newer Daily snapshot or a same-outcome change
only to `currentness_checked_at` may be recorded but cannot block finalization by
itself. Preserve the helper's `finalized_against_current_snapshot_digest` as
additional provenance, fixed ordering, and full digest. Semantic drift blocks
finalization; never repair it by moving a branch or replacing a commit.

The state helper never executes Git and therefore validates structured bindings,
not the external repository by itself. Obtain every prepared field from direct
read-only Git verification after the signed commit exists. The later interactive
publisher must recheck the actual branch, base, commit, path set, and signature
plus the committed case-content digest against the finalized manifest before any
push or pull request.

Only the finalized publication manifest is an eligible exact binding and scope
receipt for a later interactive decision. It does not itself authorize push, pull
request, merge, or repair; a Weekly plan and prepared receipt authorize nothing
either.

If Joey later approves publication, the interactive publisher must capture the
helper-defined `publication-approval` receipt before acting. That receipt binds
Joey's exact approved subset to the selection, plan, and finalized manifest. Only
after verifying the approved publication outcome may that separate workflow call
`close-publication` with both its closure receipt and `--publish-receipt`; the
scheduled Weekly never creates either receipt or calls that command.

The manifest defines the exact scope that Joey's later publish approval may bind:

- it never grants permission to push, open a pull request, or merge;
- approval may select any subset without regenerating the other entries;
- each approved entry later becomes one PR and one squash commit;
- no extra required PR checks are assumed, but local schema/format validation is
  mandatory;
- an unapproved or failed entry remains stable as `pending-publication` with the
  same case, branch, and commit SHA;
- there is no candidate cap, automatic retry, or replacement commit.

Do not push, open or update pull requests, merge, dispatch workflows, begin
repairs, close publication control state, or modify the control repository. Report
the manifest path and digest, then stop for Joey's review.

## Empty Run

An explicitly empty trusted selection is valid. Finalize an empty publication
manifest only when the helper-validated plan itself contains zero entries, either
because the trusted receipt selected none or because every requested case has a
helper-recorded `stale-selection`, `missing-case`, or `ineligible-lifecycle`
reason. In that case, create no branch or commit and use an exact empty
`prepared-commits` receipt. Report its digest and the helper's skip reasons
verbatim. If the plan contains any entry, the prepared receipt must contain every
entry exactly; a missing or blocked preparation prevents finalization rather than
turning the run into an empty manifest. Never infer an empty selection when no
trusted receipt exists.

Keep the scheduled Weekly automation paused until the Daily pilot is accepted and
Joey explicitly enables publication preparation.
