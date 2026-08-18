# Case Lifecycle And Traceability

## Identity And Minimum Record

Create a case identity once with UUIDv7 and render it as `DSF-<uuidv7>`. Keep a
short readable title alongside the identifier. Never derive identity from a file
path, date, current version, or mutable title.

Keep the structured case compatible with the state helper and ledger schemas.
Treat their accepted field names and lifecycle status values as authoritative;
do not duplicate or extend their enums in prose. Preserve at least these meanings:

- identity, title, origin, and current lifecycle status;
- narrow problem statement and expected behavior;
- causal cluster and bounded evidence pointers or summaries;
- first seen, `evidence_last_seen`, `lifecycle_changed_at`, and
  `currentness_checked_at` as separate values;
- candidate strength, proposed owning scope, and the reason for that scope;
- explicit `revisit_when` conditions;
- repair provenance and links when the ledger schema permits them;
- effectiveness criteria and observations.

Never store complete rollouts, raw prompt dumps, credentials, secrets, or evidence
unrelated to the case. Preserve a legacy source digest, date, and migration
manifest when importing an older record. Keep every persisted evidence occurrence
unchanged and in its original order; append new occurrences after that exact
prefix rather than rewriting or reordering history.

## Semantic Transitions

Use the state helper and repository schema as the field-level authority. Preserve
these semantic boundaries even if field names evolve:

The canonical semantic digest covers the exact ledger case after excluding only
its top-level integer revision and `currentness_checked_at`. Always obtain it from
`digest --candidate`; never reproduce that projection in the prompt.

1. observe and stage the case locally as watching or proposed;
2. bind a trusted interactive publication-selection receipt in control state;
3. prepare an exact signed local commit and immutable manifest in control state;
4. bind a separate later interactive publication approval before push or PR;
5. publish the case only after its one-case ledger PR is squash-merged;
6. after either verified merge or a separate interactive cancellation/staleness
   decision, close the active publication control state with an exact receipt
   while retaining its immutable plan, manifest, and closure history;
7. after a verified `published` closure, persist Joey's separate exact repair
   approval and consume it once when staging the bound next revision;
8. install the selected repair and begin effectiveness observation;
9. mark the case effective, dormant, superseded, or no longer applicable.

Every case absent from the selected control state must enter at `watching` or
`proposed`, including a record labelled `legacy-migration`. The helper has no
separate authorized migration-import mode, so `source_kind` cannot grant
lifecycle authority or skip publication and repair decisions.

The selection receipt, pending commit, manifest, publication approval, and PR
workflow state belong to host-local control state, not the ledger case schema.
Selection approval authorizes only local preparation; publication approval
authorizes only the later bound push and PR; neither authorizes a repair. The
ledger case status `approved` means repair-approved and occurs only through the
separate authority and consumption in step 7.
Never let a scheduled automation infer steps 2, 4, 6, or 7.

The later interactive publisher records a verified published outcome through:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 -I -B -S /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/.agents/skills/daily-skill-friction/scripts/friction_state.py close-publication --state-root <DIR> --receipt <FILE> --publish-receipt <FILE> --now <ISO>
```

The separate `publication-approval` receipt must record Joey's interactive
approval and bind the exact selection, plan, finalized manifest, and approved case
subset. For a verified cancelled or stale outcome, omit `--publish-receipt`; the
helper-defined closure receipt must still bind that exact outcome. A finalized
manifest alone is neither publication approval nor a closure receipt. Use
`stale` only when actual semantic or lifecycle drift is present, never as a retry
escape.

Keep an unapproved or failed publication stable as `pending-publication` in
control state; do not auto-retry, silently regenerate, replace its commit SHA, or
create a duplicate case. A same-outcome currentness check that changes only
`currentness_checked_at`, and an unrelated install with no semantic effect, do not
create a semantic revision, change eligibility, or advance `lifecycle_changed_at`.
A changed currentness outcome or applicability is semantic and must advance the
revision and semantic digest. Every lifecycle-status change and every other value
included in the helper's canonical semantic projection must likewise increment
the integer revision and recompute that digest.

## Interactive Repair Approval

This is a separate interactive control-plane action, not a scheduled Daily or
Weekly mode. Start with the current `proposed` wrapper and construct the exact
target wrapper at source revision plus one. The target may change only the
lifecycle fields needed for `proposed` to `approved`, the active repair state from
`planned` to `planned` or `open`, and that active repair's pull-request URL. It
must not change evidence, scope, lineage, title, cause, applicability, repair
history, or another semantic field. A same-outcome refresh to only
`currentness_checked_at` does not invalidate the semantic tuple.

The version 1 `repair-approval` receipt has exact top-level fields `version`,
`kind`, `approval_id`, `interaction`, `expires_at`, `source`, `target`, and
`publication`. `source` and `target` each bind the exact case ID, integer revision,
and helper-produced canonical semantic digest. `interaction` is exactly
`interactive: true`, `actor: Joey`, and `approved_at`. `publication` binds the
exact committed `published` closure ID/digest, selection ID, plan and manifest
digests, ledger pull-request URL, squash commit, and `merged_at`. The helper
requires `approved_at` to be strictly later than both `merged_at` and the closure
time, no later than the invocation time, and before `expires_at`; validity may not
exceed seven days.

Only after Joey makes that exact decision, run:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 -I -B -S /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/.agents/skills/daily-skill-friction/scripts/friction_state.py approve-repair --state-root <DIR> --candidate <APPROVED-CANDIDATE> --approval <RECEIPT> --now <ISO> --confirm-interactive-joey-decision
```

The explicit confirmation flag attests the current interactive handoff; a caller
must not set it from an unattended run. Success immutably writes the receipt and
its exact source/target index in one committed `approve-repair` WAL transaction.
The helper accepts neither a publication approval nor an uncommitted, cancelled,
or stale closure as repair authority.

Then call `stage` on only that bound target. The stage transaction revalidates the
source and target semantic tuples, full closed repair delta, published closure
provenance, authority WAL, time window, and unused state. It atomically writes one
immutable consumption record together with the approved case and stage receipt.
One authority permits one consumption; a different target, forged closure,
expired receipt, or already consumed authority fails closed. Recovery or exact
replay completes or returns the same committed transaction rather than consuming
the decision again.

## Dormancy

Retain every case. After 30 days with no lifecycle state change, use the state
helper to transition only a `watching` or `proposed` case with no pending
publication control state to `dormant`. Never auto-dormant a case with pending
publication, or a case that is `approved`, `implemented`, `observing`, `closed`,
or `superseded`. A case already present on the ledger default branch remains
eligible when its case status is still `watching` or `proposed`; changing that
ledger case still requires the ordinary approved one-case update PR. Base the
clock only on `lifecycle_changed_at`, not evidence, install, or currentness
timestamps. Exclude dormant details from expanded routine reports unless new
evidence, a `revisit_when` condition, or Joey's request wakes the case. Dormancy is
not proof that the problem is fixed.

## Repair Traceability

Keep each semantic repair change traceable to exactly one case. The repair commit
message must describe the concrete problem, why the change addresses it, and
include exactly one safe trailer:

```text
Friction-Case: DSF-<uuidv7>
```

Do not put sensitive evidence in commit messages. If the original problem later
disappears or assumptions change, make a forward removal or superseding change
linked to the same case. Do not blindly revert an unrelated aggregate commit.
Review open conditions monthly and whenever a recorded `revisit_when` condition
becomes true.

## Effectiveness

Installation is not effectiveness. Close the observation loop with the applicable
gate:

- Deterministic remedy: prove the intended installed artifact contains the
  change and a targeted regression test passes.
- Behavioral remedy: observe at least three relevant post-install opportunities
  after the currently selected repair's installation, over at least seven days,
  with no recurrence of the supported cause. An older superseded repair's install
  date cannot start this window.

If the opportunity count is insufficient, remain under observation. If the cause
recurs, append bounded evidence to the same case and return it for review rather
than minting a replacement identity. Mark effectiveness `failed` only when the
recorded applicable gate actually fails; do not contradict a passing deterministic
or behavioral observation.

Do not transition a case to `closed` until its applicable effectiveness gate has
passed.

## Sealed Same-Case Reopen

A closed case may return directly to `proposed` only through the ledger schema's
sealed same-case reopen transition. Require all newly appended recurrence evidence
to be strictly later than both the prior effectiveness `checked_on` and the prior
case closure time, with at least one occurrence matching a cause already present
in the case and the resulting support classified as `repeated`. Preserve the case
identity and all earlier evidence.

In that one transition, require and supersede the single previously current
repair, append exactly one new `planned` repair whose action is `install` or
`amend`, retain the prior
effectiveness method, and reset effectiveness to `not-started` with no evaluation.
The scheduled Daily may stage this proposal but must not approve the repair or
skip the later separate repair decision. This is the only closed-to-active
transition. A separate schema-valid closed-to-`superseded` transition remains
terminal; a `superseded` case cannot reopen or mutate.
