---
name: daily-skill-friction
description: Audit Joey's Codex session history for durable skill and workflow friction, stage private evidence cases, and prepare Joey-selected weekly ledger publication artifacts on the designated macOS host. Use only when explicitly invoked for a Daily Skill Friction weekday audit, historical pilot replay, weekly publication preparation, or case dormancy and effectiveness review.
---

# Daily Skill Friction

Run the host-scoped, evidence-first friction workflow. Detect and preserve cases;
never approve or implement a repair on Joey's behalf.

## Select The Mode

- For a weekday audit or historical replay, read
  [daily-audit.md](references/daily-audit.md),
  [signal-policy.md](references/signal-policy.md), and
  [case-lifecycle.md](references/case-lifecycle.md).
- For weekly publication preparation, read
  [weekly-publication.md](references/weekly-publication.md) and
  [case-lifecycle.md](references/case-lifecycle.md). Also read the currentness
  section of [signal-policy.md](references/signal-policy.md) to determine whether
  a selection became stale. Never finalize or publish a stale semantic tuple.
- For effectiveness or dormancy review, read
  [case-lifecycle.md](references/case-lifecycle.md) and only the evidence source
  reference needed for the case.

## Apply The Invariants

1. Use `$codex-session-mining` to inspect active and archived rollouts as one
   deduplicated corpus. Do not infer evidence from paths or mtimes alone.
2. Attribute signals to substantive human root tasks. Exclude synthetic prompts,
   replay echoes, reviewer chatter, automation wrappers, and bookkeeping.
3. Cluster evidence by cause before counting recurrence. Preserve bounded source
   identities and summaries; never copy raw session paths, full rollouts,
   credentials, or secrets.
4. Validate whether the suspected problem still exists in the current installed
   state with the narrowest static or no-side-effect check available. Unrelated
   installs do not reset or delay an unresolved case. A same-outcome currentness
   refresh is provenance only; an applicability or outcome change is semantic.
5. Default proposed repairs to the repository that owns the affected workflow.
   Do not infer global scope from repeated evidence inside only one root task.
6. Treat `high_signal` as urgency metadata. It may accelerate user review, but it
   never authorizes a repair, global placement, publication, push, or pull request.
7. Retain stable case identity and history. Prefer an explicit superseding or
   removal change when conditions change; do not erase the original problem.

## Use The State Helper

Treat the helper's `--help` output and accepted schemas as the field-level
authority. Invoke the exact mirrored helper only through the pinned interpreter:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 -I -B -S /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/.agents/skills/daily-skill-friction/scripts/friction_state.py --help
```

Append each helper mode and its arguments to that same interpreter and script
path. Never execute the script directly or resolve Python from `PATH`.

Use exactly these modes. A missing, renamed, or incompatible mode blocks the run
until an audited skill and schema update is installed:

- Daily: `new-id`, `digest`, `validate`, `stage`, and `transition-dormant`.
- Daily completion: `complete-audit` with a verified audit receipt; pass its
  historical replay option only in the explicit historical mode.
- Weekly preapproval: `selection-preflight` on an approval-free original draft
  containing only the selection basis, with no actor or approval time. The helper
  must persist its immutable ready receipt and committed WAL before Joey reviews
  the exact basis, receipt ID/digest, and resource preflight.
- Weekly planning: `weekly-plan` only with a separately approved selection that
  binds that exact helper receipt and basis. Its `approved_at` must be strictly
  later than the receipt's `checked_at`; the scheduled run must never add or
  infer approval fields.
- Weekly completion: `finalize-publication` only after exact prepared-commit
  receipts exist. There is no count cap, but the helper's aggregate publication
  and Weekly/finalization WAL byte envelope must fit before approval.
- Later interactive publication accounting: `close-publication` only with the
  helper-defined closure receipt for a verified published, cancelled, or stale
  outcome. A published closure additionally requires the separate exact Joey
  approval receipt supplied with `--publish-receipt`; the manifest is not that
  approval. A scheduled Daily or Weekly run must never invent or apply either
  receipt.
- Later interactive repair decision: `approve-repair` only after an exact
  `published` closure is committed. It requires Joey's current interactive
  confirmation and a separate time-bounded receipt binding the source and target
  case tuples plus the closure, manifest, pull request, merge commit, and merge
  time. Publication approval is not repair approval. Only a later exact `stage`
  transaction may consume that authority once; scheduled Daily and Weekly runs
  must never call this mode or stage a case from `proposed` to `approved`.

Put durable run state under the host-local
`/Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/control-state`
root, never in Git. If the helper, schema, or state root is missing or inconsistent,
report blocked without inventing fields or rewriting existing state.

The helper treats object identity, file content, and access policy as separate
protected properties. On Darwin it reads extended ACLs through each retained file
descriptor and binds a canonical digest of the kernel-ordered tag, UUID,
permission, and flag entries. Sensitive state leaves must have no extended ACL;
custody ancestors may retain deny-only entries such as the home-directory deny
delete ACE, but any allow entry is rejected. State markers and external WAL
bindings persist these ACL digests and every open/recovery path revalidates them.
Legacy state without that binding fails closed. Other platforms record the
explicit `posix-mode-only-v1` model and do not claim extended-ACL enforcement.
`mtime`, `ctime`, link count, and ordinary directory child churn are not access or
content changes by themselves.

## Run The Scheduled Preflight

Before a scheduled Daily reads evidence or writes state, run:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 -I -B -S /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/scripts/host_setup.py doctor --no-launchctl
```

The weekday 03:10 run depends on the host-owned `prefetch-control` at 02:45; it
must not invoke or replace that prefetch itself.

Before a scheduled Weekly, run the exact Weekly variant:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 -I -B -S /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/scripts/host_setup.py doctor --weekly --no-launchctl
```

Require top-level `status: ready`. Both variants validate each freshness stamp's
integrity, current repository snapshot, and age at the manifest's 60-minute limit,
plus the exact repository sets and host setup; require `freshness-final-rebind` to
be `ready`. Weekly additionally requires the `weekly-pair-receipt` check to bind
the current two stamp digests, manifest digests, repository sets, and prefetch
completion time. A missing, stale, failed, mismatched, or non-ready result blocks
the run. Do not fetch, call `ensure`, or use
`prepare-run` to manufacture a control-repository worktree. The Friday 07:00
Weekly run depends on the host-owned combined prefetch at 06:30; it must not fall
back to the older Daily stamps.

For an explicitly requested read-only historical Daily pilot replay, use:

```text
/Users/hoteng/.local/share/uv/python/cpython-3.14.2-macos-aarch64-none/bin/python3.14 -I -B -S /Users/hoteng/Program/GitHub/Joey-Tools/codex-workspace/.codex-local/daily-skill-friction/repos/codex-host-workflows/scripts/host_setup.py doctor --historical --no-launchctl
```

Require `freshness_mode: historical-age-only`. This skips only the age check for
each of the two stamps; their integrity, current Git snapshots, and every core host
check must remain ready. Label the run `historical`, freeze its time range, and use
a separate pilot state root. Never silently downgrade a scheduled run into this
path, and never combine `--historical` with the Weekly variant.

## Respect Mode Boundaries

### Daily and historical replay

- Read the corpus and write only host-local staging state through the state helper.
- Keep repair lifecycle at `proposed` or earlier. Never submit a
  `proposed`-to-`approved` candidate or invoke the interactive repair decision
  path from a scheduled or replay run.
- Do not edit canonical repositories, create commits, push, open pull requests,
  or make network-dependent changes.
- Report blocked inputs distinctly from a clean no-change result.

### Weekly publication preparation

- Consume the last completed Daily state without waiting for another Daily run.
- Require a prior interactive handoff to run `selection-preflight` on the exact
  basis-only draft, which contains no actor or approval time, and persist its
  immutable helper receipt. Joey must then separately approve that basis,
  resource preflight, and receipt ID/digest after the receipt's `checked_at`. The
  scheduled run may only consume the resulting approved selection through
  `weekly-plan`; it must never create, edit, infer, or impersonate approval.
- Apply no count cap. Require the helper's exact aggregate byte envelope for the
  publication artifacts and both Weekly/finalization WAL transactions to fit,
  then prepare at most one local ledger branch and one signed local commit per
  selected case and finalize one exact immutable publication manifest.
- Treat that finalized manifest only as an exact binding and scope receipt. It
  requires a later exact Joey publish approval before any push, pull request, or
  merge.
- Do not push, open a pull request, retry a failed publication automatically,
  replace an approved commit, close publication state, approve a repair, or begin
  a repair.

### Repair handoff

- Stop after presenting cases and exact publication artifacts for Joey's choice.
- A later interactive workflow may publish approved case commits one PR per case.
- After the ledger case PR is squash-merged and its exact `published` closure is
  committed, obtain and persist a separate exact repair approval. Stage only its
  bound next revision; that stage consumes the approval once in the same WAL
  transaction as the case and receipt.
- Begin a repair only after that exact approved case revision has a committed
  stage transaction.
- Every repair commit must identify the concrete problem with the safe trailer
  `Friction-Case: DSF-<uuidv7>`.

## Fail Closed

If a required helper, schema, mirror, freshness record, signing capability, or
case identity is missing or inconsistent, preserve existing state and report the
exact blocker. Do not clone, fetch, synthesize replacement state, or broaden
permissions from an unattended run.
