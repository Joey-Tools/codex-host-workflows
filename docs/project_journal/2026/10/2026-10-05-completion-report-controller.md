---
id: 20261005-completion-report-controller
title: Review Gate Completion Reporting Controller
status: completed
created: 2026-10-05
updated: 2026-10-05
branch: master
pr:
supersedes: []
superseded_by:
---

# Review Gate Completion Reporting Controller

## Summary

- Install the canonical review-gate controller for the v2.1.7 action release so completed verifier runs report against the exact workflow-run head.
- Align completion admission and empty-association concurrency with the source controller hardening snapshot.
- Preserve the opt-in, first-attempt, failed-run, and single-pull-request association boundaries for automatic review requests.

## Current State

- The controller matches canonical source commit `97268b8a83213300182e9f699eb5cb4dba627670` byte-for-byte (blob `c6290c800903303151cbfb34ca706463118b0d09`) and routes ordinary verifier completion through `report-completion` using `workflow_run.head_sha`.
- Completion admission accepts only the exact canonical bare workflow path or a qualified `@refs/pull/.../merge` path. This is a pre-run shape filter, not numeric PR validation; the v2.1.7 runtime independently validates its fixed workflow identity and run binding.
- Concurrency remains PR/issue/manual-association scoped when available, then falls back to `workflow_run.id` and `github.run_id` so unrelated empty-association completion runs do not share the empty group. `cancel-in-progress: false` remains in force.
- Automatic `begin-review` and `request_review` remain gated by `CODEX_REVIEW_GATE_AUTO_REQUEST`, first attempt, failure, and the single-associated-pull-request check.
- The verifier and `.github/CODEOWNERS` are unchanged. This controller-only source hardening does not modify the published Action payload, release manifest, version, or immutable tags, and does not claim that live repository variables, rulesets, or required checks were changed or verified.

## Next Steps

- No further controller-source work is in scope. Any live variable, ruleset, or required-check operation remains a separate workflow.

## Evidence

- Canonical source hardening snapshot: `codex-review-gate` commit `97268b8a83213300182e9f699eb5cb4dba627670`, controller blob `c6290c800903303151cbfb34ca706463118b0d09`.
- Local validation: actionlint 1.7.12 on verifier/controller, exact controller comparison, and the focused `tests/test_review_gate_workflows.py` contract test. The broader source controller suite hit its 120-second deadline with descendant cleanup unverified; it is not counted as passed.
