---
id: 20261024-chw001
title: Codex Review Gate Event Upgrade
status: completed
created: 2026-10-24
updated: 2026-10-24
branch: master
pr:
supersedes: []
superseded_by:
---

# Codex Review Gate Event Upgrade

## Summary

- Upgrade the consumer verifier/controller pair to the canonical v2.2.12 workflows.

## Current State

- The verifier accepts `stacked` and `edited`; non-base-ref edits use isolated ignored titles and concurrency, while the controller only processes verifier-titled workflow runs.
- The workflow supports configurable runner labels while preserving the existing hosted-runner fallback. The `@v2` action pin, token wiring, auto-request behavior, and limits-profile behavior are unchanged; no repository settings were modified.
- The repository's `actionlint` invocation ignores only its diagnostic for the `stacked` activity on `pull_request`; all other actionlint checks remain enabled.
- The source pair matches the designated canonical files byte-for-byte. No repository settings were modified.

## Next Steps

- Use a separate live canary before making operational claims about deployed behavior.

## Evidence

- Same-PR CI jobs `120886733192`, `120886733346`, and `120886733274` reported formatting of this note, formatting of `tests/test_review_gate_workflows.py`, and actionlint 1.7.12's unsupported `stacked` activity diagnostic, respectively.
- Prettier 3.9.6 formatted and checked this note. The static workflow test's wrapping matches Ruff's formatter output; local Ruff 0.13.2 format-check passed, while `uv.lock` pins Ruff 0.16.3.
- The exact actionlint ignore passed the repository-wide workflow check; the exception pattern is limited to `stacked` for `pull_request`. Journal validation and `git diff --check` passed.
- Follow-up CI job `120890336079` caught the generator/checked-in workflow mismatch.
- `scripts/setup-ci.mjs` now emits the same narrow actionlint invocation as the checked-in CI workflow. `node --test test/setup-ci.node-test.mjs` passed all 21 tests, including the workflow round-trip.
- No full CI rerun, live canary, or runtime behavior is claimed.
- `.github/workflows/codex-review-gate.yml`
- `.github/workflows/codex-review-gate-controller.yml`
- `.github/workflows/ci.yml`
- `tests/test_review_gate_workflows.py`
