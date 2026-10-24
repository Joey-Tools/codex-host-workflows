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

- Synchronize the consumer verifier/controller pair with the canonical v2.2.13 workflows.
- Canonical source: [codex-review-gate PR #146](https://github.com/Joey-Tools/codex-review-gate/pull/146), released as v2.2.13.

## Current State

- The verifier retains `opened`, `reopened`, `synchronize`, `ready_for_review`, `stacked`, and `edited`. All events use the standard verifier title, per-PR concurrency group, and job name; the ignored-edit title, isolated concurrency group, and job guard are absent.
- The controller remains byte-identical to the canonical source and continues to process verifier-titled runs.
- The `@v2` action, permission envelope, configurable runner labels and fallback, token wiring, auto-request behavior, and limits profile are preserved. No repository settings or CI generators were modified.
- The repository's `actionlint` invocation suppresses only the known unsupported `stacked` activity diagnostic for `pull_request`; other diagnostics remain enabled.

## Next Steps

- No additional local consumer-file work is planned. Live behavior still requires a separate canary and is not inferred from this YAML sync.

## Evidence

- Both workflow files match the canonical v2.2.13 bytes and passed the exported source validators.
- Exported source-contract validation, the exact actionlint workaround, project-journal validation, and `git diff --check` passed. The focused pytest file was not run because the active Python 3.13.0 environment does not have `pytest` installed.
- No live canary, production behavior, or full CI result is claimed.
