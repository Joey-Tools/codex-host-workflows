---
id: 20260929-review-gate-v2-consumer
title: Codex Review Gate v2 Consumer Migration
status: active
created: 2026-09-29
updated: 2026-09-30
branch: master
pr:
supersedes: []
superseded_by:
---

# Codex Review Gate v2 Consumer Migration

## Summary

- Replace the privileged v1 caller with the canonical read-only v2 verifier and separate controller.
- Protect both workflows and CODEOWNERS through the canonical control-plane ownership block.
- Migrate the required check only after the v2 workflow is installed, independently approved, and verified on a harmless canary PR.

## Current State

- The default branch contains the canonical v2 verifier, controller, and CODEOWNERS after this installation change is merged.
- The v2.1.3 controller additionally listens for completed first-attempt, failed verifier runs associated with exactly one pull request. Its automatic `begin-review` request path remains disabled unless `CODEX_REVIEW_GATE_AUTO_REQUEST` is set to `true`; the existing provider-comment and manual-dispatch paths remain available.
- This controller change does not enable the variable or modify the verifier or repository rulesets.
- The existing `codex/review-gate` ruleset remains active during installation. Its removal is a separate post-canary operation, not part of this source change.
- The v2 ruleset must be staged Disabled, validated against a fresh exact-head native `codex/github-review-gate` CheckRun, then activated and read back before the legacy requirement is removed.
- No v1 bridge is installed. During the short transition, a PR without the old status remains blocked by the still-active legacy rule; this is an intentional fail-closed state.

## Next Steps

- Enable the variable in a separate selected-repository rollout only after the controller updates are installed and the designated canary succeeds.
- Stage the v2 ruleset Disabled, run a separate harmless canary PR, and activate v2 only after its exact-head check succeeds.
- Remove the old required `codex/review-gate` status only after the v2 Active readback, then close the canary without merging.

## Evidence

- `.github/workflows/codex-review-gate.yml`
- `.github/workflows/codex-review-gate-controller.yml`
- `.github/CODEOWNERS`
- `https://github.com/Joey-Tools/codex-review-gate/blob/master/docs/install/human.md`
