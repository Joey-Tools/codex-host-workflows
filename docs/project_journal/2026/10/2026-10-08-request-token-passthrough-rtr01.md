---
id: 20261008-rtr01
title: Review Request Token Passthrough
status: completed
created: 2026-10-08
updated: 2026-10-08
branch: master
pr:
supersedes: []
superseded_by:
---

# Review Request Token Passthrough

## Summary

- Pass the configured `CODEX_REVIEW_GATE_REQUEST_TOKEN` secret to the review-gate action through its `review_request_token` controller input.
- Keep the verifier workflow and controller event, permission, runner, concurrency, and protection behavior unchanged.

## Current State

- The controller exposes the optional review-request credential input without storing or printing the credential value.
- The focused workflow contract test protects the controller input wiring.

## Next Steps

- No additional controller-source work is required in this repository for the request-token rollout.

## Evidence

- `tests/test_review_gate_workflows.py`
- `actionlint` on `.github/workflows/codex-review-gate-controller.yml`
