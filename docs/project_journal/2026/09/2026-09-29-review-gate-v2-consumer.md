---
id: 20260929-review-gate-v2-consumer
title: Codex Review Gate v2 Consumer Migration
status: completed
created: 2026-09-29
updated: 2026-09-29
branch: master
pr: https://github.com/Joey-Tools/codex-host-workflows/pull/3
supersedes: []
superseded_by:
---

# Codex Review Gate v2 Consumer Migration

## Summary

- Replaced the privileged v1 caller with the canonical read-only v2 verifier and separate controller.
- Protected both workflows and CODEOWNERS through the canonical control-plane ownership block.
- Migrated the required check after the v2 workflow was installed, independently approved, and verified on a harmless canary PR.

## Current State

- The default branch contains the canonical v2 verifier, controller, and CODEOWNERS from installation PR #3 (merge commit `c600d298b9aed37ed8261f4676f74e782ee42ac3`).
- The v2 ruleset (`24192222`) is Active and requires only the native `codex/github-review-gate` status. Separate canary PR #4 produced a successful exact-head check and was closed without merging; its temporary remote branch was deleted.
- The dedicated legacy v1 ruleset (`20935749`) was removed after v2 activation. The canonical two-snapshot post-cleanup verification found no remaining v1 requirement and confirmed unrelated protection was unchanged. No v1 bridge is installed.

## Next Steps

- None for this migration. Future PRs use the v2 verifier and required check.

## Evidence

- `.github/workflows/codex-review-gate.yml`
- `.github/workflows/codex-review-gate-controller.yml`
- `.github/CODEOWNERS`
- `https://github.com/Joey-Tools/codex-host-workflows/pull/3`
- `https://github.com/Joey-Tools/codex-host-workflows/pull/4`
- `https://github.com/Joey-Tools/codex-host-workflows/settings/rules/24192222`
- Post-cleanup security snapshot digest: `164356fee2bfb7da51af0b3fd934a26d343289eda18857c0c194d6f510e82aac`
- `https://github.com/Joey-Tools/codex-review-gate/blob/master/docs/install/human.md`
