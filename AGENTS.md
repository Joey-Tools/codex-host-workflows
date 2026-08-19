# Codex Host Workflows Guidelines

- Keep this repository host-scoped. Do not turn it into a second global private overlay or install its skills on every machine.
- Keep the private overlay installation manifest independent. `config/host-workspace.toml` is only a repository-management manifest for the existing `codex-workspace` helper.
- Scheduled jobs may refresh existing mirrors but must never clone a missing repository. Initial mirror creation requires an explicit `scripts/host_setup.py apply --ensure` invocation.
- Treat the skill locator, Git exclude block, and LaunchAgent plist as owned objects. Fail closed on foreign files, unsafe ownership or permissions, and unexpected symlink targets.
- Use `$project-journal`. Put ordinary workstream state in `docs/project_journal/YYYY/MM/*.md`; do not create `docs/PROJECT_STATE.md` or `docs/PROJECT_TODO.md` without a separate repo-wide need. Keep generated `docs/project_journal/INDEX.md` local and untracked.
- For PR-bound delivery, use `$review-orchestration-playbook` and report the required shape as `skill-repo-codex-gate`: exactly one fresh-context local Codex reviewer over the frozen range plus current-head GitHub Codex through exact `@codex review`. Both must be clean; do not substitute Claude or a supplied-diff helper.
- Prefer squash merge. Write tracked journal state as the intended target-branch state and keep transient PR/merge status in the PR rather than the journal.
- Use English for code, comments, identifiers, commit messages, and repository documentation.
