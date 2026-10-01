from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def test_auto_request_binds_pr_head_not_workflow_merge_head() -> None:
    controller = (WORKFLOWS / "codex-review-gate-controller.yml").read_text(encoding="utf-8")

    assert "github.event.workflow_run.pull_requests[0].head.sha" in controller
    assert "github.event.workflow_run.head_sha" not in controller


def test_verifier_can_read_workflow_run_evidence() -> None:
    verifier = (WORKFLOWS / "codex-review-gate.yml").read_text(encoding="utf-8")

    assert "permissions:\n  actions: read\n" in verifier
