from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def test_auto_request_binds_verifier_run_head_and_reports_completion() -> None:
    controller = (WORKFLOWS / "codex-review-gate-controller.yml").read_text(encoding="utf-8")

    assert (
        "expected_head_sha: ${{ github.event_name == 'workflow_run' && "
        "github.event.workflow_run.head_sha ||" in controller
    )
    assert "github.event_name == 'workflow_run' && 'report-completion'" in controller
    assert "github.event.workflow_run.pull_requests[0].head.sha" not in controller

    for guard in (
        "vars.CODEX_REVIEW_GATE_AUTO_REQUEST == 'true'",
        "github.event.workflow_run.run_attempt == 1",
        "github.event.workflow_run.conclusion == 'failure'",
        "github.event.workflow_run.event == 'pull_request'",
        "github.event.workflow_run.pull_requests[0].number",
        "!github.event.workflow_run.pull_requests[1]",
    ):
        assert guard in controller

    assert (
        "request_review: ${{ github.event_name == 'workflow_run' && "
        "vars.CODEX_REVIEW_GATE_AUTO_REQUEST == 'true' && "
        "github.event.workflow_run.run_attempt == 1 && "
        "github.event.workflow_run.conclusion == 'failure'" in controller
    )


def test_verifier_can_read_workflow_run_evidence() -> None:
    verifier = (WORKFLOWS / "codex-review-gate.yml").read_text(encoding="utf-8")

    assert "permissions:\n  actions: read\n" in verifier
