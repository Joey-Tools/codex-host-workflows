from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import stat
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER = REPO_ROOT / ".agents" / "skills" / "daily-skill-friction" / "scripts" / "friction_state.py"
SPEC = importlib.util.spec_from_file_location("friction_state", HELPER)
assert SPEC is not None and SPEC.loader is not None
fs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fs)

T0 = "2026-06-01T12:00:00Z"
VENDORED_LEDGER_ROOT = REPO_ROOT / "tests" / "fixtures" / "ledger_authority"
LEDGER_VALIDATOR_PATH = VENDORED_LEDGER_ROOT / "scripts" / "validate_ledger.py"
LEDGER_SCHEMA_PATH = VENDORED_LEDGER_ROOT / "schema" / "case.schema.json"
LEDGER_MANIFEST_PATH = VENDORED_LEDGER_ROOT / "manifest.json"
LEDGER_VALIDATOR_SHA256 = "63334ea90199215ab87abda5eb28551cc8c5780ce0b617f4e0e1cdbeb722f9b8"
LEDGER_SCHEMA_SHA256 = "10d29a101954e8c08e7c316d59dde3fb92d3ff53d719883ad9cf3204f23c2940"
LEDGER_FIXTURE_DIGEST = "sha256:d90daeb497afd84872eda842dac8315aee0b60a18de98135e0dff7187408efb3"


def _load_ledger_validator() -> Any:
    module_name = "daily_skill_friction_frozen_ledger_validator"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(module_name, LEDGER_VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    ledger = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = ledger
    spec.loader.exec_module(ledger)
    return ledger


def _audit_summary(
    *,
    candidates_considered: int = 0,
    cases_created: int = 0,
    cases_updated: int = 0,
    cases_unchanged: int = 0,
    cases_dormant: int = 0,
    no_issue_observations: int = 0,
    blocked_actions: int = 0,
    next_watchpoint: str | None = None,
) -> dict[str, Any]:
    return {
        "candidates_considered": candidates_considered,
        "cases_created": cases_created,
        "cases_updated": cases_updated,
        "cases_unchanged": cases_unchanged,
        "cases_dormant": cases_dormant,
        "no_issue_observations": no_issue_observations,
        "blocked_actions": blocked_actions,
        "next_watchpoint": next_watchpoint,
    }


def _write(path: Path, value: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path


def _occurrence(
    index: int,
    *,
    root: str = "root:root-1",
    workflow: str = "workflow:workflow-1",
    observed_at: str | None = None,
) -> dict[str, Any]:
    if observed_at is None:
        observed_at = (
            (dt.datetime(2026, 6, 1, 12, tzinfo=dt.UTC) + dt.timedelta(days=index))
            .isoformat()
            .replace("+00:00", "Z")
        )
    return {
        "root_task_id": root,
        "workflow_id": workflow,
        "repository": "Joey-Tools/example",
        "opportunity_id": f"opportunity:{root.rsplit(':', 1)[-1]}-{index}",
        "causal_signature": "sha256:" + "a" * 64,
        "observed_at": observed_at,
        "signal_type": "manual-workaround",
        "source_event_ids": [f"event:{root.rsplit(':', 1)[-1]}-{index}"],
        "source_digest": "sha256:" + f"{index + 1:064x}"[-64:],
        "summary": f"The human workflow needed a bounded workaround at opportunity {index}.",
    }


def _candidate(
    *,
    case_id: str | None = None,
    occurrences: list[dict[str, Any]] | None = None,
    result: str = "novel",
    urgency: str = "normal",
    scope: str = "repo-local",
    status: str = "watching",
    revision: int = 1,
    currentness_at: str | None = None,
    lifecycle_at: str | None = None,
    source_kind: str = "human-root",
    explicit_human_root: str | None = None,
    origin_case_id: str | None = None,
) -> dict[str, Any]:
    occurrences = occurrences or [_occurrence(0)]
    observed = [fs._parse_time(item["observed_at"], "observed") for item in occurrences]
    first = min(observed).isoformat().replace("+00:00", "Z")
    last = max(observed).isoformat().replace("+00:00", "Z")
    case_id = case_id or fs.new_case_id(first)
    roots = {item["root_task_id"] for item in occurrences}
    workflows = {item["workflow_id"] for item in occurrences}
    repositories = {item["repository"] for item in occurrences if item["repository"] is not None}
    signatures = {item["causal_signature"] for item in occurrences}
    target_repository: str | None = "Joey-Tools/example"
    global_rationale: str | None = None
    global_invariant_kind: str | None = None
    if scope != "repo-local":
        global_rationale = "The shared owner is required to enforce the supported causal boundary."
    if scope == "global-invariant":
        target_repository = None
        global_invariant_kind = "authorization"
    case: dict[str, Any] = {
        "schema_version": 1,
        "revision": revision,
        "id": case_id,
        "title": "Concrete workflow failure",
        "status": status,
        "support": result,
        "classification": scope,
        "source_kind": source_kind,
        "urgency": {
            "level": urgency,
            "reason": "material-authority-boundary-breach" if urgency == "high-signal" else None,
            "source_event_ids": occurrences[0]["source_event_ids"]
            if urgency == "high-signal"
            else [],
        },
        "causal": {
            "summary": "A missing local invariant permits the same concrete state loss.",
            "first_observed_at": first,
            "occurrence_count": len(occurrences),
            "root_task_count": len(roots),
            "workflow_count": len(workflows),
            "repository_count": len(repositories),
            "opportunity_count": len({item["opportunity_id"] for item in occurrences}),
            "causal_signature_count": len(signatures),
        },
        "evidence": occurrences,
        "evidence_last_seen": last,
        "applicability": {
            "state": "present",
            "summary": "A narrow no-side-effect probe reproduced the supported issue.",
        },
        "currentness_checked_at": currentness_at or last,
        "scope": {
            "target_repository": target_repository,
            "global_rationale": global_rationale,
            "global_invariant_kind": global_invariant_kind,
        },
        "lifecycle": {
            "created_at": first,
            "dormant_since": None,
            "dormant_from_status": None,
            "superseded_by": None,
            "revisit_when": ["The owning helper is removed or changes ownership."],
        },
        "lifecycle_changed_at": lifecycle_at or first,
        "repairs": [],
        "effectiveness": {
            "method": "none",
            "state": "not-started",
            "checked_on": None,
            "summary": None,
            "deterministic": None,
            "behavioral": None,
        },
    }
    candidate = {
        "version": 1,
        "case": case,
        "control": {
            "semantic_digest": fs.semantic_digest(case),
            "source_lineage": [
                {
                    "opportunity_id": item["opportunity_id"],
                    "source_family": (
                        "explicit-human-correction"
                        if item["signal_type"] == "explicit-human-correction"
                        else "human-root"
                    ),
                    "is_automation_descendant": False,
                    "is_replay": False,
                    "chronology": (
                        f"The human workflow reached {item['opportunity_id']} independently."
                    ),
                }
                for item in occurrences
            ],
            "explicit_human_root_task_id": explicit_human_root,
            "origin_case_id": origin_case_id,
        },
    }
    return candidate


def _stage(
    tmp_path: Path, case: dict[str, Any], now: str = "2026-07-10T12:00:00Z"
) -> tuple[Path, dict[str, Any]]:
    root = tmp_path / "state"
    receipt = fs.stage_candidate(_write(tmp_path / f"{case['case']['id']}.json", case), root, now)
    return root, receipt


def _receipt_ref(receipt: dict[str, Any]) -> dict[str, str]:
    return {"receipt_id": receipt["receipt_id"], "digest": receipt["digest"]}


def _complete_live(
    tmp_path: Path,
    root: Path,
    stage_receipts: list[dict[str, Any]],
    dormancy_receipts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    audit = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": str(uuid.uuid4()),
        "started_at": "2026-07-10T11:00:00Z",
        "ended_at": "2026-07-10T12:30:00Z",
        "previous_snapshot_digest": None,
        "stage_receipts": [_receipt_ref(item) for item in stage_receipts],
        "dormancy_receipts": [_receipt_ref(item) for item in (dormancy_receipts or [])],
        "summary": _audit_summary(
            candidates_considered=len(stage_receipts),
            cases_created=sum(item["action"] == "created" for item in stage_receipts),
            cases_updated=sum(item["action"] == "updated" for item in stage_receipts),
            cases_unchanged=sum(item["action"] == "unchanged" for item in stage_receipts),
            cases_dormant=sum(len(item["changed"]) for item in (dormancy_receipts or [])),
        ),
    }
    return fs.complete_audit(
        root,
        _write(tmp_path / "audit.json", audit),
        "2026-07-10T12:31:00Z",
        historical_replay=False,
    )


def _selection(
    snapshot_digest: str,
    cases: list[dict[str, Any]],
    *,
    actor: str = "Joey",
    interactive: bool = True,
    selected_at: str = "2026-07-11T08:00:00Z",
) -> dict[str, Any]:
    return {
        "version": 1,
        "kind": "publication-selection",
        "selection_id": str(uuid.uuid4()),
        "interaction": {
            "interactive": interactive,
            "actor": actor,
            "selected_at": selected_at,
        },
        "daily_snapshot_digest": snapshot_digest,
        "base_intent": {
            "repository": "Joey-Tools/codex-skill-friction-ledger",
            "base_branch": "master",
            "base_sha": "a" * 40,
        },
        "cases": [
            {
                "case_id": case["case"]["id"],
                "revision": case["case"]["revision"],
                "semantic_digest": case["control"]["semantic_digest"],
            }
            for case in cases
        ],
    }


def _finalize_one(
    tmp_path: Path, case: dict[str, Any]
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    plan_path = tmp_path / "plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "selection.json", _selection(completed["snapshot_digest"], [case])),
        plan_path,
        "2026-07-11T08:01:00Z",
    )
    plan = fs._load_json(plan_path)
    entry = plan["entries"][0]
    commit_sha = "b" * 40
    prepared = {
        "version": 1,
        "kind": "prepared-commits",
        "plan_digest": plan["plan_digest"],
        "entries": [
            {
                "case_id": entry["case_id"],
                "revision": entry["revision"],
                "semantic_digest": entry["semantic_digest"],
                "case_sha256": entry["case_sha256"],
                "branch": entry["branch"],
                "base_sha": entry["base_sha"],
                "changed_paths": entry["changed_paths"],
                "commit_sha": commit_sha,
                "validation": {
                    "status": "passed",
                    "commands": ["python3 scripts/validate_ledger.py"],
                    "validated_at": "2026-07-11T08:30:00Z",
                },
                "signature": {
                    "status": "verified",
                    "commit_sha": commit_sha,
                    "signer": "Joey",
                    "verified_at": "2026-07-11T08:31:00Z",
                },
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    fs.finalize_publication(
        root,
        plan_path,
        _write(tmp_path / "prepared.json", prepared),
        manifest_path,
        "2026-07-11T08:32:00Z",
    )
    return root, plan, fs._load_json(manifest_path)


def _ledger_compatibility_case() -> dict[str, Any]:
    case_id = "DSF-01a00f29-e900-7000-8000-000000000001"
    return {
        "schema_version": 1,
        "revision": 1,
        "id": case_id,
        "title": "Repeated manual repair target selection",
        "status": "watching",
        "support": "novel",
        "classification": "repo-local",
        "source_kind": "human-root",
        "urgency": {"level": "normal", "reason": None, "source_event_ids": []},
        "causal": {
            "summary": "Repair target selection required a manual workaround in the root task.",
            "first_observed_at": "2026-08-17T10:00:00Z",
            "occurrence_count": 1,
            "root_task_count": 1,
            "workflow_count": 1,
            "repository_count": 1,
            "opportunity_count": 1,
            "causal_signature_count": 1,
        },
        "evidence": [
            {
                "root_task_id": "codex-task:root-1",
                "workflow_id": "workflow:repair-selection",
                "opportunity_id": "opportunity:first",
                "causal_signature": "sha256:" + "a" * 64,
                "observed_at": "2026-08-17T10:00:00Z",
                "signal_type": "manual-workaround",
                "source_event_ids": ["codex-event:first"],
                "source_digest": "sha256:" + "b" * 64,
                "summary": "The user had to repeat a bounded workflow step.",
                "repository": "Joey-Tools/codex-host-workflows",
            }
        ],
        "evidence_last_seen": "2026-08-17T10:00:00Z",
        "applicability": {
            "state": "present",
            "summary": "The same repository-local workflow is still installed.",
        },
        "currentness_checked_at": "2026-08-17T10:30:00Z",
        "scope": {
            "target_repository": "Joey-Tools/codex-host-workflows",
            "global_rationale": None,
            "global_invariant_kind": None,
        },
        "lifecycle": {
            "created_at": "2026-08-17T10:05:00Z",
            "dormant_since": None,
            "dormant_from_status": None,
            "superseded_by": None,
            "revisit_when": [],
        },
        "lifecycle_changed_at": "2026-08-17T10:05:00Z",
        "repairs": [],
        "effectiveness": {
            "method": "none",
            "state": "not-started",
            "checked_on": None,
            "summary": None,
            "deterministic": None,
            "behavioral": None,
        },
    }


def _wrapper_for_case(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": 1,
        "case": case,
        "control": {
            "semantic_digest": fs.semantic_digest(case),
            "source_lineage": [
                {
                    "opportunity_id": item["opportunity_id"],
                    "source_family": "human-root",
                    "is_automation_descendant": False,
                    "is_replay": False,
                    "chronology": "The human workflow reached this independent opportunity.",
                }
                for item in case["evidence"]
            ],
            "explicit_human_root_task_id": None,
            "origin_case_id": None,
        },
    }


def _closed_candidate() -> dict[str, Any]:
    wrapper = _candidate(status="closed", lifecycle_at="2026-06-20T12:00:00Z")
    case_id = wrapper["case"]["id"]
    wrapper["case"]["repairs"] = [
        {
            "id": "R1",
            "repository": "Joey-Tools/example",
            "action": "install",
            "state": "merged",
            "problem_statement": "The deterministic workflow omitted an authority boundary check.",
            "change_summary": "Add the missing bounded authority check.",
            "pull_request_url": "https://github.com/Joey-Tools/example/pull/1",
            "commit": "a" * 40,
            "commit_trailer": f"Friction-Case: {case_id}",
            "installed_on": "2026-06-02",
            "removed_on": None,
            "replaces_repair_id": None,
        }
    ]
    wrapper["case"]["effectiveness"] = {
        "method": "deterministic",
        "state": "passed",
        "checked_on": "2026-06-10",
        "summary": "The installed deterministic authority gate passed.",
        "deterministic": {
            "test_ref": "tests/test_authority_gate.py",
            "result": "passed",
            "commit": "a" * 40,
        },
        "behavioral": None,
    }
    wrapper["control"]["semantic_digest"] = fs.semantic_digest(wrapper["case"])
    return wrapper


def _closed_reopen_candidate(
    closed: dict[str, Any], *, observed_at: str = "2026-06-21T12:00:00Z"
) -> dict[str, Any]:
    wrapper = json.loads(json.dumps(closed))
    occurrence = _occurrence(1, root="root:reopen", observed_at=observed_at)
    wrapper["case"]["revision"] += 1
    wrapper["case"]["status"] = "proposed"
    wrapper["case"]["support"] = "repeated"
    wrapper["case"]["evidence"].append(occurrence)
    wrapper["case"]["evidence_last_seen"] = observed_at
    wrapper["case"]["currentness_checked_at"] = observed_at
    wrapper["case"]["causal"].update(
        {
            "occurrence_count": 2,
            "root_task_count": 2,
            "workflow_count": 1,
            "repository_count": 1,
            "opportunity_count": 2,
            "causal_signature_count": 1,
        }
    )
    wrapper["case"]["lifecycle_changed_at"] = "2026-06-21T12:01:00Z"
    wrapper["case"]["repairs"][0]["state"] = "superseded"
    wrapper["case"]["repairs"].append(
        {
            "id": "R2",
            "repository": "Joey-Tools/example",
            "action": "amend",
            "state": "planned",
            "problem_statement": (
                "The recurrence shows the earlier authority boundary was incomplete."
            ),
            "change_summary": "Amend the bounded authority check for the recurrence.",
            "pull_request_url": None,
            "commit": None,
            "commit_trailer": f"Friction-Case: {wrapper['case']['id']}",
            "installed_on": None,
            "removed_on": None,
            "replaces_repair_id": None,
        }
    )
    wrapper["case"]["effectiveness"] = {
        "method": "deterministic",
        "state": "not-started",
        "checked_on": None,
        "summary": None,
        "deterministic": None,
        "behavioral": None,
    }
    wrapper["control"]["source_lineage"].append(
        {
            "opportunity_id": occurrence["opportunity_id"],
            "source_family": "human-root",
            "is_automation_descendant": False,
            "is_replay": False,
            "chronology": "The human workflow reached this independent recurrence opportunity.",
        }
    )
    wrapper["control"]["semantic_digest"] = fs.semantic_digest(wrapper["case"])
    return wrapper


def _forward_removed_candidate() -> dict[str, Any]:
    wrapper = _candidate(status="superseded", lifecycle_at="2026-06-05T12:00:00Z")
    case_id = wrapper["case"]["id"]

    def installed(repair_id: str, commit: str, installed_on: str, action: str) -> dict[str, Any]:
        return {
            "id": repair_id,
            "repository": "Joey-Tools/example",
            "action": action,
            "state": "superseded",
            "problem_statement": "The workflow needed a durable repository authority boundary.",
            "change_summary": "Install the bounded repository authority check.",
            "pull_request_url": f"https://github.com/Joey-Tools/example/pull/{repair_id[1:]}",
            "commit": commit,
            "commit_trailer": f"Friction-Case: {case_id}",
            "installed_on": installed_on,
            "removed_on": None,
            "replaces_repair_id": None,
        }

    wrapper["case"]["repairs"] = [
        installed("R1", "a" * 40, "2026-06-02", "install"),
        installed("R2", "b" * 40, "2026-06-03", "amend"),
        {
            "id": "R3",
            "repository": "Joey-Tools/example",
            "action": "remove-forward",
            "state": "merged",
            "problem_statement": (
                "The installed workflow is no longer applicable to this repository."
            ),
            "change_summary": "Remove the obsolete workflow in a forward commit.",
            "pull_request_url": "https://github.com/Joey-Tools/example/pull/3",
            "commit": "c" * 40,
            "commit_trailer": f"Friction-Case: {case_id}",
            "installed_on": None,
            "removed_on": "2026-06-04",
            "replaces_repair_id": "R2",
        },
    ]
    wrapper["case"]["applicability"] = {
        "state": "absent",
        "summary": "The formerly installed workflow is absent from the repository.",
    }
    wrapper["case"]["effectiveness"] = {
        "method": "deterministic",
        "state": "failed",
        "checked_on": "2026-06-04",
        "summary": "The latest installed repair failed its deterministic authority gate.",
        "deterministic": {
            "test_ref": "tests/test_authority_gate.py",
            "result": "failed",
            "commit": "b" * 40,
        },
        "behavioral": None,
    }
    wrapper["control"]["semantic_digest"] = fs.semantic_digest(wrapper["case"])
    return wrapper


def _tree_bytes(root: Path) -> dict[str, tuple[int, bytes]]:
    if not root.exists():
        return {}
    result: dict[str, tuple[int, bytes]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            result[str(path.relative_to(root))] = (
                stat.S_IMODE(path.stat().st_mode),
                path.read_bytes(),
            )
    return result


def _create_wal_temp(root: Path, name: str, payload: bytes = b"partial") -> None:
    with fs._state_lock(root) as store:
        with store.open_dir(Path("wal") / "stage", create=True) as directory_fd:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory_fd)


def test_uuidv7_binds_the_requested_timestamp() -> None:
    case_id = fs.new_case_id("2026-08-17T10:11:12.345Z")
    parsed = uuid.UUID(case_id.removeprefix("DSF-"))
    assert parsed.version == 7
    assert parsed.variant == uuid.RFC_4122
    assert parsed.int >> 80 == int(
        dt.datetime(2026, 8, 17, 10, 11, 12, 345000, tzinfo=dt.UTC).timestamp() * 1000
    )


def test_semantic_digest_matches_ledger_fixture_and_live_validator() -> None:
    case = _ledger_compatibility_case()
    expected = LEDGER_FIXTURE_DIGEST
    assert fs.semantic_digest(case) == expected
    wrapper = _wrapper_for_case(case)
    assert fs.validate_candidate(wrapper)["semantic_digest"] == expected

    ledger = _load_ledger_validator()
    case_path = PurePosixPath(f"cases/2026/{case['id']}.json")
    assert ledger.validate_case(case, case_path) == []
    assert ledger.semantic_case_digest(case) == fs.semantic_digest(case)


def test_frozen_ledger_authority_identity_and_local_vector_do_not_skip() -> None:
    manifest = json.loads(LEDGER_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest == {
        "version": 1,
        "source_repository": "Joey-Tools/codex-skill-friction-ledger",
        "authority": "frozen-validator-bytes",
        "files": {
            "schema/case.schema.json": LEDGER_SCHEMA_SHA256,
            "scripts/validate_ledger.py": LEDGER_VALIDATOR_SHA256,
        },
        "semantic_fixture_digest": LEDGER_FIXTURE_DIGEST,
    }
    assert hashlib.sha256(LEDGER_VALIDATOR_PATH.read_bytes()).hexdigest() == (
        LEDGER_VALIDATOR_SHA256
    )
    assert hashlib.sha256(LEDGER_SCHEMA_PATH.read_bytes()).hexdigest() == LEDGER_SCHEMA_SHA256

    case = _ledger_compatibility_case()
    wrapper = _wrapper_for_case(case)
    assert fs.semantic_digest(case) == LEDGER_FIXTURE_DIGEST
    assert fs.validate_candidate(wrapper)["semantic_digest"] == LEDGER_FIXTURE_DIGEST

    invalid = json.loads(json.dumps(wrapper))
    invalid["case"]["effectiveness"]["method"] = "deterministic"
    invalid["control"]["semantic_digest"] = fs.semantic_digest(invalid["case"])
    with pytest.raises(fs.StateError, match="no repair selected"):
        fs.validate_candidate(invalid)

    ledger = _load_ledger_validator()
    path = PurePosixPath(f"cases/2026/{case['id']}.json")
    assert ledger.validate_case(case, path) == []
    assert ledger.semantic_case_digest(case) == LEDGER_FIXTURE_DIGEST

    sibling = REPO_ROOT.parent / "codex-skill-friction-ledger" / "scripts" / "validate_ledger.py"
    if sibling.exists():
        assert hashlib.sha256(sibling.read_bytes()).hexdigest() == LEDGER_VALIDATOR_SHA256


def test_all_control_candidate_shapes_and_weekly_export_are_ledger_clean(tmp_path: Path) -> None:
    ledger = _load_ledger_validator()

    correction = _occurrence(0, root="root:correction")
    correction["signal_type"] = "explicit-human-correction"
    origin = _candidate()["case"]["id"]
    wrappers = [
        _candidate(),
        _candidate(occurrences=[_occurrence(0), _occurrence(1)], result="repeated"),
        _candidate(
            occurrences=[
                _occurrence(0, root="root:one", workflow="workflow:one"),
                _occurrence(1, root="root:two", workflow="workflow:two"),
            ],
            result="repeated",
            scope="cross-workflow",
        ),
        _candidate(scope="global-invariant"),
        _candidate(urgency="high-signal"),
        _candidate(
            occurrences=[correction],
            source_kind="automation-derived",
            explicit_human_root="root:correction",
            origin_case_id=origin,
        ),
    ]
    for wrapper in wrappers:
        summary = fs.validate_candidate(wrapper)
        case = wrapper["case"]
        path = PurePosixPath(f"cases/{fs._case_year(case['id']):04d}/{case['id']}.json")
        assert ledger.validate_case(case, path) == []
        assert summary["semantic_digest"] == ledger.semantic_case_digest(case)

    root, stage = _stage(tmp_path, wrappers[0])
    completed = _complete_live(tmp_path, root, [stage])
    plan_path = tmp_path / "compat-plan.json"
    fs.weekly_plan(
        root,
        _write(
            tmp_path / "compat-selection.json",
            _selection(completed["snapshot_digest"], [wrappers[0]]),
        ),
        plan_path,
        "2026-07-11T08:01:00Z",
    )
    exported = fs._load_json(plan_path)["entries"][0]
    assert ledger.validate_case(exported["case"], PurePosixPath(exported["ledger_case_path"])) == []
    assert exported["semantic_digest"] == ledger.semantic_case_digest(exported["case"])


def test_digest_command_calculates_without_trusting_placeholder(tmp_path: Path) -> None:
    wrapper = _wrapper_for_case(_ledger_compatibility_case())
    wrapper["control"]["semantic_digest"] = "sha256:" + "0" * 64
    result = fs._run(
        fs._parser().parse_args(
            ["digest", "--candidate", str(_write(tmp_path / "candidate.json", wrapper))]
        )
    )
    assert result["semantic_digest"] == (
        "sha256:d90daeb497afd84872eda842dac8315aee0b60a18de98135e0dff7187408efb3"
    )


def test_raw_session_and_credential_shaped_content_are_rejected_by_both_validators() -> None:
    ledger = _load_ledger_validator()
    for bad_summary in (
        "Evidence came from /Users/example/.codex/sessions/rollout-123.jsonl.",
        "The workaround exposed password=not-a-real-secret in copied text.",
    ):
        case = _ledger_compatibility_case()
        case["evidence"][0]["summary"] = bad_summary
        wrapper = _wrapper_for_case(case)
        with pytest.raises(fs.StateError):
            fs.validate_candidate(wrapper)
        path = PurePosixPath(f"cases/2026/{case['id']}.json")
        assert ledger.validate_case(case, path)


def test_invalid_repair_and_partial_both_effectiveness_are_rejected() -> None:
    approved = _candidate()
    approved["case"]["status"] = "approved"
    approved["case"]["lifecycle_changed_at"] = "2026-06-02T12:00:00Z"
    approved["control"]["semantic_digest"] = fs.semantic_digest(approved["case"])
    with pytest.raises(fs.StateError, match="requires a repair"):
        fs.validate_candidate(approved)

    case = _ledger_compatibility_case()
    case["status"] = "closed"
    case["lifecycle_changed_at"] = "2026-08-26T10:05:00Z"
    case["repairs"] = [
        {
            "id": "R1",
            "repository": "Joey-Tools/codex-host-workflows",
            "action": "install",
            "state": "merged",
            "problem_statement": "The repair target was repeatedly selected at the wrong scope.",
            "change_summary": "Keep single-repository signals local to that repository.",
            "pull_request_url": "https://github.com/Joey-Tools/codex-host-workflows/pull/1",
            "commit": "a" * 40,
            "commit_trailer": f"Friction-Case: {case['id']}",
            "installed_on": "2026-08-18",
            "removed_on": None,
            "replaces_repair_id": None,
        }
    ]
    case["effectiveness"] = {
        "method": "both",
        "state": "passed",
        "checked_on": "2026-08-26",
        "summary": "Only the deterministic half of the combined gate was recorded.",
        "deterministic": {
            "test_ref": "tests/test_scope.py",
            "result": "passed",
            "commit": "a" * 40,
        },
        "behavioral": None,
    }
    with pytest.raises(fs.StateError, match="behavioral result presence"):
        fs.validate_candidate(_wrapper_for_case(case))


@pytest.mark.parametrize(
    "pull_request_url",
    [None, "https://github.com/Joey-Tools/example/pull/1"],
)
def test_failed_behavioral_effectiveness_requires_installed_history(
    pull_request_url: str | None,
) -> None:
    wrapper = _candidate(status="superseded", lifecycle_at="2026-06-11T12:00:00Z")
    case = wrapper["case"]
    case["lifecycle"]["superseded_by"] = fs.new_case_id("2026-06-01T13:00:00Z")
    case["repairs"] = [
        {
            "id": "R1",
            "repository": "Joey-Tools/example",
            "action": "install",
            "state": "superseded",
            "problem_statement": "The proposed workflow repair did not reach installation.",
            "change_summary": "Retire the uninstalled proposal after a recurrence.",
            "pull_request_url": pull_request_url,
            "commit": None,
            "commit_trailer": f"Friction-Case: {case['id']}",
            "installed_on": None,
            "removed_on": None,
            "replaces_repair_id": None,
        }
    ]
    case["effectiveness"] = {
        "method": "behavioral",
        "state": "failed",
        "checked_on": "2026-06-10",
        "summary": "A recurrence was observed before any repair was installed.",
        "deterministic": None,
        "behavioral": {
            "started_on": "2026-06-02",
            "ended_on": "2026-06-09",
            "relevant_opportunities": 1,
            "recurrences": 1,
        },
    }
    wrapper["control"]["semantic_digest"] = fs.semantic_digest(case)
    with pytest.raises(fs.StateError, match="installed repair history"):
        fs.validate_candidate(wrapper)

    ledger = _load_ledger_validator()
    path = PurePosixPath(f"cases/{fs._case_year(case['id']):04d}/{case['id']}.json")
    assert any("installed repair history" in error for error in ledger.validate_case(case, path))


def test_no_issue_cannot_be_staged(tmp_path: Path) -> None:
    candidate = _candidate(result="no_issue")
    with pytest.raises(fs.StateError, match="not durable cases"):
        fs.stage_candidate(_write(tmp_path / "candidate.json", candidate), tmp_path / "state", T0)
    assert not (tmp_path / "state" / "cases").exists()


def test_same_root_distinct_opportunities_are_real_recurrence(tmp_path: Path) -> None:
    first = _candidate()
    root, _ = _stage(tmp_path, first)
    repeated = _candidate(
        case_id=first["case"]["id"],
        occurrences=[_occurrence(0), _occurrence(1)],
        result="repeated",
        revision=2,
    )
    receipt = fs.stage_candidate(
        _write(tmp_path / "repeated.json", repeated), root, "2026-07-10T13:00:00Z"
    )
    assert receipt["action"] == "updated"
    stored = fs._load_json(root / receipt["case_path"])
    assert stored["case"]["revision"] == 2
    assert len(stored["case"]["evidence"]) == 2


def test_reused_source_event_and_replay_family_are_rejected(tmp_path: Path) -> None:
    duplicate = _candidate(
        occurrences=[
            _occurrence(0),
            {**_occurrence(1), "source_event_ids": ["event:root-1-0"]},
        ],
        result="repeated",
    )
    with pytest.raises(fs.StateError, match="source event is reused"):
        fs.validate_candidate(duplicate)
    replay = _candidate()
    replay["control"]["source_lineage"][0]["source_family"] = "historical-replay"
    replay["control"]["source_lineage"][0]["is_replay"] = True
    with pytest.raises(fs.StateError, match="descendants, and replays"):
        fs.validate_candidate(replay)


def test_single_root_cannot_claim_cross_workflow_breadth() -> None:
    candidate = _candidate(
        occurrences=[
            _occurrence(0, workflow="workflow:one"),
            _occurrence(1, workflow="workflow:two"),
        ],
        result="repeated",
        scope="cross-workflow",
    )
    with pytest.raises(fs.StateError, match="two roots"):
        fs.validate_candidate(candidate)


def test_automation_derived_requires_new_human_root_and_cannot_reinforce_origin() -> None:
    case = _candidate()
    occurrence = _occurrence(0)
    occurrence["signal_type"] = "explicit-human-correction"
    derived = _candidate(
        case_id=case["case"]["id"],
        occurrences=[occurrence],
        source_kind="automation-derived",
        explicit_human_root="root:root-1",
        origin_case_id=case["case"]["id"],
    )
    with pytest.raises(fs.StateError, match="cannot reinforce"):
        fs.validate_candidate(derived)


def test_currentness_only_update_preserves_revision_and_other_clocks(tmp_path: Path) -> None:
    first = _candidate(currentness_at="2026-06-02T12:00:00Z")
    root, _ = _stage(tmp_path, first)
    checked = json.loads(json.dumps(first))
    checked["case"]["currentness_checked_at"] = "2026-07-01T12:00:00Z"
    receipt = fs.stage_candidate(
        _write(tmp_path / "checked.json", checked), root, "2026-07-02T12:00:00Z"
    )
    stored = fs._load_json(root / receipt["case_path"])
    assert stored["case"]["revision"] == 1
    assert stored["control"]["semantic_digest"] == first["control"]["semantic_digest"]
    assert stored["case"]["evidence_last_seen"] == first["case"]["evidence_last_seen"]
    assert stored["case"]["lifecycle_changed_at"] == first["case"]["lifecycle_changed_at"]


def test_dormancy_uses_only_lifecycle_age_and_excludes_other_statuses(tmp_path: Path) -> None:
    eligible = _candidate(lifecycle_at="2026-06-01T12:00:00Z")
    root, _ = _stage(tmp_path, eligible, "2026-07-10T12:00:00Z")
    observing = _candidate(
        occurrences=[_occurrence(0, root="root:root-2")],
        status="watching",
        lifecycle_at="2026-07-09T12:00:00Z",
    )
    _, _ = _stage(tmp_path, observing, "2026-07-10T12:00:00Z")
    receipt = fs.transition_dormant(root, "2026-07-10T12:00:00Z")
    assert [item["case_id"] for item in receipt["changed"]] == [eligible["case"]["id"]]
    dormant = fs._load_json(root / receipt["changed"][0]["case_path"])
    assert dormant["case"]["status"] == "dormant"
    assert dormant["case"]["revision"] == 2


def test_active_publication_blocks_dormancy_until_audited_closure(tmp_path: Path) -> None:
    case = _candidate(lifecycle_at="2026-06-01T12:00:00Z")
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _selection(completed["snapshot_digest"], [case])
    plan_path = tmp_path / "pending-plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "pending-selection.json", selection),
        plan_path,
        "2026-07-11T08:01:00Z",
    )
    blocked = fs.transition_dormant(root, "2026-07-12T12:00:00Z")
    assert blocked["changed"] == []
    plan = fs._load_json(plan_path)
    entry = plan["entries"][0]
    closure = {
        "version": 1,
        "kind": "publication-closure",
        "closure_id": str(uuid.uuid4()),
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "closed_at": "2026-07-12T12:01:00Z",
        },
        "reason": "cancelled",
        "summary": "Joey explicitly cancelled this prepared publication selection.",
        "entries": [
            {
                "case_id": entry["case_id"],
                "revision": entry["revision"],
                "semantic_digest": entry["semantic_digest"],
                "selection_id": plan["selection_id"],
                "plan_digest": plan["plan_digest"],
                "manifest_digest": None,
                "pull_request_url": None,
                "ledger_commit": None,
                "merged_at": None,
            }
        ],
    }
    receipt_path = _write(tmp_path / "closure.json", closure)
    closed = fs.close_publication(root, receipt_path, "2026-07-12T12:02:00Z")
    assert closed["closed_count"] == 1
    assert fs.close_publication(root, receipt_path, "2026-07-12T13:02:00Z") == closed
    active = fs._load_json(root / "publication" / "active" / f"{case['case']['id']}.json")
    assert active["status"] == "closed"
    assert (root / "publication" / "plans" / f"{plan['selection_id']}.json").exists()
    transitioned = fs.transition_dormant(root, "2026-07-12T12:03:00Z")
    assert [item["case_id"] for item in transitioned["changed"]] == [case["case"]["id"]]


def test_closed_publication_tuple_allows_only_a_higher_semantic_revision(tmp_path: Path) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    first_plan_path = tmp_path / "first-plan.json"
    fs.weekly_plan(
        root,
        _write(
            tmp_path / "first-selection.json",
            _selection(completed["snapshot_digest"], [case]),
        ),
        first_plan_path,
        "2026-07-11T08:01:00Z",
    )
    first_plan = fs._load_json(first_plan_path)
    first_entry = first_plan["entries"][0]
    closure = {
        "version": 1,
        "kind": "publication-closure",
        "closure_id": "first-publication-cancelled",
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "closed_at": "2026-07-11T08:02:00Z",
        },
        "reason": "cancelled",
        "summary": "Joey cancelled the first exact semantic publication tuple.",
        "entries": [
            {
                "case_id": first_entry["case_id"],
                "revision": first_entry["revision"],
                "semantic_digest": first_entry["semantic_digest"],
                "selection_id": first_plan["selection_id"],
                "plan_digest": first_plan["plan_digest"],
                "manifest_digest": None,
                "pull_request_url": None,
                "ledger_commit": None,
                "merged_at": None,
            }
        ],
    }
    closed = fs.close_publication(
        root,
        _write(tmp_path / "first-closure.json", closure),
        "2026-07-11T08:03:00Z",
    )

    updated = json.loads(json.dumps(case))
    updated["case"]["revision"] = 2
    updated["case"]["title"] = "Concrete workflow failure with a revised semantic boundary"
    updated["control"]["semantic_digest"] = fs.semantic_digest(updated["case"])
    second_stage = fs.stage_candidate(
        _write(tmp_path / "updated-case.json", updated),
        root,
        "2026-07-12T08:00:00Z",
    )
    audit = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": "higher-revision-audit",
        "started_at": "2026-07-12T07:59:00Z",
        "ended_at": "2026-07-12T08:30:00Z",
        "previous_snapshot_digest": completed["snapshot_digest"],
        "stage_receipts": [_receipt_ref(second_stage)],
        "dormancy_receipts": [],
        "summary": _audit_summary(),
    }
    second_completed = fs.complete_audit(
        root,
        _write(tmp_path / "higher-revision-audit.json", audit),
        "2026-07-12T08:31:00Z",
        historical_replay=False,
    )
    second_plan_path = tmp_path / "second-plan.json"
    fs.weekly_plan(
        root,
        _write(
            tmp_path / "second-selection.json",
            _selection(
                second_completed["snapshot_digest"],
                [updated],
                selected_at="2026-07-12T08:32:00Z",
            ),
        ),
        second_plan_path,
        "2026-07-12T08:33:00Z",
    )
    active = fs._load_json(root / "publication" / "active" / f"{updated['case']['id']}.json")
    assert active["status"] == "active"
    assert active["revision"] == 2
    assert active["previous_closure_digest"] == closed["closure_digest"]


def test_zero_case_audit_completes_but_incomplete_audit_never_advances(tmp_path: Path) -> None:
    empty_root = tmp_path / "empty-state"
    audit = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": "empty-audit",
        "started_at": "2026-07-10T11:00:00Z",
        "ended_at": "2026-07-10T12:00:00Z",
        "previous_snapshot_digest": None,
        "stage_receipts": [],
        "dormancy_receipts": [],
        "summary": _audit_summary(),
    }
    completed = fs.complete_audit(
        empty_root,
        _write(tmp_path / "empty-audit.json", audit),
        "2026-07-10T12:01:00Z",
        historical_replay=False,
    )
    assert completed["case_count"] == 0
    assert (empty_root / fs.LIVE_POINTER).exists()

    case = _candidate()
    root, _ = _stage(tmp_path / "incomplete", case)
    with pytest.raises(fs.StateError, match="every stage receipt"):
        fs.complete_audit(
            root,
            _write(tmp_path / "incomplete-audit.json", audit | {"audit_id": "incomplete"}),
            "2026-07-10T12:01:00Z",
            historical_replay=False,
        )
    assert not (root / fs.LIVE_POINTER).exists()


@pytest.mark.parametrize(
    "summary",
    [
        {},
        _audit_summary() | {"unexpected_nested_summary": {"value": 1}},
        _audit_summary(candidates_considered=-1),
        _audit_summary(next_watchpoint="x" * 241),
    ],
)
def test_daily_audit_summary_is_exact_and_bounded(tmp_path: Path, summary: dict[str, Any]) -> None:
    audit = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": "invalid-summary-audit",
        "started_at": "2026-07-10T11:00:00Z",
        "ended_at": "2026-07-10T12:00:00Z",
        "previous_snapshot_digest": None,
        "stage_receipts": [],
        "dormancy_receipts": [],
        "summary": summary,
    }
    root = tmp_path / "state"
    with pytest.raises(fs.StateError):
        fs.complete_audit(
            root,
            _write(tmp_path / "invalid-summary-audit.json", audit),
            "2026-07-10T12:01:00Z",
            historical_replay=False,
        )
    assert not root.exists()


def test_historical_completion_is_isolated_and_never_writes_live_pointer(tmp_path: Path) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path / "pilot", case)
    audit = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": "historical-audit",
        "started_at": "2026-07-10T11:00:00Z",
        "ended_at": "2026-07-10T12:00:00Z",
        "previous_snapshot_digest": None,
        "stage_receipts": [_receipt_ref(stage)],
        "dormancy_receipts": [],
        "summary": _audit_summary(),
    }
    completed = fs.complete_audit(
        root,
        _write(tmp_path / "historical.json", audit),
        "2026-07-10T12:01:00Z",
        historical_replay=True,
    )
    assert completed["mode"] == "historical-replay"
    assert not (root / fs.LIVE_POINTER).exists()
    assert fs._load_json(root / fs.STATE_MARKER)["mode"] == "historical-replay"
    assert Path(completed["snapshot_path"]).exists()


def test_selection_must_be_trusted_and_stale_cases_are_skipped(tmp_path: Path) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    untrusted = _selection(completed["snapshot_digest"], [case], actor="Automation")
    with pytest.raises(fs.StateError, match="actor must be Joey"):
        fs.weekly_plan(
            root,
            _write(tmp_path / "untrusted.json", untrusted),
            tmp_path / "untrusted-plan.json",
            "2026-07-11T08:01:00Z",
        )
    stale = _selection(completed["snapshot_digest"], [case])
    stale["cases"][0]["revision"] += 1
    result = fs.weekly_plan(
        root,
        _write(tmp_path / "stale.json", stale),
        tmp_path / "stale-plan.json",
        "2026-07-11T08:01:00Z",
    )
    assert result["selected_count"] == 0
    assert result["skipped"] == [{"case_id": case["case"]["id"], "reason": "stale-selection"}]


def test_selection_snapshot_must_belong_to_live_completed_ancestry(tmp_path: Path) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    pointer = fs._load_json(root / fs.LIVE_POINTER)
    orphan_body = {
        **{key: value for key, value in pointer.items() if key != "snapshot_digest"},
        "audit_id": "orphan-snapshot",
        "completed_at": "2026-07-10T12:32:00Z",
        "previous_snapshot_digest": None,
    }
    orphan = {**orphan_body, "snapshot_digest": fs._digest(orphan_body)}
    fs._atomic_write(root / "completed" / "orphan-snapshot.json", orphan, immutable=True)
    selection = _selection(orphan["snapshot_digest"], [case])
    before = _tree_bytes(root)
    with pytest.raises(fs.StateError, match="outside the live ancestry"):
        fs.weekly_plan(
            root,
            _write(tmp_path / "orphan-selection.json", selection),
            tmp_path / "orphan-plan.json",
            "2026-07-11T08:01:00Z",
        )
    assert _tree_bytes(root) == before
    assert completed["snapshot_digest"] == pointer["snapshot_digest"]


def test_high_signal_never_auto_selects_and_explicit_selection_has_no_cap(tmp_path: Path) -> None:
    cases = [
        _candidate(
            occurrences=[_occurrence(0, root=f"root:root-{index}")],
            urgency="high-signal" if index == 0 else "normal",
        )
        for index in range(66)
    ]
    root = tmp_path / "state"
    receipts = [
        fs.stage_candidate(
            _write(tmp_path / "candidates" / f"{index}.json", case),
            root,
            "2026-07-10T12:00:00Z",
        )
        for index, case in enumerate(cases)
    ]
    completed = _complete_live(tmp_path, root, receipts)
    empty = _selection(completed["snapshot_digest"], [])
    empty_result = fs.weekly_plan(
        root,
        _write(tmp_path / "empty-selection.json", empty),
        tmp_path / "empty-plan.json",
        "2026-07-11T08:01:00Z",
    )
    assert empty_result["selected_count"] == 0
    selected = _selection(completed["snapshot_digest"], cases)
    all_result = fs.weekly_plan(
        root,
        _write(tmp_path / "all-selection.json", selected),
        tmp_path / "all-plan.json",
        "2026-07-11T08:01:00Z",
    )
    assert all_result["selected_count"] == 66


def test_finalize_requires_exact_receipts_rejects_drift_and_is_idempotent(tmp_path: Path) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _selection(completed["snapshot_digest"], [case])
    plan_path = tmp_path / "plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "selection.json", selection),
        plan_path,
        "2026-07-11T08:01:00Z",
    )
    plan = fs._load_json(plan_path)
    entry = plan["entries"][0]
    commit_sha = "b" * 40
    prepared = {
        "version": 1,
        "kind": "prepared-commits",
        "plan_digest": plan["plan_digest"],
        "entries": [
            {
                "case_id": entry["case_id"],
                "revision": entry["revision"],
                "semantic_digest": entry["semantic_digest"],
                "case_sha256": entry["case_sha256"],
                "branch": entry["branch"],
                "base_sha": entry["base_sha"],
                "changed_paths": entry["changed_paths"],
                "commit_sha": commit_sha,
                "validation": {
                    "status": "passed",
                    "commands": ["python3 scripts/validate_ledger.py"],
                    "validated_at": "2026-07-11T08:30:00Z",
                },
                "signature": {
                    "status": "verified",
                    "commit_sha": commit_sha,
                    "signer": "Joey",
                    "verified_at": "2026-07-11T08:31:00Z",
                },
            }
        ],
    }
    prepared_path = _write(tmp_path / "prepared.json", prepared)
    output = tmp_path / "manifest.json"
    first = fs.finalize_publication(root, plan_path, prepared_path, output, "2026-07-11T08:32:00Z")
    before = output.read_bytes()
    second = fs.finalize_publication(root, plan_path, prepared_path, output, "2026-07-11T08:32:00Z")
    assert first["manifest_digest"] == second["manifest_digest"]
    assert output.read_bytes() == before
    assert stat.S_IMODE(output.stat().st_mode) == 0o600

    checked = json.loads(json.dumps(case))
    checked["case"]["currentness_checked_at"] = "2026-07-12T08:00:00Z"
    fs.stage_candidate(_write(tmp_path / "checked.json", checked), root, "2026-07-12T08:01:00Z")
    allowed = fs.finalize_publication(
        root,
        plan_path,
        prepared_path,
        tmp_path / "checked-manifest.json",
        "2026-07-12T08:02:00Z",
    )
    assert allowed["status"] == "finalized"

    changed = json.loads(json.dumps(checked))
    changed["case"]["revision"] = 2
    changed["case"]["applicability"] = {
        "state": "absent",
        "summary": "The current artifact no longer exhibits the supported issue.",
    }
    changed["control"]["semantic_digest"] = fs.semantic_digest(changed["case"])
    fs.stage_candidate(_write(tmp_path / "changed.json", changed), root, "2026-07-12T08:03:00Z")
    with pytest.raises(fs.StateError, match="revision changed"):
        fs.finalize_publication(
            root,
            plan_path,
            prepared_path,
            tmp_path / "drifted-manifest.json",
            "2026-07-12T08:04:00Z",
        )
    assert not (tmp_path / "drifted-manifest.json").exists()
    assert output.read_bytes() == before

    closure = {
        "version": 1,
        "kind": "publication-closure",
        "closure_id": str(uuid.uuid4()),
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "closed_at": "2026-07-12T08:05:00Z",
        },
        "reason": "stale",
        "summary": "Joey closed the publication after its semantic case binding changed.",
        "entries": [
            {
                "case_id": entry["case_id"],
                "revision": entry["revision"],
                "semantic_digest": entry["semantic_digest"],
                "selection_id": plan["selection_id"],
                "plan_digest": plan["plan_digest"],
                "manifest_digest": None,
                "pull_request_url": None,
                "ledger_commit": None,
                "merged_at": None,
            }
        ],
    }
    closure_result = fs.close_publication(
        root,
        _write(tmp_path / "published-closure.json", closure),
        "2026-07-12T08:06:00Z",
    )
    assert closure_result["status"] == "closed"


def test_atomic_state_files_and_directories_are_owner_only(tmp_path: Path) -> None:
    root, stage = _stage(tmp_path, _candidate())
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    case_path = root / stage["case_path"]
    assert stat.S_IMODE(case_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((root / fs.STATE_MARKER).stat().st_mode) == 0o600
    assert not any(
        path.name.startswith(f".{case_path.name}.tmp-") for path in case_path.parent.iterdir()
    )


def test_stage_wal_recovers_unreceipted_case_and_preserves_first_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _candidate()
    candidate_path = _write(tmp_path / "candidate.json", candidate)
    root = tmp_path / "state"
    original = fs.StateStore.write_json
    injected = False

    def fail_receipt(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        nonlocal injected
        if not injected and str(relative).startswith("receipts/stage/"):
            injected = True
            raise OSError("injected receipt interruption")
        return original(store, relative, value, immutable=immutable)

    monkeypatch.setattr(fs.StateStore, "write_json", fail_receipt)
    with pytest.raises(OSError, match="injected receipt interruption"):
        fs.stage_candidate(candidate_path, root, "2026-07-10T12:00:00Z")
    monkeypatch.setattr(fs.StateStore, "write_json", original)
    assert list((root / "cases").rglob("*.json"))
    assert not list((root / "receipts" / "stage").glob("*.json"))

    incomplete = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": "unreceipted",
        "started_at": "2026-07-10T11:00:00Z",
        "ended_at": "2026-07-10T12:30:00Z",
        "previous_snapshot_digest": None,
        "stage_receipts": [],
        "dormancy_receipts": [],
        "summary": _audit_summary(),
    }
    with pytest.raises(fs.StateError, match="every stage receipt"):
        fs.complete_audit(
            root,
            _write(tmp_path / "incomplete.json", incomplete),
            "2026-07-10T12:31:00Z",
            historical_replay=False,
        )
    assert not (root / fs.LIVE_POINTER).exists()
    recovered = fs.stage_candidate(candidate_path, root, "2026-07-10T13:00:00Z")
    assert recovered["created_at"] == "2026-07-10T12:00:00Z"
    assert fs._load_json(root / recovered["case_path"])["case"] == candidate["case"]


def test_complete_audit_recovers_history_pointer_gap_across_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    audit = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": "pointer-gap",
        "started_at": "2026-07-10T11:00:00Z",
        "ended_at": "2026-07-10T12:30:00Z",
        "previous_snapshot_digest": None,
        "stage_receipts": [_receipt_ref(stage)],
        "dormancy_receipts": [],
        "summary": _audit_summary(),
    }
    receipt_path = _write(tmp_path / "pointer-gap.json", audit)
    original = fs.StateStore.write_json
    injected = False

    def fail_pointer(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        nonlocal injected
        if not injected and Path(relative) == Path(fs.LIVE_POINTER):
            injected = True
            raise OSError("injected pointer interruption")
        return original(store, relative, value, immutable=immutable)

    monkeypatch.setattr(fs.StateStore, "write_json", fail_pointer)
    with pytest.raises(OSError, match="injected pointer interruption"):
        fs.complete_audit(root, receipt_path, "2026-07-10T12:31:00Z", historical_replay=False)
    monkeypatch.setattr(fs.StateStore, "write_json", original)
    history = root / "completed" / "pointer-gap.json"
    assert history.exists() and not (root / fs.LIVE_POINTER).exists()
    history_bytes = history.read_bytes()
    recovered = fs.complete_audit(
        root, receipt_path, "2026-07-10T13:31:00Z", historical_replay=False
    )
    assert (root / fs.LIVE_POINTER).read_bytes() == history_bytes
    assert fs._load_json(history)["completed_at"] == "2026-07-10T12:31:00Z"
    replay = fs.complete_audit(root, receipt_path, "2026-07-10T14:31:00Z", historical_replay=False)
    assert replay == recovered


def test_dormancy_batch_recovers_without_double_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cases = [
        _candidate(
            occurrences=[_occurrence(0, root=f"root:dormant-{index}")],
            lifecycle_at="2026-06-01T12:00:00Z",
        )
        for index in range(2)
    ]
    root = tmp_path / "state"
    stages = [
        fs.stage_candidate(
            _write(tmp_path / f"dormant-{index}.json", case),
            root,
            "2026-07-10T12:00:00Z",
        )
        for index, case in enumerate(cases)
    ]
    completed = _complete_live(tmp_path, root, stages)
    case_paths = sorted(Path(item["case_path"]) for item in fs._snapshot_cases(root))
    original = fs.StateStore.write_json
    injected = False

    def fail_second_case(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        nonlocal injected
        if not injected and Path(relative) == case_paths[1]:
            injected = True
            raise OSError("injected dormancy interruption")
        return original(store, relative, value, immutable=immutable)

    monkeypatch.setattr(fs.StateStore, "write_json", fail_second_case)
    with pytest.raises(OSError, match="injected dormancy interruption"):
        fs.transition_dormant(root, "2026-07-12T12:00:00Z")
    monkeypatch.setattr(fs.StateStore, "write_json", original)

    incomplete = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": "dormancy-gap",
        "started_at": "2026-07-12T11:00:00Z",
        "ended_at": "2026-07-12T12:30:00Z",
        "previous_snapshot_digest": completed["snapshot_digest"],
        "stage_receipts": [],
        "dormancy_receipts": [],
        "summary": _audit_summary(),
    }
    with pytest.raises(fs.StateError, match="every dormancy receipt"):
        fs.complete_audit(
            root,
            _write(tmp_path / "dormancy-gap.json", incomplete),
            "2026-07-12T12:31:00Z",
            historical_replay=False,
        )
    recovered = fs.transition_dormant(root, "2026-07-12T13:00:00Z")
    assert len(recovered["changed"]) == 2
    for item in recovered["changed"]:
        stored = fs._load_json(root / item["case_path"])
        assert stored["case"]["revision"] == 2
        assert stored["case"]["lifecycle_changed_at"] == "2026-07-12T12:00:00Z"


def test_weekly_output_conflict_has_no_state_side_effect(
    tmp_path: Path,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _selection(completed["snapshot_digest"], [case])
    output = _write(tmp_path / "conflicting-plan.json", {"foreign": True})
    before = _tree_bytes(root)
    with pytest.raises(fs.StateError, match="already conflicts"):
        fs.weekly_plan(
            root,
            _write(tmp_path / "conflict-selection.json", selection),
            output,
            "2026-07-11T08:01:00Z",
        )
    assert _tree_bytes(root) == before
    assert output.read_text(encoding="utf-8").strip() == '{"foreign": true}'


def test_weekly_late_active_conflict_has_no_partial_plan_or_registry(tmp_path: Path) -> None:
    cases = [
        _candidate(occurrences=[_occurrence(0, root=f"root:weekly-{index}")]) for index in range(2)
    ]
    root = tmp_path / "state"
    receipts = [
        fs.stage_candidate(
            _write(tmp_path / f"weekly-{index}.json", case),
            root,
            "2026-07-10T12:00:00Z",
        )
        for index, case in enumerate(cases)
    ]
    completed = _complete_live(tmp_path, root, receipts)
    ordered = sorted(cases, key=lambda item: item["case"]["id"])
    occupied = ordered[-1]
    fs.weekly_plan(
        root,
        _write(
            tmp_path / "occupied-selection.json",
            _selection(completed["snapshot_digest"], [occupied]),
        ),
        tmp_path / "occupied-plan.json",
        "2026-07-11T08:01:00Z",
    )
    before = _tree_bytes(root)
    output = tmp_path / "conflicted-multi-plan.json"
    with pytest.raises(fs.StateError, match="another active publication"):
        fs.weekly_plan(
            root,
            _write(
                tmp_path / "conflicted-multi-selection.json",
                _selection(completed["snapshot_digest"], ordered),
            ),
            output,
            "2026-07-11T08:02:00Z",
        )
    assert _tree_bytes(root) == before
    assert not output.exists()


def test_weekly_plan_recovers_external_output_gap_across_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection_path = _write(
        tmp_path / "interrupted-selection.json",
        _selection(completed["snapshot_digest"], [case]),
    )
    output = tmp_path / "interrupted-plan.json"
    original = fs.StateStore.write_json
    injected = False

    def fail_external_output(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        nonlocal injected
        if not injected and store.root == tmp_path and Path(relative) == Path(output.name):
            injected = True
            raise OSError("injected weekly output interruption")
        return original(store, relative, value, immutable=immutable)

    monkeypatch.setattr(fs.StateStore, "write_json", fail_external_output)
    with pytest.raises(OSError, match="injected weekly output interruption"):
        fs.weekly_plan(root, selection_path, output, "2026-07-11T08:01:00Z")
    monkeypatch.setattr(fs.StateStore, "write_json", original)
    assert not output.exists()
    recovered = fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")
    plan = fs._load_json(output)
    assert recovered["plan_digest"] == plan["plan_digest"]
    assert plan["created_at"] == "2026-07-11T08:01:00Z"
    active = fs._load_json(root / "publication" / "active" / f"{case['case']['id']}.json")
    assert active["activated_at"] == "2026-07-11T08:01:00Z"


def test_weekly_plan_supports_fourteen_large_cases_without_wal_truncation(
    tmp_path: Path,
) -> None:
    cases: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    root = tmp_path / "state"
    base = dt.datetime(2026, 6, 1, 12, tzinfo=dt.UTC)
    for case_index in range(14):
        occurrences: list[dict[str, Any]] = []
        for occurrence_index in range(256):
            observed_at = (
                (base + dt.timedelta(seconds=occurrence_index)).isoformat().replace("+00:00", "Z")
            )
            occurrence = _occurrence(
                occurrence_index,
                root=f"root:large-{case_index}",
                workflow=f"workflow:large-{case_index}",
                observed_at=observed_at,
            )
            prefix = f"Independent bounded recurrence {occurrence_index} preserved the same cause. "
            occurrence["summary"] = (prefix + "x" * 400)[:360]
            occurrences.append(occurrence)
        wrapper = _candidate(occurrences=occurrences, result="repeated")
        assert 160 * 1024 < len(fs._canonical_bytes(wrapper["case"])) < 256 * 1024
        cases.append(wrapper)
        receipts.append(
            fs.stage_candidate(
                _write(tmp_path / f"large-{case_index}.json", wrapper),
                root,
                "2026-07-10T12:00:00Z",
            )
        )

    completed = _complete_live(tmp_path, root, receipts)
    selection = _selection(completed["snapshot_digest"], cases)
    output = tmp_path / "large-weekly-plan.json"
    result = fs.weekly_plan(
        root,
        _write(tmp_path / "large-selection.json", selection),
        output,
        "2026-07-11T08:01:00Z",
    )
    assert result["selected_count"] == 14
    assert len(output.read_bytes()) < fs.MAX_JSON_BYTES
    intent_relative, _ = fs._wal_paths("weekly-plan", selection["selection_id"])
    assert (root / intent_relative).stat().st_size > 5 * 1024 * 1024


def test_oversized_wal_intent_fails_before_any_state_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    with fs._state_lock(root):
        pass
    before = _tree_bytes(root)
    monkeypatch.setattr(fs, "MAX_WAL_JSON_BYTES", 1024)
    with fs._state_lock(root, create=False) as store:
        write = fs._planned_write(
            store,
            Path("large-after-image.json"),
            {"value": "x" * 2048},
            immutable=False,
        )
        with pytest.raises(fs.StateError, match="WAL intent exceeds"):
            fs._run_transaction(
                store,
                operation="stage",
                natural_key="oversized-preflight",
                request={"operation": "oversized-preflight"},
                captured_at="2026-07-10T12:00:00Z",
                writes=[write],
                result={"status": "not-written"},
            )
    assert _tree_bytes(root) == before
    assert not (root / "wal").exists()


def test_wal_prepublication_temp_recovery_is_exact_and_fails_closed(
    tmp_path: Path,
) -> None:
    leaf = f"{'a' * 64}.intent.json"
    exact = f".{leaf}.tmp-123-{'b' * 16}"
    recoverable_root = tmp_path / "recoverable"
    _create_wal_temp(recoverable_root, exact)
    with fs._state_lock(recoverable_root, create=False) as store:
        fs._recover_pending_wal(store)
    assert not (recoverable_root / "wal" / "stage" / exact).exists()

    malformed_root = tmp_path / "malformed"
    malformed = f".{leaf}.tmp-untrusted"
    _create_wal_temp(malformed_root, malformed)
    with pytest.raises(fs.StateError, match="foreign WAL temporary"):
        with fs._state_lock(malformed_root, create=False) as store:
            fs._recover_pending_wal(store)
    assert (malformed_root / "wal" / "stage" / malformed).exists()

    ambiguous_root = tmp_path / "ambiguous"
    first = f".{leaf}.tmp-123-{'c' * 16}"
    second = f".{leaf}.tmp-124-{'d' * 16}"
    _create_wal_temp(ambiguous_root, first)
    _create_wal_temp(ambiguous_root, second)
    with pytest.raises(fs.StateError, match="ambiguous WAL temporaries"):
        with fs._state_lock(ambiguous_root, create=False) as store:
            fs._recover_pending_wal(store)
    assert (ambiguous_root / "wal" / "stage" / first).exists()
    assert (ambiguous_root / "wal" / "stage" / second).exists()


def test_path_derived_ids_are_closed_safe_basenames(tmp_path: Path) -> None:
    audit = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": "../escape",
        "started_at": "2026-07-10T11:00:00Z",
        "ended_at": "2026-07-10T12:00:00Z",
        "previous_snapshot_digest": None,
        "stage_receipts": [],
        "dormancy_receipts": [],
        "summary": _audit_summary(),
    }
    root = tmp_path / "state"
    with pytest.raises(fs.StateError, match="safe basename"):
        fs.complete_audit(
            root,
            _write(tmp_path / "unsafe-audit.json", audit),
            "2026-07-10T12:01:00Z",
            historical_replay=False,
        )
    assert not root.exists()
    assert not (tmp_path / "escape.json").exists()

    selection = _selection("a" * 64, [])
    selection["selection_id"] = "../selection"
    with pytest.raises(fs.StateError, match="safe basename"):
        fs._validate_selection(selection)

    empty_closure = {
        "version": 1,
        "kind": "publication-closure",
        "closure_id": "../closure",
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "closed_at": "2026-07-10T12:00:00Z",
        },
        "reason": "cancelled",
        "summary": "Joey cancelled the exact pending publication selection.",
        "entries": [],
    }
    with pytest.raises(fs.StateError, match="safe basename"):
        fs.close_publication(
            tmp_path / "missing-state",
            _write(tmp_path / "unsafe-closure.json", empty_closure),
            "2026-07-10T12:01:00Z",
        )


def test_empty_closure_and_noncanonical_now_are_rejected_before_state_writes(
    tmp_path: Path,
) -> None:
    closure = {
        "version": 1,
        "kind": "publication-closure",
        "closure_id": "empty-closure",
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "closed_at": "2026-07-10T12:00:00Z",
        },
        "reason": "cancelled",
        "summary": "Joey cancelled the exact pending publication selection.",
        "entries": [],
    }
    root = tmp_path / "state"
    with pytest.raises(fs.StateError, match="at least one"):
        fs.close_publication(
            root,
            _write(tmp_path / "empty-closure.json", closure),
            "2026-07-10T12:01:00Z",
        )
    with pytest.raises(fs.StateError, match="canonical UTC"):
        fs.transition_dormant(root, "2026-07-10T13:01:00+01:00")
    assert not root.exists()


def test_private_root_access_policy_and_symlink_entries_fail_closed(tmp_path: Path) -> None:
    candidate = _candidate()
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    root.chmod(0o755)
    with pytest.raises(fs.StateError, match="group or other"):
        fs.stage_candidate(_write(tmp_path / "candidate.json", candidate), root, T0)
    root.chmod(0o700)
    target = _write(tmp_path / "foreign-marker.json", {"version": 1})
    (root / fs.STATE_MARKER).symlink_to(target)
    with pytest.raises((fs.StateError, OSError)):
        fs.stage_candidate(_write(tmp_path / "candidate-2.json", candidate), root, T0)
    assert target.read_text(encoding="utf-8") == '{"version": 1}'


def test_store_distinguishes_benign_metadata_churn_identity_and_content_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    store = fs.StateStore(root)
    store.acquire_lock()
    original_read = os.read
    try:
        store.write_json("probe.json", {"a": 1})
        benign = root / "benign-child"
        benign.mkdir(mode=0o700)
        benign.rmdir()
        store.finish()

        changed = False

        def mutate_after_first_read(fd: int, size: int) -> bytes:
            nonlocal changed
            value = original_read(fd, size)
            if not changed and value == b"":
                changed = True
                writer = os.open(root / "probe.json", os.O_WRONLY)
                try:
                    os.write(writer, b'{"b":2}\n')
                    os.fsync(writer)
                finally:
                    os.close(writer)
            return value

        monkeypatch.setattr(os, "read", mutate_after_first_read)
        with pytest.raises(fs.StateError, match="content changed"):
            store.read_bytes("probe.json")
        monkeypatch.setattr(os, "read", original_read)

        old_lock = root / fs.LOCK_FILE
        displaced_lock = root / ".state.lock.displaced"
        old_lock.rename(displaced_lock)
        replacement = os.open(old_lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(replacement)
        with pytest.raises(fs.StateError, match="lock identity changed"):
            store.finish()
    finally:
        monkeypatch.setattr(os, "read", original_read)
        store.close()


def test_immutable_output_is_first_writer_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "winner.json"
    original_link = os.link
    injected = False

    def competing_link(
        src: str,
        dst: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal injected
        if not injected and dst == output.name and dst_dir_fd is not None:
            injected = True
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dst_dir_fd)
            try:
                os.write(fd, b'{"foreign":true}\n')
                os.fsync(fd)
            finally:
                os.close(fd)
        original_link(
            src,
            dst,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(os, "link", competing_link)
    with pytest.raises(fs.StateError, match="another writer won"):
        fs._atomic_write(output, {"ours": True}, immutable=True)
    assert output.read_bytes() == b'{"foreign":true}\n'


def test_evidence_and_lineage_are_exact_prefix_append_only(tmp_path: Path) -> None:
    first = _candidate()
    root, _ = _stage(tmp_path, first)
    reordered = _candidate(
        case_id=first["case"]["id"],
        occurrences=[_occurrence(1), _occurrence(0)],
        result="repeated",
        revision=2,
    )
    with pytest.raises(fs.StateError, match="exact-prefix"):
        fs.stage_candidate(
            _write(tmp_path / "reordered.json", reordered),
            root,
            "2026-07-10T13:00:00Z",
        )


def test_closed_case_reopens_only_for_a_later_same_cause_recurrence(tmp_path: Path) -> None:
    closed = _closed_candidate()
    root, _ = _stage(tmp_path, closed)
    reopened = _closed_reopen_candidate(closed)
    receipt = fs.stage_candidate(
        _write(tmp_path / "reopened.json", reopened),
        root,
        "2026-07-10T13:00:00Z",
    )
    assert receipt["action"] == "updated"
    assert fs._load_json(root / receipt["case_path"])["case"]["status"] == "proposed"

    other_root = tmp_path / "invalid-reopen-state"
    fs.stage_candidate(
        _write(tmp_path / "closed-again.json", closed),
        other_root,
        "2026-07-10T12:00:00Z",
    )
    not_later = _closed_reopen_candidate(closed, observed_at="2026-06-20T12:00:00Z")
    with pytest.raises(fs.StateError, match="strictly follow"):
        fs.stage_candidate(
            _write(tmp_path / "not-later.json", not_later),
            other_root,
            "2026-07-10T13:00:00Z",
        )

    late_root = tmp_path / "late-reopen-state"
    fs.stage_candidate(
        _write(tmp_path / "closed-before-late.json", closed),
        late_root,
        "2026-07-10T12:00:00Z",
    )
    lifecycle_too_early = _closed_reopen_candidate(closed, observed_at="2026-06-22T12:00:00Z")
    with pytest.raises(fs.StateError, match="cannot predate recurrence"):
        fs.stage_candidate(
            _write(tmp_path / "reopen-clock.json", lifecycle_too_early),
            late_root,
            "2026-07-10T13:00:00Z",
        )

    method_root = tmp_path / "method-reopen-state"
    fs.stage_candidate(
        _write(tmp_path / "closed-before-method-change.json", closed),
        method_root,
        "2026-07-10T12:00:00Z",
    )
    changed_method = _closed_reopen_candidate(closed)
    changed_method["case"]["effectiveness"]["method"] = "behavioral"
    changed_method["control"]["semantic_digest"] = fs.semantic_digest(changed_method["case"])
    with pytest.raises(fs.StateError, match="same selected effectiveness method"):
        fs.stage_candidate(
            _write(tmp_path / "reopen-method-change.json", changed_method),
            method_root,
            "2026-07-10T13:00:00Z",
        )


def test_stage_rejects_missing_or_cyclic_supersession_graph(tmp_path: Path) -> None:
    missing = _candidate(status="superseded")
    missing["case"]["lifecycle"]["superseded_by"] = _candidate()["case"]["id"]
    missing["control"]["semantic_digest"] = fs.semantic_digest(missing["case"])
    with pytest.raises(fs.StateError, match="missing successor"):
        fs.stage_candidate(
            _write(tmp_path / "missing-successor.json", missing),
            tmp_path / "missing-state",
            "2026-07-10T12:00:00Z",
        )

    successor = _candidate()
    root, _ = _stage(tmp_path, successor)
    predecessor = _candidate(status="superseded")
    predecessor["case"]["lifecycle"]["superseded_by"] = successor["case"]["id"]
    predecessor["control"]["semantic_digest"] = fs.semantic_digest(predecessor["case"])
    fs.stage_candidate(
        _write(tmp_path / "predecessor.json", predecessor),
        root,
        "2026-07-10T13:00:00Z",
    )
    cyclic = json.loads(json.dumps(successor))
    cyclic["case"]["revision"] = 2
    cyclic["case"]["status"] = "superseded"
    cyclic["case"]["lifecycle"]["superseded_by"] = predecessor["case"]["id"]
    cyclic["case"]["lifecycle_changed_at"] = "2026-06-02T12:00:00Z"
    cyclic["control"]["semantic_digest"] = fs.semantic_digest(cyclic["case"])
    with pytest.raises(fs.StateError, match="cycle"):
        fs.stage_candidate(
            _write(tmp_path / "cyclic.json", cyclic),
            root,
            "2026-07-10T14:00:00Z",
        )


def test_terminal_evaluation_and_forward_removal_bind_latest_history() -> None:
    valid = _forward_removed_candidate()
    fs.validate_candidate(valid)

    reused_commit = json.loads(json.dumps(valid))
    reused_commit["case"]["repairs"][-1]["commit"] = "a" * 40
    reused_commit["control"]["semantic_digest"] = fs.semantic_digest(reused_commit["case"])
    with pytest.raises(fs.StateError, match="every earlier repair commit"):
        fs.validate_candidate(reused_commit)

    stale_evaluation = json.loads(json.dumps(valid))
    stale_evaluation["case"]["effectiveness"]["deterministic"]["commit"] = "a" * 40
    stale_evaluation["control"]["semantic_digest"] = fs.semantic_digest(stale_evaluation["case"])
    with pytest.raises(fs.StateError, match="latest installed repair"):
        fs.validate_candidate(stale_evaluation)

    ledger = _load_ledger_validator()
    path = PurePosixPath(
        f"cases/{fs._case_year(valid['case']['id']):04d}/{valid['case']['id']}.json"
    )
    assert ledger.validate_case(valid["case"], path) == []
    assert ledger.validate_case(reused_commit["case"], path)
    assert ledger.validate_case(stale_evaluation["case"], path)


def test_local_hygiene_bool_versions_and_offset_clocks_never_skip() -> None:
    case = _ledger_compatibility_case()
    wrapper = _wrapper_for_case(case)
    wrapper["version"] = True
    with pytest.raises(fs.StateError, match="candidate.version"):
        fs.validate_candidate(wrapper)
    wrapper = _wrapper_for_case(_ledger_compatibility_case())
    wrapper["case"]["schema_version"] = True
    wrapper["control"]["semantic_digest"] = fs.semantic_digest(wrapper["case"])
    with pytest.raises(fs.StateError, match="schema_version"):
        fs.validate_candidate(wrapper)
    wrapper = _wrapper_for_case(_ledger_compatibility_case())
    wrapper["case"]["evidence"][0]["observed_at"] = "2026-08-17T11:00:00+01:00"
    wrapper["control"]["semantic_digest"] = fs.semantic_digest(wrapper["case"])
    with pytest.raises(fs.StateError, match="canonical UTC"):
        fs.validate_candidate(wrapper)
    wrapper = _wrapper_for_case(_ledger_compatibility_case())
    wrapper["case"]["currentness_checked_at"] = "2026-08-17T11:30:00+01:00"
    wrapper["control"]["semantic_digest"] = fs.semantic_digest(wrapper["case"])
    with pytest.raises(fs.StateError, match="canonical UTC"):
        fs.validate_candidate(wrapper)
    wrapper = _wrapper_for_case(_ledger_compatibility_case())
    wrapper["case"]["title"] = "github_pat_" + "A" * 24
    wrapper["control"]["semantic_digest"] = fs.semantic_digest(wrapper["case"])
    with pytest.raises(fs.StateError, match="credential-shaped"):
        fs.validate_candidate(wrapper)


def test_deterministic_effectiveness_can_monitor_then_pass() -> None:
    observing = _candidate(status="observing", lifecycle_at="2026-06-03T12:00:00Z")
    case_id = observing["case"]["id"]
    repair = {
        "id": "R1",
        "repository": "Joey-Tools/example",
        "action": "install",
        "state": "merged",
        "problem_statement": "The deterministic workflow omitted an authority boundary check.",
        "change_summary": "Add the missing bounded authority check.",
        "pull_request_url": "https://github.com/Joey-Tools/example/pull/1",
        "commit": "a" * 40,
        "commit_trailer": f"Friction-Case: {case_id}",
        "installed_on": "2026-06-02",
        "removed_on": None,
        "replaces_repair_id": None,
    }
    observing["case"]["repairs"] = [repair]
    observing["case"]["effectiveness"] = {
        "method": "deterministic",
        "state": "monitoring",
        "checked_on": "2026-06-03",
        "summary": "The installed deterministic gate is still under observation.",
        "deterministic": {
            "test_ref": "tests/test_gate.py",
            "result": "pending",
            "commit": "a" * 40,
        },
        "behavioral": None,
    }
    observing["control"]["semantic_digest"] = fs.semantic_digest(observing["case"])
    fs.validate_candidate(observing)

    closed = json.loads(json.dumps(observing))
    closed["case"]["status"] = "closed"
    closed["case"]["lifecycle_changed_at"] = "2026-06-04T12:00:00Z"
    closed["case"]["effectiveness"]["state"] = "passed"
    closed["case"]["effectiveness"]["checked_on"] = "2026-06-04"
    closed["case"]["effectiveness"]["summary"] = "The installed deterministic gate passed."
    closed["case"]["effectiveness"]["deterministic"]["result"] = "passed"
    closed["control"]["semantic_digest"] = fs.semantic_digest(closed["case"])
    fs.validate_candidate(closed)


def test_published_closure_requires_exact_approval_and_replays_across_now(
    tmp_path: Path,
) -> None:
    case = _candidate()
    root, plan, manifest = _finalize_one(tmp_path, case)
    entry = plan["entries"][0]
    closure = {
        "version": 1,
        "kind": "publication-closure",
        "closure_id": "published-one",
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "closed_at": "2026-07-11T08:36:00Z",
        },
        "reason": "published",
        "summary": "Joey confirmed the exact approved ledger pull request was merged.",
        "entries": [
            {
                "case_id": entry["case_id"],
                "revision": entry["revision"],
                "semantic_digest": entry["semantic_digest"],
                "selection_id": plan["selection_id"],
                "plan_digest": plan["plan_digest"],
                "manifest_digest": manifest["manifest_digest"],
                "pull_request_url": (
                    "https://github.com/Joey-Tools/codex-skill-friction-ledger/pull/1"
                ),
                "ledger_commit": "c" * 40,
                "merged_at": "2026-07-11T08:35:00Z",
            }
        ],
    }
    closure_path = _write(tmp_path / "published.json", closure)
    with pytest.raises(fs.StateError, match="explicit Joey approval"):
        fs.close_publication(root, closure_path, "2026-07-11T08:37:00Z")

    approval = {
        "version": 1,
        "kind": "publication-approval",
        "approval_id": "approval-one",
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "approved_at": "2026-07-11T08:34:00Z",
        },
        "selection_id": plan["selection_id"],
        "plan_digest": plan["plan_digest"],
        "manifest_digest": manifest["manifest_digest"],
        "entries": [
            {
                "case_id": entry["case_id"],
                "revision": entry["revision"],
                "semantic_digest": entry["semantic_digest"],
            }
        ],
    }
    approval_path = _write(tmp_path / "approval.json", approval)
    first = fs.close_publication(
        root,
        closure_path,
        "2026-07-11T08:37:00Z",
        approval_path,
    )
    second = fs.close_publication(
        root,
        closure_path,
        "2026-07-11T09:37:00Z",
        approval_path,
    )
    assert second == first
    history = fs._load_json(root / "publication" / "closures" / f"{closure['closure_id']}.json")
    assert history["recorded_at"] == closure["interaction"]["closed_at"]
    assert history["publication_approval_digest"] == fs._digest(approval)


def test_closure_recovers_history_active_gap_across_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, plan, _ = _finalize_one(tmp_path, case)
    entry = plan["entries"][0]
    closure = {
        "version": 1,
        "kind": "publication-closure",
        "closure_id": "cancel-gap",
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "closed_at": "2026-07-11T08:36:00Z",
        },
        "reason": "cancelled",
        "summary": "Joey explicitly cancelled the exact prepared publication.",
        "entries": [
            {
                "case_id": entry["case_id"],
                "revision": entry["revision"],
                "semantic_digest": entry["semantic_digest"],
                "selection_id": plan["selection_id"],
                "plan_digest": plan["plan_digest"],
                "manifest_digest": None,
                "pull_request_url": None,
                "ledger_commit": None,
                "merged_at": None,
            }
        ],
    }
    closure_path = _write(tmp_path / "cancel-gap.json", closure)
    active_relative = Path("publication") / "active" / f"{entry['case_id']}.json"
    original = fs.StateStore.write_json
    injected = False

    def fail_active(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        nonlocal injected
        if not injected and Path(relative) == active_relative:
            injected = True
            raise OSError("injected active closure interruption")
        return original(store, relative, value, immutable=immutable)

    monkeypatch.setattr(fs.StateStore, "write_json", fail_active)
    with pytest.raises(OSError, match="injected active closure interruption"):
        fs.close_publication(root, closure_path, "2026-07-11T08:37:00Z")
    monkeypatch.setattr(fs.StateStore, "write_json", original)
    history_path = root / "publication" / "closures" / "cancel-gap.json"
    history_bytes = history_path.read_bytes()
    recovered = fs.close_publication(root, closure_path, "2026-07-11T09:37:00Z")
    assert history_path.read_bytes() == history_bytes
    assert recovered["status"] == "closed"
    active = fs._load_json(root / active_relative)
    assert active["status"] == "closed"


def test_helper_has_no_git_network_or_subprocess_execution_surface() -> None:
    source = HELPER.read_text(encoding="utf-8")
    assert "import subprocess" not in source
    assert "import socket" not in source
    assert "import urllib" not in source
    assert "os.system" not in source


def test_cli_failures_emit_one_machine_json_object(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    malformed = _write(tmp_path / "malformed-plan.json", {"version": 1, "entries": [None]})
    code = fs.main(
        [
            "finalize-publication",
            "--state-root",
            str(tmp_path / "missing-state"),
            "--plan",
            str(malformed),
            "--prepared",
            str(malformed),
            "--output",
            str(tmp_path / "output.json"),
            "--now",
            "2026-07-11T08:00:00Z",
        ]
    )
    lines = capsys.readouterr().out.splitlines()
    assert code == 2
    assert len(lines) == 1
    error = json.loads(lines[0])
    assert error["status"] == "error"
    assert error["code"] in {"invalid-fields", "invalid-field"}
    assert not (tmp_path / "missing-state").exists()


def test_cli_advertises_every_control_transition() -> None:
    choices = fs._parser()._subparsers._group_actions[0].choices
    assert set(choices) == {
        "new-id",
        "digest",
        "validate",
        "stage",
        "transition-dormant",
        "complete-audit",
        "weekly-plan",
        "finalize-publication",
        "close-publication",
    }
