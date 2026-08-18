from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
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
LEDGER_VALIDATOR_SHA256 = "b1200da23b4096b129f838acaee4937b33707e4c236bc7f2a2fc7ff83b52ad8f"
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
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp_path.chmod(0o700)
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
    approved_at: str = "2026-07-11T08:00:00Z",
) -> dict[str, Any]:
    basis = {
        "version": 1,
        "kind": "publication-selection",
        "selection_id": str(uuid.uuid4()),
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
    case_bytes_upper_bound = sum(
        fs._publication_case_bytes_upper_bound(case["case"]) for case in cases
    )
    resource = fs._selection_resource_preflight(basis, case_bytes_upper_bound)
    receipt_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"dsf-selection-preflight:{basis['selection_id']}",
        )
    )
    return {
        **basis,
        "resource_preflight": resource,
        "preflight_receipt_id": receipt_id,
        "preflight_receipt_digest": "b" * 64,
        "interaction": {
            "interactive": interactive,
            "actor": actor,
            "approved_at": approved_at,
            "selection_basis_digest": resource["selection_basis_digest"],
            "preflight_receipt_id": receipt_id,
            "preflight_receipt_digest": "b" * 64,
        },
    }


def _approved_selection(
    tmp_path: Path,
    root: Path,
    snapshot_digest: str,
    cases: list[dict[str, Any]],
    *,
    actor: str = "Joey",
    interactive: bool = True,
    checked_at: str = "2026-07-11T07:59:00Z",
    approved_at: str = "2026-07-11T08:00:00Z",
) -> dict[str, Any]:
    selection = _selection(
        snapshot_digest,
        cases,
        actor=actor,
        interactive=interactive,
        approved_at=approved_at,
    )
    basis = {key: selection[key] for key in fs.SELECTION_BASIS_FIELDS}
    receipt = fs.preflight_selection(
        root,
        _write(tmp_path / f"{selection['selection_id']}-draft.json", basis),
        checked_at,
    )
    selection["resource_preflight"] = receipt["resource_preflight"]
    selection["preflight_receipt_id"] = receipt["receipt_id"]
    selection["preflight_receipt_digest"] = receipt["receipt_digest"]
    selection["interaction"] = {
        "interactive": interactive,
        "actor": actor,
        "approved_at": approved_at,
        "selection_basis_digest": receipt["selection_basis_digest"],
        "preflight_receipt_id": receipt["receipt_id"],
        "preflight_receipt_digest": receipt["receipt_digest"],
    }
    return selection


def _prepared_receipt(
    plan: dict[str, Any],
    *,
    validated_at: str = "2026-07-11T08:30:00Z",
    verified_at: str = "2026-07-11T08:31:00Z",
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for index, entry in enumerate(plan["entries"], start=1):
        commit_sha = f"{index:040x}"[-40:]
        entries.append(
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
                    "validated_at": validated_at,
                },
                "signature": {
                    "status": "verified",
                    "commit_sha": commit_sha,
                    "signer": "Joey",
                    "verified_at": verified_at,
                },
            }
        )
    return {
        "version": 1,
        "kind": "prepared-commits",
        "plan_digest": plan["plan_digest"],
        "entries": entries,
    }


def _finalize_one(
    tmp_path: Path, case: dict[str, Any]
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    plan_path = tmp_path / "plan.json"
    fs.weekly_plan(
        root,
        _write(
            tmp_path / "selection.json",
            _approved_selection(tmp_path, root, completed["snapshot_digest"], [case]),
        ),
        plan_path,
        "2026-07-11T08:01:00Z",
    )
    plan = fs._load_json(plan_path)
    prepared = _prepared_receipt(plan)
    manifest_path = tmp_path / "manifest.json"
    fs.finalize_publication(
        root,
        plan_path,
        _write(tmp_path / "prepared.json", prepared),
        manifest_path,
        "2026-07-11T08:32:00Z",
    )
    return root, plan, fs._load_json(manifest_path)


def _published_closure_and_approval(
    plan: dict[str, Any],
    manifest: dict[str, Any],
    *,
    closure_id: str,
    ledger_commit: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    entry = plan["entries"][0]
    closure = {
        "version": 1,
        "kind": "publication-closure",
        "closure_id": closure_id,
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
                    "https://github.com/Joey-Tools/codex-skill-friction-ledger/pull/91"
                ),
                "ledger_commit": ledger_commit,
                "merged_at": "2026-07-11T08:35:00Z",
            }
        ],
    }
    approval = {
        "version": 1,
        "kind": "publication-approval",
        "approval_id": f"approval-{closure_id}",
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
    return closure, approval


def _copy_pending_stage_intent(
    tmp_path: Path,
    target_root: Path,
    *,
    valid_for_target: bool,
) -> tuple[Path, dict[str, Any]]:
    candidate = _candidate(occurrences=[_occurrence(7, root=f"root:pending-copy-{uuid.uuid4()}")])
    scratch_root, _ = _stage(tmp_path / f"scratch-{uuid.uuid4()}", candidate)
    scratch_intent = next((scratch_root / "wal" / "stage").glob("*.intent.json"))
    intent = fs._load_json(scratch_intent)
    receipt_write = next(
        write
        for write in intent["writes"]
        if write["scope"] == "state" and write["after"].get("kind") == "stage"
    )
    if valid_for_target:
        intent["writes"] = [write for write in intent["writes"] if write["path"] != fs.STATE_MARKER]
        intent["result"]["path"] = str(target_root / receipt_write["path"])
    body = {key: value for key, value in intent.items() if key != "intent_digest"}
    intent["intent_digest"] = fs._digest(body)
    intent_relative, commit_relative = fs._wal_paths("stage", intent["natural_key"])
    intent_path = target_root / intent_relative
    intent_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    intent_path.write_bytes(fs._canonical_bytes(intent))
    intent_path.chmod(0o600)
    assert not (target_root / commit_relative).exists()
    return intent_path, candidate


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


def _with_planned_repair(proposed: dict[str, Any]) -> dict[str, Any]:
    case_id = proposed["case"]["id"]
    proposed["case"]["repairs"] = [
        {
            "id": "R1",
            "repository": "Joey-Tools/example",
            "action": "install",
            "state": "planned",
            "problem_statement": "The deterministic workflow omitted an authority boundary check.",
            "change_summary": "Add the missing bounded authority check.",
            "pull_request_url": None,
            "commit": None,
            "commit_trailer": f"Friction-Case: {case_id}",
            "installed_on": None,
            "removed_on": None,
            "replaces_repair_id": None,
        }
    ]
    proposed["case"]["effectiveness"] = {
        "method": "deterministic",
        "state": "not-started",
        "checked_on": None,
        "summary": None,
        "deterministic": None,
        "behavioral": None,
    }
    proposed["control"]["semantic_digest"] = fs.semantic_digest(proposed["case"])
    return proposed


def _repair_lifecycle_candidates() -> list[dict[str, Any]]:
    proposed = _with_planned_repair(
        _candidate(
            occurrences=[_occurrence(0), _occurrence(1)],
            result="repeated",
            status="proposed",
        )
    )

    approved = json.loads(json.dumps(proposed))
    approved["case"]["revision"] = 2
    approved["case"]["status"] = "approved"
    approved["case"]["lifecycle_changed_at"] = "2026-07-11T08:37:00Z"
    approved["case"]["repairs"][0]["state"] = "open"
    approved["case"]["repairs"][0]["pull_request_url"] = (
        "https://github.com/Joey-Tools/example/pull/1"
    )
    approved["control"]["semantic_digest"] = fs.semantic_digest(approved["case"])

    implemented = json.loads(json.dumps(approved))
    implemented["case"]["revision"] = 3
    implemented["case"]["status"] = "implemented"
    implemented["case"]["lifecycle_changed_at"] = "2026-07-11T08:45:00Z"
    implemented["case"]["repairs"][0]["state"] = "merged"
    implemented["case"]["repairs"][0]["commit"] = "a" * 40
    implemented["case"]["repairs"][0]["installed_on"] = "2026-07-11"
    implemented["control"]["semantic_digest"] = fs.semantic_digest(implemented["case"])

    observing = json.loads(json.dumps(implemented))
    observing["case"]["revision"] = 4
    observing["case"]["status"] = "observing"
    observing["case"]["lifecycle_changed_at"] = "2026-07-11T08:50:00Z"
    observing["case"]["effectiveness"] = {
        "method": "deterministic",
        "state": "monitoring",
        "checked_on": "2026-07-11",
        "summary": "The installed deterministic authority gate is under observation.",
        "deterministic": {
            "test_ref": "tests/test_authority_gate.py",
            "result": "pending",
            "commit": "a" * 40,
        },
        "behavioral": None,
    }
    observing["control"]["semantic_digest"] = fs.semantic_digest(observing["case"])

    closed = json.loads(json.dumps(observing))
    closed["case"]["revision"] = 5
    closed["case"]["status"] = "closed"
    closed["case"]["lifecycle_changed_at"] = "2026-07-11T09:00:00Z"
    closed["case"]["effectiveness"]["state"] = "passed"
    closed["case"]["effectiveness"]["checked_on"] = "2026-07-11"
    closed["case"]["effectiveness"]["summary"] = (
        "The installed deterministic authority gate passed."
    )
    closed["case"]["effectiveness"]["deterministic"]["result"] = "passed"
    closed["control"]["semantic_digest"] = fs.semantic_digest(closed["case"])
    return [proposed, approved, implemented, observing, closed]


def _closed_candidate() -> dict[str, Any]:
    return _repair_lifecycle_candidates()[-1]


def _stage_repair_lifecycle(
    tmp_path: Path, candidates: list[dict[str, Any]] | None = None
) -> tuple[Path, dict[str, Any]]:
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp_path.chmod(0o700)
    root = tmp_path / "state"
    candidates = candidates or _repair_lifecycle_candidates()
    proposed = candidates[0]
    proposed_stage = fs.stage_candidate(
        _write(tmp_path / "proposed.json", proposed),
        root,
        "2026-07-10T12:00:00Z",
    )
    _publish_and_approve_repair(tmp_path, root, proposed, candidates[1], proposed_stage)
    fs.stage_candidate(
        _write(tmp_path / "approved.json", candidates[1]),
        root,
        "2026-07-11T08:39:00Z",
    )
    for index, candidate in enumerate(candidates[2:], start=2):
        fs.stage_candidate(
            _write(tmp_path / f"{candidate['case']['status']}.json", candidate),
            root,
            f"2026-07-11T09:0{index}:00Z",
        )
    return root, candidates[-1]


def _publish_and_approve_repair(
    tmp_path: Path,
    root: Path,
    proposed: dict[str, Any],
    approved: dict[str, Any],
    proposed_stage: dict[str, Any],
    *,
    approval_id: str = "repair-approval-one",
    approved_at: str = "2026-07-11T08:37:00Z",
    expires_at: str = "2026-07-18T08:37:00Z",
    ledger_commit: str = "c" * 40,
    prepared_commit_sha: str | None = None,
    persist: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    completed = _complete_live(tmp_path, root, [proposed_stage])
    plan_path = tmp_path / "repair-plan.json"
    fs.weekly_plan(
        root,
        _write(
            tmp_path / "repair-selection.json",
            _approved_selection(tmp_path, root, completed["snapshot_digest"], [proposed]),
        ),
        plan_path,
        "2026-07-11T08:01:00Z",
    )
    plan = fs._load_json(plan_path)
    manifest_path = tmp_path / "repair-manifest.json"
    prepared = _prepared_receipt(plan)
    if prepared_commit_sha is not None:
        prepared["entries"][0]["commit_sha"] = prepared_commit_sha
        prepared["entries"][0]["signature"]["commit_sha"] = prepared_commit_sha
    fs.finalize_publication(
        root,
        plan_path,
        _write(tmp_path / "repair-prepared.json", prepared),
        manifest_path,
        "2026-07-11T08:32:00Z",
    )
    manifest = fs._load_json(manifest_path)
    entry = plan["entries"][0]
    closure = {
        "version": 1,
        "kind": "publication-closure",
        "closure_id": "repair-published-one",
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "closed_at": "2026-07-11T08:36:00Z",
        },
        "reason": "published",
        "summary": "Joey confirmed the exact ledger case publication was merged.",
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
                "ledger_commit": ledger_commit,
                "merged_at": "2026-07-11T08:35:00Z",
            }
        ],
    }
    publication_approval = {
        "version": 1,
        "kind": "publication-approval",
        "approval_id": "repair-publication-approval",
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
    closed = fs.close_publication(
        root,
        _write(tmp_path / "repair-closure.json", closure),
        "2026-07-11T08:36:30Z",
        _write(tmp_path / "repair-publication-approval.json", publication_approval),
    )
    repair_approval = {
        "version": 1,
        "kind": "repair-approval",
        "approval_id": approval_id,
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "approved_at": approved_at,
        },
        "expires_at": expires_at,
        "source": fs._case_tuple(proposed),
        "target": fs._case_tuple(approved),
        "publication": {
            "closure_id": closure["closure_id"],
            "closure_digest": closed["closure_digest"],
            "selection_id": plan["selection_id"],
            "plan_digest": plan["plan_digest"],
            "manifest_digest": manifest["manifest_digest"],
            "pull_request_url": closure["entries"][0]["pull_request_url"],
            "ledger_commit": closure["entries"][0]["ledger_commit"],
            "merged_at": closure["entries"][0]["merged_at"],
        },
    }
    authority = (
        fs.approve_repair(
            root,
            _write(tmp_path / "repair-approved-candidate.json", approved),
            _write(tmp_path / "repair-approval.json", repair_approval),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
        if persist
        else {}
    )
    return repair_approval, authority


def _persist_legacy_mismatched_repair_approval(
    tmp_path: Path,
    root: Path,
    proposed: dict[str, Any],
    target: dict[str, Any],
    proposed_stage: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    *,
    approval_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        target,
        proposed_stage,
        approval_id=approval_id,
        persist=False,
    )
    lifecycle_validator = fs._validate_repair_approval_lifecycle_time
    intent_validator = fs._validate_approve_repair_intent_lifecycle
    run_transaction = fs._run_transaction

    def persist_legacy_authority(store: Any, **kwargs: Any) -> dict[str, Any]:
        if kwargs.get("operation") == "approve-repair":
            result = dict(kwargs["result"])
            result["target_lifecycle_changed_at"] = approval["interaction"]["approved_at"]
            kwargs["result"] = result
        return run_transaction(store, **kwargs)

    monkeypatch.setattr(
        fs,
        "_validate_repair_approval_lifecycle_time",
        lambda approval_value, candidate: None,
    )
    monkeypatch.setattr(
        fs,
        "_validate_approve_repair_intent_lifecycle",
        lambda store, intent, **kwargs: None,
    )
    monkeypatch.setattr(fs, "_run_transaction", persist_legacy_authority)
    authority = fs.approve_repair(
        root,
        _write(tmp_path / f"{approval_id}-candidate.json", target),
        _write(tmp_path / f"{approval_id}.json", approval),
        "2026-07-11T08:38:00Z",
        interactive_confirmed=True,
    )
    monkeypatch.setattr(
        fs,
        "_validate_repair_approval_lifecycle_time",
        lifecycle_validator,
    )
    monkeypatch.setattr(fs, "_validate_approve_repair_intent_lifecycle", intent_validator)
    monkeypatch.setattr(fs, "_run_transaction", run_transaction)
    return approval, authority


def _persist_legacy_repair_approval_result(
    root: Path,
    candidate_path: Path,
    approval_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    intent_validator = fs._validate_approve_repair_intent_lifecycle
    run_transaction = fs._run_transaction

    def persist_legacy_result(store: Any, **kwargs: Any) -> dict[str, Any]:
        if kwargs.get("operation") == "approve-repair":
            result = dict(kwargs["result"])
            result.pop("target_lifecycle_changed_at")
            kwargs["result"] = result
        return run_transaction(store, **kwargs)

    monkeypatch.setattr(
        fs,
        "_validate_approve_repair_intent_lifecycle",
        lambda store, intent, **kwargs: None,
    )
    monkeypatch.setattr(fs, "_run_transaction", persist_legacy_result)
    authority = fs.approve_repair(
        root,
        candidate_path,
        approval_path,
        "2026-07-11T08:38:00Z",
        interactive_confirmed=True,
    )
    monkeypatch.setattr(fs, "_validate_approve_repair_intent_lifecycle", intent_validator)
    monkeypatch.setattr(fs, "_run_transaction", run_transaction)
    assert "target_lifecycle_changed_at" not in authority
    return authority


def _closed_reopen_candidate(
    closed: dict[str, Any], *, observed_at: str = "2026-07-12T12:00:00Z"
) -> dict[str, Any]:
    wrapper = json.loads(json.dumps(closed))
    occurrence = _occurrence(1, root="root:reopen", observed_at=observed_at)
    wrapper["case"]["revision"] += 1
    wrapper["case"]["status"] = "proposed"
    wrapper["case"]["support"] = "repeated"
    wrapper["case"]["evidence"].append(occurrence)
    wrapper["case"]["evidence_last_seen"] = observed_at
    wrapper["case"]["currentness_checked_at"] = observed_at
    evidence = wrapper["case"]["evidence"]
    wrapper["case"]["causal"].update(
        {
            "occurrence_count": len(evidence),
            "root_task_count": len({item["root_task_id"] for item in evidence}),
            "workflow_count": len({item["workflow_id"] for item in evidence}),
            "repository_count": len({item["repository"] for item in evidence}),
            "opportunity_count": len({item["opportunity_id"] for item in evidence}),
            "causal_signature_count": len({item["causal_signature"] for item in evidence}),
        }
    )
    wrapper["case"]["lifecycle_changed_at"] = "2026-07-12T12:01:00Z"
    wrapper["case"]["repairs"][0]["state"] = "superseded"
    repair_id = f"R{len(wrapper['case']['repairs']) + 1}"
    wrapper["case"]["repairs"].append(
        {
            "id": repair_id,
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


def _persistent_identity_snapshot(
    root: Path,
) -> dict[str, tuple[int, int, int, int, bytes | None]]:
    """Bind path inventory, object identity, access mode, and regular bytes."""

    result: dict[str, tuple[int, int, int, int, bytes | None]] = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        payload = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
        result[str(path.relative_to(root))] = (
            stat.S_IFMT(info.st_mode),
            info.st_dev,
            info.st_ino,
            stat.S_IMODE(info.st_mode),
            payload,
        )
    return result


def _rewrite_wal_checkpoint_chain(
    root: Path,
    target_path: Path,
    replacement: dict[str, Any],
) -> None:
    """Rewrite one tampered checkpoint and keep the synthetic usage chain self-consistent."""

    history_root = root / "wal-history"
    checkpoints = [
        (path, fs._load_json(path))
        for path in history_root.rglob("*.json")
        if fs.WAL_HISTORY_LEAF_RE.fullmatch(path.name) is not None
    ]
    checkpoints.sort(key=lambda item: item[1]["sequence"])
    assert any(path == target_path for path, _ in checkpoints)
    usage = fs._new_wal_history_usage()
    for path, checkpoint in checkpoints:
        if path == target_path:
            checkpoint = replacement
        checkpoint["previous_usage_digest"] = usage["usage_digest"]
        body = {key: value for key, value in checkpoint.items() if key != "checkpoint_digest"}
        checkpoint["checkpoint_digest"] = fs._digest(body)
        payload = fs._canonical_bytes(checkpoint)
        path.write_bytes(payload)
        usage = fs._project_wal_history_usage(usage, checkpoint, len(payload))
    (root / fs.WAL_HISTORY_USAGE).write_bytes(fs._canonical_bytes(usage))


@pytest.mark.parametrize(
    ("command", "input_flag"),
    [
        ("validate", "--candidate"),
        ("complete-audit", "--receipt"),
        ("selection-preflight", "--selection-draft"),
    ],
)
def test_external_json_cli_loaders_reject_no_writer_fifo_without_blocking(
    tmp_path: Path,
    command: str,
    input_flag: str,
) -> None:
    fifo = tmp_path / f"{command}.json"
    os.mkfifo(fifo, 0o600)
    argv = [sys.executable, str(HELPER), command]
    if command != "validate":
        argv.extend(["--state-root", str(tmp_path / "unused-state")])
    argv.extend([input_flag, str(fifo)])
    if command != "validate":
        argv.extend(["--now", "2026-07-11T08:00:00Z"])

    completed = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )

    assert completed.returncode == 2
    assert json.loads(completed.stdout)["code"] == "unsafe-file"
    assert not (tmp_path / "unused-state").exists()


def test_external_stable_open_still_reads_an_ordinary_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "ordinary.json", {"ordinary": True})

    raw, digest = fs._open_external_stable(path)

    assert raw == path.read_bytes()
    assert digest == hashlib.sha256(raw).hexdigest()


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


@pytest.mark.parametrize(
    ("observed_at", "causal_at", "last_seen"),
    [
        (
            "2026-06-10T12:00:00.000Z",
            "2026-06-10T12:00:00Z",
            "2026-06-10T12:00:00.000000Z",
        ),
        (
            "2026-06-10T12:00:00.1Z",
            "2026-06-10T12:00:00.100000Z",
            "2026-06-10T12:00:00.100Z",
        ),
    ],
)
def test_equivalent_utc_fraction_forms_compare_as_instants_with_ledger_parity(
    observed_at: str,
    causal_at: str,
    last_seen: str,
) -> None:
    wrapper = _candidate()
    case = wrapper["case"]
    case["evidence"][0]["observed_at"] = observed_at
    case["causal"]["first_observed_at"] = causal_at
    case["evidence_last_seen"] = last_seen
    case["currentness_checked_at"] = causal_at
    case["lifecycle"]["created_at"] = last_seen
    case["lifecycle_changed_at"] = observed_at
    wrapper["control"]["semantic_digest"] = fs.semantic_digest(case)

    assert fs.validate_candidate(wrapper)["semantic_digest"] == fs.semantic_digest(case)
    ledger = _load_ledger_validator()
    path = PurePosixPath(f"cases/{fs._case_year(case['id']):04d}/{case['id']}.json")
    assert ledger.validate_case(case, path) == []


def test_equivalent_dormancy_fraction_forms_compare_as_instants() -> None:
    wrapper = _candidate(status="dormant", lifecycle_at="2026-06-02T12:00:00.1Z")
    case = wrapper["case"]
    case["lifecycle"]["dormant_since"] = "2026-06-02T12:00:00.100000Z"
    case["lifecycle"]["dormant_from_status"] = "watching"
    wrapper["control"]["semantic_digest"] = fs.semantic_digest(case)

    fs.validate_candidate(wrapper)
    ledger = _load_ledger_validator()
    path = PurePosixPath(f"cases/{fs._case_year(case['id']):04d}/{case['id']}.json")
    assert ledger.validate_case(case, path) == []


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


def test_frozen_ledger_authority_rejects_superseded_semantic_mutation() -> None:
    ledger = _load_ledger_validator()
    path = PurePosixPath("cases/2026/DSF-01a00f29-e900-7000-8000-000000000001.json")
    base = _ledger_compatibility_case()
    base["revision"] = 2
    base["status"] = "superseded"
    base["lifecycle_changed_at"] = "2026-08-17T10:35:00Z"
    base["lifecycle"]["superseded_by"] = fs.new_case_id("2026-08-17T10:40:00Z")
    assert ledger.validate_case(base, path) == []

    changed = json.loads(json.dumps(base))
    changed["revision"] += 1
    changed["title"] = "Rewritten terminal history"
    assert ledger.semantic_case_digest(changed) != ledger.semantic_case_digest(base)
    assert ledger._validate_history_transition(base, changed, path) == [
        f"{path}: superseded case canonical semantic digest is immutable"
    ]

    refreshed = json.loads(json.dumps(base))
    refreshed["currentness_checked_at"] = "2026-08-18T10:30:00Z"
    assert ledger.semantic_case_digest(refreshed) == ledger.semantic_case_digest(base)
    assert ledger._validate_history_transition(base, refreshed, path) == []


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
            _approved_selection(tmp_path, root, completed["snapshot_digest"], [wrappers[0]]),
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


def test_new_case_rejects_every_structurally_valid_skipped_lifecycle(
    tmp_path: Path,
) -> None:
    repair_lifecycle = {
        item["case"]["status"]: json.loads(json.dumps(item))
        for item in _repair_lifecycle_candidates()[1:]
    }
    for candidate in repair_lifecycle.values():
        candidate["case"]["revision"] = 1
        candidate["control"]["semantic_digest"] = fs.semantic_digest(candidate["case"])

    dormant = _candidate(status="dormant", lifecycle_at="2026-06-02T12:00:00Z")
    dormant["case"]["lifecycle"]["dormant_since"] = "2026-06-02T12:00:00Z"
    dormant["case"]["lifecycle"]["dormant_from_status"] = "watching"
    dormant["control"]["semantic_digest"] = fs.semantic_digest(dormant["case"])
    repair_lifecycle["dormant"] = dormant

    successor = _candidate(occurrences=[_occurrence(0, root="root:successor")])
    superseded = _candidate(status="superseded", lifecycle_at="2026-06-02T12:00:00Z")
    superseded["case"]["lifecycle"]["superseded_by"] = successor["case"]["id"]
    superseded["control"]["semantic_digest"] = fs.semantic_digest(superseded["case"])
    repair_lifecycle["superseded"] = superseded

    assert set(repair_lifecycle) == {
        "approved",
        "implemented",
        "observing",
        "closed",
        "dormant",
        "superseded",
    }
    for status, candidate in repair_lifecycle.items():
        assert fs.validate_candidate(candidate)["status"] == status
        root = tmp_path / status / "state"
        if status == "superseded":
            fs.stage_candidate(
                _write(tmp_path / status / "successor.json", successor),
                root,
                "2026-07-10T11:59:00Z",
            )
        with pytest.raises(fs.StateError, match="new case must start at watching or proposed"):
            fs.stage_candidate(
                _write(tmp_path / status / "candidate.json", candidate),
                root,
                "2026-07-12T12:00:00Z",
            )
        assert not (root / fs._case_relative_path(candidate)).exists()


def test_new_case_requires_repeated_support_to_enter_proposed(tmp_path: Path) -> None:
    watching = _candidate()
    watching_receipt = fs.stage_candidate(
        _write(tmp_path / "watching" / "candidate.json", watching),
        tmp_path / "watching" / "state",
        "2026-07-10T12:00:00Z",
    )
    assert watching_receipt["action"] == "created"
    assert (
        fs._load_json(Path(watching_receipt["path"]).parents[2] / watching_receipt["case_path"])[
            "case"
        ]["status"]
        == "watching"
    )

    novel_proposed = _with_planned_repair(_candidate(status="proposed"))
    assert fs.validate_candidate(novel_proposed)["support"] == "novel"
    novel_root = tmp_path / "novel-proposed" / "state"
    with pytest.raises(fs.StateError, match="entering proposed requires repeated support") as novel:
        fs.stage_candidate(
            _write(tmp_path / "novel-proposed" / "candidate.json", novel_proposed),
            novel_root,
            "2026-07-10T12:00:00Z",
        )
    assert novel.value.code == "insufficient-proposed-support"
    assert not (novel_root / fs._case_relative_path(novel_proposed)).exists()

    repeated_proposed = _repair_lifecycle_candidates()[0]
    proposed_receipt = fs.stage_candidate(
        _write(tmp_path / "repeated-proposed" / "candidate.json", repeated_proposed),
        tmp_path / "repeated-proposed" / "state",
        "2026-07-10T12:00:00Z",
    )
    assert proposed_receipt["action"] == "created"
    stored = fs._load_json(
        Path(proposed_receipt["path"]).parents[2] / proposed_receipt["case_path"]
    )
    assert stored["case"]["status"] == "proposed"
    assert stored["case"]["support"] == "repeated"


def test_existing_case_promotion_to_proposed_requires_repeated_support(tmp_path: Path) -> None:
    watching = _candidate()
    root, _ = _stage(tmp_path, watching)

    novel_promotion = json.loads(json.dumps(watching))
    novel_promotion["case"]["revision"] = 2
    novel_promotion["case"]["status"] = "proposed"
    novel_promotion["case"]["lifecycle_changed_at"] = "2026-06-02T12:00:00Z"
    _with_planned_repair(novel_promotion)
    assert fs.validate_candidate(novel_promotion)["support"] == "novel"
    before = _persistent_identity_snapshot(root)
    with pytest.raises(fs.StateError, match="entering proposed requires repeated support") as novel:
        fs.stage_candidate(
            _write(tmp_path / "novel-promotion.json", novel_promotion),
            root,
            "2026-07-10T12:30:00Z",
        )
    assert novel.value.code == "insufficient-proposed-support"
    assert _persistent_identity_snapshot(root) == before
    assert fs._load_json(root / fs._case_relative_path(watching))["case"]["status"] == "watching"

    repeated_promotion = _with_planned_repair(
        _candidate(
            case_id=watching["case"]["id"],
            occurrences=[_occurrence(0), _occurrence(1)],
            result="repeated",
            status="proposed",
            revision=2,
            lifecycle_at="2026-06-02T12:00:00Z",
        )
    )
    promoted = fs.stage_candidate(
        _write(tmp_path / "repeated-promotion.json", repeated_promotion),
        root,
        "2026-07-10T13:00:00Z",
    )
    assert promoted["action"] == "updated"
    stored = fs._load_json(root / promoted["case_path"])
    assert stored["case"]["status"] == "proposed"
    assert stored["case"]["support"] == "repeated"

    refreshed = json.loads(json.dumps(repeated_promotion))
    refreshed["case"]["currentness_checked_at"] = "2026-07-11T12:00:00Z"
    refreshed_receipt = fs.stage_candidate(
        _write(tmp_path / "proposed-currentness.json", refreshed),
        root,
        "2026-07-11T12:01:00Z",
    )
    refreshed_stored = fs._load_json(root / refreshed_receipt["case_path"])
    assert refreshed_stored["case"]["revision"] == 2
    assert (
        refreshed_stored["control"]["semantic_digest"]
        == repeated_promotion["control"]["semantic_digest"]
    )
    assert (
        refreshed_stored["case"]["lifecycle_changed_at"]
        == repeated_promotion["case"]["lifecycle_changed_at"]
    )


def test_source_kind_cannot_bypass_initial_lifecycle(tmp_path: Path) -> None:
    legacy = json.loads(json.dumps(_repair_lifecycle_candidates()[1]))
    legacy["case"]["revision"] = 1
    legacy["case"]["source_kind"] = "legacy-migration"
    legacy["control"]["source_lineage"][0]["source_family"] = "legacy-migration"
    legacy["control"]["semantic_digest"] = fs.semantic_digest(legacy["case"])
    assert fs.validate_candidate(legacy)["status"] == "approved"
    with pytest.raises(fs.StateError, match="source_kind does not authorize"):
        fs.stage_candidate(
            _write(tmp_path / "legacy.json", legacy),
            tmp_path / "legacy-state",
            "2026-07-12T12:00:00Z",
        )

    origin = _candidate()
    root, _ = _stage(tmp_path / "automation", origin)
    correction = _occurrence(
        1,
        root="root:correction",
        observed_at="2026-06-02T12:00:00Z",
    )
    correction["signal_type"] = "explicit-human-correction"
    derived = _candidate(
        occurrences=[correction],
        status="approved",
        lifecycle_at="2026-06-03T12:00:00Z",
        source_kind="automation-derived",
        explicit_human_root="root:correction",
        origin_case_id=origin["case"]["id"],
    )
    derived["case"]["repairs"] = [
        {
            "id": "R1",
            "repository": "Joey-Tools/example",
            "action": "install",
            "state": "open",
            "problem_statement": "The derived workflow omitted an authority boundary check.",
            "change_summary": "Add the missing bounded authority check.",
            "pull_request_url": "https://github.com/Joey-Tools/example/pull/2",
            "commit": None,
            "commit_trailer": f"Friction-Case: {derived['case']['id']}",
            "installed_on": None,
            "removed_on": None,
            "replaces_repair_id": None,
        }
    ]
    derived["case"]["effectiveness"]["method"] = "deterministic"
    derived["control"]["semantic_digest"] = fs.semantic_digest(derived["case"])
    assert fs.validate_candidate(derived)["status"] == "approved"
    with pytest.raises(fs.StateError, match="source_kind does not authorize"):
        fs.stage_candidate(
            _write(tmp_path / "automation" / "derived.json", derived),
            root,
            "2026-07-10T13:00:00Z",
        )


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
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
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
            _approved_selection(tmp_path, root, completed["snapshot_digest"], [case]),
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
        "summary": _audit_summary(candidates_considered=1, cases_updated=1),
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
            _approved_selection(
                tmp_path,
                root,
                second_completed["snapshot_digest"],
                [updated],
                checked_at="2026-07-12T08:31:30Z",
                approved_at="2026-07-12T08:32:00Z",
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


@pytest.mark.parametrize(
    ("field", "incorrect"),
    [
        ("cases_created", 0),
        ("cases_updated", 1),
        ("cases_unchanged", 1),
        ("cases_dormant", 1),
    ],
)
def test_daily_audit_case_counts_must_match_exact_stage_receipts(
    tmp_path: Path, field: str, incorrect: int
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    summary = _audit_summary(candidates_considered=1, cases_created=1)
    summary[field] = incorrect
    audit_id = f"mismatched-{field}"
    audit = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": audit_id,
        "started_at": "2026-07-10T11:00:00Z",
        "ended_at": "2026-07-10T12:30:00Z",
        "previous_snapshot_digest": None,
        "stage_receipts": [_receipt_ref(stage)],
        "dormancy_receipts": [],
        "summary": summary,
    }
    with pytest.raises(fs.StateError, match="does not match its exact receipts"):
        fs.complete_audit(
            root,
            _write(tmp_path / f"{audit_id}.json", audit),
            "2026-07-10T12:31:00Z",
            historical_replay=False,
        )
    intent_path, _ = fs._wal_paths("complete-audit", audit_id)
    assert not (root / intent_path).exists()
    assert not (root / fs.LIVE_POINTER).exists()


def test_daily_audit_dormant_count_must_match_changed_receipt_entries(tmp_path: Path) -> None:
    case = _candidate(lifecycle_at="2026-06-01T12:00:00Z")
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    dormancy = fs.transition_dormant(root, "2026-07-12T12:00:00Z")
    assert len(dormancy["changed"]) == 1
    audit = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": "mismatched-dormancy-count",
        "started_at": "2026-07-12T11:00:00Z",
        "ended_at": "2026-07-12T12:30:00Z",
        "previous_snapshot_digest": completed["snapshot_digest"],
        "stage_receipts": [],
        "dormancy_receipts": [_receipt_ref(dormancy)],
        "summary": _audit_summary(cases_dormant=0),
    }
    with pytest.raises(fs.StateError, match=r"cases_dormant=0 \(expected 1\)"):
        fs.complete_audit(
            root,
            _write(tmp_path / "mismatched-dormancy-count.json", audit),
            "2026-07-12T12:31:00Z",
            historical_replay=False,
        )
    assert not (root / "completed" / "mismatched-dormancy-count.json").exists()
    audit["summary"] = _audit_summary(cases_dormant=1)
    completed_dormancy = fs.complete_audit(
        root,
        _write(tmp_path / "matched-dormancy-count.json", audit),
        "2026-07-12T12:32:00Z",
        historical_replay=False,
    )
    assert completed_dormancy["status"] == "completed"


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
        "summary": _audit_summary(candidates_considered=1, cases_created=1),
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


def test_selection_must_bind_durable_preflight_and_trusted_approval(tmp_path: Path) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    untrusted = _approved_selection(
        tmp_path, root, completed["snapshot_digest"], [case], actor="Automation"
    )
    with pytest.raises(fs.StateError, match="interactive Joey"):
        fs.weekly_plan(
            root,
            _write(tmp_path / "untrusted.json", untrusted),
            tmp_path / "untrusted-plan.json",
            "2026-07-11T08:01:00Z",
        )
    self_signed = _selection(completed["snapshot_digest"], [case])
    with pytest.raises(fs.StateError, match="no committed control transaction") as raised:
        fs.weekly_plan(
            root,
            _write(tmp_path / "self-signed.json", self_signed),
            tmp_path / "self-signed-plan.json",
            "2026-07-11T08:01:00Z",
        )
    assert raised.value.code == "missing-authority-transaction"


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
    before = _tree_bytes(root)
    with pytest.raises(fs.StateError, match="outside the live ancestry"):
        _approved_selection(
            tmp_path,
            root,
            orphan["snapshot_digest"],
            [case],
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
    empty = _approved_selection(tmp_path, root, completed["snapshot_digest"], [])
    empty_result = fs.weekly_plan(
        root,
        _write(tmp_path / "empty-selection.json", empty),
        tmp_path / "empty-plan.json",
        "2026-07-11T08:01:00Z",
    )
    assert empty_result["selected_count"] == 0
    selected = _approved_selection(tmp_path, root, completed["snapshot_digest"], cases)
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
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
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
        output,
        "2026-07-12T08:02:00Z",
    )
    assert allowed["status"] == "finalized"
    rebound_output = tmp_path / "checked-manifest.json"
    with pytest.raises(fs.StateError, match="different request") as raised:
        fs.finalize_publication(
            root,
            plan_path,
            prepared_path,
            rebound_output,
            "2026-07-12T08:02:00Z",
        )
    assert raised.value.code == "wal-request-conflict"
    assert not rebound_output.exists()

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
            output,
            "2026-07-12T08:04:00Z",
        )
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


def test_finalize_rejects_base_commit_before_claiming_immutable_writer(tmp_path: Path) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    plan_path = tmp_path / "base-commit-plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "base-commit-selection.json", selection),
        plan_path,
        "2026-07-11T08:01:00Z",
    )
    plan = fs._load_json(plan_path)
    invalid_prepared = _prepared_receipt(plan)
    base_sha = plan["base_intent"]["base_sha"]
    invalid_prepared["entries"][0]["commit_sha"] = base_sha
    invalid_prepared["entries"][0]["signature"]["commit_sha"] = base_sha
    output = tmp_path / "base-commit-manifest.json"
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError, match="must differ from the bound base SHA") as invalid:
        fs.finalize_publication(
            root,
            plan_path,
            _write(tmp_path / "base-commit-prepared.json", invalid_prepared),
            output,
            "2026-07-11T08:32:00Z",
        )
    assert invalid.value.code == "prepared-base-commit"
    assert _persistent_identity_snapshot(root) == before
    assert not output.exists()
    natural_key = f"{plan['selection_id']}:{plan['plan_digest']}"
    intent_path, commit_path = fs._wal_paths("finalize-publication", natural_key)
    assert not (root / intent_path).exists()
    assert not (root / commit_path).exists()
    assert not (root / "publication" / "manifests" / f"{plan['selection_id']}.json").exists()
    assert not (root / "publication" / "prepared" / f"{plan['selection_id']}.json").exists()

    mismatched_prepared = _prepared_receipt(plan)
    mismatched_prepared["entries"][0]["commit_sha"] = "d" * 64
    mismatched_prepared["entries"][0]["signature"]["commit_sha"] = "d" * 64
    with pytest.raises(fs.StateError, match="base SHA object-ID width") as mismatched:
        fs.finalize_publication(
            root,
            plan_path,
            _write(tmp_path / "mismatched-commit-prepared.json", mismatched_prepared),
            output,
            "2026-07-11T08:32:00Z",
        )
    assert mismatched.value.code == "prepared-commit-format"
    assert _persistent_identity_snapshot(root) == before
    assert not output.exists()

    valid_prepared = _prepared_receipt(plan)
    valid_prepared_path = _write(tmp_path / "advanced-commit-prepared.json", valid_prepared)
    first = fs.finalize_publication(
        root,
        plan_path,
        valid_prepared_path,
        output,
        "2026-07-11T08:32:00Z",
    )
    replay = fs.finalize_publication(
        root,
        plan_path,
        valid_prepared_path,
        output,
        "2026-07-11T08:32:00Z",
    )
    assert replay == first
    assert fs._load_json(output)["entries"][0]["commit_sha"] != base_sha


@pytest.mark.parametrize(
    ("commit_kind", "error_code", "error_match"),
    [
        ("base", "prepared-base-commit", "must differ from the bound base SHA"),
        ("wrong-width", "prepared-commit-format", "bound base SHA object-ID width"),
    ],
)
def test_pending_finalize_wal_revalidates_prepared_commit_before_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    commit_kind: str,
    error_code: str,
    error_match: str,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    plan_path = tmp_path / "pending-invalid-plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "pending-invalid-selection.json", selection),
        plan_path,
        "2026-07-11T08:01:00Z",
    )
    plan = fs._load_json(plan_path)
    prepared = _prepared_receipt(plan)
    commit_sha = plan["base_intent"]["base_sha"] if commit_kind == "base" else "d" * 64
    prepared["entries"][0]["commit_sha"] = commit_sha
    prepared["entries"][0]["signature"]["commit_sha"] = commit_sha
    prepared_path = _write(tmp_path / f"pending-{commit_kind}-prepared.json", prepared)
    output = tmp_path / f"pending-{commit_kind}-manifest.json"
    prepared_relative = Path("publication") / "prepared" / f"{plan['selection_id']}.json"
    manifest_relative = Path("publication") / "manifests" / f"{plan['selection_id']}.json"
    entry_validator = fs._validate_prepared_entry
    original_write = fs.StateStore.write_json

    def accept_legacy_entry(
        value: Any,
        index: int,
        plan_entry: dict[str, Any],
        *,
        plan_created_at: str,
        now: str,
    ) -> dict[str, Any]:
        del index, plan_entry, plan_created_at, now
        return value

    def interrupt_prepared(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        if Path(relative) == prepared_relative:
            raise OSError("injected invalid prepared publication interruption")
        return original_write(store, relative, value, immutable=immutable)

    monkeypatch.setattr(fs, "_validate_prepared_entry", accept_legacy_entry)
    monkeypatch.setattr(fs.StateStore, "write_json", interrupt_prepared)
    with pytest.raises(OSError, match="injected invalid prepared publication interruption"):
        fs.finalize_publication(
            root,
            plan_path,
            prepared_path,
            output,
            "2026-07-11T08:32:00Z",
        )
    monkeypatch.setattr(fs, "_validate_prepared_entry", entry_validator)
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)

    natural_key = f"{plan['selection_id']}:{plan['plan_digest']}"
    intent_relative, commit_relative = fs._wal_paths("finalize-publication", natural_key)
    assert (root / intent_relative).exists()
    assert not (root / commit_relative).exists()
    assert not (root / prepared_relative).exists()
    assert not (root / manifest_relative).exists()
    assert not output.exists()
    before = _persistent_identity_snapshot(root)
    recovery_candidate = _candidate(
        case_id=fs.new_case_id("2026-06-02T12:00:00Z"),
        occurrences=[_occurrence(0, root=f"root:pending-{commit_kind}-recovery")],
    )

    with pytest.raises(fs.StateError, match=error_match) as raised:
        fs.stage_candidate(
            _write(tmp_path / f"pending-{commit_kind}-recovery.json", recovery_candidate),
            root,
            "2026-07-12T08:00:00Z",
        )

    assert raised.value.code == error_code
    assert _persistent_identity_snapshot(root) == before
    assert not (root / prepared_relative).exists()
    assert not (root / manifest_relative).exists()
    assert not output.exists()


def test_finalize_recovers_valid_pending_prepared_and_manifest_before_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    plan_path = tmp_path / "pending-valid-plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "pending-valid-selection.json", selection),
        plan_path,
        "2026-07-11T08:01:00Z",
    )
    plan = fs._load_json(plan_path)
    prepared_path = _write(tmp_path / "pending-valid-prepared.json", _prepared_receipt(plan))
    output = tmp_path / "pending-valid-manifest.json"
    prepared_relative = Path("publication") / "prepared" / f"{plan['selection_id']}.json"
    original_write = fs.StateStore.write_json

    def interrupt_prepared(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        if Path(relative) == prepared_relative:
            raise OSError("injected valid prepared publication interruption")
        return original_write(store, relative, value, immutable=immutable)

    monkeypatch.setattr(fs.StateStore, "write_json", interrupt_prepared)
    with pytest.raises(OSError, match="injected valid prepared publication interruption"):
        fs.finalize_publication(
            root,
            plan_path,
            prepared_path,
            output,
            "2026-07-11T08:32:00Z",
        )
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)
    assert not (root / prepared_relative).exists()
    assert not output.exists()

    recovered = fs.finalize_publication(
        root,
        plan_path,
        prepared_path,
        output,
        "2026-07-11T09:32:00Z",
    )
    replayed = fs.finalize_publication(
        root,
        plan_path,
        prepared_path,
        output,
        "2026-07-11T10:32:00Z",
    )
    assert replayed == recovered
    assert recovered["status"] == "finalized"
    assert fs._load_json(output)["manifest_digest"] == recovered["manifest_digest"]


def test_finalize_public_conflict_does_not_repair_prior_external_output(
    tmp_path: Path,
) -> None:
    root, _, _ = _finalize_one(tmp_path, _candidate())
    plan_path = tmp_path / "plan.json"
    prepared_path = tmp_path / "prepared.json"
    original_output = tmp_path / "manifest.json"
    conflicting_output = tmp_path / "conflicting-manifest.json"
    original_output.unlink()
    marker = root / fs.STATE_MARKER
    marker_helper = root / f".{fs.STATE_MARKER}.tmp-1-0000000000000000"
    os.link(marker, marker_helper)
    marker_identity = (marker.stat().st_dev, marker.stat().st_ino)
    assert marker.stat().st_nlink == marker_helper.stat().st_nlink == 2

    before = _persistent_identity_snapshot(root)
    with pytest.raises(fs.StateError) as raised:
        fs.finalize_publication(
            root,
            plan_path,
            prepared_path,
            conflicting_output,
            "2026-07-11T08:33:00Z",
        )
    assert raised.value.code == "wal-request-conflict"
    assert _persistent_identity_snapshot(root) == before
    assert (marker.stat().st_dev, marker.stat().st_ino) == marker_identity
    assert (marker_helper.stat().st_dev, marker_helper.stat().st_ino) == marker_identity
    assert marker.stat().st_nlink == marker_helper.stat().st_nlink == 2
    assert not original_output.exists()
    assert not conflicting_output.exists()


def test_complete_audit_never_creates_missing_lock_before_binding_rejection(
    tmp_path: Path,
) -> None:
    root, stage = _stage(tmp_path, _candidate())
    _complete_live(tmp_path, root, [stage])
    conflicting_audit = fs._load_json(tmp_path / "audit.json")
    conflicting_audit["summary"]["next_watchpoint"] = (
        "Recheck the exact repository-local authority after its next update."
    )
    receipt_path = _write(tmp_path / "conflicting-audit.json", conflicting_audit)
    lock_path = root / fs.LOCK_FILE
    lock_path.unlink()
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError) as raised:
        fs.complete_audit(
            root,
            receipt_path,
            "2026-07-10T12:32:00Z",
            historical_replay=False,
        )
    assert raised.value.code == "initialization-in-progress"
    assert _persistent_identity_snapshot(root) == before
    assert not lock_path.exists()


def test_finalize_external_output_cannot_target_managed_state_without_side_effects(
    tmp_path: Path,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    plan_path = tmp_path / "outside-plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "finalize-inside-selection.json", selection),
        plan_path,
        "2026-07-11T08:01:00Z",
    )
    plan = fs._load_json(plan_path)
    prepared_path = _write(tmp_path / "inside-state-prepared.json", _prepared_receipt(plan))
    output = root / "publication" / "poison-manifest.json"
    before = _tree_bytes(root)

    with pytest.raises(fs.StateError, match="outside the managed state root") as raised:
        fs.finalize_publication(
            root,
            plan_path,
            prepared_path,
            output,
            "2026-07-11T08:32:00Z",
        )

    assert raised.value.code == "output-inside-state-root"
    assert _tree_bytes(root) == before
    assert not output.exists()


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
        "summary": _audit_summary(candidates_considered=1, cases_created=1),
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


def test_pending_complete_audit_wal_revalidates_its_persisted_receipt_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    audit_id = "legacy-invalid-count"
    audit = {
        "version": 1,
        "kind": "daily-audit",
        "audit_id": audit_id,
        "started_at": "2026-07-10T11:00:00Z",
        "ended_at": "2026-07-10T12:30:00Z",
        "previous_snapshot_digest": None,
        "stage_receipts": [_receipt_ref(stage)],
        "dormancy_receipts": [],
        "summary": _audit_summary(candidates_considered=1),
    }
    receipt_path = _write(tmp_path / "legacy-invalid-count.json", audit)
    original_count_validator = fs._validate_receipt_backed_audit_counts
    original_write = fs.StateStore.write_json
    history_relative = Path("completed") / f"{audit_id}.json"

    def skip_legacy_count_validation(*_args: Any, **_kwargs: Any) -> None:
        return None

    def fail_first_snapshot(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        if Path(relative) == history_relative:
            raise OSError("injected legacy completion interruption")
        return original_write(store, relative, value, immutable=immutable)

    monkeypatch.setattr(fs, "_validate_receipt_backed_audit_counts", skip_legacy_count_validation)
    monkeypatch.setattr(fs.StateStore, "write_json", fail_first_snapshot)
    with pytest.raises(OSError, match="injected legacy completion interruption"):
        fs.complete_audit(root, receipt_path, "2026-07-10T12:31:00Z", historical_replay=False)
    monkeypatch.setattr(fs, "_validate_receipt_backed_audit_counts", original_count_validator)
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)

    intent_path, commit_path = fs._wal_paths("complete-audit", f"live:{audit_id}")
    assert (root / intent_path).exists()
    assert not (root / commit_path).exists()
    assert not (root / history_relative).exists()
    before = _tree_bytes(root)

    corrected = json.loads(json.dumps(audit))
    corrected["summary"] = _audit_summary(candidates_considered=1, cases_created=1)
    with pytest.raises(fs.StateError, match="different request") as corrected_conflict:
        fs.complete_audit(
            root,
            _write(tmp_path / "corrected-legacy-count.json", corrected),
            "2026-07-10T12:32:00Z",
            historical_replay=False,
        )
    assert corrected_conflict.value.code == "wal-request-conflict"
    assert _tree_bytes(root) == before

    another_case = _candidate(occurrences=[_occurrence(0, root="root:generic-recovery")])
    with pytest.raises(fs.StateError, match="does not match its exact receipts"):
        fs.stage_candidate(
            _write(tmp_path / "generic-recovery.json", another_case),
            root,
            "2026-07-10T12:33:00Z",
        )
    assert _tree_bytes(root) == before


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
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    output = _write(tmp_path / "conflicting-plan.json", {"foreign": True})
    output.chmod(0o600)
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


@pytest.mark.parametrize("target_kind", ["root", "descendant", "normalized-descendant"])
def test_weekly_external_output_cannot_target_managed_state_without_side_effects(
    tmp_path: Path,
    target_kind: str,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    selection_path = _write(tmp_path / "inside-state-selection.json", selection)
    outputs = {
        "root": root,
        "descendant": root / "publication" / "poison-plan.json",
        "normalized-descendant": (root / "publication" / ".." / "cases" / "poison-plan.json"),
    }
    output = outputs[target_kind]
    normalized_output = Path(os.path.abspath(os.fspath(output)))
    before = _tree_bytes(root)

    with pytest.raises(fs.StateError, match="outside the managed state root") as raised:
        fs.weekly_plan(root, selection_path, output, "2026-07-11T08:01:00Z")

    assert raised.value.code == "output-inside-state-root"
    assert _tree_bytes(root) == before
    if normalized_output != root:
        assert not normalized_output.exists()


def test_weekly_external_output_allows_a_normalized_sibling(tmp_path: Path) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    sibling = tmp_path / "state-sibling"
    sibling.mkdir(mode=0o700)
    output = root / ".." / sibling.name / "plan.json"

    result = fs.weekly_plan(
        root,
        _write(tmp_path / "sibling-selection.json", selection),
        output,
        "2026-07-11T08:01:00Z",
    )

    normalized_output = sibling / "plan.json"
    assert result["status"] == "planned"
    assert result["plan_path"] == str(normalized_output)
    assert normalized_output.exists()


def test_selection_preflight_rejects_active_publication_without_partial_state(
    tmp_path: Path,
) -> None:
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
            _approved_selection(tmp_path, root, completed["snapshot_digest"], [occupied]),
        ),
        tmp_path / "occupied-plan.json",
        "2026-07-11T08:01:00Z",
    )
    before = _tree_bytes(root)
    with pytest.raises(fs.StateError, match="already has an active publication"):
        _approved_selection(
            tmp_path,
            root,
            completed["snapshot_digest"],
            ordered,
            checked_at="2026-07-11T08:02:00Z",
            approved_at="2026-07-11T08:03:00Z",
        )
    assert _tree_bytes(root) == before


def _leave_pending_weekly_external_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    output_parent: Path | None = None,
) -> tuple[Path, Path, Path, dict[str, Any]]:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection_path = _write(
        tmp_path / "interrupted-selection.json",
        _approved_selection(tmp_path, root, completed["snapshot_digest"], [case]),
    )
    parent = output_parent or tmp_path
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = parent / "interrupted-plan.json"
    original = fs.StateStore.write_json
    injected = False

    def fail_external_output(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        nonlocal injected
        if not injected and store.root == parent and Path(relative) == Path(output.name):
            injected = True
            raise OSError("injected weekly output interruption")
        return original(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )

    monkeypatch.setattr(fs.StateStore, "write_json", fail_external_output)
    with pytest.raises(OSError, match="injected weekly output interruption"):
        fs.weekly_plan(root, selection_path, output, "2026-07-11T08:01:00Z")
    monkeypatch.setattr(fs.StateStore, "write_json", original)
    assert not output.exists()
    return root, selection_path, output, case


def test_weekly_plan_recovers_external_output_gap_across_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, selection_path, output, case = _leave_pending_weekly_external_write(tmp_path, monkeypatch)
    recovered = fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")
    plan = fs._load_json(output)
    assert recovered["plan_digest"] == plan["plan_digest"]
    assert plan["created_at"] == "2026-07-11T08:01:00Z"
    active = fs._load_json(root / "publication" / "active" / f"{case['case']['id']}.json")
    assert active["activated_at"] == "2026-07-11T08:01:00Z"


def test_weekly_wal_recovery_never_recreates_a_missing_external_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_parent = tmp_path / "external"
    root, selection_path, output, _ = _leave_pending_weekly_external_write(
        tmp_path, monkeypatch, output_parent=output_parent
    )
    output_parent.rmdir()

    with pytest.raises(fs.StateError, match="parent disappeared") as raised:
        fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")

    assert raised.value.code == "external-parent-missing"
    assert not output_parent.exists()


def test_weekly_wal_recovery_rejects_same_path_replacement_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_parent = tmp_path / "external"
    root, selection_path, output, _ = _leave_pending_weekly_external_write(
        tmp_path, monkeypatch, output_parent=output_parent
    )
    displaced = tmp_path / "external-displaced"
    output_parent.rename(displaced)
    output_parent.mkdir(mode=0o700)

    with pytest.raises(fs.StateError, match="identity/name chain changed") as raised:
        fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")

    assert raised.value.code == "external-parent-replaced"
    assert not output.exists()
    assert not (displaced / output.name).exists()


@pytest.mark.parametrize("replacement_kind", ["file", "symlink"])
def test_weekly_wal_recovery_classifies_non_directory_parent_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    output_parent = tmp_path / "external"
    root, selection_path, output, _ = _leave_pending_weekly_external_write(
        tmp_path, monkeypatch, output_parent=output_parent
    )
    displaced = tmp_path / "external-displaced"
    output_parent.rename(displaced)
    if replacement_kind == "file":
        output_parent.write_text("replacement", encoding="utf-8")
        output_parent.chmod(0o600)
    else:
        output_parent.symlink_to(displaced, target_is_directory=True)

    with pytest.raises(fs.StateError, match="no longer the directory chain") as raised:
        fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")

    assert raised.value.code == "external-parent-replaced"
    assert not (displaced / output.name).exists()


def test_weekly_wal_recovery_rejects_external_parent_access_policy_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_parent = tmp_path / "external"
    root, selection_path, output, _ = _leave_pending_weekly_external_write(
        tmp_path, monkeypatch, output_parent=output_parent
    )
    output_parent.chmod(0o500)
    try:
        with pytest.raises(fs.StateError, match="parent access policy changed") as raised:
            fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")
        assert raised.value.code == "external-parent-policy-changed"
        assert not output.exists()
    finally:
        output_parent.chmod(0o700)


def test_weekly_wal_recovery_rejects_unsafe_external_custody_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_custody = tmp_path / "output-custody"
    output_parent = output_custody / "external"
    root, selection_path, output, _ = _leave_pending_weekly_external_write(
        tmp_path, monkeypatch, output_parent=output_parent
    )
    output_custody.chmod(0o770)
    try:
        with pytest.raises(fs.StateError, match="parent policy changed") as raised:
            fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")
        assert raised.value.code == "external-parent-policy-changed"
        assert not output.exists()
    finally:
        output_custody.chmod(0o700)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL contract")
def test_weekly_wal_recovery_rejects_external_parent_acl_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_parent = tmp_path / "external"
    root, selection_path, output, _ = _leave_pending_weekly_external_write(
        tmp_path, monkeypatch, output_parent=output_parent
    )
    subprocess.run(
        ["/bin/chmod", "+a", "everyone deny delete", str(output_parent)],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        with pytest.raises(fs.StateError, match="parent access policy changed") as raised:
            fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")
        assert raised.value.code == "external-parent-policy-changed"
        assert not output.exists()
    finally:
        subprocess.run(["/bin/chmod", "-N", str(output_parent)], check=True, capture_output=True)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL contract")
def test_weekly_wal_accepts_and_revalidates_preexisting_deny_only_parent_acl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_parent = tmp_path / "external"
    output_parent.mkdir(mode=0o700)
    subprocess.run(
        ["/bin/chmod", "+a", "everyone deny delete", str(output_parent)],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        root, selection_path, output, _ = _leave_pending_weekly_external_write(
            tmp_path, monkeypatch, output_parent=output_parent
        )
        recovered = fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")
        assert recovered["status"] == "planned"
        assert output.exists()
    finally:
        subprocess.run(["/bin/chmod", "-N", str(output_parent)], check=True, capture_output=True)


def test_weekly_wal_recovery_ignores_external_parent_child_churn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_parent = tmp_path / "external"
    root, selection_path, output, _ = _leave_pending_weekly_external_write(
        tmp_path, monkeypatch, output_parent=output_parent
    )
    before = output_parent.stat()
    transient = output_parent / "transient"
    transient.mkdir(mode=0o700)
    after = output_parent.stat()
    assert (before.st_mtime_ns, before.st_size, before.st_nlink) != (
        after.st_mtime_ns,
        after.st_size,
        after.st_nlink,
    )

    recovered = fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")

    assert recovered["status"] == "planned"
    assert output.exists()
    transient.rmdir()


def test_weekly_wal_recovery_revalidates_existing_after_image_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection_path = _write(
        tmp_path / "after-image-selection.json",
        _approved_selection(tmp_path, root, completed["snapshot_digest"], [case]),
    )
    output = tmp_path / "after-image-plan.json"
    original_commit = fs._commit_wal

    def interrupt_weekly_commit(store: Any, intent: dict[str, Any]) -> None:
        if intent["operation"] == "weekly-plan":
            raise OSError("injected weekly commit interruption")
        original_commit(store, intent)

    monkeypatch.setattr(fs, "_commit_wal", interrupt_weekly_commit)
    with pytest.raises(OSError, match="injected weekly commit interruption"):
        fs.weekly_plan(root, selection_path, output, "2026-07-11T08:01:00Z")
    monkeypatch.setattr(fs, "_commit_wal", original_commit)
    assert output.exists()
    output.chmod(0o644)
    try:
        with pytest.raises(fs.StateError, match="group or other access") as raised:
            fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")
        assert raised.value.code == "unsafe-permissions"
        _, commit_relative = fs._wal_paths(
            "weekly-plan", fs._load_json(selection_path)["selection_id"]
        )
        assert not (root / commit_relative).exists()
    finally:
        output.chmod(0o600)


def test_external_after_image_loss_after_commit_publication_rolls_back_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    selection_path = _write(tmp_path / "commit-custody-selection.json", selection)
    output = tmp_path / "commit-custody-plan.json"
    _, commit_relative = fs._wal_paths("weekly-plan", selection["selection_id"])
    original = fs.StateStore.write_json
    injected = False

    def remove_after_commit_publication(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        nonlocal injected
        digest = original(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )
        if not injected and store.root == root and Path(relative) == commit_relative:
            injected = True
            output.unlink()
        return digest

    monkeypatch.setattr(fs.StateStore, "write_json", remove_after_commit_publication)
    with pytest.raises(fs.StateError, match="exactly one link") as raised:
        fs.weekly_plan(root, selection_path, output, "2026-07-11T08:01:00Z")
    assert raised.value.code == "unsafe-link-count"
    monkeypatch.setattr(fs.StateStore, "write_json", original)

    intent_relative, _ = fs._wal_paths("weekly-plan", selection["selection_id"])
    assert (root / intent_relative).exists()
    assert not (root / commit_relative).exists()
    assert not output.exists()

    recovered = fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")
    assert recovered["status"] == "planned"
    assert output.exists() and (root / commit_relative).exists()


@pytest.mark.parametrize(
    "failure_point",
    [
        "publication-directory-fsync",
        "temporary-cleanup",
        "cleanup-directory-fsync",
        "final-reread",
    ],
)
def test_commit_wal_postpublication_failures_roll_back_exact_owned_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    selection_path = _write(tmp_path / f"{failure_point}-selection.json", selection)
    output = tmp_path / f"{failure_point}-plan.json"
    intent_relative, commit_relative = fs._wal_paths("weekly-plan", selection["selection_id"])
    commit_leaf = commit_relative.name

    original_link = os.link
    original_fsync = os.fsync
    original_unlink = os.unlink
    original_read_named = fs.StateStore._read_named
    published = False
    injected = False
    postpublication_fsyncs = 0
    temporary_cleanup_failures = 0

    def track_commit_link(
        src: str,
        dst: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal published
        original_link(
            src,
            dst,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )
        if dst == commit_leaf:
            published = True

    def fail_selected_fsync(fd: int) -> None:
        nonlocal injected, postpublication_fsyncs
        if published:
            postpublication_fsyncs += 1
            selected = (
                failure_point == "publication-directory-fsync" and postpublication_fsyncs == 1
            ) or (failure_point == "cleanup-directory-fsync" and postpublication_fsyncs == 2)
            if selected and not injected:
                injected = True
                raise OSError(f"injected {failure_point} failure")
        original_fsync(fd)

    def fail_selected_unlink(path: str | bytes, *, dir_fd: int | None = None) -> None:
        nonlocal injected, temporary_cleanup_failures
        if (
            failure_point == "temporary-cleanup"
            and published
            and temporary_cleanup_failures < 1
            and os.fsdecode(path).startswith(f".{commit_leaf}.tmp-")
        ):
            injected = True
            temporary_cleanup_failures += 1
            raise OSError(f"injected {failure_point} failure")
        original_unlink(path, dir_fd=dir_fd)

    def fail_selected_read(
        store: Any,
        parent_fd: int,
        name: str,
        relative: Path,
        *,
        max_bytes: int | None = None,
        expected_identity: tuple[int, int] | None = None,
    ) -> bytes:
        nonlocal injected
        if failure_point == "final-reread" and published and not injected and name == commit_leaf:
            injected = True
            raise OSError(f"injected {failure_point} failure")
        return original_read_named(
            store,
            parent_fd,
            name,
            relative,
            max_bytes=max_bytes,
            expected_identity=expected_identity,
        )

    monkeypatch.setattr(os, "link", track_commit_link)
    if "fsync" in failure_point:
        monkeypatch.setattr(os, "fsync", fail_selected_fsync)
    elif failure_point == "temporary-cleanup":
        monkeypatch.setattr(os, "unlink", fail_selected_unlink)
    else:
        monkeypatch.setattr(fs.StateStore, "_read_named", fail_selected_read)

    with pytest.raises(OSError, match=f"injected {failure_point} failure"):
        fs.weekly_plan(root, selection_path, output, "2026-07-11T08:01:00Z")
    assert published and injected

    monkeypatch.setattr(os, "link", original_link)
    monkeypatch.setattr(os, "fsync", original_fsync)
    monkeypatch.setattr(os, "unlink", original_unlink)
    monkeypatch.setattr(fs.StateStore, "_read_named", original_read_named)

    assert (root / intent_relative).exists()
    assert not (root / commit_relative).exists()
    assert not any(
        path.name.startswith(f".{commit_leaf}.tmp-")
        for path in (root / commit_relative.parent).iterdir()
    )
    assert output.exists()

    recovered = fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")
    assert recovered["status"] == "planned"
    assert (root / commit_relative).exists()


def test_commit_wal_does_not_rollback_identical_concurrent_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    selection_path = _write(tmp_path / "concurrent-commit-selection.json", selection)
    output = tmp_path / "concurrent-commit-plan.json"
    _, commit_relative = fs._wal_paths("weekly-plan", selection["selection_id"])
    original_link = os.link
    original_write = fs.StateStore.write_json
    injected = False

    def publish_identical_competing_leaf(
        src: str,
        dst: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal injected
        if not injected and dst == commit_relative.name:
            injected = True
            source_fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=src_dir_fd)
            destination_fd = os.open(
                dst,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=dst_dir_fd,
            )
            try:
                while chunk := os.read(source_fd, 64 * 1024):
                    os.write(destination_fd, chunk)
                os.fsync(destination_fd)
            finally:
                os.close(destination_fd)
                os.close(source_fd)
        original_link(
            src,
            dst,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    def remove_after_concurrent_commit(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        digest = original_write(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )
        if store.root == root and Path(relative) == commit_relative:
            output.unlink()
        return digest

    monkeypatch.setattr(os, "link", publish_identical_competing_leaf)
    monkeypatch.setattr(fs.StateStore, "write_json", remove_after_concurrent_commit)
    with pytest.raises(fs.StateError, match="exactly one link"):
        fs.weekly_plan(root, selection_path, output, "2026-07-11T08:01:00Z")
    assert injected
    assert (root / commit_relative).exists()
    assert not output.exists()

    monkeypatch.setattr(os, "link", original_link)
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)
    recovered = fs.weekly_plan(root, selection_path, output, "2026-07-11T09:01:00Z")
    assert recovered["status"] == "planned"
    assert output.exists() and (root / commit_relative).exists()


def _only_stage_wal_pair(root: Path) -> tuple[Path, Path]:
    directory = root / "wal" / "stage"
    intents = sorted(directory.glob("*.intent.json"))
    commits = sorted(directory.glob("*.commit.json"))
    assert len(intents) == len(commits) == 1
    return intents[0], commits[0]


@pytest.mark.parametrize(
    "layout_class",
    ["orphan-commit", "malformed-name", "directory", "symlink", "fifo", "foreign-entry"],
)
def test_global_wal_recovery_rejects_every_noncanonical_layout_class(
    tmp_path: Path, layout_class: str
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    intent_path, commit_path = _only_stage_wal_pair(root)
    wal_directory = intent_path.parent
    bad_path: Path

    if layout_class == "orphan-commit":
        intent_path.unlink()
        bad_path = commit_path
    elif layout_class == "malformed-name":
        bad_path = wal_directory / f"{'a' * 63}.intent.json"
        bad_path.write_bytes(b"{}\n")
        bad_path.chmod(0o600)
    elif layout_class == "foreign-entry":
        bad_path = wal_directory / "README"
        bad_path.write_bytes(b"foreign\n")
        bad_path.chmod(0o600)
    else:
        intent_path.unlink()
        bad_path = intent_path
        if layout_class == "directory":
            bad_path.mkdir(mode=0o700)
        elif layout_class == "symlink":
            bad_path.symlink_to(commit_path.name)
        else:
            os.mkfifo(bad_path, 0o600)

    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError):
            fs._recover_pending_wal(store)
    assert bad_path.exists() or bad_path.is_symlink()


def test_global_wal_recovery_exactly_validates_commit_binding(tmp_path: Path) -> None:
    root, _ = _stage(tmp_path, _candidate())
    _, commit_path = _only_stage_wal_pair(root)
    commit = fs._load_json(commit_path)
    commit["natural_key"] = "different-transaction"
    body = {key: value for key, value in commit.items() if key != "commit_digest"}
    commit["commit_digest"] = fs._digest(body)
    commit_path.write_bytes(fs._canonical_bytes(commit))

    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="exact intent") as raised:
            fs._recover_pending_wal(store)
    assert raised.value.code == "invalid-wal"


def test_global_wal_layout_preflight_precedes_pending_replay(tmp_path: Path) -> None:
    root, _ = _stage(tmp_path, _candidate())
    second = _candidate(occurrences=[_occurrence(0, root="root:blocked-pending-wal")])
    _stage(tmp_path, second, now="2026-07-10T12:01:00Z")
    wal_directory = root / "wal" / "stage"
    pending_commit = sorted(wal_directory.glob("*.commit.json"))[-1]
    pending_commit.unlink()
    foreign = wal_directory / "foreign-entry"
    foreign.write_bytes(b"foreign\n")
    foreign.chmod(0o600)

    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="unexpected WAL entry"):
            fs._recover_pending_wal(store)

    assert not pending_commit.exists()


def test_global_domain_preflight_precedes_every_pending_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        approved,
        proposed_stage,
        approval_id="mixed-valid-pending-approval",
        persist=False,
    )
    approval_relative = Path("repairs") / "approvals" / f"{approval['approval_id']}.json"
    index_relative = (
        Path("repairs")
        / "approval-index"
        / f"{fs._repair_approval_index_key(approval['source'], approval['target'])}.json"
    )
    original_write = fs.StateStore.write_json

    def interrupt_approval(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        if Path(relative) == approval_relative:
            raise OSError("injected valid pending approval")
        return original_write(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )

    monkeypatch.setattr(fs.StateStore, "write_json", interrupt_approval)
    with pytest.raises(OSError, match="valid pending approval"):
        fs.approve_repair(
            root,
            _write(tmp_path / "mixed-valid-approved.json", approved),
            _write(tmp_path / "mixed-valid-approval.json", approval),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)
    _copy_pending_stage_intent(tmp_path / "invalid-later", root, valid_for_target=False)
    before = _persistent_identity_snapshot(root)

    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="result differs from its receipt") as raised:
            fs._recover_pending_wal(store)

    assert raised.value.code == "invalid-wal"
    assert _persistent_identity_snapshot(root) == before
    assert not (root / approval_relative).exists()
    assert not (root / index_relative).exists()


def test_global_domain_preflight_precedes_committed_external_repair(tmp_path: Path) -> None:
    root, _, _ = _finalize_one(tmp_path, _candidate())
    manifest_output = tmp_path / "manifest.json"
    manifest_output.unlink()
    _copy_pending_stage_intent(tmp_path / "invalid-after-external", root, valid_for_target=False)
    before = _persistent_identity_snapshot(root)

    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="result differs from its receipt") as raised:
            fs._recover_pending_wal(store)

    assert raised.value.code == "invalid-wal"
    assert _persistent_identity_snapshot(root) == before
    assert not manifest_output.exists()


def test_global_state_target_preflight_precedes_partial_pending_stage_replay(
    tmp_path: Path,
) -> None:
    root, _ = _stage(tmp_path / "target", _candidate())
    intent_path, _ = _copy_pending_stage_intent(
        tmp_path / "pending-state-drift",
        root,
        valid_for_target=True,
    )
    intent = fs._load_json(intent_path)
    candidate_write = next(
        write for write in intent["writes"] if isinstance(write["after"].get("case"), dict)
    )
    receipt_write = next(
        write for write in intent["writes"] if write["after"].get("kind") == "stage"
    )
    conflicting_receipt = root / receipt_write["path"]
    conflicting_receipt.write_bytes(fs._canonical_bytes({"foreign": True}))
    conflicting_receipt.chmod(0o600)
    candidate_target = root / candidate_write["path"]
    assert not candidate_target.exists()
    before = _persistent_identity_snapshot(root)

    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="neither its before nor after image") as raised:
            fs._recover_pending_wal(store)

    assert raised.value.code == "wal-target-drift"
    assert _persistent_identity_snapshot(root) == before
    assert not candidate_target.exists()


def test_global_state_target_preflight_blocks_external_repair_and_pending_replay(
    tmp_path: Path,
) -> None:
    root, plan, _ = _finalize_one(tmp_path / "finalized", _candidate())
    prepared = root / "publication" / "prepared" / f"{plan['selection_id']}.json"
    external_manifest = tmp_path / "finalized" / "manifest.json"
    prepared.unlink()
    external_manifest.unlink()
    pending_intent, _ = _copy_pending_stage_intent(
        tmp_path / "pending-after-missing-authority",
        root,
        valid_for_target=True,
    )
    pending = fs._load_json(pending_intent)
    pending_candidate = root / next(
        write["path"] for write in pending["writes"] if isinstance(write["after"].get("case"), dict)
    )
    before = _persistent_identity_snapshot(root)

    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="immutable WAL target") as raised:
            fs._recover_pending_wal(store)

    assert raised.value.code == "wal-target-drift"
    assert _persistent_identity_snapshot(root) == before
    assert not external_manifest.exists()
    assert not pending_candidate.exists()


def test_global_wal_recovery_accepts_retired_history_and_one_pending_pair(
    tmp_path: Path,
) -> None:
    first = _candidate()
    root, _ = _stage(tmp_path, first)
    second = _candidate(occurrences=[_occurrence(0, root="root:mixed-wal")])
    _stage(tmp_path, second, now="2026-07-10T12:01:00Z")
    wal_directory = root / "wal" / "stage"
    commits = sorted(wal_directory.glob("*.commit.json"))
    assert len(commits) == 1
    history = sorted((root / "wal-history" / "stage").glob("*.json"))
    assert len(history) == 1
    pending_commit = commits[0]
    pending_intent = pending_commit.with_name(
        pending_commit.name.replace(".commit.json", ".intent.json")
    )
    pending_commit.unlink()

    with fs._state_lock(root, create=False) as store:
        fs._recover_pending_wal(store)

    assert pending_intent.exists() and pending_commit.exists()
    assert len(list(wal_directory.glob("*.intent.json"))) == 1
    assert len(list(wal_directory.glob("*.commit.json"))) == 1
    assert history[0].exists()


@pytest.mark.parametrize(
    "boundary",
    ["checkpoint-before-usage", "usage-before-commit-unlink", "commit-before-intent-unlink"],
)
def test_wal_compaction_crash_boundaries_converge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    second = _candidate(occurrences=[_occurrence(1, root="root:compaction-retry")])
    original_write = fs.StateStore.write_json
    original_unlink = fs.StateStore.unlink_exact
    injected = False

    def fail_usage(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        nonlocal injected
        if (
            boundary == "checkpoint-before-usage"
            and not injected
            and store.root == root
            and Path(relative) == fs.WAL_HISTORY_USAGE
        ):
            injected = True
            raise OSError("injected usage interruption")
        return original_write(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )

    def fail_cleanup(
        store: Any,
        relative: Path | str,
        expected_digest: str,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        nonlocal injected
        path = Path(relative)
        wanted = (
            boundary == "usage-before-commit-unlink" and path.name.endswith(".commit.json")
        ) or (boundary == "commit-before-intent-unlink" and path.name.endswith(".intent.json"))
        if not injected and store.root == root and wanted:
            injected = True
            raise OSError("injected cleanup interruption")
        original_unlink(
            store,
            relative,
            expected_digest,
            expected_identity=expected_identity,
        )

    monkeypatch.setattr(fs.StateStore, "write_json", fail_usage)
    monkeypatch.setattr(fs.StateStore, "unlink_exact", fail_cleanup)
    with pytest.raises(OSError, match="injected"):
        _stage(tmp_path, second, now="2026-07-10T12:02:00Z")
    assert injected
    assert len(list((root / "wal-history" / "stage").glob("*.json"))) == 1

    monkeypatch.setattr(fs.StateStore, "write_json", original_write)
    monkeypatch.setattr(fs.StateStore, "unlink_exact", original_unlink)
    recovered = _stage(tmp_path, second, now="2026-07-10T12:02:00Z")[1]
    assert recovered["action"] in {"created", "updated"}
    assert fs.audit_wal_history(root)["record_count"] == 1
    assert len(list((root / "wal" / "stage").glob("*.intent.json"))) == 1
    assert len(list((root / "wal" / "stage").glob("*.commit.json"))) == 1


@pytest.mark.parametrize(
    "boundary",
    ["checkpoint-pre-link", "checkpoint-post-link", "usage-pre-link"],
)
def test_wal_history_publication_temporary_crashes_converge_and_audit_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    second = _candidate(occurrences=[_occurrence(1, root="root:history-temp-retry")])
    original_link = fs.os.link
    original_replace = fs.os.replace
    original_unlink = fs.os.unlink
    suffix = f".tmp-{fs.WAL_HISTORY_FIXED_TEMP_PID}-{fs.WAL_HISTORY_FIXED_TEMP_NONCE}"
    injected = False

    def crash_link(source: str, target: str, *args: Any, **kwargs: Any) -> None:
        nonlocal injected
        if (
            boundary == "checkpoint-pre-link"
            and source.endswith(suffix)
            and fs.WAL_HISTORY_LEAF_RE.fullmatch(target) is not None
        ):
            injected = True
            raise OSError("injected checkpoint pre-link crash")
        original_link(source, target, *args, **kwargs)

    def crash_replace(source: str, target: str, *args: Any, **kwargs: Any) -> None:
        nonlocal injected
        if (
            boundary == "usage-pre-link"
            and source == fs._wal_history_fixed_temp_name("usage.json")
            and target == "usage.json"
        ):
            injected = True
            raise OSError("injected usage pre-link crash")
        original_replace(source, target, *args, **kwargs)

    def preserve_crash_temporary(
        path: str,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        nonlocal injected
        usage_name = fs._wal_history_fixed_temp_name("usage.json")
        preserve = (
            boundary.startswith("checkpoint") and path.endswith(suffix) and path != usage_name
        ) or (boundary == "usage-pre-link" and path == usage_name)
        if preserve:
            if boundary == "checkpoint-post-link":
                injected = True
            raise OSError("injected history temporary cleanup crash")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(fs.os, "link", crash_link)
    monkeypatch.setattr(fs.os, "replace", crash_replace)
    monkeypatch.setattr(fs.os, "unlink", preserve_crash_temporary)
    with pytest.raises(OSError, match="injected"):
        _stage(tmp_path, second, now="2026-07-10T12:01:00Z")
    assert injected

    history_directory = root / "wal-history" / "stage"
    checkpoint_temps = (
        list(history_directory.glob(f".*{suffix}")) if history_directory.exists() else []
    )
    usage_temp = root / "wal-history" / fs._wal_history_fixed_temp_name("usage.json")
    if boundary == "checkpoint-pre-link":
        assert len(checkpoint_temps) == 1
        assert checkpoint_temps[0].stat().st_nlink == 1
        assert len(list(history_directory.glob("[0-9a-f]*.json"))) == 0
    elif boundary == "checkpoint-post-link":
        assert len(checkpoint_temps) == 1
        checkpoint = next(history_directory.glob("[0-9a-f]*.json"))
        assert checkpoint_temps[0].stat().st_ino == checkpoint.stat().st_ino
        assert checkpoint.stat().st_nlink == 2
    else:
        assert usage_temp.exists() and usage_temp.stat().st_nlink == 1
        assert len(list(history_directory.glob("[0-9a-f]*.json"))) == 1

    monkeypatch.setattr(fs.os, "link", original_link)
    monkeypatch.setattr(fs.os, "replace", original_replace)
    monkeypatch.setattr(fs.os, "unlink", original_unlink)
    crash_audit = fs.audit_wal_history(root)
    assert crash_audit["status"] == "clean"
    assert crash_audit["record_count"] == (0 if boundary == "checkpoint-pre-link" else 1)
    result = _stage(tmp_path, second, now="2026-07-10T12:01:00Z")[1]
    assert result["action"] == "created"
    assert fs.audit_wal_history(root)["status"] == "clean"
    assert not [path for path in (root / "wal-history").rglob(".*") if ".tmp-" in path.name]


@pytest.mark.parametrize(
    ("name", "code"),
    [
        (".usage.json.tmp-2-0000000000000000", "foreign-helper-temp"),
        (".usage.json.tmp-malformed", "malformed-helper-temp"),
    ],
)
def test_wal_history_audit_rejects_foreign_or_malformed_temporaries(
    tmp_path: Path,
    name: str,
    code: str,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    history = root / "wal-history"
    history.mkdir(mode=0o700, exist_ok=True)
    temporary = history / name
    temporary.write_bytes(b"{}\n")
    temporary.chmod(0o600)

    with pytest.raises(fs.StateError) as raised:
        fs.audit_wal_history(root)
    assert raised.value.code == code
    assert temporary.exists()


def test_wal_history_audit_distinguishes_unreadable_fixed_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    history = root / "wal-history"
    history.mkdir(mode=0o700, exist_ok=True)
    name = fs._wal_history_fixed_temp_name("usage.json")
    temporary = history / name
    temporary.write_bytes(b"{}\n")
    temporary.chmod(0o600)
    original_open = fs.os.open

    def deny_fixed_temp(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == name and dir_fd is not None:
            raise PermissionError(fs.errno.EACCES, "injected unreadable history temp", path)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(fs.os, "open", deny_fixed_temp)
    with pytest.raises(fs.StateError) as raised:
        fs.audit_wal_history(root)
    assert raised.value.code == "helper-temp-unreadable"
    assert temporary.exists()


def test_wal_history_record_limit_precedes_every_history_payload_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    with fs._state_lock(root, create=False) as store:
        for operation in ("stage", "dormancy"):
            with store.open_dir(Path("wal-history") / operation, create=True):
                pass
    for operation, key in (("stage", "1" * 64), ("dormancy", "2" * 64)):
        directory = root / "wal-history" / operation
        leaf = directory / f"{key}.json"
        leaf.write_bytes(b"not json\n")
        leaf.chmod(0o600)
    monkeypatch.setattr(fs, "MAX_WAL_HISTORY_RECORDS", 1)
    original_read = fs.StateStore.read_json_without_publication_recovery_with_identity
    history_reads: list[Path] = []

    def track_history_read(
        store: Any,
        relative: Path | str,
        *,
        max_bytes: int | None = None,
        fixed_helper_name: str | None = None,
    ) -> tuple[dict[str, Any], str, tuple[int, int], int]:
        path = Path(relative)
        if path.parts and path.parts[0] == "wal-history":
            history_reads.append(path)
        return original_read(
            store,
            relative,
            max_bytes=max_bytes,
            fixed_helper_name=fixed_helper_name,
        )

    monkeypatch.setattr(
        fs.StateStore,
        "read_json_without_publication_recovery_with_identity",
        track_history_read,
    )
    with pytest.raises(fs.StateError) as raised:
        fs.audit_wal_history(root)
    assert raised.value.code == "wal-history-count-limit"
    assert history_reads == []


@pytest.mark.parametrize("lookup", ["committed", "conflict"])
def test_retired_exact_lookup_applies_history_limit_before_target_payload_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lookup: str,
) -> None:
    first = _candidate(
        case_id=fs.new_case_id("2026-06-01T12:00:00Z"),
        occurrences=[_occurrence(0, root="root:history-limit-target")],
    )
    second = _candidate(
        case_id=fs.new_case_id("2026-06-02T12:00:00Z"),
        occurrences=[_occurrence(1, root="root:history-limit-other")],
    )
    root, _ = _stage(tmp_path, first)
    _stage(tmp_path, second, now="2026-07-10T12:01:00Z")
    checkpoint_path = next((root / "wal-history" / "stage").glob("[0-9a-f]*.json"))
    checkpoint = fs._load_json(checkpoint_path)
    extra_path = checkpoint_path.with_name(f"{'f' * 64}.json")
    assert extra_path != checkpoint_path
    extra_path.write_bytes(b"not json\n")
    extra_path.chmod(0o600)
    monkeypatch.setattr(fs, "MAX_WAL_HISTORY_RECORDS", 1)

    original_read = fs.StateStore.read_json_without_publication_recovery_with_identity
    history_reads: list[Path] = []

    def track_history_read(
        store: Any,
        relative: Path | str,
        *,
        max_bytes: int | None = None,
        fixed_helper_name: str | None = None,
    ) -> tuple[dict[str, Any], str, tuple[int, int], int]:
        path = Path(relative)
        if path.parts and path.parts[0] == "wal-history":
            history_reads.append(path)
        return original_read(
            store,
            relative,
            max_bytes=max_bytes,
            fixed_helper_name=fixed_helper_name,
        )

    monkeypatch.setattr(
        fs.StateStore,
        "read_json_without_publication_recovery_with_identity",
        track_history_read,
    )
    before = _persistent_identity_snapshot(root)
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError) as raised:
            if lookup == "committed":
                fs._require_committed_transaction(
                    store,
                    "stage",
                    checkpoint["natural_key"],
                )
            else:
                fs._preflight_transaction_binding_read_only(
                    store,
                    operation="stage",
                    natural_key=checkpoint["natural_key"],
                    request={"candidate_file_sha256": "e" * 64},
                )
    assert raised.value.code == "wal-history-count-limit"
    assert history_reads == []
    assert _persistent_identity_snapshot(root) == before


def test_wal_history_temporary_limit_precedes_every_temporary_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    directory = root / "wal-history" / "stage"
    with fs._state_lock(root, create=False) as store:
        with store.open_dir(Path("wal-history") / "stage", create=True):
            pass
    for key in ("1" * 64, "2" * 64):
        leaf = f"{key}.json"
        temporary = directory / fs._wal_history_fixed_temp_name(leaf)
        temporary.write_bytes(b"{}\n")
        temporary.chmod(0o600)
    monkeypatch.setattr(fs, "MAX_WAL_HISTORY_RECORDS", 1)
    original_recover = fs.StateStore.recover_wal_history_temporary
    recoveries: list[Path] = []

    def track_recovery(
        store: Any,
        relative: Path | str,
        *,
        recover: bool = True,
    ) -> None:
        recoveries.append(Path(relative))
        original_recover(store, relative, recover=recover)

    monkeypatch.setattr(fs.StateStore, "recover_wal_history_temporary", track_recovery)
    with pytest.raises(fs.StateError) as raised:
        fs.audit_wal_history(root)
    assert raised.value.code == "wal-history-count-limit"
    assert recoveries == []


def test_old_checkpoint_requires_bounded_chain_membership_before_lookup_or_audit(
    tmp_path: Path,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    _stage(
        tmp_path,
        _candidate(occurrences=[_occurrence(1, root="root:membership-source")]),
        now="2026-07-10T12:01:00Z",
    )
    directory = root / "wal-history" / "stage"
    source = fs._load_json(next(directory.glob("[0-9a-f]*.json")))
    forged_key = "schema-valid-orphan-checkpoint"
    forged = dict(source)
    forged["natural_key"] = forged_key
    forged["request_digest"] = "e" * 64
    body = {key: value for key, value in forged.items() if key != "checkpoint_digest"}
    forged["checkpoint_digest"] = fs._digest(body)
    forged_path = root / fs._wal_history_path("stage", forged_key)
    forged_path.write_bytes(fs._canonical_bytes(forged))
    forged_path.chmod(0o600)

    before_lookup = _persistent_identity_snapshot(root)
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError) as lookup:
            fs._require_committed_transaction(store, "stage", forged_key)
    assert lookup.value.code == "invalid-wal-history-usage"
    assert _persistent_identity_snapshot(root) == before_lookup

    usage = root / fs.WAL_HISTORY_USAGE
    usage_temporary = usage.parent / fs._wal_history_fixed_temp_name(usage.name)
    usage_temporary.write_bytes(usage.read_bytes())
    usage_temporary.chmod(0o600)
    before_audit = _persistent_identity_snapshot(root)
    with pytest.raises(fs.StateError) as audit:
        fs.audit_wal_history(root)
    assert audit.value.code == "invalid-wal-history-usage"
    assert _persistent_identity_snapshot(root) == before_audit
    assert usage_temporary.exists()


def test_retired_lookup_revalidates_every_non_target_checkpoint_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    for index in (1, 2):
        _stage(
            tmp_path,
            _candidate(occurrences=[_occurrence(index, root=f"root:stable-chain-{index}")]),
            now=f"2026-07-10T12:0{index}:00Z",
        )
    checkpoints = sorted((root / "wal-history" / "stage").glob("[0-9a-f]*.json"))
    assert len(checkpoints) == 2
    target = fs._load_json(checkpoints[0])
    victim = checkpoints[1]
    replacement = tmp_path / "replacement-checkpoint.json"
    replacement.write_bytes(victim.read_bytes())
    replacement.chmod(0o600)
    original_usage_read = fs._read_wal_history_usage_binding_read_only
    injected = False

    def replace_non_target(store: Any) -> tuple[dict[str, Any], str | None, Any, int]:
        nonlocal injected
        value = original_usage_read(store)
        if not injected:
            injected = True
            os.replace(replacement, victim)
        return value

    monkeypatch.setattr(fs, "_read_wal_history_usage_binding_read_only", replace_non_target)
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError) as raised:
            fs._require_committed_transaction(store, "stage", target["natural_key"])
    assert injected
    assert raised.value.code == "wal-history-changed"


def test_audit_phase_one_preserves_authority_helper_when_external_is_not_repairable(
    tmp_path: Path,
) -> None:
    root, _, _ = _finalize_one(tmp_path, _candidate())
    checkpoint_path = next((root / "wal-history" / "weekly-plan").glob("*.json"))
    checkpoint = fs._load_json(checkpoint_path)
    authority_path = next(
        root / authority["path"]
        for authority in checkpoint["authorities"]
        if Path(authority["path"]).parts[:2] == ("publication", "plans")
    )
    authority_helper = authority_path.parent / (f".{authority_path.name}.tmp-1-{'1' * 16}")
    os.link(authority_path, authority_helper)
    external_plan = tmp_path / "plan.json"
    external_plan.unlink()
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError) as raised:
        fs.audit_wal_history(root)
    assert raised.value.code == "wal-history-external-drift"
    assert _persistent_identity_snapshot(root) == before
    assert authority_helper.exists() and authority_helper.stat().st_nlink == 2
    assert not external_plan.exists()


@pytest.mark.parametrize("remove_commit", [False, True])
def test_audit_repairs_external_only_from_checkpoint_before_usage_full_wal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    remove_commit: bool,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    plan_path = tmp_path / "plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "selection.json", selection),
        plan_path,
        "2026-07-11T08:01:00Z",
    )
    expected_plan = plan_path.read_bytes()
    plan = fs._load_json(plan_path)
    prepared_path = _write(tmp_path / "prepared.json", _prepared_receipt(plan))
    original_write = fs.StateStore.write_json
    injected = False

    def fail_usage(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        nonlocal injected
        if not injected and store.root == root and Path(relative) == fs.WAL_HISTORY_USAGE:
            injected = True
            raise OSError("injected checkpoint-before-usage crash")
        return original_write(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )

    monkeypatch.setattr(fs.StateStore, "write_json", fail_usage)
    with pytest.raises(OSError, match="checkpoint-before-usage"):
        fs.finalize_publication(
            root,
            plan_path,
            prepared_path,
            tmp_path / "manifest.json",
            "2026-07-11T08:32:00Z",
        )
    assert injected
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)
    weekly_checkpoint = next((root / "wal-history" / "weekly-plan").glob("*.json"))
    weekly = fs._load_json(weekly_checkpoint)
    intent_path, commit_path = fs._wal_paths("weekly-plan", weekly["natural_key"])
    assert (root / intent_path).exists() and (root / commit_path).exists()
    if remove_commit:
        (root / commit_path).unlink()
    plan_path.unlink()

    if remove_commit:
        before = _persistent_identity_snapshot(root)
        with fs._state_lock(root, create=False) as store:
            with pytest.raises(fs.StateError) as ordinary_recovery:
                fs._recover_pending_wal(store, compact_committed=False)
        assert ordinary_recovery.value.code == "invalid-wal-history-usage"
        assert _persistent_identity_snapshot(root) == before
        assert not plan_path.exists()
        with pytest.raises(fs.StateError) as raised:
            fs.audit_wal_history(root)
        assert raised.value.code == "invalid-wal-history-usage"
        assert _persistent_identity_snapshot(root) == before
        assert not plan_path.exists()
        return
    result = fs.audit_wal_history(root)
    assert result["status"] == "clean"
    assert plan_path.read_bytes() == expected_plan
    assert not (root / intent_path).exists()
    assert not (root / commit_path).exists()


def test_fixed_publication_collision_never_unlinks_unowned_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    fixed_name = fs._wal_history_fixed_temp_name("usage.json")
    foreign_payload = b"foreign fixed temporary\n"
    original_open = fs.os.open
    inserted_identity: tuple[int, int] | None = None

    def collide(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal inserted_identity
        if path == fixed_name and flags & fs.os.O_EXCL and inserted_identity is None:
            foreign_fd = original_open(
                path,
                fs.os.O_WRONLY | fs.os.O_CREAT | fs.os.O_EXCL | fs.os.O_CLOEXEC,
                0o600,
                dir_fd=dir_fd,
            )
            try:
                fs.os.write(foreign_fd, foreign_payload)
                fs.os.fsync(foreign_fd)
                info = fs.os.fstat(foreign_fd)
                inserted_identity = (info.st_dev, info.st_ino)
            finally:
                fs.os.close(foreign_fd)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(fs.os, "open", collide)
    with fs._state_lock(root, create=False) as store:
        store._fixed_publication_temporary = (fs.WAL_HISTORY_USAGE, fixed_name)
        try:
            with pytest.raises(FileExistsError):
                store.write_json(fs.WAL_HISTORY_USAGE, fs._new_wal_history_usage())
        finally:
            store._fixed_publication_temporary = None
    temporary = root / "wal-history" / fixed_name
    assert inserted_identity is not None
    assert (temporary.stat().st_dev, temporary.stat().st_ino) == inserted_identity
    assert temporary.read_bytes() == foreign_payload


@pytest.mark.parametrize(
    "boundary",
    ["checkpoint-before-usage", "usage-before-commit-unlink", "commit-before-intent-unlink"],
)
def test_mixed_legacy_backlog_retires_existing_checkpoint_before_new_sequence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    original_recover = fs._recover_pending_wal

    def preserve_legacy_backlog(
        store: Any,
        *,
        compact_committed: bool = False,
        retain_transaction: tuple[str, str] | None = None,
    ) -> None:
        del compact_committed
        original_recover(
            store,
            compact_committed=False,
            retain_transaction=retain_transaction,
        )

    monkeypatch.setattr(fs, "_recover_pending_wal", preserve_legacy_backlog)
    earlier = _candidate(
        case_id=fs.new_case_id("2026-06-01T12:00:00Z"),
        occurrences=[_occurrence(0, root="root:legacy-backlog-earlier")],
    )
    later = _candidate(
        case_id=fs.new_case_id("2026-06-02T12:00:00Z"),
        occurrences=[_occurrence(1, root="root:legacy-backlog-later")],
    )
    root, _ = _stage(tmp_path, earlier)
    _stage(tmp_path, later, now="2026-07-10T12:01:00Z")
    monkeypatch.setattr(fs, "_recover_pending_wal", original_recover)

    intents = [
        fs._load_json(path) for path in sorted((root / "wal" / "stage").glob("*.intent.json"))
    ]
    keys_by_case = {intent["result"]["case_id"]: intent["natural_key"] for intent in intents}
    retained_key = keys_by_case[earlier["case"]["id"]]
    interrupted_key = keys_by_case[later["case"]["id"]]
    assert retained_key < interrupted_key

    original_write = fs.StateStore.write_json
    original_unlink = fs.StateStore.unlink_exact
    injected = False

    def fail_usage(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        nonlocal injected
        if (
            boundary == "checkpoint-before-usage"
            and not injected
            and store.root == root
            and Path(relative) == fs.WAL_HISTORY_USAGE
        ):
            injected = True
            raise OSError("injected mixed-backlog usage interruption")
        return original_write(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )

    def fail_cleanup(
        store: Any,
        relative: Path | str,
        expected_digest: str,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        nonlocal injected
        path = Path(relative)
        wanted = (
            boundary == "usage-before-commit-unlink" and path.name.endswith(".commit.json")
        ) or (boundary == "commit-before-intent-unlink" and path.name.endswith(".intent.json"))
        if not injected and store.root == root and wanted:
            injected = True
            raise OSError("injected mixed-backlog cleanup interruption")
        original_unlink(
            store,
            relative,
            expected_digest,
            expected_identity=expected_identity,
        )

    monkeypatch.setattr(fs.StateStore, "write_json", fail_usage)
    monkeypatch.setattr(fs.StateStore, "unlink_exact", fail_cleanup)
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(OSError, match="injected mixed-backlog"):
            fs._recover_pending_wal(
                store,
                compact_committed=True,
                retain_transaction=("stage", retained_key),
            )
    assert injected
    interrupted_history = root / fs._wal_history_path("stage", interrupted_key)
    retained_history = root / fs._wal_history_path("stage", retained_key)
    assert interrupted_history.exists()
    assert not retained_history.exists()

    monkeypatch.setattr(fs.StateStore, "write_json", original_write)
    monkeypatch.setattr(fs.StateStore, "unlink_exact", original_unlink)
    next_candidate = _candidate(
        case_id=fs.new_case_id("2026-06-03T12:00:00Z"),
        occurrences=[_occurrence(2, root="root:mixed-backlog-next")],
    )
    _, next_receipt = _stage(tmp_path, next_candidate, now="2026-07-10T12:02:00Z")
    next_intent_payload = next(
        fs._load_json(path)
        for path in (root / "wal" / "stage").glob("*.intent.json")
        if fs._load_json(path)["result"].get("receipt_id") == next_receipt["receipt_id"]
    )
    next_key = next_intent_payload["natural_key"]

    history = {
        checkpoint["natural_key"]: checkpoint
        for checkpoint in (
            fs._load_json(path) for path in (root / "wal-history" / "stage").glob("*.json")
        )
    }
    assert history[interrupted_key]["sequence"] == 1
    assert history[retained_key]["sequence"] == 2
    assert fs.audit_wal_history(root)["record_count"] == 2
    next_intent, next_commit = fs._wal_paths("stage", next_key)
    assert (root / next_intent).exists() and (root / next_commit).exists()


def test_wal_request_conflict_does_not_compact_another_committed_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_recover = fs._recover_pending_wal

    def preserve_committed_pairs(
        store: Any,
        *,
        compact_committed: bool = False,
        retain_transaction: tuple[str, str] | None = None,
    ) -> None:
        del compact_committed
        original_recover(
            store,
            compact_committed=False,
            retain_transaction=retain_transaction,
        )

    monkeypatch.setattr(fs, "_recover_pending_wal", preserve_committed_pairs)
    first = _candidate(
        case_id=fs.new_case_id("2026-06-01T12:00:00Z"),
        occurrences=[_occurrence(0, root="root:conflict-other-pair")],
    )
    current = _candidate(
        case_id=fs.new_case_id("2026-06-02T12:00:00Z"),
        occurrences=[_occurrence(1, root="root:conflict-current-pair")],
    )
    root, _ = _stage(tmp_path, first)
    _stage(tmp_path, current, now="2026-07-10T12:01:00Z")
    monkeypatch.setattr(fs, "_recover_pending_wal", original_recover)

    intents = [
        fs._load_json(path) for path in sorted((root / "wal" / "stage").glob("*.intent.json"))
    ]
    current_intent = next(
        intent for intent in intents if intent["result"]["case_id"] == current["case"]["id"]
    )
    current_key = current_intent["natural_key"]
    current_intent_path, _ = fs._wal_paths("stage", current_key)
    active_final = root / current_intent_path
    active_temporary = active_final.parent / (f".{active_final.name}.tmp-1-{'0' * 16}")
    fs.os.link(active_final, active_temporary)

    before = _persistent_identity_snapshot(root)
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError) as raised:
            fs._run_transaction(
                store,
                operation="stage",
                natural_key=current_key,
                request={"candidate_file_sha256": "f" * 64, "anchor": "conflict"},
                captured_at="2026-07-10T12:02:00Z",
                writes=[],
                result={},
            )
    assert raised.value.code == "wal-request-conflict"
    assert _persistent_identity_snapshot(root) == before
    assert len(list((root / "wal" / "stage").glob("*.intent.json"))) == 2
    assert len(list((root / "wal" / "stage").glob("*.commit.json"))) == 2
    assert not (root / "wal-history").exists()


def test_retired_wal_request_conflict_preserves_history_publication_temporaries(
    tmp_path: Path,
) -> None:
    first = _candidate(
        case_id=fs.new_case_id("2026-06-01T12:00:00Z"),
        occurrences=[_occurrence(0, root="root:retired-conflict")],
    )
    second = _candidate(
        case_id=fs.new_case_id("2026-06-02T12:00:00Z"),
        occurrences=[_occurrence(1, root="root:retired-conflict-other")],
    )
    root, _ = _stage(tmp_path, first)
    _stage(tmp_path, second, now="2026-07-10T12:01:00Z")

    checkpoint_path = next((root / "wal-history" / "stage").glob("[0-9a-f]*.json"))
    checkpoint = fs._load_json(checkpoint_path)
    checkpoint_temporary = checkpoint_path.parent / fs._wal_history_fixed_temp_name(
        checkpoint_path.name
    )
    fs.os.link(checkpoint_path, checkpoint_temporary)
    usage = root / fs.WAL_HISTORY_USAGE
    usage_temporary = usage.parent / fs._wal_history_fixed_temp_name(usage.name)
    usage_temporary.write_bytes(usage.read_bytes())
    usage_temporary.chmod(0o600)

    before = _persistent_identity_snapshot(root)
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError) as raised:
            fs._run_transaction(
                store,
                operation="stage",
                natural_key=checkpoint["natural_key"],
                request={"candidate_file_sha256": "e" * 64, "anchor": "retired-conflict"},
                captured_at="2026-07-10T12:02:00Z",
                writes=[],
                result={},
            )
    assert raised.value.code == "wal-request-conflict"
    assert _persistent_identity_snapshot(root) == before
    assert checkpoint_temporary.exists() and checkpoint_temporary.stat().st_nlink == 2
    assert usage_temporary.exists() and usage_temporary.stat().st_nlink == 1
    assert len(list((root / "wal" / "stage").glob("*.intent.json"))) == 1
    assert len(list((root / "wal" / "stage").glob("*.commit.json"))) == 1


def test_wal_compaction_keeps_ordinary_history_reads_constant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root: Path | None = None
    for index in range(12):
        candidate = _candidate(occurrences=[_occurrence(index, root=f"root:history-{index}")])
        root, _ = _stage(
            tmp_path,
            candidate,
            now=f"2026-07-10T12:{index:02d}:00Z",
        )
    assert root is not None
    usage = fs._load_json(root / fs.WAL_HISTORY_USAGE)
    assert usage["record_count"] == 11
    history_paths = sorted((root / "wal-history" / "stage").glob("*.json"))
    assert len(history_paths) == 11
    active_intent = next((root / "wal" / "stage").glob("*.intent.json"))
    checkpoint = fs._load_json(history_paths[0])

    def nested_keys(value: Any) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {key for child in value.values() for key in nested_keys(child)}
        if isinstance(value, list):
            return {key for child in value for key in nested_keys(child)}
        return set()

    assert "after" not in nested_keys(checkpoint)
    assert history_paths[0].stat().st_size < active_intent.stat().st_size

    history_reads: list[str] = []
    history_lists: list[str] = []
    original_read = fs.StateStore.read_bytes_with_identity
    original_list = fs.StateStore.list_names

    def count_read(
        store: Any, relative: Path | str, *, max_bytes: int | None = None
    ) -> tuple[bytes, str, tuple[int, int]]:
        path = Path(relative)
        if path.parts and path.parts[0] == "wal-history":
            history_reads.append(path.as_posix())
        return original_read(store, relative, max_bytes=max_bytes)

    def count_list(store: Any, relative: Path | str) -> list[str]:
        path = Path(relative)
        if path.parts and path.parts[0] == "wal-history":
            history_lists.append(path.as_posix())
        return original_list(store, relative)

    monkeypatch.setattr(fs.StateStore, "read_bytes_with_identity", count_read)
    monkeypatch.setattr(fs.StateStore, "list_names", count_list)
    candidate = _candidate(occurrences=[_occurrence(12, root="root:history-12")])
    _stage(tmp_path, candidate, now="2026-07-10T12:12:00Z")

    record_reads = [path for path in history_reads if path != fs.WAL_HISTORY_USAGE.as_posix()]
    assert len(set(record_reads)) == 1
    assert history_lists == []


def test_explicit_wal_history_audit_detects_foreign_and_orphan_leaves(
    tmp_path: Path,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    _stage(
        tmp_path,
        _candidate(occurrences=[_occurrence(1, root="root:history-audit")]),
        now="2026-07-10T12:01:00Z",
    )
    assert fs.audit_wal_history(root)["status"] == "clean"
    directory = root / "wal-history" / "stage"
    foreign = directory / "README"
    foreign.write_bytes(b"foreign\n")
    foreign.chmod(0o600)
    with pytest.raises(fs.StateError, match="unexpected history leaf"):
        fs.audit_wal_history(root)
    foreign.unlink()

    orphan = directory / f"{'f' * 64}.json"
    orphan.write_bytes(b"{}\n")
    orphan.chmod(0o600)
    with pytest.raises(fs.StateError):
        fs.audit_wal_history(root)


@pytest.mark.parametrize(
    ("constant", "value", "code"),
    [
        ("MAX_WAL_HISTORY_RECORDS", 0, "wal-history-count-limit"),
        ("MAX_WAL_HISTORY_BYTES", 1, "wal-history-byte-limit"),
    ],
)
def test_wal_checkpoint_capacity_blocks_before_intent_or_after_images(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    code: str,
) -> None:
    monkeypatch.setattr(fs, constant, value)
    root = tmp_path / "state"
    with pytest.raises(fs.StateError) as raised:
        _stage(tmp_path, _candidate())
    assert raised.value.code == code
    assert not (root / "wal").exists()
    assert not (root / "cases").exists()
    assert not (root / "receipts").exists()


@pytest.mark.parametrize(
    ("constant", "value", "code"),
    [
        ("MAX_ACTIVE_WAL_TRANSACTIONS", 0, "active-wal-count-limit"),
        ("MAX_ACTIVE_WAL_BYTES", 1, "active-wal-byte-limit"),
    ],
)
def test_active_wal_bounds_fail_before_parsing_or_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    code: str,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    monkeypatch.setattr(fs, constant, value)
    with fs._state_lock(root, create=False) as store:
        original_read = fs._read_fd_stable
        reads: list[str] = []
        recoveries: list[Path] = []

        def track_read(fd: int, path: str, **kwargs: Any) -> tuple[bytes, str]:
            reads.append(path)
            return original_read(fd, path, **kwargs)

        def track_recovery(
            active_store: Any,
            relative: Path | str,
            *,
            names: Any = None,
        ) -> None:
            recoveries.append(Path(relative))

        monkeypatch.setattr(fs, "_read_fd_stable", track_read)
        monkeypatch.setattr(fs.StateStore, "recover_wal_temporaries", track_recovery)
        with pytest.raises(fs.StateError) as raised:
            fs._recover_pending_wal(store)
    assert raised.value.code == code
    assert reads == []
    assert recoveries == []


def test_active_wal_temporary_entry_limit_precedes_payload_read_and_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = _stage(tmp_path, _candidate())
    wal_directory = root / "wal" / "stage"
    intent = next(wal_directory.glob("*.intent.json"))
    for index in range(3):
        temporary = wal_directory / f".{intent.name}.tmp-1-{index + 1:016x}"
        temporary.write_bytes(intent.read_bytes())
        temporary.chmod(0o600)
    monkeypatch.setattr(fs, "MAX_ACTIVE_WAL_TRANSACTIONS", 1)

    before = _persistent_identity_snapshot(root)
    with fs._state_lock(root, create=False) as store:
        original_read = fs._read_fd_stable
        reads: list[str] = []
        recoveries: list[Path] = []

        def track_read(fd: int, path: str, **kwargs: Any) -> tuple[bytes, str]:
            reads.append(path)
            return original_read(fd, path, **kwargs)

        def track_recovery(
            active_store: Any,
            relative: Path | str,
            *,
            names: Any = None,
        ) -> None:
            recoveries.append(Path(relative))

        monkeypatch.setattr(fs, "_read_fd_stable", track_read)
        monkeypatch.setattr(fs.StateStore, "recover_wal_temporaries", track_recovery)
        with pytest.raises(fs.StateError) as raised:
            fs._recover_pending_wal(store)
    assert raised.value.code == "active-wal-count-limit"
    assert reads == []
    assert recoveries == []
    assert _persistent_identity_snapshot(root) == before


def _rewrite_external_wal_as_legacy(
    root: Path, operation: str, natural_key: str
) -> tuple[Path, Path]:
    intent_relative, commit_relative = fs._wal_paths(operation, natural_key)
    intent_path = root / intent_relative
    commit_path = root / commit_relative
    intent = fs._load_json(intent_path)
    for write in intent["writes"]:
        if write["scope"] == "external":
            write.pop("parent_binding")
    intent_body = {key: value for key, value in intent.items() if key != "intent_digest"}
    intent["intent_digest"] = fs._digest(intent_body)
    intent_path.write_bytes(fs._canonical_bytes(intent))
    commit = fs._load_json(commit_path)
    commit["intent_digest"] = intent["intent_digest"]
    commit_body = {key: value for key, value in commit.items() if key != "commit_digest"}
    commit["commit_digest"] = fs._digest(commit_body)
    commit_path.write_bytes(fs._canonical_bytes(commit))
    return intent_path, commit_path


def _rewrite_external_wal_target(
    root: Path,
    operation: str,
    natural_key: str,
    target: Path,
    *,
    committed: bool,
    legacy: bool,
) -> tuple[Path, Path]:
    intent_relative, commit_relative = fs._wal_paths(operation, natural_key)
    intent_path = root / intent_relative
    commit_path = root / commit_relative
    intent = fs._load_json(intent_path)
    external_writes = [write for write in intent["writes"] if write["scope"] == "external"]
    assert len(external_writes) == 1
    write = external_writes[0]
    absolute_target = Path(os.path.abspath(os.fspath(target)))
    write["path"] = str(absolute_target)
    write["before_sha256"] = None
    if legacy:
        write.pop("parent_binding")
    else:
        parent = fs.StateStore(absolute_target.parent, create=False)
        try:
            write["parent_binding"] = fs._external_parent_binding(parent)
        finally:
            parent.close()
    intent_body = {key: value for key, value in intent.items() if key != "intent_digest"}
    intent["intent_digest"] = fs._digest(intent_body)
    intent_path.write_bytes(fs._canonical_bytes(intent))
    if not committed:
        commit_path.unlink()
        return intent_path, commit_path
    commit = fs._load_json(commit_path)
    commit["intent_digest"] = intent["intent_digest"]
    commit_body = {key: value for key, value in commit.items() if key != "commit_digest"}
    commit["commit_digest"] = fs._digest(commit_body)
    commit_path.write_bytes(fs._canonical_bytes(commit))
    return intent_path, commit_path


@pytest.mark.parametrize(
    ("committed", "legacy"),
    [(False, False), (False, True), (True, False), (True, True)],
    ids=["pending-bound", "pending-legacy", "committed-bound", "committed-legacy"],
)
def test_global_wal_recovery_rejects_external_targets_inside_managed_state(
    tmp_path: Path,
    committed: bool,
    legacy: bool,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    fs.weekly_plan(
        root,
        _write(tmp_path / "crafted-wal-selection.json", selection),
        tmp_path / "original-external-plan.json",
        "2026-07-11T08:01:00Z",
    )
    target = root / "publication" / f"poison-{committed}-{legacy}.json"
    _rewrite_external_wal_target(
        root,
        "weekly-plan",
        selection["selection_id"],
        target,
        committed=committed,
        legacy=legacy,
    )
    before = _tree_bytes(root)

    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="outside the managed state root") as raised:
            fs._recover_pending_wal(store)

    assert raised.value.code == "output-inside-state-root"
    assert _tree_bytes(root) == before
    assert not target.exists()


def test_committed_legacy_external_wal_is_read_only_validated(
    tmp_path: Path,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    output = tmp_path / "legacy-committed-plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "legacy-committed-selection.json", selection),
        output,
        "2026-07-11T08:01:00Z",
    )
    _rewrite_external_wal_as_legacy(root, "weekly-plan", selection["selection_id"])

    with fs._state_lock(root, create=False) as store:
        fs._recover_pending_wal(store)
    assert output.exists()

    output.unlink()
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="automatic replay is unsafe") as raised:
            fs._recover_pending_wal(store)
    assert raised.value.code == "legacy-external-wal-unbound"
    assert not output.exists()


def test_pending_legacy_external_wal_fails_closed_without_rebinding(
    tmp_path: Path,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    output = tmp_path / "legacy-pending-plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "legacy-pending-selection.json", selection),
        output,
        "2026-07-11T08:01:00Z",
    )
    _, commit_path = _rewrite_external_wal_as_legacy(root, "weekly-plan", selection["selection_id"])
    commit_path.unlink()

    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="no recoverable parent identity") as raised:
            fs._recover_pending_wal(store)
    assert raised.value.code == "legacy-external-wal-unbound"
    assert output.exists()


def test_interrupted_external_retirement_repairs_before_compaction_then_fails_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    output = tmp_path / "retirement-repair-plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "retirement-repair-selection.json", selection),
        output,
        "2026-07-11T08:01:00Z",
    )
    intent_relative, commit_relative = fs._wal_paths("weekly-plan", selection["selection_id"])
    original_write = fs.StateStore.write_json
    injected = False

    def fail_usage(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        nonlocal injected
        if not injected and store.root == root and Path(relative) == fs.WAL_HISTORY_USAGE:
            injected = True
            raise OSError("injected external retirement interruption")
        return original_write(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )

    monkeypatch.setattr(fs.StateStore, "write_json", fail_usage)
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(OSError, match="external retirement interruption"):
            fs._recover_pending_wal(store, compact_committed=True)
    assert (root / intent_relative).exists() and (root / commit_relative).exists()
    assert (root / fs._wal_history_path("weekly-plan", selection["selection_id"])).exists()

    monkeypatch.setattr(fs.StateStore, "write_json", original_write)
    output.unlink()
    with fs._state_lock(root, create=False) as store:
        fs._recover_pending_wal(store)
    assert output.exists()
    assert not (root / intent_relative).exists()
    assert not (root / commit_relative).exists()

    output.unlink()
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError) as raised:
            fs._require_committed_transaction(store, "weekly-plan", selection["selection_id"])
    assert raised.value.code == "wal-history-external-drift"
    assert not output.exists()


def test_external_retirement_revalidates_content_after_fsync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    output = tmp_path / "post-sync-race-plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "post-sync-race-selection.json", selection),
        output,
        "2026-07-11T08:01:00Z",
    )
    expected_output = output.read_bytes()
    output_identity = (output.stat().st_dev, output.stat().st_ino)
    intent_relative, commit_relative = fs._wal_paths("weekly-plan", selection["selection_id"])
    history_relative = fs._wal_history_path("weekly-plan", selection["selection_id"])
    original_fsync = fs.os.fsync
    injected = False

    def mutate_after_file_fsync(fd: int) -> None:
        nonlocal injected
        original_fsync(fd)
        info = fs.os.fstat(fd)
        if not injected and (info.st_dev, info.st_ino) == output_identity:
            injected = True
            output.write_bytes(b'{"tampered":true}\n')

    monkeypatch.setattr(fs.os, "fsync", mutate_after_file_fsync)
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError) as raised:
            fs._recover_pending_wal(store, compact_committed=True)
    assert injected
    assert raised.value.code == "object-changed-after-sync"
    assert (root / intent_relative).exists()
    assert (root / commit_relative).exists()
    assert not (root / history_relative).exists()

    monkeypatch.setattr(fs.os, "fsync", original_fsync)
    output.write_bytes(expected_output)
    with fs._state_lock(root, create=False) as store:
        fs._recover_pending_wal(store, compact_committed=True)
    assert output.read_bytes() == expected_output
    assert (root / history_relative).exists()
    assert not (root / intent_relative).exists()
    assert not (root / commit_relative).exists()


def test_committed_legacy_external_wal_compacts_read_only_and_stays_fail_closed(
    tmp_path: Path,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    output = tmp_path / "legacy-compact-plan.json"
    fs.weekly_plan(
        root,
        _write(tmp_path / "legacy-compact-selection.json", selection),
        output,
        "2026-07-11T08:01:00Z",
    )
    intent_path, commit_path = _rewrite_external_wal_as_legacy(
        root, "weekly-plan", selection["selection_id"]
    )

    with fs._state_lock(root, create=False) as store:
        fs._recover_pending_wal(store, compact_committed=True)
    assert not intent_path.exists() and not commit_path.exists()
    history_path = root / fs._wal_history_path("weekly-plan", selection["selection_id"])
    assert fs._load_json(history_path)["after_images"][-1]["legacy_external"] is True
    assert fs.audit_wal_history(root)["status"] == "clean"

    output.unlink()
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError) as raised:
            fs._require_committed_transaction(store, "weekly-plan", selection["selection_id"])
    assert raised.value.code == "legacy-external-wal-unbound"


def test_retired_checkpoint_preserves_exact_result_and_first_writer_wins(
    tmp_path: Path,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], [case])
    selection_path = _write(tmp_path / "retired-selection.json", selection)
    output = tmp_path / "retired-plan.json"
    first = fs.weekly_plan(root, selection_path, output, "2026-07-11T08:01:00Z")

    _stage(
        tmp_path,
        _candidate(occurrences=[_occurrence(2, root="root:retire-weekly")]),
        now="2026-07-11T08:02:00Z",
    )
    assert (root / fs._wal_history_path("weekly-plan", selection["selection_id"])).exists()
    assert (
        fs.weekly_plan(
            root,
            selection_path,
            output,
            "2026-07-11T08:03:00Z",
        )
        == first
    )

    conflicting_output = tmp_path / "retired-plan-conflict.json"
    with pytest.raises(fs.StateError) as raised:
        fs.weekly_plan(
            root,
            selection_path,
            conflicting_output,
            "2026-07-11T08:04:00Z",
        )
    assert raised.value.code == "wal-request-conflict"
    assert not conflicting_output.exists()


def test_selection_preflight_binds_exact_draft_and_current_case_bytes(tmp_path: Path) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _selection(completed["snapshot_digest"], [case])
    draft = {key: selection[key] for key in fs.SELECTION_BASIS_FIELDS}

    result = fs.preflight_selection(
        root,
        _write(tmp_path / "selection-draft.json", draft),
        "2026-07-11T08:00:01Z",
    )

    assert result["status"] == "ready"
    assert result["resource_preflight"] == selection["resource_preflight"]
    assert result["selection_basis_digest"] == fs._digest(draft)
    assert (
        fs._load_json(root / "publication" / "preflights" / f"{selection['selection_id']}.json")
        == result
    )
    intent_relative, commit_relative = fs._wal_paths(
        "selection-preflight", selection["selection_id"]
    )
    assert (root / intent_relative).exists() and (root / commit_relative).exists()
    assert (
        fs.preflight_selection(
            root,
            tmp_path / "selection-draft.json",
            "2026-07-11T09:00:01Z",
        )
        == result
    )


def test_selection_preflight_exact_retry_survives_weekly_plan_and_preserves_first_writer(
    tmp_path: Path,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _selection(completed["snapshot_digest"], [case])
    basis = {key: selection[key] for key in fs.SELECTION_BASIS_FIELDS}
    draft_path = _write(tmp_path / "planned-preflight-draft.json", basis)
    receipt = fs.preflight_selection(root, draft_path, "2026-07-11T07:59:00Z")
    selection["resource_preflight"] = receipt["resource_preflight"]
    selection["preflight_receipt_id"] = receipt["receipt_id"]
    selection["preflight_receipt_digest"] = receipt["receipt_digest"]
    selection["interaction"] = {
        "interactive": True,
        "actor": "Joey",
        "approved_at": "2026-07-11T08:00:00Z",
        "selection_basis_digest": receipt["selection_basis_digest"],
        "preflight_receipt_id": receipt["receipt_id"],
        "preflight_receipt_digest": receipt["receipt_digest"],
    }
    fs.weekly_plan(
        root,
        _write(tmp_path / "planned-preflight-selection.json", selection),
        tmp_path / "planned-preflight-plan.json",
        "2026-07-11T08:01:00Z",
    )
    assert (root / "publication" / "active" / f"{case['case']['id']}.json").exists()
    assert (root / fs._wal_history_path("selection-preflight", selection["selection_id"])).exists()

    assert fs.preflight_selection(root, draft_path, "2026-07-11T08:02:00Z") == receipt

    conflicting_basis = json.loads(json.dumps(basis))
    conflicting_basis["base_intent"]["base_sha"] = "b" * 40
    conflict_path = _write(tmp_path / "planned-preflight-conflict.json", conflicting_basis)
    before = _persistent_identity_snapshot(root)
    with pytest.raises(fs.StateError, match="different request") as raised:
        fs.preflight_selection(root, conflict_path, "2026-07-11T08:03:00Z")
    assert raised.value.code == "wal-request-conflict"
    assert _persistent_identity_snapshot(root) == before


@pytest.mark.parametrize(
    ("checked_at", "approved_at"),
    [
        ("2026-07-11T08:00:00Z", "2026-07-11T08:00:00Z"),
        ("2026-07-10T12:31:00Z", "2026-07-10T12:31:00Z"),
    ],
)
def test_selection_approval_must_be_strictly_later_than_preflight_and_snapshot(
    tmp_path: Path,
    checked_at: str,
    approved_at: str,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _approved_selection(
        tmp_path,
        root,
        completed["snapshot_digest"],
        [case],
        checked_at=checked_at,
        approved_at=approved_at,
    )

    with pytest.raises(fs.StateError, match="must be after helper preflight") as raised:
        fs.weekly_plan(
            root,
            _write(tmp_path / "equal-time-selection.json", selection),
            tmp_path / "equal-time-plan.json",
            "2026-07-11T08:01:00Z",
        )

    assert raised.value.code == "clock-order"


def test_selection_preflight_rejects_incomplete_daily_without_new_writes(
    tmp_path: Path,
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    pending = _candidate(occurrences=[_occurrence(0, root="root:pending-daily")])
    fs.stage_candidate(
        _write(tmp_path / "pending-daily.json", pending),
        root,
        "2026-07-11T07:00:00Z",
    )
    selection = _selection(completed["snapshot_digest"], [case])
    draft = {key: selection[key] for key in fs.SELECTION_BASIS_FIELDS}
    before = _tree_bytes(root)

    with pytest.raises(fs.StateError, match="incomplete Daily audit") as raised:
        fs.preflight_selection(
            root,
            _write(tmp_path / "incomplete-daily-selection.json", draft),
            "2026-07-11T08:00:00Z",
        )

    assert raised.value.code == "daily-incomplete"
    assert _tree_bytes(root) == before


def test_selection_resource_envelope_has_no_count_cap_and_is_size_sensitive() -> None:
    case_items = [
        {
            "case_id": fs.new_case_id("2026-06-01T12:00:00Z"),
            "revision": 1,
            "semantic_digest": "sha256:" + "a" * 64,
        }
        for _ in range(256)
    ]

    def basis(count: int) -> dict[str, Any]:
        return {
            "version": 1,
            "kind": "publication-selection",
            "selection_id": str(uuid.uuid4()),
            "daily_snapshot_digest": "b" * 64,
            "base_intent": {
                "repository": "Joey-Tools/codex-skill-friction-ledger",
                "base_branch": "master",
                "base_sha": "a" * 40,
            },
            "cases": case_items[:count],
        }

    boundary_count = next(
        count
        for count in range(1, len(case_items) + 1)
        if fs._selection_resource_preflight(basis(count), count * fs.MAX_CASE_JSON_BYTES)[
            "finalize_wal_upper_bound_bytes"
        ]
        > fs.MAX_WAL_JSON_BYTES
    )
    same_count_basis = basis(boundary_count)
    small_resource = fs._selection_resource_preflight(same_count_basis, boundary_count * 1024)
    assert fs._validate_selection_resource(small_resource, same_count_basis) == small_resource

    maximum_resource = fs._selection_resource_preflight(
        same_count_basis, boundary_count * fs.MAX_CASE_JSON_BYTES
    )
    with pytest.raises(fs.StateError, match="bounded publication WAL") as raised:
        fs._validate_selection_resource(maximum_resource, same_count_basis)
    assert raised.value.code == "selection-resource-limit"


def test_selection_preflight_rejects_budget_before_any_control_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, stage = _stage(tmp_path, case)
    completed = _complete_live(tmp_path, root, [stage])
    selection = _selection(completed["snapshot_digest"], [case])
    draft = {key: selection[key] for key in fs.SELECTION_BASIS_FIELDS}
    exact = fs._selection_resource_preflight(
        draft, fs._publication_case_bytes_upper_bound(case["case"])
    )
    before = _tree_bytes(root)
    monkeypatch.setattr(
        fs,
        "MAX_WAL_JSON_BYTES",
        max(
            exact["weekly_wal_upper_bound_bytes"],
            exact["finalize_wal_upper_bound_bytes"],
        )
        - 1,
    )

    with pytest.raises(fs.StateError, match="bounded publication WAL") as raised:
        fs.preflight_selection(
            root,
            _write(tmp_path / "oversized-selection-draft.json", draft),
            "2026-07-11T08:00:01Z",
        )

    assert raised.value.code == "selection-resource-limit"
    assert _tree_bytes(root) == before


def test_weekly_plan_supports_twenty_eight_max_evidence_cases_past_legacy_cap(
    tmp_path: Path,
) -> None:
    cases: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    root = tmp_path / "state"
    base = dt.datetime(2026, 6, 1, 12, tzinfo=dt.UTC)
    for case_index in range(28):
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
    selection = _approved_selection(tmp_path, root, completed["snapshot_digest"], cases)
    output = tmp_path / "large-weekly-plan.json"
    result = fs.weekly_plan(
        root,
        _write(tmp_path / "large-selection.json", selection),
        output,
        "2026-07-11T08:01:00Z",
    )
    assert result["selected_count"] == 28
    output_size = len(output.read_bytes())
    assert fs.MAX_JSON_BYTES < output_size < fs.MAX_PUBLICATION_JSON_BYTES
    assert output_size <= selection["resource_preflight"]["publication_upper_bound_bytes"]
    intent_relative, _ = fs._wal_paths("weekly-plan", selection["selection_id"])
    intent_size = (root / intent_relative).stat().st_size
    assert intent_size > 5 * 1024 * 1024
    assert intent_size <= selection["resource_preflight"]["weekly_wal_upper_bound_bytes"]

    plan = fs._load_json(output, max_bytes=fs.MAX_PUBLICATION_JSON_BYTES)
    prepared_path = _write(tmp_path / "large-prepared.json", _prepared_receipt(plan))
    manifest_output = tmp_path / "large-manifest.json"
    finalized = fs.finalize_publication(
        root,
        output,
        prepared_path,
        manifest_output,
        "2026-07-11T08:32:00Z",
    )
    manifest_bytes = manifest_output.read_bytes()
    assert finalized["entry_count"] == 28
    assert (
        fs.MAX_JSON_BYTES
        < len(manifest_bytes)
        <= selection["resource_preflight"]["publication_upper_bound_bytes"]
    )
    finalize_key = f"{selection['selection_id']}:{plan['plan_digest']}"
    finalize_intent_relative, _ = fs._wal_paths("finalize-publication", finalize_key)
    finalize_intent_size = (root / finalize_intent_relative).stat().st_size
    assert finalize_intent_size > fs.MAX_JSON_BYTES
    assert finalize_intent_size <= selection["resource_preflight"]["finalize_wal_upper_bound_bytes"]

    manifest_output.unlink()
    replayed = fs.finalize_publication(
        root,
        output,
        prepared_path,
        manifest_output,
        "2026-07-11T09:32:00Z",
    )
    assert replayed == finalized
    assert manifest_output.read_bytes() == manifest_bytes


def test_prepared_variable_metadata_has_closed_resource_bounds(tmp_path: Path) -> None:
    _, plan, _ = _finalize_one(tmp_path, _candidate())
    maximum_metadata = _prepared_receipt(plan)
    four_byte_character = chr(0x1F642)
    maximum_metadata["entries"][0]["validation"]["commands"] = [
        four_byte_character * fs.MAX_PREPARED_COMMAND_CHARS for _ in range(fs.MAX_PREPARED_COMMANDS)
    ]
    maximum_metadata["entries"][0]["signature"]["signer"] = (
        four_byte_character * fs.MAX_PREPARED_SIGNER_CHARS
    )
    assert fs._validate_prepared_receipt(
        maximum_metadata,
        plan,
        now="2026-07-11T08:32:00Z",
    )
    assert (
        len(fs._canonical_bytes(maximum_metadata))
        <= plan["resource_preflight"]["publication_upper_bound_bytes"]
    )

    too_many_commands = _prepared_receipt(plan)
    too_many_commands["entries"][0]["validation"]["commands"] = [
        f"validate-{index}" for index in range(fs.MAX_PREPARED_COMMANDS + 1)
    ]
    with pytest.raises(fs.StateError, match="validation commands exceed") as commands_error:
        fs._validate_prepared_receipt(
            too_many_commands,
            plan,
            now="2026-07-11T08:32:00Z",
        )
    assert commands_error.value.code == "validation-too-large"

    oversized_signer = _prepared_receipt(plan)
    oversized_signer["entries"][0]["signature"]["signer"] = "x" * (fs.MAX_PREPARED_SIGNER_CHARS + 1)
    with pytest.raises(fs.StateError, match="signature.signer") as signer_error:
        fs._validate_prepared_receipt(
            oversized_signer,
            plan,
            now="2026-07-11T08:32:00Z",
        )
    assert signer_error.value.code == "invalid-text"


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


def test_legacy_state_marker_without_acl_binding_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    (root / fs.LOCK_FILE).write_bytes(b"")
    (root / fs.LOCK_FILE).chmod(0o600)
    legacy = {
        "version": 1,
        "kind": "daily-skill-friction-state",
        "mode": "unbound",
        "state_id": str(uuid.uuid4()),
        "created_at": "2026-07-10T12:00:00Z",
    }
    _write(root / fs.STATE_MARKER, legacy).chmod(0o600)
    with pytest.raises(fs.StateError, match="no persisted ACL policy") as unsupported:
        fs.transition_dormant(root, "2026-07-10T12:01:00Z")
    assert unsupported.value.code == "unsupported-state-access-policy"


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


def test_state_directory_binding_ignores_child_churn_and_classifies_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    year = root / "cases" / "2026"
    displaced = root / "cases" / ".2026-displaced"
    store = fs.StateStore(root)
    store.acquire_lock()
    real_stat = fs.os.stat
    try:
        store.write_json(Path("cases") / "2026" / "one.json", {"value": 1})
        assert set(store._directory_bindings) == {("cases",), ("cases", "2026")}
        original_limit = fs.MAX_RETAINED_STATE_DIRECTORIES
        monkeypatch.setattr(fs, "MAX_RETAINED_STATE_DIRECTORIES", 2)
        with pytest.raises(fs.StateError, match="binding limit exceeded") as bounded:
            with store.open_dir(Path("receipts") / "stage", create=True):
                pass
        assert bounded.value.code == "state-directory-binding-limit"
        assert not (root / "receipts").exists()
        monkeypatch.setattr(fs, "MAX_RETAINED_STATE_DIRECTORIES", original_limit)

        original_rename = fs._rename_state_directory_noreplace

        def lose_directory_publication_race(
            parent_fd: int,
            source_name: str,
            target_name: str,
            path: Path,
        ) -> None:
            del source_name, path
            os.mkdir(target_name, 0o700, dir_fd=parent_fd)
            raise FileExistsError(fs.errno.EEXIST, "injected no-replace race", target_name)

        monkeypatch.setattr(
            fs,
            "_rename_state_directory_noreplace",
            lose_directory_publication_race,
        )
        with pytest.raises(fs.StateError, match="lost a no-replace race") as creation_race:
            with store.open_dir(Path("receipts"), create=True):
                pass
        assert creation_race.value.code == "state-directory-replaced"
        assert ("receipts",) not in store._directory_bindings
        assert (
            sorted(path.name for path in root.iterdir() if path.name.startswith(".receipts.dir-"))
            == []
        )
        (root / "receipts").rmdir()
        monkeypatch.setattr(fs, "_rename_state_directory_noreplace", original_rename)

        transient = year / "transient"
        transient.mkdir(mode=0o700)
        transient.rmdir()
        store._bind_state_namespace("benign root-relative child churn")

        year.chmod(0o750)
        with pytest.raises(fs.StateError, match="owner or mode is unsafe") as policy:
            store._bind_state_namespace("root-relative mode drift")
        assert policy.value.code == "state-directory-policy-changed"
        year.chmod(0o700)

        year_binding = store._directory_bindings[("cases", "2026")]

        def deny_named_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            if path == "2026" and kwargs.get("dir_fd") == year_binding.parent_fd:
                raise PermissionError(fs.errno.EACCES, "injected unreadable directory", path)
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(fs.os, "stat", deny_named_stat)
        with pytest.raises(fs.StateError, match="name became unreadable") as unreadable:
            store._bind_state_namespace("root-relative unreadable name")
        assert unreadable.value.code == "state-directory-unreadable"
        monkeypatch.setattr(fs.os, "stat", real_stat)

        year.rename(displaced)
        with pytest.raises(fs.StateError, match="name disappeared") as missing:
            store._bind_state_namespace("root-relative missing name")
        assert missing.value.code == "state-directory-missing"

        year.mkdir(mode=0o700)
        with pytest.raises(fs.StateError, match="name was rebound") as replaced:
            store._bind_state_namespace("root-relative replacement")
        assert replaced.value.code == "state-directory-replaced"
        year.rmdir()
        displaced.rename(year)
        store.finish()
    finally:
        monkeypatch.setattr(fs.os, "stat", real_stat)
        if displaced.exists():
            if year.exists():
                year.rmdir()
            displaced.rename(year)
        store.close()


def test_transaction_rejects_rebound_wal_operation_before_commit_and_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    operation_dir = root / "wal" / "dormancy"
    displaced = root / "wal" / ".dormancy-displaced"
    store = fs.StateStore(root)
    store.acquire_lock()
    write = fs._planned_write(store, Path("probe.json"), {"value": 1}, immutable=False)
    authority = fs._planned_write(
        store,
        Path("receipts") / "dormancy" / "rebound-wal-operation.json",
        {"value": 1},
        immutable=True,
    )
    original_apply = fs._apply_wal_intent
    replaced = False

    def replace_operation_after_apply(current: Any, intent: dict[str, Any]) -> None:
        nonlocal replaced
        original_apply(current, intent)
        if current is store and not replaced:
            replaced = True
            operation_dir.rename(displaced)
            operation_dir.mkdir(mode=0o700)

    monkeypatch.setattr(fs, "_apply_wal_intent", replace_operation_after_apply)
    try:
        with pytest.raises(fs.StateError, match="name was rebound") as raised:
            fs._run_transaction(
                store,
                operation="dormancy",
                natural_key="rebound-wal-operation",
                request={"operation": "rebound-wal-operation"},
                captured_at="2026-07-10T12:00:00Z",
                writes=[write, authority],
                result={"status": "recovered"},
            )
        assert raised.value.code == "state-directory-replaced"
        assert replaced

        intent_path, commit_path = fs._wal_paths("dormancy", "rebound-wal-operation")
        assert not (root / commit_path).exists()
        assert (displaced / intent_path.name).exists()
        assert not (displaced / commit_path.name).exists()

        operation_dir.rmdir()
        displaced.rename(operation_dir)
        monkeypatch.setattr(fs, "_apply_wal_intent", original_apply)
        result = fs._run_transaction(
            store,
            operation="dormancy",
            natural_key="rebound-wal-operation",
            request={"operation": "rebound-wal-operation"},
            captured_at="2026-07-10T12:00:00Z",
            writes=[write, authority],
            result={"status": "recovered"},
        )
        assert result == {"status": "recovered"}
        assert (root / commit_path).exists()
        store.finish()
    finally:
        monkeypatch.setattr(fs, "_apply_wal_intent", original_apply)
        if displaced.exists():
            if operation_dir.exists():
                operation_dir.rmdir()
            displaced.rename(operation_dir)
        store.close()


def test_transaction_rejects_rebound_after_image_directory_and_recovery_is_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    year = root / "cases" / "2026"
    displaced = root / "cases" / ".2026-displaced"
    store = fs.StateStore(root)
    store.acquire_lock()
    write = fs._planned_write(
        store,
        Path("cases") / "2026" / "probe.json",
        {"value": 1},
        immutable=False,
    )
    authority = fs._planned_write(
        store,
        Path("receipts") / "dormancy" / "rebound-after-image-directory.json",
        {"value": 1},
        immutable=True,
    )
    original_bind = fs.StateStore._bind_state_namespace
    injected = False

    def replace_after_publication_preflight(current: Any, phase: str) -> None:
        nonlocal injected
        original_bind(current, phase)
        if (
            current is store
            and phase == "before publication"
            and ("cases", "2026") in current._directory_bindings
            and not injected
        ):
            injected = True
            year.rename(displaced)
            year.mkdir(mode=0o700)

    monkeypatch.setattr(
        fs.StateStore,
        "_bind_state_namespace",
        replace_after_publication_preflight,
    )
    try:
        with pytest.raises(fs.StateError, match="name was rebound") as raised:
            fs._run_transaction(
                store,
                operation="dormancy",
                natural_key="rebound-after-image-directory",
                request={"operation": "rebound-after-image-directory"},
                captured_at="2026-07-10T12:00:00Z",
                writes=[write, authority],
                result={"status": "recovered"},
            )
        assert raised.value.code == "state-directory-replaced"
        assert injected

        intent_path, commit_path = fs._wal_paths("dormancy", "rebound-after-image-directory")
        assert (root / intent_path).exists()
        assert not (root / commit_path).exists()
        assert not (year / "probe.json").exists()
        assert (displaced / "probe.json").exists()

        year.rmdir()
        displaced.rename(year)
        monkeypatch.setattr(fs.StateStore, "_bind_state_namespace", original_bind)
        fs._recover_pending_wal(store)
        assert (year / "probe.json").exists()
        assert (root / commit_path).exists()
        store.finish()
    finally:
        monkeypatch.setattr(fs.StateStore, "_bind_state_namespace", original_bind)
        if displaced.exists():
            if year.exists():
                year.rmdir()
            displaced.rename(year)
        store.close()


def test_state_transaction_revalidates_full_ancestor_chain_before_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ancestor = tmp_path / "bound-ancestor"
    ancestor.mkdir(mode=0o700)
    root = ancestor / "state"
    displaced_ancestor = tmp_path / "displaced-ancestor"
    store = fs.StateStore(root)
    store.acquire_lock()
    original_apply = fs._apply_wal_intent
    displaced = False

    def displace_after_writes(current: Any, intent: dict[str, Any]) -> None:
        nonlocal displaced
        original_apply(current, intent)
        if not displaced:
            displaced = True
            ancestor.rename(displaced_ancestor)
            ancestor.mkdir(mode=0o700)

    monkeypatch.setattr(fs, "_apply_wal_intent", displace_after_writes)
    try:
        write = fs._planned_write(store, Path("probe.json"), {"value": 1}, immutable=False)
        authority = fs._planned_write(
            store,
            Path("receipts") / "dormancy" / "ancestor-replacement.json",
            {"value": 1},
            immutable=True,
        )
        with pytest.raises(
            fs.StateError, match="name was rebound during before transaction commit"
        ):
            fs._run_transaction(
                store,
                operation="dormancy",
                natural_key="ancestor-replacement",
                request={"operation": "ancestor-replacement"},
                captured_at="2026-07-10T12:00:00Z",
                writes=[write, authority],
                result={"status": "must-not-commit"},
            )
        _, commit_path = fs._wal_paths("dormancy", "ancestor-replacement")
        assert (displaced_ancestor / "state" / "probe.json").exists()
        assert not (displaced_ancestor / "state" / commit_path).exists()
        assert not (root / "probe.json").exists()
    finally:
        store.close()


def test_state_chain_binds_ancestor_access_policy_but_ignores_metadata_churn(
    tmp_path: Path,
) -> None:
    ancestor = tmp_path / "policy-ancestor"
    ancestor.mkdir(mode=0o700)
    root = ancestor / "state"
    store = fs.StateStore(root)
    store.acquire_lock()
    try:
        transient = ancestor / "transient"
        transient.mkdir(mode=0o700)
        store._bind_state_chain("benign ancestor child churn")
        transient.rmdir()

        ancestor.chmod(0o750)
        with pytest.raises(fs.StateError, match="access policy changed"):
            store._bind_state_chain("ancestor mode drift")
    finally:
        ancestor.chmod(0o700)
        store.close()


def test_state_store_rejects_unsafe_initial_ancestor_policy(tmp_path: Path) -> None:
    ancestor = tmp_path / "unsafe-initial-ancestor"
    ancestor.mkdir(mode=0o700)
    root = ancestor / "state"
    ancestor.chmod(0o770)
    try:
        with pytest.raises(fs.StateError, match="group/world writable") as raised:
            fs.StateStore(root)
        assert raised.value.code == "unsafe-state-chain-policy"
        assert not root.exists()
    finally:
        ancestor.chmod(0o700)


def test_state_store_rejects_unsafe_ancestor_mode_drift_across_calls(
    tmp_path: Path,
) -> None:
    ancestor = tmp_path / "cross-call-policy-ancestor"
    ancestor.mkdir(mode=0o700)
    root = ancestor / "state"
    initial = fs.StateStore(root)
    initial.close()

    ancestor.chmod(0o770)
    try:
        with pytest.raises(fs.StateError, match="group/world writable") as raised:
            fs.StateStore(root, create=False)
        assert raised.value.code == "unsafe-state-chain-policy"
    finally:
        ancestor.chmod(0o700)


def test_state_store_allows_root_owned_sticky_custody_ancestor() -> None:
    sticky_parent = next(
        (
            path
            for path in (Path("/private/tmp"), Path("/tmp"))
            if path.is_dir()
            and not path.is_symlink()
            and path.stat().st_uid == 0
            and stat.S_IMODE(path.stat().st_mode) & stat.S_ISVTX
            and stat.S_IMODE(path.stat().st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        ),
        None,
    )
    if sticky_parent is None:
        pytest.skip("host has no root-owned writable sticky directory")

    with tempfile.TemporaryDirectory(prefix="dsf-sticky-custody-", dir=sticky_parent) as scope:
        scope_path = Path(scope)
        scope_path.chmod(0o700)
        store = fs.StateStore(scope_path / "state")
        try:
            store.acquire_lock()
            store.finish()
        finally:
            store.close()


def test_state_store_ignores_benign_ancestor_child_churn_across_calls(
    tmp_path: Path,
) -> None:
    ancestor = tmp_path / "cross-call-churn-ancestor"
    ancestor.mkdir(mode=0o700)
    root = ancestor / "state"
    initial = fs.StateStore(root)
    initial.close()

    transient = ancestor / "transient"
    transient.mkdir(mode=0o700)
    transient.rmdir()
    reopened = fs.StateStore(root, create=False)
    reopened.close()


def test_state_store_classifies_unreadable_initial_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ancestor = tmp_path / "unreadable-ancestor"
    ancestor.mkdir(mode=0o700)
    root = ancestor / "state"
    real_open = fs.os.open

    def deny_ancestor(
        name: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if name == ancestor.name:
            raise PermissionError(fs.errno.EACCES, "injected unreadable ancestor", name)
        return real_open(name, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(fs.os, "open", deny_ancestor)
    with pytest.raises(fs.StateError, match="custody component is unreadable") as raised:
        fs.StateStore(root, create=False)
    assert raised.value.code == "state-chain-unreadable"


def test_acl_policy_normalization_preserves_entry_order_and_separates_leaf_policy() -> None:
    first = {
        "index": 0,
        "tag": "deny",
        "qualifier": "00" * 16,
        "permissions": 16,
        "flags": 0,
    }
    second = {
        "index": 1,
        "tag": "deny",
        "qualifier": "11" * 16,
        "permissions": 2,
        "flags": 32,
    }
    ordered = {
        "version": 1,
        "model": "darwin-extended-v1",
        "entries": [first, second],
    }
    reversed_entries = {
        **ordered,
        "entries": [{**second, "index": 0}, {**first, "index": 1}],
    }
    assert fs._digest(ordered) != fs._digest(reversed_entries)
    fs._enforce_acl_policy({**ordered, "digest": fs._digest(ordered)}, "ancestor", sensitive=False)
    with pytest.raises(fs.StateError, match="extended ACL") as leaf:
        fs._enforce_acl_policy({**ordered, "digest": fs._digest(ordered)}, "leaf", sensitive=True)
    assert leaf.value.code == "state-acl-present"
    allowing = json.loads(json.dumps(ordered))
    allowing["entries"][0]["tag"] = "allow"
    with pytest.raises(fs.StateError, match="allow ACL") as ancestor:
        fs._enforce_acl_policy(allowing, "ancestor", sensitive=False)
    assert ancestor.value.code == "custody-acl-allows-access"


def test_non_darwin_acl_policy_is_explicit_posix_only_sentinel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    monkeypatch.setattr(fs.sys, "platform", "linux")
    monkeypatch.setattr(
        fs,
        "_darwin_acl_libc",
        lambda: pytest.fail("non-Darwin ACL path must not load Darwin libc"),
    )
    try:
        snapshot = fs._acl_snapshot(fd, str(tmp_path))
    finally:
        os.close(fd)
    assert snapshot == {
        "version": 1,
        "model": "posix-mode-only-v1",
        "entries": [],
        "digest": fs._digest({"version": 1, "model": "posix-mode-only-v1", "entries": []}),
    }


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL contract")
def test_darwin_acl_fd_policy_accepts_deny_custody_rejects_allow_and_binds_marker(
    tmp_path: Path,
) -> None:
    deny_ancestor = tmp_path / "deny-ancestor"
    deny_ancestor.mkdir(mode=0o700)
    subprocess.run(
        ["/bin/chmod", "+a", "everyone deny delete", str(deny_ancestor)],
        check=True,
        capture_output=True,
        text=True,
    )
    root = deny_ancestor / "state"
    case = _candidate()
    staged = fs.stage_candidate(
        _write(deny_ancestor / "candidate.json", case),
        root,
        "2026-07-10T12:00:00Z",
    )
    marker = fs._load_json(root / fs.STATE_MARKER)
    assert marker["access_policy"]["model"] == "darwin-extended-v1"
    assert any(item["name"] == deny_ancestor.name for item in marker["access_policy"]["chain"])

    case_path = root / staged["case_path"]
    subprocess.run(
        ["/bin/chmod", "+a", "everyone deny delete", str(case_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        with pytest.raises(fs.StateError, match="extended ACL") as leaf:
            fs.stage_candidate(
                _write(deny_ancestor / "candidate-again.json", case),
                root,
                "2026-07-10T12:01:00Z",
            )
        assert leaf.value.code == "state-acl-present"
    finally:
        subprocess.run(["/bin/chmod", "-N", str(case_path)], check=True, capture_output=True)

    subprocess.run(["/bin/chmod", "-N", str(deny_ancestor)], check=True, capture_output=True)
    try:
        with pytest.raises(fs.StateError, match="ACL chain no longer matches") as changed:
            fs.stage_candidate(
                _write(deny_ancestor / "candidate-after-drift.json", case),
                root,
                "2026-07-10T12:02:00Z",
            )
        assert changed.value.code == "state-chain-policy-changed"
    finally:
        subprocess.run(
            ["/bin/chmod", "+a", "everyone deny delete", str(deny_ancestor)],
            check=True,
            capture_output=True,
        )

    allow_ancestor = tmp_path / "allow-ancestor"
    allow_ancestor.mkdir(mode=0o700)
    subprocess.run(
        ["/bin/chmod", "+a", "everyone allow read", str(allow_ancestor)],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        with pytest.raises(fs.StateError, match="allow ACL") as allowing:
            fs.StateStore(allow_ancestor / "state")
        assert allowing.value.code == "custody-acl-allows-access"
    finally:
        subprocess.run(["/bin/chmod", "-N", str(allow_ancestor)], check=True, capture_output=True)
        subprocess.run(["/bin/chmod", "-N", str(deny_ancestor)], check=True, capture_output=True)


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
    lifecycle = _repair_lifecycle_candidates()
    root, closed = _stage_repair_lifecycle(tmp_path, lifecycle)
    reopened = _closed_reopen_candidate(closed)
    receipt = fs.stage_candidate(
        _write(tmp_path / "reopened.json", reopened),
        root,
        "2026-07-12T13:00:00Z",
    )
    assert receipt["action"] == "updated"
    assert fs._load_json(root / receipt["case_path"])["case"]["status"] == "proposed"
    reapproved = json.loads(json.dumps(reopened))
    reapproved["case"]["revision"] += 1
    reapproved["case"]["status"] = "approved"
    reapproved["case"]["lifecycle_changed_at"] = "2026-07-12T13:01:00Z"
    reapproved["case"]["repairs"][-1]["state"] = "open"
    reapproved["case"]["repairs"][-1]["pull_request_url"] = (
        "https://github.com/Joey-Tools/example/pull/2"
    )
    reapproved["control"]["semantic_digest"] = fs.semantic_digest(reapproved["case"])
    with pytest.raises(fs.StateError, match="exact repair approval") as fresh_approval:
        fs.stage_candidate(
            _write(tmp_path / "reapproved.json", reapproved),
            root,
            "2026-07-12T14:00:00Z",
        )
    assert fresh_approval.value.code == "missing-repair-approval"

    other_root, _ = _stage_repair_lifecycle(tmp_path / "invalid-reopen", lifecycle)
    not_later = _closed_reopen_candidate(closed, observed_at="2026-07-11T09:00:00Z")
    with pytest.raises(fs.StateError, match="strictly follow"):
        fs.stage_candidate(
            _write(tmp_path / "not-later.json", not_later),
            other_root,
            "2026-07-12T13:00:00Z",
        )

    late_root, _ = _stage_repair_lifecycle(tmp_path / "late-reopen", lifecycle)
    lifecycle_too_early = _closed_reopen_candidate(closed, observed_at="2026-07-12T12:02:00Z")
    with pytest.raises(fs.StateError, match="cannot predate recurrence"):
        fs.stage_candidate(
            _write(tmp_path / "reopen-clock.json", lifecycle_too_early),
            late_root,
            "2026-07-12T13:00:00Z",
        )

    method_root, _ = _stage_repair_lifecycle(tmp_path / "method-reopen", lifecycle)
    changed_method = _closed_reopen_candidate(closed)
    changed_method["case"]["effectiveness"]["method"] = "behavioral"
    changed_method["control"]["semantic_digest"] = fs.semantic_digest(changed_method["case"])
    with pytest.raises(fs.StateError, match="same selected effectiveness method"):
        fs.stage_candidate(
            _write(tmp_path / "reopen-method-change.json", changed_method),
            method_root,
            "2026-07-12T13:00:00Z",
        )


def test_closed_reopen_freezes_every_prior_repair_provenance(tmp_path: Path) -> None:
    lifecycle = _repair_lifecycle_candidates()
    for candidate in lifecycle:
        case = candidate["case"]
        case["repairs"].append(
            {
                "id": "R2",
                "repository": "Joey-Tools/example",
                "action": "amend",
                "state": "superseded",
                "problem_statement": (
                    "An earlier repair proposal was retired before implementation."
                ),
                "change_summary": "Retain the unimplemented repair as sealed history.",
                "pull_request_url": None,
                "commit": None,
                "commit_trailer": f"Friction-Case: {case['id']}",
                "installed_on": None,
                "removed_on": None,
                "replaces_repair_id": None,
            }
        )
        candidate["control"]["semantic_digest"] = fs.semantic_digest(case)

    root, closed = _stage_repair_lifecycle(tmp_path, lifecycle)
    reopened = _closed_reopen_candidate(closed)

    changed_prior = json.loads(json.dumps(reopened))
    changed_prior["case"]["repairs"][1]["pull_request_url"] = (
        "https://github.com/Joey-Tools/example/pull/99"
    )
    changed_prior["control"]["semantic_digest"] = fs.semantic_digest(changed_prior["case"])
    with pytest.raises(fs.StateError, match="preserve every prior repair") as prior_error:
        fs.stage_candidate(
            _write(tmp_path / "changed-prior.json", changed_prior),
            root,
            "2026-07-12T13:00:00Z",
        )
    assert prior_error.value.code == "invalid-closed-reopen"

    changed_active = json.loads(json.dumps(reopened))
    changed_active["case"]["repairs"][0]["pull_request_url"] = (
        "https://github.com/Joey-Tools/example/pull/98"
    )
    changed_active["control"]["semantic_digest"] = fs.semantic_digest(changed_active["case"])
    with pytest.raises(fs.StateError, match="preserve every prior repair") as active_error:
        fs.stage_candidate(
            _write(tmp_path / "changed-active.json", changed_active),
            root,
            "2026-07-12T13:01:00Z",
        )
    assert active_error.value.code == "invalid-closed-reopen"

    receipt = fs.stage_candidate(
        _write(tmp_path / "legal-reopen.json", reopened),
        root,
        "2026-07-12T13:02:00Z",
    )
    assert receipt["action"] == "updated"
    persisted = fs._load_json(root / receipt["case_path"])["case"]
    assert persisted["repairs"][:-1] == reopened["case"]["repairs"][:-1]
    assert persisted["repairs"][-1]["id"] == "R3"


def test_stage_rejects_missing_or_cyclic_supersession_graph(tmp_path: Path) -> None:
    missing_first = _candidate()
    missing_root, _ = _stage(tmp_path / "missing", missing_first)
    missing = json.loads(json.dumps(missing_first))
    missing["case"]["revision"] = 2
    missing["case"]["status"] = "superseded"
    missing["case"]["lifecycle_changed_at"] = "2026-06-02T12:00:00Z"
    missing["case"]["lifecycle"]["superseded_by"] = _candidate()["case"]["id"]
    missing["control"]["semantic_digest"] = fs.semantic_digest(missing["case"])
    with pytest.raises(fs.StateError, match="missing successor"):
        fs.stage_candidate(
            _write(tmp_path / "missing-successor.json", missing),
            missing_root,
            "2026-07-10T12:00:00Z",
        )

    successor = _candidate()
    root, _ = _stage(tmp_path / "cycle", successor)
    predecessor_first = _candidate()
    fs.stage_candidate(
        _write(tmp_path / "predecessor-first.json", predecessor_first),
        root,
        "2026-07-10T12:30:00Z",
    )
    predecessor = json.loads(json.dumps(predecessor_first))
    predecessor["case"]["revision"] = 2
    predecessor["case"]["status"] = "superseded"
    predecessor["case"]["lifecycle_changed_at"] = "2026-06-02T12:00:00Z"
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


def test_superseded_case_allows_only_nonsemantic_currentness_refresh(tmp_path: Path) -> None:
    successor = _candidate()
    first = _candidate()
    root, _ = _stage(tmp_path, successor)
    fs.stage_candidate(
        _write(tmp_path / "first.json", first),
        root,
        "2026-07-10T12:01:00Z",
    )
    terminal = json.loads(json.dumps(first))
    terminal["case"]["revision"] = 2
    terminal["case"]["status"] = "superseded"
    terminal["case"]["lifecycle_changed_at"] = "2026-06-02T12:00:00Z"
    terminal["case"]["lifecycle"]["superseded_by"] = successor["case"]["id"]
    terminal["control"]["semantic_digest"] = fs.semantic_digest(terminal["case"])
    fs.stage_candidate(
        _write(tmp_path / "terminal.json", terminal),
        root,
        "2026-07-10T12:02:00Z",
    )

    changed_title = json.loads(json.dumps(terminal))
    changed_title["case"]["revision"] += 1
    changed_title["case"]["title"] = "Rewritten terminal history"
    changed_title["control"]["semantic_digest"] = fs.semantic_digest(changed_title["case"])

    appended_evidence = json.loads(json.dumps(terminal))
    occurrence = _occurrence(
        1,
        root="root:terminal-history",
        observed_at="2026-06-03T12:00:00Z",
    )
    appended_evidence["case"]["revision"] += 1
    appended_evidence["case"]["support"] = "repeated"
    appended_evidence["case"]["evidence"].append(occurrence)
    appended_evidence["case"]["evidence_last_seen"] = occurrence["observed_at"]
    appended_evidence["case"]["currentness_checked_at"] = occurrence["observed_at"]
    appended_evidence["case"]["causal"].update(
        {
            "occurrence_count": 2,
            "root_task_count": 2,
            "workflow_count": 1,
            "repository_count": 1,
            "opportunity_count": 2,
            "causal_signature_count": 1,
        }
    )
    appended_evidence["control"]["source_lineage"].append(
        {
            "opportunity_id": occurrence["opportunity_id"],
            "source_family": "human-root",
            "is_automation_descendant": False,
            "is_replay": False,
            "chronology": "A later human root supplied terminal recurrence evidence.",
        }
    )
    appended_evidence["control"]["semantic_digest"] = fs.semantic_digest(appended_evidence["case"])

    appended_repair = json.loads(json.dumps(terminal))
    appended_repair["case"]["revision"] += 1
    appended_repair["case"]["repairs"] = [
        {
            "id": "R1",
            "repository": "Joey-Tools/example",
            "action": "amend",
            "state": "superseded",
            "problem_statement": "Terminal history must not gain a repair after supersession.",
            "change_summary": "Attempt to append a repair to terminal history.",
            "pull_request_url": None,
            "commit": None,
            "commit_trailer": f"Friction-Case: {terminal['case']['id']}",
            "installed_on": None,
            "removed_on": None,
            "replaces_repair_id": None,
        }
    ]
    appended_repair["case"]["effectiveness"]["method"] = "deterministic"
    appended_repair["control"]["semantic_digest"] = fs.semantic_digest(appended_repair["case"])

    for index, candidate in enumerate(
        (changed_title, appended_evidence, appended_repair),
        start=1,
    ):
        with pytest.raises(fs.StateError, match="semantic history is immutable") as semantic:
            fs.stage_candidate(
                _write(tmp_path / f"terminal-semantic-{index}.json", candidate),
                root,
                f"2026-07-10T12:1{index}:00Z",
            )
        assert semantic.value.code == "terminal-semantic-mutation"

    changed_lineage = json.loads(json.dumps(terminal))
    changed_lineage["control"]["source_lineage"][0]["chronology"] = (
        "Rewritten lineage for terminal history."
    )
    with pytest.raises(fs.StateError, match="control provenance") as lineage:
        fs.stage_candidate(
            _write(tmp_path / "terminal-lineage.json", changed_lineage),
            root,
            "2026-07-10T12:20:00Z",
        )
    assert lineage.value.code == "control-mutation"

    refreshed = json.loads(json.dumps(terminal))
    refreshed["case"]["currentness_checked_at"] = "2026-07-10T12:30:00Z"
    refreshed["control"]["semantic_digest"] = fs.semantic_digest(refreshed["case"])
    assert refreshed["case"]["revision"] == terminal["case"]["revision"]
    assert refreshed["control"]["semantic_digest"] == terminal["control"]["semantic_digest"]
    receipt = fs.stage_candidate(
        _write(tmp_path / "terminal-currentness.json", refreshed),
        root,
        "2026-07-10T12:31:00Z",
    )
    assert receipt["action"] == "updated"
    persisted = fs._load_json(root / receipt["case_path"])
    assert persisted["case"] == refreshed["case"]


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
    invalid_commits = (
        (
            "published-base-commit",
            plan["base_intent"]["base_sha"],
            "ledger-commit-base",
            "must differ from the plan base SHA",
        ),
        (
            "published-mismatched-width",
            "d" * 64,
            "ledger-commit-format",
            "plan base SHA object-ID width",
        ),
    )
    for invalid_id, ledger_commit, error_code, error_match in invalid_commits:
        invalid_closure = json.loads(json.dumps(closure))
        invalid_closure["closure_id"] = invalid_id
        invalid_closure["entries"][0]["ledger_commit"] = ledger_commit
        before = _persistent_identity_snapshot(root)
        with pytest.raises(fs.StateError, match=error_match) as invalid:
            fs.close_publication(
                root,
                _write(tmp_path / f"{invalid_id}.json", invalid_closure),
                "2026-07-11T08:37:00Z",
                approval_path,
            )
        assert invalid.value.code == error_code
        assert _persistent_identity_snapshot(root) == before
        intent_relative, commit_relative = fs._wal_paths("close-publication", invalid_id)
        assert not (root / intent_relative).exists()
        assert not (root / commit_relative).exists()
        assert not (root / "publication" / "closures" / f"{invalid_id}.json").exists()

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


@pytest.mark.parametrize(
    ("commit_kind", "error_code", "error_match"),
    [
        ("base", "ledger-commit-base", "must differ from the plan base SHA"),
        ("wrong-width", "ledger-commit-format", "plan base SHA object-ID width"),
    ],
)
def test_pending_published_closure_wal_revalidates_commit_before_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    commit_kind: str,
    error_code: str,
    error_match: str,
) -> None:
    case = _candidate()
    root, plan, manifest = _finalize_one(tmp_path, case)
    entry = plan["entries"][0]
    closure_id = f"pending-published-{commit_kind}"
    ledger_commit = plan["base_intent"]["base_sha"] if commit_kind == "base" else "d" * 64
    closure = {
        "version": 1,
        "kind": "publication-closure",
        "closure_id": closure_id,
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
                    "https://github.com/Joey-Tools/codex-skill-friction-ledger/pull/3"
                ),
                "ledger_commit": ledger_commit,
                "merged_at": "2026-07-11T08:35:00Z",
            }
        ],
    }
    approval = {
        "version": 1,
        "kind": "publication-approval",
        "approval_id": f"pending-published-{commit_kind}-approval",
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
    closure_path = _write(tmp_path / f"{closure_id}.json", closure)
    approval_path = _write(tmp_path / f"{closure_id}-approval.json", approval)
    history_relative = Path("publication") / "closures" / f"{closure_id}.json"
    active_relative = Path("publication") / "active" / f"{entry['case_id']}.json"
    original_validator = fs._validate_published_ledger_commit
    original_write = fs.StateStore.write_json

    def interrupt_history(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        if Path(relative) == history_relative:
            raise OSError("injected invalid published closure interruption")
        return original_write(store, relative, value, immutable=immutable)

    monkeypatch.setattr(fs, "_validate_published_ledger_commit", lambda item, bound_plan: None)
    monkeypatch.setattr(fs.StateStore, "write_json", interrupt_history)
    with pytest.raises(OSError, match="injected invalid published closure interruption"):
        fs.close_publication(
            root,
            closure_path,
            "2026-07-11T08:37:00Z",
            approval_path,
        )
    monkeypatch.setattr(fs, "_validate_published_ledger_commit", original_validator)
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)

    intent_relative, commit_relative = fs._wal_paths("close-publication", closure_id)
    assert (root / intent_relative).exists()
    assert not (root / commit_relative).exists()
    assert not (root / history_relative).exists()
    assert fs._load_json(root / active_relative)["status"] == "active"
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError, match=error_match) as raised:
        fs.close_publication(
            root,
            closure_path,
            "2026-07-11T09:37:00Z",
            approval_path,
        )

    assert raised.value.code == error_code
    assert _persistent_identity_snapshot(root) == before
    assert not (root / history_relative).exists()
    assert fs._load_json(root / active_relative)["status"] == "active"


@pytest.mark.parametrize("tamper_kind", ["redirect-active", "forged-manifest-tuple"])
def test_close_wal_projection_and_manifest_membership_fail_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper_kind: str,
) -> None:
    case = _repair_lifecycle_candidates()[0]
    root, plan, manifest = _finalize_one(tmp_path, case)
    closure, approval = _published_closure_and_approval(
        plan,
        manifest,
        closure_id=f"legacy-close-{tamper_kind}",
        ledger_commit="c" * 40,
    )
    history_relative = Path("publication") / "closures" / f"{closure['closure_id']}.json"
    original_write = fs.StateStore.write_json

    def interrupt_history(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        if Path(relative) == history_relative:
            raise OSError("injected pending close projection")
        return original_write(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )

    monkeypatch.setattr(fs.StateStore, "write_json", interrupt_history)
    with pytest.raises(OSError, match="pending close projection"):
        fs.close_publication(
            root,
            _write(tmp_path / "projection-closure.json", closure),
            "2026-07-11T08:37:00Z",
            _write(tmp_path / "projection-approval.json", approval),
        )
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)

    intent_relative, commit_relative = fs._wal_paths(
        "close-publication",
        closure["closure_id"],
    )
    intent_path = root / intent_relative
    intent = fs._load_json(intent_path)
    closure_write = next(
        write for write in intent["writes"] if write["after"].get("kind") == "publication-closure"
    )
    active_write = next(
        write for write in intent["writes"] if write["after"].get("kind") == "publication-pending"
    )
    if tamper_kind == "redirect-active":
        active_write["path"] = f"publication/active/{fs.new_case_id('2026-06-20T12:00:00Z')}.json"
    else:
        forged_revision = closure_write["after"]["entries"][0]["revision"] + 1
        closure_write["after"]["entries"][0]["revision"] = forged_revision
        closure_body = {
            key: value for key, value in closure_write["after"].items() if key != "closure_digest"
        }
        forged_closure_digest = fs._digest(closure_body)
        closure_write["after"]["closure_digest"] = forged_closure_digest
        closure_write["after_sha256"] = hashlib.sha256(
            fs._canonical_bytes(closure_write["after"])
        ).hexdigest()
        active_write["after"]["revision"] = forged_revision
        active_write["after"]["closure_digest"] = forged_closure_digest
        active_body = {
            key: value for key, value in active_write["after"].items() if key != "record_digest"
        }
        active_write["after"]["record_digest"] = fs._digest(active_body)
        active_write["after_sha256"] = hashlib.sha256(
            fs._canonical_bytes(active_write["after"])
        ).hexdigest()
        intent["result"]["closure_digest"] = forged_closure_digest
    intent_body = {key: value for key, value in intent.items() if key != "intent_digest"}
    intent["intent_digest"] = fs._digest(intent_body)
    intent_path.write_bytes(fs._canonical_bytes(intent))

    if tamper_kind == "redirect-active":
        before = _persistent_identity_snapshot(root)
        with fs._state_lock(root, create=False) as store:
            with pytest.raises(fs.StateError, match="path or mutability") as raised:
                fs._recover_pending_wal(store)
        assert raised.value.code == "invalid-wal"
        assert _persistent_identity_snapshot(root) == before
        assert not (root / commit_relative).exists()
        return

    membership_validator = fs._validate_manifest_closure_entry
    monkeypatch.setattr(fs, "_validate_manifest_closure_entry", lambda manifest, item: None)
    with fs._state_lock(root, create=False) as store:
        fs._recover_pending_wal(store)
    monkeypatch.setattr(fs, "_validate_manifest_closure_entry", membership_validator)
    closure_record = fs._load_json(root / history_relative)
    entry = closure_record["entries"][0]
    publication = {
        "closure_id": closure_record["closure_id"],
        "closure_digest": closure_record["closure_digest"],
        "selection_id": entry["selection_id"],
        "plan_digest": entry["plan_digest"],
        "manifest_digest": entry["manifest_digest"],
        "pull_request_url": entry["pull_request_url"],
        "ledger_commit": entry["ledger_commit"],
        "merged_at": entry["merged_at"],
    }
    source_tuple = {field: entry[field] for field in ("case_id", "revision", "semantic_digest")}
    before = _persistent_identity_snapshot(root)
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="exact finalized manifest entry") as raised:
            fs._validate_published_closure_authority(
                store,
                publication,
                source_tuple,
                recover_publication=False,
            )
    assert raised.value.code == "publication-receipt-mismatch"
    assert _persistent_identity_snapshot(root) == before


@pytest.mark.parametrize(
    ("tamper_kind", "error_match"),
    [
        ("active-path", "state after-images differ"),
        ("closure-path", "key or authority path"),
    ],
)
def test_retired_close_rejects_redirected_projection_without_mutation(
    tmp_path: Path,
    tamper_kind: str,
    error_match: str,
) -> None:
    root, plan, manifest = _finalize_one(tmp_path, _candidate())
    closure, approval = _published_closure_and_approval(
        plan,
        manifest,
        closure_id="retired-redirected-close",
        ledger_commit="c" * 40,
    )
    closure_path = _write(tmp_path / "retired-redirected-closure.json", closure)
    approval_path = _write(tmp_path / "retired-redirected-approval.json", approval)
    fs.close_publication(
        root,
        closure_path,
        "2026-07-11T08:37:00Z",
        approval_path,
    )
    with fs._state_lock(root, create=False) as store:
        fs._recover_pending_wal(store, compact_committed=True)

    checkpoint_path = root / fs._wal_history_path(
        "close-publication",
        closure["closure_id"],
    )
    checkpoint = fs._load_json(checkpoint_path)
    if tamper_kind == "active-path":
        active_image = next(
            image
            for image in checkpoint["after_images"]
            if image["path"].startswith("publication/active/")
        )
        active_image["path"] = f"publication/active/{fs.new_case_id('2026-06-20T12:00:00Z')}.json"
    else:
        closure_authority = next(
            authority
            for authority in checkpoint["authorities"]
            if authority["path"].startswith("publication/closures/")
        )
        original_path = closure_authority["path"]
        redirected_path = "publication/closures/redirected-retired-close.json"
        redirected = root / redirected_path
        redirected.write_bytes((root / original_path).read_bytes())
        redirected.chmod(0o600)
        closure_authority["path"] = redirected_path
        closure_image = next(
            image for image in checkpoint["after_images"] if image["path"] == original_path
        )
        closure_image["path"] = redirected_path
    _rewrite_wal_checkpoint_chain(root, checkpoint_path, checkpoint)

    before_retry = _persistent_identity_snapshot(root)
    with pytest.raises(fs.StateError, match=error_match) as retry:
        fs.close_publication(
            root,
            closure_path,
            "2026-07-11T09:37:00Z",
            approval_path,
        )
    assert retry.value.code == "invalid-wal-history"
    assert _persistent_identity_snapshot(root) == before_retry

    before_audit = _persistent_identity_snapshot(root)
    with pytest.raises(fs.StateError, match=error_match) as audit:
        fs.audit_wal_history(root)
    assert audit.value.code == "invalid-wal-history"
    assert _persistent_identity_snapshot(root) == before_audit


@pytest.mark.parametrize("retired", [False, True])
def test_invalid_committed_or_retired_close_retry_precedes_unrelated_pending_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    retired: bool,
) -> None:
    root, plan, manifest = _finalize_one(tmp_path, _candidate())
    closure, approval = _published_closure_and_approval(
        plan,
        manifest,
        closure_id=f"legacy-invalid-close-{'retired' if retired else 'active'}",
        ledger_commit=plan["base_intent"]["base_sha"],
    )
    closure_path = _write(tmp_path / f"{closure['closure_id']}.json", closure)
    approval_path = _write(tmp_path / f"{approval['approval_id']}.json", approval)
    commit_validator = fs._validate_published_ledger_commit
    intent_validator = fs._validate_close_publication_intent_commits
    monkeypatch.setattr(fs, "_validate_published_ledger_commit", lambda item, plan: None)
    monkeypatch.setattr(
        fs,
        "_validate_close_publication_intent_commits",
        lambda store, intent, **kwargs: None,
    )
    fs.close_publication(
        root,
        closure_path,
        "2026-07-11T08:37:00Z",
        approval_path,
    )
    if retired:
        with fs._state_lock(root, create=False) as store:
            fs._recover_pending_wal(store, compact_committed=True)
    monkeypatch.setattr(fs, "_validate_published_ledger_commit", commit_validator)
    monkeypatch.setattr(fs, "_validate_close_publication_intent_commits", intent_validator)

    authority_before = _persistent_identity_snapshot(root)
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="must differ from the plan base SHA") as authority:
            fs._require_committed_transaction(
                store,
                "close-publication",
                closure["closure_id"],
                recover_publication=False,
            )
    assert authority.value.code == "ledger-commit-base"
    assert _persistent_identity_snapshot(root) == authority_before

    pending_intent, pending_candidate = _copy_pending_stage_intent(
        tmp_path / f"unrelated-pending-{retired}",
        root,
        valid_for_target=True,
    )
    _, pending_commit_relative = fs._wal_paths(
        "stage",
        fs._load_json(pending_intent)["natural_key"],
    )
    before_retry = _persistent_identity_snapshot(root)
    with pytest.raises(fs.StateError, match="must differ from the plan base SHA") as retry:
        fs.close_publication(
            root,
            closure_path,
            "2026-07-11T09:37:00Z",
            approval_path,
        )
    assert retry.value.code == "ledger-commit-base"
    assert _persistent_identity_snapshot(root) == before_retry
    assert pending_intent.exists()
    assert not (root / pending_commit_relative).exists()
    assert not (root / fs._case_relative_path(pending_candidate)).exists()


def test_published_closure_recovers_history_active_gap_with_advanced_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _candidate()
    root, plan, manifest = _finalize_one(tmp_path, case)
    entry = plan["entries"][0]
    closure = {
        "version": 1,
        "kind": "publication-closure",
        "closure_id": "published-gap",
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
                    "https://github.com/Joey-Tools/codex-skill-friction-ledger/pull/2"
                ),
                "ledger_commit": "d" * 40,
                "merged_at": "2026-07-11T08:35:00Z",
            }
        ],
    }
    approval = {
        "version": 1,
        "kind": "publication-approval",
        "approval_id": "published-gap-approval",
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
    closure_path = _write(tmp_path / "published-gap.json", closure)
    approval_path = _write(tmp_path / "published-gap-approval.json", approval)
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
            raise OSError("injected published active closure interruption")
        return original(store, relative, value, immutable=immutable)

    monkeypatch.setattr(fs.StateStore, "write_json", fail_active)
    with pytest.raises(OSError, match="injected published active closure interruption"):
        fs.close_publication(
            root,
            closure_path,
            "2026-07-11T08:37:00Z",
            approval_path,
        )
    monkeypatch.setattr(fs.StateStore, "write_json", original)
    history_path = root / "publication" / "closures" / "published-gap.json"
    history_bytes = history_path.read_bytes()
    recovered = fs.close_publication(
        root,
        closure_path,
        "2026-07-11T09:37:00Z",
        approval_path,
    )
    assert history_path.read_bytes() == history_bytes
    assert recovered["status"] == "closed"
    assert fs._load_json(root / active_relative)["status"] == "closed"
    assert (
        fs.close_publication(
            root,
            closure_path,
            "2026-07-11T10:37:00Z",
            approval_path,
        )
        == recovered
    )


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


def test_proposed_to_approved_requires_independent_published_repair_authority(
    tmp_path: Path,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    with pytest.raises(fs.StateError, match="exact repair approval") as missing:
        fs.stage_candidate(
            _write(tmp_path / "unapproved.json", approved),
            root,
            "2026-07-11T08:39:00Z",
        )
    assert missing.value.code == "missing-repair-approval"

    approval, _ = _publish_and_approve_repair(
        tmp_path, root, proposed, approved, proposed_stage, persist=False
    )
    publication_approval = {
        "version": 1,
        "kind": "publication-approval",
        "approval_id": "not-a-repair-approval",
        "interaction": {
            "interactive": True,
            "actor": "Joey",
            "approved_at": "2026-07-11T08:37:00Z",
        },
        "selection_id": approval["publication"]["selection_id"],
        "plan_digest": approval["publication"]["plan_digest"],
        "manifest_digest": approval["publication"]["manifest_digest"],
        "entries": [approval["source"]],
    }
    with pytest.raises(fs.StateError, match="version or kind"):
        fs.approve_repair(
            root,
            _write(tmp_path / "approved-candidate.json", approved),
            _write(tmp_path / "wrong-authority.json", publication_approval),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
    with pytest.raises(fs.StateError, match="interactive Joey confirmation"):
        fs.approve_repair(
            root,
            _write(tmp_path / "approved-candidate.json", approved),
            _write(tmp_path / "repair-authority.json", approval),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=False,
        )


def test_repair_approval_binds_exact_scope_survives_currentness_and_is_consumed_once(
    tmp_path: Path,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, authority = _publish_and_approve_repair(
        tmp_path, root, proposed, approved, proposed_stage
    )
    assert authority["status"] == "approved"
    assert authority["target_lifecycle_changed_at"] == approved["case"]["lifecycle_changed_at"]
    duplicate = json.loads(json.dumps(approval))
    duplicate["approval_id"] = "duplicate-exact-repair-authority"
    with pytest.raises(fs.StateError, match="already has a different approval") as conflict:
        fs.approve_repair(
            root,
            _write(tmp_path / "duplicate-approved.json", approved),
            _write(tmp_path / "duplicate-approval.json", duplicate),
            "2026-07-11T08:38:30Z",
            interactive_confirmed=True,
        )
    assert conflict.value.code == "repair-approval-conflict"
    current = json.loads(json.dumps(approved))
    current["case"]["currentness_checked_at"] = "2026-07-11T08:38:30Z"
    current["control"]["semantic_digest"] = fs.semantic_digest(current["case"])
    staged = fs.stage_candidate(
        _write(tmp_path / "current-approved.json", current),
        root,
        "2026-07-11T08:39:00Z",
    )
    assert staged["repair_approval"] == {
        "approval_id": approval["approval_id"],
        "approval_digest": authority["approval_digest"],
    }
    consumption = fs._load_json(
        root / "repairs" / "consumptions" / f"{approval['approval_id']}.json"
    )
    assert consumption["stage_receipt_id"] == staged["receipt_id"]
    assert consumption["semantic_digest"] == fs._case_tuple(current)["semantic_digest"]
    assert consumption["repair_binding"] == {
        "active_repair_id": "R1",
        "repair_ids": ["R1"],
        "repair_identity_digest": fs._digest(
            {"repairs": fs._repair_identity_projection(current["case"]["repairs"])}
        ),
    }
    binding = fs._load_json(root / fs._repair_binding_relative(current["case"]["id"]))
    assert binding["target"] == fs._case_tuple(current)
    assert binding["repair_binding"] == consumption["repair_binding"]
    assert binding["consumption_digest"] == consumption["consumption_digest"]
    assert (
        fs.stage_candidate(
            _write(tmp_path / "current-approved.json", current),
            root,
            "2026-07-11T09:39:00Z",
        )
        == staged
    )
    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="already consumed") as used:
            fs._load_unconsumed_repair_approval(store, proposed, current, "2026-07-11T09:00:00Z")
    assert used.value.code == "repair-approval-used"


def test_consumed_repair_binding_rejects_replacement_supersession_and_later_install(
    tmp_path: Path,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    _publish_and_approve_repair(tmp_path, root, proposed, approved, proposed_stage)
    fs.stage_candidate(
        _write(tmp_path / "approved.json", approved),
        root,
        "2026-07-11T08:39:00Z",
    )

    replacement = json.loads(json.dumps(approved))
    replacement["case"]["revision"] += 1
    replacement["case"]["repairs"][0]["id"] = "R2"
    replacement["case"]["repairs"][0]["pull_request_url"] = (
        "https://github.com/Joey-Tools/example/pull/2"
    )
    replacement["control"]["semantic_digest"] = fs.semantic_digest(replacement["case"])
    with pytest.raises(fs.StateError, match="freezes every ordered repair identity") as replaced:
        fs.stage_candidate(
            _write(tmp_path / "replacement.json", replacement),
            root,
            "2026-07-11T09:00:00Z",
        )
    assert replaced.value.code == "consumed-repair-binding-change"

    superseded = json.loads(json.dumps(approved))
    superseded["case"]["revision"] += 1
    superseded["case"]["repairs"][0]["state"] = "superseded"
    superseded["case"]["repairs"].append(
        {
            "id": "R2",
            "repository": "Joey-Tools/example",
            "action": "amend",
            "state": "planned",
            "problem_statement": (
                "The proposed replacement changes the exact repair that Joey approved."
            ),
            "change_summary": "Replace the approved repair with a different amendment.",
            "pull_request_url": None,
            "commit": None,
            "commit_trailer": f"Friction-Case: {approved['case']['id']}",
            "installed_on": None,
            "removed_on": None,
            "replaces_repair_id": None,
        }
    )
    superseded["control"]["semantic_digest"] = fs.semantic_digest(superseded["case"])
    with pytest.raises(fs.StateError, match="freezes the repair list") as appended:
        fs.stage_candidate(
            _write(tmp_path / "superseded-r1.json", superseded),
            root,
            "2026-07-11T09:01:00Z",
        )
    assert appended.value.code == "consumed-repair-binding-change"

    implemented_r2 = json.loads(json.dumps(superseded))
    implemented_r2["case"]["status"] = "implemented"
    implemented_r2["case"]["lifecycle_changed_at"] = "2026-07-11T08:45:00Z"
    implemented_r2["case"]["repairs"][1].update(
        {
            "state": "merged",
            "pull_request_url": "https://github.com/Joey-Tools/example/pull/2",
            "commit": "b" * 40,
            "installed_on": "2026-07-11",
        }
    )
    implemented_r2["control"]["semantic_digest"] = fs.semantic_digest(implemented_r2["case"])
    with pytest.raises(fs.StateError, match="freezes the repair list") as installed:
        fs.stage_candidate(
            _write(tmp_path / "implemented-r2.json", implemented_r2),
            root,
            "2026-07-11T09:02:00Z",
        )
    assert installed.value.code == "consumed-repair-binding-change"
    persisted = fs._load_json(root / fs._case_relative_path(approved))
    assert persisted["case"] == approved["case"]


def test_consumed_repair_binding_allows_the_approved_repair_lifecycle(
    tmp_path: Path,
) -> None:
    proposed, approved, implemented, observing, closed = _repair_lifecycle_candidates()
    root, proposed_stage = _stage(tmp_path, proposed)
    _publish_and_approve_repair(tmp_path, root, proposed, approved, proposed_stage)
    fs.stage_candidate(
        _write(tmp_path / "approved.json", approved),
        root,
        "2026-07-11T08:39:00Z",
    )
    binding_path = root / fs._repair_binding_relative(approved["case"]["id"])
    binding_bytes = binding_path.read_bytes()

    for index, candidate in enumerate((implemented, observing, closed), start=2):
        receipt = fs.stage_candidate(
            _write(tmp_path / f"{candidate['case']['status']}.json", candidate),
            root,
            f"2026-07-11T09:0{index}:00Z",
        )
        assert receipt["action"] == "updated"
        assert binding_path.read_bytes() == binding_bytes
        assert fs._load_json(root / receipt["case_path"])["case"] == candidate["case"]


def test_repair_approval_rejects_forged_stale_and_unrelated_semantic_changes(
    tmp_path: Path,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path, root, proposed, approved, proposed_stage, persist=False
    )
    forged = json.loads(json.dumps(approval))
    forged["publication"]["closure_digest"] = "f" * 64
    with pytest.raises(fs.StateError, match="published closure"):
        fs.approve_repair(
            root,
            _write(tmp_path / "forged-candidate.json", approved),
            _write(tmp_path / "forged-approval.json", forged),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )

    unrelated = json.loads(json.dumps(approved))
    unrelated["case"]["title"] = "Unrelated semantic change hidden in repair approval"
    unrelated["control"]["semantic_digest"] = fs.semantic_digest(unrelated["case"])
    scoped = json.loads(json.dumps(approval))
    scoped["approval_id"] = "unrelated-scope"
    scoped["target"] = fs._case_tuple(unrelated)
    with pytest.raises(fs.StateError, match="cannot change evidence, scope") as scope_error:
        fs.approve_repair(
            root,
            _write(tmp_path / "unrelated.json", unrelated),
            _write(tmp_path / "unrelated-approval.json", scoped),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
    assert scope_error.value.code == "repair-approval-scope"

    stale = json.loads(json.dumps(approval))
    stale["approval_id"] = "stale-repair-approval"
    stale["expires_at"] = "2026-07-11T08:38:30Z"
    fs.approve_repair(
        root,
        _write(tmp_path / "stale-candidate.json", approved),
        _write(tmp_path / "stale-approval.json", stale),
        "2026-07-11T08:38:00Z",
        interactive_confirmed=True,
    )
    with pytest.raises(fs.StateError, match="remain unexpired") as expired:
        fs.stage_candidate(
            _write(tmp_path / "stale-target.json", approved),
            root,
            "2026-07-11T08:39:00Z",
        )
    assert expired.value.code == "repair-approval-clock-order"


@pytest.mark.parametrize(
    ("commit_kind", "error_code", "error_match"),
    [
        ("base", "ledger-commit-base", "must differ from the plan base SHA"),
        ("wrong-width", "ledger-commit-format", "plan base SHA object-ID width"),
    ],
)
def test_repair_approval_revalidates_legacy_published_commit_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    commit_kind: str,
    error_code: str,
    error_match: str,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    ledger_commit = "a" * 40 if commit_kind == "base" else "d" * 64
    commit_validator = fs._validate_published_ledger_commit
    monkeypatch.setattr(
        fs,
        "_validate_published_ledger_commit",
        lambda item, plan: None,
    )
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        approved,
        proposed_stage,
        approval_id=f"legacy-{commit_kind}-publication-authority",
        ledger_commit=ledger_commit,
        persist=False,
    )
    monkeypatch.setattr(fs, "_validate_published_ledger_commit", commit_validator)
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError, match=error_match) as raised:
        fs.approve_repair(
            root,
            _write(tmp_path / f"legacy-{commit_kind}-candidate.json", approved),
            _write(tmp_path / f"legacy-{commit_kind}-approval.json", approval),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )

    assert raised.value.code == error_code
    assert _persistent_identity_snapshot(root) == before
    assert not (root / "repairs" / "approvals" / f"{approval['approval_id']}.json").exists()


def test_repair_approval_revalidates_legacy_prepared_object_id_width_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    prepared_validator = fs._validate_prepared_entry

    def accept_legacy_entry(
        value: Any,
        index: int,
        plan_entry: dict[str, Any],
        *,
        plan_created_at: str,
        now: str,
    ) -> dict[str, Any]:
        del index, plan_entry, plan_created_at, now
        return value

    monkeypatch.setattr(
        fs,
        "_validate_prepared_entry",
        accept_legacy_entry,
    )
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        approved,
        proposed_stage,
        approval_id="legacy-wide-prepared-chain",
        prepared_commit_sha="d" * 64,
        persist=False,
    )
    monkeypatch.setattr(fs, "_validate_prepared_entry", prepared_validator)
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError, match="object-ID width") as raised:
        fs.approve_repair(
            root,
            _write(tmp_path / "legacy-wide-prepared-candidate.json", approved),
            _write(tmp_path / "legacy-wide-prepared-approval.json", approval),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )

    assert raised.value.code == "prepared-commit-format"
    assert _persistent_identity_snapshot(root) == before
    assert not (root / "repairs" / "approvals" / f"{approval['approval_id']}.json").exists()


@pytest.mark.parametrize("authority_state", ["fresh", "pending", "committed", "retired"])
def test_approve_repair_chain_revalidation_precedes_recovery_or_idempotent_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority_state: str,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    prepared_validator = fs._validate_prepared_entry

    def accept_legacy_entry(
        value: Any,
        index: int,
        plan_entry: dict[str, Any],
        *,
        plan_created_at: str,
        now: str,
    ) -> dict[str, Any]:
        del index, plan_entry, plan_created_at, now
        return value

    monkeypatch.setattr(fs, "_validate_prepared_entry", accept_legacy_entry)
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        approved,
        proposed_stage,
        approval_id=f"legacy-wide-{authority_state}-approve-wal",
        prepared_commit_sha="d" * 64,
        persist=False,
    )
    candidate_path = _write(tmp_path / f"{authority_state}-approved.json", approved)
    approval_path = _write(tmp_path / f"{authority_state}-approval.json", approval)
    approval_relative = Path("repairs") / "approvals" / f"{approval['approval_id']}.json"
    original_write = fs.StateStore.write_json

    if authority_state == "pending":

        def interrupt_approval(
            store: Any,
            relative: Path | str,
            value: dict[str, Any],
            *,
            immutable: bool = False,
            max_bytes: int | None = None,
        ) -> str:
            if Path(relative) == approval_relative:
                raise OSError("injected legacy pending approval")
            return original_write(
                store,
                relative,
                value,
                immutable=immutable,
                max_bytes=max_bytes,
            )

        monkeypatch.setattr(fs.StateStore, "write_json", interrupt_approval)
        with pytest.raises(OSError, match="legacy pending approval"):
            fs.approve_repair(
                root,
                candidate_path,
                approval_path,
                "2026-07-11T08:38:00Z",
                interactive_confirmed=True,
            )
        monkeypatch.setattr(fs.StateStore, "write_json", original_write)
    elif authority_state in {"committed", "retired"}:
        fs.approve_repair(
            root,
            candidate_path,
            approval_path,
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
        if authority_state == "retired":
            with fs._state_lock(root, create=False) as store:
                fs._recover_pending_wal(store, compact_committed=True)

    monkeypatch.setattr(fs, "_validate_prepared_entry", prepared_validator)
    pending_intent, _ = _copy_pending_stage_intent(
        tmp_path / f"{authority_state}-unrelated-pending",
        root,
        valid_for_target=True,
    )
    pending = fs._load_json(pending_intent)
    pending_candidate = root / next(
        write["path"] for write in pending["writes"] if isinstance(write["after"].get("case"), dict)
    )
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError, match="object-ID width") as raised:
        if authority_state == "fresh":
            fs.approve_repair(
                root,
                candidate_path,
                approval_path,
                "2026-07-11T08:39:00Z",
                interactive_confirmed=True,
            )
        else:
            with fs._state_lock(root, create=False) as store:
                if authority_state == "retired":
                    fs._require_committed_transaction(
                        store,
                        "approve-repair",
                        approval["approval_id"],
                        recover_publication=False,
                    )
                else:
                    fs._recover_pending_wal(store)

    assert raised.value.code == "prepared-commit-format"
    assert _persistent_identity_snapshot(root) == before
    assert not pending_candidate.exists()


def test_pending_approve_repair_rejects_extra_write_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        approved,
        proposed_stage,
        approval_id="approve-extra-write",
        persist=False,
    )
    approval_relative = Path("repairs") / "approvals" / f"{approval['approval_id']}.json"
    original_write = fs.StateStore.write_json

    def interrupt_approval(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        if Path(relative) == approval_relative:
            raise OSError("injected approve extra-write intent")
        return original_write(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )

    monkeypatch.setattr(fs.StateStore, "write_json", interrupt_approval)
    with pytest.raises(OSError, match="approve extra-write intent"):
        fs.approve_repair(
            root,
            _write(tmp_path / "approve-extra-candidate.json", approved),
            _write(tmp_path / "approve-extra-approval.json", approval),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)

    intent_relative, commit_relative = fs._wal_paths(
        "approve-repair",
        approval["approval_id"],
    )
    intent_path = root / intent_relative
    intent = fs._load_json(intent_path)
    extra_after = {"version": fs.VERSION, "kind": "unexpected-approval-side-effect"}
    intent["writes"].append(
        {
            "scope": "state",
            "path": "repairs/unexpected.json",
            "before_sha256": None,
            "after_sha256": hashlib.sha256(fs._canonical_bytes(extra_after)).hexdigest(),
            "after": extra_after,
            "immutable": False,
        }
    )
    intent_body = {key: value for key, value in intent.items() if key != "intent_digest"}
    intent["intent_digest"] = fs._digest(intent_body)
    intent_path.write_bytes(fs._canonical_bytes(intent))
    before = _persistent_identity_snapshot(root)

    with fs._state_lock(root, create=False) as store:
        with pytest.raises(fs.StateError, match="exactly two authority writes") as raised:
            fs._recover_pending_wal(store)

    assert raised.value.code == "invalid-wal"
    assert _persistent_identity_snapshot(root) == before
    assert not (root / commit_relative).exists()
    assert not (root / "repairs" / "unexpected.json").exists()


def test_retired_approve_repair_rejects_extra_projection_without_mutation(
    tmp_path: Path,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        approved,
        proposed_stage,
        approval_id="retired-extra-approval-write",
    )
    with fs._state_lock(root, create=False) as store:
        fs._recover_pending_wal(store, compact_committed=True)

    checkpoint_path = root / fs._wal_history_path(
        "approve-repair",
        approval["approval_id"],
    )
    checkpoint = fs._load_json(checkpoint_path)
    checkpoint["after_images"].append(
        {
            "scope": "state",
            "path": "repairs/unexpected-retired.json",
            "before_sha256": None,
            "after_sha256": "e" * 64,
            "immutable": False,
        }
    )
    _rewrite_wal_checkpoint_chain(root, checkpoint_path, checkpoint)
    candidate_path = _write(tmp_path / "retired-extra-approved.json", approved)
    approval_path = _write(tmp_path / "retired-extra-approval.json", approval)

    before_retry = _persistent_identity_snapshot(root)
    with pytest.raises(fs.StateError, match="state after-images differ") as retry:
        fs.approve_repair(
            root,
            candidate_path,
            approval_path,
            "2026-07-11T08:39:00Z",
            interactive_confirmed=True,
        )
    assert retry.value.code == "invalid-wal-history"
    assert _persistent_identity_snapshot(root) == before_retry

    before_audit = _persistent_identity_snapshot(root)
    with pytest.raises(fs.StateError, match="state after-images differ") as audit:
        fs.audit_wal_history(root)
    assert audit.value.code == "invalid-wal-history"
    assert _persistent_identity_snapshot(root) == before_audit


def test_repair_approval_requires_strict_post_closure_time_and_next_revision(
    tmp_path: Path,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path, root, proposed, approved, proposed_stage, persist=False
    )

    not_later = json.loads(json.dumps(approval))
    not_later["approval_id"] = "not-strictly-after-closure"
    not_later["interaction"]["approved_at"] = "2026-07-11T08:36:00Z"
    not_later_candidate = json.loads(json.dumps(approved))
    not_later_candidate["case"]["lifecycle_changed_at"] = "2026-07-11T08:36:00Z"
    not_later_candidate["control"]["semantic_digest"] = fs.semantic_digest(
        not_later_candidate["case"]
    )
    not_later["target"] = fs._case_tuple(not_later_candidate)
    with pytest.raises(fs.StateError, match="follow merge/closure") as clock:
        fs.approve_repair(
            root,
            _write(tmp_path / "not-later-candidate.json", not_later_candidate),
            _write(tmp_path / "not-later-approval.json", not_later),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
    assert clock.value.code == "repair-approval-clock-order"

    skipped_revision = json.loads(json.dumps(approved))
    skipped_revision["case"]["revision"] += 1
    skipped_revision["control"]["semantic_digest"] = fs.semantic_digest(skipped_revision["case"])
    wrong_revision = json.loads(json.dumps(approval))
    wrong_revision["approval_id"] = "skipped-repair-revision"
    wrong_revision["target"] = fs._case_tuple(skipped_revision)
    with pytest.raises(fs.StateError, match="source/target tuple is inconsistent") as revision:
        fs.approve_repair(
            root,
            _write(tmp_path / "skipped-revision-candidate.json", skipped_revision),
            _write(tmp_path / "skipped-revision-approval.json", wrong_revision),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
    assert revision.value.code == "invalid-repair-approval"


def test_repair_approval_creation_binds_exact_lifecycle_decision_time_without_mutation(
    tmp_path: Path,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path, root, proposed, approved, proposed_stage, persist=False
    )
    mismatched = json.loads(json.dumps(approved))
    mismatched["case"]["lifecycle_changed_at"] = "2026-07-11T08:36:59Z"
    mismatched["control"]["semantic_digest"] = fs.semantic_digest(mismatched["case"])
    mismatched_approval = json.loads(json.dumps(approval))
    mismatched_approval["approval_id"] = "mismatched-lifecycle-authority"
    mismatched_approval["target"] = fs._case_tuple(mismatched)
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError, match="must equal repair approved_at") as raised:
        fs.approve_repair(
            root,
            _write(tmp_path / "mismatched-lifecycle-candidate.json", mismatched),
            _write(tmp_path / "mismatched-lifecycle-approval.json", mismatched_approval),
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )

    assert raised.value.code == "repair-approval-lifecycle-mismatch"
    assert _persistent_identity_snapshot(root) == before
    approval_key = fs._repair_approval_index_key(
        mismatched_approval["source"], mismatched_approval["target"]
    )
    assert not (
        root / "repairs" / "approvals" / f"{mismatched_approval['approval_id']}.json"
    ).exists()
    assert not (root / "repairs" / "approval-index" / f"{approval_key}.json").exists()
    intent_relative, commit_relative = fs._wal_paths(
        "approve-repair", mismatched_approval["approval_id"]
    )
    assert not (root / intent_relative).exists()
    assert not (root / commit_relative).exists()


def test_legacy_repair_approval_result_replays_active_and_retired_without_new_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        approved,
        proposed_stage,
        approval_id="legacy-result-shape",
        persist=False,
    )
    candidate_path = _write(tmp_path / "legacy-result-candidate.json", approved)
    approval_path = _write(tmp_path / "legacy-result-approval.json", approval)
    first = _persist_legacy_repair_approval_result(
        root,
        candidate_path,
        approval_path,
        monkeypatch,
    )
    before_active_retry = _persistent_identity_snapshot(root)
    active_retry = fs.approve_repair(
        root,
        candidate_path,
        approval_path,
        "2026-07-11T08:39:00Z",
        interactive_confirmed=True,
    )
    assert active_retry == first
    assert "target_lifecycle_changed_at" not in active_retry
    assert _persistent_identity_snapshot(root) == before_active_retry

    with fs._state_lock(root, create=False) as store:
        fs._recover_pending_wal(store, compact_committed=True)
    checkpoint_path = root / fs._wal_history_path("approve-repair", approval["approval_id"])
    assert checkpoint_path.exists()
    checkpoint = fs._load_json(checkpoint_path)
    assert checkpoint["result_digest"] == fs._digest(first)
    retired_retry = fs.approve_repair(
        root,
        candidate_path,
        approval_path,
        "2026-07-11T08:40:00Z",
        interactive_confirmed=True,
    )
    assert retired_retry == first
    assert "target_lifecycle_changed_at" not in retired_retry
    assert fs.audit_wal_history(root)["status"] == "clean"


@pytest.mark.parametrize("authority_state", ["pending", "committed", "retired"])
def test_approve_repair_exact_retry_uses_first_writer_time_after_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority_state: str,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        approved,
        proposed_stage,
        approval_id=f"expired-retry-{authority_state}",
        expires_at="2026-07-11T08:38:30Z",
        persist=False,
    )
    candidate_path = _write(tmp_path / f"expired-retry-{authority_state}-candidate.json", approved)
    approval_path = _write(tmp_path / f"expired-retry-{authority_state}-approval.json", approval)
    approval_relative = Path("repairs") / "approvals" / f"{approval['approval_id']}.json"
    original_write = fs.StateStore.write_json

    if authority_state == "pending":

        def interrupt_approval(
            store: Any,
            relative: Path | str,
            value: dict[str, Any],
            *,
            immutable: bool = False,
            max_bytes: int | None = None,
        ) -> str:
            if Path(relative) == approval_relative:
                raise OSError("injected expired retry interruption")
            return original_write(
                store,
                relative,
                value,
                immutable=immutable,
                max_bytes=max_bytes,
            )

        monkeypatch.setattr(fs.StateStore, "write_json", interrupt_approval)
        with pytest.raises(OSError, match="expired retry interruption"):
            fs.approve_repair(
                root,
                candidate_path,
                approval_path,
                "2026-07-11T08:38:00Z",
                interactive_confirmed=True,
            )
        monkeypatch.setattr(fs.StateStore, "write_json", original_write)
        intent_relative, _ = fs._wal_paths("approve-repair", approval["approval_id"])
        expected = fs._load_json(root / intent_relative)["result"]
    else:
        expected = fs.approve_repair(
            root,
            candidate_path,
            approval_path,
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
        if authority_state == "retired":
            with fs._state_lock(root, create=False) as store:
                fs._recover_pending_wal(store, compact_committed=True)

    before_retry = _persistent_identity_snapshot(root)
    assert (
        fs.approve_repair(
            root,
            candidate_path,
            approval_path,
            "2026-07-11T08:39:00Z",
            interactive_confirmed=True,
        )
        == expected
    )
    if authority_state != "pending":
        assert _persistent_identity_snapshot(root) == before_retry

    before_idempotent_retry = _persistent_identity_snapshot(root)
    assert (
        fs.approve_repair(
            root,
            candidate_path,
            approval_path,
            "2026-07-11T08:40:00Z",
            interactive_confirmed=True,
        )
        == expected
    )
    assert _persistent_identity_snapshot(root) == before_idempotent_retry


def test_new_repair_approval_still_rejects_expired_window_without_mutation(
    tmp_path: Path,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        approved,
        proposed_stage,
        approval_id="new-expired-approval",
        expires_at="2026-07-11T08:38:30Z",
        persist=False,
    )
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError, match="remain unexpired") as raised:
        fs.approve_repair(
            root,
            _write(tmp_path / "new-expired-candidate.json", approved),
            _write(tmp_path / "new-expired-approval.json", approval),
            "2026-07-11T08:39:00Z",
            interactive_confirmed=True,
        )

    assert raised.value.code == "repair-approval-clock-order"
    assert _persistent_identity_snapshot(root) == before


def test_pending_approve_repair_rejects_expired_first_writer_time_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        approved,
        proposed_stage,
        approval_id="tampered-expired-first-writer",
        expires_at="2026-07-11T08:38:30Z",
        persist=False,
    )
    candidate_path = _write(tmp_path / "tampered-expired-candidate.json", approved)
    approval_path = _write(tmp_path / "tampered-expired-approval.json", approval)
    approval_relative = Path("repairs") / "approvals" / f"{approval['approval_id']}.json"
    original_write = fs.StateStore.write_json

    def interrupt_approval(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        if Path(relative) == approval_relative:
            raise OSError("injected captured-at interruption")
        return original_write(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )

    monkeypatch.setattr(fs.StateStore, "write_json", interrupt_approval)
    with pytest.raises(OSError, match="captured-at interruption"):
        fs.approve_repair(
            root,
            candidate_path,
            approval_path,
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)
    intent_relative, commit_relative = fs._wal_paths("approve-repair", approval["approval_id"])
    intent_path = root / intent_relative
    intent = fs._load_json(intent_path)
    intent["captured_at"] = approval["expires_at"]
    intent_body = {key: value for key, value in intent.items() if key != "intent_digest"}
    intent["intent_digest"] = fs._digest(intent_body)
    intent_path.write_bytes(fs._canonical_bytes(intent))
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError, match="remain unexpired") as raised:
        fs.approve_repair(
            root,
            candidate_path,
            approval_path,
            "2026-07-11T08:38:15Z",
            interactive_confirmed=True,
        )

    assert raised.value.code == "repair-approval-clock-order"
    assert _persistent_identity_snapshot(root) == before
    assert not (root / approval_relative).exists()
    assert not (root / commit_relative).exists()


def test_pending_approve_repair_wal_revalidates_lifecycle_time_before_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    mismatched = json.loads(json.dumps(approved))
    mismatched["case"]["lifecycle_changed_at"] = "2026-07-11T08:36:59Z"
    mismatched["control"]["semantic_digest"] = fs.semantic_digest(mismatched["case"])
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path,
        root,
        proposed,
        mismatched,
        proposed_stage,
        approval_id="pending-mismatched-approval-authority",
        persist=False,
    )
    candidate_path = _write(tmp_path / "pending-mismatched-approval-candidate.json", mismatched)
    approval_path = _write(tmp_path / "pending-mismatched-approval.json", approval)
    approval_relative = Path("repairs") / "approvals" / f"{approval['approval_id']}.json"
    approval_key = fs._repair_approval_index_key(approval["source"], approval["target"])
    index_relative = Path("repairs") / "approval-index" / f"{approval_key}.json"
    lifecycle_validator = fs._validate_repair_approval_lifecycle_time
    intent_validator = fs._validate_approve_repair_intent_lifecycle
    original_write = fs.StateStore.write_json

    def interrupt_approval(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        if Path(relative) == approval_relative:
            raise OSError("injected mismatched repair approval interruption")
        return original_write(store, relative, value, immutable=immutable)

    monkeypatch.setattr(
        fs,
        "_validate_repair_approval_lifecycle_time",
        lambda approval_value, target: None,
    )
    monkeypatch.setattr(
        fs,
        "_validate_approve_repair_intent_lifecycle",
        lambda store, intent, **kwargs: None,
    )
    monkeypatch.setattr(fs.StateStore, "write_json", interrupt_approval)
    with pytest.raises(OSError, match="injected mismatched repair approval interruption"):
        fs.approve_repair(
            root,
            candidate_path,
            approval_path,
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
    monkeypatch.setattr(
        fs,
        "_validate_repair_approval_lifecycle_time",
        lifecycle_validator,
    )
    monkeypatch.setattr(fs, "_validate_approve_repair_intent_lifecycle", intent_validator)
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)

    intent_relative, commit_relative = fs._wal_paths("approve-repair", approval["approval_id"])
    assert (root / intent_relative).exists()
    assert not (root / commit_relative).exists()
    assert not (root / approval_relative).exists()
    assert not (root / index_relative).exists()
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError, match="must equal repair approved_at") as raised:
        fs.approve_repair(
            root,
            candidate_path,
            approval_path,
            "2026-07-11T08:39:00Z",
            interactive_confirmed=True,
        )

    assert raised.value.code == "repair-approval-lifecycle-mismatch"
    assert _persistent_identity_snapshot(root) == before
    assert not (root / approval_relative).exists()
    assert not (root / index_relative).exists()


def test_stage_revalidates_legacy_repair_approval_lifecycle_time_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    mismatched = json.loads(json.dumps(approved))
    mismatched["case"]["lifecycle_changed_at"] = "2026-07-11T08:36:59Z"
    mismatched["control"]["semantic_digest"] = fs.semantic_digest(mismatched["case"])
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _persist_legacy_mismatched_repair_approval(
        tmp_path,
        root,
        proposed,
        mismatched,
        proposed_stage,
        monkeypatch,
        approval_id="legacy-mismatched-lifecycle-authority",
    )
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError, match="must equal repair approved_at") as raised:
        fs.stage_candidate(
            _write(tmp_path / "legacy-mismatched-lifecycle-target.json", mismatched),
            root,
            "2026-07-11T08:39:00Z",
        )

    assert raised.value.code == "repair-approval-lifecycle-mismatch"
    assert _persistent_identity_snapshot(root) == before
    assert not (root / "repairs" / "consumptions" / f"{approval['approval_id']}.json").exists()
    assert fs._load_json(root / fs._case_relative_path(proposed))["case"]["status"] == "proposed"


def test_pending_stage_wal_revalidates_repair_approval_lifecycle_before_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    mismatched = json.loads(json.dumps(approved))
    mismatched["case"]["lifecycle_changed_at"] = "2026-07-11T08:36:59Z"
    mismatched["control"]["semantic_digest"] = fs.semantic_digest(mismatched["case"])
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _persist_legacy_mismatched_repair_approval(
        tmp_path,
        root,
        proposed,
        mismatched,
        proposed_stage,
        monkeypatch,
        approval_id="pending-mismatched-lifecycle-authority",
    )
    lifecycle_validator = fs._validate_repair_approval_lifecycle_time
    monkeypatch.setattr(
        fs,
        "_validate_repair_approval_lifecycle_time",
        lambda approval_value, target: None,
    )
    consumption_relative = Path("repairs") / "consumptions" / f"{approval['approval_id']}.json"
    binding_relative = fs._repair_binding_relative(proposed["case"]["id"])
    original_write = fs.StateStore.write_json
    receipts_before = set((root / "receipts" / "stage").glob("*.json"))

    def interrupt_consumption(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
    ) -> str:
        if Path(relative) == consumption_relative:
            raise OSError("injected mismatched approval consumption interruption")
        return original_write(store, relative, value, immutable=immutable)

    target_path = _write(tmp_path / "pending-mismatched-lifecycle-target.json", mismatched)
    monkeypatch.setattr(fs.StateStore, "write_json", interrupt_consumption)
    with pytest.raises(OSError, match="injected mismatched approval consumption interruption"):
        fs.stage_candidate(target_path, root, "2026-07-11T08:39:00Z")
    monkeypatch.setattr(
        fs,
        "_validate_repair_approval_lifecycle_time",
        lifecycle_validator,
    )
    monkeypatch.setattr(fs.StateStore, "write_json", original_write)

    pending_intents = [
        path
        for path in (root / "wal" / "stage").glob("*.intent.json")
        if not path.with_name(path.name.replace(".intent.json", ".commit.json")).exists()
    ]
    assert len(pending_intents) == 1
    assert not (root / consumption_relative).exists()
    assert not (root / binding_relative).exists()
    assert set((root / "receipts" / "stage").glob("*.json")) == receipts_before
    before = _persistent_identity_snapshot(root)

    with pytest.raises(fs.StateError, match="must equal repair approved_at") as raised:
        fs.stage_candidate(target_path, root, "2026-07-11T08:40:00Z")

    assert raised.value.code == "repair-approval-lifecycle-mismatch"
    assert _persistent_identity_snapshot(root) == before
    assert not (root / consumption_relative).exists()
    assert not (root / binding_relative).exists()
    assert fs._load_json(root / fs._case_relative_path(proposed))["case"]["status"] == "proposed"


def test_repair_approval_consumption_recovers_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lifecycle = _repair_lifecycle_candidates()
    proposed, approved = lifecycle[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(tmp_path, root, proposed, approved, proposed_stage)
    case_relative = fs._case_relative_path(approved)
    original = fs.StateStore.write_json
    interrupted = False

    def interrupt_case(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        nonlocal interrupted
        if not interrupted and Path(relative) == case_relative:
            interrupted = True
            raise OSError("injected repair stage interruption")
        return original(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )

    monkeypatch.setattr(fs.StateStore, "write_json", interrupt_case)
    target_path = _write(tmp_path / "recover-approved.json", approved)
    with pytest.raises(OSError, match="injected repair stage interruption"):
        fs.stage_candidate(target_path, root, "2026-07-11T08:39:00Z")
    monkeypatch.setattr(fs.StateStore, "write_json", original)
    recovered = fs.stage_candidate(target_path, root, "2026-07-11T08:40:00Z")
    assert recovered["repair_approval"]["approval_id"] == approval["approval_id"]
    assert fs._load_json(root / case_relative)["case"]["status"] == "approved"
    assert (root / "repairs" / "consumptions" / f"{approval['approval_id']}.json").exists()
    binding_path = root / fs._repair_binding_relative(approved["case"]["id"])
    binding_bytes = binding_path.read_bytes()
    with fs._state_lock(root, create=False) as store:
        binding = fs._load_active_repair_binding(store, approved["case"]["id"])
    assert binding is not None
    assert binding["repair_binding"]["active_repair_id"] == "R1"

    implemented = lifecycle[2]
    implemented_path = _write(tmp_path / "recover-implemented.json", implemented)
    implemented_receipt = fs.stage_candidate(
        implemented_path,
        root,
        "2026-07-11T09:02:00Z",
    )
    assert fs.stage_candidate(implemented_path, root, "2026-07-11T10:02:00Z") == implemented_receipt
    assert binding_path.read_bytes() == binding_bytes


def test_repair_approval_authority_recovers_before_becoming_usable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proposed, approved = _repair_lifecycle_candidates()[:2]
    root, proposed_stage = _stage(tmp_path, proposed)
    approval, _ = _publish_and_approve_repair(
        tmp_path, root, proposed, approved, proposed_stage, persist=False
    )
    approval_key = fs._repair_approval_index_key(approval["source"], approval["target"])
    index_relative = Path("repairs") / "approval-index" / f"{approval_key}.json"
    original = fs.StateStore.write_json
    interrupted = False

    def interrupt_index(
        store: Any,
        relative: Path | str,
        value: dict[str, Any],
        *,
        immutable: bool = False,
        max_bytes: int | None = None,
    ) -> str:
        nonlocal interrupted
        if not interrupted and Path(relative) == index_relative:
            interrupted = True
            raise OSError("injected repair authority interruption")
        return original(
            store,
            relative,
            value,
            immutable=immutable,
            max_bytes=max_bytes,
        )

    candidate_path = _write(tmp_path / "authority-approved.json", approved)
    approval_path = _write(tmp_path / "authority-receipt.json", approval)
    monkeypatch.setattr(fs.StateStore, "write_json", interrupt_index)
    with pytest.raises(OSError, match="injected repair authority interruption"):
        fs.approve_repair(
            root,
            candidate_path,
            approval_path,
            "2026-07-11T08:38:00Z",
            interactive_confirmed=True,
        )
    monkeypatch.setattr(fs.StateStore, "write_json", original)

    recovered = fs.approve_repair(
        root,
        candidate_path,
        approval_path,
        "2026-07-11T08:39:00Z",
        interactive_confirmed=True,
    )
    assert recovered["approval_id"] == approval["approval_id"]
    assert recovered["target_lifecycle_changed_at"] == approved["case"]["lifecycle_changed_at"]
    assert (root / index_relative).exists()
    _, commit_relative = fs._wal_paths("approve-repair", approval["approval_id"])
    assert (root / commit_relative).exists()


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


def test_approve_repair_cli_requires_explicit_interactive_confirmation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = fs.main(
        [
            "approve-repair",
            "--state-root",
            str(tmp_path / "state"),
            "--candidate",
            str(tmp_path / "candidate.json"),
            "--approval",
            str(tmp_path / "approval.json"),
            "--now",
            "2026-07-11T08:38:00Z",
        ]
    )
    lines = capsys.readouterr().out.splitlines()
    assert code == 2
    assert len(lines) == 1
    error = json.loads(lines[0])
    assert error["status"] == "error"
    assert error["code"] == "invalid-command-line"
    assert "--confirm-interactive-joey-decision" in error["message"]
    assert not (tmp_path / "state").exists()


def test_cli_advertises_every_control_transition() -> None:
    choices = fs._parser()._subparsers._group_actions[0].choices
    assert set(choices) == {
        "new-id",
        "digest",
        "validate",
        "stage",
        "approve-repair",
        "transition-dormant",
        "complete-audit",
        "selection-preflight",
        "weekly-plan",
        "finalize-publication",
        "close-publication",
        "audit-wal-history",
    }
