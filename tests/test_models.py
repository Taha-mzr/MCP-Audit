import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_audit.models import (
    DISCLAIMER,
    CheckRun,
    Evidence,
    EvidenceSource,
    Finding,
    FindingKind,
    LabSection,
    ObservedAccess,
    RealConfigSection,
    Report,
    Severity,
    Status,
    report_json_schema,
)

SCHEMA_FILE = Path(__file__).parents[1] / "schema" / "report.schema.json"


def ev(source: EvidenceSource, summary: str = "observed") -> Evidence:
    return Evidence(source=source, summary=summary)


def finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "check_id": "D1",
        "server": "filesystem",
        "title": "Read outside the allowed directory via a symlink",
        "status": Status.CONFIRMED,
        "kind": FindingKind.IMPLEMENTATION_DEFECT,
        "severity": Severity.HIGH,
        "severity_rationale": "Any file readable by the server's user is exposed.",
        "owasp": ["MCP02"],
        "evidence": [ev(EvidenceSource.RETURNED_CONTENT)],
        "observed_access": ObservedAccess.READ_RETURNED,
    }
    return Finding(**{**fields, **overrides})


# --- What may be CONFIRMED -------------------------------------------------------


def test_confirmed_with_independent_evidence_is_accepted() -> None:
    assert finding().status is Status.CONFIRMED


def test_server_claim_alone_never_confirms() -> None:
    with pytest.raises(ValidationError, match="independent of the server"):
        finding(evidence=[ev(EvidenceSource.SERVER_CLAIM, "server said: wrote file")])


def test_server_claim_is_kept_as_context_next_to_real_evidence() -> None:
    f = finding(evidence=[ev(EvidenceSource.SERVER_CLAIM), ev(EvidenceSource.DISK_SNAPSHOT)])
    assert [e.source for e in f.evidence] == ["server_claim", "disk_snapshot"]


@pytest.mark.parametrize(
    "access", [ObservedAccess.NONE, ObservedAccess.METADATA, ObservedAccess.OPEN_FAILED]
)
def test_attempt_without_proven_access_cannot_be_confirmed(access: ObservedAccess) -> None:
    # EACCES/EPERM on open shows the server did not stop the request, not that it read anything.
    with pytest.raises(ValidationError, match="proven read or write"):
        finding(evidence=[ev(EvidenceSource.SYSCALL_TRACE)], observed_access=access)


def test_failed_open_is_reported_as_needs_review() -> None:
    f = finding(
        status=Status.NEEDS_REVIEW,
        evidence=[ev(EvidenceSource.SYSCALL_TRACE, "openat(...) = -1 EACCES")],
        observed_access=ObservedAccess.OPEN_FAILED,
    )
    assert f.status is Status.NEEDS_REVIEW


@pytest.mark.parametrize("status", [Status.PASSED, Status.INCONCLUSIVE, Status.NOT_RUN])
def test_non_problem_outcomes_are_check_runs_not_findings(status: Status) -> None:
    with pytest.raises(ValidationError, match="confirmed or needs review"):
        finding(status=status)


def test_severity_must_be_justified() -> None:
    with pytest.raises(ValidationError):
        finding(severity_rationale="")


def test_owasp_tags_are_checked() -> None:
    with pytest.raises(ValidationError, match="OWASP"):
        finding(owasp=["A01"])


def test_exported_artifact_must_be_hashed() -> None:
    with pytest.raises(ValidationError, match="sha256"):
        Evidence(source=EvidenceSource.SYSCALL_TRACE, summary="trace", artifact="trace.log")


# --- Check outcomes ----------------------------------------------------------------


@pytest.mark.parametrize("status", [Status.NOT_RUN, Status.INCONCLUSIVE, Status.PASSED_LIMITED])
def test_outcomes_without_full_evidence_need_a_reason(status: Status) -> None:
    with pytest.raises(ValidationError, match="needs a reason"):
        CheckRun(check_id="D1", server="filesystem", status=status)
    run = CheckRun(check_id="D1", server="filesystem", status=status, reason="Docker not found")
    assert run.reason == "Docker not found"


# --- Separation between the real configuration and the lab -------------------------


def test_static_section_rejects_lab_evidence() -> None:
    with pytest.raises(ValidationError, match="only cite the configuration"):
        RealConfigSection(findings=[finding(observed_access=None)])


def test_static_section_rejects_observed_access() -> None:
    static = finding(evidence=[ev(EvidenceSource.CONFIG)], kind=FindingKind.CONFIG_GAP)
    with pytest.raises(ValidationError, match="static analysis"):
        RealConfigSection(findings=[static])


def test_static_finding_in_static_section() -> None:
    c1 = finding(
        check_id="C1",
        kind=FindingKind.CONFIG_GAP,
        evidence=[ev(EvidenceSource.CONFIG, 'args: ["/Users/taha"]')],
        observed_access=None,
    )
    assert RealConfigSection(findings=[c1]).findings == [c1]


# --- Report --------------------------------------------------------------------------


def make_report() -> Report:
    return Report(
        tool_version="0.1.0",
        generated_at=datetime(2026, 10, 28, tzinfo=UTC),
        real_config=RealConfigSection(
            checks=[CheckRun(check_id="C1", server="filesystem", status=Status.PASSED)]
        ),
        lab_reproduction=LabSection(
            versions_tested={"server-filesystem": "2025.3.28"}, findings=[finding()]
        ),
    )


def test_report_round_trips_through_json() -> None:
    report = make_report()
    assert Report.model_validate_json(report.model_dump_json()) == report


def test_disclaimer_cannot_be_changed() -> None:
    data = json.loads(make_report().model_dump_json())
    assert data["disclaimer"] == DISCLAIMER
    data["disclaimer"] = "The server is secure."
    with pytest.raises(ValidationError):
        Report.model_validate(data)


def test_unknown_fields_are_rejected() -> None:
    data = json.loads(make_report().model_dump_json())
    data["secure"] = True
    with pytest.raises(ValidationError):
        Report.model_validate(data)


def test_committed_schema_matches_the_model() -> None:
    # A schema change must be deliberate: regenerate the file (see models.py) and review the diff.
    assert json.loads(SCHEMA_FILE.read_text()) == report_json_schema()
