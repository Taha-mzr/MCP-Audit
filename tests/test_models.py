import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_audit.models import (
    DISCLAIMER,
    INDEPENDENT_SOURCES,
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
    f = finding(evidence=[ev(EvidenceSource.SERVER_CLAIM), ev(EvidenceSource.RETURNED_CONTENT)])
    assert [e.source for e in f.evidence] == ["server_claim", "returned_content"]


@pytest.mark.parametrize(
    "access", [ObservedAccess.NONE, ObservedAccess.METADATA, ObservedAccess.OPEN_FAILED]
)
def test_attempt_without_proven_access_cannot_be_confirmed(access: ObservedAccess) -> None:
    # EACCES/EPERM on open shows the server did not stop the request, not that it read anything.
    with pytest.raises(ValidationError, match="proven read or write"):
        finding(evidence=[ev(EvidenceSource.SYSCALL_TRACE)], observed_access=access)


@pytest.mark.parametrize(
    ("access", "proof"),
    [
        (ObservedAccess.WRITE, EvidenceSource.DISK_SNAPSHOT),
        (ObservedAccess.READ_RETURNED, EvidenceSource.RETURNED_CONTENT),
        (ObservedAccess.READ_NOT_RETURNED, EvidenceSource.SYSCALL_TRACE),
    ],
)
def test_each_proven_access_is_confirmed_by_its_own_evidence(
    access: ObservedAccess, proof: EvidenceSource
) -> None:
    assert finding(evidence=[ev(proof)], observed_access=access).observed_access is access
    others = [ev(s) for s in INDEPENDENT_SOURCES if s is not proof]
    with pytest.raises(ValidationError, match="only proven by"):
        finding(evidence=others, observed_access=access)


def test_write_is_not_proven_by_a_returned_read() -> None:
    # The canary coming back shows a read; only the disk shows that a file was written.
    with pytest.raises(ValidationError, match="only proven by disk_snapshot"):
        finding(
            evidence=[ev(EvidenceSource.RETURNED_CONTENT)], observed_access=ObservedAccess.WRITE
        )


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
    static = finding(
        status=Status.NEEDS_REVIEW,
        evidence=[ev(EvidenceSource.CONFIG)],
        kind=FindingKind.CONFIG_GAP,
    )
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


def test_confirmed_lab_finding_states_observed_access() -> None:
    with pytest.raises(ValidationError, match="states observed_access"):
        LabSection(findings=[finding(observed_access=None)])


def test_lab_hint_may_omit_observed_access() -> None:
    hint = finding(status=Status.NEEDS_REVIEW, kind=FindingKind.HINT, observed_access=None)
    assert LabSection(findings=[hint]).findings == [hint]


# --- A check cannot pass and be confirmed at once ------------------------------------


@pytest.mark.parametrize("status", [Status.PASSED, Status.PASSED_LIMITED])
def test_lab_check_cannot_pass_with_a_confirmed_finding(status: Status) -> None:
    run = CheckRun(check_id="D1", server="filesystem", status=status, reason="no trace")
    with pytest.raises(ValidationError, match="confirmed finding"):
        LabSection(checks=[run], findings=[finding()])


def test_static_check_cannot_pass_with_a_confirmed_finding() -> None:
    c1 = finding(
        check_id="C1",
        kind=FindingKind.CONFIG_GAP,
        evidence=[ev(EvidenceSource.CONFIG)],
        observed_access=None,
    )
    run = CheckRun(check_id="C1", server="filesystem", status=Status.PASSED)
    with pytest.raises(ValidationError, match="confirmed finding"):
        RealConfigSection(checks=[run], findings=[c1])


def test_same_check_may_pass_on_another_server() -> None:
    run = CheckRun(check_id="D1", server="other", status=Status.PASSED)
    assert LabSection(checks=[run], findings=[finding()]).checks == [run]


# --- Report --------------------------------------------------------------------------


def make_report() -> Report:
    return Report(
        tool_version="0.1.0",
        generated_at=datetime(2026, 10, 28, tzinfo=UTC),
        owasp_mcp_top10_version="2025",
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


def test_owasp_tags_need_the_top10_edition() -> None:
    data = json.loads(make_report().model_dump_json())
    data["owasp_mcp_top10_version"] = None
    with pytest.raises(ValidationError, match="owasp_mcp_top10_version"):
        Report.model_validate(data)


def test_committed_schema_matches_the_model() -> None:
    # A schema change must be deliberate: regenerate the file (see models.py) and review the diff.
    assert json.loads(SCHEMA_FILE.read_text()) == report_json_schema()
