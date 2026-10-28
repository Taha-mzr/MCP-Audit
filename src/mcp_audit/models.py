"""Data model of an audit report.

Everything that ends up in the JSON report is defined here, so the report format can be
reviewed in one file. Enum values are stable English identifiers; human-readable labels
(French and English) belong to the renderers.

Rules that make a report trustworthy are enforced here, at construction time, rather than
left to each check:

- A finding is CONFIRMED only with evidence that does not come from the server's own claims.
- In the lab, a failed open of a forbidden path is never enough to confirm an access.
- The analysis of the real configuration and the lab reproduction stay in separate sections,
  and the real-configuration section only accepts configuration evidence.
- A check that was not run, was inconclusive or passed with missing evidence says why.

Regenerate the committed JSON Schema after any change:
    uv run python -m mcp_audit.models > schema/report.schema.json
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

REPORT_SCHEMA_VERSION = "0.1"

DISCLAIMER = (
    "A check without findings means that no problem was observed for the probes listed. "
    "It does not mean that the server is secure."
)


class Strict(BaseModel):
    """Base for every model: unknown fields are errors, not silently dropped."""

    model_config = ConfigDict(extra="forbid")


# --- Vocabulary ----------------------------------------------------------------


class Status(StrEnum):
    CONFIRMED = "confirmed"  # direct evidence of the problem
    NEEDS_REVIEW = "needs_review"  # a hint that a human must examine
    PASSED = "passed"  # check ran, no problem observed for the probes listed
    PASSED_LIMITED = "passed_limited"  # passed, but an evidence source was missing
    INCONCLUSIVE = "inconclusive"  # check ran, evidence does not support a conclusion
    NOT_RUN = "not_run"  # check skipped (unsupported, not authorized, Docker missing...)


# A finding reports a problem. Passing, inconclusive and skipped outcomes are CheckRun results.
FINDING_STATUSES = frozenset({Status.CONFIRMED, Status.NEEDS_REVIEW})
STATUSES_NEEDING_REASON = frozenset({Status.PASSED_LIMITED, Status.INCONCLUSIVE, Status.NOT_RUN})


class FindingKind(StrEnum):
    CONFIG_GAP = "config_gap"  # fixed in the configuration
    IMPLEMENTATION_DEFECT = "implementation_defect"  # fixed by an upgrade or a compensating control
    HINT = "hint"  # a risk indicator, not a proven defect


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceSource(StrEnum):
    CONFIG = "config"  # excerpt of a configuration file
    SERVER_CLAIM = "server_claim"  # what the server says (isError, message): context only
    RETURNED_CONTENT = "returned_content"  # a secret canary token found in what the server returned
    SYSCALL_TRACE = "syscall_trace"  # system calls made by the server's processes
    DISK_SNAPSHOT = "disk_snapshot"  # file hashes, sizes and mtimes before and after a probe


# Sources that can support CONFIRMED. A server's claim never can: it may lie or be wrong.
INDEPENDENT_SOURCES = frozenset(EvidenceSource) - {EvidenceSource.SERVER_CLAIM}


class ObservedAccess(StrEnum):
    """Strongest access to a forbidden path that the evidence proves, for one lab probe."""

    NONE = "none"
    METADATA = "metadata"  # stat, lstat, realpath: what a correct server does to validate a path
    OPEN_FAILED = "open_failed"  # open attempted and refused by the OS (EACCES, EPERM)
    READ_NOT_RETURNED = "read_not_returned"  # bytes read by the server, not sent back
    READ_RETURNED = "read_returned"  # the canary token came back in the response
    WRITE = "write"  # a forbidden file was created or modified on disk


PROVEN_ACCESS = frozenset(
    {ObservedAccess.READ_NOT_RETURNED, ObservedAccess.READ_RETURNED, ObservedAccess.WRITE}
)


# --- Findings and evidence -----------------------------------------------------


class Evidence(Strict):
    source: EvidenceSource
    summary: str = Field(min_length=1)
    data: dict[str, Any] = Field(default_factory=dict)
    artifact: str | None = None  # exported file, relative to the report
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _artifact_is_hashed(self) -> Self:
        if self.artifact is not None and self.sha256 is None:
            raise ValueError("an exported artifact must carry its sha256")
        return self


class Finding(Strict):
    check_id: str = Field(pattern=r"^[A-Z][0-9]+$")  # C1, D1...
    server: str
    title: str = Field(min_length=1)
    status: Status
    kind: FindingKind
    severity: Severity
    severity_rationale: str = Field(min_length=1)
    owasp: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    observed_access: ObservedAccess | None = None  # lab findings only
    recommendation: str | None = None
    limits: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _status_is_supported_by_evidence(self) -> Self:
        if self.status not in FINDING_STATUSES:
            raise ValueError(f"a finding is confirmed or needs review, not {self.status}")
        if self.status is Status.CONFIRMED:
            if not any(e.source in INDEPENDENT_SOURCES for e in self.evidence):
                raise ValueError("CONFIRMED needs evidence independent of the server's claims")
            if self.observed_access is not None and self.observed_access not in PROVEN_ACCESS:
                raise ValueError(
                    f"CONFIRMED needs a proven read or write, not {self.observed_access}"
                )
        for tag in self.owasp:
            if not (len(tag) == 5 and tag.startswith("MCP") and tag[3:].isdigit()):
                raise ValueError(f"unknown OWASP MCP category: {tag!r}")
        return self


class CheckRun(Strict):
    """One check against one server, whatever its outcome."""

    check_id: str = Field(pattern=r"^[A-Z][0-9]+$")
    server: str
    status: Status
    reason: str | None = None

    @model_validator(mode="after")
    def _reason_when_not_a_clean_result(self) -> Self:
        if self.status in STATUSES_NEEDING_REASON and not self.reason:
            raise ValueError(f"status {self.status} needs a reason")
        return self


# --- Report sections -----------------------------------------------------------


class RealConfigSection(Strict):
    """Static analysis of the user's actual configuration. Nothing is executed."""

    checks: list[CheckRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    @model_validator(mode="after")
    def _only_configuration_evidence(self) -> Self:
        for f in self.findings:
            if f.observed_access is not None:
                raise ValueError(f"{f.check_id}: no access is observed in a static analysis")
            if any(e.source is not EvidenceSource.CONFIG for e in f.evidence):
                raise ValueError(f"{f.check_id}: static findings only cite the configuration")
        return self


class PathMapping(Strict):
    """How a path of the real configuration is reproduced in the lab."""

    host_path: str
    lab_path: str
    role: Literal["allowed", "sibling_prefix", "parent", "home", "outside"]


class LabSection(Strict):
    """Dynamic tests on an isolated reproduction, never on the user's files."""

    path_mapping: list[PathMapping] = Field(default_factory=list)
    not_reproduced: list[str] = Field(default_factory=list)  # what the lab does not mirror
    versions_tested: dict[str, str] = Field(default_factory=dict)  # component -> exact version
    checks: list[CheckRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class Report(Strict):
    schema_version: Literal["0.1"] = REPORT_SCHEMA_VERSION
    tool_version: str
    generated_at: datetime
    real_config: RealConfigSection
    lab_reproduction: LabSection | None = None  # None when no dynamic test was attempted
    owasp_coverage: dict[str, str] = Field(default_factory=dict)  # category -> coverage note
    disclaimer: Literal[DISCLAIMER] = DISCLAIMER  # type: ignore[valid-type]


def report_json_schema() -> dict[str, Any]:
    return Report.model_json_schema()


if __name__ == "__main__":
    print(json.dumps(report_json_schema(), indent=2, ensure_ascii=False))
