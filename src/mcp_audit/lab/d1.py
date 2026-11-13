"""D1: does a file server leave the folder it is given? (docs/rules/D1.md)

For each server of the configuration that the policy authorizes and that has a program sheet,
D1 starts the program in a fresh locked-down container, gives it /lab/notes in place of the
folder of the configuration, sends the probes, and judges each answer from evidence that does
not come from the server: a random token in the answer, or a change on the disk.
"""

from __future__ import annotations

import secrets
import unicodedata
from dataclasses import dataclass, field

from mcp_audit.discovery import ServerSpec
from mcp_audit.lab import container, probes
from mcp_audit.lab.client import ClientError, StdioClient
from mcp_audit.lab.programs import Program, match
from mcp_audit.models import (
    CheckRun,
    Evidence,
    EvidenceSource,
    Finding,
    FindingKind,
    LabSection,
    ObservedAccess,
    PathMapping,
    Severity,
    Status,
)
from mcp_audit.policy import Policy

CALL_TIMEOUT = 15  # seconds for one tool call
START_TIMEOUT = 60  # seconds to start the server and list its tools
MAX_TEXT = 64_000  # characters kept from one answer


def clean(text: str, limit: int = 200) -> str:
    """Text from the server, safe to show: no control characters, bounded length."""
    kept = "".join(c for c in text if unicodedata.category(c)[0] != "C" or c in " ")
    return kept[:limit]


@dataclass
class Run:
    """What one D1 run produced for one server."""

    check: CheckRun
    findings: list[Finding] = field(default_factory=list)
    mapping: list[PathMapping] = field(default_factory=list)
    version: tuple[str, str] | None = None  # program name, version
    tools: list[str] = field(default_factory=list)  # what the server declares


def _not_run(spec: ServerSpec, reason: str) -> Run:
    return Run(CheckRun(check_id="D1", server=spec.key, status=Status.NOT_RUN, reason=reason))


def _call(client: StdioClient, tool: str, arguments: dict[str, str]) -> probes.Outcome:
    try:
        result = client.call_tool(tool, arguments, CALL_TIMEOUT)
    except ClientError as error:
        return probes.Outcome(failure=clean(str(error)))
    return probes.Outcome(text=result.text[:MAX_TEXT], is_error=result.is_error)


def _probe_server(box: container.Container, program: Program):
    """Send every probe; return the tools declared, the (probe, outcome) pairs and the nonce."""
    nonce = secrets.token_hex(4)
    results: list[tuple[probes.Probe, probes.Outcome]] = []
    command = box.server_command(program, probes.ALLOWED)
    container.check_args(command)
    with StdioClient(command, container.docker_env()) as client:
        client.initialize(START_TIMEOUT)
        tools = [clean(name, 80) for name in client.list_tools(START_TIMEOUT)]
        for probe in probes.PROBES:
            if probe.kind == "read":
                outcome = _call(client, program.read_tool, {"path": probe.path})
            else:
                before = box.snapshot()
                content = probes.write_content(probe, nonce)
                outcome = _call(
                    client, program.write_tool, {"path": probe.path, "content": content}
                )
                outcome.before = before
                outcome.after = box.snapshot()
            results.append((probe, outcome))
    return tools, results, nonce


def _finding(spec: ServerSpec, program: Program, probe: probes.Probe, verdict: probes.Verdict,
             token: str | None) -> Finding:  # fmt: skip
    action = "read a file" if probe.kind == "read" else "wrote a file"
    if verdict.access == "read_returned":
        evidence = Evidence(
            source=EvidenceSource.RETURNED_CONTENT,
            summary=f"the random token {token} of {probe.path} came back in the answer",
            data={"probe": probe.id, "path": probe.path, "token": token},
        )
        access = ObservedAccess.READ_RETURNED
    else:
        evidence = Evidence(
            source=EvidenceSource.DISK_SNAPSHOT,
            summary="changed outside the allowed folder: " + ", ".join(verdict.changed),
            data={"probe": probe.id, "path": probe.path, "changed": list(verdict.changed)},
        )
        access = ObservedAccess.WRITE
    return Finding(
        check_id="D1",
        server=spec.key,
        title=f"{program.name}@{program.version} {action} outside its allowed folder "
        f"({probe.way}): {probe.path}",
        status=Status.CONFIRMED,
        kind=FindingKind.IMPLEMENTATION_DEFECT,
        severity=Severity.HIGH,
        severity_rationale=(
            "Observed in the lab: a narrow folder in the configuration does not protect the "
            "files next to it, whatever the configuration says."
        ),
        owasp=["MCP02"],
        cwe=[probe.cwe],
        evidence=[evidence],
        observed_access=access,
        recommendation="Upgrade the server to a version that fixes this, then run the lab again.",
        limits=[
            f"Observed on {program.name}@{program.version} in a container, on fake files.",
            "Only the probes listed in docs/rules/D1.md were sent.",
        ],
    )


def run_d1(spec: ServerSpec, policy: Policy | None) -> Run:
    """D1 for one server of the configuration. Never raises: problems become NOT_RUN."""
    entry = policy.servers.get(spec.name) if policy else None
    if entry is None or not entry.audit_authorized:
        return _not_run(spec, "the policy does not set audit_authorized = true for this server")
    found = match(spec)
    if found.program is None:
        return _not_run(spec, found.reason or "no lab sheet for this program")
    program = found.program
    if not found.folders:
        return _not_run(spec, "no folder in the configuration to reproduce")
    problem = container.engine_ready()
    if problem:
        return _not_run(spec, f"Docker is not available: {problem}")
    if not container.image_exists(program.image):
        return _not_run(spec, f"image {program.image} is not built: run `mcp-audit lab build`")

    tokens = {
        "secret": f"MCPAUDIT-{secrets.token_hex(8)}",
        "sibling": f"MCPAUDIT-{secrets.token_hex(8)}",
    }
    try:
        with container.Container(program.image) as box:
            box.setup(tokens)
            tools, results, nonce = _probe_server(box, program)
    except (container.LabError, ClientError) as error:
        return _not_run(spec, clean(f"the lab could not run: {error}", 300))
    except Exception as error:  # noqa: BLE001 - a server that cannot start is not a crash of ours
        return _not_run(spec, clean(f"the server could not be started: {error}", 300))

    by_id = dict((p.id, o) for p, o in results)
    read_ok = probes.normal_read_works(by_id["L0"])
    e0 = next(p for p in probes.PROBES if p.id == "E0")
    write_ok = probes.normal_write_works(e0, by_id["E0"], nonce)
    findings: list[Finding] = []
    unclear: list[str] = []
    for probe, outcome in results:
        if not probe.forbidden:
            continue
        if probe.kind == "read":
            token = tokens[probe.token or "secret"]
            verdict = probes.judge_read(probe, outcome, token, read_ok)
        else:
            token = None
            verdict = probes.judge_write(probe, outcome, write_ok)
        if verdict.status == "confirmed":
            findings.append(_finding(spec, program, probe, verdict, token))
        elif verdict.status == "inconclusive":
            unclear.append(f"{probe.id}: {verdict.detail}")
    if findings:
        check = CheckRun(check_id="D1", server=spec.key, status=Status.CONFIRMED)
    elif unclear:
        check = CheckRun(check_id="D1", server=spec.key, status=Status.INCONCLUSIVE,
                         reason="; ".join(unclear))  # fmt: skip
    else:
        check = CheckRun(check_id="D1", server=spec.key, status=Status.PASSED)
    created = "(none: created by the lab)"
    mapping = [
        PathMapping(host_path=found.folders[0], lab_path=probes.ALLOWED, role="allowed"),
        PathMapping(host_path=created, lab_path="/lab/notes-prive", role="sibling_prefix"),
        PathMapping(host_path=created, lab_path="/lab/secret", role="outside"),
    ]
    return Run(check, findings, mapping, (program.name, program.version), tools)


def run_lab(specs: list[ServerSpec], policy: Policy | None) -> LabSection:
    section = LabSection()
    for spec in specs:
        run = run_d1(spec, policy)
        section.checks.append(run.check)
        section.findings.extend(run.findings)
        section.path_mapping.extend(run.mapping)
        if run.version:
            section.versions_tested[f"{spec.key}: {run.version[0]}"] = run.version[1]
    section.not_reproduced = [
        "Only the first folder of each configuration is reproduced, as /lab/notes.",
        "The Roots an application may send at run time are not reproduced.",
        "A forbidden read whose content is not sent back is not seen (no system call trace).",
        "Transitive npm dependencies are those of the lock file built by mcp-audit, which may "
        "differ from what an application installed on its own.",
    ]
    return LabSection.model_validate(section.model_dump())
