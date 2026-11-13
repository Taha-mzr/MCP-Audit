"""Audit the MCP servers configured on this machine."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from mcp_audit import __version__
from mcp_audit.checks import OWASP_EDITION, run_static
from mcp_audit.discovery import Discovery, discover_known, from_command, read_config_file
from mcp_audit.models import LabSection, RealConfigSection, Report, Status
from mcp_audit.policy import Policy, PolicyError, load_policy

LABELS = {
    Status.CONFIRMED: "CONFIRMED",
    Status.NEEDS_REVIEW: "TO REVIEW",
    Status.PASSED: "passed",
    Status.PASSED_LIMITED: "passed (limited)",
    Status.INCONCLUSIVE: "inconclusive",
    Status.NOT_RUN: "not run",
}


def _discover(args: argparse.Namespace) -> Discovery:
    if args.command:
        return Discovery(servers=[from_command(args.command)])
    if args.config:
        result = Discovery()
        for path in args.config:
            result.merge(read_config_file(path.expanduser()))
        return result
    return discover_known(Path.home(), Path.cwd())


def _print_sources(result: Discovery) -> None:
    for s in result.sources:
        line = f"[{s.status:7}] {s.source}: {s.path}"
        if s.status == "read":
            line += f" ({s.servers} server(s))"
        if s.detail:
            line += f" - {s.detail}"
        print(line)
    if result.sources:
        print()


def _print_discovery(result: Discovery) -> None:
    _print_sources(result)
    if not result.servers:
        print("No MCP server found.")
        return
    for spec in result.servers:
        target = spec.url or " ".join([spec.command or "?", *spec.args])
        where = f", project {spec.project}" if spec.project else ""
        print(f"{spec.name}  [{spec.transport}, {spec.source}{where}]")
        print(f"    {target}")
        if spec.env_keys:
            print(f"    env: {', '.join(spec.env_keys)} (values not shown)")


def build_report(result: Discovery, policy: Policy | None = None, lab: bool = False) -> Report:
    lab_section = None
    if lab:
        from mcp_audit.lab.d1 import run_lab  # only when asked: it needs Docker

        lab_section = run_lab(result.servers, policy)
    return Report(
        tool_version=__version__,
        generated_at=datetime.now(UTC),
        real_config=run_static(result.servers, policy),
        lab_reproduction=lab_section,
        owasp_mcp_top10_version=OWASP_EDITION,
    )


def _print_runs(section: RealConfigSection | LabSection, key: str) -> None:
    for run in (r for r in section.checks if r.server == key):
        line = f"  {run.check_id}  {LABELS[run.status]}"
        if run.reason:
            line += f" ({run.reason})"
        print(line)
        for f in section.findings:
            if f.server == key and f.check_id == run.check_id:
                print(f"        [{f.severity}] {f.title}")
                if isinstance(section, LabSection):
                    for e in f.evidence:
                        print(f"               proof: {e.summary}")


def _print_report(result: Discovery, report: Report) -> None:
    _print_sources(result)
    if not result.servers:
        print("No MCP server found: nothing to audit.")
        return
    sections: list[RealConfigSection | LabSection] = [report.real_config]
    if report.lab_reproduction is not None:
        sections.append(report.lab_reproduction)
    for spec in result.servers:
        print(spec.key)
        for section in sections:
            _print_runs(section, spec.key)
        print()
    if report.lab_reproduction is not None:
        lab = report.lab_reproduction
        if lab.versions_tested:
            print("Lab: versions tested")
            for component, version in lab.versions_tested.items():
                print(f"  {component} {version}")
        print("Lab: not reproduced")
        for note in lab.not_reproduced:
            print(f"  - {note}")
        print()
    findings = [f for s in sections for f in s.findings]
    confirmed = sum(f.status is Status.CONFIRMED for f in findings)
    review = sum(f.status is Status.NEEDS_REVIEW for f in findings)
    print(f"{len(result.servers)} server(s), {confirmed} confirmed, {review} to review.")
    print(report.disclaimer)


def _lab(action: str) -> int:
    from mcp_audit.lab import container, programs

    if action == "list":
        for program in programs.PROGRAMS:
            built = "built" if container.image_exists(program.image) else "not built"
            print(f"{program.name} {program.version}  {program.image}  [{built}]")
        return 0
    problem = container.engine_ready()
    if problem:
        print(f"mcp-audit: Docker is not available: {problem}", file=sys.stderr)
        return 1
    failed = 0
    for image, program in programs.images().items():
        print(f"building {image} ...", flush=True)
        try:
            container.build(program)
        except container.LabError as error:
            failed += 1
            print(f"  failed: {error}", file=sys.stderr)
        else:
            print("  done")
    return 1 if failed else 0


def _add_source_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        type=Path,
        action="append",
        help="a configuration file (JSON or TOML) listing MCP servers (repeatable)",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="after --, the command that starts one server, e.g. -- npx server-filesystem /data",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-audit", description=__doc__)
    parser.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    sub = parser.add_subparsers(dest="action")
    known = (
        "Without options, reads the configuration files of Claude Desktop, Claude Code, "
        "Cursor, VS Code, GitHub Copilot, Gemini CLI and Codex that exist."
    )

    discover = sub.add_parser(
        "discover", help="list the MCP servers to audit, without starting them", description=known
    )
    discover.add_argument("--json", action="store_true", help="print the result as JSON")
    _add_source_options(discover)

    audit = sub.add_parser(
        "audit",
        help="run the static checks C1 to C5 on the servers found; --lab adds the lab test D1",
        description=known,
    )
    audit.add_argument("--output", type=Path, help="also write the JSON report to this file")
    audit.add_argument(
        "--policy",
        type=Path,
        help="a TOML file saying which folders each server may read and write (docs/policy.md)",
    )
    audit.add_argument(
        "--lab",
        action="store_true",
        help="also run D1 in a Docker container, for the servers the policy authorizes "
        "(docs/rules/D1.md)",
    )
    _add_source_options(audit)

    lab = sub.add_parser("lab", help="prepare the Docker lab used by audit --lab")
    lab_sub = lab.add_subparsers(dest="lab_action", required=True)
    lab_sub.add_parser("build", help="build the Docker images of the lab (needs the internet)")
    lab_sub.add_parser("list", help="list the programs the lab can test, and their images")

    args = parser.parse_args(argv)
    if args.action is None:
        parser.print_help()
        return 0
    if args.action == "lab":
        return _lab(args.lab_action)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    policy = None
    if getattr(args, "policy", None):
        try:
            policy = load_policy(args.policy.expanduser())
        except PolicyError as error:
            print(f"mcp-audit: {error}", file=sys.stderr)
            return 2
    result = _discover(args)

    if args.action == "discover":
        if args.json:
            print(result.model_dump_json(indent=2))
        else:
            _print_discovery(result)
        return 0

    if args.lab and policy is None:
        print("mcp-audit: --lab needs --policy: D1 runs only what the policy authorizes",
              file=sys.stderr)  # fmt: skip
        return 2
    report = build_report(result, policy, lab=args.lab)
    _print_report(result, report)
    if args.output:
        args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nJSON report written to {args.output}")
    return 0
