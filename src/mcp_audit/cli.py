"""Audit the MCP servers configured on this machine."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from mcp_audit import __version__
from mcp_audit.checks import OWASP_EDITION, run_static
from mcp_audit.discovery import Discovery, discover_known, from_command, read_config_file
from mcp_audit.models import Report, Status

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
        print(f"{spec.name}  [{spec.transport}, {spec.source}]")
        print(f"    {target}")
        if spec.env_keys:
            print(f"    env: {', '.join(spec.env_keys)} (values not shown)")


def build_report(result: Discovery) -> Report:
    return Report(
        tool_version=__version__,
        generated_at=datetime.now(UTC),
        real_config=run_static(result.servers),
        owasp_mcp_top10_version=OWASP_EDITION,
    )


def _print_report(result: Discovery, report: Report) -> None:
    _print_sources(result)
    if not result.servers:
        print("No MCP server found: nothing to audit.")
        return
    section = report.real_config
    for spec in result.servers:
        print(spec.key)
        for run in (r for r in section.checks if r.server == spec.key):
            line = f"  {run.check_id}  {LABELS[run.status]}"
            if run.reason:
                line += f" ({run.reason})"
            print(line)
            for f in section.findings:
                if f.server == spec.key and f.check_id == run.check_id:
                    print(f"        [{f.severity}] {f.title}")
        print()
    confirmed = sum(f.status is Status.CONFIRMED for f in section.findings)
    review = sum(f.status is Status.NEEDS_REVIEW for f in section.findings)
    print(f"{len(result.servers)} server(s), {confirmed} confirmed, {review} to review.")
    print(report.disclaimer)


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
        help="run the static checks C1 to C5 on the servers found, without starting them",
        description=known,
    )
    audit.add_argument("--output", type=Path, help="also write the JSON report to this file")
    _add_source_options(audit)

    args = parser.parse_args(argv)
    if args.action is None:
        parser.print_help()
        return 0
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    result = _discover(args)

    if args.action == "discover":
        if args.json:
            print(result.model_dump_json(indent=2))
        else:
            _print_discovery(result)
        return 0

    report = build_report(result)
    _print_report(result, report)
    if args.output:
        args.output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nJSON report written to {args.output}")
    return 0
