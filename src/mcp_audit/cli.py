"""Audit the MCP servers configured on this machine."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from mcp_audit import __version__
from mcp_audit.discovery import Discovery, discover_known, from_command, read_config_file


def _discover(args: argparse.Namespace) -> Discovery:
    if args.command:
        return Discovery(servers=[from_command(args.command)])
    if args.config:
        result = Discovery()
        for path in args.config:
            result.merge(read_config_file(path.expanduser()))
        return result
    return discover_known(Path.home(), Path.cwd())


def _print_discovery(result: Discovery) -> None:
    for s in result.sources:
        line = f"[{s.status:7}] {s.source}: {s.path}"
        if s.status == "read":
            line += f" ({s.servers} server(s))"
        if s.detail:
            line += f" - {s.detail}"
        print(line)
    print()
    if not result.servers:
        print("No MCP server found.")
        return
    for spec in result.servers:
        target = spec.url or " ".join([spec.command or "?", *spec.args])
        print(f"{spec.name}  [{spec.transport}, {spec.source}]")
        print(f"    {target}")
        if spec.env_keys:
            print(f"    env: {', '.join(spec.env_keys)} (values not shown)")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-audit", description=__doc__)
    parser.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    sub = parser.add_subparsers(dest="action")

    discover = sub.add_parser(
        "discover",
        help="list the MCP servers to audit, without starting them",
        description=(
            "Without options, reads the configuration files of Claude Desktop, Claude Code, "
            "Cursor, VS Code, GitHub Copilot, Gemini CLI and Codex that exist."
        ),
    )
    discover.add_argument(
        "--config",
        type=Path,
        action="append",
        help="a configuration file (JSON or TOML) listing MCP servers (repeatable)",
    )
    discover.add_argument(
        "--json", action="store_true", help="print the result as JSON instead of text"
    )
    discover.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="after --, the command that starts one server, e.g. -- npx server-filesystem /data",
    )

    args = parser.parse_args(argv)
    if args.action != "discover":
        parser.print_help()
        return 0
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    result = _discover(args)
    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        _print_discovery(result)
    return 0
