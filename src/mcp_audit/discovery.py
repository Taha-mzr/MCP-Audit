"""Find the MCP servers to audit. Read-only: no server is ever started here.

An MCP server is the program an AI application starts to give the model a capability (read
files, query GitHub...). The same program can be started by any application, so the audit
works on servers, and discovery only answers "which servers, started how?".

Sources, all producing the same ServerSpec:

- the known configuration files of Claude Desktop and Claude Code;
- any configuration file given by the user that uses the common ``mcpServers`` format;
- a command typed by the user, for applications whose configuration is not a readable file.

Paths follow the official documentation, checked on 2026-11-04:
https://modelcontextprotocol.io/docs/develop/connect-local-servers (Claude Desktop) and
https://code.claude.com/docs/en/mcp (Claude Code).

Values of environment variables are never kept: they often hold tokens. Only their names are.
"""

from __future__ import annotations

import json
import sys
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from mcp_audit.models import Strict


class Source(StrEnum):
    CLAUDE_DESKTOP = "claude_desktop"
    CLAUDE_CODE_USER = "claude_code_user"  # ~/.claude.json, top-level mcpServers
    CLAUDE_CODE_LOCAL = "claude_code_local"  # ~/.claude.json, projects[<dir>].mcpServers
    CLAUDE_CODE_PROJECT = "claude_code_project"  # <dir>/.mcp.json
    CONFIG_FILE = "config_file"  # a file given with --config
    COMMAND_LINE = "command_line"  # a command typed by the user


Transport = Literal["stdio", "http", "sse", "unknown"]

# Values of "type" seen in configurations, mapped to the transport they mean.
_TRANSPORTS: dict[str, Transport] = {
    "stdio": "stdio",
    "http": "http",
    "streamable-http": "http",
    "sse": "sse",
}


class ServerSpec(Strict):
    """One MCP server as an application would start it."""

    name: str
    source: Source
    config_path: str | None = None  # file it was read from; None for a typed command
    transport: Transport
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env_keys: list[str] = Field(default_factory=list)  # names only, never values
    url: str | None = None


class SourceStatus(Strict):
    """What happened when a source was looked at, so the report can say what was not read."""

    source: Source
    path: str
    status: Literal["read", "missing", "invalid"]
    detail: str | None = None
    servers: int = 0


class Discovery(Strict):
    servers: list[ServerSpec] = Field(default_factory=list)
    sources: list[SourceStatus] = Field(default_factory=list)


# --- Parsing ---------------------------------------------------------------------


def _transport(entry: dict[str, Any]) -> Transport:
    declared = entry.get("type")
    if isinstance(declared, str):
        return _TRANSPORTS.get(declared, "unknown")
    if "command" in entry:
        return "stdio"
    return "unknown"  # a url without a type is ambiguous: do not guess


def parse_servers(
    block: object, source: Source, config_path: Path | None
) -> tuple[list[ServerSpec], list[str]]:
    """Turn an ``mcpServers`` object into specs. Returns the specs and one note per bad entry."""
    if not isinstance(block, dict):
        return [], ["mcpServers is not an object"]
    specs: list[ServerSpec] = []
    problems: list[str] = []
    for name, entry in block.items():
        if not isinstance(entry, dict):
            problems.append(f"{name}: entry is not an object")
            continue
        args = entry.get("args", [])
        env = entry.get("env", {})
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            problems.append(f"{name}: args is not a list of strings")
            continue
        if not isinstance(env, dict):
            problems.append(f"{name}: env is not an object")
            continue
        command = entry.get("command")
        url = entry.get("url")
        specs.append(
            ServerSpec(
                name=str(name),
                source=source,
                config_path=str(config_path) if config_path else None,
                transport=_transport(entry),
                command=command if isinstance(command, str) else None,
                args=args,
                env_keys=sorted(str(k) for k in env),
                url=url if isinstance(url, str) else None,
            )
        )
    return specs, problems


def _read(path: Path, source: Source) -> tuple[dict[str, Any] | None, SourceStatus]:
    if not path.is_file():
        return None, SourceStatus(source=source, path=str(path), status="missing")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        detail = f"{type(exc).__name__}: {exc}"
        return None, SourceStatus(source=source, path=str(path), status="invalid", detail=detail)
    if not isinstance(data, dict):
        status = SourceStatus(
            source=source, path=str(path), status="invalid", detail="top level is not an object"
        )
        return None, status
    return data, SourceStatus(source=source, path=str(path), status="read")


def _collect(
    result: Discovery, block: object, source: Source, path: Path, status: SourceStatus
) -> None:
    specs, problems = ([], []) if block is None else parse_servers(block, source, path)
    status.servers = len(specs)
    if problems:
        status.detail = "; ".join(problems)
    result.servers.extend(specs)
    result.sources.append(status)


# --- Sources ---------------------------------------------------------------------


def claude_desktop_config(home: Path, platform: str = sys.platform) -> Path:
    if platform == "darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if platform.startswith("win"):
        return home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    return home / ".config" / "Claude" / "claude_desktop_config.json"


def read_config_file(path: Path, source: Source = Source.CONFIG_FILE) -> Discovery:
    """Any file whose top level has an ``mcpServers`` object."""
    result = Discovery()
    data, status = _read(path, source)
    _collect(result, None if data is None else data.get("mcpServers", {}), source, path, status)
    return result


def discover_known(home: Path, project_dir: Path, platform: str = sys.platform) -> Discovery:
    """Read the configuration files of Claude Desktop and Claude Code that exist."""
    result = Discovery()

    desktop = read_config_file(claude_desktop_config(home, platform), Source.CLAUDE_DESKTOP)
    result.servers += desktop.servers
    result.sources += desktop.sources

    claude_json = home / ".claude.json"
    data, status = _read(claude_json, Source.CLAUDE_CODE_USER)
    _collect(
        result,
        None if data is None else data.get("mcpServers", {}),
        Source.CLAUDE_CODE_USER,
        claude_json,
        status,
    )
    if data is not None:
        projects = data.get("projects", {})
        project = projects.get(str(project_dir), {}) if isinstance(projects, dict) else {}
        block = project.get("mcpServers", {}) if isinstance(project, dict) else {}
        local = SourceStatus(
            source=Source.CLAUDE_CODE_LOCAL, path=f"{claude_json}#{project_dir}", status="read"
        )
        _collect(result, block, Source.CLAUDE_CODE_LOCAL, claude_json, local)

    project_file = read_config_file(project_dir / ".mcp.json", Source.CLAUDE_CODE_PROJECT)
    result.servers += project_file.servers
    result.sources += project_file.sources
    return result


def from_command(argv: list[str], name: str = "command-line") -> ServerSpec:
    """A server given as the command that starts it, for any application."""
    if not argv:
        raise ValueError("an empty command starts no server")
    return ServerSpec(
        name=name,
        source=Source.COMMAND_LINE,
        transport="stdio",
        command=argv[0],
        args=list(argv[1:]),
    )
