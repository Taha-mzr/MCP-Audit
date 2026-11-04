"""Find the MCP servers to audit. Read-only: no server is ever started here.

An MCP server is the program an AI application starts to give the model a capability (read
files, query GitHub...). The same program can be started by any application, so the audit
works on servers, and discovery only answers "which servers, started how?".

Sources, all producing the same ServerSpec:

- the known configuration files of the applications listed in ``known_files``;
- any configuration file given by the user (``mcpServers``, ``servers`` or ``mcp_servers``);
- a command typed by the user, for applications whose configuration is not a readable file.

Paths and formats follow each application's official documentation, checked on 2026-11-04:

- Claude Desktop: https://modelcontextprotocol.io/docs/develop/connect-local-servers
- Claude Code: https://code.claude.com/docs/en/mcp
- Cursor: https://docs.cursor.com/context/model-context-protocol
- VS Code: https://code.visualstudio.com/docs/agents/reference/mcp-configuration
- Gemini CLI: https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md
- Codex CLI: https://developers.openai.com/codex/mcp

Not covered yet, because the location was not confirmed in official documentation: Windsurf,
and the VS Code user-profile mcp.json.

Values of environment variables and headers are never kept: they often hold tokens. Only their
names are, with a hint when a value is a secret written in clear. Secret values found in the
command line are replaced by ``***``.
"""

from __future__ import annotations

import json
import os
import sys
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from mcp_audit.models import Strict
from mcp_audit.secrets import SecretHint, classify, mask_args


class Source(StrEnum):
    CLAUDE_DESKTOP = "claude_desktop"
    CLAUDE_CODE_USER = "claude_code_user"  # ~/.claude.json, top-level mcpServers
    CLAUDE_CODE_LOCAL = "claude_code_local"  # ~/.claude.json, projects[<dir>].mcpServers
    PROJECT_MCP_JSON = "project_mcp_json"  # <dir>/.mcp.json, read by Claude Code and VS Code
    CURSOR_USER = "cursor_user"
    CURSOR_PROJECT = "cursor_project"
    VSCODE_WORKSPACE = "vscode_workspace"
    COPILOT_USER = "copilot_user"
    GEMINI_USER = "gemini_user"
    GEMINI_PROJECT = "gemini_project"
    CODEX_USER = "codex_user"
    CODEX_PROJECT = "codex_project"
    CONFIG_FILE = "config_file"  # a file given with --config
    COMMAND_LINE = "command_line"  # a command typed by the user


Transport = Literal["stdio", "http", "sse", "unknown"]
Format = Literal["json", "toml"]

# Values of "type" seen in configurations, mapped to the transport they mean.
_TRANSPORTS: dict[str, Transport] = {
    "stdio": "stdio",
    "http": "http",
    "streamable-http": "http",
    "sse": "sse",
}

# Top-level keys that hold the servers, depending on the application.
SERVER_KEYS = ("mcpServers", "servers", "mcp_servers")


class ServerSpec(Strict):
    """One MCP server as an application would start it."""

    name: str
    source: Source
    config_path: str | None = None  # file it was read from; None for a typed command
    transport: Transport
    command: str | None = None
    args: list[str] = Field(default_factory=list)  # secret values replaced by ***
    env_keys: list[str] = Field(default_factory=list)  # names only, never values
    header_keys: list[str] = Field(default_factory=list)  # names only, never values
    url: str | None = None
    secrets: list[SecretHint] = Field(default_factory=list)  # secrets found in clear, no value

    @property
    def key(self) -> str:
        """Unique name in a report: the same server name can appear in several applications."""
        return f"{self.source}:{self.name}"


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

    def merge(self, other: Discovery) -> None:
        self.servers += other.servers
        self.sources += other.sources


# --- Parsing ---------------------------------------------------------------------


def _transport(entry: dict[str, Any]) -> Transport:
    declared = entry.get("type")
    if isinstance(declared, str):
        return _TRANSPORTS.get(declared, "unknown")
    if "command" in entry:
        return "stdio"
    if "httpUrl" in entry:  # Gemini CLI's name for a streamable HTTP endpoint
        return "http"
    return "unknown"  # a url without a type is ambiguous: do not guess


def parse_servers(
    block: object, source: Source, config_path: Path | None
) -> tuple[list[ServerSpec], list[str]]:
    """Turn a servers object into specs. Returns the specs and one note per bad entry."""
    if not isinstance(block, dict):
        return [], ["the servers entry is not an object"]
    specs: list[ServerSpec] = []
    problems: list[str] = []
    for name, entry in block.items():
        if not isinstance(entry, dict):
            problems.append(f"{name}: entry is not an object")
            continue
        args = entry.get("args", [])
        env = entry.get("env", {})
        headers = entry.get("headers", entry.get("http_headers", {}))
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            problems.append(f"{name}: args is not a list of strings")
            continue
        if not isinstance(env, dict) or not isinstance(headers, dict):
            problems.append(f"{name}: env or headers is not an object")
            continue
        command = entry.get("command")
        url = entry.get("url", entry.get("httpUrl"))
        masked_args, secrets = mask_args(args)
        for key, value in env.items():
            hint = classify(f"env:{key}", str(key), value)
            if hint:
                secrets.append(hint)
        for key, value in headers.items():
            hint = classify(f"header:{key}", str(key), value)
            if hint:
                secrets.append(hint)
        specs.append(
            ServerSpec(
                name=str(name),
                source=source,
                config_path=str(config_path) if config_path else None,
                transport=_transport(entry),
                command=command if isinstance(command, str) else None,
                args=masked_args,
                env_keys=sorted(str(k) for k in env),
                header_keys=sorted(str(k) for k in headers),
                url=url if isinstance(url, str) else None,
                secrets=secrets,
            )
        )
    return specs, problems


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, leaving strings untouched.

    VS Code reads its mcp.json as JSON with comments; plain json.loads would reject it.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1  # trailing comma
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _read(path: Path, source: Source, fmt: Format) -> tuple[dict[str, Any] | None, SourceStatus]:
    if not path.is_file():
        return None, SourceStatus(source=source, path=str(path), status="missing")
    try:
        text = path.read_text(encoding="utf-8")
        data = tomllib.loads(text) if fmt == "toml" else json.loads(strip_jsonc(text))
    except (OSError, UnicodeDecodeError, ValueError) as exc:  # JSON and TOML errors included
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


@dataclass(frozen=True)
class KnownFile:
    source: Source
    path: Path
    fmt: Format
    key: str  # top-level key that holds the servers


def claude_desktop_config(home: Path, platform: str = sys.platform) -> Path:
    if platform == "darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if platform.startswith("win"):
        return home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    return home / ".config" / "Claude" / "claude_desktop_config.json"


def known_files(
    home: Path,
    project_dir: Path,
    platform: str = sys.platform,
    env: dict[str, str] | None = None,
) -> list[KnownFile]:
    """Configuration files read without being asked, for the applications covered so far."""
    env = dict(os.environ) if env is None else env
    copilot_home = Path(env["COPILOT_HOME"]) if env.get("COPILOT_HOME") else home / ".copilot"
    return [
        KnownFile(
            Source.CLAUDE_DESKTOP, claude_desktop_config(home, platform), "json", "mcpServers"
        ),
        KnownFile(Source.PROJECT_MCP_JSON, project_dir / ".mcp.json", "json", "mcpServers"),
        KnownFile(Source.CURSOR_USER, home / ".cursor" / "mcp.json", "json", "mcpServers"),
        KnownFile(
            Source.CURSOR_PROJECT, project_dir / ".cursor" / "mcp.json", "json", "mcpServers"
        ),
        KnownFile(Source.VSCODE_WORKSPACE, project_dir / ".vscode" / "mcp.json", "json", "servers"),
        KnownFile(Source.COPILOT_USER, copilot_home / "mcp-config.json", "json", "mcpServers"),
        KnownFile(Source.GEMINI_USER, home / ".gemini" / "settings.json", "json", "mcpServers"),
        KnownFile(
            Source.GEMINI_PROJECT, project_dir / ".gemini" / "settings.json", "json", "mcpServers"
        ),
        KnownFile(Source.CODEX_USER, home / ".codex" / "config.toml", "toml", "mcp_servers"),
        KnownFile(
            Source.CODEX_PROJECT, project_dir / ".codex" / "config.toml", "toml", "mcp_servers"
        ),
    ]


def _read_known(known: KnownFile) -> Discovery:
    result = Discovery()
    data, status = _read(known.path, known.source, known.fmt)
    _collect(
        result,
        None if data is None else data.get(known.key, {}),
        known.source,
        known.path,
        status,
    )
    return result


def read_config_file(path: Path, source: Source = Source.CONFIG_FILE) -> Discovery:
    """A file given by the user: TOML if it ends in .toml, JSON (comments allowed) otherwise.

    The servers are taken from the first of mcpServers, servers or mcp_servers that is present.
    """
    fmt: Format = "toml" if path.suffix == ".toml" else "json"
    result = Discovery()
    data, status = _read(path, source, fmt)
    block: object = None
    if data is not None:
        key = next((k for k in SERVER_KEYS if k in data), None)
        block = data[key] if key else {}
    _collect(result, block, source, path, status)
    return result


def _claude_code_user_and_local(home: Path, project_dir: Path) -> Discovery:
    """~/.claude.json holds user servers at the top and local ones under projects[<dir>]."""
    result = Discovery()
    claude_json = home / ".claude.json"
    data, status = _read(claude_json, Source.CLAUDE_CODE_USER, "json")
    block = None if data is None else data.get("mcpServers", {})
    _collect(result, block, Source.CLAUDE_CODE_USER, claude_json, status)
    if data is not None:
        projects = data.get("projects", {})
        project = projects.get(str(project_dir), {}) if isinstance(projects, dict) else {}
        local_block = project.get("mcpServers", {}) if isinstance(project, dict) else {}
        local = SourceStatus(
            source=Source.CLAUDE_CODE_LOCAL, path=f"{claude_json}#{project_dir}", status="read"
        )
        _collect(result, local_block, Source.CLAUDE_CODE_LOCAL, claude_json, local)
    return result


def discover_known(
    home: Path,
    project_dir: Path,
    platform: str = sys.platform,
    env: dict[str, str] | None = None,
) -> Discovery:
    """Read every known configuration file that exists. Missing ones are listed, not errors."""
    result = Discovery()
    result.merge(_claude_code_user_and_local(home, project_dir))
    for known in known_files(home, project_dir, platform, env):
        result.merge(_read_known(known))
    return result


def from_command(argv: list[str], name: str = "command-line") -> ServerSpec:
    """A server given as the command that starts it, for any application."""
    if not argv:
        raise ValueError("an empty command starts no server")
    args, secrets = mask_args(list(argv[1:]))
    return ServerSpec(
        name=name,
        source=Source.COMMAND_LINE,
        transport="stdio",
        command=argv[0],
        args=args,
        secrets=secrets,
    )
