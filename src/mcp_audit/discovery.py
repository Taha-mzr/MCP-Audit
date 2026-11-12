"""Find the MCP servers to audit. Read-only: no server is ever started here.

An MCP server is the program an AI application starts to give the model a capability (read
files, query GitHub...). The same program can be started by any application, so the audit
works on servers, and discovery only answers "which servers, started how?".

Sources, all producing the same ServerSpec:

- the known configuration files of the applications listed in ``known_files``;
- any configuration file given by the user (``mcpServers``, ``servers`` or ``mcp_servers``);
- a command typed by the user, for applications whose configuration is not a readable file.

Paths and formats follow each application's official documentation, read on 2026-11-09.
docs/discovery.md lists every way to add a server per application, its source, and whether it
is read here; ways whose storage is not documented (Claude Desktop extensions, plugins, the
VS Code user profile, Windsurf...) are not read and are listed there as gaps.

- Claude Desktop: https://modelcontextprotocol.io/docs/develop/connect-local-servers
- Claude Code: https://code.claude.com/docs/en/mcp and https://code.claude.com/docs/en/managed-mcp
- Cursor: https://cursor.com/docs/mcp
- VS Code: https://code.visualstudio.com/docs/agents/reference/mcp-configuration and
  https://code.visualstudio.com/docs/agents/run/manage-mcp-servers (dev containers)
- Copilot CLI: https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers
- Gemini CLI: https://geminicli.com/docs/cli/configuration/
- Codex: https://learn.chatgpt.com/docs/config-file/config-reference

Project files are read in the folder the command runs in and in every project folder that
~/.claude.json lists, because Claude Code records there each project it was used in.

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
    CLAUDE_CODE_MANAGED = "claude_code_managed"  # managed-mcp.json, installed by an admin
    PROJECT_MCP_JSON = "project_mcp_json"  # <dir>/.mcp.json, read by Claude Code and VS Code
    CURSOR_USER = "cursor_user"
    CURSOR_PROJECT = "cursor_project"
    VSCODE_WORKSPACE = "vscode_workspace"
    COPILOT_USER = "copilot_user"
    GEMINI_USER = "gemini_user"
    GEMINI_PROJECT = "gemini_project"
    GEMINI_SYSTEM = "gemini_system"  # system settings file, installed by an admin
    CODEX_USER = "codex_user"
    CODEX_PROJECT = "codex_project"
    DEVCONTAINER = "devcontainer"  # devcontainer.json, customizations.vscode.mcp.servers
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
    project: str | None = None  # project folder, for servers that belong to one project
    transport: Transport
    command: str | None = None
    args: list[str] = Field(default_factory=list)  # secret values replaced by ***
    env_keys: list[str] = Field(default_factory=list)  # names only, never values
    header_keys: list[str] = Field(default_factory=list)  # names only, never values
    url: str | None = None
    secrets: list[SecretHint] = Field(default_factory=list)  # secrets found in clear, no value

    @property
    def key(self) -> str:
        """Unique name in a report: the same server name can appear in several applications
        and in several projects."""
        if self.project:
            return f"{self.source}:{self.project}:{self.name}"
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
    block: object, source: Source, config_path: Path | None, project: str | None = None
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
                project=project,
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
    result: Discovery,
    block: object,
    source: Source,
    path: Path,
    status: SourceStatus,
    project: str | None = None,
) -> None:
    specs, problems = ([], []) if block is None else parse_servers(block, source, path, project)
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
    keys: tuple[str, ...]  # path of keys to the servers object, e.g. ("mcpServers",)
    project: str | None = None  # set for files that belong to one project folder


def claude_desktop_config(
    home: Path, platform: str = sys.platform, env: dict[str, str] | None = None
) -> Path:
    if platform == "darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if platform.startswith("win"):
        env = {} if env is None else env
        appdata = Path(env["APPDATA"]) if env.get("APPDATA") else home / "AppData" / "Roaming"
        return appdata / "Claude" / "claude_desktop_config.json"
    return home / ".config" / "Claude" / "claude_desktop_config.json"


def _default_system_root(platform: str) -> Path:
    return Path("C:/") if platform.startswith("win") else Path("/")


def claude_code_managed_config(platform: str, system_root: Path) -> Path:
    """managed-mcp.json, per https://code.claude.com/docs/en/managed-mcp."""
    if platform == "darwin":
        return system_root / "Library" / "Application Support" / "ClaudeCode" / "managed-mcp.json"
    if platform.startswith("win"):
        return system_root / "Program Files" / "ClaudeCode" / "managed-mcp.json"
    return system_root / "etc" / "claude-code" / "managed-mcp.json"


def gemini_system_settings(platform: str, system_root: Path, env: dict[str, str]) -> Path:
    """System settings file, per https://geminicli.com/docs/cli/configuration/."""
    if env.get("GEMINI_CLI_SYSTEM_SETTINGS_PATH"):
        return Path(env["GEMINI_CLI_SYSTEM_SETTINGS_PATH"])
    if platform == "darwin":
        return system_root / "Library" / "Application Support" / "GeminiCli" / "settings.json"
    if platform.startswith("win"):
        return system_root / "ProgramData" / "gemini-cli" / "settings.json"
    return system_root / "etc" / "gemini-cli" / "settings.json"


def known_files(
    home: Path,
    platform: str = sys.platform,
    env: dict[str, str] | None = None,
    system_root: Path | None = None,
) -> list[KnownFile]:
    """Files of the user and of the machine, read without being asked."""
    env = dict(os.environ) if env is None else env
    root = _default_system_root(platform) if system_root is None else system_root
    copilot_home = Path(env["COPILOT_HOME"]) if env.get("COPILOT_HOME") else home / ".copilot"
    servers = ("mcpServers",)
    return [
        KnownFile(
            Source.CLAUDE_DESKTOP, claude_desktop_config(home, platform, env), "json", servers
        ),
        KnownFile(
            Source.CLAUDE_CODE_MANAGED, claude_code_managed_config(platform, root), "json", servers
        ),
        KnownFile(Source.CURSOR_USER, home / ".cursor" / "mcp.json", "json", servers),
        KnownFile(Source.COPILOT_USER, copilot_home / "mcp-config.json", "json", servers),
        KnownFile(Source.GEMINI_USER, home / ".gemini" / "settings.json", "json", servers),
        KnownFile(
            Source.GEMINI_SYSTEM, gemini_system_settings(platform, root, env), "json", servers
        ),
        KnownFile(Source.CODEX_USER, home / ".codex" / "config.toml", "toml", ("mcp_servers",)),
    ]


def project_files(project_dir: Path) -> list[KnownFile]:
    """Files that belong to one project folder."""
    p = str(project_dir)
    servers = ("mcpServers",)
    devcontainer = ("customizations", "vscode", "mcp", "servers")
    return [
        KnownFile(Source.PROJECT_MCP_JSON, project_dir / ".mcp.json", "json", servers, p),
        KnownFile(Source.CURSOR_PROJECT, project_dir / ".cursor" / "mcp.json", "json", servers, p),
        KnownFile(
            Source.VSCODE_WORKSPACE, project_dir / ".vscode" / "mcp.json", "json", ("servers",), p
        ),
        KnownFile(
            Source.GEMINI_PROJECT, project_dir / ".gemini" / "settings.json", "json", servers, p
        ),
        KnownFile(
            Source.CODEX_PROJECT,
            project_dir / ".codex" / "config.toml",
            "toml",
            ("mcp_servers",),
            p,
        ),
        KnownFile(
            Source.DEVCONTAINER,
            project_dir / ".devcontainer" / "devcontainer.json",
            "json",
            devcontainer,
            p,
        ),
        KnownFile(Source.DEVCONTAINER, project_dir / ".devcontainer.json", "json", devcontainer, p),
        # https://containers.dev/implementors/spec/ also allows one sub-folder level.
        *(
            KnownFile(Source.DEVCONTAINER, sub, "json", devcontainer, p)
            for sub in sorted((project_dir / ".devcontainer").glob("*/devcontainer.json"))
        ),
    ]


def _dig(data: dict[str, Any], keys: tuple[str, ...]) -> object:
    """data[k1][k2]... or {} when a key is missing on the way."""
    value: object = data
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return {}
        value = value[key]
    return value


def _read_known(known: KnownFile) -> Discovery:
    result = Discovery()
    data, status = _read(known.path, known.source, known.fmt)
    block = None if data is None else _dig(data, known.keys)
    _collect(result, block, known.source, known.path, status, known.project)
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


def _claude_code_user_and_local(home: Path) -> tuple[Discovery, list[str]]:
    """~/.claude.json holds user servers at the top and local ones under projects[<dir>].

    Returns the servers found and the project folders listed in the file.
    """
    result = Discovery()
    claude_json = home / ".claude.json"
    data, status = _read(claude_json, Source.CLAUDE_CODE_USER, "json")
    block = None if data is None else data.get("mcpServers", {})
    _collect(result, block, Source.CLAUDE_CODE_USER, claude_json, status)
    projects = {} if data is None else data.get("projects", {})
    if not isinstance(projects, dict):
        return result, []
    for folder, project in projects.items():
        local_block = project.get("mcpServers") if isinstance(project, dict) else None
        if not local_block:
            continue
        local = SourceStatus(
            source=Source.CLAUDE_CODE_LOCAL, path=f"{claude_json}#{folder}", status="read"
        )
        _collect(result, local_block, Source.CLAUDE_CODE_LOCAL, claude_json, local, str(folder))
    return result, [str(folder) for folder in projects]


def discover_known(
    home: Path,
    project_dir: Path,
    platform: str = sys.platform,
    env: dict[str, str] | None = None,
    system_root: Path | None = None,
) -> Discovery:
    """Read every known configuration file that exists.

    Files of the user, of the machine and of the current folder are always listed, so the
    report says what was looked for. Files of the other projects that ~/.claude.json lists are
    listed only when they exist, to keep the report readable.
    """
    result, claude_projects = _claude_code_user_and_local(home)
    for known in known_files(home, platform, env, system_root):
        result.merge(_read_known(known))
    for known in project_files(project_dir):
        result.merge(_read_known(known))
    seen = {project_dir.resolve()}
    for folder in claude_projects:
        path = Path(folder)
        if not path.is_absolute() or not path.is_dir() or path.resolve() in seen:
            continue
        seen.add(path.resolve())
        for known in project_files(path):
            found = _read_known(known)
            if found.sources[0].status != "missing":
                result.merge(found)
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
