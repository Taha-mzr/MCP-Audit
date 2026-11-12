import json
from pathlib import Path

import pytest

from mcp_audit.cli import main
from mcp_audit.discovery import (
    Source,
    claude_desktop_config,
    discover_known,
    from_command,
    parse_servers,
    read_config_file,
    strip_jsonc,
)

FILESYSTEM = {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice/notes"],
}
# Machine-wide files (managed by an admin) are looked for under this folder in tests, so the
# machine running the tests does not change their result.
NO_SYSTEM = Path("/nonexistent-system-root")
# Obviously fake value: it must never show up in any output.
FAKE_TOKEN = "FAKE-TOKEN-NOT-A-SECRET-0000"  # noqa: S105
GITHUB = {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-github"],
    "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE_TOKEN},
}


def write(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# --- Parsing one mcpServers object ---------------------------------------------------


def test_stdio_server_is_parsed() -> None:
    specs, problems = parse_servers({"filesystem": FILESYSTEM}, Source.CONFIG_FILE, None)
    assert problems == []
    assert specs[0].name == "filesystem"
    assert specs[0].transport == "stdio"
    assert specs[0].command == "npx"
    assert specs[0].args[-1] == "/Users/alice/notes"


def test_env_values_are_never_kept() -> None:
    specs, _ = parse_servers({"github": GITHUB}, Source.CONFIG_FILE, None)
    assert specs[0].env_keys == ["GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert FAKE_TOKEN not in specs[0].model_dump_json()


@pytest.mark.parametrize(
    ("entry", "transport"),
    [
        ({"type": "http", "url": "https://example.invalid/mcp"}, "http"),
        ({"type": "streamable-http", "url": "https://example.invalid/mcp"}, "http"),
        ({"type": "sse", "url": "https://example.invalid/sse"}, "sse"),
        ({"url": "https://example.invalid/mcp"}, "unknown"),  # ambiguous: not guessed
    ],
)
def test_transport_is_taken_from_the_entry(entry: dict[str, str], transport: str) -> None:
    specs, _ = parse_servers({"remote": entry}, Source.CONFIG_FILE, None)
    assert specs[0].transport == transport


def test_bad_entry_is_reported_and_others_kept() -> None:
    block = {"broken": {"command": "npx", "args": "not-a-list"}, "filesystem": FILESYSTEM}
    specs, problems = parse_servers(block, Source.CONFIG_FILE, None)
    assert [s.name for s in specs] == ["filesystem"]
    assert problems == ["broken: args is not a list of strings"]


# --- Files -----------------------------------------------------------------------------


def test_missing_file_is_reported_not_raised(tmp_path: Path) -> None:
    result = read_config_file(tmp_path / "nope.json")
    assert result.servers == []
    assert result.sources[0].status == "missing"


def test_invalid_json_is_reported_not_raised(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    result = read_config_file(path)
    assert result.sources[0].status == "invalid"


def test_any_file_with_mcp_servers_is_read(tmp_path: Path) -> None:
    # Cursor, VS Code-like or n8n exports: same format, read as a plain config file.
    path = write(tmp_path / "other-app.json", {"mcpServers": {"filesystem": FILESYSTEM}})
    result = read_config_file(path)
    assert [s.name for s in result.servers] == ["filesystem"]
    assert result.servers[0].config_path == str(path)


@pytest.mark.parametrize(
    ("platform", "suffix"),
    [
        ("darwin", "Library/Application Support/Claude/claude_desktop_config.json"),
        ("win32", "AppData/Roaming/Claude/claude_desktop_config.json"),
        ("linux", ".config/Claude/claude_desktop_config.json"),
    ],
)
def test_claude_desktop_path_per_platform(platform: str, suffix: str) -> None:
    assert claude_desktop_config(Path("/home/u"), platform) == Path("/home/u") / suffix


# --- Known applications -------------------------------------------------------------------


def test_all_claude_sources_are_found(tmp_path: Path) -> None:
    home, project = tmp_path / "home", tmp_path / "work" / "proj"
    write(claude_desktop_config(home, "darwin"), {"mcpServers": {"filesystem": FILESYSTEM}})
    write(
        home / ".claude.json",
        {
            "mcpServers": {"github": GITHUB},
            "projects": {str(project): {"mcpServers": {"local-fs": FILESYSTEM}}},
        },
    )
    write(project / ".mcp.json", {"mcpServers": {"team-fs": FILESYSTEM}})

    result = discover_known(home, project, "darwin", env={}, system_root=NO_SYSTEM)

    assert {(s.name, s.source) for s in result.servers} == {
        ("filesystem", Source.CLAUDE_DESKTOP),
        ("github", Source.CLAUDE_CODE_USER),
        ("local-fs", Source.CLAUDE_CODE_LOCAL),
        ("team-fs", Source.PROJECT_MCP_JSON),
    }


def test_nothing_installed_lists_every_source_as_missing(tmp_path: Path) -> None:
    result = discover_known(tmp_path, tmp_path, "darwin", env={}, system_root=NO_SYSTEM)
    assert result.servers == []
    assert {s.status for s in result.sources} == {"missing"}
    # ~/.claude.json + 7 files of the user and the machine + 7 files of the current folder
    assert len(result.sources) == 15


def test_local_servers_of_every_project_are_found(tmp_path: Path) -> None:
    # Claude Code keeps local servers of every project in ~/.claude.json: all of them count,
    # not only the project the command runs in.
    projects = {
        "/work/a": {"mcpServers": {"fs": FILESYSTEM}},
        "/work/b": {"mcpServers": {"fs": FILESYSTEM}},
        "/work/c": {"allowedTools": []},
    }
    write(tmp_path / ".claude.json", {"projects": projects})
    result = discover_known(tmp_path, tmp_path / "here", "darwin", env={}, system_root=NO_SYSTEM)
    assert sorted((s.project, s.name) for s in result.servers) == [
        ("/work/a", "fs"),
        ("/work/b", "fs"),
    ]
    assert len({s.key for s in result.servers}) == 2  # same name, two projects: two keys


def test_project_files_of_other_claude_projects_are_read(tmp_path: Path) -> None:
    home, other = tmp_path / "home", tmp_path / "other-project"
    write(home / ".claude.json", {"projects": {str(other): {}}})
    write(other / ".cursor" / "mcp.json", {"mcpServers": {"notes": FILESYSTEM}})
    result = discover_known(home, tmp_path / "here", "darwin", env={}, system_root=NO_SYSTEM)
    assert [(s.name, s.source, s.project) for s in result.servers] == [
        ("notes", Source.CURSOR_PROJECT, str(other))
    ]
    # Missing files of other projects are not listed, to keep the report readable.
    assert all(str(other) not in s.path or s.status == "read" for s in result.sources)


@pytest.mark.parametrize(
    ("platform", "suffix"),
    [
        ("darwin", "Library/Application Support/ClaudeCode/managed-mcp.json"),
        ("linux", "etc/claude-code/managed-mcp.json"),
        ("win32", "Program Files/ClaudeCode/managed-mcp.json"),
    ],
)
def test_claude_code_managed_file(tmp_path: Path, platform: str, suffix: str) -> None:
    root = tmp_path / "root"
    write(root / suffix, {"mcpServers": {"company": FILESYSTEM}})
    result = discover_known(tmp_path, tmp_path / "p", platform, env={}, system_root=root)
    assert [(s.name, s.source) for s in result.servers] == [("company", Source.CLAUDE_CODE_MANAGED)]


@pytest.mark.parametrize(
    ("platform", "suffix"),
    [
        ("darwin", "Library/Application Support/GeminiCli/settings.json"),
        ("linux", "etc/gemini-cli/settings.json"),
        ("win32", "ProgramData/gemini-cli/settings.json"),
    ],
)
def test_gemini_system_settings(tmp_path: Path, platform: str, suffix: str) -> None:
    root = tmp_path / "root"
    write(root / suffix, {"mcpServers": {"admin": FILESYSTEM}})
    result = discover_known(tmp_path, tmp_path / "p", platform, env={}, system_root=root)
    assert [(s.name, s.source) for s in result.servers] == [("admin", Source.GEMINI_SYSTEM)]


def test_gemini_system_settings_path_can_be_overridden(tmp_path: Path) -> None:
    custom = write(tmp_path / "custom.json", {"mcpServers": {"admin": FILESYSTEM}})
    env = {"GEMINI_CLI_SYSTEM_SETTINGS_PATH": str(custom)}
    result = discover_known(tmp_path, tmp_path / "p", "linux", env=env, system_root=NO_SYSTEM)
    assert [s.source for s in result.servers] == [Source.GEMINI_SYSTEM]


@pytest.mark.parametrize(
    "where",
    [
        ".devcontainer/devcontainer.json",
        ".devcontainer.json",
        ".devcontainer/python/devcontainer.json",
    ],
)
def test_devcontainer_servers(tmp_path: Path, where: str) -> None:
    project = tmp_path / "proj"
    config = {"customizations": {"vscode": {"mcp": {"servers": {"pw": FILESYSTEM}}}}}
    write(project / where, config)
    result = discover_known(tmp_path / "home", project, "darwin", env={}, system_root=NO_SYSTEM)
    assert [(s.name, s.source) for s in result.servers] == [("pw", Source.DEVCONTAINER)]


def test_claude_desktop_on_windows_follows_appdata() -> None:
    path = claude_desktop_config(Path("C:/Users/u"), "win32", {"APPDATA": "D:/Roaming"})
    assert path == Path("D:/Roaming/Claude/claude_desktop_config.json")


# --- Other applications -------------------------------------------------------------


def found(home: Path, project: Path) -> set[tuple[str, Source]]:
    return {
        (s.name, s.source)
        for s in discover_known(home, project, "darwin", env={}, system_root=NO_SYSTEM).servers
    }


def test_cursor_user_and_project(tmp_path: Path) -> None:
    home, project = tmp_path / "home", tmp_path / "proj"
    write(home / ".cursor" / "mcp.json", {"mcpServers": {"a": FILESYSTEM}})
    write(project / ".cursor" / "mcp.json", {"mcpServers": {"b": FILESYSTEM}})
    assert found(home, project) == {("a", Source.CURSOR_USER), ("b", Source.CURSOR_PROJECT)}


def test_vscode_uses_servers_key_and_allows_comments(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    path = project / ".vscode" / "mcp.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        """{
  // VS Code reads this file as JSON with comments
  "servers": {
    "fs": {"type": "stdio", "command": "npx", "args": ["server-filesystem"],},
    /* a remote one */
    "web": {"type": "http", "url": "https://example.invalid/mcp"},
  },
}""",
        encoding="utf-8",
    )
    result = discover_known(tmp_path / "home", project, "darwin", env={}, system_root=NO_SYSTEM)
    assert {(s.name, s.transport) for s in result.servers} == {("fs", "stdio"), ("web", "http")}


def test_copilot_home_is_honoured(tmp_path: Path) -> None:
    custom = tmp_path / "custom-copilot"
    write(custom / "mcp-config.json", {"mcpServers": {"c": FILESYSTEM}})
    result = discover_known(
        tmp_path, tmp_path, "darwin", env={"COPILOT_HOME": str(custom)}, system_root=NO_SYSTEM
    )
    assert [(s.name, s.source) for s in result.servers] == [("c", Source.COPILOT_USER)]


def test_gemini_http_url(tmp_path: Path) -> None:
    write(
        tmp_path / ".gemini" / "settings.json",
        {"mcpServers": {"g": {"httpUrl": "http://localhost:3000/mcp"}}},
    )
    spec = discover_known(
        tmp_path, tmp_path / "p", "darwin", env={}, system_root=NO_SYSTEM
    ).servers[0]
    assert (spec.source, spec.transport, spec.url) == (
        Source.GEMINI_USER,
        "http",
        "http://localhost:3000/mcp",
    )


CODEX_TOML = """
model = "some-model"

[mcp_servers.fs]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice/notes"]

[mcp_servers.fs.env]
API_KEY = "FAKE-TOKEN-NOT-A-SECRET-0000"
"""


def test_codex_toml(tmp_path: Path) -> None:
    path = tmp_path / ".codex" / "config.toml"
    path.parent.mkdir()
    path.write_text(CODEX_TOML, encoding="utf-8")
    spec = discover_known(
        tmp_path, tmp_path / "p", "darwin", env={}, system_root=NO_SYSTEM
    ).servers[0]
    assert (spec.name, spec.source, spec.env_keys) == ("fs", Source.CODEX_USER, ["API_KEY"])
    assert FAKE_TOKEN not in spec.model_dump_json()


def test_config_option_reads_toml_and_servers_key(tmp_path: Path) -> None:
    toml = tmp_path / "config.toml"
    toml.write_text(CODEX_TOML, encoding="utf-8")
    vscode = write(tmp_path / "mcp.json", {"servers": {"v": FILESYSTEM}})
    assert [s.name for s in read_config_file(toml).servers] == ["fs"]
    assert [s.name for s in read_config_file(vscode).servers] == ["v"]


def test_jsonc_keeps_slashes_inside_strings() -> None:
    text = '{"url": "https://a.invalid/x", "s": "a /* b */ c", } // end'
    assert json.loads(strip_jsonc(text)) == {"url": "https://a.invalid/x", "s": "a /* b */ c"}


def test_invalid_toml_is_reported_not_raised(tmp_path: Path) -> None:
    path = tmp_path / ".codex" / "config.toml"
    path.parent.mkdir()
    path.write_text("[mcp_servers.fs\n", encoding="utf-8")
    statuses = discover_known(
        tmp_path, tmp_path / "p", "darwin", env={}, system_root=NO_SYSTEM
    ).sources
    assert any(s.source is Source.CODEX_USER and s.status == "invalid" for s in statuses)


# --- Typed command ---------------------------------------------------------------------


def test_typed_command_becomes_a_stdio_server() -> None:
    spec = from_command(["npx", "-y", "@modelcontextprotocol/server-filesystem", "/lab/notes"])
    assert (spec.source, spec.transport, spec.command) == (Source.COMMAND_LINE, "stdio", "npx")
    assert spec.args[-1] == "/lab/notes"


def test_empty_command_is_refused() -> None:
    with pytest.raises(ValueError, match="empty"):
        from_command([])


# --- Command line ------------------------------------------------------------------------


def test_cli_discover_with_config_never_prints_env_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path / "c.json", {"mcpServers": {"github": GITHUB}})
    assert main(["discover", "--config", str(path)]) == 0
    out = capsys.readouterr().out
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in out
    assert FAKE_TOKEN not in out


def test_cli_discover_typed_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["discover", "--json", "--", "npx", "server-filesystem", "/lab/notes"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["servers"][0]["args"] == ["server-filesystem", "/lab/notes"]
