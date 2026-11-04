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
)

FILESYSTEM = {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/taha/notes"],
}
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
    assert specs[0].args[-1] == "/Users/taha/notes"


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

    result = discover_known(home, project, "darwin")

    assert {(s.name, s.source) for s in result.servers} == {
        ("filesystem", Source.CLAUDE_DESKTOP),
        ("github", Source.CLAUDE_CODE_USER),
        ("local-fs", Source.CLAUDE_CODE_LOCAL),
        ("team-fs", Source.CLAUDE_CODE_PROJECT),
    }


def test_nothing_installed_lists_every_source_as_missing(tmp_path: Path) -> None:
    result = discover_known(tmp_path, tmp_path, "darwin")
    assert result.servers == []
    assert {s.status for s in result.sources} == {"missing"}
    assert len(result.sources) == 3  # Desktop, ~/.claude.json, .mcp.json


def test_other_projects_are_not_mixed_in(tmp_path: Path) -> None:
    other = {"projects": {"/some/other/project": {"mcpServers": {"x": FILESYSTEM}}}}
    write(tmp_path / ".claude.json", other)
    assert discover_known(tmp_path, tmp_path / "here", "darwin").servers == []


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
