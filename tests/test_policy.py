"""The policy file (docs/policy.md) and how C1 uses it."""

from pathlib import Path

import pytest

from mcp_audit.checks import check_c1
from mcp_audit.cli import main
from mcp_audit.discovery import from_command
from mcp_audit.models import EvidenceSource, Status
from mcp_audit.policy import PolicyError, load_policy

FS = "@modelcontextprotocol/server-filesystem"

EXAMPLE = """\
# Ma politique pour mcp-audit

[servers.notes]
audit_authorized = true
read = ["~/notes"]
write = ["~/notes/brouillons"]

[servers.maison]
read = ["~/Documents/cours"]
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "politique.toml"
    path.write_text(text, encoding="utf-8")
    return path


def server(name: str, *argv: str):  # noqa: ANN201
    return from_command(list(argv), name=name)


# --- Reading the file ---------------------------------------------------------------------


def test_the_example_of_the_sheet_is_read(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, EXAMPLE))
    assert policy.servers["notes"].audit_authorized is True
    assert policy.servers["notes"].read == ("~/notes",)
    assert policy.servers["notes"].write == ("~/notes/brouillons",)
    assert policy.servers["maison"].audit_authorized is False  # false by default
    assert policy.servers["maison"].write == ()


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[servers.notes]\nread = [~/notes\n", "not valid TOML"),
        ('[servers.notes]\nlecture = ["~/notes"]\n', "unknown field 'lecture' in servers.notes"),
        ('[servers.notes]\naudit_authorized = "oui"\n', "audit_authorized must be true or false"),
        ('[servers.notes]\nread = [""]\n', "empty path in servers.notes.read"),
        ('[servers.notes]\nread = "~/notes"\n', "servers.notes.read must be a list of paths"),
        ("[servers.notes]\nwrite = [1]\n", "servers.notes.write must be a list of paths"),
        ('[serveurs.notes]\nread = ["~/notes"]\n', "unknown field 'serveurs'"),
        ("servers = 1\n", "servers must be a table"),
        ("[servers]\nnotes = 1\n", "servers.notes must be a table"),
    ],
)
def test_a_badly_written_file_stops_with_a_clear_error(
    tmp_path: Path, text: str, message: str
) -> None:
    with pytest.raises(PolicyError, match=message.replace("[", r"\[").replace(".", r"\.")):
        load_policy(write(tmp_path, text))


def test_a_missing_file_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "absent.toml")


# --- C1 with a policy, the table of docs/policy.md -------------------------------------------


def test_c1_a_folder_inside_the_policy_passes(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, EXAMPLE))
    run, findings = check_c1(server("notes", "npx", "-y", FS, "/Users/jean/notes"), policy)
    assert (run.status, findings) == (Status.PASSED, [])
    run, _ = check_c1(server("notes", "npx", "-y", FS, "~/notes/brouillons/2026"), policy)
    assert run.status is Status.PASSED


def test_c1_a_folder_broader_than_the_policy_is_confirmed(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, EXAMPLE))
    run, findings = check_c1(server("maison", "npx", "-y", FS, "/Users/jean"), policy)
    assert run.status is Status.CONFIRMED
    [finding] = findings
    assert finding.status is Status.CONFIRMED
    assert finding.severity == "high"
    assert "~/Documents/cours" in finding.title
    sources = [e.source for e in finding.evidence]
    assert sources == [EvidenceSource.CONFIG, EvidenceSource.POLICY]


def test_c1_a_folder_outside_the_policy_is_confirmed_even_if_narrow(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, EXAMPLE))
    run, findings = check_c1(server("maison", "npx", "-y", FS, "/Users/jean/photos"), policy)
    assert run.status is Status.CONFIRMED
    assert findings[0].severity == "medium"


def test_c1_a_docker_mount_is_compared_too(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, EXAMPLE))
    argv = ["docker", "run", "-i", "--rm", "-v", "/Users/jean/notes:/projects", "img", "/"]
    assert check_c1(server("notes", *argv), policy)[0].status is Status.PASSED


def test_c1_a_home_folder_allowed_by_the_policy_passes(tmp_path: Path) -> None:
    # The user wrote that this server may see the whole home folder: that is their choice.
    policy = load_policy(write(tmp_path, '[servers.maison]\nread = ["~"]\n'))
    assert check_c1(server("maison", "npx", "-y", FS, "/Users/jean"), policy)[0].status is (
        Status.PASSED
    )


def test_c1_a_server_absent_from_the_policy_is_to_review_as_before(tmp_path: Path) -> None:
    policy = load_policy(write(tmp_path, EXAMPLE))
    run, findings = check_c1(server("autre", "npx", "-y", FS, "/Users/jean"), policy)
    assert run.status is Status.NEEDS_REVIEW
    assert [f.status for f in findings] == [Status.NEEDS_REVIEW]
    # Arguments that are not paths never count, with or without a policy.
    run, _ = check_c1(server("notes", "npx", "-y", FS, "--verbose"), policy)
    assert run.status is Status.PASSED


# --- Command line ---------------------------------------------------------------------------


def test_cli_audit_uses_the_policy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        '{"mcpServers": {"maison": {"command": "npx", "args": ["-y", "'
        + FS
        + '", "/Users/jean"]}}}'
    )
    policy = write(tmp_path, EXAMPLE)
    assert main(["audit", "--config", str(config), "--policy", str(policy)]) == 0
    out = capsys.readouterr().out
    assert "C1  CONFIRMED" in out
    assert "1 confirmed" in out


def test_cli_audit_stops_on_a_bad_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = write(tmp_path, '[servers.notes]\nlecture = ["~/notes"]\n')
    assert main(["audit", "--policy", str(policy), "--", "npx", "-y", FS, "/"]) == 2
    captured = capsys.readouterr()
    assert "unknown field 'lecture'" in captured.err
    assert "C1" not in captured.out
