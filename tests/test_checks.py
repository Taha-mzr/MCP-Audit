import pytest

from mcp_audit.checks import check_c1, check_c2, check_c3, check_c4, check_c5, package_of
from mcp_audit.cli import build_report, main
from mcp_audit.discovery import Discovery, ServerSpec, Source, from_command, parse_servers
from mcp_audit.models import Status

FAKE_GITHUB = "ghp_" + "F" * 36  # built by concatenation: no token-shaped literal in the file
FS = "@modelcontextprotocol/server-filesystem"


def spec(*argv: str) -> ServerSpec:
    return from_command(list(argv), name="s")


def entry(**fields: object) -> ServerSpec:
    specs, problems = parse_servers({"s": fields}, Source.CONFIG_FILE, None)
    assert not problems
    return specs[0]


# --- C1 ----------------------------------------------------------------------------------


# The examples of docs/rules/C1.md, in the same order. None means: no finding.
C1_SHEET_EXAMPLES = [
    (["npx", "-y", FS, "/Users/taha"], "high"),
    (["npx", "-y", FS, "/"], "critical"),
    (["npx", "-y", FS, "~/.ssh"], "high"),
    (["npx", "-y", FS, "C:\\Users\\taha\\.ssh"], "high"),
    (["npx", "-y", FS, "C:/Users/taha"], "high"),
    (["npx", "-y", FS, "/users/taha"], "high"),
    (["npx", "-y", FS, "file:///Users/taha"], "high"),
    (["npx", "-y", FS, "/Users/taha/notes/.."], "high"),
    (["npx", "-y", FS, "~/.claude"], "high"),
    (
        [
            "docker",
            "run",
            "-i",
            "--rm",
            "-v",
            "/Users/taha:/projects",
            "mcp/filesystem",
            "/projects",
        ],
        "high",
    ),
    (
        [
            "docker",
            "run",
            "-i",
            "--rm",
            "--mount",
            "type=bind,source=/Users/taha,dst=/projects",
            "mcp/filesystem",
            "/projects",
        ],
        "high",
    ),
    (["npx", "-y", FS, "/Users/username/Desktop"], None),
    (["npx", "-y", FS, "/Users/taha/notes"], None),
    (["npx", "-y", FS, "/Users/Shared"], None),
    (["npx", "-y", FS, "C:"], None),
    (
        [
            "docker",
            "run",
            "-i",
            "--rm",
            "--mount",
            "type=bind,src=/Users/taha/notes,dst=/root/notes",
            "img",
            "/root",
        ],
        None,
    ),
    (["docker", "run", "-i", "--rm", "-v", "mesdonnees:/data", "img"], None),
]


@pytest.mark.parametrize(("argv", "severity"), C1_SHEET_EXAMPLES, ids=lambda v: str(v))
def test_c1_sheet_examples(argv: list[str], severity: str | None) -> None:
    run, findings = check_c1(spec(*argv))
    if severity is None:
        assert (run.status, findings) == (Status.PASSED, [])
    else:
        assert run.status is Status.NEEDS_REVIEW
        assert [f.severity for f in findings] == [severity]
        assert findings[0].cwe == ["CWE-250"]
        assert findings[0].owasp == ["MCP02"]


@pytest.mark.parametrize(
    ("path", "severity"),
    [
        # Whole disk and every user's folder.
        ("D:/", "critical"),
        ("/Users", "critical"),
        ("/home", "critical"),
        ("C:\\Users", "critical"),
        # A whole home folder, written in every way the sheet lists.
        ("/Users/sarah/", "high"),
        ("/home/ahmed", "high"),
        ("/root", "high"),
        ("/var/root", "high"),
        ("~", "high"),
        ("$HOME", "high"),
        ("${HOME}", "high"),
        ("$USERPROFILE", "high"),
        ("%USERPROFILE%", "high"),
        ("${userHome}", "high"),
        # Secrets, and files or folders inside them.
        ("/home/ahmed/.aws", "high"),
        ("~/.ssh/cles-perso", "high"),
        ("$HOME/.netrc", "high"),
        ("/Users/sarah/Library/Keychains", "high"),
        ("/Users/sarah/Library/Application Support", "high"),
        ("%USERPROFILE%\\.git-credentials", "high"),
        # Writing there lets a program run code (decision 3).
        ("~/.claude.json", "high"),
        ("/Users/sarah/.cursor", "high"),
        ("~/.zshrc", "high"),
        ("/Users/sarah/Library/LaunchAgents", "high"),
        # System folders (decision 4).
        ("/etc", "high"),
        ("/private/etc", "high"),
        ("/System", "high"),
        ("/usr", "high"),
        ("C:\\Windows", "high"),
        ("c:/programdata", "high"),
        # The value after "=" of a flag.
        ("--root=/Users/sarah", "high"),
        # Not flagged.
        ("/Users/Guest", None),
        ("/Users/sarah/.claude-notes", None),
        ("/Users/sarah/Library", None),
        ("/usr/local/share/data", None),
        ("./data", None),
    ],
)
def test_c1_paths(path: str, severity: str | None) -> None:
    run, findings = check_c1(spec("npx", "-y", FS, path))
    assert [f.severity for f in findings] == ([severity] if severity else []), path


def test_c1_docker_reads_only_host_side_mounts() -> None:
    # -w, -e and every argument after the image are inside the container.
    argv = [
        "docker",
        "run",
        "-e",
        "HOME=/",
        "-w",
        "/",
        "--volume=C:\\Users\\sarah:/data",
        "--mount",
        "type=volume,src=/,dst=/x",
        "img",
        "/",
    ]
    run, findings = check_c1(spec(*argv))
    assert [f.severity for f in findings] == ["high"]
    assert "C:\\Users\\sarah" in findings[0].title
    assert findings[0].evidence[0].data["arg_index"] == 5  # the --volume= argument


def test_c1_podman_mounts_are_read_too() -> None:
    _, findings = check_c1(spec("podman", "run", "-v", "/home/ahmed:/w:ro", "img"))
    assert [f.severity for f in findings] == ["high"]  # read-only: same severity (decision 1)


def test_c1_does_not_run_on_remote_servers() -> None:
    run, _ = check_c1(entry(type="http", url="https://example.invalid/mcp"))
    assert run.status is Status.NOT_RUN
    assert run.reason


def test_c1_runs_on_a_local_server_with_an_unknown_type() -> None:
    # Found by review on 2026-11-09: an unknown "type" made C1 skip a local server as remote.
    run, findings = check_c1(entry(type="weird", command="npx", args=["-y", FS, "/"]))
    assert run.status is Status.NEEDS_REVIEW
    assert findings[0].severity == "critical"


# --- C2 ----------------------------------------------------------------------------------


def test_c2_confirms_a_known_token_and_never_shows_it() -> None:
    s = entry(command="npx", args=["x"], env={"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE_GITHUB})
    run, findings = check_c2(s)
    assert run.status is Status.CONFIRMED
    assert FAKE_GITHUB not in findings[0].model_dump_json()
    assert findings[0].cwe == ["CWE-798"]


def test_c2_name_only_needs_review() -> None:
    run, _ = check_c2(entry(command="npx", args=["x"], env={"API_KEY": "hunter2"}))
    assert run.status is Status.NEEDS_REVIEW


def test_c2_reference_passes() -> None:
    run, _ = check_c2(entry(command="npx", args=["x"], env={"API_KEY": "${API_KEY}"}))
    assert run.status is Status.PASSED


# --- C3 ----------------------------------------------------------------------------------


def test_package_parsing() -> None:
    assert package_of(spec("npx", "-y", f"{FS}@2025.7.1", "/d")).version == "2025.7.1"
    assert package_of(spec("npx", "-y", FS, "/d")).name == FS
    assert package_of(spec("npx", "-y", FS, "/d")).version is None
    assert package_of(spec("uvx", "mcp-server-fetch==1.2.0")).version == "1.2.0"
    assert (
        package_of(spec("uvx", "--from", "mcp-server-git==0.6", "mcp-server-git")).version == "0.6"
    )
    assert package_of(spec("docker", "run", "-i", "--rm", "mcp/fetch")).version is None
    assert package_of(spec("docker", "run", "mcp/fetch:1.0")).version == "1.0"
    assert package_of(spec("/usr/local/bin/my-server")) is None


def test_c3_unpinned_and_latest_need_review() -> None:
    for argv in (("npx", "-y", FS), ("npx", "-y", f"{FS}@latest"), ("docker", "run", "mcp/x")):
        run, _ = check_c3(spec(*argv))
        assert run.status is Status.NEEDS_REVIEW, argv


def test_c3_pinned_passes_and_plain_binary_is_not_run() -> None:
    assert check_c3(spec("npx", "-y", f"{FS}@2025.7.1"))[0].status is Status.PASSED
    assert check_c3(spec("/opt/server"))[0].status is Status.NOT_RUN


# --- C4 ----------------------------------------------------------------------------------


def test_c4_flags_the_versions_in_the_advisory_ranges() -> None:
    for version in ("2025.3.28", "2025.1.14", "0.6.2"):
        run, findings = check_c4(spec("npx", "-y", f"{FS}@{version}", "/d"))
        assert run.status is Status.NEEDS_REVIEW, version
        assert "CVE-2025-53110" in findings[0].title


def test_c4_fixed_version_passes() -> None:
    for version in ("2025.7.1", "2025.8.21"):
        assert check_c4(spec("npx", "-y", f"{FS}@{version}", "/d"))[0].status is Status.PASSED


def test_c4_cannot_judge_an_unpinned_or_unknown_server() -> None:
    assert check_c4(spec("npx", "-y", FS, "/d"))[0].status is Status.NOT_RUN
    assert check_c4(spec("npx", "-y", "some-other-server@1.0.0"))[0].status is Status.NOT_RUN


# --- C5 ----------------------------------------------------------------------------------


def test_c5_shell_relative_path_and_docker() -> None:
    assert check_c5(spec("sh", "-c", "npx server"))[1][0].severity == "high"
    # Seen in a real Codex configuration: the program depends on the starting folder.
    assert check_c5(spec("./Some.app/Contents/MacOS/client", "mcp"))[1][0].severity == "low"
    # Mounted folders are C1's job since 2026-11-12; C5 keeps --privileged.
    _, docker = check_c5(spec("docker", "run", "--privileged", "-v", "/Users/taha:/data", "img"))
    assert [f.title for f in docker] == ["Risky launch: container started with --privileged"]


def test_c5_plain_launch_passes() -> None:
    assert check_c5(spec("npx", "-y", f"{FS}@2025.7.1", "/d"))[0].status is Status.PASSED


# --- Whole report ------------------------------------------------------------------------


def test_report_has_one_run_per_check_and_server_and_no_secret() -> None:
    servers = [
        spec("npx", "-y", f"{FS}@2025.3.28", "/Users/taha"),
        entry(command="npx", args=["x"], env={"TOKEN": FAKE_GITHUB}),
    ]
    report = build_report(Discovery(servers=servers))
    assert len(report.real_config.checks) == 10
    assert report.owasp_mcp_top10_version == "2025"
    assert FAKE_GITHUB not in report.model_dump_json()


def test_same_name_in_two_applications_stays_two_servers() -> None:
    a = spec("npx", "-y", FS, "/")
    b = entry(command="npx", args=["x"], env={"TOKEN": FAKE_GITHUB})
    assert a.key != b.key
    assert len({r.server for r in build_report(Discovery(servers=[a, b])).real_config.checks}) == 2


def test_cli_audit_writes_the_json_report(tmp_path, capsys) -> None:  # noqa: ANN001
    out = tmp_path / "report.json"
    assert main(["audit", "--output", str(out), "--", "npx", "-y", FS, "/"]) == 0
    assert "TO REVIEW" in capsys.readouterr().out
    assert '"check_id": "C1"' in out.read_text()
