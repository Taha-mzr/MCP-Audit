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


def test_c1_flags_home_root_and_credentials_folders() -> None:
    for path, severity in [
        ("/", "critical"),
        ("/Users", "critical"),
        ("/Users/taha", "high"),
        ("/Users/taha/", "high"),
        ("~", "high"),
        ("/home/taha/.ssh", "high"),
    ]:
        run, findings = check_c1(spec("npx", "-y", FS, path))
        assert run.status is Status.NEEDS_REVIEW, path
        assert findings[0].severity == severity, path


def test_c1_accepts_a_narrow_folder() -> None:
    run, findings = check_c1(spec("npx", "-y", FS, "/Users/taha/notes"))
    assert (run.status, findings) == (Status.PASSED, [])


def test_c1_does_not_run_on_remote_servers() -> None:
    run, _ = check_c1(entry(type="http", url="https://example.invalid/mcp"))
    assert run.status is Status.NOT_RUN
    assert run.reason


# --- C2 ----------------------------------------------------------------------------------


def test_c2_confirms_a_known_token_and_never_shows_it() -> None:
    s = entry(command="npx", args=["x"], env={"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE_GITHUB})
    run, findings = check_c2(s)
    assert run.status is Status.CONFIRMED
    assert FAKE_GITHUB not in findings[0].model_dump_json()


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
    _, docker = check_c5(spec("docker", "run", "--privileged", "-v", "/Users/taha:/data", "img"))
    assert len(docker) == 2


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
