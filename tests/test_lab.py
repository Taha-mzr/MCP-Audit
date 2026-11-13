"""D1, the lab test (docs/rules/D1.md).

The unit tests start nothing. The tests marked `docker` start lab containers: they run only when
Docker answers and the lab images are built (`mcp-audit lab build`), and are skipped otherwise.
"""

from __future__ import annotations

import sys
import textwrap

import pytest

from mcp_audit.discovery import ServerSpec
from mcp_audit.lab import container, probes, programs
from mcp_audit.lab.client import ClientError, StdioClient
from mcp_audit.lab.d1 import clean, run_d1, run_lab
from mcp_audit.models import Status
from mcp_audit.policy import Policy, ServerPolicy

NOTES = "/Users/jean/notes"
OLD = "@modelcontextprotocol/server-filesystem@2025.3.28"
NEW = "@modelcontextprotocol/server-filesystem@2025.7.1"


def spec(name: str, command: str | None, *args: str, url: str | None = None) -> ServerSpec:
    return ServerSpec(
        name=name,
        source="config_file",
        transport="http" if url else "stdio",
        command=command,
        args=list(args),
        url=url,
    )


def authorizing(*names: str) -> Policy:
    allowed = ServerPolicy(audit_authorized=True, read=(NOTES,))
    return Policy(path="politique.toml", servers=dict.fromkeys(names, allowed))


# --- The container command ------------------------------------------------------------------


def test_run_args_lock_the_container() -> None:
    args = container.run_args("mcp-audit-lab-x", "mcp-audit-lab/fake:1")
    joined = " ".join(args)
    for option in (
        "--network none",
        "--cap-drop ALL",
        "--security-opt no-new-privileges=true",
        "--read-only",
        "--user 1000:1000",
        "--memory 256m",
        "--pids-limit 64",
        "--rm",
    ):
        assert option in joined
    assert "--tmpfs" in args
    assert container.LAB_TMPFS.startswith("/lab:") and "noexec" in container.LAB_TMPFS
    container.check_args(args)  # does not raise


@pytest.mark.parametrize(
    "word",
    ["--privileged", "-v", "--volume", "--mount", "-e", "--env", "--cap-add",
     "/var/run/docker.sock:/var/run/docker.sock"],
)  # fmt: skip
def test_check_args_refuses_what_opens_the_container(word: str) -> None:
    args = container.run_args("x", "image")
    with pytest.raises(container.LabError, match="never allowed"):
        container.check_args([*args[:-2], word, *args[-2:]])


def test_docker_env_carries_nothing_from_the_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake" + "-value")
    monkeypatch.setenv("DOCKER_HOST", "unix:///tmp/d.sock")
    env = container.docker_env()
    assert "GITHUB_TOKEN" not in env
    assert env["DOCKER_HOST"] == "unix:///tmp/d.sock"


def test_server_command_is_a_list_and_passes_the_check() -> None:
    box = container.Container("mcp-audit-lab/fake:1", name="mcp-audit-lab-x")
    command = box.server_command(programs._fake("correct"), probes.ALLOWED)
    assert command[:4] == ["docker", "exec", "--interactive", "mcp-audit-lab-x"]
    assert command[-1] == "/lab/notes"
    container.check_args(command)


# --- Which program, which folders -----------------------------------------------------------


def test_match_server_filesystem_versions_of_the_lab() -> None:
    found = programs.match(spec("notes", "npx", "-y", OLD, NOTES, "/Users/jean/docs"))
    assert found.program is not None and found.program.version == "2025.3.28"
    assert found.folders == (NOTES, "/Users/jean/docs")
    assert programs.match(spec("notes", "npx", "-y", NEW, NOTES)).program is not None


@pytest.mark.parametrize(
    ("server", "reason"),
    [
        (spec("n", "npx", "-y", "@modelcontextprotocol/server-filesystem@2025.8.21", NOTES),
         "not a lab version"),
        (spec("n", "npx", "-y", "@modelcontextprotocol/server-filesystem", NOTES),
         "unpinned"),
        (spec("n", "npx", "-y", "@modelcontextprotocol/server-github"), "no lab sheet"),
        (spec("n", None, url="https://example.com/mcp"), "remote server"),
        (spec("n", "mcp-audit-test-server", "explode", NOTES), "unknown test server"),
    ],
)  # fmt: skip
def test_match_says_why_it_cannot_run(server: ServerSpec, reason: str) -> None:
    found = programs.match(server)
    assert found.program is None
    assert reason in (found.reason or "")


def test_match_fake_servers() -> None:
    found = programs.match(spec("t", "mcp-audit-test-server", "liar", NOTES))
    assert found.program is not None and found.program.command[-1] == "liar"
    assert found.folders == (NOTES,)


def test_four_fakes_share_one_image() -> None:
    assert len(programs.images()) == len(programs.FILESYSTEM_VERSIONS) + 1


# --- Verdicts, from outcomes only -----------------------------------------------------------

L3 = next(p for p in probes.PROBES if p.id == "L3")
E0 = next(p for p in probes.PROBES if p.id == "E0")
E2 = next(p for p in probes.PROBES if p.id == "E2")
TOKEN = "MCPAUDIT-" + "0123456789abcdef"


def file(sha: str) -> dict[str, object]:
    return {"type": "file", "size": 3, "sha256": sha}


def test_read_with_the_token_in_the_answer_is_confirmed() -> None:
    outcome = probes.Outcome(text=f"contents: {TOKEN}\n")
    verdict = probes.judge_read(L3, outcome, TOKEN, normal_ok=True)
    assert (verdict.status, verdict.access) == ("confirmed", "read_returned")


def test_the_token_counts_even_when_the_normal_read_failed() -> None:
    verdict = probes.judge_read(L3, probes.Outcome(text=TOKEN), TOKEN, normal_ok=False)
    assert verdict.status == "confirmed"


def test_a_refused_read_passes_only_if_the_normal_read_worked() -> None:
    refused = probes.Outcome(text="Access denied", is_error=True)
    assert probes.judge_read(L3, refused, TOKEN, normal_ok=True).status == "passed"
    assert probes.judge_read(L3, refused, TOKEN, normal_ok=False).status == "inconclusive"


def test_a_read_without_answer_is_inconclusive() -> None:
    silent = probes.Outcome(failure="no answer to tools/call after 15 s")
    assert probes.judge_read(L3, silent, TOKEN, normal_ok=True).status == "inconclusive"


def test_a_write_outside_is_confirmed_even_if_the_server_says_refused() -> None:
    outcome = probes.Outcome(
        text="Access denied",
        is_error=True,
        before={"/lab/notes-prive": {"type": "dir"}},
        after={"/lab/notes-prive": {"type": "dir"}, E2.path: file("ab")},
    )
    verdict = probes.judge_write(E2, outcome, normal_ok=True)
    assert verdict.status == "confirmed"
    assert verdict.changed == (E2.path,)


def test_a_write_inside_the_allowed_folder_is_not_a_finding() -> None:
    outcome = probes.Outcome(is_error=True, before={}, after={"/lab/notes/x.txt": file("ab")})
    assert probes.judge_write(E2, outcome, normal_ok=True).status == "passed"


def test_a_write_that_claims_success_without_change_is_inconclusive() -> None:
    outcome = probes.Outcome(text="Successfully wrote", is_error=False)
    assert probes.judge_write(E2, outcome, normal_ok=True).status == "inconclusive"


def test_a_refused_write_passes_only_if_the_normal_write_worked() -> None:
    refused = probes.Outcome(is_error=True)
    assert probes.judge_write(E2, refused, normal_ok=True).status == "passed"
    assert probes.judge_write(E2, refused, normal_ok=False).status == "inconclusive"


def test_the_normal_write_is_checked_on_the_disk() -> None:
    import hashlib

    content = probes.write_content(E0, "n1")
    good = hashlib.sha256(content.encode()).hexdigest()
    assert probes.normal_write_works(E0, probes.Outcome(after={E0.path: file(good)}), "n1")
    assert not probes.normal_write_works(E0, probes.Outcome(after={E0.path: file("0")}), "n1")
    assert not probes.normal_write_works(E0, probes.Outcome(text="Successfully wrote"), "n1")


def test_changed_paths_sees_creation_change_and_removal() -> None:
    before = {"/lab/a": file("1"), "/lab/b": file("2")}
    after = {"/lab/a": file("1"), "/lab/b": file("3"), "/lab/c": file("4")}
    assert probes.changed_paths(before, after) == ["/lab/b", "/lab/c"]
    assert probes.changed_paths(after, before) == ["/lab/b", "/lab/c"]


def test_sibling_folder_is_not_inside_the_allowed_folder() -> None:
    assert not probes._inside_allowed("/lab/notes-prive/x")
    assert probes._inside_allowed("/lab/notes/x")


def test_every_forbidden_read_has_a_token_and_every_probe_a_cwe() -> None:
    for probe in probes.PROBES:
        assert probe.cwe in {"CWE-22", "CWE-59"}
        if probe.forbidden and probe.kind == "read":
            assert probe.token in {"secret", "sibling"}


def test_clean_removes_control_characters() -> None:
    assert clean("ok\x1b[2Jhidden\x07\n", 50) == "ok[2Jhidden"
    assert len(clean("x" * 500)) == 200


# --- D1 does not start anything without reason ----------------------------------------------


@pytest.mark.parametrize(
    ("server", "policy", "reason"),
    [
        (spec("notes", "npx", "-y", OLD, NOTES), None, "audit_authorized"),
        (spec("notes", "npx", "-y", OLD, NOTES),
         Policy(path="p", servers={"notes": ServerPolicy(read=(NOTES,))}), "audit_authorized"),
        (spec("notes", "npx", "-y", OLD, NOTES), authorizing("other"), "audit_authorized"),
        (spec("gh", "npx", "-y", "@modelcontextprotocol/server-github"), authorizing("gh"),
         "no lab sheet"),
        (spec("notes", "npx", "-y", OLD), authorizing("notes"), "no folder"),
    ],
)  # fmt: skip
def test_d1_is_not_run(server: ServerSpec, policy: Policy | None, reason: str) -> None:
    run = run_d1(server, policy)
    assert run.check.status is Status.NOT_RUN
    assert reason in (run.check.reason or "")
    assert run.findings == []


def test_d1_is_not_run_without_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(container, "engine_ready", lambda: "Docker is not installed or not in PATH")
    run = run_d1(spec("notes", "npx", "-y", OLD, NOTES), authorizing("notes"))
    assert run.check.status is Status.NOT_RUN
    assert "Docker is not available" in (run.check.reason or "")


def test_d1_is_not_run_when_the_image_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(container, "engine_ready", lambda: None)
    monkeypatch.setattr(container, "image_exists", lambda image: False)
    run = run_d1(spec("notes", "npx", "-y", OLD, NOTES), authorizing("notes"))
    assert run.check.status is Status.NOT_RUN
    assert "mcp-audit lab build" in (run.check.reason or "")


# --- The client, against a peer written in Python here ---------------------------------------
# The peer is a few lines of our own test code, not an MCP program: it answers on stdout what
# each case needs, so the client is checked on bad input without starting any container.

PEER = textwrap.dedent(
    """
    import json, sys
    case = sys.argv[1]
    for line in sys.stdin:
        msg = json.loads(line)
        if "id" not in msg:
            continue
        reply = {"jsonrpc": "2.0", "id": msg["id"]}
        if msg["method"] == "initialize":
            reply["result"] = {"protocolVersion": "2024-11-05", "capabilities": {}}
        elif case == "noise":
            print("not json", flush=True)
            print("x" * 2_000_100, flush=True)
            print(json.dumps({"jsonrpc": "2.0", "id": 99, "method": "roots/list"}), flush=True)
            sys.stdin.readline()  # the client answers the request above
            reply["result"] = {"tools": [{"name": "read_file", "inputSchema": {}}]}
        elif case == "error":
            reply["error"] = {"code": -32602, "message": "bad\\x1b[31m params"}
        elif case == "silent":
            continue
        print(json.dumps(reply), flush=True)
    """
)


def peer(case: str) -> StdioClient:
    return StdioClient([sys.executable, "-I", "-c", PEER, case], env={})


def test_client_ignores_noise_and_answers_server_requests() -> None:
    with peer("noise") as client:
        client.initialize(10)
        assert client.list_tools(10) == ["read_file"]


def test_client_raises_on_error_and_on_silence() -> None:
    with peer("error") as client:
        client.initialize(10)
        with pytest.raises(ClientError, match="returned an error"):
            client.list_tools(10)
    with peer("silent") as client:
        client.initialize(10)
        with pytest.raises(ClientError, match="no answer"):
            client.list_tools(0.5)


def test_client_reports_a_server_that_stops() -> None:
    with StdioClient([sys.executable, "-I", "-c", "pass"], env={}) as client:
        with pytest.raises(ClientError):
            client.initialize(10)


# --- In containers: the expected results of docs/rules/D1.md ---------------------------------


def _lab_ready() -> bool:
    if container.engine_ready() is not None:
        return False
    return all(container.image_exists(image) for image in programs.images())


docker = pytest.mark.skipif(not _lab_ready(), reason="Docker or the lab images are missing")


def _found(run) -> set[str]:  # noqa: ANN001
    return {f.evidence[0].data["probe"] for f in run.findings}


@pytest.mark.docker
@docker
@pytest.mark.parametrize(
    ("behaviour", "status", "probes_found"),
    [
        ("correct", Status.PASSED, set()),
        ("no-check", Status.CONFIRMED, {"L1", "L2", "L3", "L4", "E1", "E2"}),
        ("liar", Status.CONFIRMED, {"E1", "E2"}),
        ("refuse-all", Status.INCONCLUSIVE, set()),
    ],
)
def test_fake_servers(behaviour: str, status: Status, probes_found: set[str]) -> None:
    run = run_d1(spec("t", "mcp-audit-test-server", behaviour, NOTES), authorizing("t"))
    assert run.check.status is status, run.check.reason
    assert _found(run) == probes_found


@pytest.mark.docker
@docker
def test_server_filesystem_2025_3_28_leaves_its_folder() -> None:
    run = run_d1(spec("notes", "npx", "-y", OLD, NOTES), authorizing("notes"))
    assert run.check.status is Status.CONFIRMED
    assert _found(run) == {"L3", "L4", "E2"}
    by_probe = {f.evidence[0].data["probe"]: f for f in run.findings}
    assert by_probe["L3"].cwe == ["CWE-22"]
    assert by_probe["L4"].cwe == ["CWE-59"]
    assert "read_file" in run.tools


@pytest.mark.docker
@docker
def test_server_filesystem_2025_7_1_stays_in_its_folder() -> None:
    run = run_d1(spec("notes", "npx", "-y", NEW, NOTES), authorizing("notes"))
    assert run.check.status is Status.PASSED, run.check.reason
    assert run.findings == []


@pytest.mark.docker
@docker
def test_run_lab_gives_a_valid_section() -> None:
    servers = [spec("notes", "npx", "-y", OLD, NOTES), spec("gh", None, url="https://x/mcp")]
    section = run_lab(servers, authorizing("notes", "gh"))
    assert [c.status for c in section.checks] == [Status.CONFIRMED, Status.NOT_RUN]
    assert {m.role for m in section.path_mapping} == {"allowed", "sibling_prefix", "outside"}
    assert section.not_reproduced
