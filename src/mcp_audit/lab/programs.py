"""The program sheets of the lab: which programs D1 can start, and how to talk to each.

A program is supported only when mcp-audit builds its image: the container has no network at
test time, so `npx` could not download anything. Tool names come from each package's published
code (dist/index.js), read on 2026-11-13; they change between versions (the current README names
read_text_file), which is why a sheet covers given versions only.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp_audit.checks import package_of
from mcp_audit.discovery import ServerSpec

IMAGE_PREFIX = "mcp-audit-lab"
FS_PACKAGE = "@modelcontextprotocol/server-filesystem"
FAKE_COMMAND = "mcp-audit-test-server"
FAKE_BEHAVIOURS = ("correct", "no-check", "liar", "refuse-all")


@dataclass(frozen=True)
class Program:
    name: str  # what the report shows
    version: str
    image: str  # local image tag, built by `mcp-audit lab build`
    dockerfile: str  # in mcp_audit/lab/images/
    build_args: tuple[tuple[str, str], ...]
    command: tuple[str, ...]  # inside the container; the allowed folder is appended
    read_tool: str  # takes {"path": ...}
    write_tool: str  # takes {"path": ..., "content": ...}


def _filesystem(version: str) -> Program:
    return Program(
        name=FS_PACKAGE,
        version=version,
        image=f"{IMAGE_PREFIX}/server-filesystem:{version}",
        dockerfile="Dockerfile.server-filesystem",
        build_args=(("VERSION", version),),
        command=(
            "node",
            "/opt/server/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js",
        ),
        read_tool="read_file",
        write_tool="write_file",
    )


def _fake(behaviour: str) -> Program:
    return Program(
        name=f"{FAKE_COMMAND} {behaviour}",
        version="1.0.0",
        image=f"{IMAGE_PREFIX}/fake:1",
        dockerfile="Dockerfile.fake",
        build_args=(),
        command=("node", "/opt/mcp-audit/fake-server.js", behaviour),
        read_tool="read_file",
        write_tool="write_file",
    )


# The versions of server-filesystem of the MVP: 2025.3.28 has CVE-2025-53110 in its code,
# 2025.7.1 fixes it (docs/rules/D1.md, "Le cas de référence").
FILESYSTEM_VERSIONS = ("2025.3.28", "2025.7.1")
PROGRAMS: tuple[Program, ...] = (
    *(_filesystem(v) for v in FILESYSTEM_VERSIONS),
    *(_fake(b) for b in FAKE_BEHAVIOURS),
)


def images() -> dict[str, Program]:
    """One program per image to build (the four fakes share one image)."""
    return {p.image: p for p in PROGRAMS}


@dataclass(frozen=True)
class Match:
    program: Program | None
    folders: tuple[str, ...]  # the folders the configuration gives, in order
    reason: str | None  # why D1 cannot run, when program is None


def match(spec: ServerSpec) -> Match:
    """The program sheet for a server of the configuration, and the folders it is given."""
    if spec.command is None:
        return Match(None, (), "remote server: nothing to start in the lab")
    runner = spec.command.rsplit("/", 1)[-1]
    if runner == FAKE_COMMAND:
        behaviour = spec.args[0] if spec.args else ""
        if behaviour not in FAKE_BEHAVIOURS:
            return Match(None, (), f"unknown test server behaviour {behaviour!r}")
        return Match(_fake(behaviour), tuple(spec.args[1:]), None)
    package = package_of(spec)
    if package is None or package.name != FS_PACKAGE:
        return Match(None, (), "no lab sheet for this program yet")
    if package.version not in FILESYSTEM_VERSIONS:
        supported = ", ".join(FILESYSTEM_VERSIONS)
        version = package.version or "an unpinned version"
        return Match(None, (), f"{version} is not a lab version (supported: {supported})")
    where = next((i for i, a in enumerate(spec.args) if FS_PACKAGE in a), None)
    if where is None:
        return Match(None, (), "could not find the folders in the arguments")
    after = spec.args[where + 1 :]
    return Match(
        _filesystem(package.version), tuple(a for a in after if not a.startswith("-")), None
    )
