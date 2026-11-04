"""Static checks C1 to C5: read a server's configuration, run nothing.

Each check looks at one ServerSpec and returns a CheckRun (what happened) and zero or more
Findings (problems). A static check only ever cites the configuration, so its evidence is
always EvidenceSource.CONFIG, and it never claims that the server actually did anything.

Status rules used here:

- CONFIRMED only when the configuration itself is the problem and is certain: a token with a
  known shape written in clear (C2).
- NEEDS_REVIEW for everything that depends on what the user intended or on the server's code:
  a broad folder may be wanted, an old version may be patched downstream.
- NOT_RUN, with the reason, when a check does not apply to a server (a remote server has no
  local folder to check).

References: OWASP MCP Top 10, edition 2025 (https://owasp.org/www-project-mcp-top-10/);
CWE-22 for C1, CWE-798 for C2; OSV.dev for C4.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from mcp_audit.discovery import ServerSpec
from mcp_audit.models import (
    CheckRun,
    Evidence,
    EvidenceSource,
    Finding,
    FindingKind,
    RealConfigSection,
    Severity,
    Status,
)

OWASP_EDITION = "2025"

# --- Helpers ---------------------------------------------------------------------


def _config_evidence(spec: ServerSpec, summary: str, **data: object) -> Evidence:
    return Evidence(
        source=EvidenceSource.CONFIG,
        summary=summary,
        data={"server": spec.key, "config": spec.config_path or spec.source, **data},
    )


def _run(spec: ServerSpec, check_id: str, findings: list[Finding], reason: str | None = None):
    """The CheckRun of a check: the worst finding status, or PASSED / NOT_RUN."""
    if reason is not None:
        status = Status.NOT_RUN
    elif any(f.status is Status.CONFIRMED for f in findings):
        status = Status.CONFIRMED
    elif findings:
        status = Status.NEEDS_REVIEW
    else:
        status = Status.PASSED
    return CheckRun(check_id=check_id, server=spec.key, status=status, reason=reason)


@dataclass(frozen=True)
class Package:
    runner: str  # npx, uvx, docker...
    name: str
    version: str | None  # None when not pinned


_FLAGS_WITH_VALUE = {"-p", "--package", "--from", "--registry", "--cache", "--python"}


def _first_positional(args: list[str]) -> str | None:
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in _FLAGS_WITH_VALUE:
            skip = True
            continue
        if not arg.startswith("-"):
            return arg
    return None


def _flag_value(args: list[str], *flags: str) -> str | None:
    for i, arg in enumerate(args):
        for flag in flags:
            if arg == flag and i + 1 < len(args):
                return args[i + 1]
            if arg.startswith(flag + "="):
                return arg.split("=", 1)[1]
    return None


def _split_npm(spec: str) -> tuple[str, str | None]:
    """'@scope/pkg@1.2.3' -> ('@scope/pkg', '1.2.3'); 'pkg' -> ('pkg', None)."""
    at = spec.rfind("@")
    if at > 0:
        return spec[:at], spec[at + 1 :] or None
    return spec, None


def package_of(spec: ServerSpec) -> Package | None:
    """The package a launcher command installs and runs, when the command is a launcher."""
    if not spec.command:
        return None
    runner = spec.command.rsplit("/", 1)[-1].removesuffix(".cmd").removesuffix(".exe")
    args = spec.args
    if runner in {"npx", "bunx", "pnpx"} or (runner in {"pnpm", "yarn"} and args[:1] == ["dlx"]):
        rest = args[1:] if runner in {"pnpm", "yarn"} else args
        target = _flag_value(rest, "-p", "--package") or _first_positional(rest)
        if not target:
            return None
        name, version = _split_npm(target)
        return Package(runner, name, version)
    if runner in {"uvx", "pipx"} or (runner == "uv" and args[:2] == ["tool", "run"]):
        rest = args[2:] if runner == "uv" else args[1:] if args[:1] == ["run"] else args
        target = _flag_value(rest, "--from") or _first_positional(rest)
        if not target:
            return None
        match = re.match(r"^([A-Za-z0-9_.\[\]-]+?)\s*==\s*(\S+)$", target)
        return Package(runner, *match.groups()) if match else Package(runner, target, None)
    if runner in {"docker", "podman"} and args[:1] == ["run"]:
        image = _first_positional(args[1:])
        if not image:
            return None
        if "@sha256:" in image:
            return Package(runner, image.split("@", 1)[0], image.split("@", 1)[1])
        last = image.rsplit("/", 1)[-1]
        if ":" in last:
            name, tag = image.rsplit(":", 1)
            return Package(runner, name, tag)
        return Package(runner, image, None)
    return None


def _version_tuple(version: str) -> tuple[int, ...] | None:
    parts = re.findall(r"\d+", version)
    if not parts or not re.match(r"^v?\d+(\.\d+)*$", version):
        return None
    return tuple(int(p) for p in parts)


# --- C1: folders broader than needed -----------------------------------------------

_ROOTS = re.compile(r"^(/|[A-Za-z]:\\?)$")
_HOME = re.compile(
    r"^(~|\$HOME|\$\{HOME\}|%USERPROFILE%|/Users/[^/]+|/home/[^/]+|/root|[A-Za-z]:\\Users\\[^\\]+)$"
)
_HOME_PARENT = re.compile(r"^(/Users|/home|[A-Za-z]:\\Users)$")
_SENSITIVE = re.compile(
    r"^(~|\$HOME|\$\{HOME\}|/Users/[^/]+|/home/[^/]+|/root)/"
    r"(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config|\.azure|Library/Keychains)$"
    r"|^/etc$"
)


def _path_candidates(args: list[str]) -> list[tuple[int, str]]:
    out = []
    for i, arg in enumerate(args):
        value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
        value = value.rstrip("/\\") or value  # "/Users/taha/" -> "/Users/taha", "/" stays
        out.append((i, value))
    return out


def check_c1(spec: ServerSpec) -> tuple[CheckRun, list[Finding]]:
    if spec.transport != "stdio":
        reason = "remote server: no local folder in its configuration"
        return _run(spec, "C1", [], reason=reason), []
    findings = []
    for i, path in _path_candidates(spec.args):
        if _ROOTS.match(path):
            scope, severity = "the whole disk", Severity.CRITICAL
        elif _HOME_PARENT.match(path):
            scope, severity = "every user's home folder", Severity.CRITICAL
        elif _HOME.match(path):
            scope, severity = "your whole home folder (SSH keys, documents...)", Severity.HIGH
        elif _SENSITIVE.match(path):
            scope, severity = "a folder that holds credentials", Severity.HIGH
        else:
            continue
        findings.append(
            Finding(
                check_id="C1",
                server=spec.key,
                title=f"Argument {path!r} gives access to {scope}",
                status=Status.NEEDS_REVIEW,
                kind=FindingKind.CONFIG_GAP,
                severity=severity,
                severity_rationale=(
                    f"If this server treats {path!r} as an allowed folder, the AI can read "
                    f"{scope}. Whether it is wanted depends on your intent."
                ),
                owasp=["MCP02"],
                evidence=[_config_evidence(spec, f"args[{i}] = {path!r}", arg_index=i)],
                recommendation="Allow only the folder the server needs, e.g. ~/Documents/notes.",
                limits=[
                    "Static: whether this argument is a folder the server may access depends "
                    "on the server; no policy of expected folders was given."
                ],
            )
        )
    return _run(spec, "C1", findings), findings


# --- C2: secrets in clear ---------------------------------------------------------------


def check_c2(spec: ServerSpec) -> tuple[CheckRun, list[Finding]]:
    findings = []
    for hint in spec.secrets:
        certain = hint.confidence == "pattern"
        what = (
            f"a token matching gitleaks rule {hint.kind}"
            if certain
            else "a value named like a secret"
        )
        findings.append(
            Finding(
                check_id="C2",
                server=spec.key,
                title=f"{hint.location} holds {what} written in clear",
                status=Status.CONFIRMED if certain else Status.NEEDS_REVIEW,
                kind=FindingKind.CONFIG_GAP,
                severity=Severity.MEDIUM,
                severity_rationale=(
                    "Anyone or anything that can read this file (backup, sync, screen share, "
                    "another tool) gets the secret."
                ),
                owasp=["MCP01"],
                evidence=[
                    _config_evidence(
                        spec,
                        f"{hint.location}: {what} (value masked)",
                        location=hint.location,
                        detection=hint.confidence,
                    )
                ],
                recommendation=(
                    "Keep the secret out of the file: reference an environment variable "
                    "(e.g. ${GITHUB_TOKEN}) if your application supports it, or a secret "
                    "manager. Rotate the secret if this file was ever shared."
                ),
                limits=["The value is never read into the report; detection uses its shape."],
            )
        )
    return _run(spec, "C2", findings), findings


# --- C3: unpinned packages -------------------------------------------------------------


def check_c3(spec: ServerSpec) -> tuple[CheckRun, list[Finding]]:
    package = package_of(spec)
    if package is None:
        return _run(spec, "C3", [], reason="not started by a package launcher"), []
    if package.version and package.version != "latest":
        return _run(spec, "C3", []), []
    finding = Finding(
        check_id="C3",
        server=spec.key,
        title=f"{package.name} is not pinned to a version ({package.runner})",
        status=Status.NEEDS_REVIEW,
        kind=FindingKind.HINT,
        severity=Severity.MEDIUM,
        severity_rationale=(
            "Each start may download a different version: a compromised or broken release "
            "would run without any change on your side."
        ),
        owasp=["MCP04"],
        evidence=[
            _config_evidence(
                spec,
                f"{spec.command} {' '.join(spec.args)}",
                package=package.name,
                version=package.version,
            )
        ],
        recommendation=f"Pin an exact version, e.g. {package.name}@<version> for npx.",
        limits=["A pinned version is still trusted as published."],
    )
    return _run(spec, "C3", [finding]), [finding]


# --- C4: versions with a known advisory --------------------------------------------------

# Local copy of OSV data, so the audit works offline. Each range is [introduced, fixed).
# Source: https://osv.dev/vulnerability/GHSA-hc55-p739-j48w (CVE-2025-53110) and
# https://osv.dev/vulnerability/GHSA-q66q-fx2p-7w4m (CVE-2025-53109), read on 2026-11-04.
ADVISORIES: dict[str, list[dict[str, object]]] = {
    "@modelcontextprotocol/server-filesystem": [
        {
            "ids": ["CVE-2025-53110", "CVE-2025-53109"],
            "summary": "path validation bypass (colliding prefix, symlinks)",
            "ranges": [((0,), (0, 6, 3)), ((2025, 1, 14), (2025, 7, 1))],
            "fixed": "2025.7.1",
        }
    ]
}


def check_c4(spec: ServerSpec) -> tuple[CheckRun, list[Finding]]:
    package = package_of(spec)
    if package is None or package.name not in ADVISORIES:
        return _run(spec, "C4", [], reason="no advisory data for this server"), []
    if not package.version or package.version == "latest":
        return _run(spec, "C4", [], reason="version not pinned: cannot tell which runs"), []
    version = _version_tuple(package.version)
    if version is None:
        return _run(spec, "C4", [], reason=f"unrecognised version {package.version!r}"), []
    findings = []
    for advisory in ADVISORIES[package.name]:
        ranges = advisory["ranges"]
        assert isinstance(ranges, list)  # noqa: S101 - shape of the table above
        if not any(low <= version < high for low, high in ranges):
            continue
        ids = ", ".join(advisory["ids"])  # type: ignore[arg-type]
        findings.append(
            Finding(
                check_id="C4",
                server=spec.key,
                title=f"{package.name}@{package.version} is affected by {ids}",
                status=Status.NEEDS_REVIEW,
                kind=FindingKind.IMPLEMENTATION_DEFECT,
                severity=Severity.HIGH,
                severity_rationale=f"Published advisory: {advisory['summary']}.",
                owasp=["MCP04"],
                evidence=[
                    _config_evidence(
                        spec,
                        f"version {package.version} pinned in the configuration",
                        package=package.name,
                        version=package.version,
                        advisories=advisory["ids"],
                    )
                ],
                recommendation=(
                    f"Upgrade to {advisory['fixed']} or later. Narrowing the allowed folders "
                    "does not fix this: the bypass works from any allowed folder."
                ),
                limits=["Based on the published advisory; the lab test (D1) can confirm it."],
            )
        )
    return _run(spec, "C4", findings), findings


# --- C5: risky ways of starting the server ---------------------------------------------

_SHELLS = {"sh", "bash", "zsh", "dash", "fish", "cmd", "powershell", "pwsh"}


def check_c5(spec: ServerSpec) -> tuple[CheckRun, list[Finding]]:
    if not spec.command:
        return _run(spec, "C5", [], reason="remote server: not started on this machine"), []
    runner = spec.command.rsplit("/", 1)[-1].removesuffix(".exe")
    reasons: list[tuple[str, Severity]] = []
    if runner in _SHELLS and any(a in {"-c", "/c", "-Command"} for a in spec.args):
        reasons.append(("started through a shell: any command can be hidden in it", Severity.HIGH))
    if spec.command.startswith(("./", "../", ".\\")):
        reasons.append(
            (
                "started from a relative path: the program that runs depends on the folder "
                "the application starts in",
                Severity.LOW,
            )
        )
    if runner in {"docker", "podman"}:
        if "--privileged" in spec.args:
            reasons.append(("container started with --privileged", Severity.HIGH))
        for i, arg in enumerate(spec.args):
            mount = spec.args[i + 1] if arg in {"-v", "--volume"} and i + 1 < len(spec.args) else ""
            source = mount.split(":", 1)[0]
            if _ROOTS.match(source) or _HOME.match(source.rstrip("/")):
                reasons.append((f"container mounts {source!r}", Severity.HIGH))
    findings = [
        Finding(
            check_id="C5",
            server=spec.key,
            title=f"Risky launch: {why}",
            status=Status.NEEDS_REVIEW,
            kind=FindingKind.HINT,
            severity=severity,
            severity_rationale="Widens what the server can do beyond what its tools declare.",
            owasp=["MCP05", "MCP02"],
            evidence=[_config_evidence(spec, f"{spec.command} {' '.join(spec.args)}")],
            recommendation="Start the program directly, by absolute path, with no extra rights.",
        )
        for why, severity in reasons
    ]
    return _run(spec, "C5", findings), findings


# --- All checks ----------------------------------------------------------------------------

STATIC_CHECKS: list[Callable[[ServerSpec], tuple[CheckRun, list[Finding]]]] = [
    check_c1,
    check_c2,
    check_c3,
    check_c4,
    check_c5,
]


def run_static(specs: list[ServerSpec]) -> RealConfigSection:
    section = RealConfigSection()
    for spec in specs:
        for check in STATIC_CHECKS:
            run, findings = check(spec)
            section.checks.append(run)
            section.findings.extend(findings)
    return RealConfigSection.model_validate(section.model_dump())  # re-run section rules
