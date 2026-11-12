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
CWE-798 and the gitleaks rules for C2 (see secrets.py), OSV.dev for C4. Each rule's sources,
logic and limits are written in docs/rules/<id>.md. C1 cited CWE-22 (path traversal) until
2026-11-09: that was wrong, nothing is traversed; it now cites CWE-250 (docs/rules/C1.md).
The lists of broad or sensitive folders (C1) and of risky launches (C5) are this project's own
choices, not taken from a published rule set: review them when extending the checks.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial

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
from mcp_audit.policy import Policy

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
# Rule sheet: docs/rules/C1.md, validated by Taha on 2026-11-12. The lists below are this
# project's own choice: the MCP specification names the families "home directory, SSH keys,
# system directories" but gives no paths.

# Ways of writing the user's home folder; each is replaced by "~" before comparing.
_HOME_VARIABLES = re.compile(r"^(~|\$HOME|\$\{HOME\}|\$USERPROFILE|%USERPROFILE%|\$\{userHome\})")
_DRIVE = re.compile(r"^[a-z]:")
_ROOTS = re.compile(r"^(/|[a-z]:/)$")
_HOME_PARENT = re.compile(r"^(/users|/home|[a-z]:/users)$")
_HOME = re.compile(r"^(~|/users/[^/]+|/home/[^/]+|/root|/var/root|[a-z]:/users/[^/]+)(/|$)")
_NOT_A_HOME = {"/users/shared", "/users/guest"}
# Inside the home folder. A path inside one of these alerts too.
_CREDENTIALS = (
    ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config",
    "library/keychains", "library/application support",
    ".netrc", ".git-credentials", ".npmrc",
)  # fmt: skip
_RUNS_CODE = (
    ".claude", ".claude.json", ".cursor", ".codex", ".gemini", ".copilot",
    ".zshrc", ".bashrc", ".profile", "library/launchagents",
)  # fmt: skip
# System folders: only the folder itself alerts, not a folder inside it.
_SYSTEM = re.compile(
    r"^(/etc|/private/etc|/system|/library|/usr|/var|/private|[a-z]:/windows|[a-z]:/programdata)$"
)


def _normalise(raw: str) -> str:
    """The path as C1 compares it: lower case, '/' only, '.' and '..' resolved, home as '~'."""
    path = raw.strip()
    if path.lower().startswith("file://"):
        path = path[len("file://") :]
        if re.match(r"^/[A-Za-z]:", path):  # file:///C:/Users -> C:/Users
            path = path[1:]
    path = _HOME_VARIABLES.sub("~", path).replace("\\", "/")
    if not path:
        return path
    drive = ""
    if _DRIVE.match(path.lower()):
        drive, path = path[:2], path[2:]
        if not path:  # "C:" alone is the current folder of that drive, not its root
            return raw.lower()
    path = posixpath.normpath(path)
    if path.startswith("//"):
        path = "/" + path.lstrip("/")
    return (drive + path).lower()


def _classify(path: str) -> tuple[str, Severity] | None:
    """What a normalised path gives access to, most serious first."""
    if _ROOTS.match(path):
        return "the whole disk", Severity.CRITICAL
    if _HOME_PARENT.match(path):
        return "every user's home folder", Severity.CRITICAL
    home = _HOME.match(path)
    if home and home.group(1) not in _NOT_A_HOME:
        inside = path[home.end() :]
        if not inside:
            return "your whole home folder (SSH keys, documents...)", Severity.HIGH
        if any(inside == item or inside.startswith(item + "/") for item in _CREDENTIALS):
            return "a folder or file that holds credentials", Severity.HIGH
        if any(inside == item or inside.startswith(item + "/") for item in _RUNS_CODE):
            return (
                "a folder or file where writing makes a program run (AI app settings, "
                "shell startup, login items)",
                Severity.HIGH,
            )
        return None
    if _SYSTEM.match(path):
        return "a system folder", Severity.HIGH
    return None


# docker run / podman run options that take no value; every other option takes one.
_DOCKER_SWITCHES = {
    "--rm", "--init", "--privileged", "--interactive", "--tty", "--detach", "--read-only",
    "--publish-all", "--no-healthcheck", "--oom-kill-disable", "--sig-proxy",
}  # fmt: skip


def _mount_source(flag: str, value: str) -> str | None:
    """The host folder of a -v/--volume or --mount value, or None for a named volume."""
    if flag == "--mount":
        fields = dict(f.split("=", 1) for f in value.split(",") if "=" in f)
        if fields.get("type") != "bind":
            return None
        return fields.get("src") or fields.get("source")
    if re.match(r"^[A-Za-z]:[\\/]", value):  # C:\Users\sarah:/data
        source = value[:2] + value[2:].split(":", 1)[0]
    elif ":" in value:
        source = value.split(":", 1)[0]
    else:
        return None  # "-v /data": a volume created inside the container
    if not re.search(r"[/\\]", source) and not source.startswith(("~", "$", "%")):
        return None  # a named volume, e.g. "mesdonnees"
    return source


def _docker_mounts(args: list[str]) -> list[tuple[int, str]]:
    """Host folders mounted by `docker run` / `podman run`, with their index in args."""
    out = []
    i = 1  # args[0] is "run"
    while i < len(args):
        arg = args[i]
        if not arg.startswith("-"):
            break  # the image: what follows runs inside the container
        flag, has_value, value = arg.partition("=")
        if flag in {"-v", "--volume", "--mount"}:
            if not has_value:
                i += 1
                value = args[i] if i < len(args) else ""
            source = _mount_source(flag, value)
            if source:
                out.append((i, source))
        elif not has_value and arg not in _DOCKER_SWITCHES and not re.match(r"^-[a-zA-Z]+$", arg):
            i += 1  # a long option with its value in the next argument
        elif (
            not has_value and re.match(r"^-[a-zA-Z]$", arg) and arg not in {"-i", "-t", "-d", "-P"}
        ):
            i += 1  # a short option with a value, e.g. -e NAME=value, -w /folder
        i += 1
    return out


def _path_candidates(spec: ServerSpec) -> list[tuple[int, str]]:
    runner = (spec.command or "").rsplit("/", 1)[-1].removesuffix(".exe")
    if runner in {"docker", "podman"} and spec.args[:1] == ["run"]:
        return _docker_mounts(spec.args)
    out = []
    for i, arg in enumerate(spec.args):
        value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
        out.append((i, value))
    return out


def _as_home(path: str) -> str:
    """'/users/jean/notes' -> '~/notes', so that a config and a policy can be compared.
    Assumes the home folder in the config is the user's own (see the limits of C1)."""
    home = _HOME.match(path)
    if home and home.group(1) not in _NOT_A_HOME:
        return "~" + path[len(home.group(1)) :]
    return path


def _inside(path: str, folder: str) -> bool:
    return path == folder or path.startswith(folder.rstrip("/") + "/")


def _looks_like_a_path(path: str) -> bool:
    return path.startswith(("/", "~")) or bool(re.match(r"^[a-z]:/", path))


def _finding(spec: ServerSpec, i: int, path: str, scope: str, severity: Severity) -> Finding:
    return Finding(
        check_id="C1",
        server=spec.key,
        title=f"'{path}' gives access to {scope}, if this server treats it as a folder",
        status=Status.NEEDS_REVIEW,
        kind=FindingKind.CONFIG_GAP,
        severity=severity,
        severity_rationale=(
            f"If this server treats '{path}' as an allowed folder, the AI can reach "
            f"{scope}, and so can anyone who manages to steer the AI. Read-only access "
            "does not lower this: reading a private key is enough to steal it."
        ),
        owasp=["MCP02"],
        cwe=["CWE-250"],
        evidence=[_config_evidence(spec, f"args[{i}] = {spec.args[i]!r}", arg_index=i)],
        recommendation=(
            "Allow only the folder the server needs, e.g. ~/Documents/notes. With "
            "Docker, add :ro to -v (or ,ro to --mount) when the server only reads. "
            "Write what you allow in a policy file (--policy) to turn this into a clear yes or no."
        ),
        limits=[
            "Static: whether this argument is a folder the server may access depends "
            "on the server; no policy of expected folders was given.",
            "The application can send other folders (MCP Roots) while the server runs; "
            "they are not in the configuration.",
        ],
    )


def _policy_finding(
    spec: ServerSpec, i: int, path: str, policy: Policy, severity: Severity, scope: str | None
) -> Finding:
    allowed = policy.servers[spec.name]
    folders = [*allowed.read, *allowed.write]
    shown = ", ".join(folders) if folders else "no folder"
    gives = f"{scope}" if scope else f"'{path}'"
    return Finding(
        check_id="C1",
        server=spec.key,
        title=(
            f"'{path}' gives access to {scope}; your policy allows only {shown}"
            if scope
            else f"'{path}' is not allowed by your policy, which allows only {shown}"
        ),
        status=Status.CONFIRMED,
        kind=FindingKind.CONFIG_GAP,
        severity=severity,
        severity_rationale=(
            f"Your configuration gives this server {gives}; your policy allows only {shown}. "
            "Both come from you, not from the server, so the gap is certain."
        ),
        owasp=["MCP02"],
        cwe=["CWE-250"],
        evidence=[
            _config_evidence(spec, f"args[{i}] = {spec.args[i]!r}", arg_index=i),
            Evidence(
                source=EvidenceSource.POLICY,
                summary=(
                    f"servers.{spec.name}: read {list(allowed.read)}, write {list(allowed.write)}"
                ),
                data={"policy": policy.path, "server": spec.name},
            ),
        ],
        recommendation=(
            "Change the configuration to give only the folders of your policy, or change the "
            "policy if this folder is really wanted."
        ),
        limits=[
            "Static: whether this argument is a folder the server may access depends on the "
            "server. The lab test (D1) checks what the server really reads and writes.",
            "A home folder written as /Users/<name> is compared as ~: it is taken to be yours.",
        ],
    )


def check_c1(spec: ServerSpec, policy: Policy | None = None) -> tuple[CheckRun, list[Finding]]:
    if spec.command is None:  # a "url" only: nothing is started on this machine
        reason = "remote server: no local folder in its configuration"
        return _run(spec, "C1", [], reason=reason), []
    allowed = policy.servers.get(spec.name) if policy else None
    folders = [_as_home(_normalise(p)) for p in (*allowed.read, *allowed.write)] if allowed else []
    findings = []
    for i, path in _path_candidates(spec):
        normal = _normalise(path)
        found = _classify(normal)
        if allowed is None or policy is None:
            if found is not None:
                findings.append(_finding(spec, i, path, *found))
            continue
        if not _looks_like_a_path(normal):
            continue
        if any(_inside(_as_home(normal), folder) for folder in folders):
            continue
        scope, severity = found if found else (None, Severity.MEDIUM)
        findings.append(_policy_finding(spec, i, path, policy, severity, scope))
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
                cwe=["CWE-798"],
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
        # Mounted folders are checked by C1 since 2026-11-12 (docs/rules/C1.md).
        if "--privileged" in spec.args:
            reasons.append(("container started with --privileged", Severity.HIGH))
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


def run_static(specs: list[ServerSpec], policy: Policy | None = None) -> RealConfigSection:
    section = RealConfigSection()
    checks = [partial(check_c1, policy=policy), *STATIC_CHECKS[1:]]
    for spec in specs:
        for check in checks:
            run, findings = check(spec)
            section.checks.append(run)
            section.findings.extend(findings)
    return RealConfigSection.model_validate(section.model_dump())  # re-run section rules
