"""Start a program in a locked-down container, prepare the fake files, read them back.

Every option comes from docs/rules/D1.md, "Le conteneur", where each one is quoted from the
Docker documentation. Commands are lists of words given to Docker, never a line for a shell.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess  # noqa: S404 - only to run the docker CLI, always with a list of arguments
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.lab.programs import Program

IMAGES_DIR = Path(__file__).parent / "images"
LAB_HELPER = "/opt/mcp-audit/lab.js"
USER = "1000:1000"  # the "node" user of the base image, never root
LIMITS = ("--memory", "256m", "--cpus", "1", "--pids-limit", "64")
LAB_TMPFS = "/lab:rw,noexec,nosuid,nodev,size=8m,uid=1000,gid=1000,mode=0700"
TMP_TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=8m,uid=1000,gid=1000,mode=0700"  # noqa: S108 - in the container
LABEL = "mcp-audit-lab=1"
COMMAND_TIMEOUT = 60  # seconds, for each docker command
# What the docker CLI needs to find the engine: nothing from the MCP configuration.
DOCKER_ENV = (
    "PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY", "SYSTEMROOT", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
)  # fmt: skip

# Never in a lab command (docs/rules/D1.md, "Ce que D1 ne met jamais").
FORBIDDEN_WORDS = ("--privileged", "docker.sock", "-v", "--volume", "--mount", "-e", "--env",
                   "--env-file", "--network=host", "--pid", "--ipc", "--cap-add")  # fmt: skip


class LabError(RuntimeError):
    """Docker is missing, an image is not built, or a docker command failed."""


def docker_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k in DOCKER_ENV}


def run_args(name: str, image: str) -> list[str]:
    """The `docker run` command of a lab container. It only waits: programs start with exec."""
    return [
        "docker", "run", "--detach", "--rm",
        "--name", name,
        "--label", LABEL,
        "--network", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true",
        "--read-only",
        "--tmpfs", LAB_TMPFS,
        "--tmpfs", TMP_TMPFS,
        "--user", USER,
        *LIMITS,
        image,
        "sleep", "infinity",
    ]  # fmt: skip


def exec_args(
    name: str, command: tuple[str, ...] | list[str], interactive: bool = False
) -> list[str]:
    return ["docker", "exec", *(["--interactive"] if interactive else []), name, *command]


def check_args(args: list[str]) -> None:
    """Refuse a command that would open the container. Called before every docker run."""
    for word in args:
        if word in FORBIDDEN_WORDS or "docker.sock" in word:
            raise LabError(f"refused: {word!r} is never allowed in a lab command")


def _docker(args: list[str], stdin: str | None = None, timeout: int = COMMAND_TIMEOUT) -> str:
    if shutil.which("docker") is None:
        raise LabError("Docker is not installed or not in PATH")
    try:
        done = subprocess.run(  # noqa: S603 - a list of arguments, no shell
            args, input=stdin, capture_output=True, text=True, timeout=timeout, env=docker_env()
        )
    except subprocess.TimeoutExpired as error:
        raise LabError(f"{args[1]} took more than {timeout} s") from error
    if done.returncode != 0:
        raise LabError(f"docker {args[1]} failed: {done.stderr.strip()[-500:]}")
    return done.stdout


def engine_ready() -> str | None:
    """None when the Docker engine answers, else why not."""
    try:
        _docker(["docker", "version", "--format", "{{.Server.Version}}"], timeout=20)
    except LabError as error:
        return str(error)
    return None


def image_exists(image: str) -> bool:
    try:
        _docker(["docker", "image", "inspect", image], timeout=20)
    except LabError:
        return False
    return True


def build(program: Program) -> None:
    args = [
        "docker",
        "build",
        "--tag",
        program.image,
        "--file",
        str(IMAGES_DIR / program.dockerfile),
    ]
    for key, value in program.build_args:
        args += ["--build-arg", f"{key}={value}"]
    _docker([*args, str(IMAGES_DIR)], timeout=900)


@dataclass
class Container:
    """A running lab container. Use it with `with`: it is removed at the end, even on error."""

    image: str
    name: str = ""

    def __enter__(self) -> Container:
        self.name = f"mcp-audit-lab-{secrets.token_hex(6)}"
        args = run_args(self.name, self.image)
        check_args(args)
        _docker(args)
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            _docker(["docker", "rm", "--force", self.name], timeout=30)
        except LabError:
            pass  # --rm removes it anyway when it stops

    def setup(self, tokens: dict[str, str]) -> None:
        """Build the fake files. The tokens go on stdin, never in a command line."""
        _docker(exec_args(self.name, ["node", LAB_HELPER, "setup"], interactive=True),
                stdin=json.dumps({"tokens": tokens}))  # fmt: skip

    def snapshot(self) -> dict[str, dict[str, object]]:
        out = _docker(exec_args(self.name, ["node", LAB_HELPER, "snapshot"]))
        try:
            data = json.loads(out)
        except json.JSONDecodeError as error:
            raise LabError("the lab snapshot is not valid JSON") from error
        if not isinstance(data, dict):
            raise LabError("the lab snapshot is not a JSON object")
        return data

    def server_command(self, program: Program, folder: str) -> list[str]:
        return exec_args(self.name, [*program.command, folder], interactive=True)
