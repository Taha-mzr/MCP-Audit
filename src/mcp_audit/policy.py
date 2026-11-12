"""The policy file: what the user allows each MCP server to do (docs/policy.md).

A TOML file, read with the standard library (tomllib, Python 3.11+). Every field is this
project's own choice: no standard describes such a file. A badly written file stops the audit
with a clear message; nothing is guessed, so a typo can never allow or forbid a test silently.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

_SERVER_FIELDS = {"audit_authorized", "read", "write"}


class PolicyError(ValueError):
    """The policy file cannot be used; the message says why, for the user."""


@dataclass(frozen=True)
class ServerPolicy:
    audit_authorized: bool = False  # may D1 start this server in Docker?
    read: tuple[str, ...] = ()  # folders it may read
    write: tuple[str, ...] = ()  # folders it may write; writing also allows reading


@dataclass(frozen=True)
class Policy:
    path: str
    servers: dict[str, ServerPolicy] = field(default_factory=dict)  # by name in the config


def _paths(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f'{where} must be a list of paths, e.g. ["~/notes"]')
    if any(not v.strip() for v in value):
        raise PolicyError(f"empty path in {where}")
    return tuple(value)


def _server(name: str, table: object) -> ServerPolicy:
    where = f"servers.{name}"
    if not isinstance(table, dict):
        raise PolicyError(f"{where} must be a table: [servers.{name}]")
    for key in table:
        if key not in _SERVER_FIELDS:
            raise PolicyError(
                f"unknown field {key!r} in {where}; known fields: "
                + ", ".join(sorted(_SERVER_FIELDS))
            )
    authorized = table.get("audit_authorized", False)
    if not isinstance(authorized, bool):
        raise PolicyError(f"{where}.audit_authorized must be true or false")
    return ServerPolicy(
        audit_authorized=authorized,
        read=_paths(table.get("read", []), f"{where}.read"),
        write=_paths(table.get("write", []), f"{where}.write"),
    )


def load_policy(path: Path) -> Policy:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise PolicyError(f"cannot read the policy {path}: {error.strerror}") from error
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise PolicyError(f"the policy {path} is not valid TOML: {error}") from error
    for key in data:
        if key != "servers":
            raise PolicyError(
                f"unknown field {key!r} at the top of the policy; expected [servers.<name>]"
            )
    servers = data.get("servers", {})
    if not isinstance(servers, dict):
        raise PolicyError("servers must be a table of [servers.<name>] sections")
    return Policy(path=str(path), servers={name: _server(name, t) for name, t in servers.items()})
