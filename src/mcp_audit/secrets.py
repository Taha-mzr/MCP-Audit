"""Recognise secrets written in clear in an MCP configuration, without ever keeping them.

Two signals, from the strongest to the weakest:

- the value has the shape of a known token (a small subset of the gitleaks rules,
  https://github.com/gitleaks/gitleaks): the secret is certainly there;
- the name says it is a secret (API_KEY, --token...) and the value is a literal: probably one.

A value that references a variable (``${GITHUB_TOKEN}``, ``${env:X}``, ``$X``) is not a secret in
clear: the configuration only says where to find it. That is the recommended practice
(CWE-798, Use of Hard-coded Credentials).
"""

from __future__ import annotations

import re
from typing import Literal

from mcp_audit.models import Strict

MASK = "***"

# Known token shapes. Kept short and specific to avoid flagging ordinary arguments.
TOKEN_PATTERNS: dict[str, re.Pattern[str]] = {
    "github_token": re.compile(r"^(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})$"),
    "anthropic_api_key": re.compile(r"^sk-ant-[A-Za-z0-9_-]{20,}$"),
    "openai_api_key": re.compile(r"^sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}$"),
    "aws_access_key_id": re.compile(r"^(AKIA|ASIA)[0-9A-Z]{16}$"),
    "slack_token": re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"),
    "google_api_key": re.compile(r"^AIza[0-9A-Za-z_-]{35}$"),
    "stripe_secret_key": re.compile(r"^(sk|rk)_live_[0-9A-Za-z]{20,}$"),
}

SECRET_NAME = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|PWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH|PAT$)",
    re.IGNORECASE,
)
SECRET_FLAGS = {
    "--api-key",
    "--apikey",
    "--token",
    "--access-token",
    "--auth-token",
    "--password",
    "--secret",
    "--client-secret",
    "--pat",
}
REFERENCE = re.compile(r"^\$\{[^}]+\}$|^\$[A-Za-z_][A-Za-z0-9_]*$")


class SecretHint(Strict):
    """Where a secret sits and why we think so. Never the value."""

    location: str  # "env:GITHUB_TOKEN", "header:Authorization", "arg:3"
    kind: str  # a TOKEN_PATTERNS key, or "secret_name" when only the name gives it away
    confidence: Literal["pattern", "name"]


def token_kind(value: str) -> str | None:
    value = value.strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    for kind, pattern in TOKEN_PATTERNS.items():
        if pattern.match(value):
            return kind
    return None


def classify(location: str, name: str, value: object) -> SecretHint | None:
    """A hint if ``value`` is a secret written in clear, None otherwise."""
    if not isinstance(value, str) or not value.strip() or REFERENCE.match(value.strip()):
        return None
    kind = token_kind(value)
    if kind:
        return SecretHint(location=location, kind=kind, confidence="pattern")
    if SECRET_NAME.search(name):
        return SecretHint(location=location, kind="secret_name", confidence="name")
    return None


def mask_args(args: list[str]) -> tuple[list[str], list[SecretHint]]:
    """Replace secret values in a command line by MASK. Returns the masked args and hints."""
    masked = list(args)
    hints: list[SecretHint] = []
    for i, arg in enumerate(args):
        if "=" in arg and arg.startswith("-"):
            flag, _, value = arg.partition("=")
            hint = classify(
                f"arg:{i}", flag.replace("-", "_") if flag in SECRET_FLAGS else "", value
            )
            if hint:
                masked[i] = f"{flag}={MASK}"
                hints.append(hint)
            continue
        previous = args[i - 1] if i else ""
        name = previous.replace("-", "_") if previous in SECRET_FLAGS else ""
        hint = classify(f"arg:{i}", name, arg) if (name or not arg.startswith("-")) else None
        if hint:
            masked[i] = MASK
            hints.append(hint)
    return masked, hints
