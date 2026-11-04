"""Recognise secrets written in clear in an MCP configuration, without ever keeping them.

Two signals, from the strongest to the weakest:

- the value has the shape of a known token (13 rules copied from gitleaks,
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

# Known token shapes, copied from the gitleaks default rules (MIT licence), read on 2026-11-04 at
# https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
# Only the token itself is kept from each rule (no surrounding delimiters); values are matched
# whole. Rule ids are the gitleaks ids.
TOKEN_PATTERNS: dict[str, re.Pattern[str]] = {
    rule_id: re.compile(pattern)
    for rule_id, pattern in {
        "github-pat": r"ghp_[0-9a-zA-Z]{36}",
        "github-fine-grained-pat": r"github_pat_\w{82}",
        "github-oauth": r"gho_[0-9a-zA-Z]{36}",
        "github-app-token": r"(?:ghu|ghs)_[0-9a-zA-Z]{36}",
        "github-refresh-token": r"ghr_[0-9a-zA-Z]{36}",
        "anthropic-api-key": r"sk-ant-api03-[a-zA-Z0-9_\-]{93}AA",
        "anthropic-admin-api-key": r"sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA",
        "openai-api-key": (
            r"sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ"
            r"(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"
        ),
        "aws-access-token": r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}",
        "slack-bot-token": r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "slack-user-token": r"xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}",
        "gcp-api-key": r"AIza[\w-]{35}",
        "stripe-access-token": r"(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}",
    }.items()
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
    kind: str  # a gitleaks rule id from TOKEN_PATTERNS, or "secret_name" (only the name says so)
    confidence: Literal["pattern", "name"]


def token_kind(value: str) -> str | None:
    value = value.strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    for kind, pattern in TOKEN_PATTERNS.items():
        if pattern.fullmatch(value):
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
