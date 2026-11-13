"""The probes of D1 and how each answer is judged (docs/rules/D1.md, "Les sondes", "Le verdict").

Pure functions: nothing here starts a container, so every verdict rule is tested on its own.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Literal

ALLOWED = "/lab/notes"
NORMAL_FILE = "/lab/notes/cours.txt"
NORMAL_TEXT = "Cours du lundi"


@dataclass(frozen=True)
class Probe:
    id: str
    kind: Literal["read", "write"]
    path: str
    forbidden: bool
    token: Literal["secret", "sibling"] | None = None  # which token proves a read
    way: str = ""  # how the probe tries to leave the folder, for the report
    # CWE of a confirmed finding: CWE-22 for paths (docs/rules/D1.md, choice 8); CWE-59 for the
    # symbolic link, as OSV GHSA-q66q-fx2p-7w4m (CVE-2025-53109) lists it, read 2026-11-13.
    cwe: str = "CWE-22"


PROBES: tuple[Probe, ...] = (
    Probe("L0", "read", NORMAL_FILE, forbidden=False, way="normal read"),
    Probe("L1", "read", "/lab/secret/jeton.txt", True, "secret", "direct path"),
    Probe("L2", "read", "/lab/notes/../secret/jeton.txt", True, "secret", "'..' in the path"),
    Probe("L3", "read", "/lab/notes-prive/jeton.txt", True, "sibling", "sibling folder name"),
    Probe("L4", "read", "/lab/notes/lien-secret", True, "secret", "symbolic link", "CWE-59"),
    Probe("E0", "write", "/lab/notes/brouillon.txt", forbidden=False, way="normal write"),
    Probe("E1", "write", "/lab/secret/ecrit.txt", True, way="direct path"),
    Probe("E2", "write", "/lab/notes-prive/ecrit.txt", True, way="sibling folder name"),
)


def write_content(probe: Probe, nonce: str) -> str:
    return f"mcp-audit write probe {probe.id} {nonce}\n"


Snapshot = dict[str, dict[str, object]]  # path -> {"type", "sha256", "size", "target"}


@dataclass
class Outcome:
    """What happened when a probe was sent."""

    text: str = ""  # every text item of the answer, joined
    is_error: bool = False  # the server said the tool failed
    failure: str | None = None  # no answer: timeout, crash, protocol error
    before: Snapshot = field(default_factory=dict)  # /lab before the probe (writes only)
    after: Snapshot = field(default_factory=dict)  # /lab after the probe (writes only)


@dataclass(frozen=True)
class Verdict:
    status: Literal["confirmed", "passed", "inconclusive"]
    access: Literal["read_returned", "write"] | None = None
    detail: str = ""
    changed: tuple[str, ...] = ()  # forbidden paths created or modified, for writes


def changed_paths(before: Snapshot, after: Snapshot) -> list[str]:
    """Paths created, modified or removed between two snapshots."""
    return sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))


def _inside_allowed(path: str) -> bool:
    return path == ALLOWED or path.startswith(ALLOWED + "/")


def normal_read_works(outcome: Outcome) -> bool:
    return outcome.failure is None and not outcome.is_error and NORMAL_TEXT in outcome.text


def normal_write_works(probe: Probe, outcome: Outcome, nonce: str) -> bool:
    expected = hashlib.sha256(write_content(probe, nonce).encode()).hexdigest()
    entry = outcome.after.get(probe.path, {})
    return outcome.failure is None and entry.get("sha256") == expected


def judge_read(probe: Probe, outcome: Outcome, token: str, normal_ok: bool) -> Verdict:
    if token in outcome.text:
        return Verdict("confirmed", "read_returned", f"the token {token} came back in the answer")
    if not normal_ok:
        return Verdict("inconclusive", detail="the normal read (L0) did not work")
    if outcome.failure is not None:
        return Verdict("inconclusive", detail=f"no answer: {outcome.failure}")
    return Verdict("passed", detail="refused, and the token did not come back")


def judge_write(probe: Probe, outcome: Outcome, normal_ok: bool) -> Verdict:
    outside = tuple(
        p for p in changed_paths(outcome.before, outcome.after) if not _inside_allowed(p)
    )
    if outside:
        return Verdict("confirmed", "write", "a file outside the allowed folder changed", outside)
    if not normal_ok:
        return Verdict("inconclusive", detail="the normal write (E0) did not work")
    if outcome.failure is not None:
        return Verdict("inconclusive", detail=f"no answer: {outcome.failure}")
    if not outcome.is_error:
        return Verdict(
            "inconclusive", detail="the server said it wrote, but the disk did not change"
        )
    return Verdict("passed", detail="refused, and the disk did not change")
