"""Command-line entry point. Kept minimal until the first real command exists."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from mcp_audit import __version__


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-audit", description=__doc__)
    parser.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    parser.parse_args(argv)
    parser.print_help()
    return 0
