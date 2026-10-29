import subprocess
import sys

import pytest

from mcp_audit import __version__
from mcp_audit.cli import main


def test_version_matches_package_metadata(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"mcp-audit {__version__}"


def test_console_script_is_installed() -> None:
    # Runs the installed entry point, not the function: catches a broken [project.scripts] line.
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_audit", "--version"], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == f"mcp-audit {__version__}"
