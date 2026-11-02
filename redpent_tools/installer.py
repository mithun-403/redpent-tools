"""Cross-platform tool installer, callable from Python.

This is what makes "install the tools when the project is installed" work: the
setuptools post-install hook (see setup.py) and the `redpent-tools-install` console script
both call run_tool_install(). It simply dispatches to the OS-appropriate installer
script that ships with the repo (install.sh on macOS/Linux, install.ps1 on Windows).

It is always best-effort: a tool that fails to install prints a warning but never raises,
so it can safely run during `pip install` without breaking the Python install.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# Repo root = one level up from this package directory.
REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_script(system: str) -> Path | None:
    if system == "Windows":
        p = REPO_ROOT / "install.ps1"
    else:
        p = REPO_ROOT / "install.sh"
    return p if p.exists() else None


def run_tool_install(lane: str = "all", *, best_effort: bool = True) -> int:
    """Install the CLI recon tools for the current OS.

    lane: 'all' | '--passive' | '--check'
    Returns the installer's exit code (0 on success). Never raises when best_effort.
    """
    if os.environ.get("REDPENT_SKIP_TOOL_INSTALL"):
        print("redpent-tools: REDPENT_SKIP_TOOL_INSTALL set — skipping CLI tool install.")
        return 0

    # Let the bootstrap/hook pick the lane via env (e.g. '--passive').
    lane = os.environ.get("REDPENT_INSTALL_LANE", lane)
    system = platform.system()
    script = _find_script(system)
    if not script:
        print(f"redpent-tools: no installer script for {system}; see README for manual steps.")
        return 0 if best_effort else 1

    try:
        if system == "Windows":
            args = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script)]
            if lane == "--passive":
                args.append("-Passive")
            elif lane == "--check":
                args.append("-Check")
        else:
            if not os.access(script, os.X_OK):
                script.chmod(0o755)
            args = ["bash", str(script), lane]
        print(f"redpent-tools: installing CLI tools via {script.name} (lane={lane}) ...")
        return subprocess.call(args)
    except Exception as e:  # never break a pip install
        print(f"redpent-tools: tool install step failed ({e}). "
              f"Run it manually: {script}")
        return 0 if best_effort else 1


def main() -> None:
    """Console entry point: `redpent-tools-install [all|--passive|--check]`."""
    lane = sys.argv[1] if len(sys.argv) > 1 else "all"
    sys.exit(run_tool_install(lane, best_effort=False))


if __name__ == "__main__":
    main()
