"""Safe subprocess runner.

  * asyncio.create_subprocess_exec only — NEVER shell=True (no injection surface).
  * per-tool timeout, output cap, raw output saved to evidence, secrets masked.
  * missing binary -> friendly error with an install hint.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from .audit import mask_secrets
from .config import Config, now_utc

# Longer timeout for the heavy active scanners.
DEFAULT_TIMEOUT = 300
HEAVY_TIMEOUT = 1800
RETURN_CHAR_CAP = 8000

# Install hints keyed by binary name — surfaced when a tool is missing.
INSTALL_HINTS = {
    "whois": "macOS: brew install whois | Debian: apt install whois",
    "dig": "macOS: brew install bind | Debian: apt install dnsutils",
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "theHarvester": "pipx install theHarvester  (or: pip install theHarvester)",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "nmap": "macOS: brew install nmap | Debian: apt install nmap",
    "masscan": "macOS: brew install masscan | Debian: apt install masscan",
    "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
    "nikto": "macOS: brew install nikto | Debian: apt install nikto",
    "sqlmap": "pipx install sqlmap  (macOS: brew install sqlmap | Debian: apt install sqlmap)",
    "commix": "pipx install git+https://github.com/commixproject/commix.git  (PyPI 'commix' is a stub)",
    "wafw00f": "pipx install wafw00f",
    "sslscan": "macOS: brew install sslscan | Debian: apt install sslscan",
    "openssl": "macOS: brew install openssl | Debian: apt install openssl",
    "curl": "macOS: brew install curl | Debian: apt install curl",
}


# Go-based tools: prefer the Go bin dir so a same-named binary earlier on PATH
# (e.g. the Python `httpx` CLI) can't shadow ProjectDiscovery's `httpx`.
_GO_TOOLS = {"subfinder", "httpx", "waybackurls", "ffuf"}


def _go_bin() -> Path:
    return Path(os.environ.get("GOBIN") or (Path.home() / "go" / "bin"))


def resolve_bin(name: str) -> str | None:
    """Resolve a tool to an absolute path, preferring Go's bin dir for Go tools and
    honouring a RECON_<TOOL>_BIN override env var."""
    override = os.environ.get(f"RECON_{name.upper()}_BIN")
    if override and Path(override).exists():
        return override
    if name in _GO_TOOLS:
        cand = _go_bin() / name
        if cand.exists():
            return str(cand)
    return shutil.which(name)


class BinaryMissing(Exception):
    pass


@dataclass
class RunResult:
    ok: bool
    exit_code: int
    stdout: str          # masked, capped
    stderr: str          # masked, capped
    raw_stdout: str      # masked, full (as saved)
    duration_s: float
    evidence_file: str
    timed_out: bool = False


def have_binary(name: str) -> bool:
    return resolve_bin(name) is not None


def require_binary(name: str) -> None:
    if not have_binary(name):
        hint = INSTALL_HINTS.get(name, f"install '{name}' and ensure it is on PATH")
        raise BinaryMissing(f"'{name}' not found. Install it: {hint}")


class Runner:
    def __init__(self, config: Config):
        self.cfg = config

    async def run(
        self,
        tool_name: str,
        cmd: list[str],
        *,
        timeout: int = DEFAULT_TIMEOUT,
        extra_output_files: list[Path] | None = None,
    ) -> RunResult:
        """Execute cmd (argv list), save raw output, return a capped+masked result."""
        require_binary(cmd[0])
        cmd = [resolve_bin(cmd[0]) or cmd[0], *cmd[1:]]  # pin to the resolved binary
        evidence_dir = self.cfg.evidence_path(tool_name)
        stamp = now_utc().strftime("%Y%m%dT%H%M%SZ")
        out_file = evidence_dir / f"{stamp}.txt"

        start = time.monotonic()
        timed_out = False
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                out_b, err_b = b"", b"process killed after timeout"
                timed_out = True
        except FileNotFoundError:
            require_binary(cmd[0])  # raises BinaryMissing with a hint
            raise
        duration = time.monotonic() - start

        stdout = mask_secrets(out_b.decode("utf-8", "replace"))
        stderr = mask_secrets(err_b.decode("utf-8", "replace"))
        exit_code = proc.returncode if proc.returncode is not None else -1

        # Persist full raw output (masked) + the exact command for provenance.
        header = f"$ {' '.join(cmd)}\n# exit={exit_code} duration={duration:.2f}s timed_out={timed_out}\n\n"
        out_file.write_text(header + stdout + ("\n--- STDERR ---\n" + stderr if stderr else ""))

        return RunResult(
            ok=(exit_code == 0 and not timed_out),
            exit_code=exit_code,
            stdout=stdout[:RETURN_CHAR_CAP],
            stderr=stderr[:2000],
            raw_stdout=stdout,
            duration_s=duration,
            evidence_file=str(out_file),
            timed_out=timed_out,
        )
