"""
btcrecover_utils.py
-------------------
Subprocess wrapper for BTCRecover seed and password recovery.

BTCRecover is run as a child process from its installation directory.
stdout is streamed line-by-line so the Streamlit UI can show live progress.
All heavy work (threading, key derivation) happens inside the BTCRecover
process — this module is a thin process-management and output-parsing layer.

SECURITY NOTES
==============
* Mnemonic / password values are passed as CLI arguments, visible in
  the process list for the duration of the run. Run on air-gapped hardware.
* Temp files (wallet.dat, tokenlist, wordlist) are written to the OS temp
  directory. Callers MUST delete them after use (use try/finally).
* No network calls. BTCRecover writes no files unless explicitly told to.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

# ---------------------------------------------------------------------------
# Installation path — resolved at import time, relative to this file.
#
# BTCRecover is bundled inside the Cryptex Lab project directory as
# cryptex-lab/btcrecover/. This is populated by install.py on first setup.
# If the bundled copy is absent, the legacy absolute path is used as a
# fallback so existing developer setups keep working.
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_BUNDLED = _HERE / "btcrecover"
_LEGACY  = Path("/home/jabs/Code/python/btcrecover-master")

def _find_btcrecover_dir() -> str:
    """Return the best available BTCRecover directory path."""
    for candidate in (_BUNDLED, _LEGACY):
        if (candidate / "seedrecover.py").exists():
            return str(candidate)
    return str(_BUNDLED)  # report bundled path in error messages

BTCRECOVER_DIR: str = _find_btcrecover_dir()


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

_SEED_MATCH_RE   = re.compile(r"\*\*\*MATCHING SEED FOUND\*\*\*")
_SEED_FOUND_RE   = re.compile(r"(?:^|\n)\s*Seed found:\s*(.+)", re.IGNORECASE)
_PASS_FOUND_RE   = re.compile(r"Password found:\s*(.+)", re.IGNORECASE)
_NOT_FOUND_RE    = re.compile(r"Seed not found|Password not found|Search Complete", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def is_available() -> bool:
    """Return True if the BTCRecover installation directory is intact."""
    return (
        os.path.isdir(BTCRECOVER_DIR)
        and os.path.isfile(os.path.join(BTCRECOVER_DIR, "seedrecover.py"))
        and os.path.isfile(os.path.join(BTCRECOVER_DIR, "btcrecover.py"))
    )


# ---------------------------------------------------------------------------
# Core subprocess runner
# ---------------------------------------------------------------------------

def _run(
    script: str,
    argv: list[str],
    line_callback: Callable[[str], None] | None = None,
    timeout: int = 3600,
) -> dict:
    """
    Run a BTCRecover script as a subprocess.

    Parameters
    ----------
    script        : "seedrecover.py" or "btcrecover.py"
    argv          : CLI arguments (excluding the script name itself)
    line_callback : called with each stdout+stderr line in real time
    timeout       : max seconds before forceful kill (default 1 hour)

    Returns
    -------
    dict:
        found        : bool
        result       : str | None   — mnemonic or password string if found
        output_lines : list[str]    — full captured output
        returncode   : int
        error        : str | None
    """
    if not is_available():
        return {
            "found": False, "result": None, "output_lines": [],
            "returncode": -1,
            "error": f"BTCRecover not found at {BTCRECOVER_DIR}",
        }

    cmd = [sys.executable, script] + argv
    output_lines: list[str] = []
    found = False
    result_str: str | None = None

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=BTCRECOVER_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            output_lines.append(line)

            if _SEED_MATCH_RE.search(line):
                found = True
            m = _SEED_FOUND_RE.search(line)
            if m:
                result_str = m.group(1).strip()
                found = True
            m2 = _PASS_FOUND_RE.search(line)
            if m2:
                result_str = m2.group(1).strip()
                found = True

            if line_callback:
                line_callback(line)

        proc.wait(timeout=timeout)
        returncode = proc.returncode

    except subprocess.TimeoutExpired:
        proc.kill()
        return {
            "found": found,
            "result": result_str,
            "output_lines": output_lines,
            "returncode": -1,
            "error": f"Process timed out after {timeout}s",
        }
    except Exception as exc:
        return {
            "found": found,
            "result": result_str,
            "output_lines": output_lines,
            "returncode": -1,
            "error": str(exc),
        }

    return {
        "found": found,
        "result": result_str,
        "output_lines": output_lines,
        "returncode": returncode,
        "error": None,
    }


def run_btcrseed(
    argv: list[str],
    line_callback: Callable[[str], None] | None = None,
    timeout: int = 3600,
) -> dict:
    """Run seedrecover.py with the given argv list."""
    return _run("seedrecover.py", argv, line_callback, timeout)


def run_btcrpass(
    argv: list[str],
    line_callback: Callable[[str], None] | None = None,
    timeout: int = 3600,
) -> dict:
    """Run btcrecover.py with the given argv list."""
    return _run("btcrecover.py", argv, line_callback, timeout)


# ---------------------------------------------------------------------------
# Temp-file helpers  (callers MUST delete returned paths when done)
# ---------------------------------------------------------------------------

def write_temp_file(content: str | bytes, suffix: str = ".txt") -> str:
    """Write content to a named temp file and return its path."""
    mode = "wb" if isinstance(content, bytes) else "w"
    encoding = None if isinstance(content, bytes) else "utf-8"
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="cx_btcr_")
    with os.fdopen(fd, mode, **({"encoding": encoding} if encoding else {})) as f:
        f.write(content)
    return path


def write_ram_temp_file(content: str | bytes, suffix: str = ".txt") -> str:
    """Attempt to write a temp file on a RAM-backed filesystem (e.g. /dev/shm).

    Falls back to the regular temp dir if no suitable ramfs is available.
    Callers MUST delete the returned path after use.
    """
    ram_dirs = ["/dev/shm", "/run/shm", "/tmp"]
    mode = "wb" if isinstance(content, bytes) else "w"
    encoding = None if isinstance(content, bytes) else "utf-8"

    for d in ram_dirs:
        try:
            if os.path.isdir(d) and os.access(d, os.W_OK | os.X_OK):
                fd, path = tempfile.mkstemp(suffix=suffix, prefix="cx_btcr_", dir=d)
                with os.fdopen(fd, mode, **({"encoding": encoding} if encoding else {})) as f:
                    f.write(content)
                return path
        except Exception:
            continue

    # Last resort: system temp
    return write_temp_file(content, suffix=suffix)


# ---------------------------------------------------------------------------
# Standard argv builders
# ---------------------------------------------------------------------------

_COMMON_FLAGS = [
    "--no-gui",
    "--no-pause",
    "--dsw",          # disable security warning (we show our own)
    "--skip-pre-start",
]


def seed_recovery_argv(
    mnemonic: str,
    wallet_type: str = "bip39",
    addrs: str = "",
    language: str = "en",
    typos: int = 1,
    big_typos: int = 0,
    addr_limit: int = 10,
    extra_flags: list[str] | None = None,
) -> list[str]:
    """
    Build seedrecover.py argv for a typo/missing-word recovery run.

    Parameters
    ----------
    mnemonic    : known mnemonic string (may be partial / contain typos).
    wallet_type : "bip39" | "electrum2" | etc.
    addrs       : comma-separated target addresses (empty = no address filter).
    language    : "en", "es", "fr", etc.
    typos       : max number of keyboard/phonetic mistakes.
    big_typos   : max number of entirely-different-word mistakes.
    addr_limit  : addresses per derivation path to check.
    extra_flags : additional raw flags to append.
    """
    argv = list(_COMMON_FLAGS)
    argv += ["--wallet-type", wallet_type]
    argv += ["--mnemonic", mnemonic]
    argv += ["--language", language]
    argv += ["--addr-limit", str(addr_limit)]

    if addrs.strip():
        # BTCRecover accepts multiple space-separated addresses for --addrs
        argv += ["--addrs"] + addrs.strip().split()

    if typos > 0:
        argv += ["--typos", str(typos)]
    if big_typos > 0:
        argv += ["--big-typos", str(big_typos)]

    if extra_flags:
        argv += extra_flags

    return argv


def seedlist_argv(
    seedlist_path: str,
    wallet_type: str = "bip39",
    addrs: str = "",
    language: str = "en",
    mnemonic_length: int = 12,
    addr_limit: int = 10,
    extra_flags: list[str] | None = None,
) -> list[str]:
    """
    Build seedrecover.py argv for --seedlist mode.

    Used by the hybrid missing-word engine: Python generates all
    checksum-valid candidates, writes them to a file, then BTCRecover
    tests each one against the target address using multi-threaded BIP32.

    Parameters
    ----------
    seedlist_path   : path to the file of candidate seeds (one per line).
    wallet_type     : "bip39" | "electrum2" | "ethereum" | etc.
    addrs           : space-separated target addresses.
    language        : BIP39 wordlist language code ("en", "es", ...).
    mnemonic_length : word count of the seeds in the list (12/15/18/21/24).
    addr_limit      : addresses per derivation path to check.
    extra_flags     : additional raw flags to append.
    """
    argv = list(_COMMON_FLAGS)
    argv += ["--wallet-type", wallet_type]
    argv += ["--seedlist", seedlist_path]
    argv += ["--mnemonic-length", str(mnemonic_length)]
    argv += ["--language", language]
    argv += ["--addr-limit", str(addr_limit)]

    if addrs.strip():
        argv += ["--addrs"] + addrs.strip().split()

    if extra_flags:
        argv += extra_flags

    return argv


def wallet_attack_argv(
    wallet_path: str,
    tokenlist_path: str | None = None,
    passwordlist_path: str | None = None,
    typos: int = 0,
    extra_flags: list[str] | None = None,
) -> list[str]:
    """
    Build btcrecover.py argv for a wallet password recovery run.

    Exactly one of tokenlist_path or passwordlist_path must be provided.
    """
    argv = list(_COMMON_FLAGS)
    argv += ["--wallet", wallet_path]

    if tokenlist_path:
        argv += ["--tokenlist", tokenlist_path]
    elif passwordlist_path:
        argv += ["--passwordlist", passwordlist_path]
    else:
        raise ValueError("Provide either tokenlist_path or passwordlist_path")

    if typos > 0:
        argv += ["--typos", str(typos)]

    if extra_flags:
        argv += extra_flags

    return argv
