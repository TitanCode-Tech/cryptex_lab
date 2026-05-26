"""
update.py
---------
Cross-platform updater for Offline Wallet Recovery Lab.

The lab does NOT auto-update over the network at runtime. That would
violate its offline-only design. Instead, when you want to update:

  1. Replace the project source files (e.g. `git pull`, or unzip a new
     release archive over the existing folder).
  2. Run this script. It will:
       * Upgrade pinned dependencies from the new requirements.txt
         (this step requires the network - it is pip-based).
       * Recreate the platform shortcut so it points at the current
         launcher.

Usage:
  python update.py                  # full update (deps + shortcut)
  python update.py --skip-deps      # just recreate the shortcut
  python update.py --no-shortcut    # just refresh deps
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import install  # reuse helpers


ROOT = Path(__file__).resolve().parent


def step(msg: str) -> None:
    print(f"\n==> {msg}")


def info(msg: str) -> None:
    print(f"    {msg}")


def upgrade_dependencies() -> None:
    req = ROOT / "requirements.txt"
    if not req.exists():
        raise SystemExit(f"requirements.txt not found at {req}")
    if not install.venv_python().exists():
        raise SystemExit(
            "No venv found. Run `python install.py` first."
        )
    step("Upgrading dependencies from requirements.txt")
    cmd = [str(install.venv_python()), "-m", "pip", "install", "--upgrade", "pip"]
    subprocess.check_call(cmd)
    cmd = [
        str(install.venv_python()), "-m", "pip", "install",
        "--upgrade", "--upgrade-strategy", "only-if-needed",
        "-r", str(req),
    ]
    subprocess.check_call(cmd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Update the Offline Wallet Recovery Lab.")
    parser.add_argument("--skip-deps", action="store_true",
                        help="Skip the pip step.")
    parser.add_argument("--no-shortcut", action="store_true",
                        help="Skip recreating the desktop shortcut.")
    args = parser.parse_args(argv)

    install.check_python()
    info(f"Project root: {ROOT}")

    if not args.skip_deps:
        upgrade_dependencies()
    else:
        info("--skip-deps: not running pip.")

    if not args.no_shortcut:
        created = install.create_shortcuts()
        if created:
            info("Recreated:")
            for p in created:
                info(f"  - {p}")

    step("Update complete")
    info("Disconnect from the internet before using the lab on real "
         "mnemonics, as always.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
