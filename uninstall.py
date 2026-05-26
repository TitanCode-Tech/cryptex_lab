"""
uninstall.py
------------
Cross-platform uninstaller for Offline Wallet Recovery Lab.

By default this script:

  1. Removes platform desktop shortcuts created by install.py.
  2. Asks before deleting the local venv/ directory.
  3. Leaves the source code in place (you keep what you cloned/copied).

Pass --venv to delete venv without prompting, or --keep-venv to skip the
venv question entirely. Pass --yes to answer "yes" to every confirmation.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path


APP_NAME = "Offline Wallet Recovery Lab"
APP_SLUG = "offline-wallet-recovery-lab"
ROOT = Path(__file__).resolve().parent


def step(msg: str) -> None:
    print(f"\n==> {msg}")


def info(msg: str) -> None:
    print(f"    {msg}")


def warn(msg: str) -> None:
    print(f"!!  {msg}")


def confirm(prompt: str, default_no: bool = True) -> bool:
    suffix = " [y/N] " if default_no else " [Y/n] "
    ans = input(prompt + suffix).strip().lower()
    if not ans:
        return not default_no
    return ans in ("y", "yes")


# ---------------------------------------------------------------------------
# Shortcut removal per platform
# ---------------------------------------------------------------------------

def remove_linux_shortcut() -> list[Path]:
    target = (Path.home() / ".local" / "share" / "applications"
              / f"{APP_SLUG}.desktop")
    removed: list[Path] = []
    if target.exists():
        target.unlink()
        removed.append(target)
    return removed


def remove_macos_app() -> list[Path]:
    candidates = [
        Path.home() / "Applications" / f"{APP_NAME}.app",
        Path("/Applications") / f"{APP_NAME}.app",
    ]
    removed: list[Path] = []
    for c in candidates:
        if c.exists():
            try:
                shutil.rmtree(c)
                removed.append(c)
            except PermissionError:
                warn(f"Permission denied removing {c} - try with sudo.")
    return removed


def remove_windows_shortcuts() -> list[Path]:
    desktop = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Desktop"
    start_menu = (
        Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
        / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    )
    removed: list[Path] = []
    for parent in (desktop, start_menu):
        target = parent / f"{APP_NAME}.lnk"
        if target.exists():
            try:
                target.unlink()
                removed.append(target)
            except OSError as e:
                warn(f"Could not remove {target}: {e}")
    return removed


def remove_shortcuts() -> list[Path]:
    step("Removing desktop shortcuts")
    if sys.platform.startswith("linux"):
        return remove_linux_shortcut()
    if sys.platform == "darwin":
        return remove_macos_app()
    if sys.platform == "win32":
        return remove_windows_shortcuts()
    warn(f"Unknown platform {sys.platform!r}; nothing to remove.")
    return []


# ---------------------------------------------------------------------------
# venv removal
# ---------------------------------------------------------------------------

def remove_venv(auto_yes: bool) -> bool:
    venv = ROOT / "venv"
    if not venv.exists():
        info("No venv/ to remove.")
        return False
    if not auto_yes:
        if not confirm(f"Delete {venv}? (the source code stays put)"):
            info("Keeping venv/.")
            return False
    step(f"Removing {venv}")
    shutil.rmtree(venv)
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"Uninstall {APP_NAME}.")
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--venv", action="store_true",
                   help="Delete venv/ without prompting.")
    g.add_argument("--keep-venv", action="store_true",
                   help="Never touch venv/.")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Answer 'yes' to every prompt.")
    args = parser.parse_args(argv)

    info(f"Project root: {ROOT}")

    removed = remove_shortcuts()
    if removed:
        info("Removed:")
        for r in removed:
            info(f"  - {r}")
    else:
        info("(no shortcut files found)")

    if args.keep_venv:
        info("--keep-venv: not touching the virtualenv.")
    elif args.venv:
        remove_venv(auto_yes=True)
    else:
        remove_venv(auto_yes=args.yes)

    step("Uninstall complete")
    info("The source folder is left intact so you can re-run install.py "
         "later if you want to reinstall.")
    info(
        "Remember: if you typed real mnemonics into the app, the only safe "
        "next step is to reboot the machine and rotate the funds to a "
        "fresh wallet."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
