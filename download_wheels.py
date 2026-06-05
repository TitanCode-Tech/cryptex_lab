"""
download_wheels.py
------------------
Run this on an INTERNET-CONNECTED machine of the same OS and Python version
as the target air-gapped workstation to pre-fetch all dependency wheels.

The resulting offline_wheels/ directory can then be:
  * Copied onto a USB drive and transferred to the air-gapped machine, OR
  * Bundled into the client ZIP by the developer before delivery.

Usage:
  python download_wheels.py                   # downloads to ./offline_wheels/
  python download_wheels.py --dest /some/path # downloads to a custom path

On the air-gapped machine, install with:
  python install.py --offline
"""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_DEST = ROOT / "offline_wheels"


def step(msg: str) -> None:
    print(f"\n==> {msg}")


def info(msg: str) -> None:
    print(f"    {msg}")


def warn(msg: str) -> None:
    print(f"!!  {msg}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Download all dependency wheels for offline installation."
    )
    parser.add_argument(
        "--dest",
        default=str(DEFAULT_DEST),
        help=f"Directory to save wheels into (default: {DEFAULT_DEST})",
    )
    args = parser.parse_args(argv)

    dest = Path(args.dest)
    req = ROOT / "requirements.txt"

    if not req.exists():
        raise SystemExit(f"requirements.txt not found at {req}")

    step("System info")
    info(f"Python : {sys.version.split()[0]}")
    info(f"OS     : {platform.system()} {platform.machine()}")
    info(f"Target : {dest}")
    info(
        "NOTE: wheels are platform-specific. Run this script on a machine with "
        "the same OS and Python version as the air-gapped target."
    )

    dest.mkdir(parents=True, exist_ok=True)

    step(f"Downloading wheels to {dest}/")
    cmd = [
        sys.executable, "-m", "pip", "download",
        "-r", str(req),
        "-d", str(dest),
    ]
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise SystemExit("pip download failed. Check your internet connection and try again.")

    wheels = list(dest.glob("*.whl")) + list(dest.glob("*.tar.gz"))
    step(f"Done — {len(wheels)} packages saved to {dest}/")

    info("")
    info("Next steps:")
    info("  1. Copy the entire CRYPTEX LAB folder (including offline_wheels/) to a USB drive.")
    info("  2. Transfer the USB to the air-gapped machine.")
    info("  3. On the air-gapped machine, run:")
    info("       python install.py --offline")
    info("")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
