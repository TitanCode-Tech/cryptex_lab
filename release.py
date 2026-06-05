"""
release.py
----------
Single-command release workflow for Cryptex Lab.

Usage:
  python release.py <fingerprint>              full build — license + compile + package
  python release.py --any                      dev/demo build (no machine locking)
  python release.py --license-only <fp>        generate license.json only (post-ship activation)

Distribution model:
  Ship dist/cryptex_lab_client_compiled.zip to ALL clients (no license inside).
  Client opens the app → sees their Machine ID → sends it to you.
  You run:  python release.py --license-only <their_fingerprint>
  Send them the CXLAB-... license key → they activate in the app and set up 2FA themselves.
"""

import subprocess
import sys
from pathlib import Path


def run(label: str, cmd: list[str]) -> None:
    print(f"\n{'='*50}")
    print(f"  {label}")
    print(f"{'='*50}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"\nERROR: '{label}' failed. Aborting.")
        sys.exit(1)


def main() -> None:
    args = sys.argv[1:]

    if not args:
        print("Usage:")
        print("  python release.py <fingerprint>              # full build")
        print("  python release.py --any                      # dev/demo build")
        print("  python release.py --license-only <fp>        # license only (post-ship)")
        sys.exit(1)

    # License-only mode — client already has the app, just needs the license file
    if args[0] == "--license-only":
        if len(args) < 2:
            print("Usage: python release.py --license-only <machine_fingerprint>")
            sys.exit(1)
        fingerprint = args[1]
        print(f"\n=== CRYPTEX LAB — LICENSE GENERATION ===")
        print(f"  Machine: {fingerprint[:16]}...")
        run("Generating signed license", [sys.executable, "generate_keys.py", fingerprint])
        print("\n=== DONE ===")
        print("  Send the CXLAB-... license key above to the client.")
        print("  The client pastes it in the app (Step 2 on the activation screen).")
        print("  They complete 2FA setup themselves inside the app on first launch.")
        return

    # Full build — compile + package (for initial distribution)
    fingerprint = args[0]
    is_demo = fingerprint == "--any"

    print("\n=== CRYPTEX LAB — FULL RELEASE ===")
    print(f"  Target: {'any machine (demo)' if is_demo else fingerprint[:16] + '...'}")

    run("Step 1/3 — Generating signed license", [sys.executable, "generate_keys.py", fingerprint])
    run("Step 2/3 — Compiling security modules", [sys.executable, "compile_modules.py"])
    run("Step 3/3 — Packaging client ZIP",       [sys.executable, "package.py", "--compiled"])

    zip_path = Path("dist/cryptex_lab_client_compiled.zip")
    print("\n=== RELEASE COMPLETE ===")
    print(f"  Package : {zip_path} ({zip_path.stat().st_size:,} bytes)")
    print()
    print("Distribution:")
    print("  - Ship dist/cryptex_lab_client_compiled.zip  (no license inside)")
    print("  - Client opens app → copies their Machine ID → sends it to you")
    print("  - You run: python release.py --license-only <their_fingerprint>")
    print("  - Send them the CXLAB-... license key")
    print("  - They activate in the app, then complete 2FA setup themselves")
    if is_demo:
        print("\n  WARNING: demo license — runs on any machine.")


if __name__ == "__main__":
    main()
