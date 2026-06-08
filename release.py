"""
release.py
----------
Single-command release workflow for Cryptex Lab.

Usage:
  python release.py <fingerprint>              full build — license + compile + package
  python release.py --any                      dev/demo build (no machine locking)
  python release.py --license-only <fp>        generate license.json only (post-ship activation)

License flags (apply to both full build and --license-only):
  --client  "Name"          client name embedded in the license (default: Authorized User)
  --expires YYYY-MM-DD      expiry date (default: 2027-01-01)
  --tier    basic|pro|full  module access tier (default: full)

Distribution model:
  Ship dist/cryptex_lab_client_compiled.zip to ALL clients (no license inside).
  Client opens the app → sees their Machine ID → sends it to you.
  You run:  python release.py --license-only <fp> --client '...' --expires YYYY-MM-DD --tier full
  Send them the CXLAB-... license key → they activate in the app and set up 2FA themselves.
  Developer never sees or handles TOTP secrets (client generates their own)
"""

import argparse
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


def license_flags(args: argparse.Namespace) -> list[str]:
    """Build the generate_keys.py flags from parsed args."""
    flags = []
    if args.client:
        flags += ["--client", args.client]
    if args.expires:
        flags += ["--expires", args.expires]
    if args.tier:
        flags += ["--tier", args.tier]
    return flags


def main() -> None:
    parser = argparse.ArgumentParser(description="Cryptex Lab release tool.")
    fp_group = parser.add_mutually_exclusive_group()
    fp_group.add_argument("fingerprint", nargs="?", help="Machine fingerprint for full build")
    fp_group.add_argument("--any", action="store_true", help="Dev/demo build (not machine-locked)")
    fp_group.add_argument("--license-only", metavar="FINGERPRINT", help="Generate license key only (client already has the app)")
    parser.add_argument("--client",  default="Authorized User", help="Client name (e.g. 'Acme Forensics LLC')")
    parser.add_argument("--expires", default="2027-01-01",      help="License expiry date YYYY-MM-DD")
    parser.add_argument("--tier",    default="full", choices=["basic", "pro", "full"], help="Module access tier")
    args = parser.parse_args()

    extra = license_flags(args)

    # License-only mode — client already has the app, just needs the activation key
    if args.license_only:
        fingerprint = args.license_only
        print(f"\n=== CRYPTEX LAB — LICENSE GENERATION ===")
        print(f"  Machine : {fingerprint[:16]}...")
        print(f"  Client  : {args.client}")
        print(f"  Expires : {args.expires}")
        print(f"  Tier    : {args.tier}")
        run("Generating signed license", [sys.executable, "generate_keys.py", fingerprint] + extra)
        print("\n=== DONE ===")
        print("  Send the CXLAB-... license key above to the client.")
        print("  The client pastes it in the app (Step 2 on the activation screen).")
        print("  They complete 2FA setup themselves inside the app on first launch.")
        return

    # Full build — compile + package (for initial distribution)
    if args.any:
        fp_arg = ["--any"]
        label = "any machine (demo)"
    elif args.fingerprint:
        fp_arg = [args.fingerprint]
        label = args.fingerprint[:16] + "..."
    else:
        parser.print_help()
        sys.exit(1)

    print("\n=== CRYPTEX LAB — FULL RELEASE ===")
    print(f"  Target  : {label}")
    print(f"  Client  : {args.client}")
    print(f"  Expires : {args.expires}")
    print(f"  Tier    : {args.tier}")

    run("Step 1/3 — Generating signed license", [sys.executable, "generate_keys.py"] + fp_arg + extra)
    run("Step 2/3 — Compiling security modules", [sys.executable, "compile_modules.py"])
    run("Step 3/3 — Packaging client ZIP",        [sys.executable, "package.py", "--compiled"])

    zip_path = Path("dist/cryptex_lab_client_compiled.zip")
    print("\n=== RELEASE COMPLETE ===")
    print(f"  Package : {zip_path} ({zip_path.stat().st_size:,} bytes)")
    print()
    print("Distribution:")
    print("  - Ship dist/cryptex_lab_client_compiled.zip  (no license inside)")
    print("  - Client opens app → copies their Machine ID → sends it to you")
    print("  - You run: python release.py --license-only <fp> --client '...' --expires YYYY-MM-DD --tier full")
    print("  - Send them the CXLAB-... license key")
    print("  - They activate in the app, then complete 2FA setup themselves")
    if args.any:
        print("\n  WARNING: demo license — runs on any machine.")


if __name__ == "__main__":
    main()
