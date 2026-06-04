"""
obfuscate.py
------------
Produces an obfuscated client build using PyArmor.

Usage:
    python obfuscate.py              # obfuscate all client modules
    python obfuscate.py --check      # verify pyarmor is available and show version

Output:
    dist/obfuscated/                 # deploy THIS directory to the client machine

The obfuscated .py files look like normal Python but contain encrypted bytecode
that only executes through PyArmor's runtime. Security checks (license, machine
fingerprint, TOTP) cannot be read or deleted even if the client has file access.

Requirements:
    - pyarmor >= 9.0 installed in the venv  (pip install pyarmor)
    - A valid PyArmor commercial license for production deployments
      (trial license works for testing; run `pyarmor reg` to register)
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# All modules shipped to clients — everything sensitive must be here
CLIENT_MODULES = [
    "app.py",
    "modes.py",
    "security_utils.py",
    "machine_id.py",
    "wallet_utils.py",
    "recovery_utils.py",
    "derivation_utils.py",
    "entropy_utils.py",
    "case_utils.py",
    "forensic_utils.py",
    "live_utils.py",
    "hash_utils.py",
    "export_utils.py",
    "license_utils.py",
    "integrity.py",
    "audit.py",
    "launcher.py",
]

OUT_DIR = Path("dist/obfuscated")


def _pyarmor_cli() -> str:
    """Return path to the pyarmor CLI in the same venv as this script."""
    venv_bin = Path(sys.executable).parent
    for name in ("pyarmor", "pyarmor3"):
        candidate = venv_bin / name
        if candidate.exists():
            return str(candidate)
    return "pyarmor"  # fall back to PATH


def check_pyarmor() -> None:
    result = subprocess.run(
        [_pyarmor_cli(), "--version"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("ERROR: pyarmor is not installed. Run: pip install pyarmor")
        sys.exit(1)
    print(result.stdout.strip())


def obfuscate() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    missing = [m for m in CLIENT_MODULES if not Path(m).exists()]
    if missing:
        print(f"WARNING: skipping missing files: {', '.join(missing)}")
        modules = [m for m in CLIENT_MODULES if Path(m).exists()]
    else:
        modules = CLIENT_MODULES

    cmd = [
        _pyarmor_cli(), "gen",
        "--output", str(OUT_DIR),
        *modules,
    ]
    print(f"Obfuscating {len(modules)} modules → {OUT_DIR}/")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("\nObfuscation failed. Check pyarmor output above.")
        sys.exit(result.returncode)

    print(f"\nObfuscated build written to {OUT_DIR}/")
    print("Copy the following to the client deployment alongside the obfuscated files:")
    print("  manifest.json, public_key.pem, license.json, assets/, .streamlit/")
    print("\nNOTE: For production use, register a PyArmor commercial license:")
    print("  pyarmor reg <your-license-file>")


if __name__ == "__main__":
    if "--check" in sys.argv:
        check_pyarmor()
    else:
        check_pyarmor()
        obfuscate()
