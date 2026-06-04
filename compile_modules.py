"""
compile_modules.py
------------------
Compiles the 4 security-critical modules to native C extensions using Cython.

Why these 4 modules:
  license_utils.py  — RSA license verification + machine fingerprint enforcement
  integrity.py      — build integrity (manifest signature check)
  machine_id.py     — hardware fingerprint collection
  audit.py          — tamper-evident audit logging

The compiled .so (Linux/macOS) or .pyd (Windows) files are imported by Python
exactly like their .py counterparts — no code changes needed anywhere else.
The source cannot be recovered from a compiled extension without a disassembler.

Requirements:
  Cython:      pip install cython      (already in requirements.txt)
  C compiler:  gcc / clang (Linux/macOS) | MSVC Build Tools (Windows)

Usage:
  python compile_modules.py             # compile → dist/compiled/
  python compile_modules.py --check     # verify Cython + compiler are available
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SECURITY_MODULES = [
    "license_utils.py",
    "integrity.py",
    "machine_id.py",
    "audit.py",
]

OUT_DIR = Path("dist/compiled")

_SETUP_TEMPLATE = """\
from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize(
        {modules!r},
        compiler_directives={{"language_level": "3", "boundscheck": False}},
        quiet=False,
    )
)
"""


# ---------------------------------------------------------------------------
# Requirement checks
# ---------------------------------------------------------------------------

def _check_cython() -> bool:
    try:
        import Cython
        print(f"  Cython {Cython.__version__}")
        return True
    except ImportError:
        print("  ERROR: Cython not installed. Run: pip install cython")
        return False


def _check_compiler() -> bool:
    if sys.platform == "win32":
        result = subprocess.run(
            ["cl"], capture_output=True, text=True
        )
        if "Microsoft" in result.stderr or "Microsoft" in result.stdout:
            print("  MSVC compiler found")
            return True
        print("  ERROR: MSVC not found.")
        print("  Install Visual C++ Build Tools:")
        print("  https://visualstudio.microsoft.com/visual-cpp-build-tools/")
        return False
    else:
        compiler = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
        if compiler:
            print(f"  C compiler: {compiler}")
            return True
        print("  ERROR: No C compiler found.")
        print("  Linux:  sudo apt install gcc  |  sudo dnf install gcc")
        print("  macOS:  xcode-select --install")
        return False


def check_requirements() -> bool:
    print("Checking build requirements...")
    ok = _check_cython() and _check_compiler()
    if ok:
        print("  All requirements met.\n")
    return ok


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

def compile_modules() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    present = [m for m in SECURITY_MODULES if Path(m).exists()]
    missing = [m for m in SECURITY_MODULES if not Path(m).exists()]
    if missing:
        print(f"  WARNING: skipping (not found): {', '.join(missing)}")
    if not present:
        print("ERROR: no source modules to compile.")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        for module in present:
            shutil.copy(module, tmp_path / module)

        (tmp_path / "setup.py").write_text(
            _SETUP_TEMPLATE.format(modules=present)
        )

        print(f"Compiling {len(present)} module(s): {', '.join(present)}")
        result = subprocess.run(
            [sys.executable, "setup.py", "build_ext", "--inplace"],
            cwd=tmp,
        )
        if result.returncode != 0:
            print("\nERROR: Cython compilation failed. See output above.")
            sys.exit(1)

        # Collect .so / .pyd files and copy to OUT_DIR
        count = 0
        for ext in ("*.so", "*.pyd"):
            for compiled in tmp_path.glob(ext):
                dest = OUT_DIR / compiled.name
                shutil.copy(compiled, dest)
                print(f"  → {dest}")
                count += 1

        if count == 0:
            print("ERROR: compilation ran but produced no extension files.")
            sys.exit(1)

    print(f"\n{count} extension(s) compiled → {OUT_DIR}/")
    print("Include dist/compiled/*.so (or *.pyd) in the client package.")
    print("Do NOT include the matching .py source files for these modules.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if "--check" in sys.argv:
        ok = check_requirements()
        sys.exit(0 if ok else 1)

    print("=== CRYPTEX LAB — Cython Security Module Compilation ===\n")
    if not check_requirements():
        sys.exit(1)
    compile_modules()
