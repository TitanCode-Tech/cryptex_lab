"""
package.py
----------
Packaging script for CRYPTEX LAB.

Two build modes:
  python package.py             -- standard build (plain source, internal use only)
  python package.py --compiled  -- production build (runs compile_modules.py first,
                                   ships .so/.pyd binaries instead of source for the
                                   4 security-critical modules)

Output (dist/):
  cryptex_lab_client.zip              -- standard (do NOT send to clients)
  cryptex_lab_developer.zip           -- full developer archive
  cryptex_lab_client_compiled.zip     -- compiled/protected client package (send this)
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# ---------------------------------------------------------------------------
# File manifests
# ---------------------------------------------------------------------------

# Modules compiled to native extensions in --compiled mode
COMPILED_MODULES = [
    "license_utils.py",
    "integrity.py",
    "machine_id.py",
    "audit.py",
]

# Remaining modules shipped as plain Python (UI/logic, no security enforcement)
PLAIN_MODULES = [
    "app.py",
    "modes.py",
    "security_utils.py",
    "wallet_utils.py",
    "recovery_utils.py",
    "derivation_utils.py",
    "passphrase_utils.py",
    "bip38_utils.py",
    "electrum_utils.py",
    "brain_wallet_utils.py",
    "xpub_utils.py",
    "slip39_utils.py",
    "entropy_utils.py",
    "case_utils.py",
    "forensic_utils.py",
    "live_utils.py",
    "hash_utils.py",
    "export_utils.py",
    "launcher.py",
    "btcrecover_utils.py",
    "tokenlist_utils.py",
    "walletdat_utils.py",
]

CLIENT_SUPPORT_FILES = [
    "requirements.txt",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "install.py",
    "download_wheels.py",
    "install.sh",
    "install.bat",
    "uninstall.py",
    "uninstall.sh",
    "uninstall.bat",
    "update.py",
    "update.sh",
    "update.bat",
    "manifest.json",
    "public_key.pem",
    "TUTORIAL_CLIENT.md",
    "dist/CRYPTEX_LAB_Client_Guide.pdf",
]

CLIENT_DIRS = ["assets", ".streamlit", "btcrecover"]

DEVELOPER_ONLY_FILES = [
    "private_key.pem",
    "generate_keys.py",
    "compile_modules.py",
    "release.py",
    "package.py",
    "generate_tutorial_pdf.py",
    ".gitignore",
    "TUTORIAL_DEVELOPER.md",
]

DEVELOPER_ONLY_DIRS = ["tests"]

COMPILED_DIR = Path("dist/compiled")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def add_file(zipf: zipfile.ZipFile, src: str | Path, archive_name: str) -> None:
    if os.path.exists(src):
        zipf.write(src, archive_name)
    else:
        print(f"  WARNING: {src} not found, skipping.")


def add_dir(zipf: zipfile.ZipFile, dirpath: str | Path, archive_prefix: str = "") -> None:
    path = Path(dirpath)
    if not path.exists():
        print(f"  WARNING: directory {dirpath} not found, skipping.")
        return
    for file in path.rglob("*"):
        if file.is_file() and "__pycache__" not in file.parts and ".pytest_cache" not in file.parts:
            archive_name = os.path.join(archive_prefix, file.relative_to(path.parent))
            zipf.write(file, archive_name)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()


def _manifest_key_for_path(path: Path) -> str:
    try:
        if path.resolve().parent == COMPILED_DIR.resolve():
            return path.name
    except Exception:
        pass
    return str(path)


def _load_private_key(path: Path):
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=None)


def _write_signed_manifest(manifest_path: Path, file_paths: list[Path], private_key_path: Path) -> None:
    if not private_key_path.exists():
        print("ERROR: private_key.pem not found. Generate keys with python generate_keys.py first.")
        sys.exit(1)

    hashes_dict: dict[str, str] = {}
    for file_path in file_paths:
        if not file_path.exists():
            print(f"ERROR: required file for manifest missing: {file_path}")
            sys.exit(1)
        hashes_dict[_manifest_key_for_path(file_path)] = sha256_file(file_path)

    private_key = _load_private_key(private_key_path)
    hashes_bytes = json.dumps(hashes_dict, sort_keys=True).encode("utf-8")
    signature = private_key.sign(hashes_bytes, padding.PKCS1v15(), hashes.SHA256())
    manifest_content = {
        "hashes": hashes_dict,
        "signature": base64.b64encode(signature).decode("utf-8"),
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_content, f, indent=2)


# ---------------------------------------------------------------------------
# Build modes
# ---------------------------------------------------------------------------

def build_standard(dist_dir: Path) -> None:
    """Plain source build — for internal development and testing only."""
    all_modules = COMPILED_MODULES + PLAIN_MODULES

    client_zip = dist_dir / "cryptex_lab_client.zip"
    print(f"\nCreating standard client package: {client_zip}")
    with zipfile.ZipFile(client_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
        for m in all_modules:
            add_file(zipf, m, m)
        for f in CLIENT_SUPPORT_FILES:
            add_file(zipf, f, f)
        for d in CLIENT_DIRS:
            add_dir(zipf, d)
    print(f"  Done. {client_zip.stat().st_size:,} bytes")

    developer_zip = dist_dir / "cryptex_lab_developer.zip"
    print(f"\nCreating developer package: {developer_zip}")
    with zipfile.ZipFile(developer_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
        for m in all_modules:
            add_file(zipf, m, m)
        for f in CLIENT_SUPPORT_FILES:
            add_file(zipf, f, f)
        for d in CLIENT_DIRS:
            add_dir(zipf, d)
        for f in DEVELOPER_ONLY_FILES:
            add_file(zipf, f, f)
        for d in DEVELOPER_ONLY_DIRS:
            add_dir(zipf, d)
    print(f"  Done. {developer_zip.stat().st_size:,} bytes")


def build_compiled(dist_dir: Path) -> None:
    """
    Production build for client delivery.
    Compiles the 4 security modules to native .so/.pyd, then packages
    those binaries alongside plain .py files for the remaining modules.
    """
    print("\nStep 1: Cython compilation of security modules...")
    result = subprocess.run([sys.executable, "compile_modules.py"])
    if result.returncode != 0:
        print("ERROR: compilation failed. Aborting package.")
        sys.exit(1)

    # Collect compiled extensions
    compiled_exts = list(COMPILED_DIR.glob("*.so")) + list(COMPILED_DIR.glob("*.pyd"))
    if not compiled_exts:
        print(f"ERROR: no compiled extensions found in {COMPILED_DIR}/")
        sys.exit(1)

    manifest_temp = dist_dir / "compiled_manifest.json"
    manifest_files = [Path(m) for m in PLAIN_MODULES] + compiled_exts
    _write_signed_manifest(manifest_temp, manifest_files, Path("private_key.pem"))

    client_zip = dist_dir / "cryptex_lab_client_compiled.zip"
    print(f"\nStep 2: Creating compiled client package: {client_zip}")
    with zipfile.ZipFile(client_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
        # Security modules as native binaries (root-level in the ZIP)
        for ext in compiled_exts:
            zipf.write(ext, ext.name)
            print(f"  + {ext.name}  (compiled)")
        # Remaining modules as plain Python
        for m in PLAIN_MODULES:
            add_file(zipf, m, m)
        # Support files — skip the repo manifest.json; we ship a freshly signed one
        for f in CLIENT_SUPPORT_FILES:
            if f == "manifest.json":
                continue
            add_file(zipf, f, f)
        for d in CLIENT_DIRS:
            add_dir(zipf, d)
        zipf.write(manifest_temp, "manifest.json")
        print(f"  + manifest.json  (signed package manifest)")

    manifest_temp.unlink(missing_ok=True)
    print(f"\n  Done. {client_zip.stat().st_size:,} bytes")
    print(f"\nProduction package ready: {client_zip}")
    print("Send this to the client. The 4 security modules ship as compiled binaries.")
    print("Source for license_utils, integrity, machine_id, and audit is NOT included.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    dist_dir = Path("dist")
    dist_dir.mkdir(exist_ok=True)

    if "--compiled" in sys.argv:
        print("=== CRYPTEX LAB — COMPILED (PRODUCTION) BUILD ===")
        build_compiled(dist_dir)
    else:
        print("=== CRYPTEX LAB — STANDARD BUILD ===")
        build_standard(dist_dir)
        print("\nTip: run 'python package.py --compiled' to build the production client package.")


if __name__ == "__main__":
    main()
