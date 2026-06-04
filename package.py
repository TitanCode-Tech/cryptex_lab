import os
import zipfile
from pathlib import Path

# Define file listings for packaging
CLIENT_FILES = [
    "app.py",
    "modes.py",
    "security_utils.py",
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
    "demo_data.py",
    "launcher.py",
    "requirements.txt",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "install.sh",
    "install.bat",
    "install.py",
    "uninstall.sh",
    "uninstall.bat",
    "uninstall.py",
    "update.sh",
    "update.bat",
    "update.py",
    "manifest.json",
    "public_key.pem",
    "license.json",
    "TUTORIAL_CLIENT.md"
]

CLIENT_DIRS = [
    "assets",
    ".streamlit"
]

DEVELOPER_ONLY_FILES = [
    "private_key.pem",
    "generate_keys.py",
    "implementation_plan.md",
    "task.md",
    "package.py",
    ".gitignore",
    "TUTORIAL_DEVELOPER.md"
]

DEVELOPER_ONLY_DIRS = [
    "tests"
]

def add_file_to_zip(zipf, filepath, archive_path):
    if os.path.exists(filepath):
        zipf.write(filepath, archive_path)
    else:
        print(f"Warning: File {filepath} not found, skipping.")

def add_dir_to_zip(zipf, dirpath, archive_prefix=""):
    path = Path(dirpath)
    if not path.exists():
        print(f"Warning: Directory {dirpath} not found, skipping.")
        return
        
    for file in path.rglob("*"):
        if file.is_file() and "__pycache__" not in file.parts and ".pytest_cache" not in file.parts:
            archive_name = os.path.join(archive_prefix, file.relative_to(path.parent))
            zipf.write(file, archive_name)

def main():
    dist_dir = Path("dist")
    dist_dir.mkdir(exist_ok=True)
    
    # 1. Package Client Software
    client_zip_path = dist_dir / "cryptex_lab_client.zip"
    print(f"Creating client package at {client_zip_path}...")
    with zipfile.ZipFile(client_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add client files
        for filename in CLIENT_FILES:
            add_file_to_zip(zipf, filename, filename)
        # Add client directories
        for dirname in CLIENT_DIRS:
            add_dir_to_zip(zipf, dirname)
            
    print(f"Client package created successfully. Size: {client_zip_path.stat().st_size} bytes.")
    
    # 2. Package Developer / Company Software (Vault)
    developer_zip_path = dist_dir / "cryptex_lab_developer.zip"
    print(f"Creating developer/company package at {developer_zip_path}...")
    with zipfile.ZipFile(developer_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Developer package contains EVERYTHING in the client package plus developer-only files
        for filename in CLIENT_FILES:
            add_file_to_zip(zipf, filename, filename)
        for dirname in CLIENT_DIRS:
            add_dir_to_zip(zipf, dirname)
            
        # Add developer-only files
        for filename in DEVELOPER_ONLY_FILES:
            add_file_to_zip(zipf, filename, filename)
        # Add developer-only directories
        for dirname in DEVELOPER_ONLY_DIRS:
            add_dir_to_zip(zipf, dirname)
            
    print(f"Developer package created successfully. Size: {developer_zip_path.stat().st_size} bytes.")

if __name__ == "__main__":
    main()
