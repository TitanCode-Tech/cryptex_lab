import json
import base64
import hashlib
import sys
import pyotp
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path
from machine_id import get_machine_fingerprint

CRITICAL_FILES = [
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
    "audit.py",
    "integrity.py"
]

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def main():
    # 1. Load or Generate RSA key pair
    private_key_path = Path("private_key.pem")
    if private_key_path.exists():
        print("Loading existing private_key.pem...")
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_public_key(f.read()) if False else serialization.load_pem_private_key(f.read(), password=None)
    else:
        print("Generating RSA key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open("private_key.pem", "wb") as f:
            f.write(private_pem)
        print("Saved private_key.pem (KEEP THIS SECRET!)")
    
    # 2. Serialize public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", "wb") as f:
        f.write(public_pem)
    print("Saved public_key.pem")
    
    # 3. Machine fingerprint
    # Pass --any as the first argument to generate a dev/demo license with no machine binding.
    if len(sys.argv) > 1 and sys.argv[1] == "--any":
        machine_fp = "any"
        print("Machine fingerprint: any (dev/demo license — NOT machine-locked)")
    else:
        print("\n=== MACHINE FINGERPRINT ===")
        print("Run 'python machine_id.py' on the TARGET machine to get its fingerprint.")
        print("Leave blank (press Enter) to embed THIS machine's fingerprint.\n")
        provided = input("Machine fingerprint (or blank for this machine): ").strip()
        if provided:
            machine_fp = provided
            print(f"Using provided fingerprint: {machine_fp[:16]}...")
        else:
            machine_fp = get_machine_fingerprint()
            print(f"Using this machine's fingerprint: {machine_fp[:16]}...")

    # 4. Create license data
    # Generate fresh TOTP secrets for each protected role (32-char base32)
    totp_secrets = {
        "Senior Analyst": pyotp.random_base32(),
        "Admin": pyotp.random_base32(),
    }
    license_data = {
        "company": "Titan Code",
        "client": "Authorized User",
        "expires": "2027-01-01",
        "modules": ["recovery", "forensic", "validator", "derivation", "reports", "vault", "advanced"],
        "machine_fingerprint": machine_fp,
        "totp_secrets": totp_secrets,
    }
    print("\n=== TOTP SECRETS (scan into authenticator app) ===")
    for role, secret in totp_secrets.items():
        uri = pyotp.TOTP(secret).provisioning_uri(name=role, issuer_name="Cryptex Lab")
        print(f"  {role}: {secret}")
        print(f"    URI: {uri}")
    print("=== Store these secrets safely — they will NOT be shown again ===\n")
    
    # Canonical string representation for signing
    license_bytes = json.dumps(license_data, sort_keys=True).encode("utf-8")
    
    # Sign the license data
    signature = private_key.sign(
        license_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Save signed license file
    license_file_content = {
        "license_data": license_data,
        "signature": base64.b64encode(signature).decode("utf-8")
    }
    
    with open("license.json", "w") as f:
        json.dump(license_file_content, f, indent=2)
    print("Saved signed license.json")

    # 4. Generate build integrity manifest
    print("Generating build integrity manifest...")
    hashes_dict = {}
    for filename in CRITICAL_FILES:
        filepath = Path(filename)
        # If file doesn't exist yet, we write a temporary hash or skip it.
        # But we'll create the file first or hash it if it exists.
        if filepath.exists():
            hashes_dict[filename] = sha256_file(filepath)
        else:
            print(f"Warning: {filename} does not exist yet. Using empty placeholder hash.")
            hashes_dict[filename] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # empty sha256
            
    hashes_bytes = json.dumps(hashes_dict, sort_keys=True).encode("utf-8")
    manifest_signature = private_key.sign(
        hashes_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    manifest_content = {
        "hashes": hashes_dict,
        "signature": base64.b64encode(manifest_signature).decode("utf-8")
    }
    
    with open("manifest.json", "w") as f:
        json.dump(manifest_content, f, indent=2)
    print("Saved signed manifest.json")

if __name__ == "__main__":
    main()
