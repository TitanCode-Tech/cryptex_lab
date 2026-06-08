import json
import base64
import hashlib
import sys
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path
from machine_id import get_machine_fingerprint

TIERS = {
    "basic": ["recovery", "validator"],
    "pro":   ["recovery", "forensic", "validator", "derivation", "reports"],
    "full":  ["recovery", "forensic", "validator", "derivation", "reports", "vault", "advanced"],
}

CRITICAL_FILES = [
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
    parser = argparse.ArgumentParser(description="Generate a signed Cryptex Lab license.")
    fp_group = parser.add_mutually_exclusive_group()
    fp_group.add_argument("fingerprint", nargs="?", help="Client machine fingerprint (hex string)")
    fp_group.add_argument("--any", action="store_true", help="Dev/demo license — not machine-locked")
    parser.add_argument("--client",  default="Authorized User", help="Client name (e.g. 'Acme Forensics LLC')")
    parser.add_argument("--expires", default="2027-01-01",      help="Expiry date YYYY-MM-DD (default: 2027-01-01)")
    parser.add_argument("--tier",    default="full", choices=list(TIERS), help="License tier: basic | pro | full")
    args = parser.parse_args()

    # 1. Load or Generate RSA key pair
    private_key_path = Path("private_key.pem")
    if private_key_path.exists():
        print("Loading existing private_key.pem...")
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        print("Generating RSA key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
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
    if args.any:
        machine_fp = "any"
        print("Machine fingerprint: any (dev/demo — NOT machine-locked)")
    elif args.fingerprint:
        machine_fp = args.fingerprint.strip()
        print(f"Machine fingerprint: {machine_fp[:16]}... (provided)")
    else:
        machine_fp = get_machine_fingerprint()
        print(f"Machine fingerprint: {machine_fp[:16]}... (this machine)")

    modules = TIERS[args.tier]
    print(f"Client : {args.client}")
    print(f"Expires: {args.expires}")
    print(f"Tier   : {args.tier} → {modules}")

    # 4. Create license data
    # TOTP secrets are NOT in the license — the client sets them up via the in-app
    # first-run setup flow. The developer never sees or handles 2FA credentials.
    license_data = {
        "company": "Titan Code",
        "client": args.client,
        "expires": args.expires,
        "modules": modules,
        "machine_fingerprint": machine_fp,
    }
    
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

    # Print activation key — this is what the client pastes into the app
    from license_utils import encode_license_key
    license_key = encode_license_key(license_file_content)
    print("\n=== LICENSE ACTIVATION KEY (send this to the client) ===")
    print(license_key)
    print("=== Client pastes this into the app: Step 2 → Enter License Key ===\n")

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
