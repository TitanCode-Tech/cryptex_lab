import json
import base64
from datetime import datetime, date
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Hardcoded fallback Titan public key PEM corresponding to the generated one
PUBKEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6kpfczEdfD0oCzyEB/BO
jVuqKTBCPub1jlmJv5QChfsNKIPrxmuYHTWVs/o7jhPp+h4rLsSeEYkKkhQxSJC7
PBNDZ3x4i88x+KbeXyxClaI8dcwdxpWUpMotB7U8hY+wl5ydTQtmxq+VDJdT/jfk
Jy6F+JkCsGwXmXW80C39C3GbnZHkBllLzTJ4v5gGYEqEPKCnou5qX7PViZQMFxzr
pUCh5Sfxdt27PlGKI3Qm6+Nj90YEsouKc4YB3nxy+2+dE6ss4ERvgR1WwKwtMu76
9yJQRuAAQJSLS4lOgjLYzuDYrNRlXRkGI3um6hNSddIDYcJ4V4Qpz1lRPnZU5WA/
rQIDAQAB
-----END PUBLIC KEY-----"""

def load_public_key(pubkey_path: Path | None = None):
    """
    Load public key from file if it exists, otherwise fallback to the hardcoded PEM.
    """
    if pubkey_path and pubkey_path.exists():
        with open(pubkey_path, "rb") as f:
            return serialization.load_pem_public_key(f.read())
    return serialization.load_pem_public_key(PUBKEY_PEM)

def verify_license_data(license_dict: dict, pubkey_path: Path | None = None) -> tuple[bool, str, dict]:
    """
    Verifies the license dictionary structure, its signature, and expiration.
    Returns (is_valid, error_reason, license_data).
    """
    try:
        if "license_data" not in license_dict or "signature" not in license_dict:
            return False, "Malformed license file: missing license_data or signature", {}
        
        license_data = license_dict["license_data"]
        sig_b64 = license_dict["signature"]
        
        # Canonicalize the data to bytes in the same way it was signed
        license_bytes = json.dumps(license_data, sort_keys=True).encode("utf-8")
        signature = base64.b64decode(sig_b64)
        
        # Load public key and verify signature
        public_key = load_public_key(pubkey_path)
        public_key.verify(
            signature,
            license_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Check expiration date
        expires_str = license_data.get("expires")
        if not expires_str:
            return False, "License is missing expiration date", {}
        
        expires_date = datetime.strptime(expires_str, "%Y-%m-%d").date()
        if expires_date < date.today():
            return False, f"License expired on {expires_str}", license_data
            
        return True, "", license_data
        
    except InvalidSignature:
        return False, "Cryptographic signature verification failed: license has been tampered with", {}
    except Exception as e:
        return False, f"Verification error: {str(e)}", {}

def check_module_access(license_data: dict, module_name: str) -> bool:
    """
    Checks if the license authorizes access to a specific module.
    """
    allowed_modules = license_data.get("modules", [])
    # Case-insensitive check
    allowed_modules_lower = [m.lower() for m in allowed_modules]
    return module_name.lower() in allowed_modules_lower or "all" in allowed_modules_lower
