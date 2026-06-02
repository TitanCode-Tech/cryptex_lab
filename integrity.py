import hashlib
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from license_utils import load_public_key

def sha256_file(path: Path) -> str:
    """Calculates the SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def verify_build_integrity(manifest_path: Path = Path("manifest.json"), pubkey_path: Path | None = None) -> tuple[bool, str]:
    """
    Verifies that all files in the manifest are unmodified and that the manifest signature is valid.
    
    Returns:
        (is_valid, error_reason)
    """
    if not manifest_path.exists():
        return False, "Build integrity manifest.json is missing. Build cannot be verified."
        
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_dict = json.load(f)
            
        if "hashes" not in manifest_dict or "signature" not in manifest_dict:
            return False, "Malformed integrity manifest: missing hashes or signature"
            
        hashes_dict = manifest_dict["hashes"]
        sig_b64 = manifest_dict["signature"]
        
        # Verify cryptographic signature of the hashes dict
        hashes_bytes = json.dumps(hashes_dict, sort_keys=True).encode("utf-8")
        signature = base64.b64decode(sig_b64)
        
        public_key = load_public_key(pubkey_path)
        public_key.verify(
            signature,
            hashes_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Now verify each file's hash
        for relative_path_str, expected_hash in hashes_dict.items():
            file_path = Path(relative_path_str)
            if not file_path.exists():
                return False, f"Critical source file missing: {relative_path_str}"
                
            current_hash = sha256_file(file_path)
            if current_hash != expected_hash:
                return False, f"Integrity check failed: '{relative_path_str}' has been modified since it was built and signed!"
                
        return True, ""
        
    except InvalidSignature:
        return False, "Build signature verification failed: manifest has been tampered with"
    except Exception as e:
        return False, f"Integrity verification error: {str(e)}"
