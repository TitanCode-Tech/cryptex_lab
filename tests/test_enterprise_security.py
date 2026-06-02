import json
import os
import pytest
from pathlib import Path
from audit import log_event, clean_event_value
from license_utils import verify_license_data, check_module_access
from integrity import verify_build_integrity, sha256_file

@pytest.fixture
def temp_audit_log(tmp_path, monkeypatch):
    # Redirect audit log directory to a temp path for testing
    monkeypatch.setattr("audit.LOG_DIR", tmp_path)
    return tmp_path / "audit.jsonl"

def test_audit_logging(temp_audit_log):
    log_event(
        case_id="CASE-999",
        module="test_module",
        action="test_action",
        role="senior",
        mode="OFFLINE_SAFE",
        export_actions="pdf"
    )
    
    assert temp_audit_log.exists()
    
    with open(temp_audit_log, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    assert len(lines) == 1
    entry = json.loads(lines[0])
    
    assert entry["case_id"] == "CASE-999"
    assert entry["module"] == "test_module"
    assert entry["action"] == "test_action"
    assert entry["role"] == "senior"
    assert entry["mode"] == "OFFLINE_SAFE"
    assert entry["export_actions"] == "pdf"
    assert "timestamp" in entry

def test_audit_redaction():
    # Verify that clean_event_value redacts seeds, private keys, passwords, passphrases
    assert clean_event_value("my private key is secret") == "[REDACTED_SECRET]"
    assert clean_event_value("password123") == "[REDACTED_SECRET]"
    assert clean_event_value("passphrase") == "[REDACTED_SECRET]"
    assert clean_event_value("seed") == "[REDACTED_SECRET]"
    
    # 64 character hex key
    hex_key = "1" * 64
    assert clean_event_value(hex_key) == "[REDACTED_HEX_KEY]"
    
    # 12 word mnemonic
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    assert clean_event_value(mnemonic) == "[REDACTED_SEED_PHRASE]"
    
    # Safe value
    assert clean_event_value("CASE-123") == "CASE-123"

def test_license_verification():
    # Read the valid license.json we generated
    assert Path("license.json").exists()
    with open("license.json", "r") as f:
        license_dict = json.load(f)
        
    is_valid, err, data = verify_license_data(license_dict, Path("public_key.pem"))
    assert is_valid, f"Expected license to be valid but got error: {err}"
    assert data["company"] == "Titan Code"
    
    # Check module access
    assert check_module_access(data, "recovery")
    assert check_module_access(data, "forensic")
    assert not check_module_access(data, "non_existent_module")
    
    # Tamper with the license company field
    tampered_dict = json.loads(json.dumps(license_dict))
    tampered_dict["license_data"]["company"] = "Hacker Corp"
    is_valid_tampered, err_t, _ = verify_license_data(tampered_dict, Path("public_key.pem"))
    assert not is_valid_tampered
    assert "signature verification failed" in err_t.lower()

def test_build_integrity():
    # Verify that the generated manifest.json is valid
    assert Path("manifest.json").exists()
    is_valid, err = verify_build_integrity(Path("manifest.json"), Path("public_key.pem"))
    assert is_valid, f"Expected build integrity to pass, but got error: {err}"
    
    # Test with non-existent manifest
    is_valid_missing, err_m = verify_build_integrity(Path("non_existent_manifest.json"))
    assert not is_valid_missing
    assert "missing" in err_m.lower()
