"""
Tests for forensic_utils.

These tests use synthetic / fabricated vault bytes - they are NOT real
encrypted wallets and they cannot be decrypted. We only verify that the
metadata-only parser reports the expected structural information.

The BIP39 mnemonic test uses the well-known "abandon abandon ... about"
test vector documented in the BIP39 specification. It is intentionally
public; do NOT send funds to any address derived from it.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from base64 import b64encode

import pytest

# Allow running `pytest` from the project root without installing the package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensic_utils import (  # noqa: E402
    LEGACY_PBKDF2_ITERATIONS,
    SQLITE_HEADER,
    identify_wallet_file,
    inspect_metamask_vault,
)


VALID_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def _make_vault(
    *,
    cipher_bytes: bytes,
    iv_bytes: bytes,
    salt_bytes: bytes,
    iterations: int | None = 600000,
) -> dict:
    """Construct a synthetic MetaMask-style vault dict (modern or legacy)."""
    vault: dict = {
        "data": b64encode(cipher_bytes).decode("ascii"),
        "iv": b64encode(iv_bytes).decode("ascii"),
        "salt": b64encode(salt_bytes).decode("ascii"),
    }
    if iterations is not None:
        vault["keyMetadata"] = {
            "algorithm": "PBKDF2",
            "params": {"iterations": iterations},
        }
    return vault


# ---------------------------------------------------------------------------
# inspect_metamask_vault
# ---------------------------------------------------------------------------

class TestInspectMetaMaskVault:
    def test_modern_vault_reports_expected_fields(self):
        cipher = b"\x11" * 96
        iv = b"\x22" * 16
        salt = b"\x33" * 32
        vault = _make_vault(
            cipher_bytes=cipher, iv_bytes=iv, salt_bytes=salt, iterations=600000
        )
        r = inspect_metamask_vault(json.dumps(vault))

        assert r["format"] == "metamask_v1"
        assert r["kdf"] == "PBKDF2"
        assert r["kdf_iterations"] == 600000
        assert r["salt_len_bytes"] == 32
        assert r["iv_len_bytes"] == 16
        assert r["ciphertext_len_bytes"] == 96
        # SHA-256 fingerprint must be deterministic over the ciphertext bytes.
        assert r["ciphertext_sha256"] == hashlib.sha256(cipher).hexdigest()
        assert set(r["raw_keys"]) == {"data", "iv", "salt", "keyMetadata"}
        # Result must not leak any raw bytes.
        assert "ciphertext" not in r
        assert "iv_bytes" not in r
        assert "salt_bytes" not in r

    def test_legacy_vault_defaults_to_10000_iterations(self):
        cipher = b"\xAA" * 64
        iv = b"\xBB" * 16
        salt = b"\xCC" * 16
        vault = _make_vault(
            cipher_bytes=cipher, iv_bytes=iv, salt_bytes=salt, iterations=None
        )
        r = inspect_metamask_vault(json.dumps(vault))

        assert r["format"] == "metamask_legacy"
        assert r["kdf_iterations"] == LEGACY_PBKDF2_ITERATIONS == 10000
        assert r["ciphertext_len_bytes"] == 64
        assert r["salt_len_bytes"] == 16
        # The notes should explain why we treated it as legacy.
        assert any("pre-10.x" in n or "legacy" in n.lower() for n in r["notes"])

    def test_wrapped_vault_unwraps(self):
        cipher = b"\x01\x02\x03\x04" * 8
        iv = b"\x10" * 16
        salt = b"\x20" * 32
        inner = _make_vault(
            cipher_bytes=cipher, iv_bytes=iv, salt_bytes=salt, iterations=600000
        )
        # Outer wrapping as seen in browser LevelDB exports: "vault" carries
        # a stringified JSON payload.
        wrapped = {"vault": json.dumps(inner)}
        r = inspect_metamask_vault(json.dumps(wrapped))

        assert r["format"] == "metamask_v1"
        assert r["kdf_iterations"] == 600000
        assert r["ciphertext_len_bytes"] == len(cipher)
        assert r["ciphertext_sha256"] == hashlib.sha256(cipher).hexdigest()

    def test_keyring_controller_wrapping_unwraps(self):
        cipher = b"\xDE\xAD\xBE\xEF" * 16
        iv = b"\x00" * 16
        salt = b"\xFF" * 32
        inner = _make_vault(
            cipher_bytes=cipher, iv_bytes=iv, salt_bytes=salt, iterations=600000
        )
        wrapped = {"KeyringController": {"vault": json.dumps(inner)}}
        r = inspect_metamask_vault(json.dumps(wrapped))

        assert r["format"] == "metamask_v1"
        assert r["ciphertext_sha256"] == hashlib.sha256(cipher).hexdigest()

    def test_invalid_json_is_rejected_cleanly(self):
        bogus = "{not really json: " + ("X" * 50)
        with pytest.raises(ValueError) as exc:
            inspect_metamask_vault(bogus)
        # The error message must not echo the bogus input back at the user.
        assert "XXXX" not in str(exc.value)
        assert "not really json" not in str(exc.value)

    def test_empty_input_rejected(self):
        with pytest.raises(ValueError):
            inspect_metamask_vault("")
        with pytest.raises(ValueError):
            inspect_metamask_vault("   ")

    def test_missing_fields_returns_unknown(self):
        # Valid JSON but no vault fields.
        r = inspect_metamask_vault('{"hello": "world"}')
        assert r["format"] == "unknown"
        assert r["ciphertext_len_bytes"] == 0
        assert r["raw_keys"] == ["hello"]

    def test_result_is_json_serialisable(self):
        # The whole point of returning metadata is so it can be displayed
        # in the UI. Make sure the dict round-trips through JSON.
        vault = _make_vault(
            cipher_bytes=b"\x00" * 32,
            iv_bytes=b"\x00" * 16,
            salt_bytes=b"\x00" * 16,
            iterations=600000,
        )
        r = inspect_metamask_vault(json.dumps(vault))
        json.dumps(r)  # must not raise


# ---------------------------------------------------------------------------
# identify_wallet_file
# ---------------------------------------------------------------------------

class TestIdentifyWalletFile:
    def test_metamask_vault_bytes(self):
        vault = _make_vault(
            cipher_bytes=b"\xAB" * 80,
            iv_bytes=b"\xCD" * 16,
            salt_bytes=b"\xEF" * 32,
            iterations=600000,
        )
        content = json.dumps(vault).encode("utf-8")
        r = identify_wallet_file(content, filename="vault.json")
        assert r["guessed_format"] == "metamask_vault"
        assert r["size_bytes"] == len(content)
        assert r["sha256"] == hashlib.sha256(content).hexdigest()
        assert r["contains_secrets_warning"] is False

    def test_sqlite_wallet_header(self):
        content = SQLITE_HEADER + b"\x00" * 256
        r = identify_wallet_file(content, filename="wallet.sqlite")
        assert r["guessed_format"] == "sqlite_wallet"
        assert r["contains_secrets_warning"] is True

    def test_bip39_mnemonic_text_is_flagged_without_echo(self):
        content = VALID_MNEMONIC.encode("utf-8")
        r = identify_wallet_file(content, filename="seed.txt")

        assert r["guessed_format"] == "bip39_mnemonic_text"
        assert r["contains_secrets_warning"] is True

        # Critical: the mnemonic words must NOT appear in the result notes
        # or anywhere else in the structured response.
        flat = json.dumps(r)
        assert "abandon" not in flat
        assert "about" not in flat

        # But the notes should communicate the structural facts.
        joined_notes = " ".join(r["notes"])
        assert "12 words" in joined_notes
        assert "VALID" in joined_notes  # checksum status reported

    def test_random_bytes_unknown(self):
        # 256 bytes of high-entropy noise. Should not match any signature.
        content = bytes(range(256))
        r = identify_wallet_file(content, filename=None)
        assert r["guessed_format"] == "unknown"
        assert r["size_bytes"] == 256
        assert r["sha256"] == hashlib.sha256(content).hexdigest()
        assert r["contains_secrets_warning"] is False
        # Sane default: at least one note explaining why we couldn't ID it.
        assert r["notes"]

    def test_empty_input(self):
        r = identify_wallet_file(b"", filename="nothing.bin")
        assert r["guessed_format"] == "unknown"
        assert r["size_bytes"] == 0
        assert r["contains_secrets_warning"] is False

    def test_pem_key_detection(self):
        content = b"-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN...\n-----END PRIVATE KEY-----\n"
        r = identify_wallet_file(content, filename="key.pem")
        assert r["guessed_format"] == "pem_key"
        assert r["contains_secrets_warning"] is True

    def test_bip_utils_export_flagged(self):
        # Synthetic export that looks like a bip-utils dump containing a
        # mnemonic. We intentionally use a NON-mnemonic string so it can't
        # be misread as a real BIP39 phrase.
        payload = {"mnemonic": "REDACTED", "addresses": []}
        content = json.dumps(payload).encode("utf-8")
        r = identify_wallet_file(content, filename="export.json")
        assert r["guessed_format"] == "bip_utils_export"
        assert r["contains_secrets_warning"] is True

    def test_electrum_wallet_detected(self):
        # Minimal Electrum-shaped JSON.
        content = json.dumps(
            {"wallet_type": "standard", "seed_version": 17}
        ).encode("utf-8")
        r = identify_wallet_file(content, filename="default_wallet")
        assert r["guessed_format"] == "electrum_wallet"
        assert r["contains_secrets_warning"] is True

    def test_non_bytes_input_rejected(self):
        with pytest.raises(ValueError):
            identify_wallet_file("not bytes", filename=None)  # type: ignore[arg-type]
