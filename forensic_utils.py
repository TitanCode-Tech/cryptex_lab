"""
forensic_utils.py
-----------------
Read-only, METADATA-ONLY forensic helpers for CRYPTEX LAB.

WHY METADATA-ONLY
=================
This module looks at wallet files (MetaMask vaults, Electrum wallet files,
Bitcoin Core wallet.dat, SQLite-backed wallets, PEM keys, BIP39 mnemonic
text files, etc.) and reports STRUCTURAL information about them:

    * which format they appear to be,
    * how big the encrypted blob is,
    * a SHA-256 fingerprint of the ciphertext,
    * the KDF parameters declared inside the file.

It NEVER:

    * attempts to decrypt the data,
    * tries any password, dictionary, or brute force,
    * downloads anything, sends anything, or imports any networking library,
    * returns the raw ciphertext / IV / salt bytes to the caller,
    * logs or echoes user-supplied secrets.

The reasoning is simple: this app is built for ETHICAL recovery scenarios
where the user already owns the wallet. Metadata-only inspection helps a
user (or an investigator working with the wallet owner) identify what kind
of file they have and confirm that its structure is plausible, without ever
performing or aiding an attack. Decryption, password cracking, or password
trial-and-error must be done by a separate, conscious tool outside the
scope of this app.

SECURITY DESIGN NOTES
=====================
* No network imports anywhere in this file.
* All functions are pure: input bytes/text in, dict out. Nothing is written
  to disk, logged, or stashed in module-level state.
* Error messages never include the raw input (which might be sensitive).
* BIP39 mnemonics that we sniff are validated but NEVER echoed back in the
  result. We report counts, lengths, and validity flags only.
"""

from __future__ import annotations

import hashlib
import json
import re
from base64 import b64decode
from typing import Any

# We reuse the existing offline BIP39 validator. wallet_utils itself imports
# only bip_utils and stdlib, so this stays fully offline.
from wallet_utils import validate_mnemonic


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Pre-10.x MetaMask vaults did not carry a `keyMetadata` field; the iteration
# count was hard-coded to 10,000 PBKDF2 rounds. Modern vaults declare it
# explicitly (typically 600,000).
LEGACY_PBKDF2_ITERATIONS = 10000

# Berkeley DB magic bytes seen at offset 12 in Bitcoin Core wallet.dat files.
# Two variants exist in the wild; we accept either.
BDB_MAGIC_BE = b"\x00\x05\x31\x62"
BDB_MAGIC_LE = b"\x62\x31\x05\x00"
BDB_MAGIC_ALT_BE = b"\x00\x06\x15\x61"
BDB_MAGIC_ALT_LE = b"\x61\x15\x06\x00"

# SQLite header is fixed and well known.
SQLITE_HEADER = b"SQLite format 3\x00"

# Valid BIP39 word counts. Matches wallet_utils.VALID_WORD_COUNTS but we
# avoid the import dependency cycle by re-declaring this small set.
VALID_BIP39_WORD_COUNTS = {12, 15, 18, 21, 24}

# Maximum size (bytes) of a file we will attempt to interpret as text when
# sniffing BIP39 mnemonics. Real mnemonic files are tiny; anything bigger is
# almost certainly something else.
MNEMONIC_TEXT_MAX_BYTES = 4096


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of `data` (uppercase-insensitive)."""
    return hashlib.sha256(data).hexdigest()


def _safe_b64_len(value: Any) -> int:
    """
    Length of the binary payload represented by a base64 string.

    Returns 0 if `value` is not a string or is not valid base64. This is a
    metadata-only helper: we never keep the decoded bytes anywhere.
    """
    if not isinstance(value, str):
        return 0
    try:
        return len(b64decode(value, validate=True))
    except Exception:
        return 0


def _safe_b64_decode(value: Any) -> bytes:
    """Decode a base64 string or return b'' on any failure."""
    if not isinstance(value, str):
        return b""
    try:
        return b64decode(value, validate=True)
    except Exception:
        return b""


def _unwrap_vault(obj: Any, depth: int = 0) -> Any:
    """
    Walk through common MetaMask vault wrappings until we reach the inner
    dict that actually contains `data`/`iv`/`salt`.

    Recognised wrappings:
        * {"vault": "<stringified inner json>"}  -> parse + recurse
        * {"vault": {...}}                        -> recurse into the dict
        * {"KeyringController": {"vault": ...}}   -> dive into the controller

    Recursion is bounded to avoid pathological inputs.
    """
    if depth > 8:
        return obj

    if isinstance(obj, dict):
        # KeyringController wrapper used in extension storage exports.
        if "KeyringController" in obj and isinstance(obj["KeyringController"], dict):
            return _unwrap_vault(obj["KeyringController"], depth + 1)

        # Direct {"vault": ...} wrapper.
        if "vault" in obj and set(obj.keys()) - {"vault"} == set():
            return _unwrap_vault(obj["vault"], depth + 1)

        # Some exports also nest under "vault" alongside other fields; if
        # the current dict doesn't itself look like a vault but does have a
        # "vault" entry, follow that.
        looks_like_vault = "data" in obj and "iv" in obj and "salt" in obj
        if not looks_like_vault and "vault" in obj:
            return _unwrap_vault(obj["vault"], depth + 1)

    if isinstance(obj, str):
        # Stringified inner JSON, very common for MetaMask vaults stored in
        # browser LevelDB.
        try:
            return _unwrap_vault(json.loads(obj), depth + 1)
        except Exception:
            return obj

    return obj


# ---------------------------------------------------------------------------
# Public API: MetaMask vault inspection
# ---------------------------------------------------------------------------

def inspect_metamask_vault(vault_text: str) -> dict:
    """
    Inspect a MetaMask vault (modern or legacy) and report its structure.

    The input must be a JSON string. Common wrappings are unwrapped
    automatically. Returns a dict describing the vault format, KDF
    parameters, and a SHA-256 fingerprint of the ciphertext. Raw ciphertext,
    IV, and salt bytes are NEVER returned.

    Raises ValueError if the input cannot be parsed as JSON or does not
    contain a recognisable vault structure. The error message never echoes
    the input.
    """
    if not isinstance(vault_text, str) or not vault_text.strip():
        raise ValueError("Vault input must be a non-empty JSON string.")

    try:
        parsed: Any = json.loads(vault_text)
    except Exception:
        # Deliberately generic - do not echo the input.
        raise ValueError("Vault input is not valid JSON.")

    unwrapped = _unwrap_vault(parsed)

    if not isinstance(unwrapped, dict):
        raise ValueError("Vault JSON did not contain a recognisable object.")

    raw_keys = sorted(unwrapped.keys())
    notes: list[str] = []

    # The three fields below are required for any MetaMask vault we know
    # about. If they're missing we cannot say anything useful.
    data = unwrapped.get("data")
    iv = unwrapped.get("iv")
    salt = unwrapped.get("salt")
    if not (isinstance(data, str) and isinstance(iv, str) and isinstance(salt, str)):
        return {
            "format": "unknown",
            "kdf": "PBKDF2",
            "kdf_iterations": 0,
            "salt_len_bytes": 0,
            "iv_len_bytes": 0,
            "ciphertext_len_bytes": 0,
            "ciphertext_sha256": "",
            "raw_keys": raw_keys,
            "notes": [
                "Missing one of the required fields: data, iv, salt.",
                "Cannot identify this as a MetaMask vault.",
            ],
        }

    # Decode just enough to measure lengths + fingerprint the ciphertext.
    # The decoded bytes are local-only and discarded at the end of the
    # function; we never return or store them.
    salt_bytes = _safe_b64_decode(salt)
    iv_bytes = _safe_b64_decode(iv)
    cipher_bytes = _safe_b64_decode(data)

    # Detect format based on presence of keyMetadata.
    key_metadata = unwrapped.get("keyMetadata")
    if isinstance(key_metadata, dict):
        fmt = "metamask_v1"
        params = key_metadata.get("params") or {}
        iterations = params.get("iterations") if isinstance(params, dict) else None
        if not isinstance(iterations, int) or iterations <= 0:
            iterations = LEGACY_PBKDF2_ITERATIONS
            notes.append(
                "keyMetadata present but iterations missing/invalid; "
                "assuming legacy default of 10,000."
            )
        algorithm = key_metadata.get("algorithm", "PBKDF2")
        if algorithm != "PBKDF2":
            notes.append(f"Unexpected KDF algorithm declared: {algorithm!r}.")
    else:
        fmt = "metamask_legacy"
        iterations = LEGACY_PBKDF2_ITERATIONS
        notes.append(
            "No keyMetadata field; treating as pre-10.x MetaMask vault "
            "(implicit PBKDF2 / 10,000 iterations)."
        )

    # Sanity-check the salt/IV lengths and add notes if they look odd. We
    # only ADD notes - we never refuse to report, because the user might
    # legitimately have an unusual vault and we want to surface that.
    if len(salt_bytes) == 0:
        notes.append("Salt field is not valid base64.")
    if len(iv_bytes) == 0:
        notes.append("IV field is not valid base64.")
    elif len(iv_bytes) != 16:
        notes.append(
            f"IV length is {len(iv_bytes)} bytes; AES-GCM/AES-CBC vaults "
            "normally use 16."
        )
    if len(cipher_bytes) == 0:
        notes.append("Ciphertext field is not valid base64.")

    result = {
        "format": fmt,
        "kdf": "PBKDF2",
        "kdf_iterations": int(iterations),
        "salt_len_bytes": len(salt_bytes),
        "iv_len_bytes": len(iv_bytes),
        "ciphertext_len_bytes": len(cipher_bytes),
        "ciphertext_sha256": _sha256_hex(cipher_bytes) if cipher_bytes else "",
        "raw_keys": raw_keys,
        "notes": notes,
    }

    # Drop our local references to decoded bytes ASAP.
    del salt_bytes, iv_bytes, cipher_bytes
    return result


# ---------------------------------------------------------------------------
# Public API: generic wallet-file fingerprinting
# ---------------------------------------------------------------------------

def _looks_like_metamask_dict(obj: Any) -> bool:
    """Heuristic: does this parsed JSON object look like a MetaMask vault?"""
    inner = _unwrap_vault(obj)
    if isinstance(inner, dict):
        return all(isinstance(inner.get(k), str) for k in ("data", "iv", "salt"))
    return False


def _try_decode_text(content: bytes) -> str | None:
    """Try to decode content as UTF-8 text; return None if it isn't text."""
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _classify_bip39_text(text: str) -> dict | None:
    """
    Decide if `text` looks like a BIP39 mnemonic file.

    Returns a result dict (containing only counts/flags, no words) or None
    if the text does not appear to be a mnemonic.
    """
    # Normalise whitespace but never store the result anywhere outside this
    # function. We only ever return numbers + booleans.
    tokens = text.lower().split()
    if not tokens:
        return None
    if len(tokens) not in VALID_BIP39_WORD_COUNTS:
        return None
    # Quick lexical filter: BIP39 words are short, lowercase, ASCII letters.
    if not all(re.fullmatch(r"[a-z]{3,8}", tok) for tok in tokens):
        return None

    info = validate_mnemonic(text)
    if not info["words_in_wordlist"]:
        return None

    note = (
        f"Looks like a BIP39 mnemonic ({info['word_count']} words, "
        f"checksum: {'VALID' if info['checksum_valid'] else 'INVALID'})."
    )
    del tokens  # explicit drop; we never return the words.
    return {
        "guessed_format": "bip39_mnemonic_text",
        "label": "BIP39 mnemonic (plain text file)",
        "contains_secrets_warning": True,
        "note": note,
    }


def _classify_json_text(text: str) -> dict | None:
    """Try to classify a JSON file into one of the formats we know about."""
    try:
        obj = json.loads(text)
    except Exception:
        return None

    # MetaMask vault: either directly or wrapped.
    if _looks_like_metamask_dict(obj):
        return {
            "guessed_format": "metamask_vault",
            "label": "MetaMask encrypted vault (JSON)",
            "contains_secrets_warning": False,
            "note": "Encrypted vault. Inspect with inspect_metamask_vault().",
        }

    if isinstance(obj, dict):
        # bip-utils style exports: contain raw mnemonic or seed.
        lowered_keys = {k.lower() for k in obj.keys() if isinstance(k, str)}
        if "mnemonic" in lowered_keys or "seed" in lowered_keys:
            return {
                "guessed_format": "bip_utils_export",
                "label": "bip-utils JSON export (contains raw secrets)",
                "contains_secrets_warning": True,
                "note": "Export contains raw mnemonic or seed; handle with care.",
            }

        # Electrum wallet file.
        if "wallet_type" in obj or "seed_version" in obj or "seed_type" in obj:
            return {
                "guessed_format": "electrum_wallet",
                "label": "Electrum wallet file (JSON)",
                # Electrum wallets may or may not be encrypted; we can't tell
                # for sure without inspecting, so we flag conservatively.
                "contains_secrets_warning": True,
                "note": "Electrum wallet file detected. May contain seeds.",
            }

    return None


def _classify_binary(content: bytes, filename: str | None) -> dict | None:
    """Try to classify a binary file by magic bytes / extension."""
    # SQLite (bitcoinlib and others) - check first 16 bytes.
    if content.startswith(SQLITE_HEADER):
        return {
            "guessed_format": "sqlite_wallet",
            "label": "SQLite wallet database (e.g. bitcoinlib)",
            "contains_secrets_warning": True,
            "note": "SQLite database; may hold encrypted or plaintext keys.",
        }

    # Bitcoin Core wallet.dat (BerkeleyDB). Magic lives at offset 12.
    if len(content) >= 16:
        magic = content[12:16]
        if magic in (BDB_MAGIC_BE, BDB_MAGIC_LE, BDB_MAGIC_ALT_BE, BDB_MAGIC_ALT_LE):
            return {
                "guessed_format": "bitcoin_core_wallet_dat",
                "label": "Bitcoin Core wallet.dat (BerkeleyDB)",
                "contains_secrets_warning": True,
                "note": "BerkeleyDB magic detected at offset 12.",
            }

    # PEM key (text inside a binary blob, check the leading bytes).
    if content.lstrip().startswith(b"-----BEGIN"):
        return {
            "guessed_format": "pem_key",
            "label": "PEM-encoded key",
            "contains_secrets_warning": True,
            "note": "PEM header detected; may be a private key.",
        }

    # Extension-only fallback for wallet.dat where the BDB magic check fails
    # (e.g. truncated test fixtures).
    if filename and filename.lower().endswith("wallet.dat"):
        return {
            "guessed_format": "bitcoin_core_wallet_dat",
            "label": "Bitcoin Core wallet.dat (by filename)",
            "contains_secrets_warning": True,
            "note": "Filename matches wallet.dat; magic bytes not confirmed.",
        }

    return None


def identify_wallet_file(content: bytes, filename: str | None = None) -> dict:
    """
    Identify what KIND of wallet file `content` represents.

    Returns a dict with a short slug (`guessed_format`), a human-readable
    label, the file size, a SHA-256 of the bytes, a warning flag for files
    that typically contain plaintext secrets, and a list of notes.

    This function NEVER decrypts anything and NEVER returns the raw bytes.
    For mnemonic-shaped text files we report counts and checksum validity,
    but the words themselves are not returned.
    """
    if not isinstance(content, bytes):
        raise ValueError("identify_wallet_file expects bytes content.")

    base = {
        "guessed_format": "unknown",
        "label": "Unknown / unrecognised wallet file",
        "size_bytes": len(content),
        "sha256": _sha256_hex(content),
        "contains_secrets_warning": False,
        "notes": [],
    }

    if len(content) == 0:
        base["notes"].append("File is empty.")
        return base

    # Binary checks first - they're cheap and unambiguous when they fire.
    binary_hit = _classify_binary(content, filename)
    if binary_hit is not None:
        base.update(
            {
                "guessed_format": binary_hit["guessed_format"],
                "label": binary_hit["label"],
                "contains_secrets_warning": binary_hit["contains_secrets_warning"],
            }
        )
        base["notes"].append(binary_hit["note"])
        return base

    # Try JSON next - covers MetaMask, Electrum, bip-utils exports.
    text = _try_decode_text(content)
    if text is not None:
        json_hit = _classify_json_text(text)
        if json_hit is not None:
            base.update(
                {
                    "guessed_format": json_hit["guessed_format"],
                    "label": json_hit["label"],
                    "contains_secrets_warning": json_hit["contains_secrets_warning"],
                }
            )
            base["notes"].append(json_hit["note"])
            return base

        # Finally: BIP39 mnemonic text files. Only for small files to avoid
        # accidentally running the wordlist check on big documents.
        if len(content) <= MNEMONIC_TEXT_MAX_BYTES:
            mnemonic_hit = _classify_bip39_text(text)
            if mnemonic_hit is not None:
                base.update(
                    {
                        "guessed_format": mnemonic_hit["guessed_format"],
                        "label": mnemonic_hit["label"],
                        "contains_secrets_warning": mnemonic_hit[
                            "contains_secrets_warning"
                        ],
                    }
                )
                base["notes"].append(mnemonic_hit["note"])
                return base

    # Nothing matched.
    base["notes"].append("No known wallet-file signature detected.")
    return base
