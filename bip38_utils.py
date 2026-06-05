"""
bip38_utils.py
--------------
BIP38 encrypted private key decryption and dictionary attack.

BIP38 keys start with '6P' and contain an AES-encrypted Bitcoin private key
protected by a passphrase using scrypt key derivation.

Two modes:
  - DecryptNoEc: standard paper-wallet / WIF encryption (most common)
  - DecryptEc:   EC-multiply mode (used by vanity-address generators)

SECURITY NOTES
==============
* No network calls. Nothing written to disk.
* Decrypted private key bytes are used transiently and not returned in results.
* Only the derived BTC address and success flag are returned to the caller.
"""

from __future__ import annotations

import multiprocessing
import time
from typing import Callable

from bip_utils import (
    Bip38Decrypter,
    Bip38PubKeyModes,
    P2PKHAddr,
    Secp256k1PrivateKey,
)

# BTC mainnet P2PKH net version byte
_BTC_NET_VER = b"\x00"

# Maximum matches returned before truncation
_MAX_MATCHES = 5


# ---------------------------------------------------------------------------
# Single-key decryption
# ---------------------------------------------------------------------------

def decrypt_bip38(encrypted_key: str, passphrase: str) -> dict:
    """
    Attempt to decrypt a BIP38-encrypted key with the given passphrase.

    Parameters
    ----------
    encrypted_key : str
        BIP38 key string, starting with '6P'.
    passphrase : str
        Passphrase to try.

    Returns
    -------
    dict with keys:
        success : bool
        address : str | None     — derived BTC P2PKH address if success
        pub_key_mode : str | None — 'compressed' or 'uncompressed'
        error : str | None
    """
    encrypted_key = encrypted_key.strip()
    passphrase = passphrase.strip()

    if not encrypted_key.startswith("6P"):
        return {"success": False, "address": None, "pub_key_mode": None,
                "error": "Not a BIP38 key (must start with '6P')"}

    try:
        priv_bytes, pub_key_mode = Bip38Decrypter.DecryptNoEc(encrypted_key, passphrase)
        priv_key = Secp256k1PrivateKey.FromBytes(priv_bytes)
        pub_key = priv_key.PublicKey()
        address = P2PKHAddr.EncodeKey(pub_key, net_ver=_BTC_NET_VER, pub_key_mode=pub_key_mode)
        mode_str = "compressed" if pub_key_mode == Bip38PubKeyModes.COMPRESSED else "uncompressed"
        return {
            "success": True,
            "address": address,
            "pub_key_mode": mode_str,
            "error": None,
        }
    except Exception:
        pass

    try:
        priv_bytes, pub_key_mode = Bip38Decrypter.DecryptEc(encrypted_key, passphrase)
        priv_key = Secp256k1PrivateKey.FromBytes(priv_bytes)
        pub_key = priv_key.PublicKey()
        address = P2PKHAddr.EncodeKey(pub_key, net_ver=_BTC_NET_VER, pub_key_mode=pub_key_mode)
        mode_str = "compressed" if pub_key_mode == Bip38PubKeyModes.COMPRESSED else "uncompressed"
        return {
            "success": True,
            "address": address,
            "pub_key_mode": mode_str,
            "error": None,
        }
    except Exception as e:
        return {"success": False, "address": None, "pub_key_mode": None,
                "error": "Wrong passphrase or invalid key"}


# ---------------------------------------------------------------------------
# Multiprocessing worker
# ---------------------------------------------------------------------------

def _bip38_worker(args: tuple) -> dict:
    """
    args: (encrypted_key, candidates_chunk, target_address)
    target_address: if provided, only return a match when the decrypted address matches it.
                    if empty/None, return any successfully decrypted address.
    Returns: {"matches": list[dict], "checked": int}
    """
    encrypted_key, candidates_chunk, target_address = args
    target = target_address.strip().lower() if target_address else None
    matches: list[dict] = []
    checked = 0

    for passphrase in candidates_chunk:
        checked += 1
        result = decrypt_bip38(encrypted_key, passphrase)
        if result["success"]:
            addr = result["address"]
            if target is None or addr.lower() == target:
                matches.append({
                    "passphrase": passphrase,
                    "address": addr,
                    "pub_key_mode": result["pub_key_mode"],
                })

    return {"matches": matches, "checked": checked}


# ---------------------------------------------------------------------------
# Dictionary attack
# ---------------------------------------------------------------------------

def attack_bip38(
    encrypted_key: str,
    candidates: list[str],
    target_address: str = "",
    progress_callback: Callable[[int, int, int], None] | None = None,
    chunk_size: int = 8,
) -> dict:
    """
    Dictionary attack on a BIP38-encrypted key.

    BIP38 decryption uses scrypt internally (CPU-heavy). Chunk size is kept
    small (8) to maintain progress granularity without excessive IPC overhead.

    Parameters
    ----------
    encrypted_key : str
        BIP38 '6P...' key to attack.
    candidates : list[str]
        Passphrase candidates.
    target_address : str
        Optional known BTC address — if supplied, only matching decryptions
        are reported. If empty, any successful decryption is reported.
    progress_callback : callable | None
        Called as (checked, total, matches_found) after each chunk.
    chunk_size : int
        Candidates per worker task (keep low — scrypt is expensive).

    Returns
    -------
    dict with keys:
        matches      : list[dict]   — {passphrase, address, pub_key_mode}
        checked      : int
        total        : int
        elapsed_time : float
        truncated    : bool
    """
    encrypted_key = encrypted_key.strip()
    if not encrypted_key.startswith("6P"):
        raise ValueError("Not a BIP38 key (must start with '6P')")
    if not candidates:
        raise ValueError("candidates list is empty")

    chunks = [candidates[i:i + chunk_size] for i in range(0, len(candidates), chunk_size)]
    tasks = [(encrypted_key, chunk, target_address) for chunk in chunks]

    total = len(candidates)
    all_matches: list[dict] = []
    checked = 0
    truncated = False

    num_workers = max(1, multiprocessing.cpu_count() - 1)
    start_time = time.time()

    with multiprocessing.Pool(num_workers) as pool:
        for res in pool.imap_unordered(_bip38_worker, tasks):
            checked += res["checked"]
            for m in res["matches"]:
                if not any(x["passphrase"] == m["passphrase"] for x in all_matches):
                    all_matches.append(m)

            if progress_callback:
                progress_callback(checked, total, len(all_matches))

            if len(all_matches) >= _MAX_MATCHES:
                truncated = True
                pool.terminate()
                break

    return {
        "matches": all_matches,
        "checked": checked,
        "total": total,
        "elapsed_time": time.time() - start_time,
        "truncated": truncated,
    }
