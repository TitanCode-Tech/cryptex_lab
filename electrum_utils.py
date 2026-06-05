"""
electrum_utils.py
-----------------
Electrum v1 and v2 wallet seed recovery tools.

Electrum uses its own mnemonic standards, independent of BIP39:

  v1  — 12 words from a 1626-word English list. No passphrase. Deterministic
         sequence of private keys derived from a 64-hex-char master secret.
         Used by Electrum < 2.0 (Bitcoin only, P2PKH addresses).

  v2  — 12-13 words. Types: standard, segwit, 2FA-standard, 2FA-segwit.
         Optional passphrase. Derives a seed via HMAC-SHA512 (not PBKDF2).
         Standard type → legacy BTC addresses.
         Segwit type   → native segwit (bech32) addresses.

SECURITY NOTES
==============
* No network calls. Nothing written to disk.
* Mnemonic and passphrase are used only as local variables and are discarded.
"""

from __future__ import annotations

import multiprocessing
import time
from typing import Callable

from bip_utils import (
    ElectrumV1,
    ElectrumV1SeedGenerator,
    ElectrumV1MnemonicValidator,
    ElectrumV2Standard,
    ElectrumV2Segwit,
    ElectrumV2SeedGenerator,
    ElectrumV2MnemonicValidator,
    ElectrumV2MnemonicTypes,
)

# Maximum matches before truncation
_MAX_MATCHES = 5

# How many addresses to scan per scan call
_DEFAULT_COUNT = 10
_DEFAULT_CHANGE_INDICES = [0, 1]  # external + internal (change) addresses


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def detect_electrum_version(mnemonic: str) -> str:
    """
    Returns 'v1', 'v2_standard', 'v2_segwit', or 'unknown'.
    """
    m = mnemonic.strip()
    try:
        if ElectrumV1MnemonicValidator().IsValid(m):
            return "v1"
    except Exception:
        pass
    for mtype, label in (
        (ElectrumV2MnemonicTypes.STANDARD, "v2_standard"),
        (ElectrumV2MnemonicTypes.SEGWIT, "v2_segwit"),
    ):
        try:
            if ElectrumV2MnemonicValidator(mtype).IsValid(m):
                return label
        except Exception:
            pass
    return "unknown"


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------

def derive_electrum_v1_addresses(
    mnemonic: str,
    count: int = _DEFAULT_COUNT,
    change: int = 0,
) -> list[dict]:
    """
    Derive `count` receiving addresses from an Electrum v1 mnemonic.

    Returns
    -------
    list of dicts: {version, path_desc, address, index}
    """
    mnemonic = mnemonic.strip()
    seed = ElectrumV1SeedGenerator(mnemonic).Generate()
    wallet = ElectrumV1.FromSeed(seed)
    results = []
    for i in range(count):
        addr = wallet.GetAddress(change, i)
        results.append({
            "version": "Electrum v1",
            "path_desc": f"change={change}, index={i}",
            "address": addr,
            "index": i,
            "change": change,
        })
    return results


def derive_electrum_v2_addresses(
    mnemonic: str,
    passphrase: str = "",
    count: int = _DEFAULT_COUNT,
    mnemonic_type: str = "auto",
    change: int = 0,
) -> list[dict]:
    """
    Derive `count` addresses from an Electrum v2 mnemonic.

    Parameters
    ----------
    mnemonic_type : str
        'standard', 'segwit', or 'auto' (tries standard then segwit).

    Returns
    -------
    list of dicts: {version, type, path_desc, address, index}
    """
    mnemonic = mnemonic.strip()
    seed = ElectrumV2SeedGenerator(mnemonic).Generate(passphrase)

    types_to_try: list[tuple] = []
    if mnemonic_type == "segwit":
        types_to_try = [(ElectrumV2Segwit, "v2_segwit")]
    elif mnemonic_type == "standard":
        types_to_try = [(ElectrumV2Standard, "v2_standard")]
    else:
        types_to_try = [(ElectrumV2Standard, "v2_standard"), (ElectrumV2Segwit, "v2_segwit")]

    results = []
    for wallet_cls, label in types_to_try:
        wallet = wallet_cls.FromSeed(seed)
        for i in range(count):
            addr = wallet.GetAddress(change, i)
            results.append({
                "version": "Electrum v2",
                "type": label,
                "path_desc": f"change={change}, index={i}",
                "address": addr,
                "index": i,
                "change": change,
                "passphrase_used": bool(passphrase),
            })
    return results


def derive_electrum_addresses(
    mnemonic: str,
    passphrase: str = "",
    count: int = _DEFAULT_COUNT,
) -> list[dict]:
    """
    Auto-detect version and derive addresses. Returns combined results.
    """
    version = detect_electrum_version(mnemonic)
    if version == "v1":
        return derive_electrum_v1_addresses(mnemonic, count=count)
    if version in ("v2_standard", "v2_segwit"):
        mtype = "segwit" if version == "v2_segwit" else "standard"
        return derive_electrum_v2_addresses(mnemonic, passphrase=passphrase, count=count, mnemonic_type=mtype)
    # Unknown — try both v2 types
    results = []
    try:
        results += derive_electrum_v2_addresses(mnemonic, passphrase=passphrase, count=count, mnemonic_type="standard")
    except Exception:
        pass
    try:
        results += derive_electrum_v2_addresses(mnemonic, passphrase=passphrase, count=count, mnemonic_type="segwit")
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# Address matching
# ---------------------------------------------------------------------------

def find_electrum_address(
    mnemonic: str,
    target_address: str,
    passphrase: str = "",
    count: int = 50,
) -> dict:
    """
    Scan up to `count` addresses (external + change) for `target_address`.

    Returns
    -------
    dict: {match: dict|None, searched: int, version: str, candidates: list[dict]}
    """
    version = detect_electrum_version(mnemonic.strip())
    candidates: list[dict] = []
    target = target_address.strip().lower()

    try:
        if version == "v1":
            for change in _DEFAULT_CHANGE_INDICES:
                candidates += derive_electrum_v1_addresses(mnemonic, count=count, change=change)
        else:
            mtype = "segwit" if version == "v2_segwit" else "auto"
            for change in _DEFAULT_CHANGE_INDICES:
                candidates += derive_electrum_v2_addresses(
                    mnemonic, passphrase=passphrase, count=count,
                    mnemonic_type=mtype, change=change,
                )
    except Exception as e:
        raise ValueError(f"Derivation failed: {e}") from e

    match = None
    for c in candidates:
        if c["address"].lower() == target:
            match = c
            break

    return {
        "match": match,
        "searched": len(candidates),
        "version": version,
        "candidates": candidates,
    }


# ---------------------------------------------------------------------------
# Passphrase recovery (v2 only) — multiprocessing
# ---------------------------------------------------------------------------

def _electrum_v2_worker(args: tuple) -> dict:
    """
    args: (mnemonic, candidates_chunk, target_address, mnemonic_type, count)
    Returns: {matches: list[dict], checked: int}
    """
    mnemonic, candidates_chunk, target_address, mnemonic_type, count = args
    target = target_address.strip().lower()
    matches: list[dict] = []
    checked = 0

    for passphrase in candidates_chunk:
        checked += 1
        try:
            seed = ElectrumV2SeedGenerator(mnemonic).Generate(passphrase)
            wallet_cls = ElectrumV2Segwit if mnemonic_type == "segwit" else ElectrumV2Standard
            wallet = wallet_cls.FromSeed(seed)
            for change in (0, 1):
                for i in range(count):
                    if wallet.GetAddress(change, i).lower() == target:
                        matches.append({
                            "passphrase": passphrase,
                            "change": change,
                            "index": i,
                        })
                        break
                if matches and matches[-1].get("passphrase") == passphrase:
                    break
        except Exception:
            pass

    return {"matches": matches, "checked": checked}


def recover_electrum_v2_passphrase(
    mnemonic: str,
    candidates: list[str],
    target_address: str,
    progress_callback: Callable[[int, int, int], None] | None = None,
    chunk_size: int = 32,
) -> dict:
    """
    Dictionary attack on an Electrum v2 wallet passphrase.

    Parameters
    ----------
    mnemonic : str
        Valid Electrum v2 mnemonic.
    candidates : list[str]
        Passphrase candidates.
    target_address : str
        Known wallet address (required).
    progress_callback : callable | None
        Called as (checked, total, matches_found).
    chunk_size : int
        Candidates per worker task.

    Returns
    -------
    dict: {matches, checked, total, elapsed_time, truncated}
    """
    mnemonic = mnemonic.strip()
    if not mnemonic:
        raise ValueError("Mnemonic is required")
    if not candidates:
        raise ValueError("Candidate list is empty")
    if not target_address.strip():
        raise ValueError("Target address is required")

    version = detect_electrum_version(mnemonic)
    if version not in ("v2_standard", "v2_segwit", "unknown"):
        raise ValueError(f"Mnemonic appears to be {version}, not Electrum v2")
    mtype = "segwit" if version == "v2_segwit" else "standard"

    chunks = [candidates[i:i + chunk_size] for i in range(0, len(candidates), chunk_size)]
    count_per_addr = 20
    tasks = [(mnemonic, chunk, target_address, mtype, count_per_addr) for chunk in chunks]

    total = len(candidates)
    all_matches: list[dict] = []
    checked = 0
    truncated = False
    num_workers = max(1, multiprocessing.cpu_count() - 1)
    start_time = time.time()

    with multiprocessing.Pool(num_workers) as pool:
        for res in pool.imap_unordered(_electrum_v2_worker, tasks):
            checked += res["checked"]
            all_matches.extend(res["matches"])
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
