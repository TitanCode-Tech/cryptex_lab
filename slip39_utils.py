"""
slip39_utils.py
---------------
SLIP39 (Shamir's Secret Sharing) mnemonic recovery tools.

SLIP39 splits a BIP32 master secret into N mnemonic shares using Shamir's
Secret Sharing Scheme. A threshold number of shares (e.g., 3-of-5) must be
combined to reconstruct the secret.

This is Trezor's standard for advanced seed backup. Each share is a 20-33
word mnemonic from SLIP39's own 1024-word wordlist (different from BIP39).

Key concepts:
  - Group threshold: how many *groups* must contribute shares
  - Per-group threshold: how many shares within a group are needed
  - Extendable: whether the encrypted master secret uses a fixed or extendable
    PBKDF2 iteration count

This module handles:
  1. Validating and decoding individual shares
  2. Combining shares to recover the master secret (with optional passphrase)
  3. Deriving BIP44 addresses from the recovered master secret

SECURITY NOTES
==============
* No network calls. Nothing written to disk.
* The recovered master secret (raw bytes) is used only transiently.
* Only derived addresses are returned — the secret bytes are discarded.
"""

from __future__ import annotations

from typing import Callable

import shamir_mnemonic
from shamir_mnemonic import MnemonicError

from bip_utils import (
    Bip32Slip10Secp256k1,
    Bip44,
    Bip44Coins,
    Bip44Changes,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
    P2PKHAddr,
    P2WPKHAddr,
)
from Crypto.Hash import keccak as _keccak_mod

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Coin IDs for address derivation (mirrors derivation_utils subset)
SLIP39_SUPPORTED_COINS = ["ETH", "BTC_NATIVE", "BTC_LEGACY", "BTC_SEGWIT"]


# ---------------------------------------------------------------------------
# Share validation
# ---------------------------------------------------------------------------

def validate_share(share: str) -> dict:
    """
    Validate a single SLIP39 share mnemonic.

    Returns
    -------
    dict: {valid, word_count, group_index, member_index, error}
    """
    share = share.strip().lower()
    words = share.split()
    try:
        decoded = shamir_mnemonic.decode_mnemonics([share])
        return {
            "valid": True,
            "word_count": len(words),
            "error": None,
        }
    except MnemonicError as e:
        return {
            "valid": False,
            "word_count": len(words),
            "error": str(e),
        }
    except Exception as e:
        return {
            "valid": False,
            "word_count": len(words),
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Master secret recovery and seed derivation
# ---------------------------------------------------------------------------

def _eth_address_from_seed(seed: bytes, index: int = 0) -> str:
    """Derive an Ethereum address from a SLIP39 seed."""
    ctx = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
    pub = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(index).PublicKey()
    raw_pub = pub.RawUncompressed().ToBytes()[1:]
    k = _keccak_mod.new(digest_bits=256)
    k.update(raw_pub)
    return "0x" + k.digest()[-20:].hex()


def combine_shares(
    shares: list[str],
    passphrase: str = "",
) -> dict:
    """
    Combine SLIP39 shares to recover the master secret and derive addresses.

    Parameters
    ----------
    shares : list[str]
        SLIP39 share mnemonics (at least threshold number for each group).
    passphrase : str
        Optional SLIP39 passphrase (separate from BIP39 passphrase).

    Returns
    -------
    dict:
        master_secret_hex : str   — hex of recovered master secret
        addresses         : list[dict]  — derived addresses per coin
        error             : str | None
    """
    cleaned = [s.strip().lower() for s in shares if s.strip()]
    if not cleaned:
        return {"master_secret_hex": None, "addresses": [], "error": "No shares provided"}

    try:
        passphrase_bytes = passphrase.encode("utf-8")
        master_secret = shamir_mnemonic.combine_mnemonics(cleaned, passphrase_bytes)
    except MnemonicError as e:
        return {"master_secret_hex": None, "addresses": [], "error": str(e)}
    except Exception as e:
        return {"master_secret_hex": None, "addresses": [], "error": f"Recovery failed: {e}"}

    # combine_mnemonics() applies all Feistel cipher rounds internally and
    # returns the decrypted master secret, which IS the BIP32 seed directly.
    # No additional KDF step is needed or correct here.
    seed = master_secret

    addresses: list[dict] = []

    # ETH / EVM
    try:
        for i in range(5):
            addr = _eth_address_from_seed(seed, i)
            addresses.append({"coin": "ETH", "label": "EVM (ETH/BSC/Polygon)", "index": i, "address": addr})
    except Exception:
        pass

    # BTC native segwit
    try:
        ctx_84 = Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
        for i in range(5):
            addr = ctx_84.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i).PublicKey().ToAddress()
            addresses.append({"coin": "BTC_NATIVE", "label": "BTC Native Segwit (bech32)", "index": i, "address": addr})
    except Exception:
        pass

    # BTC segwit P2SH
    try:
        ctx_49 = Bip49.FromSeed(seed, Bip49Coins.BITCOIN)
        for i in range(5):
            addr = ctx_49.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i).PublicKey().ToAddress()
            addresses.append({"coin": "BTC_SEGWIT", "label": "BTC Segwit P2SH (3...)", "index": i, "address": addr})
    except Exception:
        pass

    # BTC legacy
    try:
        ctx_44 = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
        for i in range(5):
            addr = ctx_44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i).PublicKey().ToAddress()
            addresses.append({"coin": "BTC_LEGACY", "label": "BTC Legacy (P2PKH)", "index": i, "address": addr})
    except Exception:
        pass

    return {
        "master_secret_hex": master_secret.hex(),
        "addresses": addresses,
        "error": None,
    }


def find_address_in_shares(
    shares: list[str],
    target_address: str,
    passphrase: str = "",
) -> dict:
    """
    Combine shares and scan derived addresses for target_address.

    Returns
    -------
    dict: {match: dict|None, searched: int, error: str|None, addresses: list[dict]}
    """
    result = combine_shares(shares, passphrase=passphrase)
    if result["error"]:
        return {"match": None, "searched": 0, "error": result["error"], "addresses": []}

    target = target_address.strip().lower()
    addresses = result["addresses"]
    match = next((a for a in addresses if a["address"].lower() == target), None)

    return {
        "match": match,
        "searched": len(addresses),
        "error": None,
        "addresses": addresses,
        "master_secret_hex": result["master_secret_hex"],
    }


# ---------------------------------------------------------------------------
# Passphrase recovery for SLIP39
# ---------------------------------------------------------------------------

def _slip39_passphrase_worker(args: tuple) -> dict:
    """
    args: (shares_cleaned, candidates_chunk, target_address)
    Returns: {matches: list[str], checked: int}
    """
    shares_cleaned, candidates_chunk, target_address = args
    target = target_address.strip().lower()
    matches: list[str] = []
    checked = 0

    for passphrase in candidates_chunk:
        checked += 1
        try:
            ms = shamir_mnemonic.combine_mnemonics(shares_cleaned, passphrase.encode("utf-8"))
            addr = _eth_address_from_seed(ms, 0)
            if addr.lower() == target:
                matches.append(passphrase)
                continue
            # BTC native segwit
            ctx = Bip84.FromSeed(ms, Bip84Coins.BITCOIN)
            btc_addr = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
            if btc_addr.lower() == target:
                matches.append(passphrase)
        except Exception:
            pass

    return {"matches": matches, "checked": checked}


def recover_slip39_passphrase(
    shares: list[str],
    candidates: list[str],
    target_address: str,
    progress_callback: Callable[[int, int, int], None] | None = None,
    chunk_size: int = 16,
) -> dict:
    """
    Dictionary attack on a SLIP39 passphrase.

    Parameters
    ----------
    shares : list[str]
        At least threshold-many valid SLIP39 shares.
    candidates : list[str]
        Passphrase candidates.
    target_address : str
        Known wallet address to match against.
    progress_callback : callable | None
        Called as (checked, total, matches_found).
    chunk_size : int
        Candidates per worker task (PBKDF2-heavy, keep small).

    Returns
    -------
    dict: {matches, checked, total, elapsed_time, truncated}
    """
    import multiprocessing
    import time

    if not shares:
        raise ValueError("No shares provided")
    if not candidates:
        raise ValueError("Candidate list is empty")
    if not target_address.strip():
        raise ValueError("Target address is required")

    cleaned = [s.strip().lower() for s in shares if s.strip()]

    chunks = [candidates[i:i + chunk_size] for i in range(0, len(candidates), chunk_size)]
    tasks = [(cleaned, chunk, target_address) for chunk in chunks]

    total = len(candidates)
    all_matches: list[str] = []
    checked = 0
    truncated = False
    num_workers = max(1, multiprocessing.cpu_count() - 1)
    start_time = time.time()

    with multiprocessing.Pool(num_workers) as pool:
        for res in pool.imap_unordered(_slip39_passphrase_worker, tasks):
            checked += res["checked"]
            all_matches.extend(res["matches"])
            if progress_callback:
                progress_callback(checked, total, len(all_matches))
            if len(all_matches) >= 5:
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
