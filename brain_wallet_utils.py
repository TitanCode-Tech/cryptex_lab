"""
brain_wallet_utils.py
---------------------
Brain wallet recovery tools.

A brain wallet converts a memorable passphrase into a Bitcoin or Ethereum
private key using a hash function:

  BTC brain wallet: SHA-256(passphrase) → 32-byte private key → P2PKH address
  ETH brain wallet: keccak-256(passphrase) → 32-byte private key → ETH address

Brain wallets were common before BIP39 and are considered insecure today because
any passphrase that a human can remember is likely in a dictionary.  They remain
a real recovery target when a client used one and lost the passphrase.

SECURITY NOTES
==============
* No network calls. Nothing written to disk.
* Private key bytes are used transiently and never returned to the caller.
* Only the derived address is returned.
"""

from __future__ import annotations

import hashlib
import multiprocessing
import time
from typing import Callable

from bip_utils import (
    P2PKHAddr,
    Secp256k1PrivateKey,
    Bip84,
    Bip84Coins,
    Bip44Changes,
)
from Crypto.Hash import keccak  # pycryptodome

# BTC mainnet net version byte for P2PKH
_BTC_NET_VER = b"\x00"

_MAX_MATCHES = 10


# ---------------------------------------------------------------------------
# Single passphrase → address helpers
# ---------------------------------------------------------------------------

def _sha256(data: str) -> bytes:
    return hashlib.sha256(data.encode("utf-8")).digest()


def _keccak256(data: str) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data.encode("utf-8"))
    return k.digest()


def _priv_to_eth_address(priv_bytes: bytes) -> str:
    """Derive an Ethereum checksummed address from a 32-byte private key."""
    priv_key = Secp256k1PrivateKey.FromBytes(priv_bytes)
    pub_key = priv_key.PublicKey()
    # Raw uncompressed pubkey (64 bytes — strip the 0x04 prefix)
    raw_pub = pub_key.RawUncompressed().ToBytes()[1:]
    k = keccak.new(digest_bits=256)
    k.update(raw_pub)
    addr_bytes = k.digest()[-20:]
    return "0x" + addr_bytes.hex()


def _priv_to_btc_address(priv_bytes: bytes) -> str:
    """Derive a BTC P2PKH (legacy) address from a 32-byte private key."""
    priv_key = Secp256k1PrivateKey.FromBytes(priv_bytes)
    pub_key = priv_key.PublicKey()
    return P2PKHAddr.EncodeKey(pub_key, net_ver=_BTC_NET_VER)


def brain_wallet_btc(passphrase: str) -> dict:
    """
    BTC brain wallet: SHA256(passphrase) → private key → P2PKH address.

    Returns
    -------
    dict: {address, algorithm, passphrase_used}
    """
    priv_bytes = _sha256(passphrase)
    try:
        addr = _priv_to_btc_address(priv_bytes)
    except Exception as e:
        return {"address": None, "algorithm": "SHA256→BTC", "error": str(e)}
    return {"address": addr, "algorithm": "SHA256→BTC", "error": None}


def brain_wallet_eth(passphrase: str) -> dict:
    """
    ETH brain wallet: keccak256(passphrase) → private key → ETH address.
    Also tries SHA256(passphrase) since some tools used that.

    Returns
    -------
    dict: {address_keccak, address_sha256, algorithm}
    """
    results = {}
    for algo_name, key_fn, addr_fn in [
        ("keccak256→ETH", _keccak256, _priv_to_eth_address),
        ("SHA256→ETH", _sha256, _priv_to_eth_address),
    ]:
        try:
            priv_bytes = key_fn(passphrase)
            addr = addr_fn(priv_bytes)
            results[algo_name] = addr
        except Exception:
            results[algo_name] = None
    return results


def brain_wallet_all(passphrase: str) -> list[dict]:
    """
    Derive all standard brain wallet address types from one passphrase.

    Returns
    -------
    list of dicts: {algorithm, address}
    """
    out = []
    btc = brain_wallet_btc(passphrase)
    if btc["address"]:
        out.append({"algorithm": "SHA256 → BTC (P2PKH)", "address": btc["address"]})

    for algo_name, addr in brain_wallet_eth(passphrase).items():
        if addr:
            out.append({"algorithm": algo_name, "address": addr})
    return out


# ---------------------------------------------------------------------------
# Multiprocessing worker
# ---------------------------------------------------------------------------

def _brain_worker(args: tuple) -> dict:
    """
    args: (candidates_chunk, target_address, coin_hint)
    coin_hint: 'btc', 'eth', or 'all'
    Returns: {matches: list[dict], checked: int}
    """
    candidates_chunk, target_address, coin_hint = args
    target = target_address.strip().lower()
    matches: list[dict] = []
    checked = 0

    for passphrase in candidates_chunk:
        checked += 1
        try:
            if coin_hint == "btc":
                addr = _priv_to_btc_address(_sha256(passphrase))
                if addr.lower() == target:
                    matches.append({"passphrase": passphrase, "address": addr, "algorithm": "SHA256→BTC"})
            elif coin_hint == "eth":
                for key_fn, algo in ((_keccak256, "keccak256→ETH"), (_sha256, "SHA256→ETH")):
                    addr = _priv_to_eth_address(key_fn(passphrase))
                    if addr.lower() == target:
                        matches.append({"passphrase": passphrase, "address": addr, "algorithm": algo})
                        break
            else:  # all
                # BTC
                btc_addr = _priv_to_btc_address(_sha256(passphrase))
                if btc_addr.lower() == target:
                    matches.append({"passphrase": passphrase, "address": btc_addr, "algorithm": "SHA256→BTC"})
                    continue
                # ETH keccak
                eth_addr = _priv_to_eth_address(_keccak256(passphrase))
                if eth_addr.lower() == target:
                    matches.append({"passphrase": passphrase, "address": eth_addr, "algorithm": "keccak256→ETH"})
                    continue
                # ETH sha256
                eth_addr2 = _priv_to_eth_address(_sha256(passphrase))
                if eth_addr2.lower() == target:
                    matches.append({"passphrase": passphrase, "address": eth_addr2, "algorithm": "SHA256→ETH"})
        except Exception:
            pass

    return {"matches": matches, "checked": checked}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def attack_brain_wallet(
    candidates: list[str],
    target_address: str,
    coin_hint: str = "all",
    progress_callback: Callable[[int, int, int], None] | None = None,
    chunk_size: int = 256,
) -> dict:
    """
    Dictionary attack against a brain wallet address.

    Parameters
    ----------
    candidates : list[str]
        Passphrase candidates to test.
    target_address : str
        Known wallet address to match against.
    coin_hint : str
        'btc', 'eth', or 'all' — restricts which derivations are attempted.
        Auto-detected from address prefix if 'all'.
    progress_callback : callable | None
        Called as (checked, total, matches_found).
    chunk_size : int
        Candidates per worker task. Brain wallet hashing is very fast (SHA256/keccak),
        so larger chunks are efficient.

    Returns
    -------
    dict: {matches, checked, total, elapsed_time, truncated}
    """
    if not candidates:
        raise ValueError("Candidate list is empty")
    target = target_address.strip()
    if not target:
        raise ValueError("Target address is required")

    # Auto-detect coin hint from address prefix
    if coin_hint == "all":
        if target.startswith("0x") and len(target) == 42:
            coin_hint = "eth"
        elif target.startswith(("1", "3", "bc1")):
            coin_hint = "btc"

    chunks = [candidates[i:i + chunk_size] for i in range(0, len(candidates), chunk_size)]
    tasks = [(chunk, target, coin_hint) for chunk in chunks]

    total = len(candidates)
    all_matches: list[dict] = []
    checked = 0
    truncated = False
    num_workers = max(1, multiprocessing.cpu_count() - 1)
    start_time = time.time()

    with multiprocessing.Pool(num_workers) as pool:
        for res in pool.imap_unordered(_brain_worker, tasks):
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
