"""
derivation_utils.py
-------------------
Generalised HD wallet derivation helpers.

Returns ONLY public information (path + address). Private keys are computed
internally as a side-effect of derivation but are never returned, logged,
or stored.
"""

from __future__ import annotations

import re
from typing import Iterable

from bip_utils import (
    Bip32Slip10Secp256k1,
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
    CoinsConf,
    EthAddrEncoder,
    P2PKHAddrEncoder,
    P2SHAddrEncoder,
    P2WPKHAddrEncoder,
    WifEncoder,
)

from wallet_utils import (
    BTC_ADDRESS_TYPES,
    ETH_PATH_TEMPLATE,
    MAX_ADDRESSES_PER_REQUEST,
    validate_mnemonic,
)


# A BIP32 path looks like m/44'/0'/0'/0/0. Each level is either an unsigned
# integer or an unsigned integer with a trailing ' (hardened).
_PATH_LEVEL_RE = re.compile(r"^\d+'?$")


def _validate_path(path: str) -> None:
    """Cheap structural check on a BIP32 path string."""
    if not isinstance(path, str):
        raise TypeError("path must be a string")
    parts = path.strip().split("/")
    if not parts or parts[0] != "m":
        raise ValueError("path must start with 'm/'")
    for level in parts[1:]:
        if not _PATH_LEVEL_RE.match(level):
            raise ValueError(f"Invalid BIP32 level {level!r} in path {path!r}")


def _seed(mnemonic: str) -> bytes:
    """BIP39 seed bytes. Caller MUST discard quickly."""
    info = validate_mnemonic(mnemonic)
    if not info["valid"]:
        raise ValueError("Mnemonic is not valid; cannot derive.")
    return Bip39SeedGenerator(" ".join(mnemonic.lower().split())).Generate()


# ---------------------------------------------------------------------------
# Standard-path scans (BIP44 / BIP49 / BIP84 wrappers).
# These mirror what most production wallets actually use.
# ---------------------------------------------------------------------------

def scan_standard_paths(
    mnemonic: str,
    coin: str,
    account: int = 0,
    change: int = 0,
    start_index: int = 0,
    count: int = 5,
    btc_address_type: str = "native_segwit",
) -> list[dict]:
    """
    Derive a contiguous range of addresses on a standard BIP path.

    coin               : "ETH" or "BTC"
    btc_address_type   : one of "legacy", "segwit", "native_segwit"
    """
    if start_index < 0:
        raise ValueError("start_index must be >= 0")
    if count < 1:
        raise ValueError("count must be >= 1")
    count = min(count, MAX_ADDRESSES_PER_REQUEST)

    seed = _seed(mnemonic)
    try:
        if coin == "ETH":
            ctx = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
            path_tmpl = f"m/44'/60'/{account}'/{change}/{{index}}"
        elif coin == "BTC":
            if btc_address_type == "legacy":
                ctx = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
                path_tmpl = f"m/44'/0'/{account}'/{change}/{{index}}"
            elif btc_address_type == "segwit":
                ctx = Bip49.FromSeed(seed, Bip49Coins.BITCOIN)
                path_tmpl = f"m/49'/0'/{account}'/{change}/{{index}}"
            elif btc_address_type == "native_segwit":
                ctx = Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
                path_tmpl = f"m/84'/0'/{account}'/{change}/{{index}}"
            else:
                raise ValueError(f"Unknown btc_address_type {btc_address_type!r}")
        else:
            raise ValueError(f"Unsupported coin {coin!r}; expected 'ETH' or 'BTC'.")

        acct = ctx.Purpose().Coin().Account(account).Change(
            Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT
        )
        out: list[dict] = []
        for i in range(start_index, start_index + count):
            addr_ctx = acct.AddressIndex(i)
            out.append(
                {
                    "coin": coin,
                    "address_type": (
                        "Ethereum" if coin == "ETH"
                        else BTC_ADDRESS_TYPES[btc_address_type]["label"]
                    ),
                    "path": path_tmpl.format(index=i),
                    "address": addr_ctx.PublicKey().ToAddress(),
                }
            )
        return out
    finally:
        del seed


# ---------------------------------------------------------------------------
# Multi-standard comparison: derive the same window across ALL standards.
# Useful when you don't know which standard a wallet used.
# ---------------------------------------------------------------------------

def compare_all_standards(mnemonic: str, count: int = 3) -> list[dict]:
    """
    Derive the first `count` addresses across every supported standard
    (ETH BIP44, BTC Legacy/SegWit/Native SegWit). Useful for forensic
    "which path produced this address?" investigations.
    """
    results: list[dict] = []
    results.extend(scan_standard_paths(mnemonic, "ETH", count=count))
    for atype in ("legacy", "segwit", "native_segwit"):
        results.extend(
            scan_standard_paths(
                mnemonic, "BTC", count=count, btc_address_type=atype
            )
        )
    return results


# ---------------------------------------------------------------------------
# Arbitrary path derivation: derive a single non-standard path. Useful for
# wallets that used unusual derivation (Electrum, Exodus quirks, etc.).
# Returns just one address per call.
# ---------------------------------------------------------------------------

def derive_arbitrary_path(
    mnemonic: str,
    path: str,
    coin: str = "ETH",
    btc_address_type: str = "native_segwit",
) -> dict:
    """
    Derive a single address at an arbitrary BIP32 path.

    coin             : "ETH" or "BTC"
    btc_address_type : "legacy" / "segwit" / "native_segwit" (BTC only)
    """
    _validate_path(path)
    seed = _seed(mnemonic)
    try:
        node = Bip32Slip10Secp256k1.FromSeed(seed).DerivePath(path)
        pub_obj = node.PublicKey().KeyObject()

        if coin == "ETH":
            address = EthAddrEncoder.EncodeKey(pub_obj)
            label = "Ethereum"
        elif coin == "BTC":
            if btc_address_type == "legacy":
                address = P2PKHAddrEncoder.EncodeKey(
                    pub_obj,
                    net_ver=CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"),
                )
            elif btc_address_type == "segwit":
                address = P2SHAddrEncoder.EncodeKey(
                    pub_obj,
                    net_ver=CoinsConf.BitcoinMainNet.ParamByKey("p2sh_net_ver"),
                )
            elif btc_address_type == "native_segwit":
                address = P2WPKHAddrEncoder.EncodeKey(
                    pub_obj,
                    hrp=CoinsConf.BitcoinMainNet.ParamByKey("p2wpkh_hrp"),
                    wit_ver=CoinsConf.BitcoinMainNet.ParamByKey("p2wpkh_wit_ver"),
                )
            else:
                raise ValueError(
                    f"Unknown btc_address_type {btc_address_type!r}"
                )
            label = BTC_ADDRESS_TYPES[btc_address_type]["label"]
        else:
            raise ValueError(f"Unsupported coin {coin!r}; expected 'ETH' or 'BTC'.")

        return {
            "coin": coin,
            "address_type": label,
            "path": path,
            "address": address,
        }
    finally:
        del seed


# ---------------------------------------------------------------------------
# Known-address matching: derive a window and report which (if any) entries
# match a target address provided by the user.
# ---------------------------------------------------------------------------

def find_address_match(
    mnemonic: str,
    target_address: str,
    max_addresses_per_standard: int = 20,
) -> dict:
    """
    Search for `target_address` across the first N addresses of every
    standard derivation. Returns a dict:
        {
          "match": {"coin", "address_type", "path", "address"} | None,
          "searched": int,                 # how many candidates checked
          "candidates": [ {...}, ... ],    # all addresses we generated
        }

    The address comparison is case-insensitive and trims whitespace.
    """
    if not isinstance(target_address, str) or not target_address.strip():
        raise ValueError("target_address must be a non-empty string")

    target = target_address.strip()
    # Ethereum addresses are case-insensitive in their hex form (case is only
    # a checksum). Bitcoin Bech32 addresses are lowercase; legacy is mixed.
    # Compare in a way that handles both: case-insensitive equality is safe
    # because the address space has no two distinct-by-case addresses.
    candidates: list[dict] = []
    candidates.extend(scan_standard_paths(mnemonic, "ETH", count=max_addresses_per_standard))
    for atype in ("legacy", "segwit", "native_segwit"):
        candidates.extend(
            scan_standard_paths(
                mnemonic, "BTC",
                count=max_addresses_per_standard,
                btc_address_type=atype,
            )
        )

    match = None
    for c in candidates:
        if c["address"].lower() == target.lower():
            match = c
            break

    return {
        "match": match,
        "searched": len(candidates),
        "candidates": candidates,
        "target": target,
    }
