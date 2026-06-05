"""
xpub_utils.py
-------------
Extended public / private key (xpub / xprv) tools.

Supports the four common serialization formats:
  xpub / xprv  — BIP44 (P2PKH)
  ypub / yprv  — BIP49 (P2SH-P2WPKH)
  zpub / zprv  — BIP84 (P2WPKH native segwit)

Given an xpub: derive watch-only receiving/change addresses — no private key
needed. Useful when a client has a watch-only wallet export but lost the seed.

Given an xprv: derive addresses AND WIF private keys for each index.

SECURITY NOTES
==============
* No network calls. Nothing written to disk.
* If an xprv is provided, WIF keys are returned only when explicitly requested
  and the caller is responsible for not persisting them.
"""

from __future__ import annotations

from bip_utils import (
    Bip44,
    Bip44Coins,
    Bip44Changes,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
    P2PKHAddr,
    P2WPKHAddr,
    WifEncoder,
    WifPubKeyModes,
)

# ---------------------------------------------------------------------------
# Extended key prefix detection
# ---------------------------------------------------------------------------

_PREFIX_MAP: dict[str, dict] = {
    "xpub": {"bip_cls": Bip44, "coin": Bip44Coins.BITCOIN,  "type": "BIP44 P2PKH",        "public": True},
    "xprv": {"bip_cls": Bip44, "coin": Bip44Coins.BITCOIN,  "type": "BIP44 P2PKH",        "public": False},
    "ypub": {"bip_cls": Bip49, "coin": Bip49Coins.BITCOIN,  "type": "BIP49 P2SH-P2WPKH",  "public": True},
    "yprv": {"bip_cls": Bip49, "coin": Bip49Coins.BITCOIN,  "type": "BIP49 P2SH-P2WPKH",  "public": False},
    "zpub": {"bip_cls": Bip84, "coin": Bip84Coins.BITCOIN,  "type": "BIP84 P2WPKH",       "public": True},
    "zprv": {"bip_cls": Bip84, "coin": Bip84Coins.BITCOIN,  "type": "BIP84 P2WPKH",       "public": False},
    # ETH uses generic xpub/xprv but coin type 60 — handled separately
}

# ETH xpub prefixes are the same as BTC xpub ('xpub') but coin type differs.
# We detect ETH vs BTC by user selection in the UI.

_ETH_PREFIX_MAP: dict[str, dict] = {
    "xpub": {"bip_cls": Bip44, "coin": Bip44Coins.ETHEREUM, "type": "BIP44 ETH",  "public": True},
    "xprv": {"bip_cls": Bip44, "coin": Bip44Coins.ETHEREUM, "type": "BIP44 ETH",  "public": False},
}


def detect_extended_key_type(ext_key: str) -> dict:
    """
    Detect the type of an extended key from its prefix.

    Returns
    -------
    dict: {prefix, type, is_public, is_private, coin_hint}
    """
    k = ext_key.strip()
    prefix = k[:4].lower()
    if prefix in _PREFIX_MAP:
        info = _PREFIX_MAP[prefix]
        return {
            "prefix": prefix,
            "type": info["type"],
            "is_public": info["public"],
            "is_private": not info["public"],
            "coin_hint": "ETH/BTC" if prefix in ("xpub", "xprv") else "BTC",
            "valid_prefix": True,
        }
    return {
        "prefix": prefix,
        "type": "Unknown",
        "is_public": False,
        "is_private": False,
        "coin_hint": "Unknown",
        "valid_prefix": False,
    }


# ---------------------------------------------------------------------------
# Derivation from extended key
# ---------------------------------------------------------------------------

def derive_from_extended_key(
    ext_key: str,
    coin: str = "BTC",
    count: int = 10,
    change: int = 0,
    start_index: int = 0,
    include_wif: bool = False,
) -> list[dict]:
    """
    Derive addresses from an extended public or private key.

    Parameters
    ----------
    ext_key : str
        Extended key (xpub, xprv, ypub, yprv, zpub, zprv).
    coin : str
        'BTC' or 'ETH' — needed to disambiguate xpub/xprv (same prefix, different coin).
    count : int
        Number of addresses to derive.
    change : int
        0 = receiving (external chain), 1 = change (internal chain).
    start_index : int
        First address index.
    include_wif : bool
        If True and ext_key is an xprv, include WIF private keys in results.
        Ignored for public-only keys.

    Returns
    -------
    list of dicts: {index, path_desc, address, wif (if applicable), type, coin}
    """
    ext_key = ext_key.strip()
    prefix = ext_key[:4].lower()

    if prefix not in _PREFIX_MAP:
        raise ValueError(f"Unrecognised extended key prefix '{prefix}'. "
                         "Expected: xpub, xprv, ypub, yprv, zpub, zprv.")

    info = _ETH_PREFIX_MAP.get(prefix) if coin == "ETH" else _PREFIX_MAP[prefix]
    bip_cls = info["bip_cls"]
    bip_coin = info["coin"]
    addr_type = info["type"]
    is_public = info["public"]

    try:
        ctx = bip_cls.FromExtendedKey(ext_key, bip_coin)
    except Exception as e:
        raise ValueError(f"Failed to parse extended key: {e}") from e

    if not is_public and include_wif and ctx.IsPublicOnly():
        include_wif = False

    results = []
    change_ctx = ctx.Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT)

    for i in range(start_index, start_index + count):
        addr_ctx = change_ctx.AddressIndex(i)
        address = addr_ctx.PublicKey().ToAddress()
        entry: dict = {
            "index": i,
            "change": change,
            "path_desc": f"change={change}, index={i}",
            "address": address,
            "type": addr_type,
            "coin": coin,
        }
        if include_wif and not ctx.IsPublicOnly():
            try:
                priv_bytes = addr_ctx.PrivateKey().Raw().ToBytes()
                wif = WifEncoder.Encode(priv_bytes, pub_key_mode=WifPubKeyModes.COMPRESSED)
                entry["wif"] = wif
            except Exception:
                entry["wif"] = None
        results.append(entry)

    return results


def find_address_in_extended_key(
    ext_key: str,
    target_address: str,
    coin: str = "BTC",
    count: int = 50,
) -> dict:
    """
    Scan receiving + change addresses derived from an extended key for target_address.

    Returns
    -------
    dict: {match: dict|None, searched: int, candidates: list[dict]}
    """
    target = target_address.strip().lower()
    all_candidates: list[dict] = []

    for change in (0, 1):
        candidates = derive_from_extended_key(ext_key, coin=coin, count=count, change=change)
        all_candidates.extend(candidates)

    match = next((c for c in all_candidates if c["address"].lower() == target), None)
    return {
        "match": match,
        "searched": len(all_candidates),
        "candidates": all_candidates,
    }


def extended_key_info(ext_key: str, coin: str = "BTC") -> dict:
    """
    Return metadata about an extended key without deriving child addresses.

    Returns
    -------
    dict: {prefix, type, coin_hint, is_public, depth, fingerprint, child_number}
    """
    ext_key = ext_key.strip()
    prefix = ext_key[:4].lower()
    if prefix not in _PREFIX_MAP:
        raise ValueError(f"Unrecognised extended key prefix '{prefix}'.")

    info = _ETH_PREFIX_MAP.get(prefix) if coin == "ETH" else _PREFIX_MAP[prefix]
    bip_cls = info["bip_cls"]
    bip_coin = info["coin"]

    try:
        ctx = bip_cls.FromExtendedKey(ext_key, bip_coin)
    except Exception as e:
        raise ValueError(f"Failed to parse extended key: {e}") from e

    bip32_key = ctx.PublicKey().Bip32Key() if ctx.IsPublicOnly() else ctx.PrivateKey().Bip32Key()
    key_data = bip32_key.Data()

    return {
        "prefix": prefix,
        "type": info["type"],
        "coin_hint": coin,
        "is_public": info["public"],
        "depth": key_data.Depth().ToInt(),
        "fingerprint": key_data.ParentFingerPrint().ToHex(),
        "child_number": key_data.Index().ToInt(),
    }
