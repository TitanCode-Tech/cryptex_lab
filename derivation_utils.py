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

# ---------------------------------------------------------------------------
# Multi-coin registry
# ---------------------------------------------------------------------------
# Each entry maps a stable coin_id → derivation config.
# "bip_class" is one of "bip44" / "bip49" / "bip84".
# "evm_note" (optional) means the address is identical on listed EVM chains.

COIN_REGISTRY: dict[str, dict] = {
    # ── Ethereum & EVM-compatible chains ───────────────────────────────────
    "ETH": {
        "label": "Ethereum",
        "symbol": "ETH",
        "coin_type": 60,
        "bip_class": "bip44",
        "coin_enum": Bip44Coins.ETHEREUM,
        "evm_note": "Same address valid on BSC, Polygon, Avalanche-C, Arbitrum, Optimism",
    },
    # ── Bitcoin address variants ───────────────────────────────────────────
    "BTC_NATIVE": {
        "label": "Bitcoin (Native SegWit / bc1)",
        "symbol": "BTC",
        "coin_type": 0,
        "bip_class": "bip84",
        "coin_enum": Bip84Coins.BITCOIN,
    },
    "BTC_SEGWIT": {
        "label": "Bitcoin (SegWit / 3…)",
        "symbol": "BTC",
        "coin_type": 0,
        "bip_class": "bip49",
        "coin_enum": Bip49Coins.BITCOIN,
    },
    "BTC_LEGACY": {
        "label": "Bitcoin (Legacy / 1…)",
        "symbol": "BTC",
        "coin_type": 0,
        "bip_class": "bip44",
        "coin_enum": Bip44Coins.BITCOIN,
    },
    # ── Litecoin ───────────────────────────────────────────────────────────
    "LTC_NATIVE": {
        "label": "Litecoin (Native SegWit / ltc1)",
        "symbol": "LTC",
        "coin_type": 2,
        "bip_class": "bip84",
        "coin_enum": Bip84Coins.LITECOIN,
    },
    "LTC_SEGWIT": {
        "label": "Litecoin (SegWit / M…)",
        "symbol": "LTC",
        "coin_type": 2,
        "bip_class": "bip49",
        "coin_enum": Bip49Coins.LITECOIN,
    },
    "LTC_LEGACY": {
        "label": "Litecoin (Legacy / L…)",
        "symbol": "LTC",
        "coin_type": 2,
        "bip_class": "bip44",
        "coin_enum": Bip44Coins.LITECOIN,
    },
    # ── Other UTXO coins ───────────────────────────────────────────────────
    "DOGE": {
        "label": "Dogecoin",
        "symbol": "DOGE",
        "coin_type": 3,
        "bip_class": "bip44",
        "coin_enum": Bip44Coins.DOGECOIN,
    },
    # ── Account-model chains ───────────────────────────────────────────────
    "XRP": {
        "label": "XRP (Ripple)",
        "symbol": "XRP",
        "coin_type": 144,
        "bip_class": "bip44",
        "coin_enum": Bip44Coins.RIPPLE,
    },
    "TRX": {
        "label": "Tron",
        "symbol": "TRX",
        "coin_type": 195,
        "bip_class": "bip44",
        "coin_enum": Bip44Coins.TRON,
    },
    "SOL": {
        "label": "Solana",
        "symbol": "SOL",
        "coin_type": 501,
        "bip_class": "bip44",
        "coin_enum": Bip44Coins.SOLANA,
    },
    "ATOM": {
        "label": "Cosmos (ATOM)",
        "symbol": "ATOM",
        "coin_type": 118,
        "bip_class": "bip44",
        "coin_enum": Bip44Coins.COSMOS,
    },
    "BNB": {
        "label": "BNB Beacon Chain",
        "symbol": "BNB",
        "coin_type": 714,
        "bip_class": "bip44",
        "coin_enum": Bip44Coins.BINANCE_CHAIN,
    },
}

# Logical coin groups for the UI multi-select.
COIN_GROUPS: dict[str, list[str]] = {
    "EVM Chains (ETH / BSC / Polygon / Avalanche-C / Arbitrum / Optimism)": ["ETH"],
    "Bitcoin": ["BTC_NATIVE", "BTC_SEGWIT", "BTC_LEGACY"],
    "Litecoin": ["LTC_NATIVE", "LTC_SEGWIT", "LTC_LEGACY"],
    "Dogecoin": ["DOGE"],
    "XRP / Ripple": ["XRP"],
    "Tron (TRX)": ["TRX"],
    "Solana (SOL)": ["SOL"],
    "Cosmos (ATOM)": ["ATOM"],
    "BNB Beacon Chain": ["BNB"],
}

# Default coin set for "scan everything" operations.
DEFAULT_SCAN_COINS: list[str] = [
    "ETH", "BTC_NATIVE", "BTC_SEGWIT", "BTC_LEGACY",
    "LTC_NATIVE", "LTC_LEGACY", "DOGE", "XRP", "TRX", "SOL", "ATOM",
]

# ---------------------------------------------------------------------------
# Hardware wallet path presets
# ---------------------------------------------------------------------------
# Each preset maps to a list of scan specs:
#   {"coin_id": str, "accounts": list[int], "count": int}
# where "accounts" is which BIP44 account indices to scan.

HARDWARE_WALLET_PRESETS: dict[str, dict] = {
    "Ledger Live — ETH / EVM": {
        "description": (
            "Ledger Live (post-2019) uses per-account paths. "
            "Accounts 0-3 are scanned at index 0 of each."
        ),
        "note": "Also covers BSC, Polygon, Avalanche-C, Arbitrum, Optimism (same address).",
        "specs": [{"coin_id": "ETH", "accounts": [0, 1, 2, 3], "count": 3}],
    },
    "Ledger Legacy — ETH": {
        "description": (
            "Old Ledger Ethereum app (pre-2019). "
            "Uses m/44'/60'/0'/index — index-based, not account-based."
        ),
        "note": "Try this if Ledger Live preset doesn't find your address.",
        "specs": [{"coin_id": "ETH", "accounts": [0], "count": 20}],
        "path_style": "legacy_eth",
    },
    "Ledger Live — BTC (All Types)": {
        "description": "Ledger Live Bitcoin: native segwit, segwit, and legacy. Accounts 0-3.",
        "specs": [
            {"coin_id": "BTC_NATIVE", "accounts": [0, 1, 2, 3], "count": 3},
            {"coin_id": "BTC_SEGWIT", "accounts": [0, 1, 2, 3], "count": 3},
            {"coin_id": "BTC_LEGACY", "accounts": [0, 1, 2, 3], "count": 3},
        ],
    },
    "Trezor Suite — ETH": {
        "description": "Trezor standard Ethereum — m/44'/60'/0'/0/index.",
        "specs": [{"coin_id": "ETH", "accounts": [0], "count": 10}],
    },
    "Trezor Suite — BTC (All Types)": {
        "description": "Trezor BTC: native segwit, segwit, legacy. Account 0.",
        "specs": [
            {"coin_id": "BTC_NATIVE", "accounts": [0], "count": 5},
            {"coin_id": "BTC_SEGWIT", "accounts": [0], "count": 5},
            {"coin_id": "BTC_LEGACY", "accounts": [0], "count": 5},
        ],
    },
    "MetaMask / Coinbase Wallet / Trust Wallet (EVM)": {
        "description": "Standard EVM path: m/44'/60'/0'/0/index. Addresses 0-9.",
        "note": "Address is identical on ETH, BSC, Polygon, Avalanche-C, Arbitrum, Optimism.",
        "specs": [{"coin_id": "ETH", "accounts": [0], "count": 10}],
    },
    "Trust Wallet — Full Multi-chain": {
        "description": "Trust Wallet derives all major coins from the same seed.",
        "specs": [
            {"coin_id": "ETH",       "accounts": [0], "count": 5},
            {"coin_id": "BTC_NATIVE","accounts": [0], "count": 5},
            {"coin_id": "BTC_LEGACY","accounts": [0], "count": 5},
            {"coin_id": "LTC_NATIVE","accounts": [0], "count": 5},
            {"coin_id": "DOGE",      "accounts": [0], "count": 5},
            {"coin_id": "XRP",       "accounts": [0], "count": 5},
            {"coin_id": "TRX",       "accounts": [0], "count": 5},
            {"coin_id": "SOL",       "accounts": [0], "count": 5},
            {"coin_id": "ATOM",      "accounts": [0], "count": 5},
        ],
    },
    "Coldcard / Jade / BitBox02 (BTC only)": {
        "description": "Bitcoin-only hardware wallets. Native segwit primary, segwit secondary.",
        "specs": [
            {"coin_id": "BTC_NATIVE", "accounts": [0], "count": 10},
            {"coin_id": "BTC_SEGWIT", "accounts": [0], "count": 5},
        ],
    },
    "KeepKey": {
        "description": "KeepKey standard paths — equivalent to Trezor.",
        "specs": [
            {"coin_id": "ETH",       "accounts": [0], "count": 5},
            {"coin_id": "BTC_NATIVE","accounts": [0], "count": 5},
            {"coin_id": "BTC_SEGWIT","accounts": [0], "count": 5},
            {"coin_id": "BTC_LEGACY","accounts": [0], "count": 5},
        ],
    },
}

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


# ---------------------------------------------------------------------------
# Multi-coin derivation (uses COIN_REGISTRY)
# ---------------------------------------------------------------------------

def derive_coin_addresses(
    mnemonic: str,
    coin_id: str,
    account: int = 0,
    change: int = 0,
    start_index: int = 0,
    count: int = 5,
) -> list[dict]:
    """
    Derive addresses for any coin in COIN_REGISTRY.

    Parameters
    ----------
    mnemonic  : BIP39 mnemonic string.
    coin_id   : Key from COIN_REGISTRY (e.g. "ETH", "BTC_NATIVE", "LTC_LEGACY").
    account   : BIP44 account level (default 0).
    change    : 0 = external (receiving), 1 = internal (change).
    start_index, count : address window.

    Returns
    -------
    list of dicts with keys: coin, coin_id, label, path, address, account, index.
    """
    if coin_id not in COIN_REGISTRY:
        raise ValueError(
            f"Unknown coin_id {coin_id!r}. Available: {list(COIN_REGISTRY.keys())}"
        )
    count = min(count, MAX_ADDRESSES_PER_REQUEST)
    cfg = COIN_REGISTRY[coin_id]
    seed = _seed(mnemonic)
    try:
        bip_cls_name = cfg["bip_class"]
        coin_enum = cfg["coin_enum"]
        coin_type = cfg["coin_type"]
        bip_num = {"bip44": 44, "bip49": 49, "bip84": 84}[bip_cls_name]

        if bip_cls_name == "bip44":
            ctx = Bip44.FromSeed(seed, coin_enum)
        elif bip_cls_name == "bip49":
            ctx = Bip49.FromSeed(seed, coin_enum)
        elif bip_cls_name == "bip84":
            ctx = Bip84.FromSeed(seed, coin_enum)
        else:
            raise ValueError(f"Unknown bip_class {bip_cls_name!r}")

        acct_ctx = ctx.Purpose().Coin().Account(account).Change(
            Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT
        )

        out: list[dict] = []
        for i in range(start_index, start_index + count):
            address = acct_ctx.AddressIndex(i).PublicKey().ToAddress()
            path = f"m/{bip_num}'/{coin_type}'/{account}'/{change}/{i}"
            out.append({
                "coin": cfg["symbol"],
                "coin_id": coin_id,
                "label": cfg["label"],
                "path": path,
                "address": address,
                "account": account,
                "index": i,
                "evm_note": cfg.get("evm_note", ""),
            })
        return out
    finally:
        del seed


def find_address_match_extended(
    mnemonic: str,
    target_address: str,
    coin_ids: list[str] | None = None,
    count_per_coin: int = 10,
    scan_accounts: int = 1,
) -> dict:
    """
    Search for target_address across multiple coins and accounts.

    Parameters
    ----------
    coin_ids      : Subset of COIN_REGISTRY keys. None = DEFAULT_SCAN_COINS.
    count_per_coin: Addresses to derive per coin per account.
    scan_accounts : Number of account indices to check (0 … scan_accounts-1).

    Returns
    -------
    dict with: match (dict | None), searched (int), candidates (list), target (str).
    """
    if not isinstance(target_address, str) or not target_address.strip():
        raise ValueError("target_address must be a non-empty string")

    if coin_ids is None:
        coin_ids = DEFAULT_SCAN_COINS

    target = target_address.strip()
    all_candidates: list[dict] = []
    match: dict | None = None

    for coin_id in coin_ids:
        if coin_id not in COIN_REGISTRY:
            continue
        for account in range(scan_accounts):
            try:
                addresses = derive_coin_addresses(
                    mnemonic, coin_id,
                    account=account,
                    count=count_per_coin,
                )
                all_candidates.extend(addresses)
                for a in addresses:
                    if a["address"].lower() == target.lower():
                        match = a
                        break
            except Exception:
                pass
            if match:
                break
        if match:
            break

    return {
        "match": match,
        "searched": len(all_candidates),
        "candidates": all_candidates,
        "target": target,
    }


def run_hardware_preset(
    mnemonic: str,
    preset_name: str,
    target_address: str | None = None,
) -> dict:
    """
    Run derivation for a named HARDWARE_WALLET_PRESETS entry.

    Returns dict with: candidates (list), match (dict|None), preset (str).
    """
    if preset_name not in HARDWARE_WALLET_PRESETS:
        raise ValueError(f"Unknown preset {preset_name!r}")

    preset = HARDWARE_WALLET_PRESETS[preset_name]
    all_candidates: list[dict] = []
    match: dict | None = None
    target = (target_address or "").strip()

    for spec in preset["specs"]:
        coin_id = spec["coin_id"]
        accounts = spec.get("accounts", [0])
        count = spec.get("count", 5)
        for account in accounts:
            try:
                rows = derive_coin_addresses(mnemonic, coin_id, account=account, count=count)
                all_candidates.extend(rows)
                if target:
                    for r in rows:
                        if r["address"].lower() == target.lower():
                            match = r
                            break
            except Exception:
                pass
            if match:
                break
        if match:
            break

    return {
        "candidates": all_candidates,
        "match": match,
        "preset": preset_name,
        "description": preset.get("description", ""),
        "note": preset.get("note", ""),
    }
