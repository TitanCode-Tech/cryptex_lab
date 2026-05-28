"""
wallet_utils.py
---------------
Pure helper functions for CRYPTEX LAB.

SECURITY DESIGN NOTES
=====================
* This module performs ALL operations locally and synchronously. It makes no
  network calls and imports nothing from `requests`, `urllib`, `socket`,
  `http`, `web3`, etc.
* Sensitive values (mnemonic, seed bytes, entropy, private keys) are NEVER
  returned to the caller, logged, stored on disk, or written into any
  data structure that leaves this module.
* The derivation helpers compute private keys internally (this is unavoidable
  because public keys are derived from them) but only the resulting public
  addresses are returned.
* The mnemonic argument is treated as opaque and is not echoed in errors.
"""

from __future__ import annotations

from bip_utils import (
    Bip39Languages,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip39WordsNum,
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# BIP39 allows these word counts. Anything else is invalid by spec.
VALID_WORD_COUNTS = {wn.value for wn in Bip39WordsNum}

# Bitcoin address types supported by this MVP, mapped to a human label
# and the bip-utils derivation class + coin enum used to compute them.
BTC_ADDRESS_TYPES = {
    "legacy": {
        "label": "Legacy (P2PKH)",
        "path_template": "m/44'/0'/0'/0/{index}",
    },
    "segwit": {
        "label": "SegWit (P2SH-P2WPKH)",
        "path_template": "m/49'/0'/0'/0/{index}",
    },
    "native_segwit": {
        "label": "Native SegWit (Bech32, P2WPKH)",
        "path_template": "m/84'/0'/0'/0/{index}",
    },
}

ETH_PATH_TEMPLATE = "m/44'/60'/0'/0/{index}"

# Hard upper bound on how many addresses we ever derive in one request.
# Prevents accidental long-running loops in the UI.
MAX_ADDRESSES_PER_REQUEST = 50


# ---------------------------------------------------------------------------
# BIP39 mnemonic validation
# ---------------------------------------------------------------------------

# Cache for the English wordlist (loaded once from bip-utils, no network).
_WORDLIST_CACHE: set[str] | None = None


def _english_wordlist() -> set[str]:
    """Return the 2048-word English BIP39 wordlist (cached, offline)."""
    global _WORDLIST_CACHE
    if _WORDLIST_CACHE is None:
        from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter

        wl = Bip39WordsListGetter.Instance().GetByLanguage(Bip39Languages.ENGLISH)
        _WORDLIST_CACHE = {wl.GetWordAtIdx(i) for i in range(wl.Length())}
    return _WORDLIST_CACHE


def _normalize_mnemonic(mnemonic: str) -> str:
    """Collapse whitespace and lowercase. Does not return original."""
    return " ".join(mnemonic.lower().split())


def validate_mnemonic(mnemonic: str) -> dict:
    """
    Validate a BIP39 mnemonic phrase.

    Returns a dict describing which checks passed. The mnemonic itself is
    NEVER included in the result.

    Result keys:
        word_count        : int
        word_count_valid  : bool   (12/15/18/21/24)
        words_in_wordlist : bool   (every word is in the English BIP39 list)
        checksum_valid    : bool   (full BIP39 checksum verification)
        valid             : bool   (all of the above)
    """
    if not isinstance(mnemonic, str):
        # Defensive: never raise with mnemonic content in the message.
        return {
            "word_count": 0,
            "word_count_valid": False,
            "words_in_wordlist": False,
            "checksum_valid": False,
            "valid": False,
        }

    normalized = _normalize_mnemonic(mnemonic)
    words = normalized.split()
    word_count = len(words)
    word_count_valid = word_count in VALID_WORD_COUNTS

    # Check each word against the official English BIP39 wordlist that ships
    # with bip-utils (no network access needed).
    wordlist = _english_wordlist()
    words_in_wordlist = bool(words) and all(w in wordlist for w in words)

    # Full checksum verification only makes sense when the structural checks
    # pass. Bip39MnemonicValidator.IsValid handles word-count + checksum.
    checksum_valid = False
    if word_count_valid and words_in_wordlist:
        try:
            checksum_valid = Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(normalized)
        except Exception:
            checksum_valid = False

    # Discard the local references to mnemonic data as soon as we are done.
    del normalized, words

    return {
        "word_count": word_count,
        "word_count_valid": word_count_valid,
        "words_in_wordlist": words_in_wordlist,
        "checksum_valid": checksum_valid,
        "valid": word_count_valid and words_in_wordlist and checksum_valid,
    }


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------

def _clamp_count(count: int) -> int:
    """Constrain the requested address count to a safe range."""
    if not isinstance(count, int):
        raise TypeError("count must be an integer")
    if count < 1:
        raise ValueError("count must be >= 1")
    return min(count, MAX_ADDRESSES_PER_REQUEST)


def _seed_from_mnemonic(mnemonic: str) -> bytes:
    """
    Generate the BIP39 seed bytes from a mnemonic.

    SECURITY: the returned bytes must be used only within this module and
    discarded as soon as derivation is complete. They are never returned
    to callers.
    """
    return Bip39SeedGenerator(_normalize_mnemonic(mnemonic)).Generate()


def derive_eth_addresses(mnemonic: str, count: int = 5) -> list[dict]:
    """
    Derive `count` Ethereum public addresses from `mnemonic`.

    Uses the BIP44 standard path m/44'/60'/0'/0/{index} (account 0,
    external chain). Returns a list of dicts with only public information:
        {"path": str, "address": str}
    """
    count = _clamp_count(count)
    info = validate_mnemonic(mnemonic)
    if not info["valid"]:
        raise ValueError("Mnemonic is not valid; cannot derive addresses.")

    seed_bytes = _seed_from_mnemonic(mnemonic)
    try:
        ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
        account = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
        results: list[dict] = []
        for i in range(count):
            addr_ctx = account.AddressIndex(i)
            results.append(
                {
                    "coin": "ETH",
                    "address_type": "Ethereum",
                    "path": ETH_PATH_TEMPLATE.format(index=i),
                    "address": addr_ctx.PublicKey().ToAddress(),
                }
            )
        return results
    finally:
        # Best-effort cleanup of seed bytes. Python doesn't guarantee secure
        # wiping, but we drop our reference so the GC can reclaim it.
        del seed_bytes


def derive_btc_addresses(
    mnemonic: str,
    address_type: str = "native_segwit",
    count: int = 5,
) -> list[dict]:
    """
    Derive `count` Bitcoin public addresses for the given address type.

    `address_type` must be one of: "legacy", "segwit", "native_segwit".
    Returns a list of dicts with only public information:
        {"coin": "BTC", "address_type": <label>, "path": str, "address": str}
    """
    if address_type not in BTC_ADDRESS_TYPES:
        raise ValueError(
            f"Unknown BTC address_type: {address_type!r}. "
            f"Expected one of {sorted(BTC_ADDRESS_TYPES)}."
        )
    count = _clamp_count(count)
    info = validate_mnemonic(mnemonic)
    if not info["valid"]:
        raise ValueError("Mnemonic is not valid; cannot derive addresses.")

    meta = BTC_ADDRESS_TYPES[address_type]
    seed_bytes = _seed_from_mnemonic(mnemonic)
    try:
        if address_type == "legacy":
            ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        elif address_type == "segwit":
            ctx = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN)
        else:  # native_segwit
            ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)

        account = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
        results: list[dict] = []
        for i in range(count):
            addr_ctx = account.AddressIndex(i)
            results.append(
                {
                    "coin": "BTC",
                    "address_type": meta["label"],
                    "path": meta["path_template"].format(index=i),
                    "address": addr_ctx.PublicKey().ToAddress(),
                }
            )
        return results
    finally:
        del seed_bytes


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
# Report generation moved to export_utils. Re-export for backward compatibility.
from export_utils import build_report  # noqa: E402, F401
