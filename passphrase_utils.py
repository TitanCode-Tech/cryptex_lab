"""
passphrase_utils.py
-------------------
Passphrase dictionary / mutation-rule attack for BIP39 wallets.

A target wallet address is REQUIRED — without it there is no way to confirm
which passphrase candidate is correct.

SECURITY NOTES
==============
* No network calls. Nothing is written to disk.
* The mnemonic and every passphrase candidate are used only as local
  variables inside worker processes and are discarded after use.
* Only matched passphrase strings are returned to the caller; the mnemonic
  itself is never included in the result dict.
* Caller is responsible for not persisting the returned passphrase.
"""

from __future__ import annotations

import multiprocessing
import time
from typing import Callable

from bip_utils import (
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
)

from wallet_utils import _normalize_mnemonic, validate_mnemonic


# ---------------------------------------------------------------------------
# Mutation rule definitions
# ---------------------------------------------------------------------------

# Years that appear most often in forgotten passphrases (wallet creation era).
_YEAR_SUFFIXES: list[str] = [str(y) for y in range(2009, 2026)]

_NUMBER_SUFFIXES: list[str] = ["1", "12", "123", "1234", "0", "00", "01", "2", "21", "99"]

_SYMBOL_SUFFIXES: list[str] = ["!", "@", "#", "$", "_", "-", ".", "?", "*", "&"]

# Leet-speak substitution table (single-pass, left-to-right, no chaining).
_LEET_TABLE = str.maketrans({
    "a": "@", "e": "3", "i": "1", "o": "0",
    "s": "$", "t": "7", "l": "1", "g": "9",
})

# Public names that map to UI checkbox labels.
MUTATION_RULES: dict[str, str] = {
    "capitalize":      "Capitalize first letter  (password → Password)",
    "uppercase":       "UPPERCASE  (password → PASSWORD)",
    "lowercase":       "lowercase  (Password → password)",
    "append_numbers":  "Append numbers  (+1 / +12 / +123 / +1234 / +0)",
    "append_years":    "Append years  (+2020 … +2025)",
    "append_symbols":  "Append symbols  (+! / +@ / +# / +$)",
    "leet":            "Leet-speak  (a→@ e→3 i→1 o→0 s→$ t→7)",
    "reverse":         "Reverse the word  (abc → cba)",
    "double":          "Double  (abc → abcabc / abc abc)",
}

_MAX_RETURNED_PASSPHRASES = 10

# Candidate count safety cap — above this we warn but still allow the user
# to proceed (the run-time estimate will show how long it takes).
CANDIDATE_WARN_THRESHOLD = 2_000_000


# ---------------------------------------------------------------------------
# Mutation engine
# ---------------------------------------------------------------------------

def _mutate(base: str, rules: set[str]) -> list[str]:
    """
    Return a deduplicated list of passphrase variants for one base string.
    The base string is always the first entry (included even if no rules).
    """
    seen: dict[str, None] = {base: None}

    def add(v: str) -> None:
        if v:
            seen.setdefault(v, None)

    cap = base.capitalize()
    upper = base.upper()
    lower = base.lower()

    if "capitalize" in rules:
        add(cap)
    if "uppercase" in rules:
        add(upper)
    if "lowercase" in rules:
        add(lower)

    # Combine capitalize with suffix rules so "Password1" / "Password!" are tested.
    bases_for_suffix = [base]
    if "capitalize" in rules:
        bases_for_suffix.append(cap)
    if "uppercase" in rules:
        bases_for_suffix.append(upper)

    if "append_numbers" in rules:
        for sfx in _NUMBER_SUFFIXES:
            for b in bases_for_suffix:
                add(b + sfx)

    if "append_years" in rules:
        for y in _YEAR_SUFFIXES:
            for b in bases_for_suffix:
                add(b + y)

    if "append_symbols" in rules:
        for s in _SYMBOL_SUFFIXES:
            for b in bases_for_suffix:
                add(b + s)

    if "leet" in rules:
        leet = base.lower().translate(_LEET_TABLE)
        add(leet)
        add(leet.capitalize())

    if "reverse" in rules:
        add(base[::-1])
        if "capitalize" in rules:
            add(base[::-1].capitalize())

    if "double" in rules:
        add(base + base)
        add(base + " " + base)

    return list(seen.keys())


def build_candidate_list(wordlist_text: str, rules: set[str]) -> list[str]:
    """
    Expand a newline- or comma-separated wordlist into a deduplicated
    passphrase candidate list with the given mutation rules applied.

    Parameters
    ----------
    wordlist_text : str
        Raw text — one word/phrase per line (commas also accepted as separators).
    rules : set[str]
        Subset of MUTATION_RULES keys.

    Returns
    -------
    list[str]  — deduplicated candidates, base words first.
    """
    raw_lines = wordlist_text.replace(",", "\n").splitlines()
    raw = [line.strip() for line in raw_lines if line.strip()]
    seen: dict[str, None] = {}
    for word in raw:
        for variant in _mutate(word, rules):
            seen.setdefault(variant, None)
    return list(seen.keys())


def estimate_candidate_count(wordlist_text: str, rules: set[str]) -> int:
    """Quick estimate of how many candidates build_candidate_list will produce."""
    raw = [ln.strip() for ln in wordlist_text.replace(",", "\n").splitlines() if ln.strip()]
    if not raw:
        return 0
    # Sample the first word and scale.
    sample = _mutate(raw[0], rules)
    return len(sample) * len(raw)


# ---------------------------------------------------------------------------
# Address detection helpers
# ---------------------------------------------------------------------------

def _detect_coin_type(address: str) -> str:
    """
    Infer which coin type an address belongs to so the worker can skip
    irrelevant derivations.  Returns one of:
        'eth', 'btc_native', 'btc_segwit', 'btc_legacy', 'ltc', 'doge',
        'xrp', 'trx', 'sol', 'atom', 'unknown'
    """
    a = address.strip()
    if a.startswith("0x") and len(a) == 42:
        return "eth"
    if a.startswith("bc1"):
        return "btc_native"
    if a.startswith("3") and 26 <= len(a) <= 34:
        return "btc_segwit"
    if a.startswith("1") and 26 <= len(a) <= 34:
        return "btc_legacy"
    if a.startswith("ltc1"):
        return "ltc"
    if a.startswith(("L", "M")) and 26 <= len(a) <= 34:
        return "ltc"
    if a.startswith("D") and 26 <= len(a) <= 34:
        return "doge"
    if a.startswith("r") and 25 <= len(a) <= 35:
        return "xrp"
    if a.startswith("T") and len(a) == 34:
        return "trx"
    if a.startswith("cosmos1"):
        return "atom"
    if len(a) in (43, 44) and a[0] in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz":
        return "sol"
    return "unknown"


# ---------------------------------------------------------------------------
# Multiprocessing worker
# ---------------------------------------------------------------------------

def _passphrase_worker(args: tuple) -> dict:
    """
    Test a chunk of passphrase candidates against the target address.

    args: (mnemonic, candidates_chunk, target_address, coin_type)

    Returns dict with:
        matches : list[str]  — candidates that produced the target address
        checked : int
    """
    mnemonic, candidates_chunk, target_address, coin_type = args
    target = target_address.strip().lower()
    matches: list[str] = []
    checked = 0

    for passphrase in candidates_chunk:
        checked += 1
        try:
            seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)

            derived_addresses: list[str] = []

            if coin_type == "eth":
                ctx = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
                a = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                derived_addresses.append(a)

            elif coin_type == "btc_native":
                ctx = Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
                a = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                derived_addresses.append(a)

            elif coin_type == "btc_segwit":
                ctx = Bip49.FromSeed(seed, Bip49Coins.BITCOIN)
                a = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                derived_addresses.append(a)

            elif coin_type == "btc_legacy":
                ctx = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
                a = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                derived_addresses.append(a)

            elif coin_type == "ltc":
                for bip_cls, coin_enum in (
                    (Bip84, Bip84Coins.LITECOIN),
                    (Bip49, Bip49Coins.LITECOIN),
                    (Bip44, Bip44Coins.LITECOIN),
                ):
                    ctx = bip_cls.FromSeed(seed, coin_enum)
                    a = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                    derived_addresses.append(a)

            elif coin_type == "doge":
                ctx = Bip44.FromSeed(seed, Bip44Coins.DOGECOIN)
                a = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                derived_addresses.append(a)

            elif coin_type == "xrp":
                ctx = Bip44.FromSeed(seed, Bip44Coins.RIPPLE)
                a = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                derived_addresses.append(a)

            elif coin_type == "trx":
                ctx = Bip44.FromSeed(seed, Bip44Coins.TRON)
                a = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                derived_addresses.append(a)

            elif coin_type == "atom":
                ctx = Bip44.FromSeed(seed, Bip44Coins.COSMOS)
                a = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                derived_addresses.append(a)

            elif coin_type == "sol":
                ctx = Bip44.FromSeed(seed, Bip44Coins.SOLANA)
                a = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                derived_addresses.append(a)

            else:
                # Unknown type — try ETH and BTC native as a best effort.
                for cls, enum in ((Bip44, Bip44Coins.ETHEREUM), (Bip84, Bip84Coins.BITCOIN)):
                    ctx = cls.FromSeed(seed, enum)
                    a = ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                    derived_addresses.append(a)

            for addr in derived_addresses:
                if addr.lower() == target:
                    matches.append(passphrase)
                    break

        except Exception:
            pass
        finally:
            try:
                del seed
            except NameError:
                pass

    return {"matches": matches, "checked": checked}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def recover_passphrase(
    mnemonic: str,
    candidates: list[str],
    target_address: str,
    progress_callback: Callable[[int, int, int], None] | None = None,
    chunk_size: int = 64,
) -> dict:
    """
    Test every candidate passphrase against the target address.

    Parameters
    ----------
    mnemonic : str
        BIP39-valid mnemonic (must pass validate_mnemonic).
    candidates : list[str]
        Passphrase candidates to test (from build_candidate_list).
    target_address : str
        The wallet address to match against.  Required.
    progress_callback : callable | None
        Called as (checked, total, matches_found) after each chunk.
    chunk_size : int
        Candidates per worker task.  64 balances overhead vs. granularity.

    Returns
    -------
    dict with keys:
        matches      : list[str]  — matched passphrases (usually 0 or 1)
        checked      : int
        total        : int
        elapsed_time : float
        truncated    : bool
    """
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ValueError("mnemonic must be a non-empty string")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("candidates must be a non-empty list")
    if not isinstance(target_address, str) or not target_address.strip():
        raise ValueError("target_address is required for passphrase recovery")

    info = validate_mnemonic(mnemonic)
    if not info["valid"]:
        raise ValueError("Mnemonic failed BIP39 validation; cannot test passphrases.")

    norm_mnemonic = _normalize_mnemonic(mnemonic)
    coin_type = _detect_coin_type(target_address)

    chunks = [candidates[i:i + chunk_size] for i in range(0, len(candidates), chunk_size)]
    tasks = [(norm_mnemonic, chunk, target_address, coin_type) for chunk in chunks]

    total = len(candidates)
    matches: list[str] = []
    checked = 0
    truncated = False

    num_workers = max(1, multiprocessing.cpu_count() - 1)
    start_time = time.time()

    with multiprocessing.Pool(num_workers) as pool:
        for res in pool.imap_unordered(_passphrase_worker, tasks):
            checked += res["checked"]
            for m in res["matches"]:
                if m not in matches:
                    matches.append(m)
            if len(matches) >= _MAX_RETURNED_PASSPHRASES:
                truncated = True

            if progress_callback:
                progress_callback(checked, total, len(matches))

            if truncated:
                pool.terminate()
                break

    elapsed = time.time() - start_time
    return {
        "matches": matches,
        "checked": checked,
        "total": total,
        "elapsed_time": elapsed,
        "truncated": truncated,
    }
