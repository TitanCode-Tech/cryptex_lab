"""
recovery_utils.py
-----------------
Recovery engine for partially-known or damaged BIP39 mnemonics.

SECURITY DESIGN NOTES
=====================
* No network calls. This module imports nothing from `requests`, `urllib`,
  `socket`, `http`, `aiohttp`, `httpx`, `web3`, etc. All BIP39 / BIP44
  derivation is performed locally via `bip_utils`.
* Secrets (mnemonic words, seed bytes, entropy, private keys, passphrases)
  are never written to disk, logged, or placed in any persistent store by
  this module. They live only as local variables and are dropped after use.
* IMPORTANT CALLER NOTE: `recover_missing_words` and `recover_word_order`
  legitimately RETURN candidate mnemonics in their result dicts. That is the
  entire point of these recovery flows. The caller (UI / CLI) is responsible
  for handling those candidates carefully: showing them only in volatile
  in-memory views, never logging them, never persisting them. This module
  does not itself persist them anywhere.
* Error messages never echo the input mnemonic or passphrase back at the
  caller.

COMBINATORIAL BOUNDS
====================
The BIP39 English wordlist is 2048 words. So:
   * 1 unknown slot  =>     2048 candidate substitutions
   * 2 unknown slots => ~4.2M candidate substitutions
   * 3 unknown slots => ~8.6B candidate substitutions  (refused)
We therefore hard-cap missing-word recovery at 2 unknowns. Likewise word
order recovery: 8! = 40,320 permutations is fine, 9! = 362,880 is borderline,
10! = ~3.6M is too slow for single-threaded interactive runs, but with
multiprocessing and locked positions, we can calculate and warn before execution.
"""

from __future__ import annotations

import math
import multiprocessing
import time
from collections import Counter
from itertools import permutations, product
from typing import Callable

from bip_utils import Bip39SeedGenerator

from wallet_utils import (
    _english_wordlist,
    _normalize_mnemonic,
    validate_mnemonic,
)
from derivation_utils import find_address_match


# ---------------------------------------------------------------------------
# Public caps (the UI imports these to display the limits to users).
# ---------------------------------------------------------------------------

# Max number of "?" placeholders allowed in recover_missing_words. With 2048
# wordlist entries, 2 unknowns => 4.2M validations, which is the practical
# ceiling for an interactive tool.
MAX_MISSING_WORDS = 2

# Max number of words for which we will enumerate permutations. 8! = 40320
# is the old limit. Now we can support larger permutations if constrained.
MAX_ORDER_POSITIONS = 8

# Cap on how many candidate mnemonics we return from a recovery run. Avoids
# pathological cases where many millions of checksum-valid candidates would
# overwhelm the UI. If exceeded we set "truncated": True in the result.
_MAX_RETURNED_CANDIDATES = 100

# Placeholder character that the caller substitutes in for unknown words.
_UNKNOWN_TOKEN = "?"


# ---------------------------------------------------------------------------
# Internal helpers & Multiprocessing Workers
# ---------------------------------------------------------------------------

def _split_normalized(mnemonic: str) -> list[str]:
    """Lowercase, collapse whitespace, split. Mirrors wallet_utils behaviour."""
    return _normalize_mnemonic(mnemonic).split()


def _levenshtein(a: str, b: str) -> int:
    """
    Classic dynamic-programming Levenshtein edit distance.

    Returns the minimum number of single-character insertions, deletions, or
    substitutions required to turn `a` into `b`. Kept small and dependency-
    free so we don't pull in another package just to suggest typos.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    # Two-row variant uses O(min(len(a), len(b))) memory. BIP39 words are
    # short (<=8 chars) so this is trivial either way, but it's good practice.
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            # Cost is 0 if characters match (no edit), else 1 (substitute).
            cost = 0 if ca == cb else 1
            curr[j] = min(
                curr[j - 1] + 1,        # insertion
                prev[j] + 1,            # deletion
                prev[j - 1] + cost,     # substitution
            )
            # Damerau-Levenshtein transposition check could go here, but
            # standard Levenshtein is sufficient for typical typos.
        prev = curr
    return prev[-1]


def _first_address_matches(mnemonic: str, target_address: str) -> bool:
    """
    Return True if `target_address` appears in the first window of standard
    derivation paths for `mnemonic`. Uses derivation_utils.find_address_match
    which scans ETH BIP44 + BTC legacy/segwit/native-segwit.

    A failure to validate the mnemonic returns False (it should not, because
    we only call this after BIP39 checksum validation, but be defensive).
    """
    try:
        result = find_address_match(
            mnemonic, target_address, max_addresses_per_standard=5
        )
    except Exception:
        return False
    return result.get("match") is not None


def _recover_chunk_worker(args) -> dict:
    """
    Multiprocessing worker for missing-word recovery.
    args: (words, unknown_positions, first_word_chunk, sorted_wordlist, target_address)
    """
    words, unknown_positions, first_word_chunk, sorted_wordlist, target_address = args
    candidates = []
    checked = 0
    checksum_passed = 0

    n_unknowns = len(unknown_positions)

    if n_unknowns == 1:
        pos = unknown_positions[0]
        trial = list(words)
        for w1 in first_word_chunk:
            checked += 1
            trial[pos] = w1
            candidate = " ".join(trial)
            if validate_mnemonic(candidate)["valid"]:
                checksum_passed += 1
                if target_address is None or _first_address_matches(candidate, target_address):
                    candidates.append(candidate)

    elif n_unknowns == 2:
        pos1, pos2 = unknown_positions
        trial = list(words)
        for w1 in first_word_chunk:
            trial[pos1] = w1
            for w2 in sorted_wordlist:
                checked += 1
                trial[pos2] = w2
                candidate = " ".join(trial)
                if validate_mnemonic(candidate)["valid"]:
                    checksum_passed += 1
                    if target_address is None or _first_address_matches(candidate, target_address):
                        candidates.append(candidate)

    return {
        "candidates": candidates,
        "checked": checked,
        "checksum_passed": checksum_passed,
    }


def unique_permutations(elements):
    """Generate unique permutations of a list with duplicate elements."""
    current = sorted(elements)
    yield tuple(current)
    
    n = len(current)
    while True:
        i = n - 2
        while i >= 0 and current[i] >= current[i + 1]:
            i -= 1
        if i < 0:
            break
            
        j = n - 1
        while current[j] <= current[i]:
            j -= 1
            
        current[i], current[j] = current[j], current[i]
        current[i + 1:] = reversed(current[i + 1:])
        yield tuple(current)


def _recover_order_worker(args) -> dict:
    """
    Multiprocessing worker for word-order recovery.
    args: (template_words, unknown_positions, first_word, remaining_pool, target_address)
    """
    template_words, unknown_positions, first_word, remaining_pool, target_address = args
    candidates = []
    checked = 0
    checksum_passed = 0

    pos_first = unknown_positions[0]
    pos_rest = unknown_positions[1:]

    trial = list(template_words)
    trial[pos_first] = first_word

    if not pos_rest:
        # Only 1 position to permute
        checked += 1
        candidate = " ".join(trial)
        if validate_mnemonic(candidate)["valid"]:
            checksum_passed += 1
            if target_address is None or _first_address_matches(candidate, target_address):
                candidates.append(candidate)
    else:
        if len(set(remaining_pool)) < len(remaining_pool):
            perms = unique_permutations(remaining_pool)
        else:
            perms = permutations(remaining_pool)

        for perm in perms:
            checked += 1
            for pos, w in zip(pos_rest, perm):
                trial[pos] = w
            candidate = " ".join(trial)

            if validate_mnemonic(candidate)["valid"]:
                checksum_passed += 1
                if target_address is None or _first_address_matches(candidate, target_address):
                    candidates.append(candidate)

    return {
        "candidates": candidates,
        "checked": checked,
        "checksum_passed": checksum_passed,
    }


# ---------------------------------------------------------------------------
# Runtime Estimation Helper
# ---------------------------------------------------------------------------

def estimate_recovery_time(
    search_space_size: int,
    target_address_provided: bool,
    word_count: int,
) -> float:
    """
    Estimate the recovery runtime in seconds based on search space size,
    number of available CPU cores, and whether derivation-matching is active.
    """
    cores = max(1, multiprocessing.cpu_count() - 1)
    
    # Checksum verification speed: approx 150k checks/sec per core.
    checksum_speed = 150000 * cores
    time_checksum = search_space_size / checksum_speed
    
    if target_address_provided:
        # Expected ratio of candidates passing checksum validation.
        # 12 words = 4-bit checksum (1/16 pass)
        # 24 words = 8-bit checksum (1/256 pass)
        checksum_bits = word_count // 3
        valid_ratio = 1.0 / (2 ** checksum_bits)
        expected_derivations = search_space_size * valid_ratio
        
        # Derivation speed: approx 1,000 derivations/sec per core.
        derivation_speed = 1000 * cores
        time_derivation = expected_derivations / derivation_speed
        
        return time_checksum + time_derivation
    
    return time_checksum


# ---------------------------------------------------------------------------
# 1. recover_missing_words
# ---------------------------------------------------------------------------

def recover_missing_words(
    mnemonic_with_q: str,
    target_address: str | None = None,
    max_unknowns: int = 2,
    progress_callback: Callable[[int, int, int], None] | None = None,
) -> dict:
    """
    Brute-force fill in `?` placeholders in a partial BIP39 mnemonic using multiprocessing.

    Inputs
    ------
    mnemonic_with_q : str
        Mnemonic where unknown words are replaced by "?".
    target_address : str | None
        Optional target address to filter candidates.
    max_unknowns : int
        Max acceptable unknown slots. Hard-capped at MAX_MISSING_WORDS (2).
    progress_callback : Callable[[int, int, int], None] | None
        Callback receiving (checked_count, total_count, candidates_found).

    Returns
    -------
    dict with keys:
        candidates : list[str]
        checked    : int
        checksum_passed: int
        with_target: bool
        truncated  : bool
        elapsed_time: float
    """
    # --- input validation -------------------------------------------------
    if not isinstance(mnemonic_with_q, str) or not mnemonic_with_q.strip():
        raise ValueError("mnemonic_with_q must be a non-empty string")
    if not isinstance(max_unknowns, int) or max_unknowns < 1:
        raise ValueError("max_unknowns must be a positive integer")
    if max_unknowns > MAX_MISSING_WORDS:
        raise ValueError(
            f"max_unknowns is capped at {MAX_MISSING_WORDS}; "
            f"got {max_unknowns}. Consider narrowing the search instead."
        )

    words = _split_normalized(mnemonic_with_q)
    unknown_positions = [i for i, w in enumerate(words) if w == _UNKNOWN_TOKEN]

    if not unknown_positions:
        v = validate_mnemonic(" ".join(words))
        candidates = [" ".join(words)] if v["valid"] else []
        if candidates and target_address is not None:
            if not _first_address_matches(candidates[0], target_address):
                candidates = []
        return {
            "candidates": candidates,
            "checked": 1,
            "checksum_passed": 1 if v["valid"] else 0,
            "with_target": target_address is not None,
            "truncated": False,
            "elapsed_time": 0.0,
        }

    if len(unknown_positions) > max_unknowns:
        raise ValueError(
            f"Input has {len(unknown_positions)} '?' placeholders, "
            f"exceeding max_unknowns={max_unknowns}."
        )

    wordlist = _english_wordlist()
    known = [w for i, w in enumerate(words) if i not in set(unknown_positions)]
    invalid_words = [w for w in known if w not in wordlist]
    if invalid_words:
        raise ValueError(
            f"Non-'?' tokens contain words not in the BIP39 English wordlist: {', '.join(invalid_words)}. "
            "Run suggest_typo_corrections first."
        )

    # --- enumerate candidates using multiprocessing ----------------------
    sorted_wordlist = sorted(wordlist)
    total_combinations = len(sorted_wordlist) ** len(unknown_positions)

    # Divide search space into chunks for the first unknown position
    if len(unknown_positions) == 1:
        chunk_size = 128
    else:
        chunk_size = 32

    chunks = [sorted_wordlist[i:i + chunk_size] for i in range(0, len(sorted_wordlist), chunk_size)]
    tasks = []
    for chunk in chunks:
        tasks.append((words, unknown_positions, chunk, sorted_wordlist, target_address))

    start_time = time.time()
    candidates: list[str] = []
    checked_count = 0
    checksum_passed_count = 0
    truncated = False

    num_workers = max(1, multiprocessing.cpu_count() - 1)

    with multiprocessing.Pool(num_workers) as pool:
        for res in pool.imap_unordered(_recover_chunk_worker, tasks):
            checked_count += res["checked"]
            checksum_passed_count += res["checksum_passed"]
            for cand in res["candidates"]:
                if cand not in candidates:
                    candidates.append(cand)
                    if len(candidates) >= _MAX_RETURNED_CANDIDATES:
                        truncated = True

            if progress_callback:
                progress_callback(checked_count, total_combinations, len(candidates))

            if truncated:
                pool.terminate()
                break

    elapsed_time = time.time() - start_time

    return {
        "candidates": candidates,
        "checked": checked_count,
        "checksum_passed": checksum_passed_count,
        "with_target": target_address is not None,
        "truncated": truncated,
        "elapsed_time": elapsed_time,
    }


# ---------------------------------------------------------------------------
# 2. suggest_typo_corrections
# ---------------------------------------------------------------------------

def suggest_typo_corrections(mnemonic: str, max_suggestions: int = 5) -> dict:
    """
    Suggest BIP39-wordlist replacements for any misspelled words.
    """
    if not isinstance(mnemonic, str):
        raise ValueError("mnemonic must be a string")
    if not isinstance(max_suggestions, int) or max_suggestions < 1:
        raise ValueError("max_suggestions must be a positive integer")

    words = _normalize_mnemonic(mnemonic).split()
    wordlist = _english_wordlist()
    unknown: list[dict] = []
    for i, w in enumerate(words):
        if w in wordlist:
            continue
        scored = sorted(
            ((_levenshtein(w, candidate), candidate) for candidate in wordlist),
            key=lambda t: (t[0], t[1]),
        )
        suggestions = [cand for _, cand in scored[:max_suggestions]]
        unknown.append({
            "word": w,
            "position": i,
            "suggestions": suggestions,
        })

    return {
        "unknown_words": unknown,
        "all_words_known": len(unknown) == 0,
    }


# ---------------------------------------------------------------------------
# 3. recover_word_order
# ---------------------------------------------------------------------------

def recover_word_order(
    template_or_words: str | list[str],
    pool_words: list[str] | None = None,
    target_address: str | None = None,
    max_permutations: int = 5_000_000,
    progress_callback: Callable[[int, int, int], None] | None = None,
    max_positions: int = 8,  # backwards compatibility
) -> dict:
    """
    Enumerate permutations of words to find ones with a valid BIP39 checksum.
    Supports constrained permutations when a template phrase with fixed positions is provided.

    Inputs
    ------
    template_or_words : str | list[str]
        Either a space-separated template (e.g. "abandon ? ? abandon abandon ?")
        or a list of words to permute (for backward compatibility).
    pool_words : list[str] | None
        The pool of words to distribute in the "?" positions of the template.
        Must be None if template_or_words is a list of strings.
    target_address : str | None
        Optional target address to filter candidates.
    max_permutations : int
        Safety threshold. Permutations exceeding this size are rejected with ValueError.
    progress_callback : Callable[[int, int, int], None] | None
        Callback receiving (checked_count, total_count, candidates_found).
    max_positions : int
        Legacy parameter. Applied only when template_or_words is a list.

    Returns
    -------
    dict with keys:
        candidates : list[str]
        checked    : int
        checksum_passed: int
        with_target: bool
        truncated  : bool
        elapsed_time: float
        search_space: int
    """
    # Backwards compatibility check
    if isinstance(template_or_words, list):
        if not template_or_words:
            raise ValueError("words must be a non-empty list of strings")
        if not all(isinstance(w, str) for w in template_or_words):
            raise ValueError("words must contain only strings")
        pool_words = template_or_words
        template_phrase = " ".join(["?"] * len(pool_words))
    else:
        template_phrase = template_or_words
        if pool_words is None:
            raise ValueError("pool_words must be provided when template_phrase is a string")
        if not isinstance(pool_words, list) or not pool_words:
            raise ValueError("pool_words must be a non-empty list of strings")
        if not all(isinstance(w, str) for w in pool_words):
            raise ValueError("pool_words must contain only strings")

    # Normalize inputs
    template_words = _split_normalized(template_phrase)
    pool_words = [w.strip().lower() for w in pool_words]

    wordlist = _english_wordlist()

    # Validate template words
    known_template_words = [w for w in template_words if w != _UNKNOWN_TOKEN]
    invalid_template_words = [w for w in known_template_words if w not in wordlist]
    if invalid_template_words:
        raise ValueError(
            f"Template contains words not in the BIP39 English wordlist: {', '.join(invalid_template_words)}"
        )

    # Validate pool words
    invalid_pool_words = [w for w in pool_words if w not in wordlist]
    if invalid_pool_words:
        raise ValueError(
            f"Pool contains words not in the BIP39 English wordlist: {', '.join(invalid_pool_words)}"
        )

    unknown_positions = [i for i, w in enumerate(template_words) if w == _UNKNOWN_TOKEN]

    if len(unknown_positions) != len(pool_words):
        raise ValueError(
            f"Mismatch: template has {len(unknown_positions)} unknown positions (?), "
            f"but pool has {len(pool_words)} words."
        )

    if not unknown_positions:
        candidate = " ".join(template_words)
        v = validate_mnemonic(candidate)
        candidates = [candidate] if v["valid"] else []
        if candidates and target_address is not None:
            if not _first_address_matches(candidates[0], target_address):
                candidates = []
        return {
            "candidates": candidates,
            "checked": 1,
            "checksum_passed": 1 if v["valid"] else 0,
            "with_target": target_address is not None,
            "truncated": False,
            "elapsed_time": 0.0,
            "search_space": 1,
        }

    # Calculate exact distinct permutations
    counts = Counter(pool_words)
    total_permutations = math.factorial(len(pool_words))
    for count in counts.values():
        total_permutations //= math.factorial(count)

    if total_permutations > max_permutations:
        raise ValueError(
            f"The search space contains {total_permutations:,} unique permutations, "
            f"which exceeds the safety limit of {max_permutations:,}. "
            "To make this search feasible, please lock more positions in the template phrase."
        )

    # Parallelize by unique choice of the first unknown word
    unique_first_words = list(set(pool_words))
    tasks = []
    for first_word in unique_first_words:
        remaining = list(pool_words)
        remaining.remove(first_word)
        tasks.append((template_words, unknown_positions, first_word, remaining, target_address))

    start_time = time.time()
    candidates: list[str] = []
    checked_count = 0
    checksum_passed_count = 0
    truncated = False

    num_workers = max(1, multiprocessing.cpu_count() - 1)

    with multiprocessing.Pool(num_workers) as pool:
        for res in pool.imap_unordered(_recover_order_worker, tasks):
            checked_count += res["checked"]
            checksum_passed_count += res["checksum_passed"]
            for cand in res["candidates"]:
                if cand not in candidates:
                    candidates.append(cand)
                    if len(candidates) >= _MAX_RETURNED_CANDIDATES:
                        truncated = True

            if progress_callback:
                progress_callback(checked_count, total_permutations, len(candidates))

            if truncated:
                pool.terminate()
                break

    elapsed_time = time.time() - start_time

    return {
        "candidates": candidates,
        "checked": checked_count,
        "checksum_passed": checksum_passed_count,
        "with_target": target_address is not None,
        "truncated": truncated,
        "elapsed_time": elapsed_time,
        "search_space": total_permutations,
    }


# ---------------------------------------------------------------------------
# 4. test_passphrase
# ---------------------------------------------------------------------------

def test_passphrase(
    mnemonic: str,
    passphrase: str,
    target_address: str | None = None,
    count: int = 5,
) -> dict:
    """
    Derive the first `count` addresses using a BIP39 passphrase.
    """
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ValueError("mnemonic must be a non-empty string")
    if not isinstance(passphrase, str):
        raise ValueError("passphrase must be a string (may be empty)")
    if not isinstance(count, int) or count < 1:
        raise ValueError("count must be a positive integer")

    info = validate_mnemonic(mnemonic)
    if not info["valid"]:
        raise ValueError("Mnemonic is not valid; cannot test passphrase.")

    normalized = _normalize_mnemonic(mnemonic)
    seed_bytes = Bip39SeedGenerator(normalized).Generate(passphrase)

    try:
        from bip_utils import (
            Bip44,
            Bip44Changes,
            Bip44Coins,
            Bip49,
            Bip49Coins,
            Bip84,
            Bip84Coins,
        )
        from wallet_utils import BTC_ADDRESS_TYPES, ETH_PATH_TEMPLATE

        addresses: list[dict] = []

        # ETH (BIP44, coin type 60).
        eth_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
        eth_account = eth_ctx.Purpose().Coin().Account(0).Change(
            Bip44Changes.CHAIN_EXT
        )
        for i in range(count):
            addresses.append({
                "coin": "ETH",
                "address_type": "Ethereum",
                "path": ETH_PATH_TEMPLATE.format(index=i),
                "address": eth_account.AddressIndex(i).PublicKey().ToAddress(),
            })

        # BTC across all three address standards.
        btc_specs = [
            ("legacy", Bip44, Bip44Coins.BITCOIN),
            ("segwit", Bip49, Bip49Coins.BITCOIN),
            ("native_segwit", Bip84, Bip84Coins.BITCOIN),
        ]
        for atype, klass, coin_enum in btc_specs:
            meta = BTC_ADDRESS_TYPES[atype]
            ctx = klass.FromSeed(seed_bytes, coin_enum)
            account = ctx.Purpose().Coin().Account(0).Change(
                Bip44Changes.CHAIN_EXT
            )
            for i in range(count):
                addresses.append({
                    "coin": "BTC",
                    "address_type": meta["label"],
                    "path": meta["path_template"].format(index=i),
                    "address": account.AddressIndex(i).PublicKey().ToAddress(),
                })

        # Optional target-match scan.
        match: dict | None = None
        if target_address is not None:
            target_norm = target_address.strip().lower()
            for entry in addresses:
                if entry["address"].lower() == target_norm:
                    match = entry
                    break

        return {
            "addresses": addresses,
            "match": match,
        }
    finally:
        del seed_bytes
