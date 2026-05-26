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
10! = ~3.6M is too slow for an interactive tool, so we cap at 8.
"""

from __future__ import annotations

from itertools import permutations, product
from typing import Iterable

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
# is the absolute ceiling we will run.
MAX_ORDER_POSITIONS = 8

# Cap on how many candidate mnemonics we return from a recovery run. Avoids
# pathological cases where many millions of checksum-valid candidates would
# overwhelm the UI. If exceeded we set "truncated": True in the result.
_MAX_RETURNED_CANDIDATES = 100

# Placeholder character that the caller substitutes in for unknown words.
_UNKNOWN_TOKEN = "?"


# ---------------------------------------------------------------------------
# Internal helpers
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


# ---------------------------------------------------------------------------
# 1. recover_missing_words
# ---------------------------------------------------------------------------

def recover_missing_words(
    mnemonic_with_q: str,
    target_address: str | None = None,
    max_unknowns: int = 2,
) -> dict:
    """
    Brute-force fill in `?` placeholders in a partial BIP39 mnemonic.

    Inputs
    ------
    mnemonic_with_q : str
        Mnemonic where unknown words are replaced by the literal character
        "?". Example with one unknown:
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon ?"
    target_address : str | None
        Optional. If supplied, only candidates that produce this address on
        a standard derivation path are kept.
    max_unknowns : int
        How many "?" slots are acceptable. Hard-capped at MAX_MISSING_WORDS
        (currently 2). Larger values raise ValueError because the search
        space would explode (2048^3 = 8.6 billion).

    Returns
    -------
    dict with keys:
        candidates : list[str]   -- valid (and target-matching) mnemonics
        checked    : int         -- how many substitutions were validated
        with_target: bool        -- whether target_address filtering applied
        truncated  : bool        -- True if more candidates existed than cap

    The result does NOT contain the original input mnemonic_with_q, nor does
    it echo any forbidden secret beyond the candidate mnemonics themselves
    (which are the whole point of this function).
    """
    # --- input validation -------------------------------------------------
    if not isinstance(mnemonic_with_q, str) or not mnemonic_with_q.strip():
        raise ValueError("mnemonic_with_q must be a non-empty string")
    if not isinstance(max_unknowns, int) or max_unknowns < 1:
        raise ValueError("max_unknowns must be a positive integer")
    if max_unknowns > MAX_MISSING_WORDS:
        # Hard refusal: 3+ unknowns is computationally infeasible AND a sign
        # the caller probably needs a different recovery strategy.
        raise ValueError(
            f"max_unknowns is capped at {MAX_MISSING_WORDS}; "
            f"got {max_unknowns}. Consider narrowing the search instead."
        )

    words = _split_normalized(mnemonic_with_q)
    unknown_positions = [i for i, w in enumerate(words) if w == _UNKNOWN_TOKEN]

    if not unknown_positions:
        # Nothing to brute-force. Fall through to validation of the input as-is.
        v = validate_mnemonic(" ".join(words))
        candidates = [" ".join(words)] if v["valid"] else []
        if candidates and target_address is not None:
            if not _first_address_matches(candidates[0], target_address):
                candidates = []
        return {
            "candidates": candidates,
            "checked": 1,
            "with_target": target_address is not None,
            "truncated": False,
        }

    if len(unknown_positions) > max_unknowns:
        raise ValueError(
            f"Input has {len(unknown_positions)} '?' placeholders, "
            f"exceeding max_unknowns={max_unknowns}."
        )

    # Any non-? word should be a real BIP39 word; if not, surface the issue.
    wordlist = _english_wordlist()
    known = [w for i, w in enumerate(words) if i not in set(unknown_positions)]
    if not all(w in wordlist for w in known):
        # We refuse to brute-force a phrase that contains misspellings: the
        # caller should run suggest_typo_corrections first.
        raise ValueError(
            "Non-'?' tokens contain words not in the BIP39 English wordlist. "
            "Run suggest_typo_corrections first."
        )

    # --- enumerate candidates --------------------------------------------
    sorted_wordlist = sorted(wordlist)  # stable order => deterministic output
    candidates: list[str] = []
    truncated = False
    checked = 0

    # product() expands the Cartesian product of the candidate word for each
    # unknown slot. For 2 unknowns that's 2048 * 2048 = 4_194_304 iterations.
    for combo in product(sorted_wordlist, repeat=len(unknown_positions)):
        checked += 1
        # Build the candidate by substituting in the chosen words.
        trial = list(words)
        for pos, candidate_word in zip(unknown_positions, combo):
            trial[pos] = candidate_word
        candidate = " ".join(trial)

        # Validate the BIP39 checksum (this is what eliminates ~99.9% of
        # combinations). Only checksum-valid phrases are real BIP39 mnemonics.
        if not validate_mnemonic(candidate)["valid"]:
            continue

        # Optional address-match filter.
        if target_address is not None:
            if not _first_address_matches(candidate, target_address):
                continue

        candidates.append(candidate)
        if len(candidates) >= _MAX_RETURNED_CANDIDATES:
            truncated = True
            break

    return {
        "candidates": candidates,
        "checked": checked,
        "with_target": target_address is not None,
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# 2. suggest_typo_corrections
# ---------------------------------------------------------------------------

def suggest_typo_corrections(mnemonic: str, max_suggestions: int = 5) -> dict:
    """
    Suggest BIP39-wordlist replacements for any misspelled words.

    For every input word that is NOT in the English BIP39 wordlist, we
    compute Levenshtein distance to every wordlist entry and return the
    `max_suggestions` closest matches (alphabetical tiebreak for stability).

    Inputs
    ------
    mnemonic        : str   -- candidate mnemonic, possibly containing typos
    max_suggestions : int   -- how many suggestions per unknown word

    Returns
    -------
    dict with keys:
        unknown_words   : list[dict]
            each entry: {"word": str, "position": int, "suggestions": list[str]}
        all_words_known : bool
            True iff every word was already in the wordlist (no suggestions).

    The result deliberately does NOT include the full input mnemonic. We
    return only the unknown words, their position, and suggested replacements
    so that even if a user pastes a real partial seed, the function's output
    doesn't reproduce the entire seed phrase.
    """
    if not isinstance(mnemonic, str):
        raise ValueError("mnemonic must be a string")
    if not isinstance(max_suggestions, int) or max_suggestions < 1:
        raise ValueError("max_suggestions must be a positive integer")

    # _normalize_mnemonic lowercases and collapses whitespace; split into tokens.
    words = _normalize_mnemonic(mnemonic).split()

    wordlist = _english_wordlist()
    unknown: list[dict] = []
    for i, w in enumerate(words):
        if w in wordlist:
            continue
        # Score every wordlist entry and take the top N.
        # We pre-build (distance, word) tuples and sort once. For 2048 words
        # this is fast; we don't bother with a heap.
        scored = sorted(
            ((_levenshtein(w, candidate), candidate) for candidate in wordlist),
            key=lambda t: (t[0], t[1]),  # distance asc, then alphabetical
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
    words: list[str],
    target_address: str | None = None,
    max_positions: int = 8,
) -> dict:
    """
    Enumerate permutations of `words` to find ones with a valid BIP39 checksum.

    Use case: the user has all the right words but wrote them down in the
    wrong order. We try every ordering, keep the BIP39-valid ones, and
    optionally filter by first-address match against `target_address`.

    Inputs
    ------
    words          : list[str]
        The complete list of BIP39 words, order unknown.
    target_address : str | None
        Optional. If supplied, only orderings whose first standard address
        matches are kept.
    max_positions  : int
        Upper bound on len(words). Hard-capped at MAX_ORDER_POSITIONS = 8
        because 9! = 362_880 already takes >1 minute of checksum validation.

    Returns
    -------
    dict with the same shape as recover_missing_words:
        candidates : list[str]
        checked    : int
        with_target: bool
        truncated  : bool

    Raises
    ------
    ValueError if `words` is empty, contains non-strings, or has more
    entries than min(max_positions, MAX_ORDER_POSITIONS).
    """
    if not isinstance(words, list) or not words:
        raise ValueError("words must be a non-empty list of strings")
    if not all(isinstance(w, str) for w in words):
        raise ValueError("words must contain only strings")
    if not isinstance(max_positions, int) or max_positions < 1:
        raise ValueError("max_positions must be a positive integer")

    # Clamp the user's max_positions to the absolute ceiling.
    effective_cap = min(max_positions, MAX_ORDER_POSITIONS)

    if len(words) > effective_cap:
        # We refuse rather than silently truncating: trying to permute 12
        # words is 479M permutations and would lock the UI. The caller should
        # split the problem (e.g. use recover_missing_words to fix specific
        # slots) instead.
        raise ValueError(
            f"recover_word_order refuses inputs longer than {effective_cap} "
            f"words (got {len(words)}). Permuting more is computationally "
            f"infeasible; consider a different recovery strategy."
        )

    # Normalise each word for fair comparison.
    norm_words = [w.strip().lower() for w in words]

    # Optional sanity check: warn (via ValueError) if any word is not BIP39.
    wordlist = _english_wordlist()
    if not all(w in wordlist for w in norm_words):
        raise ValueError(
            "One or more words are not in the BIP39 English wordlist. "
            "Fix typos before attempting order recovery."
        )

    candidates: list[str] = []
    seen: set[str] = set()  # de-duplicate orderings caused by repeated words
    truncated = False
    checked = 0

    for perm in permutations(norm_words):
        checked += 1
        candidate = " ".join(perm)
        if candidate in seen:
            continue
        seen.add(candidate)

        if not validate_mnemonic(candidate)["valid"]:
            continue
        if target_address is not None:
            if not _first_address_matches(candidate, target_address):
                continue

        candidates.append(candidate)
        if len(candidates) >= _MAX_RETURNED_CANDIDATES:
            truncated = True
            break

    return {
        "candidates": candidates,
        "checked": checked,
        "with_target": target_address is not None,
        "truncated": truncated,
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

    BIP39 supports an optional passphrase (sometimes called the "25th word")
    that is mixed into the seed via PBKDF2 along with the mnemonic. The same
    mnemonic with a different passphrase produces a completely different
    wallet -- this is the basis for plausible-deniability "hidden wallets".

    Inputs
    ------
    mnemonic       : str
        The 12/15/18/21/24-word BIP39 phrase. Must pass checksum validation.
    passphrase     : str
        The optional BIP39 passphrase to test. Empty string is allowed (and
        equivalent to no passphrase, matching standard BIP39 behaviour).
    target_address : str | None
        Optional. If provided, we additionally report whether any of the
        derived addresses match.
    count          : int
        How many addresses to derive PER derivation standard (ETH + BTC
        legacy + BTC segwit + BTC native segwit).

    Returns
    -------
    dict with keys:
        addresses : list[dict]
            Each dict: {"coin", "address_type", "path", "address"}.
            Public information only.
        match     : dict | None
            The first address dict that matches `target_address`, or None.
            Always None if `target_address` is not provided.

    The passphrase NEVER appears in the result. We do not include it in any
    field. The mnemonic is also not returned.
    """
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ValueError("mnemonic must be a non-empty string")
    if not isinstance(passphrase, str):
        raise ValueError("passphrase must be a string (may be empty)")
    if not isinstance(count, int) or count < 1:
        raise ValueError("count must be a positive integer")

    # Validate the mnemonic before doing expensive PBKDF2 work.
    info = validate_mnemonic(mnemonic)
    if not info["valid"]:
        raise ValueError("Mnemonic is not valid; cannot test passphrase.")

    # Re-derive the seed with the passphrase mixed in. This is the only thing
    # that differs from a normal derivation: Bip39SeedGenerator.Generate takes
    # an optional passphrase argument that gets concatenated into the PBKDF2
    # salt ("mnemonic" + passphrase). Two different passphrases => two
    # different seeds => two different wallets.
    normalized = _normalize_mnemonic(mnemonic)
    seed_bytes = Bip39SeedGenerator(normalized).Generate(passphrase)

    try:
        # We can't reuse derive_eth_addresses / derive_btc_addresses because
        # those functions derive their own (passphrase-less) seed internally.
        # Instead, we build the address contexts directly from the seed_bytes
        # we just generated.
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
        # Drop our seed reference promptly. Python doesn't guarantee secure
        # memory wiping, but losing the reference lets the GC reclaim it.
        del seed_bytes
