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
from itertools import combinations, permutations, product
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

# Wild-card character used for partial-word patterns (e.g. "aban*").
_WILDCARD = "*"

# Hard cap on total search-space combinations. For pure-? unknowns this
# equals 2048^2 ≈ 4.2 M. For partial patterns the same cap applies to the
# product of per-position candidate counts.
_SEARCH_SPACE_CAP = 4_200_000


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


# ---------------------------------------------------------------------------
# Keyboard adjacency map (QWERTY)
# ---------------------------------------------------------------------------

_QWERTY_ADJACENCY: dict[str, frozenset[str]] = {
    "q": frozenset("was"),
    "w": frozenset("qesad"),
    "e": frozenset("wrsdf"),
    "r": frozenset("etdfg"),
    "t": frozenset("ryfgh"),
    "y": frozenset("tughj"),
    "u": frozenset("yihjk"),
    "i": frozenset("uojkl"),
    "o": frozenset("ipkl"),
    "p": frozenset("ol"),
    "a": frozenset("qwszx"),
    "s": frozenset("awedxzc"),
    "d": frozenset("serfcxv"),
    "f": frozenset("drtgvbc"),
    "g": frozenset("ftyhbvn"),
    "h": frozenset("gyujnbm"),
    "j": frozenset("huikmn"),
    "k": frozenset("jiolm"),
    "l": frozenset("kop"),
    "z": frozenset("asx"),
    "x": frozenset("zsdc"),
    "c": frozenset("xdfv"),
    "v": frozenset("cfgb"),
    "b": frozenset("vghn"),
    "n": frozenset("bhjm"),
    "m": frozenset("njk"),
}


def _soundex(word: str) -> str:
    """
    American Soundex phonetic code.
    Returns a 4-character code, e.g. 'abandon' → 'A153'.
    Words with the same code sound phonetically similar.
    """
    if not word:
        return "0000"
    word = word.lower()
    _table = {
        "b": "1", "f": "1", "p": "1", "v": "1",
        "c": "2", "g": "2", "j": "2", "k": "2",
        "q": "2", "s": "2", "x": "2", "z": "2",
        "d": "3", "t": "3",
        "l": "4",
        "m": "5", "n": "5",
        "r": "6",
    }
    first = word[0].upper()
    code = first
    prev = _table.get(word[0], "0")
    for ch in word[1:]:
        c = _table.get(ch, "0")
        if c != "0" and c != prev:
            code += c
        prev = c
    return (code + "000")[:4]


# Pre-built soundex index over the BIP39 wordlist (populated on first use).
_SOUNDEX_INDEX: dict[str, list[str]] = {}


def _get_soundex_index() -> dict[str, list[str]]:
    global _SOUNDEX_INDEX
    if not _SOUNDEX_INDEX:
        for w in _english_wordlist():
            code = _soundex(w)
            _SOUNDEX_INDEX.setdefault(code, []).append(w)
    return _SOUNDEX_INDEX


def _keyboard_typos(word: str, wordlist_set: frozenset[str]) -> list[str]:
    """
    Return BIP39 words reachable from `word` by substituting exactly one
    character with an adjacent key on a QWERTY layout.
    """
    matches: list[str] = []
    word = word.lower()
    for i, ch in enumerate(word):
        for neighbor in _QWERTY_ADJACENCY.get(ch, frozenset()):
            candidate = word[:i] + neighbor + word[i + 1:]
            if candidate in wordlist_set:
                matches.append(candidate)
    return matches


def _expand_pattern(token: str, sorted_wordlist: list[str]) -> list[str]:
    """
    Expand a variable token to the list of matching BIP39 words.

    Supported syntax (case-insensitive, lowercase normalised):
      "?"       – fully unknown: returns all 2048 words
      "abc*"    – prefix match: words starting with "abc"
      "*abc"    – suffix match: words ending with "abc"
      "a*c"     – prefix+suffix: words starting with "a" AND ending with "c"
      "*"       – alias for "?": all words

    Returns an empty list when the pattern matches nothing (caller should
    raise a descriptive ValueError in that case).
    """
    t = token.lower().strip()
    if t == _UNKNOWN_TOKEN or t == _WILDCARD:
        return sorted_wordlist
    if _WILDCARD not in t:
        # Not a pattern – exact lookup (used internally; caller already
        # validated that exact words are in the wordlist).
        return [t] if t in set(sorted_wordlist) else []
    prefix, _, tail = t.partition(_WILDCARD)
    # If there's another wildcard in the tail, take everything after the LAST
    # one as the required suffix.
    suffix = tail.rsplit(_WILDCARD, 1)[-1] if _WILDCARD in tail else tail
    return [w for w in sorted_wordlist if w.startswith(prefix) and w.endswith(suffix)]


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
    Multiprocessing worker for missing/partial-word recovery.

    args: (words, variable_positions, first_word_chunk,
           remaining_cands_list, target_address)

      variable_positions  – list of word indices that are variable (? or pattern)
      first_word_chunk    – subset of the first position's candidate list
      remaining_cands_list – list[list[str]] of candidate lists for positions 1..N
      target_address      – optional address filter (None = no filter)
    """
    words, variable_positions, first_word_chunk, remaining_cands_list, target_address = args
    candidates = []
    checked = 0
    checksum_passed = 0

    pos0 = variable_positions[0]
    rest_positions = variable_positions[1:]
    trial = list(words)

    for w0 in first_word_chunk:
        trial[pos0] = w0
        if not rest_positions:
            checked += 1
            candidate = " ".join(trial)
            if validate_mnemonic(candidate)["valid"]:
                checksum_passed += 1
                if target_address is None or _first_address_matches(candidate, target_address):
                    candidates.append(candidate)
        else:
            for combo in product(*remaining_cands_list):
                for pos, w in zip(rest_positions, combo):
                    trial[pos] = w
                checked += 1
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
    Brute-force fill in variable positions in a partial BIP39 mnemonic.

    Variable positions are marked with one of:
      "?"       – fully unknown (searches all 2048 BIP39 words)
      "prefix*" – partial word with known prefix  (e.g. "aban*" → "abandon")
      "*suffix" – partial word with known suffix  (e.g. "*don"  → "abandon")
      "p*s"     – prefix AND suffix known         (e.g. "ab*on" → "abandon")

    Inputs
    ------
    mnemonic_with_q : str
        Mnemonic where variable positions use the syntax above.
    target_address : str | None
        Optional — filter results to candidates that derive this address.
        Without an address every checksum-valid candidate is returned;
        multiple results are possible.
    max_unknowns : int
        For pure-"?" inputs: hard cap on the number of "?" slots.
        Hard-capped at MAX_MISSING_WORDS (2).  Partial-pattern positions
        bypass this count check and are governed only by _SEARCH_SPACE_CAP.
    progress_callback : Callable[[int, int, int], None] | None
        Receives (checked_count, total_count, candidates_found).

    Returns
    -------
    dict with keys:
        candidates            : list[str]
        checked               : int
        checksum_passed       : int
        with_target           : bool
        truncated             : bool
        elapsed_time          : float
        search_space          : int   – total combinations searched
        candidates_per_position : dict[int, int]  – {word_index: n_candidates}
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

    # Identify variable positions: pure unknowns (?) and partial patterns (*)
    unknown_positions = [i for i, w in enumerate(words) if w == _UNKNOWN_TOKEN]
    partial_positions = [i for i, w in enumerate(words) if _WILDCARD in w and w != _UNKNOWN_TOKEN]
    variable_positions = sorted(set(unknown_positions) | set(partial_positions))
    has_partial = bool(partial_positions)

    # --- no variable positions: validate as-is ----------------------------
    if not variable_positions:
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
            "search_space": 1,
            "candidates_per_position": {},
        }

    # --- count cap: pure-? inputs keep the legacy MAX_MISSING_WORDS limit --
    if not has_partial and len(unknown_positions) > max_unknowns:
        raise ValueError(
            f"Input has {len(unknown_positions)} '?' placeholders, "
            f"exceeding max_unknowns={max_unknowns}."
        )

    wordlist = _english_wordlist()
    sorted_wordlist = sorted(wordlist)

    # Fixed (non-variable) positions must be valid BIP39 words
    fixed_words = [w for i, w in enumerate(words) if i not in set(variable_positions)]
    invalid_words = [w for w in fixed_words if w not in wordlist]
    if invalid_words:
        raise ValueError(
            f"Non-variable tokens contain words not in the BIP39 English wordlist: "
            f"{', '.join(invalid_words)}. Run suggest_typo_corrections first."
        )

    # --- build per-position candidate lists --------------------------------
    candidates_per_position: dict[int, list[str]] = {}
    for pos in variable_positions:
        token = words[pos]
        cands = _expand_pattern(token, sorted_wordlist)
        if not cands:
            raise ValueError(
                f"Pattern '{token}' at word position {pos + 1} matches no BIP39 words. "
                "Check your spelling or use '?' for a fully unknown word."
            )
        candidates_per_position[pos] = cands

    # --- search-space cap (applies to all inputs) -------------------------
    total_combinations = 1
    for cands in candidates_per_position.values():
        total_combinations *= len(cands)

    if total_combinations > _SEARCH_SPACE_CAP:
        raise ValueError(
            f"Search space of {total_combinations:,} combinations exceeds the cap of "
            f"{_SEARCH_SPACE_CAP:,}. Use prefix patterns (e.g. 'abc*') instead of '?' "
            "to narrow unknown positions."
        )

    # --- enumerate candidates using multiprocessing ----------------------
    pos0_candidates = candidates_per_position[variable_positions[0]]
    remaining_cands_list = [
        candidates_per_position[pos] for pos in variable_positions[1:]
    ]

    chunk_size = 128 if len(variable_positions) == 1 else 32
    chunks = [pos0_candidates[i:i + chunk_size] for i in range(0, len(pos0_candidates), chunk_size)]
    tasks = [
        (words, variable_positions, chunk, remaining_cands_list, target_address)
        for chunk in chunks
    ]

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
        "search_space": total_combinations,
        "candidates_per_position": {pos: len(cands) for pos, cands in candidates_per_position.items()},
    }


# ---------------------------------------------------------------------------
# 2. suggest_typo_corrections
# ---------------------------------------------------------------------------

def suggest_typo_corrections(mnemonic: str, max_suggestions: int = 5) -> dict:
    """
    Suggest BIP39-wordlist replacements for any misspelled words.

    Uses three complementary methods and merges results ranked by priority:
      1. Keyboard adjacency (QWERTY neighbour substitution) — exact match by
         definition; listed first if found.
      2. Phonetic (Soundex) — same-sounding words; catches vowel swap typos.
      3. Levenshtein edit distance — general spelling distance; catches
         insertions, deletions, transpositions.

    Each unknown word entry now includes a ``method`` field per suggestion so
    the UI can show the user *why* each candidate was chosen.
    """
    if not isinstance(mnemonic, str):
        raise ValueError("mnemonic must be a string")
    if not isinstance(max_suggestions, int) or max_suggestions < 1:
        raise ValueError("max_suggestions must be a positive integer")

    words = _normalize_mnemonic(mnemonic).split()
    wordlist = _english_wordlist()
    wordlist_set: frozenset[str] = frozenset(wordlist)
    soundex_idx = _get_soundex_index()
    unknown: list[dict] = []

    for i, w in enumerate(words):
        if w in wordlist_set:
            continue

        seen: dict[str, str] = {}  # candidate → method label

        # 1. Keyboard adjacency
        for cand in _keyboard_typos(w, wordlist_set):
            seen.setdefault(cand, "keyboard")

        # 2. Phonetic (Soundex)
        for cand in soundex_idx.get(_soundex(w), []):
            seen.setdefault(cand, "phonetic")

        # 3. Levenshtein — fill remaining slots
        if len(seen) < max_suggestions:
            scored = sorted(
                ((_levenshtein(w, cand), cand) for cand in wordlist if cand not in seen),
                key=lambda t: (t[0], t[1]),
            )
            for _, cand in scored:
                seen.setdefault(cand, "edit-distance")
                if len(seen) >= max_suggestions * 3:
                    break

        # Build ordered suggestion list (keyboard first, then phonetic, then edit-distance)
        ordered: list[dict] = []
        for method_priority in ("keyboard", "phonetic", "edit-distance"):
            for cand, method in seen.items():
                if method == method_priority:
                    ordered.append({"word": cand, "method": method})

        suggestions_full = ordered[:max_suggestions]
        suggestions = [s["word"] for s in suggestions_full]

        unknown.append({
            "word": w,
            "position": i,
            "suggestions": suggestions,
            "suggestions_detail": suggestions_full,
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


# ---------------------------------------------------------------------------
# 5. recover_extra_word
# ---------------------------------------------------------------------------

def recover_extra_word(
    mnemonic: str,
    target_address: str | None = None,
    progress_callback: Callable[[int, int, int], None] | None = None,
) -> dict:
    """
    Try removing each word one at a time to find a valid BIP39 mnemonic.

    For clients who wrote down one extra word by mistake (N+1 words recorded,
    one is spurious). Tries every deletion and keeps those that pass checksum.

    Parameters
    ----------
    mnemonic       : str  — the over-length mnemonic (e.g. 13 words for a 12-word seed).
    target_address : str  — optional address filter; if supplied, only candidates
                           that derive this address are returned.
    progress_callback : callable(checked, total, found)

    Returns
    -------
    dict with keys:
        candidates   : list[dict]  — {mnemonic, removed_word, position}
        checked      : int
        elapsed_time : float
        with_target  : bool
    """
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ValueError("mnemonic must be a non-empty string")

    words = _split_normalized(mnemonic)
    n = len(words)

    valid_lengths = {12, 15, 18, 21, 24}
    target_length = n - 1
    if target_length not in valid_lengths:
        raise ValueError(
            f"Removing one word from {n} words gives {target_length} words, "
            f"which is not a valid BIP39 length (12/15/18/21/24). "
            "Provide a mnemonic with exactly one extra word."
        )

    start_time = time.time()
    candidates: list[dict] = []
    checked = 0

    for i in range(n):
        trial_words = words[:i] + words[i + 1:]
        candidate = " ".join(trial_words)
        v = validate_mnemonic(candidate)
        checked += 1
        if v["valid"]:
            if target_address is None or _first_address_matches(candidate, target_address):
                candidates.append({
                    "mnemonic": candidate,
                    "removed_word": words[i],
                    "position": i + 1,  # 1-based for display
                })

        if progress_callback:
            progress_callback(checked, n, len(candidates))

    return {
        "candidates": candidates,
        "checked": checked,
        "elapsed_time": time.time() - start_time,
        "with_target": target_address is not None,
    }


# ---------------------------------------------------------------------------
# 6. recover_with_typos  (BTCRecover --typos N equivalent for BIP39 seeds)
# ---------------------------------------------------------------------------

# Cap on total substitution search space for typo recovery.
_TYPO_SEARCH_CAP = 2_000_000


def _word_typo_candidates(
    word: str, wordlist_set: frozenset[str], soundex_idx: dict
) -> list[str]:
    """
    Return BIP39 word alternatives for a potentially mistyped word, combining:
      - keyboard-adjacent substitutions (QWERTY, one char)
      - phonetic matches (Soundex)
      - edit-distance ≤ 2 against the full wordlist
    """
    seen: dict[str, None] = {}

    for w in _keyboard_typos(word, wordlist_set):
        seen.setdefault(w, None)

    for w in soundex_idx.get(_soundex(word), []):
        seen.setdefault(w, None)

    for w in wordlist_set:
        if w not in seen and _levenshtein(word, w) <= 2:
            seen.setdefault(w, None)

    return list(seen.keys())


def _typo_recovery_worker(args: tuple) -> dict:
    """
    Multiprocessing worker for recover_with_typos.
    args: (template_words, typo_positions, position_candidates, target_address)
    """
    template_words, typo_positions, position_candidates, target_address = args
    local_candidates: list[str] = []
    checked = 0
    trial = list(template_words)

    for combo in product(*position_candidates):
        for pos, w in zip(typo_positions, combo):
            trial[pos] = w
        checked += 1
        candidate = " ".join(trial)
        if validate_mnemonic(candidate)["valid"]:
            if target_address is None or _first_address_matches(candidate, target_address):
                local_candidates.append(candidate)

    return {"candidates": local_candidates, "checked": checked}


def recover_with_typos(
    mnemonic: str,
    max_typo_words: int = 1,
    target_address: str | None = None,
    progress_callback: Callable[[int, int, int], None] | None = None,
) -> dict:
    """
    BTCRecover ``--typos N`` equivalent for BIP39 mnemonics.

    For each combination of up to ``max_typo_words`` positions, substitute
    keyboard-adjacent, phonetically-similar, and edit-distance-≤2 alternatives
    from the BIP39 wordlist and test the resulting mnemonic's checksum.

    Parameters
    ----------
    mnemonic       : str  — the (possibly misspelled) mnemonic to recover.
    max_typo_words : int  — max simultaneous wrong positions to correct (1 or 2).
    target_address : str  — optional address filter.
    progress_callback : callable(checked, total, found)

    Returns
    -------
    dict with keys:
        candidates   : list[str]
        checked      : int
        elapsed_time : float
        with_target  : bool
        truncated    : bool
        search_space : int
    """
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ValueError("mnemonic must be a non-empty string")
    if not isinstance(max_typo_words, int) or max_typo_words < 1:
        raise ValueError("max_typo_words must be a positive integer")
    if max_typo_words > 2:
        raise ValueError("max_typo_words is capped at 2 to keep runtimes manageable")

    words = _split_normalized(mnemonic)
    wordlist_set = frozenset(_english_wordlist())
    soundex_idx = _get_soundex_index()

    # Build per-position alternative lists
    per_position: dict[int, list[str]] = {}
    for i, w in enumerate(words):
        alts = _word_typo_candidates(w, wordlist_set, soundex_idx)
        if alts:
            per_position[i] = alts

    if not per_position:
        return {
            "candidates": [],
            "checked": 0,
            "elapsed_time": 0.0,
            "with_target": target_address is not None,
            "truncated": False,
            "search_space": 0,
        }

    # Build tasks: one task per (position_subset) combination
    tasks = []
    total_search_space = 0

    for n_typos in range(1, max_typo_words + 1):
        for pos_combo in combinations(sorted(per_position.keys()), n_typos):
            pos_cands = [per_position[p] for p in pos_combo]
            combo_count = 1
            for pc in pos_cands:
                combo_count *= len(pc)
            total_search_space += combo_count
            tasks.append((list(pos_combo), pos_cands))

    if total_search_space > _TYPO_SEARCH_CAP:
        raise ValueError(
            f"Typo recovery search space ({total_search_space:,}) exceeds the "
            f"{_TYPO_SEARCH_CAP:,} limit. Use max_typo_words=1 or provide a "
            "target address to stop early on the first confirmed match."
        )

    start_time = time.time()
    local_candidates: list[str] = []
    checked = 0
    truncated = False
    num_workers = max(1, multiprocessing.cpu_count() - 1)

    worker_tasks = [
        (words, pos_combo, pos_cands, target_address)
        for pos_combo, pos_cands in tasks
    ]

    with multiprocessing.Pool(num_workers) as pool:
        for res in pool.imap_unordered(_typo_recovery_worker, worker_tasks):
            checked += res["checked"]
            for cand in res["candidates"]:
                if cand not in local_candidates:
                    local_candidates.append(cand)
                    if len(local_candidates) >= _MAX_RETURNED_CANDIDATES:
                        truncated = True

            if progress_callback:
                progress_callback(checked, total_search_space, len(local_candidates))

            if truncated:
                pool.terminate()
                break

    return {
        "candidates": local_candidates,
        "checked": checked,
        "elapsed_time": time.time() - start_time,
        "with_target": target_address is not None,
        "truncated": truncated,
        "search_space": total_search_space,
    }


# ---------------------------------------------------------------------------
# 7. Multi-language BIP39 support
# ---------------------------------------------------------------------------

_SUPPORTED_LANGUAGES: list[str] = [
    "english",
    "chinese_simplified",
    "chinese_traditional",
    "french",
    "italian",
    "japanese",
    "korean",
    "spanish",
    "czech",
    "portuguese",
]


def list_bip39_languages() -> list[str]:
    """Return all BIP39 language codes supported by the mnemonic package."""
    return list(_SUPPORTED_LANGUAGES)


def validate_mnemonic_multilang(mnemonic: str, language: str = "english") -> dict:
    """
    Validate a BIP39 mnemonic in the specified language.

    Parameters
    ----------
    mnemonic : str  — space-separated mnemonic phrase.
    language : str  — one of list_bip39_languages().

    Returns
    -------
    dict with keys:
        valid      : bool
        language   : str
        word_count : int
        error      : str | None
    """
    if language not in _SUPPORTED_LANGUAGES:
        raise ValueError(
            f"Unsupported language '{language}'. "
            f"Choose from: {', '.join(_SUPPORTED_LANGUAGES)}"
        )

    words = mnemonic.strip().split()
    word_count = len(words)

    if language == "english":
        result = validate_mnemonic(mnemonic)
        return {
            "valid": result["valid"],
            "language": "english",
            "word_count": word_count,
            "error": result.get("error"),
        }

    from mnemonic import Mnemonic
    m = Mnemonic(language)
    try:
        valid = m.check(mnemonic.strip())
    except Exception as exc:
        return {"valid": False, "language": language, "word_count": word_count, "error": str(exc)}

    return {
        "valid": valid,
        "language": language,
        "word_count": word_count,
        "error": None if valid else "Invalid checksum or unrecognised words",
    }
