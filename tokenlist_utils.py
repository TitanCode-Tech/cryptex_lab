"""
tokenlist_utils.py
------------------
BTCRecover-compatible tokenlist parser and candidate generator, plus a
character-set brute-force generator for short passphrases.

Tokenlist format supported:
  #  comment lines (ignored)
  + token1 token2   required line — one token always included in every guess
  ^token            begin-anchored — token placed first in the password
  token$            end-anchored   — token placed last in the password
  token1 token2     optional line  — mutually exclusive; one is chosen or skipped
  %d %2d %3d %4d   digit wildcards  (0-9, 00-99, 000-999, 0000-9999)
  %a                single lowercase letter (a-z)
  %A                single uppercase letter (A-Z)
  %n                single alphanumeric (a-z, 0-9)
  %y                single symbol (!@#$%^&*()-_=+)

Combination logic:
  - All required lines contribute exactly one token each, always present.
  - Optional lines: choose min_tokens … max_tokens of them; pick one token
    from each chosen line.
  - Non-anchored tokens are permuted; begin/end anchors are fixed at
    start/end respectively.
  - Tokens are joined with the caller-supplied separator.
  - Result is capped at MAX_CANDIDATES to keep BIP38 runtimes sane.
"""

from __future__ import annotations

import itertools
import math
import re
import string
from dataclasses import dataclass, field

MAX_CANDIDATES = 50_000

_WILDCARD_SETS: dict[str, str] = {
    "d": string.digits,
    "a": string.ascii_lowercase,
    "A": string.ascii_uppercase,
    "n": string.ascii_lowercase + string.digits,
    "N": string.ascii_uppercase + string.digits,
    "y": "!@#$%^&*()-_=+",
}

_WILDCARD_RE = re.compile(r"%([1-4]?)([dDaAnNyY])")


# ---------------------------------------------------------------------------
# Wildcard expansion
# ---------------------------------------------------------------------------

def _expand_wildcards(token: str) -> list[str]:
    """
    Expand wildcard sequences in a single token string.
    Returns a list of all expanded forms (capped per-token at 10,000).
    """
    if "%" not in token:
        return [token]

    parts: list[list[str]] = []
    last = 0

    for m in _WILDCARD_RE.finditer(token):
        literal = token[last:m.start()]
        if literal:
            parts.append([literal])

        count = int(m.group(1)) if m.group(1) else 1
        charset = _WILDCARD_SETS.get(m.group(2), _WILDCARD_SETS.get(m.group(2).lower(), "?"))

        if count == 1:
            parts.append(list(charset))
        else:
            expanded = ["".join(p) for p in itertools.product(charset, repeat=count)]
            parts.append(expanded[:10_000])
        last = m.end()

    tail = token[last:]
    if tail:
        parts.append([tail])

    if not parts:
        return [token]

    total = 1
    for p in parts:
        total *= len(p)
        if total > 10_000:
            return [token]

    return ["".join(combo) for combo in itertools.product(*parts)]


# ---------------------------------------------------------------------------
# Tokenlist data model
# ---------------------------------------------------------------------------

@dataclass
class TokenLine:
    required: bool
    options: list[str]
    begin_anchored: bool = False
    end_anchored: bool = False


def _parse_line(raw: str) -> TokenLine | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None

    required = False
    if line.startswith("+ ") or line.startswith("+\t"):
        required = True
        line = line[2:].strip()

    raw_tokens = line.split()
    expanded: list[str] = []
    begin_anchored = False
    end_anchored = False

    for tok in raw_tokens:
        ba = tok.startswith("^")
        ea = tok.endswith("$")
        core = tok.lstrip("^")
        if ea:
            core = core[:-1]
        if ba:
            begin_anchored = True
        if ea:
            end_anchored = True
        expanded.extend(_expand_wildcards(core))

    if not expanded:
        return None

    return TokenLine(required, expanded, begin_anchored, end_anchored)


def parse_tokenlist(text: str) -> list[TokenLine]:
    result = []
    for raw in text.splitlines():
        tl = _parse_line(raw)
        if tl:
            result.append(tl)
    return result


# ---------------------------------------------------------------------------
# Candidate generation
# ---------------------------------------------------------------------------

def generate_tokenlist_candidates(
    text: str,
    min_tokens: int = 1,
    max_tokens: int = 3,
    separator: str = "",
    max_results: int = MAX_CANDIDATES,
) -> list[str]:
    """
    Generate password candidates from a tokenlist.

    Parameters
    ----------
    text         Raw tokenlist text.
    min_tokens   Minimum optional token lines to include per guess.
    max_tokens   Maximum optional token lines to include per guess.
    separator    String placed between tokens (e.g. "" / " " / "-").
    max_results  Hard cap on returned candidates.
    """
    token_lines = parse_tokenlist(text)
    if not token_lines:
        return []

    required_lines = [tl for tl in token_lines if tl.required]
    optional_lines = [tl for tl in token_lines if not tl.required]

    seen: dict[str, None] = {}

    def add(cand: str) -> bool:
        if len(seen) >= max_results:
            return False
        seen.setdefault(cand, None)
        return True

    for n_opt in range(0, min(max_tokens, len(optional_lines)) + 1):
        if n_opt < min_tokens and len(required_lines) == 0:
            continue

        for opt_subset in itertools.combinations(range(len(optional_lines)), n_opt):
            chosen_opt = [optional_lines[i] for i in opt_subset]
            all_lines = required_lines + chosen_opt

            if not all_lines:
                continue

            option_lists = [tl.options for tl in all_lines]

            for token_choice in itertools.product(*option_lists):
                begin_toks: list[str] = []
                end_toks: list[str] = []
                free_toks: list[str] = []

                for tok, line in zip(token_choice, all_lines):
                    if line.begin_anchored:
                        begin_toks.append(tok)
                    elif line.end_anchored:
                        end_toks.append(tok)
                    else:
                        free_toks.append(tok)

                for perm in itertools.permutations(free_toks):
                    full = begin_toks + list(perm) + end_toks
                    candidate = separator.join(full)
                    if not add(candidate):
                        return list(seen.keys())

    return list(seen.keys())


def estimate_tokenlist_count(
    text: str,
    min_tokens: int = 1,
    max_tokens: int = 3,
    separator: str = "",
) -> int:
    """Estimate candidate count without generating them."""
    token_lines = parse_tokenlist(text)
    if not token_lines:
        return 0

    required_lines = [tl for tl in token_lines if tl.required]
    optional_lines = [tl for tl in token_lines if not tl.required]

    total = 0
    for n_opt in range(0, min(max_tokens, len(optional_lines)) + 1):
        if n_opt < min_tokens and len(required_lines) == 0:
            continue
        for opt_subset in itertools.combinations(range(len(optional_lines)), n_opt):
            chosen_opt = [optional_lines[i] for i in opt_subset]
            all_lines = required_lines + chosen_opt
            if not all_lines:
                continue

            option_combos = 1
            for tl in all_lines:
                option_combos *= len(tl.options)

            n_free = sum(
                1 for tl in all_lines if not tl.begin_anchored and not tl.end_anchored
            )
            perms = math.factorial(n_free)
            total += option_combos * perms
            if total > 10_000_000:
                return total

    return total


# ---------------------------------------------------------------------------
# Brute-force candidate generation
# ---------------------------------------------------------------------------

BRUTE_FORCE_CHARSETS: dict[str, str] = {
    "lowercase":  string.ascii_lowercase,
    "uppercase":  string.ascii_uppercase,
    "digits":     string.digits,
    "symbols":    "!@#$%^&*()-_=+[]{}|;:,.<>?",
}

BRUTE_FORCE_MAX = 50_000


def generate_brute_force_candidates(
    charsets: list[str],
    min_len: int,
    max_len: int,
    prefix: str = "",
    suffix: str = "",
    max_results: int = BRUTE_FORCE_MAX,
) -> list[str]:
    """
    Generate all strings of lengths min_len … max_len from the given charsets,
    optionally wrapped with a fixed prefix and/or suffix.

    Returns up to max_results candidates.
    """
    charset = "".join(dict.fromkeys(
        "".join(BRUTE_FORCE_CHARSETS[k] for k in charsets if k in BRUTE_FORCE_CHARSETS)
    ))
    if not charset:
        return []

    candidates: list[str] = []
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            candidates.append(prefix + "".join(combo) + suffix)
            if len(candidates) >= max_results:
                return candidates
    return candidates


def estimate_brute_force_count(
    charsets: list[str],
    min_len: int,
    max_len: int,
    prefix: str = "",
    suffix: str = "",
) -> int:
    """Estimate brute-force candidate count without generating."""
    charset_len = len(set(
        "".join(BRUTE_FORCE_CHARSETS[k] for k in charsets if k in BRUTE_FORCE_CHARSETS)
    ))
    if charset_len == 0:
        return 0
    total = 0
    for length in range(min_len, max_len + 1):
        total += charset_len ** length
        if total > 1_000_000_000:
            return total
    return total
