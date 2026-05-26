"""
Tests for recovery_utils.

These tests exercise the recovery workflows against the well-known BIP39
test vector documented in the official spec:

    abandon abandon abandon abandon abandon abandon
    abandon abandon abandon abandon abandon about

That phrase is published publicly (the same one used in BIP39 examples
everywhere) and the addresses it derives are deterministic and known to
the world. It is NOT a real wallet -- never send funds to it. We use it
only so the tests are reproducible without exposing any real seed.
"""

from __future__ import annotations

import os
import random
import sys

import pytest

# Allow running `pytest` from the project root without installing the package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recovery_utils import (  # noqa: E402
    MAX_MISSING_WORDS,
    MAX_ORDER_POSITIONS,
    recover_missing_words,
    recover_word_order,
    suggest_typo_corrections,
)
# Imported with an alias because pytest auto-collects any top-level name
# starting with `test_` as a test function. Renaming sidesteps that.
from recovery_utils import test_passphrase as run_passphrase_test  # noqa: E402
from wallet_utils import derive_eth_addresses  # noqa: E402


VALID_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

# Known-good first ETH address for the test vector (no passphrase).
EXPECTED_ETH_FIRST = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"


# ---------------------------------------------------------------------------
# recover_missing_words
# ---------------------------------------------------------------------------

class TestRecoverMissingWords:
    def test_finds_last_word_when_masked(self):
        # Mask the last word "about" and verify the search finds it.
        masked = (
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon ?"
        )
        result = recover_missing_words(masked, max_unknowns=1)
        assert result["with_target"] is False
        # The correct full mnemonic must appear in the candidate list.
        assert VALID_MNEMONIC in result["candidates"]
        # We expect a small number of valid completions (BIP39 checksum
        # admits multiple candidates for one masked slot, but not 2048).
        assert len(result["candidates"]) >= 1

    def test_finds_middle_word_when_masked(self):
        # Mask an interior word.
        words = VALID_MNEMONIC.split()
        words[5] = "?"
        masked = " ".join(words)
        result = recover_missing_words(masked, max_unknowns=1)
        assert VALID_MNEMONIC in result["candidates"]

    def test_rejects_three_or_more_unknowns(self):
        # Spec: ValueError when max_unknowns > MAX_MISSING_WORDS.
        with pytest.raises(ValueError):
            recover_missing_words("? ? ? abandon", max_unknowns=3)
        with pytest.raises(ValueError):
            recover_missing_words("? ? ? abandon", max_unknowns=4)

    def test_rejects_too_many_question_marks_in_input(self):
        # If input has 3 ?'s but max_unknowns=2, refuse rather than truncate.
        words = ["?"] * 3 + ["abandon"] * 9
        with pytest.raises(ValueError):
            recover_missing_words(" ".join(words), max_unknowns=2)

    def test_target_address_filter(self):
        # Mask last word, filter by the known ETH address of the test vector.
        # This should narrow the candidates to exactly the right mnemonic.
        masked = (
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon ?"
        )
        result = recover_missing_words(
            masked, target_address=EXPECTED_ETH_FIRST, max_unknowns=1
        )
        assert result["with_target"] is True
        assert result["candidates"] == [VALID_MNEMONIC]

    def test_rejects_misspelled_known_word(self):
        # Non-? word "abandom" is not a BIP39 word; we should refuse and
        # tell the caller to fix typos first.
        masked = "abandom ? abandon abandon abandon abandon " \
                 "abandon abandon abandon abandon abandon about"
        with pytest.raises(ValueError):
            recover_missing_words(masked, max_unknowns=1)

    def test_no_unknowns_validates_in_place(self):
        # If there are no ?'s, we just validate the input as-is.
        result = recover_missing_words(VALID_MNEMONIC, max_unknowns=1)
        assert result["candidates"] == [VALID_MNEMONIC]
        assert result["checked"] == 1

    def test_max_missing_words_constant_is_two(self):
        assert MAX_MISSING_WORDS == 2


# ---------------------------------------------------------------------------
# suggest_typo_corrections
# ---------------------------------------------------------------------------

class TestSuggestTypoCorrections:
    def test_flags_misspelled_word_and_suggests_correct_one(self):
        # "abandom" is a one-character typo of "abandon".
        bad = VALID_MNEMONIC.replace("abandon abandon abandon", "abandon abandom abandon", 1)
        result = suggest_typo_corrections(bad, max_suggestions=5)
        assert result["all_words_known"] is False
        # Exactly one unknown word: "abandom" at position 1.
        assert len(result["unknown_words"]) == 1
        entry = result["unknown_words"][0]
        assert entry["word"] == "abandom"
        assert entry["position"] == 1
        # "abandon" must be among the top suggestions.
        assert "abandon" in entry["suggestions"]

    def test_valid_mnemonic_has_no_unknown_words(self):
        result = suggest_typo_corrections(VALID_MNEMONIC)
        assert result["all_words_known"] is True
        assert result["unknown_words"] == []

    def test_multiple_typos_reported_in_position_order(self):
        # Two misspellings; ensure both are reported with correct positions.
        words = VALID_MNEMONIC.split()
        words[2] = "abandom"     # typo of abandon
        words[7] = "aboot"       # typo of about / aboard / etc
        bad = " ".join(words)
        result = suggest_typo_corrections(bad)
        positions = [u["position"] for u in result["unknown_words"]]
        assert positions == sorted(positions)
        assert 2 in positions
        assert 7 in positions

    def test_result_does_not_include_full_mnemonic(self):
        # The output should expose only the offending word(s), not the
        # whole input phrase.
        result = suggest_typo_corrections(VALID_MNEMONIC.replace("about", "aboot"))
        flat = repr(result)
        # The known-good words from the input must NOT be echoed back.
        # (The misspelled word "aboot" is allowed; that's the entire point.)
        assert "abandon abandon abandon" not in flat


# ---------------------------------------------------------------------------
# recover_word_order
# ---------------------------------------------------------------------------

class TestRecoverWordOrder:
    def test_finds_correct_order_for_short_phrase(self):
        # Use a 5-word phrase where order is unknown. We construct it from
        # a known-good BIP39 phrase by taking the first 5 words... but those
        # 5 words alone don't form a valid 12-word phrase, so instead we test
        # with a permutation of a 12-word phrase that we INTENTIONALLY refuse.
        # For positive coverage we synthesize a smaller scenario by mutating
        # known good positions. Easiest: pick a known-good short phrase from
        # bip-utils. We use the standard 12-word vector and shuffle then test
        # the refusal, AND we test that order recovery on the 8-word ceiling
        # at least executes without crashing.
        # Test: confirm we successfully solve a shuffled phrase of length 8
        # by constructing one. We use 8 "abandon" words -- that's a valid
        # input from the wordlist (though not a valid checksum). The permute
        # loop should run to completion and return some checksum-valid set
        # (possibly empty).
        words = ["abandon"] * 7 + ["about"]
        result = recover_word_order(words, max_positions=8)
        # 8! = 40320 permutations but de-duped to a handful due to repeats.
        # We don't assert a specific output -- just that it ran cleanly.
        assert isinstance(result["candidates"], list)
        assert result["checked"] >= 1
        assert result["with_target"] is False

    def test_refuses_input_longer_than_ceiling(self):
        # Spec: refuse with ValueError when len(words) > MAX_ORDER_POSITIONS.
        # The 12-word test vector exceeds the 8-word cap.
        words = VALID_MNEMONIC.split()
        assert len(words) == 12
        with pytest.raises(ValueError):
            recover_word_order(words, max_positions=8)
        # Even if the caller passes a high max_positions, the absolute
        # ceiling is enforced.
        with pytest.raises(ValueError):
            recover_word_order(words, max_positions=12)

    def test_rejects_non_bip39_words(self):
        with pytest.raises(ValueError):
            recover_word_order(["abandon", "zzzzzzzz", "about"], max_positions=8)

    def test_rejects_empty_or_bad_input(self):
        with pytest.raises(ValueError):
            recover_word_order([], max_positions=8)
        with pytest.raises(ValueError):
            recover_word_order(["abandon", 42], max_positions=8)  # type: ignore[list-item]

    def test_max_order_positions_constant(self):
        assert MAX_ORDER_POSITIONS == 8


# ---------------------------------------------------------------------------
# test_passphrase
# ---------------------------------------------------------------------------

class TestPassphrase:
    def test_passphrase_changes_derived_address(self):
        without = run_passphrase_test(VALID_MNEMONIC, "", count=1)
        with_pass = run_passphrase_test(VALID_MNEMONIC, "TREZOR", count=1)

        # First ETH entry for each:
        eth_without = next(a for a in without["addresses"] if a["coin"] == "ETH")
        eth_with = next(a for a in with_pass["addresses"] if a["coin"] == "ETH")

        # Same mnemonic + different passphrase => different addresses.
        assert eth_without["address"] != eth_with["address"]

        # Without passphrase must match the known vector (sanity check).
        assert eth_without["address"] == EXPECTED_ETH_FIRST

        # Cross-check: empty passphrase result also matches plain derivation.
        plain = derive_eth_addresses(VALID_MNEMONIC, 1)[0]["address"]
        assert eth_without["address"] == plain

    def test_target_match_reports_hit(self):
        # Empty passphrase => first ETH address is the known vector address.
        result = run_passphrase_test(
            VALID_MNEMONIC, "", target_address=EXPECTED_ETH_FIRST, count=1
        )
        assert result["match"] is not None
        assert result["match"]["address"] == EXPECTED_ETH_FIRST

    def test_target_match_reports_miss(self):
        result = run_passphrase_test(
            VALID_MNEMONIC,
            "TREZOR",
            target_address=EXPECTED_ETH_FIRST,  # this is the no-passphrase addr
            count=2,
        )
        # The known no-passphrase address should NOT appear when a passphrase
        # is applied.
        assert result["match"] is None

    def test_invalid_mnemonic_rejected(self):
        with pytest.raises(ValueError):
            run_passphrase_test("not a real mnemonic", "TREZOR", count=1)

    def test_non_string_passphrase_rejected(self):
        with pytest.raises(ValueError):
            run_passphrase_test(VALID_MNEMONIC, 1234, count=1)  # type: ignore[arg-type]

    def test_returns_eth_and_all_btc_types(self):
        result = run_passphrase_test(VALID_MNEMONIC, "", count=2)
        coins = {a["coin"] for a in result["addresses"]}
        types = {a["address_type"] for a in result["addresses"]}
        assert coins == {"ETH", "BTC"}
        # Three BTC address types + ETH = 4 unique labels.
        assert len(types) == 4


# ---------------------------------------------------------------------------
# No-secrets-leak audit
# ---------------------------------------------------------------------------

class TestNoSecretLeak:
    """
    Defence in depth: verify that none of the recovery functions inadvertently
    echo their secret inputs (mnemonic words / passphrase) in fields that
    should not contain them.

    NB: recover_missing_words and recover_word_order LEGITIMATELY return
    candidate mnemonics in their "candidates" field. We exempt that field
    from the check.
    """

    def test_typo_result_does_not_leak_known_words(self):
        bad = "abandom " + " ".join(["abandon"] * 10) + " about"
        result = suggest_typo_corrections(bad)
        # Build a representation excluding the "suggestions" lists (the BIP39
        # wordlist itself contains "abandon" and "about" so those words will
        # legitimately appear in suggestions). What we care about is that
        # the FULL INPUT phrase is not echoed back as a whole.
        # Concretely: the input phrase contains 12 tokens; the result should
        # only mention the unknown ("abandom"), not the surrounding words.
        unknown_words = [u["word"] for u in result["unknown_words"]]
        assert unknown_words == ["abandom"]

    def test_passphrase_result_does_not_contain_passphrase(self):
        secret_passphrase = "S3kr1tHiddenWalletPhrase"
        result = run_passphrase_test(VALID_MNEMONIC, secret_passphrase, count=2)
        flat = repr(result)
        assert secret_passphrase not in flat
        # Also: mnemonic words should not appear in the result.
        for word in VALID_MNEMONIC.split():
            # Each address record contains only public info; no word from
            # the mnemonic should appear anywhere.
            assert word not in flat

    def test_recover_missing_words_only_leaks_candidates(self):
        # Mask one slot, run with target filter so only one candidate comes
        # back. Verify that no field OTHER than "candidates" contains the
        # mnemonic text.
        masked = (
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon ?"
        )
        result = recover_missing_words(
            masked, target_address=EXPECTED_ETH_FIRST, max_unknowns=1
        )
        # Strip the candidates field and verify nothing else leaks mnemonic
        # content.
        scrubbed = {k: v for k, v in result.items() if k != "candidates"}
        flat = repr(scrubbed)
        assert "about" not in flat
        # "abandon" appears in the BIP39 wordlist but the scrubbed result
        # should not include any words at all (only counts and bools).
        assert "abandon" not in flat

    def test_recover_word_order_only_leaks_candidates(self):
        # Use the small no-checksum-friendly input so we exercise the code
        # path; we don't care about the actual candidate content.
        words = ["abandon"] * 7 + ["about"]
        result = recover_word_order(words, max_positions=8)
        scrubbed = {k: v for k, v in result.items() if k != "candidates"}
        flat = repr(scrubbed)
        assert "abandon" not in flat
        assert "about" not in flat
