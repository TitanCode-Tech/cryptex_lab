"""
Tests for wallet_utils.

These tests use the well-known BIP39 test vector:

    abandon abandon abandon abandon abandon abandon
    abandon abandon abandon abandon abandon about

This vector is documented in the official BIP39 specification and the
corresponding addresses are deterministic and publicly known. It is NOT a
real wallet; do NOT send funds to it. We use it solely so the tests are
reproducible without needing private data.
"""

from __future__ import annotations

import os
import sys

import pytest

# Allow running `pytest` from the project root without installing the package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wallet_utils import (  # noqa: E402
    BTC_ADDRESS_TYPES,
    MAX_ADDRESSES_PER_REQUEST,
    build_report,
    derive_btc_addresses,
    derive_eth_addresses,
    validate_mnemonic,
)


VALID_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

# Known-good first address for each derivation path with the above mnemonic.
# Cross-checked against bip-utils and the Ian Coleman BIP39 tool.
EXPECTED_FIRST = {
    "eth": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
    "btc_legacy": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    "btc_segwit": "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
    "btc_native_segwit": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
}


# ---------------------------------------------------------------------------
# validate_mnemonic
# ---------------------------------------------------------------------------

class TestValidate:
    def test_valid_phrase(self):
        r = validate_mnemonic(VALID_MNEMONIC)
        assert r["valid"] is True
        assert r["word_count"] == 12
        assert r["word_count_valid"] is True
        assert r["words_in_wordlist"] is True
        assert r["checksum_valid"] is True

    def test_extra_whitespace_is_tolerated(self):
        messy = "   " + VALID_MNEMONIC.replace(" ", "    ") + "\n"
        assert validate_mnemonic(messy)["valid"] is True

    def test_case_insensitive(self):
        assert validate_mnemonic(VALID_MNEMONIC.upper())["valid"] is True

    def test_wrong_word_count(self):
        r = validate_mnemonic("abandon abandon abandon")
        assert r["valid"] is False
        assert r["word_count"] == 3
        assert r["word_count_valid"] is False

    def test_word_not_in_wordlist(self):
        # 12 tokens but one is not a BIP39 word.
        bad = VALID_MNEMONIC.replace("about", "zzzzzzzzz")
        r = validate_mnemonic(bad)
        assert r["valid"] is False
        assert r["words_in_wordlist"] is False
        assert r["checksum_valid"] is False

    def test_bad_checksum(self):
        # All real words, correct count, but the checksum is wrong because
        # the last word doesn't satisfy the entropy hash.
        bad = "abandon " * 12
        r = validate_mnemonic(bad.strip())
        assert r["word_count"] == 12
        assert r["words_in_wordlist"] is True
        assert r["checksum_valid"] is False
        assert r["valid"] is False

    def test_empty_string(self):
        r = validate_mnemonic("")
        assert r["valid"] is False
        assert r["word_count"] == 0

    def test_non_string_input(self):
        r = validate_mnemonic(None)  # type: ignore[arg-type]
        assert r["valid"] is False

    def test_result_does_not_contain_mnemonic(self):
        # Defence in depth: ensure none of the result fields ever echo the
        # input mnemonic back at the caller.
        r = validate_mnemonic(VALID_MNEMONIC)
        flat = repr(r)
        assert "abandon" not in flat
        assert "about" not in flat


# ---------------------------------------------------------------------------
# derive_eth_addresses
# ---------------------------------------------------------------------------

class TestEth:
    def test_first_address_matches_known_vector(self):
        rows = derive_eth_addresses(VALID_MNEMONIC, 1)
        assert rows[0]["address"] == EXPECTED_FIRST["eth"]
        assert rows[0]["path"] == "m/44'/60'/0'/0/0"
        assert rows[0]["coin"] == "ETH"

    def test_multiple_addresses_unique(self):
        rows = derive_eth_addresses(VALID_MNEMONIC, 5)
        assert len(rows) == 5
        assert len({r["address"] for r in rows}) == 5
        # Paths increment by index.
        assert [r["path"] for r in rows] == [
            f"m/44'/60'/0'/0/{i}" for i in range(5)
        ]

    def test_invalid_mnemonic_rejected(self):
        with pytest.raises(ValueError):
            derive_eth_addresses("not a real mnemonic", 1)

    def test_count_zero_rejected(self):
        with pytest.raises(ValueError):
            derive_eth_addresses(VALID_MNEMONIC, 0)

    def test_count_clamped_to_max(self):
        rows = derive_eth_addresses(VALID_MNEMONIC, MAX_ADDRESSES_PER_REQUEST + 99)
        assert len(rows) == MAX_ADDRESSES_PER_REQUEST


# ---------------------------------------------------------------------------
# derive_btc_addresses
# ---------------------------------------------------------------------------

class TestBtc:
    @pytest.mark.parametrize(
        "addr_type,expected_first,expected_path_prefix",
        [
            ("legacy", EXPECTED_FIRST["btc_legacy"], "m/44'/0'/0'/0/"),
            ("segwit", EXPECTED_FIRST["btc_segwit"], "m/49'/0'/0'/0/"),
            ("native_segwit", EXPECTED_FIRST["btc_native_segwit"], "m/84'/0'/0'/0/"),
        ],
    )
    def test_known_vectors(self, addr_type, expected_first, expected_path_prefix):
        rows = derive_btc_addresses(VALID_MNEMONIC, addr_type, 1)
        assert rows[0]["address"] == expected_first
        assert rows[0]["path"] == expected_path_prefix + "0"
        assert rows[0]["coin"] == "BTC"

    def test_all_supported_types_are_covered(self):
        assert set(BTC_ADDRESS_TYPES) == {"legacy", "segwit", "native_segwit"}

    def test_unknown_type_rejected(self):
        with pytest.raises(ValueError):
            derive_btc_addresses(VALID_MNEMONIC, "taproot", 1)

    def test_invalid_mnemonic_rejected(self):
        with pytest.raises(ValueError):
            derive_btc_addresses("not a real mnemonic", "legacy", 1)


# ---------------------------------------------------------------------------
# build_report
# ---------------------------------------------------------------------------

class TestReport:
    def _sample_rows(self):
        return derive_eth_addresses(VALID_MNEMONIC, 2) + derive_btc_addresses(
            VALID_MNEMONIC, "native_segwit", 2
        )

    def test_txt_report_contains_addresses(self):
        rows = self._sample_rows()
        report = build_report(rows, "txt")
        for r in rows:
            assert r["address"] in report
            assert r["path"] in report

    def test_csv_report_has_header_and_rows(self):
        rows = self._sample_rows()
        report = build_report(rows, "csv")
        assert "coin,address_type,path,address" in report
        for r in rows:
            assert r["address"] in report

    def test_report_never_contains_mnemonic_words(self):
        rows = self._sample_rows()
        for fmt in ("txt", "csv"):
            text = build_report(rows, fmt)
            # The mnemonic words should not appear anywhere.
            assert "abandon" not in text
            assert "about" not in text

    def test_report_rejects_forbidden_fields(self):
        rows = derive_eth_addresses(VALID_MNEMONIC, 1)
        # Simulate a future bug where someone shoves a secret into a record.
        rows[0]["private_key"] = "deadbeef"
        with pytest.raises(ValueError):
            build_report(rows, "txt")

    def test_unknown_format_rejected(self):
        with pytest.raises(ValueError):
            build_report([], "yaml")
