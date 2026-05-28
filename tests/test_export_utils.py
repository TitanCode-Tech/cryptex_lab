"""
Tests for export_utils.

Uses the public BIP39 test vector (abandon x11 + about) so the assertions
can also verify that mnemonic words never leak into a generated report.
"""

from __future__ import annotations

import os
import re
import sys
import zlib

import pytest

# Allow `pytest` to be invoked from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from export_utils import (  # noqa: E402
    _REPORT_FIELDS,
    build_csv_report,
    build_pdf_report,
    build_qr_png,
    build_report,
    build_txt_report,
    safe_record,
)
from wallet_utils import derive_eth_addresses  # noqa: E402


VALID_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def _records():
    return derive_eth_addresses(VALID_MNEMONIC, 2)


def _pdf_text(data: bytes) -> str:
    """
    Concatenate every decoded text stream inside `data`. fpdf2 wraps page
    content in `stream ... endstream` blocks that are FlateDecode-compressed
    by default; we inflate each one with zlib so test assertions can grep
    for plain-text markers (notes, mnemonic words, etc.).
    """
    raw = bytes(data)
    out_parts = [raw.decode("latin-1", errors="replace")]
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, flags=re.DOTALL):
        chunk = m.group(1)
        try:
            inflated = zlib.decompress(chunk)
        except zlib.error:
            continue
        out_parts.append(inflated.decode("latin-1", errors="replace"))
    return "\n".join(out_parts)


# ---------------------------------------------------------------------------
# safe_record
# ---------------------------------------------------------------------------

class TestSafeRecord:
    def test_whitelist_only(self):
        r = safe_record(
            {
                "coin": "ETH",
                "address_type": "Ethereum",
                "path": "m/44'/60'/0'/0/0",
                "address": "0xabc",
                "extra_debug": "should be dropped",
            }
        )
        assert set(r) == set(_REPORT_FIELDS)
        assert "extra_debug" not in r

    def test_forbidden_key_raises(self):
        with pytest.raises(ValueError):
            safe_record({"address": "0x", "private_key": "deadbeef"})

    def test_forbidden_key_case_insensitive(self):
        with pytest.raises(ValueError):
            safe_record({"address": "0x", "MNEMONIC": "..."})

    def test_missing_fields_become_empty(self):
        r = safe_record({"address": "0x"})
        assert r["coin"] == ""
        assert r["path"] == ""


# ---------------------------------------------------------------------------
# TXT
# ---------------------------------------------------------------------------

class TestTxt:
    def test_includes_timestamp_header(self):
        report = build_txt_report(_records())
        # ISO-8601 UTC: YYYY-MM-DDTHH:MM:SSZ
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", report)
        assert "CRYPTEX LAB" in report
        assert "Total addresses: 2" in report
        assert "No secrets included" in report

    def test_contains_addresses_and_paths(self):
        rows = _records()
        report = build_txt_report(rows)
        for r in rows:
            assert r["address"] in report
            assert r["path"] in report

    def test_notes_included(self):
        report = build_txt_report(_records(), notes="hello world note")
        assert "Notes:" in report
        assert "hello world note" in report


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

class TestCsv:
    def test_header_line_present(self):
        report = build_csv_report(_records())
        assert "coin,address_type,path,address" in report

    def test_metadata_comments_present(self):
        report = build_csv_report(_records())
        assert report.startswith("# ")
        assert "# Generated:" in report
        assert "No secrets included" in report

    def test_rows_present(self):
        rows = _records()
        report = build_csv_report(rows)
        for r in rows:
            assert r["address"] in report

    def test_notes_comment(self):
        report = build_csv_report(_records(), notes="line1\nline2")
        # Newlines escaped so the comment stays on one CSV line.
        assert "# Notes: line1\\nline2" in report


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

class TestPdf:
    def test_returns_pdf_bytes(self):
        data = build_pdf_report(_records())
        assert isinstance(data, (bytes, bytearray))
        assert len(data) > 0
        assert bytes(data).startswith(b"%PDF")

    def test_notes_included_in_pdf(self):
        data = build_pdf_report(_records(), notes="MARKER_NOTES_ABC")
        # Decode FlateDecode-compressed content streams before scanning.
        text = _pdf_text(data)
        assert "MARKER_NOTES_ABC" in text


# ---------------------------------------------------------------------------
# QR
# ---------------------------------------------------------------------------

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class TestQr:
    def test_returns_png_bytes(self):
        png = build_qr_png("0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
        assert isinstance(png, (bytes, bytearray))
        assert len(png) > 0
        assert bytes(png).startswith(PNG_MAGIC)

    def test_empty_address_rejected(self):
        with pytest.raises(ValueError):
            build_qr_png("")

    def test_too_long_address_rejected(self):
        with pytest.raises(ValueError):
            build_qr_png("a" * 500)

    def test_box_size_must_be_positive(self):
        with pytest.raises(ValueError):
            build_qr_png("0xabc", box_size=0)


# ---------------------------------------------------------------------------
# Forbidden field rejection at the report level
# ---------------------------------------------------------------------------

class TestForbiddenFields:
    def test_private_key_field_rejected(self):
        rows = _records()
        rows[0]["private_key"] = "deadbeef"
        with pytest.raises(ValueError):
            build_txt_report(rows)
        with pytest.raises(ValueError):
            build_csv_report(rows)
        with pytest.raises(ValueError):
            build_pdf_report(rows)


# ---------------------------------------------------------------------------
# Mnemonic words must never appear in any output
# ---------------------------------------------------------------------------

class TestNoMnemonicLeak:
    def test_no_mnemonic_words_in_outputs(self):
        rows = _records()
        txt = build_txt_report(rows)
        csv_out = build_csv_report(rows)
        pdf_bytes = build_pdf_report(rows)
        pdf_text = _pdf_text(pdf_bytes)

        for haystack in (txt, csv_out, pdf_text):
            assert "abandon" not in haystack
            assert "about" not in haystack


# ---------------------------------------------------------------------------
# build_report dispatcher
# ---------------------------------------------------------------------------

class TestDispatcher:
    def test_txt_is_string(self):
        out = build_report(_records(), "txt")
        assert isinstance(out, str)

    def test_csv_is_string(self):
        out = build_report(_records(), "csv")
        assert isinstance(out, str)
        assert "coin,address_type,path,address" in out

    def test_pdf_is_bytes(self):
        out = build_report(_records(), "pdf")
        assert isinstance(out, (bytes, bytearray))
        assert bytes(out).startswith(b"%PDF")

    def test_unknown_format_rejected(self):
        with pytest.raises(ValueError):
            build_report(_records(), "yaml")


# ---------------------------------------------------------------------------
# Backward-compat shim from wallet_utils
# ---------------------------------------------------------------------------

class TestShim:
    def test_wallet_utils_build_report_reexport(self):
        # Importing through the legacy path must still work.
        from wallet_utils import build_report as wallet_build_report

        # Same function object as in export_utils.
        assert wallet_build_report is build_report

    def test_shim_produces_same_output(self):
        from wallet_utils import build_report as wallet_build_report

        rows = _records()
        # Generated timestamps would differ across two calls only by the
        # second hand; we just check the body matches structurally.
        a = wallet_build_report(rows, "txt")
        b = build_report(rows, "txt")
        # Strip the timestamp line for comparison.
        def strip_ts(s):
            return re.sub(
                r"Generated \(UTC\): \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                "Generated (UTC): X",
                s,
            )

        assert strip_ts(a) == strip_ts(b)
