"""
export_utils.py
---------------
Report and QR-code generation for CRYPTEX LAB.

This module produces TXT, CSV, and PDF reports plus PNG QR codes from
derivation records. Everything runs locally; no network calls are made
and no external services are contacted.

# WHY WHITELIST EXPORT
# ====================
# Reports are the most likely place where a secret could accidentally leak
# out of the lab: the user clicks "Export", a file is written, and that
# file might end up on cloud sync, a printer queue, a screenshot, or an
# email attachment.
#
# To make that mistake hard rather than merely discouraged, every record
# that reaches an exporter is filtered through `safe_record`, which:
#
#   1. Whitelists only the fields in `_REPORT_FIELDS`. Anything else (a
#      `private_key` field a future contributor might add, a debug
#      `seed_hex`, etc.) is dropped instead of silently passing through.
#   2. Raises `ValueError` if the record contains any name in
#      `_FORBIDDEN_KEYS`. We prefer a loud crash over a quiet leak: an
#      export that refuses to run forces a human to look at the data,
#      whereas a successful export with a secret inside it does not.
#
# The free-text `notes` field is the one place where the user can write
# whatever they want. The UI must warn them not to paste secrets there;
# this module cannot validate free-form prose for sensitivity.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Iterable, Union

import pandas as pd
import qrcode
from fpdf import FPDF


_TOOL_NAME = "CRYPTEX LAB"

_REPORT_FIELDS = ("coin", "address_type", "path", "address")

_FORBIDDEN_KEYS = {
    "mnemonic", "seed", "entropy", "private_key", "privatekey",
    "private", "secret", "passphrase", "xprv",
}

_DISCLAIMER = "No secrets included: this report contains only public addresses."

_MAX_QR_INPUT = 200


def _timestamp() -> str:
    """UTC ISO-8601 timestamp, second precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_record(record: dict) -> dict:
    """
    Whitelist-only copy of a record.

    Drops any field not in `_REPORT_FIELDS`, and raises `ValueError` if
    any key matches one of `_FORBIDDEN_KEYS` (case-insensitive). This is
    defense in depth: an exporter must never silently strip a secret-
    looking field, because that would let bugs upstream go unnoticed.
    """
    if not isinstance(record, dict):
        raise TypeError("record must be a dict")
    for k in record:
        if isinstance(k, str) and k.lower() in _FORBIDDEN_KEYS:
            raise ValueError(
                f"Refusing to export record containing forbidden field {k!r}"
            )
    return {k: record.get(k, "") for k in _REPORT_FIELDS}


def _prepare(records: Iterable[dict]) -> list[dict]:
    """Apply `safe_record` to every input row and return a fresh list."""
    return [safe_record(r) for r in records]


# ---------------------------------------------------------------------------
# TXT
# ---------------------------------------------------------------------------

def build_txt_report(records: Iterable[dict], notes: str = "") -> str:
    safe = _prepare(records)
    ts = _timestamp()

    lines = [
        f"{_TOOL_NAME} - Recovery Report",
        "=" * 50,
        f"Generated (UTC): {ts}",
        f"Total addresses: {len(safe)}",
        _DISCLAIMER,
        "",
    ]
    for idx, row in enumerate(safe, start=1):
        lines.append(f"[{idx}] {row['coin']} - {row['address_type']}")
        lines.append(f"    Path:    {row['path']}")
        lines.append(f"    Address: {row['address']}")
        lines.append("")

    if notes:
        lines.append("Notes:")
        lines.append("-" * 50)
        lines.append(notes)
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def build_csv_report(records: Iterable[dict], notes: str = "") -> str:
    safe = _prepare(records)
    ts = _timestamp()

    header_lines = [
        f"# {_TOOL_NAME} report",
        f"# Generated: {ts}",
        f"# Total addresses: {len(safe)}",
        f"# {_DISCLAIMER}",
    ]
    if notes:
        # Escape newlines so the comment stays on a single line.
        flat = notes.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")
        header_lines.append(f"# Notes: {flat}")

    df = pd.DataFrame(safe, columns=list(_REPORT_FIELDS))
    csv_body = df.to_csv(index=False)

    return "\n".join(header_lines) + "\n" + csv_body


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def _latin1(text: str) -> str:
    """Coerce text to characters representable in latin-1 (fpdf2 core fonts)."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def build_pdf_report(records: Iterable[dict], notes: str = "") -> bytes:
    safe = _prepare(records)
    ts = _timestamp()

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("helvetica", style="B", size=16)
    pdf.cell(0, 10, _latin1(f"{_TOOL_NAME} - Recovery Report"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("helvetica", size=10)
    pdf.cell(0, 6, _latin1(f"Generated (UTC): {ts}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, _latin1(f"Total addresses: {len(safe)}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", style="I", size=9)
    pdf.cell(0, 6, _latin1(_DISCLAIMER), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Table header
    pdf.set_font("helvetica", style="B", size=10)
    pdf.cell(20, 7, "Coin", border=1)
    pdf.cell(45, 7, "Type", border=1)
    pdf.cell(50, 7, "Path", border=1)
    pdf.cell(75, 7, "Address", border=1, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("helvetica", size=8)
    for row in safe:
        pdf.cell(20, 6, _latin1(str(row["coin"])), border=1)
        pdf.cell(45, 6, _latin1(str(row["address_type"]))[:40], border=1)
        pdf.cell(50, 6, _latin1(str(row["path"])), border=1)
        pdf.cell(75, 6, _latin1(str(row["address"])), border=1, new_x="LMARGIN", new_y="NEXT")

    if notes:
        pdf.ln(6)
        pdf.set_font("helvetica", style="B", size=11)
        pdf.cell(0, 7, "Notes", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", size=10)
        pdf.multi_cell(0, 5, _latin1(notes))

    return bytes(pdf.output())


# ---------------------------------------------------------------------------
# QR
# ---------------------------------------------------------------------------

def build_qr_png(address: str, box_size: int = 8) -> bytes:
    if not isinstance(address, str) or not address:
        raise ValueError("address must be a non-empty string")
    if len(address) > _MAX_QR_INPUT:
        raise ValueError(
            f"address is too long for a QR code ({len(address)} > {_MAX_QR_INPUT})"
        )
    if not isinstance(box_size, int) or box_size < 1:
        raise ValueError("box_size must be a positive integer")

    qr = qrcode.QRCode(box_size=box_size, border=2)
    qr.add_data(address)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Single-entry dispatcher (kept for backward compatibility with callers
# that pass `fmt`, including the existing wallet_utils.build_report shim).
# ---------------------------------------------------------------------------

def build_report(
    records: Iterable[dict],
    fmt: str = "txt",
    notes: str = "",
) -> Union[str, bytes]:
    fmt = fmt.lower()
    if fmt == "txt":
        return build_txt_report(records, notes=notes)
    if fmt == "csv":
        return build_csv_report(records, notes=notes)
    if fmt == "pdf":
        return build_pdf_report(records, notes=notes)
    raise ValueError("fmt must be one of 'txt', 'csv', 'pdf'")
