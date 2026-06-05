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

import hashlib
import io
from datetime import datetime, timezone
from typing import Iterable, Union

import pandas as pd
import qrcode
from fpdf import FPDF


_TOOL_NAME = "CRYPTEX LAB"
_VERSION = "2.0"

_REPORT_FIELDS = ("coin", "address_type", "path", "address")

_FORBIDDEN_KEYS = {
    "mnemonic", "seed", "entropy", "private_key", "privatekey",
    "private", "secret", "passphrase", "xprv",
    "wif", "master_secret", "master_secret_hex",
}

_DISCLAIMER = "FORENSIC REPORT - No private keys or secrets are included in this document."

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


def build_pdf_report(
    records: Iterable[dict],
    notes: str = "",
    case_info: dict | None = None,
    findings: list[dict] | None = None,
) -> bytes:
    """
    Build a forensic-grade PDF report.

    Parameters
    ----------
    records : Iterable[dict]
        Derivation records (coin, address_type, path, address).
    notes : str
        Free-text examiner notes (no secrets).
    case_info : dict | None
        Optional: {id, name, investigator, chain, opened_at}
    findings : list[dict] | None
        Optional non-address findings, e.g. from BIP38/Electrum/brain wallet.
        Each dict: {tool, result, detail}
    """
    safe = _prepare(records)
    ts = _timestamp()
    findings = findings or []

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(15, 15, 15)

    # ── Header / footer callback ────────────────────────────────────────────
    class _FPDFForensic(FPDF):
        def header(self):
            self.set_font("Helvetica", style="B", size=9)
            self.set_text_color(80, 80, 80)
            self.cell(0, 6, _latin1(f"{_TOOL_NAME} v{_VERSION} - FORENSIC RECOVERY REPORT"),
                      new_x="LMARGIN", new_y="NEXT", align="C")
            self.set_draw_color(40, 40, 40)
            self.line(15, self.get_y(), 195, self.get_y())
            self.ln(2)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", style="I", size=8)
            self.set_text_color(120, 120, 120)
            self.cell(0, 5, _latin1(f"Page {self.page_no()} | {_DISCLAIMER}"), align="C")

    pdf = _FPDFForensic(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()

    # ── Title block ─────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", style="B", size=18)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 12, "FORENSIC RECOVERY REPORT", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", size=10)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 6, _latin1(f"Generated (UTC): {ts}"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(4)

    # ── Case information ────────────────────────────────────────────────────
    if case_info:
        pdf.set_font("Helvetica", style="B", size=12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, "CASE INFORMATION", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(0, 0, 0)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(2)
        pdf.set_font("Helvetica", size=10)
        fields = [
            ("Case ID", case_info.get("id", "N/A")),
            ("Case Name", case_info.get("name", "N/A")),
            ("Investigator", case_info.get("investigator", "N/A")),
            ("Blockchain / Network", case_info.get("chain", "N/A")),
            ("Case Opened", case_info.get("opened_at", "N/A")),
        ]
        for label, value in fields:
            pdf.set_font("Helvetica", style="B", size=10)
            pdf.cell(50, 6, _latin1(f"{label}:"))
            pdf.set_font("Helvetica", size=10)
            pdf.cell(0, 6, _latin1(str(value)), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    # ── Examiner notes ───────────────────────────────────────────────────────
    if notes.strip():
        pdf.set_font("Helvetica", style="B", size=12)
        pdf.cell(0, 8, "EXAMINER NOTES", new_x="LMARGIN", new_y="NEXT")
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(2)
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(0, 5, _latin1(notes.strip()))
        pdf.ln(4)

    # ── Non-address findings (BIP38, Electrum, Brain Wallet, etc.) ──────────
    if findings:
        pdf.set_font("Helvetica", style="B", size=12)
        pdf.cell(0, 8, "RECOVERY FINDINGS", new_x="LMARGIN", new_y="NEXT")
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(2)
        for f in findings:
            pdf.set_font("Helvetica", style="B", size=10)
            pdf.cell(0, 6, _latin1(f"Tool: {f.get('tool', 'Unknown')}"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=10)
            pdf.cell(0, 6, _latin1(f"Result: {f.get('result', '')}"), new_x="LMARGIN", new_y="NEXT")
            if f.get("detail"):
                pdf.set_font("Helvetica", style="I", size=9)
                pdf.multi_cell(0, 5, _latin1(str(f["detail"])))
            pdf.ln(2)
        pdf.ln(2)

    # ── Derived address table ────────────────────────────────────────────────
    if safe:
        pdf.set_font("Helvetica", style="B", size=12)
        pdf.cell(0, 8, f"DERIVED ADDRESSES ({len(safe)} entries)", new_x="LMARGIN", new_y="NEXT")
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(2)

        # Column widths: coin=20, type=38, path=48, address=74
        col_w = (20, 38, 48, 74)
        headers = ("Coin", "Type", "Path", "Address")
        pdf.set_font("Helvetica", style="B", size=9)
        pdf.set_fill_color(220, 220, 220)
        for w, h in zip(col_w, headers):
            pdf.cell(w, 7, h, border=1, fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", size=8)
        for row in safe:
            vals = (
                str(row["coin"]),
                str(row["address_type"])[:35],
                str(row["path"]),
                str(row["address"]),
            )
            for w, v in zip(col_w, vals):
                pdf.cell(w, 6, _latin1(v[:int(w / 2.1)]), border=1)
            pdf.ln()
        pdf.ln(4)

    # ── Evidence integrity hash ───────────────────────────────────────────────
    # Build a canonical string of all exported data, hash it, and include it.
    # This allows verifying the report was not modified after generation.
    integrity_body = ts + "|" + notes + "|"
    if case_info:
        integrity_body += str(sorted(case_info.items()))
    for row in safe:
        integrity_body += str(row)
    for f in findings:
        integrity_body += str(f)
    integrity_hash = hashlib.sha256(integrity_body.encode("utf-8")).hexdigest()

    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(0, 8, "EVIDENCE INTEGRITY", new_x="LMARGIN", new_y="NEXT")
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(2)
    pdf.set_font("Helvetica", size=9)
    pdf.multi_cell(0, 5,
        "The SHA-256 hash below covers the timestamp, case details, notes, and all "
        "exported address records. Use it to verify this document has not been modified."
    )
    pdf.ln(2)
    pdf.set_font("Courier", style="B", size=9)
    pdf.cell(0, 6, _latin1(f"SHA-256: {integrity_hash}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", style="I", size=8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5,
        _latin1("Re-hash: sha256(timestamp + '|' + notes + '|' + case_info + address_rows + findings)"),
        new_x="LMARGIN", new_y="NEXT",
    )

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
