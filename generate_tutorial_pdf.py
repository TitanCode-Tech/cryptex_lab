"""
generate_tutorial_pdf.py
------------------------
Generates a fully illustrated PDF version of TUTORIAL_CLIENT.md.

Usage:
    python generate_tutorial_pdf.py
    -> dist/CRYPTEX_LAB_Client_Guide.pdf

Requires: fpdf2 (already in requirements.txt)
"""

from fpdf import FPDF
from pathlib import Path
import textwrap

# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

SS   = Path("assets/screenshots")
ICON = Path("assets/icon.png")
DIST = Path("dist")

SCREENSHOTS = {
    "01_security_landing.png":  "Security Landing — home screen shown after login",
    "02_case_management.png":   "Case Management — create and activate a forensic case",
    "03_evidence_hash.png":     "Evidence Hash Checker — hash any file for chain-of-custody",
    "04_recovery_selector.png": "Recovery Problem Selector — choose the right tool",
    "05_incomplete_seed.png":   "Incomplete Seed Recovery — replace missing words with ?",
    "06_typo_lab.png":          "Typo Correction Lab — fix misspelled seed words",
    "07_wrong_order.png":       "Wrong Word Order Helper — recover when words are shuffled",
    "08_passphrase_test.png":   "BIP39 Passphrase Testing — test a single passphrase candidate",
    "09_passphrase_attack.png": "Passphrase Recovery Attack — automated dictionary attack",
    "10_key_importer.png":      "Key Importer — import a WIF or raw private key",
    "11_xpub_tool.png":         "xpub / xprv Key Tool — derive addresses from extended keys",
    "12_slip39.png":            "SLIP39 Share Recovery — combine Shamir shares",
    "13_bip38.png":             "BIP38 Encrypted Key Tool — decrypt a paper wallet key",
    "14_electrum.png":          "Electrum Wallet Recovery — recover Electrum v1 and v2 seeds",
    "15_brain_wallet.png":      "Brain Wallet Recovery — recover from a memorable phrase",
    "16_bip39_validation.png":  "BIP39 Validation Lab — validate a seed phrase",
    "17_entropy.png":           "Entropy Analysis Lab — measure data randomness",
    "18_metamask.png":          "MetaMask Vault Inspector — inspect vault metadata",
    "19_derivation.png":        "Derivation Path Scanner — scan all standard paths",
    "20_address_matcher.png":   "Known Address Matcher — find the path for a known address",
    "21_address_gen.png":       "ETH/BTC Address Generator — generate public addresses",
    "22_hash_tools.png":        "Hash / Crypto Tools — general-purpose cryptographic utilities",
    "23_exporter.png":          "Recovery Report Exporter — generate a forensic PDF",
    "24_airgap.png":            "Air-Gapped Ops Guide — physical security checklist",
    "25_education.png":         "Educational Lab — reference material for examiners",
    "26_full_sidebar.png":      "Full sidebar at Senior Analyst role — all tools visible",
    "27_live_address.png":      "Live Address Lookup — query blockchain in Live Analysis mode",
    "28_live_tx.png":           "Live TX Lookup — look up a transaction by ID",
}

# ---------------------------------------------------------------------------
# Colour palette (R, G, B)
# ---------------------------------------------------------------------------

C_BG      = (10,  20,  15)
C_PANEL   = (18,  35,  25)
C_ACCENT  = (0,   200, 100)
C_ACCENT2 = (0,   160, 80)
C_WHITE   = (220, 240, 230)
C_MUTED   = (120, 160, 140)
C_WARNING = (255, 200, 50)
C_DANGER  = (220, 60,  60)
C_CALLOUT = (15,  45,  30)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe(text: str) -> str:
    return text.encode("latin-1", errors="replace").decode("latin-1")

def _wrap(text: str, width: int = 88) -> list[str]:
    return textwrap.wrap(text, width) or [""]

# ---------------------------------------------------------------------------
# PDF class
# ---------------------------------------------------------------------------

class TutorialPDF(FPDF):

    def __init__(self):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(18, 18, 18)
        self._toc: list[tuple[str, int]] = []

    # ------------------------------------------------------------------ header / footer

    def header(self):
        self.set_fill_color(*C_BG)
        self.rect(0, 0, 210, 297, "F")
        if self.page_no() == 1:
            return
        self.set_fill_color(*C_PANEL)
        self.rect(0, 0, 210, 12, "F")
        self.set_font("Courier", "B", 7)
        self.set_text_color(*C_ACCENT2)
        self.set_y(4)
        self.cell(0, 4, _safe("CRYPTEX LAB v3  //  FORENSIC WORKSTATION  //  CLIENT GUIDE  //  CONFIDENTIAL"), align="C")

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-12)
        self.set_font("Courier", "", 7)
        self.set_text_color(*C_MUTED)
        self.cell(0, 4, _safe(f"Page {self.page_no()}  |  Titan Code  |  Confidential - Authorized Personnel Only"), align="C")

    # ------------------------------------------------------------------ title page

    def title_page(self):
        self.add_page()
        self.set_fill_color(*C_BG)
        self.rect(0, 0, 210, 297, "F")
        self.set_fill_color(*C_ACCENT)
        self.rect(0, 0, 210, 3, "F")

        y = 30
        if ICON.exists():
            self.image(str(ICON), x=85, y=y, w=40)
            y += 48

        self.set_y(y)
        self.set_font("Courier", "B", 28)
        self.set_text_color(*C_ACCENT)
        self.cell(0, 14, "CRYPTEX LAB", align="C", new_x="LMARGIN", new_y="NEXT")

        self.set_font("Courier", "", 11)
        self.set_text_color(*C_WHITE)
        self.cell(0, 7, "v3  //  FORENSIC WORKSTATION", align="C", new_x="LMARGIN", new_y="NEXT")

        self.ln(6)
        self.set_fill_color(*C_ACCENT2)
        self.rect(40, self.get_y(), 130, 0.5, "F")
        self.ln(8)

        self.set_font("Courier", "B", 16)
        self.set_text_color(*C_WHITE)
        self.cell(0, 10, "Complete Client Guide", align="C", new_x="LMARGIN", new_y="NEXT")

        self.ln(4)
        self.set_font("Courier", "", 10)
        self.set_text_color(*C_MUTED)
        self.cell(0, 6, "Illustrated Edition  |  All Roles Covered  |  Beginner-Friendly", align="C", new_x="LMARGIN", new_y="NEXT")

        self.ln(16)
        bx, by, bw, bh = 35, self.get_y(), 140, 52
        self.set_fill_color(*C_PANEL)
        self.rect(bx, by, bw, bh, "F")
        self.set_fill_color(*C_ACCENT2)
        self.rect(bx, by, 2, bh, "F")

        lines = [
            "This guide covers every screen in Cryptex Lab from first launch",
            "to advanced forensic recovery. Screenshots of each tool are",
            "included so you can follow along visually. Sections 1-9 apply",
            "to all roles. Sections 10-14 require Senior Analyst or Admin.",
        ]
        self.set_xy(bx + 8, by + 8)
        self.set_font("Courier", "B", 9)
        self.set_text_color(*C_ACCENT)
        self.cell(bw - 10, 6, "ABOUT THIS DOCUMENT")
        for i, line in enumerate(lines):
            self.set_xy(bx + 8, by + 16 + i * 5)
            self.set_font("Courier", "", 8)
            self.set_text_color(*C_WHITE)
            self.cell(bw - 10, 5, _safe(line))

        self.ln(8)
        lx, ly = 18, max(self.get_y(), by + bh + 8)
        self.set_fill_color(*C_CALLOUT)
        self.rect(lx, ly, 174, 22, "F")
        self.set_fill_color(*C_DANGER)
        self.rect(lx, ly, 2, 22, "F")
        self.set_xy(lx + 6, ly + 4)
        self.set_font("Courier", "B", 8)
        self.set_text_color(*C_DANGER)
        self.cell(162, 5, "LEGAL NOTICE")
        self.set_xy(lx + 6, ly + 10)
        self.set_font("Courier", "", 8)
        self.set_text_color(*C_WHITE)
        self.multi_cell(162, 4.5, _safe(
            "Only use this tool on wallets you own or are explicitly and legally authorized "
            "to recover. All actions are permanently audit-logged with timestamps and cannot "
            "be modified."
        ))

        self.set_fill_color(*C_ACCENT)
        self.rect(0, 294, 210, 3, "F")

    # ------------------------------------------------------------------ TOC (written on pre-reserved page 2)

    def toc_page(self, entries: list[tuple[str, int]]):
        self.set_y(self.t_margin)
        self.set_font("Courier", "B", 14)
        self.set_text_color(*C_ACCENT)
        self.cell(0, 8, "TABLE OF CONTENTS", new_x="LMARGIN", new_y="NEXT")
        self.set_fill_color(*C_ACCENT2)
        self.rect(18, self.get_y(), 174, 0.5, "F")
        self.ln(5)

        self.set_font("Courier", "", 9)
        for title, page in entries:
            dots = "." * max(2, 62 - len(title))
            self.set_x(18)
            self.set_text_color(*C_WHITE)
            self.cell(150, 5.5, _safe(f"  {title}  {dots}"), new_x="RIGHT", new_y="TOP")
            self.set_text_color(*C_ACCENT2)
            self.cell(24, 5.5, str(page), align="R", new_x="LMARGIN", new_y="NEXT")

    # ------------------------------------------------------------------ section / subsection

    def section(self, number: str, title: str):
        available = 297 - 20 - self.get_y()
        if available < 70:
            self.add_page()
        else:
            self.ln(5)
        self._toc.append((f"{number}. {title}", self.page_no()))
        y = self.get_y()
        self.set_fill_color(*C_ACCENT)
        self.rect(18, y, 3, 10, "F")
        self.set_xy(24, y)
        self.set_font("Courier", "B", 13)
        self.set_text_color(*C_ACCENT)
        self.cell(0, 10, _safe(f"{number}. {title.upper()}"), new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def subsection(self, title: str):
        available = 297 - 20 - self.get_y()
        if available < 30:
            self.add_page()
        else:
            self.ln(3)
        self.set_font("Courier", "B", 10)
        self.set_text_color(*C_ACCENT2)
        self.set_x(self.l_margin)
        self.cell(0, 6, _safe(title), new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    # ------------------------------------------------------------------ body / bullet

    def body(self, text: str):
        self.set_font("Courier", "", 9)
        self.set_text_color(*C_WHITE)
        self.set_x(self.l_margin)
        self.multi_cell(self.epw, 5, _safe(text))
        self.ln(1)

    def bullet(self, items: list[str]):
        self.set_font("Courier", "", 9)
        for item in items:
            self.set_x(self.l_margin + 4)
            self.set_font("Courier", "B", 9)
            self.set_text_color(*C_ACCENT2)
            self.cell(5, 5, ">", new_x="RIGHT", new_y="TOP")
            self.set_font("Courier", "", 9)
            self.set_text_color(*C_WHITE)
            self.multi_cell(self.epw - 9, 5, _safe(item))
        self.ln(1)

    # ------------------------------------------------------------------ callout boxes

    def _callout(self, label: str, text: str, bar_color: tuple, label_color: tuple):
        self.ln(2)
        y = self.get_y()
        lines = _wrap(text, 88)
        h = len(lines) * 5 + 12
        if y + h > 297 - 20:
            self.add_page()
            y = self.get_y()
        self.set_fill_color(*C_CALLOUT)
        self.rect(18, y, 174, h, "F")
        self.set_fill_color(*bar_color)
        self.rect(18, y, 2, h, "F")
        self.set_xy(24, y + 3)
        self.set_font("Courier", "B", 8)
        self.set_text_color(*label_color)
        self.cell(162, 5, label)
        for i, line in enumerate(lines):
            self.set_xy(24, y + 8 + i * 5)
            self.set_font("Courier", "", 8)
            self.set_text_color(*C_WHITE)
            self.cell(162, 5, _safe(line))
        self.set_y(y + h + 3)

    def tip_box(self, text: str):
        self._callout("TIP", text, C_ACCENT, C_ACCENT)

    def warning_box(self, text: str):
        self._callout("WARNING", text, C_WARNING, C_WARNING)

    # ------------------------------------------------------------------ table

    def table(self, headers: list[str], rows: list[list[str]], col_widths: list[int] | None = None):
        n = len(headers)
        total = 174
        if col_widths is None:
            col_widths = [total // n] * n

        self.set_fill_color(*C_ACCENT2)
        self.set_text_color(*C_BG)
        self.set_font("Courier", "B", 8)
        self.set_x(18)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 6, _safe(h), border=0, fill=True)
        self.ln()

        self.set_font("Courier", "", 8)
        for ri, row in enumerate(rows):
            fill_color = C_PANEL if ri % 2 == 0 else C_BG
            max_lines = 1
            for ci, cell_text in enumerate(row):
                wrapped = _wrap(cell_text, max(4, col_widths[ci] // 2))
                max_lines = max(max_lines, len(wrapped))
            row_h = max_lines * 4.5 + 2
            start_y = self.get_y()
            self.set_fill_color(*fill_color)
            self.rect(18, start_y, total, row_h, "F")
            self.set_text_color(*C_WHITE)
            for ci, cell_text in enumerate(row):
                x_pos = 18 + sum(col_widths[:ci])
                self.set_xy(x_pos + 1, start_y + 1)
                self.multi_cell(col_widths[ci] - 2, 4.5, _safe(cell_text))
            self.set_y(start_y + row_h)
        self.ln(3)

    # ------------------------------------------------------------------ screenshot

    def screenshot(self, filename: str, caption: str | None = None):
        path = SS / filename
        if not path.exists():
            return
        cap = caption or SCREENSHOTS.get(filename, filename)
        avail = 297 - 20 - self.get_y()
        if avail < 80:
            self.add_page()

        y = self.get_y() + 2
        img_w = 170
        self.image(str(path), x=20, y=y, w=img_w)

        try:
            from PIL import Image as PILImage
            with PILImage.open(path) as im:
                iw, ih = im.size
                img_h = img_w * ih / iw
        except Exception:
            img_h = 80

        cap_y = y + img_h + 2
        self.set_fill_color(*C_PANEL)
        self.rect(18, cap_y, 174, 7, "F")
        self.set_xy(22, cap_y + 1.5)
        self.set_font("Courier", "I", 7)
        self.set_text_color(*C_MUTED)
        self.cell(0, 4, _safe(f"Fig. {filename[:2]}  |  {cap}"))
        self.set_y(cap_y + 10)

    # ------------------------------------------------------------------ numbered steps

    def steps(self, items: list[str]):
        for i, item in enumerate(items, 1):
            self.set_x(18)
            self.set_fill_color(*C_ACCENT2)
            self.set_text_color(*C_BG)
            self.set_font("Courier", "B", 8)
            self.cell(6, 5, str(i), fill=True, align="C")
            self.set_font("Courier", "", 9)
            self.set_text_color(*C_WHITE)
            self.set_x(26)
            self.multi_cell(self.epw - 8, 5, _safe(item))
        self.ln(2)


# ---------------------------------------------------------------------------
# Content builder
# ---------------------------------------------------------------------------

def build(pdf: TutorialPDF):

    # ── Section 1: Beginner Concepts ──────────────────────────────────────────
    pdf.section("1", "Beginner Concepts - Read This First")
    pdf.body(
        "If you are already familiar with cryptocurrency wallets and seed phrases, skip "
        "to Section 2. Otherwise read this first — these concepts underpin every tool "
        "in Cryptex Lab."
    )

    pdf.subsection("What is a cryptocurrency wallet?")
    pdf.body(
        "A wallet does not store coins. Coins live on the blockchain — a global, permanent "
        "public ledger. What a wallet stores is a private key: a secret number that proves "
        "ownership and authorises spending. Whoever holds the private key controls the funds."
    )

    pdf.subsection("What is a seed phrase (mnemonic)?")
    pdf.body(
        "The BIP39 standard represents a private key as 12, 18, or 24 common English words "
        "called a seed phrase, recovery phrase, or mnemonic. From those words, a deterministic "
        "process recreates every private key and address you ever used. Losing your seed phrase "
        "means permanent loss — and recovering one with typos, missing words, or a forgotten "
        "passphrase is exactly what Cryptex Lab is built for."
    )

    pdf.subsection("What is a derivation path?")
    pdf.body(
        "One seed phrase can generate thousands of different wallet addresses. A derivation "
        "path is the instruction specifying which address to produce. Different wallet apps "
        "use different defaults. If a tool derives addresses from your seed but cannot find "
        "your balance, the path is usually the reason."
    )
    pdf.table(
        ["Standard", "Path", "Used by"],
        [
            ["BIP44", "m/44'/60'/0'/0/0", "MetaMask, most ETH wallets"],
            ["BIP44", "m/44'/0'/0'/0/0",  "Bitcoin legacy (1...)"],
            ["BIP49", "m/49'/0'/0'/0/0",  "Bitcoin SegWit (3...)"],
            ["BIP84", "m/84'/0'/0'/0/0",  "Bitcoin Native SegWit (bc1...)"],
        ],
        [38, 62, 74]
    )

    pdf.subsection("What is a passphrase (the 25th word)?")
    pdf.body(
        "BIP39 supports an optional extra passphrase on top of the seed phrase. Hardware "
        "wallets like Trezor call this the 'hidden wallet' feature. If you used a passphrase "
        "when setting up your wallet, you must provide it during recovery. Most users have "
        "none — a blank passphrase is valid and very common."
    )
    pdf.tip_box(
        "Cryptex Lab can test thousands of passphrase candidates automatically using the "
        "Passphrase Recovery Attack tool — useful when you remember roughly what the "
        "passphrase was but not the exact spelling."
    )

    pdf.subsection("What is BIP38?")
    pdf.body(
        "BIP38 encrypts a single Bitcoin private key with a passphrase so it can be printed "
        "on paper safely (paper wallets). These keys start with '6P'. You need both the "
        "encrypted key and the passphrase to access the funds."
    )

    pdf.subsection("What is SLIP39 (Shamir's Secret Sharing)?")
    pdf.body(
        "SLIP39 splits a seed into multiple shares so that access requires a threshold number "
        "of shares (e.g. 3 out of 5). Even if someone steals two shares they cannot reconstruct "
        "the wallet. Trezor Model T supports this natively."
    )

    pdf.subsection("What is a brain wallet?")
    pdf.body(
        "A brain wallet derives a private key directly from a passphrase using a hash function "
        "— no seed phrase or hardware involved. Brain wallets are insecure for new wallets "
        "because common phrases are pre-computed by attackers, but Cryptex Lab can recover "
        "the address if you remember the original phrase."
    )

    pdf.subsection("What is an xpub / xprv?")
    pdf.body(
        "An extended public key (xpub) lets you derive all receiving addresses for a wallet "
        "without exposing the private key. An extended private key (xprv) can derive addresses "
        "and spend funds. Cryptex Lab can scan addresses from either."
    )

    # ── Section 2: License ────────────────────────────────────────────────────
    pdf.section("2", "Before You Start - Getting Your License")
    pdf.body(
        "Cryptex Lab ships without a license — you activate it after installation using a "
        "key tied to your specific machine hardware."
    )
    pdf.steps([
        "Install the application and launch it for the first time",
        "The app displays your Machine ID — a fingerprint of your hardware",
        "Send that Machine ID to your administrator (Titan Code)",
        "Your administrator generates a license key locked to your Machine ID",
        "Paste the CXLAB-... key into the app — activation is instant and permanent",
    ])
    pdf.warning_box(
        "Your license is machine-locked. If you move to a new computer, contact your "
        "administrator for a new key. The application will not run on unauthorised hardware."
    )

    # ── Section 3: Package contents ───────────────────────────────────────────
    pdf.section("3", "What Is in Your Package")
    pdf.table(
        ["File / Folder", "Purpose"],
        [
            ["app.py", "Main application"],
            ["recovery_utils.py, derivation_utils.py, ...", "Core logic modules"],
            ["*.so / *.pyd files", "Compiled security modules (binary — no source shipped)"],
            ["requirements.txt", "Python dependency list"],
            ["install.py / install.sh / install.bat", "Automated installer"],
            ["download_wheels.py", "Pre-fetches all wheels for air-gapped installation"],
            ["launcher.py", "App launcher — use this to start the app"],
            ["public_key.pem", "License verification key"],
            ["manifest.json", "Build integrity manifest (tamper detection)"],
            ["TUTORIAL_CLIENT.md", "This guide (plain text version)"],
            ["CRYPTEX_LAB_Client_Guide.pdf", "This illustrated PDF guide"],
            ["assets/", "Icons and screenshots"],
        ],
        [74, 100]
    )
    pdf.warning_box(
        "You will never receive: private_key.pem, source code for security modules, "
        "or license.json. These stay with your administrator."
    )

    # ── Section 4: Installation ───────────────────────────────────────────────
    pdf.section("4", "Installation")

    pdf.subsection("Requirements")
    pdf.bullet([
        "Python 3.10 or newer",
        "4 GB RAM minimum (8 GB recommended for passphrase attacks)",
        "500 MB disk space",
        "No internet connection required after initial installation",
    ])

    pdf.subsection("Linux / macOS")
    pdf.body("Open a terminal in the extracted folder and run:  python install.py")

    pdf.subsection("Windows")
    pdf.body("Double-click install.bat, or open Command Prompt and run:  python install.py")

    pdf.subsection("What the installer does")
    pdf.steps([
        "Creates a venv/ virtual environment isolated from your system Python",
        "Downloads and installs all dependencies from requirements.txt via pip",
        "Verifies the build integrity manifest — all files are checked against their "
        "cryptographic signatures. Installation halts if any file was modified in transit.",
        "Creates a desktop shortcut and prints launch instructions",
    ])

    pdf.subsection("Air-gapped installation (no internet on the workstation)")
    pdf.body(
        "Use download_wheels.py to pre-fetch all dependencies on a connected machine, "
        "then transfer them via USB to the air-gapped workstation."
    )
    pdf.steps([
        "On an internet-connected machine with the same OS and Python version, run: "
        "python download_wheels.py  — this saves all wheels to ./offline_wheels/",
        "Copy the entire Cryptex Lab folder (including offline_wheels/) to a USB drive",
        "Transfer the USB drive to the air-gapped workstation",
        "On the air-gapped machine, run: python install.py --offline",
        "The installer reads from offline_wheels/ — no internet calls are made",
    ])
    pdf.tip_box(
        "Run download_wheels.py on a machine with the SAME operating system and Python "
        "version as the air-gapped target. Wheels are platform-specific."
    )

    # ── Section 5: 2FA Setup ──────────────────────────────────────────────────
    pdf.section("5", "Setting Up Two-Factor Authentication (2FA)")
    pdf.body(
        "The first time you launch Cryptex Lab after license activation, the Security Setup "
        "screen appears. This one-time process takes about two minutes. Elevated roles "
        "(Senior Analyst and Admin) require a live 6-digit TOTP code each session, "
        "ensuring no one can access the most sensitive tools without your phone."
    )

    pdf.subsection("Step 1 - Install an authenticator app")
    pdf.bullet([
        "Google Authenticator (Android / iOS)",
        "Aegis (Android — recommended, open source)",
        "2FAS (Android / iOS)",
        "Authy (Android / iOS)",
    ])

    pdf.subsection("Step 2 - Complete in-app setup")
    pdf.body("The setup screen shows two QR codes — one for Senior Analyst, one for Admin.")
    pdf.steps([
        "Open your authenticator app and tap + or Add account",
        "Choose Scan QR code and point your camera at the QR code on screen",
        "The app adds an entry showing a 6-digit code refreshing every 30 seconds",
        "Type that 6-digit code into the Enter code field and click Confirm",
        "Repeat for the second QR code (Admin role)",
        "Click Save and Launch — setup is complete and will not appear again",
    ])
    pdf.warning_box(
        "Do not delete those authenticator entries. If you lose them, delete "
        "totp_secrets.json and redo the setup. Contact your administrator if this happens."
    )

    # ── Section 6: Launching ──────────────────────────────────────────────────
    pdf.section("6", "Launching the Application")
    pdf.body("Run the following command in the application directory:")
    pdf.body("    python launcher.py")
    pdf.body(
        "The launcher starts the application and automatically opens your browser to "
        "http://localhost:8501. If the browser does not open, navigate there manually."
    )
    pdf.tip_box(
        "The app only listens on localhost — it is never accessible from other machines "
        "on the network, even if you are connected to Wi-Fi."
    )

    # ── Section 7: Interface ──────────────────────────────────────────────────
    pdf.section("7", "Understanding the Interface")
    pdf.screenshot("01_security_landing.png")

    pdf.subsection("Sidebar (left panel)")
    pdf.bullet([
        "Mode indicator — OFFLINE SAFE (green) or LIVE ANALYSIS (red)",
        "Role selector dropdown — your current permission level",
        "LICENSE ACTIVE banner — confirms valid license",
        "Navigation — all available pages grouped by category",
    ])
    pdf.body(
        "The navigation only shows pages your current role is permitted to access. "
        "If a page is not visible, either your role lacks permission or no case is active."
    )

    pdf.subsection("Header bar (top)")
    pdf.bullet([
        "AIRGAP OK — confirms no network calls have been made this session",
        "N CASES — number of open cases in the registry",
        "SESSION LIVE — session uptime counter",
        "OFFLINE SAFE / LIVE ANALYSIS — the current operating mode",
    ])

    pdf.subsection("Audit terminal")
    pdf.body(
        "The green terminal panel visible on most pages shows your session activity in "
        "real time. Every action is timestamped and written permanently to "
        "audit_logs/audit.jsonl. This log cannot be modified from within the application."
    )

    # ── Section 8: Roles ──────────────────────────────────────────────────────
    pdf.section("8", "Role Assignment and Elevation")
    pdf.screenshot("26_full_sidebar.png")

    pdf.table(
        ["Role", "What you can do"],
        [
            ["Viewer",         "Read-only — security landing, case registry, hashing"],
            ["Analyst",        "Basic recovery — typo correction, wrong word order, "
                               "derivation paths, address matching"],
            ["Senior Analyst", "Full recovery — incomplete seeds, passphrase attacks, "
                               "BIP38, SLIP39, xpub, brain wallet, key import"],
            ["Admin",          "Same as Senior Analyst — intended for the lead examiner"],
        ],
        [38, 136]
    )
    pdf.steps([
        "Use the ROLE ASSIGNMENT dropdown in the sidebar",
        "Selecting Analyst requires no code",
        "Selecting Senior Analyst or Admin opens a 2FA dialog",
        "Enter the 6-digit code from your authenticator app",
        "Click Confirm — you are now elevated for the rest of this session",
    ])
    pdf.warning_box(
        "Roles do not persist between sessions. Every launch starts at Analyst. "
        "Re-elevate via the dropdown each time you need Senior Analyst or Admin access."
    )

    # ── Section 9: Offline Policy ─────────────────────────────────────────────
    pdf.section("9", "Working Offline - The Golden Rule")
    pdf.body(
        "OFFLINE SAFE mode is the only state in which you should work with real secrets. "
        "In this mode: no network sockets are opened, no data leaves the machine, "
        "blockchain lookups are blocked, and all seed-handling pages are available."
    )
    pdf.warning_box(
        "NEVER enter a real seed phrase while in LIVE ANALYSIS mode. "
        "When you switch to Live mode, recovery pages are automatically hidden — "
        "but as physical discipline: keep secrets off the clipboard whenever the "
        "network is active."
    )
    pdf.body(
        "The header bar always shows your current mode prominently. "
        "OFFLINE SAFE glows green. LIVE ANALYSIS glows red. "
        "Live mode is opt-in and only needed for blockchain balance lookups."
    )

    # ── Section 10: Starting a Case ───────────────────────────────────────────
    pdf.section("10", "Starting a Case")
    pdf.screenshot("02_case_management.png")
    pdf.body(
        "Before using any recovery or forensic tool, you must create and activate a case. "
        "A case ties all your work to a specific investigation with a permanent audit trail."
    )
    pdf.steps([
        "Navigate to Case Management in the sidebar",
        "Fill in the form: Priority, Chain, Incident Type, Asset, Lead Analyst, Description",
        "Click CREATE CASE — a case ID is generated automatically (CASE-YYYYMMDD-HHMMSS)",
        "Click ACTIVATE next to the new case to set it as the active case",
    ])
    pdf.tip_box(
        "The active case ID, investigator name, and chain type appear in the header "
        "breadcrumb once a case is activated. All recovery actions are logged under this ID."
    )

    # ── Section 11: Recovery Tools ────────────────────────────────────────────
    pdf.section("11", "Recovery Tools - Detailed Guide")

    pdf.subsection("Recovery Problem Selector")
    pdf.screenshot("04_recovery_selector.png")
    pdf.body(
        "If you are unsure which tool to use, start here. Choose the tile that best "
        "describes your situation and you will be taken directly to the right tool."
    )
    pdf.table(
        ["Tile", "When to use it"],
        [
            ["Missing / Partial Words",    "You have most of the seed but some words are missing"],
            ["Misspelled Words",           "Some words are misspelled or phonetically written"],
            ["Words Out of Order",         "You have all words but are unsure of the sequence"],
            ["Forgot Passphrase (Single)", "You remember roughly what the passphrase was"],
            ["Passphrase Attack",          "Test thousands of passphrase candidates automatically"],
            ["Unknown Path / Multi-Coin",  "Valid seed but cannot find your balance"],
            ["WIF / Raw Key Import",       "You have a raw private key, not a seed phrase"],
        ],
        [56, 118]
    )

    pdf.subsection("Incomplete Seed Recovery  [Senior Analyst]")
    pdf.screenshot("05_incomplete_seed.png")
    pdf.body(
        "Use when you have a seed phrase with one or two words missing. Replace unknown "
        "words with ? and the tool exhaustively tests all 2048 BIP39 words in each "
        "unknown position. The BIP39 checksum eliminates most invalid combinations. "
        "A known wallet address reduces results to a single match instantly."
    )
    pdf.steps([
        "Navigate to Incomplete Seed Recovery and accept the authorisation form",
        "Enter phrase with ? for missing words, e.g.: abandon ? abandon abandon ...",
        "Select With known wallet address mode and enter the address",
        "Click RUN RECOVERY — results appear as candidates are found",
    ])
    pdf.tip_box(
        "Providing a known wallet address makes recovery much faster and eliminates "
        "false positives. Even a single address from an old transaction is enough."
    )

    pdf.subsection("Typo Correction Lab")
    pdf.screenshot("06_typo_lab.png")
    pdf.body(
        "Use when seed words are misspelled, partially remembered, or phonetically written. "
        "Three correction methods run simultaneously:"
    )
    pdf.bullet([
        "Keyboard adjacency — words reachable by one adjacent QWERTY key substitution",
        "Phonetic similarity — Soundex coding groups words that sound alike",
        "Edit distance — Levenshtein distance finds the closest spelling matches",
    ])
    pdf.steps([
        "Paste the full phrase including the misspelled words",
        "Set Suggestions per word (default 5 is usually enough)",
        "Click RUN SPELL CHECK",
        "Review suggestions grouped by method for each suspicious word",
    ])

    pdf.subsection("Wrong Word Order Helper")
    pdf.screenshot("07_wrong_order.png")
    pdf.body(
        "Use when you have all the correct words but the order is uncertain. Fix confident "
        "positions, mark uncertain positions with ?, and list the pool of words to fill "
        "those positions. Only permutations of the uncertain words are tested, and the "
        "BIP39 checksum eliminates invalid combinations automatically."
    )

    pdf.subsection("BIP39 Passphrase Testing")
    pdf.screenshot("08_passphrase_test.png")
    pdf.body(
        "Use when you have a valid seed and want to test whether a specific passphrase "
        "produces your known wallet address. This is the single-candidate version. "
        "To test thousands at once, use the Passphrase Recovery Attack tool instead."
    )

    pdf.subsection("Passphrase Recovery Attack  [Senior Analyst]")
    pdf.screenshot("09_passphrase_attack.png")
    pdf.body(
        "Automated dictionary attack on a BIP39 passphrase. Builds a candidate list from "
        "your wordlist and applies mutation rules (capitalise, append numbers, swap letters, "
        "append symbols), then tests each against your seed and a known wallet address."
    )
    pdf.tip_box(
        "BIP39 PBKDF2 is intentionally slow (~2,048 rounds). Expect 300-2,000 "
        "candidates/second depending on hardware. 100 words x 4 mutation rules = ~4,000 "
        "candidates = under 30 seconds on modern hardware."
    )

    pdf.subsection("Key Importer  [Senior Analyst]")
    pdf.screenshot("10_key_importer.png")
    pdf.body(
        "Use when you have a raw private key or WIF-encoded key rather than a seed phrase. "
        "Supports WIF (Wallet Import Format, Base58-encoded) and raw 64-character hex. "
        "Derives BTC Legacy, SegWit, Native SegWit, and ETH/EVM addresses instantly."
    )
    pdf.warning_box(
        "The private key is never written to disk or included in any export. "
        "It exists only in memory for the duration of this page view."
    )

    pdf.subsection("xpub / xprv Key Tool  [Senior Analyst]")
    pdf.screenshot("11_xpub_tool.png")
    pdf.body(
        "Use when you have an extended key from a hardware or watch-only wallet but not "
        "the original seed. Supports xpub/xprv (BIP44), ypub/yprv (BIP49), zpub/zprv (BIP84). "
        "Watch-only xpub mode derives addresses without exposing private keys."
    )
    pdf.table(
        ["Prefix", "Standard", "Address type", "Private key?"],
        [
            ["xpub / xprv", "BIP44", "Legacy P2PKH (1...)",     "xprv only"],
            ["ypub / yprv", "BIP49", "SegWit P2SH (3...)",      "yprv only"],
            ["zpub / zprv", "BIP84", "Native SegWit (bc1...)",  "zprv only"],
            ["xpub / xprv", "BIP44", "Ethereum (0x...)",        "xprv only"],
        ],
        [34, 28, 58, 54]
    )

    pdf.subsection("SLIP39 Share Recovery  [Senior Analyst]")
    pdf.screenshot("12_slip39.png")
    pdf.body(
        "Use when the wallet was backed up with SLIP39 (Shamir's Secret Sharing). "
        "Paste your threshold-many shares (one per line), enter the passphrase if one "
        "was set, and click COMBINE & DERIVE. The tool derives ETH, BTC Native SegWit, "
        "BTC SegWit, and BTC Legacy addresses from the recovered master secret."
    )

    pdf.subsection("BIP38 Encrypted Key Tool  [Senior Analyst]")
    pdf.screenshot("13_bip38.png")
    pdf.body(
        "Use when you have a BIP38-encrypted Bitcoin private key (starts with '6P'). "
        "Single decrypt mode: enter the key and passphrase for immediate decryption. "
        "Dictionary attack mode: build a candidate list and run automated testing."
    )
    pdf.warning_box(
        "BIP38 uses scrypt key stretching — approximately 0.1-0.5 seconds per candidate. "
        "A 1,000-word dictionary takes 2-8 minutes. Plan your time accordingly."
    )

    pdf.subsection("Electrum Wallet Recovery  [Senior Analyst]")
    pdf.screenshot("14_electrum.png")
    pdf.body(
        "Use when the wallet was created with the Electrum Bitcoin client, which uses its "
        "own seed format (different from BIP39). The tool auto-detects Electrum v1 (12 "
        "words, 1,626-word list, no passphrase) vs v2 Standard/Segwit (12 words, optional "
        "passphrase). Includes a passphrase attack mode for forgotten Electrum passphrases."
    )

    pdf.subsection("Brain Wallet Recovery  [Senior Analyst]")
    pdf.screenshot("15_brain_wallet.png")
    pdf.body(
        "Use when the wallet was created from a memorable phrase hashed directly into a "
        "private key. Tests both BTC (SHA256) and ETH (keccak256) brain wallet derivations. "
        "Extremely fast — over 100,000 candidates per second via multiprocessing."
    )

    # ── Section 12: Forensics ─────────────────────────────────────────────────
    pdf.section("12", "Forensics Tools - Detailed Guide")

    pdf.subsection("BIP39 Validation Lab")
    pdf.screenshot("16_bip39_validation.png")
    pdf.body(
        "Validate a seed phrase structurally before attempting recovery. Checks word count "
        "(12/15/18/21/24), BIP39 wordlist membership for every word, and BIP39 checksum "
        "integrity. Three modes: basic validator, device simulation, and forensic "
        "validation proof for case documentation."
    )

    pdf.subsection("Entropy Analysis Lab")
    pdf.screenshot("17_entropy.png")
    pdf.body(
        "Measure the randomness of a byte sequence. True random data (keys, seeds, "
        "encrypted material) scores close to 8.0 bits/byte. Plain text scores 4-5. "
        "Useful for determining whether a byte sequence is likely wallet-related material."
    )

    pdf.subsection("MetaMask Vault Inspector")
    pdf.screenshot("18_metamask.png")
    pdf.body(
        "Inspect the structure of a MetaMask vault JSON without decrypting it. Shows "
        "format version, encryption algorithm, salt, and IV for forensic documentation. "
        "Useful for confirming a vault is genuine MetaMask format before attempting decryption."
    )

    pdf.subsection("Derivation Path Scanner")
    pdf.screenshot("19_derivation.png")
    pdf.body(
        "Scan all standard derivation paths for 13 coins simultaneously. Hardware wallet "
        "presets (Ledger Live, Trezor Suite, MetaMask, Exodus, Trust Wallet, Coinbase) "
        "let you match the exact paths your wallet app uses. Deep scan finds the exact "
        "path and index for any known address."
    )

    pdf.subsection("Known Address Matcher")
    pdf.screenshot("20_address_matcher.png")
    pdf.body(
        "Given a seed phrase and a known wallet address, finds the exact derivation path "
        "that produces that address. Scans all standard paths for all supported coins. "
        "Result includes: coin, path, address type, and index. Hardware wallet presets "
        "can narrow the search significantly."
    )

    pdf.subsection("ETH/BTC Address Generator")
    pdf.screenshot("21_address_gen.png")
    pdf.body(
        "Generate a batch of public wallet addresses from a seed phrase. Select coin and "
        "address type, set the count, and click DERIVE. Only public addresses are shown "
        "— no private keys. Safe to use for documentation and evidence review."
    )

    # ── Section 13: Utilities ─────────────────────────────────────────────────
    pdf.section("13", "Utilities")

    pdf.subsection("Hash / Crypto Tools")
    pdf.screenshot("22_hash_tools.png")
    pdf.body(
        "General-purpose cryptographic utility. Supports: SHA-256, SHA-512, SHA-3, MD5, "
        "RIPEMD-160, BLAKE2, Base58, Base64, hex encoding and decoding. "
        "All operations run locally — no data is sent anywhere."
    )

    pdf.subsection("Recovery Report Exporter")
    pdf.screenshot("23_exporter.png")
    pdf.body(
        "Produce a formal forensic PDF report containing case information, examiner notes, "
        "recovery findings, and an evidence integrity SHA-256 hash. The exporter applies "
        "a strict filter — seed phrases, private keys, WIF keys, passphrases, and extended "
        "private keys are automatically blocked from output."
    )

    pdf.subsection("Air-Gapped Ops Guide")
    pdf.screenshot("24_airgap.png")
    pdf.body(
        "Quick-reference physical security checklist: network isolation steps, media "
        "controls, screen privacy, and transfer protocols for offline deployments."
    )

    pdf.subsection("Educational Lab")
    pdf.screenshot("25_education.png")
    pdf.body(
        "Read-only reference library covering BIP32/39/44/49/84, BIP38, SLIP39, and "
        "common recovery scenarios. Useful for new examiners onboarding to the tool."
    )

    # ── Section 14: Live Analysis ─────────────────────────────────────────────
    pdf.section("14", "Live Analysis Mode")
    pdf.screenshot("27_live_address.png")
    pdf.screenshot("28_live_tx.png")
    pdf.body(
        "Live Analysis mode enables network calls to public blockchain APIs. Click "
        "ENGAGE LIVE ANALYSIS in the sidebar to switch. When active: the header turns "
        "red, recovery tools disappear from the sidebar, and only Live Tools, Utilities, "
        "and Core pages remain."
    )
    pdf.bullet([
        "Live Address Lookup — query balance and transaction history for any address",
        "Live TX Lookup — look up a transaction by its 64-character hex ID",
    ])
    pdf.tip_box(
        "Click RETURN TO OFFLINE SAFE in the sidebar to return to offline mode. "
        "Recovery tools reappear immediately."
    )
    pdf.warning_box(
        "Only enter Live mode after closing all seed-phrase sessions and clearing "
        "sensitive fields. Never paste a seed phrase into any field while in Live mode."
    )

    # ── Section 15: Workflows ─────────────────────────────────────────────────
    pdf.section("15", "Common Workflows - Step by Step")

    pdf.subsection("Workflow A: Recover a seed with one missing word")
    pdf.steps([
        "Confirm OFFLINE SAFE mode is active (green header)",
        "Case Management -> create and activate a case",
        "Recovery Problem Selector -> Missing / Partial Words",
        "Accept the authorisation form",
        "Enter the phrase with ? for the missing word: word1 ? word3 word4 ...",
        "Select With known wallet address mode and enter a known address",
        "Click RUN RECOVERY — one candidate appears with the correct word filled in",
        "Recovery Report Exporter -> generate a PDF record for the case file",
    ])

    pdf.subsection("Workflow B: Fix a misspelled word")
    pdf.steps([
        "Case Management -> activate a case",
        "Typo Correction Lab -> paste the full phrase including the misspelled word",
        "Click RUN SPELL CHECK",
        "Review suggestions — the correct word typically appears with edit distance 1",
        "Correct the phrase, then validate in BIP39 Validation Lab",
        "Confirm the corrected phrase produces your address via Derivation Path Scanner",
    ])

    pdf.subsection("Workflow C: Find a balance on a different derivation path")
    pdf.steps([
        "Derivation Path Scanner -> enter the seed",
        "Select the hardware preset for your wallet brand",
        "Enter a known wallet address in the Target Address field",
        "Click FIND ADDRESS",
        "Result shows coin and path (e.g. BTC_NATIVE, index 3)",
        "Use this path to reconfigure your wallet app",
    ])

    pdf.subsection("Workflow D: Recover a forgotten BIP39 passphrase  [Senior Analyst]")
    pdf.steps([
        "Elevate to Senior Analyst via role dropdown (enter 2FA code)",
        "Passphrase Recovery Attack -> enter seed phrase",
        "Enter the known wallet address as target",
        "Write candidate words / phrases one per line (names, dates, pet names, etc.)",
        "Select mutation rules (Capitalise, Append numbers are the most common)",
        "Review the candidate count estimate before starting",
        "Click START ATTACK — matching passphrase is highlighted if found",
    ])

    pdf.subsection("Workflow E: Recover from a BIP38 paper wallet  [Senior Analyst]")
    pdf.steps([
        "Elevate to Senior Analyst",
        "BIP38 Encrypted Key Tool -> paste the 6P... key",
        "Try Single Decrypt first if you have a passphrase candidate",
        "If that fails, build a candidate wordlist and click RUN DICTIONARY ATTACK",
        "On success, the decrypted WIF key and Bitcoin addresses are shown",
    ])

    pdf.subsection("Workflow F: Combine SLIP39 shares  [Senior Analyst]")
    pdf.steps([
        "Elevate to Senior Analyst",
        "SLIP39 Share Recovery -> paste your threshold-many shares, one per line",
        "Enter passphrase if one was set during share creation (usually none)",
        "Click COMBINE & DERIVE",
        "Derived addresses appear for ETH and BTC (all address types)",
        "Confirm against your known address",
    ])

    # ── Section 16: Security ──────────────────────────────────────────────────
    pdf.section("16", "Security Best Practices")
    pdf.bullet([
        "Air-gap the workstation. Disable Wi-Fi, Bluetooth, and all network interfaces "
        "at the OS level before entering any seed phrase.",
        "Never paste seeds in Live mode. The mode switch hides recovery pages, but as "
        "physical discipline keep secrets off the clipboard when the network is active.",
        "Do not photograph the screen. Use the built-in PDF exporter for all documentation.",
        "Lock the screen when stepping away. Sessions remain active in the browser tab.",
        "Keep your authenticator app entries backed up. Write down the TOTP seed when "
        "setting up and store it separately from the workstation.",
        "The audit log is permanent and non-editable by design for chain-of-custody integrity.",
        "Do not commit license.json or totp_secrets.json to version control. "
        "They contain machine-specific secrets.",
        "If you see CRITICAL: Build Integrity Check Failed on launch, stop immediately "
        "and contact your administrator. Do not attempt to bypass this check.",
    ])

    # ── Section 17: Troubleshooting ───────────────────────────────────────────
    pdf.section("17", "Troubleshooting")
    pdf.table(
        ["Error / Symptom", "Solution"],
        [
            ["MACHINE AUTHORIZATION FAILURE",
             "License is locked to different hardware. Send your Machine ID to your administrator."],
            ["LICENSE INACTIVE on every launch",
             "license.json is missing or corrupted. Contact administrator for a new CXLAB-... key."],
            ["CRITICAL: Build Integrity Check Failed",
             "A file was modified since signing. Re-extract the original ZIP or contact support."],
            ["TOTP code not accepted",
             "Check phone clock accuracy. Wait for the next 30-second window. If persistent, "
             "delete totp_secrets.json and redo 2FA setup."],
            ["App does not open in browser",
             "Navigate manually to http://localhost:8501. Check the terminal for error messages."],
            ["Blank white page",
             "Streamlit is still loading. Wait 3-5 seconds and refresh the browser tab."],
            ["Words not in BIP39 wordlist",
             "Fixed words in Incomplete Seed contain typos. Run through Typo Correction Lab first."],
            ["pip install fails (air-gapped machine)",
             "Run download_wheels.py on a connected machine, copy offline_wheels/, then "
             "run: python install.py --offline"],
        ],
        [74, 100]
    )


# ---------------------------------------------------------------------------
# Main — two-pass: build content, then write TOC on pre-reserved page 2
# ---------------------------------------------------------------------------

def main():
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        print("Installing Pillow for image sizing...")
        import subprocess, sys
        subprocess.run([sys.executable, "-m", "pip", "install", "Pillow", "-q"])

    DIST.mkdir(exist_ok=True)
    out = DIST / "CRYPTEX_LAB_Client_Guide.pdf"

    print("Building PDF...")
    pdf = TutorialPDF()

    pdf.title_page()   # page 1
    pdf.add_page()     # page 2 — pre-reserved for TOC (header() draws dark background)

    build(pdf)         # content starts on page 3

    # Go back to page 2 and fill in TOC now that page numbers are known
    last_page = pdf.page
    pdf.page = 2
    pdf.toc_page(pdf._toc)
    pdf.page = last_page

    pdf.output(str(out))
    size = out.stat().st_size
    print(f"Done. {out}  ({size:,} bytes, {pdf.page} pages)")


if __name__ == "__main__":
    main()
