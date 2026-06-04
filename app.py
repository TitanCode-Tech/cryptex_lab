"""
app.py
------
CRYPTEX LAB - Forensic Workstation (Streamlit UI)

Implements the CRYPTEX v2 design language over the offline backend modules.
All sensitive math runs locally. Live-mode lookups are gated by modes.py.
"""

from __future__ import annotations

import html as _html
import json
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

APP_NAME = "CRYPTEX LAB"
ICON_PATH = Path(__file__).resolve().parent / "assets" / "icon.png"

from modes import (
    init_mode,
    get_current_mode,
    set_mode,
    is_offline,
    is_live,
    OFFLINE_SAFE,
    LIVE_ANALYSIS,
)
from case_utils import (
    init_case_registry,
    get_active_case,
    get_all_cases,
    create_case,
    set_active_case,
    add_evidence_to_active_case,
    calculate_evidence_hash,
)
from security_utils import wipe_session_state
from wallet_utils import (
    validate_mnemonic,
    derive_eth_addresses,
    derive_btc_addresses,
    BTC_ADDRESS_TYPES,
)
from recovery_utils import (
    recover_missing_words,
    suggest_typo_corrections,
    recover_word_order,
    test_passphrase,
    estimate_recovery_time,
    MAX_MISSING_WORDS,
    MAX_ORDER_POSITIONS,
)
from derivation_utils import find_address_match, compare_all_standards
from forensic_utils import inspect_metamask_vault, identify_wallet_file
from hash_utils import (
    calculate_sha256,
    calculate_sha512,
    calculate_md5,
    calculate_sha1,
    calculate_ripemd160,
    calculate_hash160,
    calculate_double_sha256,
    hex_to_bytes,
    bytes_to_hex,
    b64_to_bytes,
    bytes_to_b64,
    encode_base58,
    decode_base58,
    satoshi_to_btc,
    wei_to_eth,
)
from entropy_utils import analyze_entropy
from export_utils import (
    build_txt_report,
    build_csv_report,
    build_pdf_report,
    build_qr_png,
)

try:
    import live_utils
except ImportError:
    live_utils = None

# Enterprise Security Imports & Helpers
from audit import log_event as log_audit_event
from license_utils import verify_license_data, check_module_access, verify_machine_fingerprint
from integrity import verify_build_integrity

import pyotp

def check_license() -> tuple[bool, str, dict]:
    license_path = Path("license.json")
    if not license_path.exists():
        return False, "License file (license.json) is missing.", {}
    try:
        with open(license_path, "r", encoding="utf-8") as f:
            license_dict = json.load(f)
        return verify_license_data(license_dict, Path("public_key.pem"))
    except Exception as e:
        return False, f"Failed to read license: {str(e)}", {}



# ---------------------------------------------------------------------------
# Page constants
# ---------------------------------------------------------------------------

PAGE_SECURITY_LANDING = "Security Landing"
PAGE_RECOVERY_SELECTOR = "Recovery Problem Selector"
PAGE_CASE_MGMT = "Case Management"
PAGE_EVIDENCE_HASH = "Evidence Hash Checker"

PAGE_BIP39_VALIDATION = "BIP39 Validation Lab"
PAGE_INCOMPLETE_SEED = "Incomplete Seed Recovery"
PAGE_TYPO_LAB = "Typo Correction Lab"
PAGE_WRONG_ORDER = "Wrong Word Order Helper"
PAGE_PASSPHRASE = "BIP39 Passphrase Testing"
PAGE_DERIVATION = "Derivation Path Scanner"
PAGE_ADDRESS_MATCHER = "Known Address Matcher"
PAGE_ADDRESS_GEN = "ETH/BTC Address Generator"
PAGE_ENTROPY = "Entropy Analysis Lab"
PAGE_VAULT_INSPECT = "MetaMask Vault Inspector"

PAGE_LIVE_ADDR = "Live Address Lookup"
PAGE_LIVE_TX = "Live TX Lookup"

PAGE_HASH_TOOLS = "Hash/Crypto Tools"
PAGE_AIRGAP_GUIDE = "Air-Gapped Ops Guide"
PAGE_EXPORTER = "Recovery Report Exporter"
PAGE_EDUCATION = "Educational Lab"
PAGE_WIPE = "Clear Session"


# Page icon glyphs (unicode entities, matching v2 HTML aesthetic)
PAGE_ICONS = {
    PAGE_SECURITY_LANDING: "\U0001F6E1",
    PAGE_RECOVERY_SELECTOR: "\U0001F50D",
    PAGE_CASE_MGMT: "\U0001F4C1",
    PAGE_EVIDENCE_HASH: "\U0001F9EC",
    PAGE_BIP39_VALIDATION: "\U0001F510",
    PAGE_INCOMPLETE_SEED: "\U0001F50E",
    PAGE_TYPO_LAB: "\U0001F520",
    PAGE_WRONG_ORDER: "\U0001F500",
    PAGE_PASSPHRASE: "\U0001F511",
    PAGE_DERIVATION: "⚡",
    PAGE_ADDRESS_MATCHER: "\U0001F3AF",
    PAGE_ADDRESS_GEN: "\U0001F4B3",
    PAGE_ENTROPY: "\U0001F3B2",
    PAGE_VAULT_INSPECT: "\U0001F98A",
    PAGE_LIVE_ADDR: "\U0001F4E1",
    PAGE_LIVE_TX: "\U0001F4E1",
    PAGE_HASH_TOOLS: "\U0001F9EE",
    PAGE_AIRGAP_GUIDE: "\U0001F6AB",
    PAGE_EXPORTER: "\U0001F4CA",
    PAGE_EDUCATION: "\U0001F4DA",
    PAGE_WIPE: "\U0001F9F9",
}


# ---------------------------------------------------------------------------
# CSS injection
# ---------------------------------------------------------------------------

CRYPTEX_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;600;700&display=swap');

:root {
  --bg:#020509; --panel:#050d14; --p2:#071320; --border:#0a3050;
  --a:#00d4ff; --a2:#00ff9d; --a3:#ff6b35; --a4:#bf5fff;
  --red:#ff3d3d; --txt:#c8e8f5; --dim:#4a7a9b;
  --glow:0 0 20px rgba(0,212,255,.3);
}

html, body, .stApp, [data-testid="stAppViewContainer"] {
  background:var(--bg) !important;
  color:var(--txt) !important;
  font-family:'Rajdhani', sans-serif !important;
}

[data-testid="stHeader"] {
  background:transparent !important;
  z-index:999 !important;
}
/* Style the sidebar collapse button highly aggressively */
[data-testid="stSidebarCollapseButton"] {
  position: fixed !important;
  color: var(--a) !important;
  background: rgba(0, 212, 255, .15) !important;
  border: 1px solid var(--a) !important;
  border-radius: 4px !important;
  top: 8px !important;
  left: 8px !important;
  z-index: 10000 !important;
  display: block !important;
  visibility: visible !important;
  transition: transform .35s cubic-bezier(.4,0,.2,1),
              background .25s ease,
              box-shadow .25s ease,
              border-color .25s ease !important;
  animation: cx-toggle-pulse 2.5s ease-in-out infinite !important;
}
@keyframes cx-toggle-pulse {
  0%, 100% { box-shadow: 0 0 6px rgba(0,212,255,.25); }
  50%      { box-shadow: 0 0 14px rgba(0,212,255,.5), 0 0 4px rgba(0,255,157,.2); }
}
/* Counter-act the sidebar's collapse transform (-300px) by shifting the button back */
[data-testid="stSidebar"][aria-expanded="false"] [data-testid="stSidebarCollapseButton"] {
  transform: translateX(300px) !important;
}
/* Flip the arrow icon based on sidebar state */
[data-testid="stSidebarCollapseButton"] svg {
  transition: transform .3s cubic-bezier(.4,0,.2,1) !important;
}
[data-testid="stSidebar"][aria-expanded="false"] [data-testid="stSidebarCollapseButton"] svg {
  transform: rotate(180deg) !important;
}
[data-testid="stSidebarCollapseButton"]:hover {
  background: rgba(0,212,255,.35) !important;
  box-shadow: 0 0 20px rgba(0,212,255,.5), 0 0 6px rgba(0,255,157,.3) !important;
  border-color: var(--a2) !important;
  animation: none !important;
}

/* Hide the "Made with Streamlit" menu but keep functionality */
[data-testid="stToolbar"] {visibility:hidden !important;}
footer {visibility:hidden;}
#MainMenu {visibility:hidden;}

/* Scanlines overlay */
.stApp::before {
  content:''; position:fixed; inset:0;
  background:repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,.04) 2px, rgba(0,0,0,.04) 4px);
  pointer-events:none; z-index:0;
}

/* Grid overlay */
[data-testid="stAppViewContainer"]::after {
  content:''; position:fixed; inset:0;
  background-image:linear-gradient(rgba(0,212,255,.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(0,212,255,.03) 1px, transparent 1px);
  background-size:40px 40px; pointer-events:none; z-index:-1;
}

.main, .block-container {
  background:transparent !important;
  padding-top:1rem !important;
  max-width:100% !important;
}

/* Sidebar styling */
[data-testid="stSidebar"], [data-testid="stSidebar"] > div {
  background:var(--panel) !important;
  border-right:1px solid var(--border);
}

/* Sidebar nav buttons - make them look like nav items, not blocky buttons */
[data-testid="stSidebar"] .stButton > button {
  background:transparent !important;
  border:none !important;
  border-left:2px solid transparent !important;
  border-radius:0 !important;
  color:var(--dim) !important;
  font-family:'Rajdhani', sans-serif !important;
  font-size:12px !important;
  font-weight:600;
  padding:7px 14px !important;
  text-align:left !important;
  justify-content:flex-start !important;
  transition:all .12s;
  box-shadow:none !important;
}
[data-testid="stSidebar"] .stButton > button:hover {
  background:rgba(0,212,255,.05) !important;
  color:var(--txt) !important;
  border-color:transparent !important;
}
/* Active nav button (type=primary) */
[data-testid="stSidebar"] .stButton > button[kind="primary"] {
  background:rgba(0,212,255,.09) !important;
  border-left-color:var(--a) !important;
  color:var(--a) !important;
}

/* Headings */
h1, h2, h3, h4, h5, h6 {
  font-family:'Orbitron', sans-serif !important;
  color:var(--a) !important;
  letter-spacing:2px !important;
  text-shadow:var(--glow);
}

/* Buttons - default cyan */
.stButton > button, .stDownloadButton > button {
  background:rgba(0,212,255,.1) !important;
  border:1px solid var(--a) !important;
  color:var(--a) !important;
  font-family:'Share Tech Mono', monospace !important;
  font-size:11px !important;
  letter-spacing:1px !important;
  border-radius:1px !important;
  padding:7px 14px !important;
  transition:all .12s !important;
  box-shadow:none !important;
}
.stButton > button:hover, .stDownloadButton > button:hover {
  background:rgba(0,212,255,.22) !important;
  color:var(--a) !important;
  border-color:var(--a) !important;
}
.stButton > button:focus, .stDownloadButton > button:focus {
  box-shadow:0 0 0 1px var(--a) !important;
}

/* Variants applied via parent wrapper */
.btn-green .stButton > button {
  background:rgba(0,255,157,.1) !important;
  border-color:var(--a2) !important; color:var(--a2) !important;
}
.btn-green .stButton > button:hover {background:rgba(0,255,157,.22) !important;}
.btn-orange .stButton > button {
  background:rgba(255,107,53,.1) !important;
  border-color:var(--a3) !important; color:var(--a3) !important;
}
.btn-orange .stButton > button:hover {background:rgba(255,107,53,.22) !important;}
.btn-red .stButton > button {
  background:rgba(255,61,61,.1) !important;
  border-color:var(--red) !important; color:var(--red) !important;
}
.btn-red .stButton > button:hover {background:rgba(255,61,61,.22) !important;}
.btn-purple .stButton > button {
  background:rgba(191,95,255,.1) !important;
  border-color:var(--a4) !important; color:var(--a4) !important;
}
.btn-purple .stButton > button:hover {background:rgba(191,95,255,.22) !important;}

/* Inputs */
.stTextInput input, .stTextArea textarea, .stNumberInput input,
[data-baseweb="select"] > div, .stSelectbox > div > div {
  background:#000 !important;
  border:1px solid var(--border) !important;
  color:var(--txt) !important;
  font-family:'Share Tech Mono', monospace !important;
  font-size:12px !important;
  border-radius:1px !important;
}
.stTextInput input:focus, .stTextArea textarea:focus, .stNumberInput input:focus {
  border-color:var(--a) !important;
  box-shadow:none !important;
}
.stTextInput label, .stTextArea label, .stSelectbox label, .stNumberInput label, .stRadio label, .stFileUploader label {
  font-family:'Share Tech Mono', monospace !important;
  font-size:10px !important;
  color:var(--dim) !important;
  letter-spacing:1px !important;
  text-transform:uppercase;
}

/* File uploader */
[data-testid="stFileUploader"] section, [data-testid="stFileUploaderDropzone"] {
  background:#000 !important;
  border:2px dashed var(--border) !important;
  border-radius:1px !important;
}
[data-testid="stFileUploader"] section:hover {border-color:var(--a) !important;}

/* Code blocks */
pre, code, .stCode, [data-testid="stCodeBlock"] {
  background:#000 !important;
  border:1px solid var(--border);
  color:var(--a2) !important;
  font-family:'Share Tech Mono', monospace !important;
  font-size:11px !important;
}

/* Metric */
[data-testid="stMetric"] {
  background:var(--p2);
  border:1px solid var(--border);
  padding:12px !important;
}
[data-testid="stMetricLabel"] {
  font-family:'Share Tech Mono', monospace !important;
  font-size:9px !important;
  color:var(--dim) !important;
  letter-spacing:1px;
}
[data-testid="stMetricValue"] {
  font-family:'Orbitron', sans-serif !important;
  color:var(--a) !important;
  font-size:22px !important;
  font-weight:700 !important;
}

/* Alerts */
.stAlert {
  background:var(--p2) !important;
  border:1px solid var(--border) !important;
  border-radius:1px !important;
  font-family:'Share Tech Mono', monospace !important;
  font-size:11px !important;
}
.stAlert[data-baseweb="notification"] [data-testid="stMarkdownContainer"] p {color:var(--txt) !important;}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
  gap:4px; background:transparent; border-bottom:1px solid var(--border);
}
.stTabs [data-baseweb="tab"] {
  background:transparent !important;
  color:var(--dim) !important;
  font-family:'Share Tech Mono', monospace !important;
  font-size:10px !important;
  letter-spacing:1px !important;
  border:1px solid var(--border) !important;
  border-bottom:none !important;
  padding:6px 14px !important;
}
.stTabs [aria-selected="true"] {
  color:var(--a) !important;
  border-color:var(--a) !important;
  background:rgba(0,212,255,.08) !important;
}

/* DataFrame */
[data-testid="stDataFrame"] {
  background:var(--p2) !important;
  border:1px solid var(--border);
}

/* Expander */
[data-testid="stExpander"] {
  background:var(--p2) !important;
  border:1px solid var(--border) !important;
  border-radius:1px !important;
}
[data-testid="stExpander"] summary {
  font-family:'Share Tech Mono', monospace !important;
  font-size:10px !important;
  color:var(--a) !important;
  letter-spacing:1px;
}

/* Divider */
hr, [data-testid="stDivider"] {
  border-color:var(--border) !important;
  margin:8px 0 !important;
}

/* Caption */
.stCaption, [data-testid="stCaptionContainer"] {
  font-family:'Share Tech Mono', monospace !important;
  font-size:9px !important;
  color:var(--dim) !important;
  letter-spacing:1px !important;
}

/* Markdown defaults */
.stMarkdown, [data-testid="stMarkdownContainer"] {
  font-family:'Rajdhani', sans-serif !important;
  color:var(--txt);
}

/* --- Custom-rendered chrome (header/section/box/term) --- */
.cx-header {
  position:relative; z-index:10;
  background:rgba(2,5,9,.97); backdrop-filter:blur(10px);
  border-bottom:1px solid var(--border);
  padding:8px 14px 8px 60px; margin:0 -1rem 14px -1rem;
  display:flex; align-items:center; justify-content:space-between;
}
.cx-logo {
  font-family:'Orbitron', sans-serif; font-size:18px; font-weight:900;
  color:var(--a); text-shadow:var(--glow); letter-spacing:4px;
}
.cx-logo em {color:var(--a2); font-style:normal;}
.cx-logo small {
  font-family:'Share Tech Mono', monospace; font-size:10px;
  color:var(--dim); letter-spacing:1px; margin-left:10px;
}
.cx-hbar {display:flex; align-items:center; gap:14px; flex-wrap:wrap;}
.cx-hitem {
  display:flex; align-items:center; gap:6px;
  font-family:'Share Tech Mono', monospace;
  font-size:10px; color:var(--dim);
}
.cx-dot {
  width:7px; height:7px; border-radius:50%;
  background:var(--a2); animation:cx-blink 2s infinite;
}
.cx-dot.red {background:var(--red);}
.cx-dot.orange {background:var(--a3);}
@keyframes cx-blink {0%,100% {opacity:1} 50% {opacity:.4}}
.cx-badge {
  font-family:'Orbitron', sans-serif; font-size:9px; font-weight:700;
  padding:3px 9px; letter-spacing:2px;
  border:1px solid var(--a3); color:var(--a3);
}
.cx-badge.green {border-color:var(--a2); color:var(--a2);}
.cx-badge.red {border-color:var(--red); color:var(--red);}

.cx-section {
  display:flex; align-items:center; gap:10px;
  margin:6px 0 14px 0; padding-bottom:8px;
  border-bottom:1px solid var(--border);
}
.cx-section .title {
  font-family:'Orbitron', sans-serif; font-size:13px; font-weight:700;
  color:var(--a); letter-spacing:2px;
}
.cx-section .sub {
  font-size:10px; color:var(--dim); margin-left:auto;
  font-family:'Share Tech Mono', monospace; letter-spacing:1px;
}

.cx-box {
  background:var(--p2); border:1px solid var(--border);
  border-radius:2px; margin-bottom:14px; overflow:hidden;
}
.cx-box .head {
  display:flex; align-items:center; justify-content:space-between;
  padding:7px 13px;
  background:rgba(0,212,255,.05);
  border-bottom:1px solid var(--border);
  font-family:'Share Tech Mono', monospace;
  font-size:11px; color:var(--a);
  letter-spacing:1px;
}
.cx-box .head .live {color:var(--a2); font-size:9px; animation:cx-blink 1.5s infinite;}
.cx-box .body {padding:13px;}

/* Status cards grid */
.cx-cards {
  display:grid; gap:11px; margin-bottom:14px;
}
.cx-cards.g2 {grid-template-columns:1fr 1fr;}
.cx-cards.g3 {grid-template-columns:1fr 1fr 1fr;}
.cx-cards.g4 {grid-template-columns:1fr 1fr 1fr 1fr;}
.cx-sc {
  background:var(--p2); border:1px solid var(--border);
  padding:12px;
}
.cx-sc .sl {
  font-family:'Share Tech Mono', monospace;
  font-size:9px; color:var(--dim); margin-bottom:5px; letter-spacing:1px;
}
.cx-sc .sv {
  font-family:'Orbitron', sans-serif;
  font-size:20px; font-weight:700; color:var(--a);
}
.cx-sc .sv.green {color:var(--a2);}
.cx-sc .sv.orange {color:var(--a3);}
.cx-sc .sv.red {color:var(--red);}
.cx-sc .sd {font-size:10px; color:var(--dim); margin-top:3px;}

/* Terminal */
.cx-term {
  background:#000; border:1px solid var(--border);
  border-radius:2px; overflow:hidden; margin-bottom:14px;
}
.cx-term .tb {
  display:flex; align-items:center; gap:7px;
  padding:5px 11px; background:#0a0a0a; border-bottom:1px solid #111;
}
.cx-term .td {width:9px; height:9px; border-radius:50%;}
.cx-term .tt {
  font-family:'Share Tech Mono', monospace;
  font-size:10px; color:#444; margin-left:5px; flex:1;
}
.cx-term .to {
  padding:12px; font-family:'Share Tech Mono', monospace;
  font-size:11px; line-height:1.65;
  min-height:130px; max-height:300px; overflow-y:auto;
}
.cx-term .tp {color:var(--a2);}
.cx-term .tl {display:block;}
.cx-term .c-ok {color:var(--a2);}
.cx-term .c-info {color:var(--a);}
.cx-term .c-warn {color:var(--a3);}
.cx-term .c-err {color:var(--red);}
.cx-term .c-dim {color:#666;}
.cx-term .c-cmd {color:#fff;}

/* Result block */
.cx-rblock {
  background:rgba(0,255,157,.04);
  border:1px solid rgba(0,255,157,.2);
  padding:12px; margin-top:10px;
  font-family:'Share Tech Mono', monospace;
  font-size:11px; line-height:1.7;
}
.cx-rblock .rk {color:var(--dim);}
.cx-rblock .rv {color:var(--a2);}
.cx-rblock .ra {color:var(--a);}
.cx-rblock .ro {color:var(--a3);}
.cx-rblock .rr {color:var(--red);}

/* Compact table */
.cx-dt {
  width:100%; border-collapse:collapse; font-size:11px;
  font-family:'Share Tech Mono', monospace;
  background:var(--p2);
}
.cx-dt th {
  font-size:9px; color:var(--dim); letter-spacing:1px;
  padding:7px 9px; text-align:left;
  border-bottom:1px solid var(--border);
  background:rgba(0,212,255,.03);
}
.cx-dt td {
  padding:7px 9px;
  border-bottom:1px solid rgba(10,48,80,.4);
  font-size:10px; color:var(--txt);
  vertical-align:middle; word-break:break-all;
}
.cx-dt tr:hover td {background:rgba(0,212,255,.04);}
.cx-tag {
  display:inline-block; padding:1px 7px;
  font-size:9px; border-radius:1px; border:1px solid currentColor;
}
.cx-tag.green {color:var(--a2);}
.cx-tag.orange {color:var(--a3);}
.cx-tag.red {color:var(--red);}
.cx-tag.cyan {color:var(--a);}
.cx-tag.purple {color:var(--a4);}

/* Active case banner */
.cx-banner {
  display:flex; align-items:center; gap:14px;
  background:rgba(0,212,255,.06);
  border:1px solid var(--border);
  border-left:3px solid var(--a);
  padding:8px 14px; margin-bottom:14px;
  font-family:'Share Tech Mono', monospace; font-size:11px;
}
.cx-banner.muted {
  border-left-color:var(--dim);
  background:rgba(74,122,155,.04);
  color:var(--dim);
}
.cx-banner .label {color:var(--dim); letter-spacing:1px;}
.cx-banner .val {color:var(--a); margin-right:14px;}
.cx-banner .pulse {
  width:7px; height:7px; border-radius:50%;
  background:var(--a2); animation:cx-blink 1.4s infinite;
}

/* Sidebar nav category header */
.cx-ns {
  padding:9px 14px 3px;
  font-family:'Share Tech Mono', monospace;
  font-size:9px; color:var(--dim); letter-spacing:2px;
  text-transform:uppercase;
}

/* Sidebar logo */
.cx-sb-logo {
  font-family:'Orbitron', sans-serif; font-weight:900;
  font-size:18px; color:var(--a); letter-spacing:4px;
  text-shadow:var(--glow);
  padding:10px 14px 4px;
}
.cx-sb-logo em {color:var(--a2); font-style:normal;}
.cx-sb-sub {
  padding:0 14px 8px;
  font-family:'Share Tech Mono', monospace;
  font-size:9px; color:var(--dim); letter-spacing:1px;
}

/* Mode pills */
.cx-mode {
  margin:6px 14px 10px; padding:6px 10px;
  font-family:'Share Tech Mono', monospace; font-size:10px;
  border-radius:1px; letter-spacing:1px; text-align:center;
}
.cx-mode.off {background:rgba(0,255,157,.08); border:1px solid var(--a2); color:var(--a2);}
.cx-mode.live {background:rgba(255,61,61,.08); border:1px solid var(--red); color:var(--red);}

/* Make Streamlit's columns slightly tighter for grid feel */
[data-testid="column"] {padding:0 6px;}

/* Generic muted card */
.cx-card {
  background:var(--p2); border:1px solid var(--border);
  padding:13px; margin-bottom:10px;
  font-family:'Share Tech Mono', monospace; font-size:11px;
}
.cx-card h4 {
  font-family:'Orbitron', sans-serif; font-size:12px;
  color:var(--a); letter-spacing:2px; margin-bottom:6px;
}
</style>
"""


def inject_cryptex_css() -> None:
    st.markdown(CRYPTEX_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(s) -> str:
    return _html.escape(str(s))


def render_header() -> None:
    mode = get_current_mode()
    cases = get_all_cases()
    case_count = len(cases)
    if mode == OFFLINE_SAFE:
        mode_badge = '<span class="cx-badge green">OFFLINE SAFE</span>'
        mode_dot = '<div class="cx-hitem"><div class="cx-dot"></div>AIRGAP OK</div>'
    else:
        mode_badge = '<span class="cx-badge red">LIVE ANALYSIS</span>'
        mode_dot = '<div class="cx-hitem"><div class="cx-dot red"></div>NETWORK ACTIVE</div>'

    html_block = f"""
    <div class="cx-header">
      <div class="cx-logo">CRYPT<em>EX</em> LAB<small>v3 // FORENSIC WORKSTATION</small></div>
      <div class="cx-hbar">
        {mode_dot}
        <div class="cx-hitem"><div class="cx-dot"></div>{case_count} CASES</div>
        <div class="cx-hitem"><div class="cx-dot orange"></div>SESSION LIVE</div>
        {mode_badge}
      </div>
    </div>
    """
    st.markdown(html_block, unsafe_allow_html=True)


def render_section_header(icon: str, title: str, subtitle: str = "") -> None:
    sub = f'<span class="sub">{_esc(subtitle)}</span>' if subtitle else ""
    st.markdown(
        f'<div class="cx-section"><span class="title">{_esc(icon)} {_esc(title)}</span>{sub}</div>',
        unsafe_allow_html=True,
    )


def open_box(header: str, live: bool = False, accent: str = "") -> None:
    live_html = '<span class="live">&#9679; LIVE</span>' if live else ""
    st.markdown(
        f'<div class="cx-box"><div class="head">{_esc(header)}{live_html}</div><div class="body">',
        unsafe_allow_html=True,
    )


def close_box() -> None:
    st.markdown("</div></div>", unsafe_allow_html=True)


def render_status_cards(cards, columns: int = 4) -> None:
    """cards: list of tuples (label, value, variant, optional_descr)."""
    cls = {2: "g2", 3: "g3"}.get(columns, "g4")
    inner = ""
    for c in cards:
        label, value, variant = c[0], c[1], (c[2] if len(c) > 2 else "")
        descr = c[3] if len(c) > 3 else ""
        v_cls = f"sv {variant}" if variant else "sv"
        descr_html = f'<div class="sd">{_esc(descr)}</div>' if descr else ""
        inner += (
            f'<div class="cx-sc"><div class="sl">{_esc(label)}</div>'
            f'<div class="{v_cls}">{_esc(value)}</div>{descr_html}</div>'
        )
    st.markdown(f'<div class="cx-cards {cls}">{inner}</div>', unsafe_allow_html=True)


def log_event(kind: str, text: str) -> None:
    if "activity_log" not in st.session_state:
        st.session_state["activity_log"] = []
    ts = datetime.now().strftime("%H:%M:%S")
    st.session_state["activity_log"].append({"ts": ts, "kind": kind, "text": text})
    st.session_state["activity_log"] = st.session_state["activity_log"][-200:]


def render_terminal(title: str = "session :: cryptex", max_lines: int = 40) -> None:
    log = st.session_state.get("activity_log", [])
    rows = ""
    for entry in log[-max_lines:]:
        kind = entry.get("kind", "info")
        text = _esc(entry.get("text", ""))
        ts = _esc(entry.get("ts", ""))
        if kind == "cmd":
            row = f'<span class="tl"><span class="c-ok">$ </span><span class="c-cmd">{text}</span></span>'
        elif kind == "ok":
            row = f'<span class="tl"><span class="c-ok">[{ts}] &#10004; {text}</span></span>'
        elif kind == "warn":
            row = f'<span class="tl"><span class="c-warn">[{ts}] &#9888; {text}</span></span>'
        elif kind == "err":
            row = f'<span class="tl"><span class="c-err">[{ts}] &#10007; {text}</span></span>'
        else:
            row = f'<span class="tl"><span class="c-dim">[{ts}]</span> <span class="c-info">{text}</span></span>'
        rows += row
    if not rows:
        rows = '<span class="tl"><span class="c-ok">&#10004;</span> <span class="c-dim">CRYPTEX session ready. Awaiting commands.</span></span>'
    html_block = f"""
    <div class="cx-term">
      <div class="tb">
        <div class="td" style="background:#ff5f57"></div>
        <div class="td" style="background:#febc2e"></div>
        <div class="td" style="background:#28c840"></div>
        <span class="tt">{_esc(title)}</span>
      </div>
      <div class="to">{rows}</div>
    </div>
    """
    st.markdown(html_block, unsafe_allow_html=True)


def render_rblock(rows) -> None:
    """rows: list of (label, value, color_cls). color_cls in: rk/rv/ra/ro/rr."""
    body = ""
    for r in rows:
        label, value = r[0], r[1]
        cls = r[2] if len(r) > 2 else "ra"
        body += f'<div><span class="rk">{_esc(label)}:</span> <span class="{cls}">{_esc(value)}</span></div>'
    st.markdown(f'<div class="cx-rblock">{body}</div>', unsafe_allow_html=True)


def render_data_table(headers, rows) -> None:
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = ""
    for row in rows:
        cells = "".join(f"<td>{c if isinstance(c, str) and c.startswith('<span') else _esc(c)}</td>" for c in row)
        body += f"<tr>{cells}</tr>"
    st.markdown(f'<table class="cx-dt"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>', unsafe_allow_html=True)


def render_active_case_banner() -> None:
    active = get_active_case()
    if active:
        st.markdown(
            f'<div class="cx-banner">'
            f'<div class="pulse"></div>'
            f'<span class="label">ACTIVE CASE:</span><span class="val">{_esc(active["id"])} &middot; {_esc(active["name"])}</span>'
            f'<span class="label">INVESTIGATOR:</span><span class="val">{_esc(active["investigator"] or "n/a")}</span>'
            f'<span class="label">CHAIN:</span><span class="val">{_esc(active["chain"])}</span>'
            f"</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="cx-banner muted">'
            '<span class="label">NO ACTIVE CASE</span>'
            '<span>&middot; Open one in CASE MANAGEMENT to enable evidence logging</span>'
            "</div>",
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

NAV_GROUPS_OFFLINE = [
    ("CORE", [PAGE_SECURITY_LANDING, PAGE_CASE_MGMT, PAGE_EVIDENCE_HASH]),
    ("RECOVERY TOOLS", [
        PAGE_RECOVERY_SELECTOR,
        PAGE_INCOMPLETE_SEED,
        PAGE_TYPO_LAB,
        PAGE_WRONG_ORDER,
        PAGE_PASSPHRASE,
    ]),
    ("FORENSICS", [
        PAGE_BIP39_VALIDATION,
        PAGE_ENTROPY,
        PAGE_VAULT_INSPECT,
        PAGE_DERIVATION,
        PAGE_ADDRESS_MATCHER,
        PAGE_ADDRESS_GEN,
    ]),
    ("UTILITIES", [
        PAGE_HASH_TOOLS,
        PAGE_EXPORTER,
        PAGE_AIRGAP_GUIDE,
        PAGE_EDUCATION,
        PAGE_WIPE,
    ]),
]

NAV_GROUPS_LIVE = [
    ("CORE", [PAGE_SECURITY_LANDING, PAGE_CASE_MGMT, PAGE_EVIDENCE_HASH]),
    ("LIVE TOOLS", [PAGE_LIVE_ADDR, PAGE_LIVE_TX]),
    ("UTILITIES", [
        PAGE_HASH_TOOLS,
        PAGE_EXPORTER,
        PAGE_AIRGAP_GUIDE,
        PAGE_EDUCATION,
        PAGE_WIPE,
    ]),
]


def render_sidebar() -> str:
    with st.sidebar:
        st.markdown(
            '<div class="cx-sb-logo">CRYPT<em>EX</em></div>'
            '<div class="cx-sb-sub">FORENSIC WORKSTATION v3</div>',
            unsafe_allow_html=True,
        )

        mode = get_current_mode()
        if mode == OFFLINE_SAFE:
            st.markdown('<div class="cx-mode off">&#9679; OFFLINE SAFE</div>', unsafe_allow_html=True)
            if st.button("🔴  ENGAGE LIVE ANALYSIS", key="mode_to_live", use_container_width=True):
                set_mode(LIVE_ANALYSIS)
                log_event("warn", "Switched to LIVE ANALYSIS mode")
                st.rerun()
            groups = NAV_GROUPS_OFFLINE
        else:
            st.markdown('<div class="cx-mode live">&#9679; LIVE ANALYSIS</div>', unsafe_allow_html=True)
            if st.button("🟢  RETURN TO OFFLINE SAFE", key="mode_to_offline", use_container_width=True):
                set_mode(OFFLINE_SAFE)
                log_event("ok", "Returned to OFFLINE SAFE mode")
                st.rerun()
            groups = NAV_GROUPS_LIVE

        st.divider()

        # License Check & Visual Feedback
        is_license_valid, err, license_data = check_license()
        if is_license_valid:
            client_name = license_data.get("client", "Authorized User")
            st.markdown(f'<div class="cx-tag green" style="display:block; text-align:center; margin-bottom:10px; font-weight:bold;">🔑 LICENSE ACTIVE: {client_name}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="cx-tag red" style="display:block; text-align:center; margin-bottom:10px; font-weight:bold;">🔒 LICENSE INACTIVE</div>', unsafe_allow_html=True)

        # User Role Selection (RBAC)
        if "user_role" not in st.session_state:
            st.session_state["user_role"] = "Analyst"
        
        current_role = st.session_state["user_role"]
        roles_list = ["Viewer", "Analyst", "Senior Analyst", "Admin"]
        selected_role = st.selectbox(
            "ROLE ASSIGNMENT",
            roles_list,
            index=roles_list.index(current_role),
            key="user_role_selector_sidebar"
        )
        if selected_role != current_role:
            if selected_role in TOTP_PROTECTED_ROLES:
                # Gate elevation behind TOTP — store pending and redirect to challenge
                st.session_state["pending_role"] = selected_role
                st.session_state.pop("totp_fail_count", None)
                st.session_state.pop("totp_locked_until", None)
            else:
                # Downgrade or switch to unprotected role — no 2FA needed
                st.session_state["user_role"] = selected_role
                st.session_state.pop("pending_role", None)
                log_event("ok", f"Changed role to {selected_role}")
                st.session_state["authorized_for_recovery"] = False
            st.rerun()

        st.divider()

        current = st.session_state.get("current_page", PAGE_SECURITY_LANDING)

        for group_name, pages in groups:
            st.markdown(f'<div class="cx-ns">{group_name}</div>', unsafe_allow_html=True)
            for p in pages:
                icon = PAGE_ICONS.get(p, "")
                label = f"{icon}  {p}"
                btn_key = f"nav_btn_{p}"
                is_active = (p == current)

                # Use type="primary" for the active page to visually highlight it
                if st.button(
                    label,
                    key=btn_key,
                    use_container_width=True,
                    type="primary" if is_active else "secondary",
                ):
                    if not is_active:
                        st.session_state["current_page"] = p
                        st.rerun()

        st.divider()
        st.markdown('<div class="cx-ns">SESSION</div>', unsafe_allow_html=True)
        st.caption(f"Build 2026.05 / pid {id(st.session_state) % 99999}")

        return st.session_state.get("current_page", PAGE_SECURITY_LANDING)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def _btn(label: str, *, key: str, variant: str = "cyan", use_container_width: bool = False) -> bool:
    """Render a colored streamlit button via a wrapper div."""
    cls_map = {
        "cyan": "",
        "green": "btn-green",
        "orange": "btn-orange",
        "red": "btn-red",
        "purple": "btn-purple",
    }
    cls = cls_map.get(variant, "")
    if cls:
        st.markdown(f'<div class="{cls}">', unsafe_allow_html=True)
    clicked = st.button(label, key=key, use_container_width=use_container_width)
    if cls:
        st.markdown("</div>", unsafe_allow_html=True)
    return clicked


def page_security_landing():
    render_section_header("\U0001F6E1", "SECURITY LANDING", "PROTOCOL OVERVIEW")
    mode = get_current_mode()
    cases = get_all_cases()
    evidence_count = sum(len(c.get("evidence", [])) for c in cases)
    started_at = st.session_state.get("_session_started_at")
    if started_at is None:
        started_at = datetime.now(timezone.utc)
        st.session_state["_session_started_at"] = started_at
    session_age = datetime.now(timezone.utc) - started_at
    mins, secs = divmod(int(session_age.total_seconds()), 60)
    hrs, mins = divmod(mins, 60)
    age_str = f"{hrs:02d}:{mins:02d}:{secs:02d}"

    render_status_cards([
        ("CURRENT MODE", "OFFLINE" if mode == OFFLINE_SAFE else "LIVE", "green" if mode == OFFLINE_SAFE else "red", "operational"),
        ("ACTIVE CASES", str(len(cases)), "" if cases else "orange", "in registry"),
        ("EVIDENCE LOGGED", str(evidence_count), "green" if evidence_count else "", "hash entries"),
        ("SESSION AGE", age_str, "", "since boot"),
    ])

    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("OPERATIONAL PROTOCOL")
        st.markdown(
            """
- Verify the machine is **air-gapped** before entering OFFLINE SAFE work.
- Disable Wi-Fi, Bluetooth, and any LAN interface at the OS level.
- No external storage attached unless it has been independently hashed.
- Sensitive seeds, keys, and passphrases stay in volatile session state only.
- Every export goes through a whitelist; secrets cannot leak by export.
            """
        )
        close_box()

        open_box("DUAL-MODE ARCHITECTURE")
        st.markdown(
            """
**OFFLINE SAFE** - default mode. All recovery, derivation, hashing,
entropy, and forensic features run locally. No network sockets are opened.
The `live_utils` import is permitted but its functions are guarded by
`@require_live` and will refuse to run.

**LIVE ANALYSIS** - opt-in. Blockchain lookups against public APIs
(Blockstream, mempool.space, Etherscan public endpoint) are enabled.
All sensitive recovery pages are hidden from the sidebar until you
return to OFFLINE SAFE.
            """
        )
        close_box()
    with col2:
        render_terminal("security-landing :: cryptex")
        open_box("AIRGAP CHECKLIST")
        st.markdown(
            """
- [x] Run venv installed offline
- [x] Backend modules import nothing live
- [x] Reports whitelist public fields only
- [ ] Confirm host has no network route
- [ ] Verify clipboard manager is disabled
            """
        )
        close_box()

    log_event("info", "Viewed SECURITY LANDING")


def page_case_mgmt():
    render_section_header("\U0001F4C1", "CASE MANAGEMENT", "REAL SHA256 CUSTODY HASHING")
    cases = get_all_cases()
    active = get_active_case()
    open_count = len(cases)
    evidence_total = sum(len(c.get("evidence", [])) for c in cases)
    render_status_cards([
        ("CASES IN REGISTRY", str(open_count), "" if open_count else "orange"),
        ("EVIDENCE ATTACHED", str(evidence_total), "green" if evidence_total else ""),
        ("ACTIVE CASE", active["id"] if active else "NONE", "green" if active else "orange"),
        ("MODE", "OFFLINE" if is_offline() else "LIVE", "green" if is_offline() else "red"),
    ])

    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("NEW CASE INTAKE")
        with st.form("new_case_form", clear_on_submit=True):
            r1c1, r1c2 = st.columns(2)
            with r1c1:
                pri = st.selectbox("PRIORITY", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
            with r1c2:
                chain = st.selectbox("CHAIN", ["Bitcoin", "Ethereum", "Multi-Chain", "Solana", "Monero", "Other"])
            inc_type = st.selectbox(
                "INCIDENT TYPE",
                ["Lost Seed Phrase", "Exchange Hack", "Rugpull Trace", "HW Wallet Failure",
                 "DeFi Exploit", "Ransomware", "Smart Contract Exploit", "Other"],
            )
            r2c1, r2c2 = st.columns(2)
            with r2c1:
                asset = st.text_input("ASSET", placeholder="BTC / ETH...")
            with r2c2:
                value = st.text_input("VALUE (USD)", placeholder="250000")
            lead = st.text_input("LEAD ANALYST", placeholder="Name / Badge / Firm")
            case_name = st.text_input("CASE DESIGNATION", placeholder="Target wallet / incident handle")
            notes = st.text_area("NOTES", placeholder="Describe incident details...")
            submitted = st.form_submit_button("CREATE CASE")
            if submitted:
                try:
                    desc_lines = [
                        f"Priority: {pri}",
                        f"Incident: {inc_type}",
                        f"Asset: {asset}",
                        f"Value (USD): {value}",
                        notes,
                    ]
                    cid = create_case(
                        case_name=case_name or f"{inc_type} - {chain}",
                        investigator=lead or "Unassigned",
                        chain=chain,
                        description="\n".join(s for s in desc_lines if s),
                    )
                    log_event("ok", f"Created case {cid}")
                    st.success(f"Case {cid} created and set active.")
                    st.rerun()
                except ValueError as e:
                    log_event("err", f"Case create failed: {e}")
                    st.error(str(e))
        close_box()
    with col2:
        render_terminal("case-mgmt :: registry")
        open_box("ACTIVE CASE")
        if active:
            render_rblock([
                ("ID", active["id"], "ra"),
                ("NAME", active["name"], "rv"),
                ("INVESTIGATOR", active["investigator"], "rv"),
                ("CHAIN", active["chain"], "ra"),
                ("CREATED", active["created_at"], "rk"),
                ("EVIDENCE", str(len(active.get("evidence", []))), "rv"),
            ])
        else:
            st.markdown('<div class="cx-rblock"><span class="rk">No active case selected.</span></div>', unsafe_allow_html=True)
        close_box()

    open_box(f"ACTIVE CASE REGISTRY ({len(cases)} cases)")
    if not cases:
        st.markdown('<div class="cx-rblock"><span class="rk">Registry empty. Create a case above.</span></div>', unsafe_allow_html=True)
    else:
        headers = ["ID", "NAME", "CHAIN", "LEAD", "EVIDENCE", "CREATED", "ACTIVE"]
        rows = []
        for c in cases:
            active_tag = '<span class="cx-tag green">ACTIVE</span>' if active and active["id"] == c["id"] else ""
            rows.append([
                c["id"],
                c["name"],
                c["chain"],
                c["investigator"],
                str(len(c.get("evidence", []))),
                c["created_at"].split("T")[0],
                active_tag,
            ])
        render_data_table(headers, rows)

        st.markdown("##### Activate a case")
        cols = st.columns(min(4, max(1, len(cases))))
        for idx, c in enumerate(cases):
            with cols[idx % len(cols)]:
                if st.button(f"▶ {c['id']}", key=f"activate_{c['id']}"):
                    set_active_case(c["id"])
                    log_event("ok", f"Activated case {c['id']}")
                    st.rerun()
    close_box()


def page_evidence_hash():
    render_section_header("\U0001F9EC", "EVIDENCE HASH CHECKER", "REAL SHA256 / SHA512 / MD5")
    active = get_active_case()
    if not active:
        st.warning("No active case. Hashes will be computed but not attached. Open a case under CASE MANAGEMENT first.")

    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("UPLOAD EVIDENCE FILE")
        st.markdown(
            '<div style="border:2px dashed #0a3050;padding:14px;text-align:center;'
            'font-family:\'Share Tech Mono\',monospace;color:#4a7a9b;font-size:11px;'
            'margin-bottom:8px">'
            '&#128206; Drop a file below for offline hashing. The file never leaves this machine.'
            "</div>",
            unsafe_allow_html=True,
        )
        uploaded = st.file_uploader("Select evidence file", accept_multiple_files=False, key="evidence_file_upload")
        notes = st.text_input("EVIDENCE DESCRIPTION / SOURCE", key="evidence_notes")
        if uploaded is not None:
            data = uploaded.getvalue()
            hashes = calculate_evidence_hash(data)
            render_rblock([
                ("FILE", uploaded.name, "rv"),
                ("SIZE", f"{hashes['size_bytes']} bytes", "ra"),
                ("MD5", hashes["md5"], "ro"),
                ("SHA-1", hashes["sha1"], "ro"),
                ("SHA-256", hashes["sha256"], "rv"),
                ("SHA-512", calculate_sha512(data), "rk"),
            ])
            # Fingerprint extras
            try:
                info = identify_wallet_file(data, uploaded.name)
                render_rblock([
                    ("FORMAT", info["guessed_format"], "ra"),
                    ("LABEL", info["label"], "rv"),
                    ("CONTAINS SECRETS?", "YES - HANDLE CAREFULLY" if info["contains_secrets_warning"] else "no", "rr" if info["contains_secrets_warning"] else "rk"),
                    ("NOTES", "; ".join(info["notes"]) or "-", "rk"),
                ])
            except Exception as e:
                st.warning(f"Fingerprint failed: {e}")

            if active and _btn("ATTACH TO ACTIVE CASE", key="attach_evidence", variant="green"):
                add_evidence_to_active_case(uploaded.name, data, notes)
                log_event("ok", f"Attached evidence {uploaded.name} to {active['id']}")
                st.success(f"Evidence {uploaded.name} attached to {active['id']}.")
                st.rerun()
        close_box()
    with col2:
        render_terminal("evidence-hash :: SHA256")
        if active and active.get("evidence"):
            open_box("ATTACHED EVIDENCE")
            headers = ["FILENAME", "SHA-256", "WHEN"]
            rows = [
                [e["filename"], e["sha256"][:18] + "...", e["timestamp"].split("T")[1].split(".")[0]]
                for e in active["evidence"]
            ]
            render_data_table(headers, rows)
            close_box()


def page_recovery_selector():
    render_section_header("\U0001F50D", "RECOVERY PROBLEM SELECTOR", "PICK THE RIGHT TOOL")
    st.markdown(
        "Select the closest match to your recovery situation. Each card routes to the appropriate"
        " offline engine."
    )
    grid = st.columns(2)
    items = [
        ("Missing 1-2 Words", "Brute-force the unknown slots while checking a target address.", PAGE_INCOMPLETE_SEED, "purple"),
        ("Misspelled Words", "Levenshtein suggestions against the BIP39 wordlist.", PAGE_TYPO_LAB, "orange"),
        ("Words Out of Order", f"Permute up to {MAX_ORDER_POSITIONS} words to find a valid checksum.", PAGE_WRONG_ORDER, "cyan"),
        ("Forgot Passphrase", "Test a candidate BIP39 passphrase against a target address.", PAGE_PASSPHRASE, "green"),
        ("Unknown Path", "Compare a mnemonic across all standard BIP44/49/84 paths.", PAGE_DERIVATION, "cyan"),
        ("Address Match Search", "Search the standard window for a known address.", PAGE_ADDRESS_MATCHER, "purple"),
    ]
    for i, (title, desc, page, variant) in enumerate(items):
        with grid[i % 2]:
            st.markdown(
                f'<div class="cx-card"><h4>{_esc(title)}</h4>'
                f'<div style="color:var(--dim);margin-bottom:8px">{_esc(desc)}</div></div>',
                unsafe_allow_html=True,
            )
            if _btn(f"LAUNCH {title.upper()}", key=f"rs_{page}", variant=variant, use_container_width=True):
                st.session_state["current_page"] = page
                log_event("info", f"Routed to {page}")
                st.rerun()


def page_bip39_validation():
    render_section_header("\U0001F510", "BIP39 VALIDATION LAB", "VALIDATION & WORKSPACE LABORATORY")
    tab1, tab2, tab3 = st.tabs(["🔍 MNEMONIC VALIDATOR", "🧪 SIMULATED DAMAGE WORKSPACE", "🛡️ RECOVERY VALIDATION PROOF"])
    
    with tab1:
        col1, col2 = st.columns([3, 2])
        with col1:
            open_box("MNEMONIC VALIDATOR", live=True)
            mnemonic = st.text_area("Mnemonic (12/15/18/21/24 words)", key="bip39_in", height=110)
            if _btn("VALIDATE PHRASE", key="bip39_run", variant="green"):
                if not mnemonic.strip():
                    st.warning("Provide a mnemonic phrase.")
                else:
                    report = validate_mnemonic(mnemonic)
                    color = "rv" if report["valid"] else "rr"
                    render_rblock([
                        ("WORD COUNT", str(report["word_count"]), "ra"),
                        ("WORD COUNT VALID", str(report["word_count_valid"]), "rv" if report["word_count_valid"] else "rr"),
                        ("WORDS IN BIP39 LIST", str(report["words_in_wordlist"]), "rv" if report["words_in_wordlist"] else "rr"),
                        ("CHECKSUM VALID", str(report["checksum_valid"]), "rv" if report["checksum_valid"] else "rr"),
                        ("OVERALL VALID", str(report["valid"]), color),
                    ])
                    if report["valid"]:
                        log_event("ok", "Mnemonic validated (all checks pass)")
                        st.success("Mnemonic is a valid BIP39 phrase.")
                    else:
                        log_event("warn", "Mnemonic validation failed")
                        st.error("Mnemonic did not pass all BIP39 checks.")
            close_box()
        with col2:
            render_terminal("bip39 :: validator")
            
    with tab2:
        col1, col2 = st.columns([3, 2])
        with col1:
            open_box("TEST WALLET GENERATOR", live=True)
            st.markdown(
                "Generate a clean, valid BIP39 test mnemonic to simulate damages and demonstrate "
                "how the forensic recovery engine works."
            )
            
            wcount = st.radio("WORDS COUNT", [12, 24], index=0, horizontal=True, key="lab_wcount")
            
            if _btn("GENERATE TEST WALLET", key="lab_gen_btn", variant="green"):
                from bip_utils import Bip39MnemonicGenerator, Bip39WordsNum
                num = Bip39WordsNum.WORDS_NUM_12 if wcount == 12 else Bip39WordsNum.WORDS_NUM_24
                gen_mnemonic = Bip39MnemonicGenerator().FromWordsNumber(num)
                
                # Derive ETH and BTC addresses
                eth_addr = derive_eth_addresses(gen_mnemonic, count=1)[0]["address"]
                btc_addr = derive_btc_addresses(gen_mnemonic, address_type="native_segwit", count=1)[0]["address"]
                
                st.session_state["val_mnemonic"] = gen_mnemonic
                st.session_state["val_eth_addr"] = eth_addr
                st.session_state["val_btc_addr"] = btc_addr
                
                # Clear any simulated state
                st.session_state["val_damaged_mnemonic"] = None
                st.session_state["val_shuffled_template"] = None
                st.session_state["val_shuffled_pool"] = None
                
                log_event("ok", f"Generated test wallet ({wcount} words)")
                st.success("Test wallet successfully generated in volatile session state.")
                
            if st.session_state.get("val_mnemonic"):
                st.markdown("#### GENERATED MNEMONIC")
                st.code(st.session_state["val_mnemonic"], language="text")
                
                st.markdown("#### DERIVED PUBLIC ADDRESSES")
                st.markdown(
                    f"**ETH Address (BIP44)**: `{st.session_state['val_eth_addr']}`\n\n"
                    f"**BTC Address (BIP84)**: `{st.session_state['val_btc_addr']}`"
                )
            close_box()
            
            # SIMULATION CONTROLS
            if st.session_state.get("val_mnemonic"):
                open_box("SIMULATION CONTROLS", live=True)
                sim_col1, sim_col2 = st.columns(2)
                
                with sim_col1:
                    st.markdown("##### MISSING WORD SIMULATOR")
                    words_to_remove = st.selectbox("Words to remove", [1, 2], index=0, key="lab_remove_count")
                    
                    if _btn("SIMULATE WORD LOSS", key="lab_loss_btn", variant="orange", use_container_width=True):
                        import random
                        orig_words = st.session_state["val_mnemonic"].split()
                        total_words = len(orig_words)
                        indices = random.sample(range(total_words), words_to_remove)
                        
                        damaged_words = list(orig_words)
                        for idx in indices:
                            damaged_words[idx] = "?"
                            
                        st.session_state["val_damaged_mnemonic"] = " ".join(damaged_words)
                        # Clear alternative simulation
                        st.session_state["val_shuffled_template"] = None
                        st.session_state["val_shuffled_pool"] = None
                        
                        log_event("warn", f"Simulated loss of {words_to_remove} word(s) at positions: {[i+1 for i in indices]}")
                        st.success(f"Simulated loss of {words_to_remove} word(s). See Demonstration Workspace below.")
                        
                with sim_col2:
                    st.markdown("##### SHUFFLE SIMULATOR")
                    locked_pos = st.number_input("Locked words (prefix positions)", 0, wcount - 2, value=4 if wcount == 12 else 16, key="lab_lock_count")
                    
                    if _btn("SIMULATE WORD SHUFFLE", key="lab_shuffle_btn", variant="orange", use_container_width=True):
                        import random
                        orig_words = st.session_state["val_mnemonic"].split()
                        locked = orig_words[:locked_pos]
                        to_shuffle = orig_words[locked_pos:]
                        
                        shuffled_pool = list(to_shuffle)
                        random.shuffle(shuffled_pool)
                        
                        template_words = list(locked) + ["?"] * len(to_shuffle)
                        template_phrase = " ".join(template_words)
                        
                        st.session_state["val_shuffled_template"] = template_phrase
                        st.session_state["val_shuffled_pool"] = shuffled_pool
                        # Clear alternative simulation
                        st.session_state["val_damaged_mnemonic"] = None
                        
                        log_event("warn", f"Simulated shuffle of last {len(to_shuffle)} words with first {locked_pos} words locked")
                        st.success("Simulated shuffle. See Demonstration Workspace below.")
                close_box()
                
            # DEMONSTRATION WORKSPACE
            if st.session_state.get("val_damaged_mnemonic") or st.session_state.get("val_shuffled_template"):
                open_box("FORENSIC RECOVERY WORKSPACE", live=True)
                
                if st.session_state.get("val_damaged_mnemonic"):
                    st.markdown("#### DAMAGED MNEMONIC")
                    st.code(st.session_state["val_damaged_mnemonic"], language="text")
                    
                    st.markdown(
                        f"**Target Address (ETH)**: `{st.session_state['val_eth_addr']}`\n\n"
                        "*The recovery engine will search all candidate words and perform derivation matching to find the original mnemonic.*"
                    )
                    
                    if _btn("RUN LAB RECOVERY", key="lab_recovery_missing_btn", variant="purple", use_container_width=True):
                        progress_bar = st.progress(0.0)
                        status_text = st.empty()
                        
                        def cb(checked, total, found):
                            pct = min(1.0, float(checked) / total)
                            progress_bar.progress(pct)
                            status_text.markdown(
                                f"**Checked**: {checked:,} / {total:,} ({pct*100:.1f}%) | **Candidates Found**: {found}"
                            )
                            
                        phrase = st.session_state["val_damaged_mnemonic"]
                        target_addr = st.session_state["val_eth_addr"]
                        
                        log_event("info", "Starting lab recovery for missing words...")
                        with st.spinner("Brute-forcing missing slots..."):
                            res = recover_missing_words(
                                phrase,
                                target_address=target_addr,
                                max_unknowns=MAX_MISSING_WORDS,
                                progress_callback=cb,
                            )
                            
                        # Show stats
                        st.markdown("##### Recovery Stats")
                        render_status_cards([
                            ("CHECKED", f"{res['checked']:,}", ""),
                            ("CHECKSUM PASSED", f"{res['checksum_passed']:,}", "green"),
                            ("SPEED", f"{int(res['checked'] / (res['elapsed_time'] or 0.001)):,} keys/s", ""),
                            ("ELAPSED", f"{res['elapsed_time']:.2f}s", ""),
                        ])
                        
                        if res["candidates"]:
                            recovered = res["candidates"][0]
                            st.markdown("##### RECOVERED MNEMONIC")
                            st.code(recovered, language="text")
                            
                            if recovered == st.session_state["val_mnemonic"]:
                                log_event("ok", "Mnemonic recovered successfully and matches original!")
                                st.balloons()
                                st.success("✅ MATCH SUCCESS: The original mnemonic was successfully reconstructed and verified against the target address!")
                            else:
                                st.warning("Recovered a checksum-valid mnemonic, but it does not match the original phrase.")
                        else:
                            st.error("Recovery failed: No candidates produced matching the target address.")
                            
                elif st.session_state.get("val_shuffled_template"):
                    st.markdown("#### SHUFFLED TEMPLATE")
                    st.code(st.session_state["val_shuffled_template"], language="text")
                    
                    st.markdown(
                        f"**Word Pool**: `{', '.join(st.session_state['val_shuffled_pool'])}`\n\n"
                        f"**Target Address (ETH)**: `{st.session_state['val_eth_addr']}`"
                    )
                    
                    # Permutations
                    shuffled_words = st.session_state["val_shuffled_pool"]
                    counts = Counter(shuffled_words)
                    search_space = math.factorial(len(shuffled_words))
                    for c in counts.values():
                        search_space //= math.factorial(c)
                        
                    st.markdown("### Feasibility Assessment")
                    report_html = render_feasibility_report(search_space, True, len(st.session_state["val_shuffled_pool"]) + st.session_state.get("lab_lock_count", 0))
                    st.markdown(report_html, unsafe_allow_html=True)
                    
                    is_feasible = search_space <= 5_000_000
                    if is_feasible:
                        if _btn("RUN LAB RECOVERY", key="lab_recovery_order_btn", variant="purple", use_container_width=True):
                            progress_bar = st.progress(0.0)
                            status_text = st.empty()
                            
                            def cb(checked, total, found):
                                pct = min(1.0, float(checked) / total)
                                progress_bar.progress(pct)
                                status_text.markdown(
                                    f"**Checked**: {checked:,} / {total:,} ({pct*100:.1f}%) | **Candidates Found**: {found}"
                                )
                                
                            template = st.session_state["val_shuffled_template"]
                            pool_list = st.session_state["val_shuffled_pool"]
                            target_addr = st.session_state["val_eth_addr"]
                            
                            log_event("info", "Starting lab recovery for shuffled words...")
                            with st.spinner("Permuting shuffled words..."):
                                res = recover_word_order(
                                    template,
                                    pool_list,
                                    target_address=target_addr,
                                    progress_callback=cb,
                                )
                                
                            # Show stats
                            st.markdown("##### Recovery Stats")
                            render_status_cards([
                                ("CHECKED", f"{res['checked']:,}", ""),
                                ("CHECKSUM PASSED", f"{res['checksum_passed']:,}", "green"),
                                ("SPEED", f"{int(res['checked'] / (res['elapsed_time'] or 0.001)):,} keys/s", ""),
                                ("ELAPSED", f"{res['elapsed_time']:.2f}s", ""),
                            ])
                            
                            if res["candidates"]:
                                recovered = res["candidates"][0]
                                st.markdown("##### RECOVERED MNEMONIC")
                                st.code(recovered, language="text")
                                
                                if recovered == st.session_state["val_mnemonic"]:
                                    log_event("ok", "Shuffled mnemonic recovered successfully and matches original!")
                                    st.balloons()
                                    st.success("✅ MATCH SUCCESS: The original word order was successfully reconstructed and verified against the target address!")
                                else:
                                    st.warning("Recovered a checksum-valid mnemonic, but it does not match the original phrase.")
                            else:
                                st.error("Recovery failed: No candidates produced matching the target address.")
                    else:
                        st.warning("⚠️ Permutation search space is infeasible. Please generate a new test wallet with more locked prefix positions.")
                close_box()
                
            with tab3:
                col1, col2 = st.columns([3, 2])
                with col1:
                    open_box("AUTOMATED RECOVERY PROOF", live=True)
                    st.markdown(
                        "Run an automated verification cycle that generates a fresh valid BIP39 test wallet, "
                        "simulates word loss or shuffling, executes the recovery engine, and mathematically "
                        "proves successful recovery."
                    )
                    
                    proof_wcount = st.radio("MNEMONIC TYPE", [12, 24], index=0, horizontal=True, key="proof_wcount")
                    proof_scenario = st.selectbox(
                        "DAMAGE SCENARIO",
                        [
                            "1 Missing Word (Fast)",
                            "2 Missing Words (Moderate)",
                            "Shuffled Word Order (4 Shuffled, 8/20 Locked)"
                        ],
                        key="proof_scenario"
                    )
                    proof_address_filter = st.checkbox("Enable Address Matching Filter", value=True, key="proof_addr_filter")
                    
                    if _btn("RUN RECOVERY PROOF", key="proof_run_btn", variant="purple", use_container_width=True):
                        # 1. Generate test wallet
                        from bip_utils import Bip39MnemonicGenerator, Bip39WordsNum
                        num = Bip39WordsNum.WORDS_NUM_12 if proof_wcount == 12 else Bip39WordsNum.WORDS_NUM_24
                        orig_mnemonic = Bip39MnemonicGenerator().FromWordsNumber(num)
                        
                        # Derive target address
                        eth_addr = derive_eth_addresses(orig_mnemonic, count=1)[0]["address"]
                        target_addr = eth_addr if proof_address_filter else None
                        
                        st.markdown("#### Generated Test Wallet")
                        st.code(orig_mnemonic, language="text")
                        st.markdown(f"**Target ETH Address (BIP44)**: `{eth_addr}`")
                        
                        # 2. Simulate damage/shuffle
                        st.markdown("#### Simulated Damage Template")
                        
                        words = orig_mnemonic.split()
                        if "1 Missing Word" in proof_scenario:
                            import random
                            idx = random.randint(0, len(words) - 1)
                            damaged_words = list(words)
                            damaged_words[idx] = "?"
                            damaged_phrase = " ".join(damaged_words)
                            st.code(damaged_phrase, language="text")
                            
                            st.markdown("#### Executing Missing Word Recovery...")
                            progress_bar = st.progress(0.0)
                            status_text = st.empty()
                            
                            def cb(checked, total, found):
                                pct = min(1.0, float(checked) / total)
                                progress_bar.progress(pct)
                                status_text.markdown(f"**Checked**: {checked:,} / {total:,} ({pct*100:.1f}%) | **Candidates Found**: {found}")
                                
                            log_event("info", f"Proof: starting missing word recovery (1 missing)")
                            with st.spinner("Recovering..."):
                                res = recover_missing_words(
                                    damaged_phrase,
                                    target_address=target_addr,
                                    max_unknowns=1,
                                    progress_callback=cb
                                )
                                
                        elif "2 Missing Words" in proof_scenario:
                            import random
                            indices = random.sample(range(len(words)), 2)
                            damaged_words = list(words)
                            for idx in indices:
                                damaged_words[idx] = "?"
                            damaged_phrase = " ".join(damaged_words)
                            st.code(damaged_phrase, language="text")
                            
                            st.markdown("#### Executing Missing Words Recovery...")
                            progress_bar = st.progress(0.0)
                            status_text = st.empty()
                            
                            def cb(checked, total, found):
                                pct = min(1.0, float(checked) / total)
                                progress_bar.progress(pct)
                                status_text.markdown(f"**Checked**: {checked:,} / {total:,} ({pct*100:.1f}%) | **Candidates Found**: {found}")
                                
                            log_event("info", f"Proof: starting missing words recovery (2 missing)")
                            with st.spinner("Recovering..."):
                                res = recover_missing_words(
                                    damaged_phrase,
                                    target_address=target_addr,
                                    max_unknowns=2,
                                    progress_callback=cb
                                )
                                
                        else: # Shuffled word order
                            import random
                            locked_pos = 8 if proof_wcount == 12 else 20
                            locked = words[:locked_pos]
                            to_shuffle = words[locked_pos:]
                            
                            shuffled_pool = list(to_shuffle)
                            random.shuffle(shuffled_pool)
                            
                            template_phrase = " ".join(list(locked) + ["?"] * len(to_shuffle))
                            st.code(template_phrase, language="text")
                            st.markdown(f"**Word Pool**: `{', '.join(shuffled_pool)}`")
                            
                            # Estimate search space
                            from collections import Counter
                            import math
                            counts = Counter(shuffled_pool)
                            search_space = math.factorial(len(shuffled_pool))
                            for c in counts.values():
                                search_space //= math.factorial(c)
                                
                            st.markdown("#### Executing Order Recovery...")
                            progress_bar = st.progress(0.0)
                            status_text = st.empty()
                            
                            def cb(checked, total, found):
                                pct = min(1.0, float(checked) / total)
                                progress_bar.progress(pct)
                                status_text.markdown(f"**Checked**: {checked:,} / {total:,} ({pct*100:.1f}%) | **Candidates Found**: {found}")
                                
                            log_event("info", f"Proof: starting order recovery ({search_space} permutations)")
                            with st.spinner("Recovering..."):
                                res = recover_word_order(
                                    template_phrase,
                                    shuffled_pool,
                                    target_address=target_addr,
                                    progress_callback=cb
                                )
                                
                        # 3. Report & Validate
                        st.markdown("#### Recovery Stats")
                        render_status_cards([
                            ("CHECKED", f"{res['checked']:,}", ""),
                            ("CHECKSUM PASSED", f"{res['checksum_passed']:,}", "green"),
                            ("SPEED", f"{int(res['checked'] / (res['elapsed_time'] or 0.001)):,} keys/s", ""),
                            ("ELAPSED", f"{res['elapsed_time']:.2f}s", ""),
                        ])
                        
                        if res["candidates"]:
                            recovered = res["candidates"][0]
                            matched = False
                            for cand in res["candidates"]:
                                if cand == orig_mnemonic:
                                    matched = True
                                    recovered = cand
                                    break
                                    
                            if matched:
                                log_event("ok", f"Proof successful: recovered mnemonic matches original!")
                                st.balloons()
                                st.success(
                                    f"✅ PROOF VERIFIED SUCCESSFUL!\n\n"
                                    f"**Original**: `{orig_mnemonic}`\n\n"
                                    f"**Recovered**: `{recovered}`\n\n"
                                    f"The recovery engine successfully reconstructed the mnemonic and verified it against the target address."
                                )
                            else:
                                st.warning(
                                    f"⚠️ Checksum-valid candidate found, but does not match original.\n\n"
                                    f"**Original**: `{orig_mnemonic}`\n\n"
                                    f"**Recovered First**: `{recovered}`"
                                )
                        else:
                            st.error("❌ PROOF FAILED: No candidates could be reconstructed.")
                close_box()
        with col2:
            render_terminal("bip39 :: proof")


def page_incomplete_seed():
    render_section_header("\U0001F50E", "INCOMPLETE SEED RECOVERY", f"BRUTE FORCE ≤ {MAX_MISSING_WORDS} UNKNOWNS")
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("SEED PHRASE RECONSTRUCTION", live=True)
        phrase = st.text_area(
            "KNOWN WORDS - use '?' for each unknown position",
            value="",
            key="inc_phrase",
            height=100,
        )
        target = st.text_input("TARGET ADDRESS (optional - filter candidates)", key="inc_target")
        unknowns_in_input = phrase.count("?")

        render_status_cards([
            ("UNKNOWN WORDS", str(unknowns_in_input), "orange" if unknowns_in_input else ""),
            ("ENGINE", "OFFLINE (MULTIPROCESSING)", "green"),
            ("MAX UNKNOWNS", str(MAX_MISSING_WORDS), ""),
            ("CHECKED", str(st.session_state.get("inc_last_checked", 0)), "" ),
        ])

        if _btn("RUN RECOVERY", key="inc_run", variant="orange"):
            if not phrase.strip() or "?" not in phrase:
                st.warning("Phrase must contain '?' to indicate missing words.")
            elif unknowns_in_input > MAX_MISSING_WORDS:
                st.error(f"Engine is hard-capped at {MAX_MISSING_WORDS} unknowns.")
                log_event("err", f"Refused recovery: {unknowns_in_input} > {MAX_MISSING_WORDS}")
            else:
                target_arg = target.strip() or None
                search_space = 2048 ** unknowns_in_input
                
                # Check for misspellings in known words
                try:
                    from wallet_utils import _english_wordlist, _normalize_mnemonic
                    words = _normalize_mnemonic(phrase).split()
                    wordlist = _english_wordlist()
                    known = [w for w in words if w != "?"]
                    invalid_words = [w for w in known if w not in wordlist]
                    if invalid_words:
                        st.error(f"Non-'?' tokens contain words not in the BIP39 English wordlist: {', '.join(invalid_words)}. Run Typo Correction Lab first.")
                        log_event("err", f"Refused recovery due to invalid words: {', '.join(invalid_words)}")
                        return
                except Exception as e:
                    pass

                # Display estimated runtime
                est_time = estimate_recovery_time(search_space, target_arg is not None, len(phrase.split()))
                st.info(f"Calculated Search Space: {search_space:,} combinations. Estimated Runtime: {est_time:.2f} seconds.")
                
                progress_bar = st.progress(0.0)
                status_text = st.empty()
                
                def update_progress(checked, total, found):
                    pct = min(1.0, float(checked) / total)
                    progress_bar.progress(pct)
                    status_text.markdown(
                        f"**Checked**: {checked:,} / {total:,} ({pct*100:.1f}%) | "
                        f"**Candidates Found**: {found}"
                    )

                log_event("info", f"Starting multiprocessing recovery for {unknowns_in_input} unknown(s)...")
                
                with st.spinner("Executing candidate search..."):
                    try:
                        result = recover_missing_words(
                            phrase,
                            target_address=target_arg,
                            max_unknowns=MAX_MISSING_WORDS,
                            progress_callback=update_progress,
                        )
                    except ValueError as e:
                        log_event("err", f"Recovery error: {e}")
                        st.error(str(e))
                        return
                        
                st.session_state["inc_last_checked"] = result["checked"]
                cand = result["candidates"]
                
                # Transparency Statistics
                st.markdown("### Recovery Metrics")
                render_status_cards([
                    ("TOTAL CHECKED", f"{result['checked']:,}", ""),
                    ("CHECKSUM PASSED", f"{result['checksum_passed']:,}", "green"),
                    ("CHECKSUM FILTERED", f"{result['checked'] - result['checksum_passed']:,}", "orange"),
                    ("SPEED", f"{int(result['checked'] / (result['elapsed_time'] or 0.001)):,} keys/s", ""),
                ])
                
                if cand:
                    log_event("ok", f"Recovered {len(cand)} candidate(s) in {result['elapsed_time']:.2f}s")
                    st.success(f"Found {len(cand)} candidate phrase(s) in {result['elapsed_time']:.2f} seconds.")
                    st.session_state["recovery_candidates"] = cand
                    for c in cand[:10]:
                        st.code(c, language="text")
                    if result["truncated"]:
                        st.warning("Result list truncated at 100 candidates.")
                else:
                    log_event("warn", "No candidates produced")
                    st.error("No checksum-valid candidates produced.")
        close_box()
    with col2:
        render_terminal("recovery :: missing-words")


def page_typo_lab():
    render_section_header("\U0001F520", "TYPO CORRECTION LAB", "LEVENSHTEIN SUGGESTIONS")
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("WORDLIST TYPO ANALYZER", live=True)
        phrase = st.text_area("Phrase to analyze (typos OK)", key="typo_in", height=100)
        max_sugs = st.number_input("SUGGESTIONS PER WORD", 1, 20, value=5, key="typo_max")
        if _btn("RUN SPELL CHECK", key="typo_run", variant="orange"):
            if not phrase.strip():
                st.warning("Provide a phrase.")
            else:
                try:
                    result = suggest_typo_corrections(phrase, max_suggestions=int(max_sugs))
                except ValueError as e:
                    st.error(str(e))
                    log_event("err", f"Typo lab error: {e}")
                    return
                if result["all_words_known"]:
                    log_event("ok", "All words are in BIP39 wordlist")
                    st.success("All words are valid BIP39 entries. No corrections needed.")
                else:
                    unk = result["unknown_words"]
                    log_event("warn", f"Found {len(unk)} unknown word(s)")
                    st.warning(f"Found {len(unk)} word(s) not in the BIP39 list.")
                    headers = ["#", "POSITION", "WORD", "SUGGESTIONS"]
                    rows = [
                        [str(i + 1), str(u["position"] + 1), u["word"], ", ".join(u["suggestions"])]
                        for i, u in enumerate(unk)
                    ]
                    render_data_table(headers, rows)
        close_box()
    with col2:
        render_terminal("recovery :: typo")


def render_feasibility_report(search_space: int, target_address_provided: bool, word_count: int) -> str:
    import multiprocessing
    import math
    from recovery_utils import estimate_recovery_time
    
    est_time = estimate_recovery_time(search_space, target_address_provided, word_count)
    cores = multiprocessing.cpu_count()
    
    limit = 5_000_000
    is_feasible = search_space <= limit
    
    if is_feasible:
        status_title = "🟢 FEASIBLE"
        status_color = "#00e676"  # neon green
        status_bg = "rgba(0, 230, 118, 0.05)"
        status_desc = "The search space is within safe operational limits. Multiprocessing will execute the search efficiently."
    else:
        status_title = "🔴 INFEASIBLE"
        status_color = "#ff1744"  # neon red
        status_bg = "rgba(255, 23, 68, 0.05)"
        status_desc = f"Search space exceeds the maximum safe operational limit of {limit:,} permutations. Execution is blocked to prevent crash/hang. Please lock more positions in the template phrase."
        
    if est_time < 0.1:
        time_str = "Instantaneous"
    elif est_time < 60:
        time_str = f"{est_time:.2f} seconds"
    elif est_time < 3600:
        time_str = f"{est_time / 60:.1f} minutes"
    elif est_time < 86400:
        time_str = f"{est_time / 3600:.1f} hours"
    else:
        time_str = f"{est_time / 86400:.1f} days"
        
    checksum_bits = word_count // 3
    checksum_ratio = 100.0 / (2 ** checksum_bits)
    
    log_space = math.log10(max(1, search_space))
    log_limit = math.log10(limit)
    max_log = max(8.7, log_space)
    pct = min(100.0, (log_space / max_log) * 100)
    limit_pct = (log_limit / max_log) * 100
    
    report_html = f"""
    <div style="
        border: 1px solid {status_color};
        background-color: {status_bg};
        padding: 15px;
        border-radius: 4px;
        margin-bottom: 20px;
        font-family: 'Share Tech Mono', monospace;
    ">
        <div style="font-size: 16px; font-weight: bold; color: {status_color}; display: flex; justify-content: space-between;">
            <span>🛡️ RECOVERY FEASIBILITY REPORT</span>
            <span>{status_title}</span>
        </div>
        <div style="font-size: 12px; color: #aaa; margin-top: 5px; margin-bottom: 15px;">
            {status_desc}
        </div>
        
        <!-- Complexity bar -->
        <div style="font-size: 11px; color: #888; margin-bottom: 3px; display: flex; justify-content: space-between;">
            <span>Complexity Level (Log Scale)</span>
            <span>{search_space:,} permutations</span>
        </div>
        <div style="background-color: #222; height: 12px; border-radius: 6px; position: relative; overflow: hidden; border: 1px solid #444; margin-bottom: 15px;">
            <div style="background-color: {status_color}; width: {pct}%; height: 100%; transition: width 0.5s ease-in-out;"></div>
            <div style="position: absolute; left: {limit_pct}%; top: 0; bottom: 0; width: 2px; background-color: #ff9800;" title="Safety Limit"></div>
        </div>
        
        <!-- Details grid -->
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; font-size: 12px;">
            <div>
                <span style="color: #888;">ESTIMATED RUNTIME:</span> <strong style="color: #fff;">{time_str}</strong>
            </div>
            <div>
                <span style="color: #888;">CPU CORES DETECTED:</span> <strong style="color: #fff;">{cores}</strong>
            </div>
            <div>
                <span style="color: #888;">CHECKSUM FILTER PASS:</span> <strong style="color: #fff;">~{checksum_ratio:.4f}%</strong>
            </div>
            <div>
                <span style="color: #888;">ADDRESS MATCHING:</span> <strong style="color: { '#00e676' if target_address_provided else '#ff1744' };">{ 'ENABLED' if target_address_provided else 'DISABLED' }</strong>
            </div>
        </div>
    </div>
    """
    return report_html


def page_wrong_order():
    render_section_header("\U0001F500", "WRONG WORD ORDER HELPER", "CONSTRAINED PERMUTATION ENGINE")
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("CONSTRAINED PERMUTATION RECOVERY", live=True)
        st.markdown(
            "If you know the exact positions of some words, enter them below and use `?` for the unknown positions "
            "to drastically reduce the search space."
        )
        template = st.text_area(
            "TEMPLATE PHRASE - place known words, use '?' for unknown positions",
            value="",
            placeholder="e.g. abandon ? ? abandon abandon ?",
            key="wo_template",
            height=80,
        )
        pool = st.text_input(
            "POOL WORDS - words to fill the '?' positions (space-separated)",
            value="",
            placeholder="e.g. about art baby",
            key="wo_pool",
        )
        target = st.text_input("TARGET ADDRESS (optional - filter candidates)", key="wo_target")
        
        # Calculate search space
        from collections import Counter
        import math
        
        try:
            from recovery_utils import _split_normalized
            template_words = _split_normalized(template) if template.strip() else []
        except Exception:
            template_words = template.lower().split() if template.strip() else []
            
        unknowns = template_words.count("?")
        pool_words = [w.strip().lower() for w in pool.split()] if pool.strip() else []
        
        search_space = 0
        if pool_words:
            counts = Counter(pool_words)
            search_space = math.factorial(len(pool_words))
            for c in counts.values():
                search_space //= math.factorial(c)
                
        render_status_cards([
            ("UNKNOWN SLOTS", str(unknowns), "orange" if unknowns else ""),
            ("POOL SIZE", str(len(pool_words)), ""),
            ("PERMUTATIONS", f"{search_space:,}" if search_space else "0", ""),
            ("ENGINE", "OFFLINE (MULTIPROCESSING)", "green"),
        ])
        
        # Add live feasibility report if template and pool are provided
        if template.strip() and pool.strip():
            st.markdown("### Feasibility Assessment")
            report_html = render_feasibility_report(search_space, target.strip() != "", len(template_words))
            st.markdown(report_html, unsafe_allow_html=True)
            
            is_feasible = search_space <= 5_000_000
            
            if is_feasible:
                if _btn("RUN ORDER RECOVERY", key="wo_run", variant="orange"):
                    if not template.strip():
                        st.warning("Provide a template phrase.")
                    elif "?" not in template:
                        st.warning("Template must contain '?' to indicate where pool words should be inserted.")
                    elif len(pool_words) != unknowns:
                        st.error(f"Mismatch: template has {unknowns} '?' positions, but pool has {len(pool_words)} words.")
                    else:
                        target_arg = target.strip() or None
                        est_time = estimate_recovery_time(search_space, target_arg is not None, len(template_words))
                        
                        st.info(f"Estimated Runtime: {est_time:.2f} seconds.")
                        progress_bar = st.progress(0.0)
                        status_text = st.empty()
                        
                        def cb(checked, total, found):
                            pct = min(1.0, float(checked) / total)
                            progress_bar.progress(pct)
                            status_text.markdown(
                                f"**Checked**: {checked:,} / {total:,} ({pct*100:.1f}%) | "
                                f"**Candidates Found**: {found}"
                            )
                            
                        log_event("info", f"Starting multiprocessing order recovery for {search_space:,} permutations...")
                        with st.spinner("Executing permutation search..."):
                            try:
                                result = recover_word_order(
                                    template,
                                    pool_words,
                                    target_address=target_arg,
                                    progress_callback=cb,
                                )
                            except ValueError as e:
                                st.error(str(e))
                                log_event("err", f"Order recovery error: {e}")
                                return
                                
                        cand = result["candidates"]
                        
                        # Transparency Statistics
                        st.markdown("### Recovery Metrics")
                        render_status_cards([
                            ("TOTAL PERMUTATIONS", f"{result['search_space']:,}", ""),
                            ("CHECKSUM PASSED", f"{result['checksum_passed']:,}", "green"),
                            ("CHECKSUM FILTERED", f"{result['checked'] - result['checksum_passed']:,}", "orange"),
                            ("SPEED", f"{int(result['checked'] / (result['elapsed_time'] or 0.001)):,} keys/s", ""),
                        ])
                        
                        if cand:
                            log_event("ok", f"Order recovery found {len(cand)} candidate(s) in {result['elapsed_time']:.2f}s")
                            st.success(f"Found {len(cand)} valid ordering(s) in {result['elapsed_time']:.2f} seconds.")
                            for c in cand[:10]:
                                st.code(c, language="text")
                            if result["truncated"]:
                                st.warning("Truncated at 100 candidates.")
                        else:
                            log_event("warn", "No valid orderings found")
                            st.error("No checksum-valid orderings found.")
            else:
                log_event("warn", f"Recovery feasibility check: {search_space:,} permutations is INFEASIBLE")
                st.error("⚠️ Order recovery engine locked because the permutations search space is too large. Please lock more words to make it feasible.")
        close_box()
    with col2:
        render_terminal("recovery :: order")


def page_passphrase():
    render_section_header("\U0001F511", "BIP39 PASSPHRASE TESTING", "DERIVE WITH 25TH WORD")
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("PASSPHRASE PROBE", live=True)
        mnemonic = st.text_area("MNEMONIC (12/15/18/21/24 words)", key="pp_mnem", height=90)
        passphrase = st.text_input("PASSPHRASE (25th word)", key="pp_pass", type="password")
        target = st.text_input("TARGET ADDRESS (optional)", key="pp_target")
        count = st.number_input("ADDRESSES PER PATH", 1, 20, value=5, key="pp_count")
        if _btn("TEST PASSPHRASE", key="pp_run", variant="green"):
            if not mnemonic.strip():
                st.warning("Provide a mnemonic.")
            else:
                try:
                    result = test_passphrase(
                        mnemonic, passphrase or "",
                        target_address=target.strip() or None,
                        count=int(count),
                    )
                except ValueError as e:
                    st.error(str(e))
                    log_event("err", f"Passphrase test error: {e}")
                    return
                if result["match"]:
                    m = result["match"]
                    log_event("ok", f"Passphrase match on {m['address_type']} {m['path']}")
                    st.success(f"Match found: {m['address']} ({m['address_type']}, {m['path']}).")
                else:
                    log_event("info", "Passphrase derivation complete, no target match.")
                    if target.strip():
                        st.warning("Derivation succeeded but no derived address matched the target.")
                    else:
                        st.info("Derivation succeeded.")
                rows = [
                    [a["coin"], a["address_type"], a["path"], a["address"]]
                    for a in result["addresses"]
                ]
                render_data_table(["COIN", "TYPE", "PATH", "ADDRESS"], rows)
                st.session_state["last_derivations"] = result["addresses"]
        close_box()
    with col2:
        render_terminal("recovery :: passphrase")


def page_derivation():
    render_section_header("⚡", "DERIVATION PATH SCANNER", "COMPARE BIP44/49/84")
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("ALL STANDARDS SCAN", live=True)
        mnemonic = st.text_area("MNEMONIC", key="dp_mnem", height=90)
        count = st.number_input("ADDRESSES PER STANDARD", 1, 10, value=3, key="dp_count")
        if _btn("SCAN STANDARDS", key="dp_run", variant="cyan"):
            if not mnemonic.strip():
                st.warning("Provide a mnemonic.")
            else:
                try:
                    rows_data = compare_all_standards(mnemonic, count=int(count))
                except ValueError as e:
                    st.error(str(e))
                    log_event("err", f"Derivation scan error: {e}")
                    return
                log_event("ok", f"Scanned {len(rows_data)} addresses across standards")
                rows = [[r["coin"], r["address_type"], r["path"], r["address"]] for r in rows_data]
                render_data_table(["COIN", "TYPE", "PATH", "ADDRESS"], rows)
                st.session_state["last_derivations"] = rows_data
        close_box()
    with col2:
        render_terminal("derivation :: scanner")


def page_address_matcher():
    render_section_header("\U0001F3AF", "KNOWN ADDRESS MATCHER", "SCAN STANDARD WINDOW")
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("ADDRESS LOOKUP", live=True)
        mnemonic = st.text_area("MNEMONIC", key="am_mnem", height=90)
        target = st.text_input("TARGET ADDRESS", key="am_target")
        depth = st.number_input("ADDRESSES PER STANDARD", 1, 50, value=20, key="am_depth")
        if _btn("FIND ADDRESS", key="am_run", variant="cyan"):
            if not (mnemonic.strip() and target.strip()):
                st.warning("Mnemonic and target address required.")
            else:
                try:
                    result = find_address_match(mnemonic, target, max_addresses_per_standard=int(depth))
                except ValueError as e:
                    st.error(str(e))
                    log_event("err", f"Matcher error: {e}")
                    return
                if result["match"]:
                    m = result["match"]
                    log_event("ok", f"Address match: {m['path']}")
                    render_rblock([
                        ("MATCH", "FOUND", "rv"),
                        ("COIN", m["coin"], "ra"),
                        ("TYPE", m["address_type"], "ra"),
                        ("PATH", m["path"], "rv"),
                        ("ADDRESS", m["address"], "rv"),
                        ("SEARCHED", f"{result['searched']} candidates", "rk"),
                    ])
                else:
                    log_event("warn", f"No match in {result['searched']} candidates")
                    st.error(f"No match found in {result['searched']} candidates.")
                st.session_state["last_derivations"] = result["candidates"]
        close_box()
    with col2:
        render_terminal("derivation :: matcher")


def page_address_gen():
    render_section_header("\U0001F4B3", "ETH/BTC ADDRESS GENERATOR", "DERIVE PUBLIC ADDRESSES")
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("STANDARD DERIVATION", live=True)
        mnemonic = st.text_area("MNEMONIC", key="ag_mnem", height=90)
        coin_choice = st.selectbox(
            "COIN / ADDRESS TYPE",
            ["ETH",
             f"BTC - {BTC_ADDRESS_TYPES['legacy']['label']}",
             f"BTC - {BTC_ADDRESS_TYPES['segwit']['label']}",
             f"BTC - {BTC_ADDRESS_TYPES['native_segwit']['label']}"],
        )
        count = st.number_input("COUNT", 1, 50, value=5, key="ag_count")
        if _btn("DERIVE", key="ag_run", variant="green"):
            if not mnemonic.strip():
                st.warning("Provide a mnemonic.")
            else:
                try:
                    if coin_choice == "ETH":
                        rows_data = derive_eth_addresses(mnemonic, count=int(count))
                    else:
                        atype = next(k for k, v in BTC_ADDRESS_TYPES.items() if v["label"] in coin_choice)
                        rows_data = derive_btc_addresses(mnemonic, address_type=atype, count=int(count))
                except ValueError as e:
                    st.error(str(e))
                    log_event("err", f"Generator error: {e}")
                    return
                log_event("ok", f"Derived {len(rows_data)} {coin_choice} addresses")
                render_data_table(
                    ["COIN", "TYPE", "PATH", "ADDRESS"],
                    [[r["coin"], r["address_type"], r["path"], r["address"]] for r in rows_data],
                )
                st.session_state["last_derivations"] = rows_data
        close_box()
    with col2:
        render_terminal("derivation :: generator")


def page_entropy():
    render_section_header("\U0001F3B2", "ENTROPY ANALYSIS LAB", "SHANNON + CHI-SQUARE")
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("ENTROPY TEST BATTERY", live=True)
        text_input = st.text_area("INPUT TEXT / DATA (or hex)", key="ent_in", height=120)
        as_hex = st.checkbox("Treat input as hex bytes", key="ent_hex")
        if _btn("ANALYZE ENTROPY", key="ent_run", variant="cyan"):
            if not text_input:
                st.warning("Provide input.")
            else:
                try:
                    if as_hex:
                        data = hex_to_bytes(text_input)
                    else:
                        data = text_input.encode("utf-8")
                    res = analyze_entropy(data)
                except ValueError as e:
                    st.error(str(e))
                    log_event("err", f"Entropy error: {e}")
                    return
                log_event("ok", f"Entropy analyzed: {res['quality']}, H={res['shannon_entropy']:.4f}")
                q_color = {"HIGH": "green", "MODERATE": "", "LOW": "orange", "POOR": "red", "EMPTY": "red"}.get(res["quality"], "")
                render_status_cards([
                    ("SHANNON", f"{res['shannon_entropy']:.4f}", q_color, "bits/byte"),
                    ("CHI-SQUARE", f"{res['chi_square']:.2f}", ""),
                    ("UNIQUE BYTES", f"{res['unique_bytes']}/256", ""),
                    ("QUALITY", res["quality"], q_color),
                ])
                render_rblock([
                    ("SIZE", f"{res['size_bytes']} bytes", "ra"),
                    *[(f"NOTE {i+1}", n, "rk") for i, n in enumerate(res["notes"])],
                ])
        close_box()
    with col2:
        render_terminal("entropy :: analyzer")


def page_vault_inspect():
    render_section_header("\U0001F98A", "METAMASK VAULT INSPECTOR", "STRUCTURE + KDF METADATA")
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("VAULT METADATA SCAN", live=True)
        vault_text = st.text_area(
            "Paste MetaMask vault JSON (encrypted blob - never decrypted)",
            key="vault_in", height=180,
        )
        if _btn("INSPECT VAULT", key="vault_run", variant="purple"):
            if not vault_text.strip():
                st.warning("Provide vault JSON.")
            else:
                try:
                    info = inspect_metamask_vault(vault_text)
                except ValueError as e:
                    st.error(str(e))
                    log_event("err", f"Vault inspect error: {e}")
                    return
                log_event("ok", f"Vault inspected: format={info['format']}")
                render_status_cards([
                    ("FORMAT", info["format"], "green" if info["format"].startswith("metamask") else "orange"),
                    ("KDF", info["kdf"], ""),
                    ("ITERATIONS", f"{info['kdf_iterations']:,}", "" if info["kdf_iterations"] >= 100000 else "orange"),
                    ("CIPHERTEXT", f"{info['ciphertext_len_bytes']} B", ""),
                ])
                render_rblock([
                    ("SALT LEN", f"{info['salt_len_bytes']} bytes", "ra"),
                    ("IV LEN", f"{info['iv_len_bytes']} bytes", "ra"),
                    ("CIPHERTEXT SHA-256", info["ciphertext_sha256"] or "-", "ro"),
                    ("RAW KEYS", ", ".join(info["raw_keys"]) or "-", "rk"),
                ])
                for n in info["notes"]:
                    st.caption(n)
        close_box()
    with col2:
        render_terminal("forensics :: vault")


def page_hash_tools():
    render_section_header("\U0001F9EE", "HASH / CRYPTO TOOLS", "ALL OFFLINE")
    tabs = st.tabs(["HASHES", "ENCODE / DECODE", "UNIT CONVERT"])
    with tabs[0]:
        col1, col2 = st.columns([3, 2])
        with col1:
            open_box("HASH CALCULATOR", live=True)
            data_in = st.text_area("INPUT (text or hex)", key="hash_in", height=120)
            encoding = st.selectbox("INPUT ENCODING", ["UTF-8 Text", "Hex", "Base64"], key="hash_enc")
            if _btn("COMPUTE ALL HASHES", key="hash_run", variant="green"):
                try:
                    if encoding == "Hex":
                        data = hex_to_bytes(data_in)
                    elif encoding == "Base64":
                        data = b64_to_bytes(data_in)
                    else:
                        data = data_in.encode("utf-8")
                except ValueError as e:
                    st.error(str(e))
                    return
                log_event("ok", f"Hashed {len(data)} bytes")
                render_rblock([
                    ("SIZE", f"{len(data)} bytes", "ra"),
                    ("MD5", calculate_md5(data), "ro"),
                    ("SHA-1", calculate_sha1(data), "ro"),
                    ("SHA-256", calculate_sha256(data), "rv"),
                    ("SHA-512", calculate_sha512(data), "rv"),
                    ("RIPEMD-160", calculate_ripemd160(data), "ra"),
                    ("HASH160", calculate_hash160(data), "ra"),
                    ("DOUBLE-SHA256", calculate_double_sha256(data), "ra"),
                ])
            close_box()
        with col2:
            render_terminal("crypto :: hashes")
    with tabs[1]:
        open_box("ENCODE / DECODE")
        d_in = st.text_area("INPUT", key="enc_in", height=100)
        op = st.selectbox(
            "OPERATION",
            [
                "HEX -> Base58", "Base58 -> HEX",
                "HEX -> Base64", "Base64 -> HEX",
                "UTF-8 -> HEX", "HEX -> UTF-8",
            ],
            key="enc_op",
        )
        if _btn("CONVERT", key="enc_run", variant="cyan"):
            try:
                if op == "HEX -> Base58":
                    out = encode_base58(hex_to_bytes(d_in))
                elif op == "Base58 -> HEX":
                    out = bytes_to_hex(decode_base58(d_in.strip()))
                elif op == "HEX -> Base64":
                    out = bytes_to_b64(hex_to_bytes(d_in))
                elif op == "Base64 -> HEX":
                    out = bytes_to_hex(b64_to_bytes(d_in.strip()))
                elif op == "UTF-8 -> HEX":
                    out = bytes_to_hex(d_in.encode("utf-8"))
                elif op == "HEX -> UTF-8":
                    out = hex_to_bytes(d_in).decode("utf-8", errors="replace")
                else:
                    out = "?"
                log_event("ok", f"Encoded via {op}")
                render_rblock([("OPERATION", op, "ra"), ("RESULT", out, "rv")])
            except ValueError as e:
                st.error(str(e))
        close_box()
    with tabs[2]:
        open_box("UNIT CONVERTER")
        col1, col2 = st.columns(2)
        with col1:
            sat = st.text_input("SATOSHI", key="cv_sat")
            if _btn("SAT -> BTC", key="cv_sat_run"):
                try:
                    n = int(sat)
                    st.code(f"{satoshi_to_btc(n)} BTC", language="text")
                except ValueError:
                    st.error("Satoshi must be an integer.")
        with col2:
            wei = st.text_input("WEI", key="cv_wei")
            if _btn("WEI -> ETH", key="cv_wei_run"):
                try:
                    n = int(wei)
                    st.code(f"{wei_to_eth(n)} ETH", language="text")
                except ValueError:
                    st.error("Wei must be an integer.")
        close_box()


def page_live_addr():
    render_section_header("\U0001F4E1", "LIVE ADDRESS LOOKUP", "PUBLIC NETWORK CALL")
    if not is_live():
        st.error("LIVE ANALYSIS mode required. Engage from the sidebar.")
        return
    if live_utils is None:
        st.error("live_utils module is unavailable in this build.")
        return
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("ADDRESS QUERY", live=True)
        chain = st.selectbox("CHAIN", ["Bitcoin", "Ethereum"], key="liveaddr_chain")
        addr = st.text_input("ADDRESS", key="liveaddr_addr")
        if _btn("LOOKUP", key="liveaddr_run", variant="cyan"):
            if not addr.strip():
                st.warning("Address required.")
            else:
                try:
                    with st.spinner("Calling public API..."):
                        if chain == "Bitcoin":
                            data = live_utils.lookup_btc_address(addr)
                            log_event("ok", f"BTC lookup OK for {addr[:12]}...")
                            render_rblock([
                                ("ADDRESS", data["address"], "ra"),
                                ("BALANCE (sats)", f"{data['balance_satoshi']:,}", "rv"),
                                ("BALANCE (BTC)", satoshi_to_btc(int(data["balance_satoshi"])), "rv"),
                                ("TX COUNT", str(data["tx_count"]), "ra"),
                            ])
                        else:
                            data = live_utils.lookup_eth_address(addr)
                            log_event("ok", f"ETH lookup OK for {addr[:12]}...")
                            render_rblock([
                                ("ADDRESS", data["address"], "ra"),
                                ("BALANCE (wei)", f"{data['balance_wei']:,}", "rv"),
                                ("BALANCE (ETH)", wei_to_eth(int(data["balance_wei"])), "rv"),
                            ])
                except Exception as e:
                    st.error(f"Lookup failed: {e}")
                    log_event("err", f"Lookup error: {e}")
        close_box()
        open_box("LIVE MEMPOOL FEES")
        if _btn("FETCH BTC FEES", key="fees_run", variant="green"):
            try:
                fees = live_utils.get_mempool_fees()
                rows = [[k, str(v), "sat/vB"] for k, v in fees.items()]
                render_data_table(["TIER", "FEE", "UNIT"], rows)
                log_event("ok", "Fetched mempool fees")
            except Exception as e:
                st.error(f"Fee fetch failed: {e}")
                log_event("err", f"Fee fetch error: {e}")
        close_box()
    with col2:
        render_terminal("live :: address")


def page_live_tx():
    render_section_header("\U0001F4E1", "LIVE TX LOOKUP", "BLOCKSTREAM API")
    if not is_live():
        st.error("LIVE ANALYSIS mode required. Engage from the sidebar.")
        return
    if live_utils is None:
        st.error("live_utils module is unavailable in this build.")
        return
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("TRANSACTION QUERY", live=True)
        chain = st.selectbox("CHAIN", ["Bitcoin"], key="livetx_chain")
        txid = st.text_input("TXID (64 hex)", key="livetx_id")
        if _btn("FETCH TX", key="livetx_run", variant="cyan"):
            if not txid.strip():
                st.warning("TXID required.")
            else:
                try:
                    with st.spinner("Calling Blockstream..."):
                        data = live_utils.lookup_btc_transaction(txid.strip())
                    log_event("ok", f"TX fetched: {txid[:12]}...")
                    rows = [
                        ("TXID", data.get("txid", "-"), "ra"),
                        ("SIZE", str(data.get("size", "-")), "rv"),
                        ("WEIGHT", str(data.get("weight", "-")), "rv"),
                        ("FEE (sats)", f"{data.get('fee', 0):,}", "ro"),
                        ("VIN", str(len(data.get("vin", []))), "ra"),
                        ("VOUT", str(len(data.get("vout", []))), "ra"),
                        ("STATUS", "CONFIRMED" if data.get("status", {}).get("confirmed") else "UNCONFIRMED", "rv"),
                    ]
                    render_rblock(rows)
                    st.caption("Raw JSON below for full evidence record.")
                    st.code(json.dumps(data, indent=2)[:4000], language="json")
                except Exception as e:
                    st.error(f"TX lookup failed: {e}")
                    log_event("err", f"TX lookup error: {e}")
        close_box()
    with col2:
        render_terminal("live :: tx")


def page_airgap_guide():
    render_section_header("\U0001F6AB", "AIR-GAPPED OPS GUIDE", "PHYSICAL ISOLATION PROTOCOL")
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("AIRGAP CHECKLIST")
        st.markdown(
            """
1. **Cut all network paths.** Pull the Ethernet cable. Disable Wi-Fi and Bluetooth
   in the BIOS, not just the OS. Verify with `ip link` / `iwconfig`.
2. **Boot off a known-good medium.** Tails, an offline Ubuntu live USB, or your
   internal install only if you trust it.
3. **Cover sensors.** Tape over webcams. Disconnect microphones.
4. **Use a dedicated keyboard and screen.** No KVM that has been on a network.
5. **No removable media in / out** without an out-of-band hash check.
6. **Operate from a quiet room.** Side-channel paranoia is appropriate when the
   stakes are high; ambient acoustic logging of keystrokes is a real attack.
            """
        )
        close_box()
        open_box("PSBT / OFFLINE SIGNING WORKFLOW")
        st.markdown(
            """
- Build the unsigned PSBT on the online (watch-only) machine.
- Transfer via QR code or a freshly-formatted SD card.
- Sign on the airgapped machine using a dedicated wallet UI.
- Transfer the signed PSBT back via the same out-of-band channel.
- Broadcast from the watch-only machine. The airgapped device never
  speaks to the network.
            """
        )
        close_box()
    with col2:
        render_terminal("airgap :: protocol")


def log_export(format_name: str) -> None:
    auth_case = st.session_state.get("auth_case_id", "NO_CASE")
    user_role = st.session_state.get("user_role", "Viewer")
    log_audit_event(
        case_id=auth_case,
        module="exporter",
        action=f"exported_report_{format_name}",
        role=user_role,
        mode=get_current_mode(),
        export_actions=format_name
    )

def page_exporter():
    render_section_header("\U0001F4CA", "RECOVERY REPORT EXPORTER", "TXT / CSV / PDF / QR")
    addresses = st.session_state.get("last_derivations", [])
    active = get_active_case()
    notes_default = ""
    if active:
        notes_default = (
            f"Case: {active['id']} {active['name']}\n"
            f"Investigator: {active['investigator']}\n"
            f"Chain: {active['chain']}"
        )

    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("REPORT BUILDER", live=True)
        st.write(f"Records available in session: **{len(addresses)}**.")
        notes = st.text_area("REPORT NOTES (free text - do NOT paste secrets)", value=notes_default, key="exp_notes", height=120)

        if addresses:
            preview = build_txt_report(addresses[:10], notes=notes)
            st.code(preview[:1500], language="text")
        else:
            st.caption("No addresses yet. Run DERIVATION SCANNER or ADDRESS GENERATOR first.")

        bcol1, bcol2, bcol3 = st.columns(3)
        with bcol1:
            st.markdown('<div class="btn-green">', unsafe_allow_html=True)
            if addresses:
                st.download_button(
                    "DOWNLOAD TXT",
                    data=build_txt_report(addresses, notes=notes),
                    file_name="cryptex_report.txt",
                    mime="text/plain",
                    key="dl_txt",
                    on_click=log_export,
                    args=("TXT",),
                )
            st.markdown("</div>", unsafe_allow_html=True)
        with bcol2:
            st.markdown('<div class="btn-green">', unsafe_allow_html=True)
            if addresses:
                st.download_button(
                    "DOWNLOAD CSV",
                    data=build_csv_report(addresses, notes=notes),
                    file_name="cryptex_report.csv",
                    mime="text/csv",
                    key="dl_csv",
                    on_click=log_export,
                    args=("CSV",),
                )
            st.markdown("</div>", unsafe_allow_html=True)
        with bcol3:
            st.markdown('<div class="btn-green">', unsafe_allow_html=True)
            if addresses:
                try:
                    pdf_bytes = build_pdf_report(addresses, notes=notes)
                    st.download_button(
                        "DOWNLOAD PDF",
                        data=pdf_bytes,
                        file_name="cryptex_report.pdf",
                        mime="application/pdf",
                        key="dl_pdf",
                        on_click=log_export,
                        args=("PDF",),
                    )
                except Exception as e:
                    st.error(f"PDF build failed: {e}")
            st.markdown("</div>", unsafe_allow_html=True)
        close_box()

        if addresses:
            open_box("QR CODE FOR A SINGLE ADDRESS")
            choices = [f"{i+1}: {a['address']}" for i, a in enumerate(addresses)]
            chosen = st.selectbox("ADDRESS", choices, key="qr_choice")
            idx = int(chosen.split(":", 1)[0]) - 1
            try:
                png = build_qr_png(addresses[idx]["address"], box_size=6)
                st.image(png, caption=addresses[idx]["address"], width=240)
                st.download_button(
                    "DOWNLOAD QR PNG",
                    data=png,
                    file_name="address_qr.png",
                    mime="image/png",
                    key="dl_qr",
                    on_click=log_export,
                    args=("QR_PNG",),
                )
            except ValueError as e:
                st.error(str(e))
            close_box()

    with col2:
        render_terminal("export :: report")


def page_education():
    render_section_header("\U0001F4DA", "EDUCATIONAL LAB", "REFERENCE MATERIAL")
    col1, col2 = st.columns([3, 2])
    with col1:
        open_box("CORE STANDARDS")
        st.markdown(
            """
- [BIP-0039 (mnemonic phrases)](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-0032 (HD wallets)](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-0044 (multi-account hierarchy)](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [BIP-0049 (P2SH-P2WPKH)](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki)
- [BIP-0084 (native SegWit)](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)
- [BIP-0086 (Taproot)](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)
- [SLIP-0039 (Shamir secret sharing)](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
            """
        )
        close_box()
        open_box("HARDWARE WALLETS")
        st.markdown(
            """
- Ledger device airgap recommendations.
- Trezor + Coldcard PSBT workflows.
- Common CVEs touching hardware wallets are tracked in the public CVE
  database. When working a recovery, sanity-check the device firmware
  version against the vendor changelog before deriving anything important.
            """
        )
        close_box()
    with col2:
        open_box("OPSEC PRIMER")
        st.markdown(
            """
- Treat the recovery session like incident response: log every step,
  hash every evidence file, keep a chain-of-custody record.
- Discuss seeds and keys only verbally in a private space.
- Wipe the host between unrelated cases; this app exposes
  CLEAR SESSION in the sidebar for exactly that reason.
- Don't paste secrets into the **NOTES** field of the exporter. The
  exporter's address whitelist will not save you from that mistake.
            """
        )
        close_box()


def page_wipe():
    render_section_header("\U0001F9F9", "CLEAR SESSION", "FULL WIPE")
    st.warning(
        "This destroys every case, every derivation, every entropy result, "
        "and the activity log. There is no undo."
    )
    if _btn("CONFIRM SESSION WIPE", key="wipe_confirm", variant="red"):
        wipe_session_state(st)
        log_event("ok", "Session wiped")
        st.success("Session state cleared. Reloading...")
        st.rerun()


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

ROUTE = {
    PAGE_SECURITY_LANDING: page_security_landing,
    PAGE_RECOVERY_SELECTOR: page_recovery_selector,
    PAGE_CASE_MGMT: page_case_mgmt,
    PAGE_EVIDENCE_HASH: page_evidence_hash,
    PAGE_BIP39_VALIDATION: page_bip39_validation,
    PAGE_INCOMPLETE_SEED: page_incomplete_seed,
    PAGE_TYPO_LAB: page_typo_lab,
    PAGE_WRONG_ORDER: page_wrong_order,
    PAGE_PASSPHRASE: page_passphrase,
    PAGE_DERIVATION: page_derivation,
    PAGE_ADDRESS_MATCHER: page_address_matcher,
    PAGE_ADDRESS_GEN: page_address_gen,
    PAGE_ENTROPY: page_entropy,
    PAGE_VAULT_INSPECT: page_vault_inspect,
    PAGE_HASH_TOOLS: page_hash_tools,
    PAGE_LIVE_ADDR: page_live_addr,
    PAGE_LIVE_TX: page_live_tx,
    PAGE_AIRGAP_GUIDE: page_airgap_guide,
    PAGE_EXPORTER: page_exporter,
    PAGE_EDUCATION: page_education,
    PAGE_WIPE: page_wipe,
}
# Pages that require offline mode (locked when LIVE_ANALYSIS active).
OFFLINE_LOCKED_PAGES = {
    PAGE_INCOMPLETE_SEED, PAGE_TYPO_LAB, PAGE_WRONG_ORDER,
    PAGE_PASSPHRASE, PAGE_DERIVATION, PAGE_ADDRESS_MATCHER,
    PAGE_ADDRESS_GEN, PAGE_BIP39_VALIDATION, PAGE_VAULT_INSPECT,
    PAGE_RECOVERY_SELECTOR,
}
LIVE_LOCKED_PAGES = {PAGE_LIVE_ADDR, PAGE_LIVE_TX}

# Role definitions for Role-Based Access Control (RBAC)
ROLES = {
    "Viewer": [
        PAGE_SECURITY_LANDING, PAGE_CASE_MGMT, PAGE_EVIDENCE_HASH,
        PAGE_ENTROPY, PAGE_HASH_TOOLS, PAGE_AIRGAP_GUIDE, PAGE_EDUCATION,
        PAGE_WIPE, PAGE_LIVE_ADDR, PAGE_LIVE_TX
    ],
    "Analyst": [
        PAGE_SECURITY_LANDING, PAGE_CASE_MGMT, PAGE_EVIDENCE_HASH,
        PAGE_RECOVERY_SELECTOR, PAGE_BIP39_VALIDATION, PAGE_TYPO_LAB, PAGE_WRONG_ORDER,
        PAGE_DERIVATION, PAGE_ADDRESS_MATCHER, PAGE_ADDRESS_GEN,
        PAGE_ENTROPY, PAGE_HASH_TOOLS, PAGE_AIRGAP_GUIDE, PAGE_EDUCATION,
        PAGE_WIPE, PAGE_EXPORTER, PAGE_LIVE_ADDR, PAGE_LIVE_TX
    ],
    "Senior Analyst": [
        PAGE_SECURITY_LANDING, PAGE_CASE_MGMT, PAGE_EVIDENCE_HASH,
        PAGE_RECOVERY_SELECTOR, PAGE_BIP39_VALIDATION, PAGE_INCOMPLETE_SEED, PAGE_TYPO_LAB, PAGE_WRONG_ORDER,
        PAGE_PASSPHRASE, PAGE_DERIVATION, PAGE_ADDRESS_MATCHER, PAGE_ADDRESS_GEN,
        PAGE_ENTROPY, PAGE_HASH_TOOLS, PAGE_VAULT_INSPECT, PAGE_AIRGAP_GUIDE, PAGE_EDUCATION,
        PAGE_WIPE, PAGE_EXPORTER, PAGE_LIVE_ADDR, PAGE_LIVE_TX
    ],
    "Admin": [
        PAGE_SECURITY_LANDING, PAGE_CASE_MGMT, PAGE_EVIDENCE_HASH,
        PAGE_RECOVERY_SELECTOR, PAGE_BIP39_VALIDATION, PAGE_INCOMPLETE_SEED, PAGE_TYPO_LAB, PAGE_WRONG_ORDER,
        PAGE_PASSPHRASE, PAGE_DERIVATION, PAGE_ADDRESS_MATCHER, PAGE_ADDRESS_GEN,
        PAGE_ENTROPY, PAGE_HASH_TOOLS, PAGE_VAULT_INSPECT, PAGE_AIRGAP_GUIDE, PAGE_EDUCATION,
        PAGE_WIPE, PAGE_EXPORTER, PAGE_LIVE_ADDR, PAGE_LIVE_TX
    ]
}

# Roles that require TOTP verification before elevation
TOTP_PROTECTED_ROLES: set[str] = {"Senior Analyst", "Admin"}


def _get_totp_secret(role: str) -> str | None:
    """Return the TOTP base32 secret for a role from the signed license, or None if absent."""
    _, _, license_data = check_license()
    return license_data.get("totp_secrets", {}).get(role)


def render_totp_challenge() -> None:
    """Replace the main content area with a TOTP verification form for pending role elevation."""
    pending_role = st.session_state.get("pending_role", "")
    if not pending_role:
        return

    render_section_header("🔐", "ROLE ELEVATION — 2FA REQUIRED", f"ELEVATING TO: {pending_role.upper()}")
    open_box("TOTP VERIFICATION")

    now = datetime.now(timezone.utc)
    fail_count = st.session_state.get("totp_fail_count", 0)
    locked_until = st.session_state.get("totp_locked_until", 0.0)

    if now.timestamp() < locked_until:
        remaining = int(locked_until - now.timestamp())
        st.error(f"Too many failed attempts. Try again in {remaining} second(s).")
        if st.button("CANCEL ROLE CHANGE", key="totp_cancel_locked"):
            st.session_state.pop("pending_role", None)
            st.rerun()
        close_box()
        return

    totp_secret = _get_totp_secret(pending_role)
    if not totp_secret:
        st.error(
            f"TOTP not configured for role '{pending_role}'. "
            "Ask your administrator to provision 2FA secrets in the license file."
        )
        log_audit_event(
            "system", "totp_challenge",
            f"TOTP secret missing for role {pending_role}",
            st.session_state.get("user_role", "Unknown"),
            get_current_mode(),
        )
        if st.button("CANCEL", key="totp_cancel_no_secret"):
            st.session_state.pop("pending_role", None)
            st.rerun()
        close_box()
        return

    current_role = st.session_state.get("user_role", "Viewer")
    st.warning(
        f"Role **{pending_role}** is protected. "
        "Open your authenticator app and enter the current 6-digit code."
    )

    with st.form("totp_verification_form"):
        code = st.text_input("6-DIGIT AUTHENTICATOR CODE", max_chars=6, placeholder="000000")
        submitted = st.form_submit_button("VERIFY & ELEVATE ROLE", use_container_width=True)

    if st.button("CANCEL ROLE CHANGE", key="totp_cancel_btn"):
        st.session_state.pop("pending_role", None)
        st.session_state.pop("totp_fail_count", None)
        st.rerun()

    if submitted:
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(code.strip(), valid_window=1):
            st.session_state["user_role"] = pending_role
            st.session_state.pop("pending_role", None)
            st.session_state.pop("totp_fail_count", None)
            st.session_state.pop("totp_locked_until", None)
            st.session_state["authorized_for_recovery"] = False
            log_event("ok", f"Role elevated from {current_role} to {pending_role} via TOTP 2FA")
            log_audit_event(
                "system", "totp_challenge",
                f"Role elevated from {current_role} to {pending_role}",
                pending_role, get_current_mode(),
            )
            st.success("Verification successful. Role elevated.")
            st.rerun()
        else:
            new_fail = fail_count + 1
            st.session_state["totp_fail_count"] = new_fail
            log_audit_event(
                "system", "totp_challenge",
                f"Failed TOTP attempt #{new_fail} for role {pending_role}",
                current_role, get_current_mode(),
            )
            if new_fail >= 3:
                st.session_state["totp_locked_until"] = now.timestamp() + 30
                log_event("warn", f"TOTP locked after {new_fail} failed attempts for role {pending_role}")
                st.error("Too many failed attempts. Locked for 30 seconds.")
            else:
                st.error(f"Invalid code. {3 - new_fail} attempt(s) remaining.")

    close_box()


# Mapping of pages to functional module boundaries defined in license_data.get("modules")
PAGE_MODULE_MAP = {
    PAGE_RECOVERY_SELECTOR: "recovery",
    PAGE_BIP39_VALIDATION: "recovery",
    PAGE_INCOMPLETE_SEED: "recovery",
    PAGE_TYPO_LAB: "recovery",
    PAGE_WRONG_ORDER: "recovery",
    PAGE_PASSPHRASE: "recovery",
    PAGE_DERIVATION: "recovery",
    PAGE_ADDRESS_MATCHER: "recovery",
    PAGE_ADDRESS_GEN: "recovery",
    PAGE_VAULT_INSPECT: "forensic",
    PAGE_CASE_MGMT: "forensic",
    PAGE_EVIDENCE_HASH: "forensic",
    PAGE_EXPORTER: "reports",
}

def page_license_activation(err_msg: str) -> None:
    render_section_header("🔑", "LICENSE ACTIVATION REQUIRED", "OFFLINE VERIFICATION SYSTEM")
    
    st.error(f"Application Inactive: {err_msg}")
    st.info("Please upload a valid signed license file (`license.json`) to activate Cryptex Lab.")
    
    uploaded_file = st.file_uploader("Upload license.json", type=["json"])
    if uploaded_file is not None:
        try:
            content = json.load(uploaded_file)
            is_valid, verify_err, data = verify_license_data(content, Path("public_key.pem"))
            if is_valid:
                with open("license.json", "w", encoding="utf-8") as f:
                    json.dump(content, f, indent=2)
                st.success("License activated successfully! Reloading...")
                st.rerun()
            else:
                st.error(f"Invalid License: {verify_err}")
        except Exception as e:
            st.error(f"Error parsing file: {e}")
            
    st.markdown("### Or paste license JSON contents:")
    paste_content = st.text_area("License JSON", height=200)
    if st.button("ACTIVATE LICENSE"):
        if paste_content:
            try:
                content = json.loads(paste_content)
                is_valid, verify_err, data = verify_license_data(content, Path("public_key.pem"))
                if is_valid:
                    with open("license.json", "w", encoding="utf-8") as f:
                        json.dump(content, f, indent=2)
                    st.success("License activated successfully! Reloading...")
                    st.rerun()
                else:
                    st.error(f"Invalid License: {verify_err}")
            except Exception as e:
                st.error(f"Error parsing JSON: {e}")
        else:
            st.warning("Please paste license contents.")

def render_authorization_workflow(target_page: str) -> None:
    render_section_header("⚠️", "PROCEDURAL AUTHORIZATION REQUIRED", "FORENSIC WORKSTATION AUDIT GATE")
    
    open_box("AUTHORIZATION FORM")
    
    st.warning("You are attempting to access a recovery or forensic tool. To maintain procedural accountability, you must acknowledge authorization.")
    
    active_case = get_active_case()
    active_case_id = active_case["id"] if active_case else ""
    
    with st.form("authorization_acknowledgement_form"):
        case_id = st.text_input("CASE ID", value=active_case_id, placeholder="e.g. CASE-001")
        notes = st.text_area("AUTHORIZATION NOTES / JUSTIFICATION", placeholder="Explain the legal basis or written authorization details...")
        
        authorized_check = st.checkbox(
            "I confirm I own this wallet or have written authorization from the owner to perform recovery operations."
        )
        
        submitted = st.form_submit_button("SUBMIT AUTHORIZATION & ENGAGE TOOL")
        if submitted:
            if not case_id:
                st.error("Error: Case ID is required.")
            elif not notes:
                st.error("Error: Authorization notes/justification is required.")
            elif not authorized_check:
                st.error("Error: You must check the authorization confirmation checkbox.")
            else:
                # Mark as authorized
                st.session_state["authorized_for_recovery"] = True
                st.session_state["auth_case_id"] = case_id
                
                # Log the event to audit log and terminal
                user_role = st.session_state.get("user_role", "Viewer")
                log_audit_event(
                    case_id=case_id,
                    module=target_page,
                    action="authorization_granted",
                    role=user_role,
                    mode=get_current_mode()
                )
                
                log_event("ok", f"Authorized recovery tools for Case {case_id}")
                st.success("Authorization confirmed. Loading tool...")
                st.rerun()
                
    close_box()


def main() -> None:
    st.set_page_config(
        page_title=APP_NAME,
        page_icon=str(ICON_PATH) if ICON_PATH.exists() else "\U0001F50D",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_mode()
    init_case_registry()
    inject_cryptex_css()

    # 1. Build Integrity Verification
    integrity_ok, integrity_err = verify_build_integrity()
    if not integrity_ok:
        st.error("🚨 CRITICAL: CRYPTEX LAB Build Integrity Check Failed!")
        st.info(f"Detail: {integrity_err}")
        st.warning("The application files appear to have been modified or corrupted. For safety, execution has been halted. Please check manifest.json or contact Titan Code support.")
        st.stop()

    # 2. License Verification
    is_license_valid, license_err, license_data = check_license()
    if not is_license_valid:
        render_header()
        page_license_activation(license_err)
        return

    # 2b. Machine Fingerprint Check — license must be bound to this workstation
    fp_ok, fp_err = verify_machine_fingerprint(license_data)
    if not fp_ok:
        render_header()
        st.error("MACHINE AUTHORIZATION FAILURE")
        st.warning(fp_err)
        st.info(
            "Run `python machine_id.py` on this machine and send the fingerprint "
            "to Titan Code to obtain a machine-specific license."
        )
        st.stop()

    if "current_page" not in st.session_state:
        st.session_state["current_page"] = PAGE_SECURITY_LANDING

    page = render_sidebar()
    render_header()
    render_active_case_banner()

    # 3. TOTP Role Elevation Challenge (intercepts before RBAC)
    if st.session_state.get("pending_role"):
        render_totp_challenge()
        return

    # 4. RBAC (Role-Based Access Control) Page Access Check
    user_role = st.session_state.get("user_role", "Viewer")
    allowed_pages = ROLES.get(user_role, ROLES["Viewer"])
    if page not in allowed_pages:
        st.error(f"Access Denied: Role '{user_role}' is not authorized to access '{page}'.")
        log_event("warn", f"Access denied to '{page}' for role '{user_role}'")
        return

    # License module-level access check
    required_module = PAGE_MODULE_MAP.get(page)
    if required_module:
        if not check_module_access(license_data, required_module):
            st.error(f"License Restriction: Current license does not permit access to the '{required_module}' module.")
            st.info("Please contact Titan Code support to obtain access.")
            log_event("warn", f"License check failed for module '{required_module}'")
            return

    # 5. Authorization Workflow acknowledgement check
    if page in OFFLINE_LOCKED_PAGES:
        if not st.session_state.get("authorized_for_recovery", False):
            render_authorization_workflow(page)
            return

    # Security guards: redirect to landing if user picks a locked page.
    if is_live() and page in OFFLINE_LOCKED_PAGES:
        st.error(
            f"'{page}' handles sensitive material and is locked while LIVE ANALYSIS"
            " mode is active. Return to OFFLINE SAFE in the sidebar."
        )
        log_event("warn", f"Blocked offline page {page} in live mode")
        return
    if is_offline() and page in LIVE_LOCKED_PAGES:
        st.error(
            f"'{page}' requires LIVE ANALYSIS mode. Engage from the sidebar to proceed."
        )
        log_event("warn", f"Blocked live page {page} in offline mode")
        return

    handler = ROUTE.get(page)
    if handler:
        # Log module usage to the audit log if authorized
        if page in OFFLINE_LOCKED_PAGES or required_module == "forensic":
            auth_case = st.session_state.get("auth_case_id", "NO_CASE")
            log_audit_event(
                case_id=auth_case,
                module=page,
                action="accessed_module",
                role=user_role,
                mode=get_current_mode()
            )
        handler()
    else:
        st.error(f"Unknown page: {page}")


if __name__ == "__main__":
    main()
