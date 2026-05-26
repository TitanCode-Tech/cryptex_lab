"""
Offline Wallet Recovery Lab - Streamlit workstation
===================================================

This file is the *frontend* only. All cryptography, recovery logic, forensic
parsing, and export rendering live in the modular engines:

    wallet_utils.py       BIP39 validation + standard ETH/BTC derivation
    derivation_utils.py   General HD-derivation, multi-standard scans, matching
    recovery_utils.py     Missing-word / typo / word-order / passphrase engines
    forensic_utils.py     MetaMask vault + wallet-file metadata inspection
    export_utils.py       TXT / CSV / PDF / QR exporters (whitelisted fields)

SECURITY SUMMARY
----------------
* No network calls. Grep the project for `requests`, `urllib`, `socket`, `http`,
  `web3` - nothing matches.
* The mnemonic / passphrase only ever live in local function arguments and the
  Streamlit text widgets they came from. They are never copied into custom
  session-state keys we own.
* Derived public addresses ARE kept in session state so the user can build a
  report across multiple operations. They are public information.
* The Clear Session page wipes every key (both ours and Streamlit's own widget
  state) and forces a rerun.
* Exports only contain whitelisted public fields. The export module raises if
  any record contains a forbidden field name like `mnemonic`/`seed`/etc.

Run with:
    streamlit run app.py
(The bundled .streamlit/config.toml already pins headless+localhost+dark+
 no-telemetry, so you do not need extra CLI flags.)
"""

from __future__ import annotations

import streamlit as st

from wallet_utils import (
    BTC_ADDRESS_TYPES,
    MAX_ADDRESSES_PER_REQUEST,
    derive_btc_addresses,
    derive_eth_addresses,
    validate_mnemonic,
)
from derivation_utils import (
    compare_all_standards,
    derive_arbitrary_path,
    find_address_match,
    scan_standard_paths,
)
from recovery_utils import (
    MAX_MISSING_WORDS,
    MAX_ORDER_POSITIONS,
    recover_missing_words,
    recover_word_order,
    suggest_typo_corrections,
    test_passphrase,
)
from forensic_utils import identify_wallet_file, inspect_metamask_vault
from export_utils import build_csv_report, build_pdf_report, build_qr_png, build_txt_report


# ---------------------------------------------------------------------------
# Page chrome
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Offline Wallet Recovery Lab",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

# We keep ONLY public, exportable derivation results in our own keys.
# Streamlit itself stores text-widget values under the widget's `key`; that is
# unavoidable for any text input. The "Clear session" page wipes everything.
RESULTS_KEY = "derived_addresses"
NOTES_KEY = "recovery_notes"
DISCLAIMER_KEY = "accepted_disclaimer"


def _init_state() -> None:
    if RESULTS_KEY not in st.session_state:
        st.session_state[RESULTS_KEY] = []
    if NOTES_KEY not in st.session_state:
        st.session_state[NOTES_KEY] = ""
    if DISCLAIMER_KEY not in st.session_state:
        st.session_state[DISCLAIMER_KEY] = False


def _clear_session() -> None:
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    _init_state()


def _add_results(rows: list[dict]) -> None:
    """De-duplicated append. Records contain only public fields."""
    existing = {(r["path"], r["address"]) for r in st.session_state[RESULTS_KEY]}
    for r in rows:
        key = (r["path"], r["address"])
        if key not in existing:
            st.session_state[RESULTS_KEY].append(r)
            existing.add(key)


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------

def _mnemonic_input(key: str, label: str = "BIP39 seed phrase") -> str:
    """Standard mnemonic textbox. We never write the value to our own state."""
    return st.text_area(
        label,
        height=100,
        key=key,
        placeholder="word1 word2 word3 ...  (12 / 15 / 18 / 21 / 24 words)",
        help=(
            "Processed in memory only. Never logged, saved, exported, or sent "
            "over a network. Use the Clear Session page when you are done."
        ),
    )


def _passphrase_input(key: str) -> str:
    """Optional BIP39 passphrase. Treated as a secret - never persisted."""
    return st.text_input(
        "Optional BIP39 passphrase (the '25th word')",
        type="password",
        key=key,
        help=(
            "BIP39 passphrases mutate the seed: same mnemonic + different "
            "passphrase = different wallet. Leave blank if you did not set one."
        ),
    )


def _target_address_input(key: str) -> str:
    """Known public address to match candidates against."""
    return st.text_input(
        "Known public address (optional)",
        key=key,
        placeholder="0x... (ETH) or bc1.../1.../3... (BTC)",
        help="If you remember at least one address from this wallet, paste it "
             "here to narrow recovery results down to the right derivation.",
    )


def _disclaimer_gate() -> bool:
    if not st.session_state.get(DISCLAIMER_KEY, False):
        st.warning(
            "Read and accept the disclaimer on the **Home** page before using "
            "any recovery workflow."
        )
        return False
    return True


def _ethical_banner() -> None:
    st.error(
        "**ONLY USE THIS TOOL FOR WALLETS YOU OWN OR ARE AUTHORIZED TO RECOVER.** "
        "Use against third-party wallets without written authorisation is illegal "
        "in most jurisdictions."
    )


def _show_addresses_table(rows: list[dict]) -> None:
    st.dataframe(
        [
            {
                "Coin": r["coin"],
                "Type": r["address_type"],
                "Path": r["path"],
                "Address": r["address"],
            }
            for r in rows
        ],
        use_container_width=True,
        hide_index=True,
    )


# ---------------------------------------------------------------------------
# Page: Home / security landing
# ---------------------------------------------------------------------------

def page_home() -> None:
    st.title("Offline Wallet Recovery Lab")
    st.caption(
        "A modular, fully-offline recovery workstation for authorised wallet "
        "owners and forensic recovery specialists."
    )
    _ethical_banner()

    st.subheader("What this is")
    st.markdown(
        """
        A local recovery laboratory that bundles multiple offline recovery
        engines behind a single guided UI:

        - **BIP39 validator** - word count, wordlist, checksum.
        - **Missing-word recovery** - fill in `?` placeholders, filter by checksum.
        - **Typo correction** - Levenshtein-1 suggestions from the official wordlist.
        - **Word-order recovery** - bounded permutation testing.
        - **Passphrase tester** - try a candidate BIP39 passphrase locally.
        - **Derivation path scanner** - BIP44 / BIP49 / BIP84 + arbitrary paths.
        - **Known-address matcher** - find which derivation produced a given address.
        - **Wallet file metadata inspector** - MetaMask vault structure, file ID
          (metadata only - no decryption, no password trials).
        - **Recovery report exporter** - TXT / CSV / PDF / QR (public data only).
        """
    )

    st.subheader("Offline checklist")
    st.markdown(
        """
        Before you paste any real mnemonic into this app:

        1. **Disconnect** Wi-Fi, ethernet, and any tethered mobile data.
        2. **Close** cloud sync agents (Dropbox, iCloud, OneDrive, Drive).
        3. **Quit** other browsers and remove any clipboard manager.
        4. **Optional but recommended:** run under `firejail --net=none ...` or
           an equivalent network-namespace sandbox, so the Python process
           cannot reach a network even if something tried.
        5. After finishing, use **Clear Session** and reboot the machine.
        """
    )

    st.subheader("What this tool does NOT do")
    st.markdown(
        """
        - No internet, no APIs, no RPC, no telemetry, no auto-update.
        - No balance checks (requires the network - intentionally out of scope).
        - No password cracking / decryption attempts on encrypted vaults.
        - No bulk attacks on unknown / third-party wallets.
        - No persistence of seed phrases, private keys, raw seed bytes,
          entropy, or passphrases. Anywhere. Ever.
        """
    )

    st.divider()
    accept = st.checkbox(
        "I have read the above. I will run this tool offline. I will only use "
        "it on wallets I own or am explicitly authorised to recover.",
        value=st.session_state.get(DISCLAIMER_KEY, False),
        key="_disclaimer_box",
    )
    st.session_state[DISCLAIMER_KEY] = accept
    if not accept:
        st.info("Tick the box to unlock the rest of the lab.")


# ---------------------------------------------------------------------------
# Page: Educational lab
# ---------------------------------------------------------------------------

def page_education() -> None:
    st.title("Educational lab")
    st.caption(
        "Beginner-friendly references covering wallet architecture and the "
        "BIP standards this lab implements."
    )

    topic = st.selectbox(
        "Topic",
        [
            "Wallet architecture (hot / cold / custodial)",
            "Public vs private keys, hashing, ECC",
            "BIP39 - seed phrases",
            "BIP32 - HD wallets",
            "BIP44 / BIP49 / BIP84 - derivation paths",
            "Air-gapped recovery principles",
            "Hardware wallet security",
            "Scams, phishing, and red flags",
        ],
    )

    if topic.startswith("Wallet architecture"):
        st.markdown("""
        ### Wallet architecture

        A crypto wallet stores **keys**, not coins. Coins live on-chain; the
        wallet just controls the addresses that can move them.

        **Hot wallets** (MetaMask, Trust Wallet, Phantom) - software on an
        internet-connected device. Convenient, but their private keys are
        only as safe as the OS and browser they run on.

        **Cold wallets** (Ledger, Trezor, air-gapped paper / steel backups)
        - keys never touch an internet-connected device. Recovery from a
        cold backup is exactly what this lab is designed for.

        **Custodial** wallets (Coinbase, Binance accounts) - a third party
        holds the keys. Recovery is a customer-service problem, not a
        cryptographic one. This tool is not for you.

        **Non-custodial** - you hold the keys, so you carry the recovery
        burden. Rule of thumb: *"Not your keys, not your coins."*
        """)
    elif topic.startswith("Public vs private"):
        st.markdown("""
        ### Public / private keys, hashing, ECC

        - **Private key:** a random 256-bit secret. Whoever holds it controls
          the funds. Never share, never paste online.
        - **Public key:** derived from the private key with elliptic-curve
          multiplication on **secp256k1** (Bitcoin and Ethereum both use this
          curve). Safe to share.
        - **Address:** a hash of the public key, optionally encoded. Bitcoin
          uses SHA-256 + RIPEMD-160; Ethereum uses Keccak-256.
        - **Hashing:** one-way. You can verify a guess but you cannot reverse
          a hash to recover the input. This is why a lost seed cannot be
          "decrypted" - it can only be reconstructed.
        """)
    elif topic.startswith("BIP39"):
        st.markdown("""
        ### BIP39 - seed phrases

        A BIP39 mnemonic is **entropy + checksum**, encoded as 12 / 15 / 18 /
        21 / 24 words from a 2048-word English wordlist.

        - 128 bits of entropy -> 12 words.
        - 256 bits of entropy -> 24 words.
        - The last bits of the last word are a SHA-256 checksum of the
          entropy, which is why most random 12-word strings are not valid.

        Optional **BIP39 passphrase** (the "25th word") mixes into the seed.
        Same mnemonic + different passphrase = totally different wallet.
        Passphrases must be remembered separately; losing the passphrase
        means losing the wallet just like losing the mnemonic.
        """)
    elif topic.startswith("BIP32"):
        st.markdown("""
        ### BIP32 - HD wallets

        A **hierarchical deterministic** wallet derives a tree of keys from
        a single seed using `parent_key -> child_key` derivations. You can
        compute every address you will ever need from one 12/24-word
        backup, which is why losing a single BIP39 phrase can lose
        millions of addresses' worth of coins.

        Each level in the tree is either *normal* or *hardened* (denoted
        with a `'`). Hardened derivation prevents a leaked extended public
        key from being used to compute child private keys.
        """)
    elif topic.startswith("BIP44 / BIP49 / BIP84"):
        st.markdown("""
        ### Derivation paths

        Standard structure: `m / purpose' / coin_type' / account' / change / address_index`

        | Purpose | Address style                    | Path example                |
        |--------:|----------------------------------|-----------------------------|
        |    44'  | Legacy P2PKH (BTC) / EVM (ETH)   | `m/44'/0'/0'/0/0` (BTC)     |
        |    49'  | SegWit (P2SH-P2WPKH)             | `m/49'/0'/0'/0/0`           |
        |    84'  | Native SegWit (Bech32)           | `m/84'/0'/0'/0/0`           |

        Ethereum uses purpose 44 with `coin_type = 60'`:
        `m/44'/60'/0'/0/{index}`.

        **Common recovery confusion:** legacy vs. SegWit vs. native SegWit
        produce completely different addresses from the same mnemonic. If
        your wallet "shows zero balance", the first thing to test is
        whether you are looking at the wrong path family.
        """)
    elif topic.startswith("Air-gapped"):
        st.markdown("""
        ### Air-gapped recovery principles

        - Use a machine that has **never** been used for normal browsing.
        - Boot from a freshly-installed OS (a Linux live USB is a common
          choice).
        - Pull the network cable, disable Wi-Fi from BIOS if possible.
        - Install dependencies on a *different* machine, then move the
          project folder via USB.
        - When done, **wipe** the machine (full disk encryption + reboot
          is the minimum; physical destruction of the disk is the
          paranoid option).
        - Treat clipboards, swap files, and unallocated disk space as
          potential leakage channels.
        """)
    elif topic.startswith("Hardware"):
        st.markdown("""
        ### Hardware wallet security

        - Ledger / Trezor keep the private key inside a secure element and
          only ever sign transactions internally. The host computer
          receives signed bytes, not keys.
        - **Always** record the seed on the supplied backup card during
          initial setup. The device will never show it again.
        - Verify firmware authenticity via the vendor's official channel
          before initialising.
        - Consider a BIP39 passphrase for an extra layer.
        - For BIG holdings, look at multisig setups (e.g. Sparrow, Specter,
          Casa).
        """)
    elif topic.startswith("Scams"):
        st.markdown("""
        ### Scams, phishing, and red flags

        Things a legitimate tool will **never** ask you to do:

        - Enter your seed phrase into a website.
        - Send any test coins to a "verification" address.
        - Install a "wallet recovery" browser extension.
        - "Sync" your wallet with a remote server.

        If a "recovery service" promises to brute-force a forgotten seed
        for a percentage of recovered funds, assume it is a scam. Real
        forensic recovery work uses tools like the one you are reading
        right now: offline, on hardware **the wallet owner controls**.
        """)


# ---------------------------------------------------------------------------
# Page: Recovery problem selector (the guided front-door)
# ---------------------------------------------------------------------------

PROBLEMS = {
    "I have a seed but my wallet shows zero balance":            "zero_balance",
    "I have missing seed words":                                  "missing_words",
    "I have incorrect / misspelled seed words":                  "typos",
    "I think my word order is wrong":                            "wrong_order",
    "I may have used a BIP39 passphrase":                         "passphrase",
    "I have a corrupted backup (guided reconstruction)":         "corrupted",
    "I want to inspect a wallet file or MetaMask vault":         "vault",
}


def page_problem_selector() -> None:
    st.title("Recovery workflow")
    if not _disclaimer_gate():
        return
    _ethical_banner()

    st.markdown("**What problem are you trying to solve?**")
    chosen = st.radio(
        "Problem type",
        list(PROBLEMS.keys()),
        label_visibility="collapsed",
        key="_problem_radio",
    )
    st.divider()
    workflow = PROBLEMS[chosen]
    if workflow == "zero_balance":
        wf_zero_balance()
    elif workflow == "missing_words":
        wf_missing_words()
    elif workflow == "typos":
        wf_typos()
    elif workflow == "wrong_order":
        wf_wrong_order()
    elif workflow == "passphrase":
        wf_passphrase()
    elif workflow == "corrupted":
        wf_corrupted()
    elif workflow == "vault":
        wf_vault()


# --- workflow: zero balance --------------------------------------------------

def wf_zero_balance() -> None:
    st.subheader("Wallet shows zero balance after recovery")
    st.markdown(
        "Most 'zero-balance' cases are actually **wrong derivation path** "
        "or **wrong wallet software**. This workflow scans every standard "
        "path family for the first N addresses and (optionally) tries to "
        "match a known public address you remember."
    )

    mnemonic = _mnemonic_input(key="zb_mnemonic")
    target = _target_address_input(key="zb_target")
    count = st.number_input(
        "Addresses per standard to scan", 1, MAX_ADDRESSES_PER_REQUEST, 5, key="zb_count"
    )

    if st.button("Run scan", type="primary", key="zb_btn"):
        if not mnemonic.strip():
            st.error("Please enter a mnemonic.")
            return
        try:
            if target.strip():
                result = find_address_match(
                    mnemonic, target.strip(),
                    max_addresses_per_standard=int(count),
                )
                if result["match"]:
                    st.success(
                        f"Match found at **{result['match']['path']}** "
                        f"({result['match']['address_type']})."
                    )
                else:
                    st.warning(
                        f"No match in {result['searched']} candidates. Try a "
                        "larger scan range, double-check the address you "
                        "pasted, or check if a passphrase was used."
                    )
                rows = result["candidates"]
            else:
                rows = compare_all_standards(mnemonic, count=int(count))
        except ValueError as e:
            st.error(str(e))
            return

        _add_results(rows)
        _show_addresses_table(rows)


# --- workflow: missing words -------------------------------------------------

def wf_missing_words() -> None:
    st.subheader("Recover missing seed words")
    st.markdown(
        f"Use `?` for each unknown word. The engine tries every word from "
        f"the official BIP39 wordlist in each slot and keeps only the "
        f"checksum-valid candidates. **Hard cap: {MAX_MISSING_WORDS} unknown "
        f"slots** (with 2 missing words there can be up to ~4.2 million "
        f"trials, which already takes a noticeable amount of time)."
    )

    masked = _mnemonic_input(
        key="mw_masked",
        label="Mnemonic with `?` for unknown words",
    )
    target = _target_address_input(key="mw_target")
    max_unk = st.slider("Max unknowns to allow", 1, MAX_MISSING_WORDS, 1, key="mw_max")

    if st.button("Recover", type="primary", key="mw_btn"):
        if not masked.strip():
            st.error("Please enter a masked mnemonic.")
            return
        try:
            with st.spinner("Searching the BIP39 wordlist..."):
                res = recover_missing_words(
                    masked,
                    target_address=target.strip() or None,
                    max_unknowns=int(max_unk),
                )
        except ValueError as e:
            st.error(str(e))
            return

        st.success(
            f"Checked **{res['checked']:,}** combinations. "
            f"Found **{len(res['candidates'])}** valid candidate(s)"
            + ("" if not res.get("truncated") else " (list truncated to 100).")
        )
        if res["candidates"]:
            st.warning(
                "Candidate mnemonics are shown below. **Write the correct "
                "one down on paper, then use Clear Session.** They are NOT "
                "exported to reports."
            )
            for i, cand in enumerate(res["candidates"], 1):
                st.code(cand, language="text")


# --- workflow: typos ---------------------------------------------------------

def wf_typos() -> None:
    st.subheader("Typo correction")
    st.markdown(
        "For each word that is not in the official BIP39 English wordlist, "
        "the lab suggests the closest valid words by Levenshtein distance. "
        "After picking corrections, you can re-validate the mnemonic."
    )
    mnemonic = _mnemonic_input(key="ty_mnemonic")
    n_sugg = st.slider("Suggestions per unknown word", 1, 10, 5, key="ty_n")

    if st.button("Suggest corrections", type="primary", key="ty_btn"):
        if not mnemonic.strip():
            st.error("Please enter a mnemonic.")
            return
        res = suggest_typo_corrections(mnemonic, max_suggestions=int(n_sugg))
        if res["all_words_known"]:
            st.success("Every word is already in the BIP39 wordlist.")
            info = validate_mnemonic(mnemonic)
            st.write({k: v for k, v in info.items()})
            return
        for entry in res["unknown_words"]:
            st.markdown(
                f"- **Position {entry['position'] + 1}**: unknown word "
                f"`{entry['word']}` -> suggestions: "
                f"`{', '.join(entry['suggestions'])}`"
            )


# --- workflow: wrong word order ---------------------------------------------

def wf_wrong_order() -> None:
    st.subheader("Word-order recovery")
    st.markdown(
        f"For when **all the words are correct but the order is uncertain**. "
        f"Capped at **{MAX_ORDER_POSITIONS}** positions ({MAX_ORDER_POSITIONS}! "
        f"= 40,320 permutations is the absolute ceiling). If you have a known "
        f"address, paste it - it will narrow the candidate list to the right "
        f"order."
    )
    raw = st.text_area(
        f"Up to {MAX_ORDER_POSITIONS} BIP39 words (space-separated)",
        key="wo_raw",
        height=80,
    )
    target = _target_address_input(key="wo_target")

    if st.button("Search permutations", type="primary", key="wo_btn"):
        words = raw.lower().split()
        if not words:
            st.error("Please enter the words.")
            return
        try:
            with st.spinner("Trying permutations..."):
                res = recover_word_order(
                    words,
                    target_address=target.strip() or None,
                    max_positions=MAX_ORDER_POSITIONS,
                )
        except ValueError as e:
            st.error(str(e))
            return
        st.success(
            f"Checked **{res['checked']:,}** permutations. Found "
            f"**{len(res['candidates'])}** valid candidate(s)."
        )
        for cand in res["candidates"]:
            st.code(cand, language="text")


# --- workflow: passphrase ----------------------------------------------------

def wf_passphrase() -> None:
    st.subheader("BIP39 passphrase tester")
    st.markdown(
        "If you may have set a BIP39 passphrase (the 25th word), the same "
        "mnemonic will produce **different** addresses depending on it. "
        "Paste the mnemonic and a candidate passphrase; the lab will derive "
        "the first few addresses across every standard path. Compare them "
        "to one you remember to confirm. **Passphrases are not saved.**"
    )
    mnemonic = _mnemonic_input(key="pp_mnemonic")
    passphrase = _passphrase_input(key="pp_passphrase")
    target = _target_address_input(key="pp_target")
    count = st.slider("Addresses per standard", 1, 20, 5, key="pp_count")

    if st.button("Derive with passphrase", type="primary", key="pp_btn"):
        if not mnemonic.strip():
            st.error("Please enter a mnemonic.")
            return
        try:
            res = test_passphrase(
                mnemonic, passphrase,
                target_address=target.strip() or None,
                count=int(count),
            )
        except ValueError as e:
            st.error(str(e))
            return
        if res.get("match"):
            st.success(
                f"Match at **{res['match']['path']}** "
                f"({res['match']['address_type']}) - this passphrase looks "
                "correct."
            )
        else:
            st.info(
                "No match against the target address (or no target given). "
                "Compare the derived addresses below to one you remember."
            )
        _add_results(res["addresses"])
        _show_addresses_table(res["addresses"])


# --- workflow: corrupted backup ---------------------------------------------

def wf_corrupted() -> None:
    st.subheader("Corrupted-backup guided reconstruction")
    st.markdown(
        "Use this as a checklist. As you reconstruct each word, record it "
        "in the notes field and re-validate. When all words look right but "
        "the checksum still fails, try the **Word-order recovery** workflow."
    )
    st.markdown(
        """
        **Checklist:**

        1. Photograph or write down whatever IS readable, exactly as it is.
        2. For each illegible word, note 1-3 plausible interpretations.
        3. Run **Typo correction** on each guess - the wordlist is small
           and most "looks like X" errors snap to a single neighbour.
        4. If exactly 1 or 2 words remain unknown, use **Missing-word
           recovery** with `?` placeholders.
        5. If all words look readable but the checksum fails, try
           **Word-order recovery** - some backups list the words in a
           grid that can be read top-down vs. left-right.
        6. If you have a known public address from this wallet, paste it
           into any workflow above to narrow the answer to one candidate.
        """
    )
    st.text_area(
        "Reconstruction notes (kept locally in this session only)",
        key=NOTES_KEY,
        height=160,
        help="Whatever you type here is included in the recovery report. "
             "**Do not write the actual seed phrase into this field** - the "
             "report is designed to never contain secrets.",
    )


# --- workflow: vault inspection ---------------------------------------------

def wf_vault() -> None:
    st.subheader("Wallet file metadata inspector")
    st.markdown(
        "Parses MetaMask vault JSON and identifies common wallet file "
        "formats. **Metadata only:** no decryption, no password trial, no "
        "private keys are extracted. Use this to confirm a backup file is "
        "of the kind you think it is."
    )

    tab1, tab2 = st.tabs(["MetaMask vault JSON", "Identify any wallet file"])

    with tab1:
        vault = st.text_area(
            "Paste the vault JSON (raw or wrapped)",
            key="vault_text",
            height=180,
            placeholder='{"data": "...", "iv": "...", "salt": "...", '
                         '"keyMetadata": {"algorithm": "PBKDF2", "params": '
                         '{"iterations": 600000}}}',
        )
        if st.button("Inspect vault", type="primary", key="vault_btn"):
            if not vault.strip():
                st.error("Paste the vault JSON above.")
            else:
                try:
                    res = inspect_metamask_vault(vault)
                    st.json(res)
                except ValueError as e:
                    st.error(str(e))

    with tab2:
        f = st.file_uploader(
            "Wallet file (any format)",
            key="vault_upload",
            help="The file is read in memory only. It is not copied anywhere.",
        )
        if f is not None:
            data = f.read()
            try:
                res = identify_wallet_file(data, filename=f.name)
                st.json(res)
                if res.get("contains_secrets_warning"):
                    st.error(
                        "This file type typically holds RAW secrets. "
                        "Treat the original file with great care; do not "
                        "share it, do not upload it anywhere."
                    )
            except Exception as e:
                st.error(f"Could not parse file: {e}")


# ---------------------------------------------------------------------------
# Page: Tools (direct-access power-user panels)
# ---------------------------------------------------------------------------

def page_tools() -> None:
    st.title("Tools")
    if not _disclaimer_gate():
        return
    tab1, tab2, tab3 = st.tabs(["BIP39 validator", "Address generator", "Arbitrary path"])

    with tab1:
        m = _mnemonic_input(key="tool_validate_m")
        if st.button("Validate", key="tool_validate_btn"):
            if not m.strip():
                st.error("Please enter a mnemonic.")
            else:
                r = validate_mnemonic(m)
                c1, c2 = st.columns(2)
                c1.metric("Word count", r["word_count"])
                c2.metric("Overall", "Valid" if r["valid"] else "Invalid")
                for label, ok in [
                    ("Word count is 12 / 15 / 18 / 21 / 24", r["word_count_valid"]),
                    ("All words are in the BIP39 English wordlist", r["words_in_wordlist"]),
                    ("Checksum verifies", r["checksum_valid"]),
                ]:
                    (st.success if ok else st.error)(
                        f"{'OK' if ok else 'FAIL'} - {label}"
                    )

    with tab2:
        m = _mnemonic_input(key="tool_gen_m")
        coin = st.radio("Coin", ["ETH", "BTC"], horizontal=True, key="tool_gen_coin")
        btc_type = None
        if coin == "BTC":
            btc_type = st.selectbox(
                "Bitcoin address type",
                list(BTC_ADDRESS_TYPES.keys()),
                format_func=lambda k: BTC_ADDRESS_TYPES[k]["label"],
                index=2,
                key="tool_gen_btc_type",
            )
        count = st.slider("Number of addresses", 1, MAX_ADDRESSES_PER_REQUEST, 5,
                          key="tool_gen_count")
        if st.button("Generate", type="primary", key="tool_gen_btn"):
            if not m.strip():
                st.error("Please enter a mnemonic.")
            else:
                try:
                    if coin == "ETH":
                        rows = derive_eth_addresses(m, int(count))
                    else:
                        rows = derive_btc_addresses(m, btc_type, int(count))
                    _add_results(rows)
                    _show_addresses_table(rows)
                except ValueError as e:
                    st.error(str(e))

    with tab3:
        st.markdown(
            "Derive a single address at an arbitrary BIP32 path. Useful for "
            "non-standard wallets (Electrum, Exodus quirks, custom paths)."
        )
        m = _mnemonic_input(key="tool_arb_m")
        path = st.text_input("BIP32 path", "m/44'/60'/0'/0/0", key="tool_arb_path")
        coin = st.radio("Coin", ["ETH", "BTC"], horizontal=True, key="tool_arb_coin")
        btc_type = "native_segwit"
        if coin == "BTC":
            btc_type = st.selectbox(
                "Bitcoin address type",
                list(BTC_ADDRESS_TYPES.keys()),
                format_func=lambda k: BTC_ADDRESS_TYPES[k]["label"],
                index=2,
                key="tool_arb_btc_type",
            )
        if st.button("Derive single address", type="primary", key="tool_arb_btn"):
            if not m.strip():
                st.error("Please enter a mnemonic.")
            else:
                try:
                    row = derive_arbitrary_path(m, path, coin, btc_type)
                    _add_results([row])
                    _show_addresses_table([row])
                except ValueError as e:
                    st.error(str(e))


# ---------------------------------------------------------------------------
# Page: Recovery report
# ---------------------------------------------------------------------------

def page_report() -> None:
    st.title("Recovery report")
    if not _disclaimer_gate():
        return

    rows = st.session_state.get(RESULTS_KEY, [])
    if not rows:
        st.info("No addresses generated yet. Run a recovery workflow first.")
        return

    st.markdown(
        f"**{len(rows)}** public address(es) derived in this session. "
        "Reports include only the timestamp, derivation paths, address types, "
        "and public addresses. Seeds, private keys, raw seed bytes, entropy, "
        "and passphrases are **never** written to disk."
    )
    _show_addresses_table(rows)

    st.text_area(
        "Recovery notes (free text - included in the report)",
        key=NOTES_KEY,
        height=120,
        help="Do not paste your seed phrase here. The report sanitiser does "
             "not inspect free-text notes.",
    )
    notes = st.session_state.get(NOTES_KEY, "")

    txt = build_txt_report(rows, notes=notes)
    csv = build_csv_report(rows, notes=notes)
    try:
        pdf = build_pdf_report(rows, notes=notes)
    except Exception as e:
        pdf = None
        st.error(f"PDF generation failed: {e}")

    c1, c2, c3 = st.columns(3)
    c1.download_button(
        "Download TXT", data=txt,
        file_name="wallet_recovery_report.txt", mime="text/plain",
    )
    c2.download_button(
        "Download CSV", data=csv,
        file_name="wallet_recovery_report.csv", mime="text/csv",
    )
    if pdf is not None:
        c3.download_button(
            "Download PDF", data=pdf,
            file_name="wallet_recovery_report.pdf", mime="application/pdf",
        )

    st.divider()
    st.subheader("QR code for a single public address")
    addr_options = [r["address"] for r in rows]
    target = st.selectbox(
        "Pick an address", addr_options, key="qr_pick",
    )
    if target:
        try:
            png = build_qr_png(target)
            st.image(png, caption=target, width=240)
            st.download_button(
                "Download QR (PNG)", data=png,
                file_name=f"address_{target[:10]}.png",
                mime="image/png",
            )
        except Exception as e:
            st.error(f"QR generation failed: {e}")

    with st.expander("Preview TXT report"):
        st.code(txt, language="text")


# ---------------------------------------------------------------------------
# Page: Clear session
# ---------------------------------------------------------------------------

def page_clear() -> None:
    st.title("Clear session")
    st.markdown(
        "Wipes every Streamlit session-state key, including the contents of "
        "every text input on every page. Use this before walking away from "
        "the machine, and again before closing the browser tab."
    )
    if st.button("Clear everything now", type="primary"):
        _clear_session()
        st.success("Session cleared.")
        st.rerun()


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

PAGES = {
    "Home (read first)":       page_home,
    "Recovery workflow":       page_problem_selector,
    "Tools":                   page_tools,
    "Educational lab":         page_education,
    "Recovery report":         page_report,
    "Clear session":           page_clear,
}


def main() -> None:
    _init_state()
    with st.sidebar:
        st.header("Offline Wallet Recovery Lab")
        choice = st.radio(
            "Navigation", list(PAGES.keys()), label_visibility="collapsed",
        )
        st.divider()
        st.caption("Offline only. Verify your machine is disconnected.")
        n = len(st.session_state.get(RESULTS_KEY, []))
        if n:
            st.caption(f"{n} derived address(es) in this session.")
    PAGES[choice]()


if __name__ == "__main__":
    main()
