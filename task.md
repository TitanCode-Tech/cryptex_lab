# Cryptex Lab — Rebuild Task Log

State as of 2026-05-28. The implementation is largely landed. The
file is the running checklist; see `implementation_plan.md` for the
design rationale and `SECURITY.md` for the security model.

## Phase 1: Architecture & Project Restructure
- [~] ~~Restructure into `offline_wallet_lab/` package layout with subpackages~~ — **superseded.** A flat-file layout was chosen for Streamlit import simplicity (the original deep nested layout would have complicated `streamlit run`). All modules sit at the project root.
- [x] `modes.py` — global mode switch (OFFLINE SAFE / LIVE ANALYSIS) with `init_mode`, `get_current_mode`, `set_mode`, `is_offline`, `is_live`, `@require_offline`, `@require_live`.
- [x] `security_utils.py` — `BANNED_NETWORK_MODULES` set, `audit_sys_modules`, `wipe_session_state`. Network-guard role split between this module and the `@require_offline` / `@require_live` decorators in `modes.py`.

## Phase 2: Backend Modules
- [x] `wallet_utils.py` — BIP39 validation, ETH/BTC derivation, `BTC_ADDRESS_TYPES`.
- [x] `recovery_utils.py` — `recover_missing_words`, `suggest_typo_corrections`, `recover_word_order`, `test_passphrase`.
- [x] `derivation_utils.py` — `scan_standard_paths`, `compare_all_standards`, `derive_arbitrary_path`, `find_address_match`.
- [x] `entropy_utils.py` — `analyze_entropy` returning Shannon entropy, chi-square, runs test, byte frequency, quality verdict.
- [x] `case_utils.py` — in-memory case CRUD, evidence hashing.
- [x] `forensic_utils.py` — `inspect_metamask_vault`, `identify_wallet_file` (metadata only).
- [x] `live_utils.py` — `lookup_btc_address`, `lookup_btc_transaction`, `get_mempool_fees`, `lookup_eth_address`. Guarded by `@require_live`.
- [x] `hash_utils.py` — SHA-256/512/1, MD5, RIPEMD-160, HASH160, double-SHA256, hex/base58/base64 codecs, BTC and ETH unit converters.
- [x] `export_utils.py` — `build_txt_report`, `build_csv_report`, `build_pdf_report`, `build_qr_png`, `build_report` aggregator. Whitelist enforced via `safe_record`.

## Phase 3: Streamlit Frontend Overhaul
- [x] Rewrite `app.py` with CRYPTEX v2 dark cyber UI (CSS port, Orbitron / Rajdhani / Share Tech Mono fonts, scanlines, grid overlay, themed widgets).
- [x] Sidebar navigation grouped by category (FORENSICS / RECOVERY / FORENSIC & VALIDATION / LIVE / UTILITIES).
- [x] Global mode switch with green/red colour coding and explicit OFFLINE/LIVE badge.
- [x] Helper components: section header, box (head + body), status cards, terminal log panel, result blocks, active-case banner, data tables.
- [x] Security Landing page.
- [x] Recovery Problem Selector page.
- [x] Case Management page.
- [x] Evidence Hash Checker page.
- [x] BIP39 Validation Lab page.
- [x] Incomplete Seed Recovery page.
- [x] Typo Correction Lab page.
- [x] Wrong Word Order Helper page.
- [x] BIP39 Passphrase Testing page.
- [x] Derivation Path Scanner page.
- [x] Known Address Matcher page.
- [x] ETH/BTC Public Address Generator page.
- [x] Entropy Analysis Lab page.
- [x] Hash/Crypto Tools page.
- [x] MetaMask Vault Inspector page.
- [x] Air-Gapped Operations Guide page.
- [x] Recovery Report Exporter page (TXT / CSV / PDF / QR PNG via `st.download_button`).
- [x] Educational Lab page.
- [x] Live Address Lookup page.
- [x] Live TX Lookup page.
- [x] Clear Session page.
- [x] Terminal-style activity log component (`render_terminal` + `log_event`).
- [x] Status cards and modular tool panels.
- [ ] Manual visual verification of every page in a browser session.

## Phase 4: Testing
- [x] Existing tests migrated where signatures changed (none required — backend signatures preserved).
- [x] `tests/test_entropy_utils.py` — Shannon entropy and quality verdict.
- [x] `tests/test_case_utils.py` — case CRUD and evidence hashing.
- [x] `tests/test_modes.py` — mode toggle and guard decorators.
- [x] Existing `test_wallet_utils.py`, `test_recovery_utils.py`, `test_export_utils.py`, `test_forensic_utils.py` still pass.
- [ ] `tests/test_security_utils.py` — no-network audit catches banned imports (smoke-covered by `test_modes.py`; dedicated file still pending).
- [ ] `tests/test_hash_utils.py` — known SHA / RIPEMD vectors and codec round-trips.
- [x] Full suite green (`pytest tests/ -q` → 102 passed).

## Phase 5: Documentation & Security
- [x] `requirements.txt` updated with `requests` for live mode.
- [x] `SECURITY.md` written (threat model, no-network guarantee, no-secret-persistence, export whitelist, mode isolation, audit instructions, responsible disclosure).
- [x] `demo_data.py` created with public BIP39 test vectors only.
- [ ] `README.md` — refresh for dual-mode architecture and the new module list (existing README still references the v2 architecture).
- [x] Audit grep for banned imports in offline modules — clean except `live_utils.py`.
