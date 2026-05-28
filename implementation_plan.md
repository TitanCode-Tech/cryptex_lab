# Offline Wallet Recovery Lab — Implementation Plan

Rebuild the existing Cryptex Lab into a professional offline blockchain forensic workstation with dual-mode architecture (OFFLINE SAFE / LIVE ANALYSIS), CRYPTEX v2-inspired UI, and modular backend.

## Proposed Changes

### Architecture Restructure

The existing flat file layout will be reorganized into a clean package structure while preserving working code. Rather than creating a deep nested package that would complicate Streamlit imports, we'll keep the flat layout but add new files and restructure [app.py](file:///home/jabs/Code/cryptex-lab/app.py) significantly.

> [!IMPORTANT]
> The existing backend utilities ([wallet_utils.py](file:///home/jabs/Code/cryptex-lab/wallet_utils.py), [recovery_utils.py](file:///home/jabs/Code/cryptex-lab/recovery_utils.py), [derivation_utils.py](file:///home/jabs/Code/cryptex-lab/derivation_utils.py), [forensic_utils.py](file:///home/jabs/Code/cryptex-lab/forensic_utils.py), [export_utils.py](file:///home/jabs/Code/cryptex-lab/export_utils.py)) are well-written and fully functional. We will **extend** them rather than rewrite, adding new modules alongside.

---

#### [NEW] [modes.py](file:///home/jabs/Code/cryptex-lab/modes.py)
Global mode management: `OFFLINE_SAFE` and `LIVE_ANALYSIS` constants, session-state helpers to get/set current mode, decorator `@require_offline` that blocks execution when live mode is active on sensitive functions.

#### [NEW] [security_utils.py](file:///home/jabs/Code/cryptex-lab/security_utils.py)
- Network guard: runtime check that `requests`/`httpx`/`aiohttp`/`web3`/`urllib.request` are not imported in offline modules
- Session wipe utility
- Import auditing function for test use

#### [NEW] [hash_utils.py](file:///home/jabs/Code/cryptex-lab/hash_utils.py)
Offline hash/crypto tools using `hashlib` and `pycryptodome`:
- SHA-256, SHA-512, SHA-1, MD5, RIPEMD-160, HASH160, double-SHA256
- Hex/Base64/Base58 encoding/decoding
- Unit converter (BTC ↔ satoshi)

#### [NEW] [entropy_utils.py](file:///home/jabs/Code/cryptex-lab/entropy_utils.py)
Entropy analysis using only stdlib `math`/`collections`:
- Shannon entropy calculator
- Byte frequency distribution
- Chi-square test for uniformity
- Runs test
- Overall quality score with PASS/WEAK/FAIL verdict

#### [NEW] [case_utils.py](file:///home/jabs/Code/cryptex-lab/case_utils.py)
In-memory case management (session-state only, never persisted):
- Create case with ID, type, chain, priority, analyst, notes
- Case registry with timestamp
- Evidence hash checker (SHA-256 of uploaded file bytes)

#### [NEW] [live_utils.py](file:///home/jabs/Code/cryptex-lab/live_utils.py)
Live-mode-only public blockchain lookups using `requests`:
- BTC address balance via Blockstream API
- BTC TX lookup via Blockstream API
- Mempool fee estimates via mempool.space API
- ETH address balance via public Etherscan-compatible API
- Guard: refuses to run if mode is OFFLINE_SAFE
- Guard: refuses any input that looks like a seed/private key

---

#### [MODIFY] [app.py](file:///home/jabs/Code/cryptex-lab/app.py)
Complete frontend overhaul:
- CRYPTEX v2-inspired dark cyber forensic CSS (scanlines, grid overlay, monospace fonts, glow effects)
- Sidebar navigation with categorized sections (FORENSICS, RECOVERY TOOLS, ANALYSIS, SECURITY, EXPORT)
- Global mode toggle: OFFLINE SAFE MODE / LIVE PUBLIC ANALYSIS MODE
- Terminal-style activity log component
- Status cards with metrics
- All 18+ module pages as separate functions
- Mode-aware page rendering (live pages locked in offline mode, sensitive pages locked in live mode)

#### [MODIFY] [requirements.txt](file:///home/jabs/Code/cryptex-lab/requirements.txt)
Add `requests` for live analysis mode (lazy-imported only in live modules).

---

### New Pages in app.py

| # | Page | Mode | Source |
|---|------|------|--------|
| 1 | Security Landing | Both | New |
| 2 | Recovery Problem Selector | Offline | Existing, enhanced |
| 3 | Case Management | Both | New (`case_utils.py`) |
| 4 | Evidence Hash Checker | Both | New (`case_utils.py`) |
| 5 | BIP39 Validation Lab | Offline | Existing, restyled |
| 6 | Incomplete Seed Recovery | Offline | Existing, restyled |
| 7 | Typo Correction Lab | Offline | Existing, restyled |
| 8 | Wrong Word Order Helper | Offline | Existing, restyled |
| 9 | BIP39 Passphrase Testing | Offline | Existing, restyled |
| 10 | Derivation Path Scanner | Offline | Existing, restyled |
| 11 | Known Address Matcher | Offline | Existing, restyled |
| 12 | ETH/BTC Address Generator | Offline | Existing, restyled |
| 13 | Entropy Analysis Lab | Offline | New (`entropy_utils.py`) |
| 14 | Hash/Crypto Tools | Both | New (`hash_utils.py`) |
| 15 | MetaMask Vault Inspector | Offline | Existing, restyled |
| 16 | Air-Gapped Ops Guide | Both | New (static content) |
| 17 | Recovery Report Exporter | Both | Existing, enhanced |
| 18 | Educational Lab | Both | Existing, enhanced |
| 19 | Live Address Lookup | Live only | New (`live_utils.py`) |
| 20 | Live TX Lookup | Live only | New (`live_utils.py`) |
| 21 | Clear Session | Both | Existing |

---

### Documentation

#### [NEW] [SECURITY.md](file:///home/jabs/Code/cryptex-lab/SECURITY.md)
Comprehensive security policy: no-network guarantee, no-secret-persistence, export whitelist, mode isolation rules, audit instructions.

#### [MODIFY] [README.md](file:///home/jabs/Code/cryptex-lab/README.md)
Updated for new architecture, dual-mode feature, module list, installation, usage.

#### [NEW] [demo_data.py](file:///home/jabs/Code/cryptex-lab/demo_data.py)
Safe sample data: well-known BIP39 test vector, sample public addresses, sample case data — all from published test vectors only.

---

### Tests

#### [NEW] [tests/test_entropy_utils.py](file:///home/jabs/Code/cryptex-lab/tests/test_entropy_utils.py)
- Shannon entropy of known sequences (all zeros vs random)
- Chi-square test validation
- Quality verdict thresholds

#### [NEW] [tests/test_hash_utils.py](file:///home/jabs/Code/cryptex-lab/tests/test_hash_utils.py)
- Known SHA-256/SHA-512/MD5 vectors
- HASH160 and double-SHA256
- Encoding round-trips

#### [NEW] [tests/test_case_utils.py](file:///home/jabs/Code/cryptex-lab/tests/test_case_utils.py)
- Case creation, listing
- Evidence hash computation

#### [NEW] [tests/test_security_utils.py](file:///home/jabs/Code/cryptex-lab/tests/test_security_utils.py)
- No-network audit passes for offline modules
- No-network audit catches banned imports
- Mode guard decorator behavior

#### [MODIFY] [tests/test_wallet_utils.py](file:///home/jabs/Code/cryptex-lab/tests/test_wallet_utils.py)
No changes needed — existing tests pass.

#### [MODIFY] [tests/test_recovery_utils.py](file:///home/jabs/Code/cryptex-lab/tests/test_recovery_utils.py)
No changes needed — existing tests pass.

---

## Verification Plan

### Automated Tests

Run the full test suite:
```bash
cd /home/jabs/Code/cryptex-lab && python -m pytest tests/ -v
```

The existing 4 test files cover:
- Mnemonic validation (valid/invalid/edge cases)
- ETH/BTC address derivation against known vectors
- Missing word recovery
- Typo suggestion
- Word order recovery
- Passphrase testing
- Report export (whitelist enforcement, forbidden field rejection)
- Forensic file identification
- No-secrets-leak audit

New tests will add:
- Entropy analysis correctness
- Hash tool correctness
- Case management CRUD
- Security guard / no-network enforcement

### Manual Verification

1. **Launch the app**: `cd /home/jabs/Code/cryptex-lab && streamlit run app.py`
2. **Verify UI**: Dark cyber forensic aesthetic, sidebar with all modules, mode toggle
3. **Test mode switch**: Toggle between OFFLINE and LIVE modes, verify corresponding pages lock/unlock
4. **Test BIP39 validator**: Use test vector `abandon abandon ... about` — should show VALID
5. **Test address generator**: Generate ETH addresses from test vector — should show `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` as first address
6. **Test export**: Download TXT/CSV report — verify no secrets in output
7. **Test clear session**: Verify all state wiped

### Security Audit (automated)
```bash
cd /home/jabs/Code/cryptex-lab && grep -rn "import requests\|import httpx\|import aiohttp\|from web3\|import urllib.request\|import socket" --include="*.py" --exclude="live_utils.py" --exclude="test_*"
```
Should return zero matches in any file except `live_utils.py`.
