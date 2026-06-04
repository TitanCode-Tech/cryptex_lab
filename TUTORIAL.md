# CRYPTEX LAB Tutorial Guide

This guide explains how to use the `cryptex-lab` packages from both the client and developer perspectives. It includes package contents, installation, UI screens, example workflows, and code examples for direct import usage.

> This project is built for ethical wallet recovery and forensic analysis. Only use it on wallets you own or are explicitly authorized to recover.

## 1. Package Overview

### Client package

The client package is the safe runtime distribution for end-users. It contains the Streamlit app and all offline recovery, derivation, forensic, entropy, hash, export, and mode-management modules.

Core client files:

- `app.py`
- `modes.py`
- `security_utils.py`
- `wallet_utils.py`
- `recovery_utils.py`
- `derivation_utils.py`
- `entropy_utils.py`
- `case_utils.py`
- `forensic_utils.py`
- `live_utils.py`
- `hash_utils.py`
- `export_utils.py`
- `demo_data.py`
- `launcher.py`
- `install.py` / `install.sh` / `install.bat`
- `update.py` / `update.sh` / `update.bat`
- `uninstall.py` / `uninstall.sh` / `uninstall.bat`
- `requirements.txt`
- `README.md`, `SECURITY.md`
- `.streamlit/config.toml`

### Developer package

The developer package builds on the client package and additionally includes files needed for development, packaging, testing, and signing.

Developer-only files:

- `package.py` — creates client and developer ZIP packages
- `generate_keys.py` — generates RSA keys, license.json, and manifest.json
- `private_key.pem` — developer-only private signing key
- `implementation_plan.md` — design rationale and implementation notes
- `task.md` — current checklist and completion status
- `tests/` — pytest suite for the lab
- `.gitignore`

Developer package is intended for internal build, validation, and extension work.

## 2. Client usage: install and launch

### Offline-first installation

The client package is designed to run locally as a desktop-style application.

#### Linux / macOS

```bash
git clone <repo-url>
cd cryptex-lab
./install.sh
```

#### Windows

```cmd
install.bat
```

This creates a Python virtual environment, installs pinned dependencies, and creates a desktop/start-menu shortcut that launches `launcher.py`.

### Run manually

```bash
python launcher.py
```

Or with Streamlit directly:

```bash
source venv/bin/activate   # Windows: venv\Scripts\activate
streamlit run app.py
```

### Live mode vs offline safe mode

- `OFFLINE_SAFE` is the default mode. All recovery, validation, vault inspection, entropy analysis, and report/export pages are available.
- `LIVE_ANALYSIS` is opt-in. It enables public blockchain lookups and locks sensitive pages to avoid combining secrets with network access.

The mode guard lives in `modes.py` and is enforced across the UI and network code.

## 3. Client screens and workflows

The main app is organized as Streamlit pages in the sidebar. Each page is a screen with a specific purpose.

### 3.1 Security Landing

This is the first screen the user sees. It emphasizes the offline safety model, shows the current mode, and asks the user to confirm they understand the disclaimer.

### 3.2 Recovery Problem Selector

This screen helps the user choose the right recovery path:

- Missing seed words
- Typo correction
- Wrong word order
- Passphrase testing
- Known address / derivation path matching

It routes to the appropriate engine in `recovery_utils.py` or `derivation_utils.py`.

### 3.3 Case Management

This screen uses `case_utils.py` to create and manage in-memory cases:

- Create a new case with name, investigator, chain, and description.
- Switch active cases.
- Review saved evidence metadata.

### 3.4 Evidence Hash Checker

Use this screen to hash evidence files using `calculate_evidence_hash()`.

- The tool computes MD5, SHA-1, and SHA-256 hashes.
- It stores only metadata and hashes in memory, never the raw file contents.

### 3.5 BIP39 Validation Lab

Validates any BIP39 mnemonic using `wallet_utils.validate_mnemonic()`.

It reports:

- word count validity
- all words present in the BIP39 English list
- checksum validity
- overall validity

### 3.6 Incomplete Seed Recovery

This screen is powered by `recovery_utils.recover_missing_words()`.

How it works:

- The user enters a partial mnemonic using `?` placeholders for missing words.
- The engine validates candidates and returns only checksum-valid guesses.
- Maximum supported unknown word count is 2.

Example input:

```text
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?
```

### 3.7 Typo Correction Lab

This screen uses `recovery_utils.suggest_typo_corrections()` to find BIP39 words one edit away from an invalid token.

Typical use:

- enter a mnemonic with a misspelled word
- receive suggestions for the closest valid BIP39 words

### 3.8 Wrong Word Order Helper

This screen helps reorder a corrupted mnemonic using `recovery_utils.recover_word_order()`.

Workflow:

- the user marks the words that may be out of order
- the engine permutes the marked positions
- checksum-valid results are returned

Limit: up to 8 positions for interactive performance.

### 3.9 BIP39 Passphrase Testing

This screen tests a mnemonic against candidate passphrases using `recovery_utils.test_passphrase()`.

It shows whether wallet-derived addresses change with each passphrase and whether the mnemonic remains valid.

### 3.10 Derivation Path Scanner

This screen calls functions in `derivation_utils.py`:

- `scan_standard_paths()` to derive ETH and BTC addresses from common BIP44/BIP49/BIP84 paths
- `compare_all_standards()` to generate a full cross-standard address matrix

Example output:

- ETH `m/44'/60'/0'/0/0`
- BTC legacy `m/44'/0'/0'/0/0`
- BTC segwit `m/49'/0'/0'/0/0`
- BTC native SegWit `m/84'/0'/0'/0/0`

### 3.11 Known Address Matcher

This screen uses `derivation_utils.find_address_match()` to search for a provided address across the first window of standard paths.

It is useful when a user has a known public address and wants to identify which standard path produced it.

### 3.12 ETH/BTC Address Generator

From `wallet_utils.py`, this screen derives public addresses from a valid mnemonic:

- Ethereum addresses using BIP44
- Bitcoin Legacy / SegWit / Native SegWit addresses

Example flow:

- paste a valid mnemonic
- choose `BTC` or `ETH`
- choose an address type (BTC only)
- generate the first N public addresses

### 3.13 Entropy Analysis Lab

This screen uses `entropy_utils.analyze_entropy()` to inspect binary data or files.

It reports:

- Shannon entropy
- chi-square statistic
- number of unique bytes
- qualitative quality: `HIGH`, `MODERATE`, `LOW`, or `POOR`

### 3.14 MetaMask Vault Inspector

This screen analyzes MetaMask vault JSON using `forensic_utils.inspect_metamask_vault()`.

It returns:

- vault format identification
- KDF type and parameters
- ciphertext length and fingerprint
- notes about the data structure

This is metadata-only inspection. It does not decrypt or try passwords.

### 3.15 Live Address Lookup / Live TX Lookup

When `LIVE_ANALYSIS` mode is enabled, this screen uses `live_utils.py` to query public blockchain APIs:

- BTC address stats via Blockstream
- BTC transaction details via Blockstream
- ETH balance via Etherscan
- mempool fee estimates via mempool.space

These lookups are intentionally gated behind `@require_live` and only run when the user explicitly selects live mode.

### 3.16 Hash/Crypto Tools

This screen exposes the general hashing and encoding helpers in `hash_utils.py`:

- SHA-1, SHA-256, SHA-512, MD5
- RIPEMD-160, HASH160, double-SHA256
- hex/base58/base64 decode and encode
- BTC and ETH unit conversion helpers

### 3.17 Recovery Report Exporter

This screen builds secure export artifacts using `export_utils.py`.

Supported output formats:

- TXT via `build_txt_report()`
- CSV via `build_csv_report()`
- PDF via `build_pdf_report()`
- QR PNG via `build_qr_png()`

Important safety feature:

- exports only whitelist public fields: `coin`, `address_type`, `path`, `address`
- forbidden keys like `mnemonic`, `seed`, `private_key`, `passphrase`, or `xprv` cause an error

## 4. Direct Python examples for client users

The lab modules can be imported directly from Python if you want to use the engines outside the Streamlit UI.

### 4.1 Validate a mnemonic

```python
from wallet_utils import validate_mnemonic

result = validate_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
print(result)
```

Expected output keys:

- `word_count`
- `word_count_valid`
- `words_in_wordlist`
- `checksum_valid`
- `valid`

### 4.2 Derive ETH addresses

```python
from wallet_utils import derive_eth_addresses

addresses = derive_eth_addresses(mnemonic, count=3)
for row in addresses:
    print(row)
```

### 4.3 Derive BTC addresses

```python
from wallet_utils import derive_btc_addresses

rows = derive_btc_addresses(mnemonic, address_type="native_segwit", count=3)
```

### 4.4 Scan standard derivation paths

```python
from derivation_utils import compare_all_standards

results = compare_all_standards(mnemonic, count=2)
for item in results:
    print(item)
```

### 4.5 Derive an arbitrary path

```python
from derivation_utils import derive_arbitrary_path

result = derive_arbitrary_path(mnemonic, "m/44'/0'/0'/0/0", coin="BTC")
print(result)
```

### 4.6 Find a known address match

```python
from derivation_utils import find_address_match

match = find_address_match(mnemonic, "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf3C")
print(match)
```

### 4.7 Recover missing words

```python
from recovery_utils import recover_missing_words

result = recover_missing_words(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
    target_address=None,
)
print(result)
```

### 4.8 Suggest typo corrections

```python
from recovery_utils import suggest_typo_corrections

candidates = suggest_typo_corrections("abandoon")
print(candidates)
```

### 4.9 Recover wrong word order

```python
from recovery_utils import recover_word_order

result = recover_word_order(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon about",
    positions=[10, 11],
    target_address=None,
)
print(result)
```

### 4.10 Test passphrase candidates

```python
from recovery_utils import test_passphrase

result = test_passphrase(mnemonic, ["", "password", "1234"])
print(result)
```

### 4.11 Analyze entropy

```python
from entropy_utils import analyze_entropy

with open("sample.bin", "rb") as f:
    data = f.read()
summary = analyze_entropy(data)
print(summary)
```

### 4.12 Inspect a MetaMask vault

```python
from forensic_utils import inspect_metamask_vault

with open("vault.json", "r", encoding="utf-8") as f:
    vault_text = f.read()
report = inspect_metamask_vault(vault_text)
print(report)
```

### 4.13 Export public address reports

```python
from export_utils import build_txt_report, build_csv_report, build_pdf_report, build_qr_png

records = [
    {
        "coin": "BTC",
        "address_type": "Native SegWit (Bech32)",
        "path": "m/84'/0'/0'/0/0",
        "address": "bc1q...",
    }
]

text = build_txt_report(records, notes="Demo report")
csv_text = build_csv_report(records)
pdf_bytes = build_pdf_report(records)
qr_bytes = build_qr_png(records[0]["address"])
```

## 5. Client screen examples

These example flows demonstrate how the app screens work.

### Example 1: Recover an incomplete mnemonic

1. Open the app and confirm the security disclaimer.
2. Select `Incomplete Seed Recovery` from the sidebar.
3. Paste the partial mnemonic and replace missing words with `?`.
4. Optionally enter a known address to narrow candidates.
5. Click `Recover`.
6. Review the checksum-valid mnemonic candidates.

### Example 2: Confirm a public address from a mnemonic

1. Select `Known Address Matcher`.
2. Paste the full mnemonic.
3. Enter the public address you want to verify.
4. Run the search.
5. The app reports the matching path and address type if it exists.

### Example 3: Generate an export report safely

1. Use `ETH/BTC Address Generator` or `Derivation Path Scanner`.
2. Copy the rows you want to preserve.
3. Open `Recovery Report Exporter`.
4. Choose `TXT`, `CSV`, or `PDF`.
5. Add any operational notes and export.

## 6. Developer usage: build, test, package

### 6.1 Build packages with `package.py`

The developer package ships with `package.py`.

- `cryptex_lab_client.zip` contains the client runtime.
- `cryptex_lab_developer.zip` contains the client runtime plus developer-only files and tests.

Run:

```bash
python package.py
```

This produces both zip archives in a `dist/` folder.

### 6.2 Run tests

The developer package includes a `tests/` suite.

From the repository root:

```bash
python -m pytest tests
```

This validates the recovery engines, derivation helpers, hash tools, forensic inspectors, and mode guards.

### 6.3 Generate licensing and integrity artifacts

`generate_keys.py` is a developer-only utility for signing license and integrity data.

It performs:

- generation of `private_key.pem` (developer secret key)
- creation of `public_key.pem`
- creation of `license.json` with signed license metadata
- creation of `manifest.json` with SHA-256 hashes of critical code files

Run:

```bash
python generate_keys.py
```

### 6.4 Verify build integrity

The app uses `integrity.verify_build_integrity()` to ensure shipped files are untampered.

Example:

```python
from integrity import verify_build_integrity

valid, reason = verify_build_integrity()
print(valid, reason)
```

### 6.5 License verification

The Streamlit app reads `license.json` and verifies it with `public_key.pem`.

Developer packages can include custom `license.json` profiles to control module access.

### 6.6 Developer package workflows

If you are building or customizing the lab, use the developer package for:

- writing and running new tests under `tests/`
- modifying recovery or derivation logic
- adjusting the UI in `app.py`
- creating release artifacts with `package.py`
- refreshing dependencies with `update.py`

## 7. Practical notes for clients and developers

### Safe client behavior

- Always use `OFFLINE_SAFE` mode when working with real mnemonic material.
- Only enable `LIVE_ANALYSIS` for address and transaction lookups on public data.
- Do not paste real secrets into export notes.
- Trust only the local Streamlit process and the offline environment.

### Developer extension tips

- Keep secret keys (`private_key.pem`) off client builds.
- Use `package.py` to create sanitized client distributions.
- Use `generate_keys.py` only on trusted development machines.
- Keep `tests/` updated when changing derivation logic or recovery flows.

## 8. Demo data and safe examples

Use the public demo test vectors in `demo_data.py` for screenshots and examples:

- `DEMO_MNEMONIC_ABANDON`
- `DEMO_ETH_FIRST_ADDRESS`
- `DEMO_BTC_BECH32_FIRST`
- `DEMO_BTC_LEGACY_FIRST`
- `DEMO_PARTIAL_MNEMONIC`
- `DEMO_BTC_ADDRESS`

These values are safe for documentation and demonstration.

## 9. Summary

- Use the client package for runtime recovery, forensic inspection, and reporting.
- Use the developer package for packaging, testing, signing, and internal release workflows.
- The UI is page-based, with strong offline/live separation and export safety checks.
- Direct Python imports let both clients and integrators reuse the lab engines in scripts or notebooks.

For more details, refer to `README.md` and `SECURITY.md` for installation, threat model, and operational guidance.
