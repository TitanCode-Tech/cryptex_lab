# CRYPTEX LAB Client Tutorial

This guide explains how to use the `cryptex-lab` client package. It covers installation, runtime usage, the Streamlit screens, example workflows, and direct Python engine usage.

> Only use this tool on wallets you own or are explicitly authorized to recover.

## 1. Client package contents

The client package contains the user-facing runtime and offline analysis engines.

Included files:

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
- `install.py`, `install.sh`, `install.bat`
- `update.py`, `update.sh`, `update.bat`
- `uninstall.py`, `uninstall.sh`, `uninstall.bat`
- `requirements.txt`
- `README.md`, `SECURITY.md`
- `.streamlit/config.toml`

## 2. Install and launch

### Linux / macOS

```bash
git clone <repo-url>
cd cryptex-lab
./install.sh
```

### Windows

```cmd
install.bat
```

This creates a local Python virtual environment, installs pinned dependencies, and creates a desktop/start menu shortcut that launches `launcher.py`.

### Run manually

```bash
python launcher.py
```

Or with Streamlit directly:

```bash
source venv/bin/activate   # Windows: venv\Scripts\activate
streamlit run app.py
```

## 3. Offline-safe vs live-analysis

- `OFFLINE_SAFE` is the default mode. All sensitive recovery, inspection, and export screens are available.
- `LIVE_ANALYSIS` is opt-in. It unlocks public blockchain lookups and locks sensitive seed-related screens.

The mode enforcement is implemented in `modes.py` using `@require_offline` and `@require_live` decorators.

## 4. Main client screens

### Security Landing

Explains the security model, shows current mode, and requires the user to accept the disclaimer before using the app.

### Recovery Problem Selector

Helps the user choose the correct workflow for their recovery scenario:

- Missing seed words
- Typo correction
- Wrong word order
- Passphrase testing
- Known address / derivation matching

### Case Management

Uses `case_utils.py` to create and manage in-memory cases with metadata, without storing raw evidence files.

### Evidence Hash Checker

Hashes evidence using `calculate_evidence_hash()` and stores only metadata and hash values.

### BIP39 Validation Lab

Validates a mnemonic with `wallet_utils.validate_mnemonic()` and reports:

- word count validity
- wordlist membership
- checksum validity
- overall validity

### Incomplete Seed Recovery

Uses `recovery_utils.recover_missing_words()` to recover missing words from a partial mnemonic with `?` placeholders.

Maximum supported unknown word count: `2`.

### Typo Correction Lab

Uses `recovery_utils.suggest_typo_corrections()` to suggest valid BIP39 words for misspelled tokens.

### Wrong Word Order Helper

Uses `recovery_utils.recover_word_order()` to permute selected positions and recover a correct checksum-valid mnemonic.

Position limit: up to `8` words.

### BIP39 Passphrase Testing

Uses `recovery_utils.test_passphrase()` to compare mnemonic-derived addresses across candidate passphrases.

### Derivation Path Scanner

Uses `derivation_utils.scan_standard_paths()` and `compare_all_standards()` to derive ETH and BTC addresses from common standard paths.

### Known Address Matcher

Uses `derivation_utils.find_address_match()` to search for a target address across the first addresses of standard paths.

### ETH/BTC Address Generator

Derives public ETH and BTC addresses from a valid mnemonic using `wallet_utils.derive_eth_addresses()` and `wallet_utils.derive_btc_addresses()`.

### Entropy Analysis Lab

Uses `entropy_utils.analyze_entropy()` to evaluate a byte sequence and report entropy, chi-square, unique bytes, and a quality verdict.

### MetaMask Vault Inspector

Uses `forensic_utils.inspect_metamask_vault()` to inspect MetaMask vault JSON metadata without attempting decryption.

### Live Address / TX Lookup

In live mode, uses `live_utils.py` to query public blockchain APIs for BTC address stats, BTC transaction details, ETH balance, and mempool fees.

### Hash/Crypto Tools

Exposes general-purpose cryptographic helpers from `hash_utils.py`.

### Recovery Report Exporter

Uses `export_utils.py` to produce TXT, CSV, PDF, and QR outputs with strict secret-safe whitelisting.

## 5. Example direct Python usage

### Validate a mnemonic

```python
from wallet_utils import validate_mnemonic

result = validate_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
print(result)
```

### Derive ETH addresses

```python
from wallet_utils import derive_eth_addresses

addresses = derive_eth_addresses(mnemonic, count=3)
for row in addresses:
    print(row)
```

### Derive BTC addresses

```python
from wallet_utils import derive_btc_addresses

rows = derive_btc_addresses(mnemonic, address_type="native_segwit", count=3)
```

### Scan standard derivation paths

```python
from derivation_utils import compare_all_standards

results = compare_all_standards(mnemonic, count=2)
for item in results:
    print(item)
```

### Derive an arbitrary path

```python
from derivation_utils import derive_arbitrary_path

result = derive_arbitrary_path(mnemonic, "m/44'/0'/0'/0/0", coin="BTC")
print(result)
```

### Find a known address match

```python
from derivation_utils import find_address_match

match = find_address_match(mnemonic, "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf3C")
print(match)
```

### Recover missing words

```python
from recovery_utils import recover_missing_words

result = recover_missing_words(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
    target_address=None,
)
print(result)
```

### Suggest typo corrections

```python
from recovery_utils import suggest_typo_corrections

candidates = suggest_typo_corrections("abandoon")
print(candidates)
```

### Recover wrong word order

```python
from recovery_utils import recover_word_order

result = recover_word_order(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon about",
    positions=[10, 11],
    target_address=None,
)
print(result)
```

### Test passphrase candidates

```python
from recovery_utils import test_passphrase

result = test_passphrase(mnemonic, ["", "password", "1234"])
print(result)
```

### Analyze entropy

```python
from entropy_utils import analyze_entropy

with open("sample.bin", "rb") as f:
    data = f.read()
summary = analyze_entropy(data)
print(summary)
```

### Inspect a MetaMask vault

```python
from forensic_utils import inspect_metamask_vault

with open("vault.json", "r", encoding="utf-8") as f:
    vault_text = f.read()
report = inspect_metamask_vault(vault_text)
print(report)
```

### Export public address reports

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

## 6. Client workflow examples

### Example 1: Recover an incomplete mnemonic

1. Open the app and accept the security disclaimer.
2. Select `Incomplete Seed Recovery`.
3. Paste the partial mnemonic, replacing missing words with `?`.
4. Optionally enter a known address to narrow candidates.
5. Click `Recover`.
6. Review checksum-valid candidates.

### Example 2: Confirm a public address from a mnemonic

1. Select `Known Address Matcher`.
2. Paste the full mnemonic.
3. Enter the address to verify.
4. Run the search.
5. Review the matching path and address type.

### Example 3: Generate a safe export report

1. Use `ETH/BTC Address Generator` or `Derivation Path Scanner`.
2. Copy the rows you want to preserve.
3. Open `Recovery Report Exporter`.
4. Choose `TXT`, `CSV`, or `PDF`.
5. Add operational notes and export.

## 7. Safe client practices

- Keep the app in `OFFLINE_SAFE` mode when working with real secrets.
- Only enable `LIVE_ANALYSIS` for public blockchain lookups.
- Do not paste real secrets into export notes.
- Use the built-in demos from `demo_data.py` for screenshots and documentation.

## 8. Safe demo examples

Use these demo values safely in examples and screenshots:

- `DEMO_MNEMONIC_ABANDON`
- `DEMO_ETH_FIRST_ADDRESS`
- `DEMO_BTC_BECH32_FIRST`
- `DEMO_BTC_LEGACY_FIRST`
- `DEMO_PARTIAL_MNEMONIC`
- `DEMO_BTC_ADDRESS`
