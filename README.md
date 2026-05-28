# Cryptex Lab

A modular Python workstation for **ethical wallet recovery and
blockchain forensic analysis**. Bundles BIP39 validation, missing-word
/ typo / word-order / passphrase recovery engines, multi-standard
HD-derivation, known-address matching, entropy analysis,
case-management with evidence hashing, and metadata-only forensic file
inspection behind a single Streamlit UI styled as a CRYPTEX v2 dark
cyber forensic console.

> **ONLY USE THIS TOOL FOR WALLETS YOU OWN OR ARE EXPLICITLY AUTHORIZED
> TO RECOVER.** Use against third-party wallets without written
> authorisation is illegal in most jurisdictions.

---

## Dual-mode architecture

The lab runs in exactly one of two modes at a time, toggled from the
sidebar:

- **OFFLINE SAFE** (default) — all recovery, validation, vault
  inspection, entropy, hashing, and case-management pages are
  unlocked. No networking modules are imported. Pages that talk to a
  live blockchain are blocked.
- **LIVE ANALYSIS** — opt-in. Public-blockchain lookups (BTC/ETH
  address, transaction, mempool fees) are unlocked. All sensitive
  offline pages are blocked at the router level so a stray click can
  never combine a seed phrase with an active network connection.

The mode switch, the locked-page checks, and the `@require_offline` /
`@require_live` decorators are defined in `modes.py`. Full security
posture is in `SECURITY.md`.

---

## What this is (and isn't)

**This is**
- A guided recovery workstation: pick the problem, fill the form, run
  the right offline engine.
- A reference implementation of BIP39 / BIP32 / BIP44 / BIP49 / BIP84
  with deliberate safety bounds.
- An entropy / hash / encoding toolbox for forensic work.
- A case-management surface: open a case, attach evidence (hashed in
  memory only), produce whitelisted reports.
- An educational lab covering wallet architecture, derivation paths,
  air-gapped recovery, hardware wallets, and common scams.

**This is not**
- A wallet drainer, brute-forcer, or attack tool.
- A vault password cracker. The forensic inspector reads vault
  **structure only**.
- A cloud or SaaS service. There is no server other than the local
  Streamlit process bound to `localhost`.

---

## Architecture

```
cryptex-lab/
├── app.py                 Streamlit UI - CRYPTEX v2 styling, all pages, mode-aware router
├── modes.py               OFFLINE / LIVE mode switch, @require_offline, @require_live
├── security_utils.py      BANNED_NETWORK_MODULES set, audit_sys_modules, wipe_session_state
├── case_utils.py          In-memory case management, evidence hashing
├── hash_utils.py          SHA-256/512/1, MD5, RIPEMD-160, HASH160, base58/64, BTC/ETH unit converters
├── entropy_utils.py       Shannon, chi-square, runs test, quality verdict
├── wallet_utils.py        BIP39 validation + standard ETH/BTC derivation
├── derivation_utils.py    Multi-standard scans, arbitrary paths, address matching
├── recovery_utils.py      Missing-word / typo / order / passphrase engines
├── forensic_utils.py      MetaMask vault + wallet-file metadata (READ-ONLY)
├── live_utils.py          Public blockchain lookups (live mode only) - sole module that imports requests
├── export_utils.py        TXT / CSV / PDF / QR exporters (whitelisted)
├── demo_data.py           Public BIP39 test vectors for demo flows
├── launcher.py            Cross-platform desktop launcher (used by shortcuts)
├── install.py             Cross-platform installer (venv + shortcuts)
├── uninstall.py           Removes shortcuts and (optionally) the venv
├── update.py              Refreshes pinned deps + recreates the shortcut
├── install.sh|.bat        Thin wrappers that call install.py
├── uninstall.sh|.bat      Thin wrappers that call uninstall.py
├── update.sh|.bat         Thin wrappers that call update.py
├── tests/                 pytest suite - 100+ tests, BIP39 vectors, recovery, exports, modes
├── .streamlit/config.toml Dark theme, localhost-only, telemetry off
├── SECURITY.md            Threat model, no-network guarantee, audit instructions
├── implementation_plan.md Design rationale for the rebuild
├── task.md                Running checklist of completed and pending work
├── requirements.txt
└── README.md
```

The frontend is intentionally thin. All cryptography, recovery,
forensic, and live-lookup logic lives in independent engine modules
that you can import from a notebook, a script, or your own UI without
going through Streamlit.

---

## Recovery workflows

The **Recovery workflow** page is the main entry point. Pick the
problem you have; the lab routes to the right engine.

| Problem                                      | Engine used                                                                 |
|----------------------------------------------|-----------------------------------------------------------------------------|
| Wallet shows zero balance                    | `derivation_utils.find_address_match`, `compare_all_standards`              |
| Missing seed words (use `?`)                 | `recovery_utils.recover_missing_words` (max 2 unknowns)                     |
| Misspelled / incorrect words                 | `recovery_utils.suggest_typo_corrections` (Levenshtein-1 over BIP39 wordlist)|
| Wrong word order                             | `recovery_utils.recover_word_order` (max 8 positions, 8! = 40320)           |
| Possible BIP39 passphrase                    | `recovery_utils.test_passphrase`                                            |
| Corrupted backup                             | Guided checklist + reusable engines                                         |
| Inspect MetaMask vault / wallet file         | `forensic_utils.inspect_metamask_vault`, `identify_wallet_file`             |

### Power-user **Tools** page

- BIP39 validator (word count, wordlist, checksum).
- Address generator (ETH BIP44, BTC legacy / SegWit / native SegWit).
- Arbitrary BIP32 path single-address derivation.
- Hash / crypto tools: SHA-256/512/1, MD5, HASH160, double-SHA256,
  RIPEMD-160, hex/base58/base64 codecs, BTC and ETH unit converters.
- Entropy analysis lab: Shannon, chi-square, runs test, byte
  frequency, PASS/WEAK/FAIL verdict.
- Case management: open a case, attach evidence (hashed in memory
  only), produce reports.

### Live analysis (opt-in)

When LIVE ANALYSIS mode is active, the lab exposes:

- BTC address balance and transaction lookup via Blockstream.
- ETH address balance via a public Etherscan-compatible endpoint.
- Mempool fee estimates via mempool.space.

All other pages — anything that touches a seed, key, or vault — are
locked while live mode is active. See `SECURITY.md` for the full
isolation contract.

### Recovery report exporter

Generates TXT, CSV, or PDF reports plus a PNG QR code for any single
public address. Reports contain **only**:
- UTC timestamp,
- coin (ETH / BTC),
- address type,
- derivation path,
- public address,
- user-supplied free-text notes.

Records are run through a strict whitelist; the exporter raises if any
record contains a key matching `mnemonic`, `seed`, `entropy`,
`private_key`, `private`, `secret`, `passphrase`, or `xprv`. So even
future bugs cannot accidentally write secrets to a report.

---

## Installing the app

The lab installs like a regular desktop application: one command, one
desktop shortcut, no need to remember CLI invocations afterwards.

**Requires Python 3.10+** on the install machine. (The install step is
the only step that touches the network - to fetch the pinned pip
packages. Runtime is fully offline.)

### Linux / macOS

```bash
git clone <this repo>            # or extract the project folder
cd offline-wallet-lab
./install.sh                     # creates venv, installs deps, makes shortcut
```

You can now launch the app from your application menu (Linux) or
Launchpad (macOS), or run `python launcher.py` from the project
folder.

### Windows

Open a Command Prompt or PowerShell in the project folder and run:

```cmd
install.bat
```

This creates a venv inside the folder, installs the pinned dependencies,
and creates **Desktop** and **Start Menu** shortcuts pointing at the
launcher. Double-click either to start the app.

### Air-gapped install (sneakernet)

If your target machine has no network:

1. Run `./install.sh` (or `install.bat`) on an **online** machine first.
2. Copy the **entire project folder** (including the populated `venv/`)
   to the offline machine via USB.
3. On the offline machine, run `./install.sh --skip-deps` (or
   `install.bat --skip-deps`). This just creates the platform shortcut
   pointing at the venv you brought along.

### Updating

When you replace the source files with a newer version (`git pull`, or
extracting a new release zip over the folder):

```bash
./update.sh        # Linux / macOS
update.bat         # Windows
```

This re-runs pip against the new `requirements.txt` (online step) and
re-creates the desktop shortcut so it points at the current launcher.
There is **no auto-update** at runtime - this is by design for an
offline tool.

### Uninstalling

```bash
./uninstall.sh     # Linux / macOS
uninstall.bat      # Windows
```

By default this removes the platform shortcut and prompts before
deleting the local `venv/`. The source files stay where they are so you
can re-install later. Add `--yes` to skip the prompts, or
`--keep-venv` if you want to keep dependencies in place.

---

## Running it manually

If you do not want to use the shortcut, you can launch the app any time
from the project folder:

```bash
python launcher.py            # opens browser to http://localhost:8501
python launcher.py --no-browser
python launcher.py --port 9000
```

Or, if you prefer raw Streamlit:

```bash
source venv/bin/activate      # Windows: venv\Scripts\activate
streamlit run app.py
```

The bundled `.streamlit/config.toml` pins:
- `gatherUsageStats = false` (no telemetry).
- `address = "localhost"` (no external interfaces).
- `headless = true` (no auto-launching anything that could phone home).
- Dark security-focused theme.

Stay on the **Home** page until you have read and accepted the
disclaimer; the other pages refuse to operate until you do.

### Pre-flight offline checklist

Before pasting any real mnemonic:

1. **Disconnect** Wi-Fi, ethernet, and tethered mobile data.
2. **Close** cloud sync agents (Dropbox / iCloud / Drive / OneDrive).
3. **Quit** other browsers and any clipboard manager.
4. **Optional but recommended:** run under
   `firejail --net=none streamlit run app.py` or an equivalent
   network-namespace sandbox so the Python process cannot reach a
   network even if something tried.
5. When finished, use **Clear Session**, close the tab, and reboot.

---

## Security model

### What the code guarantees

- **No network imports.** Grep the codebase for `requests`, `urllib`,
  `socket`, `http`, `aiohttp`, `httpx`, `web3`, `infura`, `alchemy` -
  there are no real matches.
- **No secret persistence.** Mnemonics, passphrases, raw seed bytes,
  entropy, and private keys live only as local function arguments and
  the Streamlit text widgets they came from. They are never written to
  disk, logged, or copied into a session-state key we own.
- **Whitelist-only export.** The exporter accepts exactly four record
  fields (`coin`, `address_type`, `path`, `address`) and refuses to
  proceed if any record contains a forbidden field name.
- **Bounded recovery.** Hard caps prevent the engines from drifting into
  brute-force territory: 2 missing words max, 8 unknown positions max
  for permutation recovery.
- **Metadata-only forensics.** The MetaMask vault inspector reports
  structure (salt length, IV length, KDF, iteration count,
  SHA-256 fingerprint of the ciphertext) and **never** attempts
  decryption or password trial.
- **Localhost-only binding.** Streamlit listens on `localhost` and
  refuses external interfaces.

### Conservative defaults you may want to know about

- **Missing-word recovery is capped at 2 unknown words.** Two unknowns
  is already ~4.2M validations. Three would be ~8.6G, which crosses
  from "reasonable recovery" into "attack tool" - intentionally not
  supported.
- **Word-order recovery is capped at 8 positions** (40320
  permutations). Beyond that the search space is impractical AND
  smells like attacking unknown wallets.
- **`bitcoinlib` is intentionally excluded** even though it is
  commonly used for BTC tooling, because its defaults touch the
  network (UTXO lookups, block-header downloads). We rely on
  `bip-utils` + `pycryptodome` only.
- **MetaMask vaults are read but never decrypted.** Pasting the
  ciphertext + a password would technically allow decryption, but
  that crosses the "no password trial" line we drew at the project's
  outset.
- **No balance checking.** Requires the network - intentionally out of
  scope. Use a separate hardware wallet or a different offline tool
  for balance UX after you've recovered the mnemonic.

### Caveats Python cannot fix

- Python strings are immutable and the runtime does not securely wipe
  memory. Reboot the machine when done.
- The browser may cache form text. Use **Clear Session** and close the
  tab.
- The clipboard you pasted from may still hold the mnemonic. Clear it.

---

## Tests

```bash
source venv/bin/activate
pytest tests/ -v
```

All tests use only the well-known public BIP39 vector
`abandon abandon abandon abandon abandon abandon abandon abandon abandon
abandon abandon about` so they are fully reproducible and contain no
private data. The suite covers BIP39 validation, ETH/BTC derivation,
recovery engines (missing-word, typo, word-order, passphrase),
MetaMask vault parsing, file-type identification, and the export
whitelist + no-secret-leak invariants.

---

## Legal and liability

This software is provided **as-is**, without warranty of any kind. The
authors accept no liability for:
- misuse against third-party wallets,
- financial loss caused by user error,
- failure to recover a wallet,
- consequences of pasting a mnemonic into a machine that was not
  actually offline.

By using this tool you confirm that you own the wallet(s) you are
attempting to recover, or that you have written authorisation from the
owner. **"Not your keys, not your coins"** also means **"not your
keys, not your right to recover them."**
