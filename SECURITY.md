# Security Policy

Cryptex Lab is an offline forensic and wallet-recovery workstation. It
handles material that, if it leaks, is unrecoverable: BIP39 mnemonics,
BIP39 passphrases, raw seed bytes, and private keys. The security
posture below describes what the codebase guarantees, what it cannot
guarantee, and how to verify the guarantees yourself.

## Threat model

In scope:
- A trusted analyst running the lab on a machine they control.
- Material includes seed phrases, passphrases, derived private keys,
  vault files, and case notes.
- The primary risk is unintentional exfiltration: a network call that
  shouldn't happen, a secret written to a report, or sensitive data
  persisting on disk.

Out of scope:
- A compromised host OS (kernel rootkits, malicious browser
  extensions, keyloggers).
- Cold-boot attacks on RAM after the analyst walks away.
- Adversaries with physical access to the running process.

## Dual-mode architecture

The lab operates in exactly one of two modes at a time, surfaced
through `modes.py`:

- **OFFLINE SAFE** (default) — pages that handle seeds, private
  keys, and vault files are unlocked. Live-network pages are blocked.
- **LIVE ANALYSIS** — opt-in. Live-network pages (public address
  lookup, transaction lookup, mempool fees) are unlocked. All
  sensitive offline pages are blocked at the router level.

Mode-aware locking is enforced by:
- The `@require_offline` and `@require_live` decorators on guarded
  functions.
- Page-level checks in `app.py` (`OFFLINE_LOCKED_PAGES`,
  `LIVE_LOCKED_PAGES`) that refuse to render rather than rely on the
  user not clicking.

## No-network guarantee for offline modules

The set of network modules that must never be imported by offline
code is declared in `security_utils.BANNED_NETWORK_MODULES`:

```
requests, urllib3, http, socket, aiohttp, httpx,
web3, eth_tester, bitcoinlib, telemetry, analytics
```

`live_utils.py` is the only module permitted to import `requests`,
and only its functions are reachable when LIVE ANALYSIS mode is
active. `security_utils.audit_sys_modules()` returns any banned
module currently loaded — used by the test suite to assert that
importing offline modules keeps a clean slate.

To audit manually:

```bash
grep -rn "import requests\|import httpx\|import aiohttp\|from web3\|import urllib.request\|import socket" \
  --include="*.py" --exclude="live_utils.py" --exclude="test_*"
```

The expected result is zero matches outside `live_utils.py`.

## No secret persistence

- Mnemonics, passphrases, raw seed bytes, entropy, and private keys
  live only as local function arguments and the Streamlit text widgets
  they came from.
- Nothing sensitive is written to disk, logged, or copied into a
  session-state key the lab owns.
- Evidence files uploaded for hashing are read into memory, hashed,
  and discarded — never written to disk.
- Streamlit's bundled config (`.streamlit/config.toml`) disables
  telemetry and binds the server to `localhost`.

## Export whitelist

`export_utils.safe_record` runs every record through a strict
whitelist before any TXT / CSV / PDF / JSON export. It:

1. Allows only the four fields in `_REPORT_FIELDS`: `coin`,
   `address_type`, `path`, `address`.
2. Raises `ValueError` if any forbidden key is present, including
   `mnemonic`, `seed`, `entropy`, `private_key`, `private`, `secret`,
   `passphrase`, and `xprv`.

A loud crash is preferred over a silent leak. The only free-text
field exposed to the user is `notes`, which the UI must explicitly
warn against pasting secrets into.

## Bounded recovery

Hard caps prevent the recovery engines from drifting into general
brute-force territory:

- Missing-word recovery — at most 2 unknowns.
- Word-order recovery — at most 8 positions (8! = 40320).
- Maximum address derivations per request is clamped in
  `wallet_utils._clamp_count`.

These caps exist so the engines stay useful for legitimate recovery
of the analyst's own wallets and stop being usable as attack tools
against unknown wallets.

## Verification

Run the test suite:

```bash
source venv/bin/activate
pytest tests/ -v
```

The suite covers BIP39 vectors, ETH/BTC derivation, recovery engines,
MetaMask vault parsing, file-type identification, the export
whitelist, mode-guard decorators, and the no-network audit invariant.

## Responsible disclosure

If you find a security issue that affects this lab — a bypass of the
offline guarantee, a path that leaks secrets to disk, an export that
escapes the whitelist — please report it privately to the maintainer
before publishing. Include a minimal reproduction and the commit hash
you tested against.
