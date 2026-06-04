# CRYPTEX LAB — Developer & Distribution Guide

This document is for **Titan Code developers only**. It covers the complete workflow for packaging, licensing, and distributing Cryptex Lab to clients. Keep this file and `private_key.pem` off client machines at all times.

---

## Table of Contents

1. [What You Own vs What the Client Receives](#1-what-you-own-vs-what-the-client-receives)
2. [New Client Onboarding — Step by Step](#2-new-client-onboarding--step-by-step)
3. [Building the Production Package](#3-building-the-production-package)
4. [Key and Secret Management](#4-key-and-secret-management)
5. [Issuing and Renewing Licenses](#5-issuing-and-renewing-licenses)
6. [Running the Test Suite](#6-running-the-test-suite)
7. [Updating a Deployed Client](#7-updating-a-deployed-client)
8. [How the Cython Protection Works](#8-how-the-cython-protection-works)
9. [Quick Reference — Developer Commands](#9-quick-reference--developer-commands)

---

## 1. What You Own vs What the Client Receives

### Developer-only files — NEVER sent to clients

| File | Purpose |
|---|---|
| `private_key.pem` | RSA private key — signs all licenses and manifests |
| `generate_keys.py` | Issues machine-locked licenses with TOTP secrets |
| `compile_modules.py` | Compiles the 4 security modules to native binaries |
| `package.py` | Creates distribution ZIP archives |
| `tests/` | Internal test suite |
| `TUTORIAL_DEVELOPER.md` | This file |
| Source `.py` files for the 4 security modules | Replaced by compiled binaries in client packages |

### What the client receives (inside `cryptex_lab_client_compiled.zip`)

| File | Notes |
|---|---|
| `license_utils.cpython-3XX-*.so` | Compiled binary — license + fingerprint checks |
| `integrity.cpython-3XX-*.so` | Compiled binary — build integrity verification |
| `machine_id.cpython-3XX-*.so` | Compiled binary — hardware fingerprint |
| `audit.cpython-3XX-*.so` | Compiled binary — audit logging |
| `app.py` | Main UI (plain Python — logic only, no security enforcement) |
| `modes.py`, `wallet_utils.py`, `recovery_utils.py`, … | Application logic (plain Python) |
| `manifest.json` | RSA-signed SHA-256 hashes of all critical files |
| `public_key.pem` | RSA public key for license/manifest verification |
| `license.json` | Machine-locked, RSA-signed license with TOTP secrets embedded |
| `requirements.txt` | Python package dependencies |
| `assets/`, `.streamlit/` | UI assets and config |
| `install.py / .sh / .bat` | Cross-platform installer |
| `uninstall.py / .sh / .bat` | Uninstaller |
| `TUTORIAL_CLIENT.md` | End-user guide |

> The 4 security modules ship as compiled native binaries (`.so` on Linux/macOS, `.pyd` on Windows). Their source code is not in the package. A disassembler is required to inspect them — a Python decompiler cannot touch them.

---

## 2. New Client Onboarding — Step by Step

### Step 1 — Client sends their machine fingerprint

Ask the client to run this on the **target workstation** (the exact machine that will run Cryptex Lab):

```bash
python machine_id.py
```

They will see:

```
Machine Fingerprint:
  2613bee6eda5f062a3f4d8e1b7c9a0f23d5e4c8b1a6f7e2d9c3b0a4e5f8d1c7

Provide this value to your Cryptex Lab administrator when requesting a license.
```

They send you the 64-character hex string. This fingerprint is derived from their OS machine ID, primary MAC address, and hostname — it is stable for the life of that OS installation and bound to that physical machine.

---

### Step 2 — Generate the machine-locked license

On your **developer machine**:

```bash
python generate_keys.py
```

When prompted:

```
Machine fingerprint (or blank for this machine): <paste the client's fingerprint>
```

Output:

```
=== TOTP SECRETS (scan into authenticator app) ===
  Senior Analyst: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    URI: otpauth://totp/Cryptex%20Lab:Senior%20Analyst?secret=XXXX...
  Admin: YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
    URI: otpauth://totp/Cryptex%20Lab:Admin?secret=YYYY...
=== Store these secrets safely — they will NOT be shown again ===
```

**Do two things immediately:**

1. **Save both TOTP secrets** in your password manager labeled with the client name and date. They are regenerated fresh on every run — if lost, the client is locked out of elevated roles until you reissue.
2. **Keep the `otpauth://` URIs** — you will send these to the client via a separate secure channel in Step 5.

This produces a signed `license.json` containing the machine fingerprint, TOTP secrets, expiry, and licensed modules — all inside the RSA signature.

---

### Step 3 — Build the compiled production package

```bash
python package.py --compiled
```

This automatically:
1. Runs `compile_modules.py` — compiles `license_utils.py`, `integrity.py`, `machine_id.py`, and `audit.py` to native `.so` binaries using Cython + gcc
2. Packages those binaries alongside the remaining `.py` modules into `dist/cryptex_lab_client_compiled.zip`

The ZIP contains the current `license.json` (from Step 2). No separate license file needs to be attached.

---

### Step 4 — Send the package to the client

Deliver `dist/cryptex_lab_client_compiled.zip` via your secure delivery channel (encrypted email, secure file transfer, or USB drive for air-gapped sites).

---

### Step 5 — Send TOTP secrets via a separate secure channel

**Never** bundle TOTP secrets with the application package. Send them separately:

- Encrypted email (PGP / S/MIME)
- Secure messaging (Signal, etc.)
- Printed card handed in person

Send the `otpauth://` URI for each role (the client converts it to a QR code and scans it with their authenticator app), or the raw base32 secret for manual entry.

---

### Step 6 — Client installs and configures

Direct the client to `TUTORIAL_CLIENT.md` inside the ZIP. They will extract, install, add their TOTP accounts, and launch.

---

## 3. Building the Production Package

### Standard build (internal / testing only)

```bash
python package.py
```

Produces:
- `dist/cryptex_lab_client.zip` — plain source files (**do not send to clients**)
- `dist/cryptex_lab_developer.zip` — full developer archive including private tools

### Compiled production build

```bash
python package.py --compiled
```

Produces:
- `dist/cryptex_lab_client_compiled.zip` — 4 security modules compiled to native binaries, all other modules as plain Python. **This is the file you send to clients.**

### Pre-release checklist

- [ ] `python -m pytest tests/ -v` — all tests pass
- [ ] `python generate_keys.py` — license issued for the correct client fingerprint, TOTP secrets saved
- [ ] `python package.py --compiled` — package built successfully
- [ ] Extract the ZIP on a clean machine and confirm it launches before sending

---

## 4. Key and Secret Management

### RSA private key (`private_key.pem`)

- **Store in your password manager vault.** This is the only copy.
- If lost: you cannot issue new licenses or update manifests. Existing client installations continue to work indefinitely, but no updates or renewals are possible until you regenerate the key pair (which invalidates all existing licenses — all clients would need new `license.json` and `public_key.pem`).
- Never commit to git (already in `.gitignore`). Never email. Never copy to a client machine.

### TOTP secrets

- Printed once by `generate_keys.py` and embedded in `license.json`. Not stored anywhere automatically.
- Save in your vault labeled: `Cryptex Lab TOTP — [Client Name] — [Date]`.
- If lost: rerun `generate_keys.py` with the same client fingerprint. New secrets are generated, old ones become invalid. Deliver new `license.json` and new TOTP secrets to the client.

### Public key (`public_key.pem`)

Safe to distribute — it can only verify signatures, not create them. Included in every client package.

---

## 5. Issuing and Renewing Licenses

### Renew an existing client's license (expiry or machine change)

1. Obtain the client's machine fingerprint (`python machine_id.py` on their machine if it changed; reuse the previous one if the machine is the same).
2. Run `python generate_keys.py` and enter the fingerprint.
3. Save the new TOTP secrets.
4. Run `python package.py --compiled` and deliver the new ZIP.
5. Send new TOTP secrets via secure channel — old secrets are now invalid.

### Dev / demo license (no machine locking)

```bash
python generate_keys.py --any
```

Sets `"machine_fingerprint": "any"` in the license — runs on any machine. For internal testing only.

### Changing client name, expiry, or licensed modules

Edit `generate_keys.py` before running it:

```python
license_data = {
    "company": "Titan Code",
    "client": "Acme Forensics Ltd",      # shown in the UI
    "expires": "2028-01-01",             # YYYY-MM-DD
    "modules": ["recovery", "forensic", "reports", "vault", "advanced"],
    ...
}
```

---

## 6. Running the Test Suite

```bash
source venv/bin/activate
python -m pytest tests/ -v
```

Always run before packaging a release. Covers recovery engines, derivation helpers, forensic inspectors, hash utilities, and mode enforcement.

---

## 7. Updating a Deployed Client

When you push a code change:

1. Make and test your changes locally (`python -m pytest tests/`).
2. Run `python generate_keys.py` (with the client's fingerprint) — this regenerates `manifest.json` with updated file hashes. It also regenerates TOTP secrets, so save them and deliver them to the client alongside the update.
3. Run `python package.py --compiled` to produce a fresh ZIP.
4. Deliver the new ZIP and new TOTP secrets to the client. They replace the old files and re-scan the authenticator secrets.

> **Keeping TOTP secrets stable across updates:** The TOTP secrets are independent of the code — only the file hashes in `manifest.json` change when code changes. If you want to avoid the client re-scanning their authenticator, manually copy the `totp_secrets` block from the old `license.json` into `license_data` in `generate_keys.py` before running it.

---

## 8. How the Cython Protection Works

`compile_modules.py` targets the 4 modules that enforce all security checks:

| Module | What it protects |
|---|---|
| `license_utils.py` | RSA signature verification, machine fingerprint check, module access control |
| `integrity.py` | Build manifest signature verification, per-file SHA-256 hash check |
| `machine_id.py` | Hardware fingerprint collection logic |
| `audit.py` | Tamper-evident audit log writing |

**Compilation pipeline:**
```
license_utils.py  ──► Cython ──► license_utils.c  ──► gcc ──► license_utils.cpython-3XX-*.so
```

The `.so` file is a native shared library — it is imported by Python with `import license_utils` exactly as before, but no Python source or bytecode exists in the file. Inspecting it requires a binary disassembler (IDA Pro, Ghidra). A Python decompiler cannot touch it.

`app.py` and the other UI modules remain as plain Python. This is intentional: the UI contains no security enforcement — all checks happen inside the compiled modules, which the UI cannot bypass or modify.

**Platform note:** `.so` files are platform-specific. The file compiled on Linux x86-64 only runs on Linux x86-64. If you distribute to multiple platforms, compile on each target platform separately (or use a cross-compilation CI pipeline).

---

## 9. Quick Reference — Developer Commands

```bash
# Get machine fingerprint of THIS machine
python machine_id.py

# Issue a machine-locked license (prompts for client fingerprint)
python generate_keys.py

# Issue a dev/demo license (no machine locking)
python generate_keys.py --any

# Verify Cython + gcc are available
python compile_modules.py --check

# Compile the 4 security modules to native .so binaries
python compile_modules.py

# Build the production client package (compiles + zips)
python package.py --compiled

# Build the standard (plain source) developer archive
python package.py

# Run the full test suite
python -m pytest tests/ -v
```
