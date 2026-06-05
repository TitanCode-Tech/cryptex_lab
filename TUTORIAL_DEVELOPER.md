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
| `license.json` | Written locally on the client machine after activation — not shipped in the ZIP |
| `requirements.txt` | Python package dependencies |
| `assets/`, `.streamlit/` | UI assets and config |
| `install.py / .sh / .bat` | Cross-platform installer |
| `uninstall.py / .sh / .bat` | Uninstaller |
| `TUTORIAL_CLIENT.md` | End-user guide |

> The 4 security modules ship as compiled native binaries (`.so` on Linux/macOS, `.pyd` on Windows). Their source code is not in the package. A disassembler is required to inspect them — a Python decompiler cannot touch them.

---

## 2. New Client Onboarding — Step by Step

The new model ships the app to everyone first, then delivers the license separately — like commercial software. You build once and issue licenses on demand.

---

### Step 1 — Ship the application (one time per platform)

```bash
python release.py --any   # builds dist/cryptex_lab_client_compiled.zip
```

Or if you already have a target fingerprint:

```bash
python release.py <fingerprint>
```

Deliver `dist/cryptex_lab_client_compiled.zip` to the client via your secure channel (encrypted email, file transfer, or USB for air-gapped sites). **No license is inside the ZIP.**

---

### Step 2 — Client sends their Machine ID

When the client launches the app they see the **LICENSE ACTIVATION** screen. It shows their **Machine ID** — a 64-character fingerprint unique to their workstation. They copy it and send it to you.

The fingerprint is derived from their OS machine ID, primary MAC, and hostname. It is stable for the life of that OS installation.

---

### Step 3 — Generate the machine-locked license key

On your **developer machine**:

```bash
python release.py --license-only <machine_fingerprint>
```

Output:

```
=== LICENSE ACTIVATION KEY (send this to the client) ===
CXLAB-eyJ...
=== Client pastes this into the app: Step 2 → Enter License Key ===
```

**Copy the `CXLAB-...` activation key** — this is all you need to send.

> **No TOTP secrets.** The license no longer contains 2FA credentials. The client generates their own secrets during first-run setup inside the app — you never see them, handle them, or transmit them.

---

### Step 4 — Send the license key to the client

Send the `CXLAB-...` key to the client via any secure channel (encrypted email, messaging, etc.).

That is the only thing you need to deliver. There is no separate 2FA credential to manage.

---

### Step 5 — Client activates and launches

1. Client pastes the `CXLAB-...` key into **Step 2** on the activation screen → clicks **Activate License**
2. The app validates the RSA signature and machine fingerprint, then opens the **Security Setup** screen
3. Client scans QR codes for each role into their authenticator app, verifies each one, clicks **Save & Launch**
4. App loads — 2FA is configured and ready

Direct the client to `TUTORIAL_CLIENT.md` inside the ZIP for the full setup guide.

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
- [ ] `python release.py --any` (or with a real fingerprint) — license key printed, TOTP secrets saved
- [ ] Extract the ZIP on a clean machine and confirm the activation screen loads before sending

---

## 4. Key and Secret Management

### RSA private key (`private_key.pem`)

- **Store in your password manager vault.** This is the only copy.
- If lost: you cannot issue new licenses or update manifests. Existing client installations continue to work indefinitely, but no updates or renewals are possible until you regenerate the key pair (which invalidates all existing licenses — all clients would need new `license.json` and `public_key.pem`).
- Never commit to git (already in `.gitignore`). Never email. Never copy to a client machine.

### TOTP secrets

- **You do not hold these.** The client generates their own 2FA secrets during first-run setup inside the app. Secrets are stored only in `totp_secrets.json` on their machine and in their authenticator app.
- If the client loses their authenticator device or needs to reset 2FA: they delete `totp_secrets.json` on their workstation and relaunch the app — the setup screen appears again and they scan fresh QR codes. No action required from you.
- `totp_secrets.json` is in `.gitignore` and is never packaged or transmitted.

### Public key (`public_key.pem`)

Safe to distribute — it can only verify signatures, not create them. Included in every client package.

---

## 5. Issuing and Renewing Licenses

### Renew an existing client's license (expiry or machine change)

1. Get their current Machine ID (they open the app — on expiry it shows the activation screen with the ID; on a machine change they send you the new ID directly).
2. Run:
   ```bash
   python release.py --license-only <fingerprint>
   ```
3. Send the new `CXLAB-...` key to the client — they paste it in the activation screen.
4. If it's a machine change, their `totp_secrets.json` from the old machine won't transfer. They delete the old file (if copied) and re-run setup — the app shows the Security Setup screen automatically.

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
2. Run `python release.py <client_fingerprint>` — this regenerates `manifest.json` with updated file hashes, creates a new license key, and packages a fresh ZIP.
3. Deliver the new ZIP to the client. They re-run the installer and paste the new `CXLAB-...` key into the activation screen.
4. Their existing `totp_secrets.json` is unaffected — 2FA credentials are independent of code updates. The client does **not** need to re-scan their authenticator.

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

## 9. Building a Windows Client Package

Windows clients need `.pyd` binaries instead of `.so`. You must run the build on a Windows machine (or Windows partition).

### Prerequisites (Windows)

1. **Python 3.10+** — download from https://python.org. During install, tick "Add Python to PATH".
2. **Visual Studio Build Tools** — download from https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Run the installer and select the **"Desktop development with C++"** workload.
   - This installs the MSVC compiler that Cython needs to produce `.pyd` files.
3. **Cython** — install inside the project after extracting the developer archive:
   ```cmd
   python -m pip install cython
   ```

### Build steps (Windows)

```cmd
REM 1. Extract cryptex_lab_developer.zip to a folder, then open Command Prompt there.

REM 2. Install dependencies
python -m pip install -r requirements.txt

REM 3. Generate keys and manifest
REM    Lock to a specific client machine:
python generate_keys.py <client-machine-id>
REM    Or for a dev/demo license (no machine locking):
python generate_keys.py --any

REM 4. Compile and package
python package.py --compiled
```

Output: `dist\cryptex_lab_client_compiled.zip` — contains `.pyd` binaries. Send this to the Windows client.

### Transferring the developer package from Linux to Windows (dual-boot)

If you are dual-booting:

1. On Linux, run `python package.py` to produce `dist/cryptex_lab_developer.zip`.
2. Copy the ZIP to a shared location (a FAT32/NTFS partition, USB drive, or shared folder both OSes can access).
3. Boot into Windows, extract the ZIP, follow the build steps above.
4. The resulting `dist\cryptex_lab_client_compiled.zip` is Windows-ready.

> **Note:** `generate_keys.py` with no arguments locks the license to whichever machine runs it.
> On Windows, run it with `--any` for testing, or with the client's machine fingerprint for production.

---

## 10. Quick Reference — Developer Commands

```bash
# Full release — compile + package (initial client delivery)
python release.py <fingerprint>

# Dev/demo release — no machine locking (internal testing)
python release.py --any

# License key only — client already has the app, needs activation key
python release.py --license-only <fingerprint>

# Get machine fingerprint of THIS machine
python machine_id.py

# Verify Cython + gcc are available
python compile_modules.py --check

# Compile the 4 security modules to native .so binaries
python compile_modules.py

# Build the production client package only (without regenerating license)
python package.py --compiled

# Build the standard (plain source) developer archive
python package.py

# Run the full test suite
python -m pytest tests/ -v
```
