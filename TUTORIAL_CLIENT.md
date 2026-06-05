# CRYPTEX LAB — Client Setup & User Guide

Welcome to Cryptex Lab, a secure offline forensic workstation for cryptocurrency wallet recovery and analysis. This guide covers everything from first-time setup to daily use.

> **Legal notice:** Only use this tool on wallets you own or are explicitly and legally authorized to recover. All actions are permanently audit-logged.

---

## Table of Contents

1. [Before You Start — Getting Your License](#1-before-you-start--getting-your-license)
2. [What Is in Your Package](#2-what-is-in-your-package)
3. [Installation](#3-installation)
4. [Setting Up Two-Factor Authentication (2FA)](#4-setting-up-two-factor-authentication-2fa)
5. [Launching the Application](#5-launching-the-application)
6. [Understanding the Interface](#6-understanding-the-interface)
7. [Role Assignment and Elevation](#7-role-assignment-and-elevation)
8. [Working Offline — The Golden Rule](#8-working-offline--the-golden-rule)
9. [Main Tools — What Each Screen Does](#9-main-tools--what-each-screen-does)
10. [Common Workflows](#10-common-workflows)
11. [Security Practices](#11-security-practices)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Before You Start — Activating Your License

Cryptex Lab ships **without a license** — like commercial software, you activate it after installation using a license key tied to your specific machine. The application guides you through this in two short steps.

### How activation works

1. Extract the Cryptex Lab ZIP to a permanent folder  
   (e.g., `C:\CryptexLab` on Windows or `~/cryptexlab` on Linux)
2. Run the installer, then launch the app (see [Section 3](#3-installation))
3. The app shows a **LICENSE ACTIVATION** screen automatically — no terminal needed
4. On that screen, **Step 1** displays your Machine ID — copy it and send it to your Titan Code administrator
5. Your administrator will send you back:
   - A **license key** — a long `CXLAB-...` string you paste directly into the app
   - **Two-factor authentication secrets** for your assigned roles — sent via a **separate secure channel** (not in the same message as the key)
6. Back in the app, paste the `CXLAB-...` key into **Step 2** and click **Activate License**
7. The app loads immediately — no file to save, no terminal commands

> **Important:** Your license key is locked to this machine. If you move the software to a different computer, contact your administrator for a new key.

---

## 2. What Is in Your Package

When you extract `cryptex_lab_client_compiled.zip` you will see:

| File / Folder | What it is |
|---|---|
| `*.so` or `*.pyd` files | The security engine — compiled native binaries (not plain Python) |
| `app.py`, `modes.py`, etc. | Application logic and user interface |
| `manifest.json` | Cryptographic signature of the application files (pre-shipped) |
| `manifest.json` | Cryptographic signature of the application files — do not modify |
| `public_key.pem` | Verification key for the license and manifest |
| `requirements.txt` | Python package list for the installer |
| `assets/` | Icons and interface assets |
| `.streamlit/` | Application configuration |
| `install.py / .sh / .bat` | Installer for your platform |
| `uninstall.py / .sh / .bat` | Uninstaller |
| `TUTORIAL_CLIENT.md` | This file |

---

## 3. Installation

### Requirements

- **Python 3.10 or newer** — check with `python --version` or `python3 --version`
- **Internet access during installation only** — needed once to download Python packages; the application itself runs fully offline afterwards

### Linux / macOS

Open a terminal in the Cryptex Lab folder:

```bash
./install.sh
```

or:

```bash
python install.py
```

### Windows

Double-click `install.bat`, or run in Command Prompt:

```cmd
install.bat
```

### What the installer does

1. Verifies Python 3.10+
2. Creates a local virtual environment (`venv/`) inside the application folder
3. Downloads and installs all dependencies from `requirements.txt` — this is the **only step that touches the internet**
4. Creates a desktop shortcut to launch the app

After this, the application runs fully offline. You may disconnect from the internet.

### Air-gapped installation (no internet on the workstation)

If your workstation is network-isolated:

1. On a machine **with** internet access, extract the ZIP and run `python install.py` to populate the `venv/` folder
2. Copy the **entire** Cryptex Lab folder (including `venv/`) to the air-gapped workstation via USB drive
3. On the air-gapped workstation, run:
   ```bash
   python install.py --skip-deps
   ```
   This creates the desktop shortcut without running pip.

---

## 4. Setting Up Two-Factor Authentication (2FA)

Cryptex Lab uses **offline TOTP 2FA** to protect elevated roles (Senior Analyst and Admin). The app guides you through setup automatically on first launch — no secrets are sent by your administrator, and no files need to be transferred.

### Step 1 — Install an authenticator app

Before running setup, install any standard TOTP authenticator on your smartphone:

| App | Platform | Notes |
|---|---|---|
| **Aegis Authenticator** | Android | Open source, local encrypted backup |
| **2FAS** | iOS / Android | Open source, no account required |
| **Google Authenticator** | iOS / Android | Simple, widely supported |
| **Microsoft Authenticator** | iOS / Android | Enterprise-friendly |

All of these work **fully offline** — your phone never connects to any server during use.

### Step 2 — Complete in-app setup

After activating your license, the app shows a **Security Setup** screen automatically.

1. The screen shows a QR code for the **Senior Analyst** role — scan it with your authenticator app
2. Enter the 6-digit code from your app to confirm the scan worked, then click **Confirm**
3. Repeat for the **Admin** role
4. Click **Save & Launch** — setup is complete and the app opens

The 2FA secrets are generated on your machine and stored only in `totp_secrets.json` on this workstation. They are never sent to anyone and cannot be recovered from outside the machine.

### Step 3 — Using 2FA day to day

Your authenticator app shows a 6-digit code for each role that changes every 30 seconds. When you switch to Senior Analyst or Admin in the sidebar, a dialog appears asking for the current code.

> **Your 2FA is yours.** Only you control the secrets — your administrator cannot generate codes for your roles. If you lose your authenticator device, contact your administrator to reset TOTP setup for this workstation.

---

## 5. Launching the Application

### Via desktop shortcut

A shortcut is created during installation. Double-click it to launch.

### Via terminal

```bash
python launcher.py
```

Or directly:

```bash
source venv/bin/activate          # Windows: venv\Scripts\activate
streamlit run app.py
```

The application opens in your default browser at `http://localhost:8501`. Everything runs locally — no data is sent over the network in Offline Safe mode.

---

## 6. Understanding the Interface

### Sidebar (left panel)

| Element | What it does |
|---|---|
| **OFFLINE SAFE / LIVE ANALYSIS** indicator | Shows the current operating mode |
| **LICENSE ACTIVE** badge | Confirms your license is valid and bound to this machine |
| **ROLE ASSIGNMENT** dropdown | Your current role — protected roles require 2FA to activate |
| **Navigation links** | Access to all tools permitted by your role |

### Header

Shows the application name, current case (if one is active), and mode status.

### Main content area

Displays whichever tool or page you have navigated to. When you elevate your role, the main area is temporarily replaced by the 2FA verification screen.

### Audit log

Every action you take — module access, role changes, authorization events — is permanently recorded in `audit_logs/audit.jsonl`. This file is append-only and cannot be edited or cleared from within the application.

---

## 7. Role Assignment and Elevation

Four roles are available, each granting access to a different set of tools:

| Role | Access |
|---|---|
| **Viewer** | Read-only: landing page, case list, evidence hashing, educational content |
| **Analyst** | Standard tools: all recovery tools, address generation, export |
| **Senior Analyst** | Advanced: passphrase testing, incomplete seed recovery, vault inspection |
| **Admin** | Full access to all tools |

The default role on first launch is **Analyst**.

### Switching to a higher role (2FA required)

1. Click the **ROLE ASSIGNMENT** dropdown in the sidebar and select the desired role
2. The main content area replaces with the **2FA Verification** screen
3. Open your authenticator app and find the `Cryptex Lab – [Role]` entry
4. Enter the current 6-digit code and click **VERIFY & ELEVATE ROLE**

Codes rotate every 30 seconds. If you enter the wrong code 3 times in a row, the form locks for 30 seconds before you can try again. Every attempt — success or failure — is written to the audit log.

### Switching to a lower role

Switching from a higher role to a lower one (e.g., Admin → Analyst) does not require 2FA. It takes effect immediately and resets your session authorization state.

---

## 8. Working Offline — The Golden Rule

**Always be in OFFLINE SAFE mode when working with seed phrases, mnemonics, or private keys.**

| Mode | Colour | What is available |
|---|---|---|
| **OFFLINE SAFE** | Green | All recovery and forensic tools; network access blocked at the application level |
| **LIVE ANALYSIS** | Red | Public blockchain lookups (address balances, transaction history); all seed-related tools locked |

Switch modes using the button at the top of the sidebar. The mode indicator is always visible.

**Best practice:** Physically disconnect your network cable or disable Wi-Fi before pasting any real secret into the application — do not rely solely on software mode enforcement.

---

## 9. Main Tools — What Each Screen Does

**Recovery Problem Selector** — guides you to the correct recovery tool for your situation. Start here if you are unsure.

**Case Management** — create and manage case records with metadata. A case must be active before you can use recovery tools.

**Evidence Hash Checker** — calculate SHA-256, SHA-512, MD5, and other hashes for evidence files. Only the hash is stored, never the file content.

**BIP39 Validation Lab** — verify a seed phrase is correctly formed (word count, wordlist, checksum) before attempting recovery.

**Incomplete Seed Recovery** — recover a phrase with one or two missing words. Replace unknown words with `?` and optionally provide a known wallet address to narrow down candidates.

**Typo Correction Lab** — find the correct BIP39 word for a misspelling (e.g., `abandoon` → `abandon`).

**Wrong Word Order Helper** — recover the correct phrase when you have all the words but the order is uncertain. Specify which positions to permute.

**BIP39 Passphrase Testing** — test a list of candidate passphrases against a known wallet address to find which one was used.

**Derivation Path Scanner** — derive ETH and BTC addresses from standard paths (BIP44, BIP49, BIP84, etc.) and compare with a known address.

**Known Address Matcher** — given a mnemonic and a wallet address, find the derivation path and address type that matches.

**ETH / BTC Address Generator** — derive public addresses from a valid mnemonic. Safe because addresses are public information.

**Entropy Analysis Lab** — measure the randomness of a byte sequence to determine whether it could be wallet-related material.

**MetaMask Vault Inspector** — inspect MetaMask vault JSON metadata (format, version) without attempting decryption.

**Hash / Crypto Tools** — general-purpose helpers: SHA-256, SHA-512, MD5, Base58, Base64, hex conversions, and more.

**Recovery Report Exporter** — export results as PDF, TXT, CSV, or QR code. Only public data (wallet addresses, derivation paths) can appear in exports — seed phrases are automatically blocked.

**Live Address / TX Lookup** — (LIVE ANALYSIS mode only) query public blockchain APIs for address balances and transaction details.

---

## 10. Common Workflows

### Validate a seed phrase before recovery

1. Navigate to **BIP39 Validation Lab**
2. Paste the phrase
3. Review the report — word count, checksum, wordlist membership
4. If valid, proceed to the appropriate recovery tool

### Recover a phrase with one missing word

1. Confirm you are in **OFFLINE SAFE** mode
2. Open **Case Management** and create or activate a case
3. Navigate to **Incomplete Seed Recovery** and complete the authorization form
4. Enter the phrase with `?` where the word is missing — e.g.:  
   `abandon ? abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
5. Optionally enter a known wallet address to filter results
6. Click **Recover** and review the candidates

### Confirm a wallet address from a mnemonic

1. Navigate to **Known Address Matcher** (Analyst role or above)
2. Paste the full mnemonic
3. Enter the wallet address you want to confirm
4. Click **Search** — all standard derivation paths are checked automatically
5. The result shows the matching path and address type

### Export a case report

1. Complete your recovery or derivation work and note the results
2. Navigate to **Recovery Report Exporter**
3. Enter the relevant public addresses and paths
4. Add case notes (case ID, investigator name, date)
5. Download as PDF, TXT, or CSV

---

## 11. Security Practices

- **Never paste a real seed phrase while in LIVE ANALYSIS mode.** The mode switch locks all seed-handling screens, but as a physical discipline: keep secrets off the clipboard and off the screen whenever the network is active.
- **Do not share your authenticator app entries** with colleagues. The 2FA secrets are tied to this workstation — each authorized user who needs elevated roles should complete their own setup on their own device. Contact your administrator to reset TOTP if a device is lost or replaced.
- **Do not take screenshots of seed phrases.** Use the built-in export tools for official records.
- **Lock your workstation** when stepping away. Your session remains active in the browser tab.
- **The audit log is permanent.** Every role change, access event, and authorization acknowledgement is written to `audit_logs/audit.jsonl` and cannot be modified from within the application.

---

## 12. Troubleshooting

### "MACHINE AUTHORIZATION FAILURE"
Your license key was issued for a different machine. Open the app — it will show your current Machine ID on the activation screen. Send it to your administrator and ask for a new license key.

### "LICENSE INACTIVE" or activation screen on every launch
The license file is missing, expired, or has been tampered with. Contact your administrator for a new `CXLAB-...` license key and re-activate via the in-app activation screen.

### "CRITICAL: Build Integrity Check Failed"
One or more application files have been modified since the build was signed. Do not continue — contact your administrator immediately to receive a verified replacement package.

### TOTP code is not accepted
- Check that your phone's clock is accurate. TOTP is time-based; a clock more than 30 seconds off will produce wrong codes. Enable automatic time sync on your phone.
- Make sure you are using the correct authenticator entry (`Cryptex Lab – Senior Analyst` or `Cryptex Lab – Admin`, matching the role you are elevating to).
- After 3 failed attempts, wait 30 seconds for the lockout to expire, then try again.

### The app does not open in the browser
Run `python launcher.py` in a terminal and look for error messages. Ensure the venv was created and dependencies were installed by rerunning `python install.py`.

### Dependency installation fails on an air-gapped machine
Use the sneakernet method: install on an online machine, copy the entire folder including `venv/`, then run `python install.py --skip-deps` on the air-gapped machine. See [Section 3](#3-installation) for details.

### I reinstalled the operating system — will my license still work?
Reinstalling the OS changes the hardware fingerprint, so the existing license key will no longer match. Launch the app — it will show the activation screen with your new Machine ID. Send it to your administrator to receive an updated license key.
