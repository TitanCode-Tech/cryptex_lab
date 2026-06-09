# Cryptex Lab — Termux (Android) Installation Guide

## Requirements
- Android 10 or later
- Termux (install from F-Droid, **not** the Play Store version)
- At least 2 GB free storage

---

## Step 1 — Install Termux dependencies

Open Termux and run:

```bash
pkg update && pkg upgrade -y
pkg install -y python git libsecp256k1 libjpeg-turbo zlib openssl clang make
pip install --upgrade pip setuptools wheel
```

---

## Step 2 — Copy the ZIP to your phone

Transfer `cryptex_lab_client.zip` to your phone (USB, Telegram, email, etc.) and note the path. Example if saved to Downloads:

```
/sdcard/Download/cryptex_lab_client.zip
```

---

## Step 3 — Extract and install

```bash
# Give Termux storage access (one-time)
termux-setup-storage

# Extract the ZIP
cd ~
unzip /sdcard/Download/cryptex_lab_client.zip -d cryptex_lab
cd cryptex_lab

# Install Python dependencies
pip install -r requirements.txt
```

If `coincurve` fails to build, run:
```bash
pkg install -y libsecp256k1
COINCURVE_IGNORE_SYSTEM_LIB=1 pip install coincurve
```

---

## Step 4 — Get your Machine ID (for license activation)

```bash
python machine_id.py
```

Copy the fingerprint shown and send it to your administrator to receive your license key.

---

## Step 5 — Activate and run

```bash
streamlit run app.py --server.port 8501 --server.headless true
```

Then open your phone browser and go to:
```
http://localhost:8501
```

Paste your license key on the activation screen when prompted.

---

## Notes

- The first time you run `machine_id.py` it creates a file at `~/.cryptexlab_device_id` — this anchors your license to this Termux installation. **Do not delete that file** or you will need a new license key.
- If you reinstall Termux or clear its data, a new license key will be required.
- Recovery with 1 missing word completes in seconds. Recovery with 2 missing words is slower on mobile — provide at least the first few characters of your wallet address for fast results.
