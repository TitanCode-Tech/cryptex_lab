# CRYPTEX LAB Developer Tutorial

This guide explains how to use the `cryptex-lab` developer package. It covers packaging, testing, signing, and build integrity workflows.

## 1. Developer package contents

The developer package includes everything in the client package plus development and packaging artifacts.

Developer-only files:

- `package.py`
- `generate_keys.py`
- `private_key.pem`
- `implementation_plan.md`
- `task.md`
- `tests/`
- `.gitignore`

The developer package is intended for internal build, testing, and release workflows.

## 2. Build and package

### Create distribution archives

Run the packaging script:

```bash
python package.py
```

This produces:

- `dist/cryptex_lab_client.zip`
- `dist/cryptex_lab_developer.zip`

The client archive contains the safe runtime files. The developer archive contains the full client archive plus developer-only files and tests.

## 3. Test suite

Run the included pytest suite from the repository root:

```bash
python -m pytest tests
```

This validates the recovery engines, derivation helpers, forensic inspectors, hash utilities, and mode enforcement.

## 4. License and manifest generation

`generate_keys.py` is a developer-only helper for creating signed licensing and integrity artifacts.

It performs:

- generation of `private_key.pem` (secret developer key)
- creation of `public_key.pem`
- creation of signed `license.json`
- creation of signed `manifest.json` with file hashes

Run:

```bash
python generate_keys.py
```

## 5. Build integrity verification

The app verifies its own build integrity using `manifest.json` and a public key.

Example:

```python
from integrity import verify_build_integrity

valid, reason = verify_build_integrity()
print(valid, reason)
```

This check confirms:

- the manifest signature is valid
- every listed file still matches its SHA-256 hash

## 6. License verification

The runtime reads `license.json` and verifies it against `public_key.pem` using `license_utils.verify_license_data()`.

This allows developer distributions to control module access without shipping the secret key.

## 7. Developer workflows

### When modifying code

- Update the client runtime modules in `app.py`, `wallet_utils.py`, `recovery_utils.py`, `derivation_utils.py`, and related files.
- Keep sensitive offline-only code separated from live/network code.
- Use `tests/` to validate new recovery paths, derivations, and export safety.

### When preparing a release

1. Run `python package.py` to create fresh archives.
2. Ensure `license.json` and `manifest.json` are current.
3. Verify the runtime with `python -m pytest tests`.
4. Confirm that the client archive contains only safe runtime files.

## 8. Packaging rules

`package.py` defines two package sets:

- `CLIENT_FILES` for the safe client runtime
- `DEVELOPER_ONLY_FILES` for extra developer files

The developer ZIP includes both sets, while the client ZIP includes only `CLIENT_FILES`.

## 9. Safe developer practices

- Never include `private_key.pem` in client distributions.
- Generate signed artifacts only on trusted build machines.
- Avoid adding secret or private-key material to exporter outputs.
- Keep `TUTORIAL_CLIENT.md` in the client package and `TUTORIAL_DEVELOPER.md` in the developer-only package list.

## 10. Recommended commands

```bash
python package.py
python -m pytest tests
python generate_keys.py
```

## 11. Notes

- `TUTORIAL_CLIENT.md` is intended for end users and client package distribution.
- `TUTORIAL_DEVELOPER.md` is intended for internal developers and is added to the developer package.
