"""
walletdat_utils.py
------------------
Bitcoin Core wallet.dat encrypted master key extraction and password attack.

Bitcoin Core encrypts wallet.dat using:
  - AES-256-CBC for the master key (48-byte ciphertext = 32-byte key + 16 PKCS7 pad)
  - Key derivation method 0: OpenSSL EVP_BytesToKey with SHA-512, N iterations (~25,000)
  - Key derivation method 1: scrypt (N=16384, r=8, p=8) — newer wallets
  - Stored in a Berkeley DB Btree file under the 'mkey' record

Attack speed: ~100–300 passwords/second on CPU with multiprocessing.
Compare to BIP38 (~2/s) — SHA-512 stretching is far cheaper than scrypt.

Verification method: PKCS7 padding check on the decrypted 48-byte block.
If the last 16 bytes are all 0x10, the password is correct (false-positive
probability ≈ 1/256^16 ≈ 10^-38).

SECURITY NOTES
==============
* No network calls. Nothing written to disk.
* Wallet bytes are read from caller-supplied in-memory bytes only.
* Decrypted master key is used transiently inside worker processes
  and is not returned to the caller.
"""

from __future__ import annotations

import hashlib
import multiprocessing
import struct
import time
from typing import Callable

from Crypto.Cipher import AES

# ---------------------------------------------------------------------------
# BDB Btree constants
# ---------------------------------------------------------------------------

_BDB_BTREE_MAGIC = 0x053162  # little-endian on x86
_P_LBTREE        = 5          # leaf Btree page type
_B_KEYDATA       = 1          # inline key/data item
_B_DELETE_FLAG   = 0x80       # set on deleted items

# AES-256-CBC geometry
_KEY_LEN    = 32
_IV_LEN     = 16
_MKEY_CTEXT = 48   # encrypted_master_key ciphertext length


# ---------------------------------------------------------------------------
# Pure Python BDB Btree reader
# ---------------------------------------------------------------------------

def _detect_endian(data: bytes) -> str:
    """Return '<' or '>' based on BDB magic, or raise ValueError."""
    magic_le = struct.unpack_from("<I", data, 12)[0]
    if magic_le == _BDB_BTREE_MAGIC:
        return "<"
    magic_be = struct.unpack_from(">I", data, 12)[0]
    if magic_be == _BDB_BTREE_MAGIC:
        return ">"
    raise ValueError(
        f"Not a BDB Btree file (magic={data[12:16].hex()}). "
        "Make sure you uploaded the wallet.dat database file, not a log file."
    )


def _read_page_items(page: bytes, endian: str) -> list[bytes | None]:
    """
    Extract all B_KEYDATA item payloads from a single BDB leaf page.
    Non-KEYDATA items (overflow, deleted) are returned as None.
    """
    if len(page) < 26 or page[25] != _P_LBTREE:
        return []

    n_entries = struct.unpack_from(f"{endian}H", page, 20)[0]
    items: list[bytes | None] = []

    for i in range(n_entries):
        idx_pos = 26 + i * 2
        if idx_pos + 2 > len(page):
            items.append(None)
            continue

        item_off = struct.unpack_from(f"{endian}H", page, idx_pos)[0]
        if item_off + 3 > len(page):
            items.append(None)
            continue

        item_len  = struct.unpack_from(f"{endian}H", page, item_off)[0]
        item_type = page[item_off + 2]

        if item_type & _B_DELETE_FLAG:
            items.append(None)
            continue

        if item_type == _B_KEYDATA:
            end = item_off + 3 + item_len
            items.append(bytes(page[item_off + 3: end]) if end <= len(page) else b"")
        else:
            items.append(None)

    return items


def _parse_bdb(data: bytes) -> list[tuple[bytes, bytes]]:
    """
    Parse a BDB Btree database and return all non-deleted key-value pairs.

    Parameters
    ----------
    data : bytes
        Raw wallet.dat file content.

    Returns
    -------
    list of (key_bytes, value_bytes) tuples.

    Raises
    ------
    ValueError if the data is not a valid BDB Btree file.
    """
    if len(data) < 4096:
        raise ValueError("File too small to be a valid wallet.dat")

    endian   = _detect_endian(data)
    pagesize = struct.unpack_from(f"{endian}I", data, 20)[0]

    if pagesize == 0 or pagesize & (pagesize - 1) != 0 or pagesize > 65536:
        pagesize = 4096  # safe default if metadata is corrupt

    pairs: list[tuple[bytes, bytes]] = []
    total_pages = len(data) // pagesize

    for pg in range(1, total_pages):
        page = data[pg * pagesize: pg * pagesize + pagesize]
        items = _read_page_items(page, endian)

        for i in range(0, len(items) - 1, 2):
            k, v = items[i], items[i + 1]
            if k is not None and v is not None:
                pairs.append((k, v))

    return pairs


# ---------------------------------------------------------------------------
# Bitcoin serialization helpers
# ---------------------------------------------------------------------------

def _read_compact_size(data: bytes, pos: int) -> tuple[int, int]:
    """Return (value, new_pos)."""
    if pos >= len(data):
        raise ValueError("Unexpected end of data reading compact size")
    b = data[pos]
    if b < 0xFD:
        return b, pos + 1
    if b == 0xFD:
        return struct.unpack_from("<H", data, pos + 1)[0], pos + 3
    if b == 0xFE:
        return struct.unpack_from("<I", data, pos + 1)[0], pos + 5
    return struct.unpack_from("<Q", data, pos + 1)[0], pos + 9


def _record_type(key_bytes: bytes) -> str:
    """Extract the record type string from a Bitcoin-serialized wallet.dat key."""
    try:
        type_len, pos = _read_compact_size(key_bytes, 0)
        if pos + type_len > len(key_bytes):
            return ""
        return key_bytes[pos: pos + type_len].decode("ascii", errors="ignore")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# mkey record parser
# ---------------------------------------------------------------------------

def _parse_mkey_value(value: bytes) -> dict | None:
    """
    Parse a CMasterKey value blob from wallet.dat.

    CMasterKey serialization:
      compact_size(48) + 48-byte encrypted key
      compact_size(8)  + 8-byte salt
      uint32 nDerivationMethod
      uint32 nDeriveIterations
      compact_size(len) + other_params (usually empty)
    """
    try:
        pos = 0

        enc_key_len, pos = _read_compact_size(value, pos)
        if enc_key_len != _MKEY_CTEXT or pos + _MKEY_CTEXT > len(value):
            return None
        encrypted_key = value[pos: pos + _MKEY_CTEXT]
        pos += _MKEY_CTEXT

        salt_len, pos = _read_compact_size(value, pos)
        if salt_len != 8 or pos + 8 > len(value):
            return None
        salt = value[pos: pos + 8]
        pos += 8

        if pos + 8 > len(value):
            return None
        deriv_method = struct.unpack_from("<I", value, pos)[0]; pos += 4
        n_iterations = struct.unpack_from("<I", value, pos)[0]; pos += 4

        other_params = b""
        if pos < len(value):
            other_len, pos = _read_compact_size(value, pos)
            if other_len and pos + other_len <= len(value):
                other_params = value[pos: pos + other_len]

        return {
            "encrypted_key":  encrypted_key,
            "salt":           salt,
            "deriv_method":   deriv_method,
            "n_iterations":   n_iterations,
            "other_params":   other_params,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public: wallet parsing
# ---------------------------------------------------------------------------

def extract_mkey(wallet_data: bytes) -> dict:
    """
    Parse wallet.dat bytes and extract the master encryption key record.

    Parameters
    ----------
    wallet_data : bytes
        Raw content of the wallet.dat file.

    Returns
    -------
    dict with keys:
        valid    : bool
        mkey     : dict | None   — encryption parameters (None = unencrypted)
        n_pairs  : int           — total BDB records found
        error    : str | None
    """
    try:
        pairs = _parse_bdb(wallet_data)
    except ValueError as e:
        return {"valid": False, "mkey": None, "n_pairs": 0, "error": str(e)}

    for key_bytes, value_bytes in pairs:
        if _record_type(key_bytes) == "mkey":
            mkey = _parse_mkey_value(value_bytes)
            if mkey:
                return {
                    "valid":   True,
                    "mkey":    mkey,
                    "n_pairs": len(pairs),
                    "error":   None,
                }

    # No mkey found — wallet may be unencrypted
    return {
        "valid":   True,
        "mkey":    None,
        "n_pairs": len(pairs),
        "error":   None,
    }


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _derive_key_sha512(password: bytes, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """
    OpenSSL EVP_BytesToKey with SHA-512 for AES-256 (key=32 bytes, IV=16 bytes).
    This is Bitcoin Core wallet.dat method 0.
    """
    key_material = b""
    d_i = b""
    while len(key_material) < _KEY_LEN + _IV_LEN:
        d_i = hashlib.sha512(d_i + password + salt).digest()
        for _ in range(iterations - 1):
            d_i = hashlib.sha512(d_i).digest()
        key_material += d_i
    return key_material[:_KEY_LEN], key_material[_KEY_LEN: _KEY_LEN + _IV_LEN]


def _derive_key_scrypt(
    password: bytes,
    salt: bytes,
    n: int = 16384,
    r: int = 8,
    p: int = 8,
) -> tuple[bytes, bytes]:
    """scrypt-based key derivation for wallet.dat method 1."""
    derived = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=_KEY_LEN + _IV_LEN)
    return derived[:_KEY_LEN], derived[_KEY_LEN: _KEY_LEN + _IV_LEN]


# ---------------------------------------------------------------------------
# Password verification
# ---------------------------------------------------------------------------

def _verify_password(mkey: dict, password: str) -> bool:
    """
    Try to decrypt the wallet master key with the given password.
    Returns True if PKCS7 padding is valid (password is correct).
    """
    pw = password.encode("utf-8")
    method = mkey["deriv_method"]

    try:
        if method == 0:
            key, iv = _derive_key_sha512(pw, mkey["salt"], mkey["n_iterations"])
        elif method == 1:
            n, r, p = 16384, 8, 8
            op = mkey["other_params"]
            if len(op) >= 16:
                n = struct.unpack_from("<Q", op, 0)[0]
                r = struct.unpack_from("<I", op, 8)[0]
                p = struct.unpack_from("<I", op, 12)[0]
            key, iv = _derive_key_scrypt(pw, mkey["salt"], n, r, p)
        else:
            return False

        cipher    = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(mkey["encrypted_key"])  # 48 bytes in → 48 bytes out

        # PKCS7 check: 32-byte master key padded with 16 × 0x10
        return decrypted[32:] == b"\x10" * 16

    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public: single-password test
# ---------------------------------------------------------------------------

def decrypt_wallet(mkey: dict, password: str) -> dict:
    """
    Test a single password against the wallet.dat master key.

    Returns
    -------
    dict with keys:
        success  : bool
        password : str | None
        error    : str | None
    """
    if _verify_password(mkey, password):
        return {"success": True, "password": password, "error": None}
    return {"success": False, "password": None, "error": "Wrong password"}


# ---------------------------------------------------------------------------
# Multiprocessing worker
# ---------------------------------------------------------------------------

def _worker(args: tuple) -> dict:
    """args: (mkey_dict, candidates_chunk)"""
    mkey, chunk = args
    matches: list[str] = []
    checked = 0
    for pw in chunk:
        checked += 1
        if _verify_password(mkey, pw):
            matches.append(pw)
    return {"matches": matches, "checked": checked}


# ---------------------------------------------------------------------------
# Public: dictionary attack
# ---------------------------------------------------------------------------

_MAX_MATCHES = 3
_CHUNK_SIZE  = 100  # larger than BIP38 because SHA-512 is much faster than scrypt


def attack_wallet(
    mkey: dict,
    candidates: list[str],
    progress_callback: Callable[[int, int, int], None] | None = None,
    chunk_size: int = _CHUNK_SIZE,
) -> dict:
    """
    Dictionary attack on a Bitcoin Core wallet.dat master key.

    Parameters
    ----------
    mkey              : dict from extract_mkey()["mkey"]
    candidates        : list of password strings to try
    progress_callback : called as (checked, total, matches_found)
    chunk_size        : candidates per worker task

    Returns
    -------
    dict with keys:
        matches      : list[str]
        checked      : int
        total        : int
        elapsed_time : float
        truncated    : bool
    """
    if not candidates:
        raise ValueError("candidates list is empty")

    chunks = [candidates[i: i + chunk_size] for i in range(0, len(candidates), chunk_size)]
    tasks  = [(mkey, chunk) for chunk in chunks]

    total       = len(candidates)
    all_matches: list[str] = []
    checked     = 0
    truncated   = False
    start_time  = time.time()
    num_workers = max(1, multiprocessing.cpu_count() - 1)

    with multiprocessing.Pool(num_workers) as pool:
        for res in pool.imap_unordered(_worker, tasks):
            checked += res["checked"]
            for m in res["matches"]:
                if m not in all_matches:
                    all_matches.append(m)

            if progress_callback:
                progress_callback(checked, total, len(all_matches))

            if len(all_matches) >= _MAX_MATCHES:
                truncated = True
                pool.terminate()
                break

    return {
        "matches":      all_matches,
        "checked":      checked,
        "total":        total,
        "elapsed_time": time.time() - start_time,
        "truncated":    truncated,
    }
