"""
hash_utils.py
-------------
Offline hash and crypto conversion features for the forensic lab.

Provides simple hashing (SHA256, SHA512, MD5, RIPEMD160), base encoding,
and unit conversions. Everything runs strictly locally.
"""

from __future__ import annotations

import base64
import hashlib

# pycryptodome provides RIPEMD160 which is not guaranteed in standard library hashlib
from Crypto.Hash import RIPEMD160

# ---------------------------------------------------------------------------
# Hashing functions
# ---------------------------------------------------------------------------

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def calculate_sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()

def calculate_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def calculate_sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def calculate_ripemd160(data: bytes) -> str:
    ripemd = RIPEMD160.new()
    ripemd.update(data)
    return ripemd.hexdigest()

def calculate_hash160(data: bytes) -> str:
    """Bitcoin's HASH160: RIPEMD160(SHA256(data))"""
    sha_digest = hashlib.sha256(data).digest()
    return calculate_ripemd160(sha_digest)

def calculate_double_sha256(data: bytes) -> str:
    """Bitcoin's hash256: SHA256(SHA256(data))"""
    first_pass = hashlib.sha256(data).digest()
    return hashlib.sha256(first_pass).hexdigest()

# ---------------------------------------------------------------------------
# Encoding / Decoding functions
# ---------------------------------------------------------------------------

def hex_to_bytes(hex_str: str) -> bytes:
    """Safely convert hex string to bytes, ignoring whitespace/prefixes."""
    clean = hex_str.strip().replace("0x", "").replace(" ", "").replace("\n", "")
    try:
        return bytes.fromhex(clean)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {str(e)}")

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def b64_to_bytes(b64_str: str) -> bytes:
    try:
        return base64.b64decode(b64_str, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid Base64 string: {str(e)}")

def bytes_to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

# Basic Base58 dictionary
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def encode_base58(b: bytes) -> str:
    """Standard Base58 encoding without checksum."""
    n = int.from_bytes(b, byteorder="big")
    if n == 0:
        return B58_ALPHABET[0] * len(b)
    
    result = ""
    while n > 0:
        n, mod = divmod(n, 58)
        result = B58_ALPHABET[mod] + result
        
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
            
    return (B58_ALPHABET[0] * pad) + result

def decode_base58(s: str) -> bytes:
    """Standard Base58 decoding."""
    n = 0
    for char in s:
        idx = B58_ALPHABET.find(char)
        if idx == -1:
            raise ValueError(f"Invalid Base58 character: '{char}'")
        n = n * 58 + idx
        
    if n == 0:
        return b"\x00" * len(s)
        
    # Convert integer to bytes
    b = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    
    # Prepend leading zeros
    pad = 0
    for char in s:
        if char == B58_ALPHABET[0]:
            pad += 1
        else:
            break
            
    return (b"\x00" * pad) + b

# ---------------------------------------------------------------------------
# Unit Conversions
# ---------------------------------------------------------------------------

def satoshi_to_btc(satoshis: int) -> str:
    if not isinstance(satoshis, int):
        raise TypeError("Satoshis must be an integer")
    btc = satoshis / 100_000_000
    return f"{btc:.8f}".rstrip('0').rstrip('.') if '.' in f"{btc:.8f}" else f"{btc:.8f}"

def wei_to_eth(wei: int) -> str:
    if not isinstance(wei, int):
        raise TypeError("Wei must be an integer")
    eth = wei / 10**18
    # Use format to avoid scientific notation on small amounts
    formatted = f"{eth:.18f}".rstrip('0').rstrip('.')
    return formatted if formatted else "0"
