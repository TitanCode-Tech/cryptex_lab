"""
demo_data.py
------------
Public test vectors for the Cryptex Lab demo flows.

Every constant here is a published BIP39 test vector or a public
blockchain landmark address. Nothing in this file represents real
funds owned by anyone using the lab. These values are safe to commit
and safe to display in screenshots.

Sources:
- BIP39 spec test vectors (Trezor)
- iancoleman.io/bip39 reference implementation
- bitcoin.org block 0 coinbase
"""

from __future__ import annotations

DEMO_MNEMONIC_ABANDON: str = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

DEMO_ETH_FIRST_ADDRESS: str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

DEMO_BTC_BECH32_FIRST: str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

DEMO_BTC_LEGACY_FIRST: str = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"

DEMO_PARTIAL_MNEMONIC: str = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon ?"
)

# Satoshi's genesis-coinbase address — useful for live-mode lookup demos.
DEMO_BTC_ADDRESS: str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf3C"

DEMO_CASE: dict = {
    "name": "Demo Recovery",
    "investigator": "demo_analyst",
    "chain": "Bitcoin",
    "description": (
        "Sample case using BIP39 test vector — no real funds involved."
    ),
}

__all__ = [
    "DEMO_MNEMONIC_ABANDON",
    "DEMO_ETH_FIRST_ADDRESS",
    "DEMO_BTC_BECH32_FIRST",
    "DEMO_BTC_LEGACY_FIRST",
    "DEMO_PARTIAL_MNEMONIC",
    "DEMO_BTC_ADDRESS",
    "DEMO_CASE",
]
