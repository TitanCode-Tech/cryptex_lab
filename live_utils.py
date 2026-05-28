"""
live_utils.py
-------------
LIVE NETWORK UTILITIES.

This is the strictly sandboxed module for live blockchain queries.
It MUST import `requests` and interacts with public APIs (Blockstream/Mempool.space).
It employs the @require_live guard decorator from modes.py to ensure
it is never executed while the application is in OFFLINE SAFE mode.
"""

from __future__ import annotations

import time
from typing import Dict, Any, List

import requests

from modes import require_live

# API configuration
# We use public, no-auth endpoints to completely avoid API keys/secrets setup.
BTC_API_BASE = "https://blockstream.info/api"
ETH_API_BASE = "https://api.etherscan.io/api" # Public, tightly rate-limited but no key needed for simple queries
MEMPOOL_API_BASE = "https://mempool.space/api"

# Basic rate limit mitigation for local calls
_LAST_CALL_TIME = 0.0

def _rate_limit() -> None:
    """Prevent spamming public APIs; minimum 1s wait."""
    global _LAST_CALL_TIME
    now = time.time()
    diff = now - _LAST_CALL_TIME
    if diff < 1.0:
        time.sleep(1.0 - diff)
    _LAST_CALL_TIME = time.time()


@require_live
def lookup_btc_address(address: str) -> Dict[str, Any]:
    """Look up a Bitcoin address balance and stats via Blockstream."""
    if not address.strip():
        raise ValueError("Address cannot be empty.")
    
    _rate_limit()
    
    url = f"{BTC_API_BASE}/address/{address.strip()}"
    
    try:
        resp = requests.get(url, timeout=10)
        
        if resp.status_code == 400:
            raise ValueError(f"Invalid BTC Address: {address}")
        resp.raise_for_status()
        
        data = resp.json()
        stats = data.get("chain_stats", {})
        
        # Calculate derived metrics
        funded = stats.get("funded_txo_sum", 0)
        spent = stats.get("spent_txo_sum", 0)
        balance = funded - spent
        
        return {
            "address": address,
            "chain_stats": stats,
            "balance_satoshi": balance,
            "tx_count": stats.get("tx_count", 0)
        }
        
    except requests.RequestException as e:
        raise RuntimeError(f"API request failed: {str(e)}")


@require_live
def lookup_btc_transaction(txid: str) -> Dict[str, Any]:
    """Look up a specific Bitcoin transaction via Blockstream."""
    txid = txid.strip()
    if not txid or len(txid) != 64:
        raise ValueError("Invalid transaction ID format.")
        
    _rate_limit()
    
    url = f"{BTC_API_BASE}/tx/{txid}"
    
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404:
            raise ValueError(f"Transaction not found: {txid}")
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        raise RuntimeError(f"API request failed: {str(e)}")


@require_live
def get_mempool_fees() -> Dict[str, int]:
    """Get recommended Bitcoin network fees via Mempool.space."""
    _rate_limit()
    
    url = f"{MEMPOOL_API_BASE}/v1/fees/recommended"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json() # Contains fastestFee, halfHourFee, hourFee, economyFee, minimumFee
    except requests.RequestException as e:
        raise RuntimeError(f"API request failed: {str(e)}")


@require_live
def lookup_eth_address(address: str) -> Dict[str, Any]:
    """Look up an Ethereum address balance via Etherscan."""
    address = address.strip()
    if not address.startswith("0x") or len(address) != 42:
        raise ValueError("Invalid Ethereum address format.")
        
    _rate_limit()
    
    # Intentionally public, heavily rate limited but reliable enough for simple tests
    url = f"{ETH_API_BASE}?module=account&action=balance&address={address}&tag=latest"
    
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        
        if data.get("status") == "1":
            return {
                "address": address,
                "balance_wei": int(data.get("result", 0))
            }
        elif data.get("status") == "0":
             raise RuntimeError(f"Etherscan error: {data.get('message', 'Unknown error')}")
        else:
             raise RuntimeError("Invalid response from Etherscan API")
            
    except requests.RequestException as e:
        raise RuntimeError(f"API request failed: {str(e)}")
