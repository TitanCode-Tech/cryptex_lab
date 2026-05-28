"""
modes.py
--------
Global mode management for CRYPTEX LAB.

The application operates in exactly one of two modes:
    1. OFFLINE_SAFE  (the default)
    2. LIVE_ANALYSIS (strictly opt-in via UI)

These are managed via Streamlit session state. This module provides
utility decorators that wrap functions in both core python and UI code
to rigidly enforce that a live-mode utility never runs accidentally
while the user thinks they are safe, and vice-versa.
"""

from __future__ import annotations

import functools

import streamlit as st

MODE_KEY = "_global_mode"

# Valid mode constants
OFFLINE_SAFE = "OFFLINE_SAFE"
LIVE_ANALYSIS = "LIVE_ANALYSIS"


def init_mode() -> None:
    """Initialise the session mode if it is missing."""
    if MODE_KEY not in st.session_state:
        st.session_state[MODE_KEY] = OFFLINE_SAFE


def get_current_mode() -> str:
    """Read the current mode string, defaulting to OFFLINE_SAFE."""
    return st.session_state.get(MODE_KEY, OFFLINE_SAFE)


def set_mode(mode: str) -> None:
    """Strictly set the global mode."""
    if mode not in (OFFLINE_SAFE, LIVE_ANALYSIS):
        raise ValueError(f"Invalid mode: {mode}")
    st.session_state[MODE_KEY] = mode


def is_offline() -> bool:
    return get_current_mode() == OFFLINE_SAFE


def is_live() -> bool:
    return get_current_mode() == LIVE_ANALYSIS


# ---------------------------------------------------------------------------
# Execution Guards (Decorators)
# ---------------------------------------------------------------------------

def require_offline(func):
    """
    Decorator for sensitive functions (seed phrase recovery, private key derivation)
    or UI pages that MUST ONLY be executed when the app is in the OFFLINE SAFE mode.
    Raises RuntimeError if called in live mode.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not is_offline():
            raise RuntimeError(
                f"SECURITY VIOLATION: '{func.__name__}' requires OFFLINE SAFE mode "
                "but was called in live mode. Execution blocked."
            )
        return func(*args, **kwargs)
    return wrapper


def require_live(func):
    """
    Decorator for network-enabled functions (blockchain API lookups) or UI pages
    that MUST ONLY be executed when the user has explicitly verified they are
    operating via a live network connection without secrets.
    Raises RuntimeError if called in offline mode.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not is_live():
            raise RuntimeError(
                f"MODE VIOLATION: '{func.__name__}' requires LIVE ANALYSIS "
                "mode but the application is offline."
            )
        return func(*args, **kwargs)
    return wrapper
