"""
case_utils.py
-------------
Case management and evidence tracking for the offline lab.

All data resides strictly in memory (Streamlit's session_state)
and is destroyed when the application restarts or the user clears it.
NEVER persists to disk.
"""

from __future__ import annotations

import streamlit as st
from datetime import datetime, timezone
import hashlib
from typing import Dict, List, Any

# Session state keys
CASE_REGISTRY_KEY = "_case_registry"
ACTIVE_CASE_KEY = "_active_case_id"


def init_case_registry() -> None:
    if CASE_REGISTRY_KEY not in st.session_state:
        st.session_state[CASE_REGISTRY_KEY] = {}
    if ACTIVE_CASE_KEY not in st.session_state:
        st.session_state[ACTIVE_CASE_KEY] = None


def create_case(
    case_name: str,
    investigator: str,
    chain: str,
    description: str = "",
) -> str:
    """Create a new case in memory."""
    init_case_registry()
    
    if not case_name.strip():
        raise ValueError("Case name cannot be empty.")
        
    case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    
    st.session_state[CASE_REGISTRY_KEY][case_id] = {
        "id": case_id,
        "name": case_name.strip(),
        "investigator": investigator.strip(),
        "chain": chain,
        "description": description.strip(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evidence": []
    }
    
    # Auto-activate the newly created case
    set_active_case(case_id)
    return case_id


def get_all_cases() -> List[Dict[str, Any]]:
    init_case_registry()
    cases = list(st.session_state[CASE_REGISTRY_KEY].values())
    # Sort newest first
    return sorted(cases, key=lambda c: c["created_at"], reverse=True)


def set_active_case(case_id: str | None) -> None:
    init_case_registry()
    if case_id is not None and case_id not in st.session_state[CASE_REGISTRY_KEY]:
        raise ValueError(f"Unknown case ID: {case_id}")
    st.session_state[ACTIVE_CASE_KEY] = case_id


def get_active_case() -> Dict[str, Any] | None:
    init_case_registry()
    active_id = st.session_state[ACTIVE_CASE_KEY]
    if active_id:
        return st.session_state[CASE_REGISTRY_KEY].get(active_id)
    return None


# ---------------------------------------------------------------------------
# Evidence Hashing
# ---------------------------------------------------------------------------

def calculate_evidence_hash(file_bytes: bytes) -> Dict[str, str]:
    """Calculate the MD5, SHA-1, and SHA-256 for chain of custody."""
    if not isinstance(file_bytes, bytes):
        raise TypeError("file_bytes must be bytes")
        
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
        "size_bytes": str(len(file_bytes))
    }

def add_evidence_to_active_case(
    filename: str,
    file_bytes: bytes,
    notes: str = ""
) -> None:
    """Hash files and record metadata to the active case without storing the file."""
    active_case = get_active_case()
    if not active_case:
        raise RuntimeError("No active case to attach evidence to.")
        
    hashes = calculate_evidence_hash(file_bytes)
    
    evidence_record = {
        "filename": filename.strip(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "notes": notes.strip(),
        **hashes
    }
    
    active_case["evidence"].append(evidence_record)
