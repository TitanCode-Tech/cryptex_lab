"""
security_utils.py
-----------------
Enforcement and auditing for the air-gapped security model.

This module provides tools to verify that sensitive offline modules
never accidentally import networking libraries (requests, socket, etc.).
"""

from __future__ import annotations

import sys
from typing import Set

# A strict list of library names (and submodules) that are absolutely
# banned from being loaded when the process is acting exclusively
# as an offline tool.
BANNED_NETWORK_MODULES: Set[str] = {
    "requests",
    "urllib3",
    "http",
    "socket",
    "aiohttp",
    "httpx",
    "web3",
    "eth_tester",       # Can pull in remote dependencies
    "bitcoinlib",       # Relies on internet sqlite dbs frequently
    "telemetry",
    "analytics"
}

def audit_sys_modules() -> list[str]:
    """
    Scan sys.modules right now to see if any forbidden networking
    packages have been imported into the python process.
    
    Returns a list of the fully-qualified names of any banned modules found.
    """
    loaded = sys.modules.keys()
    violations: list[str] = []
    
    for mod_name in loaded:
        # Check against root packages. e.g. "urllib3.connectionpool"
        # should fail if "urllib3" is banned.
        root_pkg = mod_name.split(".")[0]
        
        # We handle "http" explicitly since it's a built-in that might be
        # brought in by valid modules like Streamlit. But for our *custom*
        # modules, we statically parse imports. The runtime check here is
        # a secondary defense line, largely useful in test suites to prove
        # that importing wallet_utils, recovery_utils, etc. keeps a clean slate.
        
        if root_pkg in BANNED_NETWORK_MODULES:
            # We exempt base 'http' if running under streamlit because Streamlit
            # itself serves an HTTP server. We only care if *our* recovery scripts
            # import it. So this function is mainly a test-suite helper.
            violations.append(mod_name)
            
    return sorted(violations)


def wipe_session_state(st) -> None:
    """
    Iterate over Streamlit's session_state and delete everything.
    Used for the 'Clear Session' safe-wipe button.
    """
    for key in list(st.session_state.keys()):
        del st.session_state[key]
