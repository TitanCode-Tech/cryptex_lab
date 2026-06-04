"""
machine_id.py
-------------
Generates a stable hardware fingerprint for machine-locked licensing.

Sources used (all available offline, no root required):
  - /etc/machine-id  : unique per OS install on Linux
  - Primary MAC      : uuid.getnode() — stable on physical hardware
  - Hostname         : platform.node()

Run this script directly on the target machine and give the printed
fingerprint to your Cryptex Lab administrator when requesting a license.
"""
from __future__ import annotations

import hashlib
import platform
import uuid
from pathlib import Path


def _read_machine_id() -> str:
    for path in [Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")]:
        if path.exists():
            val = path.read_text().strip()
            if val:
                return val
    return ""


def _primary_mac() -> str:
    mac_int = uuid.getnode()
    return ":".join(f"{(mac_int >> (i * 8)) & 0xFF:02x}" for i in range(5, -1, -1))


def get_machine_fingerprint() -> str:
    """
    Return a stable SHA-256 fingerprint for this machine.
    Combines OS machine-id, primary MAC address, and hostname.
    """
    components = [
        _read_machine_id(),
        _primary_mac(),
        platform.node(),
    ]
    raw = "|".join(components)
    return hashlib.sha256(raw.encode()).hexdigest()


if __name__ == "__main__":
    fp = get_machine_fingerprint()
    print(f"\nMachine Fingerprint:\n  {fp}\n")
    print("Provide this value to your Cryptex Lab administrator when requesting a license.")
