"""
machine_id.py
-------------
Generates a stable hardware fingerprint for machine-locked licensing.

Sources used (all available offline, no root required):
  - /etc/machine-id           : unique per OS install on Linux/desktop
  - /var/lib/dbus/machine-id  : fallback Linux path
  - ~/.cryptexlab_device_id   : stable fallback for Android/Termux where
                                /etc/machine-id is absent and MACs are
                                randomized per-network (Android 10+).
                                Generated once on first run, persists
                                across sessions for the same install.
  - Primary MAC               : uuid.getnode() — stable on desktop hardware
  - Hostname                  : platform.node()

Run this script directly on the target machine and give the printed
fingerprint to your Cryptex Lab administrator when requesting a license.
"""
from __future__ import annotations

import hashlib
import platform
import uuid
from pathlib import Path


# Persistent fallback file used when no OS machine-id is available (Android/Termux).
_FALLBACK_ID_FILE = Path.home() / ".cryptexlab_device_id"


def _read_machine_id() -> str:
    # Standard Linux paths
    for path in [Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")]:
        if path.exists():
            val = path.read_text().strip()
            if val:
                return val

    # Android/Termux fallback: read or generate a stable per-install UUID.
    # Once written it never changes for this Termux installation.
    if _FALLBACK_ID_FILE.exists():
        val = _FALLBACK_ID_FILE.read_text().strip()
        if val:
            return val

    # First run on this device — generate and persist a UUID.
    new_id = str(uuid.uuid4())
    try:
        _FALLBACK_ID_FILE.write_text(new_id)
    except OSError:
        pass  # read-only fs — fingerprint will be less stable but won't crash
    return new_id


def _primary_mac() -> str:
    mac_int = uuid.getnode()
    mac_bytes = mac_int.to_bytes(6, "big")
    # Android 10+ randomizes MACs (locally-administered bit set).
    # If the MAC looks randomized, don't include it — the stable UUID above
    # already anchors the fingerprint to this specific install.
    if mac_bytes[0] & 0x02:
        return "randomized"
    return ":".join(f"{b:02x}" for b in mac_bytes)


def get_machine_fingerprint() -> str:
    """
    Return a stable SHA-256 fingerprint for this machine/install.
    Works on Linux desktop, Termux/Android, and small Linux devices.
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
