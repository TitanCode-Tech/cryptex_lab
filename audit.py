import json
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path("audit_logs")

# Redacted indicators for sensitive information
REDACT_WORDS = {
    "seed", "mnemonic", "private", "key", "password", "passphrase", "secret", "phrase"
}

def clean_event_value(value: str) -> str:
    """
    Sanitize log values to prevent accidental leakage of sensitive keys or seeds.
    """
    if not isinstance(value, str):
        return str(value)
        
    lower_val = value.lower()
    
    # Check if value looks like a BIP39 mnemonic (usually 12-24 words from the English BIP39 list)
    # Or matches secret keywords
    for word in REDACT_WORDS:
        if word in lower_val:
            return "[REDACTED_SECRET]"
            
    # Simple check for hex private keys (e.g. 64-char hex strings)
    if len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value):
        return "[REDACTED_HEX_KEY]"
        
    # Check if there are 12 or more space-separated words (a common mnemonic signature)
    if len(value.split()) >= 12:
        return "[REDACTED_SEED_PHRASE]"
        
    return value

def log_event(case_id: str, module: str, action: str, role: str, mode: str, export_actions: str | None = None) -> None:
    """
    Creates a local forensic log entry in JSONL format without storing secrets.
    
    Parameters:
        case_id: The ID of the current case.
        module: The name of the module used.
        action: The description of the action performed.
        role: The role of the user (e.g., Viewer, Analyst, Senior Analyst, Admin).
        mode: The global mode ('OFFLINE_SAFE' or 'LIVE_ANALYSIS').
        export_actions: Optional actions related to report exports.
    """
    # Ensure logs folder exists
    LOG_DIR.mkdir(exist_ok=True)
    
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "case_id": clean_event_value(case_id),
        "module": clean_event_value(module),
        "action": clean_event_value(action),
        "role": clean_event_value(role),
        "mode": clean_event_value(mode)
    }
    
    if export_actions:
        entry["export_actions"] = clean_event_value(export_actions)
        
    with open(LOG_DIR / "audit.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
