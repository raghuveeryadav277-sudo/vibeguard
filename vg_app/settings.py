"""Settings (local only) for VibeGuard. The Gemini API key lives ONLY in
data/settings.json on the user's own machine. It is never hardcoded,
never printed, never included in reports or logs.
"""

import json
import os
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = APP_DIR / "data"
SETTINGS_FILE = DATA_DIR / "settings.json"

DEFAULTS = {
    "gemini_api_key": "",
    "gemini_model": "gemini-2.0-flash",
    "gemini_base_url": "https://generativelanguage.googleapis.com",
}


def load_settings():
    s = dict(DEFAULTS)
    try:
        if SETTINGS_FILE.exists():
            stored = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            s.update({k: v for k, v in stored.items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    # Environment overrides (used by automated tests with a mock server).
    if os.environ.get("VIBEGUARD_GEMINI_API_KEY"):
        s["gemini_api_key"] = os.environ["VIBEGUARD_GEMINI_API_KEY"]
    if os.environ.get("VIBEGUARD_GEMINI_BASE_URL"):
        s["gemini_base_url"] = os.environ["VIBEGUARD_GEMINI_BASE_URL"]
    if os.environ.get("VIBEGUARD_GEMINI_MODEL"):
        s["gemini_model"] = os.environ["VIBEGUARD_GEMINI_MODEL"]
    return s


def save_settings(new_values):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    current = {}
    try:
        if SETTINGS_FILE.exists():
            current = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        current = {}
    for k in DEFAULTS:
        if k in new_values:
            current[k] = new_values[k]
    SETTINGS_FILE.write_text(json.dumps(current, indent=2), encoding="utf-8")
    return load_settings()


def has_key():
    return bool(load_settings()["gemini_api_key"].strip())
