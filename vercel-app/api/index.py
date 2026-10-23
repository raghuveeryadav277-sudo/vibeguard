"""Vercel serverless entry point for VibeGuard.

Vercel's filesystem is read-only except /tmp, so sessions/settings/cache
live under /tmp (set before importing the app). The app's own HTTP handler
is reused as-is; only the bundled demo scan is meaningful here (the big
scanner binaries — gitleaks / osv-scanner — cannot run on Vercel, so the
built-in rules engine does the scanning, exactly like the offline mode).
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("VG_DATA_DIR", "/tmp/vg-data")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vg_app.server import Handler as _VgHandler  # noqa: E402


class handler(_VgHandler):
    """Vercel entrypoint — defined in this file for Vercel's checker."""

    pass
