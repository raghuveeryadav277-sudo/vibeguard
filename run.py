#!/usr/bin/env python3
"""VibeGuard entry point — started by START.bat (Windows) / start.sh."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vg_app.server import main

if __name__ == "__main__":
    main()
