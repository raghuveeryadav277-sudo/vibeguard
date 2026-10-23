#!/bin/sh
# VibeGuard launcher for Linux/macOS (the laptop uses START.bat).
cd "$(dirname "$0")" || exit 1
exec python3 run.py
