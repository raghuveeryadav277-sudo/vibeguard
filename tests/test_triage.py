#!/usr/bin/env python3
"""Triage layer tests:
1. Mock Gemini endpoint -> triage() must return source 'gemini' and use
   the mock's explanation / adjusted severity / dedupe fields.
2. Second identical call -> source 'cache' (offline demo safety net).
3. No API key -> source 'offline', deterministic explanations.
Run: python3 tests/test_triage.py   (no network needed)
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP))

CANNED = {
    "candidates": [{
        "content": {"parts": [{"text": json.dumps({
            "findings": [
                {"index": 0,
                 "explanation": "MOCK: somebody left the master key of the whole database inside the public website code.",
                 "severity_final": "critical",
                 "rationale": "MOCK rationale: full database access, no login needed.",
                 "fix_steps": ["Move the key to a server environment variable.",
                                "Rotate the key in the Supabase dashboard."],
                 "duplicate_of": None},
                {"index": 1,
                 "explanation": "MOCK: the database door is wide open to the whole internet.",
                 "severity_final": "high",
                 "rationale": "MOCK rationale: serious, but needs the app URL to exploit.",
                 "fix_steps": ["Turn Row Level Security on."],
                 "duplicate_of": None},
            ]})}]}
    }]
}

seen = {"auth_header": None, "path": None}


class Stub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        seen["path"] = self.path
        seen["auth_header"] = self.headers.get("x-goog-api-key")
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        body = json.dumps(CANNED).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    # Hermetic: clear any pre-existing triage cache (caches are keyed by
    # findings hash, so a previous run would be served before the stub).
    cache_dir = APP / "cache"
    for old in cache_dir.glob("triage_*.json"):
        old.unlink()

    stub = HTTPServer(("127.0.0.1", 0), Stub)
    port = stub.server_address[1]
    threading.Thread(target=stub.serve_forever, daemon=True).start()

    os.environ["VIBEGUARD_GEMINI_BASE_URL"] = f"http://127.0.0.1:{port}"
    os.environ["VIBEGUARD_GEMINI_API_KEY"] = "TEST-DUMMY-KEY-not-real"

    from vg_app import core, triage

    demo = APP / "demo-app"
    findings, _ = core.scan_core(demo)
    assert len(findings) == 5, f"expected 5 findings, got {len(findings)}"

    # 1) live mock call
    tmap, source = triage.triage(demo, findings)
    assert source == "gemini", f"expected 'gemini', got {source!r}"
    assert seen["auth_header"] == "TEST-DUMMY-KEY-not-real", "key not sent via header"
    assert "generateContent" in (seen["path"] or ""), f"unexpected path {seen['path']}"
    assert tmap["0"]["explanation"].startswith("MOCK:"), tmap["0"]
    assert tmap["1"]["severity_final"] == "high", tmap["1"]
    assert tmap["0"]["fix_steps"][0].startswith("Move the key"), tmap["0"]
    assert len(tmap) == 5, "gaps must be filled deterministically"
    print("PASS 1: mock Gemini call -> source=gemini, fields parsed, gaps filled")

    # 2) cache hit (same findings -> no second HTTP call needed; source=cache)
    tmap2, source2 = triage.triage(demo, findings)
    assert source2 == "cache", f"expected 'cache', got {source2!r}"
    assert tmap2 == tmap
    print("PASS 2: second call -> source=cache (offline safety net works)")

    # 3) no key -> deterministic fallback
    del os.environ["VIBEGUARD_GEMINI_API_KEY"]
    # Isolate from any key saved in the app's real settings file:
    from vg_app import settings as _sm
    _sm.SETTINGS_FILE = Path("/tmp/vg-test-settings-absent.json")
    if _sm.SETTINGS_FILE.exists():
        _sm.SETTINGS_FILE.unlink()
    # use different findings so the cache (keyed by findings) cannot hit
    other = [dict(findings[0], evidence="different-evidence-for-fallback-test")]
    tmap3, source3 = triage.triage(demo, other)
    assert source3 == "offline", f"expected 'offline', got {source3!r}"
    assert tmap3["0"]["explanation"] == other[0]["why"]
    print("PASS 3: no key -> source=offline, built-in explanation used")

    # 4) key present but server dead -> still offline fallback, never raises
    os.environ["VIBEGUARD_GEMINI_API_KEY"] = "TEST-DUMMY-KEY-not-real"
    os.environ["VIBEGUARD_GEMINI_BASE_URL"] = "http://127.0.0.1:9"
    other2 = [dict(findings[1], evidence="dead-server-test")]
    tmap4, source4 = triage.triage(demo, other2)
    assert source4 == "offline", f"expected 'offline', got {source4!r}"
    print("PASS 4: unreachable Gemini -> offline fallback, no exception")

    stub.shutdown()
    print("ALL TRIAGE TESTS PASSED")


if __name__ == "__main__":
    main()
