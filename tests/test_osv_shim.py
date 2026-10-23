#!/usr/bin/env python3
"""OSV integration test with a SHIM binary.

Why a shim: this build VM's network proxy blocks api.osv.dev, so the real
OSV-Scanner cannot complete a live query here (verified separately — it
extracts manifests fine, then the API call is reset by the proxy).
This test verifies everything EXCEPT that network hop: it copies the app
to a temp dir, replaces the Linux osv-scanner with a shim that emits a
real-schema OSV JSON report (lodash + requests, real CVE ids), points the
reachability probe at a local stub, and runs the full engine scan of the
deps fixture. Run: python3 tests/test_osv_shim.py
"""
import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
WORK = Path("/tmp/vg-shim-app")

CANNED = {
    "results": [
        {"source": {"path": "package-lock.json", "type": "lockfile"},
         "packages": [{
             "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
             "vulnerabilities": [
                 {"id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"],
                  "summary": "Prototype Pollution in lodash",
                  "database_specific": {"severity": "HIGH"},
                  "affected": [{"ranges": [{"type": "SEMVER", "events":
                                 [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]},
                 {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"],
                  "summary": "Command Injection in lodash",
                  "severity": [{"type": "CVSS_V3",
                                "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
                  "affected": [{"ranges": [{"type": "SEMVER", "events":
                                 [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]},
             ]}]},
        {"source": {"path": "requirements.txt", "type": "lockfile"},
         "packages": [{
             "package": {"name": "requests", "version": "2.19.1", "ecosystem": "PyPI"},
             "vulnerabilities": [
                 {"id": "GHSA-x84v-xcm2-53pg", "aliases": ["CVE-2018-18074"],
                  "summary": "Requests redirects strip Authorization header",
                  "database_specific": {"severity": "HIGH"},
                  "affected": [{"ranges": [{"type": "ECOSYSTEM", "events":
                                 [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]},
             ]}]},
    ]
}

SHIM = """#!/bin/sh
if [ "$1" = "--version" ]; then echo "osv-scanner version: 2.7.0"; exit 0; fi
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--output" ]; then out="$a"; fi
  prev="$a"
done
cat > "$out" <<'JSON'
__CANNED__
JSON
exit 1
"""


class ProbeStub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        body = b"{}"
        self.send_response(400)  # any HTTP answer means "reachable"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    stub = HTTPServer(("127.0.0.1", 0), ProbeStub)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    os.environ["VIBEGUARD_OSV_API_URL"] = \
        f"http://127.0.0.1:{stub.server_address[1]}/v1/query"

    if WORK.exists():
        shutil.rmtree(WORK)
    shutil.copytree(APP, WORK, ignore=shutil.ignore_patterns(
        "data", "cache", "__pycache__", "tests"))
    (WORK / "data").mkdir()
    (WORK / "cache").mkdir()
    shim_path = WORK / "tools" / "osv-linux" / "osv-scanner"
    shim_path.write_text(SHIM.replace("__CANNED__", json.dumps(CANNED)))
    shim_path.chmod(0o755)

    sys.path.insert(0, str(WORK))
    from vg_app import engine  # noqa: E402  (imports the SHIM copy)

    fixture = APP / "tests" / "fixtures" / "deps-app"
    sid = engine.create_path_session(str(fixture))
    result = engine.run_scan(sid)

    assert result["tools"]["osv"]["ran"] is True, result["tools"]["osv"]
    deps = [f for f in result["findings"] if f["layer"] == "dependencies"]
    print(f"deps findings: {len(deps)}  (score {result['score']})")
    for f in deps:
        print(f"  [{f['severity']}] w={f['weight']} {f['title']}")
        print(f"      fix: {f['fix']}")
    assert len(deps) == 3, f"expected 3 dep findings, got {len(deps)}"
    by_cve = {f["title"].split("(")[-1].rstrip(")"): f for f in deps}
    assert by_cve["CVE-2020-8203"]["severity"] == "high"
    assert by_cve["CVE-2020-8203"]["weight"] == 10
    assert by_cve["CVE-2021-23337"]["severity"] == "high"  # CVSS bucket via PR:H
    assert by_cve["CVE-2018-18074"]["weight"] == 10
    assert "4.17.21" in by_cve["CVE-2020-8203"]["fix"]
    total_penalty = sum(f["weight"] for f in deps)
    assert total_penalty == 30, f"cap check: penalty {total_penalty} != 30"
    assert result["score"] == 70, f"score {result['score']} != 70"
    print("PASS: OSV shim -> 3 findings parsed (db severity + CVSS bucket),")
    print("      fix versions extracted, 30-point layer cap applied, score 70.")
    stub.shutdown()


if __name__ == "__main__":
    main()
