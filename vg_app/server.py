"""Local web server for VibeGuard — Python standard library only.

Binds to 127.0.0.1 only (this is a single-user local app). Started by
run.py (double-click START.bat on Windows). No pip installs needed.
"""

import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from . import engine, report, settings as settings_mod, tools_ext

APP_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = APP_DIR / "web"
STATIC = {"index.html", "style.css", "app.js"}


def _json(handler, obj, status=200):
    body = json.dumps(obj).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json_body(handler):
    length = int(handler.headers.get("Content-Length") or 0)
    raw = handler.rfile.read(length) if length else b"{}"
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        return {}


def _parse_multipart(handler):
    """Minimal multipart/form-data parser — returns {name: (filename, bytes)}."""
    ctype = handler.headers.get("Content-Type", "")
    if "boundary=" not in ctype:
        return {}
    boundary = ctype.split("boundary=", 1)[1].strip().strip('"')
    length = int(handler.headers.get("Content-Length") or 0)
    body = handler.rfile.read(length)
    parts = {}
    delimiter = ("--" + boundary).encode("utf-8")
    for chunk in body.split(delimiter):
        if b"\r\n\r\n" not in chunk:
            continue
        head, data = chunk.split(b"\r\n\r\n", 1)
        if data.endswith(b"\r\n"):
            data = data[:-2]  # the single separator CRLF before the next boundary
        name = None
        filename = None
        for line in head.decode("utf-8", "replace").split("\r\n"):
            if line.lower().startswith("content-disposition:"):
                for piece in line.split(";"):
                    piece = piece.strip()
                    if piece.startswith("name="):
                        name = piece[5:].strip('"')
                    elif piece.startswith("filename="):
                        filename = piece[9:].strip('"')
        if name:
            parts[name] = (filename, data)
    return parts


class Handler(BaseHTTPRequestHandler):
    server_version = "VibeGuard/1.0"

    def log_message(self, fmt, *args):  # quiet console
        pass

    # -- GET ---------------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            return self._serve_static("index.html", "text/html; charset=utf-8")
        if path == "/style.css":
            return self._serve_static("style.css", "text/css; charset=utf-8")
        if path == "/app.js":
            return self._serve_static("app.js", "application/javascript; charset=utf-8")
        if path == "/api/status":
            return _json(self, {
                "app": "VibeGuard",
                "has_gemini_key": settings_mod.has_key(),
                "tools": {
                    "gitleaks": tools_ext.tool_version("gitleaks"),
                    "osv-scanner": tools_ext.tool_version("osv"),
                },
                "demo_available": (APP_DIR / "demo-app").is_dir(),
            })
        if path == "/api/settings":
            return _json(self, {"has_gemini_key": settings_mod.has_key()})
        if path in ("/api/report.html", "/api/report.json"):
            qs = parse_qs(parsed.query)
            sid = (qs.get("session") or [""])[0]
            try:
                sdir = engine.session_dir(sid)
                result = json.loads(
                    (sdir / "last-result.json").read_text(encoding="utf-8"))
            except Exception as e:
                return _json(self, {"error": str(e)}, 400)
            if path.endswith(".html"):
                body = report.report_html(result).encode("utf-8")
                ctype = "text/html; charset=utf-8"
                fname = "vibeguard-report.html"
            else:
                body = report.report_json(result).encode("utf-8")
                ctype = "application/json"
                fname = "vibeguard-report.json"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return _json(self, {"error": "not found"}, 404)

    def _serve_static(self, name, ctype):
        if name not in STATIC:
            return _json(self, {"error": "not found"}, 404)
        p = WEB_DIR / name
        try:
            body = p.read_bytes()
        except OSError:
            return _json(self, {"error": "missing web file"}, 500)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- POST ----------------------------------------------------------------
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/scan/demo":
                sid = engine.create_demo_session()
                return _json(self, engine.run_scan(sid))
            if path == "/api/scan/path":
                body = _read_json_body(self)
                sid = engine.create_path_session(body.get("path", ""))
                return _json(self, engine.run_scan(sid))
            if path == "/api/scan/zip":
                parts = _parse_multipart(self)
                if "file" not in parts:
                    return _json(self, {"error": "no file uploaded"}, 400)
                filename, data = parts["file"]
                sid = engine.create_zip_session(data, filename or "upload.zip")
                return _json(self, engine.run_scan(sid))
            if path == "/api/fix":
                body = _read_json_body(self)
                return _json(self, engine.fix_all(body.get("session_id", "")))
            if path == "/api/rotated":
                body = _read_json_body(self)
                return _json(self, engine.mark_rotated(body.get("session_id", "")))
            if path == "/api/reset":
                body = _read_json_body(self)
                return _json(self, engine.reset_session(body.get("session_id", "")))
            if path == "/api/settings":
                body = _read_json_body(self)
                key = (body.get("gemini_api_key") or "").strip()
                settings_mod.save_settings({"gemini_api_key": key})
                return _json(self, {"has_gemini_key": bool(key)})
        except ValueError as e:
            return _json(self, {"error": str(e)}, 400)
        except Exception as e:  # never crash the demo on one bad request
            return _json(self, {"error": f"{type(e).__name__}: {e}"}, 500)
        return _json(self, {"error": "not found"}, 404)


def main():
    port = None
    for candidate in range(8765, 8785):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", candidate), Handler)
            port = candidate
            break
        except OSError:
            continue
    if port is None:
        raise SystemExit("Could not find a free local port (8765-8784).")
    url = f"http://127.0.0.1:{port}/"
    print(f"VibeGuard is running at {url}")
    print("Keep this window open while you use the app. Close it to stop.")
    if not os.environ.get("VIBEGUARD_NO_BROWSER"):
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
