"""Scan orchestration + session management.

A "session" is one scanned project. The project is ALWAYS a copy inside
data/sessions/<id>/project — fixes never touch the user's original
folder, and the bundled demo app is restored from demo-app/ on reset.
"""

import io
import json
import os
import shutil
import time
import uuid
import zipfile
from pathlib import Path

from . import core, sast, tools_ext, triage as triage_mod
from .settings import APP_DIR, DATA_DIR

SESSIONS_DIR = DATA_DIR / "sessions"
DEMO_APP_DIR = APP_DIR / "demo-app"
MAX_FILES = 5000
MAX_BYTES = 200 * 1000 * 1000
DEPS_SCORE_CAP = 30


# ---------------------------------------------------------------------------
# session plumbing
# ---------------------------------------------------------------------------

def _new_session(kind, project_name):
    sid = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    sdir = SESSIONS_DIR / sid
    (sdir / "project").mkdir(parents=True, exist_ok=True)
    (sdir / "tmp").mkdir(parents=True, exist_ok=True)
    meta = {"id": sid, "kind": kind, "project_name": project_name,
            "created": time.strftime("%Y-%m-%d %H:%M:%S")}
    (sdir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return sid, sdir


def session_dir(sid):
    sdir = SESSIONS_DIR / sid
    if not sdir.is_dir() or "/" in sid or "\\" in sid or ".." in sid:
        raise ValueError("unknown session")
    return sdir


def _copy_tree(src: Path, dst: Path):
    count, total = 0, 0
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d not in core.SKIP_DIRS]
        relp = Path(dirpath).relative_to(src)
        for name in filenames:
            sp = Path(dirpath) / name
            if sp.is_symlink():
                continue
            try:
                size = sp.stat().st_size
            except OSError:
                continue
            count += 1
            total += size
            if count > MAX_FILES or total > MAX_BYTES:
                raise ValueError("project too large to scan (limit 5000 files / 200 MB)")
            dp = dst / relp / name
            dp.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sp, dp)


def create_demo_session():
    sid, sdir = _new_session("demo", "Demo App — QuickNotes (bundled vulnerable app)")
    _copy_tree(DEMO_APP_DIR, sdir / "project")
    return sid


def create_path_session(folder_path):
    src = Path(folder_path).expanduser()
    if not src.is_dir():
        raise ValueError(f"folder not found: {folder_path}")
    sid, sdir = _new_session("path", src.name)
    try:
        _copy_tree(src.resolve(), sdir / "project")
    except Exception:
        shutil.rmtree(sdir, ignore_errors=True)
        raise
    return sid


def create_zip_session(zip_bytes, filename="upload.zip"):
    sid, sdir = _new_session("zip", filename)
    dest = sdir / "project"
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        total = 0
        count = 0
        dest_resolved = dest.resolve()
        for info in zf.infolist():
            if info.is_dir():
                continue
            count += 1
            total += info.file_size
            if count > MAX_FILES or total > MAX_BYTES:
                raise ValueError("zip too large (limit 5000 files / 200 MB)")
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest_resolved)):
                raise ValueError(f"unsafe path inside zip: {info.filename}")
            if any(part in core.SKIP_DIRS for part in Path(info.filename).parts):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as r, open(target, "wb") as w:
                shutil.copyfileobj(r, w)
    except Exception:
        shutil.rmtree(sdir, ignore_errors=True)
        raise
    # If the zip wraps everything in one top folder, scan inside it.
    entries = [p for p in dest.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        inner = entries[0]
        meta_p = sdir / "meta.json"
        meta = json.loads(meta_p.read_text(encoding="utf-8"))
        meta["inner_root"] = inner.name
        meta_p.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return sid


def project_root(sdir: Path):
    meta = json.loads((sdir / "meta.json").read_text(encoding="utf-8"))
    root = sdir / "project"
    if meta.get("inner_root"):
        root = root / meta["inner_root"]
    return root


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------

def _public_finding(f, triage_entry):
    return {
        "type": f["type"],
        "title": f["title"],
        "severity": f["severity"],
        "weight": f["weight"],
        "confidence": f["confidence"],
        "layer": f["layer"],
        "sources": f["sources"],
        "file": f["file"],
        "line": f["line"],
        "evidence": f["evidence"],
        "why": f["why"],
        "fix": f["fix"],
        "fixable": bool(f["patch"]),
        "triage": triage_entry,
    }


def run_scan(sid):
    sdir = session_dir(sid)
    root = project_root(sdir).resolve()
    tmp = sdir / "tmp"

    core_findings, advisory = core.scan_core(root)

    # Secrets layer: Gitleaks merge
    raw_hits, gl_status = tools_ext.run_gitleaks(root, tmp)
    gl_new = tools_ext.merge_gitleaks(root, core_findings, raw_hits) if raw_hits else []

    # SAST layer
    sast_findings = sast.scan_sast(root, core_findings)

    # Dependencies layer (score impact capped, documented in README)
    dep_findings, osv_status = tools_ext.run_osv(root, tmp)
    dep_findings.sort(key=lambda f: -f["weight"])
    running = 0
    for f in dep_findings:
        if running + f["weight"] > DEPS_SCORE_CAP:
            f["weight"] = max(0, DEPS_SCORE_CAP - running)
            if "(score impact capped" not in f["evidence"]:
                f["evidence"] += " (dependencies layer score impact is capped at 30)"
        running += f["weight"]

    findings = core.sort_findings(
        core_findings + gl_new + sast_findings + dep_findings)
    score = core.compute_score(findings, advisory)

    # LLM triage (or cache / deterministic fallback)
    triage_map, triage_source = triage_mod.triage(root, findings)

    layers = {}
    for f in findings:
        lay = layers.setdefault(f["layer"], {"count": 0, "penalty": 0})
        lay["count"] += 1
        lay["penalty"] += f["weight"]

    meta = json.loads((sdir / "meta.json").read_text(encoding="utf-8"))
    result = {
        "session_id": sid,
        "kind": meta["kind"],
        "project_name": meta["project_name"],
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "score": score,
        "findings": [
            _public_finding(f, triage_map.get(str(i)))
            for i, f in enumerate(findings)
        ],
        "advisory": advisory,
        "layers": layers,
        "tools": {"gitleaks": gl_status, "osv": osv_status},
        "tool_versions": {
            "gitleaks": tools_ext.tool_version("gitleaks"),
            "osv-scanner": tools_ext.tool_version("osv"),
            "built-in rules": "vibeguard-core 1.0 (CLI-verified)",
        },
        "triage_source": triage_source,
        "fix_notes": meta.get("last_fix_notes", []),
    }
    (sdir / "last-result.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
    return result


def fix_all(sid):
    """Apply every safe auto-fix to the session COPY, then rescan."""
    sdir = session_dir(sid)
    root = project_root(sdir).resolve()
    findings, _adv = core.scan_core(root)
    # Only core findings carry patches (same fix set as the verified CLI).
    notes = []
    for f in findings:
        if f["patch"]:
            for note in core.apply_patch(root, f):
                notes.append(f"[{f['title']}] {note}")
    meta = json.loads((sdir / "meta.json").read_text(encoding="utf-8"))
    meta["last_fix_notes"] = notes
    (sdir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return run_scan(sid)


def mark_rotated(sid):
    sdir = session_dir(sid)
    root = project_root(sdir).resolve()
    state = core.load_state(root)
    if state.get("leaked_key_fixed"):
        state["rotated"] = True
        core.save_state(root, state)
    return run_scan(sid)


def reset_session(sid):
    sdir = session_dir(sid)
    meta = json.loads((sdir / "meta.json").read_text(encoding="utf-8"))
    if meta["kind"] != "demo":
        raise ValueError("reset is only available for the demo app session")
    proj = sdir / "project"
    shutil.rmtree(proj, ignore_errors=True)
    proj.mkdir(parents=True, exist_ok=True)
    _copy_tree(DEMO_APP_DIR, proj)
    meta.pop("inner_root", None)
    meta["last_fix_notes"] = []
    (sdir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return run_scan(sid)
