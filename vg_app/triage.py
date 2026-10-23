"""LLM triage layer.

Sends the deterministic findings (+ surrounding code) to Gemini, which:
  * de-duplicates findings that describe the same problem,
  * re-checks severity / real-world exploitability with a one-line reason,
  * rewrites the explanation in very simple English for a non-technical
    founder, with concrete fix steps.

Safety rails:
  * Triggered only when the user has pasted their OWN Gemini API key in
    Settings (stored locally, never printed anywhere).
  * ANY failure (no key, offline, timeout, bad output) falls back to the
    deterministic template explanations — the demo never breaks.
  * Results are cached by findings-hash under cache/, so a triage done
    once (e.g. on Friday, with internet) is re-used offline (e.g. on
    stage on Saturday) for the identical set of findings.
"""

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

from . import core
from .settings import APP_DIR, load_settings

CACHE_DIR = APP_DIR / "cache"
SEVERITIES = {"critical", "high", "medium", "low", "info"}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def findings_hash(findings):
    canon = [
        [f["type"], f["file"], f["line"], f["evidence"], f["title"], f["severity"]]
        for f in findings
    ]
    blob = json.dumps(canon, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:24]


def get_snippet(root: Path, finding, radius=5):
    if not finding.get("file"):
        return ""
    path = root / finding["file"]
    text = core.read_text(path)
    if text is None:
        return ""
    lines = text.splitlines()
    line = finding.get("line") or 1
    lo = max(0, line - 1 - radius)
    hi = min(len(lines), line + radius)
    snippet = "\n".join(lines[lo:hi])
    return snippet[:1200]


def deterministic_triage(findings):
    """Offline fallback — the built-in explanations, structured like the
    LLM output so the UI/reports look the same either way."""
    out = {}
    for i, f in enumerate(findings):
        out[str(i)] = {
            "explanation": f["why"],
            "severity_final": f["severity"],
            "rationale": "Offline mode — severity set by the built-in rules engine.",
            "fix_steps": [f["fix"]] if f["fix"] else [],
            "duplicate_of": None,
        }
    return out


# ---------------------------------------------------------------------------
# Gemini call
# ---------------------------------------------------------------------------

PROMPT_TEMPLATE = """You are the triage brain of VibeGuard, a security scanner for apps built by non-technical founders using AI tools.

Below are {n} findings from deterministic scanners, each with a code snippet. For EACH finding:
1. "explanation": rewrite the problem in VERY simple English a shop owner could understand (2-3 short sentences, no jargon). Say what an attacker could actually do.
2. "severity_final": one of critical/high/medium/low — adjust the scanner severity ONLY if the code context clearly makes it more or less dangerous in the real world.
3. "rationale": one short sentence explaining the severity decision.
4. "fix_steps": 1-4 concrete, ordered fix steps (short imperative sentences).
5. "duplicate_of": if this finding is the SAME underlying problem as an earlier finding, put that finding's index here, else null.

Answer with ONLY a JSON object, no markdown fences:
{{"findings": [{{"index": 0, "explanation": "...", "severity_final": "high", "rationale": "...", "fix_steps": ["..."], "duplicate_of": null}}]}}

FINDINGS:
{findings_json}
"""


def _call_gemini(settings, findings, root):
    items = []
    for i, f in enumerate(findings):
        items.append({
            "index": i,
            "title": f["title"],
            "scanner_severity": f["severity"],
            "file": f["file"],
            "line": f["line"],
            "evidence": f["evidence"],
            "scanner_explanation": f["why"],
            "code_snippet": get_snippet(root, f),
        })
    prompt = PROMPT_TEMPLATE.format(
        n=len(findings), findings_json=json.dumps(items, indent=2))
    url = (settings["gemini_base_url"].rstrip("/")
           + f"/v1beta/models/{settings['gemini_model']}:generateContent")
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2,
                             "responseMimeType": "application/json"},
    }).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("x-goog-api-key", settings["gemini_api_key"])
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    parts = data["candidates"][0]["content"]["parts"]
    text = "".join(p.get("text", "") for p in parts).strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    parsed = json.loads(text)
    out = {}
    for entry in parsed.get("findings", []):
        idx = entry.get("index")
        if not isinstance(idx, int) or not (0 <= idx < len(findings)):
            continue
        sev = entry.get("severity_final", findings[idx]["severity"])
        if sev not in SEVERITIES:
            sev = findings[idx]["severity"]
        dup = entry.get("duplicate_of")
        if not isinstance(dup, int) or dup == idx or not (0 <= dup < len(findings)):
            dup = None
        steps = entry.get("fix_steps") or []
        out[str(idx)] = {
            "explanation": str(entry.get("explanation") or findings[idx]["why"]),
            "severity_final": sev,
            "rationale": str(entry.get("rationale") or ""),
            "fix_steps": [str(s) for s in steps][:4] or [findings[idx]["fix"]],
            "duplicate_of": dup,
        }
    if len(out) < len(findings):  # fill any gaps deterministically
        fallback = deterministic_triage(findings)
        for k, v in fallback.items():
            out.setdefault(k, v)
    return out


# ---------------------------------------------------------------------------
# public entry
# ---------------------------------------------------------------------------

def triage(root: Path, findings):
    """Returns (triage_map, source) — source: 'gemini' | 'cache' | 'offline'."""
    if not findings:
        return {}, "offline"
    settings = load_settings()
    h = findings_hash(findings)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"triage_{h}.json"

    if cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if isinstance(cached, dict) and cached.get("map"):
                return cached["map"], "cache"
        except (OSError, ValueError):
            pass

    if settings["gemini_api_key"].strip():
        try:
            result = _call_gemini(settings, findings, root)
            try:
                cache_file.write_text(json.dumps(
                    {"map": result, "model": settings["gemini_model"]},
                    indent=2), encoding="utf-8")
            except OSError:
                pass
            return result, "gemini"
        except Exception:
            pass  # ANY failure -> deterministic fallback; demo never breaks

    return deterministic_triage(findings), "offline"
