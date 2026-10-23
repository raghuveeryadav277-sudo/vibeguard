"""VibeGuard core engine — ported from the verified CLI prototype.

Deterministic, standard library only. The five original checks, their
weights, explanations and auto-fix patches are IDENTICAL to the CLI
(scan 34 -> fix -> 87 on the demo app). Findings additionally carry a
"layer" and "source" so the Secrets / SAST / Dependencies / Database
layers can be merged into one report.
"""

import base64
import difflib
import json
import math
import os
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# finding catalog (identical weights/text to the CLI prototype)
# ---------------------------------------------------------------------------

CHECK_ORDER = [
    "leaked-supabase-key",
    "open-db-policy",
    "env-committed",
    "unprotected-ai-route",
    "missing-meta-tags",
]

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

LAYER_OF = {
    "leaked-supabase-key": "secrets",
    "env-committed": "secrets",
    "open-db-policy": "database",
    "unprotected-ai-route": "sast",
    "missing-meta-tags": "sast",
}

FINDINGS = {
    "leaked-supabase-key": {
        "title": "Supabase service-role key hardcoded in frontend code",
        "severity": "critical",
        "weight": 24,
        "confidence": 0.98,
        "why": (
            "This key gives FULL access to your Supabase database — read, write and "
            "delete, bypassing every security rule. It is sitting in frontend "
            "JavaScript that anyone can open in their browser's developer tools. "
            "If this code is public on GitHub, bots will find the key within minutes."
        ),
        "fix": (
            "Move the key out of frontend code into a server-side environment "
            "variable. NOTE: removing it from code does not un-leak it — rotate "
            "the key in the Supabase dashboard afterwards."
        ),
    },
    "open-db-policy": {
        "title": "Database allows anyone to read and write everything",
        "severity": "critical",
        "weight": 24,
        "confidence": 0.97,
        "why": (
            "Row Level Security is disabled and an allow-all policy is active, so "
            "anyone on the internet can read, change or delete every row in your "
            "database — no login needed. This is the most common way vibe-coded "
            "apps get their data wiped or stolen."
        ),
        "fix": (
            "Turn Row Level Security back on and replace the allow-all policy "
            "with one that only lets logged-in users touch their own rows."
        ),
    },
    "env-committed": {
        "title": ".env file committed to the repository",
        "severity": "high",
        "weight": 8,
        "confidence": 0.95,
        "why": (
            "Your .env file holds real secrets (including an API key) and it is "
            "sitting in the repository — and .gitignore does not exclude it. "
            "Every clone, every fork, every CI log can expose these secrets. "
            "This is the classic GitHub leak story."
        ),
        "fix": (
            "Add .env to .gitignore, remove the committed .env file, and keep a "
            ".env.example with placeholder values for the team instead."
        ),
    },
    "unprotected-ai-route": {
        "title": "AI API route has no login check and no rate limit",
        "severity": "high",
        "weight": 8,
        "confidence": 0.90,
        "why": (
            "This API endpoint calls a paid AI service, but anyone can call it — "
            "no login required, and no limit on how often. A single bot looping "
            "this endpoint can burn through your entire AI budget in one night. "
            "This is a cost risk, not just a security risk."
        ),
        "fix": (
            "Require an Authorization header on the route and add a simple "
            "per-IP rate limit so one caller cannot hammer it."
        ),
    },
    "missing-meta-tags": {
        "title": "Page is missing title, description and social preview tags",
        "severity": "low",
        "weight": 2,
        "confidence": 0.99,
        "why": (
            "Search engines and social apps show a blank title and no preview for "
            "this page. It is a small fix, but it is the difference between "
            "looking finished and looking broken when someone shares your link."
        ),
        "fix": "Add a <title>, a meta description and Open Graph tags to <head>.",
    },
}

ROTATION_ADVISORY = {
    "title": "Leaked secrets were removed from code — rotation still pending",
    "severity": "info",
    "weight": 13,
    "confidence": 1.0,
    "why": (
        "The leaked keys are out of your code, but they were public before the "
        "fix — anyone who copied them can still use them. Rotate each key in "
        "its provider dashboard, then re-scan to confirm."
    ),
}

STATE_FILE = ".vibeguard-state.json"

# ---------------------------------------------------------------------------
# file helpers
# ---------------------------------------------------------------------------

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
SKIP_FILES = {STATE_FILE}
ENV_FILE_RE = re.compile(r"^\.env(\.|$)")


def is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(8192)
    except OSError:
        return True


def iter_text_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in SKIP_FILES:
                continue
            p = Path(dirpath) / name
            try:
                if p.stat().st_size > 1_000_000 or is_binary(p):
                    continue
            except OSError:
                continue
            yield p


def read_text(path: Path):
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None


def mask_secret(s: str) -> str:
    s = s.strip().strip("\"'")
    if len(s) <= 12:
        return s[:2] + "..."
    return s[:7] + "..." + s[-2:]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in freq.values())


def rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root)).replace(os.sep, "/")
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------

def make_finding(ftype, root, path, line=None, evidence="", patch=None,
                 extra_fix="", layer=None, source="built-in"):
    meta = FINDINGS[ftype]
    return {
        "type": ftype,
        "title": meta["title"],
        "severity": meta["severity"],
        "weight": meta["weight"],
        "confidence": meta["confidence"],
        "layer": layer or LAYER_OF.get(ftype, "sast"),
        "source": source,
        "sources": [source],
        "file": rel(root, path) if path else "",
        "line": line,
        "evidence": evidence,
        "why": meta["why"],
        "fix": extra_fix or meta["fix"],
        "patch": patch or [],
        "check_index": CHECK_ORDER.index(ftype) if ftype in CHECK_ORDER else 50,
    }


def custom_finding(ftype, title, severity, weight, confidence, layer, source,
                   file, line, evidence, why, fix, patch=None, check_index=60):
    """A finding not in the original CLI catalog (SAST / tools layers)."""
    return {
        "type": ftype,
        "title": title,
        "severity": severity,
        "weight": weight,
        "confidence": confidence,
        "layer": layer,
        "source": source,
        "sources": [source],
        "file": file,
        "line": line,
        "evidence": evidence,
        "why": why,
        "fix": fix,
        "patch": patch or [],
        "check_index": check_index,
    }


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f["severity"]], f["check_index"], f["file"]),
    )


def compute_score(findings, advisory=None):
    """Score = 100 minus finding weights (plus any residual advisory weight)."""
    penalty = sum(f["weight"] for f in findings)
    if advisory:
        penalty += advisory["weight"]
    return max(0, 100 - penalty)


# ---------------------------------------------------------------------------
# check 1: secrets (ported verbatim from the CLI scanner)
# ---------------------------------------------------------------------------

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
OPENAI_RE = re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")
AWS_RE = re.compile(r"AKIA[0-9A-Z]{16}")
SECRET_NAME_RE = re.compile(
    r"(?i)([\w.\-]*?(?:api[_-]?key|secret|token|password|private[_-]?key)[\w.\-]*?)"
    r"\s*[:=]\s*[\"']([^\"'\s]{24,})[\"']"
)


def jwt_role(token: str):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
        return data.get("role", "")
    except Exception:
        return ""


def check_secrets(root: Path):
    findings = []
    seen_lines = set()

    def claimable(path, line):
        key = (str(path), line)
        if key in seen_lines:
            return False
        seen_lines.add(key)
        return True

    for path in iter_text_files(root):
        if ENV_FILE_RE.match(path.name):
            continue
        text = read_text(path)
        if text is None:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for m in JWT_RE.finditer(line):
                if not claimable(path, i):
                    continue
                if "service_role" in jwt_role(m.group(0)):
                    new_line = re.sub(
                        r'(SUPABASE_SERVICE_KEY\s*=\s*)"[^"]+";',
                        r"\1process.env.SUPABASE_SERVICE_KEY;",
                        line,
                    )
                    new_text = (
                        "// VibeGuard fix: the service key must never ship in "
                        "frontend code —\n// load it server-side from an env var "
                        "instead.\n" + new_line
                    )
                    findings.append(
                        make_finding(
                            "leaked-supabase-key", root, path, i,
                            evidence=f"hardcoded key: {mask_secret(m.group(0))}",
                            patch=[("replace_line", path, i, new_text)],
                        )
                    )
            for m in OPENAI_RE.finditer(line):
                if not claimable(path, i):
                    continue
                findings.append(
                    make_finding(
                        "leaked-supabase-key", root, path, i,
                        evidence=f"hardcoded key: {mask_secret(m.group(0))}",
                        patch=[],
                        extra_fix="Move this key into a server-side environment "
                        "variable and rotate it — it is already exposed.",
                    )
                )
            for m in AWS_RE.finditer(line):
                if not claimable(path, i):
                    continue
                findings.append(
                    make_finding(
                        "leaked-supabase-key", root, path, i,
                        evidence=f"hardcoded key: {mask_secret(m.group(0))}",
                        patch=[],
                        extra_fix="Move this key into a server-side environment "
                        "variable and rotate it — it is already exposed.",
                    )
                )
            for m in SECRET_NAME_RE.finditer(line):
                value = m.group(2)
                if "." in value:
                    continue
                if shannon_entropy(value) < 4.3:
                    continue
                if not claimable(path, i):
                    continue
                findings.append(
                    make_finding(
                        "leaked-supabase-key", root, path, i,
                        evidence=f"{m.group(1)} = {mask_secret(value)} "
                        f"(entropy {shannon_entropy(value):.1f})",
                        patch=[],
                        extra_fix="Move this value into an environment variable "
                        "and rotate it — it looks like a real secret.",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# check 2: .env committed (ported)
# ---------------------------------------------------------------------------

def check_env_committed(root: Path):
    env_path = root / ".env"
    if not env_path.exists():
        return []
    gitignore = root / ".gitignore"
    ignored = False
    if gitignore.exists():
        content = read_text(gitignore) or ""
        ignored = any(
            ln.strip() in (".env", ".env*") and not ln.strip().startswith("#")
            for ln in content.splitlines()
        )
    if ignored:
        return []

    env_text = read_text(env_path) or ""
    key_line = next(
        (ln for ln in env_text.splitlines() if "sk-" in ln or "KEY=" in ln.upper()),
        "",
    )
    evidence = ".env is in the repo and not in .gitignore"
    if key_line:
        evidence += f"; contains: {mask_secret(key_line.split('=', 1)[-1])}"

    return [
        make_finding(
            "env-committed", root, env_path,
            evidence=evidence,
            patch=[
                ("append_line", gitignore, ".env"),
                ("create", root / ".env.example",
                 "OPENAI_API_KEY=your-key-here\n"
                 "SUPABASE_URL=https://xyzcompany.supabase.co\n"),
                ("delete", env_path),
            ],
        )
    ]


# ---------------------------------------------------------------------------
# check 3: supabase policies (ported)
# ---------------------------------------------------------------------------

DISABLE_RLS_RE = re.compile(r"DISABLE\s+ROW\s+LEVEL\s+SECURITY", re.I)
ALLOW_ALL_RE = re.compile(r"USING\s*\(\s*true\s*\)", re.I)


def check_supabase_policies(root: Path):
    findings = []
    sql_files = [p for p in iter_text_files(root)
                 if p.suffix.lower() == ".sql" or "supabase" in p.parts]
    for path in sql_files:
        text = read_text(path)
        if text is None:
            continue
        bad_rls = DISABLE_RLS_RE.search(text)
        allow_all = ALLOW_ALL_RE.search(text)
        if not (bad_rls or allow_all):
            continue
        line = 1
        if bad_rls:
            line = text[: bad_rls.start()].count("\n") + 1
        elif allow_all:
            line = text[: allow_all.start()].count("\n") + 1
        evidence_bits = []
        if bad_rls:
            evidence_bits.append("ROW LEVEL SECURITY is disabled")
        if allow_all:
            evidence_bits.append('a policy uses USING (true) — "allow all"')
        findings.append(
            make_finding(
                "open-db-policy", root, path, line,
                evidence="; ".join(evidence_bits),
                patch=[
                    ("replace", path,
                     "ALTER TABLE notes DISABLE ROW LEVEL SECURITY;",
                     "ALTER TABLE notes ENABLE ROW LEVEL SECURITY;"),
                    ("replace", path,
                     'CREATE POLICY "Allow all" ON notes FOR ALL USING (true);',
                     'CREATE POLICY "Users manage own notes" ON notes FOR ALL\n'
                     "  USING (auth.uid() = user_id)\n"
                     "  WITH CHECK (auth.uid() = user_id);"),
                ],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# check 4: unprotected AI routes (ported)
# ---------------------------------------------------------------------------

AUTH_SIGNALS = re.compile(
    r"req\.headers\s*\[\s*[\"']authorization[\"']\s*\]|"
    r"req\.headers\.authorization|getServerSession|requireAuth|verifyAuth|"
    r"withAuth|clerkAuth|authenticate\s*\(|req\.user\b",
    re.I,
)
RATELIMIT_SIGNALS = re.compile(r"rate.?limit|throttle|upstash|bucket", re.I)
AI_CALL_SIGNALS = re.compile(r"api\.openai\.com|openai|anthropic|cohere|groq", re.I)
API_DIR_RE = re.compile(r"(^|/)(api|routes|app/api)(/|$)")


def check_routes(root: Path):
    findings = []
    for path in iter_text_files(root):
        if not API_DIR_RE.search("/" + rel(root, path).replace(os.sep, "/")):
            continue
        if path.suffix.lower() not in (".js", ".ts", ".mjs", ".py"):
            continue
        text = read_text(path)
        if text is None or not AI_CALL_SIGNALS.search(text):
            continue
        if AUTH_SIGNALS.search(text) or RATELIMIT_SIGNALS.search(text):
            continue
        anchor = "export default async function handler(req, res) {"
        patch = []
        if anchor in text:
            guard = (
                "// --- VibeGuard fix: require auth + basic rate limiting ---\n"
                "const __vgRate = new Map();\n"
                "function __vgGuard(req, res) {\n"
                "  if (!req.headers.authorization) {\n"
                '    res.status(401).json({ error: "Unauthorized" });\n'
                "    return false;\n"
                "  }\n"
                '  const ip = req.headers["x-forwarded-for"] || "local";\n'
                "  const now = Date.now();\n"
                "  const hits = (__vgRate.get(ip) || []).filter(t => now - t < 60000);\n"
                "  if (hits.length >= 20) {\n"
                '    res.status(429).json({ error: "Too many requests" });\n'
                "    return false;\n"
                "  }\n"
                "  hits.push(now);\n"
                "  __vgRate.set(ip, hits);\n"
                "  return true;\n"
                "}\n"
                "\n"
                + anchor
                + "\n  if (!__vgGuard(req, res)) return;"
            )
            patch = [("replace", path, anchor, guard)]
        findings.append(
            make_finding(
                "unprotected-ai-route", root, path,
                evidence="calls a paid AI API with no auth check and no rate limit",
                patch=patch,
                extra_fix=(FINDINGS["unprotected-ai-route"]["fix"]
                           if not patch else None) or "",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# check 5: meta tags (ported)
# ---------------------------------------------------------------------------

def check_meta(root: Path):
    path = root / "index.html"
    if not path.exists():
        return []
    text = read_text(path) or ""
    missing = []
    if not re.search(r"<title[^>]*>.+?</title>", text, re.I | re.S):
        missing.append("<title>")
    if not re.search(r'<meta[^>]+name=["\']description["\']', text, re.I):
        missing.append('meta description')
    if not re.search(r'<meta[^>]+property=["\']og:title["\']', text, re.I):
        missing.append("og:title")
    if not missing:
        return []
    tags = (
        "  <title>QuickNotes — AI-powered notes</title>\n"
        '  <meta name="description" content="QuickNotes: capture ideas and '
        'summarize them with AI.">\n'
        '  <meta property="og:title" content="QuickNotes — AI-powered notes">\n'
        '  <meta property="og:description" content="QuickNotes: capture ideas '
        'and summarize them with AI.">'
    )
    return [
        make_finding(
            "missing-meta-tags", root, path,
            evidence="missing: " + ", ".join(missing),
            patch=[("replace", path, "<head>", "<head>\n" + tags)],
        )
    ]


# ---------------------------------------------------------------------------
# state + patch application (ported)
# ---------------------------------------------------------------------------

def load_state(root: Path):
    p = root / STATE_FILE
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(root: Path, state: dict):
    (root / STATE_FILE).write_text(json.dumps(state, indent=2), encoding="utf-8")


def _apply_ops_to_text(text: str, ops):
    for op in ops:
        if op[0] == "replace" and len(op) == 4:
            _, _path, old, new = op
            if old not in text:
                raise ValueError(f"patch anchor not found: {old[:60]!r}")
            text = text.replace(old, new, 1)
        elif op[0] == "replace_line":
            _, _path, lineno, new_text = op
            lines = text.splitlines(keepends=True)
            lines[lineno - 1] = new_text + ("\n" if not new_text.endswith("\n") else "")
            text = "".join(lines)
    return text


def patch_diff(root: Path, finding: dict) -> str:
    chunks = []
    by_file = {}
    for op in finding["patch"]:
        by_file.setdefault(str(op[1]), []).append(op)
    for fname, ops in by_file.items():
        path = Path(fname)
        try:
            disp = str(path.relative_to(root))
        except ValueError:
            disp = fname
        original = read_text(path) if path.exists() else ""
        new_text = original
        creates = [op for op in ops if op[0] == "create"]
        deletes = [op for op in ops if op[0] == "delete"]
        appends = [op for op in ops if op[0] == "append_line"]
        textops = [op for op in ops if op[0] in ("replace", "replace_line")]
        try:
            new_text = _apply_ops_to_text(new_text, textops)
        except ValueError as e:
            chunks.append(f"--- {disp}\n!!! {e} (manual fix needed)\n")
            continue
        for _, _p, line in appends:
            if not any(l.strip() == line for l in new_text.splitlines()):
                new_text = new_text.rstrip("\n") + "\n" + line + "\n"
        for _, _p, content in creates:
            chunks.append(
                "".join(difflib.unified_diff(
                    [], content.splitlines(keepends=True),
                    fromfile=f"a/{disp} (new file)", tofile=f"b/{disp}"))
            )
        for _op, _p in deletes:
            chunks.append(
                "".join(difflib.unified_diff(
                    original.splitlines(keepends=True), [],
                    fromfile=f"a/{disp}", tofile=f"b/{disp} (deleted)"))
            )
        if not creates and not deletes:
            chunks.append(
                "".join(difflib.unified_diff(
                    original.splitlines(keepends=True),
                    new_text.splitlines(keepends=True),
                    fromfile=f"a/{disp}", tofile=f"b/{disp}"))
            )
    return "".join(chunks) or "(no file changes — manual step)"


def apply_patch(root: Path, finding: dict):
    notes = []
    for op in finding["patch"]:
        kind = op[0]
        if kind == "replace":
            _, fpath, old, new = op
            p = Path(fpath)
            text = read_text(p) or ""
            if old not in text:
                notes.append(f"SKIP {rel(root, p)}: anchor not found (already fixed?)")
                continue
            p.write_text(text.replace(old, new, 1), encoding="utf-8")
            notes.append(f"EDIT {rel(root, p)}")
        elif kind == "replace_line":
            _, fpath, lineno, new_text = op
            p = Path(fpath)
            lines = (read_text(p) or "").splitlines(keepends=True)
            lines[lineno - 1] = new_text + ("\n" if not new_text.endswith("\n") else "")
            p.write_text("".join(lines), encoding="utf-8")
            notes.append(f"EDIT {rel(root, p)}:{lineno}")
        elif kind == "append_line":
            _, fpath, line = op
            p = Path(fpath)
            text = read_text(p) or ""
            if any(l.strip() == line for l in text.splitlines()):
                notes.append(f"SKIP {rel(root, p)}: line already present")
            else:
                p.write_text(text.rstrip("\n") + "\n" + line + "\n", encoding="utf-8")
                notes.append(f"EDIT {rel(root, p)} (appended {line!r})")
        elif kind == "create":
            _, fpath, content = op
            p = Path(fpath)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            notes.append(f"CREATE {rel(root, p)}")
        elif kind == "delete":
            _, fpath = op
            p = Path(fpath)
            if p.exists():
                p.unlink()
                notes.append(f"DELETE {rel(root, p)}")
            else:
                notes.append(f"SKIP {rel(root, p)}: already gone")
    if finding["type"] == "leaked-supabase-key":
        state = load_state(root)
        state["leaked_key_fixed"] = True
        state.setdefault("rotated", False)
        save_state(root, state)
        notes.append("NOTE: key removed from code — rotate it in the dashboard!")
    return notes


# ---------------------------------------------------------------------------
# core scan entry (the CLI's five checks)
# ---------------------------------------------------------------------------

def scan_core(root: Path):
    root = root.resolve()
    findings = []
    findings += check_secrets(root)
    findings += check_env_committed(root)
    findings += check_supabase_policies(root)
    findings += check_routes(root)
    findings += check_meta(root)

    advisory = None
    state = load_state(root)
    if state.get("leaked_key_fixed") and not state.get("rotated"):
        advisory = dict(ROTATION_ADVISORY)
    return findings, advisory
