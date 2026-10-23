"""Built-in SAST layer — deterministic Semgrep-style pattern rules.

Pure Python, standard library only. (Semgrep itself does not run natively
on a Windows laptop without WSL/Docker, so this build ships equivalent
built-in rules; Semgrep binary integration is roadmap — see README.)

Rules: XSS, SQL injection, command injection, eval, weak crypto,
unprotected API routes (auth gaps), missing security headers, and open
Firebase rules. Pattern-based, so confidence is lower than the core
checks and every finding says so honestly.
"""

import re
from pathlib import Path

from . import core
from .core import custom_finding, iter_text_files, read_text, rel

CODE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".py", ".vue", ".html"}

# --- XSS ---------------------------------------------------------------------

XSS_PATTERNS = [
    (re.compile(r"\.innerHTML\s*=\s*(?!['\"`][^'\"`]*['\"`]\s*$)"), "innerHTML assigned from a variable/expression"),
    (re.compile(r"\.innerHTML\s*\+="), "innerHTML appended with +="),
    (re.compile(r"document\.write\s*\("), "document.write() call"),
    (re.compile(r"dangerouslySetInnerHTML"), "React dangerouslySetInnerHTML"),
    (re.compile(r"v-html\s*="), "Vue v-html directive"),
    (re.compile(r"\.outerHTML\s*=\s*(?!['\"`])"), "outerHTML assigned from a variable/expression"),
]

# --- SQL injection -------------------------------------------------------------

SQLI_PATTERNS = [
    re.compile(r"(?i)(select|insert\s+into|update\s+\w+\s+set|delete\s+from)[^;\"']*[\"'`]\s*\+"),
    re.compile(r"(?i)(select|insert\s+into|update\s+\w+\s+set|delete\s+from)[^;]*\$\{"),
    re.compile(r"(?i)\.execute\s*\(\s*f[\"']"),
    re.compile(r"(?i)\.query\s*\(\s*`[^`]*\$\{"),
    re.compile(r"(?i)(query|execute)\s*\([^)]*%\s*[\w\(]"),
]

# --- command injection / eval --------------------------------------------------

CMD_PATTERNS = [
    (re.compile(r"(child_process\.)?exec(Sync)?\s*\([^)]*\+"), "shell command built by string concatenation"),
    (re.compile(r"os\.system\s*\("), "os.system() call"),
    (re.compile(r"subprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True"), "subprocess with shell=True"),
    (re.compile(r"\bexec\s*\([^)]*\+"), "exec() with concatenated input"),
]

EVAL_RE = re.compile(r"(?<![\w.])eval\s*\((?!\s*['\"`]\s*\))")

# --- weak crypto -----------------------------------------------------------------

WEAK_CRYPTO_PATTERNS = [
    (re.compile(r"createHash\s*\(\s*['\"](md5|sha1)['\"]", re.I), "MD5/SHA1 hash (createHash)"),
    (re.compile(r"hashlib\.(md5|sha1)\s*\(", re.I), "MD5/SHA1 hash (hashlib)"),
    (re.compile(r"(?i)(md5|sha1)\s*\([^)]*(password|passwd|pwd)"), "MD5/SHA1 used on a password"),
    (re.compile(r"Math\.random\s*\(\s*\)"), "Math.random() (not safe for tokens/secrets)"),
]

TOKEN_CONTEXT_RE = re.compile(r"(?i)token|secret|session|otp|code|key")

# --- routes / headers ------------------------------------------------------------

HANDLER_RE = re.compile(
    r"export\s+default\s+(async\s+)?function\s+handler|"
    r"module\.exports\s*=|app\.(get|post|put|delete|patch)\s*\(|"
    r"def\s+(get|post|put|delete|handler)\s*\("
)
DB_OP_RE = re.compile(
    r"(?i)supabase|firebase|firestore|mongodb|mongoose|prisma|sequelize|"
    r"\.from\s*\(|\.collection\s*\(|db\.|database|query\s*\("
)
SERVER_ENTRY_RE = re.compile(
    r"express\s*\(|createServer\s*\(|\.listen\s*\(|Flask\s*\(|FastAPI\s*\("
)
HEADER_SIGNALS_RE = re.compile(
    r"(?i)helmet|Content-Security-Policy|X-Frame-Options|setHeader|"
    r"headers\s*\[|SecurityMiddleware|secure_headers"
)

FIREBASE_OPEN_RE = re.compile(r"allow\s+[^:]+:\s*if\s+true", re.I)


def _is_comment_line(line, suffix):
    s = line.strip()
    if s.startswith(("//", "/*", "*", "<!--")):
        return True
    if suffix == ".py" and s.startswith("#"):
        return True
    return False


def _strip_comments(text):
    """Rough comment removal for file-level signal checks."""
    out = []
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if in_block:
            if "*/" in s:
                in_block = False
                s = s.split("*/", 1)[1]
            else:
                continue
        if s.startswith("/*"):
            if "*/" not in s[2:]:
                in_block = True
            continue
        if s.startswith("//") or s.startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


def _line_findings(root, path, rules, ftype, title, severity, weight,
                   confidence, why, fix, check_index, layer="sast"):
    out = []
    text = read_text(path)
    if text is None:
        return out
    claimed = set()
    for i, line in enumerate(text.splitlines(), 1):
        if _is_comment_line(line, path.suffix.lower()):
            continue
        for rx, label in rules:
            if i in claimed:
                break
            if rx.search(line):
                claimed.add(i)
                out.append(custom_finding(
                    ftype, title, severity, weight, confidence, layer,
                    "built-in SAST rules", rel(root, path), i,
                    f"{label}: {line.strip()[:110]}", why, fix,
                    check_index=check_index,
                ))
    return out


def check_xss(root):
    out = []
    for path in iter_text_files(root):
        if path.suffix.lower() not in CODE_SUFFIXES:
            continue
        out += _line_findings(
            root, path, XSS_PATTERNS, "xss-risk",
            "Possible XSS: web content is built from unsanitized data",
            "high", 12, 0.78,
            "Code puts data into the page with innerHTML / document.write / "
            "dangerouslySetInnerHTML. If any of that data comes from a user, "
            "an attacker can inject their own script into your page and run "
            "it in every visitor's browser — stealing sessions and logins. "
            "(Pattern-based check: confirm the data source before treating "
            "this as confirmed.)",
            "Render user data with textContent or a framework's escaped "
            "output instead of innerHTML. If HTML is truly needed, sanitize "
            "it first (e.g. DOMPurify).",
            check_index=70,
        )
    return out


def check_sqli(root):
    out = []
    rules = [(rx, "SQL built by string concatenation/formatting") for rx in SQLI_PATTERNS]
    for path in iter_text_files(root):
        if path.suffix.lower() not in (".js", ".ts", ".mjs", ".py"):
            continue
        out += _line_findings(
            root, path, rules, "sql-injection-risk",
            "Possible SQL injection: query built from raw input",
            "critical", 20, 0.82,
            "The SQL query is glued together with user input instead of "
            "using parameters. An attacker can type SQL into a form field "
            "and read, change or delete your whole database — the oldest "
            "and still one of the most damaging web attacks. "
            "(Pattern-based check: confirm the value really is user input.)",
            "Use parameterized queries / prepared statements everywhere — "
            "never build SQL with string concatenation or f-strings.",
            check_index=71,
        )
    return out


def check_cmd(root):
    out = []
    for path in iter_text_files(root):
        if path.suffix.lower() not in (".js", ".ts", ".mjs", ".py"):
            continue
        out += _line_findings(
            root, path, CMD_PATTERNS, "command-injection-risk",
            "Possible command injection: shell command built from input",
            "critical", 20, 0.82,
            "A shell command is built from program input. If any part of it "
            "comes from a user, they can append their own commands and take "
            "over the server itself — worse than a data leak. "
            "(Pattern-based check: confirm the input source.)",
            "Avoid shell commands with input. Use argument arrays "
            "(execFile / subprocess without shell=True) and allow-list "
            "values instead of concatenating strings.",
            check_index=72,
        )
        text = read_text(path)
        if text is not None:
            for i, line in enumerate(text.splitlines(), 1):
                if _is_comment_line(line, path.suffix.lower()):
                    continue
                if EVAL_RE.search(line):
                    out.append(custom_finding(
                        "eval-usage", "eval() used on dynamic code",
                        "high", 12, 0.80, "sast", "built-in SAST rules",
                        rel(root, path), i,
                        f"eval() call: {line.strip()[:110]}",
                        "eval() runs a string as code. If that string contains "
                        "user input, the user is effectively writing your "
                        "program — full code execution with your app's rights.",
                        "Remove eval(). Parse data with JSON.parse or a real "
                        "parser; never execute input as code.",
                        check_index=73,
                    ))
    return out


def check_weak_crypto(root):
    out = []
    for path in iter_text_files(root):
        if path.suffix.lower() not in (".js", ".ts", ".mjs", ".py"):
            continue
        text = read_text(path)
        if text is None:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if _is_comment_line(line, path.suffix.lower()):
                continue
            for rx, label in WEAK_CRYPTO_PATTERNS:
                if not rx.search(line):
                    continue
                if label.startswith("Math.random") and not TOKEN_CONTEXT_RE.search(text):
                    continue
                out.append(custom_finding(
                    "weak-crypto", "Weak cryptography: MD5/SHA1 or Math.random",
                    "medium", 6, 0.85, "sast", "built-in SAST rules",
                    rel(root, path), i,
                    f"{label}: {line.strip()[:110]}",
                    "MD5 and SHA1 are broken for passwords — modern hardware "
                    "guesses billions of them per second. Math.random() is "
                    "predictable, so tokens built from it can be guessed too.",
                    "Hash passwords with bcrypt/argon2. Generate tokens with "
                    "crypto.randomBytes / secrets module, and use SHA-256+ "
                    "for integrity checks.",
                    check_index=74,
                ))
                break
    return out


def check_auth_gaps(root, already_flagged_files):
    """API routes with no auth at all (AI routes are covered by core)."""
    out = []
    for path in iter_text_files(root):
        if not core.API_DIR_RE.search("/" + rel(root, path).replace("\\", "/")):
            continue
        if path.suffix.lower() not in (".js", ".ts", ".mjs", ".py"):
            continue
        if rel(root, path) in already_flagged_files:
            continue
        text = read_text(path)
        if text is None:
            continue
        if not HANDLER_RE.search(text):
            continue
        if not DB_OP_RE.search(text):
            continue
        if core.AUTH_SIGNALS.search(text):
            continue
        if core.AI_CALL_SIGNALS.search(text):
            continue  # AI routes are the core check's job (it also checks rate limits)
        out.append(custom_finding(
            "unprotected-api-route", "API route has no login check",
            "high", 8, 0.82, "sast", "built-in SAST rules",
            rel(root, path), None,
            "route touches data with no auth check anywhere in the file",
            "This endpoint reads or writes data but never checks who is "
            "calling it. Anyone who finds the URL can use it — no account "
            "needed. Unprotected routes are how 'private' app data ends up "
            "public.",
            "Add an authentication check at the top of the handler (verify "
            "the Authorization header / session) before touching any data.",
            check_index=75,
        ))
    return out


def check_headers(root):
    out = []
    for path in iter_text_files(root):
        if path.suffix.lower() not in (".js", ".ts", ".mjs", ".py"):
            continue
        text = read_text(path)
        if text is None:
            continue
        code_only = _strip_comments(text)
        if not SERVER_ENTRY_RE.search(code_only):
            continue
        if HEADER_SIGNALS_RE.search(code_only):
            continue
        out.append(custom_finding(
            "missing-security-headers",
            "Server sets no security headers",
            "low", 3, 0.75, "sast", "built-in SAST rules",
            rel(root, path), None,
            "server entry point never sets Content-Security-Policy / "
            "X-Frame-Options / similar headers",
            "Security headers tell browsers to block framing attacks, "
            "MIME-sniffing and injected scripts. Without them the app "
            "misses a cheap, standard layer of protection. "
            "(Static sites served by a platform may get these from the "
            "platform instead — check before worrying.)",
            "Add a headers middleware (e.g. helmet for Express) or set "
            "Content-Security-Policy, X-Frame-Options and "
            "X-Content-Type-Options in your server config.",
            check_index=76,
        ))
    return out


def check_firebase_rules(root):
    out = []
    for path in iter_text_files(root):
        if path.name != "firestore.rules" and not path.name.endswith(".rules"):
            continue
        text = read_text(path)
        if text is None:
            continue
        m = FIREBASE_OPEN_RE.search(text)
        if not m:
            continue
        line = text[: m.start()].count("\n") + 1
        out.append(custom_finding(
            "open-db-policy", "Firebase rules allow anyone full access",
            "critical", 24, 0.95, "database", "built-in SAST rules",
            rel(root, path), line,
            "Firestore rule uses `allow ... : if true` — no login required",
            "Your Firestore security rules let ANYONE read and write the "
            "database with no login at all. This is the Firebase equivalent "
            "of leaving the database door wide open — the most common way "
            "vibe-coded apps lose their data.",
            "Require login in the rules, e.g. "
            "`allow read, write: if request.auth != null;` and then narrow "
            "it per-user (request.auth.uid == userId).",
            check_index=77,
        ))
    return out


def scan_sast(root: Path, core_findings):
    root = root.resolve()
    flagged_route_files = {
        f["file"] for f in core_findings if f["type"] == "unprotected-ai-route"
    }
    findings = []
    findings += check_xss(root)
    findings += check_sqli(root)
    findings += check_cmd(root)
    findings += check_weak_crypto(root)
    findings += check_auth_gaps(root, flagged_route_files)
    findings += check_headers(root)
    findings += check_firebase_rules(root)
    return findings
