"""External tool layers: Gitleaks (secrets) and OSV-Scanner (dependencies).

Both are optional accelerators. If a binary is missing or fails, the
built-in checks still run and the scan result says so honestly.
Raw secrets from tool output are NEVER stored — findings carry masked
values only, and raw tool reports are deleted right after parsing.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

from . import core
from .core import custom_finding, mask_secret

APP_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = APP_DIR / "tools"

MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pipfile.lock", "poetry.lock", "go.mod", "go.sum",
    "gemfile.lock", "cargo.lock", "composer.lock",
}


def _is_windows():
    return sys.platform.startswith("win")


def tool_path(kind):
    """kind: 'gitleaks' | 'osv'. Returns Path or None."""
    if kind == "gitleaks":
        p = (TOOLS_DIR / "gitleaks-windows" / "gitleaks.exe") if _is_windows() \
            else (TOOLS_DIR / "gitleaks-linux" / "gitleaks")
    else:
        p = (TOOLS_DIR / "osv-windows" / "osv-scanner.exe") if _is_windows() \
            else (TOOLS_DIR / "osv-linux" / "osv-scanner")
    return p if p.exists() else None


def _run(cmd, timeout):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def tool_version(kind):
    p = tool_path(kind)
    if not p:
        return None
    flag = "version" if kind == "gitleaks" else "--version"
    r = _run([str(p), flag], 20)
    if r is None:
        return None
    out = (r.stdout or r.stderr or "").strip().splitlines()
    return out[0].strip() if out else "unknown"


# ---------------------------------------------------------------------------
# Gitleaks
# ---------------------------------------------------------------------------

def run_gitleaks(root: Path, tmp_dir: Path):
    """Returns (raw_results_list, status_dict)."""
    status = {"ran": False, "version": tool_version("gitleaks"), "note": ""}
    p = tool_path("gitleaks")
    if not p:
        status["note"] = "Gitleaks binary not found in tools/ — built-in secret checks only."
        return [], status
    report = tmp_dir / "gitleaks-report.json"
    cmd = [str(p), "detect", "--source", str(root), "--no-git",
           "--report-format", "json", "--report-path", str(report),
           "--exit-code", "0"]
    r = _run(cmd, 120)
    if r is not None and not report.exists():
        # Newer gitleaks renamed detect -> dir (retry only on fast failure)
        cmd = [str(p), "dir", str(root), "--report-format", "json",
               "--report-path", str(report), "--exit-code", "0"]
        r = _run(cmd, 120)
    if r is None or not report.exists():
        status["note"] = "Gitleaks failed to run — built-in secret checks only."
        return [], status
    try:
        results = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        results = []
    try:
        report.unlink()  # raw secrets never stay on disk in our data
    except OSError:
        pass
    status["ran"] = True
    status["note"] = f"Gitleaks reported {len(results)} raw hit(s) before de-duplication."
    return results, status


def merge_gitleaks(root: Path, core_findings, raw_results):
    """Merge Gitleaks hits into built-in findings where they corroborate;
    genuinely new secrets become their own findings. Returns new findings."""
    new_findings = []
    by_file = {}
    for f in core_findings:
        by_file.setdefault(f["file"].replace("\\", "/"), []).append(f)

    for hit in raw_results:
        hfile = str(hit.get("File", "")).replace("\\", "/")
        # Gitleaks File may be absolute or relative depending on version.
        try:
            hfile_rel = str(Path(hfile).resolve().relative_to(root.resolve()))
        except (ValueError, OSError):
            hfile_rel = hfile
        hfile_rel = hfile_rel.replace("\\", "/")
        hline = hit.get("StartLine")
        rule = hit.get("RuleID", "secret")
        secret_masked = mask_secret(hit.get("Secret", "") or "")
        merged = False

        candidates = by_file.get(hfile_rel, [])
        # 1) same file, same/adjacent line as a built-in finding
        for f in candidates:
            if f["line"] is not None and hline is not None and abs(f["line"] - hline) <= 1:
                _merge_into(f, rule, secret_masked)
                merged = True
                break
        # 2) hit inside a .env file that the env-committed check already owns
        if not merged and core.ENV_FILE_RE.match(Path(hfile_rel).name):
            for f in candidates:
                if f["type"] == "env-committed":
                    _merge_into(f, rule, secret_masked)
                    merged = True
                    break
        # 3) same file as a built-in leaked-secret finding (line drift ok)
        if not merged:
            for f in candidates:
                if f["type"] == "leaked-supabase-key" and (
                        f["line"] is None or hline is None or abs(f["line"] - hline) <= 3):
                    _merge_into(f, rule, secret_masked)
                    merged = True
                    break
        if merged:
            continue

        new_findings.append(custom_finding(
            "leaked-secret",
            f"Secret detected by Gitleaks ({rule})",
            "high", 12, 0.90, "secrets", "gitleaks",
            hfile_rel, hline,
            f"{rule}: {secret_masked}",
            "Gitleaks — the industry-standard secret scanner — found what "
            "looks like a live credential in your code. Any secret that has "
            "been committed or shipped should be treated as public: bots "
            "scan new code for exactly these patterns within minutes.",
            "Remove the secret from code, load it from an environment "
            "variable instead, and rotate it in the provider dashboard — "
            "deleting it from code does not un-leak it.",
            check_index=55,
        ))
    return new_findings


def _merge_into(finding, rule, secret_masked):
    if "gitleaks" not in finding["sources"]:
        finding["sources"].append("gitleaks")
    note = f"also detected by Gitleaks ({rule}: {secret_masked})"
    if note not in finding["evidence"]:
        finding["evidence"] = (finding["evidence"] + "; " + note) if finding["evidence"] else note
    finding["confidence"] = max(finding["confidence"], 0.97)


# ---------------------------------------------------------------------------
# OSV-Scanner
# ---------------------------------------------------------------------------

def has_manifests(root: Path):
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in core.SKIP_DIRS]
        if any(name.lower() in MANIFEST_NAMES for name in filenames):
            return True
    return False


def _osv_reachable():
    """Fast pre-flight: can we reach the OSV database API at all?
    Prevents a multi-minute hang when the machine is offline."""
    import os
    import urllib.error
    import urllib.request
    url = os.environ.get("VIBEGUARD_OSV_API_URL", "https://api.osv.dev/v1/query")
    req = urllib.request.Request(
        url, data=b"{}",
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            resp.read(64)
        return True
    except urllib.error.HTTPError:
        return True  # the server answered (even a 400) — it is reachable
    except Exception:
        return False


def run_osv(root: Path, tmp_dir: Path):
    """Returns (findings, status_dict)."""
    status = {"ran": False, "version": tool_version("osv"), "note": ""}
    p = tool_path("osv")
    if not p:
        status["note"] = "OSV-Scanner binary not found in tools/ — dependency check skipped."
        return [], status
    if not has_manifests(root):
        status["note"] = "No dependency manifest (package.json / requirements.txt / ...) found — nothing to check."
        return [], status
    if not _osv_reachable():
        status["note"] = ("Could not reach the OSV vulnerability database "
                          "(api.osv.dev) — dependency check skipped. Connect to the "
                          "internet and scan again for CVE results; every other layer is complete.")
        return [], status
    out_file = tmp_dir / "osv-report.json"
    version = status["version"] or ""
    is_v2 = ("version: 2" in version) or version.strip().startswith("2")
    if is_v2:
        cmd = [str(p), "scan", "--format", "json", "--output", str(out_file), str(root)]
    else:
        cmd = [str(p), "--format", "json", "--output", str(out_file), "-r", str(root)]
    r = _run(cmd, 90)
    if r is not None and not out_file.exists() and is_v2:
        # Fast failure (not a timeout) — likely a syntax surprise; try v1 form once.
        cmd = [str(p), "--format", "json", "--output", str(out_file), "-r", str(root)]
        r = _run(cmd, 90)
    if r is None or not out_file.exists():
        status["note"] = ("OSV-Scanner did not finish (timeout or error reaching the OSV "
                          "database) — dependency check skipped, rest of the scan is complete.")
        return [], status
    try:
        data = json.loads(out_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        status["note"] = "OSV-Scanner output could not be parsed — dependency check skipped."
        return [], status
    try:
        out_file.unlink()
    except OSError:
        pass
    status["ran"] = True
    findings = parse_osv(root, data)
    status["note"] = f"OSV-Scanner reported {len(findings)} vulnerable dependency finding(s)."
    return findings, status


_SEV_WEIGHT = {"critical": 15, "high": 10, "medium": 5, "low": 2}
_SEV_TEXT_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
                "MEDIUM": "medium", "LOW": "low"}


def _cvss_bucket(vector):
    """Rough severity bucket from a CVSS v3 vector string."""
    m = re.search(r"CVSS:3\.\d+/(.*)", vector or "")
    if not m:
        return "medium"
    parts = dict(kv.split(":") for kv in m.group(1).split("/") if ":" in kv)
    # Approximation of the CVSS v3 base score, bucketed (documented as rough).
    impact_high = parts.get("C") == "H" or parts.get("I") == "H" or parts.get("A") == "H"
    if (impact_high and parts.get("AV") == "N" and parts.get("AC") == "L"
            and parts.get("PR") == "N" and parts.get("UI") == "N"):
        return "critical"
    if impact_high:
        return "high"
    if parts.get("C") == "N" and parts.get("I") == "N" and parts.get("A") == "N":
        return "low"
    return "medium"


def _vuln_severity(vuln):
    db = vuln.get("database_specific") or {}
    sev = db.get("severity")
    if sev and sev.upper() in _SEV_TEXT_MAP:
        return _SEV_TEXT_MAP[sev.upper()]
    for s in vuln.get("severity") or []:
        if "CVSS" in (s.get("type") or ""):
            return _cvss_bucket(s.get("score", ""))
    return "medium"


def parse_osv(root: Path, data):
    findings = []
    for result in data.get("results", []):
        src = (result.get("source") or {}).get("path", "")
        try:
            src_rel = str(Path(src).resolve().relative_to(root.resolve()))
        except (ValueError, OSError):
            src_rel = src
        src_rel = src_rel.replace("\\", "/")
        for pkg_wrap in result.get("packages", []):
            pkg = pkg_wrap.get("package", {})
            name = pkg.get("name", "unknown")
            version = pkg.get("version", "?")
            ecosystem = pkg.get("ecosystem", "")
            for vuln in pkg_wrap.get("vulnerabilities", []):
                vid = vuln.get("id", "unknown")
                aliases = [a for a in vuln.get("aliases", []) if a.startswith("CVE")]
                cve = aliases[0] if aliases else vid
                severity = _vuln_severity(vuln)
                summary = (vuln.get("summary") or "Known vulnerability").strip()
                fixed = []
                for aff in vuln.get("affected", []):
                    for rng in aff.get("ranges", []):
                        for ev in rng.get("events", []):
                            if "fixed" in ev:
                                fixed.append(ev["fixed"])
                fix_text = (
                    f"Upgrade {name} to {fixed[0]} or later "
                    f"(`npm audit fix` / update the pinned version), then re-scan."
                    if fixed else
                    f"Upgrade {name} to the latest patched release, then re-scan."
                )
                findings.append(custom_finding(
                    "vulnerable-dependency",
                    f"Vulnerable dependency: {name} {version} ({cve})",
                    severity, _SEV_WEIGHT[severity], 0.95,
                    "dependencies", "osv-scanner",
                    src_rel, None,
                    f"{name}@{version} ({ecosystem}) — {cve}: {summary[:120]}",
                    "Your app ships a library version with a publicly known "
                    "vulnerability. Attackers keep lists of exactly these "
                    "versions and scan for apps still using them — no skill "
                    "required. This is the supply-chain hole vibe-coded apps "
                    "most often forget.",
                    fix_text,
                    check_index=80,
                ))
    return findings
