"""Standalone HTML + JSON reports, styled after the team PPT
(black / white / bold red-orange)."""

import html
import json

from . import __version__

ACCENT = "#FF4A1C"
SEV_COLORS = {
    "critical": "#D21F00",
    "high": "#FF4A1C",
    "medium": "#E8A100",
    "low": "#2E9E5B",
    "info": "#3A7BD5",
}


def score_color(score):
    if score >= 80:
        return "#2E9E5B"
    if score >= 50:
        return "#E8A100"
    return "#D21F00"


def report_json(result):
    return json.dumps({
        "tool": "VibeGuard",
        "version": __version__,
        "project": result["project_name"],
        "scanned_at": result["scanned_at"],
        "score": result["score"],
        "triage_source": result["triage_source"],
        "tool_versions": result["tool_versions"],
        "tools": result["tools"],
        "layers": result["layers"],
        "findings": [
            {k: f[k] for k in ("type", "title", "severity", "weight",
                                "confidence", "layer", "sources", "file",
                                "line", "evidence", "why", "fix")}
            | {"triage": f.get("triage")}
            for f in result["findings"]
        ],
        "advisory": result["advisory"],
        "fixes_applied": result.get("fix_notes", []),
    }, indent=2)


def report_html(result):
    e = html.escape
    score = result["score"]
    sc = score_color(score)
    findings_html = []
    for i, f in enumerate(result["findings"], 1):
        sev = f["severity"]
        color = SEV_COLORS.get(sev, "#333")
        loc = f["file"] + (f":{f['line']}" if f["line"] else "")
        tri = f.get("triage") or {}
        explanation = tri.get("explanation") or f["why"]
        steps = tri.get("fix_steps") or ([f["fix"]] if f["fix"] else [])
        steps_html = "".join(f"<li>{e(s)}</li>" for s in steps)
        sev_note = ""
        if tri.get("severity_final") and tri["severity_final"] != sev:
            sev_note = (f"<div class='rationale'>AI triage adjusted severity "
                        f"to <b>{e(tri['severity_final'])}</b>: "
                        f"{e(tri.get('rationale', ''))}</div>")
        elif tri.get("rationale"):
            sev_note = f"<div class='rationale'>{e(tri['rationale'])}</div>"
        dup = ""
        if tri.get("duplicate_of") is not None:
            dup = (f"<div class='rationale'>Same underlying problem as "
                   f"finding #{tri['duplicate_of'] + 1} (AI triage).</div>")
        findings_html.append(f"""
        <div class="card" style="border-left:8px solid {color}">
          <div class="card-head">
            <span class="sev" style="background:{color}">{e(sev.upper())}</span>
            <span class="num">#{i}</span>
            <span class="layer">{e(f['layer'])}</span>
            <span class="src">found by: {e(', '.join(f['sources']))}</span>
          </div>
          <h3>{e(f['title'])}</h3>
          <div class="loc">{e(loc)} &nbsp;·&nbsp; confidence {int(f['confidence'] * 100)}% &nbsp;·&nbsp; score impact −{f['weight']}</div>
          <div class="evidence">{e(f['evidence'])}</div>
          <p>{e(explanation)}</p>
          {sev_note}{dup}
          <div class="fix"><b>Fix:</b><ul>{steps_html}</ul></div>
        </div>""")

    advisory_html = ""
    if result.get("advisory"):
        a = result["advisory"]
        advisory_html = f"""
        <div class="card advisory">
          <div class="card-head"><span class="sev" style="background:{SEV_COLORS['info']}">ADVISORY</span></div>
          <h3>{e(a['title'])}</h3>
          <p>{e(a['why'])}</p>
          <div class="loc">score impact −{a['weight']} until resolved</div>
        </div>"""

    fixes_html = ""
    if result.get("fix_notes"):
        items = "".join(f"<li>{e(n)}</li>" for n in result["fix_notes"])
        fixes_html = f"<h2>Fixes applied</h2><ul class='fixes'>{items}</ul>"

    layers_html = "".join(
        f"<tr><td>{e(k)}</td><td>{v['count']}</td><td>−{v['penalty']}</td></tr>"
        for k, v in sorted(result["layers"].items())
    ) or "<tr><td colspan='3'>No findings in any layer.</td></tr>"

    tools_html = "".join(
        f"<li><b>{e(name)}</b>: {e(status.get('note', ''))}</li>"
        for name, status in result["tools"].items()
    )
    versions = result.get("tool_versions", {})
    versions_html = " · ".join(
        f"{e(k)}: {e(v or 'not installed')}" for k, v in versions.items())

    triage_label = {
        "gemini": "Gemini AI triage (live)",
        "cache": "Gemini AI triage (cached — works offline)",
        "offline": "Offline mode — built-in explanations (add a Gemini key in Settings for AI triage)",
    }.get(result["triage_source"], result["triage_source"])

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>VibeGuard Report — {e(result['project_name'])}</title>
<style>
  body {{ font-family: Arial, Helvetica, sans-serif; margin:0; background:#fff; color:#111; }}
  header {{ background:#000; color:#fff; padding:28px 36px; }}
  header .brand {{ font-size:15px; letter-spacing:3px; color:{ACCENT}; font-weight:bold; }}
  header h1 {{ margin:6px 0 2px; font-size:34px; }}
  header .sub {{ color:#bbb; font-size:14px; }}
  .scoreband {{ display:flex; align-items:center; gap:28px; padding:26px 36px; border-bottom:4px solid #000; }}
  .score {{ font-size:84px; font-weight:900; color:{sc}; line-height:1; }}
  .score small {{ font-size:24px; color:#666; }}
  .meta {{ font-size:14px; color:#444; line-height:1.7; }}
  main {{ padding:10px 36px 40px; max-width:980px; }}
  h2 {{ font-size:22px; border-bottom:3px solid {ACCENT}; padding-bottom:6px; }}
  table {{ border-collapse:collapse; margin:10px 0 4px; }}
  td {{ border:1px solid #ddd; padding:6px 14px; font-size:14px; }}
  .card {{ border:1px solid #ddd; border-radius:6px; padding:16px 20px; margin:16px 0; }}
  .card.advisory {{ background:#F2F7FF; }}
  .card-head {{ display:flex; gap:10px; align-items:center; font-size:12px; color:#666; }}
  .sev {{ color:#fff; padding:3px 10px; border-radius:3px; font-weight:bold; letter-spacing:1px; }}
  .card h3 {{ margin:10px 0 6px; font-size:19px; }}
  .loc {{ color:#666; font-size:13px; }}
  .evidence {{ background:#FFF3EF; border:1px solid #FFD9CC; padding:8px 12px; font-family:Consolas, monospace; font-size:13px; margin:10px 0; word-break:break-all; }}
  .rationale {{ color:#555; font-style:italic; font-size:13px; margin:6px 0; }}
  .fix ul, ul.fixes {{ margin:6px 0; }}
  footer {{ background:#000; color:#999; padding:20px 36px; font-size:12px; line-height:1.7; }}
</style></head><body>
<header>
  <div class="brand">VIBEGUARD — SECURITY REPORT</div>
  <h1>{e(result['project_name'])}</h1>
  <div class="sub">Scanned {e(result['scanned_at'])} · {len(result['findings'])} finding(s)</div>
</header>
<div class="scoreband">
  <div class="score">{score}<small>/100</small></div>
  <div class="meta">
    <b>Explanations:</b> {e(triage_label)}<br>
    <b>Tool versions:</b> {versions_html}<br>
    Score = 100 − sum of finding weights (critical secrets &amp; open databases hurt most;
    dependency findings are capped at 30 points total). Full formula in the app README.
  </div>
</div>
<main>
  <h2>Findings by layer</h2>
  <table><tr><td><b>Layer</b></td><td><b>Findings</b></td><td><b>Score impact</b></td></tr>{layers_html}</table>
  <h2>Tool notes</h2><ul>{tools_html}</ul>
  <h2>Findings</h2>
  {''.join(findings_html) if findings_html else '<p><b>No issues found. Clean.</b></p>'}
  {advisory_html}
  {fixes_html}
</main>
<footer>
  Generated by VibeGuard {e(__version__)} — a hackathon build.<br>
  Honest notes: the SAST layer uses built-in Semgrep-style pattern rules (Semgrep itself does not run
  natively on Windows laptops without WSL/Docker; binary integration is roadmap). Pattern-based
  findings are marked with their confidence — verify before treating them as confirmed.
  Secrets shown in this report are masked. Fixes are applied only to the scanned copy inside the app,
  never to your original folder.
</footer>
</body></html>"""
