"use strict";
let current = null;
let progressTimer = null;

const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function startProgress() {
  $("progress").classList.remove("hidden");
  $("results").classList.add("hidden");
  const steps = document.querySelectorAll("#progress-steps span");
  steps.forEach(s => s.className = "");
  let i = 0;
  steps[0].className = "active";
  progressTimer = setInterval(() => {
    if (i < steps.length - 1) {
      steps[i].className = "done";
      i++;
      steps[i].className = "active";
    }
  }, 1600);
  window.scrollTo({ top: $("progress").offsetTop - 20, behavior: "smooth" });
}

function stopProgress() {
  clearInterval(progressTimer);
  $("progress").classList.add("hidden");
}

async function postJSON(url, obj) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(obj || {}),
  });
  const data = await r.json();
  if (!r.ok || data.error) throw new Error(data.error || ("HTTP " + r.status));
  return data;
}

async function runScan(promise) {
  setBusy(true);
  startProgress();
  try {
    const result = await promise;
    current = result;
    render(result);
  } catch (e) {
    alert("Scan failed: " + e.message);
  } finally {
    stopProgress();
    setBusy(false);
  }
}

function setBusy(b) {
  ["btn-demo", "btn-zip", "btn-path", "btn-fix"].forEach(id => {
    const el = $(id);
    if (el) el.disabled = b;
  });
}

function scoreColor(s) {
  if (s >= 80) return "#2E9E5B";
  if (s >= 50) return "#E8A100";
  return "#D21F00";
}

const TRIAGE_LABEL = {
  gemini: "🤖 Explanations by Gemini AI triage (live)",
  cache: "🤖 Explanations by Gemini AI triage (cached — works offline)",
  offline: "📴 Offline mode — built-in explanations (add a Gemini key in Settings for AI triage)",
};

function render(result) {
  $("results").classList.remove("hidden");
  const ring = $("score-ring");
  ring.style.setProperty("--pct", result.score);
  ring.style.setProperty("--ring", scoreColor(result.score));
  $("score-num").textContent = result.score;
  $("score-num").style.color = scoreColor(result.score);
  $("result-title").textContent = result.project_name;
  $("result-sub").textContent =
    "Scanned " + result.scanned_at + " · " + result.findings.length + " finding(s)";
  $("triage-badge").innerHTML =
    '<span class="badge">' + esc(TRIAGE_LABEL[result.triage_source] || result.triage_source) + "</span>";

  const chips = Object.entries(result.layers)
    .map(([k, v]) => '<span class="chip">' + esc(k) + ": " + v.count + " (−" + v.penalty + ")</span>")
    .join("");
  $("layer-chips").innerHTML = chips;

  const tn = Object.entries(result.tools)
    .map(([k, v]) => "<li><b>" + esc(k) + "</b>: " + esc(v.note || "") + "</li>").join("");
  $("tool-notes").innerHTML = tn ? "<ul>" + tn + "</ul>" : "";

  // advisory
  const adv = $("advisory-slot");
  if (result.advisory) {
    adv.innerHTML =
      '<div class="card advisory"><div class="card-head"><span class="sev info">ADVISORY</span></div>' +
      "<h3>" + esc(result.advisory.title) + "</h3><p>" + esc(result.advisory.why) + "</p>" +
      '<div class="loc">Score impact −' + result.advisory.weight + " until you rotate the keys and confirm below.</div></div>";
    $("btn-rotated").classList.remove("hidden");
  } else {
    adv.innerHTML = "";
    $("btn-rotated").classList.add("hidden");
  }

  $("btn-reset").classList.toggle("hidden", result.kind !== "demo");
  $("btn-report-html").href = "/api/report.html?session=" + encodeURIComponent(result.session_id);
  $("btn-report-json").href = "/api/report.json?session=" + encodeURIComponent(result.session_id);

  if (result.fix_notes && result.fix_notes.length) {
    $("fix-notes").innerHTML = "<b>Fixes applied:</b><ul>" +
      result.fix_notes.map(n => "<li>" + esc(n) + "</li>").join("") + "</ul>";
  } else {
    $("fix-notes").innerHTML = "";
  }

  $("findings-count").textContent = "(" + result.findings.length + ")";
  const wrap = $("findings");
  if (!result.findings.length) {
    wrap.innerHTML = '<div class="card low"><h3>No issues found. Clean. ✅</h3></div>';
  } else {
    wrap.innerHTML = result.findings.map((f, i) => findingCard(f, i)).join("");
  }
  window.scrollTo({ top: $("results").offsetTop - 10, behavior: "smooth" });
}

function findingCard(f, i) {
  const tri = f.triage || {};
  const explanation = tri.explanation || f.why;
  const steps = (tri.fix_steps && tri.fix_steps.length ? tri.fix_steps : [f.fix]).filter(Boolean);
  let sevNote = "";
  if (tri.severity_final && tri.severity_final !== f.severity) {
    sevNote = '<div class="rationale">AI triage adjusted severity to <b>' +
      esc(tri.severity_final) + "</b>: " + esc(tri.rationale || "") + "</div>";
  } else if (tri.rationale) {
    sevNote = '<div class="rationale">' + esc(tri.rationale) + "</div>";
  }
  let dup = "";
  if (tri.duplicate_of !== null && tri.duplicate_of !== undefined) {
    dup = '<div class="dup">Same underlying problem as finding #' + (tri.duplicate_of + 1) + " (per AI triage).</div>";
  }
  const loc = f.file + (f.line ? ":" + f.line : "");
  return '<div class="card ' + esc(f.severity) + '">' +
    '<div class="card-head"><span class="sev ' + esc(f.severity) + '">' + esc(f.severity.toUpperCase()) + "</span>" +
    "<span>#" + (i + 1) + "</span><span>" + esc(f.layer) + "</span>" +
    "<span>found by: " + esc(f.sources.join(", ")) + "</span>" +
    (f.fixable ? "<span>⚒ auto-fix available</span>" : "<span>manual fix</span>") + "</div>" +
    "<h3>" + esc(f.title) + "</h3>" +
    '<div class="loc">' + esc(loc) + " · confidence " + Math.round(f.confidence * 100) + "% · score impact −" + f.weight + "</div>" +
    '<div class="evidence">' + esc(f.evidence) + "</div>" +
    "<p>" + esc(explanation) + "</p>" + sevNote + dup +
    '<div><b>Fix:</b><ul class="fixsteps">' + steps.map(s => "<li>" + esc(s) + "</li>").join("") + "</ul></div>" +
    "</div>";
}

// ---------- wiring ----------
$("btn-demo").onclick = () => runScan(postJSON("/api/scan/demo"));
$("btn-path").onclick = () => {
  const p = $("folder-path").value.trim();
  if (!p) return alert("Pehle folder ka path likho (type the folder path first).");
  runScan(postJSON("/api/scan/path", { path: p }));
};
$("btn-zip").onclick = () => {
  const file = $("zip-file").files[0];
  if (!file) return alert("Pehle ek .zip file chuno (choose a .zip file first).");
  const fd = new FormData();
  fd.append("file", file);
  runScan(fetch("/api/scan/zip", { method: "POST", body: fd }).then(async r => {
    const data = await r.json();
    if (!r.ok || data.error) throw new Error(data.error || ("HTTP " + r.status));
    return data;
  }));
};
$("btn-fix").onclick = () => {
  if (!current) return;
  runScan(postJSON("/api/fix", { session_id: current.session_id }));
};
$("btn-rotated").onclick = () => {
  if (!current) return;
  runScan(postJSON("/api/rotated", { session_id: current.session_id }));
};
$("btn-reset").onclick = () => {
  if (!current) return;
  runScan(postJSON("/api/reset", { session_id: current.session_id }));
};
$("btn-save-key").onclick = async () => {
  const key = $("api-key").value.trim();
  try {
    const r = await postJSON("/api/settings", { gemini_api_key: key });
    $("key-status").textContent = r.has_gemini_key
      ? "✔ Key saved on this computer. Next scan will use AI triage."
      : "Key cleared — offline mode.";
    $("key-status").style.color = "#2E9E5B";
    $("api-key").value = "";
  } catch (e) {
    $("key-status").textContent = "Could not save: " + e.message;
    $("key-status").style.color = "#D21F00";
  }
};

fetch("/api/status").then(r => r.json()).then(s => {
  if (s.has_gemini_key) {
    $("key-status").textContent = "✔ A Gemini key is saved on this computer.";
    $("key-status").style.color = "#2E9E5B";
  }
}).catch(() => {});
