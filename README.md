# VibeGuard — Vibe-Code Security Scanner

**Vibe-coded apps ship fast. Security does not.**
VibeGuard gives AI-generated apps a security checkpoint before launch:
it scans the code, explains every problem in plain English, and fixes
what it safely can — one click, before/after score included.

No installs. No terminal. Python 3 only (already on the laptop).

---

## How to start (Windows laptop)

1. Unzip `vibeguard-app.zip` anywhere (Desktop is fine).
2. Open the `vibeguard-app` folder and **double-click `START.bat`**.
3. A black window opens (keep it open!) and VibeGuard opens in your browser
   at `http://127.0.0.1:8765/`.
4. Click **“Demo App Scan Karo”** for the full demo story:
   scan → **Score 34** → **Fix All** → rescan → **Score 87** →
   “I rotated the leaked keys” → **Score 100** → Reset brings it back to 34.
5. To stop: close the black window.

On Linux/macOS use `./start.sh` instead — same app.

> Scans always run on a **copy** inside the app (`data/sessions/`).
> Your original project folder is never modified.

---

## Friday checklist (before the hackathon)

1. **Get a free Gemini API key** (2 minutes):
   open `aistudio.google.com` → sign in → “Get API key” → “Create API key” → copy it.
2. Start VibeGuard, scroll to **Settings**, paste the key, click **Save Key**.
   (The key is stored only on this laptop, in `data/settings.json`. It is never
   printed in any report or log.)
3. Click **Demo App Scan Karo** once **with internet on** — the AI triage result
   is cached inside the app, so on Saturday the demo app shows full AI
   explanations **even if the venue Wi-Fi fails**. Then click **Reset Demo App**.
4. Do one full practice run on this laptop: Demo scan → Fix All → rotated →
   Reset. Also scan one real ZIP/folder so the team has seen all three inputs.
5. Keep this whole folder + the old CLI prototype folder as backup.
   The CLI still works standalone: `./vg scan ./victim-app`.

---

## What it checks (the four layers from the pitch)

| Layer | How | What it finds |
|---|---|---|
| **Secrets** | Gitleaks binary (in `tools/`) + built-in checks (verified CLI rules) | Hardcoded API keys (Supabase service-role, OpenAI, AWS, high-entropy secrets), committed `.env` files |
| **SAST** | Built-in Semgrep-style pattern rules | XSS, SQL injection, command injection, `eval()`, weak crypto (MD5/SHA1, `Math.random` tokens), API routes with no login check, missing security headers |
| **Dependencies** | OSV-Scanner binary (in `tools/`) | Known CVEs in `package.json` / `requirements.txt` etc. (needs internet for the OSV database) |
| **Database** | Built-in checks (verified CLI rules) | Supabase RLS disabled / allow-all policies, open Firebase rules |

Plus **AI triage** (Gemini, with your key): re-checks each finding against its
code, removes duplicates, and rewrites explanations in very simple English with
concrete fix steps. No key / no internet → built-in explanations (offline mode).
The demo can never break because of the AI layer.

**Reports:** every scan can be downloaded as a styled **HTML report** or
**JSON** (for CI / dashboards) from the results screen.

---

## The score — how it works

`Score = max(0, 100 − sum of finding weights − advisory weight)`

| Finding | Weight |
|---|---|
| Leaked service-role key / open database (critical) | −24 each |
| SQL / command injection (critical) | −20 each |
| Vulnerable dependency | −15 / −10 / −5 / −2 (critical→low; layer total capped at −30) |
| Leaked secret found by Gitleaks, XSS, `eval()` | −12 each |
| Committed `.env`, API route with no login check | −8 each |
| Weak crypto | −6 |
| Missing security headers | −3 |
| Missing title/meta tags | −2 |
| Advisory: leaked key removed from code but **not yet rotated** | −13 until you confirm rotation |

The bundled demo app ships with exactly 5 planted holes worth −66 → **34/100**.
Fix All removes the holes but the rotation advisory (−13) remains → **87/100**.
Confirming rotation clears it → **100/100**. This matches the verified CLI
prototype exactly.

---

## Honest limits of this build

- **SAST is built-in pattern rules, not the Semgrep binary.** Semgrep does not
  run natively on a Windows laptop without WSL/Docker, so equivalent
  Semgrep-style rules are built in. Semgrep integration is roadmap. Pattern
  findings show a confidence % — verify before treating them as confirmed.
- **PDF report**: use the HTML report’s Print → “Save as PDF” (same styling).
  A one-click PDF button is roadmap.
- **GitHub URL ingest**: paste a repo URL is roadmap — for now download the
  repo ZIP from GitHub and use **Upload ZIP** (same code path, same result).
- **Auto-fix** covers the proven fix set (secrets out of code, `.env` →
  `.gitignore` + `.env.example`, RLS on + restrictive policy, auth + rate-limit
  guard on AI routes, meta tags). Everything else is reported with concrete
  manual fix steps, never silently “fixed”.
- **OWASP ZAP dynamic scanning** (the pitch’s stretch goal) is not in this
  build — it needs a running, authorized target and is unsafe to demo blind.

---

## Folder map

```
vibeguard-app/
  START.bat          <- double-click this (Windows)
  start.sh           <- same, for Linux/macOS
  run.py             <- entry point
  vg_app/            <- the app (Python standard library only)
  web/               <- the UI (HTML/CSS/JS)
  demo-app/          <- bundled vulnerable demo app (pristine)
  tools/             <- Gitleaks + OSV-Scanner binaries (Windows + Linux)
  cache/             <- cached AI triage (offline demo safety net)
  data/              <- your settings + scan sessions (created at runtime)
  tests/             <- fixtures used to verify this build
```

## Troubleshooting

- **Browser didn’t open**: type `http://127.0.0.1:8765/` in the browser yourself.
- **“Python not found”**: install Python 3 from python.org and tick
  “Add Python to PATH”, then double-click START.bat again.
- **Port busy**: the app automatically tries the next port (8766, 8767…);
  the black window prints the actual address.
- **OSV/Gitleaks “skipped” note in a scan**: the rest of the scan is complete;
  the note in the results screen says exactly why (usually: no internet for OSV).
