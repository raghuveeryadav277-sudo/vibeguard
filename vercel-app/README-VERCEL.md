# VibeGuard — Vercel version

Serverless adaptation of the VibeGuard app for a public live-demo link.
Same UI, same demo flow (Scan 34 → Fix All 87 → mark rotated 100 → Reset 34),
verified locally on 23 Oct 2026.

Differences from the laptop app (honest list):
- The big scanner binaries (Gitleaks, OSV-Scanner) cannot run on Vercel, so
  scanning uses the built-in rules engine only — same 5 planted findings and
  same scores on the bundled demo app. ZIP-upload scanning also works;
  dependency (OSV) checks are skipped.
- Sessions/settings live in /tmp (Vercel's only writable area), so a scan
  session can reset if the serverless instance recycles. Fine for a demo.
- The laptop app (repo root) remains the full version for the live demo.

Deploy: import the GitHub repo in Vercel, set Root Directory to this folder.
