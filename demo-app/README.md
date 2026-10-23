# QuickNotes — victim app (VibeGuard demo)

A small AI notes app, built the typical vibe-coded way: looks fine, works fine,
and is full of security holes underneath.

**All keys in this folder are FAKE placeholders**, planted on purpose for the
hackathon demo. They follow real key formats so the scanner can find them, but
they do not work and were never real secrets.

Planted flaws (5):
1. Supabase **service-role key hardcoded** in `app.js` (frontend code)
2. Supabase table with **RLS disabled / allow-all policy** in `supabase/policies.sql`
3. **`.env` committed** (contains an OpenAI-style key) and missing from `.gitignore`
4. **AI API route with no auth and no rate limit** in `api/summarize.js`
5. **Missing `<title>` / meta description / OG tags** in `index.html`

Run the demo from `~/workspace/vibeguard/`:

```
./vibeguard scan ./victim-app        # Score: 34, top-5 findings
./vibeguard fix ./victim-app        # preview the diffs
./vibeguard fix --apply-all ./victim-app
./vibeguard scan ./victim-app       # Score: 87 — fixed and verified
```
