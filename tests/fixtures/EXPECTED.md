# VibeGuard — Fixture Expected Findings

All secrets in these fixtures are obviously FAKE placeholders. No real `.env` file is included anywhere.

Use this table to verify the scanner: run it against each fixture app and compare the finding class per file.

## clean-app — should produce NO critical/high findings

| Fixture file | Expected finding class | Notes |
|---|---|---|
| `clean-app/index.html` | none | Has `<title>`, meta description, and `og:title`; uses `textContent` only |
| `clean-app/app.js` | none | Keys from `process.env`; parameterized fetch; no hardcoded secrets |
| `clean-app/supabase/policies.sql` | none | RLS enabled (`ENABLE ROW LEVEL SECURITY`) with restrictive `USING (auth.uid() = user_id)` policy |
| `clean-app/api/chat.js` | none | AI route (`api.openai.com`) WITH Authorization check AND rate limit — counts as protected |
| `clean-app/.gitignore` | none | Contains `.env` (and no actual `.env` file is present) |
| `clean-app/package.json` | none | `lodash 4.17.21` — current, non-vulnerable version |

## sast-app — one file per vulnerability class

| Fixture file | Expected finding class | Trigger |
|---|---|---|
| `sast-app/xss.js` | xss | `element.innerHTML = userInput`; `document.write(...)` with user input |
| `sast-app/xss-react.jsx` | xss | React `dangerouslySetInnerHTML={{ __html: userHtml }}` |
| `sast-app/sqli.js` | sqli | SQL string concatenation `"SELECT * FROM users WHERE id = " + userId` passed to `db.query(...)` |
| `sast-app/cmd.js` | command-injection | `child_process.exec("ls " + userInput)`; `eval(userInput)` |
| `sast-app/cmd.py` | command-injection | `os.system("ping " + host)`; `subprocess.run(cmd, shell=True)` |
| `sast-app/weakcrypto.js` | weak-crypto | `crypto.createHash('md5')` on a password; `Math.random()` used to build a token |
| `sast-app/api/users.js` | missing-auth | API route handler (`export default function handler`) reading/writing DB with NO auth check and NO AI call |
| `sast-app/server.js` | missing-security-headers | Express-style server with no helmet / no header-setting calls, listening on a port |

## deps-app — vulnerable dependencies

| Fixture file | Expected finding class | Trigger |
|---|---|---|
| `deps-app/package.json` | vulnerable-dependency | Pins `lodash 4.17.20` (known-vulnerable) |
| `deps-app/package-lock.json` | vulnerable-dependency | `lockfileVersion 3`, locks `lodash 4.17.20` |
| `deps-app/requirements.txt` | vulnerable-dependency | Pins `requests==2.19.1` (known-vulnerable) |
