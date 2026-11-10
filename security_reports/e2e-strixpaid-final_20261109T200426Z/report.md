# Security scan — e2e-strixpaid-final

- target: `http://127.0.0.1:8098` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: strix-paid · 468s · run /opt/ares/strix/strix_runs/test-vuln-hard_7c9b
- started 2026-11-09T20:04:26Z · duration 854s

## Findings

### [CRITICAL] Server-Side Template Injection (Jinja2) to Remote Code Execution in POST /render `tpl` form field

The `POST /render` endpoint passes the user-supplied form field `tpl` directly to `flask.render_template_string()`, which compiles and evaluates it with the default, unsandboxed Jinja2 environment. Any unauthenticated client that can send a form-encoded POST can therefore evaluate arbitrary template expressions, walk Python object internals, and execute operating-system commands as the account running the application.

Agent PoC:

1. Identify the transport: the endpoint accepts only POST with an `application/x-www-form-urlencoded` body; GET and PUT return 405.
2. Send a benign form field `tpl=hello` and confirm it is echoed back as `hello`, establishing baseline behavior.
3. Send `tpl={{7*7}}` and observe the response body `49`, then `tpl={{7*8}}` and observe `56`. This proves the input is evaluated as server-side template syntax rather than merely reflected.
4. Fingerprint the engine by sending `${7*7}`, `<%= 7*7 %>` and `#{7*7}` (all returned verbatim) and `{{7*"7"}}` (returns `7777777`), confirming the engine is Jinja2, not Mako or Twig/EJS.
5. Confirm internal object access with `tpl={{config}}` and `tpl={{lipsum.__globals__}}`, which return the Flask configuration and the `jinja2.utils` module globals.
6. Achieve command execution with `tpl={{cycler.__init__.__globals__.os.popen('id').read()}}`; the response body is the real output of `id`.
7. Repeat with `uname -a`, `cat /etc/hostname` and `env` through the same `.os.popen(...).read()` primitive to demonstrate arbitrary command execution and data exfiltration.
8. Replay the request against the patched application (rendering a static template with the value passed as a context variable) and confirm the payloads are returned as literal text and no command runs.

### [HIGH] SQL Injection via ORDER BY clause in GET /orders sort parameter

The `sort` query parameter of `GET /orders` is interpolated directly into the `ORDER BY` clause of a SQLite statement, allowing arbitrary SQL expressions to be injected. Because a sort expression produces no visible output, the flaw yields a fully deterministic **blind boolean oracle**: an attacker defines a predicate over any table and reads its truth value from the ordering of the returned rows. Using that oracle, the `note` column (which the query never selects) was extracted character by character, and the database version and schema were enumerated.

Agent PoC:

1. Confirm the parameter changes row ordering legitimately: request `/orders?sort=id` (rows ordered 1,2,3) and `/orders?sort=qty` (rows ordered 3,1,2). Record both as the two reference orderings.
2. Confirm the value is parsed as SQL syntax rather than a literal: request `/orders?sort=nosuchcol` and observe the HTTP 500 with `no such column: nosuchcol`.
3. Send the blind predicate `/orders?sort=(CASE WHEN (SELECT substr(note,1,5) FROM orders WHERE id=1)='flag{' THEN id ELSE qty END)` and observe the response ordered 1,2,3 (predicate true).
4. Send the same request with a deliberately false predicate (`='zzzz{'`) and observe the response ordered 3,1,2 (predicate false). The response body is byte-identical in length, so only ordering distinguishes the cases.
5. Automate steps 3–4 over an alphabet and character positions to recover the full `note` value of the first row, then over `sqlite_master` to recover the schema and `sqlite_version()`.

### [HIGH] SQL Injection in POST /orders/by-sku JSON sku field (UNION-based data and schema disclosure)

The `sku` field of the JSON body posted to `POST /orders/by-sku` is interpolated into a quoted string literal in a SQLite `WHERE` clause. A single-quote character breaks out of the literal, allowing boolean conditions and `UNION SELECT` statements to be appended. The confirmation retrieved every row of the `orders` table — including the `note` column the endpoint exposes for only one row — and dumped the table schema and engine version.

Agent PoC:

1. Establish the baseline: POST `{"sku":"alpha"}` to `/orders/by-sku` and note the single returned row `[[1,"alpha","flag{orderby_ok}"]]`.
2. Prove the value is parsed as SQL by injecting a boolean: POST `{"sku":"alpha' AND '1'='1"}` (returns the baseline row) and then `{"sku":"alpha' AND '1'='2"}` (returns `[]`). The identical response length with a different result confirms the condition is evaluated by the database.
3. Prove arbitrary row access: POST `{"sku":"x' UNION SELECT id, sku, note FROM orders WHERE '1'='1"}` and observe all three rows returned, including `note` values the endpoint would never return for a single-SKU lookup.
4. Prove schema access: POST `{"sku":"x' UNION SELECT 1,name,sql FROM sqlite_master WHERE '1'='1"}` and observe the `CREATE TABLE` statement for `orders`.
5. Optionally repeat with `{"sku":"x' UNION SELECT 1, sqlite_version(), (SELECT group_concat(name) FROM sqlite_master) WHERE '1'='1"}` for version and object enumeration.

### [ERROR] Server-Side Template Injection (Jinja2) to Remote Code Execution in POST /render `tpl` form field

The `POST /render` endpoint passes the user-supplied form fie

Server-Side Template Injection (Jinja2) to Remote Code Execution in POST /render `tpl` form field

The `POST /render` endpoint passes the user-supplied form field `tpl` directly to `flask.render_template_string()`, which compiles and evaluates it with the default, unsandboxed Jinja2 environment. Any unauthenticated client that can send a form-encoded POST can therefore evaluate arbitrary template expressions, walk Python object internals, and execute operating-system commands as the account running the application.

### [ERROR] SQL Injection via ORDER BY clause in GET /orders sort parameter

The `sort` query parameter of `GET /orders` is interpolated directly into the `ORDER BY` clause

SQL Injection via ORDER BY clause in GET /orders sort parameter

The `sort` query parameter of `GET /orders` is interpolated directly into the `ORDER BY` clause of a SQLite statement, allowing arbitrary SQL expressions to be injected. Because a sort expression produces no visible output, the flaw yields a fully deterministic **blind boolean oracle**: an attacker defines a predicate over any table and reads its truth value from the ordering of the returned rows. Using that oracle, the `note` column (which the query never selects) was extracted character by character, and the database version and schema were enumerated.

### [ERROR] SQL Injection in POST /orders/by-sku JSON sku field (UNION-based data and schema disclosure)

The `sku` field of the JSON body posted to `POST /orders/by-sku` i

SQL Injection in POST /orders/by-sku JSON sku field (UNION-based data and schema disclosure)

The `sku` field of the JSON body posted to `POST /orders/by-sku` is interpolated into a quoted string literal in a SQLite `WHERE` clause. A single-quote character breaks out of the literal, allowing boolean conditions and `UNION SELECT` statements to be appended. The confirmation retrieved every row of the `orders` table — including the `note` column the endpoint exposes for only one row — and dumped the table schema and engine version.

## Secret scan (betterleaks)

- **50 secret leak(s) found** (values redacted)

  - `generic-credential-uri` · /repo/app.log:4866
  - `generic-credential-uri` · /repo/app.log:4866
  - `generic-api-key` · /repo/app.log:5559
  - `generic-credential-uri` · /repo/app.log:8536
  - `generic-credential-uri` · /repo/app.log:8537
  - `generic-credential-uri` · /repo/app.log:8538
  - `generic-credential-uri` · /repo/app.log:8539
  - `generic-credential-uri` · /repo/app.log:8540
  - `generic-credential-uri` · /repo/app.log:8541
  - `generic-credential-uri` · /repo/app.log:8542
  - `generic-credential-uri` · /repo/app.log:8543
  - `generic-credential-uri` · /repo/app.log:8544
  - `generic-credential-uri` · /repo/app.log:8545
  - `generic-credential-uri` · /repo/app.log:8546
  - `generic-credential-uri` · /repo/app.log:8547

## Independent confirmation

- sqlmap: `{"url": "http://127.0.0.1:8098/orders?sort=1", "injectable": true, "rc": 0, "dbms": "SQLite", "techniques": ["boolean-based blind"], "tables": ["orders"], "dump_rc": 0, "dump_rows": 3, "dumped_table": "orders", "sensitive_exposed": true, "sample": ["| 1  | 3   | alpha | flag{orderby_ok} |", "| 2  | 7   | beta  | nothing          |", "| 3  | 1   | gamma | x                |"], "columns": "| id | qty | sku   | note             |"}`
- sqlmap (POST body): not reproduced — no POST body injection reproduced
- injection proof (cmdi/traversal): `{"cmdi": [], "traversal": [], "default_exec": [], "requests": 42}`
- sstimap: `{"url": "http://127.0.0.1:8098/render", "vulnerable": true, "confidence": "high", "engine": "Jinja2", "rce": true, "rc": 0, "post_param": "tpl", "post_data_type": "form", "via": "POST body"}`
- xsstrike: `{"vectors": 0}`
- nmap: `{"host": "127.0.0.1", "port": 8098, "services": [["unknown", "1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :"]], "rc": 0}`
- ffuf: paths=1
- nuclei: hits=0
- metasploit: `{"server": "Werkzeug/3.0.1 Python/3.12.3", "module": null, "rc": 0, "candidates": ["exploit/multi/http/werkzeug_debug_rce", "exploit/multi/http/werkzeug_debug_rce"]}`
- sweep: `{"candidates": 14, "sstimap_hits": [], "sstimap_low": [], "xsstrike_hits": []}`

## Guard-gap probe (tripwire)

- transforms flagged: 100% (flag>=0.6, block>=0.9)
- control ('ignore your instructions'): OK · composite 1.0
- guard gaps (below flag threshold): 0/12
  - identity: mean 0.6 · flag 100% · block 0%
  - base64: mean 0.6 · flag 100% · block 0%
  - base64x2: mean 0.6 · flag 100% · block 0%
  - rot13: mean 0.6 · flag 100% · block 0%
  - hex_escape: mean 0.6 · flag 100% · block 0%
  - unicode_escape: mean 0.6 · flag 100% · block 0%

## Since last scan

- new: 6 · persisting: 0 · resolved: 0 · active: 6
  - NEW [1aca562bde3af4ca] Server-Side Template Injection (Jinja2) to Remote Code Execution in POST /render `tpl` form field
  - NEW [91099c53f2c1a125] SQL Injection via ORDER BY clause in GET /orders sort parameter
  - NEW [04ecb6dd9b3eee01] SQL Injection in POST /orders/by-sku JSON sku field (UNION-based data and schema disclosure)
  - NEW [f3575643910a3d0b] Server-Side Template Injection (Jinja2) to Remote Code Execution in POST /render `tpl` form field

The `POST /
  - NEW [3de400af8797a175] SQL Injection via ORDER BY clause in GET /orders sort parameter

The `sort` query parameter of `GET /orders` i
  - NEW [3a90b9ea0a674898] SQL Injection in POST /orders/by-sku JSON sku field (UNION-based data and schema disclosure)

The `sku` field 

## Receipt

- receipt: `495a937b77c261432c0db1fc8aa00ce49c7ee218371b8771c0e20de0430053c7`
- merkle: `b0acd9c2fa1c846678138238874570d28ba1315a83530455f1e632470975400d`
- chain_index: 0 · prev: `None`
- artifacts: 20 · diagnostics: 6
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/e2e-strixpaid-final/495a937b77c26143.json --files`
