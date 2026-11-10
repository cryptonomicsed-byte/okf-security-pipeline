# Security scan — mem-demo

- target: `http://127.0.0.1:8099` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: gemini-flash-lite · 0s · run /opt/ares/strix/strix_runs/test-vuln-app_38de
- started 2026-11-07T06:15:34Z · duration 23s

## Findings

### [CRITICAL] SQL Injection in /user endpoint id parameter

The `/user` endpoint directly interpolates user input from the `id` parameter into a SQLite query string, leading to SQL Injection.

Agent PoC:

1. Send a GET request to `/user?id=1 OR 1=1`.
2. Observe that all database records are returned.

### [CRITICAL] Server-Side Template Injection (SSTI) in /hello endpoint name parameter

The `/hello` endpoint uses f-string interpolation to include user-supplied input in a template rendered by `render_template_string`, leading to Server-Side Template Injection (SSTI).

Agent PoC:

1. Send a GET request to `/hello?name={{7*7}}`.
2. Observe the response `Hello 49`.
3. Use advanced Jinja2 payloads to achieve remote code execution.

## Independent confirmation

- sqlmap: `{"url": "http://127.0.0.1:8099/user?id=1", "injectable": true, "rc": 0, "dbms": "SQLite", "techniques": ["UNION query", "boolean-based blind"], "dump_rc": 0, "dump_rows": 1, "sensitive_exposed": true, "sample": ["| 1  | flag{super_secret} | admin    |"], "columns": "| id | secret             | username |"}`
- sstimap: `{"url": "http://127.0.0.1:8099/hello?name=1", "vulnerable": true, "confidence": "high", "engine": "Jinja2", "rce": true, "rc": 0}`
- xsstrike: `{"vectors": 0}`
- nmap: `{}`
- ffuf: paths=None
- nuclei: hits=None
- metasploit: `{"server": "Werkzeug/3.0.1 Python/3.12.3", "module": null, "rc": 0, "candidates": ["exploit/multi/http/werkzeug_debug_rce", "exploit/multi/http/werkzeug_debug_rce"]}`
- sweep: `{}`

## Since last scan

- new: 0 · persisting: 2 · resolved: 0 · active: 2
  - PERSISTING [ddbd8d8e73bd75d2] SQL Injection in /user endpoint id parameter (first seen 2026-11-07T06:14:55Z)
  - PERSISTING [337535e9cd63d00b] Server-Side Template Injection (SSTI) in /hello endpoint name parameter (first seen 2026-11-07T06:14:55Z)

## Receipt

- receipt: `51535340006b38fe47e5c5b92ca7b4ad06f1b69abb0d292373ef3229037eea9a`
- merkle: `cfd9d03a6bbfad3c648a3436e931910629d1285d06b4926905396c3ead143f8c`
- chain_index: 1 · prev: `5c8f7ccdb2b130341dc4d3e2b80b889592db7312158554d60643631fe10bb465`
- artifacts: 11 · diagnostics: 2
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/mem-demo/51535340006b38fe.json --files`
