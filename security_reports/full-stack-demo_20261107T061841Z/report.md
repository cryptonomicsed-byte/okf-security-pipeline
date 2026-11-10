# Security scan — full-stack-demo

- target: `http://127.0.0.1:8099` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: gemini-flash-lite · 0s · run /opt/ares/strix/strix_runs/test-vuln-app_38de
- started 2026-11-07T06:18:41Z · duration 25s

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

## Guard-gap probe

- unavailable: skipped

## Since last scan

- new: 0 · persisting: 14 · resolved: 0 · active: 14
  - PERSISTING [ddbd8d8e73bd75d2] SQL Injection in /user endpoint id parameter (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [337535e9cd63d00b] Server-Side Template Injection (SSTI) in /hello endpoint name parameter (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [976ec1b0efcb3dd7] Detector gap: identity obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [3687a5ce48785ed0] Detector gap: rot13 obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [d67e4f790da1cf9a] Detector gap: hex_escape obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [e457967c2d801e44] Detector gap: unicode_escape obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [6d2e9bdd1c58772a] Detector gap: spaced obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [8fa6cab54e00f13f] Detector gap: fullwidth obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [8d75488c3e0ea613] Detector gap: leet obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [8f0839bf5da6352a] Detector gap: reversed obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [80b9d315fc99aa03] Detector gap: zero_width obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [7dc8289051dd5404] Detector gap: base64 obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [2befef04e60883d2] Detector gap: base64x2 obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)
  - PERSISTING [ec2baaf773e9459a] Detector gap: mixed obfuscation is not flagged (first seen 2026-11-07T06:17:45Z)

## Receipt

- receipt: `e7fa7b1584da07a079f99472af498dd40e197b83ec52e576b23984f17b4274da`
- merkle: `f9e542bf8e95e2448e3baf221bfd76a25262199416cd4d17a74603bb35585d79`
- chain_index: 1 · prev: `09460f6d02e8961e9845932854777eecf638c65a40d0a92581c3785ea16adf9b`
- artifacts: 11 · diagnostics: 14
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/full-stack-demo/e7fa7b1584da07a0.json --files`
