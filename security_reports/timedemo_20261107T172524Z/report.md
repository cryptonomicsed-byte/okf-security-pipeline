# Security scan — timedemo

- target: `http://127.0.0.1:8099` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: gemini-flash-lite · 0s · run /opt/ares/strix/strix_runs/test-vuln-app_38de
- started 2026-11-07T17:25:24Z · duration 22s

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

- new: 14 · persisting: 0 · resolved: 0 · active: 14
  - NEW [ddbd8d8e73bd75d2] SQL Injection in /user endpoint id parameter
  - NEW [337535e9cd63d00b] Server-Side Template Injection (SSTI) in /hello endpoint name parameter
  - NEW [976ec1b0efcb3dd7] Detector gap: identity obfuscation is not flagged
  - NEW [3687a5ce48785ed0] Detector gap: rot13 obfuscation is not flagged
  - NEW [d67e4f790da1cf9a] Detector gap: hex_escape obfuscation is not flagged
  - NEW [e457967c2d801e44] Detector gap: unicode_escape obfuscation is not flagged
  - NEW [6d2e9bdd1c58772a] Detector gap: spaced obfuscation is not flagged
  - NEW [8fa6cab54e00f13f] Detector gap: fullwidth obfuscation is not flagged
  - NEW [8d75488c3e0ea613] Detector gap: leet obfuscation is not flagged
  - NEW [8f0839bf5da6352a] Detector gap: reversed obfuscation is not flagged
  - NEW [80b9d315fc99aa03] Detector gap: zero_width obfuscation is not flagged
  - NEW [7dc8289051dd5404] Detector gap: base64 obfuscation is not flagged
  - NEW [2befef04e60883d2] Detector gap: base64x2 obfuscation is not flagged
  - NEW [ec2baaf773e9459a] Detector gap: mixed obfuscation is not flagged

## Receipt

- nostr: 5/6 relays accepted
  - ws://127.0.0.1:7788: ok=True id=b1d4702a3285cf09
  - wss://omokoda.duckdns.org:3443/vantage-relay: ok=True id=b1d4702a3285cf09
  - wss://omokoda.duckdns.org:3443/relay: ok=True id=0eda558ef7b4c27d
  - wss://relay.damus.io: ok=False
  - wss://relay.primal.net: ok=True id=129e2b7843b9dc49
  - wss://relay.snort.social: ok=True id=106b7f50b114e86e
- receipt: `1bdfe2d078c6ab7cd981dd8a284103ce1d3dfe0bffb4e6c32d1e82ea5f419a5b`
- merkle: `631efe483edaa6486681083121499ead98285b780b0c0fe0f8ac236c5424cf99`
- chain_index: 0 · prev: `None`
- artifacts: 9 · diagnostics: 14
- timestamp: OpenTimestamps `1bdfe2d078c6ab7c.merkle.txt.ots` (pending Bitcoin attestation)
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/timedemo/1bdfe2d078c6ab7c.json --files`
