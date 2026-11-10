# Security scan — staticsmoke

- target: `` (None)
- isolation: n/a (static-only)
- strix: gemini-flash-lite · 0s · run /opt/ares/strix/strix_runs/test-vuln-app_38de
- started 2026-11-07T06:20:56Z · duration 3s

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

- sqlmap: `{"injectable": false}`
- sstimap: `{"vulnerable": false}`
- xsstrike: `{"vectors": 0}`
- nmap: `{}`
- ffuf: paths=None
- nuclei: hits=None
- metasploit: `{"server": null}`
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

- receipt: `38928226366f85a826c143683a026c5a2d2d3e4b41b805e2423c85dfb00be994`
- merkle: `c6fdf1dee60f02566e9453be1d89d68a8c669a625973316c0faa1101f5aadf61`
- chain_index: 0 · prev: `None`
- artifacts: 1 · diagnostics: 14
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/staticsmoke/38928226366f85a8.json --files`
