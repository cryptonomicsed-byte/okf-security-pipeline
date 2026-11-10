# Security scan — sabbathdemo

- target: `` (None)
- isolation: n/a (sabbath gate — static only)
- strix: gemini-flash-lite · 0s · run /opt/ares/strix/strix_runs/test-vuln-app_38de
- started 2026-11-07T17:39:27Z · duration 6s

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

## Since last scan

- new: 2 · persisting: 0 · resolved: 0 · active: 2
  - NEW [ddbd8d8e73bd75d2] SQL Injection in /user endpoint id parameter
  - NEW [337535e9cd63d00b] Server-Side Template Injection (SSTI) in /hello endpoint name parameter

## Receipt

- receipt: `ddf7fb576d4dd4bb7c4349cff95d98302f0f1720531a4685809317ed7dd65155`
- merkle: `0d72368bdad53c92f69efb47c8b9bb6d9635d252c11ffef23cab3f751adc1c80`
- chain_index: 0 · prev: `None`
- artifacts: 1 · diagnostics: 2
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/sabbathdemo/ddf7fb576d4dd4bb.json --files`
