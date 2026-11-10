# Security scan — test-vuln-hard

- target: `http://127.0.0.1:8098` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: gemini-flash-lite · 1096s · run /opt/ares/strix/strix_runs/test-vuln-hard_671a
- started 2026-11-07T20:35:23Z · duration 1513s

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

### [ERROR] Server-Side Template Injection (SSTI) leading to RCE in /render

Server-Side Template Injection (SSTI) in the `/render` endpoint allows unauthenticated remote c

Server-Side Template Injection (SSTI) leading to RCE in /render

Server-Side Template Injection (SSTI) in the `/render` endpoint allows unauthenticated remote code execution via the `tpl` form parameter.

### [ERROR] SQL Injection in GET /orders sort parameter

The GET /orders endpoint directly interpolates the 'sort' query parameter into an SQL ORDER BY clause without sanit

SQL Injection in GET /orders sort parameter

The GET /orders endpoint directly interpolates the 'sort' query parameter into an SQL ORDER BY clause without sanitization or parameterization, allowing boolean-based blind SQL injection and data exfiltration.

### [ERROR] SQL Injection in POST /orders/by-sku sku parameter

The POST /orders/by-sku endpoint directly interpolates the JSON 'sku' parameter into an SQL WHERE clause wit

SQL Injection in POST /orders/by-sku sku parameter

The POST /orders/by-sku endpoint directly interpolates the JSON 'sku' parameter into an SQL WHERE clause without parameterization, enabling SQL injection and full data exfiltration.

## Secret scan (betterleaks)

- no leaks found (rc=0)

## Independent confirmation

- sqlmap: `{"url": "http://127.0.0.1:8098/orders?sort=1", "injectable": true, "rc": 0, "dbms": "SQLite", "techniques": ["boolean-based blind"], "tables": ["orders"], "dump_rc": 0, "dump_rows": 3, "dumped_table": "orders", "sensitive_exposed": true, "sample": ["| 1  | 3   | alpha | flag{orderby_ok} |", "| 2  | 7   | beta  | nothing          |", "| 3  | 1   | gamma | x                |"], "columns": "| id | qty | sku   | note             |"}`
- injection proof (cmdi/traversal): `{"cmdi": [], "traversal": [], "default_exec": [], "requests": 28}`
- sstimap: `{"url": "http://127.0.0.1:8098/orders/by-sku?sku=1", "vulnerable": false, "confidence": null, "engine": null, "rce": false, "rc": 0}`
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
  - NEW [1aca562bde3af4ca] Server-Side Template Injection (SSTI) leading to RCE in /render
  - NEW [d65cd2b288aeb07c] SQL Injection in GET /orders sort parameter
  - NEW [0c6629aaed8b5e9e] SQL Injection in POST /orders/by-sku sku parameter
  - NEW [4a16aa620b0f60a1] Server-Side Template Injection (SSTI) leading to RCE in /render

Server-Side Template Injection (SSTI) in the 
  - NEW [b27000c724b548c9] SQL Injection in GET /orders sort parameter

The GET /orders endpoint directly interpolates the 'sort' query p
  - NEW [f13420a6dde13b21] SQL Injection in POST /orders/by-sku sku parameter

The POST /orders/by-sku endpoint directly interpolates the

## Receipt

- nostr: 6/6 relays accepted
  - ws://127.0.0.1:7788: ok=True id=6d684ad1aafcb19d
  - wss://omokoda.duckdns.org:3443/vantage-relay: ok=True id=bd263876a64d7097
  - wss://omokoda.duckdns.org:3443/relay: ok=True id=7a7fbad74ad742e4
  - wss://relay.damus.io: ok=True id=1b76e635ba23efd7
  - wss://relay.primal.net: ok=True id=e75cf7be9175d062
  - wss://relay.snort.social: ok=True id=4a7a0009ee92126d
- receipt: `216e8dac81aa69872c4914febe88200fd86ae55e63a774091bda92d374097eb8`
- merkle: `8f9c7d054a30abd9e2ce19dd88cb5f0cdb3fe28d7b128dec2b4dbbad358e6e57`
- chain_index: 0 · prev: `None`
- artifacts: 13 · diagnostics: 6
- timestamp: OpenTimestamps `216e8dac81aa6987.merkle.txt.ots` (pending Bitcoin attestation)
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/test-vuln-hard/216e8dac81aa6987.json --files`
