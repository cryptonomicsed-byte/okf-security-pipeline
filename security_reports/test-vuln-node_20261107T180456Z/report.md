# Security scan — test-vuln-node

- target: `http://127.0.0.1:8097` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: gemini-flash-lite · 667s · run /opt/ares/strix/strix_runs/test-vuln-node_3ce7
- started 2026-11-07T18:04:56Z · duration 965s

## Findings

### [MEDIUM] Broken Function Level Authorization via Client-Supplied Header on /admin

The `/admin` endpoint relies solely on a client-supplied HTTP header (`x-admin`) to authorize administrative access. An unauthenticated attacker can supply `x-admin: 1` to bypass authorization checks and access the restricted admin panel.

Agent PoC:

1. Send a GET request to `/admin` without headers and observe a 403 Forbidden response.
2. Send a GET request to `/admin` with the header `x-admin: 1` and observe a 200 OK response with administrative panel content.

### [CRITICAL] SQL Injection in /item endpoint

The `/item` endpoint uses f-string interpolation to construct SQL queries, allowing attackers to inject arbitrary SQL via the `id` parameter.

Agent PoC:

1. Send a request to `/item` with a valid ID to establish a baseline.
2. Send a request with `id=1%20AND%201=1` to confirm boolean-based injection.
3. Send a request with `id=1%20AND%201=2` to confirm the negative case.
4. Use a `UNION SELECT` payload to extract arbitrary data.

### [HIGH] Path Traversal in /file endpoint via name parameter

The /file endpoint in the FastAPI application is vulnerable to path traversal due to improper validation of user-supplied input in the 'name' parameter. An attacker can use '../' sequences to read arbitrary files on the server.

Agent PoC:

1. Send a GET request to /file?name=../../../../etc/passwd
2. Observe that the server returns the contents of /etc/passwd

### [WARNING] Broken Function Level Authorization via Client-Supplied Header on /admin

The `/admin` endpoint relies solely on a client-supplied HTTP header (`x-admin`) to au

Broken Function Level Authorization via Client-Supplied Header on /admin

The `/admin` endpoint relies solely on a client-supplied HTTP header (`x-admin`) to authorize administrative access. An unauthenticated attacker can supply `x-admin: 1` to bypass authorization checks and access the restricted admin panel.

### [ERROR] SQL Injection in /item endpoint

The `/item` endpoint uses f-string interpolation to construct SQL queries, allowing attackers to inject arbitrary SQL via the `

SQL Injection in /item endpoint

The `/item` endpoint uses f-string interpolation to construct SQL queries, allowing attackers to inject arbitrary SQL via the `id` parameter.

### [ERROR] Path Traversal in /file endpoint via name parameter

The /file endpoint in the FastAPI application is vulnerable to path traversal due to improper validation of

Path Traversal in /file endpoint via name parameter

The /file endpoint in the FastAPI application is vulnerable to path traversal due to improper validation of user-supplied input in the 'name' parameter. An attacker can use '../' sequences to read arbitrary files on the server.

## Independent confirmation

- sqlmap: `{"url": "http://127.0.0.1:8097/item?id=1", "injectable": true, "rc": 0, "dbms": "SQLite", "techniques": ["UNION query", "boolean-based blind"], "dump_rc": 0, "dump_rows": 0, "sensitive_exposed": false, "sample": [], "columns": null}`
- sstimap: `{"vulnerable": false}`
- xsstrike: `{"vectors": 0}`
- nmap: `{"host": "127.0.0.1", "port": 8097, "services": [["sac?", "1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :"]], "rc": 0}`
- ffuf: paths=5
- nuclei: hits=0
- metasploit: `{"server": "uvicorn", "module": null, "rc": 0, "candidates": []}`
- sweep: `{"candidates": 14, "sstimap_hits": [], "sstimap_low": [], "xsstrike_hits": []}`

## Guard-gap probe

- unavailable: skipped

## Since last scan

- new: 18 · persisting: 0 · resolved: 0 · active: 18
  - NEW [4f07c6c53b7984b8] Broken Function Level Authorization via Client-Supplied Header on /admin
  - NEW [6fb8e5b6fb323fa6] SQL Injection in /item endpoint
  - NEW [8b4d531ecb11e5ae] Path Traversal in /file endpoint via name parameter
  - NEW [4b89c988f9afd5cc] Broken Function Level Authorization via Client-Supplied Header on /admin

The `/admin` endpoint relies solely 
  - NEW [2e5f16192a29c622] SQL Injection in /item endpoint

The `/item` endpoint uses f-string interpolation to construct SQL queries, al
  - NEW [5b0d5fdc23dcff8c] Path Traversal in /file endpoint via name parameter

The /file endpoint in the FastAPI application is vulnerab
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
  - ws://127.0.0.1:7788: ok=True id=e09574b5a48a0253
  - wss://omokoda.duckdns.org:3443/vantage-relay: ok=True id=e09574b5a48a0253
  - wss://omokoda.duckdns.org:3443/relay: ok=True id=99f97c3ee20ae186
  - wss://relay.damus.io: ok=False
  - wss://relay.primal.net: ok=True id=d8a3b576e3f30b27
  - wss://relay.snort.social: ok=True id=8f0e9831c87bc6d6
- receipt: `98fa093ff62d5ec5f2d48e77090c48ccd3c474beba31214f0f119ba0626d6322`
- merkle: `d59dac2e4aea4059b2d1cab71308d8a498d798d52217b1058f79e9cd01d4f939`
- chain_index: 0 · prev: `None`
- artifacts: 11 · diagnostics: 18
- timestamp: OpenTimestamps `98fa093ff62d5ec5.merkle.txt.ots` (pending Bitcoin attestation)
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/test-vuln-node/98fa093ff62d5ec5.json --files`
