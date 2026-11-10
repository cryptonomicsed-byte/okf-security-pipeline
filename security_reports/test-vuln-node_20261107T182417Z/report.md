# Security scan — test-vuln-node

- target: `http://127.0.0.1:8097` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: gemini-flash-lite · 0s · run /opt/ares/strix/strix_runs/test-vuln-node_3ce7
- started 2026-11-07T18:24:17Z · duration 255s

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

## Independent confirmation

- sqlmap: `{"url": "http://127.0.0.1:8097/item?id=1", "injectable": true, "rc": 0, "dbms": "SQLite", "techniques": ["UNION query", "boolean-based blind"], "tables": ["items"], "dump_rc": 0, "dump_rows": 2, "dumped_table": "items", "sensitive_exposed": true, "sample": ["| 1  | alpha | flag{fapi_sql_ok} |", "| 2  | beta  | nothing           |"], "columns": "| id | name  | secret            |"}`
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

- new: 3 · persisting: 12 · resolved: 6 · active: 15
  - NEW [9ae90dbbbf3c9364] Broken Function Level Authorization via Client-Supplied Header on /admin
  - NEW [b02c6517edff529f] SQL Injection in /item endpoint
  - NEW [5eebe7c2ed76d8f9] Path Traversal in /file endpoint via name parameter
  - PERSISTING [976ec1b0efcb3dd7] Detector gap: identity obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - PERSISTING [3687a5ce48785ed0] Detector gap: rot13 obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - PERSISTING [d67e4f790da1cf9a] Detector gap: hex_escape obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - PERSISTING [e457967c2d801e44] Detector gap: unicode_escape obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - PERSISTING [6d2e9bdd1c58772a] Detector gap: spaced obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - PERSISTING [8fa6cab54e00f13f] Detector gap: fullwidth obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - PERSISTING [8d75488c3e0ea613] Detector gap: leet obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - PERSISTING [8f0839bf5da6352a] Detector gap: reversed obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - PERSISTING [80b9d315fc99aa03] Detector gap: zero_width obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - PERSISTING [7dc8289051dd5404] Detector gap: base64 obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - PERSISTING [2befef04e60883d2] Detector gap: base64x2 obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - PERSISTING [ec2baaf773e9459a] Detector gap: mixed obfuscation is not flagged (first seen 2026-11-07T18:04:56Z)
  - RESOLVED [4f07c6c53b7984b8] Broken Function Level Authorization via Client-Supplied Header on /admin
  - RESOLVED [6fb8e5b6fb323fa6] SQL Injection in /item endpoint
  - RESOLVED [8b4d531ecb11e5ae] Path Traversal in /file endpoint via name parameter
  - RESOLVED [4b89c988f9afd5cc] Broken Function Level Authorization via Client-Supplied Header on /admin

The `/admin` end
  - RESOLVED [2e5f16192a29c622] SQL Injection in /item endpoint

The `/item` endpoint uses f-string interpolation to const
  - RESOLVED [5b0d5fdc23dcff8c] Path Traversal in /file endpoint via name parameter

The /file endpoint in the FastAPI app

## Receipt

- nostr: 6/6 relays accepted
  - ws://127.0.0.1:7788: ok=True id=0959d25373b90688
  - wss://omokoda.duckdns.org:3443/vantage-relay: ok=True id=0e2912d5003c5f51
  - wss://omokoda.duckdns.org:3443/relay: ok=True id=4e567d8f2c8fdc08
  - wss://relay.damus.io: ok=True id=73981675cfb2f66a
  - wss://relay.primal.net: ok=True id=695e1215c1e8956b
  - wss://relay.snort.social: ok=True id=b4863c18a906486e
- receipt: `f8d8cf9d80d1c57dbe5bafa45d69319de6ec719632a1692088d1675da9e2881a`
- merkle: `7aa33e7804ac522cad57d6f85ac2a0284b3c81781dde768cc460743cf3f9d278`
- chain_index: 1 · prev: `98fa093ff62d5ec5f2d48e77090c48ccd3c474beba31214f0f119ba0626d6322`
- artifacts: 11 · diagnostics: 15
- timestamp: OpenTimestamps `f8d8cf9d80d1c57d.merkle.txt.ots` (pending Bitcoin attestation)
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/test-vuln-node/f8d8cf9d80d1c57d.json --files`
