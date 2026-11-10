# Security scan — test-vuln-node

- target: `http://127.0.0.1:8097` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: gemini-flash-lite · 0s · run /opt/ares/strix/strix_runs/test-vuln-node_3ce7
- started 2026-11-07T18:32:08Z · duration 229s

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
- injection proof (cmdi/traversal): `{"cmdi": [{"url": "http://127.0.0.1:8097/run", "param": "cmd", "payload": ";id", "evidence": "/bin/sh: 1: 1: not found\nuid=0(root) gid=0(root) groups=0(root)"}], "traversal": [], "requests": 42}`
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

- new: 0 · persisting: 15 · resolved: 0 · active: 15
  - PERSISTING [9ae90dbbbf3c9364] Broken Function Level Authorization via Client-Supplied Header on /admin (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [b02c6517edff529f] SQL Injection in /item endpoint (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [5eebe7c2ed76d8f9] Path Traversal in /file endpoint via name parameter (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [976ec1b0efcb3dd7] Detector gap: identity obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [3687a5ce48785ed0] Detector gap: rot13 obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [d67e4f790da1cf9a] Detector gap: hex_escape obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [e457967c2d801e44] Detector gap: unicode_escape obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [6d2e9bdd1c58772a] Detector gap: spaced obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [8fa6cab54e00f13f] Detector gap: fullwidth obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [8d75488c3e0ea613] Detector gap: leet obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [8f0839bf5da6352a] Detector gap: reversed obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [80b9d315fc99aa03] Detector gap: zero_width obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [7dc8289051dd5404] Detector gap: base64 obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [2befef04e60883d2] Detector gap: base64x2 obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)
  - PERSISTING [ec2baaf773e9459a] Detector gap: mixed obfuscation is not flagged (first seen 2026-11-07T18:29:38Z)

## Receipt

- nostr: 6/6 relays accepted
  - ws://127.0.0.1:7788: ok=True id=3fbc8bdfdf44e130
  - wss://omokoda.duckdns.org:3443/vantage-relay: ok=True id=3fbc8bdfdf44e130
  - wss://omokoda.duckdns.org:3443/relay: ok=True id=d3b7461bd9a37cd4
  - wss://relay.damus.io: ok=True id=d6935a091cd2e808
  - wss://relay.primal.net: ok=True id=1256ef29e20a56b9
  - wss://relay.snort.social: ok=True id=9dbf035d74570209
- receipt: `12347a8aa7dfd018219fdebb571759f67b5680960a9467108033da2a120c88fd`
- merkle: `0cddd63cdcba5b9469f41a5690a7bfe3fecbdb93de99fa0984ebb4115b168929`
- chain_index: 3 · prev: `986c717aea752c274e3c981b4eb60a698db9d0ac78848fec4edf4276a49e1c7b`
- artifacts: 11 · diagnostics: 15
- timestamp: OpenTimestamps `12347a8aa7dfd018.merkle.txt.ots` (pending Bitcoin attestation)
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/test-vuln-node/12347a8aa7dfd018.json --files`
