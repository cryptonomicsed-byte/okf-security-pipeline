# Security scan — test-vuln-node

- target: `http://127.0.0.1:8097` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: gemini-flash-lite · 0s · run /opt/ares/strix/strix_runs/test-vuln-node_3ce7
- started 2026-11-07T19:02:52Z · duration 121s

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
- injection proof (cmdi/traversal): `{"cmdi": [{"url": "http://127.0.0.1:8097/run", "param": "cmd", "payload": "1;echo OKFCANARY22267", "evidence": "canary OKFCANARY22267 executed", "via": "echo-canary"}], "traversal": [{"url": "http://127.0.0.1:8097/file?name=1", "param": "name", "payload": "../../../../etc/passwd", "evidence": "root:x:0:0:root:/root:/bin/bash"}], "default_exec": [{"url": "http://127.0.0.1:8097/run", "evidence": "uid=0(root) gid=0(root) groups=0(root)"}], "requests": 55}`
- sstimap: `{"vulnerable": false}`
- xsstrike: `{"vectors": 0}`
- nmap: `{"host": "127.0.0.1", "port": 8097, "services": [["sac?", "1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :"]], "rc": 0}`
- ffuf: paths=5
- nuclei: hits=0
- metasploit: `{"server": "uvicorn", "module": null, "rc": 0, "candidates": []}`
- sweep: `{}`

## Guard-gap probe (tripwire)

- transforms flagged: 0% (flag>=0.6, block>=0.9)
- guard gaps (below flag threshold): 12/12
  - identity: mean 0.0 · flag 0% · block 0%
  - rot13: mean 0.0 · flag 0% · block 0%
  - hex_escape: mean 0.0 · flag 0% · block 0%
  - unicode_escape: mean 0.0 · flag 0% · block 0%
  - spaced: mean 0.0 · flag 0% · block 0%
  - fullwidth: mean 0.0 · flag 0% · block 0%

## Since last scan

- new: 0 · persisting: 15 · resolved: 0 · active: 15
  - PERSISTING [9ae90dbbbf3c9364] Broken Function Level Authorization via Client-Supplied Header on /admin (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [b02c6517edff529f] SQL Injection in /item endpoint (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [5eebe7c2ed76d8f9] Path Traversal in /file endpoint via name parameter (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [976ec1b0efcb3dd7] Detector gap: identity obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [3687a5ce48785ed0] Detector gap: rot13 obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [d67e4f790da1cf9a] Detector gap: hex_escape obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [e457967c2d801e44] Detector gap: unicode_escape obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [6d2e9bdd1c58772a] Detector gap: spaced obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [8fa6cab54e00f13f] Detector gap: fullwidth obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [8d75488c3e0ea613] Detector gap: leet obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [8f0839bf5da6352a] Detector gap: reversed obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [80b9d315fc99aa03] Detector gap: zero_width obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [7dc8289051dd5404] Detector gap: base64 obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [2befef04e60883d2] Detector gap: base64x2 obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)
  - PERSISTING [ec2baaf773e9459a] Detector gap: mixed obfuscation is not flagged (first seen 2026-11-07T18:59:12Z)

## Receipt

- nostr: 6/6 relays accepted
  - ws://127.0.0.1:7788: ok=True id=bdb43a50e5284ae3
  - wss://omokoda.duckdns.org:3443/vantage-relay: ok=True id=bdb43a50e5284ae3
  - wss://omokoda.duckdns.org:3443/relay: ok=True id=cc4a047d70cb9e49
  - wss://relay.damus.io: ok=True id=9eadd07e8cf2744d
  - wss://relay.primal.net: ok=True id=89107a089e57f83a
  - wss://relay.snort.social: ok=True id=a9f43a9f8973dc3e
- receipt: `5e3627099d5b2be49303e59e256b7506eb24971d759e20751a77e6515e71297a`
- merkle: `6781a7ff4518cda1d4f8057efd2ffe4ff214e88f9f75b83617534e7c41893cd4`
- chain_index: 7 · prev: `12a82a0edd7e34446d6655645d073b77a8a84112f59cfe7ac2ea51bacf4e3de2`
- artifacts: 11 · diagnostics: 15
- timestamp: OpenTimestamps `5e3627099d5b2be4.merkle.txt.ots` (pending Bitcoin attestation)
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/test-vuln-node/5e3627099d5b2be4.json --files`
