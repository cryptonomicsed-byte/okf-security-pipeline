# Security scan — test-vuln-node

- target: `http://127.0.0.1:8097` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: gemini-flash-lite · 0s · run /opt/ares/strix/strix_runs/test-vuln-node_3ce7
- started 2026-11-07T18:55:45Z · duration 126s

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
- injection proof (cmdi/traversal): `{"cmdi": [{"url": "http://127.0.0.1:8097/run", "param": "cmd", "payload": "1;id", "evidence": "uid=0(root) gid=0(root) groups=0(root)"}, {"url": "http://127.0.0.1:8097/run", "param": "exec", "payload": "1;id", "evidence": "uid=0(root) gid=0(root) groups=0(root)"}, {"url": "http://127.0.0.1:8097/run", "param": "ping", "payload": "1;id", "evidence": "uid=0(root) gid=0(root) groups=0(root)"}], "traversal": [{"url": "http://127.0.0.1:8097/file?name=1", "param": "name", "payload": "../../../../etc/pa`
- sstimap: `{"vulnerable": false}`
- xsstrike: `{"vectors": 0}`
- nmap: `{"host": "127.0.0.1", "port": 8097, "services": [["sac?", "1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :"]], "rc": 0}`
- ffuf: paths=5
- nuclei: hits=0
- metasploit: `{"server": "uvicorn", "module": null, "rc": 0, "candidates": []}`
- sweep: `{}`

## Guard-gap probe

- unavailable: skipped

## Since last scan

- new: 0 · persisting: 15 · resolved: 0 · active: 15
  - PERSISTING [9ae90dbbbf3c9364] Broken Function Level Authorization via Client-Supplied Header on /admin (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [b02c6517edff529f] SQL Injection in /item endpoint (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [5eebe7c2ed76d8f9] Path Traversal in /file endpoint via name parameter (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [976ec1b0efcb3dd7] Detector gap: identity obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [3687a5ce48785ed0] Detector gap: rot13 obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [d67e4f790da1cf9a] Detector gap: hex_escape obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [e457967c2d801e44] Detector gap: unicode_escape obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [6d2e9bdd1c58772a] Detector gap: spaced obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [8fa6cab54e00f13f] Detector gap: fullwidth obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [8d75488c3e0ea613] Detector gap: leet obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [8f0839bf5da6352a] Detector gap: reversed obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [80b9d315fc99aa03] Detector gap: zero_width obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [7dc8289051dd5404] Detector gap: base64 obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [2befef04e60883d2] Detector gap: base64x2 obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)
  - PERSISTING [ec2baaf773e9459a] Detector gap: mixed obfuscation is not flagged (first seen 2026-11-07T18:46:25Z)

## Receipt

- nostr: 6/6 relays accepted
  - ws://127.0.0.1:7788: ok=True id=63f8cfc8d42372f2
  - wss://omokoda.duckdns.org:3443/vantage-relay: ok=True id=63f8cfc8d42372f2
  - wss://omokoda.duckdns.org:3443/relay: ok=True id=b6420d94e83bf5bc
  - wss://relay.damus.io: ok=True id=f21254c50adc3d65
  - wss://relay.primal.net: ok=True id=18c7e9cf7cea18b2
  - wss://relay.snort.social: ok=True id=eff6adcc80e3525d
- receipt: `28104913cb0ad22ff176405608d33c2dc9f867a219d3a0d3aafa695e2d01eb78`
- merkle: `caaed611bdb3c1f710e526738be04901b883388442cdc2b1bc3da2df03d406f5`
- chain_index: 5 · prev: `0dca74cd01d439c963791cff1d62d9e89713b934ec0642eefd5f6d0c1a60e428`
- artifacts: 11 · diagnostics: 15
- timestamp: OpenTimestamps `28104913cb0ad22f.merkle.txt.ots` (pending Bitcoin attestation)
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/test-vuln-node/28104913cb0ad22f.json --files`
