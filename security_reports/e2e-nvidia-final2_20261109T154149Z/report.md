# Security scan — e2e-nvidia-final2

- target: `http://127.0.0.1:8098` (local)
- isolation: direct — no Tor for local targets (Arti has no loopback route)
- strix: nvidia-mistral-large · 2700s · run /opt/ares/strix/strix_runs/test-vuln-hard_e069
- started 2026-11-09T15:41:49Z · duration 3022s

## Findings

## Secret scan (betterleaks)

- **50 secret leak(s) found** (values redacted)

  - `generic-credential-uri` · /repo/app.log:4866
  - `generic-credential-uri` · /repo/app.log:4866
  - `generic-api-key` · /repo/app.log:5559
  - `generic-credential-uri` · /repo/app.log:8536
  - `generic-credential-uri` · /repo/app.log:8537
  - `generic-credential-uri` · /repo/app.log:8538
  - `generic-credential-uri` · /repo/app.log:8539
  - `generic-credential-uri` · /repo/app.log:8540
  - `generic-credential-uri` · /repo/app.log:8541
  - `generic-credential-uri` · /repo/app.log:8542
  - `generic-credential-uri` · /repo/app.log:8543
  - `generic-credential-uri` · /repo/app.log:8544
  - `generic-credential-uri` · /repo/app.log:8545
  - `generic-credential-uri` · /repo/app.log:8546
  - `generic-credential-uri` · /repo/app.log:8547

## Independent confirmation

- sqlmap: `{"injectable": false}`
- injection proof (cmdi/traversal): `{"cmdi": [], "traversal": [], "default_exec": [], "requests": 10}`
- sstimap: `{"vulnerable": false}`
- xsstrike: `{"vectors": 0}`
- nmap: `{"host": "127.0.0.1", "port": 8098, "services": [["unknown", "1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :"]], "rc": 0}`
- ffuf: paths=1
- nuclei: hits=0
- metasploit: `{"server": null}`
- sweep: `{"candidates": 10, "sstimap_hits": [], "sstimap_low": [], "xsstrike_hits": []}`

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

- new: 0 · persisting: 0 · resolved: 0 · active: 0

## Receipt

- receipt: `86be6b57e5160041ab32863b80c3ff3c8c5d1e77fd8db93558fbd2f774af68a1`
- merkle: `16bec50daaf4c6bc8fe0af700b192f32825b541e19a96172c6dbcc707372924e`
- chain_index: 0 · prev: `None`
- artifacts: 5 · diagnostics: 0
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/e2e-nvidia-final2/86be6b57e5160041.json --files`
