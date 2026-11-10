# Security scan — hermes-ares-6-hermes-gitea-test

- target: `` (None)
- isolation: n/a (static-only)
- strix: gemini-flash-lite · 174s · run /opt/ares/strix/strix_runs/hermes-ares-6-hermes-gitea-test_2e2c
- started 2026-11-07T20:03:33Z · duration 179s

## Findings

## Independent confirmation

- sqlmap: `{"injectable": false}`
- injection proof (cmdi/traversal): `{"cmdi": [], "traversal": [], "requests": 0}`
- sstimap: `{"vulnerable": false}`
- xsstrike: `{"vectors": 0}`
- nmap: `{}`
- ffuf: paths=None
- nuclei: hits=None
- metasploit: `{"server": null}`
- sweep: `{}`

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

- receipt: `a20d81542b9d9fcdb504911b38652fd97f67b0960bdcf0f35cebae1e4b02b301`
- merkle: `fe5800fd4aa9d888ed19c26786f74f85a3e006c7b71a72911bbdaedbdc2bc4f5`
- chain_index: 0 · prev: `None`
- artifacts: 2 · diagnostics: 0
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/hermes-ares-6-hermes-gitea-test/a20d81542b9d9fcd.json --files`
