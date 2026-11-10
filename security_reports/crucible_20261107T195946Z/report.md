# Security scan — crucible

- target: `` (None)
- isolation: n/a (static-only)
- strix: gemini-flash-lite · 1301s · run /opt/ares/strix/strix_runs/crucible_34b9
- started 2026-11-07T19:59:46Z · duration 1309s

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

- nostr: 6/6 relays accepted
  - ws://127.0.0.1:7788: ok=True id=3b59147a443c01b0
  - wss://omokoda.duckdns.org:3443/vantage-relay: ok=True id=3b59147a443c01b0
  - wss://omokoda.duckdns.org:3443/relay: ok=True id=ce55716a5da7cd7f
  - wss://relay.damus.io: ok=True id=92cafeeeb9c05d4e
  - wss://relay.primal.net: ok=True id=ac359592e8905351
  - wss://relay.snort.social: ok=True id=d25ff1eea934b598
- receipt: `f539a8ed704150ac4b87f4bf23d394515a75885ef1169d11a53041b781548b3f`
- merkle: `1f93c8deb7cad40dfd9c66ecc794542b8c144b5f2c6ed8826feef58026493c3c`
- chain_index: 0 · prev: `None`
- artifacts: 2 · diagnostics: 0
- timestamp: OpenTimestamps `f539a8ed704150ac.merkle.txt.ots` (pending Bitcoin attestation)
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/crucible/f539a8ed704150ac.json --files`
