# Security scan — clocktest-window

- target: `` (None)
- isolation: n/a (static-only)
- strix: gemini-flash-lite · 0s · run /tmp
- started 2026-11-07T22:26:43Z · duration 3s

## Findings

## Secret scan (betterleaks)

- no leaks found (rc=0)

## Independent confirmation

- dynamic tools: **not run** — static-only scan (no `--target-url`)
- absence of a hit here is not evidence of absence

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

- nostr: 5/6 relays accepted
  - ws://127.0.0.1:7788: ok=True id=f7f064df503e2572
  - wss://omokoda.duckdns.org:3443/vantage-relay: ok=True id=f7f064df503e2572
  - wss://omokoda.duckdns.org:3443/relay: ok=True id=075138b39207a9a1
  - wss://relay.damus.io: ok=False
  - wss://relay.primal.net: ok=True id=2bc94e4617876f6d
  - wss://relay.snort.social: ok=True id=e29b0c385676306a
- receipt: `4ac22d365a345a6fa591868a17c38e70afb3b0e2f2266be281a3e35aa9b695af`
- merkle: `2cee7e103e31b1f0c6da3775abd3afcdb4bc5d2a0d014020448b1c852145a546`
- chain_index: 0 · prev: `None`
- artifacts: 1 · diagnostics: 0
- timestamp: OpenTimestamps `4ac22d365a345a6f.merkle.txt.ots` (pending Bitcoin attestation)
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/clocktest-window/4ac22d365a345a6f.json --files`
