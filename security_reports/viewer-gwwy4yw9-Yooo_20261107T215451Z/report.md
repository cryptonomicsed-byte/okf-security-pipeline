# Security scan — viewer-gwwy4yw9-Yooo

- target: `` (None)
- isolation: n/a (static-only)
- strix: gemini-flash-lite · 187s · run /opt/ares/strix/strix_runs/viewer-gwwy4yw9-yooo_2802
- started 2026-11-07T21:54:51Z · duration 192s

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

- memory unavailable: invalid memory namespace: 'findings-viewer-gwwy4yw9-Yooo'

## Receipt

- nostr: 6/6 relays accepted
  - ws://127.0.0.1:7788: ok=True id=85fae689b184bae0
  - wss://omokoda.duckdns.org:3443/vantage-relay: ok=True id=120300bd7b738e3b
  - wss://omokoda.duckdns.org:3443/relay: ok=True id=959b0bd1f4159c80
  - wss://relay.damus.io: ok=True id=9ea88629b2d99603
  - wss://relay.primal.net: ok=True id=7f1055d852ef98ef
  - wss://relay.snort.social: ok=True id=0f61da54b39a870e
- receipt: `6f8ed7d9d5768aae56a039351b5f6b7157491926e91c5a2140d1b7ed4aa001fc`
- merkle: `88017b1037e0402f318b72f6b374130d22f1fba8b8581ba23198f3092e67b765`
- chain_index: 1 · prev: `016e538de0fb57cffcec9806b309c1311ccad52f0810664dbe9012f56d31f0cd`
- artifacts: 2 · diagnostics: 0
- timestamp: OpenTimestamps `6f8ed7d9d5768aae.merkle.txt.ots` (pending Bitcoin attestation)
- verify: `python3 /opt/ares/okf_receipt.py verify /opt/ares/security_receipts/viewer-gwwy4yw9-Yooo/6f8ed7d9d5768aae.json --files`
