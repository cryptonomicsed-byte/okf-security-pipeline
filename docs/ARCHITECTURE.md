# OKF security pipeline — architecture statement (doctrine §12)

Owner document: /root/AGENT-DOCTRINE.md (standing law) and
/root/AGENT-REPO-MAP.md (canonical paths + Orisha language stack, §7
authoritative over §2). This file states where this repo stands against them,
what is implemented versus proposed, and which gaps are deliberately open.
Updated 2026-11-11.

## 1. Niche

Ògún — tool execution and practical work (map §7 row 5). The repo's primary
domain logic is running external security tools (betterleaks, Strix, sqlmap,
SSTImap, XSStrike, nuclei, ffuf, nmap, msfconsole), normalising their
verdicts, and processing evidence. Its receipt/merkle/OTS layer is NOT Ògún's:
receipts and Seal are Ṣàngó's slot (map §7 row 7). That component lives here
temporarily and is recorded as a gap below.

## 2. Core language

Python — canonical for Ògún under map §7 rule 3 (which supersedes the
doctrine §2 "prototypes only" line; the map's companion note gives §7
precedence for assigned slots).

## 3. Supporting components

- Rust (Èṣù) — MANDATORY, ABSENT. Must own identity resolution, signing-key
  isolation and the execution boundary around probe processes. Today the
  pipeline assembles subprocess argv itself and holds its own Nostr signing
  key; both are the parallel paths map §7 rule 1 forbids.
- Move on Sui (Ṣàngó) — MANDATORY for receipt authority, ABSENT. Receipts are
  JSON + hash chain + OTS on local disk; no Move object owns them, so the
  strongest claim available is "this evidence existed", never "settled".
- TypeScript (Human) — present, correctly scoped: the Vantage surfaces only
  observe; they hold no private memory and no signing material.
- Go (Ọya), Julia (Ọ̀ṣun) — inapplicable. No streaming, timing, memory
  computation or recall here; adding either would be manufactured polyglot
  complexity (doctrine §2 rule 9).

## 4. Agent model

IMPLEMENTED: every run carries a profile (okf_profile.py) — goals, skills
(the manifested tools), permissions (the capability union from
tool_manifests.json), an explicitly ephemeral memory namespace, and a
monotonic lifecycle (created → running → completed|failed) recorded in the
receipt body via run_meta and hashed as a receipt artifact.
`principal` is null on purpose with the reason stated: no Èṣù gatekeeper, and
the Nostr anchor key is a signing key, not an agent identity.

STILL OPEN: the LLM agent (Strix) runs with a model and a URL — its tool
access is bounded by process + timeout, not by declared capabilities. §10's
"permissions enforced outside the language model" is not yet true for it.

## 5. Interfaces

- CLI: strix_pipeline_v4.py (+ --no-ots opt-out, --target-url for dynamic).
- Startup gate: okf_tool_manifests.require_coverage() refuses to run when an
  invoked tool has no manifest.
- MCP stdio: okf_clock_mcp.py — btc_now, btc_verify, btc_height.
- HTTP: GET /api/clock/now (200/424/503, ?require=rooted), /api/receipts/latest.
- Receipt schema v1.0: merkle_root, chain_index, prev_receipt, created_at_btc,
  anchors, run.profile, diagnostics. `okf_receipt.py verify <r> --files`
  re-hashes every artifact.
- Per-action manifests: tool_manifests.json declares input/output schema,
  capabilities, side effects, timeout, idempotency and audit for all 13
  executables; okf_tool_manifests.py fails on any executable in command
  position that has no manifest (that is how msfconsole, curl, git and
  rm -rf were caught after a first pass claimed 9/9).

## 6. Protocols by function

- Nostr — USED, right function: signed public receipt events, multiple
  relays, retrying outbox. Not used as identity.
- Sui/Move — required for settlement authority; not implemented.
- IPFS/IPNS — justified for evidence artifacts (content-addressed, pinned);
  not implemented. Evidence is currently local paths + sha256.
- NIP-17, Freenet, libp2p, Reticulum, Tor, Hypercore, Automerge —
  inapplicable to this repo's functions today; not run.

## 7. Authority

- Identity bindings: owed to Èṣù with a signed versioned manifest binding
  principal → Nostr pubkey. Actually: a bare keypair (.okf_anchor_key, git
  excluded) used as if it were the identity. GAP #1.
- Memory records: none held, correctly. The repo produces immutable evidence
  only — never private or shareable memory.
- Settlement: none. Receipts are evidence claims, not settled state. GAP #2.

## 8. Failure behaviour (each exercised, not asserted)

- Unrooted/offline clock → exit 3, no artifact written (positive control:
  clocktest-unverified).
- OTS calendar down → proof stays PENDING; hourly upgrade timer completes it.
- LLM member failing → retry across the pool, cooldown the member, fallback
  chain, explicit error field; never a cached blank (ares_orchestrator).
- Relay failure → outbox drain retries.
- Concurrent ledger writers → merge-on-write union with cap; deep verify then
  shallow tick preserves depth.
- Probe negative → recorded as skipped with params_tried, never as clean.
- Strix crash/timeout → run reported FAILED, receipt still issued with the
  failed lifecycle (verified: c552f78f5cf2504c, exit 124).

## 9. Validation

- Clock: rooted; verified depth >10,000 blocks; every difficulty-retarget
  edge validated.
- Receipts: every one carries an OTS proof; 25 VERIFIED against Bitcoin with
  PoW and merkle checked locally, remainder PENDING; 0 BAD, 0 MISMATCH.
- Probes: sqlmap GET+POST (param sku) and sstimap reproduce on the lab
  target; every probe has a positive control it has passed.
- Full flow (okf3-fullflow, receipt 466d8debfc830fa7): manifests gate passed,
  3 findings, all dynamic probes confirmed, receipt verified --files
  (problems: []), OTS stamped pending, Vantage broadcast 76702.
- Not validated: sandbox isolation (no capability-scoped sandbox exists),
  interoperability with Move/Seal (nothing implemented), relay-partition
  recovery (outbox untested under a real partition).

## 10. Open gaps, in doctrine order

1. Èṣù bypass — signing happens outside a Rust gatekeeper (cross-repo).
2. Ṣàngó bypass — receipt authority not in Move (cross-repo).
3. Strix runs without declared capabilities (in-repo, undone).
4. IPFS/IPNS addressing for evidence (needs a node or a routing decision).
