#!/usr/bin/env python3
"""
okf_anchor — publish a receipt attestation to the Nostr wire.

Answers the question "do we still need Arweave?" by separating the properties
people conflate:

  integrity      can the bytes be shown unaltered?      -> merkle + HMAC (local, free)
  existence@time can you prove it existed at time T?    -> needs an outside clock
  durability     will a third party still fetch it later? -> needs someone to store it
  attribution    who asserted this?                     -> needs a signature

Arweave sells durability (+ its own chain time). IPFS sells content addressing
and availability only while someone pins. Nostr sells attribution and
replication, not storage. So:

  * the merkle root already covers integrity (okf_receipt.py)
  * this module puts the root on Nostr, signed -> attribution + distributed copy
  * a Bitcoin-anchored timestamp (OpenTimestamps over the same root) is what
    actually establishes "existed at T"; Arweave's chain is not required for it

Event: NIP-78 app-specific data, kind 30078, addressable by d-tag
`okf:receipt:<receipt_id[:32]>`, so any client can fetch one receipt by
address. Content is the receipt summary; the merkle root is also a tag so it is
queryable without parsing content.

Signing is NOT reimplemented here: minipae owns canonical NIP-01 serialization,
BIP-340 signing and NIP-42 auth for this ecosystem.

CLI:
    python3 okf_anchor.py key
    python3 okf_anchor.py publish <receipt.json> [--relay URL]
    python3 okf_anchor.py fetch <event_id> [--relay URL]
"""
import argparse
import asyncio
import json
import os
import sys
import time

MINIPAE_PATHS = ["/opt/agent-voice-venv/lib/python3.12/site-packages",
                 "/opt/ares/minipae", "/opt/ares"]
for p in MINIPAE_PATHS:
    if os.path.isdir(p) and p not in sys.path:
        sys.path.append(p)

import minipae  # noqa: E402

KEY_FILE = os.environ.get("OKF_ANCHOR_KEY", "/opt/ares/.okf_anchor_key")
DEFAULT_RELAY = os.environ.get("OKF_ANCHOR_RELAY", "wss://omokoda.duckdns.org:3443/relay")
KIND_APP_DATA = 30078


def get_key():
    if os.path.exists(KEY_FILE):
        raw = open(KEY_FILE).read().strip()
        return bytes.fromhex(raw)
    seckey = os.urandom(32)
    minipae._validate_seckey(int.from_bytes(seckey, "big"))
    with open(KEY_FILE, "w") as f:
        f.write(seckey.hex())
    os.chmod(KEY_FILE, 0o600)
    return seckey


def npub(seckey):
    pk = minipae.pubkey_from_secret(int.from_bytes(seckey, "big"))
    return pk.hex()


def build_event(receipt, seckey, channel=None, profile="full"):
    rid = receipt["receipt_id"]
    summary = {
        "receipt_id": rid,
        "merkle_root": receipt["merkle_root"],
        "chain_index": receipt["chain_index"],
        "prev_receipt": receipt.get("prev_receipt"),
        "repo": receipt.get("repo"),
        "created_at": receipt.get("created_at"),
        "artifacts": len(receipt.get("artifacts", {})),
        "diagnostics": len(receipt.get("diagnostics", [])),
        "algorithm": "sha256-merkle+hmac-sha256",
        "verify": "okf_receipt.py verify <receipt.json> --files",
    }
    if profile == "full":
        summary["target"] = receipt.get("target")
        summary["evidence_dir"] = receipt.get("evidence_dir")
        summary["relay_only"] = True
    else:
        # Public relays are forever and world-readable: never leak local paths,
        # internal targets or hostnames. The merkle root is the proof; everything
        # else here is metadata a third party can check without our filesystem.
        summary["profile"] = "public"
        summary["evidence_dir"] = None
    tags = [
        ["d", f"okf:receipt:{rid[:32]}"],
        ["t", "okf"],
        ["t", "okf-receipt"],
        ["t", "security-scan"],
        ["repo", str(receipt.get("repo") or "")],
        ["merkle", receipt["merkle_root"]],
        ["receipt", rid],
        ["chain", str(receipt["chain_index"])],
    ]
    if profile != "full":
        tags.append(["t", "okf-receipt-public"])
    if receipt.get("prev_receipt"):
        tags.append(["prev", receipt["prev_receipt"]])
    if channel:
        # Buzz scopes reads per channel: an event without `h` is stored but not
        # returned by REQ unless the requester shares the channel.
        tags.append(["h", channel])
    return minipae.sign_event(KIND_APP_DATA, json.dumps(summary, separators=(",", ":"),
                                                        ensure_ascii=False),
                              tags, seckey)


def build_note(receipt, seckey, anchor_id, channel=None):
    """Human-readable kind-1 note so Damus/Amethyst/any client renders the
    attestation in a timeline. Machine data stays in the 30078 event; this only
    links to it."""
    repo = receipt.get("repo") or "repo"
    diags = receipt.get("diagnostics") or []
    crit = sum(1 for d in diags if str(d.get("severity", "")).lower() in ("critical", "high"))
    content = (
        f"OKF receipt {receipt['receipt_id'][:12]}\n"
        f"repo: {repo}\n"
        f"merkle: {receipt['merkle_root']}\n"
        f"chain: #{receipt['chain_index']}\n"
        f"findings: {len(diags)} ({crit} high/critical)\n"
        f"verify: okf_receipt.py verify <receipt.json> --files\n"
        f"#okf #security #receipt"
    )
    tags = [["t", "okf"], ["t", "okf-receipt"], ["t", "security"],
            ["merkle", receipt["merkle_root"]], ["repo", str(repo)]]
    if anchor_id:
        tags.append(["e", anchor_id, "", "mention"])
    if channel:
        tags.append(["h", channel])
    return minipae.sign_event(1, content, tags, seckey)


def build_profile(seckey):
    """kind 0 so clients show a name instead of a hex pubkey."""
    meta = {"name": "OKF Anchor",
            "display_name": "OKF • security receipts",
            "about": "Signs and publishes tamper-evident security scan receipts "
                     "(NIP-78 kind 30078). Merkle root is the proof; verify with okf_receipt.py.",
            "bot": True}
    return minipae.sign_event(0, json.dumps(meta, ensure_ascii=False), [], seckey)


RELAY_REGISTRY = "/opt/ares/nostr_relays.json"
LOCAL_RELAY = os.environ.get("OKF_ANCHOR_LOCAL_RELAY", "ws://127.0.0.1:7788")


def relays():
    """Ordered relay list: file registry (extension point) + Vantage's own
    registry + the local ecosystem relay. Vantage's backend/nostr/registry.py
    stays the source of truth for NOSTR_RELAYS; the JSON file only adds
    per-relay metadata (channel scoping, enabled flag) for plugins."""
    out, seen = [], set()

    def add(url, channel=None, role=None, profile=None, note=False):
        if not url or url in seen:
            return
        seen.add(url)
        out.append({"url": url, "channel": channel, "role": role or "relay",
                    "profile": profile or "full", "note": bool(note)})

    try:
        cfg = json.load(open(RELAY_REGISTRY))
        for r in cfg.get("relays", []):
            if isinstance(r, str):
                add(r)
            elif r.get("enabled", True):
                add(r.get("url"), r.get("channel"), r.get("role"),
                    r.get("profile"), r.get("note", False))
    except FileNotFoundError:
        pass

    try:
        sys.path.insert(0, "/opt/ares/Vantage")
        from backend.nostr.registry import get_relay_urls  # noqa: PLC0415
        for u in get_relay_urls():
            add(u, None, "vantage-registry")
    except Exception:  # noqa: BLE001
        for u in os.environ.get("NOSTR_RELAYS", "").split(","):
            add(u.strip(), None, "env")

    add(LOCAL_RELAY, None, "vantage-local")
    return out


async def publish_receipt(receipt, sk, default_channel=None):
    """Fan a receipt out to every relay, honouring per-relay profile.

    `profile: "public"` strips local paths/targets before anything leaves the
    box. `note: true` additionally publishes a kind-1 note so Damus/Amethyst
    render it in a timeline (machine data stays in the 30078 event)."""
    results = {}
    for r in relays():
        profile = r.get("profile") or "full"
        ch = r["channel"] or default_channel
        ev = build_event(receipt, sk, ch, profile)
        entry = {"role": r["role"], "profile": profile, "event_id": ev["id"]}
        try:
            entry.update(await publish(ev, r["url"]))
        except Exception as e:  # noqa: BLE001
            entry.update({"ok": False, "error": str(e)[:200]})
        if not entry.get("ok"):
            entry["queued"] = _queue(ev, r["url"], entry.get("error") or entry.get("message"))
        if r.get("note") and entry.get("ok"):
            try:
                nv = build_note(receipt, sk, ev["id"], ch)
                entry["note"] = {"event_id": nv["id"],
                                 **(await publish(nv, r["url"]))}
            except Exception as e:  # noqa: BLE001
                entry["note"] = {"ok": False, "error": str(e)[:200]}
            if entry.get("note") and not entry["note"].get("ok"):
                nv = build_note(receipt, sk, ev["id"], ch)
                entry["note"]["queued"] = _queue(nv, r["url"],
                                                 entry["note"].get("error"))
        results[r["url"]] = entry
    return results


def _queue(event, relay, error=None):
    """Failures go to the durable outbox so a busy relay never loses the
    attestation. Best-effort: if the outbox is unavailable the caller still gets
    ok=False in the report."""
    try:
        import okf_outbox
        return okf_outbox.enqueue(event, relay, error)
    except Exception as e:  # noqa: BLE001
        return {"queued": False, "error": str(e)[:120]}


async def publish_all(event_for, out=None):
    """Legacy helper: publish a caller-built event to every relay."""
    results = {}
    for r in relays():
        ev = event_for(r["channel"])
        try:
            results[r["url"]] = {"role": r["role"], **await publish(ev, r["url"])}
        except Exception as e:  # noqa: BLE001
            results[r["url"]] = {"role": r["role"], "ok": False, "error": str(e)[:200]}
        if out is not None:
            out.append(results[r["url"]])
    return results


async def fetch_any(event_id, timeout=20):
    """Try each relay in order; return the first event found plus its origin."""
    for r in relays():
        try:
            ev = await fetch(event_id, r["url"], timeout)
        except Exception:  # noqa: BLE001
            continue
        if ev:
            return ev, r["url"]
    return None, None


def relay_base(url):
    """Buzz validates the NIP-42 `relay` tag against scheme://host[:port] — the
    path (/relay) is NOT expected, so the auth event must omit it while the
    socket still connects to the full path."""
    from urllib.parse import urlsplit
    u = urlsplit(url)
    scheme = "wss" if u.scheme in ("wss", "https") else "ws"
    return f"{scheme}://{u.netloc}"


async def _auth(ws, challenge, seckey, base, relay):
    ev = minipae.build_auth_event(challenge, base, seckey)
    await ws.send(json.dumps(["AUTH", ev]))
    while True:
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=12))
        if msg[0] == "OK":
            return msg
        if msg[0] in ("NOTICE", "CLOSED"):
            return msg


async def publish(event, relay, attempts=3):
    """Publish with retry. Public relays answer 503 when rate-limiting a new
    pubkey; a naive single attempt reads as 'rejected' when it is really 'slow
    down'. Backs off 2s, then 5s."""
    last = None
    for i in range(attempts):
        try:
            return await _publish_once(event, relay)
        except Exception as e:  # noqa: BLE001
            last = e
            transient = any(s in str(e) for s in ("503", "429", "handshake",
                                                  "1005", "1006", "ConnectionClosed"))
            if not transient or i == attempts - 1:
                raise
            await asyncio.sleep(2 if i == 0 else 5)
    raise last


async def _publish_once(event, relay):
    import websockets
    base = relay_base(relay)
    async with websockets.connect(relay, open_timeout=15, max_size=10 << 20) as ws:
        await ws.send(json.dumps(["EVENT", event]))
        challenge = None
        while True:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=12))
            if msg[0] == "AUTH":
                challenge = msg[1]
                break
            if msg[0] == "OK":
                if msg[2]:
                    return {"ok": True, "message": msg[1], "auth": False}
                if "auth-required" not in str(msg[1]):
                    return {"ok": False, "message": msg[1], "auth": False}
                # relay wants auth first but has not issued a challenge yet
                break
            if msg[0] in ("NOTICE", "CLOSED"):
                return {"ok": False, "message": str(msg), "auth": False}
        if challenge is None:
            return {"ok": False, "message": "auth required, no challenge received", "auth": False}
        auth_ok = await _auth(ws, challenge, get_key(), base, relay)
        await ws.send(json.dumps(["EVENT", event]))
        while True:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=12))
            if msg[0] == "OK":
                return {"ok": bool(msg[2]), "message": msg[1], "auth": True,
                        "auth_result": auth_ok}
            if msg[0] in ("NOTICE", "CLOSED"):
                return {"ok": False, "message": str(msg), "auth": True}


async def fetch(event_id, relay, timeout=20, attempts=3):
    """Authenticate first when challenged, then REQ. Buzz issues AUTH on connect
    and silently ignores pre-auth REQs, so ordering matters. Public relays 503
    under load, so transient handshake failures are retried."""
    last = None
    for i in range(attempts):
        try:
            return await _fetch_once(event_id, relay, timeout)
        except Exception as e:  # noqa: BLE001
            last = e
            transient = any(s in str(e) for s in ("503", "429", "handshake",
                                                  "1005", "1006", "ConnectionClosed"))
            if not transient or i == attempts - 1:
                raise
            await asyncio.sleep(2 if i == 0 else 5)
    raise last


async def _fetch_once(event_id, relay, timeout=20):
    import websockets
    base = relay_base(relay)
    sub = f"okf-{event_id[:8]}"
    async with websockets.connect(relay, open_timeout=timeout, max_size=10 << 20) as ws:
        try:
            first = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        except asyncio.TimeoutError:
            first = None
        if first and first[0] == "AUTH":
            await _auth(ws, first[1], get_key(), base, relay)
        await ws.send(json.dumps(["REQ", sub, {"ids": [event_id]}]))
        while True:
            raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
            msg = json.loads(raw)
            if msg[0] == "EVENT" and msg[1] == sub:
                return msg[2]
            if msg[0] == "AUTH":
                await _auth(ws, msg[1], get_key(), base, relay)
                await ws.send(json.dumps(["REQ", sub, {"ids": [event_id]}]))
                continue
            if msg[0] in ("EOSE", "CLOSED", "NOTICE"):
                return None


async def backfill(limit=5, urls=None, timeout=30):
    """Re-publish the newest N receipts (public profile) plus their kind-1 notes,
    so a relay that was added later still shows history in the #okf feed."""
    import glob
    urls = urls or [r["url"] for r in relays() if r.get("note")]
    files = sorted(glob.glob("/opt/ares/security_receipts/*/*.json"),
                   key=os.path.getmtime)[-limit:]
    out = {"receipts": [], "relays": urls}
    for f in files:
        rc = json.load(open(f))
        ev = build_event(rc, get_key(), None, "public")
        row = {"receipt_id": rc["receipt_id"][:16], "event_id": ev["id"], "relays": {}}
        for u in urls:
            try:
                r1 = await publish(ev, u)
                nv = build_note(rc, get_key(), ev["id"])
                r2 = await publish(nv, u)
                row["relays"][u] = {"receipt_ok": bool(r1.get("ok")),
                                    "note_ok": bool(r2.get("ok"))}
            except Exception as e:  # noqa: BLE001
                row["relays"][u] = {"error": str(e)[:120]}
        out["receipts"].append(row)
    return out


async def feed(relay, limit=20, timeout=20, tag="okf"):
    """Read the #okf feed from one relay: every note and receipt event carrying
    the hashtag, newest first. This is what an Amethyst/Damus hashtag search
    hits."""
    import websockets
    base = relay_base(relay)
    sub = f"okf-feed-{int(time.time())}"
    items = []
    async with websockets.connect(relay, open_timeout=timeout, max_size=10 << 20) as ws:
        try:
            first = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            if first[0] == "AUTH":
                await _auth(ws, first[1], get_key(), base, relay)
        except asyncio.TimeoutError:
            pass
        await ws.send(json.dumps(["REQ", sub, {"#t": [tag], "kinds": [1, KIND_APP_DATA],
                                               "limit": limit}]))
        while True:
            try:
                m = json.loads(await asyncio.wait_for(ws.recv(), timeout=timeout))
            except asyncio.TimeoutError:
                break
            if m[0] == "EVENT" and m[1] == sub:
                items.append(m[2])
            elif m[0] == "EOSE":
                break
            elif m[0] in ("CLOSED", "NOTICE"):
                break
    return items


def verify_event(ev):
    problems = []
    if minipae.event_id(ev) != ev.get("id"):
        problems.append("event id mismatch (serialization drift)")
    pk = bytes.fromhex(ev["pubkey"])
    if not minipae.schnorr_verify(bytes.fromhex(ev["id"]), pk, bytes.fromhex(ev["sig"])):
        problems.append("BIP-340 signature invalid")
    d = next((t[1] for t in ev.get("tags", []) if t and t[0] == "d"), None)
    if not d or not d.startswith("okf:receipt:"):
        problems.append("missing okf:receipt d-tag")
    body = json.loads(ev["content"])
    merkle_tag = next((t[1] for t in ev.get("tags", []) if t and t[0] == "merkle"), None)
    if merkle_tag and merkle_tag != body.get("merkle_root"):
        problems.append("merkle tag disagrees with content")
    return {"ok": not problems, "problems": problems,
            "event_id": ev.get("id"), "author": ev.get("pubkey"),
            "created_at": ev.get("created_at"), "d": d,
            "merkle_root": body.get("merkle_root"),
            "receipt_id": body.get("receipt_id"),
            "chain_index": body.get("chain_index")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["key", "relays", "publish", "fetch", "profile",
                                    "feed", "backfill"])
    ap.add_argument("arg", nargs="?")
    ap.add_argument("--relay", default=None, help="single relay override")
    ap.add_argument("--limit", type=int, default=20, help="feed item limit")
    ap.add_argument("--profile", default="full", choices=["full", "public"],
                    help="full keeps local paths (private relays); public strips them")
    ap.add_argument("--channel", default=os.environ.get("OKF_ANCHOR_CHANNEL"),
                    help="Buzz channel uuid; required for REQ-retrievable events")
    a = ap.parse_args()
    sk = get_key()

    if a.cmd == "key":
        print(json.dumps({"npub_hex": npub(sk), "nsec": minipae.nsec_encode(sk),
                          "key_file": KEY_FILE}, indent=2))
        return

    if a.cmd == "relays":
        print(json.dumps(relays(), indent=2))
        return

    if a.cmd == "backfill":
        n = a.limit or 5
        urls = [a.relay] if a.relay else [r["url"] for r in relays() if r.get("note")]
        res = asyncio.run(backfill(n, urls))
        print(json.dumps(res, indent=2))
        return

    if a.cmd == "feed":
        url = a.relay or "wss://relay.primal.net"
        limit = a.limit or 20
        items = asyncio.run(feed(url, limit))
        for it in items:
            merkle = next((t[1] for t in it["tags"] if t[0] == "merkle"), "")[:16]
            repo = next((t[1] for t in it["tags"] if t[0] == "repo"), "")
            print(f"{it['created_at']:>12}  kind={it['kind']:<6} "
                  f"{repo[:16]:<17} merkle={merkle:<16} {it['id'][:12]}")
        print(json.dumps({"relay": url, "count": len(items)}, indent=2))
        return

    if a.cmd == "profile":
        ev = build_profile(sk)

        async def _go():
            res = {}
            for r in relays():
                try:
                    res[r["url"]] = await publish(ev, r["url"])
                except Exception as e:  # noqa: BLE001
                    res[r["url"]] = {"ok": False, "error": str(e)[:120]}
            return res

        res = asyncio.run(_go())
        print(json.dumps({"event_id": ev["id"], "npub": npub(sk),
                          "relays_ok": sum(1 for v in res.values() if v.get("ok")),
                          "per_relay": res}, indent=2))
        return

    if a.cmd == "publish":
        receipt = json.load(open(a.arg))
        if a.relay:
            ev = build_event(receipt, sk, a.channel, a.profile)
            res = {"relay": a.relay, "event_id": ev["id"],
                   "relay_response": asyncio.run(publish(ev, a.relay))}
            print(json.dumps(res, indent=2))
            return
        results = asyncio.run(publish_receipt(receipt, sk, a.channel))
        ok = sum(1 for r in results.values() if r.get("ok"))
        cleaned = {u: {k: v for k, v in r.items() if k in
                       ("role", "profile", "ok", "event_id", "message", "error", "note")}
                   for u, r in results.items()}
        print(json.dumps({"relays_ok": ok, "relays_total": len(results),
                          "per_relay": cleaned}, indent=2))
        return

    if a.cmd == "fetch":
        if a.relay:
            ev = asyncio.run(fetch(a.arg, a.relay))
            origin = a.relay
        else:
            ev, origin = asyncio.run(fetch_any(a.arg))
        if not ev:
            print(json.dumps({"found": False, "event_id": a.arg,
                              "relays_tried": [r["url"] for r in relays()]}, indent=2))
            sys.exit(4)
        out = verify_event(ev)
        out["found"] = True
        out["relay"] = origin
        print(json.dumps(out, indent=2))
        sys.exit(0 if out["ok"] else 3)


if __name__ == "__main__":
    main()
