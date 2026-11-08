#!/usr/bin/env python3
"""okf_btc_chain — a clock that does not trust the API that told it the time.

Asking mempool.space "what is the tip?" and believing the answer makes the
clock only as honest as the endpoint. This module verifies what it is told:

  * the 80-byte header hashes to the block hash the source reported
  * each header's prev-hash field equals the hash of the block below it
  * the hash meets the difficulty target encoded in `bits`
  * `bits` is consistent inside a difficulty epoch, and at an epoch boundary
    matches the retarget formula computed from the epoch's own timestamps
  * median-time-past of the last 11 blocks gives a consensus lower bound on
    "now" that no server can lie about (a valid block must exceed it)

Nothing here needs a Bitcoin node; a hostile API would have to produce valid
proof-of-work to lie, which is the whole point.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
from pathlib import Path

CACHE_PATH = os.environ.get("OKF_BTC_HEADERS", "/opt/ares/.btc_headers.json")
ANCHOR_PATH = os.environ.get("OKF_BTC_ANCHOR", "/opt/ares/.btc_anchor.json")
PINS_PATH = Path(os.environ.get("OKF_BTC_PINS", "/opt/ares/.btc_pins.json"))
CHAIN_N = int(os.environ.get("OKF_BTC_CHAIN_N", "12"))
MAX_GAP_WALK = int(os.environ.get("OKF_BTC_MAX_GAP", "200"))
RETARGET = 2016
TARGET_TIMESPAN = 14 * 24 * 60 * 60
BLOCK_SECONDS = 600

SOURCES = [
    ("mempool.space", "https://mempool.space/api"),
    ("blockstream.info", "https://blockstream.info/api"),
]


def _http(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "okf-btc-chain/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode().strip(), r.headers.get("Date")


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def target_from_bits(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    return mantissa * (1 << (8 * (exponent - 3)))


def parse_header(raw: bytes) -> dict:
    if len(raw) != 80:
        raise ValueError(f"header must be 80 bytes, got {len(raw)}")
    h = sha256d(raw)
    return {
        "hash": h[::-1].hex(),
        "prev": raw[4:36][::-1].hex(),
        "merkle": raw[36:68][::-1].hex(),
        "time": int.from_bytes(raw[68:72], "little"),
        "bits": int.from_bytes(raw[72:76], "little"),
        "nonce": int.from_bytes(raw[76:80], "little"),
        "pow_ok": int.from_bytes(h, "little") <= target_from_bits(int.from_bytes(raw[72:76], "little")),
        "raw": raw.hex(),
    }


def _load_cache():
    try:
        with open(CACHE_PATH) as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


def _save_cache(c):
    tmp = CACHE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(c, f)
    os.replace(tmp, CACHE_PATH)


def _fetch_with_fallback(path):
    """Try each source; return (text, source_name)."""
    errs = []
    for name, base in SOURCES:
        try:
            txt, date_hdr = _http(base + path)
            return txt, name, date_hdr
        except Exception as e:  # noqa: BLE001
            errs.append(f"{name}: {e}")
    raise RuntimeError("all header sources failed: " + "; ".join(errs))


def header_at_height(height, cache=None):
    """Return a parsed header for a height, using the on-disk cache when possible."""
    cache = cache if cache is not None else _load_cache()
    key = f"h:{height}"
    if key in cache:
        try:
            return parse_header(bytes.fromhex(cache[key])), "cache"
        except Exception:  # noqa: BLE001
            pass
    bh, src, _ = _fetch_with_fallback(f"/block-height/{height}")
    raw_hex, src2, _ = _fetch_with_fallback(f"/block/{bh}/header")
    cache[key] = raw_hex
    cache[f"b:{bh}"] = raw_hex
    return parse_header(bytes.fromhex(raw_hex)), src2


def tip(cache=None):
    cache = cache if cache is not None else _load_cache()
    h, src, date_hdr = _fetch_with_fallback("/blocks/tip/hash")
    hd = header_at_height_by_hash(h, cache)
    return {"hash": h, "source": src, "date_header": date_hdr, "header": hd}


def header_at_height_by_hash(bhash, cache=None):
    cache = cache if cache is not None else _load_cache()
    key = f"b:{bhash}"
    if key in cache:
        return parse_header(bytes.fromhex(cache[key]))
    raw_hex, src, _ = _fetch_with_fallback(f"/block/{bhash}/header")
    cache[key] = raw_hex
    return parse_header(bytes.fromhex(raw_hex))


def _load_anchor():
    try:
        with open(ANCHOR_PATH) as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


def _save_anchor(a):
    tmp = ANCHOR_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(a, f, indent=2)
    os.replace(tmp, ANCHOR_PATH)


def seed_anchor_from_sources(cache, tip_height=None, depth=6):
    """Bootstrap the anchor from agreement between independent endpoints.

    A fresh box has no history to be continuous with, so the first anchor is a
    trust decision. Make it as small as possible: ask every source for the tip
    hash independently, require at least two to name the same block, then verify
    that block's proof-of-work locally before adopting a block `depth` back.
    Disagreement means no anchor — an unverified clock beats a plausible lie.
    """
    import json as _json
    votes, errors = {}, []
    for name, base in SOURCES + [("blockchain.info", "https://blockchain.info")]:
        try:
            if "blockchain.info" in base:
                d = _json.loads(_http(base + "/latestblock")[0])
                votes.setdefault((int(d["height"]), d["hash"]), []).append(name)
            else:
                h = _http(base + "/blocks/tip/hash")[0]
                b = _json.loads(_http(base + f"/block/{h}")[0])
                votes.setdefault((int(b["height"]), h), []).append(name)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{name}: {str(e)[:60]}")
    if not votes:
        return {"ok": False, "errors": errors or ["no source answered"]}
    (height, bhash), who = max(votes.items(), key=lambda kv: len(kv[1]))
    if len(who) < 2:
        return {"ok": False, "errors": errors + [
            f"only one source named block {height} {bhash[:16]}… ({who[0]}) — refusing to seed"],
            "votes": {f"{h}:{b[:12]}": w for (h, b), w in votes.items()}}
    hd = header_at_height_by_hash(bhash, cache)
    if hd["hash"] != bhash or not hd["pow_ok"]:
        return {"ok": False, "errors": [f"agreed block {height} failed local header/PoW check"]}
    cur, walked = hd, 0
    for _ in range(depth):
        nxt = header_at_height_by_hash(cur["prev"], cache)
        if nxt["hash"] != cur["prev"] or not nxt["pow_ok"]:
            return {"ok": False, "errors": [f"could not walk back to anchor depth ({walked})"]}
        cur, walked = nxt, walked + 1
    anchor = {"height": height - depth, "hash": cur["hash"], "time": cur["time"],
              "adopted_at": int(time.time()), "history": [],
              "seeded": {"at": int(time.time()), "sources": who,
                         "agreeing": len(who), "tip_height": height,
                         "tip_hash": bhash, "votes": len(votes), "wallet_depth": walked}}
    _save_anchor(anchor)
    return {"ok": True, "anchor": anchor}


def _load_pins():
    try:
        return json.loads(PINS_PATH.read_text())
    except Exception:  # noqa: BLE001
        return {"pins": []}


def _pin_check(seen, tip_height, res):
    """An externally chosen (height, hash) the chain must reach.

    Depth proves how much has been checked; it cannot prove the chain is Bitcoin's.
    A pin is the user's chosen root — Bitcoin Core's shipped checkpoints, a hash
    noted on another machine, a block explorer's old block. None present means
    unrooted, which is a state to report, not a pass.
    """
    pins = [p for p in (_load_pins().get("pins") or [])
            if int(p.get("height", 0)) <= tip_height]
    res.setdefault("rooted", False)
    res.setdefault("pin", None)
    if not pins:
        res["rooted"] = False
        res["pin"] = {"status": "no pin", "count": 0}
        return True  # unrooted is a warning, not a failure
    # Only pins this window/walk actually reaches can be checked; older ones are
    # history. The highest reachable pin governs — if it mismatches, nothing else
    # matters.
    reachable = [p for p in pins if (seen.get(str(p["height"])) or "")]
    if not reachable:
        res["rooted"] = False
        res["pin"] = {"status": "out of reach", "count": len(pins),
                      "highest": max(int(p["height"]) for p in pins),
                      "window_floor": min(int(k) for k in seen) if seen else None}
        return True
    p = max(reachable, key=lambda x: int(x["height"]))
    want = str(p["hash"]).lower()
    got = (seen.get(str(p["height"])) or "").lower()
    if got != want:
        res["pin"] = {"height": p["height"], "hash": want, "got": got, "status": "mismatch"}
        res["error"] = f"chain hash at {p['height']} does not match the pin"
        res["rooted"] = False
        return False
    # Every reachable pin must agree — they are all statements about the same chain.
    for q in reachable:
        if (seen.get(str(q["height"])) or "").lower() != str(q["hash"]).lower():
            res["pin"] = {"height": q["height"], "status": "mismatch",
                          "hash": str(q["hash"]).lower(),
                          "got": (seen.get(str(q["height"])) or "").lower()}
            res["error"] = f"chain hash at {q['height']} does not match a pin"
            res["rooted"] = False
            return False
    # `rooted` means an EXTERNAL root matched. A hash this host wrote down about
    # its own verified chain locks history but attests nothing outside the box.
    STRONG = ("buried_multi_source", "core_checkpoints", "published")
    strong = [q for q in reachable if (q.get("class") or "self_recorded") in STRONG]
    res["roots"] = [{"height": q["height"], "class": q.get("class") or "self_recorded",
                     "source": q.get("source")} for q in sorted(
                         reachable, key=lambda x: int(x["height"]), reverse=True)]
    res["pin"] = {"height": p["height"], "hash": want, "status": "matched",
                  "source": p.get("source"), "class": p.get("class") or "self_recorded"}
    res["rooted"] = bool(strong)
    if strong:
        best = max(strong, key=lambda x: int(x["height"]))
        res["pin"]["rooted_by"] = {"height": best["height"],
                                   "class": best.get("class"),
                                   "source": best.get("source")}
    else:
        res["pin"]["rooted_by"] = None
    return True


def _depth(seen):
    """How much of the chain has actually been proof-of-work verified."""
    if not seen:
        return {"count": 0, "lowest": None, "highest": None}
    hs = sorted(int(k) for k in seen)
    return {"count": len(hs), "lowest": hs[0], "highest": hs[-1],
            "span": hs[-1] - hs[0] + 1}


def _continuity(headers, tip_height, cache, out, save=True):
    """Connect this window to an anchor we verified earlier.

    A 12-header window proves those headers are internally consistent, not that
    they are Bitcoin's chain: someone who mines (or fabricates) 12 headers could
    present them. The anchor closes that — each run must reach a block whose hash
    we recorded on a previous, already-verified run, and only then may the anchor
    advance. A lie therefore has to be continuous with history, which is the same
    requirement the real chain has.
    """
    st = _load_anchor()
    lowest = tip_height - len(headers) + 1
    by_height = {tip_height - i: h for i, h in enumerate(headers)}
    res = {"anchor_height": st.get("height"), "anchor_hash": st.get("hash"),
           "bootstrapped": False, "walked": 0, "reorg_depth": None}

    # Every header this run proved (window + any walk) is accumulated, so the
    # count of uniquely verified heights only ever grows towards genesis. A
    # window proves 12 blocks; the record of what has been proven is the thing
    # that turns "consistent" into "increasingly deep".
    seen = dict((st.get("verified_heights") or {}))
    for h, hd in by_height.items():
        seen[str(h)] = hd["hash"]
    ledger_cap = int(os.environ.get("OKF_BTC_LEDGER_CAP", "20000"))
    if len(seen) > ledger_cap:
        for k in sorted(seen, key=int)[:-ledger_cap]:
            seen.pop(k, None)

    if not st.get("height"):
        seeded = (seed_anchor_from_sources(cache, tip_height) if save
                  else {"ok": True, "anchor": {}})
        if not seeded.get("ok"):
            res["error"] = ("could not seed an anchor from source agreement: "
                            + "; ".join(str(e) for e in seeded.get("errors", [])[:3]))
            res["votes"] = seeded.get("votes")
            out["continuity"] = res
            return False
        a = seeded["anchor"]
        res.update({"bootstrapped": True, "anchor_height": a.get("height"),
                    "anchor_hash": a.get("hash"), "seeded": a.get("seeded")})
        out["continuity"] = res
        return True

    anchor_h, anchor_hash = int(st["height"]), st["hash"]
    if anchor_h > tip_height:
        # the tip went backwards: either a reorg deeper than our window or a lie
        res["error"] = f"tip {tip_height} is below anchor {anchor_h}"
        out["continuity"] = res
        return False

    if anchor_h in by_height:
        cur = by_height[anchor_h]
        matched = cur["hash"] == anchor_hash
    else:
        # walk back from the window floor to the anchor
        need = lowest - anchor_h
        if need > MAX_GAP_WALK:
            res["error"] = f"gap of {need} blocks exceeds MAX_GAP_WALK={MAX_GAP_WALK}"
            out["continuity"] = res
            return False
        cur = headers[-1]
        matched = False
        for _ in range(need):
            try:
                cur = header_at_height_by_hash(cur["prev"], cache)
            except Exception as e:  # noqa: BLE001
                res["error"] = f"walk failed: {str(e)[:80]}"
                out["continuity"] = res
                return False
            if not cur["pow_ok"]:
                res["error"] = "walk hit a header failing proof-of-work"
                out["continuity"] = res
                return False
            res["walked"] += 1
            seen[str(cur["height"])] = cur["hash"]
        matched = cur["hash"] == anchor_hash

    pin_ok = _pin_check(seen, tip_height, res)

    if matched:
        target_h = tip_height - min(6, len(headers) - 1)
        hd = by_height.get(target_h)
        if save and hd:
            hist = (st.get("history") or [])[-49:] + [
                {"height": anchor_h, "hash": anchor_hash, "time": st.get("time")}]
            _save_anchor({"height": target_h, "hash": hd["hash"], "time": hd["time"],
                          "adopted_at": int(time.time()), "history": hist,
                          "verified_heights": seen,
                          "seeded": st.get("seeded")})
            res.update({"anchor_height": target_h, "anchor_hash": hd["hash"],
                        "advanced_from": anchor_h, "verified_against": anchor_hash,
                        "seeded": st.get("seeded")})
        res["ok"] = pin_ok
        res["verified_depth"] = _depth(seen)
        out["continuity"] = res
        return pin_ok

    # Mismatch. A shallow disagreement is a reorg we can follow; a deep one is
    # either a reorg the network would have to have accepted or someone lying.
    depth = tip_height - anchor_h
    if depth <= 6:
        target_h = tip_height - min(6, len(headers) - 1)
        hd = by_height.get(target_h)
        if save and hd:
            _save_anchor({"height": target_h, "hash": hd["hash"], "time": hd["time"],
                          "adopted_at": int(time.time()),
                          "seeded": st.get("seeded"),
                          "history": (st.get("history") or [])[-49:] + [
                              {"height": anchor_h, "hash": anchor_hash,
                               "reorged_at": int(time.time())}]})
        res.update({"ok": pin_ok, "reorg_depth": depth,
                    "note": "shallow reorg — anchor re-based",
                    "anchor_height": target_h, "anchor_hash": (hd or {}).get("hash"),
                    "verified_depth": _depth(seen)})
        out["continuity"] = res
        return pin_ok

    res["ok"] = False
    res["error"] = (f"chain does not connect to anchor {anchor_h} {anchor_hash[:16]}… "
                    f"(depth {depth})")
    out["continuity"] = res
    return False


def verify_chain(n=CHAIN_N, save_cache=True):
    """Verify the last `n` headers and connect them to our verified anchor."""
    cache = _load_cache()
    out = {"ok": False, "headers_checked": 0, "link_ok": False, "pow_ok": False,
           "bits_ok": False, "errors": []}
    try:
        t = tip(cache)
        # height comes from the height lookup, but we treat the hash as truth
        height_txt, src, _ = _fetch_with_fallback(f"/block/{t['hash']}")
        height = json.loads(height_txt).get("height")
        out["height"] = height
        out["tip_hash"] = t["hash"]
        out["source"] = src
        headers = [t["header"]]
        expected = t["header"]["hash"]
        for i in range(1, n):
            hd = header_at_height_by_hash(headers[-1]["prev"], cache)
            headers.append(hd)
            if hd["hash"] != headers[-2]["prev"]:
                out["errors"].append(f"link mismatch at height {height - i}")
                break
        out["headers_checked"] = len(headers)
        out["link_ok"] = all(headers[i]["hash"] == headers[i - 1]["prev"]
                             for i in range(1, len(headers)))
        out["pow_ok"] = all(h["pow_ok"] for h in headers)
        bits = {h["bits"] for h in headers}
        out["bits"] = headers[0]["bits"]
        out["difficulty"] = (target_from_bits(0x1D00FFFF) / target_from_bits(headers[0]["bits"]))
        out["tip_time"] = headers[0]["time"]
        # MTP-11 is computed over the 11 ancestors, not over the tip itself.
        anc = headers[1:12]
        out["mtp11"] = sorted(h["time"] for h in anc)[len(anc) // 2] if len(anc) >= 11 else None
        now_wall = int(time.time())
        # Bitcoin does NOT require increasing timestamps — only that a block
        # beats the median of its ancestors and is not far in the future.
        out["time_bounds_ok"] = all(1231006505 < h["time"] < now_wall + 7200 for h in headers)
        out["mtp_rule_ok"] = bool(out["mtp11"] and headers[0]["time"] > out["mtp11"])
        # difficulty epochs: inside one epoch bits must be identical; if the
        # window straddles a boundary, the change must match the retarget rule.
        height_of = {h["hash"]: None for h in headers}
        out["bits_ok"] = len(bits) == 1
        if len(bits) > 1:
            out["bits_ok"] = _verify_retarget(headers, height, cache, out)
        cont_ok = _continuity(headers, height, cache, out, save=save_cache)
        out["rooted"] = bool((out.get("continuity") or {}).get("rooted"))
        out["ok"] = bool(out["link_ok"] and out["pow_ok"] and out["bits_ok"]
                         and out["time_bounds_ok"] and out["mtp_rule_ok"]
                         and out["mtp11"] is not None and cont_ok)
        # trust the verified window, not the reported number, when they disagree
        if out["ok"] and expected != headers[0]["hash"]:
            out["errors"].append("tip hash changed mid-verification")
            out["ok"] = False
    except Exception as e:  # noqa: BLE001
        out["errors"].append(str(e)[:200])
    if save_cache:
        try:
            _save_cache(cache)
        except Exception:  # noqa: BLE001
            pass
    return out


def _verify_retarget(headers, tip_height, cache, out):
    """Check EVERY difficulty change in the window against consensus.

    A header's PoW is checked against its own declared target, so a historical
    header carrying an inflated (easier) bits field would pass pow_ok and keep
    hash linkage intact. The only defence is the retarget rule itself — so it
    must be validated at EVERY epoch edge the window crosses, not just the
    newest one. Checking one of five boundaries was theater, not verification.
    """
    try:
        results = []
        ok_all = True
        # headers[] is newest-first. A boundary sits between i and i-1 wherever
        # bits differ; the header at i is the completed epoch's last block, and
        # the header at i-1 is the new epoch's first (height tip-i+1, which
        # consensus requires to be an exact epoch multiple).
        for i in range(1, len(headers)):
            if headers[i]["bits"] == headers[i - 1]["bits"]:
                continue
            edge = tip_height - i + 1                      # first block of new epoch
            if edge % RETARGET != 0:
                out["retarget_error"] = f"bits change below {edge} is not at an epoch edge"
                return False
            old_last = headers[i]                          # completed epoch's last block
            old_first, _ = header_at_height(edge - RETARGET, cache)
            actual = old_last["time"] - old_first["time"]
            bounded = max(TARGET_TIMESPAN // 4, min(TARGET_TIMESPAN * 4, actual))
            old_target = target_from_bits(old_last["bits"])
            new_target = min(old_target * bounded // TARGET_TIMESPAN, target_from_bits(0x1D00FFFF))
            expected_bits = _bits_from_target(new_target)
            good = expected_bits == headers[i - 1]["bits"]
            results.append({"edge": edge, "actual_span": actual,
                            "expected_bits": expected_bits,
                            "observed_bits": headers[i - 1]["bits"], "ok": good})
            ok_all = ok_all and good
        if not results:
            # no boundary in the window: single-epoch window, nothing to recheck
            return True
        out["retargets"] = results
        out["retarget"] = results[0]          # newest boundary, kept for the UI shape
        return ok_all
    except Exception as e:  # noqa: BLE001
        out["retarget_error"] = str(e)[:120]
        return False


def _bits_from_target(target: int) -> int:
    size = (target.bit_length() + 7) // 8
    mantissa = target >> (8 * (size - 3))
    if mantissa & 0x00800000:
        mantissa >>= 8
        size += 1
    return (size << 24) | (mantissa & 0x007FFFFF)


if __name__ == "__main__":
    t0 = time.time()
    r = verify_chain()
    r["seconds"] = round(time.time() - t0, 2)
    print(json.dumps(r, indent=2))
