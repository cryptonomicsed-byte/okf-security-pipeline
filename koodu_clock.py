#!/usr/bin/env python3
"""koodu_clock — a Bitcoin block clock that keeps Koodu as the calendar.

Koodu's btc-time.js answers "what does this height mean" (day, domain, Sabbath,
halving era). It never answers "what time is it now" — its estimateBlockHeight()
just divides wall-clock time by 600s, which drifts by minutes-to-hours because
blocks are not exactly 10 minutes apart.

This module adds the missing half without touching btc-time.js:

  clock    = height + tip nTime + mediantime + local receive time, from several
             independent mainnet sources, with quorum and a monotonic floor.
  calendar = Koodu BTCTime(height) — unchanged, still the vocabulary layer.

What a Bitcoin clock can and cannot claim
-----------------------------------------
Bitcoin's consensus clock is bounded, not exact: a block's nTime must exceed the
median of the previous 11 (median-time-past) and may be at most 2h ahead of
network-adjusted time. So "now" is an INTERVAL, not a point:

    lower = max(tip_time, mediantime)          # provable: chain says time >= this
    upper = min(wall_now, tip_time + 7200)     # provable: no block may be >2h early
    point = lower + elapsed_since_fetch        # best estimate between blocks

`skew_s` = wall_now - point. If the host clock is behind the chain or more than
2h ahead of it, the offset is reported instead of hidden (that is the clock
discipline part: NTP discipline for a chain clock).

Offline it degrades instead of lying: the last height is kept, time is
extrapolated from local elapsed seconds, and `degraded` plus a widening
uncertainty say so.

    python3 koodu_clock.py now          # point + interval + skew
    python3 koodu_clock.py snapshot     # clock + Koodu calendar in one object
    python3 koodu_clock.py refresh      # force a network refresh
    python3 koodu_clock.py watch --every 30
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

sys.path.append("/opt/ares")
import koodu_time  # noqa: E402

STATE = os.environ.get("OKF_CLOCK_STATE", "/opt/ares/.koodu_clock.json")
TTL = int(os.environ.get("OKF_CLOCK_TTL", "45"))          # refresh cadence
BLOCK_SECONDS = 600
MAX_FUTURE = 7200                                          # consensus bound
OFFLINE = os.environ.get("OKF_CLOCK_OFFLINE") == "1"
FAKE_OFFSET = int(os.environ.get("OKF_CLOCK_WALL_OFFSET", "0") or 0)


def _fetch(url, timeout=8, parse_json=True):
    """HTTP GET that also records the server's Date header.

    The Date header is the coarse NTP-like reference: Bitcoin tells us the chain
    is at least at time T, but only an independent clock tells us what "now"
    should be. RTT/2 is subtracted so a slow link does not read as clock skew.
    """
    from email.utils import parsedate_to_datetime
    req = urllib.request.Request(url, headers={"User-Agent": "koodu-clock/1"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode()
        hdr = r.headers.get("Date")
    rtt = time.time() - t0
    if hdr:
        try:
            epoch = parsedate_to_datetime(hdr).timestamp() + rtt / 2
            _DATE_SAMPLES.append({"epoch": epoch, "source": url.split("/")[2]})
        except Exception:  # noqa: BLE001
            pass
    return json.loads(raw) if parse_json else raw.strip()


_DATE_SAMPLES = []


def _get(url, timeout=8):
    return _fetch(url, timeout, parse_json=True)


def _get_text(url, timeout=8):
    """Esplora returns /blocks/tip/hash as a bare 64-char hex string, not JSON."""
    return _fetch(url, timeout, parse_json=False)


def _source_mempool():
    h = _get_text("https://mempool.space/api/blocks/tip/hash")
    b = _get(f"https://mempool.space/api/block/{h}")
    return {"source": "mempool.space", "height": b["height"], "hash": h,
            "time": b["timestamp"]}


def _source_blockstream():
    h = _get_text("https://blockstream.info/api/blocks/tip/hash")
    b = _get(f"https://blockstream.info/api/block/{h}")
    return {"source": "blockstream.info", "height": b["height"], "hash": h,
            "time": b["timestamp"]}


def _source_blockchain_info():
    d = _get("https://blockchain.info/latestblock")
    return {"source": "blockchain.info", "height": d["height"], "hash": d["hash"],
            "time": d["time"]}


def _source_local_rpc(conf="/var/lib/bitcoin/bitcoin.conf"):
    """Local bitcoind as the best possible source — if it is a mainnet node.

    This box runs a regtest node for lnd, so the check is deliberate: a regtest
    height (107) would poison the clock. The source reports why it was skipped
    rather than silently contributing a wrong number.
    """
    import base64
    import urllib.error
    creds, port = {}, 8332
    try:
        for line in open(conf):
            line = line.strip()
            if line.startswith("rpcuser="):
                creds["user"] = line.split("=", 1)[1]
            elif line.startswith("rpcpassword="):
                creds["pass"] = line.split("=", 1)[1]
            elif line.startswith("rpcport="):
                port = int(line.split("=", 1)[1])
    except FileNotFoundError:
        raise RuntimeError("no bitcoin.conf")
    if "user" not in creds:
        raise RuntimeError("no rpc credentials in bitcoin.conf")
    auth = base64.b64encode(f"{creds['user']}:{creds['pass']}".encode()).decode()
    body = json.dumps({"jsonrpc": "1.0", "id": "koodu-clock",
                       "method": "getblockchaininfo", "params": []}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=body,
                                 headers={"Authorization": f"Basic {auth}",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        d = json.loads(r.read().decode())["result"]
    if d.get("chain") != "main":
        raise RuntimeError(f"local node is '{d.get('chain')}' — not a mainnet clock")
    return {"source": "local-bitcoind", "height": d["blocks"],
            "hash": d["bestblockhash"], "time": d["time"],
            "mediantime": d.get("mediantime")}


SOURCES = [_source_local_rpc, _source_mempool, _source_blockstream,
           _source_blockchain_info]


def wall_now():
    return int(time.time()) + FAKE_OFFSET


def _pins_sig():
    """Identity of the pin file: a cached verdict belongs to one configuration."""
    p = os.environ.get("OKF_BTC_PINS", "/opt/ares/.btc_pins.json")
    try:
        st = os.stat(p)
        return f"{p}:{st.st_mtime_ns}:{st.st_size}"
    except Exception:  # noqa: BLE001
        return f"{p}:missing"


def refresh(timeout=10):
    """Ask every source, take the highest height (we want the newest tip) and
    use its block time. Report per-source answers so disagreement is visible."""
    got, errors = [], []
    _DATE_SAMPLES.clear()
    for fn in SOURCES:
        try:
            got.append(fn())
        except Exception as e:  # noqa: BLE001
            errors.append({fn.__name__: str(e)[:100]})
    if not got:
        return {"ok": False, "errors": errors}
    got.sort(key=lambda r: r["height"], reverse=True)
    best = got[0]
    heights = [g["height"] for g in got]
    spread = max(heights) - min(heights)
    # mediantime only changes when the tip changes; walking 11 headers on every
    # tick would be 11 extra requests for an identical number.
    prev = _load() or {}
    if prev.get("hash") == best["hash"] and prev.get("mediantime"):
        mediantime = prev["mediantime"]
    else:
        mediantime = best["time"]
        try:
            mediantime = mediantime_of(best["hash"])
        except Exception:  # noqa: BLE001
            pass
    st = {"ok": True, "height": best["height"], "hash": best["hash"],
          "tip_time": best["time"], "mediantime": mediantime,
          "source": best["source"], "sources": got,
          "height_spread": spread, "errors": errors,
          "fetched_wall": wall_now(), "fetched_at": time.time()}
    if _DATE_SAMPLES:
        epochs = sorted(s["epoch"] for s in _DATE_SAMPLES)
        st["ref_time"] = epochs[len(epochs) // 2]
        st["ref_spread_s"] = int(epochs[-1] - epochs[0])
        st["ref_sources"] = len(epochs)
    # Verify the headers we were told about instead of believing the quorum.
    # A hostile endpoint must now produce valid proof-of-work to move this clock.
    try:
        import okf_btc_chain
        ch = okf_btc_chain.verify_chain()
        st["chain"] = {k: ch.get(k) for k in (
            "ok", "height", "tip_hash", "headers_checked", "link_ok", "pow_ok",
            "bits_ok", "mtp11", "mtp_rule_ok", "time_bounds_ok", "difficulty",
            "continuity", "source", "errors", "rooted")}
        if ch.get("ok") and ch.get("height") and ch["height"] != st["height"]:
            # the verified chain wins over the loudest API
            st["height_mismatch"] = {"quorum": st["height"], "verified": ch["height"]}
            st["height"] = ch["height"]
            st["hash"] = ch.get("tip_hash")
            st["tip_time"] = ch.get("tip_time") or st["tip_time"]
    except Exception as e:  # noqa: BLE001
        st["chain"] = {"ok": False, "errors": [str(e)[:160]]}
    # Bind the cached answer to the pin configuration that produced it. Without
    # this, changing OKF_BTC_PINS returns the previous run's verdict from cache and
    # a wrong root looks healthy — the failure mode this file keeps finding.
    st["pins_sig"] = _pins_sig()
    _save(st)
    return st


def mediantime_of(tip_hash):
    """median of the last 11 block timestamps (Bitcoin's own clock).

    mempool.space exposes the chain of headers; walking 11 blocks is cheap and
    gives the consensus median without trusting a single `mediantime` field.
    """
    times, h = [], tip_hash
    for _ in range(11):
        b = _get(f"https://mempool.space/api/block/{h}")
        times.append(b["timestamp"])
        if not b.get("previousblockhash"):
            break
        h = b["previousblockhash"]
    times.sort()
    return times[len(times) // 2]


def _save(st):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=2)
    os.replace(tmp, STATE)
    os.chmod(STATE, 0o600)


def _load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def now(force=False):
    """Point estimate + provable interval + skew. Refreshes if the cache is
    older than TTL (unless OFFLINE)."""
    st = _load()
    # The cache answers a question that includes WHICH pins file is in force. If
    # that changed, the cached verdict belongs to a different question — refresh
    # instead of returning a stale "rooted" or "unrooted" for the wrong config.
    if st and st.get("pins_sig") != _pins_sig():
        force = True
    if OFFLINE:
        if not st:
            return {"ok": False, "error": "offline and no cached state"}
    elif force or not st or time.time() - st.get("fetched_at", 0) > TTL:
        fresh = refresh()
        if fresh.get("ok"):
            st = fresh
        elif not st:
            return fresh

    elapsed = max(0, wall_now() - st["fetched_wall"])
    lower = max(st["tip_time"], st.get("mediantime") or st["tip_time"])
    upper = min(wall_now(), st["tip_time"] + MAX_FUTURE)
    # Prefer the server-Date reference (independent clock) over pure chain time;
    # fall back to chain time + elapsed when no Date header was available.
    if st.get("ref_time"):
        raw_point = st["ref_time"] + max(0, time.time() - st.get("fetched_at", time.time()))
    else:
        raw_point = lower + elapsed
    point = int(min(max(raw_point, lower), max(lower, upper)))
    degraded = OFFLINE or (time.time() - st.get("fetched_at", 0) > 6 * TTL)

    return {
        "ok": True,
        "height": st["height"],
        "tip_time": st["tip_time"],
        "mediantime": st.get("mediantime"),
        "now_est": point,
        "interval": [lower, max(lower, upper)],
        "uncertainty_s": int(max(0, upper - lower) / 2) if upper > lower else 0,
        "elapsed_since_tip_s": elapsed,
        "next_block_eta_s": max(0, BLOCK_SECONDS - (point - st["tip_time"])),
        "skew_s": wall_now() - point,
        "wall_skew_s": wall_now() - point,
        "ref_time": st.get("ref_time"),
        "ref_spread_s": st.get("ref_spread_s"),
        "chain_lag_s": wall_now() - st["tip_time"],
        "source": st.get("source"),
        "height_spread": st.get("height_spread"),
        "verified": bool((st.get("chain") or {}).get("ok")),
        "chain": st.get("chain") or {},
        "height_mismatch": st.get("height_mismatch"),
        "degraded": degraded,
        "freshness_s": int(time.time() - st.get("fetched_at", 0)),
        "wall_now": wall_now(),
    }


def snapshot(force=False):
    """Clock + calendar in one object: the thing the rest of the ecosystem
    consumes. Height comes from the clock; meaning still comes from Koodu."""
    c = now(force)
    if not c.get("ok"):
        return c
    cal = koodu_time.snapshot(c["height"])
    return {"clock": c, "calendar": cal,
            "sabbath": cal["is_sabbath"], "domain": cal["btc_domain"],
            "btc_day": cal["btc_day"], "halving_era": cal["halving_era"]}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["now", "snapshot", "refresh", "watch"])
    ap.add_argument("--every", type=int, default=30)
    a = ap.parse_args()
    if a.cmd == "refresh":
        print(json.dumps(refresh(), indent=2))
    elif a.cmd == "now":
        print(json.dumps(now(force=True), indent=2))
    elif a.cmd == "snapshot":
        print(json.dumps(snapshot(force=True), indent=2))
    else:
        try:
            while True:
                s = now()
                print(f"{time.strftime('%H:%M:%S')} h={s.get('height')} "
                      f"skew={s.get('skew_s')}s eta={s.get('next_block_eta_s')}s "
                      f"degraded={s.get('degraded')}", flush=True)
                time.sleep(a.every)
        except KeyboardInterrupt:
            sys.exit(0)
