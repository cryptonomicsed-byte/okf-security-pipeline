#!/usr/bin/env python3
"""okf_now — the clock an agent asks when it needs to know when it is.

Every other "now" an agent can get is a number from a server it has no reason to
trust: `date`, an HTTP Date header, an LLM's guess. This one is tied to Bitcoin
and says so with evidence:

  * the tip came from independent endpoints that agreed,
  * the last N headers were verified locally (self-hash, prev linkage, PoW vs
    `bits`, epoch retarget, MTP-11), so lying costs proof-of-work,
  * the answer is an *interval* the consensus rules bound, not a point estimate,
  * the chain is rooted at a block three independent operators named and we
    verified ourselves, buried deep enough that rewriting it is not economic.

Output is JSON on stdout, always. The exit code is the verdict, so an agent can
gate on it without parsing prose:

    0  verified and rooted      — safe to stamp
    3  verified, not rooted     — time is bounded but provenance is local
    1  unverified               — do NOT stamp this result as "when"

Usage:
    okf_now.py                 # JSON, exit code = verdict
    okf_now.py --human         # one line for a human
    okf_now.py --require verified
    okf_now.py --verify <receipt.json|*.ots|*.time.json>
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

VERSION = 1
STATE = os.environ.get("OKF_CLOCK_STATE", "/opt/ares/.koodu_clock.json")


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ts)))


def build(force=False):
    import koodu_clock

    # The pin configuration is part of the question, so it must be part of the
    # cache key: a verdict computed against one pins file cannot answer for another.
    try:
        _st = koodu_clock._load() or {}
        _sig = koodu_clock._pins_sig()
        if _st.get("pins_sig") != _sig:   # missing sig counts as stale
            force = True
    except Exception:  # noqa: BLE001
        pass

    c = koodu_clock.now(force=force)
    # A cached FAILURE must not outlive the failure. The cache exists to save HTTP
    # calls, not to make a verification error sticky — and a failure IS written to
    # the shared state file, so the next caller within the TTL would inherit it and
    # report "unverified" with no cause it could see. Retry once, always, and say so.
    refreshed = False
    if not force and not (c.get("chain") or {}).get("ok"):
        fresh = koodu_clock.now(force=True)
        if fresh.get("ok"):
            c = fresh
            refreshed = True
    if not c.get("ok"):
        return {"v": VERSION, "ok": False, "verdict": "unverified",
                "error": c.get("error") or "clock unavailable",
                "checked_at": int(time.time())}

    chain = c.get("chain") or {}
    cont = chain.get("continuity") or {}
    verified = bool(chain.get("ok"))
    rooted = bool(chain.get("rooted"))
    depth = (cont.get("verified_depth") or {}).get("count")
    lo, hi = (c.get("interval") or [None, None])[:2]
    verdict = ("verified_rooted" if verified and rooted
               else "verified_unrooted" if verified else "unverified")
    problems = []
    if cont.get("error"):
        problems.append(cont["error"])
    if c.get("height_mismatch"):
        problems.append(f"verified chain disagrees with the API quorum: "
                        f"{c['height_mismatch']}")
    if not verified and not problems:
        problems.append("header verification did not complete")

    return {
        "v": VERSION,
        "ok": verified,
        "verdict": verdict,
        "problems": problems,
        "unix": c.get("now_est"),
        "utc": _iso(c.get("now_est")),
        "window": {"lo": lo, "hi": hi,
                   "lo_utc": _iso(lo) if lo else None,
                   "hi_utc": _iso(hi) if hi else None},
        "uncertainty_s": c.get("uncertainty_s"),
        "block": {"height": c.get("height"),
                  "hash": chain.get("tip_hash"),
                  "time": c.get("tip_time")},
        "chain": {"verified": verified, "depth": depth,
                  "lowest": (cont.get("verified_depth") or {}).get("lowest"),
                  "height_mismatch": c.get("height_mismatch")},
        "root": {"rooted": rooted, "pin": cont.get("pin")},
        "skew_s": c.get("skew_s"),
        "source": c.get("source"),
        "degraded": c.get("degraded"),
        "reverified": refreshed,
        "freshness_s": c.get("freshness_s"),
        "proof": {
            "method": "locally verified proof-of-work headers + MTP-11 bound",
            "offline": "python3 /opt/ares/okf_now.py --verify <proof>",
            "note": ("an agent should stamp results with window.lo..hi, never a "
                     "bare wall-clock second"),
        },
    }


def _verify(path):
    """Verify that an artifact's Bitcoin timestamp is inside our verified chain."""
    out = {"artifact": path, "ok": False, "problems": []}
    # opentimestamps lives in the conduit venv, not in whatever interpreter this
    # process happens to be — use it explicitly, same trap as everywhere else.
    ots_py = ("/opt/ares/venv/bin/python" if os.path.exists("/opt/ares/venv/bin/python")
              else sys.executable)
    if path.endswith(".ots"):
        r = subprocess.run([ots_py, "/opt/ares/okf_ots_verify.py", path, "--json"],
                           capture_output=True, text=True)
        try:
            d = json.loads(r.stdout)
        except Exception:  # noqa: BLE001
            out["problems"].append("verifier produced no JSON")
            return out
        if isinstance(d, list):
            d = d[0] if d else {}
        out["ok"] = bool(d.get("verified") or d.get("ok"))
        atts = d.get("attestations") or []
        best = None
        for at in atts:
            if at.get("verified") and (best is None or
                                       (at.get("height") or 0) > (best.get("height") or 0)):
                best = at
        if best:
            out["height"] = best.get("height")
            out["block_hash"] = best.get("block_hash")
            out["block_time"] = best.get("time")
            out["buried_ok"] = best.get("buried_ok")
            out["chain_back"] = best.get("chain_back")
        else:
            out["height"] = d.get("height")
        out["problems"] += d.get("errors") or []
        return out

    if path.endswith(".json"):
        try:
            d = json.load(open(path))
        except Exception as e:  # noqa: BLE001
            out["problems"].append(f"unreadable: {e}")
            return out
        # A time-attestation names its block; a receipt buries it under
        # created_at_btc.block, and older receipts under run.btc.
        btc = d.get("created_at_btc") or {}
        h = (d.get("height")
             or (btc.get("block") or {}).get("height")
             or (d.get("block") or {}).get("height")
             or (d.get("run", {}).get("btc") or {}).get("height")
             or d.get("block_height"))
        if not h:
            out["problems"].append("no block height in this artifact")
            return out
        import okf_btc_chain
        hd, src = okf_btc_chain.header_at_height(int(h), cache={})
        claimed = (d.get("block_hash")
                   or (btc.get("block") or {}).get("hash")
                   or (d.get("block") or {}).get("hash")
                   or (d.get("run", {}).get("btc") or {}).get("tip_hash"))
        out["height"] = int(h)
        out["block_hash"] = hd["hash"]
        out["block_time"] = hd["time"]
        out["ok"] = hd["pow_ok"] and (not claimed or
                                      str(claimed).lower() == hd["hash"].lower())
        if claimed and str(claimed).lower() != hd["hash"].lower():
            out["problems"].append("claimed block hash does not match the chain")
        if not hd["pow_ok"]:
            out["problems"].append("header at that height fails proof-of-work")
        win = btc.get("window") or {}
        if win.get("lo") and win.get("hi"):
            out["window"] = win
            if int(win["hi"]) < hd["time"]:
                out["problems"].append("window ends before its own block was mined")
                out["ok"] = False
        out["source"] = src
        return out

    out["problems"].append("unsupported artifact type")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="(default)")
    ap.add_argument("--human", action="store_true")
    ap.add_argument("--force", action="store_true", help="bypass the 45s cache")
    ap.add_argument("--require", choices=["verified", "rooted"], default="rooted",
                    help="exit nonzero unless the clock meets this bar")
    ap.add_argument("--verify", metavar="ARTIFACT")
    a = ap.parse_args()

    if a.verify:
        r = _verify(a.verify)
        print(json.dumps(r, indent=2))
        sys.exit(0 if r["ok"] else 1)

    d = build(force=a.force)

    if a.human:
        if not d.get("ok"):
            print(f"CLOCK UNVERIFIED — {d.get('error')}")
        else:
            w = d["window"]
            print(f"{d['utc']}  ± {d['uncertainty_s']}s   block {d['block']['height']} "
                  f"· depth {d['chain']['depth']} · "
                  f"{'rooted' if d['root']['rooted'] else 'NOT rooted'}")
            print(f"  provable window: {w['lo_utc']} .. {w['hi_utc']}")
            if d["block"].get("hash"):
                print(f"  tip {d['block']['hash']}")
    else:
        print(json.dumps(d, indent=2))

    if not d.get("ok"):
        sys.exit(1)
    if a.require == "rooted" and not d["root"]["rooted"]:
        sys.exit(3)
    sys.exit(0)


if __name__ == "__main__":
    main()
