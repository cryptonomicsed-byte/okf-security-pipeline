#!/usr/bin/env python3
"""okf_agent_stamp — what an agent does when it needs to timestamp a result.

This is the reference consumer, not a library: it shows the three moves that make
a "when" honest.

  1. Ask the clock, and treat its verdict as a gate — not a suggestion.
  2. Stamp the provable window, never a wall-clock second.
  3. Carry the evidence (block, depth, root class) so the stamp can be audited
     later by someone who was not here.

Exit codes:
    0  stamp written
    3  refused — clock verified but not rooted (bounded time, local provenance)
    1  refused — clock unverified (no stamp may claim a time)
    2  usage error

Usage:
    okf_agent_stamp.py --out stamp.json --note "scan of X"
    okf_agent_stamp.py --out stamp.json --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))
NOW = os.path.join(HERE, "okf_now.py")
PY = ("/opt/ares/venv/bin/python" if os.path.exists("/opt/ares/venv/bin/python")
      else sys.executable)


def ask_clock():
    r = subprocess.run([PY, NOW], capture_output=True, text=True, timeout=180)
    try:
        d = json.loads(r.stdout)
    except Exception:  # noqa: BLE001
        d = {"ok": False, "verdict": "unverified",
             "error": (r.stderr or r.stdout or "no output")[:300]}
    return d, r.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--note", default="")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--accept-unrooted", action="store_true",
                    help="stamp even when provenance is local (recorded as such)")
    a = ap.parse_args()

    clock, rc = ask_clock()
    verdict = clock.get("verdict")

    if verdict not in ("verified_rooted", "verified_unrooted"):
        out = {"stamped": False, "reason": "clock unverified",
               "verdict": verdict, "problems": clock.get("problems"),
               "error": clock.get("error")}
        print(json.dumps(out, indent=2) if a.json else
              f"REFUSED — no stamp: clock {verdict} "
              f"({(clock.get('problems') or ['?'])[0]})")
        return 1

    if verdict == "verified_unrooted" and not a.accept_unrooted:
        out = {"stamped": False, "reason": "not rooted", "verdict": verdict,
               "root": clock.get("root")}
        print(json.dumps(out, indent=2) if a.json else
              "REFUSED — time is bounded but the chain is not rooted to an "
              "external block; pass --accept-unrooted to stamp it as unrooted")
        return 3

    w = clock["window"]
    stamp = {
        "stamped": True,
        "note": a.note,
        "verdict": verdict,
        "window": {"lo": w["lo"], "hi": w["hi"],
                   "lo_utc": w["lo_utc"], "hi_utc": w["hi_utc"]},
        "block": clock["block"],
        "chain": {"depth": clock["chain"]["depth"],
                  "lowest": clock["chain"]["lowest"]},
        "root": {"rooted": clock["root"]["rooted"],
                 "class": ((clock["root"].get("pin") or {}).get("rooted_by") or
                           {}).get("class")},
        "recorded_at_host": int(time.time()),
        "verify": "okf-now --verify <this file>",
    }
    blob = json.dumps(stamp, sort_keys=True).encode()
    stamp["stamp_sha256"] = hashlib.sha256(blob).hexdigest()

    if a.out:
        with open(a.out, "w") as f:
            json.dump(stamp, f, indent=2)
    if a.json:
        print(json.dumps(stamp, indent=2))
    else:
        print(f"STAMPED  {w['lo_utc']} .. {w['hi_utc']}  block {stamp['block']['height']} "
              f"· depth {stamp['chain']['depth']} · {stamp['root']['class']}")
        if a.out:
            print(f"  -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
