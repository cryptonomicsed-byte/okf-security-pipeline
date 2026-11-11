#!/usr/bin/env python3
"""koodu_time — bridge Koodu's BTC-Time calendar into the receipt pipeline.

Koodu (`/opt/ares/Koodu/btc-time.js`) is a *calendar*, not a clock: it turns a
Bitcoin block height into the ecosystem's canonical vocabulary — BTC day/week,
domain day (Access/Score/History/Query/Sync/Run/Policy), Sabbath flag, halving
era, alchemy stage. It cannot prove time; it estimates height from wall clock
and says so. The proof comes from OpenTimestamps + a Bitcoin block header.

So the division is clean:
    proof of time   -> OpenTimestamps attestation (BitcoinBlockHeaderAttestation)
    meaning of time -> Koodu btc-time.js (era, domain day, Sabbath gate)

    python3 koodu_time.py                 # live tip height -> snapshot
    python3 koodu_time.py 974954          # explicit height
    python3 koodu_time.py --ots FILE.ots  # height from a Bitcoin attestation
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

BTC_TIME_JS = "/opt/ares/Koodu/btc-time.js"
OTS_BIN = "/opt/ares/venv/bin/ots"
TIP_SOURCES = ["https://mempool.space/api/blocks/tip/height",
               "https://blockstream.info/api/blocks/tip/height"]


def tip_height(timeout=10):
    for url in TIP_SOURCES:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return int(r.read().decode().strip())
        except Exception:  # noqa: BLE001
            continue
    return None


def attestation_height(info_text):
    """Parse `ots info` output for a Bitcoin attestation height.

    Returns None while the proof is still a PendingAttestation — a pending
    calendar commitment is not a timestamp, and must not be rendered as one.
    """
    m = re.search(r"BitcoinBlockHeaderAttestation\((\d+)\)", info_text or "")
    return int(m.group(1)) if m else None


def ots_height(ots_path):
    p = subprocess.run([OTS_BIN, "info", ots_path], capture_output=True, text=True,
                       timeout=90)
    text = (p.stdout or "") + (p.stderr or "")
    return {"height": attestation_height(text),
            "pending": "PendingAttestation" in text,
            "raw": text.strip()[:600]}


_NODE = None


def node_bin():
    """Resolve a node that actually runs.

    Background/systemd shells here can put an nvm shim first on PATH, which
    fails with `N/A: version "v24.22.1" is not yet installed` — that killed a
    pipeline run mid-flight. Prefer a concrete binary and prove it works.
    """
    global _NODE
    if _NODE:
        return _NODE
    import shutil
    for cand in (os.environ.get("OKF_NODE_BIN"), "/usr/local/bin/node",
                 "/usr/bin/node", shutil.which("node")):
        if not cand:
            continue
        try:
            p = subprocess.run([cand, "-v"], capture_output=True, text=True, timeout=10)
            if p.returncode == 0 and (p.stdout or "").strip().startswith("v"):
                _NODE = cand
                return cand
        except Exception:  # noqa: BLE001
            continue
    raise RuntimeError("no working node binary (tried OKF_NODE_BIN, /usr/local/bin, /usr/bin, PATH)")


def snapshot(height):
    """Run Koodu's BTCTime for a height and return its full snapshot."""
    js = ("import('%s').then(m=>{const t=new m.BTCTime(%d);"
          "console.log(JSON.stringify(t.snapshot()))})" % (BTC_TIME_JS, height))
    p = subprocess.run([node_bin(), "--no-warnings", "-e", js],
                       capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout).strip()[:300])
    return json.loads(p.stdout.strip())


def for_receipt(receipt_path):
    """Height for a receipt: prefer its .ots attestation, else nothing. Never
    falls back to the wall clock — that would invent a timestamp."""
    from pathlib import Path
    p = Path(receipt_path)
    ots = list(p.parent.glob(f"{p.stem}*.ots"))
    if not ots:
        return {"error": "no .ots proof next to this receipt"}
    info = ots_height(str(ots[0]))
    if not info["height"]:
        return {"ots_file": str(ots[0]), "pending": True,
                "error": "pending calendar attestation — no Bitcoin height yet"}
    # A height exists => this proof has a completed Bitcoin branch. Other
    # calendar branches may still be pending; that is not the same thing as
    # "unverified timestamp", and conflating them made every sidecar read as
    # `height: N, pending: true`.
    info["pending"] = False
    info["pending_branches"] = (info.get("raw") or "").count("PendingAttestation")
    try:
        # The opentimestamps library lives in the ares venv, not in the system
        # python that cron/systemd may use — shell out so verification does not
        # depend on which interpreter started us.
        import shutil
        import subprocess
        py = "/opt/ares/venv/bin/python3" if os.path.exists("/opt/ares/venv/bin/python3") else shutil.which("python3")
        p = subprocess.run([py, "/opt/ares/okf_ots_verify.py", str(ots[0]), "--json"],
                           capture_output=True, text=True, timeout=120)
        v = (json.loads(p.stdout or "[]") or [{}])[0]
        att = next((a for a in v.get("attestations", []) if a.get("verified")), None)
        info["verification"] = {
            "ok": bool(v.get("ok")),
            "source": v.get("source_used"),
            "block_hash": (att or {}).get("block_hash"),
            "merkle_match": (att or {}).get("merkle_match"),
            "pow_ok": (att or {}).get("pow_ok"),
            "errors": (v.get("errors") or [])[:2],
        }
    except Exception as e:  # noqa: BLE001
        info["verification"] = {"ok": False, "errors": [str(e)[:120]]}
    snap = snapshot(info["height"])
    return {"ots_file": str(ots[0]), "bitcoin": info,
            "sacred_time": snap}


def sidecars(root="/opt/ares/security_receipts"):
    """Write `<receipt>.time.json` for every receipt whose proof has a Bitcoin
    attestation. Pending proofs are skipped, not guessed — and a sidecar left
    behind by an earlier run is REMOVED once its proof is seen to be pending,
    because a file that says "height: N, pending: true" is a claim nobody can
    verify and everybody will misread as an attested time."""
    import glob
    import os
    out = {"written": [], "pending": 0, "no_proof": 0, "pruned": [], "unchanged": 0}
    for rp in sorted(glob.glob(f"{root}/*/*.json")):
        if rp.endswith((".time.json", ".attest.json")):
            continue
        try:
            res = for_receipt(rp)
        except Exception as e:  # noqa: BLE001
            out.setdefault("errors", []).append({rp: str(e)[:120]})
            continue
        path = rp[:-5] + ".time.json"
        if res.get("sacred_time"):
            # The BTCTime snapshot carries a generation wall-clock timestamp.
            # It is not attested time, it changes every run, and this docstring
            # exists precisely because such a field gets misread as "when this
            # happened". The sidecar keeps only what the Bitcoin proof attests.
            # (The JS snapshot shape is untouched -- it is a cross-repo contract.)
            res = dict(res)
            res["sacred_time"] = {k: v for k, v in res["sacred_time"].items()
                                  if k != "timestamp"}
            # Write only when content actually changed: the hourly timer must
            # not dirty 64 files (and now a git repo) with no new information.
            if os.path.exists(path):
                try:
                    if json.load(open(path)) == res:
                        out["unchanged"] = out.get("unchanged", 0) + 1
                        continue
                except Exception:  # noqa: BLE001
                    pass  # unreadable sidecar -> rewrite it
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(res, f, indent=2)
            os.replace(tmp, path)
            out["written"].append({"receipt": rp, "height": res["bitcoin"]["height"],
                                  "sidecar": path,
                                  "btc_day": res["sacred_time"]["btc_day"],
                                  "domain": res["sacred_time"]["btc_domain"]})
        else:
            if os.path.exists(path):
                os.remove(path)
                out["pruned"].append({"receipt": rp, "sidecar": path,
                                      "reason": res.get("error", "no attestation")})
            if res.get("pending"):
                out["pending"] += 1
            else:
                out["no_proof"] += 1
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("height", nargs="?", type=int)
    ap.add_argument("--ots")
    ap.add_argument("--receipt")
    ap.add_argument("--all", action="store_true",
                    help="write .time.json sidecars for every upgraded proof")
    a = ap.parse_args()

    if a.all:
        print(json.dumps(sidecars(), indent=2))
        sys.exit(0)

    if a.receipt:
        print(json.dumps(for_receipt(a.receipt), indent=2))
        sys.exit(0)
    if a.ots:
        info = ots_height(a.ots)
        print(json.dumps(info, indent=2))
        if info["height"]:
            print(json.dumps(snapshot(info["height"]), indent=2))
        sys.exit(0 if info["height"] else 4)
    h = a.height or tip_height()
    if not h:
        print(json.dumps({"error": "no height: pass one or reach a tip API"}, indent=2))
        sys.exit(2)
    print(json.dumps(snapshot(h), indent=2))
