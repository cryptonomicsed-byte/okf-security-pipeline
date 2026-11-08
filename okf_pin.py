#!/usr/bin/env python3
"""Pin the Bitcoin chain to a root someone other than this host chose.

`verified_depth` answers "how much has been checked". It cannot answer "is this
Bitcoin". A pin does: one (height, hash) taken from a source outside this
machine — Bitcoin Core's shipped checkpoints, a hash you wrote down elsewhere,
an old block explorer page. Verification then fails outright if the chain does
not reach that block with that hash.

Usage:
    okf_pin.py add 974984 <hash> --source "core checkpoints"
    okf_pin.py import checkpoints.txt --source "core"      # lines: <height> <hash>
    okf_pin.py list
    okf_pin.py remove 974984
    okf_pin.py check          # run verify_chain and report rooted/ok
"""
import argparse
import json
import sys
from pathlib import Path

PINS = Path(__import__("os").environ.get("OKF_BTC_PINS", "/opt/ares/.btc_pins.json"))


def load():
    try:
        return json.loads(PINS.read_text())
    except Exception:  # noqa: BLE001
        return {"pins": []}


def save(d):
    PINS.write_text(json.dumps(d, indent=2) + "\n")
    PINS.chmod(0o600)


def add(height, blk_hash, source=None, klass="self_recorded", extra=None):
    d = load()
    d["pins"] = [p for p in d.get("pins", []) if int(p["height"]) != int(height)]
    rec = {"height": int(height), "hash": blk_hash.strip().lower(),
           "source": source, "class": klass,
           "added_at": int(__import__("time").time())}
    if extra:
        rec.update(extra)
    d["pins"].append(rec)
    d["pins"].sort(key=lambda p: int(p["height"]))
    save(d)
    return d


def root(depth=6, min_sources=3, dry_run=False):
    """Choose the root by evidence, not by convenience.

    A single API answering "block N is H" is a claim. Three independent operators
    answering the same thing is corroboration; a locally verified proof-of-work
    header makes the claim expensive to fake. And a block six deep cannot be
    rewritten without redoing the work above it, so burial is what makes the pin
    durable rather than merely current.
    """
    sys.path.insert(0, "/opt/ares")
    import okf_btc_chain as chain

    srcs = list(chain.SOURCES) + [("blockchain.info", "https://blockchain.info")]
    tips, failures = {}, {}
    for name, base in srcs:
        try:
            h, _ = chain._http(f"{base}/blocks/tip/height" if "blockchain" not in base
                               else f"{base}/q/getblockcount")
            tips[name] = int(h.strip())
        except Exception as e:  # noqa: BLE001
            failures[name] = str(e)[:60]
    if len(tips) < min_sources:
        return {"ok": False, "error": f"only {len(tips)} source(s) answered, "
                                     f"need {min_sources}", "tips": tips, "failed": failures}
    agree = {}
    for n, h in tips.items():
        agree.setdefault(h, []).append(n)
    tip_height, agree_srcs = max(agree.items(), key=lambda kv: (len(kv[1]), kv[0]))
    if len(agree_srcs) < min_sources:
        return {"ok": False, "error": "sources disagree on tip height",
                "tips": tips, "agreeing": agree_srcs}
    target_h = tip_height - depth
    hashes, hfail = {}, {}
    for name in agree_srcs:
        base = dict(srcs)[name]
        try:
            if "blockchain" in base:
                bh = chain._http(f"{base}/block-height/{target_h}?format=json")[0]
                import json as _j
                bh = _j.loads(bh)["blocks"][0]["hash"]
            else:
                bh = chain._http(f"{base}/block-height/{target_h}")[0]
            hashes[name] = bh.strip().lower()
        except Exception as e:  # noqa: BLE001
            hfail[name] = str(e)[:60]
    if len(hashes) < min_sources:
        return {"ok": False, "error": f"only {len(hashes)} source(s) named block "
                                     f"{target_h}", "hashes": hashes, "failed": hfail}
    if len(set(hashes.values())) != 1:
        return {"ok": False, "error": f"sources disagree on block {target_h} hash",
                "hashes": hashes}
    pin_hash = next(iter(hashes.values()))

    # Verify the header ourselves: self-hash, PoW vs bits, and linkage to h-1.
    hd, src_used = chain.header_at_height(target_h, cache={})
    pow_ok = (hd["hash"].lower() == pin_hash and hd["pow_ok"])
    below, _ = chain.header_at_height(target_h - 1, cache={})
    linkage_ok = (below["hash"].lower() == hd["prev"].lower())
    result = {"ok": bool(pow_ok and linkage_ok), "height": target_h, "hash": pin_hash,
              "tip": tip_height, "depth_behind_tip": depth,
              "sources": hashes, "header_source": src_used,
              "pow_ok": pow_ok, "linkage_ok": linkage_ok,
              "block_time": hd["time"], "bits": hex(hd["bits"]),
              "class": "buried_multi_source"}
    if not result["ok"]:
        result["error"] = "local PoW/linkage verification failed — refusing to pin"
        return result
    if not dry_run:
        add(target_h, pin_hash, f"{len(hashes)}/{len(agree_srcs)} sources agree, "
                                f"buried {depth}, PoW+linkage verified locally",
            klass="buried_multi_source",
            extra={"provenance": hashes, "block_time": hd["time"]})
    return result


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add"); a.add_argument("height", type=int); a.add_argument("hash")
    a.add_argument("--source"); a.add_argument("--class", dest="klass",
                                               default="self_recorded")
    i = sub.add_parser("import"); i.add_argument("file"); i.add_argument("--source")
    i.add_argument("--class", dest="klass", default="core_checkpoints")
    rt = sub.add_parser("root")
    rt.add_argument("--depth", type=int, default=6)
    rt.add_argument("--min-sources", type=int, default=3)
    rt.add_argument("--dry-run", action="store_true")
    sub.add_parser("list")
    r = sub.add_parser("remove"); r.add_argument("height", type=int)
    sub.add_parser("check")
    ns = ap.parse_args()

    if ns.cmd == "add":
        d = add(ns.height, ns.hash, ns.source, klass=ns.klass)
        print(f"pinned {ns.height} {ns.hash.lower()[:16]}… · {len(d['pins'])} pin(s) "
              f"· class {ns.klass}")
    elif ns.cmd == "root":
        out = root(ns.depth, ns.min_sources, ns.dry_run)
        print(json.dumps(out, indent=2))
        sys.exit(0 if out.get("ok") else 1)
    elif ns.cmd == "import":
        n = 0
        for line in Path(ns.file).read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                add(int(parts[0]), parts[1], ns.source)
                n += 1
        print(f"imported {n} pin(s) from {ns.file}")
    elif ns.cmd == "list":
        d = load()
        if not d.get("pins"):
            print("no pins — the chain is unrooted (depth is known, provenance is not)")
        for p in d.get("pins", []):
            print(f"  {p['height']}  {p['hash']}  {p.get('source') or ''}")
    elif ns.cmd == "remove":
        d = load()
        d["pins"] = [p for p in d.get("pins", []) if int(p["height"]) != ns.height]
        save(d)
        print(f"removed {ns.height} · {len(d['pins'])} pin(s) left")
    elif ns.cmd == "check":
        sys.path.insert(0, "/opt/ares")
        import okf_btc_chain
        res = okf_btc_chain.verify_chain(save_cache=False)
        cont = res.get("continuity") or {}
        print(json.dumps({"height": res.get("height"), "ok": res.get("ok"),
                          "rooted": res.get("rooted"),
                          "depth": (cont.get("verified_depth") or {}).get("count"),
                          "pin": cont.get("pin"),
                          "error": cont.get("error")}, indent=2))


if __name__ == "__main__":
    main()
