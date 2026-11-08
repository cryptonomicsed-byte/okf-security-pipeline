#!/usr/bin/env python3
"""okf_ots_verify — turn "an attestation exists" into "this merkle root is in that block".

`ots info` only prints `BitcoinBlockHeaderAttestation(974956)`. That is a claim
written inside a file we generated; nothing about it is checked. This module
closes the loop without a Bitcoin node:

  1. parse the .ots proof with the opentimestamps library
  2. take the merkle root the proof claims for a given height
  3. fetch that block's 80-byte header from a public source
  4. compare the header's merkle root field to the claimed root
  5. check the header hashes to the block hash the source reported, and that
     the hash meets the difficulty target in `bits`

If all five hold, the receipt's digest really was committed into block N, and
block N is identified by its own proof-of-work. No trust in the calendar server
is required for the final step — only for having relayed the header, which is
why the block hash and PoW are both checked.

CLI:
    python3 okf_ots_verify.py <proof.ots> [--json]
    python3 okf_ots_verify.py --all
"""
import argparse
import hashlib
import io
import json
import sys

SOURCES = [
    ("mempool.space", "https://mempool.space/api/block-height/{h}", "https://mempool.space/api/block/{b}/header"),
    ("blockstream.info", "https://blockstream.info/api/block-height/{h}", "https://blockstream.info/api/block/{b}/header"),
]


def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _target_from_bits(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    return mantissa * (1 << (8 * (exponent - 3)))


def _ots_available():
    try:
        import opentimestamps  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


OTS_MISSING_MSG = ("verifier unavailable: the `opentimestamps` package is not installed "
                   "for this interpreter ({py}). This is NOT a verdict on the proof.\n"
                   "Run it with /opt/ares/venv/bin/python — that is where the package lives.")


def parse_proof(path):
    """Return [(height, merkle_root_hex_internal_order)] for Bitcoin attestations."""
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.timestamp import BitcoinBlockHeaderAttestation, DetachedTimestampFile
    with open(path, "rb") as f:
        dt = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(f.read())))
    out = []
    for msg, att in dt.timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            out.append((int(att.height), msg.hex()))
    digest = dt.file_digest
    digest_hex = digest.hex() if isinstance(digest, (bytes, bytearray)) else str(digest)
    return digest_hex, out


def _get(url, timeout=20):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "okf-ots-verify/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode().strip()


def verify_proof(path):
    res = {"proof": path, "ok": False, "attestations": [], "errors": []}
    if not _ots_available():
        res["status"] = "verifier_unavailable"
        res["errors"].append(OTS_MISSING_MSG.format(py=sys.executable))
        return res
    try:
        digest_hex, atts = parse_proof(path)
    except Exception as e:  # noqa: BLE001
        res["errors"].append(f"parse: {e}")
        return res
    res["digest"] = digest_hex
    if not atts:
        res["errors"].append("no BitcoinBlockHeaderAttestation (still pending)")
        return res

    for name, h_url, b_url in SOURCES:
        try:
            for height, claimed in atts:
                block_hash = _get(h_url.format(h=height))
                header_hex = _get(b_url.format(b=block_hash))
                header = bytes.fromhex(header_hex)
                if len(header) != 80:
                    res["errors"].append(f"{name}: header length {len(header)}")
                    continue
                merkle_field = header[36:68]
                bits = int.from_bytes(header[72:76], "little")
                h = _sha256d(header)
                entry = {
                    "height": height,
                    "block_hash": block_hash,
                    "source": name,
                    "merkle_field": merkle_field[::-1].hex(),
                    "claimed_root": bytes.fromhex(claimed)[::-1].hex(),
                    "merkle_match": merkle_field == bytes.fromhex(claimed),
                    "hash_matches": h[::-1].hex() == block_hash,
                    "pow_ok": int.from_bytes(h, "little") <= _target_from_bits(bits),
                    "time": int.from_bytes(header[68:72], "little"),
                }
                entry["verified"] = bool(entry["merkle_match"] and entry["hash_matches"] and entry["pow_ok"])
                if entry["verified"]:
                    # One header proves the merkle root is in *a* block; walking
                    # the prev chain proves that block is buried in the chain we
                    # also verify for the clock.
                    try:
                        import okf_btc_chain as C
                        cache = C._load_cache()
                        hd = C.header_at_height_by_hash(block_hash, cache)
                        back, cur = 0, hd
                        for _ in range(6):
                            nxt = C.header_at_height_by_hash(cur["prev"], cache)
                            if nxt["hash"] != cur["prev"] or not nxt["pow_ok"]:
                                break
                            back += 1
                            cur = nxt
                        entry["chain_back"] = back
                        entry["buried_ok"] = back >= 3
                    except Exception as e:  # noqa: BLE001
                        entry["buried_ok"] = False
                        entry["chain_error"] = str(e)[:100]
                    entry["verified"] = bool(entry["verified"] and entry.get("buried_ok"))
                res["attestations"].append(entry)
                if entry["verified"]:
                    res["ok"] = True
            if res["attestations"]:
                res["source_used"] = name
                break
        except Exception as e:  # noqa: BLE001
            res["errors"].append(f"{name}: {e}")
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("proof", nargs="?")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if a.all:
        import glob
        paths = sorted(glob.glob("/opt/ares/security_receipts/*/*.merkle.txt.ots"))
    elif a.proof:
        paths = [a.proof]
    else:
        ap.error("give a proof path or --all")

    out = [verify_proof(p) for p in paths]
    if a.json:
        print(json.dumps(out, indent=2))
        return 0
    for r in out:
        if r.get("status") == "verifier_unavailable":
            print(f"UNAVAILABLE  {r['proof'].split('/')[-1][:26]:<26} "
                  f"{r['errors'][-1].splitlines()[0]}")
            continue
        if r["ok"]:
            e = next(x for x in r["attestations"] if x["verified"])
            print(f"VERIFIED  {r['proof'].split('/')[-1][:28]:<28} block {e['height']} "
                  f"{e['block_hash'][:16]}… via {e['source']} · pow ok · merkle ok")
        elif r.get("attestations"):
            e = r["attestations"][0]
            print(f"MISMATCH  {r['proof'].split('/')[-1][:28]:<28} height {e['height']} "
                  f"merkle={e['merkle_match']} hash={e['hash_matches']} pow={e['pow_ok']}")
        else:
            print(f"PENDING   {r['proof'].split('/')[-1][:28]:<28} {r['errors'][-1] if r['errors'] else ''}")
    if any(r.get("status") == "verifier_unavailable" for r in out):
        return 3  # cannot answer — distinct from "proof is bad"
    return 0 if all(r["ok"] or not r.get("attestations") for r in out) else 1


if __name__ == "__main__":
    sys.exit(main())
