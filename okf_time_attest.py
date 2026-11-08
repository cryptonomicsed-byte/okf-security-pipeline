#!/usr/bin/env python3
"""okf_time_attest — a signed record saying WHEN, bound to a verified block.

A receipt proves what was found. Its `.time.json` sidecar proves nothing: it is
a cache next to the artifact, written by us, editable by anyone. This module
emits the missing artifact — a signed, self-verifying attestation that binds a
receipt's merkle root to a Bitcoin block height whose header merkle root and
proof-of-work were checked locally.

    receipt   -> what was found           (okf_receipt.py, chained per repo)
    .ots      -> commitment into a calendar tree
    .attest.json -> when, signed         (this module, chained per repo)

The attestation references the receipt by id and merkle root, so tampering with
either file breaks the reference; and its own id/signature are recomputed by
`verify` the same way receipts are.

CLI:
    python3 okf_time_attest.py <receipt.json>
    python3 okf_time_attest.py --all
    python3 okf_time_attest.py --verify <receipt.json|attest.json>
"""
import argparse
import glob
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, "/opt/ares")
import okf_ots_verify as OTSV  # noqa: E402
import okf_receipt as R  # noqa: E402


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _prev_attestation(repo_dir):
    files = sorted(glob.glob(os.path.join(repo_dir, "*.attest.json")),
                   key=os.path.getmtime)
    if not files:
        return None
    try:
        return json.load(open(files[-1])).get("attestation_id")
    except Exception:  # noqa: BLE001
        return None


def build(receipt_path):
    receipt_path = os.path.abspath(receipt_path)
    r = json.load(open(receipt_path))
    stem = receipt_path[:-5]
    proofs = sorted(glob.glob(stem + "*.ots"))
    if not proofs:
        return {"error": "no OpenTimestamps proof next to this receipt"}
    v = OTSV.verify_proof(proofs[0])
    if not v.get("ok"):
        return {"error": "proof not verified against Bitcoin",
                "detail": (v.get("errors") or [])[:3],
                "attestations": v.get("attestations", [])[:1]}
    att = next(a for a in v["attestations"] if a.get("verified"))
    # Idempotent: re-running must not re-sign an identical claim, or the
    # prev_attestation pointer would end up citing a version that no longer
    # exists.
    existing = stem + ".attest.json"
    if os.path.exists(existing):
        try:
            old = json.load(open(existing))
            if (old.get("target_merkle_root") == r.get("merkle_root")
                    and (old.get("bitcoin") or {}).get("height") == att["height"]
                    and all((old.get("checks") or {}).values())):
                return {"skipped": "already attested", "path": existing,
                        "attestation_id": old.get("attestation_id")}
        except Exception:  # noqa: BLE001
            pass
    body = {
        "attest_version": "1.0",
        "kind": "time-attestation",
        "created_at": _now(),
        "repo": r.get("repo"),
        "target_receipt_id": r.get("receipt_id"),
        "target_merkle_root": r.get("merkle_root"),
        "target_created_at": r.get("created_at"),
        "target_chain_index": r.get("chain_index"),
        "stamped_digest": v.get("digest"),
        "proof_file": os.path.basename(proofs[0]),
        "bitcoin": {
            "height": att["height"],
            "block_hash": att["block_hash"],
            "block_time": att["time"],
            "merkle_root": att["merkle_field"],
            "source": att["source"],
        },
        "checks": {
            "merkle_in_block": bool(att["merkle_match"]),
            "header_hashes_to_block": bool(att["hash_matches"]),
            "pow_meets_target": bool(att["pow_ok"]),
            "block_buried": bool(att.get("buried_ok")),
            "blocks_behind": att.get("chain_back"),
        },
        "prev_attestation": _prev_attestation(os.path.dirname(receipt_path)),
    }
    aid = R.sha256_bytes(R.canonical(body))
    body["attestation_id"] = aid
    body["signature"] = hmac.new(R._key(), R.canonical(body), hashlib.sha256).hexdigest()

    out = stem + ".attest.json"
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(body, f, indent=2, sort_keys=True)
    os.replace(tmp, out)
    return {"attestation_id": aid, "path": out, "receipt": r.get("receipt_id"),
            "height": att["height"], "block_hash": att["block_hash"],
            "prev_attestation": body["prev_attestation"]}


def verify(path):
    """Verify either an attestation or a receipt; returns a uniform report."""
    d = json.load(open(path))
    problems = []
    is_att = d.get("kind") == "time-attestation"
    body = {k: v for k, v in d.items() if k not in ("attestation_id", "receipt_id", "signature")}
    recomputed = R.sha256_bytes(R.canonical(body))
    claimed = d.get("attestation_id") if is_att else d.get("receipt_id")
    if recomputed != claimed:
        problems.append("id mismatch (body edited)")
    sig = hmac.new(R._key(), R.canonical({k: v for k, v in d.items() if k != "signature"}),
                   hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, d.get("signature", "")):
        problems.append("signature invalid")
    if is_att:
        target = os.path.join(os.path.dirname(os.path.abspath(path)),
                              (d.get("target_receipt_id") or "")[:16] + ".json")
        if not os.path.exists(target):
            problems.append("target receipt missing")
        else:
            t = json.load(open(target))
            if t.get("receipt_id") != d.get("target_receipt_id"):
                problems.append("target receipt id mismatch")
            if t.get("merkle_root") != d.get("target_merkle_root"):
                problems.append("target merkle root mismatch (receipt changed)")
        if not all(d.get("checks", {}).values()):
            problems.append("bitcoin checks not all true")
    return {"ok": not problems, "kind": "attestation" if is_att else "receipt",
            "id": claimed, "problems": problems}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--verify", metavar="FILE", action="append")
    a = ap.parse_args()

    if a.verify:
        bad = 0
        for p in a.verify:
            v = verify(p)
            print(f"{'OK  ' if v['ok'] else 'FAIL'} {v['kind']:<11} {str(v['id'])[:16]} "
                  f"{'; '.join(v['problems'])}")
            bad += 0 if v["ok"] else 1
        return 1 if bad else 0

    if a.all:
        paths = [p for p in glob.glob("/opt/ares/security_receipts/*/*.json")
                 if not p.endswith((".attest.json", ".time.json"))]
    elif a.path:
        paths = [a.path]
    else:
        ap.error("give a receipt path or --all")

    made, pending, failed = [], 0, []
    for p in sorted(paths):
        res = build(p)
        if res.get("skipped"):
            continue
        if res.get("attestation_id"):
            made.append(res)
            print(f"ATTESTED  {str(res.get('receipt'))[:16]} -> block {res.get('height')} "
                  f"{str(res.get('block_hash'))[:16]}… ({res['attestation_id'][:16]})")
        elif "no OpenTimestamps proof" in str(res.get("error", "")):
            continue
        elif res.get("error"):
            pending += 1
    if not made:
        print(f"nothing to attest ({pending} proofs unverified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
