#!/usr/bin/env python3
"""okf_sid_anchor.py — the OKF clock's half of a SID certificate.

Ownership is split on purpose:

  * OKF owns TIME. It stamps the certificate's hash with OpenTimestamps and
    reports the block it was verified against.
  * The kernel (omokoda-agent) owns IDENTITY. It consumes this artifact to mint
    the chained v2 and never delegates identity decisions here.

This script therefore mints nothing, signs nothing and edits no certificate. It
reads `cert.json`, timestamps `hash`, and writes an anchor artifact.

CLI:
    okf_sid_anchor.py stamp <cert.json> [--out <anchor.json>]

Exit codes: 0 stamped · 1 refused/error · 3 verifier unavailable.
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import okf_btc_chain  # noqa: E402
import okf_ots_verify  # noqa: E402

import okf_receipt  # noqa: E402

# One source of truth for the binary: whatever emits the pipeline's receipts.
OTS_BIN = os.environ.get("OTS_BIN", okf_receipt.OTS_BIN)
ANCHOR_FORMAT = "sid-anchor/0.1"


def _sha256_file(path):
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_clock():
    """The verified tip, from OKF's own anchor + header check.

    Refuses rather than guesses: an unverified header is not a clock.
    """
    anchor = okf_btc_chain._load_anchor()
    height = anchor.get("height")
    bhash = anchor.get("hash")
    if not isinstance(height, int) or not isinstance(bhash, str):
        raise SystemExit("okf_sid_anchor: the OKF anchor has no tip — run the clock tick first")
    cache = okf_btc_chain._load_cache()
    hd = okf_btc_chain.header_at_height_by_hash(bhash, cache)
    if not hd:
        raise SystemExit(f"okf_sid_anchor: no header for tip {height} {bhash[:16]}…")
    if not hd.get("pow_ok"):
        raise SystemExit(f"okf_sid_anchor: header {height} failed the PoW check — refusing")
    return height, bhash, hd


def stamp(cert_path):
    cert = json.load(open(cert_path))
    cert_hash = cert.get("hash")
    if not isinstance(cert_hash, str) or len(cert_hash) != 64:
        raise SystemExit("okf_sid_anchor: certificate has no 64-hex `hash` — nothing to stamp")

    d = os.path.dirname(os.path.abspath(cert_path))
    stem = os.path.splitext(os.path.basename(cert_path))[0]
    hashfile = os.path.join(d, f"{stem}.sidhash.txt")
    with open(hashfile, "w") as f:
        f.write(cert_hash + "\n")
    ots_file = hashfile + ".ots"

    stamp_rc, stamp_out = None, ""
    if os.path.exists(OTS_BIN):
        p = subprocess.run([OTS_BIN, "stamp", hashfile], capture_output=True, text=True, timeout=180)
        stamp_rc = p.returncode
        stamp_out = (p.stdout or p.stderr or "").strip()[-400:]
    else:
        stamp_out = f"{OTS_BIN} not installed — clock unavailable"

    out = {
        "format": ANCHOR_FORMAT,
        "cert_id": cert.get("id"),
        "cert_hash": cert_hash,
        "cert_version": cert.get("version"),
        "ots_proof": ots_file if os.path.exists(ots_file) else None,
        "ots_status": None,
        "anchor_block": None,
        "anchor_block_hash": None,
        "anchor_source": "okf",
        "anchor_verified": False,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "stamp_rc": stamp_rc,
        "note": stamp_out,
    }

    # The clock is independent of the OTS verifier: read it regardless, so a
    # missing python module cannot make the artifact lie about the tip.
    height, bhash, hd = read_clock()
    out.update(
        anchor_block=height,
        anchor_block_hash=bhash,
        anchor_verified=True,
        anchor_time=hd.get("time"),
    )

    rc = 0
    if out["ots_proof"]:
        v = okf_ots_verify.verify_proof(out["ots_proof"])
        if v.get("status") == "verifier_unavailable":
            # The python verifier is not installed here. Ask the binary instead:
            # a proof with no block attestation is PENDING, and pending is not
            # anchored — say so rather than assuming the best case.
            status, detail = "unknown", "verifier_unavailable"
            p = subprocess.run([OTS_BIN, "info", out["ots_proof"]], capture_output=True, text=True, timeout=60)
            text = (p.stdout or p.stderr or "")
            if "BitcoinBlockHeaderAttestation" in text:
                status, detail = "complete", "ots-info"
                rc = 0
            elif "PendingAttestation" in text or "pending" in text.lower():
                status, detail = "pending", "ots-info"
            out["ots_status"] = status
            out["ots_status_source"] = detail
            out["ots_info"] = text.strip()[:600]
            if status == "unknown":
                print("okf_sid_anchor: cannot determine proof status — verifier unavailable", file=sys.stderr)
                rc = 3
        else:
            out["ots_status"] = "complete" if v.get("ok") else "pending"
            out["ots_status_source"] = "verify_proof"
            out["ots_attestations"] = v.get("attestations") or []
    return out, rc
    out["anchor_block"] = height
    out["anchor_block_hash"] = bhash
    out["anchor_verified"] = True

def main(argv):
    if len(argv) < 3 or argv[1] != "stamp":
        print(__doc__.split("CLI:")[1].strip())
        return 1
    cert_path = argv[2]
    out_path = None
    if "--out" in argv:
        out_path = argv[argv.index("--out") + 1]
    anchor, rc = stamp(cert_path)
    out_path = out_path or os.path.splitext(cert_path)[0] + ".anchor.json"
    with open(out_path, "w") as f:
        json.dump(anchor, f, indent=2, sort_keys=True)
    print(f"cert      {anchor['cert_id']}  v{anchor['cert_version']}")
    print(f"hash      {anchor['cert_hash']}")
    print(f"ots       {anchor['ots_proof'] or 'not stamped'}  ({anchor['ots_status'] or 'none'})")
    print(f"clock     block {anchor['anchor_block']} {str(anchor['anchor_block_hash'])[:16]}…  verified={anchor['anchor_verified']}")
    print(f"wrote     {out_path}")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
