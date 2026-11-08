#!/usr/bin/env python3
"""
okf_receipt — tamper-evident receipts for pipeline runs.

Pattern lifted from Zangbeto's Devnet Shrine receipt flow (SPEC.md §1: canonical
encoding, SHA-256 over canonical bytes) and its canonical diagnostic codes
(omo_diagnostic.py: OMO-ERR-NNN, severity + category bitmask). Zangbeto anchors
receipts to Arweave + OpenTimestamps and submits them to a Sui "shrine"; we keep
the same receipt shape but anchor locally in an append-only hash-chained ledger,
with Arweave/OTS left as declared-but-unfilled anchors until keys are provided.

What it gives the red-team system that it did not have:
  - each run produces a receipt whose merkle root covers every evidence artifact
  - receipts chain (prev_receipt), so deleting or editing a past run breaks verify
  - findings carry OMO diagnostic codes, so downstream agents can route on code
    instead of prose
  - verification is offline and cheap: no network, no keys required

Canonical encoding: JSON with sorted keys, no whitespace, UTF-8 — deterministic
across machines (Zangbeto uses CBOR sort_map(true); same property, cheaper here).

CLI:
    python3 okf_receipt.py emit <evidence_dir> --repo NAME
    python3 okf_receipt.py verify <receipt.json> [--files]
    python3 okf_receipt.py ledger [repo]
"""
import hashlib
import hmac
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

ROOT = (os.environ.get("OKF_RECEIPTS_ROOT") or os.environ.get("OKF_RECEIPT_ROOT")
        or "/opt/ares/security_receipts")
OTS_BIN = os.environ.get("OTS_BIN", "/opt/ares/venv/bin/ots")
KEY_FILE = os.environ.get("OKF_RECEIPT_KEY", "/opt/ares/.receipt_key")
ANCHOR_STATE = {"arweave_tx": None, "btc_ots": None, "sui_object": None}

# Zangbeto ships OMO-ERR-023 (balance underflow) as its only concrete code.
# These extend the same namespace for the classes this pipeline can prove.
DIAG_CODES = [
    ("sql injection", "OMO-ERR-101", "SECURITY"),
    ("sqli", "OMO-ERR-101", "SECURITY"),
    ("template injection", "OMO-ERR-102", "SECURITY"),
    ("ssti", "OMO-ERR-102", "SECURITY"),
    ("cross-site scripting", "OMO-ERR-103", "SECURITY"),
    ("xss", "OMO-ERR-103", "SECURITY"),
    ("path traversal", "OMO-ERR-104", "SECURITY"),
    ("command injection", "OMO-ERR-105", "SECURITY"),
    ("ssrf", "OMO-ERR-106", "SECURITY"),
    ("idor", "OMO-ERR-107", "SECURITY"),
    ("secret", "OMO-ERR-108", "SECURITY"),
    ("credential", "OMO-ERR-108", "SECURITY"),
    ("missing header", "OMO-ERR-201", "LOGIC"),
    ("misconfiguration", "OMO-ERR-202", "LOGIC"),
]
CATEGORY_BITS = {"TYPE": 1, "LOGIC": 2, "SECURITY": 4, "RECEIPT": 8,
                 "IDENTITY": 16, "RHYTHM": 32}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def merkle_root(hashes):
    """Binary merkle over sorted hex digests; odd node duplicates itself."""
    if not hashes:
        return sha256_bytes(b"")
    layer = [bytes.fromhex(h) for h in sorted(hashes)]
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [hashlib.sha256(layer[i] + layer[i + 1]).digest()
                 for i in range(0, len(layer), 2)]
    return layer[0].hex()


def _key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    key = os.urandom(32)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(KEY_FILE, 0o600)
    return key


def diag_for(finding):
    title = (finding.get("title", "") + " " + finding.get("finding_class", "")).lower()
    for needle, code, cat in DIAG_CODES:
        if needle in title:
            return {"code": code, "category": CATEGORY_BITS[cat],
                    "severity": {"critical": 2, "high": 2, "medium": 1,
                                 "low": 1, "info": 0}.get(
                        (finding.get("severity") or "error").lower(), 2),
                    "message": finding.get("title", "")[:200],
                    "endpoint": finding.get("endpoint", ""),
                    "cvss": finding.get("cvss")}
    return {"code": "OMO-ERR-199", "category": CATEGORY_BITS["SECURITY"], "severity": 2,
            "message": finding.get("title", "")[:200],
            "endpoint": finding.get("endpoint", ""), "cvss": finding.get("cvss")}


def _ledger_path(repo):
    return os.path.join(ROOT, repo, "ledger.jsonl")


def _last_receipt(repo):
    try:
        lines = [json.loads(l) for l in open(_ledger_path(repo)) if l.strip()]
    except FileNotFoundError:
        return None
    return lines[-1] if lines else None


def emit(evidence_dir, repo, findings=None, target=None, run_meta=None, exclude=None):
    """Hash the immutable evidence (raw tool logs, dumps) into a merkle root.

    report.json / report.md are deliberately excluded: they are summaries that
    reference the receipt, so hashing them would make the receipt invalid the
    moment the summary is finalised.
    """
    evidence_dir = os.path.abspath(evidence_dir)
    exclude = set(exclude or ("report.json", "report.md", "RECEIPT.txt", "receipt.json"))
    artifacts = {}
    for root, _, files in os.walk(evidence_dir):
        for fn in sorted(files):
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, evidence_dir)
            if rel in exclude:
                continue
            artifacts[rel] = {"sha256": sha256_file(p), "bytes": os.path.getsize(p)}

    findings = findings or []
    diagnostics = [diag_for(f) for f in findings]
    prev = _last_receipt(repo)
    # Stamp the receipt with Bitcoin-bounded time, not just the host clock. The
    # wall clock is a claim; the window is a bound the consensus rules enforce and
    # we re-derived by verifying headers. A receipt that says "created_at" with no
    # window asks to be trusted; this one can be checked.
    win = None
    try:
        import okf_now
        _n = okf_now.build()
        if _n.get("ok"):
            win = {"window": _n.get("window"), "block": _n.get("block"),
                   "verified": True, "rooted": bool((_n.get("root") or {}).get("rooted")),
                   "depth": (_n.get("chain") or {}).get("depth"),
                   "verdict": _n.get("verdict")}
        else:
            win = {"verified": False, "verdict": _n.get("verdict"),
                   "error": _n.get("error")}
    except Exception as e:  # noqa: BLE001
        win = {"verified": False, "error": str(e)[:120]}
    body = {
        "receipt_version": "1.0",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "created_at_btc": win,
        "repo": repo,
        "target": target or "",
        "evidence_dir": evidence_dir,
        "run": run_meta or {},
        "artifacts": artifacts,
        "merkle_root": merkle_root([a["sha256"] for a in artifacts.values()]),
        "diagnostics": diagnostics,
        "prev_receipt": prev["receipt_id"] if prev else None,
        "chain_index": (prev["chain_index"] + 1) if prev else 0,
        "anchors": dict(ANCHOR_STATE),
    }
    receipt_id = sha256_bytes(canonical(body))
    body["receipt_id"] = receipt_id
    body["signature"] = hmac.new(_key(), canonical(body), hashlib.sha256).hexdigest()

    os.makedirs(os.path.join(ROOT, repo), exist_ok=True)
    path = os.path.join(ROOT, repo, f"{receipt_id[:16]}.json")
    with open(path, "w") as f:
        json.dump(body, f, indent=2, sort_keys=True)
    with open(_ledger_path(repo), "a") as f:
        f.write(json.dumps({"chain_index": body["chain_index"], "receipt_id": receipt_id,
                            "merkle_root": body["merkle_root"], "prev": body["prev_receipt"],
                            "created_at": body["created_at"]}, sort_keys=True) + "\n")
    return {"receipt_id": receipt_id, "path": path,
            "merkle_root": body["merkle_root"], "chain_index": body["chain_index"],
            "prev_receipt": body["prev_receipt"], "artifacts": len(artifacts),
            "diagnostics": len(diagnostics)}


def verify(path, check_files=False):
    r = json.load(open(path))
    problems = []
    body = {k: v for k, v in r.items() if k not in ("receipt_id", "signature")}
    recomputed = sha256_bytes(canonical(body))
    if recomputed != r.get("receipt_id"):
        problems.append(f"receipt_id mismatch (file={r.get('receipt_id','')[:16]} "
                        f"recomputed={recomputed[:16]})")
    sig = hmac.new(_key(), canonical({k: v for k, v in r.items()
                                     if k not in ("signature",)}), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, r.get("signature", "")):
        problems.append("signature invalid (body edited or key changed)")
    root = merkle_root([a["sha256"] for a in r.get("artifacts", {}).values()])
    if root != r.get("merkle_root"):
        problems.append(f"merkle_root mismatch ({r.get('merkle_root','')[:16]} vs {root[:16]})")

    if check_files:
        base = r.get("evidence_dir") or os.path.dirname(os.path.abspath(path))
        for rel, meta in r.get("artifacts", {}).items():
            cand = os.path.join(base, rel)
            if not os.path.exists(cand):
                problems.append(f"artifact missing: {rel}")
                continue
            if sha256_file(cand) != meta["sha256"]:
                problems.append(f"artifact changed: {rel}")

    prev = r.get("prev_receipt")
    if prev:
        try:
            ledger = [json.loads(l) for l in open(_ledger_path(r["repo"])) if l.strip()]
        except FileNotFoundError:
            ledger = []
        ids = {e["receipt_id"] for e in ledger}
        if prev not in ids:
            problems.append(f"broken chain: prev_receipt {prev[:16]} not in ledger")
        idx = [e for e in ledger if e["receipt_id"] == r["receipt_id"]]
        if idx and idx[0]["chain_index"] != r["chain_index"]:
            problems.append("chain_index inconsistent with ledger")

    links = {}
    try:
        lp = path.replace(".json", ".links.json")
        if os.path.exists(lp):
            links = json.load(open(lp))
            if links.get("receipt_id") != r.get("receipt_id"):
                problems.append("links sidecar belongs to a different receipt")
            op = links.get("ots_proof")
            if op and links.get("ots_sha256"):
                if not os.path.exists(op):
                    problems.append(f"linked OTS proof missing: {op}")
                else:
                    got = hashlib.sha256(open(op, "rb").read()).hexdigest()
                    if got != links["ots_sha256"]:
                        problems.append("linked OTS proof changed since it was recorded")
    except Exception as e:  # noqa: BLE001
        problems.append(f"links sidecar unreadable: {str(e)[:80]}")
    return {"ok": not problems, "receipt_id": r.get("receipt_id"),
            "merkle_root": r.get("merkle_root"), "chain_index": r.get("chain_index"),
            "links": links, "problems": problems}


def ots_stamp(receipt_path, timeout=180):
    """Bitcoin-anchored timestamp (OpenTimestamps) over the receipt's merkle root.

    This is the piece Arweave was standing in for: it proves the root existed at
    a point in time, with no token, no wallet and no paid storage. The .ots file
    is a commitment to calendar servers; it upgrades to a full Bitcoin
    attestation once the next block confirms (minutes to hours), at which point
    `ots upgrade` completes it offline-capable."""
    rc = json.load(open(receipt_path))
    d = os.path.dirname(os.path.abspath(receipt_path))
    base = os.path.splitext(os.path.basename(receipt_path))[0]
    mf = os.path.join(d, f"{base}.merkle.txt")
    with open(mf, "w") as f:
        f.write(rc["merkle_root"] + "\n")
    out = {"merkle_root": rc["merkle_root"], "merkle_file": mf,
           "ots_file": mf + ".ots", "stamped": False}
    p = subprocess.run([OTS_BIN, "stamp", mf], capture_output=True, text=True,
                       timeout=timeout)
    out["stamp_rc"] = p.returncode
    out["stamp_out"] = (p.stdout or p.stderr or "").strip()[-500:]
    out["stamped"] = os.path.exists(out["ots_file"])
    if out["stamped"]:
        i = subprocess.run([OTS_BIN, "info", out["ots_file"]], capture_output=True,
                           text=True, timeout=60)
        out["info"] = (i.stdout or i.stderr or "").strip()[:900]
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2 or (len(sys.argv) < 3 and sys.argv[1] != "ledger"):
        print(__doc__.split("CLI:")[1].strip())
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "emit":
        repo = "unknown"
        if "--repo" in sys.argv:
            repo = sys.argv[sys.argv.index("--repo") + 1]
        ev = sys.argv[2]
        rj = os.path.join(ev, "report.json")
        payload = json.load(open(rj)) if os.path.exists(rj) else {}
        out = emit(ev, repo, payload.get("strix_findings", []),
                   payload.get("target_url", ""), {"duration_s": payload.get("duration_s")})
        print(json.dumps(out, indent=2))
    elif cmd == "verify":
        res = verify(sys.argv[2], "--files" in sys.argv)
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["ok"] else 3)
    elif cmd == "ots":
        res = ots_stamp(sys.argv[2])
        print(json.dumps(res, indent=2))
        sys.exit(0 if res.get("stamped") else 4)
    elif cmd == "ledger":
        repo = sys.argv[2] if len(sys.argv) > 2 else None
        if repo:
            for l in open(_ledger_path(repo)):
                print(l.rstrip())
        else:
            for d in sorted(os.listdir(ROOT)) if os.path.isdir(ROOT) else []:
                p = _ledger_path(d)
                if os.path.exists(p):
                    n = sum(1 for _ in open(p))
                    print(f"{d}: {n} receipts")
    else:
        print(f"unknown command: {cmd}")
        sys.exit(2)
