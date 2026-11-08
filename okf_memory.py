#!/usr/bin/env python3
"""
okf_memory — cross-scan finding memory (pattern lifted from Memora's per-agent
JSONL episodic memory: append-only records, recall before planning).

Why this exists: the OKF pipeline v4 could tell you what a scan found, never
what CHANGED since the last scan. Without that, every run re-reports the same
SQLi as if it were news, regressions (fix that never happened) are invisible,
and an agent cannot learn from its own history.

Contract (same shape as Memora agents/mcp-server/src/core/memory.ts):
    {"ts": ISO8601, "kind": str, "content": str, "tags": [str]}

Namespaces are one file per repo: <root>/<repo>.jsonl.
Fingerprint = sha256(class|endpoint|param|normalized-title) so the same bug
seen from different scanners collapses to one identity.

CLI:
    python3 okf_memory.py active <repo>
    python3 okf_memory.py timeline <repo> [limit]
    python3 okf_memory.py forget <repo> <fingerprint>
"""
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

ROOT = os.environ.get("OKF_MEMORY_ROOT", "/opt/ares/security_memory")
NS_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
STOP = {"the", "a", "an", "in", "of", "via", "and", "to", "on", "for", "with", "is", "are"}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _file(ns):
    if not NS_RE.match(ns):
        raise ValueError(f"invalid memory namespace: {ns!r}")
    return os.path.join(ROOT, f"{ns}.jsonl")


def remember(ns, kind, content, tags=None):
    """Append one immutable record. Never rewrites history."""
    rec = {"ts": _now(), "kind": kind, "content": content, "tags": list(tags or [])}
    os.makedirs(ROOT, exist_ok=True)
    with open(_file(ns), "a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def recall(ns, kind=None, query=None, limit=200):
    """Newest-first records, filtered. Returns [] when the namespace is new."""
    try:
        raw = open(_file(ns)).read()
    except FileNotFoundError:
        return []
    q = (query or "").lower()
    out = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if kind and r.get("kind") != kind:
            continue
        if q and q not in r.get("content", "").lower() and \
                not any(q in t.lower() for t in r.get("tags", [])):
            continue
        out.append(r)
    return out[::-1][:limit]


def fingerprint(finding, tool=""):
    """Stable identity for a finding across scans and across scanners."""
    title = (finding.get("title") or "").lower()
    words = [w for w in re.findall(r"[a-z0-9]+", title) if w not in STOP and len(w) > 2]
    cls = (finding.get("finding_class") or finding.get("class") or "").lower()
    if not cls:
        for k in ("sql injection", "sqli", "ssti", "template injection", "xss",
                  "cross-site scripting", "command injection", "rce", "ssrf",
                  "path traversal", "secret", "idor"):
            if k in title:
                cls = k.replace(" ", "-")
                break
    endpoint = (finding.get("endpoint") or finding.get("url") or "").split("?")[0]
    param = ""
    m = re.search(r"[?&]([a-z0-9_]+)=", finding.get("url") or finding.get("endpoint") or "")
    if m:
        param = m.group(1)
    else:
        m = re.search(r"`?([a-z_][a-z0-9_]*)`?\s+(?:query\s+)?parameter", title, re.I)
        if m:
            param = m.group(1).lower()
    key = "|".join([tool or finding.get("source", ""), cls, endpoint.lower(), param,
                    "".join(words[:4])])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def active(ns):
    """Current live findings: latest record per fingerprint decides."""
    state = {}
    for r in reversed(recall(ns, limit=100000)):  # oldest -> newest
        fp = next((t.split(":", 1)[1] for t in (r.get("tags") or [])
                   if t.startswith("fp:")), None)
        if not fp:
            continue
        info = {}
        try:
            info = json.loads(r.get("content", "") or "{}")
        except json.JSONDecodeError:
            info = {"title": (r.get("content") or "")[:160]}
        state[fp] = {"fp": fp, "kind": r["kind"],
                     "title": info.get("title", ""),
                     "endpoint": info.get("endpoint", ""),
                     "severity": info.get("severity", ""),
                     "run": info.get("run") or r["ts"],
                     "ts": r["ts"], "tags": r.get("tags", [])}
    return {fp: v for fp, v in state.items() if v["kind"] == "finding"}


def record_run(ns, findings, run_ts=None, source="okf-pipeline-v4"):
    """Persist this run and diff it against the last known state.

    Returns {new, persisting, resolved, counts} — the regression ledger.
    """
    run_ts = run_ts or _now()
    prior = active(ns)
    seen = {}
    for f in findings:
        fp = fingerprint(f, tool=f.get("tool") or f.get("source", ""))
        seen[fp] = f

    new = [fp for fp in seen if fp not in prior]
    persisting = [fp for fp in seen if fp in prior]
    resolved = [fp for fp in prior if fp not in seen]

    for fp, f in seen.items():
        remember(ns, "finding", json.dumps({
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "endpoint": f.get("endpoint") or f.get("url", ""),
            "cvss": f.get("cvss"),
            "evidence": f.get("evidence", ""),
            "run": run_ts,
        }, sort_keys=True),
            tags=[f"fp:{fp}", f"run:{run_ts}", f"src:{source}", f"sev:{f.get('severity','')}"])
    for fp in resolved:
        remember(ns, "resolution", json.dumps({"reason": "not seen in scan", "run": run_ts}),
                 tags=[f"fp:{fp}", f"run:{run_ts}", "resolved"])

    return {
        "new": [{"fp": fp, "title": seen[fp].get("title", "")} for fp in new],
        "persisting": [{"fp": fp, "title": seen[fp].get("title", ""),
                        "first_seen": prior[fp]["run"], "severity": prior[fp]["severity"]}
                       for fp in persisting],
        "resolved": [{"fp": fp, "title": prior[fp]["title"],
                      "last_seen": prior[fp]["run"]} for fp in resolved],
        "counts": {"new": len(new), "persisting": len(persisting),
                   "resolved": len(resolved), "active": len(seen),
                   "age_of_oldest_active": min((prior[fp]["run"] for fp in persisting),
                                               default=None)},
        "run": run_ts,
    }


def timeline(ns, limit=20):
    return recall(ns, limit=limit)


def forget(ns, fp):
    remember(ns, "resolution", json.dumps({"reason": "manual", "fp": fp}),
             tags=[f"fp:{fp}", "resolved", "manual"])
    return {"forgot": fp}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__.split("CLI:")[1].strip())
        sys.exit(1)
    cmd, ns = sys.argv[1], sys.argv[2]
    if cmd == "active":
        print(json.dumps(list(active(ns).values()), indent=2))
    elif cmd == "timeline":
        lim = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        for r in timeline(ns, lim):
            print(f"{r['ts']}  {r['kind']:<10} {r['content'][:120]}")
    elif cmd == "forget":
        print(json.dumps(forget(ns, sys.argv[3]), indent=2))
    else:
        print(f"unknown command: {cmd}")
        sys.exit(2)
