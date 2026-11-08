#!/usr/bin/env python3
"""okf_outbox — durable delivery queue for relay publishes.

Public relays 503 under load; a scan must not lose its attestation because
damus was busy. Every failed publish is written here and a timer retries it with
exponential backoff. Nothing is dropped silently: a row is either `sent`, or
still `pending` with an attempt count and the last error.

Schema: one row per (relay, event id). An event already sent to a relay is never
re-sent (relays treat duplicates as no-ops, but we don't want the traffic).

    python3 okf_outbox.py enqueue <event.json> --relay URL
    python3 okf_outbox.py drain [--limit 20]
    python3 okf_outbox.py status
    python3 okf_outbox.py list [--limit 20]
"""
import argparse
import asyncio
import json
import os
import sqlite3
import sys
import time

sys.path.append("/opt/agent-voice-venv/lib/python3.12/site-packages")
sys.path.append("/opt/ares")

DB = os.environ.get("OKF_OUTBOX_DB", "/opt/ares/okf_outbox.db")
BASE_BACKOFF = float(os.environ.get("OKF_OUTBOX_BACKOFF", "30"))
MAX_BACKOFF = float(os.environ.get("OKF_OUTBOX_MAX_BACKOFF", "3600"))


def conn():
    c = sqlite3.connect(DB, timeout=15)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("""
        CREATE TABLE IF NOT EXISTS outbox (
            relay       TEXT NOT NULL,
            event_id    TEXT NOT NULL,
            event_json  TEXT NOT NULL,
            attempts    INTEGER NOT NULL DEFAULT 0,
            next_at     REAL NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            last_error  TEXT,
            created_at  REAL NOT NULL,
            sent_at     REAL,
            PRIMARY KEY (relay, event_id)
        )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_due ON outbox(status, next_at)")
    return c


def enqueue(event, relay, error=None):
    c = conn()
    try:
        c.execute(
            "INSERT OR IGNORE INTO outbox (relay, event_id, event_json, next_at,"
            " status, last_error, created_at) VALUES (?,?,?,?,'pending',?,?)",
            (relay, event["id"], json.dumps(event, separators=(",", ":")),
             time.time(), error, time.time()))
        c.commit()
        return {"queued": True, "relay": relay, "event_id": event["id"]}
    finally:
        c.close()


def due(limit=20):
    c = conn()
    try:
        return c.execute(
            "SELECT relay, event_id, event_json, attempts FROM outbox"
            " WHERE status='pending' AND next_at <= ? ORDER BY next_at LIMIT ?",
            (time.time(), limit)).fetchall()
    finally:
        c.close()


def mark(relay, event_id, ok, error=None, attempts=0):
    c = conn()
    try:
        if ok:
            c.execute("UPDATE outbox SET status='sent', sent_at=?, last_error=NULL"
                      " WHERE relay=? AND event_id=?", (time.time(), relay, event_id))
        else:
            n = attempts + 1
            delay = min(BASE_BACKOFF * (2 ** (n - 1)), MAX_BACKOFF)
            c.execute("UPDATE outbox SET attempts=?, next_at=?, last_error=?"
                      " WHERE relay=? AND event_id=?",
                      (n, time.time() + delay, str(error)[:300], relay, event_id))
        c.commit()
    finally:
        c.close()


async def drain(limit=20):
    import okf_anchor
    rows = due(limit)
    out = []
    for relay, eid, ej, attempts in rows:
        ev = json.loads(ej)
        try:
            res = await okf_anchor.publish(ev, relay)
            ok = bool(res.get("ok"))
            mark(relay, eid, ok, res.get("message") if not ok else None, attempts)
            out.append({"relay": relay, "event_id": eid, "ok": ok,
                        "attempt": attempts + 1})
        except Exception as e:  # noqa: BLE001
            mark(relay, eid, False, e, attempts)
            out.append({"relay": relay, "event_id": eid, "ok": False,
                        "attempt": attempts + 1, "error": str(e)[:160]})
    return out


def status():
    c = conn()
    try:
        rows = c.execute("SELECT status, count(*) FROM outbox GROUP BY status").fetchall()
        pend = c.execute("SELECT count(*) FROM outbox WHERE status='pending'"
                         " AND next_at <= ?", (time.time(),)).fetchone()[0]
        oldest = c.execute("SELECT min(created_at) FROM outbox WHERE status='pending'"
                           ).fetchone()[0]
        return {"by_status": dict(rows), "due_now": pend,
                "oldest_pending_age_s": int(time.time() - oldest) if oldest else 0}
    finally:
        c.close()


def listing(limit=20):
    c = conn()
    try:
        return [dict(zip(("relay", "event_id", "status", "attempts", "last_error",
                          "next_in_s"),
                         (r[0], r[1][:16], r[2], r[3], (r[4] or "")[:80],
                          int(r[5] - time.time()))))
                for r in c.execute(
                    "SELECT relay, event_id, status, attempts, last_error, next_at"
                    " FROM outbox ORDER BY created_at DESC LIMIT ?", (limit,))]
    finally:
        c.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["enqueue", "drain", "status", "list"])
    ap.add_argument("arg", nargs="?")
    ap.add_argument("--relay", default=None)
    ap.add_argument("--limit", type=int, default=20)
    a = ap.parse_args()

    if a.cmd == "enqueue":
        ev = json.load(open(a.arg))
        print(json.dumps(enqueue(ev, a.relay), indent=2))
    elif a.cmd == "drain":
        res = asyncio.run(drain(a.limit))
        print(json.dumps({"drained": len(res), "ok": sum(1 for r in res if r["ok"]),
                          "results": res, "status": status()}, indent=2))
    elif a.cmd == "status":
        print(json.dumps(status(), indent=2))
    else:
        print(json.dumps(listing(a.limit), indent=2))


if __name__ == "__main__":
    main()
