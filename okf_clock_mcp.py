#!/usr/bin/env python3
"""okf_clock_mcp — the Bitcoin-rooted clock as an MCP tool for agents.

Speaks MCP over stdio (JSON-RPC 2.0, newline-delimited). Two tools:

    btc_now      → verified time as an interval, with the proof that bounds it
    btc_verify   → check that an artifact's timestamp is inside the verified chain

Design rules that matter more than the protocol:

  * `btc_now` returns a *window*, never a bare second. An agent that stamps a
    result with a single wall-clock number is asserting precision it did not
    purchase; the interval is what the consensus rules actually bound.
  * The `verdict` field is the gate. `verified_rooted` means the chain was
    proof-of-work verified locally and matched an external root; anything else
    and the agent should say "time unverified" rather than invent one.
  * No network call is made by this process beyond the clock module's own, and
    the answer is identical to `okf_now.py`, so a human tool and an agent tool
    can never disagree about what time it is.

Run:  okf_clock_mcp.py            (stdio; an MCP client spawns it)
Test: echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | okf_clock_mcp.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
PY = "/opt/ares/venv/bin/python"
NOW = os.path.join(HERE, "okf_now.py")
PROTOCOL = "2024-11-05"

TOOLS = [
    {
        "name": "btc_now",
        "description": ("Current time tied to Bitcoin: an interval bounded by "
                        "locally verified proof-of-work headers, plus the chain "
                        "depth and external root that back it. Returns "
                        "verdict=verified_rooted when safe to stamp."),
        "inputSchema": {"type": "object", "properties": {
            "force": {"type": "boolean",
                      "description": "bypass the 45s cache and re-verify"}},
            "require": {"type": "string", "enum": ["verified", "rooted"],
                        "description": "bar the clock must meet; default rooted"}},
    },
    {
        "name": "btc_verify",
        "description": ("Verify an artifact's Bitcoin timestamp against the "
                        "locally verified chain: an OTS proof (.ots), a "
                        "time-attestation, or a receipt."),
        "inputSchema": {"type": "object", "required": ["artifact"],
                        "properties": {"artifact": {"type": "string"}}},
    },
    {
        "name": "btc_height",
        "description": "Verified block height + root status only (cheap poll).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _run_now(force=False):
    cmd = [PY, NOW]
    if force:
        cmd.append("--force")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    try:
        return json.loads(r.stdout), r.returncode
    except Exception:  # noqa: BLE001
        return {"ok": False, "verdict": "unverified",
                "error": (r.stderr or r.stdout or "no output")[:300]}, 1


def _call(name, args):
    if name == "btc_now":
        d, rc = _run_now(bool(args.get("force")))
        out = {"clock": d, "exit_code": rc,
               "stamp_rule": ("record window.lo .. window.hi; never a bare "
                              "wall-clock second")}
        return out
    if name == "btc_height":
        d, _ = _run_now(False)
        return {"height": (d.get("block") or {}).get("height"),
                "hash": (d.get("block") or {}).get("hash"),
                "verified": d.get("ok"),
                "rooted": (d.get("root") or {}).get("rooted"),
                "depth": (d.get("chain") or {}).get("depth"),
                "verdict": d.get("verdict")}
    if name == "btc_verify":
        art = args.get("artifact")
        if not art:
            raise ValueError("artifact is required")
        r = subprocess.run([PY, NOW, "--verify", art],
                           capture_output=True, text=True, timeout=180)
        try:
            return json.loads(r.stdout)
        except Exception:  # noqa: BLE001
            return {"ok": False, "problems": [(r.stderr or r.stdout)[:300]]}
    raise ValueError(f"unknown tool: {name}")


def _reply(msg_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()


def _error(msg_id, code, message):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id,
                                 "error": {"code": code, "message": message}}) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            client = (msg.get("params") or {}).get("protocolVersion") or PROTOCOL
            _reply(mid, {"protocolVersion": client,
                         "capabilities": {"tools": {"listChanged": False}},
                         "serverInfo": {"name": "okf-clock",
                                        "version": "1.0.0"}})
        elif method in ("notifications/initialized", "initialized"):
            continue
        elif method == "tools/list":
            _reply(mid, {"tools": TOOLS})
        elif method == "tools/call":
            p = msg.get("params") or {}
            name = p.get("name")
            try:
                out = _call(name, p.get("arguments") or {})
                _reply(mid, {"content": [{"type": "text",
                                          "text": json.dumps(out, indent=2)}],
                             "isError": False})
            except Exception as e:  # noqa: BLE001
                _error(mid, -32603, str(e)[:300])
        elif method == "ping":
            _reply(mid, {})
        elif mid is not None:
            _error(mid, -32601, f"method not found: {method}")


if __name__ == "__main__":
    main()
