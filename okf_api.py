#!/usr/bin/env python3
"""OKF receipt API — the door the other agents knock on.

bot-hq's bots and pentest-copilot's tool loop are Node processes; neither can
import a Python module. So the proof layer needs a network seam. This is it, and
it is deliberately narrow:

  POST /receipt          hash an evidence directory into a chained, signed receipt
  POST /verify           check a receipt: body, signature, merkle root, files, chain
  GET  /health           root, tool count, whether a token is required
  GET  /receipts/{repo}  the last few links of a repo's chain

What it refuses, because the CLI refuses the same things:

  * an evidence_dir outside OKF_EVIDENCE_ROOT          (traversal)
  * a repo that is not a slug                          (path injection)
  * a tool absent from tool_manifests.json             (manifest gate)

That last one matters most: an API that accepts any tool name would become a
bypass of the gate that makes the pipeline trustworthy. The gate applies here
exactly as it applies to strix_pipeline_v4.py.

Binds 127.0.0.1 only. Set OKF_API_TOKEN to also require a bearer token.
"""
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import okf_receipt  # noqa: E402

EVIDENCE_ROOT = Path(os.environ.get("OKF_EVIDENCE_ROOT", "/opt/ares/security_reports")).resolve()
RECEIPTS_ROOT = Path(okf_receipt.ROOT).resolve()
TOKEN = os.environ.get("OKF_API_TOKEN", "")
REPO_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

with open(os.path.join(HERE, "tool_manifests.json")) as fh:
    _MANIFEST = json.load(fh)
TOOLS = {t.get("name") for t in _MANIFEST.get("tools", []) if t.get("name")}

app = FastAPI(title="OKF receipt API", version="1.0", docs_url=None, redoc_url=None)


def _auth(authorization: str) -> None:
    if TOKEN and authorization != f"Bearer {TOKEN}":
        raise HTTPException(401, "bearer token required")


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


class ReceiptRequest(BaseModel):
    evidence_dir: str
    repo: str
    target: str = ""
    findings: list[Any] = []
    run_meta: dict[str, Any] = {}


class VerifyRequest(BaseModel):
    path: str
    check_files: bool = True


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "evidence_root": str(EVIDENCE_ROOT),
        "receipts_root": str(RECEIPTS_ROOT),
        "tools": len(TOOLS),
        "auth_required": bool(TOKEN),
    }


@app.post("/receipt")
def make_receipt(req: ReceiptRequest, authorization: str = Header(default="")) -> dict[str, Any]:
    _auth(authorization)

    if not REPO_RE.match(req.repo):
        raise HTTPException(400, "repo must match ^[a-z0-9][a-z0-9._-]{0,63}$")

    evidence = Path(req.evidence_dir).resolve()
    if not evidence.is_dir():
        raise HTTPException(400, f"evidence_dir is not a directory: {evidence}")
    if not _under(evidence, EVIDENCE_ROOT):
        raise HTTPException(403, f"evidence_dir must be under {EVIDENCE_ROOT}")

    tool: Optional[str] = (req.run_meta or {}).get("tool")
    if tool and tool not in TOOLS:
        raise HTTPException(403, f"tool '{tool}' is not in the manifest gate ({len(TOOLS)} allowed)")
    if not tool:
        raise HTTPException(400, "run_meta.tool is required — an unattributed receipt proves nothing")

    try:
        result = okf_receipt.emit(
            str(evidence), req.repo, req.findings, req.target, req.run_meta
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"emit failed: {exc}") from exc

    result["verify"] = okf_receipt.verify(result["path"], False)
    return result


@app.post("/verify")
def verify_receipt(req: VerifyRequest, authorization: str = Header(default="")) -> dict[str, Any]:
    _auth(authorization)
    path = Path(req.path).resolve()
    if not path.is_file():
        raise HTTPException(404, f"no such receipt: {path}")
    if not _under(path, RECEIPTS_ROOT):
        raise HTTPException(403, f"receipt must live under {RECEIPTS_ROOT}")
    return okf_receipt.verify(str(path), req.check_files)


@app.get("/receipts/{repo}")
def chain(repo: str, limit: int = 10, authorization: str = Header(default="")) -> dict[str, Any]:
    _auth(authorization)
    if not REPO_RE.match(repo):
        raise HTTPException(400, "repo must be a slug")
    ledger = RECEIPTS_ROOT / repo / "ledger.jsonl"
    if not ledger.is_file():
        raise HTTPException(404, "no ledger for that repo")
    lines = [json.loads(x) for x in ledger.read_text().splitlines() if x.strip()]
    return {"repo": repo, "count": len(lines), "tail": lines[-max(1, min(limit, 200)):]}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("OKF_API_PORT", "8795")))
