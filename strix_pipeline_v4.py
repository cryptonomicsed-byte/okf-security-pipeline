#!/usr/bin/env python3
"""
Sovereign OKF Pipeline v4 — routing-correct, proof-backed.

Why v4 exists (v3 defects, each verified on this box 2026-11-07):
  1. v3 ran every tool through oniux (Arti netns). Arti has no route to the host
     loopback, so against a local/lab target every request returned 000 and all
     dynamic stages silently scored 0. Fix: stealth only for public targets.
  2. v3 used STRIX_LLM=openai/nvidia-mistral-large — a reasoning model that
     returns content=null with finish_reason=length, stalling the agent loop
     (run test-vuln-app-v3_3090 ended status='running', 4 agents unfinished,
     SARIF results=[]). Fix: gemini-flash-lite (verified live on :8300).
  3. v3 read the newest dir under strix_runs/ no matter which target produced it
     -> stale empty SARIF shadowed real findings. Fix: -r <run_name> and read
     only that run; prefer vulnerabilities.json over findings.sarif.
  4. v3 passed the bare base URL to sqlmap/SSTImap/XSStrike. On a base URL with
     no parameter sqlmap finds nothing. Fix: derive (path, param) from the
     finding text and hit the real endpoint.
  5. v3 called `auxiliary/scanner/http/sql|xss`. Those modules do not exist in
     Metasploit; the stage always reported "no exploit". Fix: fingerprint with
     auxiliary/scanner/http/http_version, then match a product-specific module
     by server banner. Generic class confirmation belongs to sqlmap/SSTImap.
  6. v3 printed "Posted to Vantage: ?" and moved on. Fix: assert broadcast_id.

Usage:
  python3 strix_pipeline_v4.py <repo_url> [repo_name] --target-url http://127.0.0.1:8099
  python3 strix_pipeline_v4.py <repo_url> [repo_name] --target-url ... \
      --findings-from /opt/ares/strix/strix_runs/<run>/vulnerabilities.json
"""
import argparse
import asyncio
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

VANTAGE_URL = os.environ.get("VANTAGE_URL", "http://localhost:8001")
VANTAGE_KEY = os.environ.get("VANTAGE_KEY") or (
    open("/opt/ares/.vantage_key").read().strip()
    if os.path.exists("/opt/ares/.vantage_key") else "")
DB_PATH = "/opt/ares/Vantage/data/vantage.db"
SCAN_DIR = "/tmp/strix-pipeline"

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_name(name):
    """Slug a repo name so it cannot address a path outside SCAN_DIR.

    repo_name is a positional argument. It used to be interpolated straight
    into `rm -rf {SCAN_DIR}/{repo_name}`, so a name like "../../etc/x" deleted
    outside the scan directory. A name is a label, not a path.
    """
    raw = (name or "").strip().rstrip("/")
    base = os.path.basename(raw)
    slug = _SAFE_NAME.sub("-", base).strip("-.")
    if not slug or slug in (".", ".."):
        raise ValueError(f"unsafe repo name: {name!r}")
    return slug[:80]


def _scan_target(repo_name):
    """Absolute clone path for a repo name, asserted to sit inside SCAN_DIR."""
    base = os.path.abspath(SCAN_DIR)
    target = os.path.abspath(os.path.join(base, _safe_name(repo_name)))
    if os.path.commonpath([target, base]) != base or target == base:
        raise ValueError(f"refusing target outside {base}: {target}")
    return target
EVIDENCE_ROOT = Path("/opt/ares/security_reports")
STRIX_RUNS = Path("/opt/ares/strix/strix_runs")
STRIX_BIN = "/opt/ares/strix-venv/bin/strix"
# free-pool 400s on Strix's tool schemas (provider "oneOf" rejection, no fallback
# group), so Strix uses the single free model that completed a full scan.
STRIX_MODEL = os.environ.get("STRIX_MODEL", "strix-paid")  # DeepSeek (only this call site); falls back to free models
STRIX_RC = None  # set by run_strix(); a failed agent must not report complete
LLM_BASE = os.environ.get("LLM_API_BASE", "http://localhost:8300/v1")
VENV_PY = "/opt/ares/venv/bin/python"
ONIUX_BIN = None if os.environ.get("DISABLE_ONIUX") else (
    shutil.which("oniux")
    or ("/root/.cargo/bin/oniux" if os.path.exists("/root/.cargo/bin/oniux") else None))


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cmd, timeout=300, env_extra=None, cwd=None, stdin=None):
    env = os.environ.copy()
    env.setdefault("TMPDIR", "/root")
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env, cwd=cwd, input=stdin)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        out = ""
        for s in (e.stdout, e.stderr):
            if isinstance(s, str):
                out += s
        return 124, out + f"\n[TIMEOUT {timeout}s]"
    except Exception as e:  # noqa: BLE001
        return 1, f"[EXEC ERROR] {e}"


def classify_target(url):
    host = urllib.parse.urlparse(url).hostname or ""
    if host in ("localhost", "::1") or host.startswith("127."):
        return "local"
    if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)", host) \
            or host.endswith(".local"):
        return "private"
    return "public"


def wrap(cmd, tclass):
    """Tor isolation only when the target is reachable through it."""
    return ([ONIUX_BIN] + cmd) if (ONIUX_BIN and tclass == "public") else cmd


def domain_of(url):
    u = urllib.parse.urlparse(url)
    return u.hostname or "", u.port or (443 if u.scheme == "https" else 80), u.scheme


# ── stage 0: secrets ───────────────────────────────────────────────────────
def run_betterleaks(path):
    """Secret scan. Ask for machine-readable output: the pretty printer changed
    glyphs between versions, and counting box-drawing characters silently
    returned 0 findings on a repo with four planted leaks."""
    print(f"\n  betterleaks: {path}")
    rc, out = run(["docker", "run", "--rm", "-v", f"{path}:/repo:ro",
                   "ghcr.io/betterleaks/betterleaks:latest", "dir", "/repo",
                   "-f", "json", "-r", "-"], 180)
    leaks = []
    if "[" in out and "]" in out:
        try:
            leaks = json.loads(out[out.index("["):out.rindex("]") + 1])
        except Exception:  # noqa: BLE001
            leaks = []
    if not isinstance(leaks, list):
        leaks = []
    # Never persist the secret itself — only enough to locate and triage it.
    slim = []
    for l in leaks[:50]:
        m = str(l.get("Match") or "")
        slim.append({"rule": l.get("RuleID") or l.get("Description"),
                     "file": l.get("File"), "line": l.get("StartLine"),
                     "match_prefix": (m[:3] + "…") if m else ""})
    # betterleaks exits 1 when it finds leaks (CI convention), not on error.
    hits = len(slim)
    print(f"  betterleaks: {hits} leaks (rc={rc})")
    for s in slim[:6]:
        print(f"    {s['rule']} · {s['file']}:{s['line']} · {s['match_prefix']}")
    return {"hits": hits, "rc": rc, "leaks": slim}, out


# ── stage 1: Strix ─────────────────────────────────────────────────────────
def run_strix(path, run_name, mode, timeout):
    print(f"\n{'='*64}\n  STRIX {mode} · model={STRIX_MODEL}\n{'='*64}")
    env = {"STRIX_LLM": f"openai/{STRIX_MODEL}",
           "LLM_API_KEY": open("/opt/ares/.litellm_key").read().strip(),
           "LLM_API_BASE": LLM_BASE, "TMPDIR": "/root"}
    # NOTE: `-r/--resume` resumes a prior run; it is NOT a run-name flag.
    # Scope the result by snapshotting strix_runs/ before and after the scan.
    before = set(STRIX_RUNS.iterdir()) if STRIX_RUNS.exists() else set()
    t0 = time.time()
    rc, out = run([STRIX_BIN, "-n", "--target", path, "--scan-mode", mode],
                  timeout, env, cwd="/opt/ares/strix")
    dur = int(time.time() - t0)
    print(f"  exit={rc} elapsed={dur}s")
    global STRIX_RC
    STRIX_RC = rc

    new = [d for d in STRIX_RUNS.iterdir() if d.is_dir() and d not in before] \
        if STRIX_RUNS.exists() else []
    if not new:
        # Fallback only for dirs written DURING this scan. Taking the newest
        # matching dir regardless of time attributed a failed run to an
        # earlier run's findings.
        base = Path(path).name
        new = sorted([d for d in STRIX_RUNS.glob(f"{base}*")
                      if d.is_dir() and d.stat().st_mtime >= t0],
                     key=lambda p: p.stat().st_mtime, reverse=True)[:1]
    if not new:
        print(f"  ⚠️ no new run dir under {STRIX_RUNS}")
        return [], out, None, dur
    run_dir = sorted(new, key=lambda p: p.stat().st_mtime, reverse=True)[0]
    print(f"  run_dir={run_dir}")

    findings = []
    vj = run_dir / "vulnerabilities.json"
    if vj.exists():
        try:
            for v in json.load(open(vj)):
                if (v.get("severity") or "").lower() in ("none", "informational"):
                    continue
                findings.append({
                    "title": v.get("title", "Finding"),
                    "severity": (v.get("severity") or "unknown").lower(),
                    "description": v.get("description", ""),
                    "poc": v.get("poc_description", ""),
                    "target": v.get("target", ""),
                    "endpoint": v.get("endpoint", ""),
                    "method": v.get("method", ""),
                    "cvss": v.get("cvss"),
                    "finding_class": v.get("finding_class", ""),
                    "source": "vulnerabilities.json",
                })
        except Exception as e:  # noqa: BLE001
            print(f"  ⚠️ vulnerabilities.json: {e}")

    # SARIF repeats the same findings (and labels some as "error" severity).
    # Use it only when vulnerabilities.json produced nothing, so nothing is counted twice.
    sarif = run_dir / "findings.sarif"
    if sarif.exists() and not findings:
        try:
            data = json.load(open(sarif))
            for r in data.get("runs", []):
                for res in r.get("results", []):
                    msg = res.get("message", {}).get("text", "")
                    # Strix emits a "not applicable" summary note per clean target;
                    # notes are not findings.
                    if res.get("level") not in ("error", "warning") or \
                            msg.lower().startswith(("not applicable", "application source code review")):
                        continue
                    findings.append({
                        "title": (msg.split(".")[0][:160] or "Finding"),
                        "severity": res.get("level", "unknown"),
                        "description": msg, "poc": "", "target": "",
                        "source": "findings.sarif"})
                for inv in r.get("invocations", []):
                    for n in inv.get("toolExecutionNotifications", []):
                        if n.get("level") in ("warning", "error"):
                            print(f"  strix: {n.get('message', {}).get('text', '')[:150]}")
        except Exception as e:  # noqa: BLE001
            print(f"  ⚠️ sarif: {e}")

    print(f"  findings={len(findings)}")
    for f in findings:
        print(f"    - [{f['severity']}] {f['title'][:110]}")
    return findings, out, str(run_dir), dur


# ── endpoint derivation ────────────────────────────────────────────────────
PATH_RE = re.compile(r"(?:GET|POST|PUT|DELETE|PATCH)\s+(/[A-Za-z0-9_\-./{}]*)")
PARAM_RE = re.compile(r"`?([A-Za-z_][A-Za-z0-9_]*)`?\s+(?:query\s+)?parameter", re.I)


def extract_endpoints(findings, base_url):
    """Turn findings into concrete URLs. Strix ships structured endpoint/method
    fields — prefer them over regexing prose."""
    base = base_url.rstrip("/")
    eps = []
    for f in findings:
        text = " ".join(str(f.get(k, "")) for k in ("title", "description", "poc"))
        params = PARAM_RE.findall(text)
        param = params[0] if params else None
        paths = []
        ep = (f.get("endpoint") or "").strip()
        if ep.startswith("/"):
            paths.append(ep)
        paths += PATH_RE.findall(text)
        if not paths:
            paths = [m for m in re.findall(r"(/[A-Za-z][A-Za-z0-9_\-/]{1,40})", text)
                     if not m.startswith("//")]
        for p in dict.fromkeys(paths):
            url = f"{base}{p}?{param}=1" if param else f"{base}{p}"
            if url not in eps:
                eps.append(url)
    return eps


# ── stage 2: sqlmap with dump proof ────────────────────────────────────────
def tables_from_sqlmap(out):
    """Table names from a sqlmap `--tables` run.

    SQLite prints `[INFO] fetching tables for database: 'SQLite_masterdb'`
    followed by `<current>`, a count line and the bordered block — not a
    `Database:` header like MySQL, so anchor on either.
    """
    lines = out.splitlines()
    start = None
    for i, ln in enumerate(lines):
        s = ln.strip().lower()
        if "fetching tables for database" in s or s.startswith("database:"):
            start = i
    if start is None:
        return []
    tabs = []
    for ln in lines[start:]:
        s = ln.strip()
        if s.startswith("|") and s.count("|") >= 2:
            name = s.strip("|").strip()
            if name and not set(name) <= set("-+ "):
                tabs.append(name)
        elif tabs and (s.startswith("[") or s.lower().startswith("fetched")):
            break
    return [t for t in dict.fromkeys(tabs) if t.lower() not in ("table", "tables")]


_NOT_PARAMS = {"sql", "post", "get", "json", "the", "and", "of", "to", "in",
               "body", "form", "request", "application", "content", "type",
               "http", "https", "http", "payload", "value", "data"}


def _post_param_candidates(f):
    """Parameter names for a POST sink, most specific first.

    Strix names the sink in prose ("sku JSON field", "sort parameter"). The
    old single regex only understood "<word> parameter" and otherwise fell
    back to "id". On /orders/by-sku that sent {"id": "1"}, whose handler does
    body.get("sku", "alpha") -- the default sku ran, every response was the
    same benign row, and a real injection read as "not injectable".
    """
    blobs = " ".join(str(f.get(k) or "") for k in
                     ("title", "description", "technical_analysis"))
    def _collect(pat, lower_only=False):
        out = []
        for m in re.finditer(pat, blobs, re.I):
            name = m.group(1)
            if len(name) > 40 or name.lower() in _NOT_PARAMS or name in out:
                continue
            if lower_only and not name.islower():
                continue          # "startLineNumber" is code, not a request field
            out.append(name)
        return out

    # The prose naming ("sku JSON field", "sort parameter") is authoritative.
    # Only fall through to code-snippet heuristics when prose names nothing.
    for pat, lower_only in ((r"\b(\w+)\s+(?:JSON\s+)?(?:parameter|field|param)\b", False),
                            (r"""["'](\w+)["']\s*:""", True),
                            (r"\b(\w+)=", True)):
        cands = _collect(pat, lower_only)
        if cands:
            return cands
    return ["id"]


def probe_post_sqlmap(findings, target_url, outdir, tclass):
    """Send the POST body a finding describes, instead of a GET query string."""
    tried = []
    for f in findings:
        if (f.get("method") or "").upper() != "POST":
            continue
        blob = f"{f.get('title', '')} {f.get('description', '')}"
        if not re.search(r"sql|inject", blob, re.I):
            continue
        # "template injection" is not SQL — it contains the word and would send
        # sqlmap at a render endpoint with a made-up parameter.
        if re.search(r"template|\bssti\b|jinja|twig|mako", blob, re.I):
            continue
        ep = f.get("endpoint") or ""
        if not ep.startswith("/"):
            continue
        url = target_url.rstrip("/") + ep
        is_json = bool(re.search(r"\bjson\b", blob, re.I))
        cands = _post_param_candidates(f)
        for param in cands[:4]:
            data = json.dumps({param: "1"}) if is_json else f"{param}=1"
            ct = "application/json" if is_json else "application/x-www-form-urlencoded"
            print(f"  POST probe: {url} · param={param} · json={is_json} "
                  f"(candidates: {', '.join(cands[:4])})")
            res, raw = run_sqlmap(url, outdir, tclass, data=data, content_type=ct)
            tried.append(param)
            if res.get("injectable"):
                # name the parameter that actually reproduced, so the receipt
                # says which request was tested rather than only that one was
                res["post_param"] = param
                res["params_tried"] = list(tried)
                return res, raw
    return ({"injectable": False, "method": "POST",
             "skipped": "no POST body injection reproduced",
             "params_tried": tried}, "")


def run_sqlmap(url, outdir, tclass, data=None, content_type=None):
    """GET by default; `data` switches sqlmap to the POST body.

    Endpoint derivation flattens POST findings into `?param=1`, which silently
    tests a different request than the one that was reported — a POST-body
    injection then reads as "not injectable". Pass the body instead.
    """
    label = f"{url} [POST {data}]" if data else url
    print(f"\n  SQLmap: {label}")
    Path(outdir).mkdir(parents=True, exist_ok=True)
    cmd = ["sqlmap", "-u", url, "--batch", "--level=3", "--risk=2",
           "--technique=BEU", "--tables", "--timeout=15",
           "--retries=1", "--flush-session", f"--output-dir={outdir}"]
    if data:
        cmd += ["--method=POST", f"--data={data}"]
        if content_type:
            cmd += [f"--headers=Content-Type: {content_type}"]
    rc, out = run(wrap(cmd, tclass), 900)
    injectable = (("Parameter: " in out and ("POST" in out or not data)) or "Type: " in out) \
        and "does not seem to be injectable" not in out
    res = {"url": url, "injectable": False, "rc": rc}
    if data:
        res.update({"method": "POST", "data_template": data})
    if not injectable:
        print(f"  SQLmap: NOT injectable (rc={rc})")
        return res, out
    dbms = re.search(r"back-end DBMS:\s*(.+)", out)
    techniques = sorted({t.strip() for t in re.findall(r"Type:\s*(.+)", out)})
    res.update({"injectable": True,
                "dbms": dbms.group(1).strip() if dbms else None,
                "techniques": techniques[:6]})
    # concrete proof: dump a real table. `--tables` already ran above, so parse
    # the names instead of assuming a table called "users" exists — that
    # assumption silently produced dump_rows=0 on any schema with other names.
    tables = tables_from_sqlmap(out)
    order = sorted(tables, key=lambda t: 0 if re.search(
        r"user|account|member|admin|cred|secret|token|item", t, re.I) else 1)
    res["tables"] = tables[:8]
    rc2, out2, dumped_table = 1, "", None
    for tbl in (order[:2] or ["users"]):
        dump_cmd = ["sqlmap", "-u", url, "--batch", "--technique=BEU",
                    "-T", tbl, "--dump", "--timeout=15",
                    f"--output-dir={outdir}"]
        if data:
            dump_cmd += ["--method=POST", f"--data={data}"]
            if content_type:
                dump_cmd += [f"--headers=Content-Type: {content_type}"]
        rc2, out2 = run(wrap(dump_cmd, tclass), 900)
        rows = [ln for ln in out2.splitlines()
                if ln.startswith("|") and not any(x in ln for x in ("___", "|_ -|", ".'|"))]
        data_rows = rows[1:] if len(rows) > 1 else []
        if data_rows:
            dumped_table = tbl
            break
    secrets = re.findall(r"(flag\{[^}]*\}|admin|[a-f0-9]{32})", out2)
    res.update({"dump_rc": rc2, "dump_rows": len(data_rows),
                "dumped_table": dumped_table,
                "sensitive_exposed": bool(secrets),
                "sample": [r.strip() for r in data_rows[:4]],
                "columns": rows[0].strip() if rows else None})
    print(f"  SQLmap: INJECTABLE · dbms={res['dbms']} · techniques={res['techniques']}")
    print(f"  SQLmap: tables={tables[:5]} · dumped {dumped_table} rows={res['dump_rows']} "
          f"sensitive={res['sensitive_exposed']}")
    for s in res["sample"]:
        print(f"    {s}")
    return res, out


# ── stage 2b: prove command injection / path traversal with canaries ───────
def prove_injection_classes(urls, budget=64):
    """Prove cmdi and traversal directly — sqlmap and SSTImap cannot see either,
    so a report can score zero on a target that is trivially root-RCE.

    Read-only probes only: `id` for cmdi, /etc/passwd for traversal. No writes,
    no reverse shells, no persistence.
    """
    import urllib.parse as up
    import urllib.request as ur
    found = {"cmdi": [], "traversal": [], "default_exec": [], "requests": 0}
    cmdi_payloads = [";id", "|id", "$(id)"]
    trav_payloads = ["../../../../etc/passwd", "..%2F..%2F..%2F..%2Fetc%2Fpasswd"]

    def fetch(u):
        try:
            req = ur.Request(u, headers={"User-Agent": "okf-proof/1"})
            with ur.urlopen(req, timeout=8) as r:
                return r.read(4000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""

    def build(parts, q, param, value):
        nq = {k: (v[0] if v else "") for k, v in q.items()}
        nq[param] = value
        return up.urlunsplit((parts.scheme, parts.netloc, parts.path,
                              up.urlencode(nq), ""))

    def cmdi_hit(body):
        m = re.search(r"uid=\d+\([^)]*\)\s+gid=\d+[^\n]*", body)
        return m.group(0) if m else None

    def trav_hit(body):
        m = re.search(r"root:x:0:0[^\n]*", body)
        return m.group(0) if m else None

    urls = list(dict.fromkeys(urls))
    with_query = [u for u in urls if "?" in u][:6]
    bare = [u for u in urls if "?" not in u]
    # A bare route named /run, /exec or /ping is far more likely to be the cmdi
    # surface than /admin or /docs, and the budget is finite — order matters,
    # otherwise the interesting route gets sliced off the end.
    hot = re.compile(r"run|exec|cmd|ping|shell|system|debug|script|tool", re.I)
    without_query = (sorted(bare, key=lambda u: 0 if hot.search(u) else 1))[:6]

    # Control: an endpoint that runs a shell command from a *default* argument
    # returns `uid=` even with no parameter added. Without this baseline the
    # prover credits every guessed parameter name with a hit it did not cause.
    def baseline(u):
        found["requests"] += 1
        ev = cmdi_hit(fetch(u))
        if ev:
            found["default_exec"].append({"url": u, "evidence": ev[:120]})
        return ev

    # A default-exec endpoint already returns uid= without any parameter, so a
    # `;id` hit proves nothing about the parameter. Distinguish with a token
    # that only appears if OUR value reached the shell.
    def echo_probe(parts, q, param, token):
        found["requests"] += 1
        body = fetch(build(parts, q, param, f"1;echo {token}"))
        return token if token in body else None

    # Phase 1 — endpoints that already declare parameters (highest signal).
    for url in with_query:
        parts = up.urlsplit(url)
        q = up.parse_qs(parts.query)
        baseline_hit = baseline(url)
        for param in list(q)[:3]:
            if baseline_hit:
                token = f"OKFCANARY{abs(hash((url, param))) % 100000}"
                if echo_probe(parts, q, param, token):
                    found["cmdi"].append({"url": url, "param": param,
                                          "payload": f"1;echo {token}",
                                          "evidence": f"canary {token} executed",
                                          "via": "echo-canary"})
            else:
                for pay in cmdi_payloads:
                    if found["requests"] >= budget:
                        return found
                    ev = cmdi_hit(fetch(build(parts, q, param, (q[param][0] or "1") + pay)))
                    found["requests"] += 1
                    if ev:
                        found["cmdi"].append({"url": url, "param": param, "payload": pay,
                                              "evidence": ev[:120]})
                        break
            for pay in trav_payloads:
                if found["requests"] >= budget:
                    return found
                ev = trav_hit(fetch(build(parts, q, param, pay)))
                found["requests"] += 1
                if ev:
                    found["traversal"].append({"url": url, "param": param, "payload": pay, "evidence": ev[:120]})
                    break

    # Phase 2 — bare routes: guess the parameter names cmdi endpoints usually take.
    for url in without_query:
        parts = up.urlsplit(url)
        default_hit = baseline(url)
        for guess in ("cmd", "exec", "ping"):
            if found["requests"] >= budget:
                return found
            q = {guess: ["1"]}
            if default_hit:
                token = f"OKFCANARY{abs(hash((url, guess))) % 100000}"
                if echo_probe(parts, q, guess, token):
                    found["cmdi"].append({"url": url, "param": guess,
                                          "payload": f"1;echo {token}",
                                          "evidence": f"canary {token} executed",
                                          "via": "echo-canary"})
                continue
            for pay in cmdi_payloads:
                if found["requests"] >= budget:
                    return found
                ev = cmdi_hit(fetch(build(parts, q, guess, "1" + pay)))
                found["requests"] += 1
                if ev:
                    found["cmdi"].append({"url": url, "param": guess, "payload": "1" + pay,
                                          "evidence": ev[:120]})
                    break
    return found


# ── stage 3: SSTImap ───────────────────────────────────────────────────────
STRONG_ENGINES = {"jinja2", "mako", "twig", "freemarker", "smarty", "velocity",
                  "django", "tornado", "handlebars", "pug", "ejs", "erb",
                  "mustache", "nunjucks"}


def probe_post_ssti(findings, target_url, tclass, max_params=3):
    """SSTI sinks that only exist in a POST body.

    The GET sweep cannot reach these: it appends `?param=1` to a route that only
    answers POST, and a real `{{7*7}}` sink then reads as "no engine".
    """
    for f in findings:
        if (f.get("method") or "").upper() != "POST":
            continue
        blob = f"{f.get('title', '')} {f.get('description', '')}"
        if not re.search(r"template|\bssti\b|jinja|twig|mako|nunjucks|mustache", blob, re.I):
            continue
        ep = f.get("endpoint") or ""
        if not ep.startswith("/"):
            continue
        url = target_url.rstrip("/") + ep
        named = re.search(r"\b(\w+)\s+parameter", blob, re.I)
        cands = ([named.group(1)] if named else []) + ["tpl", "template", "name", "input", "q", "msg"]
        seen = []
        for p in cands:
            if p in seen:
                continue
            seen.append(p)
            if len(seen) > max_params:
                break
            for dtype, payload in ((None, f"{p}=1"),
                                   ("json", json.dumps({p: "1"}))):
                res, raw = run_sstimap(url, tclass, data=payload, data_type=dtype)
                if res.get("vulnerable"):
                    res["post_param"] = p
                    res["post_data_type"] = dtype or "form"
                    return res, raw
    return ({"vulnerable": False, "skipped": "no POST-body SSTI reproduced"},
            "")


def run_sstimap(url, tclass, data=None, data_type=None):
    label = f"{url} [-d {data}]" if data else url
    print(f"\n  SSTImap: {label}")
    cmd = [VENV_PY, "/opt/ares/SSTImap/sstimap.py", "-u", url,
           "--no-color", "--level", "1"]
    if data:
        cmd += ["-d", data, "-m", "POST"]
        if data_type:
            cmd += ["--data-type", data_type]
    rc, out = run(wrap(cmd, tclass), 300)
    eng = re.search(r"Engine:\s*(\S+)", out)
    engine = eng.group(1) if eng else None
    rce = "command execution: ok" in out.lower()
    # Eval_generic fires on reflection/error echo; only a named template engine
    # (or a working RCE path) is real SSTI.
    conf = "high" if (engine or "").lower() in STRONG_ENGINES or rce else \
           ("low" if engine else None)
    res = {"url": url, "vulnerable": conf == "high", "confidence": conf,
           "engine": engine, "rce": rce, "rc": rc}
    print(f"  SSTImap: engine={engine} rce={rce} confidence={conf}")
    return res, out


# ── stage 4: XSStrike ──────────────────────────────────────────────────────
def run_xsstrike(url, tclass):
    print(f"\n  XSStrike: {url}")
    rc, out = run(wrap([VENV_PY, "/opt/ares/XSStrike/xsstrike.py", "-u", url,
                        "--skip-dom", "--console-log-level", "WARNING"], tclass), 300)
    n = out.count("[+] Vector") + out.count("Reflected") + out.count("VULN")
    print(f"  XSStrike: {n} markers (rc={rc})")
    return {"url": url, "vectors": n, "rc": rc}, out


# ── stage 4b: surface sweep (catches what the AI did not report) ────────────
PARAM_GUESSES = ("id", "name", "q", "cmd", "file")


def sweep_candidates(base_url, found_paths, limit=14):
    cands, seen = [], set()
    for u in (found_paths or []) + [base_url]:
        existing = set()
        if "?" in u:
            existing = {kv.split("=")[0] for kv in u.split("?", 1)[1].split("&") if kv}
        for p in PARAM_GUESSES:
            if p in existing:
                continue
            t = f"{u}?{p}=1" if "?" not in u else f"{u}&{p}=1"
            if t not in seen:
                seen.add(t)
                cands.append(t)
    return cands[:limit]


def sweep_dynamic(base_url, found_paths, tclass, raws, want=("sstimap", "xsstrike")):
    """Bounded param sweep over discovered paths — the AI is not the only sensor."""
    cands = sweep_candidates(base_url, found_paths)
    print(f"\n  [Sweep] {len(cands)} candidate params across "
          f"{len({u.split('?')[0] for u in cands})} paths")
    res = {"candidates": len(cands), "sstimap_hits": [], "sstimap_low": [],
           "xsstrike_hits": []}
    if "sstimap" in want:
        for u in cands:
            r, raw = run_sstimap(u, tclass)
            if r.get("confidence") == "high":
                res["sstimap_hits"].append(r)
                raws[f"sstimap_sweep_{len(res['sstimap_hits'])}"] = raw
                break
            if r.get("confidence") == "low":
                res["sstimap_low"].append({k: r[k] for k in ("url", "engine", "confidence")})
    if "xsstrike" in want:
        for u in cands[:4]:
            r, raw = run_xsstrike(u, tclass)
            if r.get("vectors"):
                res["xsstrike_hits"].append(r)
                raws[f"xsstrike_sweep_{len(res['xsstrike_hits'])}"] = raw
                break
    print(f"  [Sweep] sstimap_high={len(res['sstimap_hits'])} "
          f"sstimap_low={len(res['sstimap_low'])} xsstrike={len(res['xsstrike_hits'])}")
    return res


# ── stage 5: nmap / ffuf / nuclei (surface, not proof) ─────────────────────
def run_nmap(url, tclass):
    host, port, _ = domain_of(url)
    print(f"\n  nmap: {host}:{port}")
    if tclass == "local":
        rc, out = run(["nmap", "-sV", "--version-light", "-Pn", "-T4",
                       "--host-timeout", "90s", "-p", str(port), host], 180)
    else:
        rc, out = run(wrap(["nmap", "-sV", "-sC", "-Pn", "-T4",
                            "--version-light", "--host-timeout", "300s",
                            "--top-ports", "200", host], tclass), 600)
    svc = re.findall(r"^\d+/tcp\s+open\s+(\S+)\s*(.*)$", out, re.M)
    print(f"  nmap: {svc[:3] if svc else 'no open service lines'} (rc={rc})")
    return {"host": host, "port": port, "services": svc[:5], "rc": rc}, out


def run_ffuf(url, tclass):
    wl = next((w for w in ("/opt/ares/wordlists/common.txt",
                           "/usr/share/seclists/Discovery/Web-Content/common.txt",
                           "/usr/share/wordlists/dirb/common.txt") if os.path.exists(w)), None)
    if not wl:
        print("\n  ffuf: no wordlist")
        return {"paths": 0, "note": "no wordlist"}, ""
    print(f"\n  ffuf: {url}/FUZZ")
    found = []
    for w_list in (wl, "/opt/ares/wordlists/routes-extra.txt"):
        if not os.path.exists(w_list):
            continue
        outf = f"/tmp/ffuf_v4_{Path(w_list).stem}.json"
        if os.path.exists(outf):
            os.remove(outf)
        rc, out = run(wrap(["ffuf", "-u", url.rstrip("/") + "/FUZZ", "-w", w_list,
                            "-mc", "200,204,301,302,401,403", "-t", "30",
                            "-o", outf, "-of", "json", "-s"], tclass), 900)
        if os.path.exists(outf):
            try:
                found += [r["url"] for r in json.load(open(outf)).get("results", [])]
            except Exception:  # noqa: BLE001
                pass
    found = list(dict.fromkeys(found))
    print(f"  ffuf: {len(found)} paths")
    for p in found[:12]:
        print(f"    {p}")
    return {"paths": len(found), "found": found[:40]}, ""


def run_nuclei(url, tclass):
    print(f"\n  nuclei: {url}")
    outf = "/tmp/nuclei_v4.jsonl"
    if os.path.exists(outf):
        os.remove(outf)
    rc, out = run(wrap(["nuclei", "-u", url, "-severity", "critical,high,medium",
                        "-jsonl", "-o", outf, "-silent", "-no-interactsh"], tclass), 900)
    hits = []
    if os.path.exists(outf):
        for line in open(outf):
            try:
                d = json.loads(line)
                hits.append({"template": d.get("template-id"), "severity": d.get("info", {}).get("severity"),
                             "matched": d.get("matched-at")})
            except Exception:  # noqa: BLE001
                pass
    print(f"  nuclei: {len(hits)} hits (rc={rc})")
    return {"hits": len(hits), "findings": hits[:10], "rc": rc}, out


# ── stage 6: Metasploit, used only where it can work ───────────────────────
def run_metasploit(url, do_check=False):
    host, port, _ = domain_of(url)
    print(f"\n  Metasploit: fingerprint {host}:{port}")
    rc_file = "/tmp/msf_fp_v4.rc"
    with open(rc_file, "w") as f:
        f.write(f"use auxiliary/scanner/http/http_version\nset RHOSTS {host}\n"
                f"set RPORT {port}\nrun\nexit\n")
    rc, out = run(["msfconsole", "-q", "-r", rc_file], 300)
    server = None
    for line in out.splitlines():
        # http_version prints: [+] 127.0.0.1:8099 Werkzeug/3.0.1 Python/3.12.3
        m = re.match(r"^\[\+\]\s+\S+:\d+\s+(.+)$", line.strip())
        if m:
            server = m.group(1).strip()
            break
        if re.search(r"\bServer\b\s*:", line, re.I):
            server = line.split(":", 1)[1].strip()
            break
    res = {"server": server, "module": None, "rc": rc}
    if server:
        kw = [k for k in re.sub(r"[^A-Za-z]+", " ", server).split() if len(k) > 3][:2]
        if kw:
            rc2, out2 = run(["msfconsole", "-q", "-x", f"search name:{kw[0]}; exit"], 300)
            mods = re.findall(r"\b(?:auxiliary|exploit)/[\w/]+", out2)
            res["candidates"] = [m for m in mods if kw[0].lower() in m.lower()][:5]
    print(f"  Metasploit: server={server!r} candidates={res.get('candidates', [])}")
    if do_check and res.get("candidates"):
        mod = res["candidates"][0]
        rc_chk = "/tmp/msf_check_v4.rc"
        with open(rc_chk, "w") as f:
            f.write(f"use {mod}\nset RHOSTS {host}\nset RPORT {port}\n"
                    f"set SSL {'true' if url.startswith('https') else 'false'}\n"
                    f"check\nexit\n")
        rc3, out3 = run(["msfconsole", "-q", "-r", rc_chk], 300)
        if re.search(r"appears to be vulnerable", out3, re.I):
            res["check"] = "vulnerable"
        elif re.search(r"appears not to be vulnerable|is not exploitable", out3, re.I):
            res["check"] = "not vulnerable"
        else:
            res["check"] = "inconclusive"
        res["check_module"] = mod
        print(f"  Metasploit: check {mod} -> {res['check']}")
    print(f"  Metasploit: generic class confirmation is sqlmap/SSTImap's job — "
          f"no product-specific module means no msf claim")
    return res, out


# ── evidence + Vantage ─────────────────────────────────────────────────────
def write_evidence(repo, ts, payload, raws):
    d = EVIDENCE_ROOT / f"{repo}_{ts}"
    (d / "raw").mkdir(parents=True, exist_ok=True)
    for name, blob in raws.items():
        (d / "raw" / f"{name}.log").write_text(blob or "")
    (d / "report.json").write_text(json.dumps(payload, indent=2))
    L = [f"# Security scan — {repo}", "",
         f"- target: `{payload['target_url']}` ({payload['target_class']})",
         f"- isolation: {payload['stealth']}",
         f"- strix: {payload['strix_model']} · {payload['strix_seconds']}s · run {payload['strix_run_dir']}",
         f"- started {payload['started']} · duration {payload['duration_s']}s", "",
         "## Findings", ""]
    for f in payload["strix_findings"]:
        L += [f"### [{f['severity'].upper()}] {f['title']}", "", f["description"][:1600], ""]
        if f.get("poc"):
            L += ["Agent PoC:", "", f["poc"][:1400], ""]
    bl = payload.get("betterleaks") or {}
    L += ["## Secret scan (betterleaks)", ""]
    if bl.get("hits"):
        L += [f"- **{bl['hits']} secret leak(s) found** (values redacted)", ""]
        for s in (bl.get("leaks") or [])[:15]:
            L.append(f"  - `{s.get('rule')}` · {s.get('file')}:{s.get('line')}")
        L.append("")
    else:
        L += [f"- no leaks found (rc={bl.get('rc')})", ""]
    L += ["## Independent confirmation", ""]
    if not payload.get("target_url"):
        # A probe that never ran must not be printed as a negative result.
        L += ["- dynamic tools: **not run** — static-only scan (no `--target-url`)",
              "- absence of a hit here is not evidence of absence", ""]
    else:
        L += [f"- sqlmap: `{json.dumps(payload['sqlmap'])}`"]
        sp = payload.get("sqlmap_post") or {}
        if sp.get("injectable"):
            L.append(f"- sqlmap (POST body): `{json.dumps(sp)[:600]}`")
        elif sp.get("skipped"):
            L.append(f"- sqlmap (POST body): not reproduced — {sp['skipped']}")
        L += [f"- injection proof (cmdi/traversal): `{json.dumps(payload.get('injection'))[:500]}`",
              f"- sstimap: `{json.dumps(payload['sstimap'])}`",
              f"- xsstrike: `{json.dumps(payload['xsstrike'])}`",
              f"- nmap: `{json.dumps(payload['nmap'])}`",
              f"- ffuf: paths={payload['ffuf'].get('paths')}",
              f"- nuclei: hits={payload['nuclei'].get('hits')}",
              f"- metasploit: `{json.dumps(payload['metasploit'])}`",
              f"- sweep: `{json.dumps(payload.get('sweep', {}))[:400]}`", ""]
    (d / "report.md").write_text("\n".join(L))
    return d


def post_to_vantage(repo, payload, ev):
    sm = payload["sqlmap"]
    body = [f"**Sovereign OKF Pipeline v4 — {repo}**", "",
            f"**Target:** `{payload['target_url']}` ({payload['target_class']})",
            f"**Isolation:** {payload['stealth']}",
            f"**AI findings (Strix {payload['strix_model']}):** {len(payload['strix_findings'])}", ""]
    for f in payload["strix_findings"][:5]:
        body += [f"- **[{f['severity'].upper()}]** {f['title'][:170]}",
                 f"  {f.get('description', '')[:350]}"]
    body += [""]
    bl = payload.get("betterleaks") or {}
    if bl.get("hits"):
        names = ", ".join(f"{s.get('rule')}@{s.get('file')}:{s.get('line')}"
                          for s in (bl.get("leaks") or [])[:4])
        body.append(f"**Secrets (betterleaks):** {bl['hits']} leak(s) — {names} (values redacted)")
    else:
        body.append(f"**Secrets (betterleaks):** none found (rc={bl.get('rc')})")
    if not payload.get("target_url"):
        body.append("**Dynamic tools:** not run — static-only scan (no live target); "
                    "no injection/XSS/RCE claim is being made")
    else:
        body += [f"**sqlmap — CONFIRMED:** injectable={sm.get('injectable')} · dbms={sm.get('dbms')} · "
                 f"rows_dumped={sm.get('dump_rows')} · sensitive={sm.get('sensitive_exposed')}",
                 f"**SSTImap:** vulnerable={payload['sstimap'].get('vulnerable')} · "
                 f"engine={payload['sstimap'].get('engine')} · rce={payload['sstimap'].get('rce')}",
                 f"**nuclei:** {payload['nuclei'].get('hits')} · **ffuf:** {payload['ffuf'].get('paths')} paths",
                 f"**Metasploit:** fingerprint={payload['metasploit'].get('server')} (no product CVE claim)"]
        sp = payload.get("sqlmap_post") or {}
        if sp.get("injectable"):
            body.append(f"**sqlmap — POST body CONFIRMED:** param in `{sp.get('data_template')}` · "
                        f"dbms={sp.get('dbms')} · rows={sp.get('dump_rows')}")
        elif sp.get("skipped"):
            body.append(f"**sqlmap — POST body:** not reproduced ({sp['skipped']})")
    mem = payload.get("memory") or {}
    if "counts" in mem:
        body.append(f"**Delta since last scan:** new={mem['counts']['new']} · "
                    f"persisting={mem['counts']['persisting']} · resolved={mem['counts']['resolved']}")
    ret = payload.get("receipt") or {}
    if "receipt_id" in ret:
        _clk = (payload.get("clock") or {}).get("clock") or {}
        _chn = _clk.get("chain") or {}
        _cont = _chn.get("continuity") or {}
        _d = _cont.get("verified_depth") or {}
        if not _chn.get("ok"):
            # "not rooted" and "not verified" are different admissions. Printing
            # "verified … not rooted" for a chain that never verified claims a
            # check that did not happen — the exact failure this pipeline hunts.
            _why = ((_cont.get("error") or (_chn.get("errors") or ["?"])[0]) or "?"
                    ) if isinstance(_chn.get("errors"), list) else "?"
            body.append(f"**Clock:** UNVERIFIED — headers were not proven "
                        f"({str(_why)[:120]}). This result carries no provable "
                        f"\"when\".")
        else:
            body.append(f"**Clock:** {_clk.get('height')} verified "
                        f"({_chn.get('headers_checked')} headers)"
                        + (f" · {_clk.get('uncertainty_s')}s ± "
                           f"({time.strftime('%H:%M:%SZ', time.gmtime((_clk.get('interval') or [0, 0])[0]))}"
                           f" .. {time.strftime('%H:%M:%SZ', time.gmtime((_clk.get('interval') or [0, 0])[1]))})"
                           if _clk.get("interval") else "")
                        + (f" · depth {_d.get('count')} back to {_d.get('lowest')}" if _d else "")
                        + (f" · **rooted** ({((_cont.get('pin') or {}).get('rooted_by') or {}).get('class') or 'pin'} "
                           f"block {((_cont.get('pin') or {}).get('rooted_by') or {}).get('height') or (_cont.get('pin') or {}).get('height')})"
                           if _chn.get("rooted")
                           else " · **not rooted** (verified, but no external root)"))
        body.append(f"**Receipt:** `{ret['receipt_id'][:16]}` · chain #{ret['chain_index']} · "
                    f"merkle `{ret['merkle_root'][:16]}`")
    ev_ = payload.get("evasion") or {}
    if ev_.get("overall_flag_rate") is not None:
        gaps = [r for r in (ev_.get("weakest_first") or [])
                if r["flag_rate"] < ev_.get("thresholds", {}).get("flag", 0.6)]
        body.append(f"**Guard gap (tripwire):** {ev_['overall_flag_rate']*100:.0f}% of transforms "
                    f"flagged · {len(gaps)}/{len(ev_.get('weakest_first') or [])} bypass the detector")
    body += ["", f"**Evidence:** `{ev}`", f"**Scan:** {payload['started']}"]
    body_json = json.dumps({"title": f"🔍 Security Scan: {repo}",
                            "content": "\n".join(body),
                            "tags": ["security", "strix", "pentest", "pentest-verified"],
                            "status": "published", "content_type": "text"})
    # The backend provisions identities and can stall under load; a 30s ceiling
    # silently lost the post (broadcast_id=None) with the receipt already
    # written. Wait longer and retry once rather than lose the pointer.
    bid, resp = None, {}
    # A refused connection is usually the backend still booting (Vantage takes
    # ~15s to bind while it registers its MCP servers) — that is transient, not
    # a lost post. Retry across a window that outlasts a restart.
    for attempt, wait_s in enumerate((0, 6, 15, 30), start=1):
        if wait_s:
            print(f"  ⚠️ Vantage not reachable — retrying in {wait_s}s")
            time.sleep(wait_s)
        rc, out = run(["curl", "-s", "-X", "POST", f"{VANTAGE_URL}/api/agents/posts/text",
                       "-H", "Content-Type: application/json", "-H", f"X-Agent-Key: {VANTAGE_KEY}",
                       "-d", body_json], 90)
        try:
            resp = json.loads(out)
        except Exception:  # noqa: BLE001
            resp = {"raw": out[:300], "rc": rc}
        bid = resp.get("broadcast_id") or resp.get("id")
        if bid:
            if attempt > 1:
                print(f"  Vantage: recovered on attempt {attempt}")
            break
        # rc 7/28 = refused/timeout: retry. An HTTP error with a body is not
        # transient — stop and report it rather than hammering.
        if rc not in (7, 28) and attempt >= 2:
            break
    print(f"  Vantage: broadcast_id={bid}")
    if not bid:
        print(f"  ⚠️ Vantage post NOT confirmed: {resp}")
    return bid, resp


# ── main ───────────────────────────────────────────────────────────────────


# ── Step 8.5 (ported from v3): Decepticon deep red-team stage ──────────
# Decepticon is a separate autonomous red-team agent (16 specialist LangGraph
# graphs) running in containers on this box. This stage is OPT-IN: it is
# LLM-driven, slow, non-deterministic and spends gateway credits, so it never
# runs unless --decepticon is passed. It fails closed — no approved RoE, no
# reachable graph, no run.
def run_decepticon(target_url, graph="recon", timeout=600, base=None):
    """Dispatch one Decepticon LangGraph against target_url and return
    (findings, meta). findings is a list in the pipeline's shape; meta carries
    thread_id/run_id/status so the receipt can prove a run was actually
    dispatched, not merely claimed."""
    import urllib.request
    import urllib.error
    from urllib.parse import urlparse
    BASE = base or os.environ.get("OKF_DECEPTICON_URL", "http://127.0.0.1:2024")
    host = urlparse(target_url).hostname or target_url
    # The sandbox is a separate container network: it cannot reach the host
    # loopback. host.docker.internal is wired on the langgraph image (it is how
    # the LLM base :8300 is reached), so loopback targets are rewritten.
    scope_host = ("host.docker.internal" if host in ("127.0.0.1", "localhost", "::1")
                  else host)
    reachable = (target_url.replace(host, "host.docker.internal")
                 if host in ("127.0.0.1", "localhost", "::1") else target_url)
    meta = {"graph": graph, "target": target_url, "reachable": reachable,
            "status": "not_run", "thread_id": None, "run_id": None,
            "report_chars": 0, "roe_path": None}

    # Provision machine-readable RoE. Decepticon fails closed without it: an
    # engagement with no approved in-scope target is a refusal, not a scan.
    roe_dir = "/root/.decepticon/workspace/plan"
    try:
        os.makedirs(roe_dir, exist_ok=True)
        roe = {
            "engagement_name": f"Sovereign OKF Pipeline — {target_url}",
            "machine_enforcement": {
                "in_scope": [scope_host],
                "out_of_scope": [],
                "forbidden_destinations": [],
                "forbidden_command_patterns": [],
                "allow_cloud_metadata": False,
                "allow_sensitive_tlds": False,
                "max_concurrent_connections": 10,
                "min_inter_request_delay_ms": 0,
                "authorized_windows": [],
                "blackout_windows": [],
            },
        }
        rp = os.path.join(roe_dir, "roe.json")
        with open(rp, "w") as f:
            json.dump(roe, f, indent=2)
        meta["roe_path"] = rp
        print(f"  Decepticon: RoE in_scope={[scope_host]} -> {rp}")
    except Exception as e:  # noqa: BLE001
        meta["status"] = "error"
        meta["error"] = f"roe: {e}"
        print(f"  ⚠️ Decepticon RoE error: {e}")
        return [], meta

    def post(path, data, t=30):
        req = urllib.request.Request(
            f"{BASE}{path}", data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        return json.loads(urllib.request.urlopen(req, timeout=t).read())

    def get(path, t=30):
        return json.loads(urllib.request.urlopen(
            urllib.request.Request(f"{BASE}{path}"), timeout=t).read())

    print(f"  Decepticon: dispatching '{graph}' -> {reachable} (base={BASE})")
    try:
        thread = post("/threads", {})
        tid = thread["thread_id"]
        meta["thread_id"] = tid
        run = post(f"/threads/{tid}/runs", {
            "assistant_id": graph,
            "input": {
                "messages": [{"role": "user",
                              "content": (f"Authorized reconnaissance of {reachable}. "
                                          "Identify vulnerabilities and report concisely.")}],
                "workspace_path": "/workspace",
            },
            "config": {"configurable": {"workspace_path": "/workspace"}},
        })
        rid = run.get("run_id", "")
        meta["run_id"] = rid
        meta["status"] = "dispatched"
        print(f"  Decepticon: thread={tid} run={rid} (timeout {timeout}s)")

        deadline = time.time() + timeout
        status = "pending"
        while time.time() < deadline:
            time.sleep(5)
            try:
                runs = get(f"/threads/{tid}/runs") or []
                m = [r for r in runs if r.get("run_id") == rid]
                status = m[0].get("status", "unknown") if m else "unknown"
            except Exception:  # noqa: BLE001
                status = "unknown"
            if status in ("success", "error", "interrupted", "timeout"):
                break

        if status not in ("success", "error", "interrupted", "timeout"):
            print(f"  Decepticon: timeout after {timeout}s — cancelling")
            try:
                post(f"/threads/{tid}/runs/{rid}/cancel", {})
            except Exception:  # noqa: BLE001
                pass
            status = "timeout"
        meta["status"] = status

        content = ""
        try:
            state = get(f"/threads/{tid}/state")
            msgs = (state.get("values") or {}).get("messages", []) or []
            for m in reversed(msgs):
                if m.get("type") == "ai" and m.get("content"):
                    content = m["content"]
                    break
        except Exception as e:  # noqa: BLE001
            print(f"  ⚠️ Decepticon state read: {e}")
        meta["report_chars"] = len(content)
        print(f"  Decepticon: status={status} report={len(content)} chars")
        if content:
            return ([{
                "title": f"Decepticon {graph} report",
                "severity": "info",
                "description": content[:3000],
                "location": target_url,
                "finding_class": "decepticon",
            }], meta)
        if status != "success":
            meta["error"] = f"status={status}, no report"
        return [], meta
    except Exception as e:  # noqa: BLE001
        meta["status"] = "error"
        meta["error"] = str(e)
        print(f"  ⚠️ Decepticon error: {e}")
        return [], meta


def pipeline(repo_url, repo_name=None, target_url=None, mode="quick",
             findings_from=None, strix_timeout=2700, skip_surface=False,
             do_sweep=True, msf_check=False, do_evasion=True, do_anchor=False,
             do_ots=True, do_clock=True, sabbath_gate=False,
             do_decepticon=False, decepticon_graph="recon",
             decepticon_timeout=600):
    # Proof is the default: a receipt without an OTS proof is a claim; with one it
    # is checkable. Opt out with --no-ots, never by forgetting a flag.
    if not target_url:
        print("  (no --target-url: static-only mode — Strix + betterleaks, no dynamic proof)")
        target_url = ""
    # Doctrine §9/§12.5: refuse to run a tool that has no declared manifest.
    # This is a gate, not a warning: an undeclared action is an unreviewed one.
    import okf_tool_manifests
    import okf_profile
    okf_tool_manifests.require_coverage()
    # Doctrine §1: every agent run carries a profile — goals, skills,
    # permissions, memory namespace, lifecycle. principal stays null on
    # purpose: there is no Èṣù gatekeeper here, and the Nostr key is a
    # signing key, not an identity.
    _invoked, _unknown = okf_tool_manifests.discover()
    if do_decepticon:
        _invoked = set(_invoked) | {"decepticon"}
    prof = okf_profile.RunProfile(
        repo_name, goal=f"security receipt for {repo_name}", mode=mode,
        target_url=target_url, tools=sorted(_invoked), budget_s=strix_timeout)
    prof.start()

    repo_name = _safe_name(repo_name or repo_url.rstrip("/").split("/")[-1].replace(".git", ""))
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    started, t0 = now_utc(), time.time()
    tclass = classify_target(target_url) if target_url else None
    stealth = "n/a (static-only)" if not target_url else (
        f"oniux/Tor ({tclass} target)" if (ONIUX_BIN and tclass == "public")
        else f"direct — no Tor for {tclass} targets (Arti has no loopback route)")

    # ── block clock: height + chain time + calendar meaning (Koodu) ──────────
    clock = None
    if do_clock:
        try:
            import koodu_clock
            clock = koodu_clock.snapshot()
        except Exception as e:  # noqa: BLE001
            clock = {"error": str(e)}
    sabbath_blocked = False
    if sabbath_gate and clock and clock.get("sabbath") and target_url and tclass == "public":
        sabbath_blocked = True
        h = (clock.get("clock") or {}).get("height")
        print(f"  ⛔ sabbath gate: block {h} is {clock.get('domain')} day (Sabbath) — "
              f"dynamic checks deferred on public target")
        target_url, tclass = "", None
        stealth = "n/a (sabbath gate — static only)"

    print(f"\n{'#'*66}\n#  SOVEREIGN OKF PIPELINE v4 — {repo_name}\n#  {started}\n"
          f"#  target={target_url}  class={tclass}\n#  isolation={stealth}\n"
          f"#  clock={clock.get('clock', {}).get('height') if clock else 'off'} "
          f"({'✓ chain-verified ' + str(((clock.get('clock') or {}).get('chain') or {}).get('headers_checked')) + ' headers' + (' · ' + str((((clock.get('clock') or {}).get('chain') or {}).get('continuity') or {}).get('verified_depth', {}).get('count')) + ' verified total back to block ' + str((((clock.get('clock') or {}).get('chain') or {}).get('continuity') or {}).get('verified_depth', {}).get('lowest')) if (((clock.get('clock') or {}).get('chain') or {}).get('continuity') or {}).get('verified_depth') else '') if (clock or {}).get('clock', {}).get('verified') else 'UNVERIFIED' if clock else ''})"
          f" ({clock.get('domain') if clock else '-'}, sabbath={clock.get('sabbath') if clock else '-'})\n"
          f"{'#'*66}")

    raws = {}
    target = _scan_target(repo_name)
    if repo_url.startswith(("http", "git@", "/", "file://")):
        print(f"  rm -rf {target}")
        run(["rm", "-rf", target])
        rc, _ = run(["git", "clone", "--depth", "1", repo_url, target], 120)
        print(f"  clone rc={rc} -> {target}")
    target_path = target if Path(target).exists() else repo_url

    better, raws["betterleaks"] = run_betterleaks(target_path)

    findings, run_dir, sdur = [], None, 0
    if findings_from:
        vj = Path(findings_from)
        vj = vj / "vulnerabilities.json" if vj.is_dir() else vj
        for v in json.load(open(vj)):
            findings.append({"title": v.get("title", ""), "severity": v.get("severity", "unknown"),
                             "description": v.get("description", ""), "poc": v.get("poc_description", ""),
                             "target": v.get("target", ""), "endpoint": v.get("endpoint", ""),
                             "method": v.get("method", ""), "cvss": v.get("cvss"),
                             "finding_class": v.get("finding_class", ""), "source": str(vj)})
        run_dir = str(vj.parent)
        print(f"  findings reused from {vj}: {len(findings)}")
    else:
        findings, raws["strix"], run_dir, sdur = run_strix(
            target_path, f"{repo_name}-v4", mode, strix_timeout)

    text = " ".join(f"{f['title']} {f['description']} {f.get('poc','')}" for f in findings).lower()
    eps = extract_endpoints(findings, target_url)
    print(f"\n  derived endpoints: {eps or 'none'}")

    evdir = EVIDENCE_ROOT / f"{repo_name}_{ts}"
    (evdir / "raw").mkdir(parents=True, exist_ok=True)

    sqlmap = {"injectable": False}
    sqlmap_post = {}
    sstimap = {"vulnerable": False}
    sstimap_post = {}
    xsstrike = {"vectors": 0}
    nmap = ffuf = nuclei = {}
    msf = {"server": None}
    # Does any finding describe a POST body injection? Derivation turns those
    # into `?param=1`, which tests a different request and reads as a negative.
    post_sqli_hint = any(
        (f.get("method") or "").upper() == "POST"
        and re.search(r"sql|inject", f"{f.get('title','')} {f.get('description','')}", re.I)
        and not re.search(r"template|\bssti\b|jinja|twig|mako",
                          f"{f.get('title','')} {f.get('description','')}", re.I)
        for f in findings)

    if not skip_surface and target_url:
        nmap, raws["nmap"] = run_nmap(target_url, tclass)
        ffuf, raws["ffuf"] = run_ffuf(target_url, tclass)
        nuclei, raws["nuclei"] = run_nuclei(target_url, tclass)

    if (("sql" in text or "inject" in text) and eps and target_url) or (target_url and post_sqli_hint):
        cands = [u for u in eps if "?" in u] or eps
        for u in cands[:3]:
            sqlmap, raws["sqlmap"] = run_sqlmap(u, str(evdir / "sqlmap"), tclass)
            if sqlmap.get("injectable"):
                break
        # A POST-body injection cannot be reached through the GET URL that
        # derivation produced — test the request the finding actually described.
        # This runs even when the GET probe already succeeded: they are different
        # requests, and one proof must not suppress the other.
        if post_sqli_hint and not sqlmap.get("method") == "POST":
            sqlmap_post, raws["sqlmap_post"] = probe_post_sqlmap(
                findings, target_url, str(evdir / "sqlmap_post"), tclass)
    if (any(k in text for k in ("ssti", "template", "jinja", "flask"))) and eps and target_url:
        cands = [u for u in eps if re.search(r"name|q=|msg|input", u)] or eps
        for u in cands[:3]:
            sstimap, raws["sstimap"] = run_sstimap(u, tclass)
            if sstimap.get("vulnerable"):
                break
        # A POST-only sink is unreachable from the GET sweep above.
        if not sstimap.get("vulnerable"):
            sstimap_post, raws["sstimap_post"] = probe_post_ssti(
                findings, target_url, tclass)
            if sstimap_post.get("vulnerable"):
                sstimap = {**sstimap_post, "via": "POST body"}
    if ("xss" in text or "cross-site" in text) and eps and target_url:
        xsstrike, raws["xsstrike"] = run_xsstrike(eps[0], tclass)

    inj = {"cmdi": [], "traversal": [], "requests": 0}
    if (eps or ffuf.get("found")) and target_url:
        inj = prove_injection_classes((ffuf.get("found") or []) + eps)
        if inj["cmdi"] or inj["traversal"]:
            print(f"  Proof: cmdi={len(inj['cmdi'])} traversal={len(inj['traversal'])} "
                  f"({inj['requests']} probes)")
            for hit in inj["cmdi"][:2]:
                print(f"    cmdi  {hit['param']}={hit['payload']} -> {hit['evidence'][:60]}")
            for hit in inj["traversal"][:2]:
                print(f"    trav  {hit['param']}={hit['payload']} -> {hit['evidence'][:60]}")
        else:
            print(f"  Proof: cmdi=0 traversal=0 ({inj['requests']} probes, no canary hit)")

    sweep = {}
    if do_sweep and target_url:
        want = []
        if not sstimap.get("vulnerable"):
            want.append("sstimap")
        if not xsstrike.get("vectors"):
            want.append("xsstrike")
        if want and (ffuf.get("found") or eps):
            sweep = sweep_dynamic(target_url, (ffuf.get("found") or []) + eps,
                                  tclass, raws, tuple(want))
            if sweep["sstimap_hits"]:
                sstimap = dict(sweep["sstimap_hits"][0], via="sweep")
            if sweep["xsstrike_hits"]:
                xsstrike = dict(sweep["xsstrike_hits"][0], via="sweep")

    if findings and target_url:
        msf, raws["metasploit"] = run_metasploit(target_url, msf_check)

    decepticon = {"run": False}
    if do_decepticon and target_url:
        df, dmeta = run_decepticon(target_url, decepticon_graph, decepticon_timeout)
        findings.extend(df)
        decepticon = {"run": True, **dmeta, "findings": len(df)}
    elif do_decepticon:
        decepticon = {"run": False, "skipped": "no target_url (static-only)"}

    payload = {"repo": repo_name, "repo_url": repo_url, "target_url": target_url,
               "target_class": tclass, "stealth": stealth, "started": started,
               "duration_s": int(time.time() - t0), "strix_run_dir": run_dir,
               "strix_model": STRIX_MODEL, "strix_seconds": sdur,
               "betterleaks": better, "strix_findings": findings,
               "endpoints": eps, "sqlmap": sqlmap, "sqlmap_post": sqlmap_post,
               "sstimap": sstimap,
               "xsstrike": xsstrike, "nmap": nmap, "ffuf": ffuf,
               "nuclei": nuclei, "metasploit": msf, "sweep": sweep,
               "decepticon": decepticon,
               "clock": clock,
               "injection": inj,
               "sabbath_gate": {"enabled": sabbath_gate, "blocked": sabbath_blocked}}
    prof.finish(
        "completed" if STRIX_RC in (0, 2, None) else "failed",
        findings=len(findings))
    try:
        prof.write(str(evdir / "profile.json"))
        payload["profile"] = prof.to_dict()
    except Exception as e:  # noqa: BLE001
        print(f"  ⚠️ profile: {e}")

    ev = write_evidence(repo_name, ts, payload, raws)
    payload["evidence_dir"], payload["evidence_files"] = str(ev), sorted(
        str(p.relative_to(ev)) for p in ev.rglob("*") if p.is_file())

    # ── guard-gap probe (red-team the detector, not just the app) ──
    ev_findings = []
    if do_evasion:
        try:
            import okf_evasion
            rows = [okf_evasion.evaluate(p) for p in okf_evasion.CORPUS]
            summ = okf_evasion.summarise(rows, *okf_evasion.thresholds_from_config())
            payload["evasion"] = summ
            for r in summ["weakest_first"]:
                if r["flag_rate"] < 0.5:
                    ev_findings.append({
                        "title": f"Detector gap: {r['transform']} obfuscation is not flagged",
                        "severity": "high" if r["flag_rate"] == 0 else "medium",
                        "finding_class": "detector-gap",
                        "endpoint": f"tripwire:tiers/{r['transform']}",
                        "cvss": None,
                        "evidence": f"mean={r['mean_score']} flag_rate={r['flag_rate']} "
                                    f"block_rate={r['block_rate']}",
                    })
            ctl = summ.get("control") or {}
            print(f"  evasion: {summ['overall_flag_rate']*100:.0f}% of transforms flagged "
                  f"· {len(ev_findings)} gaps · control "
                  f"{'OK' if ctl.get('ok') else 'FAILED (' + str(ctl.get('composite')) + ')'}")
        except Exception as e:  # noqa: BLE001
            payload["evasion"] = {"error": str(e)}
            print(f"  ⚠️ evasion probe: {e}")

    # ── cross-scan memory (Memora pattern: append-only JSONL + recall) ──
    tracked = findings + ev_findings
    try:
        sys.path.insert(0, "/opt/ares")
        import okf_memory
        payload["memory"] = okf_memory.record_run(f"findings-{repo_name}", tracked, started)
        mc = payload["memory"]["counts"]
        print(f"  memory: new={mc['new']} persisting={mc['persisting']} "
              f"resolved={mc['resolved']} active={mc['active']}")
    except Exception as e:  # noqa: BLE001
        payload["memory"] = {"error": str(e)}
        print(f"  ⚠️ memory: {e}")

    # ── tamper-evident receipt (Zangbeto pattern: merkle + hash chain) ──
    try:
        import okf_receipt
        clk = (clock or {}).get("clock") or {}
        chn = clk.get("chain") or {}
        btc_meta = ({"height": clk.get("height"), "tip_hash": chn.get("tip_hash"),
                     "headers_checked": chn.get("headers_checked"),
                     "pow_ok": chn.get("pow_ok"), "verified": bool(clk.get("verified")),
                     "continuity_ok": bool((chn.get("continuity") or {}).get("ok")),
                     "anchor_height": (chn.get("continuity") or {}).get("anchor_height"),
                     "anchor_seeded": bool((chn.get("continuity") or {}).get("seeded")),
                     "anchor_sources": ((chn.get("continuity") or {}).get("seeded") or {}).get("sources"),
                     "verified_depth": ((chn.get("continuity") or {}).get("verified_depth") or {}).get("count"),
                     "verified_lowest": ((chn.get("continuity") or {}).get("verified_depth") or {}).get("lowest"),
                     "rooted": bool(chn.get("rooted")),
                     "pin": (chn.get("continuity") or {}).get("pin"),
                     "difficulty": chn.get("difficulty")} if clk else None)
        payload["receipt"] = okf_receipt.emit(
            ev, repo_name, tracked, target_url,
            {"duration_s": payload["duration_s"], "strix_run_dir": run_dir,
             "strix_model": STRIX_MODEL, "btc": btc_meta,
             "profile": payload.get("profile")})
        print(f"  receipt: {payload['receipt']['receipt_id'][:16]} "
              f"chain={payload['receipt']['chain_index']} "
              f"merkle={payload['receipt']['merkle_root'][:16]}")
    except Exception as e:  # noqa: BLE001
        payload["receipt"] = {"error": str(e)}
        print(f"  ⚠️ receipt: {e}")

    # ── optional Bitcoin timestamp over the merkle root (OpenTimestamps) ──
    payload["ots"] = {"skipped": True}
    if do_ots and (payload.get("receipt") or {}).get("path"):
        try:
            import okf_receipt
            o = okf_receipt.ots_stamp(payload["receipt"]["path"])
            payload["ots"] = o
            print(f"  ots: stamped={o.get('stamped')} "
                  f"{'pending calendar attestation' if o.get('stamped') else o.get('stamp_out', '')[:60]}")
        except Exception as e:  # noqa: BLE001
            payload["ots"] = {"error": str(e)}
            print(f"  ⚠️ ots: {e}")

    # ── Koodu BTC-Time: meaning of the timestamp (never the proof itself) ──
    payload["time"] = {"skipped": True}
    if do_ots and (payload.get("receipt") or {}).get("path"):
        try:
            import koodu_time
            t = koodu_time.for_receipt(payload["receipt"]["path"])
            payload["time"] = t
            if t.get("sacred_time"):
                s = t["sacred_time"]
                print(f"  time: block {t['bitcoin']['height']} → BTC day {s['btc_day']}, "
                      f"domain {s['btc_domain']}, era {s['halving_era']}")
            else:
                print(f"  time: {t.get('error', 'no height')}")
        except Exception as e:  # noqa: BLE001
            payload["time"] = {"error": str(e)}
            print(f"  ⚠️ time: {e}")

    # ── optional Nostr attestation of the receipt root ──
    payload["anchor"] = {"skipped": True}
    if do_anchor and (payload.get("receipt") or {}).get("receipt_id"):
        try:
            import okf_anchor
            rcpt = json.load(open(payload["receipt"]["path"]))
            chan = os.environ.get("OKF_ANCHOR_CHANNEL")
            results = asyncio.run(okf_anchor.publish_receipt(
                rcpt, okf_anchor.get_key(), chan))
            ok = sum(1 for r in results.values() if r.get("ok"))
            payload["anchor"] = {"ok": ok > 0, "relays_ok": ok,
                                 "relays_total": len(results), "per_relay": results}
            print(f"  anchor: {ok}/{len(results)} relays accepted "
                  f"({', '.join(r.split('://')[-1][:22] for r in results)})")
        except Exception as e:  # noqa: BLE001
            payload["anchor"] = {"error": str(e)}
            print(f"  ⚠️ anchor: {e}")

    mem = payload.get("memory", {})
    rc_ = payload.get("receipt", {})
    with open(ev / "report.md", "a") as f:
        esum = payload.get("evasion") or {}
        # `summarise()` returns overall_flag_rate/weakest_first/thresholds and no
        # "summary" key, so testing for "summary" reported a successful probe as
        # "unavailable: skipped" — the report lied about its own coverage.
        if esum.get("overall_flag_rate") is not None or esum.get("weakest_first"):
            f.write("\n## Guard-gap probe (tripwire)\n\n")
            f.write(f"- transforms flagged: {esum['overall_flag_rate']*100:.0f}% "
                    f"(flag>={esum['thresholds']['flag']}, block>={esum['thresholds']['block']})\n")
            ctl = esum.get("control") or {}
            if ctl:
                f.write(f"- control ({ctl.get('payload')!r}): "
                        f"{'OK' if ctl.get('ok') else 'FAILED'} · composite {ctl.get('composite')}\n")
                if not ctl.get("ok"):
                    f.write("  (without a passing control, the rate above is uninterpretable)\n")
            gaps = [r for r in esum["weakest_first"] if r["flag_rate"] < esum["thresholds"]["flag"]]
            f.write(f"- guard gaps (below flag threshold): {len(gaps)}/{len(esum['weakest_first'])}\n")
            for r in esum["weakest_first"][:6]:
                f.write(f"  - {r['transform']}: mean {r['mean_score']} · "
                        f"flag {r['flag_rate']*100:.0f}% · block {r['block_rate']*100:.0f}%\n")
        elif esum:
            f.write(f"\n## Guard-gap probe\n\n- unavailable: {esum.get('error', 'skipped')}\n")
        f.write("\n## Since last scan\n\n")
        if "counts" in mem:
            f.write(f"- new: {mem['counts']['new']} · persisting: {mem['counts']['persisting']}"
                    f" · resolved: {mem['counts']['resolved']} · active: {mem['counts']['active']}\n")
            for x in mem.get("new", []):
                f.write(f"  - NEW [{x['fp']}] {x['title'][:110]}\n")
            for x in mem.get("persisting", []):
                f.write(f"  - PERSISTING [{x['fp']}] {x['title'][:90]} (first seen {x['first_seen']})\n")
            for x in mem.get("resolved", []):
                f.write(f"  - RESOLVED [{x['fp']}] {x['title'][:90]}\n")
        else:
            f.write(f"- memory unavailable: {mem.get('error')}\n")
        f.write("\n## Receipt\n\n")
        anc = payload.get("anchor") or {}
        if anc.get("relays_ok"):
            f.write(f"- nostr: {anc['relays_ok']}/{anc['relays_total']} relays accepted\n")
            for url, res in (anc.get("per_relay") or {}).items():
                eid = res.get("message") if res.get("ok") else ""
                f.write(f"  - {url}: ok={res.get('ok')}"
                        f"{(' id=' + str(eid)[:16]) if eid else ''}\n")
        elif anc and not anc.get("skipped"):
            f.write(f"- nostr: {anc.get('error', 'not anchored')}\n")
        if "receipt_id" in rc_:
            f.write(f"- receipt: `{rc_['receipt_id']}`\n- merkle: `{rc_['merkle_root']}`\n"
                    f"- chain_index: {rc_['chain_index']} · prev: `{rc_.get('prev_receipt')}`\n"
                    f"- artifacts: {rc_['artifacts']} · diagnostics: {rc_['diagnostics']}\n")
            ots = payload.get("ots") or {}
            if ots.get("stamped"):
                f.write(f"- timestamp: OpenTimestamps `{os.path.basename(ots['ots_file'])}` "
                        f"(pending Bitcoin attestation)\n")
            f.write(f"- verify: `python3 /opt/ares/okf_receipt.py verify {rc_['path']} --files`\n")
        else:
            f.write(f"- receipt unavailable: {rc_.get('error')}\n")

    bid, resp = post_to_vantage(repo_name, payload, ev)
    payload["vantage_broadcast_id"] = bid
    payload["vantage_response"] = resp
    if bid:
        # rewrite evidence so the artifact carries the post id
        (ev / "report.json").write_text(json.dumps(payload, indent=2))

    # The receipt is signed and chained before the post and the OTS proof exist,
    # so its body says `anchors.btc_ots: null` and carries no broadcast id. Rather
    # than rewrite a signed artifact, record the links beside it — a receipt that
    # cannot name its own post or its own timestamp proof is not auditable.
    try:
        rc_link = (payload.get("receipt") or {})
        if rc_link.get("path"):
            ots_l = payload.get("ots") or {}
            links = {"receipt_id": rc_link.get("receipt_id"),
                     "vantage_broadcast_id": bid,
                     "ots_proof": ots_l.get("ots_file"),
                     "recorded_at": int(time.time())}
            if ots_l.get("ots_file") and os.path.exists(ots_l["ots_file"]):
                links["ots_sha256"] = hashlib.sha256(
                    open(ots_l["ots_file"], "rb").read()).hexdigest()
            lp = str(rc_link["path"]).replace(".json", ".links.json")
            with open(lp, "w") as fh:
                json.dump(links, fh, indent=2)
            payload["links"] = links
    except Exception as e:  # noqa: BLE001
        print(f"  ⚠️ links sidecar: {e}")

    db_err = None
    for attempt in (1, 2, 3):
        try:
            db = sqlite3.connect(DB_PATH, timeout=60)
            db.execute("PRAGMA busy_timeout=60000")
            db.execute("""INSERT INTO broadcasts (agent_id, content_type, title, post_content, status, created_at)
                          VALUES (5,'intel','Vantage Scan v4 complete',?,'hidden',datetime('now'))""",
                       (json.dumps({"repo": repo_name, "findings": len(findings), "sqlmap": sqlmap,
                                    "sstimap": sstimap, "evidence": str(ev), "vantage": bid}),))
            db.commit(); db.close()
            db_err = None
            break
        except Exception as e:  # noqa: BLE001
            db_err = e
            time.sleep(3 * attempt)
    if db_err:
        print(f"  ⚠️ DB: {db_err} (broadcast id {bid} still recorded in evidence)")

    dyn = (f"sqlmap={sqlmap.get('injectable')}"
           + (f" · post={sqlmap_post.get('injectable')}" if sqlmap_post else "")
           + f" · sstimap={sstimap.get('vulnerable')}"
           if target_url else "dynamic=not run (static-only)")
    # Strix exits 2 in headless mode when it filed any finding (no --fail-on
    # threshold = any finding fails the build). That is a result, not a crash.
    # Only 0 (clean) and 2 (findings) count as a completed agent.
    if STRIX_RC not in (0, 2, None):
        print(f"\n  ❌ v4 FAILED · AI scan exit={STRIX_RC} (agent did not complete) · evidence={ev}")
        sys.exit(1)
    print(f"\n  ✅ v4 complete · AI findings={len(findings)} · {dyn} · evidence={ev}")
    return payload


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("repo_url")
    ap.add_argument("repo_name", nargs="?")
    ap.add_argument("--target-url", dest="target_url", default=None,
                    help="live URL for dynamic proof; omit for static-only")
    ap.add_argument("--mode", default="quick", choices=["quick", "standard", "deep"])
    ap.add_argument("--findings-from", dest="findings_from")
    ap.add_argument("--strix-timeout", type=int, default=2700)
    ap.add_argument("--skip-surface", action="store_true")
    ap.add_argument("--no-sweep", action="store_true")
    ap.add_argument("--msf-check", action="store_true")
    ap.add_argument("--no-evasion", action="store_true",
                    help="skip the tripwire guard-gap probe")
    ap.add_argument("--anchor", action="store_true",
                    help="publish the receipt root to the Nostr relays")
    ap.add_argument("--ots", action="store_true",
                    help="(default) OpenTimestamps the merkle root — kept for compatibility")
    ap.add_argument("--no-ots", action="store_true",
                    help="skip OpenTimestamps; a receipt with no proof is a weaker claim")
    ap.add_argument("--no-clock", action="store_true",
                    help="skip the block clock (no height/domain recorded)")
    ap.add_argument("--sabbath-gate", action="store_true",
                    help="on a Sabbath block, defer dynamic checks on public targets")
    ap.add_argument("--decepticon", action="store_true",
                    help="opt-in: dispatch Decepticon (autonomous red-team agent) "
                         "as a deep stage after the deterministic probes")
    ap.add_argument("--decepticon-graph", default="recon",
                    help="Decepticon LangGraph to dispatch (default: recon)")
    ap.add_argument("--decepticon-timeout", type=int, default=600,
                    help="seconds to wait for the Decepticon run (default: 600)")
    a = ap.parse_args()
    out = pipeline(a.repo_url, a.repo_name, a.target_url, a.mode,
                   a.findings_from, a.strix_timeout, a.skip_surface, not a.no_sweep,
                   a.msf_check, not a.no_evasion, a.anchor, (not a.no_ots),
                   not a.no_clock, a.sabbath_gate, a.decepticon,
                   a.decepticon_graph, a.decepticon_timeout)
    print(json.dumps({k: out[k] for k in ("repo", "target_class", "sqlmap", "sstimap",
                                          "xsstrike", "nuclei", "ffuf", "metasploit",
                                          "decepticon", "vantage_broadcast_id",
                                          "evidence_dir")}, indent=2))
