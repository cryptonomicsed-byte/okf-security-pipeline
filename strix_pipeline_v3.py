#!/usr/bin/env python3
"""
Sovereign OKF Pipeline v3 — Full-Spectrum AI-Driven Offensive Engine
Chains: betterleaks → Strix (SARIF) → nmap → ffuf → nuclei → XSStrike/SSTImap/SQLmap → Metasploit → Vantage
"""
import subprocess, json, os, sys, time, sqlite3, shutil, re, hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

VANTAGE_URL = "http://localhost:8001"
VANTAGE_KEY = os.environ.get("VANTAGE_KEY") or (open("/opt/ares/.vantage_key").read().strip() if os.path.exists("/opt/ares/.vantage_key") else "")
DB_PATH = "/opt/ares/Vantage/data/vantage.db"
SCAN_DIR = "/tmp/strix-pipeline"
REPORT_DIR = "/opt/ares/reports"
CACHE_FILE = "/opt/ares/.strix_cache.json"
STRIX_BIN = "/opt/ares/strix-venv/bin/strix"
ONIUX_BIN = None if os.environ.get("DISABLE_ONIUX") else (shutil.which("oniux") or ("/root/.cargo/bin/oniux" if os.path.exists("/root/.cargo/bin/oniux") else None))

os.makedirs(REPORT_DIR, exist_ok=True)

# ── Cache helpers ────────────────────────────────────────────
def get_repo_hash(target_path):
    try:
        result = subprocess.run(["git", "-C", target_path, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    h = hashlib.sha256()
    for root, dirs, files in os.walk(target_path):
        for file in sorted(files):
            path = os.path.join(root, file)
            try:
                with open(path, "rb") as f:
                    h.update(f.read())
            except Exception:
                pass
    return h.hexdigest()

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_cache(cache):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        print(f"  ⚠️ cache save error: {e}")


# ── API helpers ──────────────────────────────────────────────
def vantage_post(endpoint, data):
    cmd = ["curl", "-s", "-X", "POST", f"{VANTAGE_URL}{endpoint}",
           "-H", "Content-Type: application/json",
           "-H", f"X-Agent-Key: {VANTAGE_KEY}",
           "-d", json.dumps(data)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    return json.loads(r.stdout) if r.stdout else {}

# ── Stealth Wrapper ──────────────────────────────────────────
def wrap_cmd(cmd_list):
    if ONIUX_BIN:
        return [ONIUX_BIN] + cmd_list
    return cmd_list

# ── Step 0: betterleaks secrets scan ──────────────────────────
def run_betterleaks(target_path):
    print(f"\n  betterleaks: scanning {target_path}")
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{target_path}:/repo:ro",
             "ghcr.io/betterleaks/betterleaks:latest", "dir", "/repo"],
            capture_output=True, text=True, timeout=120
        )
        leaks = result.stdout.count("┌─")
        print(f"  betterleaks: {leaks} secrets found")
        return leaks, result.stdout
    except Exception as e:
        print(f"  ⚠️ betterleaks error: {e}")
        return 0, str(e)

# ── Step 1: Strix AI Scan ────────────────────────────────────
def run_strix(target_path, mode="quick"):
    print(f"\n{'='*60}")
    print(f"  STRIX AI SCAN (v1.7.0): {target_path}")
    print(f"{'='*60}")

    env = os.environ.copy()
    env["STRIX_LLM"] = "openai/nvidia-mistral-large"
    env["LLM_API_KEY"] = open("/opt/ares/.litellm_key").read().strip()
    env["LLM_API_BASE"] = "http://localhost:8300/v1"

    try:
        result = subprocess.run(
            [STRIX_BIN, "-n", "--target", target_path, "--scan-mode", mode],
            capture_output=True, text=True, timeout=3600,
            env=env, cwd="/opt/ares/strix"
        )
        output = result.stdout + result.stderr
        print(f"  Exit: {result.returncode}")

        runs_dir = Path("/opt/ares/strix/strix_runs")
        findings = []
        if runs_dir.exists():
            for run in sorted(runs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
                sarif = run / "findings.sarif"
                if sarif.exists():
                    with open(sarif) as f:
                        data = json.load(f)
                    for r in data.get("runs", []):
                        for res in r.get("results", []):
                            findings.append({
                                "title": res.get("message", {}).get("text", "Finding"),
                                "severity": res.get("level", "unknown"),
                                "description": res.get("message", {}).get("text", ""),
                                "location": res.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "unknown")
                            })
                    break

        print(f"  Findings: {len(findings)}")
        for f in findings:
            print(f"    - [{f.get('severity', '?')}] {f.get('title', '?')} ({f.get('location', '?')})")
        return findings, output
    except subprocess.TimeoutExpired:
        print("  ⚠️ Strix timed out after 3600s")
        return [], "TIMEOUT"
    except Exception as e:
        print(f"  ❌ Strix error: {e}")
        return [], str(e)

# ── Step 2: Network Recon (nmap) ─────────────────────────────
def run_nmap(target_url):
    parsed = urlparse(target_url)
    host = parsed.hostname
    if not host or host in ("localhost", "127.0.0.1"):
        print(f"\n  nmap: skipping localhost target")
        return "", ""
    print(f"\n  nmap: scanning {host}")
    try:
        cmd = wrap_cmd(["nmap", "-sV", "-sC", "-T4", "--top-ports", "100", host])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env={**os.environ, 'TMPDIR': '/root'})
        print(f"  nmap: completed")
        return result.stdout, result.stderr
    except Exception as e:
        print(f"  ⚠️ nmap error: {e}")
        return "", str(e)

# ── Step 3: Directory Fuzzing (ffuf) ─────────────────────────
def run_ffuf(target_url):
    print(f"\n  ffuf: fuzzing paths on {target_url}")
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    if not os.path.exists(wordlist):
        print("  ⚠️ ffuf: no wordlist found")
        return 0, ""
    try:
        url = target_url.rstrip("/") + "/FUZZ"
        cmd = wrap_cmd(["ffuf", "-u", url, "-w", wordlist, "-mc", "200,301,302,403", "-t", "20", "-o", "/tmp/ffuf.json", "-of", "json"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env={**os.environ, 'TMPDIR': '/root'})
        count = 0
        if os.path.exists("/tmp/ffuf.json"):
            with open("/tmp/ffuf.json") as f:
                data = json.load(f)
            count = len(data.get("results", []))
        print(f"  ffuf: {count} paths discovered")
        return count, result.stdout
    except Exception as e:
        print(f"  ⚠️ ffuf error: {e}")
        return 0, str(e)

# ── Step 4: Nuclei Template Scan ─────────────────────────────
def run_nuclei(target_url):
    print(f"\n  nuclei: scanning {target_url}")
    try:
        cmd = wrap_cmd(["nuclei", "-u", target_url, "-severity", "critical,high,medium", "-jsonl", "-o", "/tmp/nuclei.jsonl", "-silent"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env={**os.environ, 'TMPDIR': '/root'})
        count = 0
        if os.path.exists("/tmp/nuclei.jsonl"):
            with open("/tmp/nuclei.jsonl") as f:
                count = sum(1 for _ in f)
        print(f"  nuclei: {count} vulnerabilities found")
        return count, result.stdout
    except Exception as e:
        print(f"  ⚠️ nuclei error: {e}")
        return 0, str(e)

# ── Step 5: XSStrike (XSS) ───────────────────────────────────
def run_xsstrike(url):
    print(f"\n  XSStrike: scanning {url}")
    try:
        cmd = wrap_cmd(["/opt/ares/venv/bin/python", "/opt/ares/XSStrike/xsstrike.py",
                        "-u", url, "--skip-dom", "--console-log-level", "WARNING"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env={**os.environ, 'TMPDIR': '/root'})
        vulns = result.stdout.count("VULN") + result.stdout.count("[+] Vector") + result.stdout.count("Reflected")
        print(f"  XSStrike findings: {vulns} potential XSS")
        return vulns, result.stdout
    except Exception as e:
        print(f"  ⚠️ XSStrike error: {e}")
        return 0, str(e)

# ── Step 6: SSTImap (SSTI) ───────────────────────────────────
def run_sstimap(url):
    print(f"\n  SSTImap: scanning {url}")
    try:
        cmd = wrap_cmd(["/opt/ares/venv/bin/python", "/opt/ares/SSTImap/sstimap.py",
                        "-u", url, "--no-color"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env={**os.environ, 'TMPDIR': '/root'})
        vulns = result.stdout.count("is vulnerable") + result.stdout.count("[!]")
        print(f"  SSTImap findings: {vulns} potential SSTI")
        return vulns, result.stdout
    except Exception as e:
        print(f"  ⚠️ SSTImap error: {e}")
        return 0, str(e)

# ── Step 7: SQLmap (SQLi) ────────────────────────────────────
def run_sqlmap(url):
    print(f"\n  SQLmap: scanning {url}")
    try:
        cmd = wrap_cmd(["sqlmap", "-u", url, "--batch", "--crawl=2", "--level=1", "--risk=1", "--smart"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env={**os.environ, 'TMPDIR': '/root'})
        vulns = result.stdout.count("is vulnerable") + result.stdout.count("injectable")
        print(f"  SQLmap findings: {vulns} potential SQLi")
        return vulns, result.stdout
    except Exception as e:
        print(f"  ⚠️ SQLmap error: {e}")
        return 0, str(e)

# ── Step 8: Metasploit validation ────────────────────────────
def run_metasploit(target_url, vuln_type="xss"):
    print(f"\n  Metasploit: testing exploit for {vuln_type}")
    msf_rc = f"""
use auxiliary/scanner/http/{vuln_type}
set RHOSTS {target_url}
set METHOD GET
run
exit
"""
    rc_file = "/tmp/msf_scan.rc"
    with open(rc_file, "w") as f:
        f.write(msf_rc)
    try:
        result = subprocess.run(
            ["msfconsole", "-q", "-r", rc_file],
            capture_output=True, text=True, timeout=120
        )
        success = "VULNERABLE" in result.stdout or "[+]" in result.stdout
        print(f"  Metasploit: {'✅ EXPLOITABLE' if success else 'no exploit'}")
        return success, result.stdout
    except Exception as e:
        print(f"  ⚠️ Metasploit error: {e}")
        return False, str(e)

# ── Step 8.5: Decepticon Fallback (LangGraph API) ─────────────
def run_decepticon(target_url, timeout=600, graph="recon"):
    print(f"\n  Decepticon: dispatching '{graph}' graph against {target_url}")
    import urllib.request
    from urllib.parse import urlparse
    BASE = "http://127.0.0.1:2024"

    # Provision machine-readable RoE (Decepticon fails closed without it)
    host = urlparse(target_url).hostname or target_url
    roe_dir = "/root/.decepticon/workspace/plan"
    os.makedirs(roe_dir, exist_ok=True)
    roe = {
        "engagement_name": f"Sovereign OKF Pipeline — {target_url}",
        "machine_enforcement": {
            "in_scope": [host],
            "out_of_scope": [],
            "forbidden_destinations": [],
            "forbidden_command_patterns": [],
            "allow_cloud_metadata": False,
            "allow_sensitive_tlds": False,
            "max_concurrent_connections": 10,
            "min_inter_request_delay_ms": 0,
            "authorized_windows": [],
            "blackout_windows": []
        }
    }
    with open(os.path.join(roe_dir, "roe.json"), "w") as f:
        json.dump(roe, f, indent=2)
    print(f"  Decepticon RoE written: in_scope={roe['machine_enforcement']['in_scope']}")

    def post(path, data, t=30):
        req = urllib.request.Request(
            f"{BASE}{path}",
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        return json.loads(urllib.request.urlopen(req, timeout=t).read())

    def get(path, t=30):
        req = urllib.request.Request(f"{BASE}{path}")
        return json.loads(urllib.request.urlopen(req, timeout=t).read())

    try:
        thread = post("/threads", {})
        tid = thread["thread_id"]
        run = post(f"/threads/{tid}/runs", {
            "assistant_id": graph,
            "input": {
                "messages": [{"role": "user", "content": f"Authorized reconnaissance of {target_url}. Identify vulnerabilities and report concisely."}],
                "workspace_path": "/workspace"
            },
            "config": {"configurable": {"workspace_path": "/workspace"}}
        })
        rid = run.get("run_id", "")
        print(f"  Decepticon thread={tid} run={rid} (timeout {timeout}s)")

        deadline = time.time() + timeout
        status = "pending"
        while time.time() < deadline:
            time.sleep(5)
            try:
                runs = get(f"/threads/{tid}/runs") or []
                match = [r for r in runs if r.get("run_id") == rid]
                status = match[0].get("status", "unknown") if match else "unknown"
            except Exception:
                status = "unknown"
            if status in ("success", "error", "interrupted", "timeout"):
                break

        if status not in ("success", "error", "interrupted", "timeout"):
            print(f"  Decepticon: timeout after {timeout}s — cancelling run")
            try:
                post(f"/threads/{tid}/runs/{rid}/cancel", {})
            except Exception:
                pass
            status = "timeout"

        content = ""
        try:
            state = get(f"/threads/{tid}/state")
            messages = (state.get("values") or {}).get("messages", []) or []
            for m in reversed(messages):
                if m.get("type") == "ai" and m.get("content"):
                    content = m["content"]
                    break
        except Exception as e:
            print(f"  ⚠️ Decepticon state read error: {e}")

        print(f"  Decepticon status={status}, report={len(content)} chars")
        if content:
            return [{
                "title": f"Decepticon {graph} Report",
                "severity": "info",
                "description": content[:3000],
                "location": target_url
            }]
        return []
    except Exception as e:
        print(f"  ⚠️ Decepticon error: {e}")
        return []

# ── Report Generation ────────────────────────────────────────
def generate_report(repo_name, betterleaks_count, strix_findings, nmap_out, ffuf_count, nuclei_count, xsstrike_count, sstimap_count, sqlmap_count, msf_exploited):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"{REPORT_DIR}/{repo_name}_{timestamp}.md"

    lines = [
        f"# Sovereign OKF Security Report — {repo_name}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Stealth:** {'🛡️ Oniux (Tor)' if ONIUX_BIN else '⚠️ Direct'}",
        "",
        "## Executive Summary",
        f"- **Secrets Leaked (betterleaks):** {betterleaks_count}",
        f"- **AI Findings (Strix v1.7.0):** {len(strix_findings)}",
        f"- **Paths Discovered (ffuf):** {ffuf_count}",
        f"- **CVEs/Vulns (nuclei):** {nuclei_count}",
        f"- **XSS Vectors (XSStrike):** {xsstrike_count}",
        f"- **SSTI Vectors (SSTImap):** {sstimap_count}",
        f"- **SQLi Vectors (SQLmap):** {sqlmap_count}",
        f"- **Exploit Confirmed (Metasploit):** {'✅ Yes' if msf_exploited else 'No'}",
        "",
        "## AI Findings (Strix)",
    ]
    for f in strix_findings:
        lines.append(f"### {f.get('title', 'Finding')} [{f.get('severity', '?')}]")
        lines.append(f"**Location:** `{f.get('location', 'unknown')}`")
        lines.append(f"{f.get('description', '')}")
        lines.append("")

    if nmap_out:
        lines.append("## Network Recon (nmap)")
        lines.append("```")
        lines.append(nmap_out[:2000])
        lines.append("```")

    with open(report_path, "w") as f:
        f.write("\n".join(lines))
    print(f"  Report saved: {report_path}")

    # Generate HTML
    try:
        import markdown
        with open(report_path) as f:
            html = markdown.markdown(f.read())
    except ImportError:
        with open(report_path) as f:
            html = f"<pre>{f.read()}</pre>"
    html_path = report_path.replace(".md", ".html")
    with open(html_path, "w") as f:
        f.write(f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sovereign OKF Report — {repo_name}</title>
<style>body{{font-family:monospace;max-width:900px;margin:2em auto;padding:1em;background:#111;color:#eee}}
h1,h2,h3{{color:#0f0}} pre{{background:#222;padding:1em;overflow-x:auto}} code{{background:#333;padding:0.2em}} a{{color:#0ff}}</style>
</head><body>{html}</body></html>""")
    print(f"  HTML report: {html_path}")

    return report_path

# ── Step 9: Post to Vantage ──────────────────────────────────
def post_to_vantage(repo_name, betterleaks_count, strix_findings, ffuf_count, nuclei_count, xsstrike_count, sstimap_count, sqlmap_count, msf_exploited):
    title = f"🔍 Sovereign Scan: {repo_name}"
    finding_lines = []
    for f in strix_findings[:5]:
        finding_lines.append(f"- **{f.get('title', 'Finding')}** ({f.get('severity', '?')}) — `{f.get('location', '?')}`")

    content = f"""**Sovereign OKF Pipeline — {repo_name}**

**Stealth:** {'🛡️ Oniux (Tor)' if ONIUX_BIN else '⚠️ Direct'}
**Secrets:** {betterleaks_count} | **AI Findings:** {len(strix_findings)} | **ffuf:** {ffuf_count} | **nuclei:** {nuclei_count}
**XSS:** {xsstrike_count} | **SSTI:** {sstimap_count} | **SQLi:** {sqlmap_count}
**Metasploit:** {'✅ EXPLOITABLE' if msf_exploited else 'No exploit'}

{chr(10).join(finding_lines) if finding_lines else 'No AI findings.'}

**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
"""
    resp = vantage_post("/api/agents/posts/text", {
        "title": title,
        "content": content,
        "tags": ["security", "sovereign", "pentest", "strix"],
        "status": "published",
        "content_type": "text"
    })
    print(f"  Posted to Vantage: {resp.get('broadcast_id', resp.get('id', resp.get('status', '?')))}")

# ── Main Pipeline ────────────────────────────────────────────
def pipeline(repo_url, repo_name, target_url=None):
    print(f"\n{'#'*60}")
    print(f"#  SOVEREIGN OKF PIPELINE v3: {repo_name}")
    print(f"#  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"#  Target: {target_url or 'STATIC ONLY'}")
    print(f"#  Stealth: {'ON' if ONIUX_BIN else 'OFF'}")
    print(f"{'#'*60}")

    target = f"{SCAN_DIR}/{repo_name}"
    subprocess.run(["rm", "-rf", target], capture_output=True)
    subprocess.run(["git", "clone", "--depth", "1", repo_url, target], capture_output=True, text=True, timeout=60)
    print(f"  Clone: {repo_url} → {target}")

    betterleaks_count, _ = run_betterleaks(target)

    repo_hash = get_repo_hash(target)
    cache = load_cache()
    if repo_name in cache and cache[repo_name].get("hash") == repo_hash:
        print(f"  [CACHE HIT] Repo unchanged (hash={repo_hash[:8]}). Skipping Strix LLM scan.")
        findings = cache[repo_name].get("findings", [])
    else:
        findings, _ = run_strix(target)
        cache[repo_name] = {"hash": repo_hash, "findings": findings, "timestamp": datetime.now().isoformat()}
        save_cache(cache)

    finding_text = " ".join([str(f.get("title", "")) + " " + str(f.get("description", "")) for f in findings]).lower()

    # Network + Web surface
    nmap_out = ""
    ffuf_count = 0
    nuclei_count = 0
    xsstrike_count = 0
    sstimap_count = 0
    sqlmap_count = 0
    msf_exploited = False

    if target_url:
        nmap_out, _ = run_nmap(target_url)
        ffuf_count, _ = run_ffuf(target_url)
        nuclei_count, _ = run_nuclei(target_url)

        if "xss" in finding_text or "cross-site scripting" in finding_text:
            print("\n  [Dynamic Route] XSS detected.")
            xsstrike_count, _ = run_xsstrike(target_url)

        if "ssti" in finding_text or "template injection" in finding_text or "jinja" in finding_text:
            print("\n  [Dynamic Route] SSTI detected.")
            sstimap_count, _ = run_sstimap(target_url)

        if "sql" in finding_text or "injection" in finding_text:
            print("\n  [Dynamic Route] SQLi detected.")
            sqlmap_count, _ = run_sqlmap(target_url)

        if findings:
            msf_type = "sql" if "sql" in finding_text else ("xss" if "xss" in finding_text else "xss")
            msf_exploited, _ = run_metasploit(target_url, msf_type)
        else:
            print("\n  [Fallback] Strix found 0 findings. Dispatching Decepticon red-team graph...")
            findings = run_decepticon(target_url)

    report_path = generate_report(repo_name, betterleaks_count, findings, nmap_out, ffuf_count, nuclei_count, xsstrike_count, sstimap_count, sqlmap_count, msf_exploited)
    post_to_vantage(repo_name, betterleaks_count, findings, ffuf_count, nuclei_count, xsstrike_count, sstimap_count, sqlmap_count, msf_exploited)

    # Store in DB
    try:
        db = sqlite3.connect(DB_PATH, timeout=30)
        db.execute("""
            INSERT INTO broadcasts (agent_id, content_type, title, post_content, status, created_at)
            VALUES (5, 'intel', 'Sovereign Scan Complete', ?, 'hidden', datetime('now'))
        """, (json.dumps({
            "repo": repo_name, "report": report_path,
            "findings": len(findings), "betterleaks": betterleaks_count,
            "ffuf": ffuf_count, "nuclei": nuclei_count,
            "xsstrike": xsstrike_count, "sstimap": sstimap_count,
            "sqlmap": sqlmap_count, "msf_exploited": msf_exploited,
            "stealth": bool(ONIUX_BIN)
        }),))
        db.commit()
        db.close()
    except Exception as e:
        print(f"  ⚠️ DB write error: {e}")

    print(f"\n  ✅ Pipeline complete: {repo_name}")
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: strix_pipeline_v3.py <repo_url> [repo_name] [target_url]")
        sys.exit(1)

    repo_url = sys.argv[1]
    repo_name = sys.argv[2] if len(sys.argv) > 2 else repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    target_url = sys.argv[3] if len(sys.argv) > 3 else None

    findings = pipeline(repo_url, repo_name, target_url)
    print(f"\nDone: {len(findings)} findings")
