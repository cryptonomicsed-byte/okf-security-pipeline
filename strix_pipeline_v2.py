#!/usr/bin/env python3
"""
Sovereign OKF Pipeline — Dynamic AI-Driven Routing
Chains betterleaks → Strix (v1.7.0) → Dynamic Tools (XSStrike/SSTImap/SQLmap) → Metasploit → Vantage
"""
import subprocess, json, os, sys, time, sqlite3, shutil
from datetime import datetime
from pathlib import Path

VANTAGE_URL = "http://localhost:8001"
VANTAGE_KEY = os.environ.get("VANTAGE_KEY") or (open("/opt/ares/.vantage_key").read().strip() if os.path.exists("/opt/ares/.vantage_key") else "")
DB_PATH = "/opt/ares/Vantage/data/vantage.db"
SCAN_DIR = "/tmp/strix-pipeline"
STRIX_BIN = "/opt/ares/strix-venv/bin/strix"
ONIUX_BIN = None if os.environ.get("DISABLE_ONIUX") else (shutil.which("oniux") or ("/root/.cargo/bin/oniux" if os.path.exists("/root/.cargo/bin/oniux") else None))

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
    """Wrap command in oniux for kernel-level Tor isolation if available."""
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
                                "description": res.get("message", {}).get("text", "")
                            })
                    break

        print(f"  Findings: {len(findings)}")
        for f in findings:
            print(f"    - [{f.get('severity', '?')}] {f.get('title', '?')}")
        return findings, output
    except subprocess.TimeoutExpired:
        print("  ⚠️ Strix timed out after 300s")
        return [], "TIMEOUT"
    except Exception as e:
        print(f"  ❌ Strix error: {e}")
        return [], str(e)

# ── Step 2: XSStrike (for XSS findings) ─────────────────────
def run_xsstrike(url):
    print(f"\n  XSStrike: scanning {url}")
    try:
        cmd = wrap_cmd(["/opt/ares/venv/bin/python", "/opt/ares/XSStrike/xsstrike.py",
                        "-u", url, "--skip-dom", "--console-log-level", "WARNING"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env={**os.environ, 'TMPDIR': '/root'})
        output = result.stdout
        vulns = output.count("VULN") + output.count("[+] Vector") + output.count("Reflected")
        print(f"  XSStrike findings: {vulns} potential XSS")
        return vulns, output
    except Exception as e:
        print(f"  ⚠️ XSStrike error: {e}")
        return 0, str(e)

# ── Step 3: SSTImap (for SSTI findings) ──────────────────────
def run_sstimap(url):
    print(f"\n  SSTImap: scanning {url}")
    try:
        cmd = wrap_cmd(["/opt/ares/venv/bin/python", "/opt/ares/SSTImap/sstimap.py",
                        "-u", url, "--no-color"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env={**os.environ, 'TMPDIR': '/root'})
        output = result.stdout
        vulns = output.count("is vulnerable") + output.count("[!]")
        print(f"  SSTImap findings: {vulns} potential SSTI")
        return vulns, output
    except Exception as e:
        print(f"  ⚠️ SSTImap error: {e}")
        return 0, str(e)

# ── Step 4: SQLmap (for SQLi findings) ───────────────────────
def run_sqlmap(url):
    print(f"\n  SQLmap: scanning {url}")
    try:
        cmd = wrap_cmd(["sqlmap", "-u", url, "--batch", "--crawl=2", "--level=1", "--risk=1", "--smart"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env={**os.environ, 'TMPDIR': '/root'})
        output = result.stdout
        vulns = output.count("is vulnerable") + output.count("injectable")
        print(f"  SQLmap findings: {vulns} potential SQLi")
        return vulns, output
    except Exception as e:
        print(f"  ⚠️ SQLmap error: {e}")
        return 0, str(e)

# ── Step 5: Metasploit exploit validation ────────────────────
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
        output = result.stdout
        success = "VULNERABLE" in output or "[+]" in output
        print(f"  Metasploit: {'✅ EXPLOITABLE' if success else 'no exploit'}")
        return success, output
    except Exception as e:
        print(f"  ⚠️ Metasploit error: {e}")
        return False, str(e)

# ── Step 6: Post to Vantage ──────────────────────────────────
def post_to_vantage(repo_name, betterleaks_count, strix_findings, xsstrike_count, sstimap_count, sqlmap_count, msf_exploited):
    title = f"🔍 Security Scan: {repo_name}"

    finding_lines = []
    for f in strix_findings[:5]:
        finding_lines.append(
            f"- **{f.get('title', 'Finding')}** ({f.get('severity', '?')})\n"
            f"  {f.get('description', '')[:200]}"
        )

    stealth_status = "🛡️ Oniux (Tor)" if ONIUX_BIN else "⚠️ Direct (No Oniux)"

    content = f"""**Sovereign OKF Pipeline Scan — {repo_name}**

**Stealth Layer:** {stealth_status}
**Secrets (betterleaks):** {betterleaks_count} exposed
**AI Analysis (Strix v1.7.0):** {len(strix_findings)} findings
{chr(10).join(finding_lines) if finding_lines else '  No findings'}

**XSS Scanner (XSStrike):** {xsstrike_count} potential XSS vectors
**SSTI Scanner (SSTImap):** {sstimap_count} potential SSTI vectors
**SQLi Scanner (SQLmap):** {sqlmap_count} potential SQLi vectors

**Exploit Validation (Metasploit):** {'✅ Exploitable' if msf_exploited else 'No exploit confirmed'}

**Scan time:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
"""

    resp = vantage_post("/api/agents/posts/text", {
        "title": title,
        "content": content,
        "tags": ["security", "strix", "pentest", "code", "sovereign"],
        "status": "published",
        "content_type": "text"
    })
    print(f"  Posted to Vantage: {resp.get('broadcast_id', resp.get('id', resp.get('status', '?')))}")

# ── Main Pipeline ────────────────────────────────────────────
def pipeline(repo_url, repo_name, target_url="http://localhost:8001"):
    print(f"\n{'#'*60}")
    print(f"#  SOVEREIGN OKF PIPELINE: {repo_name}")
    print(f"#  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"#  Stealth: {'ON' if ONIUX_BIN else 'OFF'}")
    print(f"{'#'*60}")

    target = f"{SCAN_DIR}/{repo_name}"
    subprocess.run(["rm", "-rf", target], capture_output=True)
    clone = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, target],
        capture_output=True, text=True, timeout=30
    )
    print(f"  Clone: {repo_url} → {target}")

    betterleaks_count, _ = run_betterleaks(target)
    findings, strix_output = run_strix(target)

    # ── Dynamic Routing based on AI Findings ─────────────────
    xsstrike_count = 0
    sstimap_count = 0
    sqlmap_count = 0

    # Aggregate titles and descriptions into one searchable string
    finding_text = " ".join([str(f.get("title", "")) + " " + str(f.get("description", "")) for f in findings]).lower()

    # Check for XSS indicators
    if "xss" in finding_text or "cross-site scripting" in finding_text:
        print("\n  [Dynamic Route] XSS indicators detected. Launching XSStrike...")
        xsstrike_count, _ = run_xsstrike(target_url)

    # Check for SSTI indicators
    if "ssti" in finding_text or "template injection" in finding_text or "jinja" in finding_text:
        print("\n  [Dynamic Route] SSTI indicators detected. Launching SSTImap...")
        sstimap_count, _ = run_sstimap(target_url)

    # Check for SQLi indicators
    if "sql" in finding_text or "injection" in finding_text:
        print("\n  [Dynamic Route] SQLi indicators detected. Launching SQLmap...")
        sqlmap_count, _ = run_sqlmap(target_url)

    # ── Metasploit Validation ────────────────────────────────
    msf_exploited = False
    if findings:
        # Try to determine vuln type from the highest severity finding
        msf_type = "sql" if "sql" in finding_text else "xss"
        msf_exploited, _ = run_metasploit(target_url, msf_type)

    # ── Reporting ────────────────────────────────────────────
    post_to_vantage(repo_name, betterleaks_count, findings, xsstrike_count, sstimap_count, sqlmap_count, msf_exploited)

    # Store findings in DB
    try:
        db = sqlite3.connect(DB_PATH, timeout=30)
        db.execute("""
            INSERT INTO broadcasts (agent_id, content_type, title, post_content, status, created_at)
            VALUES (5, 'intel', 'Security Scan Complete', ?, 'hidden', datetime('now'))
        """, (json.dumps({
            "repo": repo_name,
            "findings": len(findings),
            "betterleaks": betterleaks_count,
            "xsstrike": xsstrike_count,
            "sstimap": sstimap_count,
            "sqlmap": sqlmap_count,
            "msf_exploited": msf_exploited,
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
        print("Usage: strix_pipeline.py <repo_url> [repo_name]")
        sys.exit(1)

    repo_url = sys.argv[1]
    repo_name = sys.argv[2] if len(sys.argv) > 2 else repo_url.rstrip("/").split("/")[-1].replace(".git", "")

    target_url = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:8001"
    findings = pipeline(repo_url, repo_name, target_url)
    print(f"\nDone: {len(findings)} findings")
