#!/usr/bin/env python3
"""Per-action manifests for every executable this repo invokes (doctrine §9, §12.5).

The point is not to have a JSON file. The point is that adding a tool to the
pipeline without declaring its schemas, capabilities, side effects, timeout,
idempotency and audit obligation fails a check instead of shipping.

Discovery reads the pipeline source twice:

  * command position — list literals on lines that build or run a command
    (`run([...])`, `subprocess.run([...])`, `cmd = [...]`). Any token found
    there that has no manifest is an ERROR, including tokens this file has
    never heard of. That is how `msfconsole`, `curl`, `git` and `rm` were
    caught after the first pass claimed 9/9 coverage.
  * module variables and interpreter-script pairs — `STRIX_BIN`, `OTS_BIN`,
    `[VENV_PY, ".../sstimap.py"]`.

A manifest with no matching invocation is reported as stale, so declarations
cannot drift away from the code while still passing.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST_PATH = os.environ.get("OKF_TOOL_MANIFESTS", os.path.join(HERE, "tool_manifests.json"))
SRC_DIR = os.environ.get("OKF_TOOL_SRC_DIR", HERE)
SOURCES = ["strix_pipeline_v4.py", "okf_receipt.py"]

REQUIRED = {
    "name": str, "exec": list, "input_schema": dict, "output_schema": dict,
    "capabilities": list, "side_effects": list, "timeout_s": int,
    "idempotent": bool, "audit": list,
}

# executable token -> manifest name
BINARY_ALIASES = {
    "sqlmap": "sqlmap", "nuclei": "nuclei", "ffuf": "ffuf", "nmap": "nmap",
    "msfconsole": "msfconsole", "docker": "betterleaks", "ots": "ots",
    "curl": "curl", "git": "git", "rm": "rm", "gitleaks": "gitleaks",
}
SCRIPT_ALIASES = {"sstimap.py": "sstimap", "xsstrike.py": "xsstrike"}
VAR_ALIASES = {"STRIX_BIN": "strix", "OTS_BIN": "ots"}
# runner-function name -> manifest name. Some tools are not a subprocess at
# all (Decepticon is an HTTP API on the already-running LangGraph server), so
# command-position discovery cannot see them. A call to the runner function is
# the evidence of invocation.
FUNCTION_ALIASES = {"run_decepticon": "decepticon"}

# a line that builds or runs a command
CMD_LINE = re.compile(r"(?:subprocess\.\w+|\brun\(|\bwrap\(|\b_cmd\s*=|\bcmd\s*=|dump_cmd\s*=)")
TOKEN_IN_LIST = re.compile(r'\[\s*"([A-Za-z0-9][A-Za-z0-9_.-]*)"\s*,')
TOKEN_INLINE = re.compile(r'\[\s*"([A-Za-z0-9][A-Za-z0-9_.-]*)"\s*,')


def discover(src_dir=None):
    """Return (found, unknown) where found maps manifest_name -> evidence and
    unknown is a list of (token, where) that appear in command position but are
    not mapped to any manifest."""
    src_dir = src_dir or SRC_DIR
    found, unknown = {}, []
    for name in SOURCES:
        path = os.path.join(src_dir, name)
        if not os.path.exists(path):
            continue
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        for i, line in enumerate(lines, 1):
            where = f"{name}:{i}"
            script_hit = False
            if CMD_LINE.search(line):
                for tok in TOKEN_IN_LIST.findall(line):
                    tool = BINARY_ALIASES.get(tok)
                    if tool:
                        found.setdefault(tool, f"{where} {tok}")
                    elif tok not in ("python", "python3", "sh", "bash"):
                        unknown.append((tok, where))
                m = re.search(r'\[\s*[A-Z_][A-Z0-9_]*\s*,\s*"([^"]+\.py)"', line)
                if m:
                    tool = SCRIPT_ALIASES.get(os.path.basename(m.group(1)))
                    if tool:
                        found.setdefault(tool, f"{where} script {os.path.basename(m.group(1))}")
                        script_hit = True
                    else:
                        unknown.append((os.path.basename(m.group(1)), where))
                for var in re.findall(r'\[\s*([A-Z_][A-Z0-9_]*)\s*,', line):
                    tool = VAR_ALIASES.get(var)
                    if tool:
                        found.setdefault(tool, f"{where} var {var}")
            # OTS_BIN is referenced through a variable in okf_receipt.py
            if "OTS_BIN" in line and name == "okf_receipt.py":
                found.setdefault("ots", f"{where} var OTS_BIN")
    # runner-function dispatch (HTTP APIs, not subprocesses): a call to the
    # function is the invocation. `def run_decepticon` alone is not; it must be
    # called somewhere.
    for fn, tool in FUNCTION_ALIASES.items():
        for name in SOURCES:
            path = os.path.join(src_dir, name)
            if not os.path.exists(path):
                continue
            src = open(path, encoding="utf-8", errors="replace").read()
            call = re.search(r"(?<!def )\b" + fn + r"\s*\(", src)
            if call:
                found.setdefault(tool, f"{name} call {fn}()")
    return found, unknown


def load(path=None):
    path = path or MANIFEST_PATH
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc.get("tools"), list):
        raise ValueError("manifest file has no 'tools' list")
    return doc


def validate(doc):
    """Return (errors, warnings, found). Structural errors first, then drift."""
    errors, warnings = [], []
    tools = doc.get("tools", [])
    names = [t.get("name") for t in tools if isinstance(t, dict)]
    if len(names) != len(tools):
        errors.append("a manifest is not an object")
    dupes = {n for n in names if n and names.count(n) > 1}
    for d in sorted(dupes):
        errors.append(f"duplicate manifest for {d!r}")

    for t in tools:
        if not isinstance(t, dict):
            continue
        n = t.get("name", "<unnamed>")
        for field, typ in REQUIRED.items():
            if field not in t or t[field] is None:
                errors.append(f"{n}: missing {field}")
            elif not isinstance(t[field], typ):
                errors.append(f"{n}: {field} is {type(t[field]).__name__}, expected {typ.__name__}")
        if isinstance(t.get("exec"), list) and not t["exec"]:
            errors.append(f"{n}: exec is empty")
        if isinstance(t.get("timeout_s"), int) and t["timeout_s"] <= 0:
            errors.append(f"{n}: timeout_s must be positive")
        for lst in ("capabilities", "side_effects", "audit"):
            if isinstance(t.get(lst), list) and not t[lst]:
                errors.append(f"{n}: {lst} is empty — an action with no declared {lst} is undeclared, not harmless")
        for sch in ("input_schema", "output_schema"):
            v = t.get(sch)
            if isinstance(v, dict) and v.get("type") not in ("object", "array", "string", "integer", "boolean"):
                errors.append(f"{n}: {sch}.type missing or invalid")
        if t.get("idempotent") is False and not t.get("idempotency_note"):
            errors.append(f"{n}: non-idempotent actions must explain why in idempotency_note")
        if t.get("destructive") is True and not t.get("destructive_note"):
            errors.append(f"{n}: destructive actions must state their blast radius in destructive_note")

    found, unknown = discover()
    for tok, where in unknown:
        errors.append(f"unmanifested executable in command position: {tok!r} ({where})")
    for tool, where in found.items():
        if tool not in names:
            errors.append(f"invoked but unmanifested: {tool} ({where})")
    for n in names:
        if n and n not in found:
            warnings.append(f"stale manifest: {n} declared but no invocation found in {', '.join(SOURCES)}")
    return errors, warnings, found


def require_coverage(path=None):
    """Startup gate: raise if any invoked tool lacks a manifest."""
    doc = load(path)
    errors, _, _ = validate(doc)
    hard = [e for e in errors if "unmanifested" in e or ": missing" in e]
    if hard:
        raise RuntimeError(
            "tool manifest gate failed (doctrine §9/§12.5): "
            + "; ".join(hard)
            + " — declare it in tool_manifests.json before running."
        )
    return True


def main():
    doc = load()
    errors, warnings, found = validate(doc)
    tools = [t for t in doc["tools"] if isinstance(t, dict)]
    print(f"tool_manifests.json: {len(tools)} declared, {len(found)} invoked in source")
    if not errors:
        for t in tools:
            print(f"  {t['name']:<12} timeout={t['timeout_s']:>5}s idempotent={str(t['idempotent']):<5} "
                  f"caps={len(t['capabilities'])} side_effects={len(t['side_effects'])} audit={len(t['audit'])}"
                  + ("  DESTRUCTIVE" if t.get("destructive") else ""))
    for w in warnings:
        print(f"  WARN  {w}")
    for e in errors:
        print(f"  ERROR {e}")
    if errors:
        print(f"FAILED: {len(errors)} error(s)")
        return 1
    print(f"OK: every executable in command position is declared ({len(found)}/{len(found)})"
          + (f", {len(warnings)} stale" if warnings else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
