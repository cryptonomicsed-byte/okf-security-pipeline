#!/usr/bin/env python3
"""Per-run agent profile (doctrine §1: identity, goals, skills, permissions,
memory namespace, lifecycle state).

Before this module a pipeline run was anonymous: it produced a receipt with no
statement of what agent did the work, under which capabilities, with what
budget, or in what lifecycle state. §12 item 4 called that the agent-boundary
gap; this closes the part that can be closed inside this repo.

Two things it deliberately does NOT do:

  * It does not mint an identity. There is no Èṣù gatekeeper here, so the
    profile records `principal: null` with the reason, rather than promoting
    the Nostr anchor key into an agent identity — the equivalence §6 forbids.
  * It does not claim persistence. The namespace is per-run and ephemeral;
    a profile that pretends to be a durable memory is worse than none.
"""
import json
import os
import time
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST_PATH = os.environ.get("OKF_TOOL_MANIFESTS", os.path.join(HERE, "tool_manifests.json"))

STATES = ("created", "running", "completed", "failed")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def capabilities_for(tools):
    """Union of the capabilities declared by the manifests of `tools`."""
    caps = set()
    try:
        doc = json.load(open(MANIFEST_PATH, encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    for t in doc.get("tools", []):
        if t.get("name") in tools:
            caps.update(t.get("capabilities") or [])
    return sorted(caps)


class RunProfile:
    """A run-scoped agent profile with an explicit, monotonic lifecycle."""

    def __init__(self, repo, goal, mode="quick", target_url=None, tools=None,
                 budget_s=None, memory_namespace=None):
        self.data = {
            "profile_version": "1.0",
            "profile_id": f"okf-runner-{uuid.uuid4().hex[:12]}",
            "agent": {
                "name": "okf-security-pipeline",
                "niche": "Ògún — tool execution",
                "principal": None,
                "principal_note": ("unresolved: no Èṣù gatekeeper in this repo; the Nostr anchor key "
                                   "is a signing key, not an agent identity (repomap §6/§7 rule 1)"),
            },
            "goal": {"repo": repo, "target_url": target_url, "mode": mode, "objective":
                     "produce a proof-backed security receipt for this target"},
            "skills": {"tools": list(tools or []), "count": len(tools or [])},
            "permissions": {"capabilities": capabilities_for(tools or []),
                            "enforced_by": "tool manifests + _scan_target path guard (not by an LLM)"},
            "memory": {"namespace": memory_namespace or f"ephemeral/{repo}",
                       "persistent": False,
                       "note": "per-run scratch only; this repo stores no private or shareable memory"},
            "budget": {"wall_clock_s": budget_s},
            "lifecycle": {"state": "created", "history": [{"state": "created", "at": _now()}]},
            "created_at": _now(),
        }

    # ── lifecycle ────────────────────────────────────────────────────────
    def _transition(self, state, **extra):
        if state not in STATES:
            raise ValueError(f"unknown state {state!r}")
        if self.data["lifecycle"]["state"] in ("completed", "failed"):
            raise RuntimeError("profile is final; start a new run instead of reopening it")
        entry = {"state": state, "at": _now()}
        entry.update({k: v for k, v in extra.items() if v is not None})
        self.data["lifecycle"]["state"] = state
        self.data["lifecycle"]["history"].append(entry)
        return self

    def start(self):
        return self._transition("running")

    def finish(self, status="completed", findings=None, receipt_id=None):
        return self._transition(status, findings=findings, receipt_id=receipt_id)

    def fail(self, reason):
        return self._transition("failed", reason=reason)

    # ── io ───────────────────────────────────────────────────────────────
    def to_dict(self):
        return json.loads(json.dumps(self.data))

    def write(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=1)
        os.replace(tmp, path)
        return path

    def summary(self):
        d = self.data
        return (f"{d['profile_id']} state={d['lifecycle']['state']} "
                f"tools={d['skills']['count']} caps={len(d['permissions']['capabilities'])} "
                f"principal={'unresolved' if d['agent']['principal'] is None else d['agent']['principal']}")


def validate(doc):
    """Structural check; returns a list of problems (empty = valid)."""
    p = []
    for key in ("profile_version", "profile_id", "agent", "goal", "skills",
                "permissions", "memory", "budget", "lifecycle"):
        if key not in doc:
            p.append(f"missing {key}")
    lc = doc.get("lifecycle", {})
    if lc.get("state") not in STATES:
        p.append(f"bad lifecycle state {lc.get('state')!r}")
    hist = lc.get("history") or []
    if not hist:
        p.append("lifecycle history is empty")
    else:
        seen = [h.get("state") for h in hist]
        for i in range(1, len(seen)):
            if seen[i] == seen[i - 1]:
                p.append(f"lifecycle repeated state {seen[i]!r}")
        if seen[-2:] == ["started", "created"]:
            p.append("lifecycle went backwards")
    if doc.get("agent", {}).get("principal") is None and not doc["agent"].get("principal_note"):
        p.append("an unresolved principal must say why")
    if not doc.get("permissions", {}).get("capabilities"):
        p.append("no capabilities declared")
    return p


if __name__ == "__main__":
    import sys
    prof = RunProfile("demo-repo", "demo goal", tools=["sqlmap", "nuclei", "strix"])
    prof.start().finish("completed", findings=0, receipt_id="deadbeef")
    print(prof.summary())
    print("problems:", validate(prof.to_dict()) or "none")
    sys.exit(0 if not validate(prof.to_dict()) else 1)
