#!/bin/bash
# Strix wrapper for Vantage code pipeline
# Usage: strix_scan.sh <repo_path> [--quick]
# Posts findings to Vantage code scan endpoint

REPO_PATH="$1"
SCAN_MODE="${2:---scan-mode quick}"
# Model: DeepSeek is dead; the live free-pool model on litellm :8300 is
# gemini-flash-lite (same default as strix_pipeline_v4.py). Override via env.
STRIX_LLM="${STRIX_LLM:-openai/free-pool}"
# Keys are never hardcoded: env first, then the on-box key files. A missing
# litellm key file means the caller must export LLM_API_KEY themselves.
if [ -z "${LLM_API_KEY:-}" ] && [ -r /opt/ares/.litellm_key ]; then
  LLM_API_KEY=$(cat /opt/ares/.litellm_key)
fi
LLM_API_KEY="${LLM_API_KEY:-}"
VANTAGE_URL="http://localhost:8001"
VANTAGE_KEY="${VANTAGE_KEY:-$(cat /opt/ares/.vantage_key 2>/dev/null || echo '')}"
REPO_NAME=$(basename "$REPO_PATH")
RUN_ID="strix-$(date +%Y%m%d-%H%M%S)"

export STRIX_LLM LLM_API_KEY

echo "=== Strix Scan: $REPO_NAME ==="
echo "Mode: $SCAN_MODE | Model: $STRIX_LLM | Run: $RUN_ID"

# Run Strix headless
cd /opt/ares/strix
strix -n --target "$REPO_PATH" --scan-mode "$SCAN_MODE" 2>&1 | tee "/tmp/${RUN_ID}.log"

# Check for findings
FINDINGS_DIR="strix_runs"
if [ -d "$FINDINGS_DIR" ]; then
    LATEST=$(ls -t "$FINDINGS_DIR" 2>/dev/null | head -1)
    if [ -n "$LATEST" ]; then
        FINDINGS_FILE="$FINDINGS_DIR/$LATEST/report.json"
        if [ -f "$FINDINGS_FILE" ]; then
            VULN_COUNT=$(python3 -c "import json; d=json.load(open('$FINDINGS_FILE')); print(len(d.get('findings',[])))" 2>/dev/null || echo "?")
            echo "Findings: $VULN_COUNT vulnerabilities in $FINDINGS_FILE"
            
            # Post summary to Vantage feed
            curl -s -X POST "$VANTAGE_URL/api/agents/posts/text" \
              -H "Content-Type: application/json" \
              -H "X-Agent-Key: $VANTAGE_KEY" \
              -d "{\"title\":\"Strix Scan: $REPO_NAME\",\"content\":\"Scanned $REPO_NAME with Strix. $VULN_COUNT findings. Run: $RUN_ID\",\"tags\":[\"strix\",\"security\",\"code\"],\"status\":\"published\",\"content_type\":\"text\"}" > /dev/null
        fi
    fi
fi

echo "=== DONE: $RUN_ID ==="
