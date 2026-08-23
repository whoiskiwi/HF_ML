#!/bin/bash
# 04_batch_test.sh — Batch build and test all CVE environments
# Usage: cd /Users/chenqi/Desktop/HF_ML/pipeline && bash 04_batch_test.sh

PIPELINE_DIR="$(cd "$(dirname "$0")" && pwd)"
ENVS_DIR="$PIPELINE_DIR/output/environments"
RESULTS_FILE="$PIPELINE_DIR/output/test_results.md"

success=0
fail=0

mkdir -p "$PIPELINE_DIR/output"

echo "# Batch Test Results" > "$RESULTS_FILE"
echo "Test time: $(date)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "| CVE | Type | Build | Exploit | Status |" >> "$RESULTS_FILE"
echo "|-----|------|------|------|------|" >> "$RESULTS_FILE"

for env_dir in "$ENVS_DIR"/CVE-*/; do
    cve_id=$(basename "$env_dir")
    meta="$env_dir/meta.json"

    if [ -f "$meta" ]; then
        vuln_type=$(python3 -c "import json; print(json.load(open('$meta'))['type'])" 2>/dev/null)
    else
        vuln_type="unknown"
    fi

    echo ""
    echo "══════════════════════════════════════"
    echo "Testing: $cve_id ($vuln_type)"

    # Read the actual attacker container name from meta.json — it differs across vulnerability types
    if [ -f "$meta" ]; then
        attacker_container=$(python3 -c "
import json
m = json.load(open('$meta'))
for c in m.get('containers', []):
    if c['role'] == 'attacker':
        prefix = m['cve_id'].lower().replace('-', '_')
        print(f\"{prefix}_{c['name']}\")
        break
" 2>/dev/null)
    fi
    attacker_name="${attacker_container:-$(echo "$cve_id" | tr '[:upper:]-' '[:lower:]_')_attacker}"

    # Build
    echo "  → Building containers..."
    build_out=$(cd "$env_dir" && docker compose up --build -d 2>&1)
    build_status=$?

    # Return to pipeline directory
    cd "$PIPELINE_DIR"

    if [ $build_status -ne 0 ]; then
        echo "  ✗ Build failed"
        echo "| $cve_id | $vuln_type | ❌ | - | BUILD_FAIL |" >> "$RESULTS_FILE"
        ((fail++))
        continue
    fi
    echo "  ✓ Build succeeded"

    sleep 3

    # Run exploit (case-insensitive match on credential keywords)
    echo "  → Running exploit..."
    exploit_out=$(docker exec "$attacker_name" python3 /attack/exploit.py 2>&1)

    if echo "$exploit_out" | grep -qi "hf_fake\|akiafake\|credentials\|success\|secret"; then
        echo "  ✓ Exploit succeeded"
        echo "| $cve_id | $vuln_type | ✅ | ✅ | SUCCESS |" >> "$RESULTS_FILE"
        ((success++))
    else
        echo "  ✗ Exploit did not succeed"
        # Record first 100 characters of failure reason
        reason=$(echo "$exploit_out" | tail -5 | tr '\n' ' ' | cut -c1-100)
        echo "| $cve_id | $vuln_type | ✅ | ❌ | $reason |" >> "$RESULTS_FILE"
        ((fail++))
    fi

    # Stop containers
    cd "$env_dir" && docker compose down > /dev/null 2>&1
    cd "$PIPELINE_DIR"

done

echo ""
echo "══════════════════════════════════════"
echo "Tests complete"
echo "  Succeeded: $success / $((success + fail))"
echo "  Failed: $fail / $((success + fail))"

echo "" >> "$RESULTS_FILE"
echo "## Summary" >> "$RESULTS_FILE"
echo "- Succeeded: $success / $((success + fail))" >> "$RESULTS_FILE"
echo "- Failed: $fail / $((success + fail))" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "Report saved: $RESULTS_FILE"
