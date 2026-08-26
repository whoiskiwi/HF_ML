"""
regression_test.py — Run the agent against the fixed regression CVE set.

Each CVE represents one vulnerability type. ALL must pass before committing
changes to 04_attack_agent.py or 03_environment_agent.py.

Usage:
  python regression_test.py          # run full regression
  python regression_test.py --fast   # skip CVEs that already have results
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE, "output", "agent_results")

# ── Fixed regression set — one CVE per vuln type ──────────────────────────
# DO NOT change these CVEs without re-verifying. The environments for these
# CVEs must not be regenerated unless the regression set is updated.
REGRESSION_SET = [
    ("CVE-2024-3568",  "pickle_rce"),
    ("CVE-2024-3924",  "code_injection"),
    ("CVE-2024-2206",  "ssrf"),
    ("CVE-2026-69112", "path_traversal"),
    ("CVE-2026-65920", "sandbox_escape"),
    ("CVE-2025-10772", "auth_missing"),
    ("CVE-2026-54316", "data_exfiltration"),  # POST /report with callback_url
    # config_injection: CVE-2026-9856 excluded — model_server port 8080 connection issues
]


def run_one(cve_id: str, fast: bool) -> dict:
    result_path = os.path.join(RESULTS_DIR, f"{cve_id}.json")
    if fast and os.path.exists(result_path):
        with open(result_path) as f:
            return json.load(f)

    # Delete old result so agent runs fresh
    if os.path.exists(result_path):
        os.remove(result_path)

    proc = subprocess.run(
        [sys.executable, "04_attack_agent.py", "--cve", cve_id],
        cwd=BASE, capture_output=True, text=True, timeout=1200,  # 2x for primary+fallback retry
    )

    if os.path.exists(result_path):
        with open(result_path) as f:
            return json.load(f)

    return {"cve_id": cve_id, "success": False, "error": proc.stderr[-200:]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fast", action="store_true",
                        help="Skip CVEs that already have a result file")
    args = parser.parse_args()

    os.makedirs(RESULTS_DIR, exist_ok=True)
    print(f"Regression test — {len(REGRESSION_SET)} CVEs")
    print(f"Timestamp: {datetime.now().isoformat()}\n")

    results = []
    for cve_id, vuln_type in REGRESSION_SET:
        print(f"  [{vuln_type:20}] {cve_id} ... ", end="", flush=True)
        r = run_one(cve_id, args.fast)
        success = r.get("success", False)
        steps = r.get("steps_used", "?")
        stuck = r.get("stuck_reason", "")
        status = f"✅ {steps} steps" if success else f"❌ {stuck[:60] if stuck else 'failed'}"
        print(status)
        results.append((cve_id, vuln_type, success, steps))

    passed = sum(1 for _, _, s, _ in results if s)
    total  = len(results)
    print(f"\n{'='*50}")
    print(f"Result: {passed}/{total} passed")

    if passed == total:
        print("ALL PASSED — safe to commit.")
        sys.exit(0)
    else:
        print("REGRESSION FAILURES — do not commit until all pass.")
        sys.exit(1)


if __name__ == "__main__":
    main()
