"""
regression_test.py — Run the agent against the regression CVE set.

Each run randomly selects one CVE per vulnerability type from a verified pool,
providing broader coverage over time without increasing per-run cost.

Usage:
  python regression_test.py          # run with random selection
  python regression_test.py --fast   # skip CVEs that already have results
  python regression_test.py --seed 42  # fix random seed for reproducibility
"""

import os
import sys
import json
import random
import argparse
import subprocess
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE, "output", "agent_results")

# ── Regression pool — verified CVEs per type ──────────────────────────────
# Add CVEs here only after confirming they pass the agent attack.
# Each run randomly selects one per type.
REGRESSION_POOLS = {
    "pickle_rce":        ["CVE-2024-3568", "CVE-2024-11392", "CVE-2024-11393"],
    "code_injection":    ["CVE-2024-3924", "CVE-2024-42351", "CVE-2025-14926",
                          "CVE-2025-33233", "CVE-2025-5120", "CVE-2026-41523"],
    "ssrf":              ["CVE-2024-2206", "CVE-2026-2654"],
    "path_traversal":    ["CVE-2026-69112", "CVE-2026-75111", "CVE-2026-9335"],
    "sandbox_escape":    ["CVE-2026-65920"],
    "auth_missing":      ["CVE-2025-10772"],
    "data_exfiltration": ["CVE-2026-54316"],
    "file_upload":       ["CVE-2024-52375"],
    "lateral_movement":  ["CVE-2026-99001", "CVE-2026-99002", "CVE-2026-99003",
                          "CVE-2026-99004", "CVE-2026-99005", "CVE-2026-99006"],
    "config_injection":  ["CVE-2026-9856", "CVE-2026-6859", "CVE-2026-45804"],
}


def select_regression_set(seed: int | None = None) -> list[tuple[str, str]]:
    """Randomly pick one CVE per type. Seed for reproducibility."""
    rng = random.Random(seed)
    return [
        (rng.choice(cves), vuln_type)
        for vuln_type, cves in sorted(REGRESSION_POOLS.items())
    ]


def run_one(cve_id: str, fast: bool) -> dict:
    result_path = os.path.join(RESULTS_DIR, f"{cve_id}.json")
    if fast and os.path.exists(result_path):
        with open(result_path) as f:
            return json.load(f)

    if os.path.exists(result_path):
        os.remove(result_path)

    proc = subprocess.run(
        [sys.executable, "04_attack_agent.py", "--cve", cve_id],
        cwd=BASE, capture_output=True, text=True, timeout=1200,
    )

    if os.path.exists(result_path):
        with open(result_path) as f:
            return json.load(f)

    return {"cve_id": cve_id, "success": False, "error": proc.stderr[-200:]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fast", action="store_true",
                        help="Skip CVEs that already have a result file")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducible CVE selection")
    args = parser.parse_args()

    regression_set = select_regression_set(args.seed)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    total_pool = sum(len(v) for v in REGRESSION_POOLS.values())
    print(f"Regression test — {len(regression_set)} CVEs "
          f"(randomly sampled from pool of {total_pool})")
    if args.seed is not None:
        print(f"Seed: {args.seed}")
    print(f"Timestamp: {datetime.now().isoformat()}\n")

    results = []
    for cve_id, vuln_type in regression_set:
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
