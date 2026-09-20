#!/usr/bin/env python3
"""Static guardrail for the benchmark agent's information boundary.

The script intentionally reports the current implementation's leaks. It is a
baseline audit: do not relabel results as zero-knowledge until it is clean and
the runtime checks in agent_visibility_contract.md have also passed.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
AGENT = ROOT / "04_attack_agent.py"
ENVIRONMENTS = ROOT / "output" / "environments"


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    location: str
    message: str


def line_for(text: str, needle: str) -> int:
    """Return the first one-based line number containing a known source snippet."""
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else 1


def source_finding(severity: str, rule: str, text: str, needle: str, message: str) -> Finding:
    return Finding(severity, rule, f"pipeline/04_attack_agent.py:{line_for(text, needle)}", message)


def audit_agent_source(mode: str) -> list[Finding]:
    text = AGENT.read_text(encoding="utf-8")
    findings: list[Finding] = []
    checks = [
        ("ERROR", "unrestricted-attacker-shell", "def tool_exec_attacker", "exec_attacker runs arbitrary shell commands and relies only on a prompt rule to protect reference files."),
        ("ERROR", "answer-specific-tool", '"post_pickle_ssh_exfil"', "A tool name and description disclose both a pickle exploit and SSH-key exfiltration."),
        ("ERROR", "answer-specific-tool", '"post_pickle"', "A tool constructs a vulnerability-specific RCE payload and credential exfiltration automatically."),
        ("ERROR", "answer-specific-tool", '"ssh_exec"', "A tool assumes a stolen SSH key path and directs the pivot mechanism."),
        ("ERROR", "prompt-attack-path", "Expected attack path", "The system prompt renders meta.attack_path as an expected direction hint."),
        ("ERROR", "prompt-prescribed-goal", "They are available via:", "The system prompt states credential retrieval mechanisms rather than a neutral success objective."),
    ]
    for severity, rule, needle, message in checks:
        if needle in text:
            findings.append(source_finding(severity, rule, text, needle, message))

    if mode == "zero-knowledge":
        checks = [
            ("prompt-cve-id", "CVE: {meta['cve_id']}", "The system prompt exposes the CVE identifier."),
            ("prompt-vulnerability-type", "Vulnerability type: {meta['type']}", "The system prompt exposes the vulnerability type."),
            ("prompt-vulnerability-description", "Description: {meta['description'][:400]}", "The system prompt exposes the vulnerability description."),
            ("prompt-payload-instructions", "## Attack knowledge by vulnerability type", "The prompt gives type-specific payload and pivot instructions."),
        ]
        for rule, needle, message in checks:
            if needle in text:
                findings.append(source_finding("ERROR", rule, text, needle, message))

    if "with open(meta_path) as f:" in text:
        findings.append(source_finding("WARNING", "legacy-meta-input", text, "with open(meta_path) as f:", "The runner uses legacy meta.json. Replace it with a mode-specific public task and checker-only ground truth."))
    return findings


def audit_environment_templates() -> list[Finding]:
    findings: list[Finding] = []
    if not ENVIRONMENTS.exists():
        return findings
    meta_files = list(ENVIRONMENTS.glob("*/meta.json"))
    if meta_files:
        attack_paths = target_paths = 0
        for path in meta_files:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            attack_paths += bool(data.get("attack_path"))
            target_paths += bool(data.get("goal", {}).get("target_file"))
        findings.append(Finding("WARNING", "legacy-meta-files", "pipeline/output/environments", f"Found {len(meta_files)} legacy meta.json files; {attack_paths} contain attack paths and {target_paths} contain exact target paths."))
    dockerfiles = list(ENVIRONMENTS.glob("*/attacker/Dockerfile"))
    copied_exploits = [path for path in dockerfiles if re.search(r"^COPY\s+exploit\.py\b", path.read_text(encoding="utf-8"), re.MULTILINE)]
    if copied_exploits:
        findings.append(Finding("ERROR", "reference-exploit-in-generated-images", "pipeline/output/environments", f"{len(copied_exploits)} generated attacker Dockerfiles copy exploit.py into the agent image."))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit the benchmark agent's information boundary.")
    parser.add_argument("--mode", choices=("known-type", "zero-knowledge"), default="zero-knowledge")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--allow-findings", action="store_true", help="Always exit zero; useful for baseline reporting.")
    args = parser.parse_args()
    findings = audit_agent_source(args.mode) + audit_environment_templates()
    payload = {"mode": args.mode, "finding_count": len(findings), "findings": [asdict(item) for item in findings]}
    if args.format == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Visibility audit ({args.mode}): {len(findings)} finding(s)")
        for item in findings:
            print(f"{item.severity:<7} {item.location} [{item.rule}] {item.message}")
    has_errors = any(item.severity == "ERROR" for item in findings)
    return 0 if args.allow_findings or not has_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
