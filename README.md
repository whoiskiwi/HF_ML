# HuggingFace Vulnerability Benchmark Pipeline

An automated pipeline that collects real-world HuggingFace CVEs, generates Docker attack environments for each one, and evaluates whether an autonomous AI agent can exploit them without being told how.

## What This Does

```
Input:  Company name + date range (HuggingFace, 2024–2026)
           ↓
Step 1  01_research.py          — Fetch CVEs from NVD + GitHub GHSA
           ↓
Step 2  02_process.py           — Classify and filter → structured vulns.json
           ↓
Step 3  03_environment_agent.py — Auto-generate Docker attack environments (LLM: DeepSeek V3)
           ↓
Step 4  04_attack_agent.py      — Autonomous AI attacker (LLM: DeepSeek R1)
           ↓
Output: Per-CVE attack results with success/failure, steps taken, credentials found
```

## Current Results (2026-09-02)

| Metric | Value |
|--------|-------|
| CVEs collected | 86 |
| Docker environments generated | 72 |
| Vulnerability types covered | 10 |
| Full batch attack success | **71/72 (98.6%)** |
| Regression test (AI agent) | **10/10 passed** (random pool of 27 CVEs) |

### Full Batch Results — AI Agent Success by Vulnerability Type

| Type | Success | Pass Rate |
|------|---------|-----------|
| auth_missing | 1/1 | 100% |
| code_injection | 28/28 | 100% |
| config_injection | 3/3 | 100% |
| data_exfiltration | 1/1 | 100% |
| file_upload | 1/1 | 100% |
| lateral_movement | 6/6 | 100% |
| path_traversal | 8/8 | 100% |
| pickle_rce | 21/21 | 100% |
| sandbox_escape | 1/1 | 100% |
| ssrf | 1/2 | 50% (1 timing fluke) |
| **Total** | **71/72** | **98.6%** |

## Architecture

### Pipeline Scripts

| Script | Role | Model |
|--------|------|-------|
| `01_research.py` | Fetch CVEs from NVD + GHSA | — |
| `02_process.py` | Classify, filter, output vulns.json | — |
| `03_environment_agent.py` | Generate Docker environments | DeepSeek V3 |
| `04_attack_agent.py` | Autonomous attack agent | DeepSeek R1 (+ R1-Distill-32B fallback) |
| `regression_test.py` | Randomised regression suite (10 CVEs, 1 per type) | — |

### Environment Structure (per CVE)

```
pipeline/output/environments/{cve_id}/
├── docker-compose.yml     # Network topology + containers
├── attacker/              # Attacker container (exfil server on :9999)
├── victim/                # Vulnerable Flask service
├── internal/              # Internal server (holds credentials)
├── attack/exploit.py      # Reference exploit (not shown to AI agent)
└── meta.json              # Structured attack path (step, from, to, action)
```

### Network Topology

**Single-step (most types):**
```
[attacker]  172.x.0.10    exfil server :9999
     ↓
[victim]    172.x.0.20    vulnerable service :8080
     ↓
[internal]  172.x.0.30    credential store
```

**Multi-step lateral movement:**
```
[attacker]  172.x.0.10    exfil server + SSH client
     ↓  pickle RCE → steal SSH key
[worker]    172.x.0.20    vulnerable worker (holds SSH key to internal)
     ↓  SSH pivot with stolen key
[internal]  172.x.0.30    SSH server (holds target credentials)
```

## Agent Tools

| Tool | Purpose |
|------|---------|
| `scan_endpoints` | Wordlist-based endpoint discovery |
| `probe_http` | GET probe |
| `post_http` | POST payload |
| `post_pickle` | Auto-generate pickle RCE payload + POST |
| `post_pickle_ssh_exfil` | Pickle payload that steals SSH key |
| `check_ssh_key` | Check if stolen SSH key arrived at exfil |
| `ssh_exec` | SSH into internal server with stolen key |
| `exec_attacker` | Shell command inside attacker container |
| `check_exfil` | Check exfil server for stolen credentials |

## Key Design Decisions

**Simulated vs. Realistic environments**: All 72 environments are simulated (Flask services that mimic vulnerability behavior, not real affected packages). This avoids GPU/CUDA dependencies and enables fast batch generation.

**AI agent cheating prevention**: The `/credentials` framework endpoint is blocked via `_BLOCKED_PATHS` — the agent must exploit the actual vulnerability.

**Robustness**: Primary model (DeepSeek R1) + automatic fallback to R1-Distill-32B on failure. Exfil server filters non-credential test data.

**Attack path consistency**: `validate_attack_path_consistency()` statically checks that `meta.json` attack_path fields match actual service.py endpoints. On mismatch, re-generates attack_path with real route/field hints (zero token cost on happy path).

**Randomised regression**: Each regression run randomly samples 1 CVE per vulnerability type from a verified pool of 27 CVEs, providing broader coverage over multiple runs without increasing per-run cost.

## Origin

This project began as a manual reproduction of the HuggingFace July 2026 AI agent intrusion incident (`hf_ml_attack/`), where an autonomous AI agent performed pickle RCE + SSH lateral movement to exfiltrate internal credentials. That single hand-crafted scenario was the prototype; this pipeline generalizes it to 72 real CVEs automatically.

## Requirements

- Docker Desktop
- Python 3.12+
- Portkey account with DeepInfra configured (`pipeline/.env`)

## Usage

```bash
cd pipeline

# Run full pipeline
python 01_research.py
python 02_process.py
python 03_environment_agent.py
python 04_attack_agent.py

# Run regression test (random CVE selection per type)
python regression_test.py

# Run with fixed seed for reproducibility
python regression_test.py --seed 42

# Attack a specific CVE or type
python 04_attack_agent.py --cve CVE-2024-3568
python 04_attack_agent.py --type lateral_movement
```

## Disclaimer

For academic security research only. All attacks target isolated local Docker environments. Do not use against real systems without explicit authorization.
