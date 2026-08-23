"""
Incident Deep Research Agent — Entry Point

运行方式:
  cd /Users/chenqi/Desktop/HF_ML/incident_research_agent
  pip install -r requirements.txt
  python main.py
"""

from agent import run_agent

TASK = """\
Complete the following two tasks in order.

---

## Task 1: Verify and complete Vuln3 documentation + generate Docker environment
### CVE-2026-25874 — LeRobot gRPC Pickle RCE (April 2026)

Steps:
1. Read the existing Vuln3 section in HF-vulnerability.md
2. Search the web for "CVE-2026-25874 LeRobot gRPC" — at least 2 different searches
3. Fetch primary source URLs to verify: CVSS score, affected versions, fix status
4. Update HF-vulnerability.md only if information is missing or inaccurate (preserve existing verified content)
5. Generate a complete Docker environment at:
   /Users/chenqi/Desktop/HF_ML/hf_ml_attack/vuln3_lerobot_grpc_2026/

Docker design for Vuln3 (gRPC pickle RCE):
- attacker (172.23.0.10): has grpcio installed, runs exploit.py that sends malicious pickle to the PolicyServer
- policy_server (172.23.0.20): simulates the vulnerable LeRobot PolicyServer — a gRPC server that calls pickle.loads() on received data without authentication. Port 50051 exposed.
- internal_server (172.23.0.30): SSH server holding sensitive data (simulates GPU cluster credentials), accessible only from policy_server via SSH key
- Attack path: attacker → gRPC pickle RCE → policy_server → SSH lateral move → internal_server → steal credentials
- Use subnet 172.23.0.0/24
- Success: attacker reads /internal/gpu_credentials.json from internal_server

Implement the vulnerable gRPC server with a minimal Python gRPC server (no need to install actual lerobot). The server should:
- Accept gRPC connections on port 50051 with no authentication
- Deserialize received bytes with pickle.loads()
- This simulates the vulnerable SendPolicyInstructions handler

---

## Task 2: Research Vuln4 and generate Docker environment
### CVE-2026-4372 — Transformers Config File Injection RCE (June 2026)

Steps:
1. Read the existing Vuln4 section in HF-vulnerability.md
2. Search the web for "CVE-2026-4372 HuggingFace Transformers config injection" — at least 2 searches
3. Fetch the original CSO Online article to verify technical details
4. Update HF-vulnerability.md if information is missing
5. Generate a complete Docker environment at:
   /Users/chenqi/Desktop/HF_ML/hf_ml_attack/vuln4_transformers_config_2026/

Docker design for Vuln4 (config file injection):
- attacker (172.24.0.10): hosts a malicious model repository via HTTP (simulates HuggingFace Hub). Serves a config.json with _attn_implementation_internal pointing to an attacker-controlled kernel URL. Also serves a simple malicious kernel (__init__.py) that runs a reverse shell.
- victim (172.24.0.30): data scientist machine with transformers + kernels installed. Has a script that periodically loads a model from the attacker's model server, triggering the config injection. Also stores sensitive credentials as the goal artifact.
- Attack path: victim downloads model → transformers reads config.json → _attn_implementation_internal triggers kernel download → kernel __init__.py executes → reverse shell to attacker
- Use subnet 172.24.0.0/24
- Since the actual "kernels" package behavior is complex to reproduce, simulate it: the victim's load_model.py manually implements the vulnerable logic (downloads and exec()s the kernel __init__.py) to demonstrate the attack concept
- Success: attacker reads victim's ~/.huggingface/token and ~/.aws/credentials

---

After completing both tasks, provide a summary of:
- What information was verified/updated in HF-vulnerability.md
- What Docker environments were created and their file structure
- Any information that could not be verified from primary sources
"""

if __name__ == "__main__":
    print("=" * 60)
    print("Incident Deep Research Agent")
    print("Model: claude-sonnet-4-6")
    print("=" * 60)

    result = run_agent(TASK, max_iterations=80, verbose=True)

    print("\n" + "=" * 60)
    print("FINAL RESULT")
    print("=" * 60)
    print(result)
