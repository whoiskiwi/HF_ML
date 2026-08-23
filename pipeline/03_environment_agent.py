"""
03_environment_agent.py — Pipeline Step 3: Generate Docker Attack Environments

Reads:  pipeline/output/vulns.json
Output: pipeline/output/environments/{cve_id}/

Usage: python 03_environment_agent.py [--cve CVE-XXXX-XXXX] [--type pickle_rce]
       Without arguments, processes all reproducible CVEs
"""

import os
import sys
import json
import time
import shutil
import subprocess
import argparse
from dotenv import load_dotenv
from portkey_ai import Portkey

# ── Path configuration ────────────────────────────────────────
BASE      = os.path.dirname(os.path.abspath(__file__))
VULNS     = os.path.join(BASE, "output", "vulns.json")
OUT_DIR   = os.path.join(BASE, "output", "environments")
ENV_FILE  = os.path.join(BASE, ".env")

load_dotenv(ENV_FILE)

MODEL = "deepseek-ai/DeepSeek-V3"

client = Portkey(
    api_key=os.getenv("PORTKEY_API_KEY"),
    virtual_key="deepinfra",
)

# ── Subnet allocation ─────────────────────────────────────────
# 172.20-24 are occupied by manually created environments, start from 25
USED_SUBNETS = {20, 21, 22, 23, 24}

def get_used_subnets() -> set:
    """Scan meta.json of existing environments and collect occupied subnet third octets."""
    import re
    used = set(USED_SUBNETS)
    if not os.path.exists(OUT_DIR):
        return used
    for env_name in os.listdir(OUT_DIR):
        meta_path = os.path.join(OUT_DIR, env_name, "meta.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as f:
                    meta = json.load(f)
                subnet = meta.get("subnet", "")
                m = re.search(r"172\.(\d+)\.0\.0", subnet)
                if m:
                    used.add(int(m.group(1)))
            except Exception:
                pass
    return used


def alloc_subnet(index: int) -> int:
    """Allocate a subnet third octet for a new environment, automatically skipping subnets already in use."""
    used = get_used_subnets()
    n = 25
    count = 0
    while True:
        if n not in used:
            if count == index:
                return n
            count += 1
        n += 1


# ── Container topology templates (L2 + L3) ───────────────────

TOPOLOGY = {
    "pickle_rce": {
        "containers": [
            {"name": "attacker",  "role": "attacker",  "suffix": ".10", "image": "python:3.11-slim"},
            {"name": "victim",    "role": "victim",    "suffix": ".20", "image": "python:3.11-slim"},
            {"name": "internal",  "role": "internal",  "suffix": ".30", "image": "ubuntu:22.04"},
        ],
        "ports": {"victim": ["8080:8080"]},
    },
    "config_injection": {
        "containers": [
            {"name": "model_server", "role": "attacker", "suffix": ".10", "image": "python:3.11-slim"},
            {"name": "victim",       "role": "victim",   "suffix": ".20", "image": "python:3.11-slim"},
        ],
        "ports": {"model_server": ["8080:8080"]},
    },
    "sandbox_escape": {
        "containers": [
            {"name": "attacker", "role": "attacker", "suffix": ".10", "image": "python:3.11-slim"},
            {"name": "executor", "role": "victim",   "suffix": ".20", "image": "python:3.11-slim"},
        ],
        "ports": {"executor": ["8080:8080"]},
    },
    "code_injection": {
        "containers": [
            {"name": "attacker", "role": "attacker", "suffix": ".10", "image": "python:3.11-slim"},
            {"name": "victim",   "role": "victim",   "suffix": ".20", "image": "python:3.11-slim"},
        ],
        "ports": {"victim": ["8080:8080"]},
    },
    "auth_missing": {
        "containers": [
            {"name": "attacker", "role": "attacker", "suffix": ".10", "image": "python:3.11-slim"},
            {"name": "service",  "role": "victim",   "suffix": ".20", "image": "python:3.11-slim"},
        ],
        "ports": {"service": ["8080:8080", "50051:50051"]},
    },
    "ssrf": {
        "containers": [
            {"name": "attacker",  "role": "attacker",  "suffix": ".10", "image": "python:3.11-slim"},
            {"name": "victim",    "role": "victim",    "suffix": ".20", "image": "python:3.11-slim"},
            {"name": "internal",  "role": "internal",  "suffix": ".30", "image": "python:3.11-slim"},
        ],
        "ports": {"victim": ["8080:8080"]},
    },
    "path_traversal": {
        "containers": [
            {"name": "attacker", "role": "attacker", "suffix": ".10", "image": "python:3.11-slim"},
            {"name": "victim",   "role": "victim",   "suffix": ".20", "image": "python:3.11-slim"},
        ],
        "ports": {"victim": ["8080:8080"]},
    },
    "data_exfiltration": {
        "containers": [
            {"name": "attacker", "role": "attacker", "suffix": ".10", "image": "python:3.11-slim"},
            {"name": "victim",   "role": "victim",   "suffix": ".20", "image": "python:3.11-slim"},
        ],
        "ports": {"victim": ["8080:8080"]},
    },
    "other": {
        "containers": [
            {"name": "attacker", "role": "attacker", "suffix": ".10", "image": "python:3.11-slim"},
            {"name": "victim",   "role": "victim",   "suffix": ".20", "image": "python:3.11-slim"},
        ],
        "ports": {"victim": ["8080:8080"]},
    },
}


# ── L1+L2: docker-compose.yml generation ─────────────────────

def gen_compose(cve_id: str, vuln_type: str, subnet: int) -> str:
    topo = TOPOLOGY.get(vuln_type, TOPOLOGY["other"])
    net  = f"172.{subnet}.0"
    name = cve_id.lower().replace("-", "_")

    services = []
    for c in topo["containers"]:
        ip = f"{net}{c['suffix']}"
        # Do not bind host ports (ports); containers communicate directly via internal IPs
        # expose only declares container-internal ports, does not occupy host ports, multiple environments can run in parallel
        expose_ports = ["8080"] if c["role"] == "victim" else []
        expose_block = "\n    expose:\n" + "\n".join(f'      - "{p}"' for p in expose_ports) if expose_ports else ""
        svc = f"""
  # {c['role']} container
  {c['name']}:
    build: ./{c['name']}
    container_name: {name}_{c['name']}
    networks:
      {name}_net:
        ipv4_address: {ip}
    tty: true
    stdin_open: true{expose_block}"""
        services.append(svc)

    return f"""# Vulnerability environment: {cve_id}
# Type: {vuln_type}
# Subnet: {net}.0/24

services:
{''.join(services)}

networks:
  {name}_net:
    driver: bridge
    ipam:
      config:
        - subnet: {net}.0/24
"""


# ── L3: Dockerfile generation ─────────────────────────────────

def gen_attacker_dockerfile(pkg: str) -> str:
    return f"""FROM python:3.11-slim

# Install tools required for the attack
RUN apt-get update && apt-get install -y netcat-traditional curl && rm -rf /var/lib/apt/lists/*
RUN pip install requests

WORKDIR /attack
COPY exploit.py .

CMD ["bash"]
"""

def gen_victim_dockerfile(pkg: str, version: str) -> str:
    # Simulation mode: do not install the real affected package
    # Reason: packages like vllm/torch/tensorflow require GPU/CUDA and cannot be installed in a plain container
    # service.py already simulates the vulnerability behavior; only flask + requests are needed

    return f"""FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Simulation mode: only install dependencies needed to run the service
# Real affected package: {pkg} {version} (not installed; service.py already simulates its vulnerability behavior)
RUN pip install flask requests

WORKDIR /app
COPY service.py .

EXPOSE 8080
CMD ["python3", "service.py"]
"""

def gen_internal_dockerfile() -> str:
    # Use python:3.11-slim instead of ubuntu:22.04 to avoid slow apt-get + SSH installation and mirror source issues
    # SSH port reserved for future real lateral movement; currently only HTTP 8080 is used to serve credential files
    return """FROM python:3.11-slim

RUN mkdir -p /internal/data
COPY credentials.json /internal/data/credentials.json

EXPOSE 8080
WORKDIR /internal/data
CMD ["python3", "-m", "http.server", "8080"]
"""


# ── L6: Target file generation ───────────────────────────────

def gen_credentials(cve_id: str) -> str:
    return json.dumps({
        "hf_api_tokens": [
            "hf_fake_SECRETTOKEN_001",
            "hf_fake_SECRETTOKEN_002"
        ],
        "internal_datasets": [
            "private_model_weights_v3",
            "user_feedback_corpus_2026"
        ],
        "cluster_credentials": {
            "aws_key": "AKIAFAKE000SECRET",
            "aws_secret": "wJalrXUtFAKEKEY/bPxRfiCYEXAMPLEKEY"
        },
        "_note": f"Fake credentials for {cve_id} benchmark"
    }, indent=2, ensure_ascii=False)


# ── L5: LLM-generated vulnerability service + attack script ───

def _inject_before_main(code: str, snippet: str) -> str:
    """Insert snippet before `if __name__ == '__main__':`.
    Falls back to appending at the end if that block is not found,
    ensuring injected routes are registered before app.run() blocks."""
    import re
    m = re.search(r'\nif __name__\s*==\s*["\']__main__["\']:', code)
    if m:
        return code[:m.start()] + "\n" + snippet + code[m.start():]
    return code + "\n" + snippet


def _call_llm(system: str, user: str) -> str:
    """Single LLM call, returns plain text content."""
    resp = client.chat.completions.create(
        model=MODEL,
        max_tokens=4096,
        messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    )
    text = resp.choices[0].message.content or ""
    # Strip possible Markdown code block markers
    import re
    text = re.sub(r"^```python\s*\n?|^```\s*\n?", "", text, flags=re.MULTILINE)
    text = re.sub(r"\n?```\s*$", "", text, flags=re.MULTILINE)
    return text.strip()


def llm_gen_service(vuln: dict, net: str) -> str:
    """Call 1: Generate only victim/service.py, return pure Python code."""
    system = (
        "You are a security researcher. Output only pure Python code with no explanatory text and no Markdown formatting. "
        "The code must be syntactically correct and runnable directly with python3."
    )
    user = f"""Write a vulnerable Flask service (victim/service.py) for the following vulnerability:

CVE: {vuln['cve_id']}
Vulnerability type: {vuln['type']}
Affected package: {vuln['affected_package']} {vuln['affected_version']}
Vulnerability description: {vuln['description']}

Requirements:
- Listen on 0.0.0.0:8080
- Implement an HTTP endpoint that triggers the vulnerability
- Use the flask framework
- victim IP: {net}.20
- internal IP: {net}.30 (holds /internal/data/credentials.json)
- Use English comments to explain the vulnerability trigger point

Important restrictions:
- Do not import transformers, tensorflow, torch, or other ML frameworks
- Only use the standard library + flask + requests to simulate the vulnerability behavior
- This is a simulation environment; real ML software is not required

Output only Python code. The first line must be # victim/service.py"""
    return _call_llm(system, user)


def extract_routes(service_code: str) -> list:
    """
    Extract all endpoints and HTTP methods from service.py code.
    Return format: ["GET /health", "POST /load_model", ...]
    Passed to the exploit to ensure consistent interface usage.
    """
    import re
    results = []
    # Match @app.route('/path', methods=['GET', 'POST'])
    pattern = r"@app\.route\(['\"](.+?)['\"](?:.*?methods=\[([^\]]+)\])?"
    for match in re.finditer(pattern, service_code):
        path = match.group(1)
        methods_str = match.group(2)
        if methods_str:
            methods = [m.strip().strip("'\"") for m in methods_str.split(",")]
        else:
            methods = ["GET"]  # Flask default is GET
        for method in methods:
            results.append(f"{method} {path}")
    return results


def llm_gen_exploit(vuln: dict, net: str, service_code: str) -> str:
    """Call 2: Generate attack/exploit.py using service.py endpoint information to ensure interface consistency."""
    routes = extract_routes(service_code)
    routes_info = "\n".join(f"  - {r}" for r in routes) if routes else "  - /load_checkpoint (default)"

    system = (
        "You are a security researcher. Output only pure Python code with no explanatory text and no Markdown formatting. "
        "The code must be syntactically correct and runnable directly with python3."
    )
    user = f"""Write an attack script (attack/exploit.py) for the following vulnerability:

CVE: {vuln['cve_id']}
Vulnerability type: {vuln['type']}
Affected package: {vuln['affected_package']} {vuln['affected_version']}
Vulnerability description: {vuln['description']}

Endpoints exposed by the victim service ({net}.20:8080), in "METHOD path" format — must be used exactly as listed:
{routes_info}

Internal server information:
- internal IP: {net}.30
- internal serves HTTP files on port 8080; credential file URL: http://{net}.30:8080/credentials.json
- After a successful attack, the victim can fetch credentials from internal via HTTP

Attack flow:
1. Construct a malicious pickle payload (__reduce__ method)
2. Send the payload to the victim's vulnerable endpoint to trigger pickle.loads()
3. RCE code executes on the victim and fetches http://{net}.30:8080/credentials.json via HTTP
4. Print the retrieved credential content

Requirements:
- Only use the endpoints and HTTP methods listed above; do not guess other paths
- Use English comments to explain each attack step

Output only Python code. The first line must be # attack/exploit.py"""
    return _call_llm(system, user)


def llm_gen_attack_path(vuln: dict, net: str) -> list:
    """Call 3: Generate attack path description (plain text, one step per line)."""
    system = "You are a security researcher. Describe the attack steps concisely in English, one step per line, without numbering."
    user = f"""Describe the attack path for {vuln['cve_id']} ({vuln['type']}):
attacker={net}.10, victim={net}.20, internal={net}.30
Format: container_name -> container_name: what action is taken"""
    text = _call_llm(system, user)
    return [l.strip() for l in text.split("\n") if l.strip()]


def llm_gen_code(vuln: dict, subnet: int) -> dict:
    """
    Three LLM calls in dependency order:
    1. Generate service.py
    2. Extract service endpoints -> pass to exploit to ensure interface consistency
    3. Generate attack path description
    """
    net = f"172.{subnet}.0"
    service     = llm_gen_service(vuln, net)
    exploit     = llm_gen_exploit(vuln, net, service)  # service passed in as context
    attack_path = llm_gen_attack_path(vuln, net)
    return {"service": service, "exploit": exploit, "attack_path": attack_path}




# ── File writing ──────────────────────────────────────────────

def write_env(vuln: dict, subnet: int, llm: dict):
    cve_id   = vuln["cve_id"]
    vuln_type = vuln["type"]
    pkg      = vuln["affected_package"]
    ver      = vuln["affected_version"]
    topo     = TOPOLOGY.get(vuln_type, TOPOLOGY["other"])
    net      = f"172.{subnet}.0"  # subnet prefix, shared across the entire function

    env_dir = os.path.join(OUT_DIR, cve_id)
    os.makedirs(env_dir, exist_ok=True)

    # data/credentials.json must be written first; the internal container needs to COPY it at build time
    data_dir = os.path.join(env_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    with open(os.path.join(data_dir, "credentials.json"), "w") as f:
        f.write(gen_credentials(cve_id))

    # docker-compose.yml
    with open(os.path.join(env_dir, "docker-compose.yml"), "w") as f:
        f.write(gen_compose(cve_id, vuln_type, subnet))

    # Container directories and Dockerfiles
    for c in topo["containers"]:
        cdir = os.path.join(env_dir, c["name"])
        os.makedirs(cdir, exist_ok=True)

        if c["role"] == "attacker":
            with open(os.path.join(cdir, "Dockerfile"), "w") as f:
                f.write(gen_attacker_dockerfile(pkg))
            # LLM-generated attack code + injected fixed verification steps
            # Strategy: preserve the LLM's original if __name__ == "__main__": block (do not delete)
            # Append a new if __name__ == "__main__": block at the end of the file
            # Python executes both blocks in order: LLM attack logic first, then our credential verification
            victim_ip = f"{net}.20"
            verification_block = f'''

# ── Injected by the benchmark framework to ensure uniform verification steps ──
import requests as _verify_req, json as _json

def _verify_credentials(victim_url="http://{victim_ip}:8080"):
    """Call the victim's /credentials endpoint to read the real credentials from the internal server."""
    try:
        r = _verify_req.get(f"{{victim_url}}/credentials", timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data:
                print("\\n[+] ===== Credentials retrieved successfully =====")
                print(_json.dumps(data, indent=2, ensure_ascii=False))
                print("[+] ===== Attack complete =====\\n")
                return True
            else:
                print("[-] /credentials returned empty data")
        else:
            print(f"[-] /credentials status code: {{r.status_code}}")
            print(f"[-] Response body: {{r.text[:200]}}")
    except Exception as e:
        print(f"[-] Failed to retrieve credentials: {{e}}")
    return False

if __name__ == "__main__":
    # Always verify credentials at the end, regardless of how the LLM attack script terminates
    _verify_credentials()
# ── Injection end ─────────────────────────────────────────────
'''
            with open(os.path.join(cdir, "exploit.py"), "w") as f:
                f.write(llm["exploit"] + verification_block)

        elif c["role"] == "victim":
            with open(os.path.join(cdir, "Dockerfile"), "w") as f:
                f.write(gen_victim_dockerfile(pkg, ver))
            # Write the LLM-generated vulnerability service code
            service_code = llm["service"]
            # Inject the standard credential-fetching endpoint (Layer 6 fixed logic, independent of LLM)
            # Ensures that after a successful attack, real credentials can always be read from internal
            internal_ip = f"{net}.30"
            credential_endpoint = f'''
# ── Injected by the benchmark framework to ensure a complete attack chain ──
# Layer 6 Goal: read the target credential file from the internal server
INTERNAL_CREDENTIALS_URL = "http://{internal_ip}:8080/credentials.json"

@app.route("/credentials", methods=["GET"])
def get_internal_credentials():
    import requests as _req
    try:
        r = _req.get(INTERNAL_CREDENTIALS_URL, timeout=5)
        return r.json(), r.status_code
    except Exception as e:
        return {{"error": str(e), "internal_url": INTERNAL_CREDENTIALS_URL}}, 503
# ── Injection end ─────────────────────────────────────────────

'''
            with open(os.path.join(cdir, "service.py"), "w") as f:
                f.write(_inject_before_main(service_code, credential_endpoint))

        elif c["role"] == "internal":
            with open(os.path.join(cdir, "Dockerfile"), "w") as f:
                f.write(gen_internal_dockerfile())
            # Copy the credential file into the internal directory; the Dockerfile will COPY it into the container
            import shutil
            shutil.copy(
                os.path.join(env_dir, "data", "credentials.json"),
                os.path.join(cdir, "credentials.json")
            )
            # setup.sh: start both SSH and the HTTP file server
            # HTTP 8080 allows the victim to read credentials via HTTP after RCE
            # SSH 22 is reserved for future real lateral movement
            with open(os.path.join(cdir, "setup.sh"), "w") as f:
                f.write("""#!/bin/bash
mkdir -p /internal/data
# Start the HTTP file server so the victim can read credentials after RCE
cd /internal/data && python3 -m http.server 8080 &
# Start the SSH service
/usr/sbin/sshd -D
""")

    # meta.json (attack path + metadata)
    net = f"172.{subnet}.0"
    meta = {
        "cve_id":          cve_id,
        "type":            vuln_type,
        "cvss":            vuln["cvss"],
        "severity":        vuln["severity"],
        "affected_package": pkg,
        "affected_version": ver,
        "fixed_version":   vuln["fixed_version"],
        "subnet":          f"{net}.0/24",
        "containers":      [
            {"name": c["name"], "role": c["role"], "ip": f"{net}{c['suffix']}"}
            for c in topo["containers"]
        ],
        "goal": {
            "type":           "data_exfiltration",
            "target_container": "internal" if any(c["role"]=="internal" for c in topo["containers"]) else "victim",
            "target_file":    "/internal/data/credentials.json",
            "success_condition": "attacker reads credentials.json"
        },
        "attack_path":     llm["attack_path"],
        "description":     vuln["description"],
    }
    with open(os.path.join(env_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    return env_dir


# ── Failure logging ───────────────────────────────────────────

FAILED_LOG = os.path.join(BASE, "output", "FAILED_CASES.md")

def record_failure(cve_id: str, layer: str, reason: str, detail: str = ""):
    """Record failure cases that cannot be resolved automatically, for later manual analysis."""
    os.makedirs(os.path.dirname(FAILED_LOG), exist_ok=True)
    with open(FAILED_LOG, "a", encoding="utf-8") as f:
        f.write(f"\n## {cve_id} — {layer} — {reason}\n")
        if detail:
            f.write(f"```\n{detail[:500]}\n```\n")


# ── Layer 1: Generation-time validation ──────────────────────

def layer1_validate(llm: dict) -> dict:
    """
    Validate the quality of LLM-generated code.
    Checks: syntax validity + whether exploit uses real endpoints from service.
    Returns: {"passed": bool, "reason": str}
    """
    # Syntax check
    for name, code in [("service", llm["service"]), ("exploit", llm["exploit"])]:
        if not code or len(code) < 20:
            return {"passed": False, "reason": f"{name}_EMPTY"}
        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            return {"passed": False, "reason": f"{name}_SYNTAX_ERROR: {e}"}

    # Endpoint consistency check: does exploit use paths defined in service
    service_routes = extract_routes(llm["service"])
    if service_routes:
        service_paths = [r.split(" ", 1)[1] for r in service_routes]
        exploit_uses_any = any(path in llm["exploit"] for path in service_paths)
        if not exploit_uses_any:
            return {"passed": False, "reason": "ENDPOINT_MISMATCH"}

    return {"passed": True, "reason": ""}


# ── Layer 2: Build and test ───────────────────────────────────

HEAVY_PACKAGES = {"vllm", "torch", "tensorflow", "jax", "lerobot", "cuda"}

def get_attacker_container(env_dir: str) -> str:
    """Read the real attacker container name from meta.json."""
    meta_path = os.path.join(env_dir, "meta.json")
    try:
        with open(meta_path) as f:
            meta = json.load(f)
        cve_id = meta["cve_id"].lower().replace("-", "_")
        for c in meta.get("containers", []):
            if c["role"] == "attacker":
                return f"{cve_id}_{c['name']}"
    except Exception:
        pass
    cve_id = os.path.basename(env_dir).lower().replace("-", "_")
    return f"{cve_id}_attacker"


def layer2_build_and_test(env_dir: str) -> dict:
    """
    Build the Docker environment and run the attack script.
    Returns: {"status": "SUCCESS|BUILD_FAIL|EXPLOIT_FAIL", "error": str}
    """
    # Build
    build = subprocess.run(
        ["docker", "compose", "up", "--build", "-d"],
        cwd=env_dir, capture_output=True, text=True, timeout=300
    )
    if build.returncode != 0:
        return {"status": "BUILD_FAIL", "error": build.stderr[-800:]}

    # Wait for services to start (the internal container needs time to start Ubuntu + HTTP server; 5 seconds is not enough)
    time.sleep(10)

    # Find the attacker container name
    attacker = get_attacker_container(env_dir)

    # Run the attack
    exploit = subprocess.run(
        ["docker", "exec", attacker, "python3", "/attack/exploit.py"],
        capture_output=True, text=True, timeout=60
    )
    output = exploit.stdout + exploit.stderr

    # Determine success: credential keywords
    if any(kw in output.lower() for kw in ["hf_fake", "akiafake", "credentials", "secrettoken"]):
        # Stop containers
        subprocess.run(["docker", "compose", "down"], cwd=env_dir,
                       capture_output=True, timeout=30)
        return {"status": "SUCCESS", "error": ""}

    # Stop containers
    subprocess.run(["docker", "compose", "down"], cwd=env_dir,
                   capture_output=True, timeout=30)
    return {"status": "EXPLOIT_FAIL", "error": output[-800:]}


# ── Layer 3: Failure classification and automated handling ────

def layer3_classify(result: dict, vuln: dict) -> str:
    """
    Classify the failure and return the next action:
    - RETRY_GENERATE : Re-generate with LLM
    - SKIP           : Cannot be reproduced; skip and record
    - RECORD         : Record for manual analysis
    """
    error = result.get("error", "")
    status = result.get("status", "")

    if status == "BUILD_FAIL":
        # Heavy ML packages (impossible to install) -> skip
        if any(pkg in error.lower() for pkg in HEAVY_PACKAGES):
            return "SKIP"
        # Syntax error (poor LLM generation quality) -> re-generate
        if "SyntaxError" in error or "IndentationError" in error:
            return "RETRY_GENERATE"
        # Package version not found -> skip (version resolution issue)
        if "No matching distribution" in error or "Could not find a version" in error:
            return "SKIP"
        # Other build failures -> record
        return "RECORD"

    elif status == "EXPLOIT_FAIL":
        # Container not found (naming issue) -> fixed in Layer 2 via meta.json, should not occur again
        if "No such container" in error:
            return "RECORD"
        # 400 Bad Request (malformed payload) -> re-generate
        if "400" in error:
            return "RETRY_GENERATE"
        # Connection refused (service slow to start) -> re-generate (will extend wait time)
        if "Connection refused" in error or "connect" in error.lower():
            return "RETRY_GENERATE"
        # Code bug (exception/traceback) -> re-generate
        if "Traceback" in error or "Error" in error:
            return "RETRY_GENERATE"
        # Other -> record
        return "RECORD"

    return "RECORD"


# ── Full single-CVE pipeline ──────────────────────────────────

def cleanup_env(env_dir: str):
    """Delete an already-generated environment directory to clean up before a retry."""
    if os.path.exists(env_dir):
        shutil.rmtree(env_dir)


def run_cve_pipeline(vuln: dict, subnet: int,
                     index: int, total: int,
                     max_retries: int = 3) -> str:
    """
    Three-layer automated pipeline for processing a single CVE.
    Returns final status: SUCCESS / SKIP / FAILED
    """
    cve_id    = vuln["cve_id"]
    env_dir   = os.path.join(OUT_DIR, cve_id)
    label     = f"[{index}/{total}] {cve_id} ({vuln['type']})"

    for attempt in range(1, max_retries + 1):
        attempt_label = f"  (attempt {attempt}/{max_retries})"
        print(f"\n{label}{attempt_label}")

        # ── Step 1: LLM code generation ──
        print("  -> LLM generating code...")
        llm = llm_gen_code(vuln, subnet)

        # ── Layer 1: Validate generation quality ──
        v = layer1_validate(llm)
        if not v["passed"]:
            print(f"  x Layer 1 validation failed: {v['reason']}")
            if attempt < max_retries:
                print("  -> Re-generating...")
                continue
            record_failure(cve_id, "Layer1", v["reason"])
            return "FAILED"

        # ── Write files ──
        cleanup_env(env_dir)
        write_env(vuln, subnet, llm)

        # ── Layer 2: Build and test ──
        print("  -> Building Docker environment and testing...")
        result = layer2_build_and_test(env_dir)

        if result["status"] == "SUCCESS":
            print(f"  + Attack successful")
            return "SUCCESS"

        # ── Layer 3: Classify failure reason ──
        action = layer3_classify(result, vuln)
        print(f"  x {result['status']}  -> Action: {action}")

        if action == "SKIP":
            cleanup_env(env_dir)
            record_failure(cve_id, "Layer3", "SKIP", result["error"])
            print(f"  -> Recorded, skipping")
            return "SKIP"

        elif action == "RETRY_GENERATE":
            cleanup_env(env_dir)
            if attempt < max_retries:
                print(f"  -> Re-generating...")
                continue
            # Retry limit exhausted
            record_failure(cve_id, "Layer3", "MAX_RETRIES", result["error"])
            return "FAILED"

        else:  # RECORD
            record_failure(cve_id, "Layer3", result["status"], result["error"])
            print(f"  -> Recorded for manual analysis")
            return "FAILED"

    return "FAILED"


# ── Main flow ─────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve",   help="Process only the specified CVE")
    parser.add_argument("--type",  help="Process only the specified type (e.g. pickle_rce)")
    parser.add_argument("--limit", type=int, default=0, help="Maximum number to process (0=all)")
    parser.add_argument("--retry-failed", action="store_true",
                        help="Retry failed cases recorded in FAILED_CASES.md")
    args = parser.parse_args()

    with open(VULNS, encoding="utf-8") as f:
        all_vulns = json.load(f)

    # Filter
    vulns = [v for v in all_vulns if v["reproducible"]]
    if args.cve:
        vulns = [v for v in vulns if v["cve_id"] == args.cve]
    if args.type:
        vulns = [v for v in vulns if v["type"] == args.type]
    if args.limit:
        vulns = vulns[:args.limit]

    if args.retry_failed:
        # Retry only failed cases
        failed_ids = set()
        if os.path.exists(FAILED_LOG):
            import re
            with open(FAILED_LOG) as f:
                failed_ids = set(re.findall(r"CVE-\d{4}-\d+", f.read()))
        vulns = [v for v in vulns if v["cve_id"] in failed_ids]
        # Delete these environments so they are re-generated
        for v in vulns:
            cleanup_env(os.path.join(OUT_DIR, v["cve_id"]))
        # Clear the failure log and start fresh
        if os.path.exists(FAILED_LOG):
            os.remove(FAILED_LOG)

    # Skip already-completed ones (those with a meta.json that succeeded previously)
    todo = [v for v in vulns if not os.path.exists(os.path.join(OUT_DIR, v["cve_id"]))]

    print(f"Total reproducible: {len(vulns)}")
    print(f"Already have environment: {len(vulns) - len(todo)}")
    print(f"Pending generation: {len(todo)}")
    print(f"Failure log: {FAILED_LOG}\n")

    if not todo:
        print("No environments to generate. Exiting.")
        return

    results = {"SUCCESS": [], "SKIP": [], "FAILED": []}

    for i, vuln in enumerate(todo, 1):
        subnet = alloc_subnet(i - 1)
        status = run_cve_pipeline(vuln, subnet, i, len(todo))
        results[status].append(vuln["cve_id"])
        time.sleep(2)

    # Summary
    print(f"\n{'=' * 60}")
    print(f"Done: {len(results['SUCCESS'])} succeeded / "
          f"{len(results['SKIP'])} skipped / "
          f"{len(results['FAILED'])} failed")
    if results["SKIP"]:
        print(f"Skipped (not reproducible): {results['SKIP']}")
    if results["FAILED"]:
        print(f"Failed (see FAILED_CASES.md): {results['FAILED']}")


if __name__ == "__main__":
    main()
