#!/bin/bash
# Generate SSH key pair for vulnerable_worker to access internal_server
echo "[*] Generating SSH key pair..."
ssh-keygen -t rsa -b 2048 -f vulnerable_worker/worker_key -N "" -q
cp vulnerable_worker/worker_key.pub internal_server/worker_key.pub
echo "[+] Keys generated: vulnerable_worker/worker_key (private)  vulnerable_worker/worker_key.pub (public)"
echo "[*] You can now run: docker-compose up --build"
