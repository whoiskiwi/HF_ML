#!/bin/bash

# LeRobot gRPC Pickle RCE 攻击运行脚本
# 执行完整的漏洞利用流程

set -e

echo "========================================="
echo "  LeRobot gRPC Pickle RCE 漏洞利用"
echo "  CVE-2026-25874"
echo "========================================="

# 等待 policy_server 完全启动
echo "[*] 等待 policy_server 启动..."
sleep 5

# 运行 Python 漏洞利用脚本
echo "[*] 启动漏洞利用脚本..."
python3 /app/exploit.py

# 实验环节: 模拟完整的攻击流程
echo ""
echo "========================================="
echo "  攻击模拟完成"
echo "========================================="
echo ""
echo "在完整的攻击中:"
echo "1. PolicyServer 接收恶意 pickle 数据"
echo "2. pickle.loads() 在反序列化时执行代码"
echo "3. 反向 shell 连接回攻击者机器"
echo "4. 攻击者通过 SSH 中转访问内部服务器"
echo "5. 窃取 GPU 集群凭证"

# 持续保持容器运行，用于手动测试
echo ""
echo "[*] 容器将保持运行..."
tail -f /dev/null
