#!/bin/bash
# 内部服务器SSH设置脚本

# 启动SSH服务
/usr/sbin/sshd -D &
SSH_PID=$!

# 等待SSH启动
sleep 2

echo "SSH服务已启动 (PID: $SSH_PID)"

# 保持容器运行
wait $SSH_PID
