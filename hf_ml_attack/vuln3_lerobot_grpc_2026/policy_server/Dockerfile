# 易受攻击的 LeRobot PolicyServer - 模拟 LeRobot 0.4.3
# 关键特性:
# - gRPC 服务器在 50051 端口 (无 TLS, 无身份验证)
# - SendPolicyInstructions RPC 处理器调用 pickle.loads()
# - 包含 SSH 服务器用于横向移动演示

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    openssh-server \
    openssh-client \
    openssh-keygen \
    netcat-openbsd \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    grpcio==1.63.0 \
    grpcio-tools==1.63.0 \
    protobuf==5.26.1

# 准备 SSH 服务器
RUN mkdir -p /var/run/sshd
RUN mkdir -p /root/.ssh

EXPOSE 50051 22 5555

CMD ["/bin/bash"]
