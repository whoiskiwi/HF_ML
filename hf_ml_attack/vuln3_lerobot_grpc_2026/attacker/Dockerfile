# 攻击者机器 - LeRobot gRPC Pickle RCE 攻击脚本运行环境
# 依赖: grpcio, protobuf, ssh-client

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    openssh-client \
    netcat-openbsd \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    grpcio==1.63.0 \
    grpcio-tools==1.63.0 \
    protobuf==5.26.1

EXPOSE 5555

CMD ["/bin/bash"]
