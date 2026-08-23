#!/bin/bash

# ============================================================
# vuln1_pickle_rce_2024 构建脚本
#
# 问题：model_server 需要用到 attacker 生成的 malicious_model.pkl
# 但 Docker 构建时不同服务之间不能直接共享文件
# 解决方案：先单独构建 attacker，把 pkl 文件提取出来，再整体启动
# ============================================================

echo "Step 1: 构建 attacker 镜像，生成 malicious_model.pkl..."
docker build -t vuln1-attacker-builder ./attacker

echo "Step 2: 从 attacker 镜像中提取 malicious_model.pkl 到 model_server 目录..."
# 创建一个临时容器（不运行），只是为了复制文件
docker create --name tmp-attacker vuln1-attacker-builder
docker cp tmp-attacker:/model/malicious_model.pkl ./model_server/malicious_model.pkl
# 删除临时容器
docker rm tmp-attacker

echo "malicious_model.pkl 已复制到 model_server/"

echo "Step 3: 启动所有容器..."
docker compose up --build
