FROM python:3.11-slim

# 安装 cron，用于设置定时任务自动加载模型（模拟数据科学家的日常工作流）
RUN apt-get update && apt-get install -y cron && rm -rf /var/lib/apt/lists/*

# 安装 requests（用于下载模型文件）
# pickle 是 Python 内置模块，不需要额外安装
RUN pip install requests

# 植入伪造的凭证文件，模拟真实数据科学家机器上的敏感信息
# 这些是攻击者获得 shell 后的目标文件
RUN mkdir -p /root/.huggingface /root/.aws /root/.ssh
# HuggingFace API token
COPY secrets/hf_token /root/.huggingface/token
# AWS 访问密钥
COPY secrets/aws_credentials /root/.aws/credentials
# SSH 私钥
COPY secrets/ssh_key /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa

WORKDIR /app
COPY load_model.py .

# 设置定时任务：每分钟自动运行一次 load_model.py
COPY crontab.txt /etc/cron.d/load-model
RUN chmod 0644 /etc/cron.d/load-model && crontab /etc/cron.d/load-model

# 启动 cron 守护进程
CMD ["cron", "-f"]