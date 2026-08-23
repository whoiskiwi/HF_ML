FROM python:3.11-slim

# 安装 requests，用于发送 HTTP 请求执行攻击
RUN pip install requests

WORKDIR /attack
COPY attack.py .

# 保持容器运行，攻击者手动执行 attack.py
CMD ["bash"]
