FROM python:3.11-slim

WORKDIR /app
COPY repo_server.py .

# 暴露 9090 端口，对外提供私有仓库服务
EXPOSE 9090

CMD ["python3", "repo_server.py"]
