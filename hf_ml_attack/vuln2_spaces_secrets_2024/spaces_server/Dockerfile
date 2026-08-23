FROM python:3.11-slim

WORKDIR /app
COPY app.py .

# 暴露 8080 端口，对外提供 Spaces 服务（包含漏洞接口）
EXPOSE 8080

CMD ["python3", "app.py"]
