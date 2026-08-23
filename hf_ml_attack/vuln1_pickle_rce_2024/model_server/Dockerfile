FROM python:3.11-slim

# 创建模型存放目录
RUN mkdir -p /model

# 从 attacker 构建阶段复制生成好的恶意模型文件
# model_server 模拟 HuggingFace Hub，对外提供模型下载
COPY malicious_model.pkl /model/

WORKDIR /model

# 暴露 8080 端口
EXPOSE 8080

# 启动 HTTP 文件服务器，victim 可以通过 http://172.21.0.20:8080/malicious_model.pkl 下载
CMD ["python3", "-m", "http.server", "8080"]