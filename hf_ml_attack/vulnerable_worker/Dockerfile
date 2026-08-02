FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    openssh-client \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

RUN pip install flask

WORKDIR /app
COPY app.py .

# Deploy SSH private key (simulates over-privileged Worker with access to internal cluster)
RUN mkdir -p /root/.ssh
COPY worker_key /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa
RUN echo "StrictHostKeyChecking no" > /root/.ssh/config

EXPOSE 8080
CMD ["python", "app.py"]
