FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    netcat-traditional \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN pip install requests

WORKDIR /attack
COPY attack.py .
COPY malicious_dataset/ ./malicious_dataset/

CMD ["bash"]
