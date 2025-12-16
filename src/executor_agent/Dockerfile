#src/executor_agent/Dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG K8S_VERSION=v1.28.4

RUN curl -L -o /usr/local/bin/kubectl \
    https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/kubectl \
    && chmod +x /usr/local/bin/kubectl

WORKDIR /app

COPY src/executor_agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY src /app/src

CMD ["python3", "-m", "uvicorn", "src.executor_agent.executor:app", "--host", "0.0.0.0", "--port", "8035"]