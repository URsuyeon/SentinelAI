# src/auth/Dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src /app/src
CMD ["python3", "-m", "uvicorn", "src.auth.auth:app", "--host", "0.0.0.0", "--port", "8060"]