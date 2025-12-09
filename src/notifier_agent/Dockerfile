# src/notifier_agent/Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY src /app/src
CMD ["python3", "-m", "uvicorn", "src.notifier_agent.notifier:app", "--host", "0.0.0.0", "--port", "8037"]