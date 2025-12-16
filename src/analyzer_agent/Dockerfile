# src/analyzer_agent/Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY src/analyzer_agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY src /app/src
CMD ["python3", "-m", "uvicorn", "src.analyzer_agent.analyzer:app", "--host", "0.0.0.0", "--port", "8034"]