# detector-agent +  Dockerfile

#FROM python:3.11-slim
#WORKDIR /app
#RUN apt-get update && apt-get install -y --no-install-recommends \
#    ca-certificates \
# && rm -rf /var/lib/apt/lists/*
#COPY requirements.txt .
#RUN pip install --no-cache-dir -r requirements.txt

#COPY ./src/detector_agent/detector.py .
#ENV KUBECONFIG=/root/.kube/config
#CMD ["python", "detector.py"]


FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    bash \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .    
RUN pip install --no-cache-dir -r requirements.txt

COPY ./src/orchestrator/orchestrator.py .
COPY ./src/detector_agent/detector.py .

COPY ./start.sh .
RUN chmod +x ./start.sh

ENV BOSS_URL="http://127.0.0.1:8032/detect"
ENV BOSS_TOKEN="dev-token"
EXPOSE 8032 8033

# 동시 실행 (orchestrator + detector)
CMD ["./start.sh"]