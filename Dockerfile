# Dockerfile
FROM python:3.11-slim

# 작업 디렉토리 설정
WORKDIR /app

# 종속성 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스 코드 복사
COPY src /app/src

EXPOSE 8032
EXPOSE 8033
EXPOSE 8034
EXPOSE 8035
EXPOSE 8036
EXPOSE 8037