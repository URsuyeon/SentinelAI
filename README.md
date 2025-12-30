# SentinelAI: LLM 기반 인프라 모니터링 에이전트

SentinelAI는 Kubernetes 환경에서 발생하는 이상을 탐지하고, 분석하며, 자율적으로 해결하는 것을 목표로 하는 에이전트 기반 시스템입니다.

## 1. 구성 요소

| 구성 요소 | 역할 | 기술 스택 | 포트 |
| :--- | :--- | :--- | :--- |
| **Orchestrator** | 중앙 허브, 워크플로우 관리, 인증/인가 | FastAPI | 8032 |
| **Detector Agent** | K8s 상태 스캔 및 이상 탐지 | Python/FastAPI | 8033 |
| **Analyzer Agent** | 문제 원인/해결 분석 및 K8s 명령어 생성 | FastAPI | 8034 |
| **Executor Agent** | Orchestrator 승인 명령 실행 | FastAPI | 8035 |
| **RAG Agent** | 문서 기반 참고 정보 검색 | FastAPI | 8036 |
| **Slack Notifier** | 운영자 승인 요청 및 알림 | FastAPI | 8037 |

## 2. 핵심 워크플로우

1.  **탐지**: Detector가 K8s 이상 감지 후 Orchestrator에 알림.
2.  **1차 분석 및 증거 수집**: Orchestrator는 Analyzer에 증거 수집 명령을 요청하고, Executor를 통해 **읽기 전용 토큰**으로 명령 실행.
3.  **RAG 검색**: 수집된 증거를 기반으로 RAG Agent를 통해 유사 문서 검색.
4.  **2차 분석 및 해결 명령 생성**: Analyzer는 모든 정보를 종합하여 최종 해결 명령을 생성.
5.  **승인 및 최종 실행**: 위험 명령일 경우 Slack Notifier를 통해 운영자 승인 요청. 승인 후 **쓰기 전용 토큰**으로 Executor를 통해 명령 실행.
6.  **완료**: Slack Notifier를 통해 최종 작업 완료 알림 전송.

## 3. 실행 방법 (Docker Compose)

SentinelAI는 Docker Compose를 사용하여 모든 에이전트를 격리된 환경에서 실행하도록 구성되어 있습니다.

### 3.1. 필수 요구 사항

*   Docker
*   Docker Compose (또는 `docker compose` 플러그인)

### 3.2. 빌드 및 실행

프로젝트 루트 디렉토리에서 다음 명령을 실행합니다.

```bash
# Docker 이미지 빌드 및 모든 서비스 백그라운드 실행
sudo docker-compose up --build -d
```

### 3.3. 로그 확인

모든 서비스의 통합 로그를 확인하려면 다음 명령을 사용합니다.

```bash
sudo docker-compose logs -f
```

### 3.4. 테스트 시나리오 확인

Detector Agent는 30초마다 OOMKilled 시나리오를 모킹하여 Orchestrator에 알림을 보냅니다. 로그를 통해 전체 워크플로우가 순차적으로 진행되는 것을 확인할 수 있습니다.

**Orchestrator 로그 예시:**

```
... | ORCHESTRATOR | 📩 [POST /detect] Received event from default/my-app-pod-abcde
... | ORCHESTRATOR | ✅ [WORKFLOW START] TaskID: task-20251203T100000Z-abc
... | ORCHESTRATOR | ➡️ [ANALYZER_INITIAL] Task ... forwarded to http://analyzer:8034.
... | EXECUTOR | ⚙️ [EXEC] Executing command: kubectl describe pod my-app-pod-abcde -n default
... | ORCHESTRATOR | ✅ [EXECUTOR CALLBACK] Task ... received read logs. Status: success
... | RAG | 🔍 [SEARCH] Task ... searching knowledge base.
... | ORCHESTRATOR | ➡️ [RAG_SEARCH] Task ... forwarded to http://rag:8036.
... | ORCHESTRATOR | ➡️ [ANALYZER_FINAL] Task ... forwarded to http://analyzer:8034.
... | NOTIFIER | 🔔 [SLACK] Task ...: Operator approval requested for commands: ['kubectl apply -f /tmp/fix_oom_my-app-pod-abcde.yaml -n default']
... | NOTIFIER | ✅ [SLACK] Task ...: Auto-approved. Sending callback to Orchestrator.
... | ORCHESTRATOR | ✅ [SLACK CALLBACK] Task ... approved by operator.
... | EXECUTOR | ⚙️ [EXEC] Executing command: kubectl apply -f /tmp/fix_oom_my-app-pod-abcde.yaml -n default
... | ORCHESTRATOR | ✅ [EXECUTOR CALLBACK] Task ... received final logs. Status: success
... | NOTIFIER | 🎉 [SLACK] Task ... completion notification sent.
... | ORCHESTRATOR | 🎉 [WORKFLOW COMPLETE] Task ... finished with status: resolved
```

### 3.5. 서비스 종료

```bash
sudo docker-compose down
```
