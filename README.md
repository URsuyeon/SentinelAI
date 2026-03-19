# SentinelAI: LLM 기반 인프라 모니터링 에이전트

SentinelAI는 Kubernetes 환경에서 발생하는 이상을 탐지하고, 분석하며, 자율적으로 해결하는 것을 목표로 하는 에이전트 기반 시스템입니다.
![(수정1)ipp_project_이수연_page-0001](https://github.com/user-attachments/assets/70aaf787-61ff-4a97-8bf1-770776987f1c)
![(수정1)ipp_project_이수연_page-0002](https://github.com/user-attachments/assets/0a6e86b4-b096-497c-a996-cbe27669e020)
![(수정1)ipp_project_이수연_page-0004](https://github.com/user-attachments/assets/65488bdb-1ce6-48b0-ba67-5b9243589fe4)
![(수정1)ipp_project_이수연_page-0005](https://github.com/user-attachments/assets/6235c9f6-7d2a-4191-b792-9809b7819d0f)
![(수정1)ipp_project_이수연_page-0006](https://github.com/user-attachments/assets/68f1f025-3ad8-4bbf-82b1-3916525d51c0)
![(수정1)ipp_project_이수연_page-0007](https://github.com/user-attachments/assets/1daab82a-42c0-415a-8bda-20848d89aae9)
![(수정1)ipp_project_이수연_page-0008](https://github.com/user-attachments/assets/311e87af-ddad-4605-98e2-83b4fc93040d)
![(수정1)ipp_project_이수연_page-0009](https://github.com/user-attachments/assets/d344586b-cfff-492e-b6b7-7d81e2278c12)
![(수정1)ipp_project_이수연_page-0010](https://github.com/user-attachments/assets/b62f4f60-af25-4997-9a2c-96e984c023aa)
![(수정1)ipp_project_이수연_page-0011](https://github.com/user-attachments/assets/157865a3-1849-46f2-a30b-609a54fa91b7)
![(수정1)ipp_project_이수연_page-0012](https://github.com/user-attachments/assets/592accb9-a91e-48b6-9bca-798753fcc704)
![(수정1)ipp_project_이수연_page-0013](https://github.com/user-attachments/assets/bbf6aed6-bfb6-4ea6-9ec2-99712a9f09a8)
![(수정1)ipp_project_이수연_page-0014](https://github.com/user-attachments/assets/b7523886-cb15-43dd-8a48-1a3b503ec560)
![(수정1)ipp_project_이수연_page-0015](https://github.com/user-attachments/assets/8888f887-994f-4c30-b207-e70ead29be1c)
![(수정1)ipp_project_이수연_page-0016](https://github.com/user-attachments/assets/eee6e03a-8c7f-4720-b809-757f428cf324)
![(수정1)ipp_project_이수연_page-0017](https://github.com/user-attachments/assets/b4d102c2-183c-4fbb-9477-82ba3f130a66)
![(수정1)ipp_project_이수연_page-0018](https://github.com/user-attachments/assets/9bd9d649-f6a5-40a9-987e-7f442e2a97de)
![(수정1)ipp_project_이수연_page-0019](https://github.com/user-attachments/assets/5304ea1d-5d6e-4da8-a9c9-a66b1557eb10)
![(수정1)ipp_project_이수연_page-0020](https://github.com/user-attachments/assets/f988b86b-271b-4f66-9c72-f36a54d8ddd6)
![(수정1)ipp_project_이수연_page-0021](https://github.com/user-attachments/assets/841b0867-9748-4a20-9a55-f621229b52fd)

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
