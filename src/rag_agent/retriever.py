# src/rag_agent/retriever.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import logging
import json
import os
import asyncio

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | RAG | %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="RAG Agent API", version="0.1")

# --- 환경 변수 기반 모킹/실제 실행 로직 ---
# DISABLE_RAG_INTEGRATION=True 일 때 모킹 활성화 (사용자 요청에 따라 로직 반전)
DISABLE_RAG_INTEGRATION = os.getenv("DISABLE_RAG_INTEGRATION", "True").lower() in ('true', '1', 't')
logger.info(f"⚙️  RAG Integration Status: {'MOCKING' if DISABLE_RAG_INTEGRATION else 'ACTIVE'}")

# --- 데이터 모델 ---
class RAGSearchRequest(BaseModel):
    task_id: str
    detection_log: Dict[str, Any]
    execution_log: List[Dict[str, Any]]

class RAGResult(BaseModel):
    document_id: str
    title: str
    content: str
    score: float

class RAGSearchResponse(BaseModel):
    rag_results: List[RAGResult]

# --- 핵심 로직 ---
def _search_vector_db(req: RAGSearchRequest) -> List[RAGResult]:
    """
    실제 Vector DB에서 유사 문서를 검색하는 로직 (미구현)
    """
    # TODO: 실제 Vector DB (Chroma, Pinecone 등) 클라이언트를 사용하여 검색 로직 구현
    logger.warning(f"⚠️ [RAG SEARCH] Actual RAG search is not yet implemented. Task: {req.task_id}")
    
    # 임시로 모킹 결과를 반환
    return _mock_search_knowledge_base(req)

def _mock_search_knowledge_base(req: RAGSearchRequest) -> List[RAGResult]:
    """
    탐지로그 + 증거로그 기반으로 유사 문서 검색을 모킹합니다.
    """
    logger.info(f"🔍 [MOCK SEARCH] Task {req.task_id} searching knowledge base.")
    
    # 로그에서 키워드 추출
    detection_text = f"{req.detection_log.get('event_type', '')} {req.detection_log.get('describe_snippet', '')} {req.detection_log.get('raw_log_tail', '')}"
    execution_text = " ".join([log.get("output", "") for log in req.execution_log])
    full_text = detection_text + " " + execution_text

    # OOMKilled 시나리오 모킹
    if "OOMKilled" in full_text or "Out of memory" in full_text:
        return [
            RAGResult(
                document_id="doc-oom-001",
                title="K8s Pod OOMKilled 문제 해결 가이드",
                content="Pod가 OOMKilled 상태일 경우, 메모리 리소스 요청(requests) 및 제한(limits)을 늘려야 합니다. `kubectl apply -f` 명령을 사용하여 Deployment/StatefulSet의 리소스 설정을 업데이트하는 것이 일반적인 해결책입니다. **주의: OOMKilled은 메모리 부족을 의미하며, Pod 재시작만으로는 해결되지 않습니다.**",
                score=0.95
            ),
            RAGResult(
                document_id="doc-oom-002",
                title="리소스 설정 업데이트 방법",
                content="리소스 설정 업데이트 시, `resources.limits.memory`를 현재 사용량보다 넉넉하게 설정하고, `resources.requests.memory`도 함께 조정해야 합니다.",
                score=0.88
            )
        ]
    
    # 일반적인 CrashLoopBackOff 시나리오 모킹
    elif "CrashLoopBackOff" in full_text:
        return [
            RAGResult(
                document_id="doc-crash-001",
                title="CrashLoopBackOff 디버깅 체크리스트",
                content="CrashLoopBackOff는 Pod가 반복적으로 시작에 실패할 때 발생합니다. 1. 로그 확인 (`kubectl logs`), 2. 이벤트 확인 (`kubectl describe pod`), 3. 이전 컨테이너 로그 확인 (`--previous`) 순으로 디버깅을 진행합니다.",
                score=0.90
            )
        ]
        
    return [
        RAGResult(
            document_id="doc-default-001",
            title="K8s 문제 해결 일반 가이드",
            content="문제가 발생하면, Pod를 삭제하여 재생성하는 것이 가장 빠른 해결책일 수 있습니다. (단, Deployment/StatefulSet에 의해 관리되는 경우에 한함)",
            score=0.70
        )
    ]

def _get_rag_results(req: RAGSearchRequest) -> List[RAGResult]:
    """모킹 여부에 따라 검색 함수를 선택합니다."""
    if DISABLE_RAG_INTEGRATION:
        return _mock_search_knowledge_base(req)
    else:
        return _search_vector_db(req)


# --- API 엔드포인트 ---

@app.post('/search', response_model=RAGSearchResponse)
async def search_knowledge(req: RAGSearchRequest):
    """로그 기반으로 유사 문서 검색 요청"""
    logger.info(f"📩 [POST /search] Task {req.task_id} received search request.")
    await asyncio.sleep(1)
    results = _get_rag_results(req)
    return RAGSearchResponse(rag_results=results)

@app.get('/health')
async def health():
    return {"status": "ok"}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8036, log_level="info")
