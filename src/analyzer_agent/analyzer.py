# src/analyzer_agent/analyzer.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import logging
import json
import os
import asyncio

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | ANALYZER | %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Analyzer Agent API", version="0.1")

# --- 환경 변수 기반 모킹/실제 실행 로직 ---
# DISABLE_LLM_INTEGRATION=True 일 때 모킹 활성화 (사용자 요청에 따라 로직 반전)
DISABLE_LLM_INTEGRATION = os.getenv("DISABLE_LLM_INTEGRATION", "True").lower() in ('true', '1', 't')
logger.info(f"⚙️  LLM Integration Status: {'MOCKING' if DISABLE_LLM_INTEGRATION else 'ACTIVE'}")

# --- 데이터 모델 (Orchestrator와 공유) ---

class DetectRequest(BaseModel):
    timestamp: Any
    namespace: str
    pod_name: str              
    event_type: str
    phase: Optional[str] = None
    container_statuses: Optional[List[Dict[str, Any]]] = None
    reasons: Optional[List[str]] = None
    raw_log_tail: Optional[str] = ""
    describe_snippet: Optional[str] = "" 
    metadata: Optional[Dict[str, Any]] = None
    detection_signature: Optional[str] = None
    class Config:
        extra = 'allow'

class AnalyzeCommandResponse(BaseModel):
    command_type: str # 'read' or 'write'
    command_list: List[str]
    is_risky: bool = False

class InitialAnalyzeRequest(BaseModel):
    task_id: str
    detect_request: DetectRequest

class FinalAnalyzeRequest(BaseModel):
    task_id: str
    detect_request: DetectRequest
    execution_logs: List[Dict[str, Any]]
    rag_results: List[Dict[str, Any]]

# --- 캐시 구조 모킹 ---
# TODO: Redis나 DB를 사용해야 함
COMMAND_CACHE: Dict[str, AnalyzeCommandResponse] = {}


# --- 핵심 로직 ---
def _call_llm_api(req: InitialAnalyzeRequest | FinalAnalyzeRequest, is_final: bool) -> AnalyzeCommandResponse:
    """
    실제 LLM API 호출 로직 (미구현)
    """
    # TODO: 실제 LLM API 호출 로직 구현
    logger.warning(f"⚠️ [LLM CALL] Actual LLM API call is not yet implemented. Task: {req.task_id}")
    
    # 임시로 모킹 결과를 반환 (실제 구현 시에는 LLM 응답을 파싱해야 함)
    if is_final:
        return _mock_llm_generate_final_command(req)
    else:
        return _mock_llm_generate_initial_command(req)

def _mock_llm_generate_initial_command(req: InitialAnalyzeRequest) -> AnalyzeCommandResponse:
    """
    문제 원인 파악을 위한 증거수집 명령어 생성 (LLM 모킹)
    """
    pod_name = req.detect_request.pod_name
    namespace = req.detect_request.namespace
    
    # 2. LLM으로 명령어 생성 (하드코딩 모킹)
    logger.info(f"🧠 [LLM MOCK] Generating initial command for {pod_name}")
    
    commands = [
        f"kubectl describe pod {pod_name} -n {namespace}",
        f"kubectl logs {pod_name} -n {namespace} --tail=50"
    ]
    
    response = AnalyzeCommandResponse(
        command_type="read",
        command_list=commands,
        is_risky=False
    )
    
    return response

def _mock_llm_generate_final_command(req: FinalAnalyzeRequest) -> AnalyzeCommandResponse:
    """
    최종 문제 해결 명령어 생성 (LLM 모킹)
    """
    pod_name = req.detect_request.pod_name
    namespace = req.detect_request.namespace
    
    # 2. LLM으로 명령어 생성 (하드코딩 모킹)
    logger.info(f"🧠 [LLM MOCK] Generating final command for {pod_name}")
    
    # RAG 결과에서 "OOMKilled" 관련 문서가 있으면 메모리 증가 명령을 생성하는 모킹 로직
    rag_content = " ".join([r.get("content", "") for r in req.rag_results])
    is_oom_issue = "OOMKilled" in rag_content
    
    if is_oom_issue:
        commands = [
            f"kubectl delete pod {pod_name} -n {namespace}" # Pod 삭제 후 재생성 유도 (OOMKilled 해결을 위한 임시 조치)
        ]
        is_risky = True # delete 명령은 위험하다고 가정
    else:
        # 그 외의 경우, 안전한 명령어 모킹
        commands = [
            "echo 'No write command generated for this scenario.'"
        ]
        is_risky = False
        
    response = AnalyzeCommandResponse(
        command_type="write",
        command_list=commands,
        is_risky=is_risky
    )
    
    return response

def _get_generated_command(req: InitialAnalyzeRequest | FinalAnalyzeRequest, is_final: bool) -> AnalyzeCommandResponse:
    """모킹 여부에 따라 명령어 생성 함수를 선택합니다."""
    
    # 캐시 키 생성
    pod_name = req.detect_request.pod_name
    signature = req.detect_request.detection_signature
    cache_key = f"{'final' if is_final else 'initial'}:{signature}:{pod_name}"
    
    # 1. 캐시 확인 (모킹/실제 모두 적용)
    if cache_key in COMMAND_CACHE:
        logger.info(f"💾 [CACHE HIT] Task {req.task_id} command found in cache.")
        return COMMAND_CACHE[cache_key]

    # 2. 모킹/실제 실행 선택
    if DISABLE_LLM_INTEGRATION:
        cmd = _mock_llm_generate_final_command(req) if is_final else _mock_llm_generate_initial_command(req)
    else:
        cmd = _call_llm_api(req, is_final)
        
    # 3. 캐시에 저장 (실제로는 signature 기반으로 저장해야 함)
    # COMMAND_CACHE[cache_key] = cmd # 현재는 캐시를 사용하지 않도록 주석 처리
    
    return cmd

# --- API 엔드포인트 ---

@app.post('/analyze/initial', response_model=AnalyzeCommandResponse)
async def analyze_initial(req: InitialAnalyzeRequest):
    """증거 수집을 위한 초기 명령어 생성"""
    logger.info(f"📩 [POST /analyze/initial] Task {req.task_id} received for initial analysis.")
    await asyncio.sleep(1) 
    return _get_generated_command(req, is_final=False)

@app.post('/analyze/final', response_model=AnalyzeCommandResponse)
async def analyze_final(req: FinalAnalyzeRequest):
    """최종 문제 해결 명령어 생성"""
    logger.info(f"📩 [POST /analyze/final] Task {req.task_id} received for final analysis.")
    await asyncio.sleep(1)
    return _get_generated_command(req, is_final=True)

@app.get('/health')
async def health():
    return {"status": "ok"}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8034, log_level="info")
