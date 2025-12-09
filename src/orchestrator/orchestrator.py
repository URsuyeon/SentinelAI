# src/orchestrator/orchestrator.py
from fastapi import Header, FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
from datetime import datetime
import secrets
import logging
import os
import httpx
import json

# AuthManager 임포트
from src.auth.auth import auth_manager

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | ORCHESTRATOR | %(message)s')
logger = logging.getLogger(__name__)

# 환경 변수 설정
BOSS_TOKEN = os.getenv("BOSS_TOKEN", "dev-token")
ANALYZER_URL = os.getenv("ANALYZER_URL", "http://127.0.0.1:8034")
EXECUTOR_URL = os.getenv("EXECUTOR_URL", "http://127.0.0.1:8035")
RAG_URL = os.getenv("RAG_URL", "http://127.0.0.1:8036")
NOTIFIER_URL = os.getenv("NOTIFIER_URL", "http://127.0.0.1:8037")
ORCHESTRATOR_CALLBACK_URL = os.getenv("ORCHESTRATOR_CALLBACK_URL", "http://127.0.0.1:8032")

app = FastAPI(title="Orchestrator API", version="0.1")

# Task 상태 저장소
TASK_STORE: Dict[str, Dict[str, Any]] = {}

# --- 데이터 모델 ---
class DetectRequest(BaseModel):
    timestamp: datetime = Field(..., description="ISO8601 UTC timestamp")
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

class DetectResponse(BaseModel):
    status: str
    task_id: str

class AnalyzeCommandResponse(BaseModel):
    command_type: str # 'read' or 'write'
    command_list: List[str]
    is_risky: bool = False # 최종 해결 명령 시에만 사용

class ExecutorCallback(BaseModel):
    task_id: str
    status: str # 'success' or 'failure'
    execution_logs: List[Dict[str, Any]]

class SlackCallback(BaseModel):
    task_id: str
    approved: bool
    reason: Optional[str] = None

# --- 유틸리티 함수 ---

def _generate_task_id() -> str:
    t = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    suf = secrets.token_hex(3)
    return f"task-{t}-{suf}"

async def _http_post(url: str, data: Dict[str, Any], task_id: str, step: str):
    """HTTP POST 요청을 보내는 유틸리티 함수"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            payload = jsonable_encoder(data)
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                logger.info(f"➡️ [{step}] Task {task_id} forwarded to {url}. Response: {resp.json()}")
                return resp.json()
            else:
                logger.error(f"❌ [{step}] Task {task_id} failed to forward to {url}. Status: {resp.status_code}, Body: {resp.text[:200]}")
                TASK_STORE[task_id]["status"] = f"failed_at_{step}"
                return None
    except Exception as e:
        logger.error(f"❌ [{step}] Task {task_id} failed to forward to {url}. Exception: {e}")
        TASK_STORE[task_id]["status"] = f"failed_at_{step}"
        return None

# --- 핵심 워크플로우 함수 ---

async def _start_workflow(task_id: str, payload: Dict[str, Any]):
    """
    워크플로우의 시작점: Detector 알림 수신 후 초기 분석 요청
    """
    TASK_STORE[task_id] = {
        "received_at": datetime.utcnow().isoformat() + 'Z',
        "payload": payload,
        "status": "queued",
        "history": []
    }
    pod = payload.get('pod_name', 'unknown')
    evt = payload.get('event_type', 'unknown')
    logger.info(f"✅ [WORKFLOW START] TaskID: {task_id}")
    logger.info(f"   └── Event: {pod} [{evt}] | Signature: {payload.get('detection_signature')}")
    
    TASK_STORE[task_id]["status"] = "analyzing_initial"
    TASK_STORE[task_id]["history"].append({"step": "analyzing_initial", "timestamp": datetime.utcnow().isoformat() + 'Z'})

    # 1. Analyzer Agent에 초기 분석 요청 (증거 수집 명령어 요청)
    analyze_req = {"task_id": task_id, "detect_request": payload}
    analyze_resp = await _http_post(f"{ANALYZER_URL}/analyze/initial", analyze_req, task_id, "ANALYZER_INITIAL")
    
    if not analyze_resp:
        return

    try:
        analyze_cmd = AnalyzeCommandResponse(**analyze_resp)
        TASK_STORE[task_id]["initial_commands"] = analyze_cmd.dict()
        
        # 2. 화이트리스트 검증 (읽기 전용)
        for cmd in analyze_cmd.command_list:
            if not auth_manager.check_whitelist(cmd, analyze_cmd.command_type):
                logger.error(f"❌ [WHITELIST] Command rejected: {cmd}")
                TASK_STORE[task_id]["status"] = "failed_whitelist_check"
                return
        
        # 3. 읽기 전용 토큰 발급
        read_token = auth_manager.generate_token(task_id, analyze_cmd.command_type)
        
        # 4. Executor Agent에 실행 요청
        executor_req = {
            "task_id": task_id,
            "token": read_token,
            "command_type": analyze_cmd.command_type,
            "command_list": analyze_cmd.command_list,
            "callback_url": f"{ORCHESTRATOR_CALLBACK_URL}/executor/callback"
        }
        
        TASK_STORE[task_id]["status"] = "executing_read_commands"
        TASK_STORE[task_id]["history"].append({"step": "executing_read_commands", "timestamp": datetime.utcnow().isoformat() + 'Z'})
        
        await _http_post(f"{EXECUTOR_URL}/execute", executor_req, task_id, "EXECUTOR_READ")

    except Exception as e:
        logger.error(f"❌ [WORKFLOW] Error in initial analysis/execution: {e}")
        TASK_STORE[task_id]["status"] = "failed_initial_execution"


async def _continue_workflow_after_read(task_id: str, executor_callback: ExecutorCallback):
    """
    Executor Agent로부터 읽기 명령어 실행 결과를 받은 후 워크플로우 계속
    """
    logger.info(f"✅ [EXECUTOR CALLBACK] Task {task_id} received read logs. Status: {executor_callback.status}")
    
    if executor_callback.status != "success":
        TASK_STORE[task_id]["status"] = "failed_read_execution"
        TASK_STORE[task_id]["history"].append({"step": "failed_read_execution", "timestamp": datetime.utcnow().isoformat() + 'Z', "logs": executor_callback.execution_logs})
        return

    TASK_STORE[task_id]["read_logs"] = executor_callback.execution_logs
    TASK_STORE[task_id]["status"] = "searching_rag"
    TASK_STORE[task_id]["history"].append({"step": "searching_rag", "timestamp": datetime.utcnow().isoformat() + 'Z'})

    # 1. RAG Agent에 문서 검색 요청
    rag_req = {
        "task_id": task_id,
        "detection_log": TASK_STORE[task_id]["payload"],
        "execution_log": executor_callback.execution_logs
    }
    rag_resp = await _http_post(f"{RAG_URL}/search", rag_req, task_id, "RAG_SEARCH")
    
    if not rag_resp:
        return

    TASK_STORE[task_id]["rag_results"] = rag_resp.get("rag_results", [])
    TASK_STORE[task_id]["status"] = "analyzing_final"
    TASK_STORE[task_id]["history"].append({"step": "analyzing_final", "timestamp": datetime.utcnow().isoformat() + 'Z'})

    # 2. Analyzer Agent에 최종 해결 명령어 요청
    final_analyze_req = {
        "task_id": task_id,
        "detect_request": TASK_STORE[task_id]["payload"],
        "execution_logs": TASK_STORE[task_id]["read_logs"],
        "rag_results": TASK_STORE[task_id]["rag_results"]
    }
    final_analyze_resp = await _http_post(f"{ANALYZER_URL}/analyze/final", final_analyze_req, task_id, "ANALYZER_FINAL")

    if not final_analyze_resp:
        return

    try:
        final_analyze_cmd = AnalyzeCommandResponse(**final_analyze_resp)
        TASK_STORE[task_id]["final_commands"] = final_analyze_cmd.dict()
        
        # 3. 화이트리스트 검증 (쓰기 전용)
        for cmd in final_analyze_cmd.command_list:
            if not auth_manager.check_whitelist(cmd, final_analyze_cmd.command_type):
                logger.error(f"❌ [WHITELIST] Final command rejected: {cmd}")
                TASK_STORE[task_id]["status"] = "failed_final_whitelist_check"
                return

        # 4. 위험도 확인 및 승인 절차
        if final_analyze_cmd.is_risky:
            TASK_STORE[task_id]["status"] = "awaiting_approval"
            TASK_STORE[task_id]["history"].append({"step": "awaiting_approval", "timestamp": datetime.utcnow().isoformat() + 'Z'})
            
            # Slack Notifier에 승인 요청
            approval_req = {
                "task_id": task_id,
                "command_list": final_analyze_cmd.command_list,
                "callback_url": f"{ORCHESTRATOR_CALLBACK_URL}/slack/callback"
            }
            await _http_post(f"{NOTIFIER_URL}/notify/approval", approval_req, task_id, "NOTIFIER_APPROVAL")
        else:
            # 위험하지 않으면 바로 실행
            await _execute_final_command(task_id, final_analyze_cmd)

    except Exception as e:
        logger.error(f"❌ [WORKFLOW] Error in final analysis/execution: {e}")
        TASK_STORE[task_id]["status"] = "failed_final_execution_prep"


async def _execute_final_command(task_id: str, final_analyze_cmd: AnalyzeCommandResponse):
    """
    최종 해결 명령을 Executor Agent에 실행 요청
    """
    # 1. 쓰기 전용 토큰 발급
    write_token = auth_manager.generate_token(task_id, final_analyze_cmd.command_type)
    
    # 2. Executor Agent에 실행 요청
    executor_req = {
        "task_id": task_id,
        "token": write_token,
        "command_list": final_analyze_cmd.command_list,
        "command_type": final_analyze_cmd.command_type,
        "callback_url": f"{ORCHESTRATOR_CALLBACK_URL}/executor/callback"
    }
    
    TASK_STORE[task_id]["status"] = "executing_write_commands"
    TASK_STORE[task_id]["history"].append({"step": "executing_write_commands", "timestamp": datetime.utcnow().isoformat() + 'Z'})
    
    await _http_post(f"{EXECUTOR_URL}/execute", executor_req, task_id, "EXECUTOR_WRITE")


async def _complete_workflow(task_id: str, final_callback: ExecutorCallback):
    """
    Executor Agent로부터 최종 해결 명령어 실행 결과를 받은 후 워크플로우 완료
    """
    logger.info(f"✅ [EXECUTOR CALLBACK] Task {task_id} received final logs. Status: {final_callback.status}")
    
    TASK_STORE[task_id]["final_logs"] = final_callback.execution_logs
    
    if final_callback.status == "success":
        TASK_STORE[task_id]["status"] = "resolved"
        summary = "K8s 문제 해결 완료."
    else:
        TASK_STORE[task_id]["status"] = "failed_resolution"
        summary = "K8s 문제 해결 실패."

    TASK_STORE[task_id]["history"].append({"step": TASK_STORE[task_id]["status"], "timestamp": datetime.utcnow().isoformat() + 'Z', "logs": final_callback.execution_logs})

    # Slack Notifier에 완료 알림
    completion_req = {
        "task_id": task_id,
        "status": TASK_STORE[task_id]["status"],
        "summary": summary,
        "details": TASK_STORE[task_id]
    }
    await _http_post(f"{NOTIFIER_URL}/notify/completion", completion_req, task_id, "NOTIFIER_COMPLETION")
    logger.info(f"🎉 [WORKFLOW COMPLETE] Task {task_id} finished with status: {TASK_STORE[task_id]['status']}")


# --- API 엔드포인트 ---

@app.post('/detect', response_model=DetectResponse)
async def detect_endpoint(req: DetectRequest, background_tasks: BackgroundTasks, authorization: Optional[str] = Header(None),):
    """Detector Agent로부터 K8s 이상 탐지 알림 수신"""
    if BOSS_TOKEN:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing Authorization header")
        token = authorization.split(" ", 1)[1]

        if not secrets.compare_digest(token, BOSS_TOKEN):
            raise HTTPException(status_code=403, detail="Invalid token")
    
    task_id = _generate_task_id()
    payload = req.dict()

    logger.info(f"📩 [POST /detect] Received event from {req.namespace}/{req.pod_name}")
    
    # 워크플로우 시작
    background_tasks.add_task(_start_workflow, task_id, payload)
    return DetectResponse(status="received", task_id=task_id)


@app.post('/executor/callback')
async def executor_callback_endpoint(req: ExecutorCallback, background_tasks: BackgroundTasks):
    """Executor Agent로부터 명령어 실행 결과 수신"""
    task_id = req.task_id
    
    if task_id not in TASK_STORE:
        raise HTTPException(status_code=404, detail="Task not found")

    current_status = TASK_STORE[task_id]["status"]
    
    if current_status == "executing_read_commands":
        background_tasks.add_task(_continue_workflow_after_read, task_id, req)
    elif current_status == "executing_write_commands":
        background_tasks.add_task(_complete_workflow, task_id, req)
    else:
        logger.warning(f"⚠️ [EXECUTOR CALLBACK] Received unexpected callback for task {task_id} in status {current_status}")
        raise HTTPException(status_code=400, detail=f"Unexpected callback in status {current_status}")
        
    return {"status": "accepted"}


@app.post('/slack/callback')
async def slack_callback_endpoint(req: SlackCallback, background_tasks: BackgroundTasks):
    """Slack Notifier로부터 운영자 승인/거부 결과 수신"""
    task_id = req.task_id
    
    if task_id not in TASK_STORE:
        raise HTTPException(status_code=404, detail="Task not found")

    if TASK_STORE[task_id]["status"] != "awaiting_approval":
        logger.warning(f"⚠️ [SLACK CALLBACK] Received unexpected callback for task {task_id} in status {TASK_STORE[task_id]['status']}")
        raise HTTPException(status_code=400, detail=f"Unexpected callback in status {TASK_STORE[task_id]['status']}")

    TASK_STORE[task_id]["history"].append({"step": "approval_received", "timestamp": datetime.utcnow().isoformat() + 'Z', "approved": req.approved, "reason": req.reason})

    if req.approved:
        logger.info(f"✅ [SLACK CALLBACK] Task {task_id} approved by operator.")
        final_analyze_cmd = AnalyzeCommandResponse(**TASK_STORE[task_id]["final_commands"])
        background_tasks.add_task(_execute_final_command, task_id, final_analyze_cmd)
    else:
        logger.warning(f"❌ [SLACK CALLBACK] Task {task_id} rejected by operator. Reason: {req.reason}")
        TASK_STORE[task_id]["status"] = "rejected_by_operator"
        # 완료 알림 전송
        completion_req = {
            "task_id": task_id,
            "status": TASK_STORE[task_id]["status"],
            "summary": "K8s 문제 해결 명령 운영자 거부.",
            "details": TASK_STORE[task_id]
        }
        await _http_post(f"{NOTIFIER_URL}/notify/completion", completion_req, task_id, "NOTIFIER_REJECTION_COMPLETION")
        
    return {"status": "accepted"}


@app.get('/health')
async def health():
    """Health Check"""
    return {"status": "ok"}


@app.get('/tasks/{task_id}')
async def get_task(task_id: str):
    """특정 Task의 현재 상태 조회"""
    task = TASK_STORE.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail='task not found')
    return task

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8032, log_level="info")
