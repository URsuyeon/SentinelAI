# src/executor_agent/executor.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import logging
import os
import httpx
import asyncio
from datetime import datetime

# AuthManager 임포트
# Executor는 자체적으로 AuthManager를 가지지 않고, Orchestrator가 발급한 토큰만 검증.
# 하지만, 화이트리스트 검증을 위해 AuthManager를 로드할 수 있음.
from src.auth.auth import auth_manager

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | EXECUTOR | %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Executor Agent API", version="0.1")

# --- 환경 변수 기반 모킹/실제 실행 로직 ---
# DISABLE_K8S_INTEGRATION=True 일 때 모킹 활성화 
DISABLE_K8S_INTEGRATION = os.getenv("DISABLE_K8S_INTEGRATION", "True").lower() in ('true', '1', 't')
logger.info(f"⚙️  K8s Integration Status: {'MOCKING' if DISABLE_K8S_INTEGRATION else 'ACTIVE'}")

# --- 데이터 모델 ---

class ExecuteRequest(BaseModel):
    task_id: str
    token: str
    command_list: List[str]
    callback_url: str
    command_type: str # 'read' or 'write'

class ExecuteResponse(BaseModel):
    status: str

class ExecutorCallback(BaseModel):
    task_id: str
    status: str # 'success' or 'failure'
    execution_logs: List[Dict[str, Any]]

# --- 핵심 로직 ---

def _get_execution_result(command: str) -> Dict[str, Any]:
    """
    모킹 여부에 따라 실행 함수를 선택합니다.
    """
    if DISABLE_K8S_INTEGRATION:
        return _mock_k8s_execute(command)
    else:
        return _execute_k8s_command(command)

def _execute_k8s_command(command: str) -> Dict[str, Any]:
    """
    실제 K8s 명령 실행 로직 (미구현)
    """
    # TODO: 실제 K8s 클라이언트를 사용하여 명령 실행 로직 구현
    logger.warning(f"⚠️  [K8S EXEC] 미구현. Command: {command}")
    return {
        "command": command,
        "status": "failure",
        "output": "Actual K8s execution not implemented.",
        "timestamp": datetime.utcnow().isoformat() + 'Z'
    }

def _mock_k8s_execute(command: str) -> Dict[str, Any]:
    """
    K8s 명령 실행을 모킹하고 결과를 반환합니다.
    """
    logger.info(f"⚙️  [MOCK EXEC] Executing command: {command}")

    now = datetime.utcnow().isoformat() + 'Z'

    # 명령어 종류에 따른 모킹 결과
    if "describe pod" in command:
        return {
            "command": command,
            "status": "success",
            "output": "Name: my-app-pod\nStatus: CrashLoopBackOff\nReason: OOMKilled\n...",
            "timestamp": now
        }
    elif "logs" in command:
        return {
            "command": command,
            "status": "success",
            "output": "2025-12-03T09:59:58Z Out of memory: Kill process 123 (java) score 999 or sacrifice child\n2025-12-03T09:59:59Z Killed process 123 (java) total-vm:...",
            "timestamp": now
        }
    elif "delete pod" in command:
        return {
            "command": command,
            "status": "success",
            "output": f'pod "{command.split()[-2]}" deleted',
            "timestamp": now
        }
    elif "apply -f" in command:
        return {
            "command": command,
            "status": "success",
            "output": "deployment.apps/my-app configured",
            "timestamp": now
        }
    else:
        return {
            "command": command,
            "status": "success",
            "output": f"Mock execution successful for: {command}",
            "timestamp": now
        }


async def _execute_and_callback(req: ExecuteRequest):
    """
    명령어를 실행하고 Orchestrator에 콜백을 보냅니다.
    """
    task_id = req.task_id
    token = req.token
    command_list = req.command_list
    callback_url = req.callback_url
    command_type = req.command_type
    
    # 1. 토큰 검증 (JWT 기반으로 변경)
    if not auth_manager.validate_token(token, task_id, command_type):
        logger.error(f"❌ [AUTH FAIL] Invalid or expired token for task {task_id}")
        callback_payload = ExecutorCallback(
            task_id=task_id,
            status="failure",
            execution_logs=[{"error": "Invalid or expired execution token"}]
        )
        await _send_callback(callback_url, callback_payload.dict(), task_id)
        return

    # 2. 명령어 실행
    execution_logs = []
    success = True
    for command in command_list:
        try:
            # 화이트리스트 재검증
            if not auth_manager.check_whitelist(command, command_type):
                log = {"command": command, "status": "failure", "output": "Command not in whitelist"}
                success = False
            else:
                log = _get_execution_result(command)
            
            execution_logs.append(log)
            if log["status"] != "success":
                success = False
                break
        except Exception as e:
            logger.error(f"❌ [EXEC FAIL] Exception during command execution: {e}")
            execution_logs.append({"command": command, "status": "failure", "output": str(e)})
            success = False
            break

    # 3. Orchestrator에 콜백 전송
    callback_payload = ExecutorCallback(
        task_id=task_id,
        status="success" if success else "failure",
        execution_logs=execution_logs
    )
    await _send_callback(callback_url, callback_payload.dict(), task_id)

async def _send_callback(url: str, data: Dict[str, Any], task_id: str):
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=data)
            if resp.status_code == 200:
                logger.info(f"✅ [CALLBACK] Task {task_id} result sent to Orchestrator.")
            else:
                logger.error(f"❌ [CALLBACK FAIL] Task {task_id} failed to send callback. Status: {resp.status_code}, Body: {resp.text[:200]}")
    except Exception as e:
        logger.error(f"❌ [CALLBACK FAIL] Task {task_id} failed to send callback. Exception: {e}")

# --- API 엔드포인트 ---

@app.post('/execute', response_model=ExecuteResponse)
async def execute_command(req: ExecuteRequest, background_tasks: BackgroundTasks):
    logger.info(f"📩 [POST /execute] Task {req.task_id} received {len(req.command_list)} commands.")
    background_tasks.add_task(_execute_and_callback, req)
    return ExecuteResponse(status="accepted")

@app.get('/health')
async def health():
    return {"status": "ok"}

if __name__ == '__main__':
    from datetime import datetime
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8035, log_level="info")
