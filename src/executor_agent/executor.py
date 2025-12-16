# src/executor_agent/executor.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import logging
import os
import httpx
import asyncio
from datetime import datetime
import tempfile
from pathlib import Path
import shlex

# AuthManager 임포트
# Executor는 자체적으로 AuthManager를 가지지 않고, Orchestrator가 발급한 토큰만 검증.
# 하지만, 화이트리스트 검증을 위해 AuthManager를 로드할 수 있음.
from src.auth.auth import auth_manager
import subprocess

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
    token: Optional[str] = None
    kubeconfig: Optional[str] = None
    callback_url: str
    command_list: List[str]
    command_type: str # 'read' or 'write'

class ExecuteResponse(BaseModel):
    status: str

class ExecutorCallback(BaseModel):
    task_id: str
    status: str # 'success' or 'failure'
    execution_logs: List[Dict[str, Any]]

# --- 핵심 로직 ---

def _get_execution_result(command: str, kubeconfig_path: Path) -> Dict[str, Any]:
    """
    모킹 여부에 따라 실행 함수를 선택합니다.
    """
    if DISABLE_K8S_INTEGRATION:
        return _mock_k8s_execute(command)
    else:
        return _execute_k8s_command(command, kubeconfig_path)

def _write_temp_kubeconfig(task_id: str, kubeconfig_str: str) -> Path:
    fd, path = tempfile.mkstemp(suffix=".kubeconfig", prefix=f"{task_id}-", dir="/tmp")
    with os.fdopen(fd, "w") as fh:
        fh.write(kubeconfig_str)
    p = Path(path)
    p.chmod(0o600)
    return p


def _execute_k8s_command(command: str, kubeconfig_path: Path) -> Dict[str, Any]:
    """
    실제 K8s 명령 실행 로직
    """
    logger.info(f"🚀 [K8S EXEC] Executing command: {command}")

    now = datetime.utcnow().isoformat() + 'Z'
    
    # Orchestrator에서 발급한 K8s ServiceAccount 토큰을 사용하여 인증
    try:
        command_tokens = shlex.split(command)
        if not command_tokens or command_tokens[0] != "kubectl":
            raise ValueError("Only 'kubectl' commands are allowed.")

        # 기존 환경 변수를 복사하고 KUBECONFIG을 추가
        env = os.environ.copy()
        env["KUBECONFIG"] = str(kubeconfig_path)
        command_tokens = command.split()

        result = subprocess.run(
            command_tokens,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
            env=env,
        )
        
        return {
            "command": command,
            "status": "success",
            "output": result.stdout.strip(),
            "timestamp": now
        }
    
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ [K8S EXEC FAIL] Command failed: {e.cmd}. Stderr: {e.stderr.strip()}")
        return {
            "command": command,
            "status": "failure",
            "output": f"Command failed. Stderr: {e.stderr.strip()}",
            "timestamp": now
        }
    except subprocess.TimeoutExpired as e:
        logger.error(f"❌ [K8S EXEC FAIL] Command timed out: {e.cmd}")
        return {
            "command": command,
            "status": "failure",
            "output": "Command timed out after 30 seconds.",
            "timestamp": now
        }
    except ValueError as e:
        logger.error(f"❌ [K8S EXEC FAIL] Invalid command: {e}")
        return {
            "command": command,
            "status": "failure",
            "output": f"Invalid command format: {e}",
            "timestamp": now
        }
    except Exception as e:
        logger.error(f"❌ [K8S EXEC FAIL] Unexpected error: {e}")
        return {
            "command": command,
            "status": "failure",
            "output": f"Unexpected error during execution: {e}",
            "timestamp": now
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


async def _process_execution(req: ExecuteRequest):
    """
    명령어 리스트를 순차적으로 실행하고 결과를 콜백 URL로 전송합니다.
    """
    task_id = req.task_id
    execution_logs: List[Dict[str, Any]] = []
    overall_status = "success"
    
    # 1. 토큰 유효성 검증 (JWT 방식일 경우에만 유효)
    # K8s 토큰은 Executor가 K8s API 서버에 직접 인증하므로, 여기서 검증하지 않습니다.
    # JWT 토큰 방식일 경우에만 유효성 검증을 수행합니다.
    # K8s 토큰은 JWT 형식이 아니므로, auth_manager.validate_token은 실패할 가능성이 높습니다.
    # 따라서, K8s 토큰을 사용하는 경우 이 검증 단계를 건너뛰거나, Executor가 K8s API 서버에 토큰을 검증하는 로직을 추가해야 합니다.
    # 현재는 JWT 토큰 방식일 때만 검증한다고 가정하고, K8s 토큰 방식일 때는 토큰을 그대로 사용합니다.
    
    # if not auth_manager.validate_token(req.token, req.task_id, req.command_type):
    #     logger.error(f"❌ [TOKEN VALIDATION FAIL] Task {task_id} token validation failed.")
    #     overall_status = "failure"
    #     execution_logs.append({
    #         "command": "Token Validation",
    #         "status": "failure",
    #         "output": "Invalid or expired token.",
    #         "timestamp": datetime.utcnow().isoformat() + 'Z'
    #     })
    # else:
    if not DISABLE_K8S_INTEGRATION:
        if not req.token:
            logger.error(f"❌ [AUTH] Missing token for K8s execution. Task {task_id}")
            overall_status = "failure"
            execution_logs.append({
                "command": "auth",
                "status": "failure",
                "output": "Missing token for K8s execution.",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            # 바로 콜백 전송
            callback_data = ExecutorCallback(task_id=task_id, status=overall_status, execution_logs=execution_logs)
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(req.callback_url, json=callback_data.dict())
            return

        if not req.kubeconfig:
            logger.error(f"❌ [AUTH] Missing kubeconfig for K8s execution. Task {task_id}")
            overall_status = "failure"
            execution_logs.append({
                "command": "auth",
                "status": "failure",
                "output": "Missing kubeconfig for K8s execution.",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            callback_data = ExecutorCallback(task_id=task_id, status=overall_status, execution_logs=execution_logs)
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(req.callback_url, json=callback_data.dict())
            return

    kubeconfig_path: Optional[Path] = None

    try:
        if not DISABLE_K8S_INTEGRATION:
            kubeconfig_path = _write_temp_kubeconfig(req.task_id, req.kubeconfig)

        # 2. 명령어 순차 실행
        for command in req.command_list:
            try:
                if not auth_manager.check_whitelist(command, req.command_type):
                    logger.error(f"❌ [WHITELIST] Command rejected by executor whitelist: {command}")
                    execution_logs.append({
                        "command": command,
                        "status": "failure",
                        "output": "Rejected by executor whitelist.",
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    })
                    overall_status = "failure"
                    if req.command_type == "write":
                        break
                    else:
                        # 읽기라면 다음 명령 계속 진행
                        continue
            except Exception as e:
                # whitelist 검사 실패 시 보수적으로 실패 처리
                logger.error(f"❌ [WHITELIST ERROR] {e}")
                execution_logs.append({
                    "command": command,
                    "status": "failure",
                    "output": f"Whitelist check error: {e}",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                })
                overall_status = "failure"
                if req.command_type == "write":
                    break
                else:
                    continue

            # 실제 실행 (모킹/실제 분기)
            result = _get_execution_result(command, kubeconfig_path)
            execution_logs.append(result)

            if result["status"] != "success":
                overall_status = "failure"
                if req.command_type == "write":
                    logger.error(f"❌ [EXECUTION STOP] Write command failed. Stopping further execution.")
                    break
        
        # 3. 콜백 전송
        callback_data = ExecutorCallback(
            task_id=task_id,
            status=overall_status,
            execution_logs=execution_logs
        )
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                req.callback_url,
                json=callback_data.dict()
            )

            if resp.status_code == 200:
                logger.info(
                    f"✅ [CALLBACK] Task {task_id} callback sent successfully"
                )
            else:
                logger.error(
                    f"❌ [CALLBACK FAIL] Status={resp.status_code}, Body={resp.text[:200]}"
                )

    finally:
        # 임시 kubeconfig가 생성되어 있다면 안전하게 제거
        if kubeconfig_path and kubeconfig_path.exists():
            try:
                kubeconfig_path.unlink()
                logger.info(f"🧹 [KUBECONFIG CLEANUP] Removed temp kubeconfig for task {task_id}")
            except Exception as e:
                logger.warning(f"⚠️ [KUBECONFIG CLEANUP FAIL] {e}")

# --- API 엔드포인트 ---

@app.post('/execute', response_model=ExecuteResponse)
async def execute_command(req: ExecuteRequest, background_tasks: BackgroundTasks):
    logger.info(f"📩 [POST /execute] Task {req.task_id} received {len(req.command_list)} commands.")
    background_tasks.add_task(_process_execution, req)
    return ExecuteResponse(status="accepted")

@app.get('/health')
async def health():
    return {"status": "ok"}

if __name__ == '__main__':
    from datetime import datetime
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8035, log_level="info")
