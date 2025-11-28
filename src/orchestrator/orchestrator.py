from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
from datetime import datetime
import secrets
import logging

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | ORCHESTRATOR | %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Orchestrator API", version="0.1")

TASK_STORE: Dict[str, Dict[str, Any]] = {}

# Detector Payload 구조
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


def _generate_task_id() -> str:
    t = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    suf = secrets.token_hex(3)
    return f"task-{t}-{suf}"


def _enqueue_task(task_id: str, payload: Dict[str, Any]):
    TASK_STORE[task_id] = {
        "received_at": datetime.utcnow().isoformat() + 'Z',
        "payload": payload,
        "status": "queued",
    }
    pod = payload.get('pod_name', 'unknown')
    evt = payload.get('event_type', 'unknown')
    logger.info(f"✅ [EVENT QUEUED] TaskID: {task_id}")
    logger.info(f"   └── Event: {pod} [{evt}] | Signature: {payload.get('detection_signature')}")


@app.post('/detect', response_model=DetectResponse)
async def detect_endpoint(req: DetectRequest, background_tasks: BackgroundTasks):
    if BOSS_TOKEN:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing Authorization header")
        token = authorization.split(" ", 1)[1]

        if not secrets.compare_digest(token, BOSS_TOKEN):
            raise HTTPException(status_code=403, detail="Invalid token")
    
    task_id = _generate_task_id()
    payload = req.dict()

    logger.info(f"📩 [POST /detect] Received event from {req.namespace}/{req.pod_name}")
    
    background_tasks.add_task(_enqueue_task, task_id, payload)
    return DetectResponse(status="received", task_id=task_id)


@app.get('/health')
async def health():
    return {"status": "ok"}


@app.get('/tasks/{task_id}')
async def get_task(task_id: str):
    task = TASK_STORE.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail='task not found')
    return task

if __name__ == '__main__':
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8032, log_level="info") 