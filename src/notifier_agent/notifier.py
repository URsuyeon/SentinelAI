# src/notifier_agent/notifier.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import logging
import os
import httpx
import asyncio

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | NOTIFIER | %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Slack Notifier API", version="0.1")

# --- 환경 변수 기반 모킹/실제 실행 로직 ---
# DISABLE_SLACK_INTEGRATION=True 일 때 모킹 활성화 (사용자 요청에 따라 로직 반전)
DISABLE_SLACK_INTEGRATION = os.getenv("DISABLE_SLACK_INTEGRATION", "True").lower() in ('true', '1', 't')
logger.info(f"⚙️  Slack Integration Status: {'MOCKING' if DISABLE_SLACK_INTEGRATION else 'ACTIVE'}")

# --- 데이터 모델 ---

class ApprovalRequest(BaseModel):
    task_id: str
    command_list: List[str]
    callback_url: str

class CompletionNotification(BaseModel):
    task_id: str
    status: str # 'resolved', 'failed_resolution', 'rejected_by_operator'
    summary: str
    details: Dict[str, Any]

class SlackCallback(BaseModel):
    task_id: str
    approved: bool
    reason: Optional[str] = None

class ApprovalResponse(BaseModel):
    status: str

# --- 핵심 로직 ---

async def _send_slack_message(message: str, blocks: Optional[List[Dict[str, Any]]] = None):
    """
    실제 Slack API를 호출하여 메시지를 전송합니다. (미구현)
    """
    # TODO: 실제 Slack Webhook URL 또는 API 토큰을 사용하여 메시지 전송 로직 구현
    logger.warning(f"⚠️ [SLACK SEND] Actual Slack message sending is not yet implemented. Message: {message[:50]}...")
    
    # 모킹 모드에서는 로그로 출력
    if DISABLE_SLACK_INTEGRATION:
        logger.info(f"⚙️ [MOCK SLACK] Message: {message}")
        if blocks:
            logger.info(f"⚙️ [MOCK SLACK] Blocks: {blocks}")


async def _mock_send_approval_request(req: ApprovalRequest):
    """
    Slack으로 승인 요청 메시지를 보내고, 5초 후 모킹 응답을 보냅니다.
    """
    message = f"🚨 **위험 명령 승인 요청** (Task ID: {req.task_id})"
    commands_text = "\n".join(req.command_list)

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": message}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"실행 명령어:\n```\n{commands_text}\n```"}} ,
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "✅ 승인"}, "style": "primary", "value": "approved"},
            {"type": "button", "text": {"type": "plain_text", "text": "❌ 거부"}, "style": "danger", "value": "rejected"}
        ]}
    ]
    await _send_slack_message(message, blocks)
    
    # 5초 후 승인 콜백 모킹
    await asyncio.sleep(5)
    
    callback_payload = {
        "task_id": req.task_id,
        "approved": True, # 기본적으로 승인 모킹
        "reason": "Mocked automatic approval after 5 seconds."
    }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(req.callback_url, json=callback_payload)
            if resp.status_code == 200:
                logger.info(f"✅ [MOCK CALLBACK] Task {req.task_id} approval callback sent to Orchestrator.")
            else:
                logger.error(f"❌ [MOCK CALLBACK FAIL] Failed to send mock callback. Status: {resp.status_code}, Body: {resp.text[:200]}")
    except Exception as e:
        logger.error(f"❌ [MOCK CALLBACK FAIL] Exception during mock callback: {e}")

async def _mock_send_completion_notification(req: CompletionNotification):
    """
    Slack으로 완료 알림 메시지를 보냅니다.
    """
    status_emoji = "✅" if req.status == "resolved" else "❌" if req.status.startswith("failed") else "🚫"
    message = f"{status_emoji} **작업 완료 알림** (Task ID: {req.task_id})"
    
    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": message}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"**상태:** {req.status}\n**요약:** {req.summary}"}},
        {"type": "divider"}
    ]
    
    await _send_slack_message(message, blocks)

# --- API 엔드포인트 ---

@app.post('/notify/approval', response_model=ApprovalResponse)
async def notify_approval(req: ApprovalRequest, background_tasks: BackgroundTasks):
    logger.info(f"📩 [POST /notify/approval] Received approval request for Task {req.task_id}.")
    
    if DISABLE_SLACK_INTEGRATION:
        background_tasks.add_task(_mock_send_approval_request, req)
    else:
        # TODO: 실제 Slack 메시지 전송 로직을 _send_slack_message에 구현하고 여기서 호출
        background_tasks.add_task(_send_slack_message, f"🚨 **위험 명령 승인 요청** (Task ID: {req.task_id})", None)
        logger.warning("⚠️ [SLACK] Actual Slack approval request sent. Waiting for operator action.")
        
    return ApprovalResponse(status="accepted")

@app.post('/notify/completion')
async def notify_completion(req: CompletionNotification, background_tasks: BackgroundTasks):
    logger.info(f"📩 [POST /notify/completion] Received completion notification for Task {req.task_id}. Status: {req.status}")
    
    if DISABLE_SLACK_INTEGRATION:
        background_tasks.add_task(_mock_send_completion_notification, req)
    else:
        # TODO: 실제 Slack 메시지 전송 로직을 _send_slack_message에 구현하고 여기서 호출
        status_emoji = "✅" if req.status == "resolved" else "❌" if req.status.startswith("failed") else "🚫"
        background_tasks.add_task(_send_slack_message, f"{status_emoji} **작업 완료 알림** (Task ID: {req.task_id})", None)
        
    return {"status": "accepted"}

@app.get('/health')
async def health():
    return {"status": "ok"}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8037, log_level="info")
