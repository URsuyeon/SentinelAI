# src/notifier_agent/notifier.py
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import logging
import os
import httpx
import asyncio
import json
import hashlib
import hmac
from datetime import datetime
from urllib.parse import parse_qsl
from contextlib import asynccontextmanager
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
import threading

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | NOTIFIER | %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Slack Notifier API", version="0.1")
# DISABLE_SLACK_INTEGRATION=True 일 때 모킹 활성화 (사용자 요청에 따라 로직 반전)
DISABLE_SLACK_INTEGRATION = os.getenv("DISABLE_SLACK_INTEGRATION", "True").lower() in ('true', '1', 't')
logger.info(f"⚙️  Slack Integration Status: {'MOCKING' if DISABLE_SLACK_INTEGRATION else 'ACTIVE'}")

# --- 설정 로드 ---
def load_secrets():
    secret_path = "/app/secrets.json"  
    if not os.path.exists(secret_path):
        logger.warning("⚠️ secret/secret.json not found. Falling back to environment variable.")
        return os.getenv("SLACK_BOT_TOKEN"), os.getenv("SLACK_APP_TOKEN")
    
    try:
        with open(secret_path, 'r') as f:
            data = json.load(f)
            bot_token = data.get("SLACK_BOT_TOKEN")
            app_token = data.get("SLACK_APP_TOKEN")
            if not bot_token:
                logger.error("❌ SLACK_BOT_TOKEN missing in secrets.json")
            if not app_token:
                logger.error("❌ SLACK_APP_TOKEN missing in secrets.json")
            return bot_token, app_token
    except Exception as e:
        logger.error(f"❌ Failed to load SLACK_BOT_TOKEN from secret.json: {e}")
        return os.getenv("SLACK_BOT_TOKEN"), os.getenv("SLACK_APP_TOKEN")

SLACK_BOT_TOKEN, SLACK_APP_TOKEN = load_secrets()

if not DISABLE_SLACK_INTEGRATION:
    if not SLACK_BOT_TOKEN:
        logger.error("❌ SLACK_BOT_TOKEN not found!")
    if not SLACK_APP_TOKEN:
        logger.error("❌ SLACK_APP_TOKEN not found! (Required for Socket Mode)")

SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")  

# --- 데이터 모델 ---
class ApprovalRequest(BaseModel):
    task_id: str
    command_list: List[str]
    callback_url: str

class CompletionNotification(BaseModel):
    task_id: str
    status: str
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)

class ApprovalResponse(BaseModel):
    status: str

# --- Slack 서명 검증 ---
def verify_slack_request(request: Request, body: bytes) -> bool:
    if not SLACK_SIGNING_SECRET:
        logger.warning("SLACK_SIGNING_SECRET not set. Skipping verification.")
        return True

    timestamp = request.headers.get("X-Slack-Request-Timestamp")
    slack_signature = request.headers.get("X-Slack-Signature")

    if not timestamp or not slack_signature:
        return False

    # 5분 이상 오래된 요청 차단 (replay attack 방지)
    import time
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False

    basestring = f"v0:{timestamp}:{body.decode()}"
    computed = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(),
        basestring.encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(computed, slack_signature)

# --- 실제 Slack 메시지 전송 ---
async def _send_slack_message(channel: str = None, text: str = None, blocks: Optional[List[Dict]] = None):
    if DISABLE_SLACK_INTEGRATION:
        logger.info(f"⚙️ [MOCK SLACK] Message: {text or 'No text'}")
        if blocks:
            logger.info(f"⚙️ [MOCK SLACK] Blocks: {blocks}")
        return

    if not SLACK_BOT_TOKEN:
        logger.error("❌ Cannot send Slack message: SLACK_BOT_TOKEN missing")
        return

    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "channel": channel or os.getenv("SLACK_DEFAULT_CHANNEL", "sentinel-alerts"),
        "text": text or "Sentinel AI Notification",
    }
    if blocks:
        payload["blocks"] = blocks

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, json=payload, headers=headers, timeout=10.0)
            data = resp.json()
            if data.get("ok"):
                logger.info(f"✅ [SLACK SENT] Message sent successfully.")
            else:
                logger.error(f"❌ [SLACK ERROR] Failed to send message: {data.get('error')} | Full response: {data}")
        except Exception as e:
            logger.error(f"❌ [SLACK SEND FAIL] {e}")

# --- 승인 요청 메시지 생성 ---
async def _send_approval_request(req: ApprovalRequest):
    task_id = req.task_id
    commands_text = "\n".join(req.command_list)

    blocks = [
        # 큰 헤더 (위험 강조)
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 위험 명령 승인 요청",
                "emoji": True
            }
        },
        # Task ID 강조
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Task ID*: `{task_id}`"
            }
        },
        # 실행 명령어 (코드 블록으로 깔끔하게)
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*실행될 명령어*"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"```{commands_text}```"
            }
        },
        # 승인/거부 버튼 (크고 선명하게)
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "✅ 승인"
                    },
                    "style": "primary",  # 녹색
                    "action_id": "approve",
                    "value": task_id
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "❌ 거부"
                    },
                    "style": "danger",   # 빨강
                    "action_id": "reject",
                    "value": task_id
                }
            ]
        },
        # 하단 안내 문구
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "_5분 동안 응답이 없으면 자동으로 승인됩니다._"
                }
            ]
        }
    ]

    fallback_text = f"🚨 위험 명령 승인 요청 | Task ID: {task_id} | 명령어: {req.command_list[0]}"

    await _send_slack_message(text=fallback_text, blocks=blocks)
    
# --- 완료 알림 ---
async def _send_completion_notification(req: CompletionNotification):
    status = req.status
    summary = req.summary
    task_id = req.task_id

    # 상태별 설정
    if "auto_approved" in status:
        header_emoji = "⏰"
        header_text = "자동 승인 및 실행 완료"
        color = "#FFA500"  # 주황
        extra_text = "*5분 동안 응답이 없어 자동으로 승인 후 실행되었습니다.*"
    elif status == "resolved":
        header_emoji = "✅"
        header_text = "문제 해결 완료"
        color = "#36A64F"  # 녹색
        extra_text = "*위험 명령어가 성공적으로 실행되었습니다.*"
    elif "failed" in status:
        header_emoji = "❌"
        header_text = "실행 실패"
        color = "#E01E5A"  # 빨강
        extra_text = "*명령어 실행 중 오류가 발생했습니다.*"
    elif status == "rejected_by_operator":
        header_emoji = "🚫"
        header_text = "운영자에 의해 거부됨"
        color = "#808080"  # 회색
        extra_text = "*운영자가 위험 명령 실행을 거부했습니다.*"
    else:
        header_emoji = "ℹ️"
        header_text = "작업 완료"
        color = "#4A90E2"
        extra_text = ""

    blocks = [
        # 큰 헤더 (색상 강조)
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{header_emoji} {header_text}",
                "emoji": True
            }
        },
        # 상태와 Task ID 나란히 배치 (fields 사용 → 깔끔한 2열)
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*상태*\n`{status}`"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Task ID*\n`{task_id}`"
                }
            ]
        },
        # 요약
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*요약*\n{summary}"
            }
        },
    ]

    # 추가 설명 있으면 넣기
    if extra_text:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": extra_text
            }
        })

    # 구분선 + 타임스탬프
    blocks += [
        {"type": "divider"},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"알림 시간: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
                }
            ]
        }
    ]

    fallback_text = f"{header_emoji} {header_text} | Task ID: {task_id} | 상태: {status}"

    await _send_slack_message(text=fallback_text, blocks=blocks)

# --- API 엔드포인트 ---
bolt_app = App(token=SLACK_BOT_TOKEN)

@bolt_app.action("approve")
def handle_approve(ack, body, logger):
    ack()  
    task_id = body["actions"][0]["value"]
    user_name = body["user"]["username"]
    logger.info(f"✅ Task {task_id} approved by {user_name}")

    callback_url = os.getenv("ORCHESTRATOR_CALLBACK_URL", "http://orchestrator:8032/slack/callback")
    callback_payload = {
        "task_id": task_id,
        "approved": True,
        "reason": f"Approved by {user_name}"
    }
    
    try:
        response = httpx.post(callback_url, json=callback_payload, timeout=10.0)
        if response.status_code == 200:
            logger.info(f"✅ Callback sent successfully to orchestrator")
        else:
            logger.error(f"❌ Callback failed: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"❌ Callback exception: {e}")

    bolt_app.client.chat_postMessage(
        channel=body["channel"]["id"],
        text=f"✅ {user_name}님이 Task `{task_id}`를 승인했습니다!"
    )

@bolt_app.action("reject")
def handle_reject(ack, body, logger):
    ack()
    task_id = body["actions"][0]["value"]
    user_name = body["user"]["username"]
    logger.info(f"❌ Task {task_id} rejected by {user_name}")

    callback_url = os.getenv("ORCHESTRATOR_CALLBACK_URL", "http://orchestrator:8032/slack/callback")
    callback_payload = {
        "task_id": task_id,
        "approved": False,
        "reason": f"Rejected by {user_name}"
    }
    
    try:
        httpx.post(callback_url, json=callback_payload, timeout=10.0)
    except Exception as e:
        logger.error(f"❌ Reject callback failed: {e}")

    bolt_app.client.chat_postMessage(
        channel=body["channel"]["id"],
        text=f"❌ {user_name}님이 Task `{task_id}`를 거부했습니다!"
    )

handler = None # 타입 힌트도 변경

@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    global handler
    if not DISABLE_SLACK_INTEGRATION and SLACK_APP_TOKEN:
        logger.info("🚀 Initializing Slack Socket Mode handler...")
        handler = SocketModeHandler(bolt_app, SLACK_APP_TOKEN)
        
        def run_handler():
            handler.start()  
        
        thread = threading.Thread(target=run_handler, daemon=True)
        thread.start()
        
        logger.info("✅ Slack Socket Mode handler started in background thread.")
    
    yield
    
    if handler:
        logger.info("🛑 Shutting down Slack Socket Mode handler...")


app = FastAPI(title="Slack Notifier API", version="0.1", lifespan=lifespan)

# --- /notify/approval 엔드포인트 ---
@app.post('/notify/approval')
async def notify_approval(req: ApprovalRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(_send_approval_request, req)
    return {"status": "accepted"}


@app.get('/health')
async def health():
    return {"status": "ok"}

@app.post('/notify/completion')
async def notify_completion(req: CompletionNotification, background_tasks: BackgroundTasks):
    background_tasks.add_task(_send_completion_notification, req)
    return {"status": "accepted"}

async def _send_approval_callback(task_id: str, approved: bool, user_name: str):
    callback_payload = {
        "task_id": task_id,
        "approved": approved,
        "reason": f"{user_name} via Slack slash command"
    }

    async with httpx.AsyncClient() as client:
        try:
            orchestrator_callback = os.getenv("ORCHESTRATOR_CALLBACK_URL", "http://orchestrator:8032/slack/callback")
            resp = await client.post(orchestrator_callback, json=callback_payload, timeout=10.0)
            if resp.status_code == 200:
                logger.info(f"✅ [SLASH CALLBACK] Task {task_id} {'approved' if approved else 'rejected'} by {user_name}")
            else:
                logger.error(f"❌ [SLASH CALLBACK FAIL] {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"❌ [SLASH CALLBACK ERROR] {e}")

# --- 기존 MOCK 함수들 ---
async def _mock_send_approval_request(req: ApprovalRequest):
    task_id = req.task_id
    message = f"🚨 **위험 명령 승인 요청**"
    commands_text = "\n".join([f"{cmd}" for cmd in req.command_list])

    # Slack에서 클릭하면 명령어 자동 입력되는 링크!
    approve_link = f"<slack:/approve {task_id}|✅ 승인 (클릭하면 자동 입력)>"
    reject_link = f"<slack:/reject {task_id}|❌ 거부 (클릭하면 자동 입력)>"

    # task_id 강조 표시 (코드 블록으로 → 클릭 시 전체 선택)
    task_id_code = f"`{task_id}`"

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": message}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Task ID:* {task_id_code}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*실행 명령어:*\n```{commands_text}```"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{approve_link}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{reject_link}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "_클릭하면 아래 입력창에 명령어가 자동으로 들어갑니다. 엔터만 누르세요!_"}},
        {"type": "divider"}
    ]

    await _send_slack_message(text=message + f" (Task {task_id})", blocks=blocks)
    
    await asyncio.sleep(5)
    callback_payload = {
        "task_id": req.task_id,
        "approved": True,
        "reason": "Mocked automatic approval after 5 seconds."
    }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(req.callback_url, json=callback_payload)
            if resp.status_code == 200:
                logger.info(f"✅ [MOCK CALLBACK] Task {req.task_id} approval callback sent.")
            else:
                logger.error(f"❌ [MOCK CALLBACK FAIL] Status: {resp.status_code}")
    except Exception as e:
        logger.error(f"❌ [MOCK CALLBACK FAIL] {e}")

async def _mock_send_completion_notification(req: CompletionNotification):
    status_emoji = "✅" if req.status == "resolved" else "❌" if req.status.startswith("failed") else "🚫"
    message = f"{status_emoji} **작업 완료 알림** (Task ID: {req.task_id})\n"
    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": message}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"**상태:** {req.status}\n**요약:** {req.summary}"}},
        {"type": "divider"}
    ]
    
    await _send_slack_message(message, blocks)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run("notifier:app", host="0.0.0.0", port=8037, reload=True)