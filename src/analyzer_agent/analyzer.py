# src/analyzer_agent/analyzer.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import logging
import json
import os
import asyncio
import hashlib
import httpx
import uuid
import google.genai as genai  
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchValue

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | ANALYZER | %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Analyzer Agent API", version="0.1")

# --- 시크릿 로드 ---
SECRETS_PATH = os.getenv("SECRETS_PATH", "/app/secrets.json")

def load_secrets() -> Dict[str, str]:
    if not os.path.exists(SECRETS_PATH):
        logger.warning(f"⚠️ Secrets file not found: {SECRETS_PATH}")
        return {}
    try:
        with open(SECRETS_PATH, "r") as f:
            secrets = json.load(f)
        logger.info(f"🔑 Secrets loaded from {SECRETS_PATH}")
        return secrets
    except Exception as e:
        logger.error(f"Failed to load secrets: {e}")
        return {}

secrets = load_secrets()

# 각 LLM별 API 키
OPENAI_API_KEY = secrets.get("OPENAI_API_KEY")
GEMINI_API_KEY = secrets.get("GEMINI_API_KEY")
GROK_API_KEY = secrets.get("GROK_API_KEY")

# --- 환경 변수 ---
DISABLE_LLM_INTEGRATION = os.getenv("DISABLE_LLM_INTEGRATION", "True").lower() in ('true', '1', 't')
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini").lower()  # openai / gemini / grok

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "analyzer_cache")

logger.info(f"⚙️ LLM Provider: {LLM_PROVIDER.upper()}")
logger.info(f"⚙️ LLM Integration Status: {'MOCKING' if DISABLE_LLM_INTEGRATION else 'ACTIVE'}")

if not DISABLE_LLM_INTEGRATION:
    if LLM_PROVIDER == "openai" and not OPENAI_API_KEY:
        logger.error("❌ OPENAI_API_KEY missing!")
    elif LLM_PROVIDER == "gemini" and not GEMINI_API_KEY:
        logger.error("❌ GEMINI_API_KEY missing!")
    elif LLM_PROVIDER == "grok" and not GROK_API_KEY:
        logger.error("❌ GROK_API_KEY missing!")

# Gemini 초기화 (gemini 선택 시에만 필요)
if LLM_PROVIDER == "gemini" and not DISABLE_LLM_INTEGRATION:
    genai.configure(api_key=GEMINI_API_KEY)

# --- Qdrant 클라이언트 초기화 ---
qdrant_client = QdrantClient(url=QDRANT_URL, prefer_grpc=True)

COLLECTION_NAME = QDRANT_COLLECTION

async def init_qdrant_collection():
    """앱 시작 시 컬렉션 생성 (이미 있으면 무시)"""
    collections = await asyncio.to_thread(qdrant_client.get_collections)
    collection_names = [c.name for c in collections.collections]
    
    if COLLECTION_NAME not in collection_names:
        await asyncio.to_thread(
            qdrant_client.create_collection,
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=128, distance=Distance.COSINE),
        )
        logger.info(f"Created Qdrant collection: {COLLECTION_NAME}")
    else:
        logger.info(f"Qdrant collection {COLLECTION_NAME} already exists")

@app.on_event("startup")
async def startup_event():
    await init_qdrant_collection()

# --- 데이터 모델 ---
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
    event_types: Optional[List[str]] = None
    detection_signatures: Optional[List[str]] = None
    original_events: Optional[List[Dict]] = None
    class Config:
        extra = 'allow'

class AnalyzeCommandResponse(BaseModel):
    command_type: str  # 'read' or 'write'
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

# --- 캐시 키 생성 ---
def make_cache_key(detect_request: DetectRequest, is_final: bool = False) -> str:
    base = f"{detect_request.detection_signature or 'unknown'}:{detect_request.pod_name}:{'final' if is_final else 'initial'}"
    return hashlib.sha256(base.encode()).hexdigest()

# --- Qdrant 캐시 조회/저장 ---
async def get_cached_command(cache_key: str) -> Optional[AnalyzeCommandResponse]:
    try:
        result = await asyncio.to_thread(
            qdrant_client.search,
            collection_name=COLLECTION_NAME,
            query_vector=[0.0] * 128,  # 더미 벡터
            query_filter=Filter(
                must=[FieldCondition(key="cache_key", match=MatchValue(value=cache_key))]
            ),
            limit=1
        )
        if result:
            payload = result[0].payload
            return AnalyzeCommandResponse(**payload["response"])
    except Exception as e:
        logger.warning(f"Qdrant cache lookup failed: {e}")
    return None

async def save_to_cache(cache_key: str, response: AnalyzeCommandResponse):
    try:
        point_id = str(uuid.uuid4())
        point = PointStruct(
            id=point_id,
            vector=[0.0] * 128,
            payload={
                "cache_key": cache_key,
                "response": response.dict()
            }
        )
        await asyncio.to_thread(
            qdrant_client.upsert,
            collection_name=COLLECTION_NAME,
            points=[point]
        )
        logger.info(f"💾 [CACHE SAVE] Saved command for key {cache_key[:12]}...")
    except Exception as e:
        logger.error(f"Qdrant cache save failed: {e}")

# --- LLM 입력 페이로드 생성 ---
def build_llm_input(detect_request: DetectRequest, execution_logs: Optional[List[Dict]] = None,
                    rag_results: Optional[List[Dict]] = None) -> Dict[str, Any]:
    """
    LLM에 보낼 최적화된 페이로드 생성 (Core Signal만, 중복·메타 제거)
    """
    incident = {
        "namespace": detect_request.namespace,
        "pod": detect_request.pod_name,
        "types": detect_request.event_types or [detect_request.event_type],
        "reasons": detect_request.reasons or [],
        "phase": detect_request.phase,
        "container_statuses": detect_request.container_statuses or [],
        "logs": detect_request.raw_log_tail.strip() if detect_request.raw_log_tail else "",
        "describe": detect_request.describe_snippet.strip() if detect_request.describe_snippet else "",
        "timestamp": str(detect_request.timestamp),
    }

    # detection_signature 요약
    if detect_request.detection_signatures:
        incident["detection_hint"] = f"Detected {len(detect_request.detection_signatures)} times"
    
    # RAG 결과 요약 (최대 3개)
    rag_summary = []
    if rag_results:
        for r in rag_results[:3]:
            title = r.get("title", "Unknown")
            summary = r.get("summary") or r.get("content", "")[:200] + "..." if not r.get("summary") else r.get("summary")
            rag_summary.append({"title": title, "summary": summary})

    # execution_logs 요약 (에러·중요 정보만)
    log_summary = []
    if execution_logs:
        for log in execution_logs:
            if log.get("status") == "error" or "error" in log.get("output", "").lower():
                log_summary.append({
                    "command": log.get("command"),
                    "error": log.get("output")[:500] + "..." if len(log.get("output", "")) > 500 else log.get("output")
                })
            elif "OOMKilled" in log.get("output", "") or "CrashLoopBackOff" in log.get("output", ""):
                log_summary.append({
                    "command": log.get("command"),
                    "key_info": log.get("output")[:500] + "..."
                })
    
    payload = {
        "incident": incident,
    }
    if log_summary:
        payload["observations"] = {"kubectl_results": log_summary}
    if rag_summary:
        payload["observations"] = payload.get("observations", {}) | {"rag_hints": rag_summary}

    return payload

# --- 모킹 함수 ---
def _mock_llm_generate_initial_command(req: InitialAnalyzeRequest) -> AnalyzeCommandResponse:
    logger.info(f"🧠 [MOCK] Initial command for {req.detect_request.pod_name}")
    commands = [
        f"kubectl describe pod {req.detect_request.pod_name} -n {req.detect_request.namespace}",
        f"kubectl logs {req.detect_request.pod_name} -n {req.detect_request.namespace} --tail=50"
    ]
    return AnalyzeCommandResponse(command_type="read", command_list=commands, is_risky=False)

def _mock_llm_generate_final_command(req: FinalAnalyzeRequest) -> AnalyzeCommandResponse:
    logger.info(f"🧠 [MOCK] Final command for {req.detect_request.pod_name}")
    commands = ["echo 'No critical issue requiring write command.'"]
    is_risky = False
    if any("OOMKilled" in str(log.get("output", "")) for log in req.execution_logs):
        commands = [f"kubectl delete pod {req.detect_request.pod_name} -n {req.detect_request.namespace}"]
        is_risky = True
    return AnalyzeCommandResponse(command_type="write", command_list=commands, is_risky=is_risky)

# --- 실제 LLM 호출 (통합 버전) ---
async def _call_llm_api(req: InitialAnalyzeRequest | FinalAnalyzeRequest, is_final: bool) -> AnalyzeCommandResponse:
    if DISABLE_LLM_INTEGRATION:
        raise ValueError("LLM integration is disabled")

    payload = build_llm_input(
        req.detect_request,
        req.execution_logs if isinstance(req, FinalAnalyzeRequest) else None,
        req.rag_results if isinstance(req, FinalAnalyzeRequest) else None
    )

    # 공통 프롬프트
    system_prompt = (
    "You are an expert Kubernetes troubleshooter. "
    "Analyze the incident carefully and suggest the MINIMAL set of kubectl commands needed.\n"
    "Rules:\n"
    "- Initial phase: Suggest ONLY 'read' commands for information gathering.\n"
    "- Final phase: Suggest 'write' commands only if necessary to fix the issue.\n"
    "- Always limit command_list to 1-3 commands MAXIMUM. Prioritize the most impactful ones first.\n"
    "- Do not suggest redundant or similar commands (e.g., avoid both 'describe pod' and 'get pod -o yaml').\n"
    "- 'is_risky' must be true only for destructive commands (delete, scale, edit, etc.).\n"
    "Return ONLY a valid JSON object with exactly these keys:\n"
    '- "command_type": "read" or "write"\n'
    '- "command_list": array of kubectl command strings (1-3 items max)\n'
    '- "is_risky": boolean\n'
    "No explanations, no additional text, no markdown."
    )

    if is_final:
        system_prompt += "\nThis is the final analysis phase. If a fix is clearly needed and safe, suggest minimal 'write' commands."
        user_prompt = f"Final analysis - suggest minimal fix commands if necessary:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
    else:
        system_prompt += "\nThis is the initial analysis phase. Suggest only the most essential 'read' commands to gather critical information."
        user_prompt = f"Initial analysis - suggest minimal investigation commands:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
    
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            if LLM_PROVIDER == "openai":
                api_payload = {
                    "model": "gpt-4o",  # 또는 gpt-4-turbo, gpt-3.5-turbo 등 원하는 모델
                    "temperature": 0.2,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "response_format": {"type": "json_object"}
                }
                headers = {
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json"
                }
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers=headers,
                    json=api_payload
                )

            elif LLM_PROVIDER == "gemini":
                model = genai.GenerativeModel('gemini-1.5-pro')
                response = await asyncio.to_thread(
                    model.generate_content,
                    gemini_prompt,
                    generation_config=genai.GenerationConfig(
                        temperature=0.2,
                        response_mime_type="application/json"
                    )
                )
                content = response.text
                try:
                    parsed = json.loads(content)
                    return AnalyzeCommandResponse(**parsed)
                except json.JSONDecodeError:
                    logger.error(f"Gemini JSON parse failed: {content}")
                    raise HTTPException(status_code=500, detail="Invalid LLM response")

            elif LLM_PROVIDER == "grok":
                api_payload = {
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "model": "grok-beta",  
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"}
                }
                headers = {
                    "Authorization": f"Bearer {GROK_API_KEY}",
                    "Content-Type": "application/json"
                }
                response = await client.post(
                    "https://api.x.ai/v1/chat/completions",
                    headers=headers,
                    json=api_payload
                )

            else:
                raise ValueError(f"Unsupported LLM_PROVIDER: {LLM_PROVIDER}")

            # OpenAI / Grok 공통 처리
            if LLM_PROVIDER in ["openai", "grok"]:
                response.raise_for_status()
                result = response.json()
                content = result["choices"][0]["message"]["content"]

                try:
                    parsed = json.loads(content)
                    return AnalyzeCommandResponse(
                        command_type=parsed.get("command_type", "read" if not is_final else "write"),
                        command_list=parsed.get("command_list", []),
                        is_risky=parsed.get("is_risky", False)
                    )
                except json.JSONDecodeError:
                    logger.error(f"JSON parse failed ({LLM_PROVIDER}): {content}")
                    raise HTTPException(status_code=500, detail="Invalid LLM response format")

        except httpx.HTTPStatusError as e:
            logger.error(f"LLM API error ({LLM_PROVIDER}): {e.response.text}")
            raise HTTPException(status_code=500, detail="LLM API call failed")
        except Exception as e:
            logger.error(f"Unexpected LLM error ({LLM_PROVIDER}): {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))

# --- 공통 분석 함수 및 엔드포인트 (캐시 포함) ---
async def analyze_common(req: InitialAnalyzeRequest | FinalAnalyzeRequest, is_final: bool):
    cache_key = make_cache_key(req.detect_request, is_final=is_final)
    logger.info(f"🔍 [CACHE CHECK] Task {req.task_id} | Key: {cache_key[:12]}...")

    cached = await get_cached_command(cache_key)
    if cached:
        logger.info(f"🎯 [CACHE HIT] Task {req.task_id}")
        return cached

    if DISABLE_LLM_INTEGRATION:
        response = _mock_llm_generate_final_command(req) if is_final else _mock_llm_generate_initial_command(req)
    else:
        response = await _call_llm_api(req, is_final)

    await save_to_cache(cache_key, response)
    return response

# --- API 엔드포인트 ---
@app.post('/analyze/initial')
async def analyze_initial(req: InitialAnalyzeRequest):
    logger.info(f"📩 [POST /analyze/initial] Task {req.task_id}")
    return await analyze_common(req, is_final=False)

@app.post('/analyze/final')
async def analyze_final(req: FinalAnalyzeRequest):
    logger.info(f"📩 [POST /analyze/final] Task {req.task_id}")
    return await analyze_common(req, is_final=True)

@app.get('/health')
async def health():
    return {"status": "ok"}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8034, log_level="info")