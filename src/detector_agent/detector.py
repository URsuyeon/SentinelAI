# src/detector_agent/detector.py
import asyncio
import hashlib
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional, Tuple

# --- Kubernetes Client Import (선택적) ---
try:
    from kubernetes import client, config, watch
    from kubernetes.client.rest import ApiException
except Exception:
    client = None
    config = None
    watch = None
    ApiException = Exception


# 로그 설정
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s | %(levelname)s | DETECTOR | %(message)s')
logger = logging.getLogger(__name__)

# --- 환경 변수 기반 모킹/실제 실행 로직 ---
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://127.0.0.1:8032")
BOSS_TOKEN = os.getenv("BOSS_TOKEN", "dev-token")
DEBOUNCE_SECONDS = int(os.getenv("DEBOUNCE_SECONDS", "300"))
MAX_CONCURRENT_SENDS = int(os.getenv("MAX_CONCURRENT_SENDS", "10"))
QUEUE_MAX_SIZE = int(os.getenv("QUEUE_MAX_SIZE", "1000"))
CACHE_CLEANUP_INTERVAL = int(os.getenv("CACHE_CLEANUP_INTERVAL", "3600"))

app = FastAPI(title="Detector Agent API", version="0.1")

# DISABLE_DETECTOR_INTEGRATION=True 일 때 모킹 활성화 (사용자 요청에 따라 로직 반전)
DISABLE_DETECTOR_INTEGRATION = os.getenv("DISABLE_DETECTOR_INTEGRATION", "True").lower() in ('true', '1', 't')
logger.info(f"⚙️  Detector Integration Status: {'MOCKING' if DISABLE_DETECTOR_INTEGRATION else 'ACTIVE'}")

# --- 데이터 모델 ---
class ContainerStatusInfo(BaseModel):
    name: str
    ready: bool
    restart_count: int
    state_summary: str

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

# --- 핵심 로직 ---
class DetectorAgent:
    def __init__(self):
        # Kubernetes client availability
        self.k8s_available = True
        try:
            if config is None:
                raise Exception("kubernetes package not available")
            # Try in-cluster, fallback to kubeconfig
            try:
                config.load_incluster_config()
                logger.info("Loaded in-cluster config.")
            except Exception:
                config.load_kube_config()
                logger.info("Loaded local kube-config.")
        except Exception as e:
            logger.warning(f"No kubernetes config found or client unavailable: {e}. Running without watcher (no demo).")
            self.k8s_available = False

        self.v1 = client.CoreV1Api() if self.k8s_available and client is not None else None

        self.restart_tracker: Dict[str, Tuple[int, float]] = {}
        self.debounce_cache: Dict[str, float] = {}
        self.stop_event = threading.Event()

        self.http_client: Optional[httpx.AsyncClient] = None
        self.send_semaphore: Optional[asyncio.Semaphore] = None
        self.main_loop: Optional[asyncio.AbstractEventLoop] = None

        self.event_queue: Optional[asyncio.Queue] = None
        self.worker_task: Optional[asyncio.Task] = None

        self.start_time = time.time()

    async def start_resources(self):
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(timeout=10.0, verify=True)
        if self.send_semaphore is None:
            self.send_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SENDS)
        if self.event_queue is None:
            self.event_queue = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
            self.worker_task = asyncio.create_task(self._event_worker())
            logger.info("Event worker started.")

    async def close_resources(self):
        if self.worker_task:
            self.worker_task.cancel()
            try:
                await self.worker_task
            except asyncio.CancelledError:
                pass
        if self.http_client:
            await self.http_client.aclose()
            self.http_client = None

    def cleanup_stale_data(self):
        now = time.time()
        expired_sigs = [k for k, v in self.debounce_cache.items() if now - v > DEBOUNCE_SECONDS]
        for sig in expired_sigs:
            del self.debounce_cache[sig]

        expired_uids = [k for k, v in self.restart_tracker.items() if now - v[1] > 3600]
        for uid in expired_uids:
            del self.restart_tracker[uid]

        if expired_sigs or expired_uids:
            logger.info(f"Cleanup: removed {len(expired_sigs)} signatures, {len(expired_uids)} trackers.")

    def _generate_signature(self, ns: str, name: str, uid: str, reason: str) -> str:
        raw = f"{ns}:{name}:{uid}:{reason}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _is_debounced(self, signature: str) -> bool:
        last_time = self.debounce_cache.get(signature)
        return bool(last_time and (time.time() - last_time < DEBOUNCE_SECONDS))

    async def _safe_fetch(self, func, *args, **kwargs) -> str:
        try:
            return await asyncio.to_thread(func, *args, **kwargs)
        except Exception as e:
            return f"[Fetch Error] {str(e)}"

    def _get_k8s_logs(self, ns, name, container):
        if not self.v1:
            return f"[No K8s client] logs unavailable for {ns}/{name}/{container}"
        try:
            return self.v1.read_namespaced_pod_log(
                name=name, namespace=ns, container=container, tail_lines=50, _request_timeout=5
            )
        except ApiException as e:
            return f"[Log API Error] {getattr(e, 'reason', str(e))}"
        except Exception as e:
            return f"[Log Error] {str(e)}"

    def _get_k8s_events(self, ns, name, uid):
        if not self.v1:
            return f"[No K8s client] events unavailable for {ns}/{name}"
        try:
            fs = f"involvedObject.name={name},involvedObject.uid={uid},involvedObject.kind=Pod"
            events = self.v1.list_namespaced_event(namespace=ns, field_selector=fs, _request_timeout=5)
            lines = [f"--- Events for {name} ---"]
            if not events.items:
                lines.append("No events found.")
            else:
                sorted_ev = sorted(events.items, key=lambda x: x.last_timestamp or x.event_time or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
                for ev in sorted_ev[:5]:
                    lines.append(f"[{ev.last_timestamp}] {ev.type}: {ev.reason} - {ev.message}")
            return "\n".join(lines)[:800]
        except Exception as e:
            return f"[Describe API Error] {str(e)}"

    def _collect_anomalies(self, pod, uid, statuses) -> Tuple[List[str], Optional[str]]:
        reasons = []
        target_container = None

        WAITING_ERRORS = [
            "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull",
            "CreateContainerConfigError", "InvalidImageName", "ContainerCreating",
            "RunContainerError"
        ]

        phase = getattr(pod.status, "phase", "Unknown")

        if phase == "Failed" and getattr(pod.status, "reason", "") == "Evicted":
            reasons.append("Evicted")
            return reasons, None

        if phase == "Pending":
            conditions = getattr(pod.status, "conditions", []) or []
            for cond in conditions:
                if cond.type == "PodScheduled" and cond.status == "False" and cond.reason == "Unschedulable":
                    reasons.append(f"Unschedulable({cond.message})")
                    return reasons, None

        for cs in statuses:
            state = getattr(cs, "state", None)
            if not state:
                continue

            waiting = getattr(state, "waiting", None)
            if waiting:
                r_reason = getattr(waiting, "reason", None)
                if r_reason in WAITING_ERRORS:
                    reasons.append(f"Waiting({r_reason})")
                    if not target_container:
                        target_container = cs.name

            term = getattr(state, "terminated", None)
            if term:
                r_reason = getattr(term, "reason", None)
                exit_code = getattr(term, "exit_code", 0)
                signal = getattr(term, "signal", 0)

                is_oom = "oom" in (r_reason or "").lower() or exit_code == 137 or signal == 9
                is_start_error = r_reason in ["ContainerCannotRun", "StartError"]
                is_error = exit_code != 0

                if is_oom:
                    reasons.append(f"Terminated(OOMKilled, code={exit_code})")
                    target_container = cs.name
                elif is_start_error:
                    reasons.append(f"Terminated({r_reason})")
                    target_container = cs.name
                elif is_error:
                    reasons.append(f"Terminated(Error, code={exit_code}, signal={signal})")
                    if not target_container:
                        target_container = cs.name

            running = getattr(state, "running", None)
            if running and not getattr(cs, "ready", False):
                reasons.append(f"NotReady({cs.name})")
                if not target_container:
                    target_container = cs.name

        total_restarts = sum(getattr(cs, "restart_count", 0) for cs in statuses)
        prev_count, _ = self.restart_tracker.get(uid, (0, 0))

        if total_restarts >= prev_count + 3:
            reasons.append(f"RestartSurge(+{total_restarts - prev_count})")
            if statuses and not target_container:
                target_container = max(statuses, key=lambda x: getattr(x, "restart_count", 0)).name
        elif total_restarts > 5 and total_restarts > prev_count:
            if not any("RestartSurge" in r for r in reasons):
                reasons.append(f"HighRestartCount({total_restarts})")
                if statuses and not target_container:
                    target_container = max(statuses, key=lambda x: getattr(x, "restart_count", 0)).name

        self.restart_tracker[uid] = (total_restarts, time.time())

        return reasons, target_container

    def _build_payload(self, pod, event_type, reasons, signature, log_tail, describe_text):
        ns = pod.metadata.namespace
        name = pod.metadata.name
        uid = pod.metadata.uid
        status_obj = getattr(pod, "status", None)
        phase_str = getattr(status_obj, "phase", "Unknown") if status_obj else "Unknown"
        statuses = getattr(status_obj, "container_statuses", []) or []

        simple_statuses = []
        for cs in statuses:
            state = getattr(cs, "state", None)
            summary = "Unknown"
            if state:
                if getattr(state, "terminated", None):
                    t = state.terminated
                    summary = f"Terminated({getattr(t, 'reason', '')})"
                elif getattr(state, "waiting", None):
                    w = state.waiting
                    summary = f"Waiting({getattr(w, 'reason', '')})"
                elif getattr(state, "running", None):
                    summary = "Running"

            csi = ContainerStatusInfo(
                name=cs.name,
                ready=getattr(cs, "ready", False),
                restart_count=getattr(cs, "restart_count", 0),
                state_summary=summary
            )

            simple_statuses.append(csi.model_dump())

        return DetectRequest(
            timestamp=datetime.now(timezone.utc).isoformat(),
            namespace=ns, pod_name=name, event_type=event_type,
            phase=phase_str,
            container_statuses=simple_statuses,
            reasons=reasons,
            raw_log_tail=log_tail,
            describe_snippet=describe_text,
            metadata={"node": getattr(pod.spec, "node_name", ""), "uid": uid},
            detection_signature=signature
        )

    async def send_alert(self, payload: DetectRequest):
        if not self.http_client or not self.send_semaphore:
            missing = []
            if not self.http_client:
                missing.append("http_client")
            if not self.send_semaphore:
                missing.append("send_semaphore")
            logger.warning("Dropping alert because resources are not initialized: %s", ",".join(missing))
            return

        url = f"{ORCHESTRATOR_URL.rstrip('/')}/detect"
        headers = {"Authorization": f"Bearer {BOSS_TOKEN}"}

        async with self.send_semaphore:
            for attempt in range(3):
                try:
                    resp = await self.http_client.post(url, json=jsonable_encoder(payload), headers=headers)
                    resp.raise_for_status()
                    logger.info(f"✅ Sent: {payload.pod_name} ({payload.detection_signature}) Code:{resp.status_code}")
                    self.debounce_cache[payload.detection_signature] = time.time()
                    return
                except httpx.HTTPStatusError as e:
                    logger.warning(f"⚠️ HTTP Error ({attempt+1}/3): {getattr(e.response, 'status_code', '')} - {getattr(e.response, 'text', '')[:200]}")
                except Exception as e:
                    logger.exception(f"⚠️ Send Exception ({attempt+1}/3) for {payload.pod_name}: {e}")

                if attempt < 2:
                    await asyncio.sleep(1 * (2 ** attempt))

            logger.error(f"❌ Dropped alert for {payload.pod_name} after retries.")

    async def _event_worker(self):
        while True:
            try:
                pod, event_type = await self.event_queue.get()
                await self._process_event_task(pod, event_type)
                self.event_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker Error: {e}")

    async def _process_event_task(self, pod: client.V1Pod, event_type: str):
        if event_type != "MODIFIED":
            return
        try:
            ns = pod.metadata.namespace
            name = pod.metadata.name
            uid = pod.metadata.uid
            statuses = getattr(pod.status, "container_statuses", []) or []
        except AttributeError:
            return

        reasons, target_container = self._collect_anomalies(pod, uid, statuses)
        if not reasons:
            return

        summary = ",".join(reasons)
        sig = self._generate_signature(ns, name, uid, summary)
        if self._is_debounced(sig):
            return

        logger.info(f"Detect: {ns}/{name} - {summary}")

        log_data = await self._safe_fetch(self._get_k8s_logs, ns, name, target_container) if target_container else ""
        desc_data = await self._safe_fetch(self._get_k8s_events, ns, name, uid)

        payload = self._build_payload(pod, event_type, reasons, sig, log_data, desc_data)
        await self.send_alert(payload)

    def watch_loop(self):
        if not self.k8s_available or not self.v1:
            logger.info("Kubernetes client unavailable: watcher not started.")
            return

        w = watch.Watch()
        logger.info("Watcher thread started.")
        last_cleanup = time.time()

        while not self.stop_event.is_set():
            try:
                if time.time() - last_cleanup > CACHE_CLEANUP_INTERVAL:
                    self.cleanup_stale_data()
                    last_cleanup = time.time()

                for event in w.stream(self.v1.list_pod_for_all_namespaces, timeout_seconds=30):
                    if self.stop_event.is_set():
                        break

                    if self.main_loop and not self.main_loop.is_closed():
                        asyncio.run_coroutine_threadsafe(
                            self.event_queue.put((event['object'], event['type'])),
                            self.main_loop
                        )
            except Exception as e:
                logger.error(f"Watcher error: {e}")
                time.sleep(5)

        logger.info("Watcher thread stopped.")

async def _send_alert(alert: DetectRequest):
    """
    Orchestrator에 탐지 알림을 전송합니다.
    """
    url = f"{ORCHESTRATOR_URL}/detect"
    headers = {"Authorization": f"Bearer {BOSS_TOKEN}"}
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            payload = jsonable_encoder(alert)
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                logger.info(f"✅ [ALERT SENT] Alert for {alert.pod_name} sent to Orchestrator. Task ID: {resp.json().get('task_id')}")
            else:
                logger.error(f"❌ [ALERT FAIL] Failed to send alert. Status: {resp.status_code}, Body: {resp.text[:200]}")
    except Exception as e:
        logger.error(f"❌ [ALERT FAIL] Exception during alert sending: {e}")

async def _mock_detection_loop():
    """
    K8s 이상 탐지 루프를 모킹합니다. (5초마다 OOMKilled 시나리오 발생 모킹)
    """
    await asyncio.sleep(5) # 초기 대기
    
    while True:
        logger.info("👀 [SCANNING] K8s cluster for anomalies...")
        
        # OOMKilled 시나리오 모킹
        alert = DetectRequest(
            timestamp=datetime.utcnow(),
            namespace="default",
            pod_name="my-app-pod-abcde",
            event_type="PodFailed",
            phase="Failed",
            reasons=["OOMKilled"],
            describe_snippet="... Last State: Terminated, Reason: OOMKilled ...",
            raw_log_tail="Out of memory: Kill process 123 (java) score 999 or sacrifice child",
            detection_signature="oomkilled-pod-failure"
        )
        
        await _send_alert(alert)
        
        # 30초마다 반복
        await asyncio.sleep(30)
        


# --- API 엔드포인트 ---
agent = DetectorAgent()
@app.get('/health')
async def health():
    return {"status": "ok"}

@app.on_event("startup")
async def on_startup():
    agent.main_loop = asyncio.get_running_loop()
    await agent.start_resources()

    if DISABLE_DETECTOR_INTEGRATION:
        # 모킹 활성화 시, 모킹 루프 시작
        asyncio.create_task(_mock_detection_loop())
        logger.info("🚀 Detector Agent started mock detection loop.")
        return

    # 모킹 비활성화 시, K8s 클라이언트가 사용 가능하면 워처 시작
    if agent.k8s_available:
        # 워처 스레드 시작
        agent.main_loop.run_in_executor(None, agent.watch_loop)
        logger.info("🚀 Detector Agent started K8s watcher.")
    else:
        logger.warning("Kubernetes config not available and mock mode disabled: watcher not started.")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down Detector Agent...")
    agent.stop_event.set()
    await agent.close_resources()

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8033, log_level="info")
