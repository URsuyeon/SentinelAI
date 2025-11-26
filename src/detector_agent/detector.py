import os
import sys
import time
import json
import logging
import asyncio
import hashlib
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, Field
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException

# ------------------------------------------------------------------------------
# 1. 설정 및 환경 변수
# ------------------------------------------------------------------------------
BOSS_URL = os.getenv("BOSS_URL", "")
BOSS_TOKEN = os.getenv("BOSS_TOKEN", "")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
DEBOUNCE_SECONDS = int(os.getenv("DEBOUNCE_SECONDS", "300"))
MAX_CONCURRENT_SENDS = 10
QUEUE_MAX_SIZE = 1000  
CACHE_CLEANUP_INTERVAL = 3600

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("DetectorAgent")

# ------------------------------------------------------------------------------
# 2. 데이터 모델
# ------------------------------------------------------------------------------
class ContainerStatusInfo(BaseModel):
    name: str
    ready: bool
    restart_count: int
    state_summary: str

class AlertPayload(BaseModel):
    timestamp: str
    namespace: str
    pod_name: str
    event_type: str
    phase: str
    container_statuses: List[ContainerStatusInfo]
    raw_log_tail: str = Field(default="")
    describe_snippet: str = Field(default="")
    metadata: Dict[str, Any]
    detection_signature: str

# ------------------------------------------------------------------------------
# 3. Detector Agent 구현
# ------------------------------------------------------------------------------
class DetectorAgent:
    def __init__(self):
        # Kubernetes 클라이언트
        # Try in-cluster, then local kubeconfig. If both fail, run in "demo" mode instead of exiting.
        self.k8s_available = True
        try:
            config.load_incluster_config()
            logger.info("Loaded in-cluster config.")
        except config.ConfigException:
            try:
                config.load_kube_config()
                logger.info("Loaded local kube-config.")
            except Exception as e:
                logger.warning(f"No kubernetes config found, running in demo mode: {e}")
                self.k8s_available = False

        self.v1 = client.CoreV1Api() if self.k8s_available else None
    
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
        # Async 리소스 및 Worker 초기화
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(timeout=5.0, verify=True)
        
        if self.send_semaphore is None:
            self.send_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SENDS)

        if self.event_queue is None:
            self.event_queue = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
            self.worker_task = asyncio.create_task(self._event_worker())
            logger.info("Event worker started.")

    async def close_resources(self):
        # Worker 종료
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
        # 메모리 정리
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
            return f"[Log API Error] {e.reason}"
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

    # 탐지 & 보고 
    def _collect_anomalies(self, pod, uid, statuses) -> Tuple[List[str], Optional[str]]:
        reasons = []
        target_container = None
        
        # 에러 리스트 
        WAITING_ERRORS = [
            "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", 
            "CreateContainerConfigError", "InvalidImageName", "ContainerCreating",
            "RunContainerError"
        ]
        
        # pod 상태
        phase = getattr(pod.status, "phase", "Unknown")
        
        # Evicted 상태 
        if phase == "Failed" and getattr(pod.status, "reason", "") == "Evicted":
             reasons.append("Evicted")
             return reasons, None 

        # Pending 상태 및 스케줄링 실패(Unschedulable) 
        if phase == "Pending":
            conditions = getattr(pod.status, "conditions", []) or []
            for cond in conditions:
                if cond.type == "PodScheduled" and cond.status == "False" and cond.reason == "Unschedulable":
                    reasons.append(f"Unschedulable({cond.message})")
                    return reasons, None

        # 컨테이너 상태
        for cs in statuses:
            state = getattr(cs, "state", None)
            if not state: continue

            # Waiting 상태
            waiting = getattr(state, "waiting", None)
            if waiting:
                r_reason = getattr(waiting, "reason", None)
                if r_reason in WAITING_ERRORS:
                    reasons.append(f"Waiting({r_reason})")
                    if not target_container: target_container = cs.name

            # Terminated 상태 
            term = getattr(state, "terminated", None)
            if term:
                r_reason = getattr(term, "reason", None)
                exit_code = getattr(term, "exit_code", 0)
                signal = getattr(term, "signal", 0)
                
                # OOMKilled 체크 
                is_oom = "oom" in (r_reason or "").lower() or exit_code == 137 or signal == 9
                # 시작 실패 체크
                is_start_error = r_reason in ["ContainerCannotRun", "StartError"]
                # 일반 에러 종료 (0이 아님)
                is_error = exit_code != 0
                
                if is_oom:
                    reasons.append(f"Terminated(OOMKilled, code={exit_code})")
                    target_container = cs.name
                elif is_start_error:
                    reasons.append(f"Terminated({r_reason})")
                    target_container = cs.name
                elif is_error:
                    reasons.append(f"Terminated(Error, code={exit_code}, signal={signal})")
                    if not target_container: target_container = cs.name

            # Readiness Probe 실패 
            running = getattr(state, "running", None)
            if running and not getattr(cs, "ready", False):
                reasons.append(f"NotReady({cs.name})")
                if not target_container: target_container = cs.name

        # 재시작 횟수 분석
        total_restarts = sum(getattr(cs, "restart_count", 0) for cs in statuses)
        prev_count, _ = self.restart_tracker.get(uid, (0, 0))
        
        # 재시작 급증 (Restart Surge)
        if total_restarts >= prev_count + 3:
            reasons.append(f"RestartSurge(+{total_restarts - prev_count})")
            if statuses and not target_container:
                 target_container = max(statuses, key=lambda x: getattr(x, "restart_count", 0)).name
        
        # 누적 재시작 횟수 과다 (High Restart Count)
        elif total_restarts > 5 and total_restarts > prev_count:
             if not any("RestartSurge" in r for r in reasons): 
                reasons.append(f"HighRestartCount({total_restarts})")
                if statuses and not target_container:
                     target_container = max(statuses, key=lambda x: getattr(x, "restart_count", 0)).name

        # 상태 업데이트
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
                if getattr(state, "terminated", None): summary = f"Terminated({state.terminated.reason})"
                elif getattr(state, "waiting", None): summary = f"Waiting({state.waiting.reason})"
                elif getattr(state, "running", None): summary = "Running"
            
            simple_statuses.append(ContainerStatusInfo(
                name=cs.name,
                ready=getattr(cs, "ready", False),
                restart_count=getattr(cs, "restart_count", 0),
                state_summary=summary
            ))

        return AlertPayload(
            timestamp=datetime.now(timezone.utc).isoformat(),
            namespace=ns, pod_name=name, event_type=event_type,
            phase=phase_str,
            container_statuses=simple_statuses,
            raw_log_tail=log_tail,
            describe_snippet=describe_text,
            metadata={"node": getattr(pod.spec, "node_name", ""), "uid": uid},
            detection_signature=signature
        )
    
    async def send_alert(self, payload: AlertPayload):
        if not self.http_client or not self.send_semaphore:
            return

        headers = {"Authorization": f"Bearer {BOSS_TOKEN}"}
        
        async with self.send_semaphore:
            for attempt in range(3):
                try:
                    resp = await self.http_client.post(BOSS_URL, json=payload.dict(), headers=headers)
                    resp.raise_for_status()
                    
                    logger.info(f"🟢 Sent: {payload.pod_name} ({payload.detection_signature}) Code:{resp.status_code}")
                    self.debounce_cache[payload.detection_signature] = time.time()
                    return

                except httpx.HTTPStatusError as e:
                    logger.warning(f"🟡 HTTP Error ({attempt+1}/3): {e.response.status_code} - {e.response.text[:100]}")
                except Exception as e:
                    logger.exception(f"🟡 Send Exception ({attempt+1}/3) for {payload.pod_name}: {e}")
                
                if attempt < 2: await asyncio.sleep(1 * (2 ** attempt))
            
            logger.error(f"🔴 Dropped alert for {payload.pod_name} after retries.")

    async def _event_worker(self):
        # 이벤트 큐 워커
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
        # 이벤트 분석 및 처리 (워커 내부 실행)
        if event_type != "MODIFIED": return

        try:
            ns = pod.metadata.namespace
            name = pod.metadata.name
            uid = pod.metadata.uid
            statuses = getattr(pod.status, "container_statuses", []) or []
        except AttributeError:
            return

        # 1. 탐지
        reasons, target_container = self._collect_anomalies(pod, uid, statuses)
        if not reasons: return

        # 2. 연속 탐지 방지
        summary = ",".join(reasons)
        sig = self._generate_signature(ns, name, uid, summary)
        if self._is_debounced(sig): return

        logger.info(f"Detect: {ns}/{name} - {summary}")

        # 3. 데이터 수집
        log_data = await self._safe_fetch(self._get_k8s_logs, ns, name, target_container) if target_container else ""
        desc_data = await self._safe_fetch(self._get_k8s_events, ns, name, uid)

        # 4. 빌드 및 전송
        payload = self._build_payload(pod, event_type, reasons, sig, log_data, desc_data)
        asyncio.create_task(self.send_alert(payload))

    def watch_loop(self):
        # 워처 스레드 루프
        if not self.k8s_available or not self.v1:
            logger.info("Kubernetes client unavailable: watcher not started (demo mode).")
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
                    if self.stop_event.is_set(): break
                    
                    if self.main_loop and not self.main_loop.is_closed():
                        asyncio.run_coroutine_threadsafe(
                            self.event_queue.put((event['object'], event['type'])),
                            self.main_loop
                        )
            except Exception as e:
                logger.error(f"Watcher error: {e}")
                time.sleep(5)
        logger.info("Watcher thread stopped.")
    
# ------------------------------------------------------------------------------
# 4. 앱 사이클 관리
# ------------------------------------------------------------------------------
agent = DetectorAgent()
app = FastAPI(title="Detector Agent")

@app.on_event("startup")
async def on_startup():
    if not BOSS_URL or not BOSS_TOKEN:
        logger.critical("🔴 MISSING CONFIG: BOSS_URL and BOSS_TOKEN must be set.")
        sys.exit(1)
        
    agent.main_loop = asyncio.get_running_loop()
    await agent.start_resources()
    # k8s 사용 가능 시 워처 시작
    if agent.k8s_available:
        agent.main_loop.run_in_executor(None, agent.watch_loop)
    else:
        # 데모 모드: 샘플 알림 전송
        async def _send_demo_alert():
            await asyncio.sleep(1.5)
            demo_status = ContainerStatusInfo(name="demo", ready=False, restart_count=1, state_summary="Terminated(Demo)")
            demo_payload = AlertPayload(
                timestamp=datetime.now(timezone.utc).isoformat(),
                namespace="demo",
                pod_name="demo-pod",
                event_type="DEMO",
                phase="Failed",
                container_statuses=[demo_status],
                raw_log_tail="[demo] no logs",
                describe_snippet="[demo] no events",
                metadata={"node": "local", "uid": "demo-uid"},
                detection_signature="demo-signature"
            )
            asyncio.create_task(agent.send_alert(demo_payload))
        asyncio.create_task(_send_demo_alert())

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down Detector Agent...")
    agent.stop_event.set()
    await agent.close_resources()

@app.get("/health")
async def health_check():
    q_size = agent.event_queue.qsize() if agent.event_queue else 0
    return {
        "status": "ok", 
        "uptime": int(time.time() - agent.start_time),
        "tracked_pods": len(agent.restart_tracker),
        "queue_size": q_size
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8032)

