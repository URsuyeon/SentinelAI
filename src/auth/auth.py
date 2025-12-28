# src/auth/auth.py
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Any
import jwt
import json
import os
import re
import time
import shlex
import logging
import base64
import yaml
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import kubernetes, inspect

# --- K8s Token Generation Imports ---
try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    K8S_CLIENT_AVAILABLE = True
except ImportError:
    K8S_CLIENT_AVAILABLE = False
    pass
# ------------------------------------

# 5분짜리 토큰 발급 및 검증을 위한 간단한 JWT/세션 대체 구현
# 실제 프로덕션에서는 JWT, OAuth2 등을 사용해야 합니다.
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | AUTH | %(message)s')
logger = logging.getLogger(__name__)

#TODO: 환경변수 또는 설정 파일에서 시크릿 키 관리
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-key-for-sentinel-ai")
ALGORITHM = "HS256"

# --- K8s 관련 환경 변수 ---
# K8s 토큰 인증 사용 여부 (True/False)
USE_K8S_TOKEN_AUTH = os.getenv("USE_K8S_TOKEN_AUTH", "False").lower() in ('true', '1', 't')

# 토큰의 Audience 
K8S_TOKEN_AUDIENCE = os.getenv("K8S_TOKEN_AUDIENCE")
# 토큰을 발행할 ServiceAccount의 네임스페이스
K8S_SA_NAMESPACE = os.getenv("K8S_SA_NAMESPACE", "sentinel")
# kubeconfig 파일 경로
K8S_KUBECONFIG_PATH = os.getenv("K8S_KUBECONFIG_PATH")
# ---------------------------

class AuthManager:
    """
    JWT 기반 토큰 발급, 검증 및 명령어 화이트리스트 검증을 담당하는 클래스.
    K8s 토큰 인증 사용 시, K8s ServiceAccount 토큰 발급을 담당합니다.
    """
    def __init__(self, token_duration_minutes: int = 10):
        self.use_k8s_auth = USE_K8S_TOKEN_AUTH
        self.token_duration = timedelta(minutes=token_duration_minutes)
        self.whitelist: Dict[str, List[str]] = self._load_whitelist()
        self._k8s_client = None

        if self.use_k8s_auth and not K8S_CLIENT_AVAILABLE:
            logger.error("❌ [K8S AUTH] K8s client unavailable. Falling back to JWT.")
            logger.info(f"Kubernetes version: {kubernetes.__version__}, {inspect.getfile(kubernetes)}")
            self.use_k8s_auth = False

    def _load_whitelist(self) -> Dict[str, List[str]]:
        """
        화이트리스트 파일을 로드합니다.
        """
        # Executor Agent의 화이트리스트를 사용한다고 가정
        whitelist_path = os.path.join(os.path.dirname(__file__), '../executor_agent/whitelist.json')
        
        # 파일이 없으면 기본값으로 초기화
        default_whitelist = {
            "global": [
                "kubectl -n {namespace} describe pod {pod}",
                "kubectl describe pod {pod} -n {namespace}",
                "kubectl -n {namespace} logs {pod} --previous",
                "kubectl -n {namespace} get events --field-selector involvedObject.name={pod}",
                "kubectl -n {namespace} top pod {pod} --containers",
                "kubectl -n {namespace} exec {pod} -c {container} -- cat /proc/1/status || true"
            ],
            "read": [
                "kubectl -n {namespace} get pods",
                "kubectl -n {namespace} get pod {pod}",
                "kubectl -n {namespace} get pod {pod} -o wide",
                "kubectl -n {namespace} get pod {pod} -o yaml",
                "kubectl -n {namespace} get pod {pod} -o json",
                "kubectl -n {namespace} get pod {pod} --show-labels",
                "kubectl -n {namespace} get svc {svc}",
                "kubectl -n {namespace} get svc {svc} -o wide",
                "kubectl -n {namespace} get deployment {deployment}",
                "kubectl -n {namespace} get deployment {deployment} -o yaml",
                "kubectl -n {namespace} describe node {node}",
                "kubectl -n {namespace} get events",
                "kubectl -n {namespace} get events --field-selector involvedObject.name={pod}",
                "kubectl -n {namespace} top pod",
                "kubectl -n {namespace} top pod {pod}",
                "kubectl -n {namespace} top pod {pod} --containers",
                "kubectl -n {namespace} logs {pod}",
                "kubectl -n {namespace} logs {pod} -c {container}",
                "kubectl -n {namespace} logs {pod} --previous",
                "kubectl -n {namespace} logs {pod} --tail={lines}",
                "kubectl -n {namespace} logs {pod} -c {container} --tail={lines}",
                "kubectl -n {namespace} exec {pod} -c {container} -- cat /proc/1/status || true"
            ],
            "file-read": [
                "kubectl -n {namespace} exec {pod} -c {container} -- sh -c 'tail -n {lines} /var/log/app.log' || true",
                "kubectl -n {namespace} exec {pod} -c {container} -- sh -c 'head -n {lines} /var/log/app.log' || true",
                "kubectl -n {namespace} exec {pod} -c {container} -- sh -c 'sed -n \"1,{lines}p\" /var/log/app.log' || true",
                "kubectl -n {namespace} exec {pod} -c {container} -- sh -c 'cat /var/log/app.log | tail -n {lines}' || true"
            ],
            "write": [
                "kubectl -n {namespace} delete pod {pod} --grace-period=0 --force",
                "kubectl -n {namespace} delete pod {pod}",
                "kubectl -n {namespace} delete deployment {deployment}",
                "kubectl -n {namespace} scale deployment {deployment} --replicas={replicas}",
                "kubectl -n {namespace} rollout restart deployment {deployment}",
                "kubectl -n {namespace} rollout restart deployment {deployment} -n {namespace}",
                "kubectl -n {namespace} apply -f {manifest_file}"
            ]
        }
        
        if not os.path.exists(whitelist_path):
            # 파일이 없으면 생성
            with open(whitelist_path, 'w') as f:
                json.dump(default_whitelist, f, indent=4)
            return default_whitelist
        
        with open(whitelist_path, 'r') as f:
            return json.load(f)

    def _get_k8s_client(self):
        if not self.use_k8s_auth:
            return None

        if self._k8s_client is None:
            try:
                if K8S_KUBECONFIG_PATH and os.path.exists(K8S_KUBECONFIG_PATH):
                    config.load_kube_config(config_file=K8S_KUBECONFIG_PATH)
                    logger.info(f"✅ [K8S AUTH] Loaded kubeconfig: {K8S_KUBECONFIG_PATH}")
                else:
                    config.load_incluster_config()
                    logger.info("✅ [K8S AUTH] Loaded in-cluster config")
            except Exception as e:
                logger.error(f"❌ [K8S AUTH] Failed to load kube config: {e}")
                return None

            self._k8s_client = client.CoreV1Api()

        return self._k8s_client
    
    def _resolve_service_account(self, command_type: str) -> str:
        """
        command_type에 따라 사용할 ServiceAccount 결정
        """
        if command_type == "write":
            return "sentinel-executor-write-sa"
        return "sentinel-executor-read-sa"


    def _create_k8s_execution_token(self, task_id: str, command_type: str) -> Optional[str]:
        """
        Kubernetes ServiceAccount TokenRequest API를 사용하여 임시 토큰을 발급합니다.
        """
        k8s_client = self._get_k8s_client()
        if not k8s_client:
            return None

        sa_name = self._resolve_service_account(command_type)
        
        # 토큰 요청 객체 생성
        token_request = {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "spec": {
                "audiences": [K8S_TOKEN_AUDIENCE],
                "expirationSeconds": int(self.token_duration.total_seconds()),
            },
        }
        
        for attempt in range(3):
            try:
                resp = k8s_client.create_namespaced_service_account_token(
                    name=sa_name,
                    namespace=K8S_SA_NAMESPACE,
                    body=token_request,
                )
                return resp.status.token

            except ApiException as e:
                logger.warning(f"⚠️ TokenRequest failed ({attempt+1}/3)")
                time.sleep(0.2)

        raise RuntimeError("K8s TokenRequest failed after retries")

    def _build_dynamic_kubeconfig(self, token: str) -> str:
        """
        Orchestrator가 사용하는 '진짜 kubeconfig'를 기반으로
        task 전용 kubeconfig를 문자열로 생성
        """
        with open(K8S_KUBECONFIG_PATH, "r") as f:
            base_cfg = yaml.safe_load(f)

        cluster = base_cfg["clusters"][0]["cluster"]
        server = cluster["server"]
        ca_data = cluster.get("certificate-authority-data")

        kubeconfig = {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [{
                "name": "cluster",
                "cluster": {
                    "server": server,
                    "certificate-authority-data": ca_data,
                },
            }],
            "users": [{
                "name": "executor",
                "user": {
                    "token": token,
                },
            }],
            "contexts": [{
                "name": "exec",
                "context": {
                    "cluster": "cluster",
                    "user": "executor",
                },
            }],
            "current-context": "exec",
        }

        return yaml.safe_dump(kubeconfig)

    def get_execution_credentials(
        self,
        task_id: str,
        command_type: str
    ) -> Dict[str, str]:
        token = self.get_execution_token(task_id, command_type)

        if self.use_k8s_auth:
            kubeconfig = self._build_dynamic_kubeconfig(token)
            return {
                "token": token,
                "kubeconfig": kubeconfig,
            }

        # JWT fallback (kubeconfig 없음)
        return {
            "token": token,
            "kubeconfig": "",
        }


    def get_execution_token(self, task_id: str, command_type: str) -> str:      
        if self.use_k8s_auth:
            # K8s 토큰 발급 시도
            try:
                token = self._create_k8s_execution_token(task_id, command_type)
                if token:
                    # K8s 토큰 발급 성공 시, 토큰을 반환
                    return token
            except Exception as e:
                # K8s 토큰 발급 최종 실패 시, JWT로 대체
                logger.error(f"❌ [K8S TOKEN] Fallback to JWT: {e}")

        # JWT 토큰 발급 (비상용)    
        now = datetime.now(timezone.utc)
        expiry = now + self.token_duration
            
        payload = {
            "task_id": task_id,
            "command_type": command_type,
            "iat": now,
            "exp": expiry,
            "sub": "sentinel-executor",
        }
        
        logger.info(f"🔑 [TOKEN] Task {task_id} ({command_type}) token created, expires at {expiry.isoformat()}")
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    def validate_token(self, token: str, task_id: str, command_type: str) -> bool:
        """
        JWT 토큰의 유효성을 검증합니다. (폐기 예정)
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
            # 1. task_id 일치 확인
            if payload.get("task_id") != task_id:
                logger.warning(f"❌ [TOKEN FAIL] Task ID mismatch. Expected: {task_id}, Got: {payload.get('task_id')}")
                return False
            
            # 2. command_type 일치 확인
            if payload.get("command_type") != command_type:
                logger.warning(f"❌ [TOKEN FAIL] Command Type mismatch. Expected: {command_type}, Got: {payload.get('command_type')}")
                return False
            
            # 3. 만료 시간은 jwt.decode가 자동으로 처리 (ExpiredSignatureError 발생)
            logger.info(f"✅ [TOKEN VALID] Task {task_id} token validated.")
            return True
            
        except jwt.ExpiredSignatureError:
            logger.error("❌ [TOKEN FAIL] Token has expired.")
            return False
        except jwt.InvalidTokenError as e:
            logger.error(f"❌ [TOKEN FAIL] Invalid token - {e}")
            return False
        except Exception as e:
            logger.error(f"❌ [TOKEN FAIL] An unexpected error occurred - {e}")
            return False
    
    # --- 화이트리스트 매칭 헬퍼들 ---
    def _strip_trailing_or_true(self, s: str) -> str:
        # "|| true" 같은 꼬리 제거(공백, 다양한 포맷 허용)
        return re.sub(r'\s*\|\|\s*true\s*$', '', s.strip())
    
    def _token_matches_pattern(self, pattern_token: str, cmd_token: str) -> bool:
        # 전체 플레이스홀더 토큰 (한 토큰을 어떤 값으로든 허용)
        if self._pattern_token_is_placeholder(pattern_token):
            return True

        # 패턴 토큰 안에 플레이스홀더가 섞여 있는 경우 
        if '{' in pattern_token and '}' in pattern_token:
            escaped = re.escape(pattern_token)
            regex = re.sub(r'\\\{[^}]+\\\}', r'(.+)', escaped)
            regex = '^' + regex + '$'
            return re.match(regex, cmd_token) is not None

        return pattern_token == cmd_token

    def _tokenize(self, s: str) -> List[str]:
        try:
            return shlex.split(s)
        except ValueError:
            # shlex 실패 시 단순 공백 분리 fallback
            return s.split()

    def _pattern_token_is_placeholder(self, token: str) -> bool:
        return re.fullmatch(r'\{[^}]+\}', token) is not None
    
    def _remove_namespace_tokens(self, tokens: List[str]) -> List[str]:
        """
        토큰 리스트에서 '-n <ns>', '--namespace <ns>', '--namespace=<ns>' 형태의 토큰들을 제거합니다.
        (네임스페이스 유무에 관계없이 매칭하려고)
        """
        out = []
        i = 0
        while i < len(tokens):
            t = tokens[i]
            # '-n' 또는 '--namespace' 뒤의 값 제거
            if t in ("-n", "--namespace"):
                i += 2
                continue
            # '--namespace=foo' 형태 제거
            if t.startswith("--namespace="):
                i += 1
                continue
            out.append(t)
            i += 1
        return out
    
    def _match_pattern_tokens(self, pattern_tokens: List[str], cmd_tokens: List[str]) -> bool:
        i = j = 0
        while i < len(pattern_tokens) and j < len(cmd_tokens):
            p = pattern_tokens[i]
            c = cmd_tokens[j]

            if self._token_matches_pattern(p, c):
                i += 1
                j += 1
                continue

            # 매칭 실패
            return False

        # 패턴 토큰을 모두 소비했을 때
        if i == len(pattern_tokens):
            # 명령 토큰도 모두 소비됐으면 성공
            if j == len(cmd_tokens):
                return True

            # 남아있는 cmd_tokens이 모두 옵션형태이면 허용
            remaining = cmd_tokens[j:]
            for t in remaining:
                # 옵션은 보통 - 또는 --로 시작하거나, key=value 형태로 올 수 있음
                if t.startswith('-') or ('=' in t):
                    continue
                # 옵션이 아닌 토큰이 남아있으면 불일치
                return False
            return True

        # 패턴 토큰이 남아있음 => 불일치
        return False

    def _pattern_matches_command(self, pattern: str, command: str) -> bool:
        # 꼬리 제거 및 토큰화
        p = self._strip_trailing_or_true(pattern)
        c = self._strip_trailing_or_true(command)
        p_tokens = self._tokenize(p)
        c_tokens = self._tokenize(c)

        # 네임스페이스 토큰(-n, --namespace, --namespace=)은 비교에서 제외
        p_tokens = self._remove_namespace_tokens(p_tokens)
        c_tokens = self._remove_namespace_tokens(c_tokens)

        return self._match_pattern_tokens(p_tokens, c_tokens)

    def check_whitelist(self, command: str, command_type: str = "") -> bool:
        """
        명령어가 화이트리스트와 매칭되는지 확인.
        - command_type이 주어지면 'global' + command_type 관련 섹션들을 함께 검사합니다.
        - command_type을 비워두면 모든 섹션을 검사합니다.
        """
        if not self.whitelist:
            return False

        targets: List[str] = []
        if not command_type:
            # 전체 섹션 검사
            for k in self.whitelist.keys():
                targets.extend(self.whitelist.get(k, []))
        else:
            # 항상 global 포함
            targets.extend(self.whitelist.get("global", []))
            # 정확 키 매칭 우선
            if command_type in self.whitelist:
                targets.extend(self.whitelist.get(command_type, []))
            else:
                # 키 이름에 command_type이 포함된 섹션들 (예: 'file-read' vs 'read')
                for k in self.whitelist.keys():
                    if k == "global":
                        continue
                    if command_type in k or k in command_type:
                        targets.extend(self.whitelist.get(k, []))

        # 각 패턴과 비교
        for pattern in targets:
            try:
                if self._pattern_matches_command(pattern, command):
                    return True
            except Exception:
                # 안전하게 실패처리: 에러가 나면 다음 패턴으로
                continue

        return False


auth_manager = AuthManager()


# --- FastAPI Dependency (Detector Agent 인증용) ---

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Detector Agent의 인증을 위한 함수 (BOSS_TOKEN 검증)
    """
    BOSS_TOKEN = os.getenv("BOSS_TOKEN", "dev-token")
    if token != BOSS_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "Detector Agent"