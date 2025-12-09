# src/auth/auth.py
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Any
import jwt
import json
import os
import re
import shlex
import logging
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

# 5분짜리 토큰 발급 및 검증을 위한 간단한 JWT/세션 대체 구현
# 실제 프로덕션에서는 JWT, OAuth2 등을 사용해야 합니다.
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | AUTH | %(message)s')
logger = logging.getLogger(__name__)

#TODO: 환경변수 또는 설정 파일에서 시크릿 키 관리
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-key-for-sentinel-ai")
ALGORITHM = "HS256"

class AuthManager:
    """
    JWT 기반 토큰 발급, 검증 및 명령어 화이트리스트 검증을 담당하는 클래스.
    """
    def __init__(self, token_duration_minutes: int = 5):
        self.token_duration = timedelta(minutes=token_duration_minutes)
        # 활성 토큰 저장소는 더 이상 필요하지 않음 (JWT는 자체 포함)
        self.whitelist: Dict[str, List[str]] = self._load_whitelist()

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
                "kubectl -n {namespace} get svc {svc}",
                "kubectl -n {namespace} get deployment {deployment}",
                "kubectl -n {namespace} describe node {node}",
                "kubectl -n {namespace} logs {pod} --previous",
                "kubectl -n {namespace} logs {pod} --tail={lines}",
                "kubectl -n {namespace} exec {pod} -c {container} -- cat /proc/1/status || true"
            ],
            "file-read": [
                "kubectl -n {namespace} exec {pod} -c {container} -- sh -c 'tail -n 200 /var/log/app.log' || true",
                "kubectl -n {namespace} exec {pod} -c {container} -- sh -c 'sed -n \"1,200p\" /var/log/app.log' || true"
            ],
            "write": [
                "kubectl -n {namespace} delete pod {pod}",
                "kubectl -n {namespace} delete deployment {deployment}",
                "kubectl -n {namespace} scale deployment {deployment} --replicas {replicas}",
                "kubectl -n {namespace} rollout restart deployment {deployment}",
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

    def generate_token(self, task_id: str, command_type: str) -> str:
        """
        새로운 JWT 실행 토큰을 발급합니다.
        """
        now = datetime.now(timezone.utc)
        expiry = now + self.token_duration
        
        payload = {
            "task_id": task_id,
            "command_type": command_type, # 'read' or 'write'
            "exp": expiry,
            "iat": now,
            "sub": "executor-execution-token"
        }
        
        encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        logger.info(f"🔑 [TOKEN] Task {task_id} ({command_type}) token created, expires at {expiry.isoformat()}")
        return encoded_jwt

    def validate_token(self, token: str, task_id: str, command_type: str) -> bool:
        """
        JWT 토큰의 유효성을 검증합니다.
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