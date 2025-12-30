# src/rag_agent/retriever.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, List
import logging
import os
import asyncio

# LangChain
from langchain_community.embeddings.fastembed import FastEmbedEmbeddings
from langchain_qdrant import QdrantVectorStore
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import DirectoryLoader, TextLoader

# Qdrant client
from qdrant_client import QdrantClient

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | RAG | %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Simple RAG Agent API", version="0.1")

DISABLE_RAG_INTEGRATION = os.getenv("DISABLE_RAG_INTEGRATION", "True").lower() in ('true', '1', 't')
logger.info(f"⚙️ RAG Integration Status: {'MOCKING' if DISABLE_RAG_INTEGRATION else 'ACTIVE'}")

# 임베딩 모델 (작고 빠름)
embeddings = FastEmbedEmbeddings(model_name="BAAI/bge-small-en-v1.5")

vector_db = None

def init_vector_db():
    global vector_db
    if DISABLE_RAG_INTEGRATION or vector_db:
        return

    logger.info("🛠️ Initializing Vector DB (minimal mode)...")

    client = QdrantClient(url="http://qdrant:6333")
    
    # 항상 깨끗한 상태로 시작
    try:
        client.delete_collection(collection_name="k8s_incident_knowledge")
        logger.info("Old collection deleted")
    except Exception:
        pass

    # 문서 로드
    loader = DirectoryLoader("/app/docs/kubernetes", glob="**/*.md", loader_cls=TextLoader)
    documents = loader.load()
    logger.info(f"📚 Loaded {len(documents)} documents")

    # 빈 문서 제거만 하고 나머지는 다 사용
    documents = [doc for doc in documents if doc.page_content.strip()]
    logger.info(f"📄 After removing empty docs: {len(documents)}")

    if not documents:
        logger.warning("⚠️ No documents found")
        return

    # chunk 크기 작게 → 문서가 짧아도 여러 chunk 생성 방지 + 최대한 삽입
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=400,
        chunk_overlap=50,
        keep_separator=True
    )
    splits = text_splitter.split_documents(documents)
    logger.info(f"✂️ Split into {len(splits)} chunks")

    if not splits:
        logger.error("❌ No chunks after splitting")
        return

    # 바로 from_documents로 삽입 (중간 필터링 없음)
    try:
        vector_db = QdrantVectorStore.from_documents(
            documents=splits,
            embedding=embeddings,
            url="http://qdrant:6333",
            collection_name="k8s_incident_knowledge",
            prefer_grpc= False,
        )
        logger.info("🎉 Vector DB initialized successfully!")
    except Exception as e:
        logger.error(f"❌ Failed to initialize vector store: {e}")
        vector_db = None

# 앱 시작 시 한 번만 초기화
init_vector_db()

# --- API 모델 ---
class RAGSearchRequest(BaseModel):
    task_id: str
    detection_log: Dict[str, Any]
    execution_log: List[Dict[str, Any]]

class RAGResult(BaseModel):
    title: str
    content: str

class RAGSearchResponse(BaseModel):
    rag_results: List[RAGResult]

def _search_vector_db(req: RAGSearchRequest) -> List[RAGResult]:
    if not vector_db:
        logger.warning("Vector DB not ready → fallback to mock")
        return _mock_search_knowledge_base(req)

    query = f"""
{req.detection_log.get('event_type', '')}
{req.detection_log.get('pod_name', '')} {req.detection_log.get('namespace', 'default')}
{req.detection_log.get('raw_log_tail', '')}
{' '.join(req.detection_log.get('events', []))}
""".strip()

    retriever = vector_db.as_retriever(
        search_type="similarity",
        search_kwargs={"k": 3}  # 결과 수 줄임
    )
    docs = retriever.invoke(query)

    results = []
    for doc in docs:
        title = doc.metadata.get("source", "Unknown").split("/")[-1].replace(".md", "")
        results.append(RAGResult(title=title, content=doc.page_content.strip()))

    if not results:
        results.append(RAGResult(title="No results", content="관련 문서를 찾지 못했습니다."))

    return results

def _mock_search_knowledge_base(req: RAGSearchRequest) -> List[RAGResult]:
    logger.info(f"🔍 [MOCK SEARCH] Task {req.task_id}")
    
    full_text = (
        f"{req.detection_log.get('event_type', '')} "
        f"{req.detection_log.get('describe_snippet', '')} "
        f"{req.detection_log.get('raw_log_tail', '')} "
        + " ".join([log.get("output", "") for log in req.execution_log])
    ).lower()

    results = []

    if "crashloopbackoff" in full_text:
        results.append(RAGResult(
            title="CrashLoopBackOff Troubleshooting",
            content="CrashLoopBackOff는 컨테이너가 반복 종료되는 상태입니다. kubectl describe pod로 종료 코드와 이유를 확인하고, 필요시 kubectl logs --previous로 이전 로그를 보세요."
        ))
    elif "oomkilled" in full_text or "out of memory" in full_text:
        results.append(RAGResult(
            title="OOMKilled",
            content="메모리 부족으로 종료되었습니다. Pod의 resources.limits.memory를 늘리고 롤링 업데이트하세요."
        ))
    elif "pending" in full_text:
        results.append(RAGResult(
            title="Pending Pod",
            content="Pod가 Pending이면 리소스 부족, taint, PVC 문제 등을 의심하세요. kubectl describe pod의 Events를 확인하세요."
        ))

    if not results:
        results.append(RAGResult(
            title="General Advice",
            content="kubectl describe pod와 kubectl logs를 먼저 확인하세요."
        ))

    return results

def _get_rag_results(req: RAGSearchRequest) -> List[RAGResult]:
    return _mock_search_knowledge_base(req) if DISABLE_RAG_INTEGRATION else _search_vector_db(req)

@app.post('/search', response_model=RAGSearchResponse)
async def search_knowledge(req: RAGSearchRequest):
    logger.info(f"📩 [POST /search] Task {req.task_id}")
    await asyncio.sleep(0.5)  # 약간의 지연 (실제 검색 느낌)
    return RAGSearchResponse(rag_results=_get_rag_results(req))

@app.get('/health')
async def health():
    return {"status": "ok", "rag_active": not DISABLE_RAG_INTEGRATION, "vector_db_ready": vector_db is not None}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8036, log_level="info")