from langchain_core.tools import tool
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS 
from langchain_community.embeddings import HuggingFaceEmbeddings 
import os


index_path = "/app/cyber_agent/rag/faiss_index"
embeddings = HuggingFaceEmbeddings(
    model_name="BAAI/bge-small-en-v1.5", 
    model_kwargs={'device': 'cpu'} 
)
if os.path.exists(index_path):
    vectorstore = FAISS.load_local(
        index_path, 
        embeddings, 
        allow_dangerous_deserialization=True
    )
    retriever = vectorstore.as_retriever(search_kwargs={"k": 3})
else:
    retriever = None

@tool
def cybersecurity_knowledge_base(query: str) -> str:
    """
    Используй этот инструмент для поиска актуальной информации об уязвимостях, 
    CVE, тактиках MITRE ATT&CK, внутренних политиках безопасности и инструкциях. 
    Аргумент query должен быть кратким поисковым запросом на естественном языке.
    """
    if retriever is None:
        return "Ошибка: База знаний RAG еще не проиндексирована. Запустите скрипт индексации."
    docs = retriever.invoke(query)
    if not docs:
        return "По вашему запросу в базе знаний ничего не найдено."
    formatted_results = []
    for i, doc in enumerate(docs, 1):
        source = doc.metadata.get('source', 'Неизвестный источник')
        formatted_results.append(f"--- Фрагмент {i} (Источник: {source}) ---\n{doc.page_content}")
    
    return "\n\n".join(formatted_results)

rag_tool = cybersecurity_knowledge_base