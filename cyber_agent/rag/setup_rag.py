import os
import sys
from pathlib import Path
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from sentence_transformers import SentenceTransformer
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS

def main():
    print("Начало индексации RAG-базы знаний...")
    kb_path = "/app/cyber_agent/knowledge_base"
    index_path = "/app/cyber_agent/rag/faiss_index"
    if not os.path.exists(kb_path) or not any(Path(kb_path).iterdir()):
        print(f" Папка {kb_path} пуста или не существует.")
        print("Добавьте .md или .txt файлы в эту папку и запустите скрипт снова.")
        sys.exit(1)
    if not os.getenv("OPENAI_API_KEY"):
        print("Ошибка: Переменная окружения OPENAI_API_KEY не найдена")
        sys.exit(1)

    print(f"Загрузка документов из: {kb_path}")
    loader = DirectoryLoader(
        kb_path, 
        glob="**/*.md", 
        loader_cls=TextLoader, 
        show_progress=True
    )
    docs = loader.load()
    print(f"Загружено документов: {len(docs)}")
    print("Разбиение текста на фрагменты")
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200
    )
    chunks = text_splitter.split_documents(docs)
    print(f"Создано фрагментов (chunks): {len(chunks)}")
    print("Генерация векторов")
    print("Загрузка локальной модели эмбеддингов")
    embeddings = HuggingFaceEmbeddings(
        model_name="BAAI/bge-small-en-v1.5", 
        model_kwargs={'device': 'cpu'} 
    )
    vectorstore = FAISS.from_documents(chunks, embeddings)
    os.makedirs(index_path, exist_ok=True)
    vectorstore.save_local(index_path)
    print(f" Индексация успешно завершена")
    print(f"База знаний сохранена в: {index_path}")

if __name__ == "__main__":
    main()