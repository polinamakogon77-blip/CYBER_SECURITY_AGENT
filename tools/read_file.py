# чтение файла
from langchain.tools import tool
from pathlib import Path


MAX_CNT_CHARS = 150_000

# файлы,чтение которых запрещено
FORBIDDEN_FILES = (
    ".git/", ".ssh/", ".aws/", # служебные директории 
    ".key", ".p12", ".pfx", ".pem", # сертификаты и ключи
    "id_rsa", "id_ed25519", "id_ecdsa" # SSH-ключи
)
# файлы, чтение которых разрешено
ALLOWED_FILES = (
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".cs",
    ".c", ".cpp", ".h", ".hpp", ".html", ".htm", ".vue", ".svelte", ".json", 
    ".yaml", ".yml", ".xml", ".toml", ".env", ".ini", ".conf", ".config", ".sql", 
    ".sh", ".bash", ".md", ".txt",
)


def validate_path(path: str):
    """
    проверяет путь
    возвращает путь и ошибку
    """
    path_file = Path(path).expanduser()
    resolved = path_file.resolve()

    for file in FORBIDDEN_FILES:
        if file in str(resolved):
            return path_file, "чтение файла запрещено"

    if not path_file.exists():
        return path_file, "файл не найден"

    if not path_file.is_file():
        return path_file, "это не файл"

    if path_file.suffix.lower() not in ALLOWED_FILES:
        return path_file, "файлы данного расширения не подходят для чтения"

    return path_file, None



@tool
def read_file(path: str, cnt_chars: int):
    """
    читает файл целиком (до 150_000 символов)
    
    используй, когда нужно увидеть содержимое файла целиком, чтобы понять архитектуру
    

    path - путь к файлу
    cnt_chars - максимально к-во символов для чтения

    возвращает содержимое файла вместе с метаданными 
    """

    path_file, error = validate_path(path)
    if error:
        return f"возникла ошибка: {error}"

    # проверка к-ва символов для чтения
    if cnt_chars < 100: cnt_chars = 100
    if cnt_chars > MAX_CNT_CHARS: cnt_chars = MAX_CNT_CHARS


    # ========== чтение файла  ==========
    try: 
        with open(path_file, "r", encoding="utf-8", errors="replace") as f:
            data = f.read(cnt_chars + 1)
    except Exception as e:
        return f"ошибка: {e}"

    # ========== метаданные файла ==========
    try:
        size_file = path_file.stat().st_size
        with open(path_file, "rb") as f:
            cnt_lines = sum(1 for i in f)
    except Exception:
        size_file = 0
        cnt_lines = 0

    # ========== формирование результата ==========
    result = (
        f"файл: {path_file}\n"
        f"размер: {size_file}\n"
        f"к-во строк: {cnt_lines}\n"
        f"к-во прочитанных символов: {len(data)}\n"
        f"{f'файл обрезан на {cnt_chars} символах' if len(data) > cnt_chars else 'файл полностью прочитан'}"
    )

    return result
