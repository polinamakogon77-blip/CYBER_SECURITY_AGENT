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
    если Semgrep нашел уязвимость на конкретной строке, используй read_file_around_line

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
        f"{f'файл обрезан на {cnt_chars} символах' if len(data) > cnt_chars else 'файл полностью прочитан'}\n"
    )

    return result + data


@tool
def read_file_around_line(path: str, line: int, cnt_chars: int):
    """
    читает файл вокруг заданной строки
    
    используй, когда Semgrep нашел уязвимость на конкретной строке или
    нужно проверить контекст вокруг подозрительного кода

    path - путь к файлу
    line - номер строки
    cnt_char - к-во символов для чтения до и после строки

    возвращает прочитанный фрагмент с номерами строк и указание на заданную строку
    """

    path_file, error = validate_path(path)
    if error: return f"возникла ошибка: {error}"

    # проверка но номер строки и к-во символов для чтения
    if line < 1: return f"номер строки должен быть >= 1"
    if cnt_chars < 5: cnt_chars = 5
    if cnt_chars > 500: cnt_chars - 500

    # ========== чтение файла  ==========
    try: 
        with open(path_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return f"ошибка: {e}"

    cnt_all_lines = len(lines)
    if cnt_all_lines == 0: return "файл пуст"
    if line > cnt_all_lines: return "некорректный номер строки"

    # ========== формирование результата ==========
    start = max(0, line - cnt_chars - 1) # 1-ая строка для чтения
    end = min(cnt_all_lines, line + cnt_chars) # последняя строка для чтения

    fragment_file = "".join([lines[i] for i in range(start, end)])
    header = (
        f"файл: {path_file}\n"
        f"всего строк в файле: {cnt_all_lines}\n"
        f"были прочитаны строки {start + 1}-{end}\n"
        f"опорная строка: {line}\n"
    )

    return header + fragment_file



        