from langchain.tools import tool
import json
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from ._helpers import _finding


DEFAULT_WORDLIST = Path("/app/tools/wordlists/hidden_paths.txt")
FALLBACK_PATHS = [
    "score-board", "scoreboard", "admin", "administrator",
    "hidden", "debug", "console", "dashboard", "backup",
    "internal", "private", "management", "api-docs", "swagger",
    ".git/config", "server-status", "actuator", "metrics",
]
SENSITIVE_HINTS = (
    "admin", "administrator", "backup", "config", ".git",
    "debug", "internal", "private", "management", "actuator",
    "metrics", "server-status", "swagger", "api-docs", "console",
    "dashboard",
)


def _is_sensitive(url: str):
    path = urlparse(url).path.lower()
    return any(hint in path for hint in SENSITIVE_HINTS)


def _classify(url: str, status: int, length: int):
    """возвращает (severity, title, description) по общим правилам."""
    sensitive = _is_sensitive(url)
    path = urlparse(url).path

    if status in (200, 204):
        if sensitive:
            return (
                "medium",
                f"Потенциально чувствительный путь доступен: {path}",
                f"Путь {url} отвечает {status} без аутентификации. "
                f"Путь относится к типовым чувствительным (admin/backup/config и т.п.).",
            )
        return (
            "low",
            f"Скрытый путь доступен: {path}",
            f"Путь {url} отвечает {status} (length={length}). "
            f"Требует ручной проверки: возможно, это статика или SPA-роут.",
        )
    if status in (301, 302, 307):
        return (
            "info",
            f"Скрытый путь существует (редирект): {path}",
            f"Путь {url} отвечает {status} (length={length}). "
            f"Проверить, куда ведёт редирект.",
        )
    if status in (401, 403):
        return (
            "info",
            f"Скрытый путь существует (защищён): {path}",
            f"Путь {url} отвечает {status} (length={length}). "
            f"Ресурс есть, но закрыт — проверить обход авторизации.",
        )
    return (
        "info",
        f"Скрытый путь найден: {path}",
        f"Путь {url} отвечает {status} (length={length}).",
    )


@tool
def test_ffuf(base_url: str, wordlist: str = "", extensions: str = "", threads: int = 10):
    """
    перебирает скрытые пути через ffuf (generic, для любого приложения).

    1) если wordlist не задан — использует встроенный маленький словарь
    2) запускает ffuf с -ac (авто-калибровка против soft-404 / SPA-заглушек)
    3) парсит JSON-вывод и возвращает Finding для каждого найденного ответа

    base_url - адрес приложения (например http://host:3000)
    wordlist - путь к словарю (если пусто — встроенный)
    extensions - расширения через запятую (например ".bak,.json")
    threads - число потоков (по умолчанию 10)
    """
    base = base_url.rstrip("/")
    output_file = "/tmp/ffuf_out.json"

    # ========== подготовка словаря ==========
    wl_path = wordlist
    if not wl_path:
        if DEFAULT_WORDLIST.exists():
            wl_path = str(DEFAULT_WORDLIST)
        else:
            wl_path = "/tmp/ffuf_wordlist.txt"
            with open(wl_path, "w") as f:
                f.write("\n".join(FALLBACK_PATHS))

    # ========== сборка команды ==========
    cmd = [
        "ffuf",
        "-u", f"{base}/FUZZ",
        "-w", wl_path,
        "-mc", "200,204,301,302,307,401,403",
        "-ac",
        "-t", str(threads),
        "-o", output_file,
        "-of", "json",
        "-s",
    ]
    if extensions:
        cmd += ["-e", extensions]

    # ========== запуск ==========
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "ffuf timeout (300s)"}, ensure_ascii=False)
    except FileNotFoundError:
        return json.dumps({"error": "ffuf не установлен в контейнере"}, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"error": f"ffuf: {exc}"}, ensure_ascii=False)

    # ========== парсинг JSON ==========
    if not Path(output_file).exists():
        return json.dumps({
            "error": f"ffuf не создал отчёт (returncode={proc.returncode})",
            "stderr": (proc.stderr or "")[:500],
        }, ensure_ascii=False)

    try:
        data = json.loads(Path(output_file).read_text())
    except Exception as exc:
        return json.dumps({"error": f"parse: {exc}"}, ensure_ascii=False)

    results = data.get("results", [])
    findings = []

    for r in results:
        url = r.get("url", "")
        status = r.get("status", 0)
        length = r.get("length", 0)

        severity, title, description = _classify(url, status, length)

        f = _finding(
            title=title,
            severity=severity,
            endpoint=url,
            evidence=f"status={status}, length={length}",
            status="confirmed",
            description=description,
            recommendation=(
                "Закрыть путь авторизацией или убрать из production, "
                "если он не предназначен для публичного доступа."
            ),
            tool="test_ffuf",
        )
        findings.append(f)

    if not findings:
        f = _finding(
            title="ffuf: скрытые пути не найдены",
            severity="info",
            endpoint=base,
            evidence=f"returncode={proc.returncode}, results=0",
            status="requires_verification",
            description="ffuf не нашёл путей, отличающихся от baseline (с учётом -ac).",
            recommendation="Попробовать другой словарь или увеличить threads.",
            tool="test_ffuf",
        )
        findings.append(f)

    return json.dumps({"findings": findings}, ensure_ascii=False, indent=2)