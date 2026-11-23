
import json
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from langchain.tools import tool

from ._helpers import _finding


DEFAULT_WORDLIST = Path("/app/tools/wordlists/hidden_paths.txt")

FALLBACK_PATHS = [
    "score-board",
    "scoreboard",
    "admin",
    "administrator",
    "hidden",
    "debug",
    "console",
    "dashboard",
    "backup",
    "internal",
    "private",
    "management",
    "api-docs",
    "swagger",
    ".git/config",
    "server-status",
    "actuator",
    "metrics",
]

SENSITIVE_HINTS = (
    "admin",
    "administrator",
    "backup",
    "config",
    ".git",
    "debug",
    "internal",
    "private",
    "management",
    "actuator",
    "metrics",
    "server-status",
    "swagger",
    "api-docs",
    "console",
    "dashboard",
)

MAX_THREADS = 10
MAX_FINDINGS = 50


def _is_sensitive(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(hint in path for hint in SENSITIVE_HINTS)


def _classify(url: str, status: int, length: int):
    """Возвращает (severity, title, description)."""

    sensitive = _is_sensitive(url)
    path = urlparse(url).path

    if status in (200, 204):
        if sensitive:
            return (
                "medium",
                f"Потенциально чувствительный путь доступен: {path}",
                f"Путь {url} отвечает HTTP {status} без передачи "
                "учётных данных инструментом. "
                "Необходимо проверить содержимое ресурса "
                "и фактические требования авторизации.",
            )

        return (
            "low",
            f"Обнаружен доступный путь: {path}",
            f"Путь {url} отвечает HTTP {status} "
            f"(length={length}). "
            "Возможно, это обычная публичная страница "
            "или маршрут SPA.",
        )

    if status in (301, 302, 307):
        return (
            "info",
            f"Обнаружен редирект: {path}",
            f"Путь {url} отвечает HTTP {status} "
            f"(length={length}). "
            "Необходимо проверить адрес перенаправления.",
        )

    if status in (401, 403):
        return (
            "info",
            f"Обнаружен защищённый путь: {path}",
            f"Путь {url} отвечает HTTP {status} "
            f"(length={length}). "
            "Это не доказывает возможность обхода авторизации.",
        )

    return (
        "info",
        f"Обнаружен путь: {path}",
        f"Путь {url} отвечает HTTP {status} "
        f"(length={length}).",
    )


@tool
def test_ffuf(
    base_url: str,
    wordlist: str = "",
    extensions: str = "",
    threads: int = 10,
):
    """
    Ищет скрытые пути с помощью ffuf на разрешённом тестовом стенде.

    base_url: адрес тестового приложения.
    wordlist: путь к словарю; пустая строка — стандартный словарь.
    extensions: расширения через запятую, например .bak,.json.
    threads: количество потоков, максимум 10.

    Использует автоматическую калибровку ffuf (-ac).

    Результат обнаружения пути не равнозначен
    подтверждённой уязвимости.
    """

    parsed = urlparse(base_url)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return json.dumps({
            "error": "Некорректный URL тестового приложения"
        }, ensure_ascii=False)

    if parsed.query or parsed.fragment:
        return json.dumps({
            "error": "base_url не должен содержать query или fragment"
        }, ensure_ascii=False)

    # Разрешение на тестирование и область проверки
    # должны контролироваться вызывающим агентом.
    base = base_url.rstrip("/")

    if type(threads) is not int or not 1 <= threads <= MAX_THREADS:
        return json.dumps({
            "error": f"threads должен быть от 1 до {MAX_THREADS}"
        }, ensure_ascii=False)

    # Проверяем словарь
    if wordlist:
        wl_path = Path(wordlist)

        if not wl_path.is_file():
            return json.dumps({
                "error": f"Словарь не найден: {wordlist}"
            }, ensure_ascii=False)

    elif DEFAULT_WORDLIST.is_file():
        wl_path = DEFAULT_WORDLIST

    else:
        wl_path = None

    # Каждый запуск получает свой временный каталог,
    # чтобы результаты разных проверок не смешивались.
    with tempfile.TemporaryDirectory(prefix="ffuf_") as temp_dir:

        temp_path = Path(temp_dir)
        output_file = temp_path / "result.json"

        if wl_path is None:
            wl_path = temp_path / "wordlist.txt"
            wl_path.write_text(
                "\n".join(FALLBACK_PATHS) + "\n",
                encoding="utf-8",
            )

        cmd = [
            "ffuf",
            "-u", f"{base}/FUZZ",
            "-w", str(wl_path),
            "-mc", "200,204,301,302,307,401,403",
            "-ac",
            "-t", str(threads),
            "-timeout", "10",
            "-o", str(output_file),
            "-of", "json",
            "-s",
        ]

        if extensions:
            cmd.extend(["-e", extensions])

        # ============ запуск ffuf ============
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

        except subprocess.TimeoutExpired:
            return json.dumps({
                "error": "ffuf timeout (300s)"
            }, ensure_ascii=False)

        except FileNotFoundError:
            return json.dumps({
                "error": "ffuf не установлен в контейнере"
            }, ensure_ascii=False)

        except Exception as exc:
            return json.dumps({
                "error": f"Ошибка запуска ffuf: {exc}"
            }, ensure_ascii=False)

        if not output_file.is_file():
            return json.dumps({
                "error": "ffuf не создал отчёт",
                "returncode": proc.returncode,
                "stderr": (proc.stderr or "")[:500],
            }, ensure_ascii=False)

        # ============ чтение JSON ============
        try:
            data = json.loads(
                output_file.read_text(encoding="utf-8")
            )
        except Exception as exc:
            return json.dumps({
                "error": f"Ошибка чтения результата ffuf: {exc}"
            }, ensure_ascii=False)

        if proc.returncode != 0:
            return json.dumps({
                "error": "ffuf завершился с ошибкой",
                "returncode": proc.returncode,
                "stderr": (proc.stderr or "")[:500],
            }, ensure_ascii=False)

    results = data.get("results", [])

    if not isinstance(results, list):
        return json.dumps({
            "error": "Некорректный формат результатов ffuf"
        }, ensure_ascii=False)

    findings = []

    # Ограничиваем объём ответа модели.
    for result in results[:MAX_FINDINGS]:
        url = str(result.get("url", ""))
        status = result.get("status", 0)
        length = result.get("length", 0)

        severity, title, description = _classify(
            url,
            status,
            length,
        )

        finding = _finding(
            title=title,
            severity=severity,
            endpoint=url,
            evidence=f"status={status}, length={length}",
            status="requires_verification",
            description=description,
            recommendation=(
                "Проверить содержимое ресурса и требования "
                "авторизации. Если обнаружены чувствительные "
                "данные, ограничить доступ."
            ),
            tool="test_ffuf",
        )

        findings.append(finding)

    if not findings:
        findings.append(
            _finding(
                title="ffuf: скрытые пути не найдены",
                severity="info",
                endpoint=base,
                evidence=f"returncode={proc.returncode}, results=0",
                status="requires_verification",
                description=(
                    "ffuf не обнаружил путей, отличающихся "
                    "от контрольных ответов с учётом -ac."
                ),
                recommendation=(
                    "При необходимости проверить другое "
                    "согласованное множество путей."
                ),
                tool="test_ffuf",
            )
        )

    return json.dumps(
        {
            "target": base,
            "tool": "test_ffuf",
            "total_results": len(results),
            "returned_findings": len(findings),
            "truncated": len(results) > MAX_FINDINGS,
            "findings": findings,
        },
        ensure_ascii=False,
        indent=2,
    )
