import subprocess
import json
from langchain.tools import tool


@tool
def run_nuclei(target_url: str, templates: str = "", severity: str = ""):
    """
    запускает Nuclei по заданной цели для поиска мисконфигов,
    открытых панелей и известных CVE

    target_url - адрес цели
    templates - путь к шаблонам, a если пусто - используются шаблоны по умолчанию
    severity - фильтр по критичности (например critical, high, medium, low, info), a если пусто - все уровни

    возвращает список находок в формате JSON (JSON-lines)
    """
    cmd = ["nuclei", "-u", target_url, "-jsonl", "-silent"]

    if templates:
        cmd += ["-t", templates]
    if severity:
        cmd += ["-severity", severity]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode not in (0, 1):
            return f"ошибка запуска nuclei: {result.stderr.strip()}"

        findings = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if not findings:
            return "находок не обнаружено"

        return json.dumps(findings, ensure_ascii=False, indent=2)

    except subprocess.TimeoutExpired:
        return "Error: таймаут выполнения nuclei"
    except FileNotFoundError:
        return "Error: nuclei не установлен или не найден в PATH"
    except Exception as e:
        return f"ошибка запроса {e}"