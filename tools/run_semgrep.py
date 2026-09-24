# Semgrep
import subprocess
import json
import os
from pathlib import Path
from langchain.tools import tool


@tool
def run_semgrep(source_path: str, rules_path: str):
    """
    запускает Semgrep на исходниках
    ищет паттерны уязвимостей
    
    используется для статического анализа,
    когда есть путь к папке с кодом 

    source_path - путь к коду
    rules_path - путь к файлу правил

    возвращает: Json со списком находок (check_id, path, line, message, severity, snippet)
    """

    # ======= проверка путей ======= 
    if not os.path.exists(source_path):
        return f"не найден путь: {source_path}"
    if not os.path.exists(rules_path):
        return f"не найден файл: {rules_path}"

     # ======= запуск Semgrep ======= 
    # команда для запуска Semgrep
    cmd = [ 
        "semgrep",
        "scan",
        "--config", rules_path, # путь к файлу правил
        "--json", # формат вывода
        "--metrics", "off", # сбор метрик отключен
        source_path
    ]

    try:
        res = subprocess.run(
            cmd,
            capture_output=True, # захватывает stdout, stderr
            text=True, # возвращает строки, а не байты
            timeout=600 # ожидание 10 минут
        )


        if res.returncode not in (0, 1):
            raise RuntimeError(
                f"Sempgrep завершился с кодом {res.returncode}"
            )

        # парсинг JSON
        data = json.loads(res.stdout)

        #извлекаем результаты
        findings = data.get("results", [])

        # ======= находок нет ======= 
        if not findings:
            return "Sempgrep ничего не нашел"

        # ======= вывод =======
        output = []
        for f in findings[:20]:
            extra = f.get("extra", {})
            output.append({
                "check_id": f.get("check_id", ""),
                "path": f.get("path", ""),
                "line": f.get("start", {}).get("line", 0),
                "severity": extra.get("severity", "INFO"),
                "message": (extra.get("message", "") or "")[:100],
                "snippet": (extra.get("lines", "") or "")[:100]
            })

        summary = {
            "total_findings": len(findings),
            "returned": len(output),
            "findings": output
        }

        return json.dumps(summary, ensure_ascii=False, indent=2)

    except Exception as e:
        return f"ошибка {e}"


