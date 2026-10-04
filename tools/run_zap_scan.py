from langchain.tools import tool
import json
import subprocess
import os
import shutil


# режимы сканирования
SCAN_MODES = {
    "baseline": "zap-baseline.py",
    "full": "zap-full-scan.py",
    "api": "zap-api-scan.py"
}


@tool
def run_zap_scan(target_url: str, scan_mode: str, auth_token: str = ''):
    """
    запускает OWASP ZAP на целевом URL через Docker

    сканирует работающее веб-приложение и находит уязвимости
    поддерживает 3 уровня сканирования:
        1) baseline - быстрое сканирование для регулярных проверок
        2) full - активное сканирование, атаки: XSS, SQLi, path traversal,
           использовать только для локальных стендов
        3) api - активное сканирование по OpenAPI/SOAP/GraphQL спецификации

    target_url - URL объекта сканирования
    scan_mode - режим сканирования
    auth_token - Bearer-токен для аутентификации

    возвращает json с алертами ZAP
    """
    # ========== выбор режима ==========
    scan_mode = scan_mode.lower().strip()
    if scan_mode not in SCAN_MODES:
        return f"нет режима {scan_mode}"
    script = SCAN_MODES[scan_mode]

    # ========== подготовка папки отчётов ==========
    output_dir = os.path.abspath("reports")
    os.makedirs(output_dir, exist_ok=True)

    # ========== сборка команды Docker ==========
    json_report = "zap_report.json"
    html_report = "zap_report.html"

    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if r.returncode != 0:
            return "Docker не запущен"
    except Exception as e:
        return f"ошибка проверки Docker {e}"

    cmd = [
        "docker", "run", "--rm",
        "--user", "root",
        "--network", "host",
        "-v", f"{output_dir}:/zap/wrk/:rw",   
        "zaproxy/zap-stable",
        script,
        "-t", target_url,
        "-J", json_report,
        "-r", html_report,
        "-I",
    ]

    # ========== запуск ==========
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800
        )
        print("ZAP returncode:", result.returncode)
        print("ZAP stdout:", result.stdout[:1000])
        print("ZAP stderr:", result.stderr[:1000])
    except Exception as e:
        return f"возникла ошибка: {e}"

    # ========== извлечение алертов ==========
    json_path = os.path.join(output_dir, json_report)

    if not os.path.exists(json_path):
        return f"ZAP: отчёт не создан: {json_path}"

    try:
        with open(json_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except Exception as e:
        return f"при чтении json возникла ошибка {e}"

    alerts = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances", [])
            first = instances[0] if instances else {}
            alerts.append({
                "alert": alert.get("alert", ""),
                "risk": alert.get("riskdesc", ""),
                "confidence": alert.get("confidence", ""),
                "url": first.get("uri", ""),
                "method": first.get("method", ""),
                "param": first.get("param", ""),
                "evidence": (first.get("evidence", "") or "")[:200],
                "description": (alert.get("desc", "") or "")[:200],
                "solution": (alert.get("solution", "") or "")[:200],
                "instances_count": len(instances),
            })

    if not alerts:
        return f"алертов не найдено (отчёт: {json_path})"

    # ========== формирование результата ==========
    summary = {
        "scan_mode": scan_mode,
        "target_url": target_url,
        "total_alerts": len(alerts),
        "alerts": alerts[:30],
        "reports": {
            "json": json_path,
            "html": os.path.join(output_dir, html_report),
        },
    }

    return json.dumps(summary, ensure_ascii=False, indent=2)


