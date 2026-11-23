from langchain.tools import tool
import json

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

@tool
def rank_findings(findings: str, matrix: str = "") -> str:
    """
    Сортирует находки по критичности.

    findings — JSON-строка со списком находок
    matrix — опциональная JSON-строка с кастомным порядком 
             {"CRITICAL":0, "HIGH":1, ...}

    Возвращает отсортированный список.
    """
    try:
        items = json.loads(findings)
    except json.JSONDecodeError:
        return "ошибка: findings должен быть валидным JSON"

    order = SEVERITY_ORDER
    if matrix:
        try:
            order = json.loads(matrix)
        except json.JSONDecodeError:
            return "ошибка: matrix должен быть валидным JSON"

    sorted_items = sorted(
        items,
        key=lambda x: order.get(str(x.get("severity", "LOW")).upper(), 99),
    )
    return json.dumps(sorted_items, ensure_ascii=False, indent=2)