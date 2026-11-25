from langchain_core.tools import tool 
import json
from pathlib import Path
from datetime import datetime

FINDINGS_FILE = Path("reports/findings.json")

@tool
def generate_report(
    findings: str = "",
    format: str = "both",
    output_path: str = "reports/report",
) -> str:
    """
    Генерирует итоговый отчёт в JSON и/или Markdown.
    ВАЖНО: Этот инструмент завершает работу агента. Вызывайте его только когда все проверки закончены.
    findings — JSON-строка со списком находок (если пусто — берёт из reports/findings.json)
    format — json / md / both
    output_path — базовый путь без расширения (по умолчанию reports/report)
    Возвращает полный текст отчета в формате Markdown.
    """
    format = format.lower()
    if format not in {"json", "md", "both"}:
        return "ошибка: format должен быть json, md или both"
    items = []
    if findings:
        try:
            items = json.loads(findings)
        except json.JSONDecodeError:
            return "ошибка: findings должен быть валидным JSON"
    else:
        if FINDINGS_FILE.exists():
            try:
                items = json.loads(FINDINGS_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        
    if not items:
        return "Нет данных для формирования отчета. Проверьте, были ли сохранены находки через save_finding."

    out_dir = Path(output_path).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    base = Path(output_path)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_items = sorted(
        items,
        key=lambda x: severity_order.get(x.get("severity", "LOW").upper(), 99),
    )
    md_lines = [
        "# 🛡️ Отчет о проверке безопасности",
        f"**Дата генерации:** {datetime.utcnow().isoformat()}Z",
        f"**Всего находок:** {len(items)}",
        "",
        "---",
        ""
    ]
    for i, f in enumerate(sorted_items, 1):
        title = f.get('title', 'Без названия')
        severity = f.get('severity', 'N/A')
        category = f.get('category', 'N/A')
        evidence = f.get('evidence', 'Нет доказательств')
        recommendation = f.get('recommendation', 'Нет рекомендаций')
        
        md_lines.extend([
            f"## {i}. {title}",
            f"- **Критичность:** {severity}",
            f"- **Категория:** {category}",
            f"- **Доказательства:**\n  ```\n  {evidence}\n  ```",
            f"- **Рекомендация:** {recommendation}",
            "",
            "---",
            ""
        ])
    md_content = "\n".join(md_lines)
    created_files = []
    if format in {"md", "both"}:
        md_path = base.with_suffix(".md")
        md_path.write_text(md_content, encoding="utf-8")
        created_files.append(str(md_path))
    if format in {"json", "both"}:
        json_path = base.with_suffix(".json")
        report_json = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total": len(items),
            "findings": items,
        }
        json_path.write_text(
            json.dumps(report_json, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        created_files.append(str(json_path))
    return md_content