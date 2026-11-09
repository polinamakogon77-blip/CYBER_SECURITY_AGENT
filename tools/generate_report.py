from langchain.tools import tool
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

    findings — JSON-строка со списком находок (если пусто — берёт из reports/findings.json)
    format — json / md / both
    output_path — базовый путь без расширения (по умолчанию reports/report)

    Возвращает пути к созданным файлам.
    """
    format = format.lower()
    if format not in {"json", "md", "both"}:
        return "ошибка: format должен быть json, md или both"

    # загрузка находок
    if findings:
        try:
            items = json.loads(findings)
        except json.JSONDecodeError:
            return "ошибка: findings должен быть валидным JSON"
    else:
        if not FINDINGS_FILE.exists():
            return "нет сохранённых находок и findings не передан"
        items = json.loads(FINDINGS_FILE.read_text(encoding="utf-8"))

    out_dir = Path(output_path).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    base = Path(output_path)
    created = []

    # JSON
    if format in {"json", "both"}:
        json_path = base.with_suffix(".json")
        report = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total": len(items),
            "findings": items,
        }
        json_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        created.append(str(json_path))

    # Markdown
    if format in {"md", "both"}:
        md_path = base.with_suffix(".md")
        lines = [
            "# Security Report",
            f"Generated: {datetime.utcnow().isoformat()}Z",
            f"Total findings: {len(items)}",
            "",
        ]
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_items = sorted(
            items,
            key=lambda x: severity_order.get(x.get("severity", "LOW").upper(), 99),
        )
        for i, f in enumerate(sorted_items, 1):
            lines.extend([
                f"## {i}. {f.get('title', 'Untitled')}",
                f"- **Severity:** {f.get('severity', 'N/A')}",
                f"- **Category:** {f.get('category', 'N/A')}",
                f"- **Evidence:** {f.get('evidence', '')}",
                f"- **Recommendation:** {f.get('recommendation', '')}",
                "",
            ])
        md_path.write_text("\n".join(lines), encoding="utf-8")
        created.append(str(md_path))

    return "созданы файлы: " + ", ".join(created)