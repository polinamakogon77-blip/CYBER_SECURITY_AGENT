from langchain.tools import tool
import json
import uuid
from pathlib import Path
from datetime import datetime

FINDINGS_FILE = Path("reports/findings.json")

@tool
def save_finding(
    title: str,
    severity: str,
    category: str,
    evidence: str,
    recommendation: str,
) -> str:
    """
    Сохраняет находку в общий список findings.

    title — краткое название
    severity — LOW / MEDIUM / HIGH / CRITICAL
    category — категория (например, IDOR, XSS, Misconfig)
    evidence — доказательства
    recommendation — рекомендация по исправлению

    Возвращает id сохранённой находки.
    """
    severity = severity.upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return "ошибка: severity должен быть LOW, MEDIUM, HIGH или CRITICAL"

    FINDINGS_FILE.parent.mkdir(parents=True, exist_ok=True)

    findings = []
    if FINDINGS_FILE.exists():
        try:
            findings = json.loads(FINDINGS_FILE.read_text(encoding="utf-8"))
        except Exception:
            findings = []

    finding_id = str(uuid.uuid4())[:8]
    finding = {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "category": category,
        "evidence": evidence,
        "recommendation": recommendation,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    findings.append(finding)
    FINDINGS_FILE.write_text(
        json.dumps(findings, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return f"находка сохранена, id={finding_id}"