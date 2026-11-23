from langchain.tools import tool
import json
import requests
from ._helpers import _finding, BASE_TIMEOUT


@tool
def test_ftp_directory_listing(base_url: str):
    """
    проверяет открытый листинг /ftp/ и доступ к acquisitions.md
    """
    findings = []
    ftp_url = f"{base_url.rstrip('/')}/ftp/"

    try:
        r = requests.get(ftp_url, timeout=BASE_TIMEOUT)
        if r.status_code == 200 and ("acquisitions.md" in r.text or "coupons" in r.text):
            findings.append(_finding(
                title="Открытый листинг директории /ftp/",
                severity="medium",
                endpoint=ftp_url,
                evidence=r.text[:500],
                description="Directory listing включён, видны имена файлов.",
                recommendation="Отключить autoindex / directory listing.",
                tool="test_ftp_directory_listing",
            ))
    except Exception as exc:
        findings.append({"error": f"ftp listing: {exc}"})

    # конфиденциальный документ
    doc_url = f"{base_url.rstrip('/')}/ftp/acquisitions.md"
    try:
        r = requests.get(doc_url, timeout=BASE_TIMEOUT)
        if r.status_code == 200 and len(r.text) > 50:
            findings.append(_finding(
                title="Доступ к конфиденциальному документу",
                severity="high",
                endpoint=doc_url,
                evidence=r.text[:500],
                description="acquisitions.md доступен без аутентификации.",
                recommendation="Убрать чувствительные файлы из web-root.",
                tool="test_ftp_directory_listing",
            ))
    except Exception as exc:
        findings.append({"error": f"acquisitions: {exc}"})

    if not findings:
        findings.append(_finding(
            title="FTP exposures (не подтверждено)",
            severity="info",
            endpoint=ftp_url,
            evidence="листинг или acquisitions.md недоступны",
            status="requires_verification",
            tool="test_ftp_directory_listing",
        ))
    return json.dumps({"findings": findings}, ensure_ascii=False, indent=2)