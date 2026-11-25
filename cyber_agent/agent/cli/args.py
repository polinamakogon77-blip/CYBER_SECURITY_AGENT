import argparse

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Агент по кибербезопасности: проверка веб-приложений на уязвимости"
    )
    parser.add_argument("--url", default=None, help="URL приложения (Juice Shop)")
    parser.add_argument("--source", default=None, help="путь к исходникам Juice Shop")
    parser.add_argument("--rules", default=None, help="путь к файлу правил Semgrep")
    parser.add_argument("--idor-endpoint", default="/rest/basket", help="точка входа для IDOR")
    parser.add_argument("--idor-id", default="1", help="ID объекта для IDOR")
    parser.add_argument("--idor-token", default="test-token-123", help="токен для IDOR")
    parser.add_argument("--no-idor", action="store_true", help="не проверять IDOR")
    parser.add_argument("--no-semgrep", action="store_true", help="не запускать Semgrep")
    parser.add_argument("--zap-url", default=None, help="URL для ZAP-сканирования")
    parser.add_argument("--zap-mode", default="baseline",
                        choices=["baseline", "full", "api"], help="Режим ZAP-сканирования")
    parser.add_argument("--no-zap", action="store_true", help="не запускать ZAP")
    parser.add_argument("--no-nuclei", action="store_true", help="не запускать Nuclei")
    parser.add_argument("--sqli-lab-url", default=None, help="URL SQLi Lab стенда")
    parser.add_argument("--sqli-source", default=None, help="путь к исходникам SQLi Lab")
    parser.add_argument("--no-sqli-lab", action="store_true", help="не проверять SQLi Lab")
    parser.add_argument("--nosqli-lab-url", default=None, help="URL NoSQLi Lab стенда")
    parser.add_argument("--nosqli-source", default=None, help="путь к исходникам NoSQLi Lab")
    parser.add_argument("--no-nosqli-lab", action="store_true", help="не проверять NoSQLi Lab")
    parser.add_argument("--task", default=None, help="произвольная задача (перекрывает остальное)")
    parser.add_argument("--defend", action="store_true",
                        help="Режим защиты: guardrails + белый список инструментов")
    return parser