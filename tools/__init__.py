# экспорт всех тулов агента
from .check_idor import check_idor
from .run_semgrep import run_semgrep
from .test_sqli_login import test_sqli_login


ALL_TOOLS = [
    check_idor,
    run_semgrep,
    test_sqli_login
]

__all__ = ["ALL_TOOLS", "check_idor", "run_semgrep", "test_sqli_login"]