# экспорт всех тулов агента
from .check_idor import check_idor

ALL_TOOLS = [
    check_idor
]

__all__ = ["ALL_TOOLS", "CHECK_IDOR"]