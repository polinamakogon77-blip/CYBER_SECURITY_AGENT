import os
from pathlib import Path
from langchain.tools import tool

IGNORE = {".git", "__pycache__", ".venv", "venv", "node_modules"}

@tool
def list_files(path: str, max_depth: int = 3) -> str:
    """Показывает файлы и папки по указанному пути.

    path — корневой каталог (например, /app/target)
    max_depth — на сколько уровней вглубь заходить (по умолчанию 3)
    """
    if not os.path.exists(path):
        return f"не найден путь: {path}"
    if not os.path.isdir(path):
        return f"это не каталог: {path}"

    lines = []
    total = 0

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in IGNORE]
        depth = len(Path(os.path.relpath(root, path)).parts)
        if depth > max_depth:
            dirs[:] = []
            continue
        lines.append("  " * depth + os.path.basename(root) + "/")
        for f in sorted(files):
            lines.append(f"{'  ' * depth}  {f} ")
            total += 1

    if total == 0:
        return f"в {path} нет файлов"

    return f"Каталог {path} — {total} файлов:\n" + "\n".join(lines)