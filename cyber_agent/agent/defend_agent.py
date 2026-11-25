import re
import sys

PATTERNS_INJECTION = [
    re.compile(p, re.IGNORECASE) for p in [
        r"игнорируй\s+(все\s+)?предыдущ",
        r"забудь\s+(свой\s+)?(системн|промпт|инструкц)",
        r"ты\s+теперь\s+(dan|режим)",
        r"отключи\s+(свои\s+)?(ограничен|фильтр|защит)",
        r"выведи\s+(свой\s+)?(системный\s+промпт|инструкц)",
        r"новая\s+инструкция\s*:",
        r"действуй\s+как\s+",
        r"притворись\s+(что\s+ты\s+)?",
        r"ignore\s+(all\s+)?(previous|prior)",
        r"forget\s+(your\s+)?(system\s+prompt|instructions)",
        r"you\s+are\s+now\s+dan",
        r"new\s+instructions?\s*:",
    ]
]

OUTPUT_PATTERNS = [
    (re.compile(p, re.IGNORECASE), "[REDACTED]") for p in [
        r"ignore\s+(all\s+)?(previous|prior)\s+instructions?",
        r"игнорируй\s+(все\s+)?предыдущ\w*\s+инструкц\w*",
        r"you\s+are\s+now\s+dan",
        r"ты\s+теперь\s+dan",
        r"новые\s+инструкции\s*:",
        r"new\s+instructions?\s*:",
        r"system\s*prompt\s*:",
        r"системный\s+промпт\s*:",
    ]
]


def _cut_payloads(text: str) -> str:
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"`[^`]*`", " ", text)
    text = re.sub(r"https?://\S+", " ", text)
    text = re.sub(r"\"[^\"]*\"", " ", text)
    text = re.sub(r"'[^']*'", " ", text)
    return text


def check_task(task: str) -> tuple[bool, str]:
    cuted = _cut_payloads(task)
    for idx, pat in enumerate(PATTERNS_INJECTION):
        if pat.search(cuted):
            print(
                f"[DEFEND][debug] сработал паттерн {idx}: {pat.pattern}",
                file=sys.stderr,
            )
            return True, "запрос содержит признаки манипуляции инструкциями"
    return False, ""


def replace_tool_output(text: str) -> str:
    for pat, repl in OUTPUT_PATTERNS:
        text = pat.sub(repl, text)
    return text

DEFENSIVE_ALLOWED_TOOLS = {
    "list_files",
    "run_semgrep",
    "read_file",
    "read_file_around_line",
    "save_finding",
    "generate_report",
    "check_arp_table",
}