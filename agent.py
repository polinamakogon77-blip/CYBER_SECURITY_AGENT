import os
import sys
import argparse
import re
from pathlib import Path
from typing import TypedDict, Annotated
from dotenv import load_dotenv
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from schemas.finding import Finding
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from tools import ALL_TOOLS

SYSTEM_PROMPT = Path("prompts/system_prompt.md").read_text(encoding="utf-8")
CRITIC_PROMPT = Path("prompts/critic_prompt.md").read_text(encoding="utf-8")

load_dotenv()
NSU_TOKEN = os.getenv("NSU_TOKEN")
if not NSU_TOKEN:
    raise RuntimeError("Создайте файл .env в вашей директории и укажите: NSU_TOKEN='токен Беспалова'")

MAX_TOOL_CALLS = 8
MAX_REVISIONS = 2

llm = ChatOpenAI(
    model="qwen3.8-flash-next",
    api_key=NSU_TOKEN,
    base_url="https://deepcode.ci.nsu.ru/api",
    temperature=0,
)

llm_tools = llm.bind_tools(ALL_TOOLS)
NAME_TOOLS = {t.name: t for t in ALL_TOOLS}

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
    """Вырезает из текста payload'ы, URL и код."""
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)  
    text = re.sub(r"`[^`]*`", " ", text)              
    text = re.sub(r"https?://\S+", " ", text)         
    text = re.sub(r"\"[^\"]*\"", " ", text)           
    text = re.sub(r"'[^']*'", " ", text)              
    return text


def check_task(task: str) -> tuple[bool, str]:
    """Проверяет задачу на prompt injection.
    Возвращает (blocked, reason)."""
    cuted = _cut_payloads(task)
    for idx, pat in enumerate(PATTERNS_INJECTION):
        if pat.search(cuted):
            print(f"[DEFEND][debug] сработал паттерн {idx}: {pat.pattern}",
        file=sys.stderr)
            return True, "запрос содержит признаки манипуляции инструкциями"
    return False, ""


def replace_tool_output(text: str) -> str:
    """Заменяет инъекционные вставки в выводе инструментов."""
    for pat, repl in OUTPUT_PATTERNS:
        text = pat.sub(repl, text)
    return text


DEFENSIVE_ALLOWED_TOOLS = {
    "list_files",
    "run_semgrep",
    "test_nosqli_lab",
    "check_arp_table",
}

class FindingsResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    revision_count: int
    final_res: str
    tools_call_count: int
    findings: list[dict]
    defend_mode: bool


def agent_node(state: AgentState) -> dict:
    messages = list(state["messages"])
    if not messages or not isinstance(messages[0], SystemMessage):
        messages.insert(0, SystemMessage(content=SYSTEM_PROMPT))

    findings = state.get("findings", [])
    if findings:
        messages.append(HumanMessage(content=(
            "Накопленные структурированные находки:\n"
            f"{findings}\nНе придумывай новые доказательства."
        )))

    used = state.get("tools_call_count", 0)
    if used >= MAX_TOOL_CALLS:
        messages.append(HumanMessage(content=(
            "Лимит инструментов исчерпан. Не вызывай инструменты. "
            "Сформируй окончательный отчёт по имеющимся данным."
        )))
        response = llm.invoke(messages)
    else:
        response = llm_tools.invoke(messages)

    result = {"messages": [response]}
    if not getattr(response, "tool_calls", None):
        result["final_res"] = response.content
    return result


def tools_node(state: AgentState) -> dict:
    last = state["messages"][-1]
    used = state.get("tools_call_count", 0)
    defend = state.get("defend_mode", False)
    tool_messages = []

    for call in last.tool_calls:
        name, args, call_id = call["name"], call["args"], call["id"]
        if used >= MAX_TOOL_CALLS:
            result = "Лимит инструментов исчерпан."
        elif defend and name not in DEFENSIVE_ALLOWED_TOOLS:
            result = f"[Guardrails: инструмент '{name}' запрещён в режиме защиты]"
            used += 1
        else:
            tool = NAME_TOOLS.get(name)
            try:
                result = tool.invoke(args) if tool else f"Инструмент '{name}' не найден."
            except Exception as exc:
                result = f"Ошибка при вызове {name}: {exc}"
            used += 1

        text = str(result)
        if defend:
            text = replace_tool_output(text)
        tool_messages.append(ToolMessage(content=text, tool_call_id=call_id))

    return {"messages": tool_messages, "tools_call_count": used}


def finding_node(state: AgentState) -> dict:
    results = []
    for message in reversed(state["messages"]):
        if not isinstance(message, ToolMessage):
            break
        results.append(message.content)
    if not results:
        return {}

    results.reverse()
    prompt = (
        f"Проанализируй результаты инструментов:\n{results}\n"
        "Сформируй отдельный Finding для каждой уязвимости. "
        "Не выдумывай доказательства. При нехватке доказательств "
        "используй status='requires_verification'. "
        "Если находок нет, верни пустой список findings."
    )
    parsed = llm.with_structured_output(FindingsResult).invoke(prompt)
    existing = state.get("findings", [])
    new = [item.model_dump() for item in parsed.findings]
    return {"findings": existing + [item for item in new if item not in existing]}


def critic_node(state: AgentState) -> dict:
    messages = state["messages"]
    task = next((m.content for m in messages if isinstance(m, HumanMessage)), "")
    report = state.get("final_res", "")
    request = [
        SystemMessage(content=CRITIC_PROMPT),
        HumanMessage(content=f"Задача:\n{task}\n\nОтчёт:\n{report}")
    ]
    feedback = str(llm.invoke(request).content)
    verdict = re.search(
        r"^Verdict:\s*(SUCCESS|NEEDS_IMPROVE)\s*$",
        feedback, re.MULTILINE | re.IGNORECASE
    )
    success = verdict is not None and verdict.group(1).upper() == "SUCCESS"
    if success:
        return {}
    return {
        "messages": [HumanMessage(content=(
            f"Критик нашёл проблемы:\n{feedback}\n"
            "Исправь итоговый отчёт без новых неподтверждённых фактов."
        ))],
        "revision_count": state.get("revision_count", 0) + 1,
    }


def should_revise(state: AgentState) -> str:
    if state.get("revision_count", 0) >= MAX_REVISIONS:
        return "end"
    last = state["messages"][-1]
    if isinstance(last, HumanMessage) and "Критик нашёл проблемы" in last.content:
        return "revise"
    return "end"


def should_condition(state: AgentState) -> str:
    if getattr(state["messages"][-1], "tool_calls", None):
        return "tools"
    return "end"


workflow = StateGraph(AgentState)
workflow.add_node("agent", agent_node)
workflow.add_node("tools", tools_node)
workflow.add_node("finding", finding_node)
workflow.add_node("critic", critic_node)
workflow.add_edge(START, "agent")
workflow.add_conditional_edges(
    "agent",
    should_condition,
    {
        "tools": "tools",
        "end": "critic",
    },
)
workflow.add_edge("tools", "finding")
workflow.add_edge("finding", "agent")
workflow.add_conditional_edges(
    "critic",
    should_revise,
    {
        "revise": "agent",
        "end": END,
    },
)

agent = workflow.compile()
agent.get_graph().print_ascii()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Агент по кибербезопасности: проверка веб-приложений на уязвимости"
    )
    parser.add_argument("--url", default=None, help="URL приложения (Juice Shop)")
    parser.add_argument("--source", default=None, help="путь к исходникам Juice Shop")
    parser.add_argument("--rules", default=None, help="путь к файлу правил Semgrep")

    # ============ IDOR ============
    parser.add_argument("--idor-endpoint", default="/rest/basket", help="точка входа для IDOR")
    parser.add_argument("--idor-id", default="1", help="ID объекта для IDOR")
    parser.add_argument("--idor-token", default="test-token-123", help="токен для IDOR")
    parser.add_argument("--no-idor", action="store_true", help="не проверять IDOR")

    # ============ Semgrep ============
    parser.add_argument("--no-semgrep", action="store_true", help="не запускать Semgrep")

    # ============ ZAP ============
    parser.add_argument("--zap-url", default=None,
                        help="URL для ZAP-сканирования")
    parser.add_argument("--zap-mode", default="baseline",
                        choices=["baseline", "full", "api"],
                        help="Режим ZAP-сканирования")
    parser.add_argument("--no-zap", action="store_true", help="не запускать ZAP")

    # ============ SQLi Lab ============
    parser.add_argument("--sqli-lab-url", default=None,
                        help="URL SQLi Lab стенда")
    parser.add_argument("--sqli-source", default=None,
                        help="путь к исходникам SQLi Lab")
    parser.add_argument("--no-sqli-lab", action="store_true",
                        help="не проверять SQLi Lab")
    # ============ NoSQLi Lab ============
    parser.add_argument("--nosqli-lab-url", default=None,
                        help="URL NoSQLi Lab стенда")
    parser.add_argument("--nosqli-source", default=None,
                        help="путь к исходникам NoSQLi Lab")
    parser.add_argument("--no-nosqli-lab", action="store_true",
                        help="не проверять NoSQLi Lab")
    # ============ произвольная задача ============
    parser.add_argument("--task", default=None,
                        help="произвольная задача (перекрывает остальное)")

    # флаг режима защиты
    parser.add_argument("--defend", action="store_true",
                        help="Режим защиты: guardrails + белый список инструментов")

    args = parser.parse_args()

    if args.defend:
        SYSTEM_PROMPT = Path("prompts/defend_prompt.md").read_text(encoding="utf-8")

    if args.task:
        task = args.task
    else:
        # ============ чтение параметров ============
        SOURCE_PATH = args.source or os.getenv("SOURCE_PATH", "/app/juice-shop")
        TARGET_URL = args.url or os.getenv("TARGET_URL", "http://juice-shop:3000")
        RULES_PATH = args.rules or os.getenv("RULES_PATH", "/app/rules/rules_semgrep.yaml")
        SQLI_LAB_URL = args.sqli_lab_url or os.getenv("SQLI_LAB_URL", "")
        SQLI_SOURCE_PATH = args.sqli_source or os.getenv("SQLI_SOURCE_PATH", "")
        NOSQLI_LAB_URL = args.nosqli_lab_url or os.getenv("NOSQLI_LAB_URL", "")
        NOSQLI_SOURCE_PATH = args.nosqli_source or os.getenv("NOSQLI_SOURCE_PATH", "")
        ZAP_URL = args.zap_url or os.getenv("ZAP_URL", "")
        ZAP_MODE = args.zap_mode
        DAN_LAB_URL = os.getenv("DAN_LAB_URL", "")

        parts = [f"Проведи анализ защищённости приложения {TARGET_URL}."]

        # ============ IDOR ============
        if not args.no_idor:
            parts.append(
                f"Проверь IDOR на точке входа {args.idor_endpoint} "
                f"с id='{args.idor_id}' и токеном '{args.idor_token}'."
            )

        # ============ Semgrep ============
        if not args.no_semgrep:
            parts.append(
                f"Запусти Semgrep на {SOURCE_PATH} с правилами {RULES_PATH}."
            )

        # ============ ZAP ============
        if not args.no_zap and ZAP_URL:
            parts.append(
                f"Запусти ZAP-скан ({ZAP_MODE}) на {ZAP_URL}."
            )

        # ============ SQLi Lab ============
        if not args.no_sqli_lab and SQLI_LAB_URL:
            parts.append(
                f"Проведи анализ SQLi на стенде {SQLI_LAB_URL}. "
                f"Проверь эндпоинты: "
                f"1) /api/login с payload \"' OR 1=1-- -\" (auth bypass); "
                f"2) /api/login с payload "
                f"\"x' UNION SELECT id, secret_usser, secret_usser FROM Secrets-- -\" (union); "
                f"3) /api/check_user с payload \"1' AND 1=1-- -\" и "
                f"\"1' AND 1=2-- -\" (blind boolean); "
                f"4) /api/check_user_slow с payload \"admin\" и "
                f"\"' OR (SELECT length(randomblob(100000000)))>0 AND 1=1-- -\" (time-based); "
                f"5) /api/oob с payload "
                f"\"admin'; ATTACH DATABASE 'oob_channel/leak.db' AS leak; "
                f"CREATE TABLE leak.d(x); INSERT INTO leak.d SELECT secret_usser FROM Secrets; --\" (OOB)."
            )
            if SQLI_SOURCE_PATH:
                parts.append(f"Запусти Semgrep на {SQLI_SOURCE_PATH}.")

        # ============ NoSQLi Lab ============
        if not args.no_nosqli_lab and NOSQLI_LAB_URL:
            parts.append(
                f"Проведи анализ NoSQLi на стенде {NOSQLI_LAB_URL}. "
                f"Проверь эндпоинты: "
                f"1) POST /api/login с payload "
                f"{{\"username\":\"admin\",\"password\":{{\"$ne\":null}}}} (auth bypass); "
                f"2) GET /api/check_user с payload "
                f"?username=admin&password[$regex]=^S (blind boolean); "
                f"3) GET /api/check_user_slow с payload "
                f"?username=admin&where=sleep(3000)||true (blind time); "
                f"4) GET /api/search с payload "
                f"?q=1';return this.hidden// (JS-injection в $where)."
            )
            if NOSQLI_SOURCE_PATH:
                parts.append(f"Запусти Semgrep на {NOSQLI_SOURCE_PATH}.")

        # ============ DAN / Prompt Injection ============
        if DAN_LAB_URL:
            parts.append(
                f"Проведи анализ Prompt Injection / DAN на стенде {DAN_LAB_URL}. "
                f"Используй инструмент test_dan."
            )

        parts.append("Опиши найденные уязвимости с критичностью и рекомендациями.")

        task = " ".join(parts)

    if args.defend:
        blocked, reason = check_task(task)
        if blocked:
            print(f"[DEFENCE] Ввод заблокирован: {reason}")
            sys.exit(1)

    # ============ запуск ============
    print(f'{"=" * 30}\nЗАДАЧА ДЛЯ АГЕНТА:\n{task}\n{"=" * 30}')
    result = agent.invoke({
        "messages": [HumanMessage(content=task)],
        "defend_mode": args.defend,
        "revision_count": 0,
        "tools_call_count": 0,
        "final_res": "",
        "findings": [],
    })

    # ============ отчет ============
    report = result.get("final_res") or "Агент не сформировал отчёт."

    if args.defend:
        report = replace_tool_output(report)

    print(f'{"=" * 30}\nИТОГОВЫЙ ОТЧЁТ:\n{report}\n{"=" * 30}')

    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "report.md"
    with open(report_path, "w", encoding="utf-8") as file:
        file.write(report)
    print(f"\nОТЧЁТ СОХРАНЕН: {report_path.resolve()}")
