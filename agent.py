import os
import argparse
from pathlib import Path
from typing import TypedDict, Annotated
from dotenv import load_dotenv
from langchain_deepseek import ChatDeepSeek
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from schemas.finding import Finding
from langchain_openai import ChatOpenAI

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

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    revision_count: int
    final_res: str
    tools_call_count: int
    finding: dict

def agent_node(state: AgentState) -> dict:
    messages = list(state["messages"])
    if not messages or not isinstance(messages[0], SystemMessage):
        messages = [SystemMessage(content=SYSTEM_PROMPT)] + messages
    finding = state.get("finding")
    if finding:
        messages.append(
            HumanMessage(
                content=(
                    "Вот структурированный результат анализа инструмента:\n"
                    f"{finding}\n\n"
                    "Используй его при формировании итогового отчёта. "
                    "Не искажай доказательства и не придумывай новые факты."
                )
            )
        )
    response = llm_tools.invoke(messages)
    newres = {"messages": [response]}
    if not getattr(response, "tool_calls", None):
        newres["final_res"] = response.content
    return newres

def tools_node(state: AgentState) -> dict:
    last_message = state["messages"][-1]
    tool_messages = []
    for tool_call in last_message.tool_calls:
        tool_name = tool_call["name"]
        tool_args = tool_call["args"]
        tool_id = tool_call["id"]
        tool_fn = NAME_TOOLS.get(tool_name)
        if tool_fn is None:
            result = f"Инструмент '{tool_name}' не найден."
        else:
            try:
                result = tool_fn.invoke(tool_args)
            except Exception as e:
                result = f"Ошибка при вызове {tool_name}: {e}"
        tool_messages.append(
            ToolMessage(content=result, tool_call_id=tool_id)
        )

    return {"messages": tool_messages,
            "tools_call_count": state.get("tools_call_count", 0) + 1}

def finding_node(state: AgentState) -> dict:
    # Преобразует результаты инструментов в структурированный Finding

    messages = state["messages"]
    tool_results = [
        m.content
        for m in messages
        if isinstance(m, ToolMessage)
    ]

    if not tool_results:
        return {}

    structured_llm = llm.with_structured_output(Finding)

    prompt = f"""
    Проанализируй результаты инструментов безопасности: {tool_results}. Сформируй одну находку безопасности.
    Не придумывай уязвимость, если доказательств недостаточно.
    В таком случае используй status="requires_verification".
    """

    finding = structured_llm.invoke(prompt)

    return {
        "finding": finding.model_dump()
    }

def critic_node(state: AgentState) -> dict:
    """Оценивает финальный отчёт агента."""
    messages = state["messages"]
    last_ag_message = messages[-1].content
    task = next(
        (m.content for m in messages if isinstance(m, HumanMessage)),
        ""
    )
    request = [
        SystemMessage(content=CRITIC_PROMPT),
        HumanMessage(content=f"Задача:\n{task}\n\nОтчёт:\n{last_ag_message}")
    ]
    response = llm.invoke(request).content
    y = "SUCCESS" in response.upper()
    if not y:
        return {
            "messages": [
                HumanMessage(content=(
                    f"Критик нашёл проблемы в твоём отчёте:\n\n{response}\n\n"
                    "Перепиши отчёт, исправив замечания."
                ))
            ],
            "revision_count": state.get("revision_count", 0) + 1,
        }
    return {"revision_count": state.get("revision_count", 0)}

def should_revise(state: AgentState) -> str:
    """После критика: либо переписать результат, либо вывести ответ llm."""
    if state.get("revision_count", 0) >= MAX_REVISIONS:
        return "end"  
    last = state["messages"][-1]
    if isinstance(last, HumanMessage) and "Критик нашёл проблемы" in last.content:
        return "revise"
    return "end" 

def should_condition(state: AgentState) -> str:
    last_message = state["messages"][-1]
    if getattr(last_message, "tool_calls", None):
        if state.get("tools_call_count", 0) >= MAX_TOOL_CALLS:
            return "end"
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

    args = parser.parse_args()

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
     # ============ запуск ============
    print(f'{"=" * 30}\nЗАДАЧА ДЛЯ АГЕНТА:\n{task}\n{"=" * 30}')
    result = agent.invoke({
        "messages": [HumanMessage(content=task)]
    })

    # ============ отчет ============
    report = result.get("final_res", "Агент не сформировал отчёт.")
    print(f'{"=" * 30}\nИТОГОВЫЙ ОТЧЁТ:\n{report}\n{"=" * 30}')

    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "report.md"
    with open(report_path, "w", encoding="utf-8") as file:
        file.write(report)
    print(f"\nОТЧЁТ СОХРАНЕН: {report_path.resolve()}")
