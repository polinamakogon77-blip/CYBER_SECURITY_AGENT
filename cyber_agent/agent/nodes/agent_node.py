from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from cyber_agent.agent.config import llm_tools, MAX_TOOL_CALLS

def agent_node(state) -> dict:
    messages = list(state["messages"])

    if not messages or not isinstance(messages[0], SystemMessage):
        messages.insert(
            0,
            SystemMessage(content=state.get("system_prompt", "")),
        )
    
    findings = state.get("findings", [])
    if findings:
        messages.append(HumanMessage(content=(
            "Накопленные структурированные находки:\n"
            f"{findings}\n"
            "ОБЯЗАТЕЛЬНО включи в итоговый отчёт КАЖДУЮ находку "
            "из списка, включая LOW/informational "
            "(например, security.txt). "
            "Не придумывай новые доказательства и не удаляй находки."
        )))
    
    used = state.get("tools_call_count", 0)
    if used >= MAX_TOOL_CALLS:
        messages.append(HumanMessage(content=(
            "Лимит инструментов исчерпан. Не вызывай инструменты. "
            "Сформируй окончательный отчёт по имеющимся данным."
        )))
    
    print("[AGENT] Отправляю запрос модели...", flush=True)
    response: AIMessage = llm_tools.invoke(messages)
    print("[AGENT] Ответ модели получен", flush=True)
    
    result = {"messages": [response]}
    if not getattr(response, "tool_calls", None):
        result["final_res"] = response.content
        
    return result