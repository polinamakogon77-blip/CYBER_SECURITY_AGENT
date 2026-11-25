from langchain_core.messages import HumanMessage, AIMessage
from cyber_agent.agent.config import MAX_REVISIONS

def should_revise(state) -> str:
    if state.get("revision_count", 0) >= MAX_REVISIONS:
        return "end"
    
    last = state["messages"][-1]
    # Проверяем, есть ли указание на проблемы от критика
    if isinstance(last, HumanMessage) and "Критик нашёл проблемы" in last.content:
        return "revise"
    return "end"

def should_condition(state) -> str:
    last_message = state["messages"][-1]
    # Проверяем, является ли последнее сообщение AIMessage и есть ли в нем вызовы инструментов
    if isinstance(last_message, AIMessage) and getattr(last_message, "tool_calls", None):
        return "tools"
    return "end"

def route_after_tools(state) -> str:
    """
    Проверяет, был ли только что вызван generate_report. 
    Если да — немедленно завершает работу графа.
    """
    messages = state["messages"]
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            if any(tc["name"] == "generate_report" for tc in msg.tool_calls):
                return "end" 
            break 
    return "finding"