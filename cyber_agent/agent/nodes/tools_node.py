from langchain_core.messages import ToolMessage
from cyber_agent.agent.config import get_name_to_tools
from cyber_agent.agent.defend_agent import replace_tool_output, DEFENSIVE_ALLOWED_TOOLS

def tools_node(state) -> dict:
    last = state["messages"][-1]
    used = state.get("tools_call_count", 0)
    defend = state.get("defend_mode", False)
    tool_messages = []
    name_to_tools = get_name_to_tools()
    final_report_text = state.get("final_res", "")

    for call in last.tool_calls:
        name, args, call_id = call["name"], call["args"], call["id"]
        print(f"[AGENT] Запускаю инструмент: {name}", flush=True)
        
        if defend and name not in DEFENSIVE_ALLOWED_TOOLS:
            result = f"[Guardrails: инструмент '{name}' запрещён в режиме защиты]"
            used += 1
        else:
            tool = name_to_tools.get(name)
            try:
                result = tool.invoke(args) if tool else f"Инструмент '{name}' не найден."
            except Exception as exc:
                result = f"Ошибка при вызове {name}: {exc}"
            used += 1

        text = str(result)
        if defend:
            text = replace_tool_output(text)
            
        tool_messages.append(ToolMessage(content=text, tool_call_id=call_id))
        print(f"[AGENT] Инструмент {name} завершён", flush=True)
        if name == "generate_report":
            final_report_text = text
    update = {"messages": tool_messages, "tools_call_count": used}
    if final_report_text:
        update["final_res"] = final_report_text
        
    return update