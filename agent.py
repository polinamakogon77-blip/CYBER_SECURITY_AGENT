import os
from pathlib import Path
from typing import TypedDict, Annotated
from dotenv import load_dotenv
from langchain_deepseek import ChatDeepSeek
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

from tools import ALL_TOOLS

SYSTEM_PROMPT = Path("prompts/system_prompt.md").read_text(encoding="utf-8")

load_dotenv()
NSU_TOKEN = os.getenv("NSU_TOKEN")
if not NSU_TOKEN:
    raise RuntimeError("Создайте файл .env в вашей директории и укажите: NSU_TOKEN='токен Беспалова'")

llm = ChatDeepSeek(
    model="deepseek-ai/DeepSeek-V4-Flash-0731",
    api_key=NSU_TOKEN,
    base_url="https://deepcode.ci.nsu.ru/api",
    temperature=0,
)

llm_tools = llm.bind_tools(ALL_TOOLS)
NAME_TOOLS = {t.name: t for t in ALL_TOOLS}

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]

def agent_node(state: AgentState) -> dict:
    messages = state["messages"]
    if not messages or not isinstance(messages[0], SystemMessage):
        messages = [SystemMessage(content=SYSTEM_PROMPT)] + list(messages)
    response = llm_tools.invoke(messages)
    return {"messages": [response]}

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

    return {"messages": tool_messages}

def condition(state: AgentState) -> str:
    last_message = state["messages"][-1]
    if getattr(last_message, "tool_calls", None):
        return "tools"
    return "end"

workflow = StateGraph(AgentState)
workflow.add_node("agent", agent_node)
workflow.add_node("tools", tools_node)
workflow.add_edge(START, "agent")
workflow.add_conditional_edges(
    "agent",
    condition,
    {
        "tools": "tools",
        "end": END,
    },
)
workflow.add_edge("tools", "agent")
agent = workflow.compile()
agent.get_graph().print_ascii()

if __name__ == "__main__":
    task = (
        "проверить приложение http://localhost:3000 на уязвимости "
        "проверить IDOR на точке входа /rest/basket с id='1' и токеном 'test-token-123'"
    )

    result = agent.invoke({
        "messages": [HumanMessage(content=task)]
    })

    print(result["messages"][-1].content)