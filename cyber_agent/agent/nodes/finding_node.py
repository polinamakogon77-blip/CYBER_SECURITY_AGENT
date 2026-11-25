from langchain_core.messages import ToolMessage
from cyber_agent.agent.config import llm
from cyber_agent.agent.state import FindingsResult

def finding_node(state) -> dict:
    results = []
    for message in reversed(state["messages"]):
        if not isinstance(message, ToolMessage):
            break
        results.append(message.content)

    if not results:
        return {}
        
    results.reverse()
    results = [str(r)[:2000] for r in results]
    
    total, trimmed = 0, []
    for r in results:
        if total + len(r) > 16000:
            trimmed.append("... [остальные результаты опущены из-за лимита]")
            break
        trimmed.append(r)
        total += len(r)
        
    prompt = (
        f"Проанализируй результаты инструментов:\n{trimmed}\n"
        "Сформируй отдельный Finding для каждой уязвимости. "
        "Не выдумывай доказательства. При нехватке доказательств "
        "используй status='requires_verification'. "
        "Если находок нет, верни пустой список findings."
    )
    
    parsed: FindingsResult = llm.with_structured_output(FindingsResult).invoke(prompt)
    existing = state.get("findings", [])
    new = [item.model_dump() for item in parsed.findings]
    unique_new = [i for i in new if i not in existing]
    
    return {"findings": existing + unique_new}