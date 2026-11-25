import re
from langchain_core.messages import SystemMessage, HumanMessage
from cyber_agent.agent.config import llm, load_prompts
from cyber_agent.agent.state import AgentState

def critic_node(state: AgentState) -> dict:
    """
    Узел графа, который проверяет сформированный отчёт на полноту и качество.
    Если отчёт плохой, увеличивает счётчик ревизий и возвращает замечания агенту.
    """
    prompts = load_prompts()
    critic_prompt = prompts.get("critic", "Оцени полноту и качество отчета.")
    messages = state["messages"]
    task = next(
        (m.content for m in messages if isinstance(m, HumanMessage)),
        "Задача не указана",
    )

    report = state.get("final_res", "")
    request = [
        SystemMessage(content=critic_prompt),
        HumanMessage(
            content=f"Задача:\n{task}\n\nОтчёт:\n{report}"
        ),
    ]
    feedback = str(llm.invoke(request).content)
    verdict = re.search(
        r"^Verdict:\s*(SUCCESS|NEEDS_IMPROVE)\s*$",
        feedback,
        re.MULTILINE | re.IGNORECASE,
    )
    success = (
        verdict is not None
        and verdict.group(1).upper() == "SUCCESS"
    )
    if success:
        return {}
    return {
        "messages": [
            HumanMessage(content=(
                f"Критик нашёл проблемы:\n{feedback}\n"
                "Исправь итоговый отчёт без новых неподтверждённых фактов."
            ))
        ],
        "revision_count": state.get("revision_count", 0) + 1,
    }