from langgraph.graph import StateGraph, START, END
from cyber_agent.agent.state import AgentState
from cyber_agent.agent.nodes.agent_node import agent_node
from cyber_agent.agent.nodes.tools_node import tools_node
from cyber_agent.agent.nodes.finding_node import finding_node
from cyber_agent.agent.nodes.critic_node import critic_node
from cyber_agent.agent.routing import should_condition, should_revise

def build_agent():
    workflow = StateGraph(AgentState)
    workflow.add_node("agent", agent_node)
    workflow.add_node("tools", tools_node)
    workflow.add_node("finding", finding_node)
    workflow.add_node("critic", critic_node)
    workflow.add_edge(START, "agent")
    workflow.add_conditional_edges(
        "agent", should_condition, {"tools": "tools", "end": "critic"}
    )
    workflow.add_edge("tools", "finding")
    workflow.add_edge("finding", "agent")
    workflow.add_conditional_edges(
        "critic", should_revise, {"revise": "agent", "end": END}
    )
    return workflow.compile()

agent = build_agent()