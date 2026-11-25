from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field
from cyber_agent.schemas.finding import Finding

class FindingsResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)

class AgentState(TypedDict, total=False):
    messages: Annotated[list, add_messages]
    revision_count: int
    final_res: str
    tools_call_count: int
    findings: list[dict]
    defend_mode: bool
    system_prompt: str