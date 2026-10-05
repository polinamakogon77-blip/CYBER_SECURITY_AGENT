from typing import Literal
from pydantic import BaseModel


class Finding(BaseModel):
    title: str
    type: str

    severity: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    location: str
    tool: str
    evidence: str

    status: Literal[
        "confirmed",
        "requires_verification"
    ]

    description: str
    recommendation: str
