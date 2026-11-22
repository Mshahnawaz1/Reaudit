from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel

Area = Literal["secrets", "deps", "ci", "code", "config", "meta"]
Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Hit(BaseModel):
    rule_id: str
    area: Area
    severity: Severity
    file: str
    line: int
    end_line: int | None = None
    snippet: str
    cwe: str | None = None
    title: str
    explanation: str
    confidence: float = 0.9
    fix_hint: str = ""


class ScanFile(Protocol):
    path: str
    size: int
    lang: str | None
    area: str | None
