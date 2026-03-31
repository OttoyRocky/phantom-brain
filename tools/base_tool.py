"""
PHANTOM BRAIN - BaseTool
Clase base para todas las herramientas de analisis.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ToolResult:
    success: bool
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class BaseTool(ABC):
    name: str = ""
    description: str = ""

    @abstractmethod
    def prompt(self) -> str:
        pass

    @abstractmethod
    def run(self, input_data: Any) -> ToolResult:
        pass

    def validate(self, input_data: Any) -> bool:
        return True

    def format_result(self, data: Dict[str, Any]) -> str:
        lines = []
        for key, value in data.items():
            if value is not None and value != [] and key != "raw":
                lines.append(f"{key.upper()}: {value}")
        return "\n".join(lines)
