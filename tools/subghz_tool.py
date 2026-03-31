"""
PHANTOM BRAIN - SubGHzTool
Wrapper de SubGhzParser en el patron BaseTool.
"""

from tools.base_tool import BaseTool, ToolResult
from prompts.system_prompts import obtener_prompt


class SubGHzTool(BaseTool):
    name = "Sub-GHz"
    description = "Analiza archivos .sub del Flipper Zero (Security+, Rolling Code, Fixed Code)"

    def prompt(self) -> str:
        return obtener_prompt("Sub-GHz")

    def run(self, input_data: str) -> ToolResult:
        """input_data: ruta al archivo .sub"""
        try:
            from sub_ghz_parser import SubGhzParser
            parser = SubGhzParser(input_data)
            data = parser.get_data()
            resumen = f"Protocolo: {data.get('protocol')}\nFrecuencia: {data.get('frequency')} Hz\nKey: {data.get('key')}\nBits: {data.get('bit')}"
            return ToolResult(
                success=True,
                content=resumen,
                metadata={
                    "protocolo": data.get("protocol"),
                    "frecuencia": data.get("frequency"),
                    "key": data.get("key"),
                }
            )
        except Exception as e:
            return ToolResult(success=False, content="", error=f"Error Sub-GHz: {e}")

    def validate(self, input_data) -> bool:
        import os
        return isinstance(input_data, str) and input_data.endswith(".sub") and os.path.exists(input_data)
