"""
PHANTOM BRAIN - NFCTool
Wrapper de NFCParser en el patron BaseTool.
"""

from tools.base_tool import BaseTool, ToolResult
from prompts.system_prompts import obtener_prompt


class NFCTool(BaseTool):
    name = "NFC"
    description = "Analiza archivos .nfc del Flipper Zero (Mifare, EMV, NTAG, DESFire, ST25TA)"

    def prompt(self) -> str:
        return obtener_prompt("NFC")

    def run(self, input_data: str) -> ToolResult:
        try:
            from nfc_parser import NFCParser
            parser = NFCParser(input_data)
            data = parser.get_data()
            summary = parser.get_summary() if hasattr(parser, "get_summary") else str(data)
            return ToolResult(
                success=True,
                content=summary,
                metadata={
                    "tipo": data.get("card_type") or data.get("type", "Unknown"),
                    "uid": data.get("uid"),
                    "protocolo": data.get("protocol"),
                }
            )
        except Exception as e:
            return ToolResult(success=False, content="", error=f"Error NFC: {e}")

    def validate(self, input_data) -> bool:
        return isinstance(input_data, str) and len(input_data.strip()) > 0
