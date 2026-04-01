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
            tipo = data.get("card_type") or data.get("type", "Unknown")
            tipo_lower = str(tipo).lower()
            if "classic" in tipo_lower or "mifare" in tipo_lower:
                risk = "CRITICO"
            elif "emv" in tipo_lower or "ntag" in tipo_lower:
                risk = "ALTO"
            elif "desfire" in tipo_lower:
                risk = "MEDIO"
            else:
                risk = "DESCONOCIDO"
            findings = data.get("vulnerabilities", [])

            return ToolResult(
                success=True,
                content=summary,
                risk=risk,
                findings=findings,
                metadata={
                    "tipo": tipo,
                    "uid": data.get("uid"),
                    "protocolo": data.get("protocol"),
                }
            )
        except Exception as e:
            return ToolResult(success=False, content="", error=f"Error NFC: {e}")

    def validate(self, input_data) -> bool:
        return isinstance(input_data, str) and len(input_data.strip()) > 0
