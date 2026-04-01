"""
PHANTOM BRAIN - ProxmarkTool
Wrapper de ProxmarkParser en el patron BaseTool.
El parser original (proxmark_parser.py) no se modifica.
"""

from tools.base_tool import BaseTool, ToolResult
from prompts.system_prompts import obtener_prompt


class ProxmarkTool(BaseTool):
    name = "Proxmark3"
    description = "Analiza output del Proxmark3 (EM410x, MIFARE Classic, MIFARE Plus, EMV, ST25TA, Indala)"

    def prompt(self) -> str:
        return obtener_prompt("Proxmark3")

    def run(self, input_data: str) -> ToolResult:
        try:
            from proxmark_parser import ProxmarkParser
            parser = ProxmarkParser(input_data)
            data = parser.get_data()
            summary = parser.get_summary()
            vulns = data.get("vulnerabilities", [])
            # Determinar risk level
            tipo = data.get("type", "Unknown")
            if tipo in ("EM410x", "MIFARE Classic") or "CRITICO" in " ".join(vulns):
                risk = "CRITICO"
            elif tipo in ("MIFARE Plus", "ST25TA", "EMV"):
                risk = "ALTO"
            elif tipo == "Unknown":
                risk = "DESCONOCIDO"
            else:
                risk = "MEDIO"

            return ToolResult(
                success=True,
                content=summary,
                risk=risk,
                findings=vulns,
                metadata={
                    "tipo": tipo,
                    "uid": data.get("uid") or data.get("raw_id"),
                    "protocolo": data.get("protocol"),
                    "frecuencia": data.get("frequency"),
                }
            )
        except Exception as e:
            return ToolResult(
                success=False,
                content="",
                error=f"Error al parsear output Proxmark3: {e}"
            )

    def validate(self, input_data) -> bool:
        if not isinstance(input_data, str) or len(input_data.strip()) == 0:
            return False
        return True
