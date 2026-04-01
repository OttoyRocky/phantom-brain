"""
PHANTOM BRAIN - WPA2Tool
Wrapper de PCAPParserV2 en el patron BaseTool.
"""

from tools.base_tool import BaseTool, ToolResult
from prompts.system_prompts import obtener_prompt


class WPA2Tool(BaseTool):
    name = "WPA2"
    description = "Analiza capturas .pcap de handshakes WPA2 y PMKID"

    def prompt(self) -> str:
        return obtener_prompt("WPA2")

    def run(self, input_data: str) -> ToolResult:
        """input_data: ruta al archivo .pcap"""
        try:
            from pcap_parser_v2 import PCAPParserV2
            parser = PCAPParserV2(input_data)
            data = parser.get_data()
            summary = parser.get_summary() if hasattr(parser, "get_summary") else str(data)
            handshake = data.get("handshake_complete", False)
            pmkid = data.get("pmkid_found", False)
            risk = "CRITICO" if (handshake or pmkid) else "MEDIO"
            findings = []
            if handshake:
                findings.append("Handshake WPA2 completo - crackeo offline posible")
            if pmkid:
                findings.append("PMKID capturado - no requiere cliente conectado")
            if not findings:
                findings.append("Handshake incompleto - captura parcial")

            return ToolResult(
                success=True,
                content=summary,
                risk=risk,
                findings=findings,
                metadata={
                    "bssid": data.get("bssid"),
                    "ssid": data.get("ssid"),
                    "handshake_completo": handshake,
                    "pmkid": pmkid,
                }
            )
        except Exception as e:
            return ToolResult(success=False, content="", error=f"Error WPA2: {e}")

    def validate(self, input_data) -> bool:
        import os
        return isinstance(input_data, str) and os.path.exists(input_data)
