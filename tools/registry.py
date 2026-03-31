"""
PHANTOM BRAIN - Tool Registry
Registro central de herramientas disponibles.
Permite resolver cualquier tool por nombre sin imports dispersos.
"""

from tools.proxmark_tool import ProxmarkTool
from tools.nfc_tool import NFCTool
from tools.wpa2_tool import WPA2Tool
from tools.subghz_tool import SubGHzTool

REGISTRY = {
    "Proxmark3": ProxmarkTool(),
    "NFC":       NFCTool(),
    "WPA2":      WPA2Tool(),
    "Sub-GHz":   SubGHzTool(),
}

def get_tool(nombre: str):
    """Retorna la instancia del tool o None si no existe."""
    return REGISTRY.get(nombre)

def listar_tools():
    """Lista todos los tools registrados."""
    return [(nombre, tool.description) for nombre, tool in REGISTRY.items()]
