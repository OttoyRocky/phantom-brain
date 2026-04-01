"""
PHANTOM BRAIN - Auto Classifier
Detecta automaticamente el tipo de captura dado un input.
Permite el pipeline: input -> classify -> tool -> analyze
"""

import os


def clasificar(input_data: str) -> str:
    """
    Detecta el tipo de captura y retorna el nombre del tool correspondiente.
    Retorna "Generico" si no puede determinar el tipo.
    """
    # Archivo en disco
    if os.path.exists(input_data):
        ext = os.path.splitext(input_data)[1].lower()
        if ext == ".sub":
            return "Sub-GHz"
        if ext in (".pcap", ".cap", ".pcapng"):
            return "WPA2"
        if ext == ".nfc":
            return "NFC"
        if ext in (".json", ".txt", ".log"):
            contenido = _leer_fragmento(input_data)
            return _clasificar_texto(contenido)
        return "Manual"

    # Texto directo
    return _clasificar_texto(input_data)


def _leer_fragmento(filepath: str, bytes_max: int = 2048) -> str:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(bytes_max)
    except Exception:
        return ""


def _clasificar_texto(texto: str) -> str:
    t = texto.lower()

    # Proxmark3
    if any(k in t for k in ["em 410x", "em410x", "mifare", "proxmark", "hf search", "lf search", "t55xx", "emv", "st25ta", "indala"]):
        return "Proxmark3"

    # WiFi Marauder (antes de WPA2 porque también tiene bssid/essid)
    if any(k in t for k in ["rxd wps configs", "marauder", "rssi:", "redes con wps"]):
        return "WiFi-Marauder"

    # WPA2
    if any(k in t for k in ["eapol", "handshake", "pmkid", "hcxpcapngtool", "wpa2", "bssid", "essid"]):
        return "WPA2"

    # Sub-GHz
    if any(k in t for k in ["filetype: flipper radio", "frequency:", "preset:", "protocol:", "te:", "security+ 2.0", "rolling code"]):
        return "Sub-GHz"

    # NFC
    if any(k in t for k in ["filetype: flipper nfc", "uid:", "atqa:", "sak:", "nfc", "mifare", "ndef", "iso14443"]):
        return "NFC"

    # WiFi Marauder
    if any(k in t for k in ["rssi:", "rxd wps configs", "marauder", "essid:", "bssid:"]):
        return "WiFi-Marauder"

    return "Generico"
