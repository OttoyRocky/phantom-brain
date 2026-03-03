"""
PHANTOM BRAIN - Parsers de capturas
Marauder, Sub-GHz, NFC, PCAP
"""

import os
import re

from config import CONFIG, logger


def parsear_marauder(contenido):
    wps_expuesto = []
    redes_ocultas = []
    lineas = contenido.split('\n')
    red_actual = {}
    for linea in lineas:
        linea = linea.strip()
        if 'RSSI:' in linea and 'BSSID:' in linea and 'ESSID:' in linea:
            red_actual = {}
            try:
                rssi = re.search(r'RSSI:\s*([-\d]+)', linea)
                ch = re.search(r'Ch:\s*(\d+)', linea)
                bssid = re.search(r'BSSID:\s*([\w:]+)', linea)
                essid = re.search(r'ESSID:\s*(.+)', linea)
                if rssi and ch and bssid and essid:
                    red_actual = {
                        'rssi': int(rssi.group(1)),
                        'ch': ch.group(1),
                        'bssid': bssid.group(1),
                        'essid': essid.group(1).strip()
                    }
                    if red_actual['essid'] == red_actual['bssid']:
                        redes_ocultas.append(red_actual.copy())
            except Exception as e:
                logger.debug(f"Error parsing linea Marauder: {e}")
        if 'RXd WPS Configs' in linea and red_actual:
            nombre_red = linea.split(':')[0].strip()
            wps_expuesto.append({
                'essid': nombre_red,
                'bssid': red_actual.get('bssid', 'N/A'),
                'ch': red_actual.get('ch', 'N/A'),
                'rssi': red_actual.get('rssi', 'N/A')
            })
    total_redes = len([l for l in lineas if 'RSSI:' in l and 'BSSID:' in l])
    resumen = "=== ANALISIS FILTRADO DEL LOG MARAUDER ===\n\n"
    resumen += "[REDES CON WPS EXPUESTO - RIESGO CRITICO]\n"
    if wps_expuesto:
        for r in wps_expuesto:
            resumen += f"- ESSID: {r['essid']} | BSSID: {r['bssid']} | Ch: {r['ch']} | RSSI: {r['rssi']} dBm\n"
    else:
        resumen += "- Ninguna detectada\n"
    resumen += "\n[REDES OCULTAS DETECTADAS - RIESGO ALTO]\n"
    if redes_ocultas:
        for r in redes_ocultas:
            resumen += f"- BSSID: {r['bssid']} | Ch: {r['ch']} | RSSI: {r['rssi']} dBm\n"
    else:
        resumen += "- Ninguna detectada\n"
    resumen += "\n[ESTADISTICAS GENERALES]\n"
    resumen += f"- Total redes detectadas: {total_redes}\n"
    resumen += f"- Redes con WPS vulnerable: {len(wps_expuesto)}\n"
    resumen += f"- Redes ocultas: {len(redes_ocultas)}\n"
    return resumen


def listar_capturas_subghz(directory):
    try:
        capturas = [f for f in os.listdir(directory) if f.endswith('.sub')]
        return sorted(capturas)
    except Exception as e:
        logger.error(f"Error al listar capturas Sub-GHz en '{directory}': {e}")
        return []


def parsear_subghz_archivo(filepath):
    try:
        from sub_ghz_parser import SubGhzParser
        parser = SubGhzParser(filepath)
        captura = parser.get_data()
        resumen = "=== ANALISIS SUB-GHZ FLIPPER ===\n\n"
        resumen += "[CAPTURA DETECTADA]\n"
        resumen += f"Archivo: {captura['filename']}\n"
        resumen += f"Protocolo: {captura['protocol']}\n"
        resumen += f"Frecuencia: {captura['frequency']} Hz\n"
        resumen += f"Preset: {captura['preset']}\n"
        resumen += f"Bits: {captura['bit']}\n"
        resumen += f"Key: {captura['key']}\n"
        resumen += f"Packet: {captura.get('secplus_packet_1', 'N/A')}\n\n"
        return resumen
    except ImportError:
        logger.error("sub_ghz_parser.py no encontrado.")
        print("[ERROR] sub_ghz_parser.py no encontrado en la carpeta del proyecto.")
        return None
    except FileNotFoundError:
        logger.error(f"Archivo Sub-GHz no encontrado: {filepath}")
        print(f"[ERROR] Archivo '{filepath}' no encontrado.")
        return None
    except Exception as e:
        logger.error(f"Error al parsear Sub-GHz '{filepath}': {e}")
        print(f"[ERROR] No se pudo leer el archivo Sub-GHz: {e}")
        return None


def parsear_nfc_archivo(filepath):
    try:
        from nfc_parser import NFCParser
        parser = NFCParser(filepath)
        captura = parser.get_data()
        resumen = "=== ANALISIS NFC FLIPPER ===\n\n"
        resumen += "[CAPTURA DETECTADA]\n"
        resumen += f"Archivo: {captura.get('filename', 'N/A')}\n"
        resumen += f"Tipo: {captura.get('device_type', 'N/A')}\n"
        resumen += f"UID: {captura.get('uid', 'N/A')}\n"
        resumen += f"Fabricante: {captura.get('manufacturer', 'N/A')}\n\n"
        return resumen
    except ImportError:
        logger.error("nfc_parser.py no encontrado.")
        print("[ERROR] nfc_parser.py no encontrado en la carpeta del proyecto.")
        return None
    except FileNotFoundError:
        logger.error(f"Archivo NFC no encontrado: {filepath}")
        print(f"[ERROR] Archivo '{filepath}' no encontrado.")
        return None
    except Exception as e:
        logger.error(f"Error al parsear NFC '{filepath}': {e}")
        print(f"[ERROR] No se pudo leer el archivo NFC: {e}")
        return None


def listar_capturas_pcap(directory):
    try:
        from pcap_parser_v2 import analyze_pcap_files
        capturas_data = analyze_pcap_files(directory)
        archivos = [c['filename'] for c in capturas_data]
        return sorted(archivos), capturas_data
    except ImportError:
        logger.error("pcap_parser_v2.py no encontrado.")
        print("[ERROR] pcap_parser_v2.py no encontrado. Instala scapy: pip install scapy")
        return [], []
    except Exception as e:
        logger.error(f"Error al listar capturas PCAP: {e}")
        print(f"[ERROR] No se pudieron listar archivos .pcap: {e}")
        return [], []


def parsear_pcap_archivo(filepath):
    try:
        from pcap_parser_v2 import PCAPParserV2
        parser = PCAPParserV2(filepath)
        captura = parser.get_data()
        resumen = "=== ANALISIS WPA2 HANDSHAKE ===\n\n"
        resumen += "[CAPTURA DETECTADA]\n"
        resumen += f"Archivo: {captura['filename']}\n"
        resumen += f"Total paquetes: {captura['total_packets']}\n"
        resumen += f"BSSID: {captura['bssid']}\n"
        resumen += f"SSID: {captura['ssid']}\n"
        resumen += f"Frames EAPOL: {len(captura['eapol_frames'])}\n"
        resumen += f"Handshake completo: {captura['handshake_complete']}\n\n"
        if captura.get('vulnerabilities'):
            resumen += "[VULNERABILIDADES DETECTADAS]\n"
            for vuln in captura['vulnerabilities']:
                resumen += f"- [{vuln['nivel']}] {vuln['nombre']}: {vuln['descripcion']}\n"
            resumen += "\n"
        return resumen
    except ImportError:
        logger.error("pcap_parser_v2.py no encontrado.")
        print("[ERROR] pcap_parser_v2.py no encontrado.")
        return None
    except FileNotFoundError:
        logger.error(f"Archivo PCAP no encontrado: {filepath}")
        print(f"[ERROR] Archivo '{filepath}' no encontrado o corrupto.")
        return None
    except Exception as e:
        logger.error(f"Error al parsear PCAP '{filepath}': {e}")
        print(f"[ERROR] No se pudo leer el archivo PCAP. ¿Esta corrupto? Detalle: {e}")
        return None
