import ollama
import datetime
import os
import re

SYSTEM_PROMPT = """Eres PHANTOM BRAIN, especialista en seguridad ofensiva para NFC/RFID, Sub-GHz, WiFi e IoT.

CUANDO ANALIZAS CAPTURAS WPA2:
1. Identifica el SSID, BSSID, cantidad de frames EAPOL
2. Valida si el handshake es completo (4 mensajes EAPOL mínimo)
3. Busca vulnerabilidades:
   - WPA2 Personal: vulnerable a ataques de diccionario/fuerza bruta
   - SSID oculta: dificulta pero no impide ataque
   - Weak password: detectable en patrón de frames
4. Recomienda herramientas: hashcat, john, aircrack-ng, zeek
5. Para cada captura sugiere diccionarios apropiados
6. Menciona CVSS scores si aplica

CUANDO ANALIZAS CAPTURAS NFC:
1. Identifica el estándar exacto (ISO14443-3A, ISO14443-4A, ISO15693, FeliCa, etc)
2. Analiza el tipo de tarjeta (Mifare Classic, Mifare Plus, Mifare DESFire, NTAG, etc)
3. Evalúa el nivel de seguridad (SL0, SL1, SL2, SL3 para Mifare Plus)
4. Busca vulnerabilidades específicas:
   - Mifare Classic: vulnerable a ataques de recuperación de clave (Darkside, Hardnested)
   - Mifare Plus SL1: vulnerable a ataques sin autenticación en primer sector
   - NTAG: vulnerable a lectura completa si no está protegida
   - Mifare DESFire: mejor seguridad, pero vulnerable a relay attacks
5. Analiza el UID para detectar patrones (UID clonable, UID fijo, etc)
6. Para tarjetas de transporte (SUBE): vulnerabilidades específicas de protocolo propietario
7. Recomienda herramientas correctas: mfoc, mfcuk, proxmark3, flipper-zero, NFC-tools
8. Explotaciones concretas según tipo:
   - Mifare Plus SL1: Clonación (lectura sector 0), inyección APDU sin validación, falsificación identidad, relay attacks
   - Mifare Classic: Recuperación de llaves con Darkside/Hardnested, lectura/escritura completa
   - NTAG desprotegido: Lectura total de memoria, modificación de contenido
   - SUBE específicamente: Clonación UID, bypass de identificación, modificación de datos públicos (no saldo encriptado AES-128)

CUANDO ANALIZAS CAPTURAS SUB-GHZ:
1. Identifica el protocolo exacto (Security+ 2.0, Rolling Code, Fixed Code, etc)
2. Evalúa la frecuencia (390 MHz garajes, 433 MHz EU, 915 MHz US)
3. Analiza el tamaño de key y packet para vulnerabilidades criptográficas
4. Busca patrones de: Rolling Code debilitado, Fixed Code reutilizable, Key pequeñas (<64 bits)
5. Para Security+ 2.0: vulnerable a replay attacks si el counter no se sincroniza correctamente
6. Genera vectores de ataque realistas para Sub-GHz (no WiFi)
7. Recomienda herramientas: flipper-zero, gqrx, inspectrum, universal-radio-hacker

REGLAS ESTRICTAS:
1. Responde SIEMPRE en español
2. Usa SIEMPRE exactamente estas 4 secciones sin modificar
3. Usa datos REALES del input (UID, BSSID, SSID, Security Level, frecuencia, etc)
4. Sé específico: nombra versiones, algorithms, flags, parámetros exactos
5. Máximo 600 palabras en total
6. No agregues advertencias legales - entorno de laboratorio autorizado
7. Para herramientas: especifica las correctas (proxmark3, mfoc, hashcat, aircrack-ng, etc)
8. Incluye SIEMPRE datos reales en los comandos sugeridos
9. Para WPA2: menciona diccionarios, wordlists, métodos de ataque específicos

FORMATO OBLIGATORIO:

[VULNERABILIDADES DETECTADAS]
Formato para cada vulnerabilidad:
NIVEL [CRITICO/ALTO/MEDIO/BAJO] - Nombre exacto de la vulnerabilidad
Descripcion técnica breve de por qué es explotable

[VECTORES DE ATAQUE]
Para cada vulnerabilidad CRITICA o ALTA:
OBJETIVO: dispositivo/protocolo específico
METODO: pasos concretos del ataque
HERRAMIENTA: nombre exacto de la herramienta recomendada

[COMANDOS SUGERIDOS]
# Descripción breve del comando
comando exacto con parámetros reales

[MITIGACIONES]
Una línea concisa de cómo mitigarlo"""

def mostrar_banner():
    print("=" * 55)
    print("        PHANTOM BRAIN v0.5")
    print("    Analizador offline de pentesting con IA")
    print("    WiFi + Sub-GHz + NFC + WPA2")
    print("=" * 55)
    print()

def elegir_modelo():
    modelos = ["phi3:mini", "mistral:7b-instruct"]
    print("Modelos disponibles:")
    for i, m in enumerate(modelos, 1):
        print(f"{i}. {m}")
    eleccion = input("\nElegi un modelo (1 o 2): ")
    if eleccion == "2":
        return "mistral:7b-instruct"
    return "phi3:mini"

def parsear_marauder(contenido):
    vulnerables = []
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

            except Exception:
                pass

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
    """Lista todos los archivos .sub disponibles"""
    capturas = []
    for file in os.listdir(directory):
        if file.endswith('.sub'):
            capturas.append(file)
    return sorted(capturas)

def parsear_subghz_archivo(filepath):
    """Parsea un archivo .sub específico"""
    from sub_ghz_parser import SubGhzParser
    
    parser = SubGhzParser(filepath)
    captura = parser.get_data()
    
    resumen = f"=== ANALISIS SUB-GHZ FLIPPER ===\n\n"
    resumen += f"[CAPTURA DETECTADA]\n"
    resumen += f"Archivo: {captura['filename']}\n"
    resumen += f"Protocolo: {captura['protocol']}\n"
    resumen += f"Frecuencia: {captura['frequency']} Hz\n"
    resumen += f"Preset: {captura['preset']}\n"
    resumen += f"Bits: {captura['bit']}\n"
    resumen += f"Key: {captura['key']}\n"
    resumen += f"Packet: {captura['secplus_packet_1']}\n\n"
    
    return resumen

def menu_subghz():
    """Menú para seleccionar qué captura Sub-GHz analizar"""
    capturas = listar_capturas_subghz(".")
    
    if not capturas:
        print("No se encontraron archivos .sub en la carpeta.")
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
            from sub_ghz_analyzer import SubGhzAnalyzer
            analyzer = SubGhzAnalyzer(".")
            return analyzer.generar_reporte_patrones()
        elif opcion == len(capturas) + 1:
            resumen = "=== ANALISIS SUB-GHZ FLIPPER - MULTIPLES CAPTURAS ===\n\n"
            for captura in capturas:
                resumen += parsear_subghz_archivo(captura)
            from sub_ghz_analyzer import SubGhzAnalyzer
            analyzer = SubGhzAnalyzer(".")
            resumen += analyzer.generar_reporte_patrones()
            return resumen
        elif 1 <= opcion <= len(capturas):
            archivo = capturas[opcion - 1]
            return parsear_subghz_archivo(archivo)
        else:
            print("Opcion invalida.")
            return None
    except ValueError:
        print("Ingresa un numero valido.")
        return None

def listar_capturas_nfc(directory):
    """Lista todos los archivos .nfc disponibles"""
    capturas = []
    for file in os.listdir(directory):
        if file.endswith('.nfc'):
            capturas.append(file)
    return sorted(capturas)

def parsear_nfc_archivo(filepath):
    """Parsea un archivo .nfc específico"""
    from nfc_parser import NFCParser
    
    parser = NFCParser(filepath)
    captura = parser.get_data()
    
    resumen = f"=== ANALISIS NFC FLIPPER ===\n\n"
    resumen += f"[CAPTURA DETECTADA]\n"
    resumen += f"Archivo: {captura['filename']}\n"
    resumen += f"Device Type: {captura['device_type']}\n"
    resumen += f"Card Type: {captura['card_type']}\n"
    resumen += f"UID: {captura['uid']}\n"
    resumen += f"Security Level: {captura['security_level']}\n"
    resumen += f"Memory Size: {captura['memory_size']}\n"
    resumen += f"ATQA: {captura['atqa']}\n"
    resumen += f"SAK: {captura['sak']}\n\n"
    
    return resumen

def menu_nfc():
    """Menú para seleccionar qué captura NFC analizar"""
    capturas = listar_capturas_nfc(".")
    
    if not capturas:
        print("No se encontraron archivos .nfc en la carpeta.")
        return None
    
    print("\n--- CAPTURAS NFC DISPONIBLES ---")
    for i, captura in enumerate(capturas, 1):
        print(f"{i}. {captura}")
    print(f"{len(capturas) + 1}. Analizar TODAS")
    print(f"{len(capturas) + 2}. Ver patrones y vulnerabilidades comunes")
    print("0. Cancelar")
    
    opcion = input("\nSelecciona una opcion: ")
    
    try:
        opcion = int(opcion)
        if opcion == 0:
            return None
        elif opcion == len(capturas) + 2:
            from nfc_analyzer import NFCAnalyzer
            analyzer = NFCAnalyzer(".")
            return analyzer.generar_reporte_patrones()
        elif opcion == len(capturas) + 1:
            resumen = "=== ANALISIS NFC FLIPPER - MULTIPLES CAPTURAS ===\n\n"
            for captura in capturas:
                resumen += parsear_nfc_archivo(captura)
            from nfc_analyzer import NFCAnalyzer
            analyzer = NFCAnalyzer(".")
            resumen += analyzer.generar_reporte_patrones()
            return resumen
        elif 1 <= opcion <= len(capturas):
            archivo = capturas[opcion - 1]
            return parsear_nfc_archivo(archivo)
        else:
            print("Opcion invalida.")
            return None
    except ValueError:
        print("Ingresa un numero valido.")
        return None

def listar_capturas_pcap(directory):
    """Lista todos los archivos .pcap disponibles"""
    from pcap_parser_v2 import analyze_pcap_files
    
    capturas_data = analyze_pcap_files(directory)
    archivos = [c['filename'] for c in capturas_data]
    return sorted(archivos), capturas_data

def parsear_pcap_archivo(filepath):
    """Parsea un archivo .pcap específico"""
    from pcap_parser_v2 import PCAPParserV2
    
    parser = PCAPParserV2(filepath)
    captura = parser.get_data()
    
    resumen = f"=== ANALISIS WPA2 HANDSHAKE ===\n\n"
    resumen += f"[CAPTURA DETECTADA]\n"
    resumen += f"Archivo: {captura['filename']}\n"
    resumen += f"Total paquetes: {captura['total_packets']}\n"
    resumen += f"BSSID: {captura['bssid']}\n"
    resumen += f"SSID: {captura['ssid']}\n"
    resumen += f"Frames EAPOL: {len(captura['eapol_frames'])}\n"
    resumen += f"¿Handshake completo?: {captura['handshake_complete']}\n\n"
    
    if captura.get('vulnerabilities'):
        resumen += "[VULNERABILIDADES DETECTADAS]\n"
        for vuln in captura['vulnerabilities']:
            resumen += f"- [{vuln['nivel']}] {vuln['nombre']}: {vuln['descripcion']}\n"
        resumen += "\n"
    
    return resumen

def menu_pcap():
    """Menú para seleccionar qué captura PCAP analizar"""
    archivos, capturas_data = listar_capturas_pcap(".")
    
    if not archivos:
        print("No se encontraron archivos .pcap válidos en la carpeta.")
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
                resumen += parsear_pcap_archivo(archivo)
            return resumen
        elif 1 <= opcion <= len(archivos):
            archivo = archivos[opcion - 1]
            return parsear_pcap_archivo(archivo)
        else:
            print("Opcion invalida.")
            return None
    except ValueError:
        print("Ingresa un numero valido.")
        return None

def obtener_input():
    print("\n1. Pegar texto manualmente")
    print("2. Leer archivo generico (scan.txt, nmap, etc)")
    print("3. Leer log de Flipper Zero / Marauder (.log)")
    print("4. Analizar capturas Sub-GHz (.sub)")
    print("5. Analizar capturas NFC (.nfc)")
    print("6. Analizar capturas WPA2 Handshakes (.pcap)")
    opcion = input("\nElegi una opcion (1, 2, 3, 4, 5 o 6): ")

    if opcion == "1":
        return input("\nPega el output aqui:\n> "), False

    elif opcion == "2":
        archivo = input("\nNombre del archivo (ej: scan1.txt): ")
        if not os.path.exists(archivo):
            print(f"Archivo '{archivo}' no encontrado.")
            exit()
        with open(archivo, "r") as f:
            contenido = f.read()
        print(f"Archivo '{archivo}' cargado correctamente.")
        return contenido, False

    elif opcion == "3":
        archivo = input("\nNombre del archivo .log (ej: scanap_0.log): ")
        if not os.path.exists(archivo):
            print(f"Archivo '{archivo}' no encontrado.")
            exit()
        with open(archivo, "r") as f:
            contenido = f.read()
        print(f"Log '{archivo}' cargado. Procesando...")
        filtrado = parsear_marauder(contenido)
        print("\n--- PREVIEW DEL FILTRADO ---")
        print(filtrado)
        print("----------------------------\n")
        return filtrado, True

    elif opcion == "4":
        print("Cargando capturas Sub-GHz disponibles...")
        contenido = menu_subghz()
        if contenido is None:
            print("Operacion cancelada.")
            exit()
        print("\n" + contenido)
        return contenido, False

    elif opcion == "5":
        print("Cargando capturas NFC disponibles...")
        contenido = menu_nfc()
        if contenido is None:
            print("Operacion cancelada.")
            exit()
        print("\n" + contenido)
        return contenido, False

    elif opcion == "6":
        print("Cargando capturas WPA2 disponibles...")
        contenido = menu_pcap()
        if contenido is None:
            print("Operacion cancelada.")
            exit()
        print("\n" + contenido)
        return contenido, False

    else:
        print("Opcion invalida.")
        exit()

def guardar_reporte(scan_input, resultado):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre = f"reporte_{timestamp}.txt"
    with open(nombre, "w", encoding="utf-8") as f:
        f.write("PHANTOM BRAIN - Reporte de Analisis\n")
        f.write(f"Fecha: {timestamp}\n")
        f.write("=" * 55 + "\n\n")
        f.write("INPUT ANALIZADO:\n")
        f.write(scan_input + "\n\n")
        f.write("ANALISIS:\n")
        f.write(resultado)
    return nombre

def analizar(scan_input, modelo):
    print(f"\nAnalizando con {modelo}...\n")
    response = ollama.chat(
        model=modelo,
        options={"num_predict": 1500},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": scan_input}
        ]
    )
    return response['message']['content']

# MAIN
mostrar_banner()
modelo = elegir_modelo()
scan_input, es_marauder = obtener_input()
resultado = analizar(scan_input, modelo)

print(resultado)

nombre_reporte = guardar_reporte(scan_input, resultado)
print("\n" + "=" * 55)
print(f"Reporte guardado como: {nombre_reporte}")
print("=" * 55)