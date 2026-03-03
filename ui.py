"""
PHANTOM BRAIN - Interfaz de usuario y menus
"""

import os
import sys

from config import CONFIG, CONFIG_DEFAULT, DB, logger
from parsers import (
    listar_capturas_pcap,
    listar_capturas_subghz,
    parsear_marauder,
    parsear_nfc_archivo,
    parsear_pcap_archivo,
    parsear_subghz_archivo,
)


def mostrar_banner():
    ver = CONFIG.get("proyecto", {}).get("version", "0.6")
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


def menu_pcap():
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
                filepath = os.path.join(directorio, archivo)
                resultado = parsear_pcap_archivo(filepath)
                if resultado:
                    resumen += resultado
            return resumen
        elif 1 <= opcion <= len(archivos):
            filepath = os.path.join(directorio, archivos[opcion - 1])
            return parsear_pcap_archivo(filepath)
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
    """Muestra filas de reportes en formato tabular."""
    print(f"\n{'ID':>4} | {'Fecha':^19} | {'Tipo':^12} | {'UID/BSSID':^20} | {'Riesgo':^8} | Archivo")
    print("-" * 90)
    for row in rows:
        id_, ts, tipo_, uid, riesgo, archivo = row
        uid = (uid or "N/A")[:20]
        riesgo = (riesgo or "?")[:8]
        archivo = os.path.basename(archivo or "")
        print(f"{id_:>4} | {ts:^19} | {tipo_:^12} | {uid:^20} | {riesgo:^8} | {archivo}")
    print()


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
            _mostrar_filas_reportes(rows)
        else:
            print("No se encontraron resultados.")
    elif opcion == "3":
        rows = DB.reportes_criticos()
        if not rows:
            print("No hay reportes criticos guardados.")
        else:
            print(f"\n{'ID':>4} | {'Fecha':^19} | {'Tipo':^12} | {'UID/BSSID':^20} | Archivo")
            print("-" * 75)
            for row in rows:
                id_, ts, tipo_, uid, riesgo, archivo = row
                print(f"{id_:>4} | {ts:^19} | {tipo_:^12} | {(uid or 'N/A'):^20} | {os.path.basename(archivo or '')}")
    elif opcion == "4":
        DB.estadisticas()


def obtener_input():
    print("\n0. Salir")
    print("1. Pegar texto manualmente")
    print("2. Leer archivo generico (scan.txt, nmap, etc)")
    print("3. Leer log de Flipper Zero / Marauder (.log)")
    print("4. Analizar capturas Sub-GHz (.sub)")
    print("5. Analizar capturas NFC (.nfc)")
    print("6. Analizar capturas WPA2 Handshakes (.pcap)")
    print("7. Analizar captura Proxmark3 (pegar output directo)")
    print("8. Ver historial de reportes")
    opcion = input("\nElegi una opcion (0-8): ").strip()

    if opcion == "0":
        print("Hasta luego.")
        sys.exit(0)

    if opcion == "1":
        return input("\nPega el output aqui:\n> "), False, "Manual", None

    elif opcion == "2":
        archivo = input("\nNombre del archivo (ej: scan1.txt): ").strip()
        if not os.path.exists(archivo):
            print(f"[ERROR] Archivo '{archivo}' no encontrado. Volviendo al menu.")
            return None, False, "CANCELAR", None
        try:
            with open(archivo, "r", encoding="utf-8") as f:
                contenido = f.read()
            print(f"Archivo '{archivo}' cargado correctamente.")
            return contenido, False, "Generico", None
        except Exception as e:
            print(f"[ERROR] No se pudo leer el archivo: {e}. Volviendo al menu.")
            return None, False, "CANCELAR", None

    elif opcion == "3":
        archivo = input("\nNombre del archivo .log (ej: scanap_0.log): ").strip()
        if not os.path.exists(archivo):
            print(f"[ERROR] Archivo '{archivo}' no encontrado. Volviendo al menu.")
            return None, False, "CANCELAR", None
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
            print(f"[ERROR] No se pudo leer el archivo de log: {e}. Volviendo al menu.")
            return None, False, "CANCELAR", None

    elif opcion == "4":
        print("Cargando capturas Sub-GHz disponibles...")
        contenido = menu_subghz()
        if contenido is None:
            print("Operacion cancelada. Volviendo al menu.")
            return None, False, "CANCELAR", None
        print("\n" + contenido)
        return contenido, False, "Sub-GHz", None

    elif opcion == "5":
        print("Cargando capturas NFC disponibles...")
        contenido = menu_nfc()
        if contenido is None:
            print("Operacion cancelada. Volviendo al menu.")
            return None, False, "CANCELAR", None
        print("\n" + contenido)
        return contenido, False, "NFC", None

    elif opcion == "6":
        print("Cargando capturas WPA2 disponibles...")
        contenido = menu_pcap()
        if contenido is None:
            print("Operacion cancelada. Volviendo al menu.")
            return None, False, "CANCELAR", None
        print("\n" + contenido)
        return contenido, False, "WPA2", None

    elif opcion == "7":
        contenido, datos_pm3 = menu_proxmark()
        if contenido is None:
            print("Operacion cancelada. Volviendo al menu.")
            return None, False, "CANCELAR", None
        return contenido, False, "Proxmark3", datos_pm3

    elif opcion == "8":
        menu_historial()
        return None, False, "HISTORIAL", None

    else:
        print("Opcion invalida. Volviendo al menu.")
        return None, False, "CANCELAR", None
