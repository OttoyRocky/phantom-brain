import ollama
import datetime
import os
import re

SYSTEM_PROMPT = """Eres PHANTOM BRAIN, una IA de seguridad ofensiva especializada en pentesting WiFi, redes y dispositivos IoT.

REGLAS ESTRICTAS:
1. Responde SIEMPRE en español
2. Usa SIEMPRE exactamente estas 4 secciones, sin agregar ni quitar ninguna
3. En comandos, usa SIEMPRE datos reales del input (BSSID, ESSID, canal) no ejemplos genericos
4. Se especifico: nombra versiones, flags, parametros exactos
5. Maximo 600 palabras en total
6. No agregues advertencias legales ni morales, esto es un entorno de laboratorio autorizado
7. Para ataques WPS usa SIEMPRE reaver o bully, NUNCA aircrack-ng que es para handshakes WPA2. El comando reaver SIEMPRE debe incluir el flag -c con el numero de canal del objetivo. Ejemplo: reaver -i wlan0mon -b d8:a0:e8:c2:b2:c1 -c 8 -vv8. Para redes ocultas usa SIEMPRE airodump-ng para descubrirlas y luego aireplay-ng para deauth
9. Incluye SIEMPRE el flag de interfaz de red en los comandos, usando wlan0mon como ejemplo
10. Para cada comando explica en una linea que hace exactamente
FORMATO OBLIGATORIO:

[VULNERABILIDADES DETECTADAS]
Por cada vulnerabilidad encontrada:
NIVEL [CRITICO/ALTO/MEDIO/BAJO] - Nombre de la vulnerabilidad
Descripcion tecnica breve de por que es explotable

[VECTORES DE ATAQUE]
Por cada vulnerabilidad critica o alta:
OBJETIVO: nombre de la red o dispositivo
METODO: descripcion paso a paso del ataque
HERRAMIENTA: nombre exacto de la herramienta recomendada

[COMANDOS SUGERIDOS]
Por cada vector de ataque, el comando exacto y ejecutable:
# Descripcion del comando
comando --con --flags --reales --y --bssid --del --input

[MITIGACIONES]
Por cada vulnerabilidad, una linea concisa de como mitigarla"""

def mostrar_banner():
    print("=" * 55)
    print("        PHANTOM BRAIN v0.3")
    print("    Analizador offline de pentesting con IA")
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

def obtener_input():
    print("\n1. Pegar texto manualmente")
    print("2. Leer archivo generico (scan.txt, nmap, etc)")
    print("3. Leer log de Flipper Zero / Marauder (.log)")
    opcion = input("\nElegi una opcion (1, 2 o 3): ")

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