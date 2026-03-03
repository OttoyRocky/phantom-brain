"""
PHANTOM BRAIN v0.6
Analizador offline de pentesting con IA
WiFi + Sub-GHz + NFC + WPA2 + Proxmark3

Modulos:
- config: configuracion, logging, base de datos
- parsers: Marauder, Sub-GHz, NFC, PCAP
- ui: menus e interfaz
- analizador: IA con Ollama
"""

import datetime
import os

from analizador import analizar
from config import CARPETA_REPORTES, CONFIG, DB, logger
from ui import elegir_modelo, obtener_input, mostrar_banner


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
            f.write(f"Version: {CONFIG.get('proyecto', {}).get('version', '0.6')}\n")
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


def _ejecutar_analisis(modelo):
    """Obtiene input, analiza y guarda. Retorna False para salir."""
    while True:
        scan_input, es_marauder, tipo_captura, datos_extra = obtener_input()
        if tipo_captura in ("HISTORIAL", "CANCELAR"):
            continue
        if scan_input is None:
            continue
        break

    resultado = analizar(scan_input, modelo)
    print(resultado)

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


def main():
    mostrar_banner()
    modelo = elegir_modelo()
    _ejecutar_analisis(modelo)
    while True:
        otra = input("\n¿Analizar otra captura? (s/n): ").strip().lower()
        if otra in ("n", "no"):
            print("Hasta luego.")
            break
        if otra in ("s", "si"):
            _ejecutar_analisis(modelo)


if __name__ == "__main__":
    main()
