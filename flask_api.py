"""
PHANTOM BRAIN - API REST con Flask
Integra analizador, db_manager y config para exposicion via HTTP.
Ollama local, sin APIs externas.
"""

import os
from datetime import datetime

from flask import Flask, request, jsonify

# Importar desde phantom_brain (no ejecuta main gracias a if __name__)
import phantom_brain as pb

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload

EXTENSIONES_PERMITIDAS = {".pcap", ".nfc", ".sub"}


def _respuesta_base(success, analysis_id=None, type_=None, results=None, errors=None):
    """Formato estandar: success, analysis_id, timestamp, type, results, errors."""
    return jsonify({
        "success": success,
        "analysis_id": analysis_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": type_,
        "results": results,
        "errors": errors or [],
    })


@app.route("/status", methods=["GET"])
def status():
    """Verifica Ollama y devuelve modelos disponibles."""
    try:
        import ollama
        resp = ollama.list()
        models_list = getattr(resp, "models", [])
        model_names = [getattr(m, "model", getattr(m, "name", str(m))) for m in models_list]
        return _respuesta_base(
            success=True,
            results={
                "ollama_running": True,
                "models": model_names,
                "default_model": pb.CONFIG.get("modelo_por_defecto", "mistral:7b-instruct"),
            },
        )
    except Exception as e:
        pb.logger.error(f"Error al verificar Ollama: {e}")
        return _respuesta_base(
            success=False,
            results={"ollama_running": False, "models": []},
            errors=[str(e)],
        ), 503


@app.route("/upload", methods=["POST"])
def upload():
    """Recibe archivo .pcap, .nfc o .sub y lo guarda en carpeta de capturas."""
    if "file" not in request.files:
        return _respuesta_base(success=False, errors=["No se envio el campo 'file'"]), 400

    file = request.files["file"]
    if file.filename == "":
        return _respuesta_base(success=False, errors=["Nombre de archivo vacio"]), 400

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in EXTENSIONES_PERMITIDAS:
        return _respuesta_base(
            success=False,
            errors=[f"Extension no permitida. Permitidas: {', '.join(EXTENSIONES_PERMITIDAS)}"],
        ), 400

    carpeta = pb.CONFIG.get("rutas", {}).get("capturas", ".")
    try:
        os.makedirs(carpeta, exist_ok=True)
        filepath = os.path.join(carpeta, file.filename)
        file.save(filepath)
        return _respuesta_base(
            success=True,
            type_=ext[1:],
            results={
                "filename": file.filename,
                "saved_path": filepath,
                "size_bytes": os.path.getsize(filepath),
            },
        )
    except Exception as e:
        pb.logger.error(f"Error al guardar archivo: {e}")
        return _respuesta_base(success=False, errors=[str(e)]), 500


def _obtener_contenido_para_analizar(tipo, datos):
    """Prepara el texto de entrada para el analizador segun tipo."""
    carpeta = pb.CONFIG.get("rutas", {}).get("capturas", ".")
    tipo_lower = tipo.lower()

    if tipo_lower == "proxmark":
        content = datos.get("content") or datos.get("data")
        if not content:
            raise ValueError("Para tipo 'proxmark' se requiere 'content' o 'data' con el output en texto")
        from proxmark_parser import parse_proxmark_output
        parser = parse_proxmark_output(content)
        return parser.get_summary(), parser.get_data()

    file_path = datos.get("file_path") or datos.get("file")
    if not file_path:
        raise ValueError(f"Para tipo '{tipo}' se requiere 'file_path' o 'file' con la ruta al archivo")

    full_path = os.path.join(carpeta, os.path.basename(file_path))
    if not os.path.exists(full_path):
        full_path = file_path
    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

    if tipo_lower == "pcap":
        resumen = pb.parsear_pcap_archivo(full_path)
        return resumen, None
    elif tipo_lower == "nfc":
        resumen = pb.parsear_nfc_archivo(full_path)
        return resumen, None
    elif tipo_lower == "subghz":
        resumen = pb.parsear_subghz_archivo(full_path)
        return resumen, None
    else:
        raise ValueError(f"Tipo no soportado: {tipo}. Usar: pcap, nfc, subghz, proxmark")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Recibe JSON: tipo (pcap/nfc/subghz/proxmark), datos (file_path o content). Opcional: modelo."""
    try:
        body = request.get_json() or {}
        tipo = body.get("tipo") or body.get("type")
        datos = body.get("datos") or body.get("data") or {}
        modelo = body.get("modelo") or body.get("model") or pb.CONFIG.get("modelo_por_defecto", "mistral:7b-instruct")

        if not tipo:
            return _respuesta_base(
                success=False,
                errors=["Se requiere 'tipo' (pcap, nfc, subghz, proxmark)"],
            ), 400

        scan_input, datos_extra = _obtener_contenido_para_analizar(tipo, datos)
        if not scan_input:
            return _respuesta_base(
                success=False,
                type_=tipo,
                errors=["No se pudo parsear el archivo o contenido"],
            ), 400

        resultado = pb.analizar(scan_input, modelo)

        uid_bssid = None
        if datos_extra and isinstance(datos_extra, dict):
            uid_bssid = datos_extra.get("uid") or datos_extra.get("raw_id")
        uid_bssid = uid_bssid or "N/A"

        nivel_riesgo = pb.extraer_nivel_riesgo(resultado)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        archivo_txt = os.path.join(pb.CARPETA_REPORTES, f"reporte_{timestamp_str}.txt")

        try:
            os.makedirs(pb.CARPETA_REPORTES, exist_ok=True)
            with open(archivo_txt, "w", encoding="utf-8") as f:
                f.write("PHANTOM BRAIN - Reporte de Analisis\n")
                f.write(f"Version: {pb.CONFIG.get('proyecto', {}).get('version', '0.6')}\n")
                f.write(f"Fecha: {timestamp_str}\n")
                f.write(f"Tipo: {tipo}\n")
                f.write(f"Modelo IA: {modelo}\n")
                f.write("=" * 55 + "\n\n")
                f.write("INPUT ANALIZADO:\n")
                f.write(scan_input + "\n\n")
                f.write("ANALISIS:\n")
                f.write(resultado)
        except Exception as e:
            pb.logger.error(f"Error al guardar archivo de reporte: {e}")
            archivo_txt = f"reporte_{timestamp_str}.txt"

        analysis_id = None
        if pb.DB is not None:
            analysis_id = pb.DB.guardar_reporte(
                tipo=tipo,
                uid_bssid=uid_bssid,
                nivel_riesgo=nivel_riesgo,
                modelo_ia=modelo,
                archivo_txt=archivo_txt,
                resumen=resultado,
            )

        return _respuesta_base(
            success=True,
            analysis_id=analysis_id,
            type_=tipo,
            results={"analysis": resultado, "report_file": archivo_txt},
        )

    except ValueError as e:
        return _respuesta_base(success=False, errors=[str(e)]), 400
    except FileNotFoundError as e:
        return _respuesta_base(success=False, errors=[str(e)]), 404
    except RuntimeError as e:
        return _respuesta_base(success=False, errors=[str(e)]), 503
    except Exception as e:
        pb.logger.exception(f"Error en /analyze: {e}")
        return _respuesta_base(success=False, errors=[str(e)]), 500


def _leer_analisis_completo(archivo_txt):
    """Extrae la seccion ANALISIS del archivo de reporte."""
    if not archivo_txt or not os.path.exists(archivo_txt):
        return None
    try:
        with open(archivo_txt, "r", encoding="utf-8") as f:
            content = f.read()
        if "ANALISIS:\n" in content:
            return content.split("ANALISIS:\n", 1)[1].strip()
        return content
    except Exception:
        return None


@app.route("/analysis/<int:analysis_id>", methods=["GET"])
def get_analysis(analysis_id):
    """Consulta un analisis guardado en SQLite por ID."""
    if pb.DB is None:
        return _respuesta_base(success=False, errors=["Base de datos no disponible"]), 503

    reporte = pb.DB.obtener_por_id(analysis_id)
    if not reporte:
        return _respuesta_base(
            success=False,
            analysis_id=analysis_id,
            errors=[f"Analisis con ID {analysis_id} no encontrado"],
        ), 404

    archivo = reporte.get("archivo_txt")
    analysis_full = _leer_analisis_completo(archivo)
    if analysis_full is None:
        analysis_full = reporte.get("resumen") or ""

    return _respuesta_base(
        success=True,
        analysis_id=reporte["id"],
        type_=reporte["tipo"],
        results={
            "id": reporte["id"],
            "timestamp": reporte["timestamp"],
            "tipo": reporte["tipo"],
            "uid_bssid": reporte["uid_bssid"],
            "nivel_riesgo": reporte["nivel_riesgo"],
            "modelo_ia": reporte["modelo_ia"],
            "archivo_txt": reporte["archivo_txt"],
            "analysis": analysis_full,
        },
    )


if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
