"""
PHANTOM BRAIN - Configuracion centralizada
Carga config.yaml, logging y base de datos.
"""

import logging
import os

try:
    import yaml
    YAML_DISPONIBLE = True
except ImportError:
    YAML_DISPONIBLE = False

CONFIG_DEFAULT = {
    "proyecto": {"nombre": "PHANTOM BRAIN", "version": "0.6"},
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


CONFIG = cargar_config()
logger = configurar_logging(CONFIG)

CARPETA_REPORTES = CONFIG.get("rutas", {}).get("reportes", "reportes")
try:
    os.makedirs(CARPETA_REPORTES, exist_ok=True)
    logger.debug(f"Carpeta de reportes: {CARPETA_REPORTES}")
except Exception as e:
    logger.warning(f"No se pudo crear carpeta de reportes '{CARPETA_REPORTES}': {e}")
    CARPETA_REPORTES = "."

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
