"""
PHANTOM BRAIN - Gestor de base de datos SQLite
Guarda historial de capturas y reportes para consulta rapida
"""

import sqlite3
import os
import logging
from datetime import datetime

logger = logging.getLogger("phantom_brain.db")


class DBManager:
    def __init__(self, db_path="phantom_brain.db"):
        self.db_path = db_path
        self._inicializar()

    def _inicializar(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS reportes (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL,
                    tipo        TEXT NOT NULL,
                    uid_bssid   TEXT,
                    nivel_riesgo TEXT,
                    modelo_ia   TEXT,
                    archivo_txt TEXT,
                    resumen     TEXT
                )
            """)
            conn.commit()
            conn.close()
            logger.debug(f"Base de datos inicializada: {self.db_path}")
        except Exception as e:
            logger.error(f"Error al inicializar base de datos: {e}")

    def guardar_reporte(self, tipo, uid_bssid, nivel_riesgo, modelo_ia, archivo_txt, resumen):
        """Guarda reporte y retorna el ID insertado, o None en caso de error."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                INSERT INTO reportes (timestamp, tipo, uid_bssid, nivel_riesgo, modelo_ia, archivo_txt, resumen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, tipo, uid_bssid, nivel_riesgo, modelo_ia, archivo_txt, resumen[:500]))
            row_id = c.lastrowid
            conn.commit()
            conn.close()
            logger.info(f"Reporte guardado en DB: id={row_id}, tipo={tipo}, uid/bssid={uid_bssid}")
            return row_id
        except Exception as e:
            logger.error(f"Error al guardar reporte en DB: {e}")
            return None

    def obtener_por_id(self, report_id):
        """Obtiene un reporte por su ID. Retorna dict con todos los campos o None."""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                SELECT id, timestamp, tipo, uid_bssid, nivel_riesgo, modelo_ia, archivo_txt, resumen
                FROM reportes WHERE id = ?
            """, (report_id,))
            row = c.fetchone()
            conn.close()
            if row:
                return {
                    "id": row[0], "timestamp": row[1], "tipo": row[2], "uid_bssid": row[3],
                    "nivel_riesgo": row[4], "modelo_ia": row[5], "archivo_txt": row[6], "resumen": row[7],
                }
            return None
        except Exception as e:
            logger.error(f"Error al obtener reporte por ID: {e}")
            return None

    def listar_reportes(self, tipo=None, limite=20):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            if tipo:
                c.execute("""
                    SELECT id, timestamp, tipo, uid_bssid, nivel_riesgo, archivo_txt
                    FROM reportes WHERE tipo = ? ORDER BY timestamp DESC LIMIT ?
                """, (tipo, limite))
            else:
                c.execute("""
                    SELECT id, timestamp, tipo, uid_bssid, nivel_riesgo, archivo_txt
                    FROM reportes ORDER BY timestamp DESC LIMIT ?
                """, (limite,))
            rows = c.fetchall()
            conn.close()
            return rows
        except Exception as e:
            logger.error(f"Error al listar reportes: {e}")
            return []

    def buscar_por_uid(self, uid):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                SELECT id, timestamp, tipo, uid_bssid, nivel_riesgo, archivo_txt
                FROM reportes WHERE uid_bssid LIKE ? ORDER BY timestamp DESC
            """, (f"%{uid}%",))
            rows = c.fetchall()
            conn.close()
            return rows
        except Exception as e:
            logger.error(f"Error al buscar por UID: {e}")
            return []

    def reportes_criticos(self, limite=10):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                SELECT id, timestamp, tipo, uid_bssid, nivel_riesgo, archivo_txt
                FROM reportes WHERE nivel_riesgo = 'CRITICO'
                ORDER BY timestamp DESC LIMIT ?
            """, (limite,))
            rows = c.fetchall()
            conn.close()
            return rows
        except Exception as e:
            logger.error(f"Error al buscar criticos: {e}")
            return []

    def mostrar_historial(self, tipo=None, limite=20):
        rows = self.listar_reportes(tipo=tipo, limite=limite)
        if not rows:
            print("No hay reportes guardados aun.")
            return
        print(f"\n{'ID':>4} | {'Fecha':^19} | {'Tipo':^12} | {'UID/BSSID':^20} | {'Riesgo':^8} | Archivo")
        print("-" * 90)
        for row in rows:
            id_, ts, tipo_, uid, riesgo, archivo = row
            uid = (uid or "N/A")[:20]
            riesgo = (riesgo or "?")[:8]
            archivo = os.path.basename(archivo or "")
            print(f"{id_:>4} | {ts:^19} | {tipo_:^12} | {uid:^20} | {riesgo:^8} | {archivo}")
        print()

    def estadisticas(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM reportes")
            total = c.fetchone()[0]
            c.execute("SELECT tipo, COUNT(*) FROM reportes GROUP BY tipo")
            por_tipo = c.fetchall()
            c.execute("SELECT nivel_riesgo, COUNT(*) FROM reportes GROUP BY nivel_riesgo")
            por_riesgo = c.fetchall()
            conn.close()
            print(f"\n=== ESTADISTICAS PHANTOM BRAIN ===")
            print(f"Total capturas analizadas: {total}")
            print("\nPor tipo:")
            for tipo, cnt in por_tipo:
                print(f"  {tipo:15}: {cnt}")
            print("\nPor nivel de riesgo:")
            for riesgo, cnt in (por_riesgo or []):
                print(f"  {(riesgo or 'Sin clasificar'):15}: {cnt}")
            print()
        except Exception as e:
            logger.error(f"Error en estadisticas: {e}")
