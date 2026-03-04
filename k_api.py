[1mdiff --git a/cardputer_dashboard.py b/cardputer_dashboard.py[m
[1mindex 60a50bc..022eca2 100644[m
[1m--- a/cardputer_dashboard.py[m
[1m+++ b/cardputer_dashboard.py[m
[36m@@ -1,14 +1,13 @@[m
 import os[m
 import json[m
 from datetime import datetime[m
[31m-import serial[m
 import time[m
 [m
 class CardputerDashboard:[m
[31m-    def __init__(self, port='COM5', baudrate=115200):[m
[32m+[m[32m    def __init__(self, port='COM5', baudrate=115200, reports_dir=None):[m
         self.port = port[m
         self.baudrate = baudrate[m
[31m-        self.reports_dir = "."[m
[32m+[m[32m        self.reports_dir = reports_dir or "."[m
         [m
     def get_latest_report(self):[m
         """Obtiene el último reporte generado"""[m
[36m@@ -18,12 +17,13 @@[m [mclass CardputerDashboard:[m
             return None[m
         [m
         reports.sort(reverse=True)[m
[31m-        latest = reports[0][m
[31m-        [m
[31m-        with open(latest, 'r', encoding='utf-8') as f:[m
[32m+[m[32m        latest_name = reports[0][m
[32m+[m[32m        latest_path = os.path.join(self.reports_dir, latest_name)[m
[32m+[m
[32m+[m[32m        with open(latest_path, 'r', encoding='utf-8') as f:[m
             content = f.read()[m
[31m-        [m
[31m-        return {'filename': latest, 'content': content}[m
[32m+[m
[32m+[m[32m        return {'filename': latest_name, 'content': content}[m
     [m
     def parse_report(self, report_content):[m
         """Parsea el reporte para extraer datos clave"""[m
[36m@@ -117,13 +117,11 @@[m [mclass CardputerDashboard:[m
         print(content[:1000])  # Primeros 1000 caracteres[m
         print("\n... (ver archivo completo para más detalles)")[m
         input("\nPresiona Enter para volver...")[m
[31m-        self.display_dashboard()[m
     [m
     def _export_report(self, filename):[m
         """Exporta reporte"""[m
         print(f"\n✓ Reporte {filename} exportado")[m
         input("Presiona Enter para volver...")[m
[31m-        self.display_dashboard()[m
 [m
 if __name__ == "__main__":[m
     dashboard = CardputerDashboard()[m
