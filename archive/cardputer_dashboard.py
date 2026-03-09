import os
import json
from datetime import datetime
import time

class CardputerDashboard:
    def __init__(self, port='COM5', baudrate=115200, reports_dir=None):
        self.port = port
        self.baudrate = baudrate
        self.reports_dir = reports_dir or "."
        
    def get_latest_report(self):
        """Obtiene el último reporte generado"""
        reports = [f for f in os.listdir(self.reports_dir) 
                  if f.startswith('reporte_') and f.endswith('.txt')]
        if not reports:
            return None
        
        reports.sort(reverse=True)
        latest_name = reports[0]
        latest_path = os.path.join(self.reports_dir, latest_name)

        with open(latest_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return {'filename': latest_name, 'content': content}
    
    def parse_report(self, report_content):
        """Parsea el reporte para extraer datos clave"""
        data = {
            'vulnerabilities': [],
            'vectors': [],
            'commands': [],
            'mitigations': []
        }
        
        sections = report_content.split('[')
        
        for section in sections:
            if 'VULNERABILIDADES' in section:
                lines = section.split('\n')[1:]
                for line in lines:
                    if 'NIVEL' in line or 'CRITICO' in line or 'ALTO' in line:
                        data['vulnerabilities'].append(line.strip())
            
            elif 'VECTORES DE ATAQUE' in section:
                lines = section.split('\n')[1:]
                for line in lines:
                    if line.strip():
                        data['vectors'].append(line.strip())
            
            elif 'COMANDOS' in section:
                lines = section.split('\n')[1:]
                for line in lines:
                    if line.strip() and not line.startswith('#'):
                        data['commands'].append(line.strip())
        
        return data
    
    def display_dashboard(self):
        """Muestra dashboard en consola (simulación de Cardputer)"""
        report = self.get_latest_report()
        
        if not report:
            print("\n╔════════════════════════════╗")
            print("║   PHANTOM BRAIN DASHBOARD   ║")
            print("║                            ║")
            print("║  No reports found yet      ║")
            print("║  Run phantom_brain.py      ║")
            print("╚════════════════════════════╝\n")
            return
        
        data = self.parse_report(report['content'])
        
        # PANTALLA 1: ESTADO GENERAL
        print("\n" + "="*50)
        print("    PHANTOM BRAIN - ESTADO GENERAL")
        print("="*50)
        print(f"Reporte: {report['filename']}")
        print(f"Vulnerabilidades detectadas: {len(data['vulnerabilities'])}")
        print(f"Vectores de ataque: {len(data['vectors'])}")
        print(f"Comandos sugeridos: {len(data['commands'])}")
        print("="*50)
        
        # PANTALLA 2: VULNERABILIDADES
        if data['vulnerabilities']:
            print("\n[VULNERABILIDADES DETECTADAS]")
            for i, vuln in enumerate(data['vulnerabilities'][:3], 1):
                print(f"{i}. {vuln[:60]}")
        
        # PANTALLA 3: COMANDOS
        if data['commands']:
            print("\n[COMANDOS SUGERIDOS]")
            for i, cmd in enumerate(data['commands'][:2], 1):
                print(f"{i}. {cmd[:60]}")
        
        print("\n[NAVEGACIÓN]")
        print("1. Ver detalles")
        print("2. Exportar reporte")
        print("3. Actualizar")
        print("0. Salir")
        
        choice = input("\nSelecciona opción: ")
        
        if choice == "1":
            self._show_details(report['content'])
        elif choice == "2":
            self._export_report(report['filename'])
        elif choice == "3":
            self.display_dashboard()
    
    def _show_details(self, content):
        """Muestra detalles completos del reporte"""
        print("\n" + "="*50)
        print("DETALLES COMPLETOS")
        print("="*50)
        print(content[:1000])  # Primeros 1000 caracteres
        print("\n... (ver archivo completo para más detalles)")
        input("\nPresiona Enter para volver...")
    
    def _export_report(self, filename):
        """Exporta reporte"""
        print(f"\n✓ Reporte {filename} exportado")
        input("Presiona Enter para volver...")

if __name__ == "__main__":
    dashboard = CardputerDashboard()
    
    while True:
        dashboard.display_dashboard()
        time.sleep(1)