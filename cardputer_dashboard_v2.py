import os
import json
from datetime import datetime

class CardputerDashboardV2:
    def __init__(self):
        self.reports_dir = "."
        self.current_screen = 0
        
    def get_latest_report(self):
        """Obtiene el último reporte generado"""
        reports = [f for f in os.listdir(self.reports_dir) 
                  if f.startswith('reporte_') and f.endswith('.txt')]
        if not reports:
            return None
        reports.sort(reverse=True)
        return reports[0]
    
    def parse_report_detailed(self, filename):
        """Parsea reporte de forma más robusta"""
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        data = {
            'file': filename,
            'timestamp': filename.replace('reporte_', '').replace('.txt', ''),
            'type': self._detect_type(content),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'summary': []
        }
        
        # Contar vulnerabilidades por nivel
        if '[CRITICO]' in content:
            data['critical'] = content.count('[CRITICO]')
        if '[ALTO]' in content:
            data['high'] = content.count('[ALTO]')
        if '[MEDIO]' in content:
            data['medium'] = content.count('[MEDIO]')
        if '[BAJO]' in content:
            data['low'] = content.count('[BAJO]')
        
        # Extraer línea de resumen
        if 'Archivo:' in content:
            lines = content.split('\n')
            for line in lines:
                if 'Archivo:' in line or 'BSSID:' in line or 'UID:' in line:
                    data['summary'].append(line.strip())
        
        return data
    
    def _detect_type(self, content):
        """Detecta tipo de análisis"""
        if 'WPA2' in content:
            return '📡 WPA2 Handshake'
        elif 'Sub-GHz' in content:
            return '🌊 Sub-GHz'
        elif 'NFC' in content:
            return '🏷️ NFC/RFID'
        elif 'Marauder' in content:
            return '📊 WiFi Scan'
        return '❓ Unknown'
    
    def screen_1_overview(self):
        """PANTALLA 1: RESUMEN GENERAL"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("╔════════════════════════════════╗")
        print("║  PHANTOM BRAIN v0.5 - OVERVIEW ║")
        print("╚════════════════════════════════╝\n")
        
        report_file = self.get_latest_report()
        if not report_file:
            print("❌ No reports found\n")
            print("Genera un reporte ejecutando:")
            print("  python phantom_brain.py\n")
            self._show_menu()
            return
        
        data = self.parse_report_detailed(report_file)
        
        print(f"Reporte actual: {data['type']}")
        print(f"Timestamp: {data['timestamp']}\n")
        
        print("VULNERABILIDADES:")
        print(f"  🔴 CRITICO:  {data['critical']}")
        print(f"  🟠 ALTO:     {data['high']}")
        print(f"  🟡 MEDIO:    {data['medium']}")
        print(f"  🟢 BAJO:     {data['low']}\n")
        
        print(f"TOTAL: {data['critical'] + data['high'] + data['medium'] + data['low']} vulnerabilidades\n")
        
        self._show_menu()
    
    def screen_2_details(self):
        """PANTALLA 2: DETALLES DEL REPORTE"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("╔════════════════════════════════╗")
        print("║     DETALLES DEL REPORTE      ║")
        print("╚════════════════════════════════╝\n")
        
        report_file = self.get_latest_report()
        if not report_file:
            print("❌ No reports\n")
            self._show_menu()
            return
        
        with open(report_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Mostrar primeras líneas importantes
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if i > 30:  # Mostrar solo 30 líneas en pantalla pequeña
                print("... (ver archivo completo)\n")
                break
            if line.strip():
                print(line[:60])
        
        self._show_menu()
    
    def screen_3_commands(self):
        """PANTALLA 3: COMANDOS SUGERIDOS"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("╔════════════════════════════════╗")
        print("║   COMANDOS SUGERIDOS          ║")
        print("╚════════════════════════════════╝\n")
        
        report_file = self.get_latest_report()
        if not report_file:
            print("❌ No reports\n")
            self._show_menu()
            return
        
        with open(report_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        in_commands = False
        cmd_count = 0
        
        for line in content.split('\n'):
            if '[COMANDOS SUGERIDOS]' in line:
                in_commands = True
                continue
            
            if in_commands and '[MITIGACIONES]' in line:
                break
            
            if in_commands and line.strip() and not line.startswith('['):
                if line.startswith('#'):
                    print(f"\n📝 {line[2:]}")
                else:
                    print(f"   $ {line.strip()}")
                cmd_count += 1
        
        if cmd_count == 0:
            print("No commands found\n")
        
        self._show_menu()
    
    def screen_4_mitigations(self):
        """PANTALLA 4: MITIGACIONES"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("╔════════════════════════════════╗")
        print("║      MITIGACIONES             ║")
        print("╚════════════════════════════════╝\n")
        
        report_file = self.get_latest_report()
        if not report_file:
            print("❌ No reports\n")
            self._show_menu()
            return
        
        with open(report_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        in_mitigations = False
        mit_count = 0
        
        for line in content.split('\n'):
            if '[MITIGACIONES]' in line:
                in_mitigations = True
                continue
            
            if in_mitigations and line.strip() and not line.startswith('['):
                print(f"✓ {line.strip()[:70]}")
                mit_count += 1
        
        if mit_count == 0:
            print("No mitigations found\n")
        
        self._show_menu()
    
    def _show_menu(self):
        """Menú de navegación"""
        print("\n╔════════════════════════════════╗")
        print("║ NAVEGACIÓN                     ║")
        print("╠════════════════════════════════╣")
        print("║ 1. Resumen General             ║")
        print("║ 2. Detalles Completos          ║")
        print("║ 3. Comandos Sugeridos          ║")
        print("║ 4. Mitigaciones                ║")
        print("║ 0. Salir                       ║")
        print("╚════════════════════════════════╝\n")
        
        choice = input("Selecciona pantalla (0-4): ")
        self.navigate(choice)
    
    def navigate(self, choice):
        """Navega entre pantallas"""
        if choice == '1':
            self.screen_1_overview()
        elif choice == '2':
            self.screen_2_details()
        elif choice == '3':
            self.screen_3_commands()
        elif choice == '4':
            self.screen_4_mitigations()
        elif choice == '0':
            print("\n👋 Saliendo...\n")
            exit()
        else:
            print("❌ Opción inválida\n")
            self._show_menu()
    
    def run(self):
        """Inicia el dashboard"""
        while True:
            self.screen_1_overview()

if __name__ == "__main__":
    dashboard = CardputerDashboardV2()
    dashboard.run()