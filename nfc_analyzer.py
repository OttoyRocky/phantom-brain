import os
from nfc_parser import analyze_nfc_files

class NFCAnalyzer:
    def __init__(self, directory="."):
        self.capturas = analyze_nfc_files(directory)
    
    def analizar_patrones(self):
        """Detecta patrones sospechosos entre múltiples capturas NFC"""
        if len(self.capturas) < 2:
            return None
        
        patrones = {
            'uids_identicos': [],
            'mismo_device_type': [],
            'mismo_security_level': [],
            'mismo_card_type': [],
            'vulnerabilidades_comunes': []
        }
        
        for i in range(len(self.capturas)):
            for j in range(i + 1, len(self.capturas)):
                cap1 = self.capturas[i]
                cap2 = self.capturas[j]
                
                # UIDs idénticos
                if cap1['uid'] == cap2['uid']:
                    patrones['uids_identicos'].append({
                        'archivo1': cap1['filename'],
                        'archivo2': cap2['filename'],
                        'uid': cap1['uid']
                    })
                
                # Mismo device type
                if cap1['device_type'] == cap2['device_type']:
                    patrones['mismo_device_type'].append({
                        'archivo1': cap1['filename'],
                        'archivo2': cap2['filename'],
                        'device_type': cap1['device_type']
                    })
                
                # Mismo security level
                if cap1['security_level'] == cap2['security_level']:
                    patrones['mismo_security_level'].append({
                        'archivo1': cap1['filename'],
                        'archivo2': cap2['filename'],
                        'security_level': cap1['security_level']
                    })
                
                # Mismo card type
                if cap1['card_type'] == cap2['card_type']:
                    patrones['mismo_card_type'].append({
                        'archivo1': cap1['filename'],
                        'archivo2': cap2['filename'],
                        'card_type': cap1['card_type']
                    })
        
        return patrones
    
    def detectar_vulnerabilidades_comunes(self):
        """Detecta patrones de vulnerabilidad en las capturas"""
        vulnerabilidades = []
        
        for captura in self.capturas:
            device = captura.get('device_type', '')
            security = captura.get('security_level', '')
            card_type = captura.get('card_type', '')
            
            # Mifare Classic siempre vulnerable
            if 'Mifare Classic' in device or 'Mifare Classic' in card_type:
                vulnerabilidades.append({
                    'archivo': captura['filename'],
                    'vulnerabilidad': 'Mifare Classic - Vulnerable a ataques Darkside/Hardnested',
                    'nivel': 'CRITICO'
                })
            
            # Mifare Plus SL1 vulnerable
            if 'Mifare Plus' in device and security == 'SL1':
                vulnerabilidades.append({
                    'archivo': captura['filename'],
                    'vulnerabilidad': 'Mifare Plus SL1 - Reader Authentication Bypass',
                    'nivel': 'CRITICO'
                })
            
            # NTAG sin protección
            if 'NTAG' in device and security in ['SL0', None]:
                vulnerabilidades.append({
                    'archivo': captura['filename'],
                    'vulnerabilidad': 'NTAG sin protección - Lectura completa posible',
                    'nivel': 'ALTO'
                })
        
        return vulnerabilidades
    
    def generar_reporte_patrones(self):
        """Genera reporte de patrones detectados"""
        patrones = self.analizar_patrones()
        vulnerabilidades = self.detectar_vulnerabilidades_comunes()
        
        reporte = "\n=== ANALISIS DE PATRONES NFC ===\n\n"
        
        if vulnerabilidades:
            reporte += "[VULNERABILIDADES DETECTADAS]\n"
            for vuln in vulnerabilidades:
                reporte += f"  - [{vuln['nivel']}] {vuln['archivo']}: {vuln['vulnerabilidad']}\n"
            reporte += "\n"
        
        if patrones is None:
            reporte += "No hay suficientes capturas para análisis de patrones.\n"
            return reporte
        
        if patrones['uids_identicos']:
            reporte += "[RIESGO CRITICO] UIDs Idénticos Detectados\n"
            for item in patrones['uids_identicos']:
                reporte += f"  - {item['archivo1']} y {item['archivo2']}\n"
                reporte += f"    UID: {item['uid']}\n"
            reporte += "\n"
        
        if patrones['mismo_device_type']:
            reporte += "[INFO] Mismo Device Type en Múltiples Capturas\n"
            for item in patrones['mismo_device_type']:
                reporte += f"  - {item['archivo1']} y {item['archivo2']}: {item['device_type']}\n"
            reporte += "\n"
        
        if patrones['mismo_security_level']:
            reporte += "[INFO] Mismo Security Level en Múltiples Capturas\n"
            for item in patrones['mismo_security_level']:
                reporte += f"  - {item['archivo1']} y {item['archivo2']}: {item['security_level']}\n"
            reporte += "\n"
        
        if patrones['mismo_card_type']:
            reporte += "[INFO] Mismo Card Type en Múltiples Capturas\n"
            for item in patrones['mismo_card_type']:
                reporte += f"  - {item['archivo1']} y {item['archivo2']}: {item['card_type']}\n"
            reporte += "\n"
        
        return reporte

if __name__ == "__main__":
    analyzer = NFCAnalyzer(".")
    print(analyzer.generar_reporte_patrones())