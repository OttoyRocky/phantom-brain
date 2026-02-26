import os
from sub_ghz_parser import analyze_subghz_files

class SubGhzAnalyzer:
    def __init__(self, directory="."):
        self.capturas = analyze_subghz_files(directory)
    
    def analizar_patrones(self):
        """Detecta patrones sospechosos entre múltiples capturas"""
        if len(self.capturas) < 2:
            return None
        
        patrones = {
            'keys_identicas': [],
            'keys_similares': [],
            'mismo_protocolo': [],
            'frecuencias_identicas': []
        }
        
        for i in range(len(self.capturas)):
            for j in range(i + 1, len(self.capturas)):
                cap1 = self.capturas[i]
                cap2 = self.capturas[j]
                
                # Detectar keys idénticas
                if cap1['key'] == cap2['key']:
                    patrones['keys_identicas'].append({
                        'archivo1': cap1['filename'],
                        'archivo2': cap2['filename'],
                        'key': cap1['key']
                    })
                
                # Detectar keys similares (hamming distance)
                if self._hamming_distance(cap1['key'], cap2['key']) <= 2:
                    patrones['keys_similares'].append({
                        'archivo1': cap1['filename'],
                        'archivo2': cap2['filename'],
                        'distancia': self._hamming_distance(cap1['key'], cap2['key'])
                    })
                
                # Mismo protocolo
                if cap1['protocol'] == cap2['protocol']:
                    patrones['mismo_protocolo'].append({
                        'archivo1': cap1['filename'],
                        'archivo2': cap2['filename'],
                        'protocolo': cap1['protocol']
                    })
                
                # Misma frecuencia
                if cap1['frequency'] == cap2['frequency']:
                    patrones['frecuencias_identicas'].append({
                        'archivo1': cap1['filename'],
                        'archivo2': cap2['filename'],
                        'frecuencia': cap1['frequency']
                    })
        
        return patrones
    
    def _hamming_distance(self, key1, key2):
        """Calcula distancia de Hamming entre dos keys hexadecimales"""
        if not key1 or not key2:
            return float('inf')
        
        k1 = key1.replace(' ', '')
        k2 = key2.replace(' ', '')
        
        if len(k1) != len(k2):
            return float('inf')
        
        distance = 0
        try:
            for i in range(0, len(k1), 2):
                byte1 = int(k1[i:i+2], 16)
                byte2 = int(k2[i:i+2], 16)
                xor = byte1 ^ byte2
                distance += bin(xor).count('1')
        except:
            return float('inf')
        
        return distance
    
    def generar_reporte_patrones(self):
        """Genera reporte de patrones detectados"""
        patrones = self.analizar_patrones()
        
        if not patrones:
            return "No hay suficientes capturas para análisis de patrones."
        
        reporte = "\n=== ANALISIS DE PATRONES SUB-GHZ ===\n\n"
        
        if patrones['keys_identicas']:
            reporte += "[RIESGO CRITICO] Keys Idénticas Detectadas\n"
            for item in patrones['keys_identicas']:
                reporte += f"  - {item['archivo1']} y {item['archivo2']}\n"
                reporte += f"    Key reutilizada: {item['key']}\n"
            reporte += "\n"
        
        if patrones['keys_similares']:
            reporte += "[RIESGO ALTO] Keys Similares Detectadas\n"
            for item in patrones['keys_similares']:
                reporte += f"  - {item['archivo1']} y {item['archivo2']}\n"
                reporte += f"    Distancia Hamming: {item['distancia']} bits\n"
            reporte += "\n"
        
        if patrones['mismo_protocolo']:
            reporte += "[INFO] Mismo Protocolo en Múltiples Capturas\n"
            for item in patrones['mismo_protocolo']:
                reporte += f"  - {item['archivo1']} y {item['archivo2']}: {item['protocolo']}\n"
            reporte += "\n"
        
        if patrones['frecuencias_identicas']:
            reporte += "[INFO] Misma Frecuencia en Múltiples Capturas\n"
            for item in patrones['frecuencias_identicas']:
                reporte += f"  - {item['archivo1']} y {item['archivo2']}: {item['frecuencia']} Hz\n"
            reporte += "\n"
        
        return reporte

if __name__ == "__main__":
    analyzer = SubGhzAnalyzer(".")
    print(analyzer.generar_reporte_patrones())