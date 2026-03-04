import re
import os
from datetime import datetime

class SubGhzParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = {}
        self.parse()
    
    def parse(self):
        """Parsea archivos .sub del Flipper"""
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.data = {
                'filename': os.path.basename(self.filepath),
                'filetype': self.extract_value(content, 'Filetype'),
                'version': self.extract_value(content, 'Version'),
                'frequency': self.extract_value(content, 'Frequency'),
                'preset': self.extract_value(content, 'Preset'),
                'protocol': self.extract_value(content, 'Protocol'),
                'bit': self.extract_value(content, 'Bit'),
                'key': self.extract_value(content, 'Key'),
                'secplus_packet_1': self.extract_value(content, 'Secplus_packet_1'),
                'raw_content': content
            }
        except Exception as e:
            print(f"Error parsing {self.filepath}: {str(e)}")
    
    def extract_value(self, content, key):
        """Extrae valores del formato key: value"""
        match = re.search(rf'{key}:\s*(.+)', content)
        return match.group(1).strip() if match else None
    
    def get_data(self):
        return self.data
    
    def get_summary(self):
        """Retorna un resumen técnico para PHANTOM BRAIN"""
        return f"""
CAPTURA SUB-GHZ ANALIZADA
Archivo: {self.data.get('filename')}
Protocolo: {self.data.get('protocol')}
Frecuencia: {self.data.get('frequency')} Hz
Preset: {self.data.get('preset')}
Bits: {self.data.get('bit')}
Key: {self.data.get('key')}
Packet: {self.data.get('secplus_packet_1')}
"""

def analyze_subghz_files(directory):
    """Analiza todos los .sub en una carpeta"""
    results = []
    for file in os.listdir(directory):
        if file.endswith('.sub'):
            filepath = os.path.join(directory, file)
            parser = SubGhzParser(filepath)
            results.append(parser.get_data())
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    else:
        directory = "."
    
    capturas = analyze_subghz_files(directory)
    for captura in capturas:
        print(f"Archivo: {captura['filename']}")
        print(f"Protocolo: {captura['protocol']}")
        print(f"Frecuencia: {captura['frequency']}")
        print(f"Key: {captura['key']}\n")