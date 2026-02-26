import re
import os
from datetime import datetime

class NFCParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = {}
        self.parse()
    
    def parse(self):
        """Parsea archivos .nfc del Flipper"""
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.data = {
                'filename': os.path.basename(self.filepath),
                'filetype': self.extract_value(content, 'Filetype'),
                'version': self.extract_value(content, 'Version'),
                'device_type': self.extract_value(content, 'Device type'),
                'uid': self.extract_value(content, 'UID'),
                'atqa': self.extract_value(content, 'ATQA'),
                'sak': self.extract_value(content, 'SAK'),
                'card_type': self.extract_value(content, 'Card Type'),
                'security_level': self.extract_value(content, 'Security Level'),
                'memory_size': self.extract_value(content, 'Memory Size'),
                'picc_version': self.extract_value(content, 'PICC Version'),
                'raw_content': content
            }
        except Exception as e:
            print(f"Error parsing {filepath}: {str(e)}")
    
    def extract_value(self, content, key):
        """Extrae valores del formato key: value"""
        match = re.search(rf'{key}:\s*(.+)', content)
        return match.group(1).strip() if match else None
    
    def get_data(self):
        return self.data
    
    def get_summary(self):
        """Retorna un resumen técnico para PHANTOM BRAIN"""
        return f"""
CAPTURA NFC ANALIZADA
Archivo: {self.data.get('filename')}
Device Type: {self.data.get('device_type')}
Card Type: {self.data.get('card_type')}
UID: {self.data.get('uid')}
Security Level: {self.data.get('security_level')}
Memory Size: {self.data.get('memory_size')}
ATQA: {self.data.get('atqa')}
SAK: {self.data.get('sak')}
"""

def analyze_nfc_files(directory):
    """Analiza todos los .nfc en una carpeta"""
    results = []
    for file in os.listdir(directory):
        if file.endswith('.nfc'):
            filepath = os.path.join(directory, file)
            parser = NFCParser(filepath)
            results.append(parser.get_data())
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    else:
        directory = "."
    
    capturas = analyze_nfc_files(directory)
    for captura in capturas:
        print(f"Archivo: {captura['filename']}")
        print(f"Device Type: {captura['device_type']}")
        print(f"Card Type: {captura['card_type']}")
        print(f"UID: {captura['uid']}")
        print(f"Security Level: {captura['security_level']}\n")