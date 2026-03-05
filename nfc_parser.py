import re
import os
from datetime import datetime


# Mapa de AID conocidos a fabricante/red
AID_MAP = {
    "A0000000031010": "VISA",
    "A0000000032010": "VISA Electron",
    "A0000000033010": "VISA Interlink",
    "A0000000041010": "Mastercard",
    "A0000000043060": "Mastercard Maestro",
    "A0000000650101": "JCB",
    "A0000003241010": "Discover",
    "A000000025010401": "American Express",
    "A0000000291010": "American Express",
}

# Mapa SAK a tipo de tarjeta
SAK_MAP = {
    "08": "Mifare Classic 1K",
    "18": "Mifare Classic 4K",
    "20": "ISO14443-4 (EMV / ST25TA)",
    "28": "Mifare Classic + ISO14443-4",
    "38": "Mifare Classic 4K + ISO14443-4",
    "00": "NTAG / Mifare Ultralight",
    "10": "Mifare Plus SL2",
    "11": "Mifare Plus SL2",
}


class NFCParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = {}
        self.parse()

    def parse(self):
        """Parsea archivos .nfc del Flipper Zero"""
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            sak = self.extract_value(content, 'SAK')
            aid_raw = self.extract_value(content, 'AID')
            aid_clean = aid_raw.replace(' ', '').upper() if aid_raw else None
            fabricante = AID_MAP.get(aid_clean, None)

            # Inferir fabricante desde SAK si no hay AID
            if not fabricante:
                fabricante = SAK_MAP.get(sak, 'N/A') if sak else 'N/A'

            self.data = {
                'filename': os.path.basename(self.filepath),
                'filetype': self.extract_value(content, 'Filetype'),
                'version': self.extract_value(content, 'Version'),
                'device_type': self.extract_value(content, 'Device type'),
                'uid': self.extract_value(content, 'UID'),
                'atqa': self.extract_value(content, 'ATQA'),
                'sak': sak,
                'card_type': self.extract_value(content, 'Card Type'),
                'security_level': self.extract_value(content, 'Security Level'),
                'memory_size': self.extract_value(content, 'Memory Size'),
                'picc_version': self.extract_value(content, 'PICC Version'),
                'manufacturer': fabricante,
                # Campos EMV
                'emv_cardholder': self.extract_value(content, 'Cardholder name'),
                'emv_app_name': self.extract_value(content, 'Application name'),
                'emv_app_label': self.extract_value(content, 'Application label'),
                'emv_pan': self.extract_value(content, 'PAN'),
                'emv_aid': aid_raw,
                'emv_country': self.extract_value(content, 'Country code'),
                'emv_currency': self.extract_value(content, 'Currency code'),
                'emv_exp_year': self.extract_value(content, 'Expiration year'),
                'emv_exp_month': self.extract_value(content, 'Expiration month'),
                'emv_pin_counter': self.extract_value(content, 'PIN try counter'),
                'emv_aip': self.extract_value(content, 'Application interchange profile'),
                'raw_content': content
            }

        except FileNotFoundError:
            print(f"[ERROR] Archivo no encontrado: {self.filepath}")
            self.data = {'filename': os.path.basename(self.filepath), 'error': 'File not found'}
        except Exception as e:
            print(f"[ERROR] Error parsing {self.filepath}: {str(e)}")
            self.data = {'filename': os.path.basename(self.filepath), 'error': str(e)}

    def extract_value(self, content, key):
        """Extrae valores del formato key: value"""
        match = re.search(rf'^{re.escape(key)}:\s*(.+)', content, re.MULTILINE)
        return match.group(1).strip() if match else None

    def get_data(self):
        return self.data

    def get_summary(self):
        """Retorna un resumen tecnico para PHANTOM BRAIN"""
        d = self.data
        emv_block = ""
        if d.get('emv_app_name'):
            emv_block = f"""
EMV - Datos de la tarjeta:
  Red/App       : {d.get('emv_app_name')} ({d.get('emv_app_label', 'N/A')})
  AID           : {d.get('emv_aid', 'N/A')}
  PAN (parcial) : {d.get('emv_pan', 'N/A')}
  Vencimiento   : {d.get('emv_exp_month', '??')}/{d.get('emv_exp_year', '??')}
  AIP           : {d.get('emv_aip', 'N/A')}
  PIN counter   : {d.get('emv_pin_counter', 'N/A')}"""

        return f"""
CAPTURA NFC ANALIZADA
Archivo       : {d.get('filename')}
Device Type   : {d.get('device_type')}
Card Type     : {d.get('card_type', 'N/A')}
UID           : {d.get('uid')}
Fabricante    : {d.get('manufacturer')}
Security Level: {d.get('security_level', 'N/A')}
ATQA          : {d.get('atqa', 'N/A')}
SAK           : {d.get('sak', 'N/A')}{emv_block}
"""


def analyze_nfc_files(directory):
    """Analiza todos los .nfc en una carpeta"""
    results = []
    try:
        for file in sorted(os.listdir(directory)):
            if file.endswith('.nfc'):
                filepath = os.path.join(directory, file)
                parser = NFCParser(filepath)
                results.append(parser.get_data())
    except Exception as e:
        print(f"[ERROR] No se pudo leer directorio '{directory}': {e}")
    return results


if __name__ == "__main__":
    import sys
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    capturas = analyze_nfc_files(directory)
    for captura in capturas:
        print(f"Archivo     : {captura['filename']}")
        print(f"Device Type : {captura.get('device_type')}")
        print(f"UID         : {captura.get('uid')}")
        print(f"Fabricante  : {captura.get('manufacturer')}")
        if captura.get('emv_app_name'):
            print(f"Red EMV     : {captura.get('emv_app_name')}")
            print(f"PAN         : {captura.get('emv_pan')}")
        print()
