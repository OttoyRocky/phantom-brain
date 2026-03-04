import re
import os
from datetime import datetime

class ProxmarkParser:
    def __init__(self, raw_output):
        self.raw = raw_output
        self.data = {}
        self.parse()

    def parse(self):
        self.data['raw'] = self.raw
        self.data['timestamp'] = datetime.now().strftime("%Y%m%d_%H%M%S")

        if 'EM 410x' in self.raw or 'EM410x' in self.raw:
            self.data['type'] = 'EM410x'
            self.data['frequency'] = '125kHz'
            self.data['protocol'] = 'LF'
            uid = re.search(r'EM 410x ID\s+([0-9A-Fa-f]+)', self.raw, re.IGNORECASE)
            self.data['uid'] = uid.group(1) if uid else None
            chipset = re.search(r'Chipset\.\.\.\s+(.+)', self.raw)
            self.data['chipset'] = chipset.group(1).strip() if chipset else None
            dez8 = re.search(r'DEZ 8\s+:\s+(\d+)', self.raw)
            self.data['dez8'] = dez8.group(1) if dez8 else None
            dez10 = re.search(r'DEZ 10\s+:\s+(\d+)', self.raw)
            self.data['dez10'] = dez10.group(1) if dez10 else None
            paxton = re.search(r'Pattern Paxton\s+:\s+(\d+)', self.raw)
            self.data['paxton'] = paxton.group(1) if paxton else None
            self.data['vulnerabilities'] = [
                'Sin cifrado - datos transmitidos en claro',
                'Clonable con tarjeta T55xx en blanco',
                'UID fijo y predecible - replay attack posible',
                'Compatible con multiples formatos de control de acceso'
            ]
            self.data['comandos'] = [
                '# Leer informacion completa de la tarjeta EM410x',
                f'lf em 410x reader',
                '',
                '# Clonar UID en tarjeta T55xx en blanco',
                f'lf em 410x clone --id {self.data["uid"] if self.data["uid"] else "0A00244697"}',
                '',
                '# Simular la tarjeta (emulacion)',
                f'lf em 410x sim --id {self.data["uid"] if self.data["uid"] else "0A00244697"}',
                '',
                '# Analizar chipset T55xx detectado',
                'lf t55xx info',
                '',
                '# Detectar configuracion del T55xx',
                'lf t55xx detect',
                '',
                '# Decodificar formato Wiegand del UID',
                f'wiegand decode --raw {self.data["uid"] if self.data["uid"] else "0A00244697"}',
                '',
                '# Dump completo de la tarjeta',
                'lf t55xx dump',
            ]

        elif 'MIFARE Plus' in self.raw:
            self.data['type'] = 'MIFARE Plus'
            self.data['frequency'] = '13.56MHz'
            self.data['protocol'] = 'ISO14443-A'
            uid = re.search(r'UID:\s+([0-9A-F\s]+)\(', self.raw)
            self.data['uid'] = uid.group(1).strip() if uid else None
            sl = re.search(r'MIFARE Plus\s+\w+\s+(\d+K)\s+in\s+(SL\d)', self.raw)
            if sl:
                self.data['size'] = sl.group(1)
                self.data['security_level'] = sl.group(2)
            self.data['vulnerabilities'] = [
                'SL1: Reader Authentication Bypass - sector 0 accesible sin clave',
                'SL1: Vulnerable a ataques Darkside y Hardnested',
                'Clonacion de UID posible con proxmark3',
                'Relay attack posible en distancias cortas'
            ]
            uid_str = self.data['uid'].replace(' ', '') if self.data['uid'] else '048B382A865E80'
            self.data['comandos'] = [
                '# Informacion completa de la tarjeta MIFARE Plus',
                'hf mfp info',
                '',
                '# Leer tag MIFARE Plus como NFC',
                'nfc mf pread',
                '',
                '# Intentar autenticacion con claves por defecto',
                'hf mf chk --1k -f mfc_default_keys.dic',
                '',
                '# Ataque Hardnested para recuperar claves',
                'hf mf hardnested -t --tk ffffffffffff',
                '',
                '# Dump completo de la tarjeta (requiere claves)',
                'hf mf dump --1k',
                '',
                '# Verificar nivel de seguridad SL',
                'hf mfp chk',
                '',
                '# Clonar tarjeta en blanco compatible',
                f'hf mf cload -f hf-mf-{uid_str}-dump.bin',
            ]

        elif 'ST Microelectronics' in self.raw or 'st25ta' in self.raw.lower():
            self.data['type'] = 'ST25TA'
            self.data['frequency'] = '13.56MHz'
            self.data['protocol'] = 'ISO14443-A'
            uid = re.search(r'UID:\s+([0-9A-F\s]+)\(', self.raw)
            self.data['uid'] = uid.group(1).strip() if uid else None
            self.data['manufacturer'] = 'ST Microelectronics France'
            self.data['vulnerabilities'] = [
                'Lectura NDEF sin autenticacion en configuracion por defecto',
                'Datos NFC accesibles sin pin en algunos modelos',
                'Protocolo ST25TA con posible bypass de proteccion de lectura'
            ]
            self.data['comandos'] = [
                '# Informacion completa ST25TA',
                'hf st25ta info',
                '',
                '# Leer como NFC Type 4A',
                'nfc type4a st25taread',
                '',
                '# Leer registros NDEF',
                'nfc type4a read',
                '',
                '# Busqueda general HF',
                'hf search',
                '',
                '# Informacion ISO14443-A',
                'hf 14a info',
                '',
                '# Raw APDU para explorar estructura',
                'hf 14a raw -s -c 00A4040007D276000085010100',
            ]

        elif 'EMV' in self.raw:
            self.data['type'] = 'EMV'
            self.data['frequency'] = '13.56MHz'
            self.data['protocol'] = 'ISO14443-A'
            uid = re.search(r'UID:\s+([0-9A-F\s]+)\(', self.raw)
            self.data['uid'] = uid.group(1).strip() if uid else None
            fingerprint = re.findall(r'\[\+\]\s+(.+(?:Bank|Visa|Mastercard|card|bPay|BPP).+)', self.raw)
            self.data['fingerprint'] = fingerprint if fingerprint else []
            self.data['vulnerabilities'] = [
                'Datos basicos legibles sin autenticacion (PAN parcial, fecha expiracion)',
                'Relay attack posible en terminales sin limite de distancia',
                'Fingerprinting del emisor expuesto en ATR historico',
                'Track2 equivalent data accesible en algunos casos'
            ]
            self.data['comandos'] = [
                '# Leer tarjeta EMV completa',
                'emv reader',
                '',
                '# Escaneo EMV detallado',
                'emv scan -a -t -v',
                '',
                '# Extraer datos del chip',
                'emv extract',
                '',
                '# Leer como smart card ISO7816',
                'smart reader',
                '',
                '# Informacion del chip',
                'smart info',
                '',
                '# Fuerza bruta de SFI (Service File Identifier)',
                'smart brute',
                '',
                '# Raw APDU - seleccionar aplicacion Visa',
                'hf 14a raw -s -c 00A4040007A0000000031010',
                '',
                '# Raw APDU - seleccionar aplicacion Mastercard',
                'hf 14a raw -s -c 00A4040007A0000000041010',
            ]

        elif 'Indala' in self.raw:
            self.data['type'] = 'Indala'
            self.data['frequency'] = '125kHz'
            self.data['protocol'] = 'LF'
            raw_id = re.search(r'Raw:\s+([0-9a-f]+)', self.raw)
            self.data['raw_id'] = raw_id.group(1) if raw_id else None
            self.data['vulnerabilities'] = [
                'Formato propietario Motorola/HID sin cifrado',
                'Clonable con proxmark3 en tarjeta compatible',
                'Sin mecanismo de autenticacion mutua'
            ]
            raw_str = self.data['raw_id'] if self.data['raw_id'] else '800000010000010008040004'
            self.data['comandos'] = [
                '# Leer tarjeta Indala',
                'lf indala reader',
                '',
                '# Demodular desde buffer',
                'lf indala demod',
                '',
                '# Clonar en tarjeta compatible',
                f'lf indala clone --raw {raw_str}',
                '',
                '# Simular la tarjeta',
                f'lf indala sim --raw {raw_str}',
                '',
                '# Analizar formato del ID',
                'lf indala altdemod',
            ]

        else:
            self.data['type'] = 'Unknown'
            self.data['vulnerabilities'] = ['Tipo no identificado - analisis manual requerido']
            self.data['comandos'] = [
                '# Busqueda automatica LF',
                'lf search',
                '',
                '# Busqueda automatica HF',
                'hf search',
                '',
                '# Deteccion automatica completa',
                'auto',
            ]

    def get_summary(self):
        t = self.data.get('type', 'Unknown')
        uid = self.data.get('uid', self.data.get('raw_id', 'N/A'))
        freq = self.data.get('frequency', 'N/A')
        proto = self.data.get('protocol', 'N/A')
        vulns = '\n'.join([f'  - {v}' for v in self.data.get('vulnerabilities', [])])

        fingerprint = ''
        if self.data.get('fingerprint'):
            fingerprint = '\nFingerprint emisor:\n' + '\n'.join([f'  - {f}' for f in self.data['fingerprint']])

        sl = ''
        if self.data.get('security_level'):
            sl = f"\nSecurity Level : {self.data['security_level']}"

        size = ''
        if self.data.get('size'):
            size = f"\nTamano memoria : {self.data['size']}"

        chipset = ''
        if self.data.get('chipset'):
            chipset = f"\nChipset        : {self.data['chipset']}"

        comandos = ''
        if self.data.get('comandos'):
            comandos = '\nComandos Proxmark3 sugeridos:\n' + '\n'.join([f'  {c}' for c in self.data['comandos']])

        return f"""
CAPTURA PROXMARK3 ANALIZADA
Tipo           : {t}
UID            : {uid}
Frecuencia     : {freq}
Protocolo      : {proto}{sl}{size}{chipset}{fingerprint}

Vulnerabilidades detectadas:
{vulns}
{comandos}
"""

    def get_data(self):
        return self.data


def parse_proxmark_output(raw_text):
    parser = ProxmarkParser(raw_text)
    return parser


if __name__ == "__main__":
    print("=" * 50)
    print(" PROXMARK PARSER - Test")
    print("=" * 50)
    print("Pega output del Proxmark3 (Enter en linea vacia para terminar):")
    lineas = []
    while True:
        linea = input()
        if linea == "":
            break
        lineas.append(linea)
    raw = "\n".join(lineas)
    p = parse_proxmark_output(raw)
    print(p.get_summary())