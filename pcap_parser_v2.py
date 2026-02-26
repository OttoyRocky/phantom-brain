from scapy.all import rdpcap, Dot11, EAPOL
import os

class PCAPParserV2:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = {}
        self.parse()
    
    def parse(self):
        """Parsea PCAP con Scapy"""
        try:
            packets = rdpcap(self.filepath)
            
            self.data = {
                'filename': os.path.basename(self.filepath),
                'total_packets': len(packets),
                'bssid': None,
                'ssid': None,
                'channel': None,
                'eapol_frames': [],
                'handshake_complete': False,
                'vulnerabilities': []
            }
            
            eapol_count = 0
            beacon_count = 0
            
            for pkt in packets:
                # Buscar beacons para extraer BSSID y SSID
                if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
                    if not self.data['bssid']:
                        self.data['bssid'] = pkt.addr2
                    
                    # SSID está en Information Elements
                    if hasattr(pkt, 'info') and pkt.info:
                        self.data['ssid'] = pkt.info
                    
                    beacon_count += 1
                
                # Buscar EAPOL frames (WPA Handshake)
                if pkt.haslayer(EAPOL):
                    eapol_count += 1
                    eapol_layer = pkt[EAPOL]
                    
                    self.data['eapol_frames'].append({
                        'frame_num': len(self.data['eapol_frames']) + 1,
                        'src': pkt[Dot11].addr2 if pkt.haslayer(Dot11) else "Unknown",
                        'dst': pkt[Dot11].addr1 if pkt.haslayer(Dot11) else "Unknown",
                        'type': eapol_layer.type if hasattr(eapol_layer, 'type') else "Unknown"
                    })
            
            # Detectar handshake completo (4 mensajes EAPOL)
            if eapol_count >= 4:
                self.data['handshake_complete'] = True
                self.data['vulnerabilities'].append({
                    'nivel': 'ALTO',
                    'nombre': 'Handshake WPA2 Capturado',
                    'descripcion': f'Se capturaron {eapol_count} frames EAPOL, suficientes para ataque de diccionario'
                })
            
            # Análisis de vulnerabilidades
            if not self.data['ssid']:
                self.data['vulnerabilities'].append({
                    'nivel': 'MEDIO',
                    'nombre': 'Red Oculta',
                    'descripcion': 'SSID no transmitido, dificulta identificación'
                })
        
        except Exception as e:
            print(f"Error parsing {self.filepath}: {str(e)}")
            self.data = {
                'filename': os.path.basename(self.filepath),
                'error': str(e)
            }
    
    def get_data(self):
        return self.data
    
    def get_summary(self):
        return f"""
CAPTURA WPA2 ANALIZADA
Archivo: {self.data.get('filename')}
Total paquetes: {self.data.get('total_packets')}
BSSID: {self.data.get('bssid')}
SSID: {self.data.get('ssid')}
Frames EAPOL: {len(self.data.get('eapol_frames', []))}
¿Handshake completo?: {self.data.get('handshake_complete')}
"""

def analyze_pcap_files(directory, min_size_kb=10):
    """Analiza archivos PCAP > 10 KB"""
    results = []
    for file in os.listdir(directory):
        if file.endswith('.pcap'):
            filepath = os.path.join(directory, file)
            file_size_kb = os.path.getsize(filepath) / 1024
            
            if file_size_kb >= min_size_kb:
                parser = PCAPParserV2(filepath)
                if 'error' not in parser.get_data():
                    results.append(parser.get_data())
    
    return results

if __name__ == "__main__":
    capturas = analyze_pcap_files(".")
    print(f"Encontrados {len(capturas)} archivos PCAP válidos\n")
    for captura in capturas:
        print(f"Archivo: {captura['filename']}")
        print(f"Paquetes: {captura['total_packets']}")
        print(f"BSSID: {captura['bssid']}")
        print(f"SSID: {captura['ssid']}")
        print(f"EAPOL frames: {len(captura['eapol_frames'])}")
        print(f"¿Handshake?: {captura['handshake_complete']}\n")