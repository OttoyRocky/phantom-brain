import struct
import os
from datetime import datetime

class PCAPParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = {}
        self.packets = []
        self.parse()
    
    def parse(self):
        """Parsea archivos PCAP y extrae frames 802.11"""
        try:
            with open(self.filepath, 'rb') as f:
                # Leer header PCAP global
                global_header = f.read(24)
                magic = struct.unpack('<I', global_header[0:4])[0]
                
                if magic != 0xa1b2c3d4 and magic != 0xd4c3b2a1:
                    print(f"Error: Archivo no es PCAP válido")
                    return
                
                # Extraer metadatos
                version_major = struct.unpack('<H', global_header[4:6])[0]
                version_minor = struct.unpack('<H', global_header[6:8])[0]
                snaplen = struct.unpack('<I', global_header[16:20])[0]
                network = struct.unpack('<I', global_header[20:24])[0]
                
                self.data = {
                    'filename': os.path.basename(self.filepath),
                    'version': f"{version_major}.{version_minor}",
                    'snaplen': snaplen,
                    'network': network,
                    'packet_count': 0,
                    'bssid': None,
                    'ssid': None,
                    'channel': None,
                    'has_handshake': False,
                    'wpa_messages': []
                }
                
                # Leer paquetes
                packet_num = 0
                while True:
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break
                    
                    ts_sec = struct.unpack('<I', packet_header[0:4])[0]
                    ts_usec = struct.unpack('<I', packet_header[4:8])[0]
                    incl_len = struct.unpack('<I', packet_header[8:12])[0]
                    orig_len = struct.unpack('<I', packet_header[12:16])[0]
                    
                    packet_data = f.read(incl_len)
                    if len(packet_data) < incl_len:
                        break
                    
                    packet_num += 1
                    self._analyze_packet(packet_data)
                
                self.data['packet_count'] = packet_num
        
        except Exception as e:
            print(f"Error parsing {self.filepath}: {str(e)}")
    
    def _analyze_packet(self, data):
        """Analiza un paquete individual"""
        if len(data) < 8:
            return
        
        # Radiotap header (típico en PCAP 802.11)
        if data[0] == 0x00:  # Radiotap
            radiotap_len = struct.unpack('<H', data[2:4])[0]
            frame_data = data[radiotap_len:]
            self._parse_802_11_frame(frame_data)
    
    def _parse_802_11_frame(self, frame):
        """Parsea frames 802.11"""
        if len(frame) < 24:
            return
        
        frame_control = struct.unpack('<H', frame[0:2])[0]
        frame_type = (frame_control >> 2) & 0x3
        frame_subtype = (frame_control >> 4) & 0xF
        
        # Frame type 2 = Data frames (que contienen EAPOL para handshake)
        if frame_type == 2:
            # Extraer direcciones MAC
            dst_addr = ':'.join(f'{b:02x}' for b in frame[4:10])
            src_addr = ':'.join(f'{b:02x}' for b in frame[10:16])
            bssid = ':'.join(f'{b:02x}' for b in frame[16:22])
            
            if not self.data['bssid']:
                self.data['bssid'] = bssid
            
            # Buscar EAPOL (WPA Handshake)
            if len(frame) > 30:
                # EAPOL comienza después de headers (típico en offset 34+)
                for i in range(len(frame) - 2):
                    if frame[i:i+2] == b'\x88\x8e':  # EAPOL ethertype
                        self.data['has_handshake'] = True
                        msg_type = frame[i+6] if i+6 < len(frame) else 0
                        self.data['wpa_messages'].append({
                            'offset': i,
                            'type': msg_type,
                            'src': src_addr,
                            'dst': dst_addr
                        })
    
    def get_data(self):
        return self.data
    
    def get_summary(self):
        """Retorna resumen para PHANTOM BRAIN"""
        return f"""
CAPTURA WPA2 PCAP ANALIZADA
Archivo: {self.data.get('filename')}
Total paquetes: {self.data.get('packet_count')}
BSSID: {self.data.get('bssid')}
SSID: {self.data.get('ssid')}
Canal: {self.data.get('channel')}
¿Handshake detectado?: {self.data.get('has_handshake')}
Mensajes WPA encontrados: {len(self.data.get('wpa_messages', []))}
"""

def analyze_pcap_files(directory, min_size_kb=10):
    """Analiza archivos PCAP grandes en una carpeta"""
    results = []
    for file in os.listdir(directory):
        if file.endswith('.pcap'):
            filepath = os.path.join(directory, file)
            file_size_kb = os.path.getsize(filepath) / 1024
            
            # Solo archivos > 10 KB (tienen más datos)
            if file_size_kb >= min_size_kb:
                parser = PCAPParser(filepath)
                results.append(parser.get_data())
    
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    else:
        directory = "."
    
    capturas = analyze_pcap_files(directory)
    print(f"Encontrados {len(capturas)} archivos PCAP > 10 KB\n")
    for captura in capturas:
        print(f"Archivo: {captura['filename']}")
        print(f"Paquetes: {captura['packet_count']}")
        print(f"BSSID: {captura['bssid']}")
        print(f"¿Handshake?: {captura['has_handshake']}\n")