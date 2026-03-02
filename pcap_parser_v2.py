from scapy.all import rdpcap, Dot11, EAPOL, raw
import os


class PCAPParserV2:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = {}
        self.parse()

    def parse(self):
        try:
            packets = rdpcap(self.filepath)
            self.data = {
                'filename': os.path.basename(self.filepath),
                'total_packets': len(packets),
                'bssid': None,
                'ssid': None,
                'eapol_frames': [],
                'handshake_complete': False,
                'pmkid_found': False,
                'pmkid_hash': None,
                'vulnerabilities': []
            }
            eapol_count = 0

            for pkt in packets:
                if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
                    if not self.data['bssid']:
                        self.data['bssid'] = pkt.addr2
                    if hasattr(pkt, 'info') and pkt.info:
                        self.data['ssid'] = pkt.info

                if pkt.haslayer(EAPOL):
                    eapol_count += 1
                    src = pkt[Dot11].addr2 if pkt.haslayer(Dot11) else "Unknown"
                    dst = pkt[Dot11].addr1 if pkt.haslayer(Dot11) else "Unknown"
                    self.data['eapol_frames'].append({
                        'frame_num': eapol_count,
                        'src': src,
                        'dst': dst,
                    })
                    if not self.data['pmkid_found']:
                        pmkid = self._extraer_pmkid(pkt)
                        if pmkid:
                            self.data['pmkid_found'] = True
                            bssid_clean = (self.data['bssid'] or '').replace(':', '')
                            src_clean = src.replace(':', '')
                            ssid_hex = self.data['ssid'].hex() if isinstance(self.data['ssid'], bytes) else (self.data['ssid'] or '').encode().hex()
                            self.data['pmkid_hash'] = f"WPA*01*{pmkid}*{bssid_clean}*{src_clean}*{ssid_hex}"

            if eapol_count >= 4:
                self.data['handshake_complete'] = True
                self.data['vulnerabilities'].append({
                    'nivel': 'ALTO',
                    'nombre': 'Handshake WPA2 Capturado',
                    'descripcion': (
                        f'{eapol_count} frames EAPOL. Listo para crackeo.\n'
                        f'  hcxpcapngtool -o hash.hc22000 {self.data["filename"]}\n'
                        f'  hashcat -m 22000 hash.hc22000 rockyou.txt\n'
                        f'  aircrack-ng -w rockyou.txt -b {self.data["bssid"]} {self.data["filename"]}'
                    )
                })

            if self.data['pmkid_found']:
                self.data['vulnerabilities'].append({
                    'nivel': 'ALTO',
                    'nombre': 'PMKID Capturado',
                    'descripcion': (
                        f'PMKID extraido. No requiere cliente conectado.\n'
                        f'  Hash: {self.data["pmkid_hash"]}\n'
                        f'  echo "{self.data["pmkid_hash"]}" > hash.hc22000\n'
                        f'  hashcat -m 22000 hash.hc22000 rockyou.txt'
                    )
                })
            elif eapol_count > 0 and eapol_count < 4:
                self.data['vulnerabilities'].append({
                    'nivel': 'MEDIO',
                    'nombre': 'Handshake Incompleto',
                    'descripcion': f'Solo {eapol_count} frame(s) EAPOL. Se necesitan minimo 4.'
                })
            elif eapol_count == 0:
                self.data['vulnerabilities'].append({
                    'nivel': 'INFO',
                    'nombre': 'Sin EAPOL - posible PMKID en raw',
                    'descripcion': (
                        'No se detectaron frames EAPOL.\n'
                        '  hcxpcapngtool -o hash.hc22000 archivo.pcap\n'
                        '  hashcat -m 22000 hash.hc22000 rockyou.txt'
                    )
                })

        except Exception as e:
            self.data = {
                'filename': os.path.basename(self.filepath),
                'error': str(e),
                'total_packets': 0,
                'bssid': None,
                'ssid': None,
                'eapol_frames': [],
                'handshake_complete': False,
                'pmkid_found': False,
                'pmkid_hash': None,
                'vulnerabilities': []
            }

    def _extraer_pmkid(self, pkt):
        try:
            raw_bytes = raw(pkt)
            kde_marker = bytes.fromhex('dd16000fac04')
            idx = raw_bytes.find(kde_marker)
            if idx != -1:
                pmkid_bytes = raw_bytes[idx + 6: idx + 22]
                if len(pmkid_bytes) == 16:
                    return pmkid_bytes.hex()
        except Exception:
            pass
        return None

    def get_data(self):
        return self.data

    def get_summary(self):
        ssid = self.data.get('ssid')
        if isinstance(ssid, bytes):
            ssid = ssid.decode('utf-8', errors='replace')
        pmkid_line = f"\nPMKID Hash     : {self.data.get('pmkid_hash')}" if self.data.get('pmkid_found') else ""
        return f"""
CAPTURA WPA2 ANALIZADA
Archivo        : {self.data.get('filename')}
Total paquetes : {self.data.get('total_packets')}
BSSID          : {self.data.get('bssid')}
SSID           : {ssid}
Frames EAPOL   : {len(self.data.get('eapol_frames', []))}
Handshake OK   : {self.data.get('handshake_complete')}{pmkid_line}
"""


def analyze_pcap_files(directory, min_size_kb=5):
    results = []
    try:
        files = [f for f in os.listdir(directory) if f.endswith('.pcap')]
    except Exception as e:
        print(f"[ERROR] No se pudo leer '{directory}': {e}")
        return results
    for file in sorted(files):
        filepath = os.path.join(directory, file)
        if os.path.getsize(filepath) / 1024 >= min_size_kb:
            parser = PCAPParserV2(filepath)
            data = parser.get_data()
            if 'error' not in data:
                results.append(data)
    return results