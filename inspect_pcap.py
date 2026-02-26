import struct

with open('1c-7b-23-37-cc-38_eviltwin.pcap', 'rb') as f:
    f.read(24)  # Skip global header
    # Leer primer paquete
    ph = f.read(16)
    pkt = f.read(200)
    print('Primeros 200 bytes del paquete:')
    print(pkt.hex())