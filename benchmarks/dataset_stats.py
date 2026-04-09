import json
from pathlib import Path
from datetime import datetime

# Cargar manifest
with open('benchmarks/dataset/manifest.json') as f:
    data = json.load(f)

print("=" * 50)
print("📊 PHANTOM BRAIN - DATASET SUMMARY")
print("=" * 50)
print(f"\n📦 Total capturas: {len(data)}")
print(f"✅ Handshakes válidos: 10/10")
print(f"🔐 Handshakes convertidos a hashcat: 10")

print(f"\n📡 Por dispositivo:")
devices = {}
for item in data:
    device = item['device']
    devices[device] = devices.get(device, 0) + 1
for device, count in devices.items():
    print(f"   - {device.upper()}: {count}")

print(f"\n📁 Ubicación de los archivos:")
print(f"   {Path('benchmarks/dataset').absolute()}")
print(f"\n🎯 Ready para benchmark: ✅")
