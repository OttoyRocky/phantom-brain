#!/usr/bin/env python3
import subprocess
import os
from pathlib import Path

def validate_capture(cap_file):
    """Valida si un archivo .cap o .pcap contiene handshake o PMKID"""
    try:
        # Versión compatible con Python 3.6+
        result = subprocess.run(
            ["hcxpcapngtool", str(cap_file)],
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True
        )
        output = result.stdout
        
        if "EAPOL" in output:
            return "handshake"
        elif "PMKID" in output:
            return "pmkid"
        else:
            return "invalid"
    except FileNotFoundError:
        return "hcxtools_not_installed"
    except Exception as e:
        return f"error: {str(e)}"

def main():
    print("=== VALIDANDO DATASET ===\n")
    
    devices = ["flipper", "proxmark3", "pineapple"]
    stats = {"handshake": 0, "pmkid": 0, "invalid": 0, "error": 0, "total": 0}
    
    for device in devices:
        device_path = Path(f"benchmarks/dataset/{device}")
        if not device_path.exists():
            continue
            
        caps = list(device_path.glob("*.cap")) + list(device_path.glob("*.pcap"))
        if caps:
            print(f"📡 {device.upper()}:")
            for cap in caps:
                result = validate_capture(cap)
                stats[result] = stats.get(result, 0) + 1
                stats["total"] += 1
                
                if result == "handshake":
                    print(f"  ✅ {cap.name} - Handshake válido")
                    # Convertir a hc22000
                    hc22000 = cap.with_suffix(".hc22000")
                    subprocess.run(["hcxpcapngtool", str(cap), "-o", str(hc22000)], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif result == "pmkid":
                    print(f"  ✅ {cap.name} - PMKID encontrado")
                elif result == "invalid":
                    print(f"  ❌ {cap.name} - No válido")
                elif result == "hcxtools_not_installed":
                    print(f"  ⚠️ {cap.name} - hcxtools no instalado")
                    print("     Instalar con: sudo apt install hcxtools")
                    return
                else:
                    print(f"  ❌ {cap.name} - {result}")
            print()
    
    print("\n=== RESUMEN ===")
    print(f"📊 Total capturas: {stats['total']}")
    print(f"   ✅ Handshakes: {stats['handshake']}")
    print(f"   🔑 PMKIDs: {stats['pmkid']}")
    print(f"   ❌ Inválidas: {stats['invalid']}")
    if stats.get('error', 0) > 0:
        print(f"   ⚠️ Errores: {stats['error']}")

if __name__ == "__main__":
    main()
