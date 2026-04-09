#!/usr/bin/env python3
import json
import subprocess
from pathlib import Path

def test_handshake(hc22000_file):
    """Prueba si el handshake es crackeable"""
    try:
        # Verificar formato
        result = subprocess.run(
            ["hcxpcapngtool", "--info", hc22000_file],
            capture_output=True, text=True
        )
        return "ESSID" in result.stdout
    except:
        return False

def main():
    print("=" * 50)
    print("🎯 EJECUTANDO BENCHMARK CON DATASET REAL")
    print("=" * 50)
    
    # Cargar manifest
    with open('benchmarks/dataset/manifest.json') as f:
        captures = json.load(f)
    
    results = []
    for cap in captures:
        hc22000 = Path(cap['file']).with_suffix('.hc22000')
        if hc22000.exists():
            is_valid = test_handshake(hc22000)
            results.append({
                "device": cap['device'],
                "file": Path(cap['file']).name,
                "hash": cap['hash'],
                "valid": is_valid
            })
            status = "✅" if is_valid else "⚠️"
            print(f"{status} {cap['device'].upper()}: {Path(cap['file']).name}")
    
    # Guardar resultados
    with open('benchmarks/results/dataset_benchmark.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📊 Total procesados: {len(results)}")
    print(f"✅ Válidos: {sum(1 for r in results if r['valid'])}")
    print(f"\n💾 Resultados guardados en: benchmarks/results/dataset_benchmark.json")

if __name__ == "__main__":
    Path('benchmarks/results').mkdir(exist_ok=True)
    main()
