#!/usr/bin/env python3
import json, hashlib, sys
from pathlib import Path
from datetime import datetime

def register_capture(device, file_path, metadata=""):
    manifest = Path("benchmarks/dataset/manifest.json")
    
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()[:8]
    
    record = {
        "device": device,
        "timestamp": datetime.now().isoformat(),
        "file": str(file_path),
        "hash": file_hash,
        "metadata": metadata
    }
    
    if manifest.exists():
        with open(manifest) as f:
            data = json.load(f)
    else:
        data = []
    
    data.append(record)
    with open(manifest, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"✅ {device.upper()}: {Path(file_path).name} -> {file_hash}")
    return file_hash

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3 ingest.py <device> <file_path> [metadata]")
        sys.exit(1)
    register_capture(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
