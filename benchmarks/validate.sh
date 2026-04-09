#!/bin/bash
echo "=== VALIDANDO DATASET ==="
for device in flipper proxmark3 pineapple; do
    echo -e "\n📡 $device:"
    for cap in benchmarks/dataset/$device/*.{cap,pcap} 2>/dev/null; do
        if [ -f "$cap" ]; then
            echo -n "  $(basename $cap): "
            if hcxpcapngtool "$cap" 2>&1 | grep -q "EAPOL"; then
                echo "✅ Handshake válido"
                # Convertir a hc22000
                hcxpcapngtool "$cap" -o "${cap%.*}.hc22000" 2>/dev/null
            elif hcxpcapngtool "$cap" 2>&1 | grep -q "PMKID"; then
                echo "✅ PMKID encontrado"
            else
                echo "❌ No válido"
            fi
        fi
    done
done
