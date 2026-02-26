# PHANTOM BRAIN v0.5
## Sistema de Análisis Ofensivo Multi-Hardware con IA

Herramienta de pentesting offline que integra análisis de seguridad para WiFi, Sub-GHz, NFC/RFID y WPA2 usando IA local (Ollama).

### ✅ Completado

#### 1. WiFi / Marauder (v0.1-0.3)
- Parser de logs Marauder
- Detección de redes WPS vulnerables
- Identificación de redes ocultas
- Estadísticas de seguridad

#### 2. Sub-GHz / AIO Board (v0.4)
- **Parser Sub-GHz** (`sub_ghz_parser.py`)
  - Lectura archivos `.sub` del Flipper Zero
  - Extracción: protocolo, frecuencia, keys, packets
  
- **Analyzer de patrones** (`sub_ghz_analyzer.py`)
  - Detección de keys idénticas
  - Hamming distance entre keys
  - Análisis de protocolos reutilizados
  - Frecuencias coincidentes
  
- **Integración PHANTOM BRAIN**
  - Menú selectivo de capturas
  - Análisis con IA (phi3:mini / mistral)
  - Detecta: Rolling Code bypass, replay attacks, vulnerabilidades Security+ 2.0
  - Reportes automáticos con timestamp

#### 3. NFC/RFID / Proxmark3 (v0.4)
- **Parser NFC** (`nfc_parser.py`)
  - Lectura archivos `.nfc` del Flipper Zero
  - Extracción: Device Type, Card Type, UID, Security Level, Memory Size
  - Soporta: Mifare Classic, Mifare Plus, NTAG, FeliCa, etc
  
- **Analyzer de vulnerabilidades** (`nfc_analyzer.py`)
  - Detección automática de vulnerabilidades por tipo de tarjeta
  - Mifare Classic: Vulnerable a Darkside/Hardnested
  - Mifare Plus SL1: Reader Authentication Bypass, sector 0 sin protección
  - NTAG: Lectura completa si no está protegida
  - Análisis de UIDs idénticos
  
- **Integración PHANTOM BRAIN**
  - Menú selectivo con análisis de patrones
  - Detecta explotaciones concretas (clonación, inyección APDU, relay attacks)
  - Herramientas específicas: mfoc, mfcuk, proxmark3, flipper-zero
  - Análisis especial para tarjetas SUBE (transporte público)

#### 4. WPA2 Handshakes / Pineapple (v0.5)
- **Parser PCAP** (`pcap_parser_v2.py`)
  - Lectura archivos `.pcap` con Scapy
  - Extracción: BSSID, SSID, frames EAPOL, validación de handshake
  - Detección de handshakes completos (4+ mensajes EAPOL)
  
- **Integración PHANTOM BRAIN**
  - Menú selectivo de capturas WPA2
  - Análisis de vulnerabilidades
  - Recomendación de diccionarios (rockyou.txt)
  - Comandos con hashcat, john, aircrack-ng
  - Análisis de múltiples handshakes simultáneamente

### 📊 Archivos Generados
```
C:\Users\neurobelg\Desktop\nueva\ai tinkerers\
├── phantom_brain.py              # Sistema principal de análisis
├── sub_ghz_parser.py             # Parser Sub-GHz
├── sub_ghz_analyzer.py           # Analyzer patrones Sub-GHz
├── nfc_parser.py                 # Parser NFC
├── nfc_analyzer.py               # Analyzer vulnerabilidades NFC
├── pcap_parser_v2.py             # Parser PCAP WPA2
├── 893LM_7359_1.sub              # Captura Sub-GHz (Security+ 2.0)
├── 893LM_7359_2.sub              # Captura Sub-GHz (Security+ 2.0)
├── Sube.nfc                      # Captura NFC (Mifare Plus X SL1)
├── *_eviltwin.pcap               # Capturas WPA2 (9 handshakes válidos)
└── reporte_*.txt                 # Reportes generados automáticamente
```

### 🚀 Uso
```bash
# Analizar Sub-GHz
python phantom_brain.py
# Opción 4 -> Seleccionar captura .sub

# Analizar NFC
python phantom_brain.py
# Opción 5 -> Seleccionar captura .nfc

# Analizar WPA2
python phantom_brain.py
# Opción 6 -> Seleccionar captura .pcap

# Ver patrones Sub-GHz
python sub_ghz_analyzer.py

# Ver patrones NFC
python nfc_analyzer.py

# Analizar PCAPs directamente
python pcap_parser_v2.py
```

### 📋 Modelos IA Soportados

- **phi3:mini** - Rápido, análisis básico
- **mistral:7b-instruct** - Detallado, recomendado para análisis profundo

### 🔜 Próximos Pasos

5. **Raspberry Pi como servidor de campo** - Recibir datos en vivo
6. **M5StickC Plus2 como dashboard** - Visualización en tiempo real
7. **Demo final + repositorio público** - Para AI Tinkerers Community

### 📝 Notas Técnicas

- WiFi: Análisis offline de logs Marauder
- Sub-GHz: Soporte Security+ 2.0, Rolling Code, Fixed Code
- NFC: Soporte ISO14443-3A/4A, ISO15693, FeliCa, Mifare family
- WPA2: Validación de handshakes 4-way, cracking con diccionarios
- IA: Integración con Ollama para análisis offline

### ⚠️ Disclaimer

Para uso en entornos de laboratorio autorizados únicamente.

---
**Versión:** 0.5  
**Fecha actualización:** 26/02/2026  
**Autor:** neurobelg  
**Comunidad:** AI Tinkerers