# PHANTOM BRAIN v0.5
## Sistema de Análisis Ofensivo Multi-Hardware con IA

Herramienta modular de pentesting que integra análisis de seguridad para WiFi, Sub-GHz, NFC/RFID y WPA2 usando IA local (Ollama).

---

## 📋 Arquitectura del Sistema
```
OPERACIONES DE CAMPO (Móviles):
┌──────────────┐
│ Flipper Zero │ ──► Captura Sub-GHz, NFC
│              │     Batería: 40+ horas
└──────────────┘

┌──────────────┐
│  Cardputer   │ ──► Dashboard portátil
│  M5Stack     │     Teclado + Pantalla 2.4"
│              │     Batería: 7-10 días
└──────────────┘

OPERACIONES DE BASE (Fijas):
┌──────────────────┐
│  Raspberry Pi    │ ──► Servidor centralizado
│  Kali Linux      │     Flask API REST
│  PHANTOM BRAIN   │     Procesa datos en vivo
│  (enchufada)     │     Almacena reportes
└──────────────────┘

FLUJO DE DATOS:
Flipper (campo) ──► Cardputer (visualiza) ──► Raspberry (procesa) ──► Cardputer (muestra resultados)
```

---

## ✅ Features Completados

### **1. WiFi / Marauder (v0.1-0.3)**
- Parser de logs Marauder
- Detección de redes WPS vulnerables
- Identificación de redes ocultas
- Estadísticas de seguridad

### **2. Sub-GHz / AIO Board (v0.4)**
**Parser Sub-GHz** (`sub_ghz_parser.py`)
- Lectura archivos `.sub` del Flipper Zero
- Extracción: protocolo, frecuencia, keys, packets
- Soporta: Security+ 2.0, Rolling Code, Fixed Code

**Analyzer de patrones** (`sub_ghz_analyzer.py`)
- Detección de keys idénticas
- Hamming distance entre keys
- Análisis de protocolos reutilizados

**Integración PHANTOM BRAIN**
- Menú selectivo de capturas
- Análisis con IA (phi3:mini / mistral)
- Detecta: Rolling Code bypass, replay attacks
- Reportes automáticos

### **3. NFC/RFID / Proxmark3 (v0.4)**
**Parser NFC** (`nfc_parser.py`)
- Lectura archivos `.nfc` del Flipper Zero
- Extracción: Device Type, Card Type, UID, Security Level
- Soporta: Mifare Classic, Mifare Plus, NTAG, FeliCa

**Analyzer de vulnerabilidades** (`nfc_analyzer.py`)
- Detección automática por tipo de tarjeta
- Mifare Plus SL1: Reader Authentication Bypass
- Mifare Classic: Vulnerable a Darkside/Hardnested
- Análisis de UIDs idénticos

**Integración PHANTOM BRAIN**
- Menú selectivo con análisis de patrones
- Detecta explotaciones concretas
- Herramientas: mfoc, mfcuk, proxmark3, flipper-zero
- Análisis especial para SUBE (transporte público)

### **4. WPA2 Handshakes / Pineapple (v0.5)**
**Parser PCAP** (`pcap_parser_v2.py`)
- Lectura archivos `.pcap` con Scapy
- Extracción: BSSID, SSID, frames EAPOL
- Validación de handshakes completos (4+ mensajes EAPOL)

**Integración PHANTOM BRAIN**
- Menú selectivo de capturas WPA2
- Análisis de vulnerabilidades
- Recomendación de diccionarios (rockyou.txt)
- Comandos con hashcat, john, aircrack-ng
- Análisis de múltiples handshakes simultáneamente

---

## 🚀 Próximos Pasos (Roadmap v0.6+)

### **6. Cardputer Dashboard (EN PROGRESO)**
- Firmware M5Stack
- Interfaz de 4 pantallas
- Conexión WiFi
- Lectura de reportes JSON
- Botones para navegación
- Teclado integrado para inputs

### **7. Raspberry Pi - Servidor Base (Próximo)**
- Kali Linux + Flask
- Servidor API REST (/api/upload/*, /api/reports, /api/status)
- Recibe datos de Flipper/Pineapple
- Procesa con PHANTOM BRAIN
- Base de datos SQLite/JSON

### **8. Integración Completa (Futuro)**
- Scripts de upload automático
- Sincronización WiFi Flipper ↔ Raspberry
- WebSocket para datos en tiempo real
- Dashboard web (Raspberry)

### **9. Demo Final + Community (Final)**
- Documentación completa
- Scripts listos para usar
- Tutorial de instalación
- Repositorio público para AI Tinkerers

---

## 📁 Estructura de Archivos
```
phantom-brain/
├── phantom_brain.py          # Sistema principal de análisis
├── sub_ghz_parser.py         # Parser Sub-GHz
├── sub_ghz_analyzer.py       # Analyzer patrones Sub-GHz
├── nfc_parser.py             # Parser NFC
├── nfc_analyzer.py           # Analyzer vulnerabilidades NFC
├── pcap_parser_v2.py         # Parser PCAP WPA2
├── server.py                 # Flask API (Raspberry Pi)
├── cardputer_dashboard.ino   # Firmware Cardputer (En desarrollo)
├── 893LM_7359_1.sub          # Captura Sub-GHz ejemplo
├── 893LM_7359_2.sub          # Captura Sub-GHz ejemplo
├── Sube.nfc                  # Captura NFC ejemplo
├── *.pcap                    # Capturas WPA2 ejemplos
├── .gitignore                # Excluye reportes generados
└── README.md                 # Este archivo
```

---

## 🔧 Requisitos

### **Windows (Para análisis)**
- Python 3.11+
- Ollama (para IA local)
- Scapy, requests, flask

### **Flipper Zero (Captura)**
- Sub-GHz, NFC habilitados
- Archivos: .sub, .nfc

### **Cardputer (Dashboard)**
- M5Stack firmware
- WiFi integrado
- Batería 2000 mAh (7-10 días)

### **Raspberry Pi (Base - Futuro)**
- Kali Linux
- Python 3.11+
- Flask, Scapy, requests
- Conexión Ethernet/WiFi permanente

### **Pineapple (Captura WiFi)**
- Marauder/Evil Twin
- Archivos: .pcap, .log

---

## 📊 Modelos IA

- **phi3:mini** - Rápido, análisis básico (~10 segundos)
- **mistral:7b-instruct** - Detallado, recomendado (~30 segundos)

Ambos ejecutan **100% offline** con Ollama.

---

## 🎯 Casos de Uso

### **Operación de Campo**
```
1. Captura con Flipper (Sub-GHz, NFC)
2. Visualiza en Cardputer (reportes guardados)
3. De vuelta a base → Envía a Raspberry
4. Raspberry procesa → Cardputer visualiza resultados
```

### **Laboratorio/Oficina**
```
1. Raspberry siempre encendida (análisis en vivo)
2. Múltiples Flipper capturando
3. Cardputer como dashboard central
4. Reportes automáticos en tiempo real
```

### **Análisis Offline (PC)**
```
1. Descarga archivos de Flipper/Pineapple a Windows
2. Ejecuta PHANTOM BRAIN
3. Genera reportes
4. Visualiza en Cardputer (opcional)
```

---

## 📝 Ejemplos de Uso
```bash
# Análisis en Windows
python phantom_brain.py
# Opción 4 → Sub-GHz
# Opción 5 → NFC
# Opción 6 → WPA2

# Análisis directo
python sub_ghz_analyzer.py
python nfc_analyzer.py
python pcap_parser_v2.py

# Servidor Raspberry (futuro)
python server.py
# Escucha en http://0.0.0.0:5000
```

---

## ⚠️ Disclaimer

Este proyecto es para entornos de laboratorio autorizados únicamente.

---

## 📌 Versiones

| Versión | Fecha | Features |
|---------|-------|----------|
| 0.5 | 26/02/2026 | WiFi, Sub-GHz, NFC, WPA2 completos |
| 0.6 (EN PROG) | TBD | Cardputer Dashboard |
| 0.7 | TBD | Raspberry Pi + Flask |
| 1.0 | TBD | Demo final + Community |

---

**Autor:** Otto&Rocky  
**Comunidad:** AI Tinkerers  
**Repo:** https://github.com/OttoyRocky/phantom-brain