# PHANTOM BRAIN v0.5
## Sistema de Análisis Ofensivo Offline con IA y Hardware Real

Herramienta modular de pentesting que integra análisis de seguridad para WiFi, Sub-GHz, NFC/RFID y WPA2 usando IA local (Ollama).

---

## 📋 Arquitectura del Sistema
```
OPERACIONES DE CAMPO (Móviles):
┌──────────────────┐
│  Flipper Zero    │ ──► Captura: Sub-GHz, NFC, WiFi Scanning
│                  │     Batería: 40+ horas
└──────────────────┘

┌──────────────────┐
│  Pineapple       │ ──► Captura: WPA2 Handshakes, Evil Twin
│  WiFi Hacking    │     Batería: 6-8 horas (con powerbank)
└──────────────────┘

┌──────────────────┐
│  Proxmark3       │ ──► Captura: RFID/NFC avanzado
│  (USB)           │     Análisis de tags complejos
└──────────────────┘

OPERACIONES DE BASE (Fijas):
┌──────────────────┐
│   Windows PC     │ ──► PHANTOM BRAIN CLI
│   + Python 3.11  │     Análisis completo
│   + Ollama       │     Reportes automáticos
└──────────────────┘

┌──────────────────────┐
│  Raspberry Pi        │ ──► Servidor centralizado (Futuro)
│  Kali Linux          │     Flask API REST
│  PHANTOM BRAIN       │     Procesa datos en vivo
│  (enchufada 24/7)    │     Captura WiFi con Atheros
└──────────────────────┘
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
- Frecuencias coincidentes

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

---

## 🚀 Próximos Pasos (Roadmap v0.6+)

### **5. Raspberry Pi - Servidor Base (EN PROGRESO)**
- Kali Linux + Flask
- Servidor API REST (/api/upload/*, /api/reports, /api/status)
- Recibe datos de Flipper/Pineapple
- Procesa con PHANTOM BRAIN
- Captura WiFi simultánea con Atheros AR9271
- Base de datos SQLite/JSON

### **6. Integración Completa (Próximo)**
- Scripts de upload automático
- Sincronización WiFi Flipper ↔ Raspberry
- WebSocket para datos en tiempo real
- Dashboard web (Raspberry)

### **7. Demo Final + Community (Final)**
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
├── server.py                 # Flask API (Raspberry Pi - Futuro)
├── 893LM_7359_1.sub          # Captura Sub-GHz ejemplo
├── 893LM_7359_2.sub          # Captura Sub-GHz ejemplo
├── Sube.nfc                  # Captura NFC ejemplo
├── *.pcap                    # Capturas WPA2 ejemplos
├── archive/                  # Hardware desactivado temporalmente
│   ├── cardputer_dashboard.py
│   └── cardputer_dashboard_v2.py
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

### **Pineapple (Captura WiFi)**
- Marauder/Evil Twin
- Archivos: .pcap, .log

### **Proxmark3 (Captura RFID)**
- Firmware actualizado
- Archivos de captura compatible

### **Raspberry Pi (Base - Futuro)**
- Kali Linux
- Python 3.11+
- Flask, Scapy, requests
- Atheros AR9271 (WiFi)
- Conexión Ethernet permanente

---

## 📊 Modelos IA Soportados

- **phi3:mini** - Rápido, análisis básico (~10 segundos)
- **mistral:7b-instruct** - Detallado, recomendado (~30 segundos)

Ambos ejecutan **100% offline** con Ollama.

---

## 🏠 Distribución Física (Setup Real)

### Hardware por Ubicación

**UBICACIÓN 1: PC Windows (Análisis)**
- Windows 10/11
- Python 3.11+
- Ollama + mistral:7b
- PHANTOM BRAIN CLI
- USB para Flipper/Pineapple/Proxmark

**UBICACIÓN 2: Raspberry Pi (Servidor Fijo)**
- Kali Linux
- Python 3.11+
- Flask API (Futuro)
- Atheros AR9271 (WiFi Marauder)
- Ethernet permanente
- Procesamiento 24/7

**UBICACIÓN 3: Campo (Móvil)**
- Flipper Zero (Sub-GHz, NFC)
- WiFi Pineapple (WPA2)
- Proxmark3 (RFID avanzado)

### Flujos de Datos Operativos

**Opción 1: Análisis Local (Ahora - Windows)**
```
Flipper (campo) → USB → Windows PC
                    ↓
                python phantom_brain.py
                    ↓
                Reportes locales
```

**Opción 2: Servidor Centralizado (Futuro - Raspberry)**
```
Flipper/Pineapple (campo)
        ↓
    De vuelta a casa
        ↓
    Conecta a Raspberry (USB/WiFi)
        ↓
    Raspberry procesa 24/7
        ↓
    Tu PC accede vía WiFi (API)
```

**Opción 3: Captura Continua (Avanzado)**
```
Raspberry:
├─ Terminal 1: python server.py (recibe datos)
└─ Terminal 2: marauder (captura WiFi viva)
        ↓
    Análisis en paralelo
        ↓
    Tu PC (remoto): Ver reportes vía HTTP
```

---

## 🎯 Casos de Uso

### **Escenario 1: Análisis de Campo Simple (Actual)**
```
1. Captura con Flipper (Sub-GHz, NFC, WiFi)
2. Regresas a casa con Windows PC
3. Conectas Flipper → USB
4. python phantom_brain.py
5. Análisis completo en 30 segundos
```

### **Escenario 2: Análisis de Base Centralizado (Futuro)**
```
1. Raspberry Pi siempre encendida
2. Flipper/Pineapple capturan en campo
3. Regresan y envían datos a Raspberry (WiFi/USB)
4. Raspberry procesa automáticamente
5. Reportes almacenados en servidor
```

### **Escenario 3: Operación Profesional (Avanzado)**
```
Múltiples Flipper + Pineapple (campo)
    ↓
Raspberry Pi (hub central)
    ├─→ Análisis paralelo
    ├─→ Base de datos consolidada
    └─→ API para acceso remoto
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
| 0.6 (EN PROG) | TBD | Raspberry Pi + Flask |
| 1.0 | TBD | Demo final + Community |

---

**Autor:** Otto&Rocky  
**Comunidad:** AI Tinkerers  
**Repo:** https://github.com/OttoyRocky/phantom-brain