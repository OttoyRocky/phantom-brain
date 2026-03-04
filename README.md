# PHANTOM BRAIN v0.6
## Sistema de Análisis Ofensivo Offline con IA y Hardware Real

Herramienta modular de pentesting que integra análisis de seguridad para WiFi, Sub-GHz, NFC/RFID y WPA2 usando IA local (Ollama). Sin APIs externas, 100% offline.

---

## Arquitectura del Sistema

```
CAMPO (Móvil):
┌──────────────────┐
│  Flipper Zero    │ ──→ Sub-GHz (.sub), NFC (.nfc), WiFi scanning
└──────────────────┘
┌──────────────────┐
│  WiFi Pineapple  │ ──→ WPA2 Handshakes (.pcap), deauth, PMKID
└──────────────────┘
┌──────────────────┐
│  Proxmark3       │ ──→ RFID/NFC avanzado (EM410x, MIFARE, EMV)
└──────────────────┘

BASE (Fija):
┌──────────────────────┐
│  Windows PC          │ ──→ PHANTOM BRAIN CLI + Flask API
│  Python 3.14 + Ollama│     Análisis completo, reportes automáticos
└──────────────────────┘
┌──────────────────────┐
│  Raspberry Pi 4      │ ──→ Servidor centralizado (en desarrollo)
│  Kali Linux + Ollama │     Flask API, procesa capturas remotas
└──────────────────────┘
```

---

## Features Completados

### WiFi / Marauder
- Parser de logs Marauder
- Detección de redes WPS vulnerables
- Identificación de redes ocultas
- Estadísticas de seguridad

### Sub-GHz / Flipper Zero
- Parser de archivos `.sub` (`sub_ghz_parser.py`)
- Extracción: protocolo, frecuencia, keys, packets
- Soporta: Security+ 2.0, Rolling Code, Fixed Code
- Analyzer de patrones entre capturas (`sub_ghz_analyzer.py`)

### NFC / Flipper Zero + Proxmark3
- Parser de archivos `.nfc` (`nfc_parser.py`)
- Soporta: Mifare Classic, Mifare Plus, NTAG, FeliCa
- Analyzer de vulnerabilidades (`nfc_analyzer.py`)
- Detección: Darkside, Hardnested, Reader Auth Bypass
- Análisis especial para SUBE (transporte público)
- Parser de output Proxmark3 (`proxmark_parser.py`)

### WPA2 / WiFi Pineapple
- Parser PCAP con Scapy (`pcap_parser_v2.py`)
- Extracción: BSSID, SSID, frames EAPOL, PMKID
- Validación de handshakes completos
- Pipeline completo: `hcxpcapngtool` → `hashcat -m 22000`

### Base de Datos y Reportes
- SQLite para historial de análisis (`db_manager.py`)
- Reportes en texto plano con timestamp
- Búsqueda por UID/BSSID, filtro por nivel de riesgo
- Estadísticas de análisis

### Flask API REST
- `flask_api.py` operativo en puerto 5000
- `GET /status` — verifica Ollama y modelos disponibles
- `POST /upload` — recibe archivos `.pcap`, `.nfc`, `.sub`
- `POST /analyze` — analiza con Ollama y guarda en SQLite
- `GET /analysis/<id>` — consulta análisis guardado por ID

---

## Modelos IA Soportados

| Modelo | Velocidad | Recomendado para |
|--------|-----------|-----------------|
| `phi3:mini` | ~10s | Raspberry Pi 4 (4GB RAM) |
| `mistral:7b-instruct` | ~30s | Análisis completo, comandos precisos |
| `deepseek-r1:7b` | ~45s | Análisis detallado, mitigaciones |

Todos ejecutan **100% offline** con Ollama.

---

## Estructura de Archivos

```
phantom-brain/
├── phantom_brain.py          # CLI principal - punto de entrada
├── flask_api.py              # API REST Flask
├── db_manager.py             # SQLite - historial de reportes
├── pcap_parser_v2.py         # Parser WPA2/PCAP
├── proxmark_parser.py        # Parser output Proxmark3
├── nfc_parser.py             # Parser archivos .nfc Flipper
├── nfc_analyzer.py           # Analyzer vulnerabilidades NFC
├── sub_ghz_parser.py         # Parser archivos .sub Flipper
├── sub_ghz_analyzer.py       # Analyzer patrones Sub-GHz
├── cardputer_dashboard.py    # Dashboard para M5Stack Cardputer
├── proxmark_launch.bat       # Script lanzador Proxmark3 (Windows)
├── config.yaml.example       # Plantilla de configuración
├── requirements.txt          # Dependencias Python
├── reportes/                 # Reportes generados (ignorado en git)
├── pcap/                     # Capturas WPA2 (ignorado en git)
└── .cursorrules              # Contexto para Cursor AI
```

---

## Instalación

```bash
# Clonar repo
git clone https://github.com/OttoyRocky/phantom-brain.git
cd phantom-brain

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Instalar dependencias
pip install -r requirements.txt

# Copiar y ajustar configuración
cp config.yaml.example config.yaml

# Instalar Ollama y descargar modelo
ollama pull mistral:7b-instruct
```

### Raspberry Pi (Kali Linux)
```bash
# Configurar Ollama con modelos en disco externo
echo 'export OLLAMA_MODELS=/media/kali/discoexterno/ollama' >> ~/.zshrc
source ~/.zshrc
ollama pull phi3:mini

# Clonar repo en disco externo
cd /media/kali/discoexterno
git clone https://github.com/OttoyRocky/phantom-brain.git
```

---

## Uso

```bash
# Análisis interactivo (CLI)
python phantom_brain.py

# API REST
python flask_api.py
# Escucha en http://127.0.0.1:5000

# Verificar API
curl http://127.0.0.1:5000/status

# Enviar archivo para análisis
curl -X POST http://127.0.0.1:5000/upload \
  -F "file=@captura.pcap"

curl -X POST http://127.0.0.1:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"tipo": "pcap", "datos": {"file_path": "captura.pcap"}}'
```

---

## Flujos de Trabajo

**Análisis local (Windows):**
```
Flipper/Pineapple/Proxmark → USB → Windows PC
                                        ↓
                              python phantom_brain.py
                                        ↓
                              Reporte en reportes/
```

**Servidor centralizado (Raspberry Pi - en desarrollo):**
```
Flipper/Pineapple (campo)
        ↓
  De vuelta a casa
        ↓
  POST /upload → Raspberry Pi
        ↓
  POST /analyze → Ollama local
        ↓
  GET /analysis/<id> → Reporte
```

---

## Roadmap

| Versión | Estado | Features |
|---------|--------|----------|
| 0.1-0.3 | ✅ | WiFi / Marauder |
| 0.4 | ✅ | Sub-GHz + NFC/RFID |
| 0.5 | ✅ | WPA2 Handshakes + Proxmark3 |
| 0.6 | ✅ | SQLite + Flask API + deepseek-r1:7b |
| 0.7 | 🔄 | Raspberry Pi operativa + Flask API conectada |
| 1.0 | ⏳ | Testing completo hardware real + demo |

---

## Requisitos

**Windows:**
- Python 3.11+
- Ollama
- `pip install -r requirements.txt`

**Raspberry Pi:**
- Kali Linux
- Python 3.11+
- Ollama (modelos en disco externo recomendado)
- Entorno virtual con dependencias

---

## Disclaimer

Este proyecto es para entornos de laboratorio autorizados únicamente.

---

**Autor:** Otto & Rocky  
**Comunidad:** AI Tinkerers  
**Repo:** https://github.com/OttoyRocky/phantom-brain
