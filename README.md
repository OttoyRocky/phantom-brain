# PHANTOM BRAIN v0.8

> **Offline AI-powered pentesting analysis tool with real hardware integration**
> 
> Local LLM analysis (via Ollama) for WiFi, Sub-GHz, NFC/RFID and WPA2 captures — no internet required, no cloud APIs, 100% offline.

**Hardware supported:** Flipper Zero · WiFi Pineapple MK7 · Proxmark3 · Raspberry Pi 4 (Kali Linux) · Atheros AR9271

**Models:** `mistral:7b-instruct` · `deepseek-r1:7b` · `phi3:mini`

**License:** GPL-3.0 | **Author:** Otto | **Community:** AI Tinkerers

---

# PHANTOM BRAIN v0.8
## Sistema de Análisis Ofensivo Offline con IA y Hardware Real

Herramienta modular de pentesting que integra análisis de seguridad para WiFi, Sub-GHz, NFC/RFID y WPA2 usando IA local (Ollama). Sin APIs externas, 100% offline.

---

## Arquitectura del Sistema

```
CAMPO (Móvil):
┌──────────────────┐
│  Flipper Zero    │ ──► Sub-GHz (.sub), NFC (.nfc), WiFi scanning
└──────────────────┘
┌──────────────────┐
│  WiFi Pineapple  │ ──► WPA2 Handshakes (.pcap), deauth, PMKID
└──────────────────┘
┌──────────────────┐
│  Proxmark3       │ ──► RFID/NFC avanzado (EM410x, MIFARE, EMV)
└──────────────────┘

BASE (Fija):
┌──────────────────────┐
│  Windows PC          │ ──► PHANTOM BRAIN CLI + Flask API
│  Python 3.11+ Ollama │     Análisis completo, reportes automáticos
└──────────────────────┘
┌──────────────────────┐
│  Raspberry Pi 4      │ ──► Nodo secundario con phi3:mini
│  Kali Linux + Ollama │     Atheros AR9271 para captura en vivo (v0.8)
└──────────────────────┘
```

---

## Features

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
- Soporta: MIFARE Classic 1K/4K, MIFARE Plus, NTAG, FeliCa, EMV
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
| `phi3:mini` | ~5min | Raspberry Pi 4 (8GB RAM + swap) |
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
├── exploit_guide.py          # Guías de explotación sin IA
├── proxmark_launch.bat       # Script lanzador Proxmark3 (Windows)
├── config.yaml.example       # Plantilla de configuración
├── requirements.txt          # Dependencias Python
├── reportes/                 # Reportes generados (ignorado en git)
├── pcap/                     # Capturas WPA2 (ignorado en git)
└── archive/                  # Versiones anteriores
```

---

## Instalación

```bash
# Clonar repo
git clone https://github.com/OttoyRocky/phantom-brain.git
cd phantom-brain

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

# Swap permanente (recomendado para Pi 4B 8GB)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

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
```

### Menú principal
```
1. Pegar texto manualmente
2. Leer archivo genérico (scan.txt, nmap, etc)
3. Leer log de Flipper Zero / Marauder (.log)
4. Analizar capturas Sub-GHz (.sub)
5. Analizar capturas NFC (.nfc)
6. Analizar capturas WPA2 Handshakes (.pcap)
7. Analizar captura Proxmark3 (pegar output directo)
8. Ver historial de reportes
9. Guías de explotación (sin análisis IA)
```

---

## Roadmap

| Versión | Estado | Features |
|---------|--------|----------|
| 0.1-0.3 | ✅ | WiFi / Marauder |
| 0.4 | ✅ | Sub-GHz + NFC/RFID |
| 0.5 | ✅ | WPA2 Handshakes + Proxmark3 |
| 0.6 | ✅ | SQLite + Flask API + deepseek-r1:7b |
| 0.7 | ✅ | Raspberry Pi operativa + streaming + timeout |
| 0.8 | 🔄 | Atheros AR9271 captura en vivo + demo completo |
| 1.0 | ⏳ | Testing completo hardware real + release |

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
- 2GB swap recomendado

---

## Disclaimer

Este proyecto es para entornos de laboratorio autorizados únicamente. El uso de estas herramientas en redes o dispositivos sin autorización explícita es ilegal.

---

**Autor:** Otto
**Comunidad:** AI Tinkerers
**Repo:** https://github.com/OttoyRocky/phantom-brain
