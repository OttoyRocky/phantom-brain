# PHANTOM BRAIN v0.9

> ⚠️ **Proyecto experimental — no para uso en producción.**
> El análisis con IA asiste al investigador humano; no reemplaza una auditoría manual. Siempre verifica los hallazgos de forma independiente.

## Lo que ES y NO ES Phantom Brain

| ✅ Lo que ES | ❌ Lo que NO ES |
|---|---|
| Analizador automático que estructura hallazgos de capturas | Un reemplazo de Wireshark, bettercap o aircrack-ng |
| Generador de reportes con IA (offline, LLM local) | Un pentester autónomo |
| Orquestador entre herramientas hardware (Flipper, Pineapple, Proxmark) | Una herramienta de seguridad lista para producción |
| Plataforma de investigación y aprendizaje | Un sustituto de auditoría manual |
| 100% offline — sin exfiltración de datos | Dependiente de la nube o APIs |

> 💡 Cada reporte generado por IA debe tratarse como un **punto de partida**, no como un veredicto final.
> Los LLM pueden alucinar vulnerabilidades. La salida estructurada de los parsers (sin IA) es siempre más confiable.

> **Offline AI-powered pentesting analysis tool with real hardware integration**
>
> Local LLM analysis (via Ollama) for WiFi, Sub-GHz, NFC/RFID and WPA2 captures — no internet required, no cloud APIs, 100% offline.
> El LLM principal corre en una PC con Windows. La Raspberry Pi actúa como nodo secundario liviano (captura en vivo + phi3:mini únicamente).

**Hardware supported:** Flipper Zero · WiFi Pineapple MK7 · Proxmark3 · Raspberry Pi 4 (Kali Linux) · Atheros AR9271

**Models:** `mistral:7b-instruct` · `deepseek-r1:7b` · `phi3:mini`

**License:** GPL-3.0 | **Author:** Otto | **Community:** AI Tinkerers

---

# PHANTOM BRAIN v0.9
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

BASE — NODO PRINCIPAL (requerido para funcionalidad completa):
┌──────────────────────────────────────────────────────┐
│  PC con Windows (o Linux de escritorio)              │
│  Python 3.11+ · Ollama · Flask API                  │
│  Modelos: mistral:7b-instruct, deepseek-r1:7b        │
│  ► PHANTOM BRAIN CLI, análisis completo, reportes    │
└──────────────────────────────────────────────────────┘

BASE — NODO SECUNDARIO (opcional, liviano):
┌──────────────────────────────────────────────────────┐
│  Raspberry Pi 4 (Kali Linux)                         │
│  Ollama · Atheros AR9271                             │
│  Solo corre: phi3:mini (mistral:7b es demasiado pesado para la Pi) │
│  ► Captura WiFi en vivo · inferencia local liviana   │
│  NOTA: se conecta al Ollama de la PC para modelos pesados │
└──────────────────────────────────────────────────────┘
```

> ⚠️ **Nota de arquitectura:** La Raspberry Pi **no** ejecuta el stack completo de Phantom Brain de forma autónoma. Para análisis completo con `mistral:7b-instruct` o `deepseek-r1:7b`, se requiere una PC con Ollama. La Pi funciona como nodo de captura y puede correr `phi3:mini` para inferencia liviana offline únicamente.

### Pipeline de Análisis (v0.9)

```
input → classifier → tool.run() → ToolResult(risk, findings) → Ollama
```

Cada tipo de captura pasa por su tool específico antes de llegar al LLM. El tool estructura el resultado con nivel de riesgo y hallazgos clave, enriqueciendo el contexto que recibe Ollama.

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

### Sistema de Tools (nuevo en v0.9)
- `tools/base_tool.py` — contrato unificado `BaseTool` + `ToolResult`
- `ToolResult` con campos `risk` (CRITICO/ALTO/MEDIO/BAJO) y `findings` estructurados
- `tools/registry.py` — registro central, despacha el tool correcto por tipo
- `tools/classifier.py` — auto-detección de tipo por extensión y contenido
- 14/14 tests pasando con fixtures reales (`pytest tests/test_tools.py`)

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

| Modelo | RAM mínima | Almacenamiento | Velocidad (CPU) | Ideal para | Nodo |
|--------|------------|----------------|-----------------|-----------|------|
| `phi3:mini` | 4 GB | ~2.3 GB | ~5 min | Triage rápido, inferencia liviana, funciona en Pi — razonamiento limitado | Raspberry Pi / PC |
| `mistral:7b-instruct` | 8 GB | ~4.1 GB | ~30 s (PC) | **Recomendado.** Análisis completo, comandos precisos y accionables, mejor ratio calidad/velocidad | Solo PC |
| `deepseek-r1:7b` | 8 GB | ~4.5 GB | ~45 s (PC) | Análisis en profundidad, pasos de mitigación detallados, razonamiento paso a paso | Solo PC |

> **Nota:** Benchmarks medidos en PC con 32 GB RAM (solo CPU, sin GPU). La aceleración por GPU (CUDA/ROCm) reduce significativamente los tiempos. La Pi solo puede correr `phi3:mini` de forma estable — `mistral:7b` causa throttling térmico y OOM en Pi 4B 8GB.

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
├── tools/                    # Sistema de tools modular (v0.9)
│   ├── base_tool.py          # BaseTool + ToolResult con risk/findings
│   ├── classifier.py         # Auto-detección de tipo de captura
│   ├── registry.py           # Registro central de tools
│   ├── proxmark_tool.py      # Tool Proxmark3
│   ├── nfc_tool.py           # Tool NFC
│   ├── wpa2_tool.py          # Tool WPA2/PCAP
│   └── subghz_tool.py        # Tool Sub-GHz
├── tests/                    # Tests automatizados (14/14 pasando)
│   └── test_tools.py
├── prompts/                  # System prompts separados por tipo
│   └── system_prompts.py
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

# Correr tests
python -m pytest tests/test_tools.py -v
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
10. Captura en vivo WiFi - Atheros AR9271 (solo Raspberry Pi)
11. Generar wordlist inteligente con IA (basada en SSID)
```

### Generación de Wordlists Inteligente con IA

- Genera diccionarios personalizados usando IA local (Ollama) a partir del SSID objetivo.
- Entrada: SSID + contexto opcional (país, ISP, año, etc).
- Salida: archivo `wordlist_<SSID>_<timestamp>.txt` en el directorio de trabajo actual.
- Patrones generados: variantes del SSID, años 2020-2025, fechas argentinas, referencias típicas (ISP, fútbol, eventos), y símbolos como `!@#`.
- Muestra un comando `hashcat -m 22000 captura.hc22000 wordlist_<SSID>_<timestamp>.txt` listo para usar al final.

---

## Roadmap

| Versión | Estado | Features |
|---------|--------|----------|
| 0.1-0.3 | ✅ | WiFi / Marauder |
| 0.4 | ✅ | Sub-GHz + NFC/RFID |
| 0.5 | ✅ | WPA2 Handshakes + Proxmark3 |
| 0.6 | ✅ | SQLite + Flask API + deepseek-r1:7b |
| 0.7 | ✅ | Raspberry Pi operativa + streaming + timeout |
| 0.8 | ✅ | Sistema de tools modular + ToolResult(risk/findings) + pipeline completo + 14/14 tests |
| 0.9 | ✅ | Atheros AR9271 captura en vivo + generación de wordlists IA + demo completo |
| 1.0 | ⏳ | Testing completo hardware real + release |

---

## Requisitos

## Requisitos

**PC con Windows (Nodo principal — requerido para funcionalidad completa):**
- Python 3.11+
- Ollama con `mistral:7b-instruct` (recomendado) o `deepseek-r1:7b`
- 8 GB RAM mínimo · 16 GB+ recomendado
- `pip install -r requirements.txt`

**Raspberry Pi 4 (Nodo secundario — opcional):**
- Kali Linux
- Python 3.11+
- Ollama con `phi3:mini` únicamente (modelos más pesados no son compatibles)
- Modelo de 8 GB RAM recomendado · 2 GB swap requerido
- Adaptador Atheros AR9271 para captura en vivo (Opción 10)

---

## Disclaimer

Este proyecto es para entornos de laboratorio autorizados únicamente. El uso de estas herramientas en redes o dispositivos sin autorización explícita es ilegal.

---

**Autor:** Otto
**Comunidad:** AI Tinkerers
**Repo:** https://github.com/OttoyRocky/phantom-brain

