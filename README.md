# PHANTOM BRAIN v0.9

> **Offline AI-powered pentesting analysis tool with real hardware integration**
>
> Local LLM analysis (via Ollama) for WiFi, Sub-GHz, NFC/RFID and WPA2 captures — no internet required, no cloud APIs, 100% offline.

**Hardware supported:** Flipper Zero · WiFi Pineapple MK7 · Proxmark3 · Raspberry Pi 4 (Kali Linux) · Atheros AR9271

**Models:** `mistral:7b-instruct` · `deepseek-r1:7b` · `phi3:mini`

**License:** GPL-3.0 | **Author:** Otto | **Community:** AI Tinkerers

> ⚠️ **Experimental project — not for production use.**
> AI analysis assists human researchers; it does not replace manual auditing. Always verify findings independently.

---

## What Phantom Brain IS and IS NOT

| ✅ What it IS | ❌ What it is NOT |
|---|---|
| Automatic analyzer that structures capture findings | A replacement for Wireshark, bettercap, or aircrack-ng |
| AI-powered report generator (offline, local LLM) | An autonomous pentester |
| Orchestrator between hardware tools (Flipper, Pineapple, Proxmark) | A production-ready security tool |
| Research and learning platform | A substitute for manual auditing |
| 100% offline — no data exfiltration | Cloud-dependent or API-reliant |

> 💡 Every AI-generated report should be treated as a **starting point**, not a final verdict.
> LLMs can hallucinate vulnerabilities. Structured parser output (without AI) is always more reliable.

---

## System Architecture

\`\`\`
FIELD (Mobile):
┌──────────────────┐
│  Flipper Zero    │ ──► Sub-GHz (.sub), NFC (.nfc), WiFi scanning
└──────────────────┘
┌──────────────────┐
│  WiFi Pineapple  │ ──► WPA2 Handshakes (.pcap), deauth, PMKID
└──────────────────┘
┌──────────────────┐
│  Proxmark3       │ ──► Advanced RFID/NFC (EM410x, MIFARE, EMV)
└──────────────────┘

BASE (Fixed):
┌──────────────────────┐
│  Windows PC          │ ──► PHANTOM BRAIN CLI + Flask API
│  Python 3.11+ Ollama │     Full analysis, automatic reports
└──────────────────────┘
┌──────────────────────┐
│  Raspberry Pi 4      │ ──► Secondary node with phi3:mini
│  Kali Linux + Ollama │     Atheros AR9271 for live capture (v0.9)
└──────────────────────┘
\`\`\`

### Analysis Pipeline (v0.9)

\`\`\`
input → classifier → tool.run() → ToolResult(risk, findings) → Ollama
\`\`\`

Each capture type goes through its specific tool before reaching the LLM. The tool structures the output with a risk level and key findings, enriching the context sent to Ollama.

---

## Features

### WiFi / Marauder
- Marauder log parser
- Detection of vulnerable WPS networks
- Identification of hidden networks
- Security statistics

### Sub-GHz / Flipper Zero
- \`.sub\` file parser (\`sub_ghz_parser.py\`)
- Extraction: protocol, frequency, keys, packets
- Supports: Security+ 2.0, Rolling Code, Fixed Code
- Pattern analyzer across captures (\`sub_ghz_analyzer.py\`)

### NFC / Flipper Zero + Proxmark3
- \`.nfc\` file parser (\`nfc_parser.py\`)
- Supports: MIFARE Classic 1K/4K, MIFARE Plus, NTAG, FeliCa, EMV
- Vulnerability analyzer (\`nfc_analyzer.py\`)
- Detection: Darkside, Hardnested, Reader Auth Bypass
- Special analysis for SUBE (public transport)
- Proxmark3 output parser (\`proxmark_parser.py\`)

### WPA2 / WiFi Pineapple
- PCAP parser with Scapy (\`pcap_parser_v2.py\`)
- Extraction: BSSID, SSID, EAPOL frames, PMKID
- Validation of complete handshakes
- Full pipeline: \`hcxpcapngtool\` → \`hashcat -m 22000\`

### Tools System (v0.9)
- \`tools/base_tool.py\` — unified \`BaseTool\` + \`ToolResult\` contract
- \`ToolResult\` with \`risk\` (CRITICO/ALTO/MEDIO/BAJO) and structured \`findings\`
- \`tools/registry.py\` — central registry, dispatches the correct tool by type
- \`tools/classifier.py\` — auto-detection by extension and content
- 14/14 tests passing with real fixtures (\`pytest tests/test_tools.py\`)

### Database and Reports
- SQLite for analysis history (\`db_manager.py\`)
- Plain-text reports with timestamp
- Search by UID/BSSID, filter by risk level
- Analysis statistics

### Flask API REST
- \`flask_api.py\` running on port 5000
- \`GET /status\` — checks Ollama and available models
- \`POST /upload\` — receives \`.pcap\`, \`.nfc\`, \`.sub\` files
- \`POST /analyze\` — analyzes with Ollama and saves to SQLite
- \`GET /analysis/<id>\` — queries saved analysis by ID

---

## Supported AI Models

| Model | Speed | Recommended for |
|--------|-----------|-----------------|
| \`phi3:mini\` | ~5min | Raspberry Pi 4 (8GB RAM + swap) |
| \`mistral:7b-instruct\` | ~30s | Full analysis, precise commands |
| \`deepseek-r1:7b\` | ~45s | Detailed analysis, mitigations |

All run **100% offline** with Ollama.

---

## File Structure

\`\`\`
phantom-brain/
├── phantom_brain.py          # Main CLI - entry point
├── flask_api.py              # API REST Flask
├── db_manager.py             # SQLite - report history
├── pcap_parser_v2.py         # Parser WPA2/PCAP
├── proxmark_parser.py        # Parser output Proxmark3
├── nfc_parser.py             # Flipper .nfc file parser
├── nfc_analyzer.py           # NFC vulnerability analyzer
├── sub_ghz_parser.py         # Flipper .sub file parser
├── sub_ghz_analyzer.py       # Sub-GHz pattern analyzer
├── exploit_guide.py          # Exploitation guides without AI
├── proxmark_launch.bat       # Proxmark3 launcher script (Windows)
├── config.yaml.example       # Configuration template
├── requirements.txt          # Python dependencies
├── tools/                    # Modular tools system (v0.9)
│   ├── base_tool.py          # BaseTool + ToolResult with risk/findings
│   ├── classifier.py         # Capture type auto-detection
│   ├── registry.py           # Central tools registry
│   ├── proxmark_tool.py      # Tool Proxmark3
│   ├── nfc_tool.py           # Tool NFC
│   ├── wpa2_tool.py          # Tool WPA2/PCAP
│   └── subghz_tool.py        # Tool Sub-GHz
├── tests/                    # Automated tests (14/14 passing)
│   └── test_tools.py
├── prompts/                  # System prompts separated by type
│   └── system_prompts.py
├── reportes/                 # Generated reports (ignored in git)
├── pcap/                     # WPA2 captures (ignored in git)
└── archive/                  # Previous versions
\`\`\`

---

## Installation

\`\`\`bash
git clone https://github.com/OttoyRocky/phantom-brain.git
cd phantom-brain
pip install -r requirements.txt
cp config.yaml.example config.yaml
ollama pull mistral:7b-instruct
\`\`\`

### Raspberry Pi (Kali Linux)
\`\`\`bash
echo 'export OLLAMA_MODELS=/media/kali/discoexterno/ollama' >> ~/.zshrc
source ~/.zshrc
ollama pull phi3:mini

sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

cd /media/kali/discoexterno
git clone https://github.com/OttoyRocky/phantom-brain.git
\`\`\`

---

## Usage

\`\`\`bash
python phantom_brain.py
python flask_api.py
curl http://127.0.0.1:5000/status
python -m pytest tests/test_tools.py -v
\`\`\`

### Main Menu
\`\`\`
1.  Paste text manually
2.  Read generic file (scan.txt, nmap, etc)
3.  Read Flipper Zero / Marauder log (.log)
4.  Analyze Sub-GHz captures (.sub)
5.  Analyze NFC captures (.nfc)
6.  Analyze WPA2 Handshake captures (.pcap)
7.  Analyze Proxmark3 capture (paste output directly)
8.  View report history
9.  Exploitation guides (without AI analysis)
10. Live WiFi capture - Atheros AR9271 (Raspberry Pi only)
11. Generate smart wordlist with AI (SSID-based)
\`\`\`

### Smart Wordlist Generation with AI
- Generates personalized dictionaries using local AI (Ollama) from the target SSID.
- Input: SSID + optional context (country, ISP, year, etc).
- Output: \`wordlist_<SSID>_<timestamp>.txt\` in the current working directory.
- Patterns: SSID variants, years 2020-2025, Argentinian context (football, dates, ISPs), symbols like \`!@#\`.
- Prints ready-to-use command: \`hashcat -m 22000 captura.hc22000 wordlist_<SSID>_<timestamp>.txt\`

---

## Roadmap

| Version | Status | Features |
|---------|--------|----------|
| 0.1-0.3 | ✅ | WiFi / Marauder |
| 0.4 | ✅ | Sub-GHz + NFC/RFID |
| 0.5 | ✅ | WPA2 Handshakes + Proxmark3 |
| 0.6 | ✅ | SQLite + Flask API + deepseek-r1:7b |
| 0.7 | ✅ | Raspberry Pi operational + streaming + timeout |
| 0.8 | ✅ | Modular tools system + ToolResult(risk/findings) + 14/14 tests |
| 0.9 | ✅ | Atheros AR9271 live capture + AI wordlist + dual README |
| **1.0** | ⏳ | Option 12 (facts-only mode) · post-AI validation · benchmarks · asciinema demo |

---

## Requirements

**Windows:** Python 3.11+ · Ollama · \`pip install -r requirements.txt\`

**Raspberry Pi:** Kali Linux · Python 3.11+ · Ollama · 2GB swap recommended

---

## Disclaimer

This project is intended for **authorized lab environments only**. Using these tools against networks or devices without explicit written authorization is illegal and unethical.

> AI-generated analysis is not a substitute for professional security assessment. All findings must be verified manually.

---

**Author:** Otto | **Community:** AI Tinkerers | **Repo:** https://github.com/OttoyRocky/phantom-brain

For Spanish version, see [README.es.md](README.es.md)
