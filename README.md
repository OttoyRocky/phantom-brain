\# 🧠 PHANTOM BRAIN



Red portátil de reconocimiento inteligente con IA offline.



\## ¿Qué es?

PHANTOM BRAIN es un sistema que une hardware de pentesting con una IA local

para analizar datos de campo, sugerir vectores de ataque y generar reportes

automáticos — sin internet, sin APIs externas, sin mandar tus datos a ningún servidor.



## Hardware del proyecto
- Flipper Zero con WiFi board (Momentum) + AIO board v1.4
- WiFi Pineapple Mark VII
- Cardputer M5Stack con Bruce
- DSTIKE Deauther Watch (ESP8266 + ATmega32U4)
- Proxmark3 Kit
- M5Stack M5StickC Plus2
- Raspberry Pi 4B con Kali Linux
- USB WiFi Atheros AR9271 con antena 6dBi (modo monitor + packet injection)
- PC Windows 11 con WSL (cerebro central)



\## Modos de operación



\### 🎒 Modo Viaje

Flipper + Deauther + Cardputer capturan datos en campo.

Los archivos se guardan y se analizan al volver a conectarse a la PC.



\### 🖥️ Modo Completo

Todos los dispositivos activos. Análisis en tiempo real desde la PC.



\## Stack tecnológico

\- Ollama (motor LLM local)

\- Modelo: mistral:7b-instruct

\- Python 3.14

\- Sin dependencias de internet



\## Instalación



\### 1. Instalar Ollama

Descargar desde https://ollama.com/download e instalar.



\### 2. Bajar el modelo



\### 3. Instalar dependencias Python



\### 4. Ejecutar



\## Uso

Al ejecutar, el script ofrece dos modos:

1\. \*\*Manual\*\* — pegás el output directamente en la terminal

2\. \*\*Archivo\*\* — le das un archivo .txt con el output de tu herramienta



El análisis se guarda automáticamente como `reporte\_FECHA\_HORA.txt`



\## Estado del proyecto

\- \[x] IA local funcionando offline

\- \[x] Análisis de outputs de nmap

\- \[x] Lectura automática de archivos

\- \[x] Reportes automáticos con timestamp

\- \[ ] Integración con Flipper Zero

\- \[ ] Integración con WiFi Pineapple

\- \[ ] Integración con Proxmark3

\- \[ ] Dashboard visual en M5Stack

\- \[ ] Modo Raspberry Pi como servidor de campo



\## Autor

neurobelg — Proyecto presentado en AI Tinkerers

