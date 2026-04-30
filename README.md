# 🛡️ SIEM Local con IA — Ollama + LLaMA 3.1

SIEM (Security Information and Event Management) local, 100% privado, potenciado con inteligencia artificial. Corre completamente en tu PC sin mandar ningún dato a internet.

## ¿Qué hace?

- Monitorea eventos del **Windows Event Viewer** en tiempo real (System, Application, Security)
- Analiza los eventos con **IA local** (Ollama + LLaMA 3.1 8b) y clasifica severidad
- Detecta automáticamente eventos críticos: creación de usuarios, cambios de privilegios, fallos de autenticación
- Muestra todo en un **dashboard web** con tema oscuro
- Sistema de **gestión de tickets** con estados y comentarios
- **Notificaciones nativas de Windows** ante alertas HIGH o CRITICAL
- **Exportación de reportes en PDF**
- Indicador LIVE con contador de escaneos y próximo análisis

## Stack

- Python 3.x
- Ollama (LLaMA 3.1 8b)
- Windows Event Viewer API (PowerShell)
- HTML / JavaScript vanilla
- ReportLab (PDF)

## Requisitos

- Windows 10/11
- Python 3.x
- Ollama instalado → [ollama.com](https://ollama.com)
- 8GB RAM mínimo (recomendado 16GB)
- GPU NVIDIA recomendada (funciona también con CPU)

## Instalación

1. Cloná el repo
\\\
git clone https://github.com/TU_USUARIO/siem-local-ai
cd siem-local-ai
\\\

2. Instalá dependencias
\\\
py -m pip install reportlab
\\\

3. Bajá el modelo
\\\
ollama pull llama3.1:8b
\\\

4. Corré el SIEM (como Administrador)
\\\
py siem.py
\\\

5. Corré el dashboard (otra ventana)
\\\
py dashboard.py
\\\

6. Abrí el dashboard en tu navegador
\\\
http://localhost:8080
\\\

## Eventos monitoreados

| Event ID | Descripción | Severidad |
|----------|-------------|-----------|
| 4720 | Usuario creado | CRITICAL |
| 4732 | Usuario agregado a Administradores | CRITICAL |
| 4625 | Fallo de autenticación | HIGH |
| 4672 | Privilegios especiales asignados | HIGH |
| 4726 | Usuario eliminado | CRITICAL |
| 4728 | Usuario agregado a grupo global | CRITICAL |

## Estructura del proyecto

\\\
siem-local-ai/
├── siem.py          # Motor de monitoreo y análisis con IA
├── dashboard.py     # Servidor web del dashboard
├── index.html       # Frontend del dashboard
└── README.md
\\\

## Autor

Desarrollado como proyecto de aprendizaje en el marco del curso **IA Powered Security**.
