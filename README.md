# SIEM Local con IA — Ollama + qwen2.5:3b

SIEM (Security Information and Event Management) local, 100% privado, potenciado con inteligencia artificial. Corre completamente en tu PC sin mandar ningún dato a internet.

## Arquitectura

```
src/agents/windows/agente_windows.py  ──┐
                                         ├──► src/server/siem_servidor.py ──► Ollama ──► Dashboard
src/agents/ubuntu/agente_ubuntu.py    ──┘
```

Cada agente recopila logs de su plataforma y los manda al servidor central cada 5 minutos. El servidor analiza con un **motor híbrido**: reglas Python deterministas como piso de severidad + IA local (qwen2.5:3b) para descripciones y recomendaciones.

## ¿Qué hace?

- Monitorea eventos del **Windows Event Viewer** en tiempo real (System, Application, Security)
- Monitorea logs de **Ubuntu Linux** (/var/log/auth.log, syslog, journald)
- Analiza con **motor híbrido** — Python detecta (confiable), IA describe (legible)
- Detecta automáticamente: creación de usuarios, cambios de privilegios, fallos de autenticación
- **File Integrity Monitoring (FIM)** — configurable desde el dashboard, sin tocar código
- Dashboard web con **identificación de origen** — cada alerta muestra si viene de Windows o Ubuntu
- Sistema de **gestión de tickets** con estados y comentarios
- **Notificaciones nativas de Windows** ante alertas HIGH/CRITICAL
- **Exportación de reportes en PDF**
- Autenticación con sesiones, cambio de contraseña forzado en primer login

## Stack

- Python 3.x
- Ollama (qwen2.5:3b — 1.9 GB VRAM, optimizado para GPU con 4 GB)
- Windows Event Viewer API (PowerShell)
- Linux logs (/var/log/auth.log, syslog, journald)
- HTML / JavaScript vanilla
- ReportLab (PDF)
- bcrypt (hashing de contraseñas)
- Windows Task Scheduler (autostart headless)
- systemd (Ubuntu autostart)

## Requisitos

### Servidor SIEM (Windows)
- Windows 10/11
- Python 3.x
- Ollama instalado → [ollama.com](https://ollama.com)
- 4 GB VRAM mínimo (GTX 1050 Ti o superior)

### Agente Ubuntu
- Ubuntu 20.04+
- Python 3.x
- Acceso a /var/log (sudo)
- Conectividad de red al servidor SIEM

## Instalación (Windows)

```bash
git clone https://github.com/facupasini7/siem-local-ai
cd siem-local-ai
pip install -r requirements.txt
ollama pull qwen2.5:3b
```

### Opción A — Autostart automático (recomendada)

```bash
# Instala tres tareas en el Programador de Tareas y crea acceso directo en el Escritorio
python install_services.py
```

El SIEM arrancará solo en cada login. Accedé desde `http://localhost:8080` o el acceso directo en el Escritorio.

Para desinstalar:
```bash
python uninstall_services.py
```

### Opción B — Manual (debug)

```bash
# Ventana 1 — dashboard
python run_dashboard.py

# Ventana 2 — servidor de análisis
python run_servidor.py

# Ventana 3 — agente Windows (como Administrador)
python run_agente.py
```

### Agente Ubuntu

```bash
# En la máquina Ubuntu
scp src/agents/ubuntu/agente_ubuntu.py facu@IP_UBUNTU:~/siem-agente/
```

Editá `SIEM_URL` en `agente_ubuntu.py` con la IP del servidor Windows e instalá como servicio systemd.

## Eventos monitoreados

### Windows
| Event ID | Descripción | Severidad |
|----------|-------------|-----------|
| 4720 | Usuario creado | CRITICAL |
| 4732 | Usuario agregado a Administradores | CRITICAL |
| 4625 | Fallo de autenticación | HIGH |
| 4672 | Privilegios especiales asignados | HIGH |
| 4726 | Usuario eliminado | CRITICAL |
| 4728 | Usuario agregado a grupo global | CRITICAL |
| 4663 | Acceso/modificación en carpeta FIM | HIGH |
| 4660 | Eliminación en carpeta FIM | CRITICAL |

### Linux (Ubuntu)
| Evento | Descripción | Severidad |
|--------|-------------|-----------|
| sshd Failed | Fallo de autenticación SSH | HIGH |
| sudo: auth failure | Escalada de privilegios fallida | HIGH |
| Invalid user | Usuario inválido en SSH | HIGH |
| OOM Killer | Proceso eliminado por falta de memoria | MEDIUM |

## Estructura del proyecto

```
siem-local-ai/
├── src/
│   ├── server/
│   │   ├── database.py        # SQLite: alertas, tickets, usuarios
│   │   ├── auth.py            # Login, sesiones, bcrypt
│   │   ├── dashboard.py       # Servidor HTTP del dashboard
│   │   └── siem_servidor.py   # Motor de análisis híbrido Python+IA
│   ├── agents/
│   │   ├── windows/
│   │   │   └── agente_windows.py   # Recolector de eventos Windows
│   │   └── ubuntu/
│   │       └── agente_ubuntu.py    # Recolector de logs Linux
│   └── web/
│       └── index.html         # Frontend del dashboard
├── data/                      # SQLite DB y config (ignorado por git)
├── logs/                      # Logs de runtime (ignorados por git)
├── run_dashboard.py           # Launcher headless — dashboard
├── run_servidor.py            # Launcher headless — servidor de análisis
├── run_agente.py              # Launcher headless — agente Windows
├── install_services.py        # Instala/desinstala Task Scheduler
├── uninstall_services.py      # Desinstalador
├── requirements.txt
└── README.md
```

## Autor

Desarrollado como proyecto de aprendizaje en el marco del curso **IA Powered Security**.
