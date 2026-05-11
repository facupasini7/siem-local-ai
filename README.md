# SIEM Local con IA — Ollama + qwen2.5:3b

SIEM (Security Information and Event Management) local, 100% privado, potenciado con inteligencia artificial. Corre completamente en tu PC sin mandar ningún dato a internet.

## ¿Qué hace?

- Monitorea eventos del **Windows Event Viewer** (System, Application, Security)
- Monitorea logs de **Ubuntu Linux** (/var/log/auth.log, syslog, journald)
- Analiza con **motor híbrido** — Python detecta (confiable), IA describe (legible)
- Clasifica alertas según el **framework MITRE ATT&CK / TTPs** en tiempo real
- Enriquece IPs con **Threat Intelligence real** (AbuseIPDB) y escala severidad automáticamente
- **File Integrity Monitoring (FIM)** en tiempo real con watchdog
- **Notificaciones a Telegram** con táctica MITRE y score de reputación IP
- Dashboard web con gráficos, filtros por táctica ATT&CK y widget de IPs sospechosas
- Sistema de **gestión de alertas** con estados, comentarios y deduplicación
- **Autenticación en dos factores (2FA/TOTP)**
- **Auditoría completa** de cambios con valor anterior y valor nuevo
- **Políticas de seguridad** configurables desde el dashboard
- **Cifrado Fernet** para credenciales sensibles almacenadas en DB
- Exportación de **reportes en PDF**
- Autostart headless vía Windows Task Scheduler y systemd

## Arquitectura

```
src/agents/windows/agente_windows.py  ──┐
                                         ├──► siem_servidor.py ──► Ollama (qwen2.5:3b)
src/agents/ubuntu/agente_ubuntu.py    ──┘         │
                                                   ▼
                                            dashboard.py  ──► http://localhost:8080
                                                   │
                                            mitre.py  (MITRE ATT&CK)
                                            abuseipdb.py  (Threat Intelligence)
                                            encryption.py (Fernet)
```

## Stack

| Componente | Tecnología |
|---|---|
| Motor IA | Ollama + qwen2.5:3b (1.9 GB VRAM) |
| Backend | Python 3.x — HTTP server nativo (sin frameworks) |
| Base de datos | SQLite (alertas, usuarios, auditoría, caché de IPs) |
| Frontend | HTML + JavaScript vanilla + Chart.js |
| Threat Intelligence | AbuseIPDB API (plan gratuito — 1.000 req/día) |
| Framework de amenazas | MITRE ATT&CK (tácticas + técnicas) |
| Autenticación | bcrypt + TOTP (2FA) + sesiones |
| Cifrado | Fernet (cryptography) para API keys y tokens |
| FIM | watchdog (eventos nativos del SO) |
| Notificaciones | Telegram Bot API + notificaciones nativas Windows |
| PDF | ReportLab |
| Autostart | Windows Task Scheduler / systemd (Ubuntu) |

## Módulos MITRE ATT&CK

Las alertas se enriquecen automáticamente con táctica y técnica del framework MITRE:

| Evento | Técnica | Táctica |
|---|---|---|
| Event ID 4625 — Login fallido | T1110 Brute Force | Credential Access |
| Event ID 4720 — Usuario creado | T1136 Create Account | Persistence |
| Event ID 4672 — Privilegios especiales | T1078 Valid Accounts | Privilege Escalation |
| Event ID 1102 — Log borrado | T1070 Indicator Removal | Defense Evasion |
| FIM — Archivo eliminado | T1485 Data Destruction | Impact |
| FIM — Archivo creado | T1105 Ingress Tool Transfer | Command and Control |
| FIM — Archivo movido | T1036 Masquerading | Defense Evasion |

## Threat Intelligence — AbuseIPDB

Cada IP pública que aparece en una alerta se consulta contra AbuseIPDB:

- **Score ≥ 90** → severidad escala a HIGH automáticamente
- **Score ≥ 75** → IP marcada como sospechosa
- IPs privadas/loopback se omiten (sin cuota consumida)
- Resultados cacheados 24h en SQLite para no agotar la cuota gratuita
- Widget "IPs sospechosas" en el Overview del dashboard

Configurá tu API key gratuita en **Seguridad → AbuseIPDB** dentro del dashboard.

## Notificaciones Telegram

Las alertas HIGH y CRITICAL llegan a tu Telegram con contexto completo:

```
🟠 Alerta FIM — HIGH
━━━━━━━━━━━━━━━━━━━━━━━━
🗑️ Evento: Archivo eliminado
📁 Archivo: contrato.pdf
📂 Ruta: C:/Users/.../contrato.pdf
🖥️ Agente: windows-agente  |  192.168.1.48
🕐 Hora: 11/05/2026 20:13:10
━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ MITRE ATT&CK: Impact
🎯 Técnica: T1485 Data Destruction
⚡ Revisá el Dashboard para más detalles
```

## Requisitos

### Servidor SIEM (Windows)
- Windows 10/11
- Python 3.x
- Ollama → [ollama.com](https://ollama.com)
- 4 GB VRAM mínimo (GTX 1050 Ti o superior)

### Agente Ubuntu (opcional)
- Ubuntu 20.04+
- Python 3.x
- Acceso a /var/log (sudo)
- Conectividad de red al servidor SIEM

## Instalación

```bash
git clone https://github.com/facupasini7/siem-local-ai
cd siem-local-ai
pip install -r requirements.txt
ollama pull qwen2.5:3b
```

### Opción A — Autostart automático (recomendada)

```bash
python install_services.py
```

Crea tres tareas en el Programador de Tareas de Windows. El SIEM arranca solo en cada login.
Accedé desde `http://localhost:8080` o el acceso directo en el Escritorio.

```bash
python uninstall_services.py  # para desinstalar
```

### Opción B — Manual (debug)

```bash
# Ventana 1
python run_dashboard.py

# Ventana 2
python run_servidor.py

# Ventana 3 (como Administrador)
python run_agente.py
```

### Agente Ubuntu

Copiá `src/agents/ubuntu/agente_ubuntu.py` a la máquina Ubuntu, configurá `SIEM_URL` con la IP del servidor Windows e instalá como servicio systemd.

## Configuración inicial

1. Abrí `http://localhost:8080` — el primer login crea el usuario `admin`
2. Cambiá la contraseña en el primer acceso (forzado)
3. Activá 2FA en **Perfil → TOTP** (opcional pero recomendado)
4. Configurá tu API key de AbuseIPDB en **Seguridad → AbuseIPDB**
5. Configurá tu bot de Telegram en **Seguridad → Telegram**
6. Definí las carpetas a monitorear con FIM en **Config FIM**

## Estructura del proyecto

```
siem-local-ai/
├── src/
│   ├── server/
│   │   ├── database.py        # SQLite: alertas, usuarios, auditoría, caché IPs
│   │   ├── auth.py            # Login, sesiones, bcrypt, TOTP
│   │   ├── dashboard.py       # Servidor HTTP + todos los endpoints API
│   │   ├── siem_servidor.py   # Motor de análisis híbrido Python+IA
│   │   ├── mitre.py           # Mapeo MITRE ATT&CK / TTPs
│   │   ├── abuseipdb.py       # Threat Intelligence — reputación de IPs
│   │   └── encryption.py      # Cifrado Fernet para datos sensibles
│   ├── agents/
│   │   ├── windows/
│   │   │   └── agente_windows.py   # Recolector de eventos Windows + FIM watchdog
│   │   └── ubuntu/
│   │       └── agente_ubuntu.py    # Recolector de logs Linux
│   └── web/
│       └── index.html         # Frontend del dashboard (vanilla JS)
├── data/                      # SQLite DB (ignorado por git)
├── logs/                      # Logs de runtime (ignorados por git)
├── run_dashboard.py
├── run_servidor.py
├── run_agente.py
├── install_services.py
├── uninstall_services.py
└── requirements.txt
```

## Autor

Desarrollado como proyecto de aprendizaje en el marco del curso **IA Powered Security**.
