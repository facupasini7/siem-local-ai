# 🛡️ SIEM Local con IA — Ollama + LLaMA 3.1

SIEM (Security Information and Event Management) local, 100% privado, potenciado con inteligencia artificial. Corre completamente en tu PC sin mandar ningún dato a internet.

## Arquitectura

\\\
agente_windows.py  ──┐
                      ├──► siem_servidor.py ──► Ollama ──► Dashboard
agente_ubuntu.py   ──┘
\\\

Cada agente recopila logs de su plataforma y los manda al servidor central cada 5 minutos. El servidor analiza con IA local y genera alertas en el dashboard.

## ¿Qué hace?

- Monitorea eventos del **Windows Event Viewer** en tiempo real (System, Application, Security)
- Monitorea logs de **Ubuntu Linux** (/var/log/auth.log, syslog, journald)
- Analiza los eventos con **IA local** (Ollama + LLaMA 3.1 8b) y clasifica severidad
- Detecta automáticamente eventos críticos: creación de usuarios, cambios de privilegios, fallos de autenticación
- **File Integrity Monitoring (FIM)** — monitorea carpetas específicas y detecta accesos, modificaciones y eliminaciones de archivos
- Configurable desde el dashboard — agregá y quitá carpetas a monitorear sin tocar código
- Dashboard web con **identificación de origen** — cada alerta muestra si viene de Windows, Ubuntu u otro agente
- Sistema de **gestión de tickets** con estados y comentarios
- **Notificaciones nativas de Windows** ante alertas HIGH o CRITICAL con indicación del agente origen
- **Exportación de reportes en PDF**
- Indicador LIVE con contador de escaneos y próximo análisis

## Stack

- Python 3.x
- Ollama (LLaMA 3.1 8b)
- Windows Event Viewer API (PowerShell)
- Linux logs (/var/log/auth.log, syslog, journald)
- HTML / JavaScript vanilla
- ReportLab (PDF)
- systemd (Ubuntu autostart)

## Requisitos

### Servidor SIEM (Windows)
- Windows 10/11
- Python 3.x
- Ollama instalado → [ollama.com](https://ollama.com)
- 8GB RAM mínimo (recomendado 16GB)
- GPU NVIDIA recomendada

### Agente Ubuntu
- Ubuntu 20.04+
- Python 3.x
- Acceso a /var/log (sudo)
- Conectividad de red al servidor SIEM

## Instalación

### Servidor SIEM (Windows)

1. Cloná el repo
\\\
git clone https://github.com/facupasini7/siem-local-ai
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

4. Corré el agente Windows (como Administrador)
\\\
py agente_windows.py
\\\

5. Corré el servidor SIEM (otra ventana)
\\\
py siem_servidor.py
\\\

6. Corré el dashboard (otra ventana)
\\\
py dashboard.py
\\\

7. Abrí el dashboard
\\\
http://localhost:8080
\\\

### Agente Ubuntu

1. Copiá agente_ubuntu.py a la máquina Ubuntu
\\\
scp agente_ubuntu.py facu@IP_UBUNTU:~/siem-agente/
\\\

2. Editá la IP del servidor SIEM en agente_ubuntu.py
\\\python
SIEM_URL = "http://IP_SERVIDOR_WINDOWS:8080/api/eventos-externos"
\\\

3. Instalá como servicio systemd
\\\
sudo nano /etc/systemd/system/siem-agente.service
sudo systemctl enable siem-agente
sudo systemctl start siem-agente
\\\

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
| 4663 | Acceso/modificación en carpeta monitoreada | HIGH |
| 4660 | Eliminación en carpeta monitoreada | CRITICAL |
| 4656 | Apertura de archivo en carpeta monitoreada | MEDIUM |

### Linux (Ubuntu)
| Evento | Descripción | Severidad |
|--------|-------------|-----------|
| sshd Failed | Fallo de autenticación SSH | HIGH |
| sudo: auth failure | Escalada de privilegios fallida | HIGH |
| Invalid user | Usuario inválido en SSH | HIGH |
| OOM Killer | Proceso eliminado por falta de memoria | MEDIUM |
| Kernel error | Error crítico del kernel | HIGH |

## File Integrity Monitoring (FIM)

Desde la pestaña **⚙️ Configuracion FIM** del dashboard podés agregar y quitar carpetas a monitorear sin tocar código. El SIEM aplica automáticamente reglas SACL en Windows y detecta:

- Quién accedió al archivo (usuario)
- Qué proceso lo abrió
- Qué tipo de operación se realizó (lectura, escritura, eliminación)

## Estructura del proyecto

\\\
siem-local-ai/
├── agente_windows.py  # Agente recolector de logs Windows
├── agente_ubuntu.py   # Agente recolector de logs Ubuntu/Linux
├── siem_servidor.py   # Servidor central: analiza con IA y genera alertas
├── dashboard.py       # Servidor web del dashboard
├── index.html         # Frontend del dashboard
├── config.json        # Carpetas monitoreadas por FIM
└── README.md
\\\

## Roadmap

- [ ] Login para el dashboard
- [ ] Gestión de agentes desde el dashboard (agregar/editar IPs)
- [ ] Agente para AWS CloudTrail
- [ ] Agente para GCP Cloud Audit Logs
- [ ] Migración a modelo más potente (Gemma4 / Qwen3)

## Autor

Desarrollado como proyecto de aprendizaje en el marco del curso **IA Powered Security**.
