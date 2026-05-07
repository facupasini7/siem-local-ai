"""
SIEM Local — Instalador de Servicios Windows
=============================================
Crea tres tareas en el Programador de Tareas de Windows para que
el SIEM arranque automáticamente al iniciar sesión, sin ventanas
de consola visibles.

Tareas creadas:
  SIEM-Dashboard     → run_dashboard.py  → http://localhost:8080
  SIEM-Servidor      → run_servidor.py   → motor de análisis con Ollama
  SIEM-Agente-Windows → run_agente.py   → recopila eventos de Windows

Uso:
  python install_services.py          # instala servicios
  python install_services.py --stop   # detiene las tres tareas
  python install_services.py --start  # arranca las tres tareas manualmente

Se auto-eleva con UAC si no tiene permisos de Administrador.
"""

import ctypes
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from datetime import datetime

# ─── Configuración ────────────────────────────────────────────
BASE_DIR  = Path(r"C:\siem-claude")
LOGS_DIR  = BASE_DIR / "logs"
ERROR_LOG = LOGS_DIR / "service_errors.txt"

PYTHONW   = Path(sys.executable).with_name("pythonw.exe")
if not PYTHONW.exists():
    PYTHONW = Path(sys.executable)  # fallback: python.exe si pythonw no existe

# Delays escalonados para minimizar el impacto al inicio de sesión:
#   Dashboard primero → UI disponible casi de inmediato
#   Servidor después  → ya puede conectarse al dashboard
#   Agente al final   → necesita al servidor activo para enviar logs
TAREAS = [
    {
        "nombre":      "SIEM-Dashboard",
        "script":      "run_dashboard.py",
        "descripcion": "Dashboard web del SIEM — escucha en http://localhost:8080",
        "delay":       "PT15S",   # 15 segundos después del logon
        "prioridad":   6,         # alta (1=máxima, 10=mínima)
    },
    {
        "nombre":      "SIEM-Servidor",
        "script":      "run_servidor.py",
        "descripcion": "Motor de análisis SIEM con Ollama/qwen2.5:3b",
        "delay":       "PT30S",   # 30 segundos
        "prioridad":   7,
    },
    {
        "nombre":      "SIEM-Agente-Windows",
        "script":      "run_agente.py",
        "descripcion": "Agente de recopilación de eventos del Security event log",
        "delay":       "PT45S",   # 45 segundos
        "prioridad":   7,
    },
]
# ─────────────────────────────────────────────────────────────


def es_administrador() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevar_con_uac():
    """Relanza este script con privilegios de administrador vía UAC."""
    print("[UAC] Solicitando permisos de Administrador...")
    args = " ".join(f'"{a}"' for a in sys.argv)
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, args, str(BASE_DIR), 1
    )
    if ret <= 32:
        print(f"[ERROR] No se pudo elevar permisos (código {ret}).")
        sys.exit(1)
    sys.exit(0)


def log(msg: str, nivel: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefijo = {"INFO": "  ", "OK": "✓ ", "ERR": "✗ ", "WARN": "⚠ "}.get(nivel, "  ")
    print(f"[{ts}] {prefijo}{msg}")


def registrar_error(msg: str):
    LOGS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")


def crear_xml_tarea(tarea: dict, usuario_sid: str) -> str:
    """
    Genera el XML de definición de tarea para el Programador de Tareas de Windows.

    Parámetros clave:
    - RunLevel=HighestAvailable: corre con admin si el usuario es admin (necesario para leer Security log)
    - InteractiveToken: corre en la sesión del usuario (permite notificaciones en bandeja)
    - ExecutionTimeLimit=PT0S: sin límite de tiempo (los procesos corren indefinidamente)
    - RestartOnFailure: reinicia hasta 5 veces con intervalos de 2 minutos ante crashes
    - MultipleInstancesPolicy=IgnoreNew: no abre una segunda instancia si ya está corriendo
    """
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{tarea['descripcion']}</Description>
    <Author>SIEM Local Installer</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Delay>{tarea['delay']}</Delay>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{usuario_sid}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>{tarea['prioridad']}</Priority>
    <RestartOnFailure>
      <Interval>PT2M</Interval>
      <Count>5</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{PYTHONW}</Command>
      <Arguments>"{BASE_DIR / tarea['script']}"</Arguments>
      <WorkingDirectory>{BASE_DIR}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"""


def obtener_sid_usuario() -> str:
    """Obtiene el SID del usuario actual para el Principal de la tarea."""
    try:
        res = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=True, check=True
        )
        # Formato: "DOMAIN\user","S-1-5-21-..."
        partes = res.stdout.strip().strip('"').split('","')
        return partes[1] if len(partes) >= 2 else os.environ.get("USERNAME", "")
    except Exception:
        return os.environ.get("USERNAME", "")


def instalar_tarea(tarea: dict, usuario_sid: str) -> bool:
    """Crea una tarea en el Programador de Tareas vía schtasks + XML."""
    nombre = tarea["nombre"]
    xml    = crear_xml_tarea(tarea, usuario_sid)

    # schtasks /create /xml requiere el archivo codificado en UTF-16 con BOM
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-16", suffix=".xml", delete=False
    ) as f:
        f.write(xml)
        xml_path = f.name

    try:
        resultado = subprocess.run(
            ["schtasks", "/create", "/xml", xml_path, "/tn", nombre, "/f"],
            capture_output=True, text=True
        )
        if resultado.returncode == 0:
            log(f"Tarea '{nombre}' creada", "OK")
            return True
        else:
            err = resultado.stderr.strip() or resultado.stdout.strip()
            log(f"Error al crear '{nombre}': {err}", "ERR")
            registrar_error(f"instalar_tarea({nombre}): {err}")
            return False
    except FileNotFoundError:
        log("schtasks.exe no encontrado — ¿estás en Windows?", "ERR")
        return False
    finally:
        os.unlink(xml_path)


def ejecutar_tarea(nombre: str) -> bool:
    """Arranca una tarea inmediatamente (sin esperar el próximo logon)."""
    res = subprocess.run(
        ["schtasks", "/run", "/tn", nombre],
        capture_output=True, text=True
    )
    if res.returncode == 0:
        log(f"'{nombre}' iniciada", "OK")
        return True
    else:
        err = res.stderr.strip() or res.stdout.strip()
        log(f"No se pudo iniciar '{nombre}': {err}", "WARN")
        return False


def detener_tarea(nombre: str) -> bool:
    """Detiene una tarea en ejecución."""
    res = subprocess.run(
        ["schtasks", "/end", "/tn", nombre],
        capture_output=True, text=True
    )
    ok = res.returncode == 0
    if ok:
        log(f"'{nombre}' detenida", "OK")
    else:
        log(f"'{nombre}' no estaba corriendo o no existe", "WARN")
    return ok


def eliminar_tarea(nombre: str) -> bool:
    """Elimina una tarea del Programador de Tareas."""
    res = subprocess.run(
        ["schtasks", "/delete", "/tn", nombre, "/f"],
        capture_output=True, text=True
    )
    ok = res.returncode == 0
    if ok:
        log(f"Tarea '{nombre}' eliminada", "OK")
    else:
        log(f"Tarea '{nombre}' no existe o no se pudo eliminar", "WARN")
    return ok


def crear_acceso_directo_escritorio():
    """
    Crea un acceso directo tipo URL en el Escritorio.
    Al hacer doble clic, abre http://localhost:8080 en el navegador predeterminado.
    Usa el ícono de escudo de shell32.dll (apropiado para una app de seguridad).
    """
    desktop = Path(os.environ.get("USERPROFILE", "~")) / "Desktop"
    shortcut_path = desktop / "SIEM Dashboard.url"

    contenido = (
        "[InternetShortcut]\n"
        "URL=http://localhost:8080\n"
        "IconFile=%SystemRoot%\\system32\\shell32.dll\n"
        "IconIndex=167\n"          # ícono de escudo en shell32.dll
        "HotKey=0\n"
        "IDList=\n"
    )

    try:
        with open(shortcut_path, "w", encoding="utf-8") as f:
            f.write(contenido)
        log(f"Acceso directo creado: {shortcut_path}", "OK")
        return True
    except Exception as e:
        log(f"No se pudo crear el acceso directo: {e}", "WARN")
        registrar_error(f"crear_acceso_directo: {e}")
        return False


def verificar_prerequisitos() -> bool:
    """Verifica que todo esté en orden antes de instalar."""
    ok = True

    # Python sin ventana (pythonw.exe)
    if not PYTHONW.exists():
        log(f"pythonw.exe no encontrado en {PYTHONW}", "WARN")
        log("  Se usará python.exe (puede aparecer consola brevemente)", "WARN")

    # Scripts del SIEM
    for tarea in TAREAS:
        script = BASE_DIR / tarea["script"]
        if not script.exists():
            log(f"Script no encontrado: {script}", "ERR")
            ok = False

    # Dependencias críticas del SIEM en su nueva ubicación src/
    requeridos_server = ["database.py", "auth.py", "dashboard.py", "siem_servidor.py"]
    for req in requeridos_server:
        path = BASE_DIR / "src" / "server" / req
        if not path.exists():
            log(f"Archivo SIEM no encontrado: {path}", "ERR")
            ok = False

    agente_path = BASE_DIR / "src" / "agents" / "windows" / "agente_windows.py"
    if not agente_path.exists():
        log(f"Archivo SIEM no encontrado: {agente_path}", "ERR")
        ok = False

    return ok


def instalar():
    print()
    print("=" * 58)
    print("  SIEM Local — Instalador de Servicios Windows")
    print("=" * 58)
    print()

    # Crear directorio de logs
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log(f"Directorio de logs: {LOGS_DIR}")
    log(f"Python headless:    {PYTHONW}")
    log(f"Directorio SIEM:    {BASE_DIR}")
    print()

    if not verificar_prerequisitos():
        print()
        log("Prerequisitos fallidos. Abortando instalación.", "ERR")
        sys.exit(1)

    usuario_sid = obtener_sid_usuario()
    log(f"Usuario/SID: {usuario_sid}")
    print()

    log("Creando tareas en el Programador de Tareas...")
    exitos = 0
    for tarea in TAREAS:
        if instalar_tarea(tarea, usuario_sid):
            exitos += 1

    print()
    if exitos == len(TAREAS):
        log(f"Todas las tareas creadas ({exitos}/{len(TAREAS)})", "OK")
    else:
        log(f"Algunas tareas fallaron ({exitos}/{len(TAREAS)})", "WARN")

    print()
    log("Creando acceso directo en el Escritorio...")
    crear_acceso_directo_escritorio()

    print()
    log("Iniciando tareas ahora (sin esperar al próximo login)...")
    import time
    for tarea in TAREAS:
        ejecutar_tarea(tarea["nombre"])
        time.sleep(2)  # pequeña pausa entre arranques

    print()
    print("=" * 58)
    print("  Instalación completada.")
    print()
    print("  El SIEM arrancará automáticamente en cada login.")
    print("  Accedé desde: http://localhost:8080")
    print("  Logs de errores: logs\\service_errors.txt")
    print()
    print("  Para gestionar: Programador de Tareas de Windows")
    print("  Para desinstalar: python uninstall_services.py")
    print("=" * 58)
    print()
    input("Presioná Enter para cerrar...")


def cmd_stop():
    print("\n[STOP] Deteniendo todas las tareas SIEM...\n")
    for tarea in TAREAS:
        detener_tarea(tarea["nombre"])
    print("\nListo.\n")


def cmd_start():
    print("\n[START] Iniciando todas las tareas SIEM...\n")
    import time
    for tarea in TAREAS:
        ejecutar_tarea(tarea["nombre"])
        time.sleep(1)
    print("\nListo. Abrí http://localhost:8080 en 15 segundos.\n")


if __name__ == "__main__":
    # Auto-elevación: si no es admin, relanzar con UAC
    if not es_administrador():
        elevar_con_uac()

    if "--stop" in sys.argv:
        cmd_stop()
    elif "--start" in sys.argv:
        cmd_start()
    else:
        instalar()
