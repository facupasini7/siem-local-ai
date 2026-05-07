"""
Launcher silencioso para src/agents/windows/agente_windows.py.
Usado por la tarea SIEM-Agente-Windows del Programador de Tareas.
pythonw.exe ejecuta este archivo sin ventana de consola.
Requiere permisos de Administrador para leer el Security event log.
stdout/stderr se redirigen a logs/agente_out.txt.
"""
import sys
import os
import traceback
from datetime import datetime
from pathlib import Path

ROOT      = Path(__file__).parent
LOGS_DIR  = ROOT / "logs"
ERROR_LOG = LOGS_DIR / "service_errors.txt"
OUT_LOG   = LOGS_DIR / "agente_out.txt"

sys.path.insert(0, str(ROOT / "src" / "agents" / "windows"))


def _registrar_error(componente: str, detalle: str):
    LOGS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write(f"\n[{ts}] CRASH en {componente}:\n{detalle}\n{'─'*60}\n")


LOGS_DIR.mkdir(exist_ok=True)
_out = open(OUT_LOG, "a", encoding="utf-8", buffering=1)
sys.stdout = _out
sys.stderr = _out

os.chdir(ROOT)
print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] run_agente.py iniciado")

try:
    import agente_windows
    agente_windows.ciclo_monitoreo()
except SystemExit:
    pass
except PermissionError as e:
    msg = (
        f"Error de permisos: {e}\n"
        "El agente necesita ejecutarse como Administrador para leer el Security event log.\n"
        "Verificá que la tarea SIEM-Agente-Windows tenga 'Ejecutar con privilegios máximos'.\n"
        f"{traceback.format_exc()}"
    )
    print(msg)
    _registrar_error("agente_windows", msg)
    sys.exit(1)
except Exception:
    msg = traceback.format_exc()
    print(msg)
    _registrar_error("agente_windows", msg)
    sys.exit(1)
