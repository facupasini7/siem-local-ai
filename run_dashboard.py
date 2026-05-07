"""
Launcher silencioso para src/server/dashboard.py.
Usado por la tarea SIEM-Dashboard del Programador de Tareas.
pythonw.exe ejecuta este archivo sin ventana de consola.
stdout/stderr se redirigen a logs/dashboard_out.txt.
"""
import sys
import os
import traceback
from datetime import datetime
from pathlib import Path

ROOT      = Path(__file__).parent          # C:\siem-claude
LOGS_DIR  = ROOT / "logs"
ERROR_LOG = LOGS_DIR / "service_errors.txt"
OUT_LOG   = LOGS_DIR / "dashboard_out.txt"

# Inyectar src/server/ en sys.path para que `import database` y `import auth`
# funcionen exactamente igual que antes sin cambiar los imports internos
sys.path.insert(0, str(ROOT / "src" / "server"))


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
print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] run_dashboard.py iniciado")

try:
    import dashboard
    dashboard.arrancar()
except SystemExit:
    pass
except OSError as e:
    msg = f"Error de red/puerto (¿puerto 8080 ocupado?): {e}\n{traceback.format_exc()}"
    print(msg)
    _registrar_error("dashboard", msg)
    sys.exit(1)
except Exception:
    msg = traceback.format_exc()
    print(msg)
    _registrar_error("dashboard", msg)
    sys.exit(1)
