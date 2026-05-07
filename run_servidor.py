"""
Launcher silencioso para src/server/siem_servidor.py.
Usado por la tarea SIEM-Servidor del Programador de Tareas.
pythonw.exe ejecuta este archivo sin ventana de consola.
stdout/stderr se redirigen a logs/servidor_out.txt.
"""
import sys
import os
import traceback
from datetime import datetime
from pathlib import Path

ROOT      = Path(__file__).parent
LOGS_DIR  = ROOT / "logs"
ERROR_LOG = LOGS_DIR / "service_errors.txt"
OUT_LOG   = LOGS_DIR / "servidor_out.txt"

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
print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] run_servidor.py iniciado")

try:
    import siem_servidor
    siem_servidor.procesar_ciclo()
except SystemExit:
    pass
except Exception:
    msg = traceback.format_exc()
    print(msg)
    _registrar_error("siem_servidor", msg)
    sys.exit(1)
