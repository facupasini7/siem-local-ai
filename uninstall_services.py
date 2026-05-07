"""
SIEM Local — Desinstalador de Servicios Windows
================================================
Detiene y elimina las tres tareas del Programador de Tareas.
También elimina el acceso directo del Escritorio.

Uso: python uninstall_services.py
"""

import ctypes
import os
import subprocess
import sys
from pathlib import Path

TAREAS = [
    "SIEM-Dashboard",
    "SIEM-Servidor",
    "SIEM-Agente-Windows",
]


def es_administrador() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevar_con_uac():
    args = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1)
    sys.exit(0)


def log(msg: str, nivel: str = "INFO"):
    prefijo = {"OK": "✓ ", "ERR": "✗ ", "WARN": "⚠ "}.get(nivel, "  ")
    print(f"  {prefijo}{msg}")


if __name__ == "__main__":
    if not es_administrador():
        elevar_con_uac()

    print()
    print("=" * 50)
    print("  SIEM Local — Desinstalador de Servicios")
    print("=" * 50)
    print()

    # Detener y eliminar tareas
    log("Deteniendo y eliminando tareas...")
    for nombre in TAREAS:
        # Detener primero
        subprocess.run(["schtasks", "/end", "/tn", nombre], capture_output=True)
        # Eliminar
        res = subprocess.run(
            ["schtasks", "/delete", "/tn", nombre, "/f"],
            capture_output=True, text=True
        )
        if res.returncode == 0:
            log(f"'{nombre}' eliminada", "OK")
        else:
            log(f"'{nombre}' no existía o ya fue eliminada", "WARN")

    # Eliminar acceso directo del Escritorio
    print()
    log("Eliminando acceso directo del Escritorio...")
    desktop = Path(os.environ.get("USERPROFILE", "~")) / "Desktop"
    shortcut = desktop / "SIEM Dashboard.url"
    if shortcut.exists():
        shortcut.unlink()
        log("Acceso directo eliminado", "OK")
    else:
        log("Acceso directo no encontrado", "WARN")

    print()
    print("  Desinstalación completada.")
    print("  Los archivos del SIEM y la base de datos no fueron modificados.")
    print()
    input("Presioná Enter para cerrar...")
