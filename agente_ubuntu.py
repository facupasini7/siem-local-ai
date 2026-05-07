import subprocess
import json
import urllib.request
import time
import socket
from datetime import datetime, timedelta

# ─── CONFIGURACION ───────────────────────────────────────────
SIEM_URL        = "http://192.168.1.48:8080/api/eventos-externos"
AGENTE_NOMBRE   = "ubuntu-agente"
VENTANA_MINUTOS = 5
IP_LOCAL        = "192.168.1.7"
LOG_FILE        = "/home/facu/siem-agente/agente.log"
# ─────────────────────────────────────────────────────────────

def log(msg: str):
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    txt = f"[{ts}] {msg}"
    print(txt)
    with open(LOG_FILE, "a") as f:
        f.write(txt + "\n")

def get_logs_since(since: datetime) -> str:
    """Lee logs de auth.log y syslog desde una fecha."""
    since_str = since.strftime("%b %d %H:%M:%S").replace(" 0", "  ")
    logs      = []

    # auth.log — SSH, sudo, autenticacion
    archivos = [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/kern.log"
    ]

    for archivo in archivos:
        try:
            result = subprocess.run(
                ["sudo", "tail", "-n", "500", archivo],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                # Filtrar solo eventos relevantes
                for linea in result.stdout.splitlines():
                    linea_lower = linea.lower()
                    if any(kw in linea_lower for kw in [
                        "failed", "error", "invalid", "unauthorized",
                        "sudo", "su:", "authentication", "connection",
                        "refused", "timeout", "warning", "critical",
                        "kernel", "oom", "segfault", "denied"
                    ]):
                        logs.append(f"[{archivo.split('/')[-1]}] {linea[:200]}")
        except Exception as e:
            log(f"Error leyendo {archivo}: {e}")

    # Limitar a los ultimos 30 eventos relevantes
    return "\n".join(logs[-30:]) if logs else ""

def get_journald_logs(since: datetime) -> str:
    """Lee logs de journald desde una fecha."""
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")
    try:
        result = subprocess.run(
            ["journalctl", f"--since={since_str}",
             "--priority=warning", "--no-pager", "-n", "20"],
            capture_output=True, text=True, timeout=15
        )
        if result.stdout and "No entries" not in result.stdout:
            return result.stdout[:3000]
    except Exception as e:
        log(f"Error leyendo journald: {e}")
    return ""

def enviar_al_siem(logs: str) -> bool:
    """Manda los logs al SIEM central."""
    payload = json.dumps({
        "agente": AGENTE_NOMBRE,
        "ip":     IP_LOCAL,
        "logs":   logs
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            SIEM_URL,
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data.get("ok", False)
    except Exception as e:
        log(f"Error enviando al SIEM: {e}")
        return False

def ciclo_monitoreo():
    log("Agente Ubuntu iniciado")
    log(f"SIEM central: {SIEM_URL}")
    log(f"Ventana de analisis: {VENTANA_MINUTOS} minutos")
    log("-" * 50)

    while True:
        inicio_ventana = datetime.now()
        proxima        = inicio_ventana + timedelta(minutes=VENTANA_MINUTOS)
        log(f"Recopilando eventos hasta {proxima.strftime('%H:%M:%S')}...")

        while datetime.now() < proxima:
            time.sleep(10)

        # Recopilar logs
        logs_arch     = get_logs_since(inicio_ventana)
        logs_journald = get_journald_logs(inicio_ventana)
        logs_total    = ""

        if logs_arch:
            logs_total += logs_arch
        if logs_journald:
            logs_total += "\n[journald]\n" + logs_journald

        if not logs_total.strip():
            log("Sin eventos relevantes en esta ventana")
            continue

        n = len(logs_total.splitlines())
        log(f"{n} lineas de logs recopiladas - enviando al SIEM...")

        if enviar_al_siem(logs_total):
            log("Logs enviados correctamente al SIEM")
        else:
            log("ERROR: No se pudo enviar al SIEM — verificar conectividad")

if __name__ == "__main__":
    ciclo_monitoreo()
