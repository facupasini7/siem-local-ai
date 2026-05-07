import json
import os
import subprocess
import urllib.request
import time
import re
from datetime import datetime, timedelta

# ─── CONFIGURACION ───────────────────────────────────────────
LOG_FILE         = r"C:\siem-claude\alertas.jsonl"
SIEM_LOG         = r"C:\siem-claude\siem_output.log"
EVENTOS_EXT_FILE = r"C:\siem-claude\eventos_externos.jsonl"
SEVERITY_MINIMA  = "medium"
OLLAMA_MODEL     = "llama3.1:8b"
OLLAMA_URL       = "http://localhost:11434/api/generate"
VENTANA_MINUTOS  = 5
TIMEOUT_SEGUNDOS = 240

LINUX_RUIDO = [
    "apparmor=\"DENIED\".*firefox",
    "apparmor=\"DENIED\".*snap",
    "audit.*snap\\.",
    "systemd-resolved",
    "NetworkManager.*dhcp",
]
# ─────────────────────────────────────────────────────────────

ORDEN_SEVERIDAD = ["low", "medium", "high", "critical"]

def log(msg: str):
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    txt = f"[{ts}] {msg}"
    print(txt)
    with open(SIEM_LOG, "a", encoding="utf-8") as f:
        f.write(txt + "\n")

def filtrar_ruido_linux(logs: str) -> str:
    lineas = logs.splitlines()
    filtradas = []
    for linea in lineas:
        es_ruido = False
        for patron in LINUX_RUIDO:
            if re.search(patron, linea, re.IGNORECASE):
                es_ruido = True
                break
        if not es_ruido:
            filtradas.append(linea)
    return "\n".join(filtradas)

def get_eventos_pendientes() -> list:
    if not os.path.exists(EVENTOS_EXT_FILE):
        return []
    eventos = []
    with open(EVENTOS_EXT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    ev = json.loads(line)
                    if ev.get("estado") == "pendiente":
                        eventos.append(ev)
                except:
                    pass
    return eventos

def marcar_procesados():
    if not os.path.exists(EVENTOS_EXT_FILE):
        return
    eventos = []
    with open(EVENTOS_EXT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    ev = json.loads(line)
                    ev["estado"] = "procesado"
                    eventos.append(ev)
                except:
                    pass
    with open(EVENTOS_EXT_FILE, "w", encoding="utf-8") as f:
        for ev in eventos:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

def analyze_with_ollama(logs: str, fuente: str = "windows") -> dict:
    contexto = ""
    if fuente in ("linux", "ubuntu-agente"):
        contexto = """
These logs come from Ubuntu Linux. Focus on:
- SSH failures or brute force (sshd: Failed, Invalid user)
- Sudo privilege escalation
- AppArmor DENIED on sensitive paths (NOT /proc/ from firefox - normal)
- Service crashes or OOM killer
- Kernel errors
"""
    else:
        contexto = """
These logs come from Windows. Focus on:
- Auth failures (Event ID 4625)
- Privilege escalation (Event ID 4672, 4673)
- New users/group changes (Event ID 4720, 4732)
- FIM events on monitored folders
- Firewall changes (Event ID 2003)
"""

    prompt = f"""You are a cybersecurity expert analyzing system logs.
Respond ONLY with valid JSON, no extra text, no markdown, no backticks.

{{
  "severity": "low",
  "fuente": "{fuente}",
  "events": [
    {{"id": "EVENT_ID_OR_TYPE", "descripcion": "what happened in Spanish", "riesgo": "risk level in Spanish"}}
  ],
  "summary": "brief summary in Spanish",
  "accion_recomendada": "what to do in Spanish"
}}

severity: low | medium | high | critical
{contexto}

NORMAL - ignore:
- AppArmor DENIED firefox/snap on /proc/
- systemd-resolved, NetworkManager DHCP
- Windows Event ID 10010, 10016, 7040, 16384

Logs:
{logs}

JSON only:"""

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_SEGUNDOS) as resp:
        data = json.loads(resp.read())
        return json.loads(data["response"].strip())

def notificar_windows(severity: str, summary: str, fuente: str = "windows"):
    titulo  = f"SIEM - Alerta {severity.upper()} [{fuente.upper()}]"
    resumen = summary[:200].replace('"', "'")
    script  = f"""
    Add-Type -AssemblyName System.Windows.Forms
    $n = New-Object System.Windows.Forms.NotifyIcon
    $n.Icon = [System.Drawing.SystemIcons]::Warning
    $n.Visible = $true
    $n.BalloonTipTitle = "{titulo}"
    $n.BalloonTipText  = "{resumen}"
    $n.BalloonTipIcon  = "Warning"
    $n.ShowBalloonTip(8000)
    Start-Sleep -Seconds 9
    $n.Dispose()
    """
    subprocess.Popen(
        ["powershell", "-WindowStyle", "Hidden", "-Command", script],
        creationflags=subprocess.CREATE_NO_WINDOW
    )

def guardar_alerta(analysis: dict, ts: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps({"timestamp": ts, **analysis}, ensure_ascii=False) + "\n")

def procesar_ciclo():
    log("SIEM Servidor iniciado")
    log(f"Modelo: {OLLAMA_MODEL} | Umbral: {SEVERITY_MINIMA.upper()}")
    log(f"Procesando eventos de todos los agentes cada {VENTANA_MINUTOS} minutos")
    log("-" * 50)

    while True:
        proxima = datetime.now() + timedelta(minutes=VENTANA_MINUTOS)
        log(f"Esperando eventos hasta {proxima.strftime('%H:%M:%S')}...")

        while datetime.now() < proxima:
            time.sleep(10)

        ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        eventos = get_eventos_pendientes()

        if not eventos:
            log("Sin eventos pendientes de ningun agente")
            continue

        log(f"{len(eventos)} evento(s) pendiente(s) de agentes")

        for evento in eventos:
            agente = evento.get("agente", "desconocido")
            ip     = evento.get("ip", "desconocida")
            logs   = evento.get("logs", "")

            if not logs.strip():
                continue

            # Filtrar ruido si es Linux
            if "ubuntu" in agente.lower() or "linux" in agente.lower():
                logs = filtrar_ruido_linux(logs)
                if not logs.strip():
                    log(f"  {agente} ({ip}) — solo ruido, ignorando")
                    continue

            n = len(logs.splitlines())
            log(f"  Analizando {n} lineas de {agente} ({ip})...")

            try:
                analysis         = analyze_with_ollama(logs, fuente=agente)
                analysis["agente"] = agente
                analysis["ip"]     = ip
                guardar_alerta(analysis, ts)

                sev = analysis.get("severity", "low")
                log(f"  {agente}: {sev.upper()} - {analysis.get('summary', '-')}")

                if sev in ("high", "critical"):
                    notificar_windows(sev, analysis.get("summary", ""), fuente=agente)
                    log(f"  Notificacion enviada para {agente}")

                if ORDEN_SEVERIDAD.index(sev) >= ORDEN_SEVERIDAD.index(SEVERITY_MINIMA):
                    log(f"  ALERTA: {analysis.get('accion_recomendada', '-')}")
                    for ev in analysis.get("events", []):
                        log(f"    * {ev.get('id','-')} - {ev.get('descripcion','-')}")

            except Exception as e:
                log(f"  ERROR analizando {agente}: {e}")

        marcar_procesados()

if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    procesar_ciclo()