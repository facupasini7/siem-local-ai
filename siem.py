import subprocess
import json
import urllib.request
import time
from datetime import datetime, timedelta

# ─── CONFIGURACION ───────────────────────────────────────────
LOG_FILE         = r"C:\siem-claude\alertas.jsonl"
SIEM_LOG         = r"C:\siem-claude\siem_output.log"
SEVERITY_MINIMA  = "medium"
OLLAMA_MODEL     = "llama3.1:8b"
OLLAMA_URL       = "http://localhost:11434/api/generate"
VENTANA_MINUTOS  = 5
MAX_EVENTOS      = 30
TIMEOUT_SEGUNDOS = 180

EVENTOS_IGNORAR  = [10010, 10016, 16384, 16394, 7040, 7045, 1014]
# ─────────────────────────────────────────────────────────────

ORDEN_SEVERIDAD = ["low", "medium", "high", "critical"]

def log(msg: str):
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    txt = f"[{ts}] {msg}"
    print(txt)
    with open(SIEM_LOG, "a", encoding="utf-8") as f:
        f.write(txt + "\n")

def get_events_since(since: datetime) -> str:
    """Lee eventos de System, Application y Security desde una fecha."""
    ids_ignorar  = ",".join(str(i) for i in EVENTOS_IGNORAR)
    since_str    = since.strftime("%Y-%m-%dT%H:%M:%S")
    ids_criticos = "4720,4722,4723,4724,4725,4726,4728,4732,4756,4625,4672,4673"

    cmd = [
        "powershell", "-Command",
        f"""
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $desde = [datetime]::Parse("{since_str}")

        $resultado = @()

        # Security: solo IDs criticos, maximo 10
        try {{
            $seg = Get-WinEvent -LogName Security -MaxEvents 200 -ErrorAction SilentlyContinue |
                Where-Object {{ $_.TimeCreated -gt $desde -and $_.Id -in @({ids_criticos}) }} |
                Select-Object -First 10 TimeCreated, Id, LevelDisplayName, ProviderName, Message
            if ($seg) {{ $resultado += $seg }}
        }} catch {{}}

        # System y Application: maximo 20
        try {{
            $sys = Get-WinEvent -LogName System,Application -MaxEvents 100 -ErrorAction SilentlyContinue |
                Where-Object {{ $_.TimeCreated -gt $desde -and $_.Id -notin @({ids_ignorar}) }} |
                Select-Object -First 20 TimeCreated, Id, LevelDisplayName, ProviderName, Message
            if ($sys) {{ $resultado += $sys }}
        }} catch {{}}

        $resultado | ForEach-Object {{
            if ($_ -ne $null) {{
                $msg = $_.Message -replace '[`n`r]',' '
                if ($msg.Length -gt 180) {{ $msg = $msg.Substring(0, 180) }}
                "$($_.TimeCreated) | ID:$($_.Id) | $($_.LevelDisplayName) | $($_.ProviderName) | $msg"
            }}
        }}
        """
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60
    )
    if result.stdout and result.stdout.strip():
        return "\n".join(
            l for l in result.stdout.strip().splitlines() if l.strip()
        )
    return ""

def analyze_with_ollama(logs: str) -> dict:
    prompt = f"""You are a cybersecurity expert analyzing Windows Event Viewer logs.
Analyze the following events and respond ONLY with valid JSON, no extra text, no markdown, no backticks.

Use exactly this structure:
{{
  "severity": "low",
  "events": [
    {{"id": "EVENT_ID", "descripcion": "what happened in Spanish", "riesgo": "risk level in Spanish"}}
  ],
  "summary": "brief summary in Spanish",
  "accion_recomendada": "what to do in Spanish"
}}

severity must be one of: low, medium, high, critical

CRITICAL severity — always flag these immediately:
- Event ID 4720: New user account created → CRITICAL
- Event ID 4732: User added to Administrators group → CRITICAL
- Event ID 4728: User added to global privileged group → CRITICAL
- Event ID 4756: User added to universal privileged group → CRITICAL
- Event ID 4726: User account deleted → CRITICAL
- Event ID 4625: Failed logon (especially repeated) → HIGH or CRITICAL
- Event ID 4672: Special privileges assigned → HIGH
- Event ID 4673: Privileged service called → HIGH
- Event ID 2003: Firewall disabled → CRITICAL

HIGH severity:
- Event ID 4722: User account enabled
- Event ID 4724: Password reset attempt
- Event ID 4723: Password change attempt
- Malware-like service names or suspicious paths

NORMAL events - do NOT flag:
- Event ID 10010: DCOM timeout
- Event ID 10016: DCOM permission
- Event ID 7040: Service start type changed
- Event ID 16384/16394: Software protection

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
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_SEGUNDOS) as resp:
        data = json.loads(resp.read())
        return json.loads(data["response"].strip())

def notificar_windows(severity: str, summary: str):
    titulo  = f"SIEM - Alerta {severity.upper()}"
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

def ciclo_monitoreo():
    log("SIEM iniciado - ventana de analisis: 5 minutos")
    log(f"Modelo: {OLLAMA_MODEL} | Umbral alertas: {SEVERITY_MINIMA.upper()}")
    log(f"Monitoreando: System, Application, Security")
    log("-" * 50)

    while True:
        inicio_ventana = datetime.now()
        proxima        = inicio_ventana + timedelta(minutes=VENTANA_MINUTOS)

        log(f"Esperando eventos hasta {proxima.strftime('%H:%M:%S')}...")

        while datetime.now() < proxima:
            time.sleep(10)

        ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logs = get_events_since(inicio_ventana)

        if not logs:
            log("Sin eventos nuevos en esta ventana")
            continue

        n = len(logs.splitlines())
        log(f"{n} eventos nuevos - analizando con Ollama...")

        try:
            analysis = analyze_with_ollama(logs)
        except Exception as e:
            log(f"ERROR en analisis: {e}")
            continue

        sev = analysis.get("severity", "low")
        guardar_alerta(analysis, ts)
        log(f"Resultado: {sev.upper()} - {analysis.get('summary', '-')}")

        if sev in ("high", "critical"):
            notificar_windows(sev, analysis.get("summary", "Revisa el dashboard"))
            log("Notificacion Windows enviada")

        if ORDEN_SEVERIDAD.index(sev) >= ORDEN_SEVERIDAD.index(SEVERITY_MINIMA):
            log(f"ALERTA: {analysis.get('accion_recomendada', '-')}")
            for ev in analysis.get("events", []):
                log(f"  * ID {ev.get('id','-')} - {ev.get('descripcion','-')}")

if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ciclo_monitoreo()