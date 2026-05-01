import subprocess
import json
import urllib.request
import time
from datetime import datetime, timedelta

# ─── CONFIGURACION ───────────────────────────────────────────
LOG_FILE         = r"C:\siem-claude\alertas.jsonl"
SIEM_LOG         = r"C:\siem-claude\siem_output.log"
CONFIG_FILE      = r"C:\siem-claude\config.json"
SEVERITY_MINIMA  = "medium"
OLLAMA_MODEL     = "llama3.1:8b"
OLLAMA_URL       = "http://localhost:11434/api/generate"
VENTANA_MINUTOS  = 5
MAX_EVENTOS      = 15
TIMEOUT_SEGUNDOS = 240

EVENTOS_IGNORAR  = [10010, 10016, 16384, 16394, 7040, 7045, 1014]
# ─────────────────────────────────────────────────────────────

ORDEN_SEVERIDAD  = ["low", "medium", "high", "critical"]
carpetas_activas = set()

def log(msg: str):
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    txt = f"[{ts}] {msg}"
    print(txt)
    with open(SIEM_LOG, "a", encoding="utf-8") as f:
        f.write(txt + "\n")

def leer_config() -> dict:
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {"carpetas_monitoreadas": []}

def aplicar_sacl(carpeta: str):
    cmd = [
        "powershell", "-Command",
        f"""
        $path = "{carpeta}"
        if (-not (Test-Path $path)) {{
            Write-Output "ERROR: La carpeta no existe: $path"
            return
        }}
        $acl = Get-Acl -Path $path
        $sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $regla = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $sid,
            "ReadData,WriteData,Delete",
            "ContainerInherit,ObjectInherit",
            "None",
            "Success"
        )
        $acl.AddAuditRule($regla)
        Set-Acl -Path $path -AclObject $acl
        Write-Output "OK: SACL aplicado en $path"
        """
    ]
    result = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=15)
    return result.stdout.strip()

def aplicar_sacls_configuradas():
    global carpetas_activas
    config   = leer_config()
    carpetas = set(config.get("carpetas_monitoreadas", []))
    nuevas   = carpetas - carpetas_activas
    if not nuevas:
        return
    log(f"Nuevas carpetas detectadas — aplicando SACL en {len(nuevas)} carpeta(s)...")
    for carpeta in nuevas:
        resultado = aplicar_sacl(carpeta)
        log(f"  SACL: {resultado}")
    carpetas_activas = carpetas

def get_events_since(since: datetime) -> str:
    ids_ignorar  = ",".join(str(i) for i in EVENTOS_IGNORAR)
    ids_criticos = "4720,4722,4723,4724,4725,4726,4728,4732,4756,4625,4672,4673"
    since_str    = since.strftime("%Y-%m-%d %H:%M:%S")

    config   = leer_config()
    carpetas = config.get("carpetas_monitoreadas", [])
    filtro_fim = ""
    if carpetas:
        rutas = " -or ".join([
            f'$_.Message -like "*{c.split(chr(92))[-1]}*"'
            for c in carpetas
        ])
        filtro_fim = f"""
        try {{
            $fim = Get-WinEvent -LogName Security -MaxEvents 500 -ErrorAction SilentlyContinue |
                Where-Object {{ $_.TimeCreated -gt $desde -and $_.Id -in @(4663, 4656, 4660) }} |
                Where-Object {{ {rutas} }} |
                Select-Object -First 8 TimeCreated, Id, LevelDisplayName, ProviderName, Message
            if ($fim) {{
                $fim | ForEach-Object {{
                    $ev  = $_
                    $msg = $ev.Message

                    $archivo = if ($msg -match 'Nombre de objeto:[ \t]+(.+?)(\r|\n|$)') {{ $matches[1].Trim() }} else {{ 'desconocido' }}
                    $acceso  = if ($msg -match 'Derechos de acceso:[ \t]+(.+?)(\r|\n|$)') {{ $matches[1].Trim() }} else {{
                               if ($msg -match 'Accesses:[ \t]+(.+?)(\r|\n|$)') {{ $matches[1].Trim() }} else {{ 'desconocido' }} }}
                    $proceso = if ($msg -match 'Nombre de proceso:[ \t]+(.+?)(\r|\n|$)') {{ $matches[1].Trim() }} else {{
                               if ($msg -match 'Process Name:[ \t]+(.+?)(\r|\n|$)') {{ $matches[1].Trim() }} else {{ 'desconocido' }} }}
                    $usuario = if ($msg -match 'Nombre de cuenta:[ \t]+(.+?)(\r|\n|$)') {{ $matches[1].Trim() }} else {{
                               if ($msg -match 'Account Name:[ \t]+(.+?)(\r|\n|$)') {{ $matches[1].Trim() }} else {{ 'desconocido' }} }}

                    $tipo = switch ($ev.Id) {{
                        4663 {{ "ACCESO-MODIFICACION" }}
                        4660 {{ "ELIMINACION" }}
                        4656 {{ "APERTURA" }}
                        default {{ "EVENTO" }}
                    }}

                    $resultado += "$($ev.TimeCreated) | ID:$($ev.Id) | FIM-$tipo | archivo=$archivo | acceso=$acceso | proceso=$proceso | usuario=$usuario"
                }}
            }}
        }} catch {{}}
        """

    cmd = [
        "powershell", "-Command",
        f"""
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $desde = [datetime]::ParseExact("{since_str}", "yyyy-MM-dd HH:mm:ss", $null)
        $resultado = @()

        # Security: IDs criticos
        try {{
            $seg = Get-WinEvent -LogName Security -MaxEvents 200 -ErrorAction SilentlyContinue |
                Where-Object {{ $_.TimeCreated -gt $desde -and $_.Id -in @({ids_criticos}) }} |
                Select-Object -First 8 TimeCreated, Id, LevelDisplayName, ProviderName, Message
            if ($seg) {{
                $seg | ForEach-Object {{
                    $msg = $_.Message -replace '[`n`r`t]',' '
                    $msg = $msg -replace '[^\x20-\x7E\xC0-\xFF]', ''
                    if ($msg.Length -gt 200) {{ $msg = $msg.Substring(0, 200) }}
                    $resultado += "$($_.TimeCreated) | ID:$($_.Id) | $($_.LevelDisplayName) | $($_.ProviderName) | $msg"
                }}
            }}
        }} catch {{}}

        {filtro_fim}

        # System y Application
        try {{
            $sys = Get-WinEvent -LogName System,Application -MaxEvents 100 -ErrorAction SilentlyContinue |
                Where-Object {{ $_.TimeCreated -gt $desde -and $_.Id -notin @({ids_ignorar}) }} |
                Select-Object -First 12 TimeCreated, Id, LevelDisplayName, ProviderName, Message
            if ($sys) {{
                $sys | ForEach-Object {{
                    $msg = $_.Message -replace '[`n`r`t]',' '
                    $msg = $msg -replace '[^\x20-\x7E\xC0-\xFF]', ''
                    if ($msg.Length -gt 180) {{ $msg = $msg.Substring(0, 180) }}
                    $resultado += "$($_.TimeCreated) | ID:$($_.Id) | $($_.LevelDisplayName) | $($_.ProviderName) | $msg"
                }}
            }}
        }} catch {{}}

        $resultado
        """
    ]
    result = subprocess.run(
        cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=60
    )
    if result.stdout and result.stdout.strip():
        return "\n".join(l for l in result.stdout.strip().splitlines() if l.strip())
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

For FIM events (lines containing FIM-ACCESO, FIM-ELIMINACION, FIM-APERTURA):
- Extract the exact file path from "archivo=" field
- Extract the user from "usuario=" field
- Extract the process from "proceso=" field
- Describe exactly: "El usuario X accedio/modifico/elimino el archivo Y usando el proceso Z"
- FIM-ELIMINACION → CRITICAL
- FIM-ACCESO-MODIFICACION → HIGH
- FIM-APERTURA → MEDIUM

CRITICAL severity:
- Event ID 4720: New user account created → CRITICAL
- Event ID 4732: User added to Administrators group → CRITICAL
- Event ID 4728: User added to global privileged group → CRITICAL
- Event ID 4756: User added to universal privileged group → CRITICAL
- Event ID 4726: User account deleted → CRITICAL
- Event ID 4625: Failed logon (repeated) → HIGH or CRITICAL
- Event ID 2003: Firewall disabled → CRITICAL

HIGH severity:
- Event ID 4672: Special privileges assigned → HIGH
- Event ID 4722: User account enabled → HIGH
- Event ID 4724: Password reset → HIGH

NORMAL - do NOT flag:
- Event ID 10010, 10016: DCOM (normal)
- Event ID 7040: Service start type (normal)
- Event ID 16384/16394: Software protection (normal)

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
    log(f"Monitoreando: System, Application, Security, FIM")
    log("-" * 50)

    while True:
        aplicar_sacls_configuradas()

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