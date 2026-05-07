import subprocess
import json
import urllib.request
import time
from datetime import datetime, timedelta
from pathlib import Path

# ─── CONFIGURACION ───────────────────────────────────────────
# Raíz del proyecto: src/agents/windows/ → src/agents/ → src/ → raíz
_ROOT            = Path(__file__).parent.parent.parent.parent

SIEM_URL         = "http://localhost:8080/api/eventos-externos"
AGENTE_NOMBRE    = "windows-agente"
IP_LOCAL         = "192.168.1.48"
VENTANA_MINUTOS  = 5
AGENTE_LOG       = _ROOT / "logs" / "agente_windows.log"
CONFIG_FILE      = _ROOT / "data" / "config.json"

EVENTOS_IGNORAR  = [10010, 10016, 16384, 16394, 7040, 7045, 1014]
# ─────────────────────────────────────────────────────────────

carpetas_activas = set()

def log(msg: str):
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    txt = f"[{ts}] {msg}"
    print(txt)
    with open(AGENTE_LOG, "a", encoding="utf-8") as f:
        f.write(txt + "\n")

def leer_config() -> dict:
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {"carpetas_monitoreadas": [], "api_key": ""}

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
    log(f"Nuevas carpetas — aplicando SACL en {len(nuevas)} carpeta(s)...")
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

def enviar_al_siem(logs: str) -> bool:
    body = {
        "agente": AGENTE_NOMBRE,
        "ip":     IP_LOCAL,
        "logs":   logs
    }
    api_key = leer_config().get("api_key", "")
    if api_key:
        body["api_key"] = api_key
    payload = json.dumps(body).encode("utf-8")
    try:
        req = urllib.request.Request(
            SIEM_URL, data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data.get("ok", False)
    except Exception as e:
        log(f"Error enviando al SIEM: {e}")
        return False

def ciclo_monitoreo():
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    log("Agente Windows iniciado")
    log(f"SIEM central: {SIEM_URL}")
    log(f"Ventana: {VENTANA_MINUTOS} minutos")
    log("-" * 50)

    while True:
        aplicar_sacls_configuradas()

        inicio_ventana = datetime.now()
        proxima        = inicio_ventana + timedelta(minutes=VENTANA_MINUTOS)
        log(f"Recopilando eventos hasta {proxima.strftime('%H:%M:%S')}...")

        while datetime.now() < proxima:
            time.sleep(10)

        logs = get_events_since(inicio_ventana)

        if not logs:
            log("Sin eventos relevantes")
            continue

        n = len(logs.splitlines())
        log(f"{n} eventos recopilados - enviando al SIEM...")

        if enviar_al_siem(logs):
            log("Eventos enviados correctamente")
        else:
            log("ERROR: No se pudo enviar al SIEM")

if __name__ == "__main__":
    ciclo_monitoreo()