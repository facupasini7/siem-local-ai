import subprocess
import json
import urllib.request
import urllib.error
import time
import threading
import os
from datetime import datetime, timedelta
from pathlib import Path

# Ocultar ventana de consola en Windows al llamar subprocesos
_CREATIONFLAGS = 0
try:
    _CREATIONFLAGS = subprocess.CREATE_NO_WINDOW
except AttributeError:
    pass  # No es Windows

def _startupinfo():
    """STARTUPINFO con SW_HIDE: oculta la ventana de consola del subproceso."""
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        return si
    except Exception:
        return None

# ─── CONFIGURACION ───────────────────────────────────────────
# Raíz del proyecto: src/agents/windows/ → src/agents/ → src/ → raíz
_ROOT            = Path(__file__).parent.parent.parent.parent

AGENTE_NOMBRE    = "windows-agente"
VENTANA_MINUTOS  = 5
AGENTE_LOG       = _ROOT / "logs" / "agente_windows.log"
CONFIG_FILE      = _ROOT / "data" / "config.json"

EVENTOS_IGNORAR  = [10010, 10016, 16384, 16394, 7040, 7045, 1014]

# Valores por defecto — se sobreescriben con config.json en cada ciclo
_SIEM_URL_DEFAULT     = "http://localhost:8080/api/eventos-externos"
_SIEM_FIM_DEFAULT     = "http://localhost:8080/api/alerta-fim"
_IP_LOCAL_DEFAULT     = "192.168.1.48"
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
        return {"carpetas_monitoreadas": [], "api_key": "", "siem_url": "", "ip_local": ""}

def aplicar_sacl(carpeta: str):
    # La ruta se pasa como argumento separado al script para evitar
    # inyección de comandos via interpolación de strings en PowerShell.
    script = (
        "param([string]$path)\n"
        "if (-not (Test-Path $path)) { Write-Output 'ERROR: La carpeta no existe: ' + $path; return }\n"
        "$acl = Get-Acl -Path $path\n"
        "$sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')\n"
        "$regla = New-Object System.Security.AccessControl.FileSystemAuditRule("
        "$sid,'ReadData,WriteData,Delete','ContainerInherit,ObjectInherit','None','Success')\n"
        "$acl.AddAuditRule($regla)\n"
        "Set-Acl -Path $path -AclObject $acl\n"
        "Write-Output ('OK: SACL aplicado en ' + $path)"
    )
    cmd = [
        "powershell", "-NoProfile", "-NonInteractive",
        "-Command", script,   # script sin interpolación de carpeta
        "-path", carpeta      # ruta como argumento separado, no embebida en el script
    ]
    result = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=15,
                            creationflags=_CREATIONFLAGS, startupinfo=_startupinfo())
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

    cmd = [
        "powershell", "-Command",
        f"""
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $desde = [datetime]::ParseExact("{since_str}", "yyyy-MM-dd HH:mm:ss", $null)
        $resultado = @()

        try {{
            $seg = Get-WinEvent -LogName Security -MaxEvents 500 -ErrorAction SilentlyContinue |
                Where-Object {{ $_.TimeCreated -gt $desde -and $_.Id -in @({ids_criticos}) }} |
                Select-Object -First 50 TimeCreated, Id, LevelDisplayName, ProviderName, Message
            if ($seg) {{
                $seg | ForEach-Object {{
                    $msg = $_.Message -replace '[`n`r`t]',' '
                    $msg = $msg -replace '[^\x20-\x7E\xC0-\xFF]', ''
                    if ($msg.Length -gt 200) {{ $msg = $msg.Substring(0, 200) }}
                    $resultado += "$($_.TimeCreated) | ID:$($_.Id) | $($_.LevelDisplayName) | $($_.ProviderName) | $msg"
                }}
            }}
        }} catch {{}}

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
        cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=60,
        creationflags=_CREATIONFLAGS, startupinfo=_startupinfo()
    )
    if result.stdout and result.stdout.strip():
        return "\n".join(l for l in result.stdout.strip().splitlines() if l.strip())
    return ""

def enviar_al_siem(logs: str) -> bool:
    cfg      = leer_config()
    siem_url = cfg.get("siem_url", "").strip() or _SIEM_URL_DEFAULT
    ip_local = cfg.get("ip_local", "").strip() or _IP_LOCAL_DEFAULT
    body = {
        "agente": AGENTE_NOMBRE,
        "ip":     ip_local,
        "logs":   logs
    }
    api_key = cfg.get("api_key", "")
    if api_key:
        body["api_key"] = api_key
    payload = json.dumps(body).encode("utf-8")
    try:
        req = urllib.request.Request(
            siem_url, data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data.get("ok", False)
    except Exception as e:
        log(f"Error enviando al SIEM: {e}")
        return False


# ─── FIM REAL-TIME (watchdog) ─────────────────────────────────

def _enviar_alerta_fim(tipo: str, ruta: str):
    """
    Envía un evento FIM directamente al endpoint /api/alerta-fim.
    Bypasea Ollama — la severidad se asigna por tipo de evento:
      ELIMINACION  → high
      MODIFICACION → medium
      CREACION     → medium
      MOVIMIENTO   → medium
    """
    import urllib.parse as _up
    cfg      = leer_config()
    siem_url = cfg.get("siem_url", "").strip() or _SIEM_URL_DEFAULT
    # Construir la URL de FIM desde la base, sin depender de reemplazar un path específico
    parsed   = _up.urlparse(siem_url)
    fim_url  = _up.urlunparse(parsed._replace(path="/api/alerta-fim"))
    ip_local = cfg.get("ip_local", "").strip() or _IP_LOCAL_DEFAULT

    body = {
        "agente":    AGENTE_NOMBRE,
        "ip":        ip_local,
        "tipo":      tipo,
        "archivo":   ruta,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    api_key = cfg.get("api_key", "")
    if api_key:
        body["api_key"] = api_key

    try:
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            fim_url, data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if data.get("ok"):
                log(f"[FIM] {tipo}: {ruta} → alerta guardada")
            else:
                log(f"[FIM] {tipo}: {ruta} → rechazado: {data.get('error','?')}")
    except Exception as e:
        log(f"[FIM] Error enviando {tipo} {ruta}: {e}")


class _FIMHandler:
    """
    Manejador de eventos watchdog.
    Deduplica eventos repetidos en una ventana de 3 segundos
    (watchdog puede disparar múltiples eventos por la misma acción).
    """
    def __init__(self):
        self._lock        = threading.Lock()
        self._ultimo      = {}   # clave → timestamp último envío

    def _dedup_y_enviar(self, tipo: str, ruta: str):
        clave = f"{tipo}:{ruta}"
        ahora = time.time()
        with self._lock:
            if ahora - self._ultimo.get(clave, 0) < 3:
                return  # duplicado — ignorar
            self._ultimo[clave] = ahora
        # Enviar en hilo separado para no bloquear watchdog
        threading.Thread(
            target=_enviar_alerta_fim, args=(tipo, ruta), daemon=True
        ).start()

    def dispatch(self, event):
        if event.is_directory:
            return
        ruta = getattr(event, "src_path", "")
        tipo_map = {
            "created":  "CREACION",
            "deleted":  "ELIMINACION",
            "modified": "MODIFICACION",
            "moved":    "MOVIMIENTO",
        }
        tipo = tipo_map.get(event.event_type)
        if tipo:
            self._dedup_y_enviar(tipo, ruta)


def iniciar_fim_watcher() -> object | None:
    """
    Inicia el observer watchdog para todas las carpetas configuradas.
    Retorna el observer (ya iniciado) o None si watchdog no está disponible
    o no hay carpetas configuradas.
    """
    try:
        from watchdog.observers import Observer
        from watchdog.events   import FileSystemEventHandler

        config   = leer_config()
        carpetas = config.get("carpetas_monitoreadas", [])
        if not carpetas:
            return None

        handler  = _FIMHandler()

        # watchdog espera un FileSystemEventHandler; usamos un wrapper
        class _Wrapper(FileSystemEventHandler):
            def dispatch(self, event):
                handler.dispatch(event)

        observer = Observer()
        for carpeta in carpetas:
            if os.path.isdir(carpeta):
                observer.schedule(_Wrapper(), carpeta, recursive=True)
                log(f"[FIM] Watchdog activo en: {carpeta}")
            else:
                log(f"[FIM] Carpeta no encontrada (se omite): {carpeta}")

        observer.start()
        return observer

    except ImportError:
        log("[FIM] watchdog no instalado — FIM en tiempo real deshabilitado")
        log("[FIM]   Instalá con: pip install watchdog")
        return None
    except Exception as e:
        log(f"[FIM] Error iniciando watchdog: {e}")
        return None


# ─── CICLO PRINCIPAL ──────────────────────────────────────────

def ciclo_monitoreo():
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    cfg      = leer_config()
    siem_url = cfg.get("siem_url", "").strip() or _SIEM_URL_DEFAULT
    log("Agente Windows iniciado")
    log(f"SIEM central: {siem_url}")
    log(f"Ventana: {VENTANA_MINUTOS} minutos")
    log("-" * 50)

    # Aplicar SACLs e iniciar FIM en tiempo real
    aplicar_sacls_configuradas()
    observer = iniciar_fim_watcher()

    try:
        while True:
            # Re-leer config por si se agregaron carpetas nuevas
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

    finally:
        if observer:
            observer.stop()
            observer.join()


if __name__ == "__main__":
    ciclo_monitoreo()
