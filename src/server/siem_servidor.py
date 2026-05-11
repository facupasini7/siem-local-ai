import json
import os
import subprocess
import urllib.request
import time
import re
from datetime import datetime, timedelta
from pathlib import Path

import database  # módulo local — maneja toda la persistencia en SQLite
import mitre     # módulo local — enriquecimiento MITRE ATT&CK
import abuseipdb # módulo local — threat intelligence de IPs

# ─── CONFIGURACION ───────────────────────────────────────────
# Raíz del proyecto: src/server/ → src/ → raíz
_ROOT            = Path(__file__).parent.parent.parent
# SIEM_LOG sigue siendo un archivo de texto: el dashboard lo parsea para saber
# cuándo fue el último escaneo y si el servidor está activo.
SIEM_LOG         = _ROOT / "logs" / "siem_output.log"
SEVERITY_MINIMA  = "medium"

# Modelo: qwen2.5:3b — elegido sobre llama3.1:8b porque:
#   - llama3.1:8b pesa 4.9 GB y la GTX 1050 Ti tiene 4 GB VRAM → CPU offload (~120-240s)
#   - qwen2.5:3b pesa 1.9 GB → corre 100% en GPU → ~25-45s por ciclo
#   - Superior en salida JSON estructurada (crítico para parsear la respuesta)
#   - Mejor soporte de español y logs estructurados (syslog/JSON/XML)
OLLAMA_MODEL     = "qwen2.5:3b"
OLLAMA_URL       = "http://localhost:11434/api/generate"
VENTANA_MINUTOS  = 5
TIMEOUT_SEGUNDOS = 120  # reducido: qwen2.5:3b en GPU no necesita 240s

# Parámetros de inferencia optimizados para análisis de logs en GTX 1050 Ti:
#   temperature=0.1 → respuestas deterministas (clasificación precisa, no creativa)
#   num_ctx=2048    → suficiente para un batch de logs; KV cache más pequeño = más VRAM libre
#   num_predict=600 → la respuesta JSON nunca supera eso; evita generaciones infinitas
OLLAMA_OPTIONS = {
    "temperature": 0.1,
    "num_ctx":     2048,
    "num_predict": 600,
}

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

def detectar_amenazas_python(logs: str, fuente: str) -> tuple:
    """
    Motor de detección de amenazas basado en reglas deterministas.

    Arquitectura híbrida: Python clasifica (confiable), LLM narra (creativo).
    Los LLMs pequeños (≤3B) son poco confiables contando ocurrencias en texto plano.
    Python garantiza que el brute force, escalada de privilegios y creación de usuarios
    sean clasificados correctamente con severidad 'high' o 'critical' siempre.

    Retorna:
      (severidad_minima: str, hallazgos: list[str])
      severidad_minima es el 'piso' — si el LLM da algo menor, se usa este valor.
    """
    hallazgos = []
    nivel_idx = 0  # índice en ORDEN_SEVERIDAD

    def subir_nivel(nuevo: str):
        nonlocal nivel_idx
        idx = ORDEN_SEVERIDAD.index(nuevo)
        if idx > nivel_idx:
            nivel_idx = idx

    if "ubuntu" in fuente.lower() or "linux" in fuente.lower():
        # ── SSH brute force ──────────────────────────────────────
        ssh_fallos: dict = {}
        for linea in logs.splitlines():
            if re.search(r'(Failed password|Invalid user|authentication failure)', linea, re.IGNORECASE):
                m = re.search(r'from ([0-9a-f:.]+)', linea)
                ip = m.group(1) if m else "unknown"
                ssh_fallos[ip] = ssh_fallos.get(ip, 0) + 1

        for ip, cnt in ssh_fallos.items():
            if cnt >= 5:
                hallazgos.append(f"Brute force SSH: {cnt} intentos fallidos desde {ip}")
                subir_nivel("critical")
            elif cnt >= 3:
                hallazgos.append(f"SSH sospechoso: {cnt} intentos fallidos desde {ip}")
                subir_nivel("high")
            else:
                hallazgos.append(f"Fallo SSH ({cnt}x) desde {ip}")
                subir_nivel("medium")

        # ── Root login por SSH ────────────────────────────────────
        if re.search(r'Accepted.*(password|publickey).*root', logs, re.IGNORECASE):
            hallazgos.append("Login SSH de root aceptado")
            subir_nivel("critical")

        # ── Sudo ─────────────────────────────────────────────────
        for m in re.finditer(r'sudo:\s+(\w+)\s+:', logs):
            usuario = m.group(1)
            if usuario.lower() not in ("root", "ansible", "deploy", "ubuntu"):
                hallazgos.append(f"Comando sudo ejecutado por usuario '{usuario}'")
                subir_nivel("high")

        # ── AppArmor en rutas sensibles (no /proc/ de browsers) ──
        for linea in logs.splitlines():
            if 'apparmor="DENIED"' in linea.lower():
                if not re.search(r'(firefox|snap|chromium|proc)', linea, re.IGNORECASE):
                    hallazgos.append(f"AppArmor DENIED en ruta sensible")
                    subir_nivel("high")

    else:  # Windows
        # ── Failed logons (Event 4625) por IP ────────────────────
        fallos_win: dict = {}
        for linea in logs.splitlines():
            if "ID:4625" in linea:
                m = re.search(r'(?:Source Network Address|Ip Address)[:\s]+([0-9.]+)', linea, re.IGNORECASE)
                ip = m.group(1) if m else "unknown"
                fallos_win[ip] = fallos_win.get(ip, 0) + 1

        for ip, cnt in fallos_win.items():
            if cnt >= 5:
                hallazgos.append(f"Brute force: {cnt} logons fallidos (4625) desde {ip}")
                subir_nivel("critical")
            elif cnt >= 3:
                hallazgos.append(f"Logons fallidos sospechosos ({cnt}x) desde {ip}")
                subir_nivel("high")
            else:
                hallazgos.append(f"Logon fallido ({cnt}x) desde {ip}")
                subir_nivel("medium")

        # ── Nueva cuenta + grupo (4720 + 4732) ────────────────────
        if re.search(r'ID:4720', logs) and re.search(r'ID:4732', logs):
            hallazgos.append("Nueva cuenta creada y añadida a grupo en la misma ventana (4720+4732)")
            subir_nivel("critical")
        elif re.search(r'ID:4720', logs):
            hallazgos.append("Nueva cuenta de usuario creada (Event 4720)")
            subir_nivel("high")

        # ── Privilegios especiales para cuentas no-SYSTEM ─────────
        for m in re.finditer(r'ID:4672.*?Account Name:\s*(\S+)', logs, re.IGNORECASE | re.DOTALL):
            cuenta = m.group(1).strip()
            if cuenta.upper() not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-", "ANONYMOUS LOGON"):
                hallazgos.append(f"Privilegios especiales asignados a '{cuenta}' (Event 4672)")
                subir_nivel("high")

        # ── FIM: eliminación de archivo (4660) ────────────────────
        if re.search(r'ID:4660', logs):
            hallazgos.append("Archivo eliminado en carpeta monitorizada (Event 4660)")
            subir_nivel("high")

        # ── Cambio en firewall (2003) ─────────────────────────────
        if re.search(r'ID:2003', logs):
            hallazgos.append("Regla de firewall modificada (Event 2003)")
            subir_nivel("high")

    severidad = ORDEN_SEVERIDAD[nivel_idx]
    return severidad, hallazgos


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

def analyze_with_ollama(logs: str, fuente: str = "windows") -> dict:
    # ── 1. Detección determinista Python (severidad garantizada) ──
    sev_python, hallazgos = detectar_amenazas_python(logs, fuente)

    # Construir resumen de hallazgos para el contexto del LLM
    ctx_hallazgos = ""
    if hallazgos:
        ctx_hallazgos = (
            "DETECCIONES CONFIRMADAS (no las cuestiones, usalas para el resumen):\n"
            + "\n".join(f"- {h}" for h in hallazgos)
        )

    # ── 2. Contexto específico por plataforma (para descripciones) ──
    if "ubuntu" in fuente.lower() or "linux" in fuente.lower():
        plataforma = "Ubuntu Linux"
        guia = "Enfocate en SSH, sudo, AppArmor y kernel."
    else:
        plataforma = "Windows"
        guia = "Enfocate en logons fallidos (4625), escalada de privilegios (4672/4673) y cambios de cuenta (4720)."

    prompt = f"""Sos un analista SOC senior. Analizá estos logs de seguridad de {plataforma} y devolvé un JSON.
Escribí SOLO JSON válido. Sin markdown, sin explicaciones, sin backticks.

Formato requerido:
{{
  "severity": "{sev_python}",
  "fuente": "{fuente}",
  "events": [
    {{"id": "EVENT_ID_O_TIPO", "descripcion": "descripcion en espanol", "riesgo": "nivel de riesgo en espanol"}}
  ],
  "summary": "resumen ejecutivo en espanol (1-2 oraciones, menciona IPs y cuentas si aplica)",
  "accion_recomendada": "accion concreta en espanol"
}}

Nota: el campo "severity" ya fue calculado por el motor de deteccion. No lo modifiques.
{guia}
{ctx_hallazgos}

Logs:
{logs}

JSON:"""

    payload = json.dumps({
        "model":   OLLAMA_MODEL,
        "prompt":  prompt,
        "stream":  False,
        "format":  "json",
        "options": OLLAMA_OPTIONS,
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_SEGUNDOS) as resp:
        data     = json.loads(resp.read())
        analysis = json.loads(data["response"].strip())

    # Sanitizar campos de texto: eliminar caracteres extraños y espacios dobles
    import re
    def _clean(text: str) -> str:
        if not isinstance(text, str):
            return text
        # Quitar caracteres de control y no imprimibles
        text = re.sub(r'[\x00-\x1f\x7f]', ' ', text)
        # Colapsar espacios múltiples
        text = re.sub(r' {2,}', ' ', text)
        return text.strip()

    analysis["summary"]            = _clean(analysis.get("summary", ""))
    analysis["accion_recomendada"] = _clean(analysis.get("accion_recomendada", ""))
    for ev in analysis.get("events", []):
        ev["descripcion"] = _clean(ev.get("descripcion", ""))
        ev["riesgo"]      = _clean(ev.get("riesgo", ""))

    return analysis

def enviar_telegram(summary: str, fuente: str, severity: str, ip: str = "",
                    tacticas: list = None, tecnicas: list = None,
                    ip_score: int = None, ip_pais: str = None) -> bool:
    """
    Envía una alerta HIGH/CRITICAL a Telegram vía Bot API.
    Incluye información de MITRE ATT&CK y AbuseIPDB si está disponible.
    Retorna True si el envío fue exitoso.
    """
    try:
        import urllib.request, json as _json, ssl as _ssl
        token   = database.get_config_global("telegram_bot_token", "").strip()
        chat_id = database.get_config_global("telegram_chat_id",   "").strip()
        activo  = database.get_config_global("telegram_activo",    "0") == "1"

        if not activo or not token or not chat_id:
            return False

        _ctx = _ssl.create_default_context()
        _ctx.check_hostname = False
        _ctx.verify_mode    = _ssl.CERT_NONE

        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")

        # Línea MITRE ATT&CK (si hay datos)
        mitre_linea = ""
        if tacticas or tecnicas:
            tac_str  = ", ".join(tacticas[:3]) if tacticas else "—"
            tec_list = [f"{t['id']} {t['nombre']}" for t in (tecnicas or [])[:3]]
            tec_str  = ", ".join(tec_list) if tec_list else "—"
            mitre_linea = f"🛡️ *MITRE ATT&CK:* {tac_str}\n🎯 *Técnica:* `{tec_str}`\n"

        # Línea AbuseIPDB (si hay datos)
        abuse_linea = ""
        if ip_score is not None:
            nivel = "🔴 MALICIOSA" if ip_score >= 90 else "🟠 Sospechosa" if ip_score >= 75 else "🟡 Bajo riesgo"
            abuse_linea = f"🌐 *IP Reputation:* {nivel} — Score `{ip_score}/100` ({ip_pais or '?'})\n"

        texto = (
            f"{sev_emoji} *SIEM ALERTA {severity.upper()}*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"*Agente:* `{fuente}`\n"
            f"*IP:* `{ip or 'desconocida'}`\n"
            f"*Resumen:* {summary[:300]}\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"{mitre_linea}"
            f"{abuse_linea}"
            f"_SIEM Local — {datetime.now().strftime('%d/%m/%Y %H:%M')}_"
        )
        payload = _json.dumps({
            "chat_id":    chat_id,
            "text":       texto,
            "parse_mode": "Markdown"
        }).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10, context=_ctx) as resp:
            data = _json.loads(resp.read())
            return data.get("ok", False)
    except Exception as e:
        log(f"  [Telegram] Error al enviar: {e}")
        return False


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

def procesar_ciclo():
    # Inicializar la base de datos al arrancar (crea tablas si no existen)
    database.init_db()
    log("SIEM Servidor iniciado")
    log(f"Modelo: {OLLAMA_MODEL} | Umbral: {SEVERITY_MINIMA.upper()}")
    log(f"Procesando eventos de todos los agentes cada {VENTANA_MINUTOS} minutos")
    log("-" * 50)

    ultimo_cleanup = datetime.now()

    while True:
        proxima = datetime.now() + timedelta(minutes=VENTANA_MINUTOS)
        log(f"Esperando eventos hasta {proxima.strftime('%H:%M:%S')}...")

        while datetime.now() < proxima:
            time.sleep(10)

        ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Limpieza de alertas antiguas — una vez cada 24 horas
        if (datetime.now() - ultimo_cleanup).total_seconds() > 86400:
            eliminadas = database.limpiar_alertas_antiguas()
            if eliminadas:
                log(f"[Retención] {eliminadas} alerta(s) eliminadas por política de retención")
            database.limpiar_sesiones_expiradas()
            ultimo_cleanup = datetime.now()

        # Leer eventos pendientes desde la DB (antes leía eventos_externos.jsonl)
        eventos = database.get_eventos_pendientes()

        if not eventos:
            log("Sin eventos pendientes de ningun agente")
            continue

        log(f"{len(eventos)} evento(s) pendiente(s) de agentes")

        for evento in eventos:
            evento_id = evento["id"]       # ID de la fila en eventos_externos
            agente    = evento.get("agente", "desconocido")
            ip        = evento.get("ip", "desconocida")
            logs      = evento.get("logs", "")

            if not logs.strip():
                # Marcar como procesado aunque esté vacío para no bloquear la cola
                database.marcar_evento_procesado(evento_id, None)
                continue

            # Filtrar ruido si es Linux
            if "ubuntu" in agente.lower() or "linux" in agente.lower():
                logs = filtrar_ruido_linux(logs)
                if not logs.strip():
                    log(f"  {agente} ({ip}) — solo ruido, ignorando")
                    database.marcar_evento_procesado(evento_id, None)
                    continue

            n = len(logs.splitlines())
            log(f"  Analizando {n} lineas de {agente} ({ip})...")

            try:
                analysis           = analyze_with_ollama(logs, fuente=agente)
                analysis["agente"] = agente
                analysis["ip"]     = ip

                # Enriquecer con MITRE ATT&CK antes de guardar
                mitre.enriquecer_alerta(analysis, logs)
                if analysis.get("tacticas"):
                    log(f"  ATT&CK: {', '.join(analysis['tacticas'])}")

                # Enriquecer con reputación de IP (AbuseIPDB)
                abuseipdb.enriquecer_analisis(analysis)
                if analysis.get("ip_score") is not None:
                    emoji = analysis.get("ip_info", {}).get("pais_emoji", "")
                    log(f"  IP {ip}: score={analysis['ip_score']} {emoji} ({analysis.get('ip_pais','-')})")

                # Garantizar que la severidad Python (determinista) sea el piso.
                # El LLM puede devolver algo menor por alucinación; Python no se equivoca.
                sev_python, _ = detectar_amenazas_python(logs, agente)
                sev_llm       = analysis.get("severity", "low")
                if ORDEN_SEVERIDAD.index(sev_python) > ORDEN_SEVERIDAD.index(sev_llm):
                    log(f"  Severidad corregida: LLM={sev_llm} → Python={sev_python}")
                    analysis["severity"] = sev_python

                # Descartar análisis "sin novedad" — el LLM a veces reporta
                # "no se detectaron eventos significativos" cuando no hay nada real.
                # No tiene sentido guardar alertas vacías de contenido.
                _summary_lower = analysis.get("summary", "").lower()
                _FRASES_RUIDO = [
                    "no hay eventos", "no se detectaron", "no se registraron",
                    "no se observaron", "sin eventos", "sin actividad",
                    "no significant", "nothing significant", "no events",
                    "actividad normal", "sin novedades", "sin incidentes",
                ]
                if any(f in _summary_lower for f in _FRASES_RUIDO) and analysis.get("severity") == "low":
                    log(f"  {agente}: sin novedad — descartado (no se guarda alerta)")
                    database.marcar_evento_procesado(evento_id, None)
                    continue

                alerta_id, es_nueva = database.guardar_alerta(analysis, ts)
                database.marcar_evento_procesado(evento_id, alerta_id)

                sev = analysis.get("severity", "low")
                if es_nueva:
                    log(f"  {agente}: {sev.upper()} — nueva alerta #{alerta_id} — {analysis.get('summary', '-')}")
                else:
                    log(f"  {agente}: {sev.upper()} — consolidado en alerta #{alerta_id} (+1 ocurrencia)")

                if sev in ("high", "critical"):
                    notificar_windows(sev, analysis.get("summary", ""), fuente=agente)
                    log(f"  Notificacion Windows enviada para {agente}")

                if sev in ("high", "critical"):
                    ok = enviar_telegram(
                        summary   = analysis.get("summary", ""),
                        fuente    = agente,
                        severity  = sev,
                        ip        = ip,
                        tacticas  = analysis.get("tacticas"),
                        tecnicas  = analysis.get("tecnicas"),
                        ip_score  = analysis.get("ip_score"),
                        ip_pais   = analysis.get("ip_pais"),
                    )
                    if ok:
                        log(f"  [Telegram] Alerta {sev.upper()} enviada correctamente")
                    else:
                        log(f"  [Telegram] No configurado o error al enviar")

                if ORDEN_SEVERIDAD.index(sev) >= ORDEN_SEVERIDAD.index(SEVERITY_MINIMA):
                    log(f"  ALERTA: {analysis.get('accion_recomendada', '-')}")
                    for ev in analysis.get("events", []):
                        log(f"    * {ev.get('id','-')} - {ev.get('descripcion','-')}")

            except Exception as e:
                log(f"  ERROR analizando {agente}: {e}")
                # Marcar como procesado incluso ante error para no bloquear la cola.
                # alerta_id=None indica que no se generó alerta para este evento.
                database.marcar_evento_procesado(evento_id, None)

if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    procesar_ciclo()
