"""
mitre.py — Módulo de enriquecimiento MITRE ATT&CK para el SIEM local.

Mapea eventos conocidos (Windows Event IDs, keywords Linux, tipos FIM)
a tácticas y técnicas del framework ATT&CK de MITRE.

Referencia: https://attack.mitre.org/
"""
import re
import json

# ─── MAPA: Windows Event ID → Técnica ATT&CK ─────────────────────────────────
# Solo los IDs relevantes para un entorno corporativo típico.
# Fuente: https://attack.mitre.org/datasources/DS0026/ (Windows Security Log)
EVENTOS_WINDOWS: dict = {
    # ── Credential Access ────────────────────────────────────────────────────
    4625: {"tecnica": "T1110",   "nombre": "Brute Force",                          "tactica": "Credential Access"},
    4771: {"tecnica": "T1110",   "nombre": "Brute Force (Kerberos pre-auth)",      "tactica": "Credential Access"},
    4768: {"tecnica": "T1558",   "nombre": "Steal or Forge Kerberos Tickets",      "tactica": "Credential Access"},
    4776: {"tecnica": "T1110",   "nombre": "Brute Force (NTLM)",                   "tactica": "Credential Access"},

    # ── Privilege Escalation ─────────────────────────────────────────────────
    4672: {"tecnica": "T1078",   "nombre": "Valid Accounts – Privileged",          "tactica": "Privilege Escalation"},
    4673: {"tecnica": "T1548",   "nombre": "Abuse Elevation Control Mechanism",   "tactica": "Privilege Escalation"},
    4674: {"tecnica": "T1548",   "nombre": "Abuse Elevation Control Mechanism",   "tactica": "Privilege Escalation"},

    # ── Persistence ──────────────────────────────────────────────────────────
    4720: {"tecnica": "T1136",   "nombre": "Create Account",                       "tactica": "Persistence"},
    4722: {"tecnica": "T1098",   "nombre": "Account Manipulation",                 "tactica": "Persistence"},
    4723: {"tecnica": "T1098",   "nombre": "Account Manipulation",                 "tactica": "Persistence"},
    4724: {"tecnica": "T1098",   "nombre": "Account Manipulation",                 "tactica": "Persistence"},
    4728: {"tecnica": "T1098",   "nombre": "Account Manipulation – Group Add",     "tactica": "Persistence"},
    4732: {"tecnica": "T1098",   "nombre": "Account Manipulation – Group Add",     "tactica": "Persistence"},
    4756: {"tecnica": "T1098",   "nombre": "Account Manipulation – Group Add",     "tactica": "Persistence"},
    4698: {"tecnica": "T1053",   "nombre": "Scheduled Task/Job",                   "tactica": "Persistence"},
    4702: {"tecnica": "T1053",   "nombre": "Scheduled Task/Job – Modified",        "tactica": "Persistence"},
    7045: {"tecnica": "T1543",   "nombre": "Create or Modify System Process",      "tactica": "Persistence"},

    # ── Impact ───────────────────────────────────────────────────────────────
    4725: {"tecnica": "T1531",   "nombre": "Account Access Removal",               "tactica": "Impact"},
    4726: {"tecnica": "T1531",   "nombre": "Account Access Removal",               "tactica": "Impact"},
    4660: {"tecnica": "T1485",   "nombre": "Data Destruction",                     "tactica": "Impact"},

    # ── Defense Evasion ──────────────────────────────────────────────────────
    1102: {"tecnica": "T1070",   "nombre": "Indicator Removal – Clear Logs",       "tactica": "Defense Evasion"},
    4719: {"tecnica": "T1562",   "nombre": "Impair Defenses – Audit Policy Change","tactica": "Defense Evasion"},

    # ── Lateral Movement ─────────────────────────────────────────────────────
    4648: {"tecnica": "T1550",   "nombre": "Use Alternate Authentication Material","tactica": "Lateral Movement"},
    4624: {"tecnica": "T1078",   "nombre": "Valid Accounts – Successful Login",    "tactica": "Initial Access"},

    # ── Execution ────────────────────────────────────────────────────────────
    4688: {"tecnica": "T1059",   "nombre": "Command and Scripting Interpreter",    "tactica": "Execution"},
}

# ─── MAPA: Tipos FIM → Técnica ATT&CK ────────────────────────────────────────
# Los tipos los genera el agente watchdog: ELIMINACION / MODIFICACION / CREACION / MOVIMIENTO
FIM_MAP: dict = {
    "ELIMINACION":  ("T1485", "Data Destruction",      "Impact"),
    "MODIFICACION": ("T1565", "Data Manipulation",     "Impact"),
    "CREACION":     ("T1105", "Ingress Tool Transfer", "Command and Control"),
    "MOVIMIENTO":   ("T1036", "Masquerading",          "Defense Evasion"),
}

# ─── MAPA: Palabras clave Linux → Técnica ATT&CK ─────────────────────────────
# Cada entrada: (patron_regex, tecnica_id, nombre_tecnica, tactica)
# Se aplica contra los logs de texto plano antes de que Ollama los procese.
KEYWORDS_LINUX: list = [
    (r"failed password|invalid user|authentication failure",
     "T1110", "Brute Force",                          "Credential Access"),
    (r"accepted .*(password|publickey).*root",
     "T1078", "Valid Accounts – Root Login",          "Initial Access"),
    (r"\bsu\s*:",
     "T1548", "Abuse Elevation Control Mechanism",    "Privilege Escalation"),
    (r"\bsudo\b",
     "T1548", "Abuse Elevation Control Mechanism",    "Privilege Escalation"),
    (r"useradd|adduser",
     "T1136", "Create Account",                       "Persistence"),
    (r"passwd:.*changed|password changed",
     "T1098", "Account Manipulation",                 "Persistence"),
    (r"segfault",
     "T1203", "Exploitation for Client Execution",    "Execution"),
    (r'apparmor="DENIED"',
     "T1562", "Impair Defenses",                      "Defense Evasion"),
    (r"connection refused|port scan|nmap",
     "T1046", "Network Service Discovery",            "Discovery"),
    (r"crontab|cron\.d",
     "T1053", "Scheduled Task/Job",                   "Persistence"),
]

# ─── COLORES POR TÁCTICA (para la UI) ────────────────────────────────────────
TACTICA_COLORES: dict = {
    "Initial Access":          "#e3b341",   # amarillo
    "Execution":               "#f0883e",   # naranja
    "Persistence":             "#bc8cff",   # púrpura
    "Privilege Escalation":    "#f85149",   # rojo
    "Defense Evasion":         "#79c0ff",   # azul claro
    "Credential Access":       "#ff7b72",   # coral
    "Discovery":               "#56d364",   # verde
    "Lateral Movement":        "#ffa657",   # ámbar
    "Collection":              "#d2a8ff",   # lavanda
    "Command and Control":     "#58a6ff",   # azul
    "Exfiltration":            "#e3b341",   # amarillo
    "Impact":                  "#f85149",   # rojo
}

# ─── FUNCIÓN PRINCIPAL ────────────────────────────────────────────────────────

def enriquecer_alerta(analysis: dict, logs: str = "") -> dict:
    """
    Añade 'tacticas' (list[str]) y 'tecnicas' (list[dict]) al diccionario
    de análisis, mapeando eventos conocidos a MITRE ATT&CK.

    Fuentes de mapeo (en orden):
      1. Event IDs encontrados en los eventos del análisis (campo 'id')
      2. Event IDs encontrados en el texto crudo de los logs
      3. Keywords Linux sobre el texto de los logs
      4. Tipos FIM (ELIMINACION/MODIFICACION/CREACION/MOVIMIENTO) en los eventos

    El dict 'analysis' se modifica in-place y también se retorna.
    """
    tacticas_set: set  = set()
    tecnicas_list: list = []
    vistos: set         = set()   # evita duplicados por técnica id

    def _agregar(tid: str, nombre: str, tactica: str):
        if tid not in vistos:
            vistos.add(tid)
            tecnicas_list.append({"id": tid, "nombre": nombre, "tactica": tactica})
            tacticas_set.add(tactica)

    # ── 1. Event IDs en los eventos del análisis ──────────────────────────
    for ev in analysis.get("events", []):
        eid = str(ev.get("id", ""))
        m = re.search(r'\b(\d{4,5})\b', eid)
        if m:
            num = int(m.group(1))
            if num in EVENTOS_WINDOWS:
                t = EVENTOS_WINDOWS[num]
                _agregar(t["tecnica"], t["nombre"], t["tactica"])

    # ── 2. Event IDs en el texto crudo de logs ────────────────────────────
    if logs:
        for m in re.finditer(r'\bID:(\d+)\b', logs):
            num = int(m.group(1))
            if num in EVENTOS_WINDOWS:
                t = EVENTOS_WINDOWS[num]
                _agregar(t["tecnica"], t["nombre"], t["tactica"])

        # ── 3. Keywords Linux ─────────────────────────────────────────────
        for patron, tid, nombre, tactica in KEYWORDS_LINUX:
            if re.search(patron, logs, re.IGNORECASE):
                _agregar(tid, nombre, tactica)

    # ── 4. Tipos FIM en los event IDs ─────────────────────────────────────
    for ev in analysis.get("events", []):
        eid = str(ev.get("id", "")).upper()
        for fim_tipo, (tid, nombre, tactica) in FIM_MAP.items():
            if fim_tipo in eid:
                _agregar(tid, nombre, tactica)
                break

    # También desde el summary y accion del análisis (para alertas Ollama)
    _summary = (analysis.get("summary", "") + " " + analysis.get("accion_recomendada", "")).upper()
    if "BRUTE FORCE" in _summary or "LOGON FALLIDO" in _summary or "FUERZA BRUTA" in _summary:
        _agregar("T1110", "Brute Force", "Credential Access")
    if "PRIVILEGIO" in _summary or "ESCALAD" in _summary or "PRIVILEGE" in _summary:
        _agregar("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation")
    if "NUEVA CUENTA" in _summary or "USUARIO CREADO" in _summary or "CREATE ACCOUNT" in _summary:
        _agregar("T1136", "Create Account", "Persistence")

    # Ordenar tácticas en el orden canónico de la kill chain ATT&CK
    ORDEN_TACTICAS = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
    ]
    tacticas_ordenadas = sorted(
        tacticas_set,
        key=lambda t: ORDEN_TACTICAS.index(t) if t in ORDEN_TACTICAS else 99
    )

    analysis["tacticas"] = tacticas_ordenadas
    analysis["tecnicas"] = tecnicas_list
    return analysis


def color_tactica(tactica: str) -> str:
    """Retorna el color hex asignado a una táctica ATT&CK para la UI."""
    return TACTICA_COLORES.get(tactica, "#8b949e")


def estadisticas(alertas: list) -> dict:
    """
    Calcula distribución de tácticas y top técnicas a partir de una lista
    de alertas (cada alerta ya tiene 'tacticas' y 'tecnicas' como listas).

    Retorna:
      {
        "por_tactica": {"Credential Access": 12, ...},
        "top_tecnicas": [{"id": "T1110", "nombre": ..., "tactica": ..., "count": 10}, ...],
        "colores_tactica": {"Credential Access": "#ff7b72", ...}
      }
    """
    por_tactica: dict  = {}
    tecnicas_cnt: dict = {}   # tid → {"id","nombre","tactica","count"}

    for alerta in alertas:
        tacticas = alerta.get("tacticas") or []
        tecnicas = alerta.get("tecnicas") or []

        # Parsear si vienen como string JSON (directo desde DB)
        if isinstance(tacticas, str):
            try:
                tacticas = json.loads(tacticas)
            except Exception:
                tacticas = []
        if isinstance(tecnicas, str):
            try:
                tecnicas = json.loads(tecnicas)
            except Exception:
                tecnicas = []

        for t in tacticas:
            por_tactica[t] = por_tactica.get(t, 0) + 1

        for tec in tecnicas:
            tid = tec.get("id", "")
            if tid not in tecnicas_cnt:
                tecnicas_cnt[tid] = {"id": tid, "nombre": tec.get("nombre", tid),
                                     "tactica": tec.get("tactica", ""), "count": 0}
            tecnicas_cnt[tid]["count"] += 1

    top_tecnicas = sorted(tecnicas_cnt.values(), key=lambda x: x["count"], reverse=True)[:10]

    return {
        "por_tactica":     por_tactica,
        "top_tecnicas":    top_tecnicas,
        "colores_tactica": {t: color_tactica(t) for t in por_tactica},
    }
