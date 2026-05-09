import json
import os
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
from urllib.parse import urlparse
from pathlib import Path

import database  # módulo local — persistencia SQLite
import auth      # módulo local — autenticación bcrypt + sesiones
import secrets as _secrets_mod

# ── Tokens temporales para login en dos pasos (TOTP) ─────────
# Mapa: temp_token → {"username": str, "expires": datetime}
# Expiran en 5 minutos. Se limpian al usar o al expirar.
_pending_totp: dict = {}
_pending_totp_lock  = threading.Lock()   # protege acceso concurrente al dict


def _enviar_telegram_fim(summary: str, fuente: str, severity: str, archivo: str, ip: str = ""):
    """
    Notifica por Telegram cuando el endpoint FIM genera una alerta HIGH o CRITICAL.
    Solo envía si telegram_activo=1 y las credenciales están configuradas.
    """
    import urllib.request as _req, urllib.error as _uerr, json as _json, ssl as _ssl
    from pathlib import Path as _Path

    _log_path = _Path(__file__).parent.parent.parent / "logs" / "telegram.log"

    def _tg_log(msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}\n"
        print("[TELEGRAM]", msg)
        try:
            _log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(_log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

    try:
        token   = database.get_config_global("telegram_bot_token", "").strip()
        chat_id = database.get_config_global("telegram_chat_id",   "").strip()
        activo  = database.get_config_global("telegram_activo",    "0") == "1"

        _tg_log(f"activo={activo} token_len={len(token)} chat_id={chat_id!r}")

        if not activo:
            _tg_log("Notificaciones desactivadas — omitiendo")
            return
        if not token or not chat_id:
            _tg_log("Token o chat_id vacíos — omitiendo")
            return

        _ctx = _ssl.create_default_context()
        _ctx.check_hostname = False
        _ctx.verify_mode    = _ssl.CERT_NONE

        # Extraer nombre de archivo de la ruta completa
        import os as _os
        nombre_archivo = _os.path.basename(archivo) or archivo

        tipo_emoji = {
            "ELIMINACION":  "🗑️",
            "MODIFICACION": "✏️",
            "CREACION":     "📄",
            "MOVIMIENTO":   "📦",
        }
        accion_label = {
            "ELIMINACION":  "Archivo eliminado",
            "MODIFICACION": "Archivo modificado",
            "CREACION":     "Archivo creado",
            "MOVIMIENTO":   "Archivo movido/renombrado",
        }
        # Detectar tipo desde el summary
        tipo_detectado = "ELIMINACION" if "eliminado" in summary.lower() else \
                         "MODIFICACION" if "modificado" in summary.lower() else \
                         "CREACION" if "creado" in summary.lower() else \
                         "MOVIMIENTO" if "movido" in summary.lower() else "DESCONOCIDO"

        sev_emoji  = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(severity, "⚪")
        evento_ico = tipo_emoji.get(tipo_detectado, "⚠️")
        evento_lbl = accion_label.get(tipo_detectado, summary)

        texto = (
            f"{sev_emoji} *Alerta FIM — {severity.upper()}*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{evento_ico} *Evento:* {evento_lbl}\n"
            f"📁 *Archivo:* `{nombre_archivo}`\n"
            f"📂 *Ruta:* `{archivo}`\n"
            f"🖥️ *Agente:* `{fuente}`  \\|  `{ip or 'desconocida'}`\n"
            f"🕐 *Hora:* {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⚡ _Revisá el Dashboard para más detalles_"
        )
        payload = _json.dumps({
            "chat_id": chat_id, "text": texto, "parse_mode": "Markdown"
        }).encode("utf-8")
        req = _req.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload, headers={"Content-Type": "application/json"}
        )
        with _req.urlopen(req, timeout=10, context=_ctx) as r:
            resp = r.read().decode()
            _tg_log(f"Enviado OK — {resp[:120]}")

    except _uerr.HTTPError as e:
        _tg_log(f"HTTP {e.code}: {e.read().decode()[:200]}")
    except Exception as e:
        _tg_log(f"ERROR {type(e).__name__}: {e}")

# ─── CONFIGURACION ───────────────────────────────────────────
# Raíz del proyecto: src/server/ → src/ → raíz
_ROOT       = Path(__file__).parent.parent.parent

SIEM_LOG    = _ROOT / "logs" / "siem_output.log"
PDF_OUTPUT  = _ROOT / "data"  / "reporte_siem.pdf"
CONFIG_FILE = _ROOT / "data"  / "config.json"
INDEX_HTML  = _ROOT / "src"   / "web" / "index.html"

# Rutas legacy para migración única al primer arranque
LEGACY_ALERTAS_JSONL = _ROOT / "data" / "alertas.jsonl"
LEGACY_TICKETS_JSON  = _ROOT / "data" / "tickets.json"
# ─────────────────────────────────────────────────────────────


# ─── Helpers de archivos (no requieren DB) ────────────────────

def leer_config():
    if not os.path.exists(CONFIG_FILE):
        return {"carpetas_monitoreadas": []}
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def guardar_config(config):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

def leer_estado_siem():
    """Parsea el log del servidor SIEM para obtener estado y timestamps."""
    if not os.path.exists(SIEM_LOG):
        return {"ultimo": None, "proximo": None, "total_escaneos": 0, "estado": "detenido"}
    try:
        try:
            with open(SIEM_LOG, "r", encoding="utf-16", errors="replace") as f:
                lineas = f.readlines()
        except Exception:
            with open(SIEM_LOG, "r", encoding="utf-8", errors="replace") as f:
                lineas = f.readlines()
    except Exception:
        return {"ultimo": None, "proximo": None, "total_escaneos": 0, "estado": "detenido"}

    ultimo = None
    escaneos = 0
    estado   = "detenido"

    for l in lineas:
        if "Esperando eventos hasta" in l:
            escaneos += 1
            estado    = "activo"
            try:
                inicio = l.index("[") + 1
                fin    = l.index("]")
                ultimo = l[inicio:fin]
            except Exception:
                pass

    proximo = None
    if ultimo:
        try:
            dt      = datetime.strptime(ultimo, "%Y-%m-%d %H:%M:%S")
            proximo = (dt + timedelta(minutes=5)).strftime("%H:%M:%S")
        except Exception:
            pass

    return {"ultimo": ultimo, "proximo": proximo,
            "total_escaneos": escaneos, "estado": estado}


def generar_csv(alertas: list) -> str:
    """Genera un CSV con las alertas para exportar a Excel."""
    import csv, io
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "ID", "Timestamp", "Severidad", "Fuente", "IP",
        "Resumen", "Acción recomendada", "Estado", "Ocurrencias", "Última vez"
    ])
    for a in alertas:
        writer.writerow([
            a.get("id", ""),
            a.get("timestamp", ""),
            a.get("severity", ""),
            a.get("fuente", ""),
            a.get("ip", ""),
            a.get("summary", ""),
            a.get("accion_recomendada", ""),
            a.get("estado", ""),
            a.get("ocurrencias", 1),
            a.get("ultima_vez", ""),
        ])
    return out.getvalue()


def generar_pdf_auditoria(registros: list, filtros: dict = None):
    """Genera un PDF del log de auditoría con los registros recibidos."""
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER, TA_LEFT

    PDF_AUDIT = PDF_OUTPUT.parent / "auditoria_siem.pdf"
    doc = SimpleDocTemplate(str(PDF_AUDIT), pagesize=landscape(A4),
                            leftMargin=1.5*cm, rightMargin=1.5*cm,
                            topMargin=1.5*cm, bottomMargin=1.5*cm)
    story = []

    ACCENT = colors.HexColor("#58a6ff")
    GRAY   = colors.HexColor("#8b949e")
    WHITE  = colors.white
    GREEN  = colors.HexColor("#3fb950")
    RED    = colors.HexColor("#f85149")

    titulo_s = ParagraphStyle("t", fontSize=18, fontName="Helvetica-Bold",
                               textColor=ACCENT, alignment=TA_CENTER, spaceAfter=4)
    sub_s    = ParagraphStyle("s", fontSize=9,  fontName="Helvetica",
                               textColor=GRAY, alignment=TA_CENTER, spaceAfter=14)
    cell_s   = ParagraphStyle("c", fontSize=7.5, fontName="Helvetica", textColor=colors.black)
    bold_s   = ParagraphStyle("b", fontSize=7.5, fontName="Helvetica-Bold", textColor=colors.black)

    story.append(Paragraph("SIEM Local — Log de Auditoría", titulo_s))
    story.append(Paragraph(
        f"Generado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}  |  "
        f"{len(registros)} registros", sub_s
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 10))

    # Sección de filtros aplicados
    if filtros:
        partes = []
        if filtros.get("fecha_desde") or filtros.get("fecha_hasta"):
            partes.append(f"Período: {filtros.get('fecha_desde','inicio')} → {filtros.get('fecha_hasta','hoy')}")
        if filtros.get("usuario"):
            partes.append(f"Usuario: {filtros['usuario']}")
        if filtros.get("accion"):
            partes.append(f"Acción: {filtros['accion']}")
        if partes:
            filt_s = ParagraphStyle("f", fontSize=8, fontName="Helvetica-Oblique",
                                    textColor=GRAY, spaceAfter=10)
            story.append(Paragraph("Filtros: " + "  ·  ".join(partes), filt_s))

    # Tabla de registros
    headers = ["Fecha", "Usuario", "Acción", "Entidad", "Valor anterior", "Valor nuevo"]
    rows = [[Paragraph(h, bold_s) for h in headers]]

    ACCION_COLOR = {
        "login": colors.HexColor("#3fb95022"),
        "login_fallido": colors.HexColor("#f8514922"),
        "logout": colors.HexColor("#8b949e22"),
        "eliminar_usuario": colors.HexColor("#f8514922"),
        "eliminar_rol": colors.HexColor("#f8514922"),
    }

    for r in registros:
        entidad_txt = r.get("entidad", "") or ""
        if r.get("id_entidad"):
            entidad_txt += f" #{r['id_entidad']}"
        rows.append([
            Paragraph(str(r.get("ts",""))[:16], cell_s),
            Paragraph(str(r.get("usuario","")), bold_s),
            Paragraph(str(r.get("accion","")), cell_s),
            Paragraph(entidad_txt, cell_s),
            Paragraph(str(r.get("valor_anterior","") or "—")[:60], cell_s),
            Paragraph(str(r.get("valor_nuevo","") or "—")[:80], cell_s),
        ])

    col_widths = [3.2*cm, 2.5*cm, 4.5*cm, 3.5*cm, 4.5*cm, 6.3*cm]
    t = Table(rows, colWidths=col_widths, repeatRows=1)

    row_colors = []
    for i, r in enumerate(registros, start=1):
        bg = ACCION_COLOR.get(r.get("accion",""), colors.white)
        row_colors.append(("BACKGROUND", (0, i), (-1, i), bg))

    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  ACCENT),
        ("TEXTCOLOR",     (0,0), (-1,0),  WHITE),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 7.5),
        ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#d0d0d0")),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.HexColor("#f8f9fa"), WHITE]),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ] + row_colors))

    story.append(t)
    story.append(Spacer(1, 10))
    footer_s = ParagraphStyle("ft", fontSize=7, fontName="Helvetica-Oblique",
                               textColor=GRAY, alignment=TA_CENTER)
    story.append(HRFlowable(width="100%", thickness=0.3, color=GRAY))
    story.append(Paragraph(
        f"Reporte de auditoría generado automáticamente — SIEM Local — "
        f"{datetime.now().strftime('%d/%m/%Y')}", footer_s
    ))
    doc.build(story)
    return PDF_AUDIT


def generar_pdf(alertas: list, filtros: dict = None):
    """
    Genera un PDF con resumen ejecutivo y detalle de alertas.
    Si se pasan filtros, se muestra una sección con los criterios aplicados.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER

    doc   = SimpleDocTemplate(str(PDF_OUTPUT), pagesize=A4,
                              leftMargin=2*cm, rightMargin=2*cm,
                              topMargin=2*cm, bottomMargin=2*cm)
    story = []

    ACCENT = colors.HexColor("#58a6ff")
    RED    = colors.HexColor("#f85149")
    ORANGE = colors.HexColor("#ff7b72")
    YELLOW = colors.HexColor("#e3b341")
    GREEN  = colors.HexColor("#3fb950")
    GRAY   = colors.HexColor("#8b949e")
    WHITE  = colors.white
    SEV_COLOR = {"critical": RED, "high": ORANGE, "medium": YELLOW, "low": GREEN}

    titulo_style = ParagraphStyle("titulo", fontSize=22, fontName="Helvetica-Bold",
                                  textColor=ACCENT, alignment=TA_CENTER, spaceAfter=4)
    sub_style    = ParagraphStyle("sub",    fontSize=10, fontName="Helvetica",
                                  textColor=GRAY, alignment=TA_CENTER, spaceAfter=20)
    sec_style    = ParagraphStyle("sec",    fontSize=13, fontName="Helvetica-Bold",
                                  textColor=ACCENT, spaceBefore=14, spaceAfter=6)
    body_style   = ParagraphStyle("body",   fontSize=9, fontName="Helvetica",
                                  textColor=colors.black, spaceAfter=3)
    footer_style = ParagraphStyle("footer", fontSize=7, fontName="Helvetica-Oblique",
                                  textColor=GRAY, alignment=TA_CENTER, spaceBefore=8)

    story.append(Paragraph("SIEM Dashboard — Reporte de Seguridad", titulo_style))
    story.append(Paragraph(
        f"Generado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}  |  "
        f"Motor: Ollama  |  Monitoreo: Local + Agentes", sub_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 14))

    # Sección de filtros aplicados (solo si se pasaron filtros)
    if filtros:
        partes = []
        if filtros.get("fecha_desde") or filtros.get("fecha_hasta"):
            rng = f"{filtros.get('fecha_desde','inicio')} → {filtros.get('fecha_hasta','hoy')}"
            partes.append(f"Período: {rng}")
        if filtros.get("severidades"):
            partes.append(f"Severidad: {', '.join(filtros['severidades'])}")
        if filtros.get("estados"):
            partes.append(f"Estado: {', '.join(filtros['estados'])}")
        if filtros.get("fuentes"):
            partes.append(f"Agentes: {', '.join(filtros['fuentes'])}")
        if partes:
            filtros_style = ParagraphStyle("filt", fontSize=9, fontName="Helvetica-Oblique",
                                           textColor=GRAY, spaceBefore=0, spaceAfter=12,
                                           backColor=colors.HexColor("#f8f9fa"),
                                           borderPad=6, borderColor=ACCENT, borderWidth=0.5)
            story.append(Paragraph("Filtros aplicados: " + "  ·  ".join(partes), filtros_style))
            story.append(Spacer(1, 4))

    cnt = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alertas:
        s = a.get("severity", "low")
        if s in cnt:
            cnt[s] += 1

    resueltas        = sum(1 for a in alertas if a.get("estado") == "resuelta")
    falsos_positivos = sum(1 for a in alertas if a.get("estado") == "falso-positivo")
    investigando     = sum(1 for a in alertas if a.get("estado") == "investigando")
    nuevas           = sum(1 for a in alertas if a.get("estado") == "nueva")

    story.append(Paragraph("Resumen Ejecutivo", sec_style))
    data_resumen = [
        ["Severidad", "Cantidad", "Estado",          "Cantidad"],
        ["CRITICAL",  str(cnt["critical"]), "Resueltas",         str(resueltas)],
        ["HIGH",      str(cnt["high"]),     "Falsos positivos",  str(falsos_positivos)],
        ["MEDIUM",    str(cnt["medium"]),   "En investigacion",  str(investigando)],
        ["LOW",       str(cnt["low"]),      "Nuevas",            str(nuevas)],
    ]
    t = Table(data_resumen, colWidths=[4*cm, 3*cm, 5*cm, 3*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (-1,0),  ACCENT),
        ("TEXTCOLOR",      (0,0), (-1,0),  WHITE),
        ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 9),
        ("ALIGN",          (0,0), (-1,-1), "CENTER"),
        ("GRID",           (0,0), (-1,-1), 0.5, colors.HexColor("#30363d")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8f9fa"), WHITE]),
        ("TEXTCOLOR",      (0,1), (0,1),   RED),
        ("TEXTCOLOR",      (0,2), (0,2),   ORANGE),
        ("TEXTCOLOR",      (0,3), (0,3),   YELLOW),
        ("TEXTCOLOR",      (0,4), (0,4),   GREEN),
        ("FONTNAME",       (0,1), (0,-1),  "Helvetica-Bold"),
        ("TOPPADDING",     (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d")))
    story.append(Paragraph("Detalle de Alertas", sec_style))

    if not alertas:
        story.append(Paragraph("Sin alertas registradas.", body_style))
    else:
        for a in alertas:
            sev   = a.get("severity", "low")
            color = SEV_COLOR.get(sev, GREEN)
            estado = a.get("estado", "nueva").upper()
            ts    = a.get("timestamp", "-")

            h_sev     = ParagraphStyle("hs",  fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)
            h_summary = ParagraphStyle("hsu", fontSize=9, fontName="Helvetica",      textColor=WHITE)
            h_ts      = ParagraphStyle("hts", fontSize=8, fontName="Helvetica",
                                       textColor=colors.HexColor("#cccccc"))

            header_data = [[
                Paragraph(sev.upper(),           h_sev),
                Paragraph(a.get("summary", "-"), h_summary),
                Paragraph(f"{estado}  |  {ts}",  h_ts),
            ]]
            th = Table(header_data, colWidths=[2.2*cm, 10*cm, 4.8*cm])
            th.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), color),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ]))
            story.append(th)

            body_rows = [["Accion recomendada:", a.get("accion_recomendada", "-")]]
            for ev in a.get("events", []):
                body_rows.append([
                    f"ID {ev.get('id', '-')}",
                    f"{ev.get('descripcion', '-')} — Riesgo: {ev.get('riesgo', '-')}"
                ])
            for c in a.get("comentarios", []):
                body_rows.append([f"Nota ({c.get('ts', '')})", c.get("texto", "-")])

            col_style = ParagraphStyle("cs", fontSize=8, fontName="Helvetica-Bold", textColor=GRAY)
            val_style = ParagraphStyle("vs", fontSize=8, fontName="Helvetica", textColor=colors.black)
            tb_data   = [[Paragraph(r[0], col_style), Paragraph(r[1], val_style)] for r in body_rows]
            tb = Table(tb_data, colWidths=[3.5*cm, 13.5*cm])
            tb.setStyle(TableStyle([
                ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#e0e0e0")),
                ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#fafafa")),
                ("TOPPADDING",    (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ]))
            story.append(tb)
            story.append(Spacer(1, 8))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d")))
    story.append(Paragraph(
        f"Reporte generado automaticamente por SIEM local con IA — "
        f"{datetime.now().strftime('%d/%m/%Y')}", footer_style
    ))
    doc.build(story)
    return PDF_OUTPUT


# ─── Handler HTTP ─────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Suprimir logs HTTP del servidor para no ensuciar la consola

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    # ── Middleware de autenticación ───────────────────────────

    def _get_token(self) -> str:
        """
        Extrae el token del header Authorization.
        Formato esperado: "Authorization: Bearer <token>"
        El frontend lo envía desde sessionStorage en cada request protegido.
        """
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]  # Eliminar el prefijo "Bearer "
        return ""

    def _get_user(self) -> dict | None:
        """Retorna el usuario autenticado o None si el token es inválido/expirado."""
        return auth.get_session_user(self._get_token())

    def _require_auth(self) -> dict | None:
        """
        Verifica autenticación. Envía 401 y retorna None si falla.
        El 401 le indica al frontend que debe redirigir al login.

        Si el usuario tiene 'debe_cambiar_password=1', bloquea todos los endpoints
        salvo /api/me, /api/me/password y /api/logout, forzando el cambio antes de operar.
        """
        user = self._get_user()
        if not user:
            self.send_json({"error": "No autenticado. Iniciá sesión."}, 401)
            return None
        path = urlparse(self.path).path
        PERMITIDOS_FORZADO = {"/api/me", "/api/me/password", "/api/logout"}
        if user.get("debe_cambiar_password") and path not in PERMITIDOS_FORZADO:
            self.send_json({
                "error": "Debés cambiar tu contraseña antes de continuar.",
                "debe_cambiar_password": True
            }, 403)
            return None
        return user

    def _require_admin(self) -> dict | None:
        """
        Verifica que el usuario sea administrador (rol TEXT = 'admin').
        Usado para operaciones de sistema que siempre requieren admin
        independientemente de los permisos RBAC custom.
        """
        user = self._require_auth()
        if not user:
            return None
        if user.get("rol") != "admin":
            self.send_json({"error": "Acción restringida a administradores."}, 403)
            return None
        return user

    def _require_permission(self, codigo: str) -> dict | None:
        """
        Verifica que el usuario autenticado tenga el permiso especificado.

        Jerarquía de verificación:
          1. Token válido → _require_auth()
          2. Carga permisos: usuario.rol_id → roles → rol_permisos → permisos.codigo
          3. Si 'codigo' no está en el set → 403 Forbidden

        Más granular que _require_admin(): un analista puede tener
        'exportar_reportes' sin tener acceso a gestión de usuarios.
        """
        user = self._require_auth()
        if not user:
            return None
        permisos = database.obtener_permisos_usuario(user["id"])
        if codigo not in permisos:
            self.send_json(
                {"error": f"No tenés permiso para esta acción ({codigo})."}, 403
            )
            return None
        return user

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    # ── GET ───────────────────────────────────────────────────

    def do_GET(self):
        path = urlparse(self.path).path

        # ── Rutas públicas (sin auth) ─────────────────────────
        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            with open(INDEX_HTML, "rb") as f:
                self.wfile.write(f.read())
            return

        # ── Rutas protegidas (requieren token válido) ─────────
        if path == "/api/alertas":
            if not self._require_permission("ver_alertas"):
                return
            self.send_json(database.leer_alertas())

        elif path == "/api/estado-siem":
            if not self._require_auth():
                return
            self.send_json(leer_estado_siem())

        elif path == "/api/config":
            if not self._require_permission("ver_config"):
                return
            self.send_json(leer_config())

        elif path == "/api/eventos-externos":
            if not self._require_auth():
                return
            self.send_json(database.leer_eventos_externos())

        elif path == "/api/agentes":
            if not self._require_permission("ver_agentes"):
                return
            self.send_json(database.leer_config_agentes())

        elif path == "/api/agentes/tracking":
            # Datos de tracking histórico (tabla agentes): nombre, ip, tipo, ultimo_contacto.
            # La strip del resumen usa este endpoint para calcular estado online/offline en tiempo real.
            if not self._require_permission("ver_agentes"):
                return
            self.send_json(database.leer_agentes())

        elif path == "/api/usuarios":
            if not self._require_permission("ver_usuarios"):
                return
            self.send_json(database.leer_usuarios())

        elif path == "/api/roles":
            if not self._require_permission("gestionar_roles"):
                return
            self.send_json(database.leer_roles())

        elif path == "/api/permisos":
            if not self._require_permission("gestionar_roles"):
                return
            self.send_json(database.leer_permisos())

        elif path == "/api/me":
            # No pasa por _require_auth para no bloquear si debe_cambiar_password=1
            user = self._get_user()
            if not user:
                self.send_json({"error": "No autenticado."}, 401)
                return
            permisos = database.obtener_permisos_usuario(user["id"])
            self.send_json({
                "username":              user["username"],
                "rol":                   user["rol"],
                "rol_id":                user.get("rol_id"),
                "debe_cambiar_password": bool(user.get("debe_cambiar_password", 0)),
                "permisos":              list(permisos)
            })

        elif path == "/api/pdf":
            if not self._require_permission("exportar_reportes"):
                return
            try:
                alertas = database.leer_alertas()
                pdf     = generar_pdf(alertas)
                with open(pdf, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", "attachment; filename=reporte_siem.pdf")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)

        elif path == "/api/auditoria":
            if not self._require_permission("ver_auditoria"):
                return
            self.send_json(database.leer_auditoria())

        elif path == "/api/auditoria/acciones":
            if not self._require_permission("ver_auditoria"):
                return
            self.send_json(database.leer_acciones_distintas())

        elif path == "/api/totp/estado":
            user = self._require_auth()
            if not user:
                return
            secret = database.get_totp_secret(user["username"])
            self.send_json({"configurado": bool(secret)})

        elif path == "/api/config/forzar-2fa":
            user = self._require_permission("editar_config")
            if not user:
                return
            self.send_json({"forzar_2fa": database.get_config_global("forzar_2fa") == "1"})

        elif path == "/api/config/seguridad":
            user = self._require_permission("editar_config")
            if not user:
                return
            cfg = database.get_all_config_global()
            # Excluir token de Telegram del GET de seguridad general
            self.send_json({
                "session_timeout_minutos":  cfg.get("session_timeout_minutos", "30"),
                "password_min_length":      cfg.get("password_min_length", "8"),
                "password_require_upper":   cfg.get("password_require_upper", "1"),
                "password_require_number":  cfg.get("password_require_number", "1"),
                "password_require_special": cfg.get("password_require_special", "0"),
                "login_max_intentos":       cfg.get("login_max_intentos", "5"),
                "login_bloqueo_minutos":    cfg.get("login_bloqueo_minutos", "15"),
                "forzar_2fa":               cfg.get("forzar_2fa", "0"),
                "alerta_retencion_dias":    cfg.get("alerta_retencion_dias", "90"),
            })

        elif path == "/api/config/telegram":
            user = self._require_permission("editar_config")
            if not user:
                return
            token   = database.get_config_global("telegram_bot_token", "")
            chat_id = database.get_config_global("telegram_chat_id",   "")
            activo  = database.get_config_global("telegram_activo",    "0")
            # Enmascarar el token en la respuesta (seguridad)
            token_masked = f"{'*' * (len(token) - 6)}{token[-6:]}" if len(token) > 6 else ("*" * len(token))
            self.send_json({
                "activo":        activo == "1",
                "token_masked":  token_masked,
                "chat_id":       chat_id,
                "configurado":   bool(token and chat_id),
            })

        else:
            self.send_response(404)
            self.end_headers()

    # ── POST ──────────────────────────────────────────────────

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_body()

        # ── Auth: Login (pública) ─────────────────────────────
        if path == "/api/login":
            username = body.get("username", "").strip()
            password = body.get("password", "")
            if not username or not password:
                self.send_json({"error": "Completá usuario y contraseña."}, 400)
                return
            resultado = auth.login(username, password)
            if resultado and "error" in resultado:
                # Cuenta bloqueada
                database.registrar_auditoria(username, "login_bloqueado", "sesion",
                                             valor_nuevo=resultado["error"])
                self.send_json({"error": resultado["error"]}, 403)
            elif resultado and resultado.get("requiere_totp"):
                # Credenciales válidas pero tiene TOTP — generar token temporal
                temp = _secrets_mod.token_hex(24)
                with _pending_totp_lock:
                    _pending_totp[temp] = {
                        "username": username,
                        "expires":  datetime.now() + timedelta(minutes=5)
                    }
                self.send_json({"requiere_totp": True, "totp_token": temp})
            elif resultado:
                database.registrar_auditoria(username, "login", "sesion")
                # Si forzar_2fa está activo y el usuario no tiene TOTP → avisar al frontend
                forzar = database.get_config_global("forzar_2fa") == "1"
                if forzar and not database.get_totp_secret(username):
                    resultado["requiere_setup_2fa"] = True
                self.send_json(resultado)
            else:
                database.registrar_auditoria(username, "login_fallido", "sesion",
                                             valor_nuevo="credenciales incorrectas")
                self.send_json({"error": "Credenciales incorrectas."}, 401)

        # ── Auth: Verificar código TOTP (paso 2 del login) ────
        elif path == "/api/login/totp":
            totp_token = body.get("totp_token", "")
            code       = body.get("code", "").strip()

            # Limpiar tokens expirados y obtener el pendiente — todo bajo lock
            ahora = datetime.now()
            with _pending_totp_lock:
                expirados = [k for k, v in _pending_totp.items() if ahora > v["expires"]]
                for k in expirados:
                    _pending_totp.pop(k, None)
                pending = _pending_totp.get(totp_token)
            if not pending:
                self.send_json({"error": "Sesión expirada. Iniciá sesión nuevamente."}, 401)
                return

            username    = pending["username"]
            totp_secret = database.get_totp_secret(username)
            if not totp_secret:
                self.send_json({"error": "2FA no configurado."}, 400)
                return

            try:
                import pyotp
                totp = pyotp.TOTP(totp_secret)
                if not totp.verify(code, valid_window=2):
                    database.registrar_auditoria(username, "login_2fa_fallido", "sesion",
                                                 valor_nuevo="código incorrecto")
                    self.send_json({"error": "Código 2FA incorrecto."}, 401)
                    return
            except Exception as e:
                self.send_json({"error": f"Error verificando TOTP: {e}"}, 500)
                return

            # TOTP correcto → consumir token temporal y crear sesión real
            with _pending_totp_lock:
                _pending_totp.pop(totp_token, None)
            usuario = database.obtener_usuario(username)
            token   = database.crear_sesion(usuario["id"])
            database.registrar_auditoria(username, "login_2fa", "sesion")

            resp = {
                "token":                 token,
                "rol":                   usuario["rol"],
                "username":              usuario["username"],
                "debe_cambiar_password": bool(usuario.get("debe_cambiar_password", 0)),
            }
            self.send_json(resp)

        # ── Auth: Logout ──────────────────────────────────────
        elif path == "/api/logout":
            user  = self._get_user()
            token = self._get_token()
            if token:
                auth.logout(token)
            if user:
                database.registrar_auditoria(user["username"], "logout", "sesion")
            self.send_json({"ok": True})

        # ── Auth: Cambiar mi propia contraseña ────────────────
        elif path == "/api/me/password":
            user = self._require_auth()
            if not user:
                return
            password_actual = body.get("password_actual", "")
            password_nuevo  = body.get("password_nuevo", "")
            if not password_actual or not password_nuevo:
                self.send_json({"error": "Campos incompletos."}, 400)
                return
            # Validar política de contraseñas
            errores = auth.validar_password_policy(password_nuevo)
            if errores:
                self.send_json({"error": " ".join(errores)}, 400)
                return
            # Verificar contraseña actual antes de cambiarla
            usuario_db = database.obtener_usuario(user["username"])
            if not auth.verify_password(password_actual, usuario_db["password_hash"]):
                self.send_json({"error": "Contraseña actual incorrecta."}, 403)
                return
            nuevo_hash = auth.hash_password(password_nuevo)
            database.actualizar_password(user["id"], nuevo_hash)
            database.registrar_auditoria(user["username"], "cambio_password", "usuario",
                                         str(user["id"]))
            self.send_json({"ok": True, "mensaje": "Contraseña actualizada. Iniciá sesión nuevamente."})

        # ── Tickets: Cambiar estado ───────────────────────────
        elif path == "/api/estado":
            user = self._require_permission("gestionar_alertas")
            if not user:
                return
            alerta_id = body.get("id")
            estado    = body.get("estado")
            if alerta_id is None or not estado:
                self.send_json({"error": "Datos incompletos."}, 400)
                return
            database.actualizar_estado_alerta(int(alerta_id), estado)
            database.registrar_auditoria(user["username"], "cambio_estado_alerta", "alerta",
                                         str(alerta_id), valor_nuevo=estado)
            self.send_json({"ok": True})

        # ── Tickets: Agregar comentario ───────────────────────
        elif path == "/api/comentario":
            user = self._require_permission("gestionar_alertas")
            if not user:
                return
            alerta_id = body.get("id")
            texto     = body.get("texto", "").strip()
            if not texto:
                self.send_json({"ok": False, "error": "Comentario vacío."}, 400)
                return
            database.agregar_comentario(int(alerta_id), texto)
            self.send_json({"ok": True})

        # ── Config FIM ────────────────────────────────────────
        elif path == "/api/config/carpeta":
            if not self._require_permission("editar_config"):
                return
            carpeta  = body.get("carpeta", "").strip()
            if not carpeta:
                self.send_json({"ok": False, "error": "Carpeta vacía."}, 400)
                return
            config   = leer_config()
            carpetas = config.get("carpetas_monitoreadas", [])
            if carpeta not in carpetas:
                carpetas.append(carpeta)
                config["carpetas_monitoreadas"] = carpetas
                guardar_config(config)
            self.send_json({"ok": True, "carpetas": carpetas})

        elif path == "/api/config/carpeta/eliminar":
            if not self._require_permission("editar_config"):
                return
            carpeta  = body.get("carpeta", "").strip()
            config   = leer_config()
            carpetas = config.get("carpetas_monitoreadas", [])
            if carpeta in carpetas:
                carpetas.remove(carpeta)
                config["carpetas_monitoreadas"] = carpetas
                guardar_config(config)
            self.send_json({"ok": True, "carpetas": carpetas})

        # ── Gestión de Agentes ────────────────────────────────
        elif path == "/api/agentes/crear":
            if not self._require_permission("gestionar_agentes"):
                return
            nombre      = body.get("nombre", "").strip()
            ip          = body.get("ip", "").strip()
            descripcion = body.get("descripcion", "").strip()
            tipo        = body.get("tipo", "windows")
            if not nombre:
                self.send_json({"error": "El nombre del agente es obligatorio."}, 400)
                return
            try:
                agente = database.crear_agente(nombre, ip, descripcion, tipo)
                self.send_json({"ok": True, "agente": agente})
            except Exception as e:
                self.send_json({"error": f"Ya existe un agente con ese nombre: {e}"}, 409)

        elif path == "/api/agentes/estado":
            if not self._require_permission("gestionar_agentes"):
                return
            nombre = body.get("nombre", "").strip()
            estado = body.get("estado", "")
            if not nombre or estado not in ("activo", "pendiente", "inactivo"):
                self.send_json({"error": "Datos inválidos."}, 400)
                return
            database.actualizar_estado_agente(nombre, estado)
            self.send_json({"ok": True})

        elif path == "/api/agentes/eliminar":
            if not self._require_permission("gestionar_agentes"):
                return
            nombre = body.get("nombre", "").strip()
            if not nombre:
                self.send_json({"error": "Nombre requerido."}, 400)
                return
            database.eliminar_agente_config(nombre)
            self.send_json({"ok": True})

        elif path == "/api/agentes/regenerar-key":
            if not self._require_permission("gestionar_agentes"):
                return
            nombre = body.get("nombre", "").strip()
            if not nombre:
                self.send_json({"error": "Nombre requerido."}, 400)
                return
            nueva_key = database.regenerar_api_key(nombre)
            self.send_json({"ok": True, "api_key": nueva_key})

        # ── Gestión de Usuarios ───────────────────────────────
        elif path == "/api/usuarios/crear":
            if not self._require_permission("gestionar_usuarios"):
                return
            username = body.get("username", "").strip()
            password = body.get("password", "")
            rol      = body.get("rol", "analista")
            if not username or not password:
                self.send_json({"error": "Usuario y contraseña son obligatorios."}, 400)
                return
            errores_pw = auth.validar_password_policy(password)
            if errores_pw:
                self.send_json({"error": " ".join(errores_pw)}, 400)
                return
            if rol not in ("admin", "analista"):
                self.send_json({"error": "Rol inválido."}, 400)
                return
            try:
                password_hash = auth.hash_password(password)
                uid = database.crear_usuario(username, password_hash, rol)
                admin = self._get_user()
                database.registrar_auditoria(admin["username"], "crear_usuario", "usuario",
                                             str(uid), valor_nuevo=f"{username} ({rol})")
                self.send_json({"ok": True, "id": uid})
            except Exception as e:
                self.send_json({"error": f"El usuario '{username}' ya existe."}, 409)

        elif path == "/api/usuarios/toggle":
            admin = self._require_permission("gestionar_usuarios")
            if not admin:
                return
            uid    = body.get("id")
            activo = body.get("activo")
            if uid is None or activo is None:
                self.send_json({"error": "ID y activo requeridos."}, 400)
                return
            if int(uid) == admin["id"]:
                self.send_json({"error": "No podés deshabilitarte a vos mismo."}, 400)
                return
            database.toggle_usuario_activo(int(uid), int(activo))
            estado_str = "habilitado" if activo else "deshabilitado"
            database.registrar_auditoria(admin["username"], f"usuario_{estado_str}", "usuario",
                                         str(uid), valor_nuevo=estado_str)
            self.send_json({"ok": True})

        elif path == "/api/usuarios/eliminar":
            admin = self._require_permission("gestionar_usuarios")
            if not admin:
                return
            uid = body.get("id")
            if uid is None:
                self.send_json({"error": "ID requerido."}, 400)
                return
            if int(uid) == admin["id"]:
                self.send_json({"error": "No podés eliminar tu propio usuario."}, 400)
                return
            # Guardar nombre antes de eliminar para el log
            usuario_target = database.leer_usuarios()
            nombre_target  = next((u["username"] for u in usuario_target if u["id"] == int(uid)), str(uid))
            database.eliminar_usuario(int(uid))
            database.registrar_auditoria(admin["username"], "eliminar_usuario", "usuario",
                                         str(uid), valor_anterior=nombre_target)
            self.send_json({"ok": True})

        elif path == "/api/usuarios/password":
            admin = self._require_permission("gestionar_usuarios")
            if not admin:
                return
            uid      = body.get("id")
            password = body.get("password", "")
            if uid is None or len(password) < 6:
                self.send_json({"error": "ID y contraseña (mín. 6 chars) requeridos."}, 400)
                return
            nuevo_hash = auth.hash_password(password)
            database.actualizar_password(int(uid), nuevo_hash, debe_cambiar=True)
            database.registrar_auditoria(admin["username"], "reset_password_usuario", "usuario",
                                         str(uid), valor_nuevo="forzar cambio al próximo login")
            self.send_json({"ok": True})

        # ── Auditoría: filtrar y exportar ────────────────────
        elif path == "/api/auditoria/filtrar":
            if not self._require_permission("ver_auditoria"):
                return
            registros = database.leer_auditoria_filtrada(
                fecha_desde = body.get("fecha_desde"),
                fecha_hasta = body.get("fecha_hasta"),
                usuario     = body.get("usuario")  or None,
                accion      = body.get("accion")   or None,
            )
            self.send_json(registros)

        elif path == "/api/auditoria/csv":
            if not self._require_permission("ver_auditoria"):
                return
            registros = database.leer_auditoria_filtrada(
                fecha_desde = body.get("fecha_desde"),
                fecha_hasta = body.get("fecha_hasta"),
                usuario     = body.get("usuario")  or None,
                accion      = body.get("accion")   or None,
            )
            import csv, io
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(["ID","Fecha","Usuario","Acción","Entidad","ID Entidad","Valor anterior","Valor nuevo"])
            for r in registros:
                writer.writerow([
                    r.get("id",""), r.get("ts",""), r.get("usuario",""),
                    r.get("accion",""), r.get("entidad",""), r.get("id_entidad",""),
                    r.get("valor_anterior",""), r.get("valor_nuevo",""),
                ])
            data  = out.getvalue().encode("utf-8-sig")
            fname = f"auditoria_siem_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f"attachment; filename={fname}")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        elif path == "/api/auditoria/pdf":
            if not self._require_permission("ver_auditoria"):
                return
            registros = database.leer_auditoria_filtrada(
                fecha_desde = body.get("fecha_desde"),
                fecha_hasta = body.get("fecha_hasta"),
                usuario     = body.get("usuario")  or None,
                accion      = body.get("accion")   or None,
            )
            filtros = {k: v for k, v in body.items() if v}
            try:
                pdf  = generar_pdf_auditoria(registros, filtros)
                with open(pdf, "rb") as f:
                    data = f.read()
                fname = f"auditoria_siem_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", f"attachment; filename={fname}")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)

        # ── Cambiar rol de un usuario ─────────────────────────
        elif path == "/api/usuarios/rol":
            admin = self._require_permission("gestionar_roles")
            if not admin:
                return
            uid    = body.get("id")
            rol_id = body.get("rol_id")
            if uid is None or rol_id is None:
                self.send_json({"error": "id y rol_id requeridos."}, 400)
                return
            if int(uid) == admin["id"] and int(rol_id) != admin.get("rol_id"):
                self.send_json({"error": "No podés cambiar tu propio rol."}, 400)
                return
            database.asignar_rol_usuario(int(uid), int(rol_id))
            database.registrar_auditoria(
                admin["username"], "cambio_rol_usuario", "usuario",
                str(uid), valor_nuevo=str(rol_id)
            )
            self.send_json({"ok": True})

        # ── Gestión de Roles (admin) ──────────────────────────
        elif path == "/api/roles/crear":
            if not self._require_permission("gestionar_roles"):
                return
            nombre      = body.get("nombre", "").strip()
            descripcion = body.get("descripcion", "").strip()
            if not nombre:
                self.send_json({"error": "El nombre es obligatorio."}, 400)
                return
            try:
                rid   = database.crear_rol(nombre, descripcion)
                admin = self._get_user()
                database.registrar_auditoria(
                    admin["username"], "crear_rol", "rol",
                    id_entidad=str(rid),
                    valor_nuevo=f'"{nombre}" — {descripcion or "sin descripción"}'
                )
                self.send_json({"ok": True, "id": rid})
            except Exception:
                self.send_json({"error": f"El rol '{nombre}' ya existe."}, 409)

        elif path == "/api/roles/eliminar":
            if not self._require_permission("gestionar_roles"):
                return
            rol_id = body.get("id")
            if rol_id is None:
                self.send_json({"error": "id requerido."}, 400)
                return
            # Obtener nombre antes de eliminar para el log
            roles_actuales = database.leer_roles()
            rol_target = next((r for r in roles_actuales if r["id"] == int(rol_id)), None)
            ok = database.eliminar_rol(int(rol_id))
            if ok:
                admin = self._get_user()
                database.registrar_auditoria(
                    admin["username"], "eliminar_rol", "rol",
                    id_entidad=str(rol_id),
                    valor_anterior=f'"{rol_target["nombre"]}"' if rol_target else str(rol_id)
                )
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "El rol 'admin' no puede eliminarse."}, 403)

        elif path == "/api/roles/permisos":
            if not self._require_permission("gestionar_roles"):
                return
            rol_id      = body.get("rol_id")
            permiso_ids = body.get("permiso_ids", [])
            if rol_id is None:
                self.send_json({"error": "rol_id requerido."}, 400)
                return

            # Resolver nombre del rol y códigos de permisos para un log legible
            roles_actuales = database.leer_roles()
            rol_target     = next((r for r in roles_actuales if r["id"] == int(rol_id)), None)
            todos_permisos = database.leer_permisos()
            id_to_codigo   = {p["id"]: p["codigo"] for p in todos_permisos}
            codigos_nuevos = [id_to_codigo.get(int(pid), str(pid)) for pid in permiso_ids]
            rol_nombre     = rol_target["nombre"] if rol_target else str(rol_id)

            database.set_rol_permisos(int(rol_id), permiso_ids)
            admin = self._get_user()
            database.registrar_auditoria(
                admin["username"], "modificar_permisos_rol", "rol",
                id_entidad=f'{rol_id} — {rol_nombre}',
                valor_nuevo=", ".join(sorted(codigos_nuevos)) or "(sin permisos)"
            )
            self.send_json({"ok": True})

        # ── TOTP: Configuración del autenticador ──────────────
        elif path == "/api/totp/setup":
            """Genera un nuevo secret TOTP y retorna el URI + QR en base64."""
            user = self._require_auth()
            if not user:
                return
            try:
                import pyotp
            except ImportError:
                self.send_json({"error": "pyotp no instalado. Ejecutá: pip install pyotp"}, 500)
                return
            secret = pyotp.random_base32()
            uri    = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user["username"], issuer_name="SIEM Local"
            )
            # Generar QR como imagen base64 (sin depender de CDN)
            qr_b64 = None
            try:
                import qrcode, base64
                import qrcode.constants
                from io import BytesIO
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_M,
                    box_size=6,
                    border=2,
                )
                qr.add_data(uri)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                buf = BytesIO()
                img.save(buf, format="PNG")
                qr_b64 = base64.b64encode(buf.getvalue()).decode()
            except Exception as qr_err:
                print(f"[TOTP] Error generando QR: {qr_err}")
                pass  # qrcode no instalado — el frontend usa clave manual
            self.send_json({"secret": secret, "uri": uri, "qr_b64": qr_b64})

        elif path == "/api/totp/activar":
            """Verifica el código y guarda el secret TOTP en la DB."""
            user = self._require_auth()
            if not user:
                return
            try:
                import pyotp
            except ImportError:
                self.send_json({"error": "pyotp no instalado."}, 500)
                return
            secret = body.get("secret", "")
            codigo = body.get("codigo", "")
            if not secret or not codigo:
                self.send_json({"error": "secret y codigo requeridos."}, 400)
                return
            totp = pyotp.TOTP(secret)
            if not totp.verify(codigo, valid_window=2):
                self.send_json({"error": "Código incorrecto. Asegurate de que el reloj esté sincronizado."}, 400)
                return
            database.set_totp_secret(user["id"], secret)
            database.registrar_auditoria(user["username"], "totp_activado", "usuario", str(user["id"]))
            self.send_json({"ok": True})

        elif path == "/api/totp/desactivar":
            """Elimina el secret TOTP del usuario (requiere verificar código actual)."""
            user = self._require_auth()
            if not user:
                return
            try:
                import pyotp
            except ImportError:
                self.send_json({"error": "pyotp no instalado."}, 500)
                return
            codigo = body.get("codigo", "")
            secret = database.get_totp_secret(user["username"])
            if not secret:
                self.send_json({"error": "No tenés TOTP configurado."}, 400)
                return
            if not pyotp.TOTP(secret).verify(codigo, valid_window=1):
                self.send_json({"error": "Código incorrecto."}, 400)
                return
            database.set_totp_secret(user["id"], None)
            database.registrar_auditoria(user["username"], "totp_desactivado", "usuario", str(user["id"]))
            self.send_json({"ok": True})

        elif path == "/api/config/forzar-2fa":
            user = self._require_permission("editar_config")
            if not user:
                return
            valor = body.get("forzar_2fa", False)
            database.set_config_global("forzar_2fa", "1" if valor else "0")
            database.registrar_auditoria(
                user["username"], "modificar", "config",
                None, valor_nuevo=f"forzar_2fa={'activado' if valor else 'desactivado'}"
            )
            self.send_json({"ok": True})

        elif path == "/api/config/seguridad":
            user = self._require_permission("editar_config")
            if not user:
                return
            claves_permitidas = {
                "session_timeout_minutos", "password_min_length",
                "password_require_upper", "password_require_number",
                "password_require_special", "login_max_intentos",
                "login_bloqueo_minutos", "forzar_2fa", "alerta_retencion_dias"
            }
            items = {k: str(v) for k, v in body.items() if k in claves_permitidas}
            if not items:
                self.send_json({"error": "Sin parámetros válidos."}, 400)
                return
            # Guardar valores anteriores para auditoría
            cfg_anterior = database.get_all_config_global()
            database.set_many_config_global(items)
            # Un registro de auditoría por cada campo que realmente cambió
            for k, v_nuevo in items.items():
                v_anterior = cfg_anterior.get(k, "")
                if str(v_anterior) != str(v_nuevo):
                    database.registrar_auditoria(
                        user["username"], "modificar", "config", k,
                        valor_anterior=str(v_anterior),
                        valor_nuevo=str(v_nuevo)
                    )
            self.send_json({"ok": True})

        elif path == "/api/config/telegram":
            user = self._require_permission("editar_config")
            if not user:
                return
            token   = body.get("token", "").strip()
            chat_id = body.get("chat_id", "").strip()
            activo  = body.get("activo", False)

            if token and chat_id:
                # Validar el token contra la API de Telegram antes de guardar
                try:
                    import urllib.request as _ur, json as _json, ssl as _ssl
                    _ctx = _ssl.create_default_context()
                    _ctx.check_hostname = False
                    _ctx.verify_mode    = _ssl.CERT_NONE
                    req = _ur.Request(
                        f"https://api.telegram.org/bot{token}/getMe",
                        headers={"Content-Type": "application/json"}
                    )
                    with _ur.urlopen(req, timeout=8, context=_ctx) as resp:
                        data = _json.loads(resp.read())
                    if not data.get("ok"):
                        self.send_json({"error": "Token de Telegram inválido."}, 400)
                        return
                    bot_name = data.get("result", {}).get("username", "")
                except Exception as e:
                    self.send_json({"error": f"No se pudo conectar a Telegram: {e}"}, 400)
                    return

                database.set_many_config_global({
                    "telegram_bot_token": token,
                    "telegram_chat_id":   chat_id,
                    "telegram_activo":    "1" if activo else "0",
                })
                database.registrar_auditoria(
                    user["username"], "modificar", "config", "telegram",
                    valor_nuevo=f"bot={bot_name}, chat_id={chat_id}, activo={'sí' if activo else 'no'}"
                )
                self.send_json({"ok": True, "bot_name": bot_name})
            else:
                # Solo actualizar estado activo/inactivo
                database.set_config_global("telegram_activo", "1" if activo else "0")
                self.send_json({"ok": True})

        elif path == "/api/config/telegram/test":
            user = self._require_permission("editar_config")
            if not user:
                return
            try:
                import urllib.request as _ur, json as _json, ssl as _ssl
                _ctx = _ssl.create_default_context()
                _ctx.check_hostname = False
                _ctx.verify_mode    = _ssl.CERT_NONE
                token   = database.get_config_global("telegram_bot_token", "")
                chat_id = database.get_config_global("telegram_chat_id", "")
                if not token or not chat_id:
                    self.send_json({"error": "Configurá el token y chat ID primero."}, 400)
                    return
                payload = _json.dumps({
                    "chat_id":    chat_id,
                    "text":       "✅ *SIEM Local* — Prueba de conexión exitosa. Las alertas críticas llegarán aquí.",
                    "parse_mode": "Markdown"
                }).encode("utf-8")
                req = _ur.Request(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    data=payload, headers={"Content-Type": "application/json"}
                )
                with _ur.urlopen(req, timeout=10, context=_ctx) as resp:
                    data = _json.loads(resp.read())
                if data.get("ok"):
                    self.send_json({"ok": True})
                else:
                    self.send_json({"error": "Telegram rechazó el mensaje. Verificá el Chat ID."}, 400)
            except Exception as e:
                self.send_json({"error": f"Error: {e}"}, 400)

        elif path == "/api/password/recuperar":
            """Endpoint público: recupera contraseña con TOTP.
            No requiere sesión — es el flujo de 'olvidé mi contraseña'."""
            try:
                import pyotp
            except ImportError:
                self.send_json({"error": "pyotp no instalado."}, 500)
                return
            username     = body.get("username", "").strip()
            totp_codigo  = body.get("totp_codigo", "")
            nueva_pass   = body.get("nueva_password", "")
            if not username or not totp_codigo or not nueva_pass:
                self.send_json({"error": "Campos incompletos."}, 400)
                return
            if len(nueva_pass) < 6:
                self.send_json({"error": "La contraseña debe tener al menos 6 caracteres."}, 400)
                return
            secret = database.get_totp_secret(username)
            if not secret:
                self.send_json({"error": "Este usuario no tiene autenticador configurado. Contactá al administrador."}, 403)
                return
            if not pyotp.TOTP(secret).verify(totp_codigo, valid_window=1):
                self.send_json({"error": "Código del autenticador incorrecto."}, 400)
                return
            usuario = database.obtener_usuario(username)
            if not usuario:
                self.send_json({"error": "Usuario no encontrado."}, 404)
                return
            nuevo_hash = auth.hash_password(nueva_pass)
            database.actualizar_password(usuario["id"], nuevo_hash, debe_cambiar=False)
            database.registrar_auditoria(username, "recuperar_password_totp", "usuario", str(usuario["id"]))
            self.send_json({"ok": True, "mensaje": "Contraseña actualizada. Podés iniciar sesión."})

        # ── Reportería Avanzada ───────────────────────────────
        elif path == "/api/reportes/preview":
            if not self._require_permission("ver_reportes"):
                return
            filtros = {
                "fecha_desde": body.get("fecha_desde"),
                "fecha_hasta": body.get("fecha_hasta"),
                "severidades": body.get("severidades") or [],
                "fuentes":     body.get("fuentes")     or [],
                "estados":     body.get("estados")     or [],
            }
            alertas = database.leer_alertas_filtradas(**filtros)
            self.send_json(alertas)

        elif path == "/api/reportes/pdf":
            if not self._require_permission("exportar_reportes"):
                return
            filtros = {
                "fecha_desde": body.get("fecha_desde"),
                "fecha_hasta": body.get("fecha_hasta"),
                "severidades": body.get("severidades") or [],
                "fuentes":     body.get("fuentes")     or [],
                "estados":     body.get("estados")     or [],
            }
            try:
                alertas = database.leer_alertas_filtradas(**filtros)
                pdf     = generar_pdf(alertas, filtros=filtros)
                with open(pdf, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                fname = f"reporte_siem_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
                self.send_header("Content-Disposition", f"attachment; filename={fname}")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)

        elif path == "/api/reportes/csv":
            if not self._require_permission("exportar_reportes"):
                return
            filtros = {
                "fecha_desde": body.get("fecha_desde"),
                "fecha_hasta": body.get("fecha_hasta"),
                "severidades": body.get("severidades") or [],
                "fuentes":     body.get("fuentes")     or [],
                "estados":     body.get("estados")     or [],
            }
            alertas  = database.leer_alertas_filtradas(**filtros)
            csv_body = generar_csv(alertas)
            data     = csv_body.encode("utf-8-sig")  # BOM para Excel
            fname    = f"alertas_siem_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f"attachment; filename={fname}")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        # ── Endpoint FIM real-time (watchdog, sin Ollama) ─────
        elif path == "/api/alerta-fim":
            agente  = body.get("agente", "desconocido")
            ip      = body.get("ip", "desconocida")
            api_key = body.get("api_key", None)

            permitido, motivo = database.validar_agente_acceso(agente, ip, api_key)
            if not permitido:
                self.send_json({"ok": False, "error": motivo}, 403)
                return

            tipo    = body.get("tipo", "DESCONOCIDO")   # CREACION / MODIFICACION / ELIMINACION / MOVIMIENTO
            archivo = body.get("archivo", "desconocido")
            ts      = body.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            # Severidad directa según tipo — sin pasar por Ollama
            severity_map = {
                "ELIMINACION":  "high",
                "MODIFICACION": "medium",
                "CREACION":     "medium",
                "MOVIMIENTO":   "medium",
            }
            severity = severity_map.get(tipo, "medium")

            # Descripción legible
            descripciones = {
                "ELIMINACION":  f"Archivo eliminado de carpeta monitoreada: {archivo}",
                "MODIFICACION": f"Archivo modificado en carpeta monitoreada: {archivo}",
                "CREACION":     f"Archivo creado en carpeta monitoreada: {archivo}",
                "MOVIMIENTO":   f"Archivo movido/renombrado en carpeta monitoreada: {archivo}",
            }
            accion_map = {
                "ELIMINACION":  "Verificar si la eliminación fue autorizada. Revisar usuario y proceso involucrado.",
                "MODIFICACION": "Revisar el contenido del archivo y confirmar que el cambio fue legítimo.",
                "CREACION":     "Verificar que la creación del archivo fue intencional y autorizada.",
                "MOVIMIENTO":   "Confirmar que el movimiento o renombrado del archivo fue autorizado.",
            }

            analysis = {
                "severity":          severity,
                "fuente":            agente,
                "ip":                ip,
                "summary":           descripciones.get(tipo, f"FIM {tipo}: {archivo}"),
                "accion_recomendada": accion_map.get(tipo, "Investigar el cambio detectado."),
                "events": [{
                    "id":          f"FIM-{tipo}",
                    "descripcion": archivo,
                    "riesgo":      severity,
                }],
            }

            alerta_id, es_nueva = database.guardar_alerta(analysis, ts)
            database.registrar_auditoria(
                "sistema", f"fim_{tipo.lower()}", "alerta", str(alerta_id),
                valor_nuevo=archivo
            )
            # Notificar por Telegram si es HIGH o CRITICAL
            if severity in ("high", "critical"):
                threading.Thread(
                    target=_enviar_telegram_fim,
                    args=(analysis["summary"], agente, severity, archivo, ip),
                    daemon=True
                ).start()
            self.send_json({"ok": True, "alerta_id": alerta_id, "es_nueva": es_nueva})

        # ── Endpoint de agentes (recepción de logs) ───────────
        elif path == "/api/eventos-externos":
            # Este endpoint NO usa autenticación de usuario.
            # Los agentes se autentican por nombre+ip y api_key opcional.
            agente  = body.get("agente", "desconocido")
            logs    = body.get("logs", "")
            ip      = body.get("ip", "desconocida")
            api_key = body.get("api_key", None)  # Opcional — compatibilidad con agentes sin key

            if not logs:
                self.send_json({"ok": False, "error": "Logs vacíos."}, 400)
                return

            # Validar el agente contra la whitelist en config_agentes
            permitido, motivo = database.validar_agente_acceso(agente, ip, api_key)
            if not permitido:
                self.send_json({"ok": False, "error": motivo}, 403)
                return

            database.guardar_evento_externo(agente, ip, logs)
            self.send_json({"ok": True, "mensaje": f"Evento recibido de {agente}"})

        else:
            self.send_response(404)
            self.end_headers()


# ─── Tarea de limpieza periódica ──────────────────────────────

def _limpiar_sesiones_loop():
    """
    Hilo de background que elimina sesiones expiradas cada hora.
    Mantiene la tabla 'sesiones' limpia sin trabajo manual.
    """
    while True:
        time.sleep(3600)  # cada hora
        try:
            database.limpiar_sesiones_expiradas()
        except Exception:
            pass


def arrancar(puerto: int = 8080):
    """
    Punto de entrada único para el dashboard.
    Invocable tanto desde __main__ como desde run_dashboard.py (launcher headless).
    """
    # 1. Inicializar la base de datos (crea tablas e índices si no existen)
    database.init_db()

    # 2. Crear usuario admin por defecto si no hay ninguno
    auth.init_admin_if_needed()

    # 3. Migración única: importar datos legacy si la DB está vacía
    migrados = database.migrar_datos_legacy(LEGACY_ALERTAS_JSONL, LEGACY_TICKETS_JSON)
    if migrados > 0:
        print(f"[DB] Migración completada: {migrados} alertas importadas desde archivos legacy.")

    # 4. Iniciar hilo de limpieza de sesiones expiradas en background
    t = threading.Thread(target=_limpiar_sesiones_loop, daemon=True)
    t.start()

    server = HTTPServer(("0.0.0.0", puerto), Handler)
    print("=" * 55)
    print(f"  Dashboard SIEM corriendo en: http://localhost:{puerto}")
    print("  Aceptando agentes en:        http://192.168.1.48:8080")
    print("=" * 55)
    server.serve_forever()


if __name__ == "__main__":
    arrancar()
