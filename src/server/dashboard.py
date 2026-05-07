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


def generar_pdf(alertas: list):
    """Genera un PDF con el resumen ejecutivo y detalle de todas las alertas."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER

    doc   = SimpleDocTemplate(PDF_OUTPUT, pagesize=A4,
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
        Verifica que el usuario sea administrador.
        Envía 401 si no está autenticado, 403 si es analista.
        """
        user = self._require_auth()
        if not user:
            return None
        if user.get("rol") != "admin":
            self.send_json({"error": "Acción restringida a administradores."}, 403)
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
            if not self._require_auth():
                return
            self.send_json(database.leer_alertas())

        elif path == "/api/estado-siem":
            if not self._require_auth():
                return
            self.send_json(leer_estado_siem())

        elif path == "/api/config":
            # Solo admin puede ver la configuración de carpetas FIM
            if not self._require_admin():
                return
            self.send_json(leer_config())

        elif path == "/api/eventos-externos":
            if not self._require_auth():
                return
            self.send_json(database.leer_eventos_externos())

        elif path == "/api/agentes":
            # Cualquier usuario autenticado puede ver la lista de agentes
            if not self._require_auth():
                return
            self.send_json(database.leer_config_agentes())

        elif path == "/api/usuarios":
            # Solo admin puede listar usuarios
            if not self._require_admin():
                return
            self.send_json(database.leer_usuarios())

        elif path == "/api/me":
            # Retorna info del usuario actual (usado por el frontend al cargar)
            # No pasa por _require_auth para no bloquear si debe_cambiar_password=1
            user = self._get_user()
            if not user:
                self.send_json({"error": "No autenticado."}, 401)
                return
            self.send_json({
                "username":             user["username"],
                "rol":                  user["rol"],
                "debe_cambiar_password": bool(user.get("debe_cambiar_password", 0))
            })

        elif path == "/api/pdf":
            if not self._require_auth():
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
            if resultado:
                self.send_json(resultado)
            else:
                # Mensaje genérico: no revelar si falla por usuario o password
                self.send_json({"error": "Credenciales incorrectas."}, 401)

        # ── Auth: Logout ──────────────────────────────────────
        elif path == "/api/logout":
            token = self._get_token()
            if token:
                auth.logout(token)
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
            if len(password_nuevo) < 6:
                self.send_json({"error": "La contraseña debe tener al menos 6 caracteres."}, 400)
                return
            # Verificar contraseña actual antes de cambiarla
            usuario_db = database.obtener_usuario(user["username"])
            if not auth.verify_password(password_actual, usuario_db["password_hash"]):
                self.send_json({"error": "Contraseña actual incorrecta."}, 403)
                return
            nuevo_hash = auth.hash_password(password_nuevo)
            database.actualizar_password(user["id"], nuevo_hash)
            self.send_json({"ok": True, "mensaje": "Contraseña actualizada. Iniciá sesión nuevamente."})

        # ── Tickets: Cambiar estado ───────────────────────────
        elif path == "/api/estado":
            # Analistas y admins pueden gestionar el estado de tickets
            user = self._require_auth()
            if not user:
                return
            alerta_id = body.get("id")
            estado    = body.get("estado")
            if alerta_id is None or not estado:
                self.send_json({"error": "Datos incompletos."}, 400)
                return
            database.actualizar_estado_alerta(int(alerta_id), estado)
            self.send_json({"ok": True})

        # ── Tickets: Agregar comentario ───────────────────────
        elif path == "/api/comentario":
            user = self._require_auth()
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
            if not self._require_admin():
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
            if not self._require_admin():
                return
            carpeta  = body.get("carpeta", "").strip()
            config   = leer_config()
            carpetas = config.get("carpetas_monitoreadas", [])
            if carpeta in carpetas:
                carpetas.remove(carpeta)
                config["carpetas_monitoreadas"] = carpetas
                guardar_config(config)
            self.send_json({"ok": True, "carpetas": carpetas})

        # ── Gestión de Agentes (admin) ────────────────────────
        elif path == "/api/agentes/crear":
            if not self._require_admin():
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
            if not self._require_admin():
                return
            nombre = body.get("nombre", "").strip()
            estado = body.get("estado", "")
            if not nombre or estado not in ("activo", "pendiente", "inactivo"):
                self.send_json({"error": "Datos inválidos."}, 400)
                return
            database.actualizar_estado_agente(nombre, estado)
            self.send_json({"ok": True})

        elif path == "/api/agentes/eliminar":
            if not self._require_admin():
                return
            nombre = body.get("nombre", "").strip()
            if not nombre:
                self.send_json({"error": "Nombre requerido."}, 400)
                return
            database.eliminar_agente_config(nombre)
            self.send_json({"ok": True})

        elif path == "/api/agentes/regenerar-key":
            if not self._require_admin():
                return
            nombre = body.get("nombre", "").strip()
            if not nombre:
                self.send_json({"error": "Nombre requerido."}, 400)
                return
            nueva_key = database.regenerar_api_key(nombre)
            self.send_json({"ok": True, "api_key": nueva_key})

        # ── Gestión de Usuarios (admin) ───────────────────────
        elif path == "/api/usuarios/crear":
            if not self._require_admin():
                return
            username = body.get("username", "").strip()
            password = body.get("password", "")
            rol      = body.get("rol", "analista")
            if not username or not password:
                self.send_json({"error": "Usuario y contraseña son obligatorios."}, 400)
                return
            if len(password) < 6:
                self.send_json({"error": "La contraseña debe tener al menos 6 caracteres."}, 400)
                return
            if rol not in ("admin", "analista"):
                self.send_json({"error": "Rol inválido."}, 400)
                return
            try:
                password_hash = auth.hash_password(password)
                uid = database.crear_usuario(username, password_hash, rol)
                self.send_json({"ok": True, "id": uid})
            except Exception as e:
                self.send_json({"error": f"El usuario '{username}' ya existe."}, 409)

        elif path == "/api/usuarios/eliminar":
            admin = self._require_admin()
            if not admin:
                return
            uid = body.get("id")
            if uid is None:
                self.send_json({"error": "ID requerido."}, 400)
                return
            # Un admin no puede eliminarse a sí mismo
            if int(uid) == admin["id"]:
                self.send_json({"error": "No podés eliminar tu propio usuario."}, 400)
                return
            database.eliminar_usuario(int(uid))
            self.send_json({"ok": True})

        elif path == "/api/usuarios/password":
            # Admin cambia la contraseña de otro usuario
            # El usuario deberá cambiarla en su próximo login (debe_cambiar=True)
            if not self._require_admin():
                return
            uid      = body.get("id")
            password = body.get("password", "")
            if uid is None or len(password) < 6:
                self.send_json({"error": "ID y contraseña (mín. 6 chars) requeridos."}, 400)
                return
            nuevo_hash = auth.hash_password(password)
            database.actualizar_password(int(uid), nuevo_hash, debe_cambiar=True)
            self.send_json({"ok": True})

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
