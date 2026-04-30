import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
from urllib.parse import urlparse

LOG_FILE     = r"C:\siem-claude\alertas.jsonl"
TICKETS_FILE = r"C:\siem-claude\tickets.json"
SIEM_LOG     = r"C:\siem-claude\siem_output.log"
PDF_OUTPUT   = r"C:\siem-claude\reporte_siem.pdf"

# ─── Helpers ─────────────────────────────────────────────────

def leer_alertas():
    if not os.path.exists(LOG_FILE):
        return []
    alertas = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if line:
                try:
                    a = json.loads(line)
                    a["_id"] = i
                    alertas.append(a)
                except:
                    pass
    return list(reversed(alertas))

def leer_tickets():
    if not os.path.exists(TICKETS_FILE):
        return {}
    with open(TICKETS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def guardar_tickets(tickets):
    with open(TICKETS_FILE, "w", encoding="utf-8") as f:
        json.dump(tickets, f, ensure_ascii=False, indent=2)

def combinar(alertas, tickets):
    resultado = []
    for a in alertas:
        aid    = str(a["_id"])
        ticket = tickets.get(aid, {})
        resultado.append({
            **a,
            "estado":      ticket.get("estado", "nueva"),
            "comentarios": ticket.get("comentarios", [])
        })
    return resultado

def leer_estado_siem():
    if not os.path.exists(SIEM_LOG):
        return {"ultimo": None, "proximo": None, "total_escaneos": 0, "estado": "detenido"}

    try:
        with open(SIEM_LOG, "r", encoding="utf-16", errors="replace") as f:
            lineas = f.readlines()
    except:
        try:
            with open(SIEM_LOG, "r", encoding="utf-8", errors="replace") as f:
                lineas = f.readlines()
        except:
            return {"ultimo": None, "proximo": None, "total_escaneos": 0, "estado": "detenido"}

    ultimo   = None
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
            except:
                pass

    proximo = None
    if ultimo:
        try:
            dt      = datetime.strptime(ultimo, "%Y-%m-%d %H:%M:%S")
            proximo = (dt + timedelta(minutes=5)).strftime("%H:%M:%S")
        except:
            pass

    return {
        "ultimo":         ultimo,
        "proximo":        proximo,
        "total_escaneos": escaneos,
        "estado":         estado
    }

def generar_pdf(alertas, tickets):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER

    doc   = SimpleDocTemplate(PDF_OUTPUT, pagesize=A4,
                              leftMargin=2*cm, rightMargin=2*cm,
                              topMargin=2*cm,  bottomMargin=2*cm)
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
                                  textColor=GRAY,   alignment=TA_CENTER, spaceAfter=20)
    sec_style    = ParagraphStyle("sec",    fontSize=13, fontName="Helvetica-Bold",
                                  textColor=ACCENT, spaceBefore=14, spaceAfter=6)
    body_style   = ParagraphStyle("body",   fontSize=9,  fontName="Helvetica",
                                  textColor=colors.black, spaceAfter=3)
    footer_style = ParagraphStyle("footer", fontSize=7,  fontName="Helvetica-Oblique",
                                  textColor=GRAY, alignment=TA_CENTER, spaceBefore=8)

    # ── Encabezado ──
    story.append(Paragraph("SIEM Dashboard — Reporte de Seguridad", titulo_style))
    story.append(Paragraph(
        f"Generado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}  |  "
        f"Motor: Ollama llama3.1:8b  |  Monitoreo: Local",
        sub_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 14))

    # ── Resumen ejecutivo ──
    cnt = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    combined = combinar(alertas, tickets)
    for a in combined:
        s = a.get("severity", "low")
        if s in cnt:
            cnt[s] += 1

    resueltas        = sum(1 for a in combined if a.get("estado") == "resuelta")
    falsos_positivos = sum(1 for a in combined if a.get("estado") == "falso-positivo")
    investigando     = sum(1 for a in combined if a.get("estado") == "investigando")
    nuevas           = sum(1 for a in combined if a.get("estado") == "nueva")

    story.append(Paragraph("Resumen Ejecutivo", sec_style))

    data_resumen = [
        ["Severidad", "Cantidad", "Estado",            "Cantidad"],
        ["CRITICAL",  str(cnt["critical"]), "Resueltas",          str(resueltas)],
        ["HIGH",      str(cnt["high"]),     "Falsos positivos",   str(falsos_positivos)],
        ["MEDIUM",    str(cnt["medium"]),   "En investigacion",   str(investigando)],
        ["LOW",       str(cnt["low"]),      "Nuevas",             str(nuevas)],
    ]

    t = Table(data_resumen, colWidths=[4*cm, 3*cm, 5*cm, 3*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  ACCENT),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  WHITE),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
        ("GRID",           (0, 0), (-1, -1), 0.5, colors.HexColor("#30363d")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f9fa"), WHITE]),
        ("TEXTCOLOR",      (0, 1), (0, 1),   RED),
        ("TEXTCOLOR",      (0, 2), (0, 2),   ORANGE),
        ("TEXTCOLOR",      (0, 3), (0, 3),   YELLOW),
        ("TEXTCOLOR",      (0, 4), (0, 4),   GREEN),
        ("FONTNAME",       (0, 1), (0, -1),  "Helvetica-Bold"),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d")))

    # ── Detalle de alertas ──
    story.append(Paragraph("Detalle de Alertas", sec_style))

    if not combined:
        story.append(Paragraph("Sin alertas registradas.", body_style))
    else:
        for a in combined:
            sev    = a.get("severity", "low")
            color  = SEV_COLOR.get(sev, GREEN)
            estado = a.get("estado", "nueva").upper()
            ts     = a.get("timestamp", "-")

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
                ("BACKGROUND",    (0, 0), (-1, -1), color),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ]))
            story.append(th)

            body_rows = [["Accion recomendada:", a.get("accion_recomendada", "-")]]

            for ev in a.get("events", []):
                body_rows.append([
                    f"ID {ev.get('id', '-')}",
                    f"{ev.get('descripcion', '-')} — Riesgo: {ev.get('riesgo', '-')}"
                ])

            for c in a.get("comentarios", []):
                body_rows.append([
                    f"Nota ({c.get('ts', '')})",
                    c.get("texto", "-")
                ])

            col_style = ParagraphStyle("cs", fontSize=8, fontName="Helvetica-Bold",
                                       textColor=GRAY)
            val_style = ParagraphStyle("vs", fontSize=8, fontName="Helvetica",
                                       textColor=colors.black)

            tb_data = [
                [Paragraph(r[0], col_style), Paragraph(r[1], val_style)]
                for r in body_rows
            ]
            tb = Table(tb_data, colWidths=[3.5*cm, 13.5*cm])
            tb.setStyle(TableStyle([
                ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#e0e0e0")),
                ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#fafafa")),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(tb)
            story.append(Spacer(1, 8))

    # ── Pie ──
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d")))
    story.append(Paragraph(
        f"Reporte generado automaticamente por SIEM local con IA — "
        f"Ollama llama3.1:8b — {datetime.now().strftime('%d/%m/%Y')}",
        footer_style
    ))

    doc.build(story)
    return PDF_OUTPUT

# ─── Handler HTTP ─────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/alertas":
            alertas = leer_alertas()
            tickets = leer_tickets()
            self.send_json(combinar(alertas, tickets))

        elif path == "/api/estado-siem":
            self.send_json(leer_estado_siem())

        elif path == "/api/pdf":
            try:
                alertas = leer_alertas()
                tickets = leer_tickets()
                pdf     = generar_pdf(alertas, tickets)
                with open(pdf, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition",
                                 "attachment; filename=reporte_siem.pdf")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)

        elif path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            with open(r"C:\siem-claude\index.html", "rb") as f:
                self.wfile.write(f.read())

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path    = urlparse(self.path).path
        body    = self.read_body()
        tickets = leer_tickets()

        if path == "/api/estado":
            aid    = str(body.get("id"))
            estado = body.get("estado")
            if aid not in tickets:
                tickets[aid] = {"estado": "nueva", "comentarios": []}
            tickets[aid]["estado"] = estado
            guardar_tickets(tickets)
            self.send_json({"ok": True})

        elif path == "/api/comentario":
            aid   = str(body.get("id"))
            texto = body.get("texto", "").strip()
            if not texto:
                self.send_json({"ok": False, "error": "comentario vacio"}, 400)
                return
            if aid not in tickets:
                tickets[aid] = {"estado": "nueva", "comentarios": []}
            tickets[aid]["comentarios"].append({
                "texto": texto,
                "ts":    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            guardar_tickets(tickets)
            self.send_json({"ok": True})

        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    server = HTTPServer(("localhost", 8080), Handler)
    print("=" * 50)
    print("Dashboard SIEM corriendo en: http://localhost:8080")
    print("=" * 50)
    server.serve_forever()