import sqlite3
import json
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
import encryption  # cifrado de campos sensibles

# ─── CONFIGURACION ───────────────────────────────────────────
# Raíz del proyecto: src/server/ → src/ → raíz
_ROOT   = Path(__file__).parent.parent.parent
DB_PATH = _ROOT / "data" / "siem_local.db"
# ─────────────────────────────────────────────────────────────


def get_connection() -> sqlite3.Connection:
    """
    Abre y retorna una conexión SQLite configurada.

    WAL (Write-Ahead Logging): permite que múltiples lectores accedan a la DB
    mientras el servidor SIEM escribe alertas, sin bloquearse mutuamente.

    check_same_thread=False: necesario porque dashboard.py usa un servidor HTTP
    multihilo donde distintos threads pueden llamar funciones de esta DB.

    row_factory=sqlite3.Row: hace que las filas se comporten como dicts,
    permitiendo acceder a columnas por nombre (fila["severity"]) en vez de índice.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # lecturas y escrituras concurrentes
    conn.execute("PRAGMA foreign_keys=ON")    # activa integridad referencial
    return conn


def init_db():
    """
    Crea todas las tablas e índices si no existen todavía.
    Es idempotente: puede llamarse múltiples veces sin efectos secundarios.
    Se llama al arrancar tanto siem_servidor.py como dashboard.py.
    """
    conn = get_connection()
    try:
        c = conn.cursor()

        # ── Tabla principal de alertas ──────────────────────────────────────
        # Cada fila representa un análisis completo de Ollama sobre un lote de logs.
        # ocurrencias: cuántas veces se repitió el mismo patrón (deduplicación).
        # ultima_vez:  timestamp del ciclo más reciente que disparó esta alerta.
        c.execute("""
            CREATE TABLE IF NOT EXISTS alertas (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp          TEXT NOT NULL,
                severity           TEXT NOT NULL,
                fuente             TEXT NOT NULL,
                ip                 TEXT,
                summary            TEXT,
                accion_recomendada TEXT,
                ocurrencias        INTEGER DEFAULT 1,
                ultima_vez         TEXT,
                created_at         TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)

        # ── Eventos individuales dentro de cada alerta (relación 1:N) ───────
        # Ollama devuelve una lista de eventos; cada uno va en esta tabla.
        # ON DELETE CASCADE: si se elimina la alerta padre, se eliminan sus eventos.
        c.execute("""
            CREATE TABLE IF NOT EXISTS eventos_alerta (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                alerta_id   INTEGER NOT NULL,
                event_id    TEXT,
                descripcion TEXT,
                riesgo      TEXT,
                FOREIGN KEY (alerta_id) REFERENCES alertas(id) ON DELETE CASCADE
            )
        """)

        # ── Tickets: estado de investigación de cada alerta ──────────────────
        # UNIQUE en alerta_id garantiza exactamente un ticket por alerta.
        c.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                alerta_id  INTEGER UNIQUE NOT NULL,
                estado     TEXT DEFAULT 'nueva',
                updated_at TEXT DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (alerta_id) REFERENCES alertas(id) ON DELETE CASCADE
            )
        """)

        # ── Comentarios de investigadores ────────────────────────────────────
        # Un analista puede agregar múltiples notas de investigación a cada alerta.
        c.execute("""
            CREATE TABLE IF NOT EXISTS comentarios (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                alerta_id INTEGER NOT NULL,
                texto     TEXT NOT NULL,
                ts        TEXT DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (alerta_id) REFERENCES alertas(id) ON DELETE CASCADE
            )
        """)

        # ── Cola de eventos recibidos de agentes (reemplaza eventos_externos.jsonl) ──
        # estado='pendiente' → esperando análisis de Ollama
        # estado='procesado' → ya analizado; alerta_id apunta al resultado
        c.execute("""
            CREATE TABLE IF NOT EXISTS eventos_externos (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                agente             TEXT NOT NULL,
                ip                 TEXT,
                logs               TEXT NOT NULL,
                estado             TEXT DEFAULT 'pendiente',
                timestamp_recibido TEXT DEFAULT (datetime('now', 'localtime')),
                alerta_id          INTEGER,
                FOREIGN KEY (alerta_id) REFERENCES alertas(id)
            )
        """)

        # ── Registro de agentes que han reportado (tracking histórico) ───────
        c.execute("""
            CREATE TABLE IF NOT EXISTS agentes (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre          TEXT UNIQUE NOT NULL,
                ip              TEXT,
                tipo            TEXT,
                ultimo_contacto TEXT,
                estado          TEXT DEFAULT 'activo'
            )
        """)

        # ── Usuarios del sistema (administradores y analistas) ───────────────
        # password_hash: generado con bcrypt (ver auth.py)
        # rol: 'admin' puede gestionar todo | 'analista' solo lee y comenta
        # activo: 0 = cuenta deshabilitada sin eliminarla (trazabilidad)
        # debe_cambiar_password: 1 = el usuario debe cambiar la contraseña al próximo login
        #   Se activa: al crear el admin inicial, al hacer reset admin-to-user.
        c.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                username              TEXT UNIQUE NOT NULL,
                password_hash         TEXT NOT NULL,
                rol                   TEXT DEFAULT 'analista',
                activo                INTEGER DEFAULT 1,
                debe_cambiar_password INTEGER DEFAULT 0,
                created_at            TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)

        # ── RBAC: Catálogo de permisos del sistema ───────────────────────────
        # Inmutable desde código. 'codigo' es la clave que el backend valida.
        # 'categoria' agrupa los permisos en la UI para mostrarlos en secciones.
        #
        # Jerarquía de acceso:
        #   usuario.rol_id → roles → rol_permisos → permisos.codigo
        #   Si rol_id es NULL → fallback por campo 'rol' TEXT (compat. legacy)
        c.execute("""
            CREATE TABLE IF NOT EXISTS permisos (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                codigo      TEXT UNIQUE NOT NULL,
                descripcion TEXT,
                categoria   TEXT
            )
        """)

        # ── RBAC: Roles asignables a usuarios ────────────────────────────────
        # es_builtin=1: admin y analista no se pueden eliminar ni renombrar.
        c.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre      TEXT UNIQUE NOT NULL,
                descripcion TEXT,
                es_builtin  INTEGER DEFAULT 0,
                created_at  TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)

        # ── RBAC: Relación N:M roles ↔ permisos ─────────────────────────────
        # ON DELETE CASCADE: eliminar un rol limpia automáticamente sus permisos.
        c.execute("""
            CREATE TABLE IF NOT EXISTS rol_permisos (
                rol_id     INTEGER NOT NULL REFERENCES roles(id)    ON DELETE CASCADE,
                permiso_id INTEGER NOT NULL REFERENCES permisos(id) ON DELETE CASCADE,
                PRIMARY KEY (rol_id, permiso_id)
            )
        """)

        # Semilla de permisos (INSERT OR IGNORE → idempotente en cada arranque)
        _PERMISOS_SEED = [
            ("ver_alertas",        "Ver lista de alertas",                        "alertas"),
            ("gestionar_alertas",  "Cambiar estado y agregar comentarios",        "alertas"),
            ("ver_agentes",        "Ver lista de agentes conectados",             "agentes"),
            ("gestionar_agentes",  "Aprobar, desactivar y eliminar agentes",      "agentes"),
            ("ver_config",         "Ver configuración FIM",                       "config"),
            ("editar_config",      "Agregar y eliminar carpetas monitoreadas",    "config"),
            ("ver_reportes",       "Ver pestaña de reportes",                     "reportes"),
            ("exportar_reportes",  "Descargar PDF y CSV",                         "reportes"),
            ("ver_usuarios",       "Ver gestión de usuarios",                     "usuarios"),
            ("gestionar_usuarios", "Crear, deshabilitar y resetear usuarios",     "usuarios"),
            ("ver_auditoria",      "Ver log de auditoría",                        "usuarios"),
            ("gestionar_roles",    "Crear roles y modificar permisos",            "usuarios"),
        ]
        for codigo, desc, cat in _PERMISOS_SEED:
            c.execute(
                "INSERT OR IGNORE INTO permisos (codigo, descripcion, categoria) VALUES (?,?,?)",
                (codigo, desc, cat)
            )

        # Semilla de roles builtin con IDs fijos para referencias reproducibles
        c.execute("""INSERT OR IGNORE INTO roles (id, nombre, descripcion, es_builtin)
                     VALUES (1, 'admin', 'Acceso completo al sistema', 1)""")
        c.execute("""INSERT OR IGNORE INTO roles (id, nombre, descripcion, es_builtin)
                     VALUES (2, 'analista', 'Puede ver y gestionar alertas y reportes', 1)""")

        # Rol admin → todos los permisos
        c.execute("""
            INSERT OR IGNORE INTO rol_permisos (rol_id, permiso_id)
            SELECT 1, id FROM permisos
        """)

        # Rol analista → subconjunto de permisos
        for codigo in ("ver_alertas", "gestionar_alertas", "ver_agentes",
                       "ver_reportes", "exportar_reportes"):
            c.execute("""
                INSERT OR IGNORE INTO rol_permisos (rol_id, permiso_id)
                SELECT 2, id FROM permisos WHERE codigo = ?
            """, (codigo,))

        conn.commit()

        # Migraciones no destructivas para DBs existentes
        for migration in [
            "ALTER TABLE usuarios ADD COLUMN debe_cambiar_password INTEGER DEFAULT 0",
            "ALTER TABLE alertas ADD COLUMN ocurrencias INTEGER DEFAULT 1",
            "ALTER TABLE alertas ADD COLUMN ultima_vez TEXT",
            # RBAC: clave foránea al rol del usuario
            "ALTER TABLE usuarios ADD COLUMN rol_id INTEGER REFERENCES roles(id)",
            # TOTP: secret base32 para recuperación de contraseña
            "ALTER TABLE usuarios ADD COLUMN totp_secret TEXT",
            # MITRE ATT&CK: tácticas y técnicas detectadas en la alerta (JSON arrays)
            "ALTER TABLE alertas ADD COLUMN tacticas TEXT DEFAULT '[]'",
            "ALTER TABLE alertas ADD COLUMN tecnicas TEXT DEFAULT '[]'",
            # AbuseIPDB: reputación de la IP de origen
            "ALTER TABLE alertas ADD COLUMN ip_score   INTEGER DEFAULT NULL",
            "ALTER TABLE alertas ADD COLUMN ip_pais    TEXT    DEFAULT NULL",
            "ALTER TABLE alertas ADD COLUMN ip_reports INTEGER DEFAULT NULL",
        ]:
            try:
                c.execute(migration)
                conn.commit()
            except Exception:
                pass  # columna ya existe — ignorar

        # Rellenar ultima_vez en filas antiguas que no la tienen
        c.execute("UPDATE alertas SET ultima_vez = timestamp WHERE ultima_vez IS NULL")

        # Asignar rol_id a usuarios existentes que aún no lo tienen
        # Mapea el campo 'rol' TEXT al id correspondiente en la tabla roles
        c.execute("""
            UPDATE usuarios
            SET rol_id = (SELECT id FROM roles WHERE nombre = usuarios.rol)
            WHERE rol_id IS NULL
        """)
        conn.commit()

        # ── Sesiones activas ─────────────────────────────────────────────────
        # token: secrets.token_hex(32) — 64 caracteres hexadecimales aleatorios.
        # expires_at: timestamp de expiración (8 horas después del login).
        # ON DELETE CASCADE: si se elimina el usuario, sus sesiones desaparecen.
        c.execute("""
            CREATE TABLE IF NOT EXISTS sesiones (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                token      TEXT UNIQUE NOT NULL,
                usuario_id INTEGER NOT NULL,
                created_at TEXT DEFAULT (datetime('now', 'localtime')),
                expires_at TEXT NOT NULL,
                FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
            )
        """)

        # ── Agentes configurados (whitelist de seguridad) ────────────────────
        # Diferencia con la tabla 'agentes': esta es la lista aprobada por el admin.
        # Un agente desconocido se auto-registra aquí como 'pendiente' y es rechazado
        # hasta que el admin lo aprueba desde el Dashboard.
        #
        # api_key: token único por agente para autenticación opcional.
        # Si el agente no envía api_key, se valida solo por nombre+ip (compatibilidad).
        # Si el agente envía api_key, debe coincidir exactamente con la almacenada.
        c.execute("""
            CREATE TABLE IF NOT EXISTS config_agentes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre      TEXT UNIQUE NOT NULL,
                ip          TEXT,
                descripcion TEXT DEFAULT '',
                api_key     TEXT UNIQUE,
                estado      TEXT DEFAULT 'pendiente',
                tipo        TEXT DEFAULT 'windows',
                created_at  TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)

        # ── Configuración global del SIEM ────────────────────────────────────
        c.execute("""
            CREATE TABLE IF NOT EXISTS config_global (
                clave TEXT PRIMARY KEY,
                valor TEXT NOT NULL
            )
        """)
        # Valores por defecto — forzar_2fa existente + nuevas políticas de seguridad
        defaults = [
            ("forzar_2fa",                "0"),
            # Sesión
            ("session_timeout_minutos",   "30"),
            # Política de contraseñas
            ("password_min_length",       "8"),
            ("password_require_upper",    "1"),
            ("password_require_number",   "1"),
            ("password_require_special",  "0"),
            # Bloqueo por intentos fallidos
            ("login_max_intentos",        "5"),
            ("login_bloqueo_minutos",     "15"),
            # Telegram
            ("telegram_bot_token",        ""),
            ("telegram_chat_id",          ""),
            ("telegram_activo",           "0"),
            # AbuseIPDB — Threat Intelligence
            ("abuseipdb_api_key",         ""),
            # Retención de datos
            ("alerta_retencion_dias",     "90"),
        ]
        for clave, valor in defaults:
            c.execute("INSERT OR IGNORE INTO config_global (clave, valor) VALUES (?, ?)", (clave, valor))

        # ── Migraciones: columnas nuevas en tablas existentes ────────────────
        # Agregar ultimo_acceso a sesiones (sliding window para session timeout)
        try:
            c.execute("ALTER TABLE sesiones ADD COLUMN ultimo_acceso TEXT")
        except Exception:
            pass  # ya existe
        # Inicializar ultimo_acceso en sesiones existentes
        c.execute("""
            UPDATE sesiones SET ultimo_acceso = created_at
            WHERE ultimo_acceso IS NULL
        """)

        # Agregar campos de lockout a usuarios
        try:
            c.execute("ALTER TABLE usuarios ADD COLUMN intentos_fallidos INTEGER DEFAULT 0")
        except Exception:
            pass
        try:
            c.execute("ALTER TABLE usuarios ADD COLUMN bloqueado_hasta TEXT DEFAULT NULL")
        except Exception:
            pass

        # Agregar totp_secret y rol_id si no existen (migraciones previas)
        try:
            c.execute("ALTER TABLE usuarios ADD COLUMN totp_secret TEXT")
        except Exception:
            pass
        try:
            c.execute("ALTER TABLE usuarios ADD COLUMN rol_id INTEGER REFERENCES roles(id)")
        except Exception:
            pass

        # ── Log de auditoría ─────────────────────────────────────────────────
        # Registra toda acción sensible: quién, cuándo, qué entidad, valor anterior y nuevo.
        # entidad: 'alerta', 'usuario', 'agente', 'config', 'sesion'
        # accion:  'crear', 'eliminar', 'modificar', 'login', 'logout', 'reset_password', etc.
        c.execute("""
            CREATE TABLE IF NOT EXISTS auditoria (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                ts             TEXT DEFAULT (datetime('now', 'localtime')),
                usuario        TEXT NOT NULL,
                accion         TEXT NOT NULL,
                entidad        TEXT,
                id_entidad     TEXT,
                valor_anterior TEXT,
                valor_nuevo    TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_auditoria_ts      ON auditoria(ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_auditoria_usuario  ON auditoria(usuario)")

        # ── Caché de reputación de IPs (AbuseIPDB) ──────────────────────────
        # TTL gestionado por Python: consultado_at + 24h. Si expiró, se vuelve a consultar.
        c.execute("""
            CREATE TABLE IF NOT EXISTS ip_reputacion (
                ip            TEXT PRIMARY KEY,
                score         INTEGER NOT NULL,
                pais          TEXT,
                pais_emoji    TEXT,
                isp           TEXT,
                total_reports INTEGER DEFAULT 0,
                categorias    TEXT DEFAULT '[]',
                consultado_at TEXT NOT NULL
            )
        """)

        # ── Índices para las consultas más frecuentes del dashboard ──────────
        # Sin índices, cada filtro haría un full-scan de la tabla alertas.
        c.execute("CREATE INDEX IF NOT EXISTS idx_alertas_severity  ON alertas(severity)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_alertas_fuente    ON alertas(fuente)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_alertas_timestamp ON alertas(timestamp DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_eventos_estado    ON eventos_externos(estado)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_sesiones_token    ON sesiones(token)")

        conn.commit()
    finally:
        conn.close()

    # Inicializar cifrado: crea la clave maestra si no existe todavía
    encryption.init()
    # Restringir permisos del archivo de DB (solo el usuario actual puede acceder)
    encryption.restringir_db(DB_PATH)


# ─── ALERTAS ─────────────────────────────────────────────────

# Ventana de deduplicación: alertas del mismo agente y severidad dentro de este
# período se consolidan en una sola fila (incrementando ocurrencias) en lugar de
# crear entradas duplicadas. Se reinicia cuando el ticket pasa a 'cerrada'.
DEDUP_VENTANA_HORAS = 6


def guardar_alerta(analysis: dict, ts: str) -> tuple:
    """
    Persiste o consolida una alerta en la base de datos.
    Retorna (alerta_id, es_nueva: bool).

    Deduplicación: si existe una alerta abierta del mismo agente y severidad
    en las últimas DEDUP_VENTANA_HORAS horas, la incrementa en lugar de crear
    una nueva. El resumen y acción se actualizan con la información más reciente.
    """
    conn = get_connection()
    try:
        c = conn.cursor()
        fuente   = analysis.get("fuente", analysis.get("agente", "desconocido"))
        severity = analysis.get("severity", "low")

        # Buscar alerta abierta reciente del mismo origen y severidad.
        # El corte se calcula en Python para evitar mezclar datetime('now','localtime')
        # de SQLite con los timestamps locales almacenados por Python datetime.now().
        cutoff = (datetime.now() - timedelta(hours=DEDUP_VENTANA_HORAS)).strftime("%Y-%m-%d %H:%M:%S")
        fila = c.execute("""
            SELECT a.id FROM alertas a
            LEFT JOIN tickets t ON t.alerta_id = a.id
            WHERE a.fuente = ?
              AND a.severity = ?
              AND COALESCE(t.estado, 'nueva') != 'cerrada'
              AND datetime(a.ultima_vez) > ?
            ORDER BY a.id DESC
            LIMIT 1
        """, (fuente, severity, cutoff)).fetchone()

        # Serializar ATT&CK para almacenamiento
        tacticas_json = json.dumps(analysis.get("tacticas", []), ensure_ascii=False)
        tecnicas_json = json.dumps(analysis.get("tecnicas", []), ensure_ascii=False)
        # Datos de reputación IP (AbuseIPDB)
        ip_score   = analysis.get("ip_score")
        ip_pais    = analysis.get("ip_pais")
        ip_reports = analysis.get("ip_reports")

        if fila:
            alerta_id = fila[0]
            c.execute("""
                UPDATE alertas
                SET ocurrencias        = ocurrencias + 1,
                    ultima_vez         = ?,
                    summary            = ?,
                    accion_recomendada = ?,
                    tacticas           = ?,
                    tecnicas           = ?,
                    ip_score           = ?,
                    ip_pais            = ?,
                    ip_reports         = ?
                WHERE id = ?
            """, (ts, analysis.get("summary", ""), analysis.get("accion_recomendada", ""),
                  tacticas_json, tecnicas_json,
                  ip_score, ip_pais, ip_reports,
                  alerta_id))
            conn.commit()
            return alerta_id, False

        # Nueva alerta: insertar fila completa con ticket inicial
        c.execute("""
            INSERT INTO alertas
                (timestamp, severity, fuente, ip, summary, accion_recomendada,
                 ocurrencias, ultima_vez, tacticas, tecnicas,
                 ip_score, ip_pais, ip_reports)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
        """, (
            ts, severity, fuente,
            analysis.get("ip", ""),
            analysis.get("summary", ""),
            analysis.get("accion_recomendada", ""),
            ts,
            tacticas_json, tecnicas_json,
            ip_score, ip_pais, ip_reports,
        ))
        alerta_id = c.lastrowid

        # Insertar cada evento individual devuelto por Ollama
        for ev in analysis.get("events", []):
            c.execute("""
                INSERT INTO eventos_alerta (alerta_id, event_id, descripcion, riesgo)
                VALUES (?, ?, ?, ?)
            """, (alerta_id, ev.get("id", ""), ev.get("descripcion", ""), ev.get("riesgo", "")))

        c.execute("INSERT INTO tickets (alerta_id, estado) VALUES (?, 'nueva')", (alerta_id,))
        conn.commit()
        return alerta_id, True
    finally:
        conn.close()


def leer_alertas() -> list:
    """
    Retorna todas las alertas con sus eventos y estado de ticket combinados.
    Ordenadas por ID descendente (más recientes primero).

    El campo '_id' es un alias de 'id' para compatibilidad con el frontend
    que espera '_id' en las llamadas a /api/estado y /api/comentario.
    """
    conn = get_connection()
    try:
        c = conn.cursor()

        c.execute("""
            SELECT
                a.id, a.timestamp, a.severity, a.fuente, a.ip,
                a.summary, a.accion_recomendada, a.created_at,
                COALESCE(a.ocurrencias, 1)          AS ocurrencias,
                COALESCE(a.ultima_vez, a.timestamp) AS ultima_vez,
                COALESCE(t.estado, 'nueva')         AS estado,
                COALESCE(a.tacticas, '[]')           AS tacticas,
                COALESCE(a.tecnicas, '[]')           AS tecnicas,
                a.ip_score, a.ip_pais, a.ip_reports
            FROM alertas a
            LEFT JOIN tickets t ON t.alerta_id = a.id
            ORDER BY a.id DESC
        """)

        alertas = []
        for fila in c.fetchall():
            alerta = dict(fila)
            alerta["_id"] = alerta["id"]  # alias para el frontend
            # Deserializar ATT&CK de JSON a listas Python
            try:
                alerta["tacticas"] = json.loads(alerta.get("tacticas") or "[]")
            except Exception:
                alerta["tacticas"] = []
            try:
                alerta["tecnicas"] = json.loads(alerta.get("tecnicas") or "[]")
            except Exception:
                alerta["tecnicas"] = []

            # Traer los eventos individuales de esta alerta
            c.execute("""
                SELECT event_id AS id, descripcion, riesgo
                FROM eventos_alerta WHERE alerta_id = ?
            """, (alerta["id"],))
            alerta["events"] = [dict(ev) for ev in c.fetchall()]

            # Traer los comentarios ordenados cronológicamente
            c.execute("""
                SELECT texto, ts FROM comentarios
                WHERE alerta_id = ? ORDER BY id ASC
            """, (alerta["id"],))
            alerta["comentarios"] = [dict(cm) for cm in c.fetchall()]

            alertas.append(alerta)

        return alertas
    finally:
        conn.close()


def actualizar_estado_alerta(alerta_id: int, estado: str):
    """
    Actualiza el estado del ticket de una alerta.
    ON CONFLICT DO UPDATE: crea el ticket si no existe, lo actualiza si ya existe.
    """
    conn = get_connection()
    try:
        ts_ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("""
            INSERT INTO tickets (alerta_id, estado, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(alerta_id) DO UPDATE SET
                estado = excluded.estado, updated_at = excluded.updated_at
        """, (alerta_id, estado, ts_ahora))
        conn.commit()
    finally:
        conn.close()


def agregar_comentario(alerta_id: int, texto: str):
    """Agrega una nota de investigación a una alerta."""
    conn = get_connection()
    try:
        ts_ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO comentarios (alerta_id, texto, ts) VALUES (?, ?, ?)",
            (alerta_id, texto, ts_ahora)
        )
        conn.commit()
    finally:
        conn.close()


# ─── EVENTOS EXTERNOS ─────────────────────────────────────────

def guardar_evento_externo(agente: str, ip: str, logs: str) -> int:
    """
    Guarda un lote de logs en la cola de procesamiento y actualiza el tracking del agente.
    Retorna el id del evento insertado.
    """
    conn = get_connection()
    try:
        c = conn.cursor()
        ts_ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tipo = "linux" if ("ubuntu" in agente.lower() or "linux" in agente.lower()) else "windows"

        # Upsert del agente en la tabla de tracking histórico
        c.execute("""
            INSERT INTO agentes (nombre, ip, tipo, ultimo_contacto, estado)
            VALUES (?, ?, ?, ?, 'activo')
            ON CONFLICT(nombre) DO UPDATE SET
                ip = excluded.ip,
                ultimo_contacto = excluded.ultimo_contacto,
                estado = 'activo'
        """, (agente, ip, tipo, ts_ahora))

        c.execute("""
            INSERT INTO eventos_externos (agente, ip, logs, estado, timestamp_recibido)
            VALUES (?, ?, ?, 'pendiente', ?)
        """, (agente, ip, logs, ts_ahora))

        evento_id = c.lastrowid
        conn.commit()
        return evento_id
    finally:
        conn.close()


def get_eventos_pendientes() -> list:
    """Retorna eventos pendientes para que siem_servidor.py los analice (FIFO)."""
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT id, agente, ip, logs, timestamp_recibido
            FROM eventos_externos WHERE estado = 'pendiente' ORDER BY id ASC
        """)
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()


def marcar_evento_procesado(evento_id: int, alerta_id: int = None):
    """
    Marca un evento como procesado y vincula la alerta generada (si hubo una).
    alerta_id=None cuando Ollama falló — el evento igual se marca procesado
    para no bloquear la cola con datos corruptos.
    """
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE eventos_externos SET estado='procesado', alerta_id=? WHERE id=?",
            (alerta_id, evento_id)
        )
        conn.commit()
    finally:
        conn.close()


def leer_eventos_externos() -> list:
    """Retorna todos los eventos externos para el dashboard (más recientes primero)."""
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT id, agente, ip, logs, estado, timestamp_recibido, alerta_id
            FROM eventos_externos ORDER BY id DESC
        """)
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()


def leer_agentes() -> list:
    """Retorna el tracking histórico de agentes (tabla agentes, no config_agentes)."""
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM agentes ORDER BY ultimo_contacto DESC")
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()


# ─── USUARIOS ────────────────────────────────────────────────

def crear_usuario(username: str, password_hash: str, rol: str = "analista",
                  debe_cambiar_password: int = 0) -> int:
    """Crea un nuevo usuario. El password_hash debe venir de auth.hash_password()."""
    conn = get_connection()
    try:
        c = conn.cursor()
        # Buscar el rol_id correspondiente al nombre de rol para el RBAC
        rol_row = c.execute("SELECT id FROM roles WHERE nombre = ?", (rol,)).fetchone()
        rol_id  = rol_row["id"] if rol_row else None
        c.execute("""
            INSERT INTO usuarios (username, password_hash, rol, rol_id, debe_cambiar_password)
            VALUES (?, ?, ?, ?, ?)
        """, (username, password_hash, rol, rol_id, debe_cambiar_password))
        conn.commit()
        return c.lastrowid
    finally:
        conn.close()


def obtener_usuario(username: str) -> dict | None:
    """Busca un usuario por nombre. Retorna dict con password_hash (para verificar en login)."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM usuarios WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# Claves de config_global que contienen datos sensibles y deben cifrarse
_CONFIG_CIFRADAS = {"telegram_bot_token", "abuseipdb_api_key"}

def get_config_global(clave: str, default: str = "") -> str:
    conn = get_connection()
    try:
        row = conn.execute("SELECT valor FROM config_global WHERE clave = ?", (clave,)).fetchone()
        if not row:
            return default
        valor = row["valor"]
        # Descifrar si es un campo sensible
        if clave in _CONFIG_CIFRADAS:
            valor = encryption.decrypt(valor)
        return valor
    finally:
        conn.close()

def set_config_global(clave: str, valor: str):
    if clave in _CONFIG_CIFRADAS and valor:
        valor = encryption.encrypt(valor)
    conn = get_connection()
    try:
        conn.execute("INSERT OR REPLACE INTO config_global (clave, valor) VALUES (?, ?)", (clave, valor))
        conn.commit()
    finally:
        conn.close()

def get_all_config_global() -> dict:
    """Retorna todas las configuraciones globales como dict (campos sensibles descifrados)."""
    conn = get_connection()
    try:
        rows = conn.execute("SELECT clave, valor FROM config_global").fetchall()
        result = {}
        for r in rows:
            val = r["valor"]
            if r["clave"] in _CONFIG_CIFRADAS:
                val = encryption.decrypt(val)
            result[r["clave"]] = val
        return result
    finally:
        conn.close()

def set_many_config_global(items: dict):
    """Guarda múltiples claves cifrando las sensibles."""
    conn = get_connection()
    try:
        for clave, valor in items.items():
            v = str(valor)
            if clave in _CONFIG_CIFRADAS and v:
                v = encryption.encrypt(v)
            conn.execute(
                "INSERT OR REPLACE INTO config_global (clave, valor) VALUES (?, ?)",
                (clave, v)
            )
        conn.commit()
    finally:
        conn.close()

# ─── LOCKOUT ──────────────────────────────────────────────────

def registrar_intento_fallido(username: str) -> dict:
    """
    Incrementa el contador de intentos fallidos.
    Si supera el máximo configurado, bloquea la cuenta por N minutos.
    Retorna {"bloqueado": bool, "intentos": int, "bloqueado_hasta": str|None}
    """
    from datetime import datetime, timedelta
    max_intentos    = int(get_config_global("login_max_intentos", "5"))
    bloqueo_minutos = int(get_config_global("login_bloqueo_minutos", "15"))

    conn = get_connection()
    try:
        conn.execute(
            "UPDATE usuarios SET intentos_fallidos = intentos_fallidos + 1 WHERE username = ?",
            (username,)
        )
        conn.commit()
        row = conn.execute(
            "SELECT intentos_fallidos, bloqueado_hasta FROM usuarios WHERE username = ?",
            (username,)
        ).fetchone()
        if not row:
            return {"bloqueado": False, "intentos": 0, "bloqueado_hasta": None}

        intentos = row["intentos_fallidos"]
        if intentos >= max_intentos:
            hasta = (datetime.now() + timedelta(minutes=bloqueo_minutos)).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "UPDATE usuarios SET bloqueado_hasta = ?, intentos_fallidos = 0 WHERE username = ?",
                (hasta, username)
            )
            conn.commit()
            return {"bloqueado": True, "intentos": intentos, "bloqueado_hasta": hasta}

        return {"bloqueado": False, "intentos": intentos, "bloqueado_hasta": None}
    finally:
        conn.close()

def resetear_intentos_fallidos(username: str):
    """Resetea el contador de intentos fallidos tras un login exitoso."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE username = ?",
            (username,)
        )
        conn.commit()
    finally:
        conn.close()

def verificar_bloqueo(username: str) -> dict:
    """
    Verifica si una cuenta está bloqueada.
    Si el bloqueo expiró, lo limpia automáticamente.
    Retorna {"bloqueado": bool, "bloqueado_hasta": str|None, "segundos_restantes": int}
    """
    from datetime import datetime
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT bloqueado_hasta FROM usuarios WHERE username = ?",
            (username,)
        ).fetchone()
        if not row or not row["bloqueado_hasta"]:
            return {"bloqueado": False, "bloqueado_hasta": None, "segundos_restantes": 0}

        hasta = datetime.strptime(row["bloqueado_hasta"], "%Y-%m-%d %H:%M:%S")
        ahora = datetime.now()
        if ahora >= hasta:
            # Bloqueo expirado — limpiar
            conn.execute(
                "UPDATE usuarios SET bloqueado_hasta = NULL, intentos_fallidos = 0 WHERE username = ?",
                (username,)
            )
            conn.commit()
            return {"bloqueado": False, "bloqueado_hasta": None, "segundos_restantes": 0}

        segundos = int((hasta - ahora).total_seconds())
        return {"bloqueado": True, "bloqueado_hasta": row["bloqueado_hasta"], "segundos_restantes": segundos}
    finally:
        conn.close()

def leer_usuarios() -> list:
    """Retorna todos los usuarios sin el password_hash.
    Incluye rol_id, nombre del rol y si tiene 2FA activo."""
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT u.id, u.username, u.rol, u.activo, u.created_at,
                   u.rol_id, COALESCE(r.nombre, u.rol) AS rol_nombre,
                   CASE WHEN u.totp_secret IS NOT NULL AND u.totp_secret != '' THEN 1 ELSE 0 END AS totp_activo
            FROM usuarios u
            LEFT JOIN roles r ON r.id = u.rol_id
            ORDER BY u.id ASC
        """)
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()


def actualizar_password(usuario_id: int, nuevo_hash: str, debe_cambiar: bool = False):
    """
    Cambia el password de un usuario e invalida todas sus sesiones activas.

    debe_cambiar=False (defecto): el usuario cambió su propia contraseña → limpiar la bandera.
    debe_cambiar=True: admin hizo un reset → el usuario deberá cambiarla en el próximo login.
    """
    nuevo_flag = 1 if debe_cambiar else 0
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE usuarios SET password_hash = ?, debe_cambiar_password = ? WHERE id = ?",
            (nuevo_hash, nuevo_flag, usuario_id)
        )
        # Forzar re-login al cambiar contraseña (seguridad: sesiones comprometidas quedan inválidas)
        conn.execute("DELETE FROM sesiones WHERE usuario_id = ?", (usuario_id,))
        conn.commit()
    finally:
        conn.close()


def eliminar_usuario(usuario_id: int):
    """Elimina un usuario y sus sesiones (CASCADE)."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM usuarios WHERE id = ?", (usuario_id,))
        conn.commit()
    finally:
        conn.close()


def toggle_usuario_activo(usuario_id: int, activo: int):
    """Habilita o deshabilita una cuenta sin eliminarla."""
    conn = get_connection()
    try:
        conn.execute("UPDATE usuarios SET activo = ? WHERE id = ?", (activo, usuario_id))
        if not activo:
            # Si se deshabilita, cerrar todas las sesiones activas
            conn.execute("DELETE FROM sesiones WHERE usuario_id = ?", (usuario_id,))
        conn.commit()
    finally:
        conn.close()


# ─── SESIONES ────────────────────────────────────────────────

def crear_sesion(usuario_id: int) -> str:
    """
    Genera un token de sesión aleatorio criptográficamente seguro,
    lo almacena en la DB con expiración de 8 horas y lo retorna.

    secrets.token_hex(32) genera 64 caracteres hexadecimales → 256 bits de entropía.
    Es prácticamente imposible de adivinar por fuerza bruta.
    """
    DURACION_HORAS = 8
    token      = secrets.token_hex(32)
    expires_at = (datetime.now() + timedelta(hours=DURACION_HORAS)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO sesiones (token, usuario_id, expires_at) VALUES (?, ?, ?)",
            (token, usuario_id, expires_at)
        )
        conn.commit()
        return token
    finally:
        conn.close()


def validar_sesion(token: str) -> dict | None:
    """
    Valida el token con sliding-window inactivity timeout.

    Flujo:
      1. Busca la sesión activa (expires_at no expirado, usuario activo).
      2. Verifica inactividad: si now - ultimo_acceso > session_timeout_minutos → elimina y retorna None.
      3. Si válida → actualiza ultimo_acceso (sliding window).
    """
    from datetime import datetime, timedelta
    conn = get_connection()
    try:
        row = conn.execute("""
            SELECT u.id, u.username, u.rol, u.rol_id, u.debe_cambiar_password,
                   s.ultimo_acceso
            FROM sesiones s
            JOIN usuarios u ON u.id = s.usuario_id
            WHERE s.token = ?
              AND s.expires_at > datetime('now', 'localtime')
              AND u.activo = 1
        """, (token,)).fetchone()

        if not row:
            return None

        # Verificar inactividad (sliding window)
        timeout_min = int(get_config_global("session_timeout_minutos", "30"))
        ultimo = row["ultimo_acceso"]
        if ultimo:
            try:
                ultima_vez = datetime.strptime(ultimo, "%Y-%m-%d %H:%M:%S")
                if datetime.now() - ultima_vez > timedelta(minutes=timeout_min):
                    conn.execute("DELETE FROM sesiones WHERE token = ?", (token,))
                    conn.commit()
                    return None
            except Exception:
                pass

        # Actualizar ultimo_acceso (sliding window)
        ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("UPDATE sesiones SET ultimo_acceso = ? WHERE token = ?", (ahora, token))
        conn.commit()

        return {
            "id":                    row["id"],
            "username":              row["username"],
            "rol":                   row["rol"],
            "rol_id":                row["rol_id"],
            "debe_cambiar_password": row["debe_cambiar_password"],
        }
    finally:
        conn.close()


def eliminar_sesion(token: str):
    """Elimina una sesión específica (logout)."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM sesiones WHERE token = ?", (token,))
        conn.commit()
    finally:
        conn.close()


def limpiar_sesiones_expiradas():
    """
    Elimina sesiones vencidas para mantener la tabla limpia.
    Se llama periódicamente desde el servidor.
    """
    conn = get_connection()
    try:
        conn.execute("DELETE FROM sesiones WHERE expires_at <= datetime('now', 'localtime')")
        conn.commit()
    finally:
        conn.close()


def limpiar_alertas_antiguas() -> int:
    """
    Elimina alertas (y sus eventos/tickets asociados) más antiguas que
    alerta_retencion_dias. Retorna la cantidad de alertas eliminadas.
    Se llama periódicamente desde siem_servidor.py.
    """
    dias = int(get_config_global("alerta_retencion_dias", "90"))
    if dias <= 0:
        return 0  # 0 = retención indefinida
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("""
            DELETE FROM alertas
            WHERE created_at <= datetime('now', 'localtime', ?)
        """, (f"-{dias} days",))
        eliminadas = c.rowcount
        conn.commit()
        return eliminadas
    finally:
        conn.close()


# ─── CONFIG AGENTES ───────────────────────────────────────────

def leer_config_agentes() -> list:
    """Retorna todos los agentes configurados (whitelist) ordenados por estado y nombre."""
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT id, nombre, ip, descripcion, api_key, estado, tipo, created_at
            FROM config_agentes
            ORDER BY
                CASE estado WHEN 'pendiente' THEN 0 WHEN 'activo' THEN 1 ELSE 2 END,
                nombre ASC
        """)
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()


def crear_agente(nombre: str, ip: str, descripcion: str = "", tipo: str = "windows") -> dict:
    """
    Registra un nuevo agente en la whitelist con estado 'activo'.
    Genera automáticamente un api_key único y lo almacena cifrado.
    Retorna el dict del agente con el api_key en texto plano (solo se muestra una vez).
    """
    api_key     = secrets.token_urlsafe(32)
    api_key_enc = encryption.encrypt(api_key)
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO config_agentes (nombre, ip, descripcion, api_key, estado, tipo)
            VALUES (?, ?, ?, ?, 'activo', ?)
        """, (nombre, ip, descripcion, api_key_enc, tipo))
        conn.commit()
        return {"nombre": nombre, "ip": ip, "descripcion": descripcion,
                "api_key": api_key, "estado": "activo", "tipo": tipo}
    finally:
        conn.close()


def actualizar_estado_agente(nombre: str, estado: str):
    """Cambia el estado de un agente (activo/pendiente/inactivo)."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE config_agentes SET estado = ? WHERE nombre = ?", (estado, nombre)
        )
        conn.commit()
    finally:
        conn.close()


def actualizar_agente(nombre: str, ip: str = None, descripcion: str = None):
    """Actualiza campos editables de un agente."""
    conn = get_connection()
    try:
        if ip is not None:
            conn.execute("UPDATE config_agentes SET ip = ? WHERE nombre = ?", (ip, nombre))
        if descripcion is not None:
            conn.execute(
                "UPDATE config_agentes SET descripcion = ? WHERE nombre = ?", (descripcion, nombre)
            )
        conn.commit()
    finally:
        conn.close()


def eliminar_agente_config(nombre: str):
    """Elimina un agente de la whitelist."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM config_agentes WHERE nombre = ?", (nombre,))
        conn.commit()
    finally:
        conn.close()


def regenerar_api_key(nombre: str) -> str:
    """Genera un nuevo api_key cifrado. Retorna el valor en plano para mostrarlo al admin."""
    nuevo_key     = secrets.token_urlsafe(32)
    nuevo_key_enc = encryption.encrypt(nuevo_key)
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE config_agentes SET api_key = ? WHERE nombre = ?", (nuevo_key_enc, nombre)
        )
        conn.commit()
        return nuevo_key
    finally:
        conn.close()


def validar_agente_acceso(nombre: str, ip: str, api_key: str = None) -> tuple:
    """
    Verifica si un agente está autorizado para enviar eventos.

    Lógica de validación (en orden):
    1. Si el agente no existe en config_agentes → auto-registrar como 'pendiente', rechazar.
    2. Si estado='pendiente' → rechazar (esperando aprobación del admin).
    3. Si estado='inactivo' → rechazar.
    4. Si estado='activo':
       a. Si el agente tiene api_key Y el cliente envió api_key → comparar.
       b. Si el agente tiene api_key pero el cliente NO envió → aceptar (modo compatibilidad).
       c. Si el agente no tiene api_key → aceptar por nombre+ip.

    Retorna: (True, "") si aceptado | (False, "mensaje") si rechazado.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM config_agentes WHERE nombre = ?", (nombre,)
        ).fetchone()

        if not row:
            # Auto-registrar como pendiente para que el admin lo vea en el dashboard
            tipo = "linux" if ("ubuntu" in nombre.lower() or "linux" in nombre.lower()) else "windows"
            nuevo_key = encryption.encrypt(secrets.token_urlsafe(32))
            conn.execute("""
                INSERT OR IGNORE INTO config_agentes (nombre, ip, api_key, estado, tipo)
                VALUES (?, ?, ?, 'pendiente', ?)
            """, (nombre, ip, nuevo_key, tipo))
            conn.commit()
            return (False, f"Agente '{nombre}' auto-registrado como pendiente. Aprobalo desde el Dashboard.")

        agente = dict(row)

        if agente["estado"] == "pendiente":
            return (False, f"Agente '{nombre}' pendiente de aprobación del administrador.")

        if agente["estado"] == "inactivo":
            return (False, f"Agente '{nombre}' desactivado.")

        # estado == 'activo' — si el agente tiene api_key configurada, el cliente DEBE enviarla
        if agente.get("api_key"):
            if not api_key:
                return (False, "Este agente requiere API key para autenticarse.")
            # Descifrar la key almacenada antes de comparar
            stored_key = encryption.decrypt(agente["api_key"])
            # secrets.compare_digest evita timing attacks (comparación de longitud constante)
            if not secrets.compare_digest(str(stored_key), str(api_key)):
                return (False, "API key inválida.")

        # Actualizar IP si cambió (agentes con IP dinámica)
        if ip and agente.get("ip") != ip:
            conn.execute("UPDATE config_agentes SET ip = ? WHERE nombre = ?", (ip, nombre))
            conn.commit()

        return (True, "")
    finally:
        conn.close()


# ─── MIGRACIÓN LEGACY ─────────────────────────────────────────

def migrar_datos_legacy(alertas_jsonl: str, tickets_json: str) -> int:
    """
    Migración única desde los archivos de texto a la base de datos SQLite.
    Importa alertas.jsonl y tickets.json si la DB está vacía.
    Retorna la cantidad de alertas migradas.
    """
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM alertas").fetchone()[0]
        if count > 0:
            return 0
        if not os.path.exists(alertas_jsonl):
            return 0

        tickets_legacy = {}
        if os.path.exists(tickets_json):
            with open(tickets_json, "r", encoding="utf-8") as f:
                tickets_legacy = json.load(f)

        c = conn.cursor()
        migrados = 0

        with open(alertas_jsonl, "r", encoding="utf-8") as f:
            for i, linea in enumerate(f):
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    a = json.loads(linea)
                    c.execute("""
                        INSERT INTO alertas (timestamp, severity, fuente, ip, summary, accion_recomendada)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        a.get("timestamp", ""),
                        a.get("severity", "low"),
                        a.get("fuente", a.get("agente", "desconocido")),
                        a.get("ip", ""),
                        a.get("summary", ""),
                        a.get("accion_recomendada", "")
                    ))
                    alerta_id = c.lastrowid

                    for ev in a.get("events", []):
                        c.execute("""
                            INSERT INTO eventos_alerta (alerta_id, event_id, descripcion, riesgo)
                            VALUES (?, ?, ?, ?)
                        """, (alerta_id, ev.get("id", ""), ev.get("descripcion", ""), ev.get("riesgo", "")))

                    # Los tickets legacy usan el número de línea como _id
                    ticket = tickets_legacy.get(str(i), {})
                    c.execute(
                        "INSERT INTO tickets (alerta_id, estado) VALUES (?, ?)",
                        (alerta_id, ticket.get("estado", "nueva"))
                    )

                    for cm in ticket.get("comentarios", []):
                        c.execute(
                            "INSERT INTO comentarios (alerta_id, texto, ts) VALUES (?, ?, ?)",
                            (alerta_id, cm.get("texto", ""), cm.get("ts", ""))
                        )

                    migrados += 1
                except Exception:
                    pass  # Línea corrupta — continuar con la siguiente

        conn.commit()
        return migrados
    finally:
        conn.close()


# ─── RBAC ────────────────────────────────────────────────────
#
# Jerarquía de permisos:
#   usuario.rol_id ──► roles ──► rol_permisos ──► permisos.codigo
#
# El backend siempre valida por 'codigo' (string) para no acoplar
# lógica de negocio a IDs numéricos.  Si rol_id es NULL (usuario
# legacy pre-RBAC), se aplica fallback por el campo 'rol' TEXT.

def obtener_permisos_usuario(usuario_id: int) -> set:
    """
    Retorna el set de códigos de permiso del usuario según su rol_id.
    Fallback: si no tiene rol_id, usa el campo 'rol' TEXT para inferir permisos.
    """
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT p.codigo FROM permisos p
            JOIN rol_permisos rp ON rp.permiso_id = p.id
            JOIN usuarios u      ON u.rol_id       = rp.rol_id
            WHERE u.id = ?
        """, (usuario_id,)).fetchall()

        if rows:
            return {r[0] for r in rows}

        # Fallback legacy: usuario sin rol_id asignado
        u = conn.execute("SELECT rol FROM usuarios WHERE id = ?", (usuario_id,)).fetchone()
        if u and u[0] == "admin":
            return {r[0] for r in conn.execute("SELECT codigo FROM permisos").fetchall()}
        # Permiso mínimo estilo 'analista'
        return {"ver_alertas", "gestionar_alertas", "ver_agentes",
                "ver_reportes", "exportar_reportes"}
    finally:
        conn.close()


def leer_roles() -> list:
    """Retorna todos los roles con la lista de permisos asignados a cada uno."""
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT id, nombre, descripcion, es_builtin, created_at
            FROM roles ORDER BY id ASC
        """)
        roles = []
        for row in c.fetchall():
            rol = dict(row)
            c.execute("""
                SELECT p.id, p.codigo, p.descripcion, p.categoria
                FROM permisos p
                JOIN rol_permisos rp ON rp.permiso_id = p.id
                WHERE rp.rol_id = ?
                ORDER BY p.categoria, p.codigo
            """, (rol["id"],))
            rol["permisos"] = [dict(p) for p in c.fetchall()]
            roles.append(rol)
        return roles
    finally:
        conn.close()


def leer_permisos() -> list:
    """Retorna todos los permisos disponibles ordenados por categoría."""
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT id, codigo, descripcion, categoria
            FROM permisos ORDER BY categoria, codigo
        """)
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()


def crear_rol(nombre: str, descripcion: str) -> int:
    """Crea un rol custom. Lanza IntegrityError si el nombre ya existe."""
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO roles (nombre, descripcion, es_builtin) VALUES (?, ?, 0)",
            (nombre, descripcion)
        )
        conn.commit()
        return c.lastrowid
    finally:
        conn.close()


def eliminar_rol(rol_id: int) -> bool:
    """
    Elimina un rol.  Retorna False SOLO si es el rol 'admin' (id=1),
    que es el único intocable del sistema.
    El rol 'analista' y cualquier rol custom pueden eliminarse siendo admin.
    Los usuarios con ese rol quedan con rol_id=NULL → fallback analista.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, nombre FROM roles WHERE id = ?", (rol_id,)
        ).fetchone()
        if not row:
            return False
        # Solo el rol 'admin' (id=1) es intocable
        if row["nombre"] == "admin":
            return False
        conn.execute("UPDATE usuarios SET rol_id = NULL WHERE rol_id = ?", (rol_id,))
        conn.execute("DELETE FROM roles WHERE id = ?", (rol_id,))
        conn.commit()
        return True
    finally:
        conn.close()


def set_rol_permisos(rol_id: int, permiso_ids: list):
    """Reemplaza completamente los permisos de un rol (DELETE + INSERT)."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM rol_permisos WHERE rol_id = ?", (rol_id,))
        for pid in permiso_ids:
            conn.execute(
                "INSERT OR IGNORE INTO rol_permisos (rol_id, permiso_id) VALUES (?, ?)",
                (rol_id, int(pid))
            )
        conn.commit()
    finally:
        conn.close()


def asignar_rol_usuario(usuario_id: int, rol_id: int):
    """Cambia el rol de un usuario. Mantiene en sync el campo 'rol' TEXT (compat.)."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT nombre FROM roles WHERE id = ?", (rol_id,)
        ).fetchone()
        rol_nombre = row[0] if row else "analista"
        conn.execute(
            "UPDATE usuarios SET rol_id = ?, rol = ? WHERE id = ?",
            (rol_id, rol_nombre, usuario_id)
        )
        conn.commit()
    finally:
        conn.close()


# ─── TOTP ─────────────────────────────────────────────────────

def set_totp_secret(usuario_id: int, secret: str | None):
    """Guarda (cifrado) o elimina el secret TOTP de un usuario (None = desactivar)."""
    valor = encryption.encrypt(secret) if secret else None
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE usuarios SET totp_secret = ? WHERE id = ?",
            (valor, usuario_id)
        )
        conn.commit()
    finally:
        conn.close()


def get_totp_secret(username: str) -> str | None:
    """Retorna el secret TOTP del usuario descifrado, o None si no tiene configurado."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT totp_secret FROM usuarios WHERE username = ?", (username,)
        ).fetchone()
        raw = row[0] if row and row[0] else None
        return encryption.decrypt(raw) if raw else None
    finally:
        conn.close()


# ─── REPORTERÍA FILTRADA ──────────────────────────────────────

def leer_alertas_filtradas(
    fecha_desde: str = None,
    fecha_hasta: str = None,
    severidades: list = None,
    fuentes:     list = None,
    estados:     list = None,
    limite:      int  = 1000
) -> list:
    """
    Consulta SQL dinámica para el módulo de reportería.
    Todos los filtros son opcionales; sin filtros equivale a leer_alertas().

    Parámetros:
      fecha_desde/hasta : 'YYYY-MM-DD' — rango sobre alertas.timestamp
      severidades       : ['critical', 'high', ...] — filtro OR
      fuentes           : ['windows-agente', ...] — filtro OR por LIKE
      estados           : ['nueva', 'resuelta', ...] — sobre tickets.estado
      limite            : máximo de filas retornadas (default 1000)
    """
    conn = get_connection()
    try:
        c = conn.cursor()
        conditions, params = [], []

        if fecha_desde:
            conditions.append("a.timestamp >= ?")
            params.append(fecha_desde + " 00:00:00")
        if fecha_hasta:
            conditions.append("a.timestamp <= ?")
            params.append(fecha_hasta + " 23:59:59")
        if severidades:
            ph = ",".join("?" * len(severidades))
            conditions.append(f"a.severity IN ({ph})")
            params.extend(severidades)
        if estados:
            ph = ",".join("?" * len(estados))
            conditions.append(f"COALESCE(t.estado, 'nueva') IN ({ph})")
            params.extend(estados)
        if fuentes:
            sub = " OR ".join(["a.fuente LIKE ?" for _ in fuentes])
            conditions.append(f"({sub})")
            params.extend([f"%{f}%" for f in fuentes])

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        c.execute(f"""
            SELECT
                a.id, a.timestamp, a.severity, a.fuente, a.ip,
                a.summary, a.accion_recomendada,
                COALESCE(a.ocurrencias, 1)          AS ocurrencias,
                COALESCE(a.ultima_vez, a.timestamp) AS ultima_vez,
                COALESCE(t.estado, 'nueva')         AS estado,
                COALESCE(a.tacticas, '[]')           AS tacticas,
                COALESCE(a.tecnicas, '[]')           AS tecnicas,
                a.ip_score, a.ip_pais, a.ip_reports
            FROM alertas a
            LEFT JOIN tickets t ON t.alerta_id = a.id
            {where}
            ORDER BY a.id DESC
            LIMIT ?
        """, params + [limite])

        alertas = []
        for fila in c.fetchall():
            alerta = dict(fila)
            alerta["_id"] = alerta["id"]
            try:
                alerta["tacticas"] = json.loads(alerta.get("tacticas") or "[]")
            except Exception:
                alerta["tacticas"] = []
            try:
                alerta["tecnicas"] = json.loads(alerta.get("tecnicas") or "[]")
            except Exception:
                alerta["tecnicas"] = []
            c.execute("""
                SELECT event_id AS id, descripcion, riesgo
                FROM eventos_alerta WHERE alerta_id = ?
            """, (alerta["id"],))
            alerta["events"] = [dict(ev) for ev in c.fetchall()]
            c.execute("""
                SELECT texto, ts FROM comentarios
                WHERE alerta_id = ? ORDER BY id ASC
            """, (alerta["id"],))
            alerta["comentarios"] = [dict(cm) for cm in c.fetchall()]
            alertas.append(alerta)

        return alertas
    finally:
        conn.close()


# ─── AUDITORÍA ───────────────────────────────────────────────

def registrar_auditoria(usuario: str, accion: str, entidad: str = None,
                        id_entidad: str = None, valor_anterior: str = None,
                        valor_nuevo: str = None):
    """Registra una acción en el log de auditoría."""
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO auditoria (usuario, accion, entidad, id_entidad, valor_anterior, valor_nuevo)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (usuario, accion, entidad, id_entidad, valor_anterior, valor_nuevo))
        conn.commit()
    finally:
        conn.close()


def leer_auditoria(limite: int = 200) -> list:
    """Retorna los últimos N registros de auditoría (sin filtros)."""
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT id, ts, usuario, accion, entidad, id_entidad, valor_anterior, valor_nuevo
            FROM auditoria ORDER BY id DESC LIMIT ?
        """, (limite,))
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()


def leer_auditoria_filtrada(
    fecha_desde: str = None,
    fecha_hasta: str = None,
    usuario:     str = None,
    accion:      str = None,
    limite:      int = 500
) -> list:
    """
    Consulta filtrada del log de auditoría para reportería y exportación.

    Parámetros:
      fecha_desde/hasta : 'YYYY-MM-DD' — rango sobre auditoria.ts
      usuario           : búsqueda parcial por nombre de usuario (LIKE)
      accion            : código exacto de acción (ej: 'modificar_permisos_rol')
      limite            : máximo de filas (default 500)
    """
    conn = get_connection()
    try:
        conditions, params = [], []

        if fecha_desde:
            conditions.append("ts >= ?")
            params.append(fecha_desde + " 00:00:00")
        if fecha_hasta:
            conditions.append("ts <= ?")
            params.append(fecha_hasta + " 23:59:59")
        if usuario:
            conditions.append("usuario LIKE ?")
            params.append(f"%{usuario}%")
        if accion:
            conditions.append("accion = ?")
            params.append(accion)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        c = conn.cursor()
        c.execute(f"""
            SELECT id, ts, usuario, accion, entidad, id_entidad, valor_anterior, valor_nuevo
            FROM auditoria
            {where}
            ORDER BY id DESC
            LIMIT ?
        """, params + [limite])
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()


def leer_acciones_distintas() -> list:
    """Retorna la lista de acciones únicas registradas (para el filtro dropdown)."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT DISTINCT accion FROM auditoria ORDER BY accion ASC"
        ).fetchall()
        return [r[0] for r in rows]
    finally:
        conn.close()


# ─── CACHÉ AbuseIPDB ─────────────────────────────────────────

_CACHE_TTL_HORAS = 24

def get_ip_reputacion(ip: str) -> dict | None:
    """
    Retorna los datos de reputación de una IP desde la caché, o None si no
    existe o si la entrada expiró (TTL: 24 horas).
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM ip_reputacion WHERE ip = ?", (ip,)
        ).fetchone()
        if not row:
            return None
        # Verificar TTL
        try:
            consultado = datetime.strptime(row["consultado_at"], "%Y-%m-%d %H:%M:%S")
            if datetime.now() - consultado > timedelta(hours=_CACHE_TTL_HORAS):
                conn.execute("DELETE FROM ip_reputacion WHERE ip = ?", (ip,))
                conn.commit()
                return None
        except Exception:
            return None
        return {
            "ip":            row["ip"],
            "score":         row["score"],
            "pais":          row["pais"] or "",
            "pais_emoji":    row["pais_emoji"] or "",
            "isp":           row["isp"] or "",
            "total_reports": row["total_reports"] or 0,
            "categorias":    json.loads(row["categorias"] or "[]"),
            "sospechosa":    row["score"] >= 75,
        }
    finally:
        conn.close()


def set_ip_reputacion(ip: str, data: dict):
    """Guarda o actualiza la reputación de una IP en la caché."""
    conn = get_connection()
    try:
        conn.execute("""
            INSERT OR REPLACE INTO ip_reputacion
                (ip, score, pais, pais_emoji, isp, total_reports, categorias, consultado_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip,
            data.get("score", 0),
            data.get("pais", ""),
            data.get("pais_emoji", ""),
            data.get("isp", ""),
            data.get("total_reports", 0),
            json.dumps(data.get("categorias", []), ensure_ascii=False),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ))
        conn.commit()
    finally:
        conn.close()


def leer_ips_sospechosas(limite: int = 20) -> list:
    """Retorna las IPs más maliciosas de la caché, ordenadas por score descendente."""
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT ip, score, pais, pais_emoji, isp, total_reports, categorias
            FROM ip_reputacion
            WHERE score >= 75
            ORDER BY score DESC, total_reports DESC
            LIMIT ?
        """, (limite,)).fetchall()
        result = []
        for r in rows:
            result.append({
                "ip":            r["ip"],
                "score":         r["score"],
                "pais":          r["pais"] or "",
                "pais_emoji":    r["pais_emoji"] or "",
                "isp":           r["isp"] or "",
                "total_reports": r["total_reports"] or 0,
                "categorias":    json.loads(r["categorias"] or "[]"),
            })
        return result
    finally:
        conn.close()
