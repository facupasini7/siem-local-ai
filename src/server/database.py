import sqlite3
import json
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path

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

        # Migraciones no destructivas para DBs existentes
        for migration in [
            "ALTER TABLE usuarios ADD COLUMN debe_cambiar_password INTEGER DEFAULT 0",
            "ALTER TABLE alertas ADD COLUMN ocurrencias INTEGER DEFAULT 1",
            "ALTER TABLE alertas ADD COLUMN ultima_vez TEXT",
        ]:
            try:
                c.execute(migration)
                conn.commit()
            except Exception:
                pass  # columna ya existe — ignorar

        # Rellenar ultima_vez en filas antiguas que no la tienen
        c.execute("UPDATE alertas SET ultima_vez = timestamp WHERE ultima_vez IS NULL")
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

        # Buscar alerta abierta reciente del mismo origen y severidad
        fila = c.execute("""
            SELECT a.id FROM alertas a
            LEFT JOIN tickets t ON t.alerta_id = a.id
            WHERE a.fuente = ?
              AND a.severity = ?
              AND COALESCE(t.estado, 'nueva') != 'cerrada'
              AND datetime(a.ultima_vez) > datetime('now', 'localtime', ?)
            ORDER BY a.id DESC
            LIMIT 1
        """, (fuente, severity, f'-{DEDUP_VENTANA_HORAS} hours')).fetchone()

        if fila:
            alerta_id = fila[0]
            c.execute("""
                UPDATE alertas
                SET ocurrencias        = ocurrencias + 1,
                    ultima_vez         = ?,
                    summary            = ?,
                    accion_recomendada = ?
                WHERE id = ?
            """, (ts, analysis.get("summary", ""), analysis.get("accion_recomendada", ""), alerta_id))
            conn.commit()
            return alerta_id, False

        # Nueva alerta: insertar fila completa con ticket inicial
        c.execute("""
            INSERT INTO alertas
                (timestamp, severity, fuente, ip, summary, accion_recomendada, ocurrencias, ultima_vez)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        """, (
            ts, severity, fuente,
            analysis.get("ip", ""),
            analysis.get("summary", ""),
            analysis.get("accion_recomendada", ""),
            ts,
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
                COALESCE(a.ocurrencias, 1) AS ocurrencias,
                COALESCE(a.ultima_vez, a.timestamp) AS ultima_vez,
                COALESCE(t.estado, 'nueva') AS estado
            FROM alertas a
            LEFT JOIN tickets t ON t.alerta_id = a.id
            ORDER BY a.id DESC
        """)

        alertas = []
        for fila in c.fetchall():
            alerta = dict(fila)
            alerta["_id"] = alerta["id"]  # alias para el frontend

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
        c.execute("""
            INSERT INTO usuarios (username, password_hash, rol, debe_cambiar_password)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, rol, debe_cambiar_password))
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


def leer_usuarios() -> list:
    """Retorna todos los usuarios sin el password_hash (para listar en el dashboard)."""
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT id, username, rol, activo, created_at FROM usuarios ORDER BY id ASC")
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
    Valida que el token exista y no haya expirado.
    Retorna {id, username, rol, debe_cambiar_password} del usuario, o None si inválido.

    datetime('now', 'localtime') compara contra la hora local del sistema.
    """
    conn = get_connection()
    try:
        row = conn.execute("""
            SELECT u.id, u.username, u.rol, u.debe_cambiar_password
            FROM sesiones s
            JOIN usuarios u ON u.id = s.usuario_id
            WHERE s.token = ?
              AND s.expires_at > datetime('now', 'localtime')
              AND u.activo = 1
        """, (token,)).fetchone()
        return dict(row) if row else None
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
    Genera automáticamente un api_key único para ese agente.
    Retorna el dict del agente creado (incluyendo el api_key para mostrarlo al admin).
    """
    # secrets.token_urlsafe(32) genera un token de 43 caracteres URL-safe
    api_key = secrets.token_urlsafe(32)
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO config_agentes (nombre, ip, descripcion, api_key, estado, tipo)
            VALUES (?, ?, ?, ?, 'activo', ?)
        """, (nombre, ip, descripcion, api_key, tipo))
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
    """Genera un nuevo api_key para un agente (útil si el anterior fue comprometido)."""
    nuevo_key = secrets.token_urlsafe(32)
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE config_agentes SET api_key = ? WHERE nombre = ?", (nuevo_key, nombre)
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
            nuevo_key = secrets.token_urlsafe(32)
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

        # estado == 'activo' — validar api_key si ambos lados la tienen configurada
        if agente.get("api_key") and api_key:
            # secrets.compare_digest evita timing attacks (comparación de longitud constante)
            if not secrets.compare_digest(str(agente["api_key"]), str(api_key)):
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
