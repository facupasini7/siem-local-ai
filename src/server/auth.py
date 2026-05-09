"""
Módulo de autenticación del SIEM.

Responsabilidades:
  - Hash y verificación de contraseñas con bcrypt (algoritmo estándar para passwords).
  - Login: verificar credenciales y emitir token de sesión.
  - Validación de token: extraer el usuario autenticado desde un token Bearer.
  - Inicialización del usuario admin por defecto en el primer arranque.

Dependencia: pip install bcrypt
bcrypt aplica un factor de costo configurable (rounds=12 ≈ 250ms por hash),
lo que hace que los ataques de fuerza bruta sean computacionalmente costosos.
"""

import bcrypt
import re
import database

# ─── PASSWORDS ───────────────────────────────────────────────

def hash_password(password: str) -> str:
    """
    Genera el hash bcrypt de una contraseña en texto plano.

    bcrypt.gensalt(rounds=12): genera una salt aleatoria con factor de costo 12.
    Más rounds = más lento (más seguro), pero 12 es el balance recomendado en 2025.
    La salt está embebida en el hash resultante, no se guarda por separado.

    Ejemplo de hash resultante:
      $2b$12$eImiTXuWVxfM37uY4JANjQ.../...etc
      ^   ^                              ^
      alg cost                          hash+salt combinados (60 chars)
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifica que una contraseña en texto plano coincida con el hash almacenado.

    bcrypt.checkpw extrae la salt del hash almacenado, hashea la contraseña
    ingresada con esa misma salt y compara. Es resistente a timing attacks.
    """
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except Exception:
        return False


# ─── INICIALIZACIÓN ──────────────────────────────────────────

def init_admin_if_needed():
    """
    Crea el usuario administrador por defecto si no existe ningún usuario en la DB.
    Se llama una sola vez al arrancar dashboard.py.

    La contraseña se genera aleatoriamente en el primer arranque y se muestra
    UNA SOLA VEZ en la consola. No existe contraseña por defecto predecible.

    ⚠ El admin DEBE cambiar la contraseña desde el Dashboard en el primer login.
    """
    import secrets as _sec
    conn = database.get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
        if count > 0:
            return  # Ya existen usuarios, no hacer nada
    finally:
        conn.close()

    # Contraseña aleatoria segura — token de 16 bytes en base64 URL-safe (~22 chars)
    password_inicial = _sec.token_urlsafe(16)
    password_hash = hash_password(password_inicial)
    database.crear_usuario("admin", password_hash, "admin", debe_cambiar_password=1)

    print("=" * 60)
    print("  [AUTH] Primer arranque — usuario admin creado")
    print("  [AUTH]   Usuario:  admin")
    print(f"  [AUTH]   Password: {password_inicial}")
    print("  [AUTH]   ⚠  Esta contraseña se muestra UNA SOLA VEZ.")
    print("  [AUTH]   ⚠  Cambiar desde el Dashboard en el primer login.")
    print("=" * 60)


# ─── LOGIN Y SESIONES ─────────────────────────────────────────

def validar_password_policy(password: str) -> list[str]:
    """
    Valida la contraseña contra las políticas configuradas en config_global.
    Retorna lista de errores (vacía = contraseña válida).
    """
    errores = []
    min_len  = int(database.get_config_global("password_min_length",      "8"))
    req_up   = database.get_config_global("password_require_upper",   "1") == "1"
    req_num  = database.get_config_global("password_require_number",  "1") == "1"
    req_spec = database.get_config_global("password_require_special", "0") == "1"

    if len(password) < min_len:
        errores.append(f"Mínimo {min_len} caracteres.")
    if req_up and not re.search(r"[A-Z]", password):
        errores.append("Debe contener al menos una mayúscula.")
    if req_num and not re.search(r"\d", password):
        errores.append("Debe contener al menos un número.")
    if req_spec and not re.search(r"[!@#$%^&*()\-_=+\[\]{};:',.<>?/\\|`~]", password):
        errores.append("Debe contener al menos un carácter especial (!@#$%...).")
    return errores


def verificar_credenciales(username: str, password: str) -> dict | None:
    """
    Valida usuario y contraseña SIN crear sesión.

    Usado por el flujo de login en dos pasos (cuando hay TOTP activo):
      Paso 1: verificar_credenciales() → ok → preguntar código TOTP
      Paso 2: código correcto → crear_sesion() → emitir token

    Retorna:
      dict del usuario  si las credenciales son válidas.
      {"error": str}    si la cuenta está bloqueada.
      None              si las credenciales son incorrectas.
    """
    usuario = database.obtener_usuario(username)
    if not usuario or not usuario.get("activo"):
        return None

    bloqueo = database.verificar_bloqueo(username)
    if bloqueo["bloqueado"]:
        mins = bloqueo["segundos_restantes"] // 60 + 1
        return {"error": f"Cuenta bloqueada. Intentá en {mins} minuto(s)."}

    if not verify_password(password, usuario["password_hash"]):
        resultado = database.registrar_intento_fallido(username)
        if resultado["bloqueado"]:
            mins = int(database.get_config_global("login_bloqueo_minutos", "15"))
            return {"error": f"Demasiados intentos fallidos. Cuenta bloqueada por {mins} minuto(s)."}
        return None

    database.resetear_intentos_fallidos(username)
    return usuario


def login(username: str, password: str) -> dict | None:
    """
    Autentica un usuario y emite un token de sesión si las credenciales son válidas.

    Flujo de dos pasos cuando el usuario tiene TOTP configurado:
      - Si tiene TOTP: retorna {"requiere_totp": True, "username": str} (sin sesión)
      - El dashboard almacena un token temporal y espera el código TOTP
      - Si no tiene TOTP: crea la sesión directamente y retorna el token

    Retorna:
      {"token": str, "rol": str, "username": str}    → login completo (sin TOTP)
      {"requiere_totp": True, "username": str}        → necesita verificar TOTP
      {"error": str}                                  → cuenta bloqueada
      None                                            → credenciales incorrectas
    """
    usuario = verificar_credenciales(username, password)

    if usuario is None:
        return None
    if "error" in usuario:
        return usuario  # cuenta bloqueada

    # Verificar si el usuario tiene TOTP activo
    totp_secret = database.get_totp_secret(username)
    if totp_secret:
        # No crear sesión todavía — el frontend debe pedir el código TOTP
        return {
            "requiere_totp": True,
            "username":      usuario["username"],
        }

    # Sin TOTP → crear sesión directamente
    token = database.crear_sesion(usuario["id"])
    return {
        "token":                 token,
        "rol":                   usuario["rol"],
        "username":              usuario["username"],
        "debe_cambiar_password": bool(usuario.get("debe_cambiar_password", 0))
    }


def get_session_user(token: str) -> dict | None:
    """
    Valida un token de sesión Bearer y retorna el usuario asociado.

    Retorna:
      {"id": int, "username": str, "rol": str}  si el token es válido y no expiró.
      None  si el token no existe, expiró, o el usuario fue deshabilitado.
    """
    if not token:
        return None
    return database.validar_sesion(token)


def logout(token: str):
    """Invalida el token de sesión (logout explícito)."""
    database.eliminar_sesion(token)
