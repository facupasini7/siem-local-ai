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

    Credenciales por defecto:
      Usuario:  admin
      Password: admin123

    ⚠ El admin DEBE cambiar la contraseña desde el Dashboard en el primer login.
    """
    conn = database.get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
        if count > 0:
            return  # Ya existen usuarios, no hacer nada
    finally:
        conn.close()

    # Crear el admin por defecto con bandera de cambio obligatorio de contraseña
    password_hash = hash_password("admin123")
    database.crear_usuario("admin", password_hash, "admin", debe_cambiar_password=1)

    print("=" * 55)
    print("  [AUTH] Primer arranque — usuario admin creado")
    print("  [AUTH]   Usuario:  admin")
    print("  [AUTH]   Password: admin123")
    print("  [AUTH]   ⚠  Cambiar contraseña desde el Dashboard!")
    print("=" * 55)


# ─── LOGIN Y SESIONES ─────────────────────────────────────────

def login(username: str, password: str) -> dict | None:
    """
    Autentica un usuario y emite un token de sesión si las credenciales son válidas.

    Flujo:
      1. Busca el usuario en la DB por nombre de usuario.
      2. Verifica que la cuenta esté activa (activo=1).
      3. Compara la contraseña con el hash almacenado usando bcrypt.
      4. Si todo es correcto, crea una sesión en la DB y retorna el token.

    Retorna:
      {"token": str, "rol": str, "username": str}  si las credenciales son válidas.
      None  si el usuario no existe, la cuenta está deshabilitada, o la contraseña es incorrecta.

    Nota de seguridad: el mensaje de error no distingue entre "usuario no existe"
    y "contraseña incorrecta" para no dar información al atacante.
    """
    usuario = database.obtener_usuario(username)

    if not usuario:
        return None

    if not usuario.get("activo"):
        return None

    if not verify_password(password, usuario["password_hash"]):
        return None

    # Credenciales válidas → crear sesión en la DB y retornar el token
    token = database.crear_sesion(usuario["id"])

    return {
        "token":                token,
        "rol":                  usuario["rol"],
        "username":             usuario["username"],
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
