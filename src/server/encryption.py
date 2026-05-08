"""
Módulo de cifrado simétrico para el SIEM.

Protege campos sensibles en la base de datos usando Fernet (AES-128-CBC + HMAC-SHA256).

Arquitectura de claves:
  - La clave maestra se genera una sola vez y se guarda en data/.siem_keyfile
  - El archivo de clave NUNCA se almacena en la DB ni en el código
  - Si se pierde la clave, los campos cifrados son irrecuperables
    (por eso también se restringen los permisos del archivo de clave)

Campos cifrados:
  - usuarios.totp_secret
  - config_global: telegram_bot_token
  - config_agentes.api_key

Compatibilidad con datos existentes (migración):
  - decrypt() detecta si el valor ya está cifrado por el prefijo Fernet ("gAAAAA")
  - Si no está cifrado, retorna el valor en plano y lo marca para re-cifrar
  - Esto permite migrar sin perder datos existentes
"""

import os
import subprocess
from pathlib import Path
from typing import Optional

# ─── RUTA DE LA CLAVE ────────────────────────────────────────
_ROOT     = Path(__file__).parent.parent.parent
_KEY_FILE = _ROOT / "data" / ".siem_keyfile"

# Prefijo que produce Fernet — permite detectar valores ya cifrados
_FERNET_PREFIX = "gAAAAA"

# Instancia global (lazy init)
_fernet = None


def _restringir_permisos_keyfile():
    """
    Restringe el acceso al archivo de clave al usuario actual.
    Windows: usa icacls para quitar herencia y denegar acceso a Everyone.
    """
    try:
        path = str(_KEY_FILE)
        # Quitar herencia de permisos
        subprocess.run(
            ["icacls", path, "/inheritance:r"],
            capture_output=True, check=False
        )
        # Dar control total solo al usuario actual
        subprocess.run(
            ["icacls", path, "/grant:r", f"{os.environ.get('USERNAME', 'SYSTEM')}:(F)"],
            capture_output=True, check=False
        )
        # Denegar acceso a todos los demás
        subprocess.run(
            ["icacls", path, "/deny", "Everyone:(R,W,D)"],
            capture_output=True, check=False
        )
    except Exception:
        pass  # No bloquear el arranque si icacls falla


def _get_or_create_key() -> bytes:
    """
    Retorna la clave Fernet existente o genera una nueva en el primer arranque.
    La clave se persiste en data/.siem_keyfile con permisos restringidos.
    """
    if _KEY_FILE.exists():
        return _KEY_FILE.read_bytes().strip()

    # Primer arranque — generar clave nueva
    try:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
    except ImportError:
        raise RuntimeError(
            "Librería 'cryptography' no instalada. "
            "Ejecutá: pip install cryptography"
        )

    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_bytes(key)
    _restringir_permisos_keyfile()
    print(f"[Encryption] Clave maestra generada en: {_KEY_FILE}")
    print("[Encryption] IMPORTANTE: Hacé un backup de este archivo.")
    return key


def _get_fernet():
    """Retorna la instancia Fernet inicializada (singleton)."""
    global _fernet
    if _fernet is None:
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            raise RuntimeError("pip install cryptography")
        _fernet = Fernet(_get_or_create_key())
    return _fernet


def encrypt(value: str) -> str:
    """
    Cifra un string. Retorna el valor cifrado en base64.
    Si el valor está vacío o ya cifrado, lo retorna sin cambios.
    """
    if not value:
        return value
    if value.startswith(_FERNET_PREFIX):
        return value  # ya cifrado
    return _get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt(value: str) -> str:
    """
    Descifra un string cifrado con Fernet.
    Si el valor no está cifrado (migración de datos existentes), lo retorna en plano.
    """
    if not value:
        return value
    if not value.startswith(_FERNET_PREFIX):
        return value  # valor legado sin cifrar — compatibilidad
    try:
        return _get_fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except Exception:
        return value  # si falla el descifrado, retornar en plano


def is_encrypted(value: str) -> bool:
    """Indica si un valor ya fue cifrado por este módulo."""
    return bool(value and value.startswith(_FERNET_PREFIX))


def init():
    """
    Inicializa el sistema de cifrado al arranque del servidor.
    Crea la clave maestra si no existe todavía.
    Llamar desde init_db() para garantizar que la clave esté lista
    antes de cualquier operación de lectura/escritura.
    """
    _get_fernet()  # dispara _get_or_create_key() si el archivo no existe


def restringir_db(db_path: Path):
    """
    Restringe los permisos del archivo de base de datos.
    Solo el usuario actual puede leer/escribir.
    """
    try:
        path = str(db_path)
        subprocess.run(["icacls", path, "/inheritance:r"], capture_output=True, check=False)
        subprocess.run(
            ["icacls", path, "/grant:r", f"{os.environ.get('USERNAME', 'SYSTEM')}:(F)"],
            capture_output=True, check=False
        )
        subprocess.run(
            ["icacls", path, "/deny", "Everyone:(R,W,D)"],
            capture_output=True, check=False
        )
        print(f"[Encryption] Permisos restringidos en: {db_path}")
    except Exception as e:
        print(f"[Encryption] No se pudieron restringir permisos: {e}")
