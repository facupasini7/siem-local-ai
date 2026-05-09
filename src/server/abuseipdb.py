"""
abuseipdb.py — Enriquecimiento de IPs con threat intelligence de AbuseIPDB.

Flujo:
  1. Verifica si la IP es pública (descarta privadas/loopback — no tienen reputación).
  2. Consulta la caché en DB (tabla ip_reputacion, TTL 24h) para no desperdiciar cuota.
  3. Si no está en caché: llama a la API de AbuseIPDB.
  4. Guarda el resultado en caché y lo devuelve.
  5. Si ip_score >= 75: marca la IP como sospechosa en el análisis.
  6. Si ip_score >= 90: escala la severidad de la alerta a HIGH como mínimo.

API gratuita de AbuseIPDB: 1000 consultas / día.
Referencia: https://docs.abuseipdb.com/#check-endpoint
"""
import urllib.request
import urllib.error
import json
import ssl
import ipaddress
from datetime import datetime, timedelta

import database  # caché persistente en SQLite

# TTL de la caché: 24 horas (las reputaciones no cambian tan rápido)
CACHE_TTL_HORAS = 24

# Umbral para etiquetar como sospechosa / escalar severidad
SCORE_SOSPECHOSO = 75
SCORE_ESCALAR    = 90

_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

# ─── CATEGORÍAS AbuseIPDB (las más relevantes para un SIEM) ──────────────────
CATEGORIAS: dict = {
    3:  "Fraude",
    4:  "DDoS",
    9:  "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    14: "Port Scan",
    15: "Hacking",
    18: "Brute Force",
    19: "Bad Web Bot",
    20: "Explotación",
    21: "Web App Attack",
    22: "SSH Attack",
    23: "IoT Targeted",
}


def es_ip_publica(ip: str) -> bool:
    """
    Retorna True si la IP es pública y vale la pena consultar su reputación.
    Descarta: privadas (RFC1918), loopback, link-local, multicast, broadcast.
    """
    if not ip or ip in ("desconocida", "unknown", "localhost", "-", ""):
        return False
    try:
        obj = ipaddress.ip_address(ip)
        return (
            not obj.is_private
            and not obj.is_loopback
            and not obj.is_link_local
            and not obj.is_multicast
            and not obj.is_reserved
            and not obj.is_unspecified
        )
    except ValueError:
        return False


def _pais_a_emoji(codigo: str) -> str:
    """Convierte un código de país ISO 3166-1 alpha-2 en emoji de bandera."""
    if not codigo or len(codigo) != 2:
        return ""
    try:
        return "".join(
            chr(0x1F1E6 + ord(c) - ord("A"))
            for c in codigo.upper()
        )
    except Exception:
        return ""


def _api_key() -> str:
    """Lee la API key de AbuseIPDB desde config_global (cifrada en DB)."""
    return database.get_config_global("abuseipdb_api_key", "").strip()


def consultar_ip(ip: str) -> dict | None:
    """
    Consulta la reputación de una IP. Primero revisa caché, luego llama a la API.

    Retorna dict con:
      {
        "ip":           "185.220.101.45",
        "score":        100,            # 0-100: cuánto se considera maliciosa
        "pais":         "DE",
        "pais_emoji":   "🇩🇪",
        "isp":          "Tor Project",
        "total_reports": 8423,
        "categorias":   ["SSH Attack", "Brute Force"],
        "sospechosa":   True,           # score >= SCORE_SOSPECHOSO
        "desde_cache":  False,
      }
    Retorna None si la IP es privada, no hay API key configurada, o falla la API.
    """
    if not es_ip_publica(ip):
        return None

    api_key = _api_key()
    if not api_key:
        return None

    # ── Revisar caché ─────────────────────────────────────────────────────
    cached = database.get_ip_reputacion(ip)
    if cached:
        return {**cached, "desde_cache": True}

    # ── Llamar a la API ───────────────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        url = f"{_ENDPOINT}?ipAddress={ip}&maxAgeInDays=90&verbose"
        req = urllib.request.Request(
            url,
            headers={
                "Key":    api_key,
                "Accept": "application/json",
            }
        )
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            data = json.loads(resp.read()).get("data", {})

        score   = data.get("abuseConfidenceScore", 0)
        pais    = data.get("countryCode", "") or ""
        isp     = data.get("isp", "") or ""
        reports = data.get("totalReports", 0)

        # Decodificar categorías numéricas a nombres legibles
        cats_raw = data.get("reports", [])
        cats_set: set = set()
        for r in cats_raw:
            for cat_id in r.get("categories", []):
                if cat_id in CATEGORIAS:
                    cats_set.add(CATEGORIAS[cat_id])
        categorias = sorted(cats_set)

        resultado = {
            "ip":            ip,
            "score":         score,
            "pais":          pais,
            "pais_emoji":    _pais_a_emoji(pais),
            "isp":           isp,
            "total_reports": reports,
            "categorias":    categorias,
            "sospechosa":    score >= SCORE_SOSPECHOSO,
            "desde_cache":   False,
        }

        # Guardar en caché
        database.set_ip_reputacion(ip, resultado)
        return resultado

    except urllib.error.HTTPError as e:
        if e.code == 429:
            print(f"[AbuseIPDB] Cuota diaria agotada (429) para IP {ip}")
        else:
            print(f"[AbuseIPDB] HTTP {e.code} consultando {ip}")
        return None
    except Exception as e:
        print(f"[AbuseIPDB] Error consultando {ip}: {e}")
        return None


def enriquecer_analisis(analysis: dict) -> dict:
    """
    Agrega datos de reputación al dict de análisis (in-place + retornado).
    Si el score supera los umbrales, escala la severidad automáticamente.

    Agrega:
      analysis["ip_info"]    = dict con datos de AbuseIPDB (o None)
      analysis["ip_score"]   = int 0-100 (o None)
      analysis["ip_pais"]    = str código país (o None)
      analysis["ip_reports"] = int total de reportes (o None)
    """
    ip    = analysis.get("ip", "")
    info  = consultar_ip(ip)

    analysis["ip_info"]    = info
    analysis["ip_score"]   = info["score"]   if info else None
    analysis["ip_pais"]    = info["pais"]    if info else None
    analysis["ip_reports"] = info["total_reports"] if info else None

    if not info:
        return analysis

    score = info["score"]

    # Escalar severidad según reputación
    ORDEN = ["low", "medium", "high", "critical"]
    sev_actual = analysis.get("severity", "low")

    if score >= SCORE_ESCALAR:           # >= 90 → mínimo HIGH
        piso = "high"
    elif score >= SCORE_SOSPECHOSO:      # >= 75 → mínimo MEDIUM
        piso = "medium"
    else:
        piso = None

    if piso and ORDEN.index(piso) > ORDEN.index(sev_actual):
        analysis["severity"] = piso
        print(
            f"[AbuseIPDB] {ip} score={score} ({info['pais']}) — "
            f"severidad escalada {sev_actual}→{piso}"
        )
    else:
        cats = ", ".join(info["categorias"][:3]) if info["categorias"] else "—"
        print(
            f"[AbuseIPDB] {ip} score={score} ({info['pais']}) "
            f"· {info['total_reports']} reportes · {cats}"
        )

    return analysis
