#!/usr/bin/env python3
"""E5 · S05 — Módulo de Ciberseguridad.

- Auth con hashing seguro: bcrypt (nunca texto plano).
- RBAC: roles admin/analista con permisos.
- Cifrado: AES-256-GCM de datos sensibles (historial/URLs).
- Auditoría: SQLite con quién, qué URL, cuándo, resultado.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROLES = {"admin", "analista"}
PERMISOS = {
    "admin": {"analizar", "ver_historial", "ver_auditoria", "gestionar_usuarios"},
    "analista": {"analizar", "ver_historial"},
}
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "phishing.db"
_KEY_FILE = Path(__file__).resolve().parent.parent / "data" / ".secret_key"


# ---------- Cifrado AES-256-GCM ----------
def _clave() -> bytes:
    _KEY_FILE.parent.mkdir(exist_ok=True)
    if _KEY_FILE.exists():
        return bytes.fromhex(_KEY_FILE.read_text().strip())
    k = AESGCM.generate_key(bit_length=256)
    _KEY_FILE.write_text(k.hex())
    _KEY_FILE.chmod(0o600)
    return k


def cifrar(texto: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(_clave()).encrypt(nonce, texto.encode(), None)
    return (nonce + ct).hex()


def descifrar(blob: str) -> str:
    raw = bytes.fromhex(blob)
    return AESGCM(_clave()).decrypt(raw[:12], raw[12:], None).decode()


# ---------- Base de datos y auditoría ----------
def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS usuarios(
        usuario TEXT PRIMARY KEY, hash TEXT NOT NULL,
        rol TEXT NOT NULL CHECK(rol IN ('admin','analista')), salt TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS auditoria(
        id INTEGER PRIMARY KEY AUTOINCREMENT, usuario TEXT, accion TEXT,
        url TEXT, resultado TEXT, ts REAL);
    CREATE TABLE IF NOT EXISTS historial(
        id INTEGER PRIMARY KEY AUTOINCREMENT, usuario TEXT, url_cif TEXT,
        nivel TEXT, score INTEGER, ts REAL);
    """)
    return conn


# ---------- Auth con hashing seguro ----------
def crear_usuario(usuario: str, password: str, rol: str) -> None:
    if rol not in ROLES:
        raise ValueError(f"rol inválido: {rol} (use {sorted(ROLES)})")
    salt = secrets.token_hex(16)
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    with db() as c:
        c.execute("INSERT INTO usuarios VALUES (?,?,?,?)", (usuario, h, rol, salt))
        _auditoria(c, usuario, "crear_usuario", None, f"rol={rol}")


def login(usuario: str, password: str) -> dict | None:
    with db() as c:
        row = c.execute("SELECT * FROM usuarios WHERE usuario=?", (usuario,)).fetchone()
        if row is None:
            return None
        ok = bcrypt.checkpw(password.encode(), row["hash"].encode())
        _auditoria(c, usuario, "login", None, "ok" if ok else "fallido")
        if not ok:
            return None
        token = secrets.token_hex(16)
        return {"usuario": usuario, "rol": row["rol"], "token": token,
                "permisos": sorted(PERMISOS[row["rol"]])}


def requiere_rol(token_info: dict | None, permiso: str) -> bool:
    if not token_info:
        return False
    return permiso in PERMISOS.get(token_info.get("rol", ""), set())


def _auditoria(conn: sqlite3.Connection, usuario: str, accion: str,
                url: str | None, resultado: str) -> None:
    conn.execute("INSERT INTO auditoria(usuario,accion,url,resultado,ts) VALUES (?,?,?,?,?)",
                 (usuario, accion, url, resultado, time.time()))


def auditar(usuario: str, accion: str, url: str | None, resultado: str) -> None:
    with db() as c:
        _auditoria(c, usuario, accion, url, resultado)


# ---------- Historial cifrado ----------
def guardar_historial(usuario: str, url: str, nivel: str, score: int) -> None:
    with db() as c:
        c.execute("INSERT INTO historial(usuario,url_cif,nivel,score,ts) VALUES (?,?,?,?,?)",
                  (usuario, cifrar(url), nivel, score, time.time()))
        _auditoria(c, usuario, "analizar", url, f"{nivel}:{score}")


def historial(usuario: str, limite: int = 50) -> list[dict]:
    with db() as c:
        filas = c.execute(
            "SELECT url_cif,nivel,score,ts FROM historial WHERE usuario=? "
            "ORDER BY ts DESC LIMIT ?", (usuario, limite)).fetchall()
    return [{"url": descifrar(f["url_cif"]), "nivel": f["nivel"],
             "score": f["score"], "ts": f["ts"]} for f in filas]


def auditoria(accion: str | None = None, limite: int = 100) -> list[dict]:
    sql = "SELECT usuario,accion,url,resultado,ts FROM auditoria"
    args: list = []
    if accion:
        sql += " WHERE accion=?"
        args.append(accion)
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(limite)
    with db() as c:
        return [dict(f) for f in c.execute(sql, args).fetchall()]


if __name__ == "__main__":
    # Auto-verificación rápida (no usa usuarios reales)
    u = "demo_" + secrets.token_hex(3)
    crear_usuario(u, "Password1!", "analista")
    sesion = login(u, "Password1!")
    assert sesion and not requiere_rol(sesion, "gestionar_usuarios")
    assert requiere_rol(sesion, "analizar")
    guardar_historial(u, "http://192.168.0.1/login@fake.com/verify", "critica", 70)
    assert historial(u)[0]["url"].startswith("http://192.168")
    print("[E5] OK — auth+RBAC+cifrado+auditoría verificados")
