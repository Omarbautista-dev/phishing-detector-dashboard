#!/usr/bin/env python3
"""E7 · S07 — Integración Backend (parser + motor + API REST).

POST /api/analyze  {url}        -> {nivel, score, hits, razones}
POST /api/login    {usuario,password} -> {token, rol, permisos}
GET  /api/historial             -> historial cifrado del usuario (auth)
GET  /api/health                -> estado del motor

Uso: python3 backend/api.py [--port 8000]
"""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import backend.auth as auth  # noqa: E402
from engine.motor import evaluar  # noqa: E402

SESIONES: dict[str, dict] = {}

RAZONES = {
    "ip": "Dirección IP explícita en lugar de dominio",
    "larga": "Longitud excesiva (>75 caracteres)",
    "multisub": "Más de 3 niveles de subdominio",
    "keywords": "Palabras clave sospechosas (login/verify/secure/update)",
    "sin_https": "Sin HTTPS",
    "arroba": "Arroba (@): destino real oculto",
    "guion": "Guion en dominio (typosquatting)",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "PhishingAPI/1.0"

    # ---------- helpers ----------
    def _json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # CORS (S09: dashboard en GitHub Pages)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return {}

    def _sesion(self):
        auth_h = self.headers.get("Authorization", "")
        return SESIONES.get(auth_h.replace("Bearer ", "").strip())

    def log_message(self, fmt, *args):  # log limpio
        sys.stdout.write("[S07] " + (fmt % args) + "\n")

    # ---------- rutas ----------
    def do_OPTIONS(self):
        self._json({})

    def do_GET(self):
        if self.path == "/api/health":
            return self._json({"status": "ok", "motor": "engine/motor.py",
                               "reglas": "engine/phishing_rules.pl"})
        if self.path == "/api/historial":
            s = self._sesion()
            if not auth.requiere_rol(s, "ver_historial"):
                return self._json({"error": "no autorizado"}, 401)
            return self._json({"historial": auth.historial(s["usuario"])})
        if self.path == "/api/auditoria":
            s = self._sesion()
            if not auth.requiere_rol(s, "ver_auditoria"):
                return self._json({"error": "no autorizado (requiere admin)"}, 403)
            return self._json({"auditoria": auth.auditoria()})
        self._json({"error": "no encontrado"}, 404)

    def do_POST(self):
        if self.path == "/api/analyze":
            data = self._body()
            url = (data.get("url") or "").strip()
            if not url:
                return self._json({"error": "campo 'url' requerido"}, 400)
            r = evaluar(url)
            s = self._sesion()
            usuario = s["usuario"] if s else "anon"
            if not url.startswith("http"):
                url = "http://" + url
            auth.guardar_historial(usuario, url, r["nivel"], r["score"])
            return self._json({
                "url": r["url"], "nivel": r["nivel"], "score": r["score"],
                "hits": r["hits"],
                "razones": [RAZONES[h] for h in r["hits"]],
                "reputation": "unknown",  # S03-US02: Safe Browsing en S09
            })
        if self.path == "/api/login":
            data = self._body()
            sesion = auth.login(data.get("usuario", ""), data.get("password", ""))
            if not sesion:
                return self._json({"error": "credenciales inválidas"}, 401)
            SESIONES[sesion["token"]] = sesion
            return self._json(sesion)
        self._json({"error": "no encontrado"}, 404)


def main(port: int = 8000) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 8000
    print(f"[S07] API en http://localhost:{port}  (Ctrl+C para salir)")
    try:
        main(port).serve_forever()
    except KeyboardInterrupt:
        print("\n[S07] detenido")
