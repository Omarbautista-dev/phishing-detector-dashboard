# Integración Backend – Prolog (S07)
> S07 (19–23 Oct) · Prog. Lógica / Ciberseguridad · Omar + John · Completo (27-oct-2026, regularización)
> Código: `backend/api.py` + `engine/motor.py` + `backend/auth.py` · Pruebas: **8/8 OK** (18/18 totales)

## 1. API REST (US01)
Servidor stdlib (`ThreadingHTTPServer`, sin dependencias externas), CORS habilitado para el dashboard de GitHub Pages (S09).

| Método | Ruta | Auth | Respuesta |
|---|---|---|---|
| GET | `/api/health` | — | `{status, motor, reglas}` |
| POST | `/api/analyze` | — | `{nivel, score, hits, razones[], reputation}` |
| POST | `/api/login` | — | `{token, rol, permisos}` |
| GET | `/api/historial` | Bearer | historial descifrado (rol analista+) |
| GET | `/api/auditoria` | Bearer | bitácora completa (solo admin) |

Contrato E2-US02 cumplido: `POST /api/analyze {url}` → `{score, level, hits[7], reputation}` con `reputation: "unknown"` hasta integrar Safe Browsing (S09). Fallback: sin motor externo, responde con motor local.

## 2. Parser de los 7 indicadores (US02)
`engine/motor.py::detectar(url)` — extrae IP, longitud>75, multisubdominio, keywords, sin HTTPS, @ y guion; normaliza URL sin esquema (`banco-seguro.com` → `http://banco-seguro.com`). El mismo parser alimenta al motor E6 (una sola fuente de verdad).

## 3. Pruebas de integración (US03)
`tests/test_api.py` — servidor real en puerto 8765 + peticiones HTTP:
1. health → 200
2. analyze crítico → `critica 70`, razones pobladas
3. analyze legítimo → `segura 0`, razones `[]`
4. URL sin esquema → normalizada, `sospechosa`
5. sin `url` → 400
6. login + RBAC: analista ve su historial cifrado; auditoría → 403
7. login inválido → 401
8. historial sin token → 401

```bash
python3 backend/api.py --port 8000
python3 -m unittest discover -s tests        # Ran 18 tests ... OK
```
