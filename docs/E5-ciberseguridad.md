# E5 · Módulo de Ciberseguridad (S05)
> S05 (05–09 Oct) · Ciberseguridad · John · Completo (27-oct-2026, regularización)
> Código: `backend/auth.py` · Pruebas: `python3 backend/auth.py` → `[E5] OK`

## 1. Autenticación con hashing seguro (US01)
- **bcrypt** (cost 12) — nunca texto plano; verificación con `checkpw`.
- Usuario único + `salt` por registro; login registra `ok`/`fallido` en auditoría.
- Sesión con token opaco (`secrets.token_hex`, 32 hex) guardado en servidor; sin secretos hardcodeados.

```python
crear_usuario("omar", "Password1!", "analista")   # INSERT con hash bcrypt
login("omar", "Password1!")                        # -> {usuario, rol, token, permisos}
```

## 2. RBAC y cifrado (US02)
| Rol | Permisos |
|---|---|
| `admin` | analizar, ver_historial, ver_auditoria, gestionar_usuarios |
| `analista` | analizar, ver_historial |

`requiere_rol(sesion, permiso)` valida cada endpoint. Datos sensibles (URLs del historial) cifrados con **AES-256-GCM** (nonce aleatorio, clave en `data/.secret_key` chmod 600, fuera de git).

## 3. Registro de auditoría (US03)
SQLite `data/phishing.db`:
- `auditoria(usuario, accion, url, resultado, ts)` — quién, qué URL, cuándo, resultado.
- `historial(usuario, url_cif, nivel, score, ts)` — historial cifrado de análisis.
- `usuarios(usuario, hash, rol, salt)`.

Eventos registrados: `crear_usuario`, `login` (ok/fallido), `analizar`.

## 4. Verificación
```bash
python3 backend/auth.py   # [E5] OK — auth+RBAC+cifrado+auditoría verificados
```
Cubre: hash bcrypt, rol sin permiso extra (analista≠admin), cifrado/descifrado roundtrip, auditoría insertada.
