# E2 · S03-US01 — Patrones técnicos de phishing y estructuras URL sospechosas
> Proyecto Phishing Detector · S03 (21–25 Sep) · Responsable: John · Alimenta a S06 (motor) y valida S01 (7 indicadores)

## 1. Objetivo
Documentar los patrones explotados en URLs de phishing para fundamentar las 7 reglas implementadas en `phishingDetector/js/app.js` y los pesos de US03.

## 2. Patrones por indicador S01

| # | Indicador S01 | Patrón de ataque | Ejemplo malicioso | Ejemplo legítimo | Detección (`app.js`) |
|---|---|---|---|---|---|
| 1 | IP explícita | Evade DNS/reputación; host desechable | `http://192.168.0.1/banco-login` | `https://banco.com` | `/https?:\/\/\d{1,3}(\.\d{1,3}){3}/` |
| 2 | Longitud > 75 | Oculta dominio real con padding/ruta larga | `http://.../verify/account/update/.../1234567890` | `https://google.com` | `u.length > 75` |
| 3 | +3 subdominios | Jerarquía engañosa; el dominio base queda a la derecha | `http://login-secure-update.ejemplo.largo.sub.dominio.com/...` | `https://mail.google.com` | `hostname.split('.').length > 4` |
| 4 | Palabras clave | Señuelo `login/verify/secure/update/bank/free/bonus` | `http://banco-seguro-login@fake.com/verify` | `https://banco.com/ayuda` | `/(login\|verify\|secure\|update\|...)/i` |
| 5 | Sin HTTPS | Intercepción/modificación; sin certificado válido | `http://sitio.com/login` | `https://sitio.com/login` | `!/^https:\/\//` |
| 6 | Arroba (@) | Todo antes de `@` se ignora como userinfo; oculta destino | `http://banco.com@evil.com` | `https://banco.com` | `u.includes('@')` |
| 7 | Guion en dominio | Typosquatting `banco-seguro.com` vs `banco.com` | `http://banco-seguro.com` | `https://banco.com` | `hostname.includes('-')` |

## 3. Técnicas transversales
- **Typosquatting:** `g00gle.com`, `banco-seguro.com` → se captura con indicador 7 + 4.
- **Homógrafos (IDN):** `bаnco.com` (a cirílica). Límite actual: regex ASCII no lo detecta → pendiente normalización punycode en S07 parser.
- **Acortadores:** `bit.ly/xyz` ocultan estructura → pendiente expansión de URL en S07 + consulta reputación en US02.
- **Userinfo + `@`:** `https://banco.com@evil.com` → navegador va a `evil.com`. Indicador 6 lo marca crítico.
- **Relleno de longitud:** subdominios + ruta larga combinados (ejemplo 71% en pruebas) → justifica peso alto combinado en US03.

## 4. Casos de prueba usados (verificados en `js/app.js`)
- `https://google.com` → 0/7, 0% segura.
- `http://192.168.0.1/banco-seguro-login@fake.com/verify` → 4/7 (ip, keywords, sin-https, @), 57% crítica.
- URL larga con 5 subdominios → 5/7, 71% crítica.

## 5. Salida hacia US02/US03 y S06
- US02 debe resolver: reputación (Safe Browsing/VirusTotal) para homógrafos y acortadores, que el regex local no cubre.
- US03 debe ponderar: `@` + IP + sin-HTTPS como peso alto; longitud/subdominios como peso medio que escala en combinación.
- S06 motor Prolog: cada fila de la tabla es una cláusula `SI indicador ENTONCES suma-peso`.
