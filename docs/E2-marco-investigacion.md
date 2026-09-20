# E2 · Marco de Investigación — Phishing Detector (S03)
> Omar & John · S03 (21–25 Sep) · Taller de Inv. I / Admón. de Redes · Estado: completo (20-sep-2026, anticipado)
> Consolida: US01 patrones + US02 APIs + US03 pesos. Detalle en `E2-marco-US01-patrones.md`, `E2-marco-US02-apis.md`, `E2-marco-US03-pesos.md`.

## 1. Patrones técnicos y estructuras sospechosas (US01)
Se validan los 7 indicadores S01 como cláusulas del futuro motor S06, cada uno con ejemplo y regex provisional en `js/app.js`:

| # | Indicador | Patrón | Ejemplo malicioso | Detección |
|---|---|---|---|---|
| 1 | IP explícita | Evade DNS/reputación | `http://192.168.0.1/banco-login` | `/\d{1,3}(\.\d{1,3}){3}/` |
| 2 | Longitud > 75 | Relleno que oculta dominio | ruta larga + `.../1234567890` | `u.length > 75` |
| 3 | +3 subdominios | Jerarquía engañosa | `login-secure-update.ejemplo.largo.sub.dominio.com` | `hostname.split('.').length > 4` |
| 4 | Keywords | Señuelo login/verify/secure/update | `banco-seguro-login@fake.com/verify` | `/(login\|verify\|...)/i` |
| 5 | Sin HTTPS | Sin cifrado ni cert válido | `http://sitio.com/login` | `!/^https:\/\//` |
| 6 | Arroba (@) | `banco.com@evil.com` → va a `evil.com` | userinfo que oculta destino | `includes('@')` |
| 7 | Guion en dominio | Typosquatting `banco-seguro.com` | dominio con `-` | `hostname.includes('-')` |

Técnicas transversales: typosquatting (ind. 7+4), homógrafos IDN `bаnco.com` (límite: requiere normalización punycode en S07), acortadores `bit.ly/xyz` (requieren expansión en S07), userinfo+`@` y relleno combinado. Casos verificados: `https://google.com` 0% segura; `http://192.168.0.1/banco-seguro-login@fake.com/verify` 4/7 57% crítica; URL larga multisubdominio 5/7 71% crítica.

## 2. APIs de reputación y encabezados (US02)
El regex local no cubre homógrafos, acortadores ni edad del dominio; se complementa con: **Safe Browsing v4** (veredicto tiempo real, 10k req/día, key en backend), **VirusTotal/URLScan** (análisis profundo bajo demanda con caché 24h por cuota 4/min), **AbuseIPDB** (solo si ind. 1 dispara) y feeds **PhishTank/OpenPhish**. Encabezados S07: `Location` (acortadores), cert (refuerza ind. 5), WHOIS/`SPF-DKIM-DMARC`. Contrato S07: `POST /api/analyze {url}` → `{score, level, hits[7], reputation, headers}` con fallback local `reputation: unknown`; S10 bloquea con `crítica + SafeBrowsing=malicioso`.

## 3. Fundamentación y ponderación para S06 (US03)
Peso 1–5 = especificidad × severidad. `@`=5, IP=5, sin-HTTPS=3, keywords=3, guion=3, longitud=2, subdominios=2; máximo 23. Fórmula: `score = round(sum/23·100)`; umbrales `0–24 segura · 25–55 sospechosa · 56–100 crítica`. Calibración: 0%, 70% (16/23), 57% (13/23). Reglas: `@`/IP → mínimo sospechosa; SB malicioso → crítica directa. Esqueleto Prolog en `E2-marco-US03-pesos.md`.

## 4. Cierre
E2 valida S01, alimenta S06 (motor) y S07 (parser+API). Siguiente: S04 Dataset (28 Sep–02 Oct).
