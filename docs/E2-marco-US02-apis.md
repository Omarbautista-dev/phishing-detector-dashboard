# E2 · S03-US02 — APIs de reputación y análisis de encabezados
> Proyecto Phishing Detector · S03 (21–25 Sep) · Responsable: John · Entrada para S07 (Backend-Prolog)

## 1. Objetivo
Elegir APIs que cubran lo que el regex local (`js/app.js`, US01) no cubre: homógrafos IDN, acortadores, dominios recién creados y reputación histórica.

## 2. Comparativa

| API | Qué aporta | Límite free | Costo/latencia | Límite clave |
|---|---|---|---|---|
| Google Safe Browsing v4 | Lista phishing/malware, ideal para bloqueo S10 | 10k req/día aprox., API key gratis | Baja latencia, cuota generosa | No explica por qué; requiere backend proxy (no exponer key) |
| VirusTotal v3 | 70+ motores + WHOIS + análisis URL/headers | 4 req/min, 500/día free | Alta latencia (análisis asíncrono) | Cuota corta; solo para re-análisis manual, con caché |
| AbuseIPDB | Reputación IP (complementa indicador 1) | 1k req/día free | Rápida | Solo IP, no URL |
| PhishTank / OpenPhish feed | Feed comunitario phishing, sin key | Rate-limit agresivo | Gratis | Cobertura parcial, falsos negativos |
| URLScan.io | Render + DOM + encabezados + certificado | Free limitado | Lenta (segundos) | Solo análisis profundo bajo demanda |

Encabezados a analizar en S07: `Age/Domain age (WHOIS)`, `SPF/DKIM/DMARC` (para `.eml`), `Location` (redirecciones de acortadores), `Cert issuer/validity` (refuerza indicador 5 Sin HTTPS).

## 3. Decisión propuesta
1. **Tiempo real (S07/S09):** Safe Browsing como veredicto externo principal + reglas locales US01.
2. **Profundo (bajo demanda):** VirusTotal/URLScan solo al pulsar "análisis profundo", con caché 24h en backend.
3. **IP:** AbuseIPDB solo si indicador 1 (IP explícita) dispara.
4. **Seguridad:** keys en backend (`ENV`), nunca en `js/app.js`; backend hace proxy y aplica rate-limit propio.

## 4. Integración S07 (contrato)
- `POST /api/analyze {url}` → `{score, level, hits[7], reputation:{safeBrowsing, vt_cached}, headers:{redirects, cert}}`.
- Fallback: si API cae o sin key, responde solo con motor local + `reputation: unknown`.
- Caché: `url_hash → resultado 24h` para no quemar cuotas.
- S10 Bloqueo usará `level=critica + safeBrowsing=malicioso` como condición de bloqueo.

## 5. Riesgos y mitigación
- Cuotas free → caché + análisis profundo manual.
- Privacidad (enviar URLs a terceros) → avisar en UI + no enviar URLs internas.
- Latencia VT/URLScan → async, no bloquea veredicto local.
