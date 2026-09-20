# E2 · S03-US03 — Fundamentación y ponderación de riesgo
> Proyecto Phishing Detector · S03 · Responsable: John · Consume US01+US02, alimenta S06 (motor Prolog)

## 1. Criterio de ponderación (escala 1-5)
Peso = especificidad (¿cuánto distingue phishing?) × severidad (¿cuánto facilita robo?).

| # | Indicador | Peso | Justificación |
|---|---|---|---|
| 6 | Arroba (@) | 5 | Abuso RFC: `banco.com@evil.com` va a `evil.com`. Casi nunca legítimo en URL pegada. |
| 1 | IP explícita | 5 | Evade DNS/reputación (US02). Host desechable típico. |
| 5 | Sin HTTPS | 3 | Señal media: aún hay HTTP legítimo, pero crítico si pide credenciales. Refuerzo con cert en S07. |
| 4 | Palabras clave | 3 | Señuelo directo (login/verify). Alta frecuencia en feeds PhishTank. |
| 7 | Guion en dominio | 3 | Typosquatting (`banco-seguro.com`). Especificidad alta en dominio. |
| 2 | Longitud > 75 | 2 | Evasión por relleno; débil sola, fuerte combinada. |
| 3 | +3 subdominios | 2 | Jerarquía engañosa; débil sola, fuerte combinada. |
| | **Máximo** | **23** | Suma de pesos. |

## 2. Fórmula S06
`score = round(sum(pesos_hits) / 23 * 100)`
`0–24 segura · 25–55 sospechosa · 56–100 crítica`

Calibración con casos US01:
- `https://google.com` → 0/23 = 0% segura.
- `http://192.168.0.1/banco-seguro-login@fake.com/verify` → 5+3+3+5=16/23 = 70% crítica.
- URL larga 5 subdominios → 2+2+3+3+3=13/23 = 57% crítica (borde, correcto: pide veredicto externo US02).

Regla S06: si `@` o `IP` presentes → mínimo `sospechosa` aunque score bajo; si `Safe Browsing=malicioso` (US02) → `crítica` directa (S10 bloqueo).

## 3. Esqueleto Prolog (S06)
```prolog
peso(ip, 5). peso(at, 5). peso(https, 3). peso(keywords, 3).
peso(dash, 3). peso(length, 2). peso(subdomains, 2).
score(Hits, S) :- sum_pesos(Hits, X), S is round(X/23*100).
nivel(S, critica) :- S >= 56. nivel(S, sospechosa) :- S >= 25, S < 56. nivel(_, segura).
```

## 4. Cierre E2
E2 completo: US01 (patrones) + US02 (APIs) + US03 (pesos). S06 puede codificar motor; S07 parser + `POST /api/analyze`; S01 queda validado.
