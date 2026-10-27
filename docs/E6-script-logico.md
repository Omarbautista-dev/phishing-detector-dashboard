# E6 · Script Lógico (S06)
> S06 (12–16 Oct) · Prog. Lógica y Funcional · Omar · Completo (27-oct-2026, regularización)
> Código: `engine/phishing_rules.pl` (canónico) + `engine/motor.py` (espejo ejecutable)
> Pruebas: `python3 -m unittest discover -s tests` → **18/18 OK**

## 1. Motor de reglas (US01) — cláusulas SI...ENTONCES
```prolog
peso(ind_ip, 5).        peso(ind_arroba, 5).
peso(ind_sin_https, 3). peso(ind_keywords, 3). peso(ind_guion, 3).
peso(ind_larga, 2).     peso(ind_multisub, 2).
maximo(23).

nivel(S, critica)    :- S >= 56.
nivel(S, sospechosa) :- S >= 25, S < 56.
nivel(S, segura)     :- S < 25.

% SI ind_ip O ind_arroba ENTONCES minimo sospechosa
siempre_alerta(ind_ip).
siempre_alerta(ind_arroba).
alerta(URL) :- ind(URL, I), siempre_alerta(I).
```
Consulta: `riesgo(URL, Nivel, Score)` → `sumar_pesos/2` con `findall`, `score/2 = round(Suma*100/23)`.

Nota: el entorno de despliegue no tiene SWI-Prolog; `engine/motor.py` replica exactamente la misma lógica (pesos, umbrales, regla de alerta) para que la API y las pruebas corran sin dependencias. El `.pl` es la evidencia de la materia y su calibración está documentada en sus comentarios.

## 2. Ponderación de riesgo (US02) — pesos E2/S03
Máximo 23 = `@`(5) + IP(5) + sin-HTTPS/keywords/guion(3) + longitud/multisub(2).
`score = round(sum*100/23)` · umbrales 0–24 / 25–55 / 56–100.

## 3. Pruebas unitarias y calibración (US03)
| Caso | Esperado | Resultado |
|---|---|---|
| `https://google.com` | segura, 0% | ✅ 0% |
| `http://192.168.0.1/banco-seguro-login@fake.com/verify` | crítica, 70% | ✅ 70% |
| URL larga multisubdominio | crítica, 57% | ✅ 57% |
| `http://8.8.8.8/x` (IP sola) | mín. sospechosa (regla alerta) | ✅ sospechosa |
| Dataset S04: 40 legítimas | 0 falsos positivos | ✅ 40/40 |
| Dataset S04: 29 phishing | recall ≥ 90% | ✅ 93% (2 FN documentados) |

Los 2 falsos negativos (`bit.ly/3xK9fQm` acortador, `g00gle.com.mx` typosquatting) son límites documentados en E2-US01: requieren reputación externa (Safe Browsing, US02/S07).

```bash
python3 -m unittest discover -s tests -v   # Ran 18 tests ... OK
```
