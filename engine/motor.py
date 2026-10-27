#!/usr/bin/env python3
"""E6 · S06 — Espejo en Python del motor en engine/phishing_rules.pl.

Canonical: phishing_rules.pl (Prog. Lógica). Este módulo replica la misma
lógica (pesos /23, umbrales 25/56, alerta ip/arroba) porque el servidor de
despliegue no tiene SWI-Prolog. Si `swipl` está instalado, usar_swipl()()
permite validar contra el .pl real.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

PESOS = {
    "ind_ip": 5,
    "ind_arroba": 5,
    "ind_sin_https": 3,
    "ind_keywords": 3,
    "ind_guion": 3,
    "ind_larga": 2,
    "ind_multisub": 2,
}
MAXIMO = 23
ALERTA = {"ind_ip", "ind_arroba"}
KEYWORDS = ("login", "verify", "secure", "update", "bank", "free", "bonus")

INDICE_NOMBRES = {
    "ip": "ind_ip",
    "arroba": "ind_arroba",
    "sin_https": "ind_sin_https",
    "keywords": "ind_keywords",
    "guion": "ind_guion",
    "larga": "ind_larga",
    "multisub": "ind_multisub",
}


def detectar(url: str) -> list[str]:
    """Parser de los 7 indicadores S01 (contrato de S07)."""
    u = url.strip()
    p = urlparse(u if "//" in u else "http://" + u)
    host = p.hostname or ""
    niveles = host.split(".") if host else []
    hits: list[str] = []
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""):
        hits.append("ip")
    if len(u) > 75:
        hits.append("larga")
    if len(niveles) > 4:
        hits.append("multisub")
    if any(re.search(k, u, re.I) for k in KEYWORDS):
        hits.append("keywords")
    if p.scheme.lower() != "https":
        hits.append("sin_https")
    if "@" in u:
        hits.append("arroba")
    if "-" in host:
        hits.append("guion")
    return hits


def evaluar(url: str) -> dict:
    """Riesgo(URL) de phishing_rules.pl -> dict JSON para la API."""
    hits = detectar(url)
    suma = sum(PESOS[INDICE_NOMBRES[h]] for h in hits)
    score = round(suma * 100 / MAXIMO)
    if score >= 56:
        nivel = "critica"
    elif score >= 25:
        nivel = "sospechosa"
    else:
        nivel = "segura"
    if nivel == "segura" and (ALERTA & {INDICE_NOMBRES[h] for h in hits}):
        nivel = "sospechosa"
    return {"url": url, "hits": hits, "score": score, "nivel": nivel,
            "suma": suma, "maximo": MAXIMO}


if __name__ == "__main__":
    import json
    import sys
    print(json.dumps(evaluar(sys.argv[1] if len(sys.argv) > 1 else "https://google.com"),
                     ensure_ascii=False, indent=2))
