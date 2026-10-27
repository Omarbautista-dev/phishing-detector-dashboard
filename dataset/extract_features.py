#!/usr/bin/env python3
"""E3 · S04 — Emulador de extracción y normalización de atributos de URL.
Lee dataset/dataset.csv y genera dataset/dataset_normalizado.csv con los
7 indicadores S01 en formato uniforme (0/1 + entero), listos para S06.
"""
import csv
import re
from pathlib import Path
from urllib.parse import urlparse

KEYWORDS = ("login", "verify", "secure", "update", "bank", "free", "bonus")


def tiene_ip(host: str) -> bool:
    return re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or "") is not None


def extraer(url: str) -> dict:
    u = url.strip()
    p = urlparse(u if "//" in u else "http://" + u)
    host = p.hostname or ""
    niveles = host.split(".") if host else []
    kw = [k for k in KEYWORDS if re.search(k, u, re.I)]
    return {
        "https": int(p.scheme.lower() == "https"),
        "len": len(u),
        "larga": int(len(u) > 75),
        "ip": int(tiene_ip(host)),
        "subdominios": max(0, len(niveles) - 2),
        "multisub": int(len(niveles) > 4),
        "keywords": int(bool(kw)),
        "kw_lista": "|".join(kw),
        "arroba": int("@" in u),
        "guion": int("-" in host),
        "host": host,
    }


def main() -> None:
    base = Path(__file__).resolve().parent
    entrada = base / "dataset.csv"
    salida = base / "dataset_normalizado.csv"

    with entrada.open(encoding="utf-8") as fi, salida.open("w", newline="", encoding="utf-8") as fo:
        reader = csv.DictReader(fi)
        campos = ["url", "label", "source", "date", "host", "https", "len", "larga",
                  "ip", "subdominios", "multisub", "keywords", "kw_lista", "arroba", "guion"]
        writer = csv.DictWriter(fo, fieldnames=campos)
        writer.writeheader()
        n = 0
        for row in reader:
            writer.writerow({**row, **extraer(row["url"])})
            n += 1
    print(f"[E3] {n} URLs procesadas -> {salida.name}")


if __name__ == "__main__":
    main()
