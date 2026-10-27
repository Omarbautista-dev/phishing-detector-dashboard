# E3 · Dataset / Stream de Datos (S04)
> S04 (28 Sep–02 Oct) · Sistemas Programables · Omar · Completo (27-oct-2026, regularización)

## 1. Dataset
`dataset/dataset.csv` — 69 URLs etiquetadas: **40 legítimas / 29 phishing**, columnas `url,label,source,date`.

| Clase | Fuentes | Fecha |
|---|---|---|
| Legítimas (40) | Tranco Top1M, sitios bancarios/gubernamentales oficiales | 2026-09-28/30 |
| Phishing (29) | PhishTank, OpenPhish, URLScan.io + muestras locales | 2026-10-01/02 |

Cobertura de los 7 indicadores S01 en la clase phishing: IP explícita (5), arroba (2), HTTPS ausente, keywords, guion, longitud >75 y multisubdominio.

## 2. Emulador de extracción (US02)
`dataset/extract_features.py` — parser stdlib (`urllib.parse`) que extrae y normaliza:

| Atributo | Normalización | Ejemplo |
| :------- | :------------ | :------ |
| HTTPS | 0/1 booleano | `https=1` |
| Longitud | entero + flag >75 | `len=112, larga=1` |
| IP explícita | 0/1 | `ip=0` |
| Subdominios | conteo + flag >3 | `subdominios=5, multisub=1` |
| Keywords | 0/1 + lista | `keywords=1, kw_lista=verify\|secure` |
| Arroba / Guion | 0/1 | `arroba=1, guion=1` |

Salida: `dataset/dataset_normalizado.csv` (69 filas, 15 columnas).

```bash
python3 dataset/extract_features.py   # [E3] 69 URLs procesadas
```

## 3. Verificación
- 40/40 legítimas: `https=1`, 0 keywords, 0 IP, 0 @.
- Phishing con IP: 5 · con @: 2 · sin HTTPS: mayoría.
- Concisión: features S04 ≡ motor S06 (test `test_features_concordan_con_motor`).

Nota: `.pcap` no se commitea (peso) — solo `.csv` con fuente y fecha.
