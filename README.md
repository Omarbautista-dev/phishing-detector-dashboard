# 🎣 Phishing Detector Dashboard

Dashboard web para detectar intentos de phishing con 7 heurísticas en frontend. Analiza una URL, calcula nivel de riesgo y recomienda medidas.

Stack: HTML + CSS + JS vanilla. Sin backend, sin build.

> Autores: Omar & John

---

## ✨ Funciones

- Analizar URL desde barra de búsqueda (`js/app.js:analyze()`)
- 7 indicadores:
  1. IP explícita `http://192.168...`
  2. Longitud > 75
  3. +3 subdominios
  4. Palabras clave: login, verify, secure, update, bank, free, bonus
  5. Sin HTTPS
  6. Arroba `@`
  7. Guion en dominio `banco-seguro.com`
- Score: `hits / 7 * 100`
  - `>=57%` → critica
  - `>=29%` → sospechosa
  - else → segura
- Historial de URLs analizadas con badge y filtro: Todos / Seguras / Sospechosas / Críticas
- Gráfico de riesgo (conic-gradient) + panel de Medidas Recomendadas
- Investigación en `docs/E2-marco-*.md`

## 🛠️ Stack

- `index.html` — layout dashboard
- `css/styles.css` + `css/variables.css` — estilos
- `js/app.js` — detector local provisional
- FontAwesome 6.4 CDN para iconos
- GitHub Pages + Actions para deploy (` .github/workflows/pages.yml`)

> Nota: el detector actual es provisional S08 maquetado. S06/S07 lo reemplaza por motor Prolog + API.

## ✅ Requisitos

- Navegador moderno (Chrome / Edge / Firefox)
- Opcional para servidor local: Python 3 o VS Code + Live Server
- No necesitas Node, npm, ni base de datos

## 🚀 Uso

### Opción 1: Demo online (si tienes Pages activo)

```text
https://omarbautista-dev.github.io/phishing-detector-dashboard/
```

Se despliega solo con push a `master` por `.github/workflows/pages.yml`.

Actívalo en: Repo > Settings > Pages > Deploy from GitHub Actions.

### Opción 2: Abrir local directo

```bash
git clone https://github.com/Omarbautista-dev/phishing-detector-dashboard.git
cd phishing-detector-dashboard
# doble clic en index.html
```

### Opción 3: Con servidor local (recomendado, evita problemas con rutas)

```bash
git clone https://github.com/Omarbautista-dev/phishing-detector-dashboard.git
cd phishing-detector-dashboard
python3 -m http.server 8000
# abre http://localhost:8000
```

O en VS Code: clic derecho en `index.html` > Open with Live Server.

## 🧪 Prueba rápida

1. Ingresa: `http://login-banco-seguro-gratis.com.verify-update.com/login?user=1`
2. Debe marcar `critica` con varios indicadores.
3. Ingresa: `https://www.google.com`
4. Debe marcar `segura`.
5. Usa los filtros `Seguras / Sospechosas / Criticas` a la izquierda.
6. Clic en una URL del historial para ver detalle y medidas.

## 📁 Estructura

```text
phishing-detector-dashboard/
├── index.html                  # Dashboard, search-bar, panels
├── css/styles.css              # Estilos principales
├── css/variables.css           # Variables
├── js/app.js                   # INDICATORS, analyze(), render(), showDetail()
├── docs/                       # Investigación E2-marco-*.md
└── .github/workflows/pages.yml # Deploy a Pages
```

## 🔧 Cómo funciona

`js/app.js`:

```js
const score = Math.round((hits.length / 7) * 100);
```

Cada indicador es un `{id, label, test(url), fix}` con regex / `URL()`. No hay IA, son reglas.

Para agregar un indicador nuevo, agrega un objeto a `INDICATORS` y su `.legend-item` en `index.html`.

## 📚 Docs

- `docs/E2-marco-investigacion.md`
- `docs/E2-marco-US01-patrones.md`
- `docs/E2-marco-US02-apis.md`
- `docs/E2-marco-US03-pesos.md`

## 🗺️ Roadmap

- [ ] Conectar motor Prolog + API real (S06/S07)
- [ ] Guardar historial en localStorage
- [ ] Agregar modo oscuro / exportar reporte
- [ ] Tests de URLs

## 👨‍💻 Autores

Omar Bautista - Instituto Tecnológico de Comitán
