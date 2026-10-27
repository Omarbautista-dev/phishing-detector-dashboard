# E4 · Dashboard Web (Maquetado) — S08
> S08 (26–30 Oct) · Front End · John · Completo (27-oct-2026)
> Código: `index.html` + `css/styles.css` + `js/app.js` · Desplegado en GitHub Pages

## 1. Vistas del dashboard (US01)
HTML5 + CSS3 puro según maqueta `sources/Labyrinth UI-FRE-v1.0.penpot`:
- Header con logo + autor.
- Panel izquierdo **URLs Analizadas** (lista + filtros).
- Área principal: barra de búsqueda + grilla de 2 columnas.

## 2. Interfaz de entrada y tarjetas (US02)
- Barra `#url-input` + botón lupa (`#analyze-btn`) en `#analyze-form`.
- Filtros-pastilla: Todos / Seguras / Sospechosas / Críticas (`data-filter`, JS activo).
- Lista `#url-list` con tarjeta por análisis: URL + badge de estado (`segura`/`sospechosa`/`critica` + score %).

## 3. Gráficos de riesgo y razones (US03)
- `#risk-chart`: pie-chart con `conic-gradient` proporcional al score.
- `#risk-score`: nivel + hits (`CRÍTICA — riesgo 70% (4/7)`).
- Leyenda de los **7 indicadores S01** reales (no texto genérico), con `.hit` resaltado según análisis.
- `#measures-list`: medidas 1:1 por indicador activo.

```html
<div class="legend-item" data-ind="ip"><span class="color-box c1"></span> IP explícita</div>
<!-- ... 7 indicadores; base: index.html + css/styles.css (232 líneas) + js/app.js -->
```

## 4. Estado
- Prototipo funcional adelantado el 20-sep-2026 (verificado 0%/57%/71%) y desplegado en Pages.
- Pendiente S09: sustituir detección local por `POST /api/analyze` (backend S07) y métricas en vivo.
