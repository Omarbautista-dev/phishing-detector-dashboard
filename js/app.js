// Detector local provisional (S08 maquetado). S06/S07 lo reemplaza por motor Prolog + API.
const INDICATORS = [
  { id: "ip", label: "IP explícita", test: (u) => /https?:\/\/\d{1,3}(\.\d{1,3}){3}/i.test(u),
    fix: "No ingreses credenciales: navega al dominio oficial escribiéndolo a mano." },
  { id: "length", label: "Longitud > 75", test: (u) => u.length > 75,
    fix: "URL anormalmente larga: verifica el destino real antes de abrirla." },
  { id: "subdomains", label: "+3 subdominios", test: (u) => { try { return new URL(u).hostname.split(".").length > 4; } catch { return (u.match(/\./g) || []).length > 4; } },
    fix: "Subdominios excesivos (típico engaño): revisa el dominio base." },
  { id: "keywords", label: "Palabras clave", test: (u) => /(login|verify|secure|update|bank|free|bonus)/i.test(u),
    fix: "Palabra señuelo (login/verify): confirma por canal oficial." },
  { id: "https", label: "Sin HTTPS", test: (u) => !/^https:\/\//i.test(u),
    fix: "Sin HTTPS: no envíes datos sensibles en esta conexión." },
  { id: "at", label: "Arroba (@)", test: (u) => u.includes("@"),
    fix: "Contiene @ (destino oculto): copia la URL y analiza el dominio real." },
  { id: "dash", label: "Guion en dominio", test: (u) => { try { return new URL(u).hostname.includes("-"); } catch { return false; } },
    fix: "Guion tipo banco-seguro.com (typosquatting): valida el dominio." },
];

const state = { items: [], filter: "todos" };
const $ = (s) => document.querySelector(s);

function analyze(url) {
  const hits = INDICATORS.filter((i) => { try { return i.test(url); } catch { return false; } });
  const score = Math.round((hits.length / INDICATORS.length) * 100);
  const level = score >= 57 ? "critica" : score >= 29 ? "sospechosa" : "segura";
  return { url, hits: hits.map((h) => h.id), score, level };
}

function render() {
  const list = $("#url-list");
  list.innerHTML = "";
  state.items
    .filter((it) => state.filter === "todos" || it.level === state.filter)
    .forEach((it, idx) => {
      const li = document.createElement("li");
      li.innerHTML = `<span class="url">${it.url}</span><span class="badge ${it.level}">${it.level} ${it.score}%</span>`;
      li.title = it.hits.join(", ") || "sin indicadores";
      li.onclick = () => showDetail(it);
      list.appendChild(li);
    });
}

function showDetail(it) {
  const chart = $("#risk-chart");
  chart.style.background = `conic-gradient(#9d1b4c 0 ${it.score}%, #e3e6be ${it.score}% 100%)`;
  $("#risk-score").textContent = `${it.level.toUpperCase()} — riesgo ${it.score}% (${it.hits.length}/7)`;
  document.querySelectorAll(".legend-item").forEach((el) =>
    el.classList.toggle("hit", it.hits.includes(el.dataset.ind)));
  const box = $("#measures-list");
  box.innerHTML = "";
  if (!it.hits.length) {
    box.innerHTML = `<div class="measure-row">Sin indicadores: URL aparentemente segura. Mantén verificación habitual.</div>`;
    return;
  }
  INDICATORS.filter((i) => it.hits.includes(i.id)).forEach((i) => {
    const d = document.createElement("div");
    d.className = "measure-row";
    d.textContent = `${i.label}: ${i.fix}`;
    box.appendChild(d);
  });
}

$("#analyze-form").addEventListener("submit", (e) => {
  e.preventDefault();
  let url = $("#url-input").value.trim();
  if (!url) return;
  if (!/^https?:\/\//i.test(url)) url = "http://" + url;
  const it = analyze(url);
  state.items.unshift(it);
  $("#url-input").value = "";
  render();
  showDetail(it);
});

document.querySelectorAll(".pill").forEach((p) =>
  p.addEventListener("click", () => {
    document.querySelectorAll(".pill").forEach((x) => x.classList.remove("active"));
    p.classList.add("active");
    state.filter = p.dataset.filter;
    render();
  }));

render();
