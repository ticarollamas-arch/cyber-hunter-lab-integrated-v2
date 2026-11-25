"use strict";
// Painel do CyberHuntLab. Dados vindos dos alvos são tratados como não confiáveis:
// tudo é inserido com textContent (nunca innerHTML).

const state = { token: sessionStorage.getItem("chl_token") || "", me: null, programs: [], program: null, job: null, tab: "findings", poll: null, findingFilter: "hypothesis" };
const $ = (sel) => document.querySelector(sel);
const SEV_PT = { critical: "crítica", high: "alta", medium: "média", low: "baixa", info: "info" };
const STATE_PT = { observation: "observação", hypothesis: "hipótese", validated: "validado", false_positive: "falso positivo" };
const STATUS_PT = { queued: "na fila", running: "em execução", awaiting_approval: "aguardando aprovação", completed: "concluída", failed: "falhou",
  cancelled: "interrompida", pending: "pendente", done: "concluída", skipped: "não aplicada", unavailable: "indisponível", approved: "aprovada", rejected: "recusada", expired: "expirada" };

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function toast(msg, err = false) {
  const t = $("#toast"); t.textContent = msg; t.className = "toast" + (err ? " err" : "");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add("hidden"), 5000);
}
async function api(path, opts = {}) {
  const headers = { Authorization: `Bearer ${state.token}`, ...(opts.headers || {}) };
  if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) { logout(); throw new Error("sessão expirada"); }
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("json") ? await res.json() : await res.blob();
  if (!res.ok) { const e = new Error((data && data.error) || `HTTP ${res.status}`); e.data = data; throw e; }
  return data;
}
const sev = (s) => h("span", { class: `badge sev-${s}` }, SEV_PT[s] || s);
const st = (s) => h("span", { class: `st-${s}` }, STATUS_PT[s] || s);

// --- sessão ---------------------------------------------------------------------------------
function logout() { sessionStorage.removeItem("chl_token"); state.token = ""; clearInterval(state.poll); boot(); }
async function boot() {
  if (!state.token) { $("#login").classList.remove("hidden"); $("#app").classList.add("hidden"); $("#who").textContent = ""; return; }
  try { state.me = await api("/api/me"); } catch { $("#login").classList.remove("hidden"); return; }
  $("#login").classList.add("hidden"); $("#app").classList.remove("hidden");
  $("#who").replaceChildren(h("span", {}, `${state.me.name} · ${state.me.role}`), h("button", { class: "ghost small", onclick: logout }, "sair"));
  await Promise.all([loadPrograms(), loadJobs(), loadTools()]);
}
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault(); state.token = $("#token").value.trim(); sessionStorage.setItem("chl_token", state.token);
  $("#login-error").textContent = ""; await boot(); if (!state.me) $("#login-error").textContent = "Token inválido.";
});

// --- barra lateral ------------------------------------------------------------------------------
async function loadPrograms() {
  state.programs = await api("/api/programs");
  $("#programs").replaceChildren(...state.programs.map((p) => h("li", { class: state.program && state.program.id === p.id ? "active" : "", onclick: () => openProgram(p.id) },
    p.name, h("small", {}, p.scope ? `escopo v${p.scope.version} · ${p.scope.allowed.length} ativo(s)` : "sem escopo"))));
}
async function loadJobs() {
  const jobs = await api("/api/jobs");
  $("#jobs").replaceChildren(...jobs.slice(0, 15).map((j) => h("li", { class: state.job && state.job.id === j.id ? "active" : "", onclick: () => openJob(j.id) },
    `#${j.id} ${j.target}`, h("small", {}, st(j.status), ` · ${j.progress}%`))));
}
async function loadTools() {
  const tools = await api("/api/tools");
  $("#tools").replaceChildren(...tools.map((t) => h("li", { title: `${t.purpose} · rede: ${t.network}` },
    h("span", { class: t.available ? "ok" : "muted" }, t.available ? "● " : "○ "), t.name, h("small", {}, t.available ? `${t.kind} · ${t.purpose}` : "indisponível (não instalada)"))));
}
$("#new-program").addEventListener("click", () => renderProgramForm());

// --- programa e escopo ---------------------------------------------------------------------------
function lines(text) { return text.split("\n").map((s) => s.trim()).filter(Boolean); }
function renderProgramForm() {
  state.program = null; state.job = null; clearInterval(state.poll);
  const f = h("form", { class: "card", onsubmit: async (e) => {
    e.preventDefault();
    const body = { name: f.querySelector("[name=name]").value, platform: f.querySelector("[name=platform]").value, policy_url: f.querySelector("[name=policy]").value };
    try { const r = await api("/api/programs", { method: "POST", json: body }); toast("Programa criado. Agora cadastre o escopo."); await loadPrograms(); openProgram(r.id); }
    catch (err) { toast(err.message, true); }
  } },
  h("h2", {}, "Novo programa"),
  h("label", {}, "Nome", h("input", { name: "name", required: true, placeholder: "Programa X (HackerOne)" })),
  h("div", { class: "grid2" }, h("label", {}, "Plataforma", h("input", { name: "platform", placeholder: "HackerOne, Bugcrowd, Intigriti…" })),
    h("label", {}, "URL da política do programa", h("input", { name: "policy", placeholder: "https://hackerone.com/…/policy" }))),
  h("p", {}, h("button", { type: "submit" }, "Criar programa")));
  $("#content").replaceChildren(f);
}

async function openProgram(pid) {
  clearInterval(state.poll); state.job = null;
  state.program = state.programs.find((p) => p.id === pid) || (await loadPrograms(), state.programs.find((p) => p.id === pid));
  await loadPrograms();
  const p = state.program; const s = p.scope || { allowed: [], excluded: [], repositories: [], rules: {} };
  const r = s.rules || {};
  const scopeForm = h("form", { class: "card", onsubmit: async (e) => {
    e.preventDefault();
    const q = (n) => scopeForm.querySelector(`[name=${n}]`);
    let headers = {};
    try { headers = q("headers").value.trim() ? JSON.parse(q("headers").value) : {}; } catch { return toast("Cabeçalhos obrigatórios: JSON inválido", true); }
    const body = { allowed: lines(q("allowed").value), excluded: lines(q("excluded").value), repositories: lines(q("repos").value),
      rules: { rate_limit_rps: Number(q("rps").value), max_requests_per_job: Number(q("maxreq").value), max_crawl_pages: Number(q("pages").value),
        max_crawl_depth: Number(q("depth").value), active_testing_allowed: q("active").checked, allow_private_network: q("private").checked,
        required_headers: headers, notes: q("notes").value } };
    try { const res = await api(`/api/programs/${p.id}/scope`, { method: "PUT", json: body }); toast(`Escopo salvo (versão ${res.version}).`); await loadPrograms(); openProgram(p.id); }
    catch (err) { toast(err.message, true); }
  } },
  h("div", { class: "row" }, h("h2", {}, `Escopo — ${p.name}`), h("span", { class: "spacer" }), p.scope ? h("span", { class: "badge" }, `v${s.version} · ${String(s.sha256).slice(0, 12)}…`) : h("span", { class: "badge sev-high" }, "sem escopo")),
  h("p", { class: "muted" }, "Um padrão por linha: app.exemplo.com, *.exemplo.com, host:porta ou URL com caminho (https://api.exemplo.com/v1/). Exclusões vencem inclusões. Cada alteração gera nova versão registrada."),
  h("div", { class: "grid2" },
    h("label", {}, "Ativos permitidos", h("textarea", { name: "allowed", value: (s.allowed || []).join("\n") })),
    h("label", {}, "Ativos excluídos", h("textarea", { name: "excluded", value: (s.excluded || []).join("\n") }))),
  h("label", {}, "Repositórios autorizados (para envio de código-fonte)", h("textarea", { name: "repos", value: (s.repositories || []).join("\n"), style: "min-height:50px" })),
  h("div", { class: "grid4" },
    h("label", {}, "Requisições/s", h("input", { name: "rps", type: "number", step: "0.1", min: "0.1", max: "50", value: r.rate_limit_rps ?? 1 })),
    h("label", {}, "Máx. requisições/pesquisa", h("input", { name: "maxreq", type: "number", min: "1", value: r.max_requests_per_job ?? 500 })),
    h("label", {}, "Máx. páginas", h("input", { name: "pages", type: "number", min: "1", value: r.max_crawl_pages ?? 50 })),
    h("label", {}, "Profundidade", h("input", { name: "depth", type: "number", min: "0", value: r.max_crawl_depth ?? 2 }))),
  h("label", {}, "Cabeçalhos exigidos pelo programa (JSON)", h("input", { name: "headers", value: JSON.stringify(r.required_headers || {}), placeholder: '{"X-Bug-Bounty": "seu-usuario"}' })),
  h("label", {}, "Regras do programa (notas)", h("input", { name: "notes", value: r.notes || "" })),
  h("div", { class: "row", style: "margin:10px 0" },
    h("label", { class: "inline" }, h("input", { type: "checkbox", name: "active", checked: r.active_testing_allowed }), "O programa permite testes ativos (DAST com payloads)"),
    h("label", { class: "inline" }, h("input", { type: "checkbox", name: "private", checked: r.allow_private_network }), "Permitir rede privada/localhost (só laboratório)")),
  h("button", { type: "submit" }, "Salvar nova versão do escopo"));

  const checkOut = h("span", { class: "muted" });
  const checkIn = h("input", { placeholder: "https://alvo/caminho" });
  const checker = h("div", { class: "card" }, h("h2", {}, "Testar uma URL contra o escopo"),
    h("div", { class: "row" }, checkIn, h("button", { class: "ghost", onclick: async () => {
      const d = await api(`/api/programs/${p.id}/scope/check`, { method: "POST", json: { url: checkIn.value } });
      checkOut.textContent = `${d.allowed ? "PERMITIDO" : "BLOQUEADO"} — ${d.reason}`; checkOut.className = d.allowed ? "ok" : "error";
    } }, "Verificar")), h("p", {}, checkOut), h("p", { class: "muted" }, "Esta verificação não envia nenhuma requisição ao alvo."));

  const jobForm = h("form", { class: "card", onsubmit: async (e) => {
    e.preventDefault();
    const fd = new FormData(jobForm);
    fd.set("program_id", p.id); fd.set("active", jobForm.querySelector("[name=active]").checked ? "1" : "0"); fd.set("ai", jobForm.querySelector("[name=ai]").checked ? "1" : "0");
    if (!jobForm.querySelector("[name=source]").files.length) fd.delete("source");
    try { const res = await api("/api/jobs", { method: "POST", body: fd }); toast(`Pesquisa #${res.id} iniciada.`); await loadJobs(); openJob(res.id); }
    catch (err) { toast(err.message, true); }
  } },
  h("h2", {}, "Nova pesquisa"),
  h("label", {}, "URL do alvo", h("input", { name: "target", required: true, placeholder: "https://app.exemplo.com/" })),
  h("div", { class: "grid2" },
    h("label", {}, "Código-fonte (ZIP, opcional)", h("input", { name: "source", type: "file", accept: ".zip" })),
    h("label", {}, "Repositório do código (precisa estar no escopo)", h("input", { name: "repository", placeholder: "github.com/org/projeto" }))),
  h("div", { class: "row", style: "margin:10px 0" },
    h("label", { class: "inline" }, h("input", { type: "checkbox", name: "active", disabled: !r.active_testing_allowed }), "Propor testes ativos (pedem sua aprovação antes de rodar)"),
    h("label", { class: "inline" }, h("input", { type: "checkbox", name: "ai", checked: true }), "Triagem por IA")),
  h("button", { type: "submit", disabled: !p.scope }, p.scope ? "Iniciar pesquisa" : "Cadastre o escopo antes"));
  $("#content").replaceChildren(scopeForm, checker, jobForm);
}

// --- tarefa --------------------------------------------------------------------------------------
async function openJob(jid) {
  clearInterval(state.poll);
  state.job = { id: jid };
  await renderJob();
  state.poll = setInterval(async () => {
    if (!state.job || state.job.id !== jid) return clearInterval(state.poll);
    const prev = state.job.status;
    await renderJob(true);
    if (prev !== state.job.status) loadJobs();
    if (["completed", "failed", "cancelled"].includes(state.job.status) && prev === state.job.status) clearInterval(state.poll);
  }, 2000);
  loadJobs();
}

async function renderJob(isPoll = false) {
  const job = await api(`/api/jobs/${state.job.id}`);
  state.job = job;
  const live = !["completed", "failed", "cancelled"].includes(job.status);
  const head = h("div", { class: "card" },
    h("div", { class: "row" }, h("h2", {}, `Pesquisa #${job.id}`), st(job.status), h("span", { class: "spacer" }),
      live ? h("button", { class: "danger", onclick: async () => { if (confirm("Interromper esta pesquisa agora?")) { await api(`/api/jobs/${job.id}/cancel`, { method: "POST" }); toast("Interrupção solicitada."); renderJob(); } } }, "Interromper") : null),
    h("p", { class: "mono" }, job.target),
    h("div", { class: "progress" }, h("div", { style: `width:${job.progress}%` })),
    h("p", { class: "muted" }, job.current_step ? `Etapa: ${job.current_step}` : "", job.error ? h("span", { class: "error" }, ` · ${job.error}`) : null),
    h("div", { class: "grid4" },
      h("div", { class: "stat" }, h("b", {}, job.requests_sent), h("span", {}, "requisições enviadas")),
      h("div", { class: "stat" }, h("b", {}, job.requests_blocked), h("span", {}, "bloqueadas pelo escopo")),
      h("div", { class: "stat" }, h("b", {}, job.counts.hypothesis || 0), h("span", {}, "hipóteses")),
      h("div", { class: "stat" }, h("b", {}, job.counts.validated || 0), h("span", {}, "achados validados"))));

  const steps = h("div", { class: "card" }, h("h2", {}, "Etapas e ferramentas"),
    h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Etapa"), h("th", {}, "Ferramenta"), h("th", {}, "Status"), h("th", {}, "Resultado"))),
      h("tbody", {}, job.steps.map((s) => h("tr", {}, h("td", {}, s.name), h("td", { class: "mono" }, s.tool), h("td", {}, st(s.status)), h("td", {}, s.summary || ""))))));

  const blocks = [head];
  for (const ap of job.approvals.filter((a) => a.status === "pending")) blocks.push(approvalCard(ap));
  blocks.push(steps);
  const tabs = [["findings", "Achados"], ["assets", "Ativos e superfície"], ["evidence", "Evidências HTTP"], ["audit", "Auditoria"], ["report", "Relatório"]];
  const tabBar = h("div", { class: "tabs" }, tabs.map(([k, label]) => h("button", { class: state.tab === k ? "active" : "", onclick: () => { state.tab = k; renderJob(); } }, label)));
  const body = h("div", { class: "card" }, tabBar, await renderTab(job));
  blocks.push(body);
  if (isPoll && document.activeElement && document.activeElement.closest(".finding form")) return; // não apaga um formulário em edição
  $("#content").replaceChildren(...blocks);
}

function approvalCard(ap) {
  const reason = h("input", { placeholder: "Justificativa (ex.: política permite testes de baixo impacto)" });
  const confirmBox = h("input", { type: "checkbox" });
  const byTest = {};
  ap.plan.forEach((t) => { byTest[t.test] = (byTest[t.test] || 0) + 1; });
  return h("div", { class: "card approval" },
    h("h2", {}, "Aprovação necessária: testes ativos"),
    h("p", {}, `${ap.plan.length} testes planejados: `, Object.entries(byTest).map(([k, v]) => `${k} (${v})`).join(", "),
      ". Os payloads são marcadores inofensivos, enviados com o limite de taxa do programa, só para URLs no escopo."),
    h("details", {}, h("summary", {}, "ver plano completo"), h("pre", {}, ap.plan.map((t) => `${t.test.padEnd(15)} ${t.method} ${t.url}  parâmetro=${t.param}`).join("\n"))),
    reason, h("label", { class: "inline", style: "margin:10px 0" }, confirmBox, "Confirmo que o programa autoriza estes testes e assumo a responsabilidade pela execução."),
    h("div", { class: "row" },
      h("button", { class: "warn", onclick: async () => {
        if (!confirmBox.checked) return toast("Marque a confirmação para aprovar.", true);
        try { await api(`/api/approvals/${ap.id}`, { method: "POST", json: { approve: true, confirm: true, reason: reason.value } }); toast("Testes aprovados."); renderJob(); } catch (e) { toast(e.message, true); }
      } }, "Aprovar e executar"),
      h("button", { class: "ghost", onclick: async () => { await api(`/api/approvals/${ap.id}`, { method: "POST", json: { approve: false, reason: reason.value } }); toast("Testes recusados."); renderJob(); } }, "Recusar")));
}

async function renderTab(job) {
  if (state.tab === "findings") return renderFindings(job);
  if (state.tab === "assets") {
    const assets = await api(`/api/jobs/${job.id}/assets`);
    const groups = {};
    assets.forEach((a) => (groups[a.kind] = groups[a.kind] || []).push(a));
    return h("div", {}, Object.entries(groups).map(([k, list]) => h("div", {}, h("h3", {}, `${k} (${list.length})`),
      h("table", {}, h("tbody", {}, list.map((a) => h("tr", {}, h("td", { class: "mono" }, a.value), h("td", { class: "muted mono" }, JSON.stringify(a.meta).slice(0, 220)))))))));
  }
  if (state.tab === "evidence") {
    const ev = await api(`/api/jobs/${job.id}/evidence`);
    const detail = h("pre", { class: "hidden" });
    return h("div", {}, h("p", { class: "muted" }, "Cada requisição (enviada ou bloqueada) fica registrada com a regra de escopo aplicada. Cabeçalhos sensíveis e segredos são mascarados."),
      h("table", {}, h("thead", {}, h("tr", {}, ["#", "etapa", "decisão", "método", "URL", "status", "regra", "ms"].map((c) => h("th", {}, c)))),
        h("tbody", {}, ev.map((e) => h("tr", { onclick: async () => { const d = await api(`/api/evidence/${e.id}`); detail.classList.remove("hidden");
          detail.textContent = `${d.method} ${d.url}\n${d.request_headers || ""}\n${d.request_body || ""}\n\n→ HTTP ${d.status ?? "-"}\n${d.response_headers || ""}\n\n${d.body_excerpt || ""}`; detail.scrollIntoView({ behavior: "smooth" }); }, style: "cursor:pointer" },
          h("td", {}, e.id), h("td", {}, e.step || ""), h("td", { class: e.decision === "blocked" ? "error" : "" }, e.decision), h("td", {}, e.method),
          h("td", { class: "mono" }, e.url), h("td", {}, e.status ?? "-"), h("td", { class: "mono muted" }, e.scope_rule || ""), h("td", {}, e.duration_ms ?? "-"))))), detail);
  }
  if (state.tab === "audit") {
    const rows = await api(`/api/jobs/${job.id}/audit`);
    return h("table", {}, h("thead", {}, h("tr", {}, ["quando", "quem", "ação", "alvo", "regra de escopo", "resultado"].map((c) => h("th", {}, c)))),
      h("tbody", {}, rows.map((a) => h("tr", {}, h("td", { class: "mono" }, a.ts.replace("T", " ").slice(0, 19)), h("td", {}, a.actor), h("td", {}, a.action),
        h("td", { class: "mono" }, a.target || ""), h("td", { class: "mono muted" }, a.scope_rule || ""), h("td", {}, a.result)))));
  }
  if (state.tab === "report") {
    const out = h("div", {});
    const dl = (fmt) => h("button", { class: "ghost", onclick: async () => {
      try { const blob = await api(`/api/jobs/${job.id}/report?format=${fmt}`); const a = h("a", { href: URL.createObjectURL(blob), download: `relatorio-job${job.id}.${fmt}` }); a.click(); }
      catch (e) { out.replaceChildren(h("p", { class: "error" }, e.message), h("ul", {}, (e.data && e.data.problems || []).map((p) => h("li", {}, p)))); }
    } }, fmt.toUpperCase());
    return h("div", {}, h("p", {}, "O relatório inclui somente achados validados por você, com descrição, passos de reprodução, impacto, evidências, CWE, CVSS e recomendação."),
      h("div", { class: "row" }, dl("md"), dl("pdf"), dl("json"), dl("sarif")), out);
  }
  return h("div");
}

async function renderFindings(job) {
  const all = await api(`/api/jobs/${job.id}/findings`);
  const filters = [["hypothesis", "Hipóteses"], ["validated", "Validados"], ["observation", "Observações"], ["false_positive", "Falsos positivos"], ["all", "Todos"]];
  const list = state.findingFilter === "all" ? all : all.filter((f) => f.state === state.findingFilter);
  const bar = h("div", { class: "row", style: "margin-bottom:10px" }, filters.map(([k, label]) =>
    h("button", { class: state.findingFilter === k ? "small" : "ghost small", onclick: () => { state.findingFilter = k; renderJob(); } },
      `${label} (${k === "all" ? all.length : all.filter((f) => f.state === k).length})`)));
  if (!list.length) return h("div", {}, bar, h("p", { class: "muted" }, "Nada nesta categoria."));
  return h("div", {}, bar, list.map(findingCard));
}

function findingCard(f) {
  const box = h("div", { class: "finding" });
  const actions = h("div", { class: "row" });
  const transition = async (to, extra = {}) => {
    const note = prompt(to === "validated" ? "Justificativa da validação (como você reproduziu):" : to === "false_positive" ? "Por que é falso positivo?" : "Observação (opcional):") ?? null;
    if (note === null) return;
    try {
      if (Object.keys(extra).length) await api(`/api/findings/${f.id}`, { method: "PATCH", json: extra });
      await api(`/api/findings/${f.id}/transition`, { method: "POST", json: { to, note } }); toast(`Achado #${f.id}: ${STATE_PT[to]}.`); renderJob();
    } catch (e) { toast(e.message, true); }
  };
  if (f.state === "observation") actions.append(h("button", { class: "ghost small", onclick: () => transition("hypothesis") }, "Promover a hipótese"));
  if (f.state === "observation" || f.state === "hypothesis") actions.append(h("button", { class: "ghost small", onclick: () => transition("false_positive") }, "Falso positivo"));
  if (f.state === "validated" || f.state === "false_positive") actions.append(h("button", { class: "ghost small", onclick: () => transition("hypothesis") }, "Reabrir"));
  let form = null;
  if (f.state === "hypothesis") {
    form = h("form", { onsubmit: (e) => { e.preventDefault(); const q = (n) => form.querySelector(`[name=${n}]`).value;
      transition("validated", { cvss_vector: q("vector") || null, impact: q("impact"), repro_steps: q("repro"), description: q("desc") }); } },
      h("details", {}, h("summary", {}, "Validar este achado"),
        h("label", {}, "Vetor CVSS 3.1 (revise o sugerido)", h("input", { name: "vector", value: f.cvss_vector || "", placeholder: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" })),
        h("label", {}, "Descrição", h("textarea", { name: "desc", value: f.description || "" })),
        h("label", {}, "Passos de reprodução", h("textarea", { name: "repro", value: f.repro_steps || "" })),
        h("label", {}, "Impacto demonstrado", h("textarea", { name: "impact", value: f.impact || "" })),
        h("button", { type: "submit" }, "Validar (só se você reproduziu)")));
  }
  const ev = (f.evidence_json || [])[0] || {};
  box.append(...[
    h("h4", {}, `#${f.id} ${f.title}`),
    h("div", { class: "meta" }, sev(f.severity), h("span", { class: "badge" }, STATE_PT[f.state]), f.cwe ? h("span", { class: "badge" }, f.cwe) : null,
      f.wstg ? h("span", { class: "badge" }, f.wstg) : null, f.cvss_score !== null ? h("span", { class: "badge" }, `CVSS ${f.cvss_score}`) : null,
      h("span", { class: "badge" }, f.source_tool), f.duplicate_of ? h("span", { class: "badge sev-medium" }, `duplicata provável de #${f.duplicate_of}`) : null),
    h("div", { class: "mono" }, f.location),
    f.description ? h("p", {}, f.description) : null,
    (f.fp_signals || []).length ? h("div", { class: "fp" }, "Sinais de falso positivo: ", f.fp_signals.join("; ")) : null,
    f.ai_json ? (() => { const a = JSON.parse(f.ai_json); return h("div", { class: "ai" }, h("b", {}, `IA (${a.model}): prioridade ${a.priority}, chance de falso positivo ${a.false_positive_likelihood}. `), a.rationale, a.next_validation_step ? h("div", {}, "Próximo passo: ", a.next_validation_step) : null); })() : null,
    ev.request || ev.snippet ? h("details", {}, h("summary", {}, "evidência"), h("pre", {}, ev.request ? `${ev.request}\n\n${ev.response || ""}` : `${ev.file}:${ev.line}\n${ev.snippet}`)) : null,
    form, actions].filter((c) => c !== null && c !== undefined && c !== false));
  return box;
}

boot();
