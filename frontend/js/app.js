/* AI Network IDS dashboard. Every number rendered here comes from the backend
 * (WebSocket /ws/live frames or REST /api/*). Nothing is simulated client-side. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (n) => (n == null ? "—" : Number(n).toLocaleString());
  const pct = (v) => (v == null ? "—" : (v * 100).toFixed(1) + "%");
  const t2 = (ts) => (ts ? new Date(ts * 1000).toLocaleTimeString() : "—");
  const host = (ip, port) => (ip ? esc(ip) + (port != null ? `<span class="muted">:${port}</span>` : "") : '<span class="muted">n/a</span>');
  const LEVEL_COLORS = { LOW: "#38bdf8", MEDIUM: "#f7b955", HIGH: "#ff8c42", CRITICAL: "#ff5470" };
  const CLASS_ORDER = ["normal", "DoS", "Probe", "R2L", "U2R"];

  const state = {
    view: "dashboard", mode: "dataset", stats: null, status: null, series: [],
    events: [], alerts: [], models: [], ws: null, alertsTotal: 0,
  };

  async function api(path, opts) {
    const r = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, opts || {}));
    let body = null;
    try { body = await r.json(); } catch (_) { /* csv etc */ }
    if (!r.ok) {
      const d = body && (body.detail || body.error);
      const msg = typeof d === "object" ? (d.error || JSON.stringify(d)) : (d || r.statusText);
      throw new Error(msg);
    }
    return body;
  }
  const post = (p, b) => api(p, { method: "POST", body: JSON.stringify(b || {}) });

  function toast(msg, cls) {
    const host = $("toasts");
    while (host.children.length >= 3) host.firstChild.remove();
    const el = document.createElement("div");
    el.className = "toast " + (cls || "");
    el.innerHTML = msg;
    host.appendChild(el);
    setTimeout(() => el.remove(), 5000);
  }

  /* ---------------- navigation ---------------- */
  const TITLES = { dashboard: "Dashboard", live: "Live Monitor", threats: "Threats", analytics: "Analytics",
    models: "Models", gan: "GAN Lab", alerts: "Alerts", system: "System" };
  function show(view) {
    state.view = view;
    document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + view));
    document.querySelectorAll("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
    $("viewTitle").textContent = TITLES[view];
    try { localStorage.setItem("ids.view", view); } catch (_) {}
    if (view === "models") loadModels();
    if (view === "gan") loadGan();
    if (view === "alerts") loadAlerts();
    if (view === "threats") loadThreats();
    if (view === "system") loadSystem();
    if (view === "analytics") loadDrift();
    requestAnimationFrame(renderAll);
  }
  document.querySelectorAll("#nav button").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));
  document.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => show(b.dataset.goto)));

  /* ---------------- theme ---------------- */
  function setTheme(t) {
    document.documentElement.dataset.theme = t;
    try { localStorage.setItem("ids.theme", t); } catch (_) {}
    renderAll();
  }
  $("btnTheme").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));

  /* ---------------- mode controls ---------------- */
  const MODE_NOTES = {
    dataset: "Dataset Simulation replays genuine NSL-KDD KDDTest+ connection records through the 41-feature engine. It is benchmark data, not live traffic; records have no IP addresses.",
    flow_replay: "Flow Replay feeds NSL-KDD records reduced to the 28 packet-derivable features through the same flow engine used for live capture. Addresses are synthetic placeholders for grouping.",
    pcap: "PCAP Replay parses a capture file and runs it through flow tracking, feature extraction and the 28-feature flow engine. Any .pcap placed in data/pcaps can be used. The bundled file is benign traffic.",
    live: "Live Capture sniffs real packets with Scapy. Requires Npcap + Administrator on Windows (root on Linux). The flow engine was trained on NSL-KDD, so treat live verdicts as indicative - the benchmark domain differs from modern traffic. Broadcast/multicast discovery traffic (SSDP, mDNS, NetBIOS, DHCP) is counted but not scored, because NSL-KDD contains none and the model would mislabel it as Probe.",
  };
  function setMode(m) {
    state.mode = m;
    document.querySelectorAll("#modeSeg button").forEach((b) => b.classList.toggle("active", b.dataset.mode === m));
    $("fPcap").style.display = m === "pcap" ? "" : "none";
    $("fIface").style.display = m === "live" ? "" : "none";
    $("fRate").style.display = m === "dataset" || m === "flow_replay" ? "" : "none";
    $("modeNote").style.display = "";
    $("modeNote").textContent = MODE_NOTES[m];
    if (m === "pcap") loadPcaps();
    if (m === "live") loadIfaces();
  }
  document.querySelectorAll("#modeSeg button").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));

  async function loadPcaps() {
    try {
      const d = await api("/api/pcaps");
      $("pcapSel").innerHTML = d.pcaps.map((p) => `<option ${p === d.default ? "selected" : ""}>${esc(p)}</option>`).join("") || "<option value=''>(no .pcap in data/pcaps)</option>";
    } catch (e) { toast("PCAP list: " + esc(e.message)); }
  }
  async function loadIfaces() {
    try {
      const d = await api("/api/capture/capability");
      if (!d.available) {
        $("modeNote").innerHTML = "<b>Live capture unavailable:</b> " + esc(d.reason) + "<br>Dataset Simulation, Flow Replay and PCAP Replay still work.";
        return;
      }
      $("ifaceSel").innerHTML = '<option value="">default</option>' + d.interfaces.map((i) => `<option value="${esc(i.name)}">${esc(i.description || i.name)} ${i.ip ? "(" + esc(i.ip) + ")" : ""}</option>`).join("");
    } catch (e) { toast("Interfaces: " + esc(e.message)); }
  }

  $("btnStart").addEventListener("click", async () => {
    const speed = parseFloat($("speedSel").value), rate = parseFloat($("rateIn").value) || 25;
    try {
      let r;
      if (state.mode === "dataset") r = await post("/api/capture/dataset/start", { rate, speed });
      else if (state.mode === "flow_replay") r = await post("/api/flow-replay/start", { rate, speed });
      else if (state.mode === "pcap") r = await post("/api/replay/start", { file: $("pcapSel").value || null, speed });
      else r = await post("/api/capture/start", { interface: $("ifaceSel").value || null });
      toast("Started: " + esc(r.source.label));
    } catch (e) { toast("<b>Could not start</b><br>" + esc(e.message), "crit"); }
  });
  $("btnStop").addEventListener("click", async () => { await post("/api/source/stop"); toast("Source stopped"); });
  $("btnPause").addEventListener("click", () => post("/api/source/pause"));
  $("btnResume").addEventListener("click", () => post("/api/source/resume"));
  $("speedSel").addEventListener("change", async () => {
    try { await post("/api/source/speed", { speed: parseFloat($("speedSel").value) }); } catch (_) { /* no active source */ }
  });
  $("btnDemo").addEventListener("click", async () => {
    $("btnDemo").disabled = true;
    try {
      toast("Full demo: checking health, loading models, initialising DB…");
      const h = await api("/api/health");
      if (h.status !== "ok") throw new Error("health check failed");
      const r = await post("/api/demo/start");
      setMode("dataset");
      toast("Demo running: " + esc(r.banner));
      show("dashboard");
    } catch (e) { toast("<b>Demo failed</b><br>" + esc(e.message), "crit"); }
    finally { $("btnDemo").disabled = false; }
  });

  /* ---------------- websocket ---------------- */
  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws/live`);
    state.ws = ws;
    ws.onopen = () => { $("miniWs").textContent = "live"; $("miniWs").style.color = "var(--ok)"; };
    ws.onclose = () => {
      $("miniWs").textContent = "reconnecting"; $("miniWs").style.color = "var(--warn)";
      setTimeout(connect, 2000);
    };
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.status) state.status = m.status;
      if (m.stats) state.stats = m.stats;
      if (m.series) state.series = m.series;
      if (m.events && m.events.length) {
        state.events = m.events.slice().reverse().concat(state.events).slice(0, 300);
      }
      if (m.alerts && m.alerts.length) {
        m.alerts.forEach((a) => state.alerts.unshift(a));
        state.alerts = state.alerts.slice(0, 100);
        // one summary toast per frame instead of one per alert (avoids flooding)
        const serious = m.alerts.filter((a) => a.severity === "CRITICAL" || a.severity === "HIGH");
        if (serious.length) {
          const top = serious.slice().sort((a, b) => b.risk_score - a.risk_score)[0];
          const nCrit = serious.filter((a) => a.severity === "CRITICAL").length;
          const more = serious.length > 1 ? ` <span class="muted">+${serious.length - 1} more (${nCrit} critical)</span>` : "";
          toast(`<b>${esc(top.severity)}</b> ${esc(top.predicted_class)} · ${esc(top.src_ip || "dataset record")} · risk ${top.risk_score}${more}`, nCrit ? "crit" : "high");
        }
      }
      renderAll();
    };
  }

  /* ---------------- render ---------------- */
  function renderStatus() {
    const st = state.status; if (!st) return;
    const active = st.mode !== "idle";
    if (active && st.mode !== state.mode && MODE_NOTES[st.mode]) setMode(st.mode);
    $("modeBanner").textContent = st.banner;
    $("modeDot").className = "dot " + (active ? "live" : "idle");
    $("engineTxt").innerHTML = st.engine ? `<b>Detection engine in use:</b> ${esc(st.engine)}` :
      '<span class="muted">No engine running. Choose a mode and press Start, or use Start Full Demo.</span>';
    $("miniEngine").textContent = active ? st.mode : "idle";
    const src = st.source;
    if (src && src.progress) {
      const p = src.progress;
      const done = p.processed != null ? `${fmt(p.processed)} / ${fmt(p.total_packets || p.total_records)} (${p.percent}%)` : (p.interface ? "interface " + p.interface : "");
      $("progressTxt").innerHTML = `${esc(src.state)} · ${done} · x${src.speed}` + (src.error ? ` · <span style="color:var(--danger)">${esc(src.error)}</span>` : "");
    }
    $("navAlertCount").textContent = fmt(st.alerts ? st.alerts.created : 0);
    $("alDedup").textContent = st.alerts ? `dedup merged ${fmt(st.alerts.deduplicated)} · rate-limited ${fmt(st.alerts.suppressed)} (window ${st.alerts.dedup_window_s}s)` : "";
  }

  function renderKpis() {
    const s = state.stats; if (!s) return;
    $("kPackets").textContent = fmt(s.packets);
    $("kPps").textContent = `${fmt(s.pps)} pkt/s · ${fmt(s.unsupported_packets)} non-IP/unsupported`;
    $("kEvents").textContent = fmt(s.events);
    $("kEps").textContent = `${fmt(s.eps)} /s · ${fmt(s.flows)} flows · ${fmt(s.dropped)} dropped` +
      (s.broadcast_skipped ? ` · ${fmt(s.broadcast_skipped)} broadcast/multicast not scored` : "");
    $("kAttacks").textContent = fmt(s.attacks);
    $("kSusp").textContent = `${fmt(s.suspicious)} suspicious · ${fmt(s.invalid)} invalid`;
    const created = state.status && state.status.alerts ? state.status.alerts.created : 0;
    $("kAlerts").textContent = fmt(created);
    $("kAlertSub").textContent = state.status && state.status.alerts ? `${fmt(state.status.alerts.deduplicated)} merged by dedup` : "";
    const sim = s.simulation || {};
    $("kSimAcc").textContent = sim.accuracy == null ? "—" : pct(sim.accuracy);
    $("kSimSub").textContent = sim.total ? `${fmt(sim.correct)} / ${fmt(sim.total)} records correct` : "only for dataset / flow replay";
    $("miniLat").textContent = s.latency_ms_p95 != null ? s.latency_ms_p95 + " ms" : "—";
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"].forEach((l, i) => { $(["tCrit", "tHigh", "tMed", "tLow"][i]).textContent = fmt((s.levels || {})[l] || 0); });
  }

  function evRow(e, full) {
    const proto = esc((e.protocol || "").toUpperCase());
    const cls = e.verdict === "Normal" ? '<span class="muted">normal</span>' : `<span class="badge v-${esc(e.verdict)}">${esc(e.predicted_class)}</span>`;
    const risk = `<span class="badge lvl-${esc(e.risk_level)}">${esc(e.risk_level)} ${e.risk_score}</span>`;
    if (!full) return `<tr><td class="mono">${t2(e.ts)}</td><td class="mono">${host(e.src_ip)}</td><td class="mono">${host(e.dst_ip)}</td><td>${proto}</td><td>${cls}</td><td>${risk}</td></tr>`;
    const truth = e.ground_truth ? (e.ground_truth === e.predicted_class ? `<span style="color:var(--ok)">✓ ${esc(e.ground_truth)}</span>` : `<span style="color:var(--danger)">✗ ${esc(e.ground_truth)}</span>`) : '<span class="muted">—</span>';
    return `<tr><td class="mono">${t2(e.ts)}</td><td class="mono">${host(e.src_ip, e.src_port)}</td><td class="mono">${host(e.dst_ip, e.dst_port)}</td><td>${proto}</td><td>${esc(e.service)}</td><td class="mono">${esc(e.flag)}</td><td><span class="badge v-${esc(e.verdict)}">${esc(e.verdict)}</span></td><td>${esc(e.predicted_class)}</td><td>${pct(e.confidence)}</td><td>${risk}</td><td>${truth}</td></tr>`;
  }

  function renderTables() {
    const ev = state.events;
    if (state.view === "dashboard") {
      $("tbDashEvents").innerHTML = ev.slice(0, 40).map((e) => evRow(e, false)).join("") || `<tr><td colspan="6" class="muted">No detections yet.</td></tr>`;
      $("tbDashAlerts").innerHTML = state.alerts.slice(0, 25).map((a) =>
        `<tr class="alert-row" data-id="${a.id}"><td><span class="badge sev-${esc(a.severity)}">${esc(a.severity)}</span></td><td>${esc(a.predicted_class)}</td><td class="mono">${host(a.src_ip)}</td><td>${fmt(a.count)}</td><td>${a.risk_score}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">No alerts yet.</td></tr>`;
    }
    if (state.view === "live") {
      const f = ($("liveFilter").value || "").toLowerCase();
      const rows = f ? ev.filter((e) => JSON.stringify([e.src_ip, e.dst_ip, e.service, e.predicted_class, e.verdict, e.protocol]).toLowerCase().includes(f)) : ev;
      $("tbLive").innerHTML = rows.slice(0, 150).map((e) => evRow(e, true)).join("") || `<tr><td colspan="11" class="muted">No detections yet.</td></tr>`;
    }
  }

  function renderCharts() {
    const s = state.stats; if (!s) return;
    const ser = state.series || [];
    if (state.view === "dashboard") {
      Charts.lineChart($("chTraffic"), [
        { label: "events/s", data: ser.map((x) => x.events) },
        { label: "attacks/s", data: ser.map((x) => x.attacks), color: "#ff5470" },
        { label: "suspicious/s", data: ser.map((x) => x.suspicious), color: "#f7b955" },
      ], { legend: true, fill: true });
      const lv = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
      Charts.doughnut($("chLevels"), lv, lv.map((l) => (s.levels || {})[l] || 0), { colors: lv.map((l) => LEVEL_COLORS[l]) });
      const att = CLASS_ORDER.filter((c) => c !== "normal");
      Charts.barChart($("chClasses"), att, att.map((c) => (s.classes || {})[c] || 0), { colorByIndex: true });
      const pk = Object.keys(s.protocols || {});
      Charts.doughnut($("chProto"), pk.length ? pk : ["none"], pk.length ? pk.map((k) => s.protocols[k]) : [1]);
    }
    if (state.view === "live") {
      Charts.lineChart($("chPps"), [{ label: "pkt/s", data: ser.map((x) => x.packets) }], { fill: true });
      Charts.lineChart($("chBps"), [{ label: "B/s", data: ser.map((x) => x.bytes), color: "#30d0b6" }], { fill: true });
    }
    if (state.view === "analytics") {
      Charts.lineChart($("chAttTime"), [
        { label: "attacks/s", data: ser.map((x) => x.attacks), color: "#ff5470" },
        { label: "suspicious/s", data: ser.map((x) => x.suspicious), color: "#f7b955" },
      ], { legend: true, fill: true });
      const lv = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
      Charts.barChart($("chSev"), lv, lv.map((l) => (s.levels || {})[l] || 0), { colorByIndex: false, color: "#ff8c42" });
      const ts = s.top_src || [], td = s.top_dst || [], sv = s.services_attacked || [];
      Charts.barChart($("chTopSrc"), ts.map((x) => x[0]), ts.map((x) => x[1]), { rotate: true });
      Charts.barChart($("chTopDst"), td.map((x) => x[0]), td.map((x) => x[1]), { rotate: true, color: "#30d0b6" });
      Charts.barChart($("chSvc"), sv.map((x) => x[0]), sv.map((x) => x[1]), { rotate: true, color: "#a78bfa" });
    }
  }

  function renderAll() {
    renderStatus(); renderKpis(); renderTables(); renderCharts();
  }

  /* ---------------- threats ---------------- */
  async function loadThreats() {
    const q = new URLSearchParams();
    [["verdict", "thVerdict"], ["predicted_class", "thClass"], ["protocol", "thProto"], ["src_ip", "thSrc"], ["dst_ip", "thDst"], ["q", "thQ"]]
      .forEach(([k, id]) => { if ($(id).value) q.set(k, $(id).value); });
    q.set("limit", "300");
    try {
      const d = await api("/api/events?" + q);
      $("thCount").textContent = `${fmt(d.total)} matching events (showing ${d.events.length})`;
      $("tbThreats").innerHTML = d.events.map((e) => `<tr><td class="mono">${e.id}</td><td class="mono">${t2(e.ts)}</td><td><span class="pill">${esc(e.mode)}</span></td><td class="mono">${host(e.src_ip, e.src_port)}</td><td class="mono">${host(e.dst_ip, e.dst_port)}</td><td>${esc((e.protocol || "").toUpperCase())}</td><td>${esc(e.service)}</td><td><span class="badge v-${esc(e.verdict)}">${esc(e.verdict)}</span></td><td>${esc(e.predicted_class)}</td><td>${pct(e.confidence)}</td><td><span class="badge lvl-${esc(e.risk_level)}">${e.risk_score}</span></td></tr>`).join("") || `<tr><td colspan="11" class="muted">No matching events.</td></tr>`;
    } catch (e) { toast("Threat search: " + esc(e.message)); }
  }
  $("thGo").addEventListener("click", loadThreats);

  /* ---------------- alerts ---------------- */
  async function loadAlerts() {
    const q = new URLSearchParams({ limit: "300" });
    if ($("alSev").value) q.set("severity", $("alSev").value);
    if ($("alStatus").value) q.set("status", $("alStatus").value);
    if ($("alQ").value) q.set("q", $("alQ").value);
    try {
      const d = await api("/api/alerts?" + q);
      $("alCount").textContent = `${fmt(d.total)} alerts`;
      $("tbAlerts").innerHTML = d.alerts.map((a) => `<tr class="alert-row" data-id="${a.id}"><td class="mono">${esc(a.alert_uid)}</td><td class="mono">${t2(a.last_seen)}</td><td><span class="badge sev-${esc(a.severity)}">${esc(a.severity)}</span></td><td>${esc(a.predicted_class)}</td><td class="mono">${host(a.src_ip, a.src_port)}</td><td class="mono">${host(a.dst_ip, a.dst_port)}</td><td>${esc((a.protocol || "").toUpperCase())}</td><td>${fmt(a.count)}</td><td>${pct(a.confidence)}</td><td>${a.risk_score}</td><td><span class="pill">${esc(a.status)}</span></td></tr>`).join("") || `<tr><td colspan="11" class="muted">No alerts.</td></tr>`;
    } catch (e) { toast("Alerts: " + esc(e.message)); }
  }
  $("alGo").addEventListener("click", loadAlerts);

  document.addEventListener("click", (ev) => {
    const row = ev.target.closest(".alert-row");
    if (row) openAlert(row.dataset.id);
  });
  $("overlay").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeDrawer(); });
  function closeDrawer() { $("drawer").classList.remove("open"); $("overlay").classList.remove("open"); }

  async function openAlert(id) {
    let a;
    try { a = await api("/api/alerts/" + id); } catch (e) { toast(esc(e.message)); return; }
    const ex = a.explanation;
    let exHtml = '<p class="small muted">No feature attribution for this alert (suspicious verdicts and non-tree engines have none).</p>';
    if (ex && ex.top_features) {
      const max = Math.max(...ex.top_features.map((f) => Math.abs(f.contribution)), 1e-6);
      exHtml = `<p class="small muted">${esc(ex.method)}<br>Explained member: ${esc(ex.model)} (the ensemble's tree model; its probability can differ from the ensemble confidence) · base rate ${ex.base_rate} → P(${esc(ex.predicted_class)}) = ${ex.probability}</p>` +
        ex.top_features.map((f) => `<div class="explain-row"><span><b>${esc(f.feature)}</b> = <span class="mono">${esc(f.value)}</span></span><span class="mono">${f.contribution > 0 ? "+" : ""}${f.contribution}</span>
          <div style="grid-column:1/3;background:var(--card2);border-radius:4px"><div class="bar" style="height:6px;border-radius:4px;width:${(Math.abs(f.contribution) / max * 100).toFixed(0)}%;background:${f.contribution >= 0 ? "var(--danger)" : "var(--ok)"}"></div></div></div>`).join("") +
        '<p class="small muted">Path attribution shows how the model reached its output; it is not a causal explanation of the traffic.</p>';
    }
    $("drawer").innerHTML = `
      <div class="flex"><h3>${esc(a.alert_uid)}</h3><div class="spacer"></div><button class="btn sm" id="dClose">✕</button></div>
      <div class="flex wrap"><span class="badge sev-${esc(a.severity)}">${esc(a.severity)}</span><span class="pill">${esc(a.mode)}</span><span class="pill">${esc(a.status)}</span></div>
      <h4 style="margin:18px 0 4px">Why was this traffic classified as an attack?</h4>
      <div class="kv">
        <span class="k">Prediction</span><span class="v">${esc(a.predicted_class)}</span>
        <span class="k">Confidence</span><span class="v">${pct(a.confidence)}</span>
        <span class="k">Risk score</span><span class="v">${a.risk_score} / 100 (${esc(a.severity)})</span>
        <span class="k">Risk factors</span><span class="v">${(a.risk_factors || []).map(esc).join("<br>") || "—"}</span>
      </div>
      ${exHtml}
      <div class="kv">
        <span class="k">Source</span><span class="v">${esc(a.src_ip || "n/a")}${a.src_port != null ? ":" + a.src_port : ""}</span>
        <span class="k">Destination</span><span class="v">${esc(a.dst_ip || "n/a")}${a.dst_port != null ? ":" + a.dst_port : ""}</span>
        <span class="k">Protocol / service</span><span class="v">${esc(a.protocol)} / ${esc(a.service)}</span>
        <span class="k">First / last seen</span><span class="v">${t2(a.first_seen)} / ${t2(a.last_seen)}</span>
        <span class="k">Occurrences</span><span class="v">${fmt(a.count)} (deduplicated)</span>
        <span class="k">Model used</span><span class="v">${esc(a.model_used)}</span>
      </div>
      <div class="flex wrap">${["New", "Investigating", "Resolved", "Ignored"].map((s) => `<button class="btn sm ${s === a.status ? "primary" : ""}" data-status="${s}">${s}</button>`).join("")}</div>
      <p class="small muted" style="margin-top:14px">Risk score is an application-level triage value derived from model confidence and context - not a calibrated probability of compromise.</p>`;
    $("drawer").classList.add("open"); $("overlay").classList.add("open");
    $("dClose").onclick = closeDrawer;
    $("drawer").querySelectorAll("[data-status]").forEach((b) => b.onclick = async () => {
      try { await post(`/api/alerts/${a.id}/status`, { status: b.dataset.status }); toast("Status → " + b.dataset.status); openAlert(a.id); loadAlerts(); }
      catch (e) { toast(esc(e.message), "crit"); }
    });
  }

  /* ---------------- models ---------------- */
  async function loadModels() {
    try {
      const d = await api("/api/models");
      state.models = d.models;
      renderModels();
    } catch (e) { toast("Models: " + esc(e.message)); }
  }
  function renderModels() {
    const split = $("mSplit").value;
    const ms = state.models;
    $("tbModels").innerHTML = ms.map((m) => {
      const t = m.metrics[split] || {};
      const auc = t.roc_auc ?? t.roc_auc_ovr_macro;
      return `<tr><td>${esc(m.name)}</td><td>${esc(m.task)}</td><td><span class="pill">${esc(m.feature_set)} (${m.n_features})</span></td><td>v${m.version}</td><td>${pct(t.accuracy)}</td><td>${pct(t.precision)}</td><td>${pct(t.recall)}</td><td><b>${pct(t.f1)}</b></td><td>${pct(t.false_positive_rate)}</td><td>${auc == null ? "—" : auc.toFixed(3)}</td><td class="small muted">${esc((m.trained_at || "").replace("T", " ").slice(0, 16))}</td></tr>`;
    }).join("") || `<tr><td colspan="11" class="muted">No trained models. Run: python scripts/train_models.py</td></tr>`;
    const sel = $("cmSel"), prev = sel.value;
    sel.innerHTML = ms.map((m) => `<option value="${esc(m.id)}">${esc(m.id)}</option>`).join("");
    sel.value = prev && ms.some((m) => m.id === prev) ? prev : (ms.find((m) => m.id === "full-multiclass-ensemble") || ms[0] || {}).id || "";
    renderCM();
    const multi = ms.filter((m) => m.task === "multiclass" && !m.variant);
    Charts.barChart($("chModelCmp"), multi.map((m) => m.id.replace("-multiclass", "")), multi.map((m) => +(100 * (m.metrics[split] || {}).accuracy || 0).toFixed(1)), { rotate: true });
  }
  function renderCM() {
    const m = state.models.find((x) => x.id === $("cmSel").value);
    if (!m) return;
    const t = m.metrics[$("mSplit").value];
    Charts.heatmap($("chCM"), t.confusion_matrix, t.classes);
    $("perClass").innerHTML = '<table class="tbl"><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Support</th></tr></thead><tbody>' +
      Object.entries(t.per_class).map(([c, v]) => `<tr><td>${esc(c)}</td><td>${pct(v.precision)}</td><td>${pct(v.recall)}</td><td>${pct(v.f1)}</td><td>${fmt(v.support)}</td></tr>`).join("") + "</tbody></table>" +
      (t.macro_f1 != null ? `<p class="muted">macro-F1 ${pct(t.macro_f1)} · weighted-F1 ${pct(t.weighted_f1)}</p>` : "");
    const fiModel = state.models.find((x) => x.feature_importance && x.feature_set === m.feature_set && x.task === m.task && x.algo === "rf" && !x.variant) || state.models.find((x) => x.feature_importance);
    if (fiModel) {
      const fi = fiModel.feature_importance.slice(0, 12);
      Charts.barChart($("chFI"), fi.map((f) => f.feature), fi.map((f) => +(f.importance * 100).toFixed(2)), { rotate: true, color: "#30d0b6" });
    }
  }
  $("mSplit").addEventListener("change", renderModels);
  $("cmSel").addEventListener("change", renderCM);

  /* ---------------- GAN lab ---------------- */
  let ganPoll = null;
  async function loadGan() {
    try {
      const d = await api("/api/gan/status");
      $("gStatus").textContent = d.available ? `status: ${d.status}${d.message ? " · " + d.message : ""}` : `TensorFlow unavailable: ${d.info}`;
      $("gTrain").disabled = !d.available || d.status === "running";
      $("gLog").innerHTML = (d.progress || []).map(esc).join("<br>");
      if (d.error) $("gStatus").innerHTML = `<span style="color:var(--danger)">error: ${esc(d.error)}</span>`;
      renderGanReport(d.report);
      if (d.status === "running" && !ganPoll) ganPoll = setInterval(loadGan, 3000);
      if (d.status !== "running" && ganPoll) { clearInterval(ganPoll); ganPoll = null; }
    } catch (e) { toast("GAN: " + esc(e.message)); }
  }
  function renderGanReport(r) {
    if (!r) {
      $("gVal").innerHTML = '<p class="muted">No GAN run yet. Train the GAN to generate and validate synthetic minority-class samples.</p>';
      $("gImpact").innerHTML = ""; return;
    }
    const before = r.class_balance_before, after = r.class_balance_after;
    const orig = Object.values(before).reduce((a, b) => a + b, 0);
    $("gOrig").textContent = fmt(orig);
    $("gSyn").textContent = fmt(r.synthetic_total);
    $("gCls").textContent = (r.classes_augmented || []).join(", ") || "—";
    const qs = Object.values(r.per_class || {}).map((v) => v.quality_score);
    $("gQ").textContent = qs.length ? (qs.reduce((a, b) => a + b, 0) / qs.length).toFixed(1) : "—";
    const cls = Object.keys(after);
    Charts.lineChart($("chGanLoss"), [
      { label: "critic W-estimate", data: (r.loss_curve || []).map((x) => Math.max(0, x.wasserstein)) },
    ], { fill: true });
    // grouped bars rendered as two series: draw before/after side by side via labels
    const labels = [], vals = [];
    cls.forEach((c) => { labels.push(c + " (before)"); vals.push(before[c] || 0); labels.push(c + " (after)"); vals.push(after[c] || 0); });
    Charts.barChart($("chGanBal"), labels, vals, { rotate: true, colors: ["#64789e", "#30d0b6"] });
    $("gVal").innerHTML = `<p>${esc(r.architecture)} · ${r.epochs} epochs · ${r.train_seconds}s</p>` +
      '<table class="tbl"><thead><tr><th>Class</th><th>Generated</th><th>Valid</th><th>Kept</th><th>Dup. of real</th><th>Internal dup.</th><th>Distribution</th><th>Quality</th></tr></thead><tbody>' +
      Object.entries(r.per_class || {}).map(([c, v]) => `<tr><td>${esc(c)}</td><td>${fmt(v.generated)}</td><td>${fmt(v.valid)}</td><td>${fmt(v.kept)}</td><td>${fmt(v.duplicates_of_real)}</td><td>${fmt(v.internal_duplicates)}</td><td>${v.distribution_closeness}</td><td><b>${v.quality_score}</b></td></tr>`).join("") +
      "</tbody></table><p class='muted'>Quality = 50% validity + 20% non-duplication + 30% feature-mean closeness to real samples of that class.</p>";
    const rt = r.retrain;
    if (rt && rt.per_class_recall) {
      $("gImpact").innerHTML = `<p>Baseline accuracy ${pct(rt.baseline_test.accuracy)} → augmented ${pct(rt.augmented_test.accuracy)} · macro-F1 ${pct(rt.baseline_test.macro_f1)} → ${pct(rt.augmented_test.macro_f1)}</p>` +
        '<table class="tbl"><thead><tr><th>Class</th><th>Recall (baseline)</th><th>Recall (GAN-augmented)</th><th>Δ</th></tr></thead><tbody>' +
        Object.entries(rt.per_class_recall).map(([c, v]) => { const d = v.augmented - v.baseline; return `<tr><td>${esc(c)}</td><td>${pct(v.baseline)}</td><td>${pct(v.augmented)}</td><td style="color:${d >= 0 ? "var(--ok)" : "var(--danger)"}">${d >= 0 ? "+" : ""}${(d * 100).toFixed(1)} pp</td></tr>`; }).join("") +
        "</tbody></table><p class='muted'>Measured on KDDTest+. Augmentation can trade majority-class precision for minority recall; both directions are reported as measured.</p>";
    } else {
      $("gImpact").innerHTML = '<p class="muted">Retraining comparison not run (enable “retrain” when training the GAN).</p>';
    }
  }
  $("gTrain").addEventListener("click", async () => {
    try {
      const per = parseInt($("gPer").value, 10);
      await post("/api/gan/train", { epochs: parseInt($("gEpochs").value, 10) || 60, per_class: per > 0 ? per : null, retrain: $("gRetrain").checked });
      toast("GAN training started"); loadGan();
    } catch (e) { toast("GAN: " + esc(e.message), "crit"); }
  });

  /* ---------------- drift ---------------- */
  async function loadDrift() {
    try {
      const d = await api("/api/drift");
      const eng = Object.entries(d.engines || {});
      $("driftBox").innerHTML = `<p class="muted">${esc(d.method)} · window ${d.window}</p>` + (eng.length ? eng.map(([fs, v]) => `
        <div style="margin-bottom:12px"><b>${esc(fs)} engine</b> · <span class="badge ${v.status.startsWith("potential") ? "v-Attack" : v.status.startsWith("moderate") ? "v-Suspicious" : "v-Normal"}">${esc(v.status)}</span>
        <div class="kv"><span class="k">PSI</span><span class="v">${v.psi ?? "—"}</span><span class="k">Predictions</span><span class="v">${fmt(v.n)}</span>
        <span class="k">Mean confidence</span><span class="v">${v.mean_confidence ?? "—"}</span>
        <span class="k">Unseen categories</span><span class="v">${pct(v.unseen_category_rate)}</span><span class="k">Above training max</span><span class="v">${pct(v.out_of_range_rate)}</span></div></div>`).join("") : '<p class="muted">No predictions yet.</p>');
    } catch (e) { $("driftBox").textContent = e.message; }
  }

  /* ---------------- system ---------------- */
  async function loadSystem() {
    try {
      const d = await api("/api/system");
      const h = d.health;
      $("sCpu").textContent = h.cpu_percent + "%"; $("sCpuBar").style.width = h.cpu_percent + "%";
      $("sMem").textContent = h.memory_percent + "%"; $("sMemBar").style.width = h.memory_percent + "%";
      $("sDb").textContent = h.database.ok ? "OK" : "ERROR";
      $("sDb").style.color = h.database.ok ? "var(--ok)" : "var(--danger)";
      $("sDbSub").textContent = h.database.ok ? `${fmt(h.database.events)} events · ${fmt(h.database.alerts)} alerts` : h.database.error;
      $("sCap").textContent = d.capture.available ? "Available" : "Unavailable";
      $("sCap").style.color = d.capture.available ? "var(--ok)" : "var(--warn)";
      $("sCapSub").textContent = d.capture.reason || `${d.capture.platform} · scapy ${d.capture.scapy ? "ok" : "missing"}`;
      $("sEnv").innerHTML = [["App version", h.app_version], ["Environment", h.environment], ["Python", h.python], ["Platform", h.platform],
        ["Process memory", h.process_rss_mb + " MB"], ["Uptime", Math.round(h.uptime_s) + " s"], ["Database", h.database.path || "—"]]
        .map(([k, v]) => `<span class="k">${esc(k)}</span><span class="v">${esc(v)}</span>`).join("");
      $("sEng").innerHTML = Object.entries(d.detector).map(([k, v]) => `<span class="k">${esc(k.replace(":", ""))}</span><span class="v">${v.ready ? esc(v.engine) : '<span style="color:var(--danger)">unavailable</span>'}${(v.problems || []).length ? "<br><span class='muted'>" + v.problems.map(esc).join("<br>") + "</span>" : ""}</span>`).join("") +
        `<span class="k">Queue depth</span><span class="v">${d.engine.queue_depth}</span><span class="k">Active flows</span><span class="v">${d.engine.active_flows}</span>`;
      $("sLogs").innerHTML = (d.logs || []).slice().reverse().map((l) => `<div class="logline"><span class="lvl-${esc(l.level)}">${esc(l.level)}</span> ${new Date(l.ts * 1000).toLocaleTimeString()} <b>${esc(l.logger)}</b> ${esc(l.message)}</div>`).join("");
      $("miniCpu").textContent = h.cpu_percent + "%"; $("miniMem").textContent = h.memory_percent + "%";
    } catch (e) { toast("System: " + esc(e.message)); }
  }
  $("sRefresh").addEventListener("click", loadSystem);

  async function loadPacketSample() {
    if (state.view !== "live") return;
    try {
      const d = await api("/api/packets/recent");
      $("tbPackets").innerHTML = (d.packets || []).map((p) => `<tr><td class="mono">${new Date(p.ts * 1000).toLocaleTimeString()}</td><td class="mono">${esc(p.src)}</td><td class="mono">${esc(p.dst)}</td><td>${esc(p.proto.toUpperCase())}</td><td>${p.sport || ""}</td><td>${p.dport || ""}</td><td>${p.len}</td><td class="mono">${tcpFlags(p.flags)}</td></tr>`).join("") || `<tr><td colspan="8" class="muted">No packets in the current mode.</td></tr>`;
    } catch (_) {}
  }
  function tcpFlags(f) {
    if (!f) return "";
    return [[0x02, "S"], [0x10, "A"], [0x01, "F"], [0x04, "R"], [0x08, "P"], [0x20, "U"]].filter(([b]) => f & b).map(([, n]) => n).join("");
  }

  /* periodic refresh of pages that are not fully websocket-driven */
  setInterval(() => {
    if (state.view === "alerts") loadAlerts();
    if (state.view === "analytics") loadDrift();
    if (state.view === "system") loadSystem();
    loadPacketSample();
  }, 3000);
  setInterval(async () => {
    try { const h = await api("/api/health"); $("miniCpu").textContent = h.system.cpu_percent + "%"; $("miniMem").textContent = h.system.memory_percent + "%"; } catch (_) {}
  }, 5000);
  window.addEventListener("resize", () => renderAll());
  $("liveFilter").addEventListener("input", renderTables);

  /* ---------------- boot ---------------- */
  let theme = "dark", view = "dashboard";
  try { theme = localStorage.getItem("ids.theme") || "dark"; view = localStorage.getItem("ids.view") || "dashboard"; } catch (_) {}
  document.documentElement.dataset.theme = theme;
  setMode("dataset");
  connect();
  show(TITLES[view] ? view : "dashboard");
  api("/api/alerts?limit=25").then((d) => { state.alerts = d.alerts; renderAll(); }).catch(() => {});
  api("/api/events/recent?limit=100").then((d) => { state.events = d.events; renderAll(); }).catch(() => {});
})();
