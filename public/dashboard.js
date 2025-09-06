// dashboard.js — LinqBridge Dashboard (Leads + Connect + Sprouts-style account settings)

const API_BASE = ""; // same-origin (served by your backend)
const LS_TOKEN = "lb_token";
const LS_EMAIL = "lb_email";

// ---------- tiny helpers ----------
function $(id) { return document.getElementById(id); }
function show(el) { if (el) el.style.display = "block"; }
function hide(el) { if (el) el.style.display = "none"; }
function setText(el, txt) { if (el) el.textContent = txt; }
function setAttr(el, k, v) { if (el) el.setAttribute(k, v); }
function hasEl(id) { return !!$(id); }
function val(id) { const el = $(id); return el ? el.value : ""; }
function setVal(id, v) { const el = $(id); if (el) el.value = v ?? ""; }

function setMsg(el, text, type = "info") {
  if (!el) return;
  el.className = "msg " + type;
  el.textContent = text;
  show(el);
}
function clearMsg(el) {
  if (!el) return;
  el.textContent = "";
  hide(el);
}

async function api(path, { method = "GET", headers = {}, body } = {}) {
  const token = localStorage.getItem(LS_TOKEN);
  const finalHeaders = {
    "Content-Type": "application/json",
    ...(token ? { "Authorization": `Bearer ${token}` } : {}),
    ...headers
  };
  const res = await fetch(path.startsWith("/") ? API_BASE + path : API_BASE + "/" + path, {
    method,
    headers: finalHeaders,
    body
  });
  const ct = res.headers.get("content-type") || "";
  const text = await res.text();
  if (!ct.includes("application/json")) {
    // Pass through raw on error
    if (!res.ok) throw new Error(text || `HTTP ${res.status}`);
    return { _raw: text, _status: res.status };
  }
  const json = JSON.parse(text);
  if (!res.ok) throw new Error(json.error || json.message || `HTTP ${res.status}`);
  return json;
}

// ---------- auth wiring ----------
function switchAuthTab(tab) {
  const loginTab = $("tab-login"), regTab = $("tab-register");
  const loginForm = $("login-form"), regForm = $("register-form");
  if (tab === "login") {
    loginTab?.classList.add("active"); regTab?.classList.remove("active");
    loginForm?.classList.add("form-active"); regForm?.classList.remove("form-active");
  } else {
    regTab?.classList.add("active"); loginTab?.classList.remove("active");
    regForm?.classList.add("form-active"); loginForm?.classList.remove("form-active");
  }
}

async function doLogin() {
  const email = $("login-email").value.trim();
  const password = $("login-password").value;
  const msg = $("auth-msg");

  if (!email || !password) return setMsg(msg, "Enter email and password.", "error");

  try {
    const data = await api("/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });
    localStorage.setItem(LS_TOKEN, data.token);
    localStorage.setItem(LS_EMAIL, data.userEmail);
    setMsg(msg, "Logged in!", "success");
    showApp();
  } catch (e) {
    setMsg(msg, e.message || "Login failed.", "error");
  }
}

async function doRegister() {
  const email = $("reg-email").value.trim();
  const p1 = $("reg-password").value;
  const p2 = $("reg-password2").value;
  const msg = $("auth-msg");
  if (!email || !p1 || !p2) return setMsg(msg, "Fill all fields.", "error");
  if (p1 !== p2) return setMsg(msg, "Passwords do not match.", "error");

  try {
    await api("/register", {
      method: "POST",
      body: JSON.stringify({ email, password: p1 })
    });
    setMsg(msg, "Account created. You can log in now.", "success");
    switchAuthTab("login");
  } catch (e) {
    setMsg(msg, e.message || "Register failed.", "error");
  }
}

function logout() {
  localStorage.removeItem(LS_TOKEN);
  localStorage.removeItem(LS_EMAIL);
  setText($("whoami"), "");
  hide($("app"));
  show($("auth-card"));
}

// ---------- views (tabs inside app) ----------
function switchAppView(view) {
  const leadsBtn = $("app-tab-leads");
  const connBtn  = $("app-tab-connection");
  const leads    = $("view-leads");
  const conn     = $("view-connection");

  if (view === "leads") {
    leadsBtn?.classList.add("active"); connBtn?.classList.remove("active");
    leads?.classList.add("view-active"); if (leads) leads.style.display = "block";
    conn?.classList.remove("view-active"); if (conn) conn.style.display = "none";
  } else {
    connBtn?.classList.add("active"); leadsBtn?.classList.remove("active");
    conn?.classList.add("view-active"); if (conn) conn.style.display = "block";
    leads?.classList.remove("view-active"); if (leads) leads.style.display = "none";
  }
}

// ---------- leads ----------
async function loadLeads() {
  const msg = $("app-msg");
  try {
    const data = await api("/api/leads");
    renderLeadsTable(data.leads || []);
    hide(msg);
  } catch (e) {
    setMsg(msg, e.message || "Failed to load leads.", "error");
  }
}

function renderLeadsTable(rows) {
  const tbody = $("leads-table").querySelector("tbody");
  tbody.innerHTML = "";
  rows.forEach(r => {
    const tr = document.createElement("tr");
    const td = (v) => {
      const t = document.createElement("td");
      if (typeof v === "string" && v.startsWith("http")) {
        const a = document.createElement("a");
        a.href = v; a.target = "_blank"; a.textContent = v;
        t.appendChild(a);
      } else {
        t.textContent = v ?? "";
      }
      return t;
    };
    tr.appendChild(td(r.first_name));
    tr.appendChild(td(r.last_name));
    tr.appendChild(td(r.organization));
    tr.appendChild(td(r.title));
    tr.appendChild(td(r.public_profile_url));
    tr.appendChild(td(r.sales_nav_url || r.profile_url));
    tr.appendChild(td(r.automation_status));
    tbody.appendChild(tr);
  });
}

async function downloadExcel() {
  const token = localStorage.getItem(LS_TOKEN);
  const res = await fetch("/download-leads-excel", {
    method: "GET",
    headers: { "Authorization": `Bearer ${token}` }
  });
  if (!res.ok) {
    setMsg($("app-msg"), `Download failed (HTTP ${res.status})`, "error");
    return;
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `linqbridge_leads_${(localStorage.getItem(LS_EMAIL)||"me").split("@")[0]}_${Date.now()}.xlsx`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------- connection (secure browser + job polling) ----------
let connectJobId = null;
let connectPollTimer = null;
let lastViewerUrl = null;

function setConnVisual({ state = "idle", text = "Not linked", badge = null, dot = null, spinning = false, msg = null, msgType = "info" } = {}) {
  const dotEl = $("conn-dot");
  const txtEl = $("conn-status-text");
  if (dotEl) dotEl.className = "dot" + (dot ? " " + dot : "");
  if (txtEl) setText(txtEl, text);

  const badgeEl = $("conn-status");
  if (badgeEl) { badge ? (badgeEl.className = "badge " + badge, show(badgeEl)) : hide(badgeEl); }

  const spinner = $("conn-spinner");
  if (spinner) spinning ? show(spinner) : hide(spinner);

  const msgEl = $("conn-msg");
  if (msgEl) { msg ? setMsg(msgEl, msg, msgType) : clearMsg(msgEl); }
}

async function startConnectFlow() {
  try {
    setConnVisual({ state: "linking", text: "Linking… complete login + 2FA", dot: "info", spinning: true, msg: "A secure browser will open. Sign in to LinkedIn and finish 2FA." });
    const res = await api("/api/connect/start", { method: "POST" });
    connectJobId = res.jobId || null;
    lastViewerUrl = res.viewerUrl || null;

    if (hasEl("open-viewer-link") && lastViewerUrl) {
      setAttr($("open-viewer-link"), "href", lastViewerUrl);
      window.open(lastViewerUrl, "_blank", "noopener");
    }

    beginConnectPolling();
  } catch (e) {
    setConnVisual({ state: "error", text: "Error", dot: "fail", spinning: false, msg: e.message || "Failed to start connect.", msgType: "error" });
  }
}

async function testConnectFlow() {
  try {
    setConnVisual({ state: "testing", text: "Verifying session…", dot: "info", spinning: true });
    const res = await api("/api/connect/test", { method: "POST" });
    connectJobId = res.jobId || null;
    beginConnectPolling();
  } catch (e) {
    setConnVisual({ state: "error", text: "Error", dot: "fail", spinning: false, msg: e.message || "Failed to start test.", msgType: "error" });
  }
}

function beginConnectPolling() {
  if (!connectJobId) return;
  if (connectPollTimer) clearInterval(connectPollTimer);
  connectPollTimer = setInterval(pollConnectStatus, 2000);
}

async function pollConnectStatus() {
  if (!connectJobId) return;
  try {
    const r = await api(`/api/connect/status/${connectJobId}`, { method: "GET" });
    const job = r.job || {};
    const pool = r.pool || job.pool || "";
    const status = job.status || "";
    const result = job.result || {};
    const ok = result.ok === true;

    if (pool === "done" || status === "done" || ok) {
      clearInterval(connectPollTimer); connectPollTimer = null; connectJobId = null;
      setConnVisual({ state: "linked", text: "Linked ✓ (valid)", dot: "ok", spinning: false, badge: "ok", msg: "Authenticated. You can start automation now.", msgType: "success" });
      return;
    }
    if (pool === "failed" || status === "failed") {
      clearInterval(connectPollTimer); connectPollTimer = null; connectJobId = null;
      const details = (result && (result.details || result.reason)) || job.lastError || "Action needed. Re-authenticate.";
      setConnVisual({ state: "action_needed", text: "Action needed", dot: "warn", spinning: false, badge: "warn", msg: details.toString(), msgType: "warning" });
      return;
    }

    setConnVisual({ state: "linking", text: "Linking… complete login + 2FA", dot: "info", spinning: true });
  } catch (e) {
    clearInterval(connectPollTimer); connectPollTimer = null; connectJobId = null;
    setConnVisual({ state: "error", text: "Error", dot: "fail", spinning: false, msg: e.message || "Polling error.", msgType: "error" });
  }
}

// Legacy soft check
async function checkConnection() {
  try {
    setConnVisual({ state: "checking", text: "Checking…", dot: "info", spinning: true });
    const data = await api("/api/connection/check");
    if (data.connected === true) {
      setConnVisual({
        state: "linked",
        text: data.name ? `Connected as ${data.name}` : "Connected",
        dot: "ok",
        spinning: false,
        badge: "ok",
        msg: "Your cookies are valid. Worker can send connection requests.",
        msgType: "success"
      });
    } else if (data.mode === "cooldown") {
      const mins = Math.ceil((data.cooldownMs || 0) / 60000);
      setConnVisual({
        state: "cooldown",
        text: "Stored session (cooldown)",
        dot: "info",
        spinning: false,
        badge: "cooldown",
        msg: `Live check cooldown in effect. Try again in ~${mins} min.`,
        msgType: "info"
      });
    } else if (data.connected === "stored") {
      setConnVisual({
        state: "stored",
        text: "Cookies stored",
        dot: "info",
        spinning: false,
        msg: data.hint || "Stored cookies found. For a durable session, use Login via secure browser.",
        msgType: "info"
      });
    } else {
      setConnVisual({
        state: "not_linked",
        text: "Not connected",
        dot: "fail",
        spinning: false,
        badge: "fail",
        msg: data.reason || "Not connected.",
        msgType: "error"
      });
    }
  } catch (e) {
    setConnVisual({ state: "error", text: "Error", dot: "fail", spinning: false, msg: e.message || "Failed to check status.", msgType: "error" });
  }
}

async function loadLogs() {
  const tbody = $("logs-table").querySelector("tbody");
  tbody.innerHTML = "";
  try {
    const data = await api("/api/connection/logs?limit=50");
    (data.logs || []).forEach(log => {
      const tr = document.createElement("tr");
      const td = (v) => { const t = document.createElement("td"); t.textContent = v ?? ""; return t; };
      tr.appendChild(td(new Date(log.at).toLocaleString()));
      tr.appendChild(td(log.level));
      tr.appendChild(td(log.event));
      tr.appendChild(td(typeof log.details === "object" ? JSON.stringify(log.details) : (log.details || "")));
      tbody.appendChild(tr);
    });
  } catch (e) {
    setMsg($("conn-msg"), e.message || "Failed to load logs.", "error");
  }
}

// ---------- Account settings (Sprouts-style) ----------
async function loadAccountSettings() {
  try {
    const r = await api("/api/account/settings");
    const s = r.settings || {};
    setText($("creds-status"), s.username === "saved" && s.password === "saved" ? "Credentials: saved" :
      (s.username === "saved" || s.password === "saved" ? "Credentials: partially saved" : "Credentials: not saved"));
    setText($("totp-status"), s.totp === "saved" ? "TOTP: saved" : "TOTP: not set");
    const px = s.proxy || {};
    setText($("proxy-status"), px.server ? `Proxy: ${px.server} (${px.username === "saved" ? "auth set" : "no auth"})` : "Proxy: not set");
    setText($("settings-updated-at"), s.updated_at ? `Last updated: ${new Date(s.updated_at).toLocaleString()}` : "");
    // do not prefill username/password/totp for safety; keep inputs blank
  } catch (e) {
    setMsg($("acct-msg"), e.message || "Failed to load account settings.", "error");
  }
}

async function saveCreds() {
  const msg = $("acct-msg");
  clearMsg(msg);
  const username = val("li-username").trim();
  const password = val("li-password");
  if (!username || !password) return setMsg(msg, "Enter both username and password.", "error");
  try {
    await api("/api/account/creds", { method: "POST", body: JSON.stringify({ username, password }) });
    setVal("li-password", "");
    setMsg(msg, "Credentials saved.", "success");
    await loadAccountSettings();
  } catch (e) {
    setMsg(msg, e.message || "Failed to save credentials.", "error");
  }
}

async function saveTotp() {
  const msg = $("acct-msg");
  clearMsg(msg);
  const totpSecret = val("totp-secret").trim();
  if (!totpSecret) return setMsg(msg, "Enter your TOTP secret.", "error");
  try {
    await api("/api/account/totp", { method: "POST", body: JSON.stringify({ totpSecret }) });
    setVal("totp-secret", "");
    setMsg(msg, "TOTP secret saved.", "success");
    await loadAccountSettings();
  } catch (e) {
    setMsg(msg, e.message || "Failed to save TOTP.", "error");
  }
}

async function saveProxy() {
  const msg = $("acct-msg");
  clearMsg(msg);
  const server = val("proxy-server").trim();
  const username = val("proxy-username").trim();
  const password = val("proxy-password");
  try {
    await api("/api/account/proxy", { method: "POST", body: JSON.stringify({ server, username, password }) });
    setVal("proxy-password", "");
    setMsg(msg, "Proxy settings saved.", "success");
    await loadAccountSettings();
  } catch (e) {
    setMsg(msg, e.message || "Failed to save proxy.", "error");
  }
}

// ---------- app show/hide ----------
function showApp() {
  const email = localStorage.getItem(LS_EMAIL) || "";
  setText($("whoami"), email ? `Logged in as ${email}` : "");
  hide($("auth-card"));
  show($("app"));
  switchAppView("leads");
  loadLeads();
}

// ---------- event wiring ----------
document.addEventListener("DOMContentLoaded", () => {
  // auth tab buttons
  $("tab-login")?.addEventListener("click", () => switchAuthTab("login"));
  $("tab-register")?.addEventListener("click", () => switchAuthTab("register"));

  // auth actions
  $("login-btn")?.addEventListener("click", doLogin);
  $("register-btn")?.addEventListener("click", doRegister);
  $("logout-btn")?.addEventListener("click", logout);

  // app tab buttons
  $("app-tab-leads")?.addEventListener("click", () => switchAppView("leads"));
  $("app-tab-connection")?.addEventListener("click", () => {
    switchAppView("connection");
    // refresh status, logs, and account settings
    checkConnection();
    loadLogs();
    loadAccountSettings();
  });

  // leads actions
  $("reload-btn")?.addEventListener("click", loadLeads);
  $("download-btn")?.addEventListener("click", downloadExcel);

  // connect flow
  $("connect-start-btn")?.addEventListener("click", startConnectFlow);
  $("connect-test-btn")?.addEventListener("click", testConnectFlow);

  // account settings actions
  $("save-creds-btn")?.addEventListener("click", saveCreds);
  $("save-totp-btn")?.addEventListener("click", saveTotp);
  $("save-proxy-btn")?.addEventListener("click", saveProxy);

  // prevent empty viewer href
  if (hasEl("open-viewer-link") && !lastViewerUrl) {
    $("open-viewer-link").addEventListener("click", (e) => {
      if (!lastViewerUrl) e.preventDefault();
    });
  }

  // autologin if token exists
  if (localStorage.getItem(LS_TOKEN)) {
    showApp();
  } else {
    show($("auth-card"));
  }
});
