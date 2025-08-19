// dashboard.js — LinqBridge Dashboard (Leads + Connect LinkedIn)

const API_BASE = ""; // same-origin (Railway domain serves this file)
const LS_TOKEN = "lb_token";
const LS_EMAIL = "lb_email";

// ---------- tiny helpers ----------
function $(id) { return document.getElementById(id); }
function show(el) { el && (el.style.display = "block"); }
function hide(el) { el && (el.style.display = "none"); }
function setText(el, txt) { el && (el.textContent = txt); }

function setMsg(el, text, type="info") {
  if (!el) return;
  el.className = "msg " + type;
  el.textContent = text;
  show(el);
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
    // allow file downloads to pass through this helper as non-json
    return { _raw: text, _status: res.status };
  }
  const json = JSON.parse(text);
  if (!res.ok) throw new Error(json.message || `HTTP ${res.status}`);
  return json;
}

// ---------- auth wiring ----------
function switchAuthTab(tab) {
  const loginTab = $("tab-login"), regTab = $("tab-register");
  const loginForm = $("login-form"), regForm = $("register-form");
  if (tab === "login") {
    loginTab.classList.add("active"); regTab.classList.remove("active");
    loginForm.classList.add("form-active"); regForm.classList.remove("form-active");
  } else {
    regTab.classList.add("active"); loginTab.classList.remove("active");
    regForm.classList.add("form-active"); loginForm.classList.remove("form-active");
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
  $("whoami").textContent = "";
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
    leadsBtn.classList.add("active"); connBtn.classList.remove("active");
    leads.classList.add("view-active"); leads.style.display = "block";
    conn.classList.remove("view-active"); conn.style.display = "none";
  } else {
    connBtn.classList.add("active"); leadsBtn.classList.remove("active");
    conn.classList.add("view-active"); conn.style.display = "block";
    leads.classList.remove("view-active"); leads.style.display = "none";
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

// ---------- connection ----------
async function checkConnection() {
  const status = $("conn-status");
  const msg = $("conn-msg");
  setText(status, "Checking…");
  status.className = "badge";
  hide(msg);
  try {
    const data = await api("/api/connection/check");
    if (data.connected) {
      status.className = "badge ok";
      setText(status, data.name ? `Connected as ${data.name}` : "Connected");
      setMsg(msg, "Your cookies are valid. Worker can send connection requests.", "success");
    } else {
      status.className = "badge fail";
      setText(status, "Not connected");
      setMsg(msg, data.reason || "Not connected.", "error");
    }
  } catch (e) {
    status.className = "badge fail";
    setText(status, "Error");
    setMsg(msg, e.message || "Failed to check status.", "error");
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
  $("tab-login").addEventListener("click", () => switchAuthTab("login"));
  $("tab-register").addEventListener("click", () => switchAuthTab("register"));

  // auth actions
  $("login-btn").addEventListener("click", doLogin);
  $("register-btn").addEventListener("click", doRegister);
  $("logout-btn").addEventListener("click", logout);

  // app tab buttons
  $("app-tab-leads").addEventListener("click", () => switchAppView("leads"));
  $("app-tab-connection").addEventListener("click", () => {
    switchAppView("connection");
    // auto-refresh status & logs when opening the tab
    checkConnection();
    loadLogs();
  });

  // leads actions
  $("reload-btn").addEventListener("click", loadLeads);
  $("download-btn").addEventListener("click", downloadExcel);

  // connection actions
  $("check-conn-btn").addEventListener("click", checkConnection);
  $("reload-logs-btn").addEventListener("click", loadLogs);

  // autologin if token exists
  if (localStorage.getItem(LS_TOKEN)) {
    showApp();
  } else {
    show($("auth-card"));
  }
});
