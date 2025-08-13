// Persist token in localStorage between refreshes
let token = localStorage.getItem("linqbridge_token") || null;
let emailCache = localStorage.getItem("linqbridge_email") || null;

const el = (id) => document.getElementById(id);
const show = (node, on = true) => (node.style.display = on ? "" : "none");
const setMsg = (node, text, isError = false) => {
  node.textContent = text;
  node.className = "msg" + (isError ? " error" : "");
  show(node, !!text);
};

function switchTab(to) {
  const isLogin = to === "login";
  el("tab-login").classList.toggle("active", isLogin);
  el("tab-register").classList.toggle("active", !isLogin);
  el("login-form").classList.toggle("form-active", isLogin);
  el("register-form").classList.toggle("form-active", !isLogin);
  setMsg(el("auth-msg"), "");
}

el("tab-login").addEventListener("click", () => switchTab("login"));
el("tab-register").addEventListener("click", () => switchTab("register"));

async function login(email, password) {
  const r = await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const j = await r.json();
  if (!r.ok || !j.success) throw new Error(j.message || "Login failed");
  token = j.token;
  emailCache = j.userEmail || email;
  localStorage.setItem("linqbridge_token", token);
  localStorage.setItem("linqbridge_email", emailCache);
}

async function register(email, password) {
  const r = await fetch("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const j = await r.json();
  if (!r.ok || !j.success) throw new Error(j.message || "Register failed");
}

async function fetchLeads() {
  const r = await fetch("/api/leads", {
    headers: { Authorization: "Bearer " + token },
  });
  if (r.status === 401 || r.status === 403) {
    throw new Error("Unauthorized. Please log in again.");
  }
  const j = await r.json();
  if (!j.success) throw new Error(j.message || "Failed to fetch leads");
  return j.leads || [];
}

function renderLeads(leads) {
  const tbody = document.querySelector("#leads-table tbody");
  tbody.innerHTML = "";
  for (const lead of leads) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${lead.first_name || ""}</td>
      <td>${lead.last_name || ""}</td>
      <td>${lead.organization || ""}</td>
      <td>${lead.title || ""}</td>
      <td>${(lead.public_profile_url || lead.profile_url) ? `<a href="${lead.public_profile_url || lead.profile_url}" target="_blank">Profile</a>` : ""}</td>
      <td>${lead.sales_nav_url ? `<a href="${lead.sales_nav_url}" target="_blank">SalesNav</a>` : ""}</td>
      <td>${lead.automation_status || ""}</td>
    `;
    tbody.appendChild(tr);
  }
}

async function downloadExcel() {
  // We’ll fetch with Authorization, then create a blob download
  const r = await fetch("/download-leads-excel", {
    headers: { Authorization: "Bearer " + token },
  });
  if (!r.ok) {
    const txt = await r.text();
    throw new Error(`Download failed: ${txt || r.status}`);
  }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const who = (emailCache || "me").split("@")[0];
  a.download = `linqbridge_leads_${who}_${Date.now()}.xlsx`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function logout() {
  token = null;
  emailCache = null;
  localStorage.removeItem("linqbridge_token");
  localStorage.removeItem("linqbridge_email");
  show(el("app"), false);
  show(el("auth-card"), true);
  switchTab("login");
}

// UI events
el("login-btn").addEventListener("click", async () => {
  const email = el("login-email").value.trim();
  const pass = el("login-password").value;
  setMsg(el("auth-msg"), "Logging in…");
  try {
    await login(email, pass);
    setMsg(el("auth-msg"), "");
    show(el("auth-card"), false);
    show(el("app"), true);
    el("whoami").textContent = emailCache;
    setMsg(el("app-msg"), "Loading leads…");
    const leads = await fetchLeads();
    renderLeads(leads);
    setMsg(el("app-msg"), `Loaded ${leads.length} lead(s).`);
  } catch (e) {
    setMsg(el("auth-msg"), e.message, true);
  }
});

el("register-btn").addEventListener("click", async () => {
  const email = el("reg-email").value.trim();
  const p1 = el("reg-password").value;
  const p2 = el("reg-password2").value;
  if (!email || !p1)
    return setMsg(el("auth-msg"), "Email & password required", true);
  if (p1 !== p2) return setMsg(el("auth-msg"), "Passwords do not match", true);

  setMsg(el("auth-msg"), "Creating account…");
  try {
    await register(email, p1);
    setMsg(el("auth-msg"), "Account created. You can log in now.");
    switchTab("login");
    el("login-email").value = email;
    el("login-password").focus();
  } catch (e) {
    setMsg(el("auth-msg"), e.message, true);
  }
});

el("reload-btn").addEventListener("click", async () => {
  try {
    setMsg(el("app-msg"), "Refreshing…");
    const leads = await fetchLeads();
    renderLeads(leads);
    setMsg(el("app-msg"), `Loaded ${leads.length} lead(s).`);
  } catch (e) {
    setMsg(el("app-msg"), e.message, true);
  }
});

el("download-btn").addEventListener("click", async () => {
  try {
    setMsg(el("app-msg"), "Preparing download…");
    await downloadExcel();
    setMsg(el("app-msg"), "Download started.");
  } catch (e) {
    setMsg(el("app-msg"), e.message, true);
  }
});

el("logout-btn").addEventListener("click", logout);

// Auto-log in if token exists
(async function boot() {
  if (token) {
    try {
      show(el("auth-card"), false);
      show(el("app"), true);
      el("whoami").textContent = emailCache || "";
      setMsg(el("app-msg"), "Loading leads…");
      const leads = await fetchLeads();
      renderLeads(leads);
      setMsg(el("app-msg"), `Loaded ${leads.length} lead(s).`);
    } catch (e) {
      // token likely invalid/expired
      logout();
    }
  }
})();
