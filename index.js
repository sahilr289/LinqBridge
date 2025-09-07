// index.js — LinqBridge backend (FINAL with RapidAPI person-resolution + Sprouts-mode)

const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const path = require("path");
const ExcelJS = require("exceljs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs-extra");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
require("dotenv").config();

// --- Server ---
const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key_change_this_for_prod";
const ENC_SECRET = process.env.ENC_SECRET || "change_me_32+chars_in_prod";

// --- Optional viewer info for Connect flow ---
const VIEWER_BASE_URL = process.env.VIEWER_BASE_URL || "";     // e.g. https://linqbridge-worker-xxxx.up.railway.app
const NOVNC_PASSWORD  = process.env.NOVNC_PASSWORD  || "changeme123";

// --- RapidAPI config ---
const RAPIDAPI_KEY = process.env.RAPIDAPI_KEY || ""; // <<< set this in Railway
const RAPIDAPI_HOST = process.env.RAPIDAPI_HOST || "linkedin-data-api.p.rapidapi.com"; // rockapis
const RAPIDAPI_STRATEGY = process.env.RAPIDAPI_STRATEGY || "rapidapi-first"; // rapidapi-first | cookies-first
const RAPIDAPI_GEO = process.env.RAPIDAPI_GEO || ""; // e.g. "103644278" (United States). You can put multiple: "103644278,101165590"
const RAPIDAPI_TIMEOUT_MS = parseInt(process.env.RAPIDAPI_TIMEOUT_MS || "10000", 10);
const RAPIDAPI_DEBUG = /^(1|true|yes)$/i.test(process.env.RAPIDAPI_DEBUG || "0");

// --- File-backed Job Queue ---
const DATA_DIR = path.join(__dirname, "data");
const JOBS_FILE = path.join(DATA_DIR, "jobs.json");

(async () => {
  await fs.ensureDir(DATA_DIR);
  if (!(await fs.pathExists(JOBS_FILE))) {
    await fs.writeJson(JOBS_FILE, { queued: [], active: [], done: [], failed: [] }, { spaces: 2 });
  }
})();
async function readJobs() { return fs.readJson(JOBS_FILE); }
async function writeJobs(d) { return fs.writeJson(JOBS_FILE, d, { spaces: 2 }); }

// Helper: find job by id across all queues
async function findJobById(id) {
  const d = await readJobs();
  const pools = ["queued", "active", "done", "failed"];
  for (const p of pools) {
    const i = d[p].findIndex(j => j.id === id);
    if (i !== -1) return { pool: p, index: i, job: d[p][i] };
  }
  return null;
}

// --- Worker-only Auth ---
function requireWorkerAuth(req, res, next) {
  const header = req.get("x-worker-secret");
  if (!header || header !== process.env.WORKER_SHARED_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// --- Middleware ---
app.use(express.json({ limit: "50mb" }));
app.use(express.static("public"));

// CORS: allow extension + Railway + localhost
const ALLOWED_ORIGINS = new Set([
  "chrome-extension://mhfjpfanjgflnflifenhoejbfjecleen",
  "http://localhost:3000",
  "http://localhost:8080",
  "https://calm-rejoicing-linqbridge.up.railway.app",
]);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.has(origin)) return cb(null, true); // allow curl/postman (no origin)
    return cb(new Error(`Origin ${origin} not allowed by CORS`));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-worker-secret"],
  credentials: false,
}));
app.options("*", cors());

// --- DB ---
const dbPath = path.join(__dirname, "linqbridge.db");
const LOG_SQL = (/^(true|1|yes)$/i).test(process.env.LOG_SQL || "false");
const db = new Database(dbPath, LOG_SQL ? { verbose: console.log } : {});

function initializeDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS leads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL,
      first_name TEXT,
      last_name TEXT,
      profile_url TEXT,
      public_profile_url TEXT,
      sales_nav_url TEXT,
      organization TEXT,
      title TEXT,
      timestamp TEXT NOT NULL,
      scraped_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      automation_status TEXT DEFAULT 'scraped',
      last_action_timestamp DATETIME,
      next_action_due_date DATETIME,
      connection_note TEXT,
      followup_1_message TEXT,
      followup_2_message TEXT,
      followup_3_message TEXT,
      liked_post_url TEXT
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS message_templates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL,
      type TEXT NOT NULL,
      name TEXT NOT NULL,
      content TEXT NOT NULL,
      UNIQUE(user_email, name)
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS cookies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      li_at TEXT NOT NULL,
      jsessionid TEXT,
      bcookie TEXT,
      timestamp TEXT
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS connection_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL,
      level TEXT NOT NULL,      -- info | warn | error
      event TEXT NOT NULL,      -- cookies_saved | status_soft_ok | status_live_ok | status_fail
      details TEXT,             
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // NEW: account_settings for Sprouts-mode
  db.exec(`
    CREATE TABLE IF NOT EXISTS account_settings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      li_username_enc TEXT,
      li_password_enc TEXT,
      totp_secret_enc TEXT,
      proxy_server TEXT,
      proxy_username_enc TEXT,
      proxy_password_enc TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_leads_unique_public
    ON leads(user_email, public_profile_url)
    WHERE public_profile_url IS NOT NULL;
  `);

  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_leads_unique_legacy
    ON leads(user_email, profile_url)
    WHERE profile_url IS NOT NULL;
  `);

  console.log("Database initialized.");
}
initializeDatabase();

// --- Crypto helpers for stored secrets ---
const ENC_ALGO = "aes-256-gcm";
function enc(plain) {
  if (!plain) return null;
  const iv = crypto.randomBytes(12);
  const key = crypto.createHash("sha256").update(ENC_SECRET).digest();
  const cipher = crypto.createCipheriv(ENC_ALGO, key, iv);
  const encd = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encd]).toString("base64");
}
function dec(blob) {
  if (!blob) return null;
  const raw = Buffer.from(blob, "base64");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const data = raw.subarray(28);
  const key = crypto.createHash("sha256").update(ENC_SECRET).digest();
  const decipher = crypto.createDecipheriv(ENC_ALGO, key, iv);
  decipher.setAuthTag(tag);
  const decd = Buffer.concat([decipher.update(data), decipher.final()]);
  return decd.toString("utf8");
}

// --- Misc helpers ---
async function safeText(res) { try { return await res.text(); } catch { return ""; } }
function logConn(email, level, event, detailsObj) {
  try {
    db.prepare(`INSERT INTO connection_logs (user_email, level, event, details) VALUES (?, ?, ?, ?)`)
      .run(email, level, event, detailsObj ? JSON.stringify(detailsObj) : null);
  } catch (e) {
    console.warn("logConn error:", e.message);
  }
}
function getLatestLiAtForUser(email) {
  try {
    const row = db.prepare("SELECT li_at FROM cookies WHERE email = ? ORDER BY id DESC LIMIT 1").get(email);
    return row?.li_at || null;
  } catch (e) {
    console.error("getLatestLiAtForUser error:", e);
    return null;
  }
}
function extractFsSalesProfileId(salesNavUrl = "") {
  const m = salesNavUrl.match(/fs_salesProfile:(\d+)/) || salesNavUrl.match(/fs_salesProfile:\((\d+)\)/);
  return m ? m[1] : null;
}
function derivePublicFromSalesNav(salesNavUrl) {
  if (!salesNavUrl) return null;
  const m = salesNavUrl.match(/\/sales\/lead\/([^,\/\?]+)/i);
  if (m && m[1]) return `https://www.linkedin.com/in/${m[1]}`;
  return null;
}

// Try LinkedIn Sales API (with cookies)
async function resolveSalesNavToPublicUrl(salesNavUrl, liAtCookie) {
  if (!salesNavUrl || !liAtCookie) return null;
  const profileId = extractFsSalesProfileId(salesNavUrl);
  if (!profileId) return null;

  const apiUrl = `https://www.linkedin.com/sales-api/salesApiProfiles/${profileId}`;
  try {
    const resp = await fetch(apiUrl, {
      method: "GET",
      headers: {
        "accept": "application/json",
        "x-restli-protocol-version": "2.0.0",
        "csrf-token": "ajax:123456789",
        "cookie": `li_at=${liAtCookie};`,
      },
      signal: AbortSignal.timeout ? AbortSignal.timeout(12000) : undefined,
    });
    if (!resp.ok) {
      if (RAPIDAPI_DEBUG) console.warn("resolveSalesNavToPublicUrl non-OK:", resp.status, await safeText(resp));
      return null;
    }
    const data = await (async () => { try { return await resp.json(); } catch { return {}; } })();
    const candidates = [
      data?.profile?.profileUrl,
      data?.publicProfileUrl,
      data?.profile?.publicIdentifier ? `https://www.linkedin.com/in/${data.profile.publicIdentifier}` : null,
    ].filter(Boolean);
    return candidates[0] || null;
  } catch (e) {
    console.error("resolveSalesNavToPublicUrl error:", e);
    return null;
  }
}

// ---------------- RapidAPI helpers ----------------
function norm(s){ return (s||"").toString().toLowerCase().trim().replace(/\s+/g," "); }

function looksLikeNameMatch(item, first, last) {
  const fn = norm(first), ln = norm(last);
  const name = norm(item?.name || item?.fullName || [item?.firstName, item?.lastName].filter(Boolean).join(" "));
  if (!fn && !ln) return false;
  return (fn ? name.includes(fn) : true) && (ln ? name.includes(ln) : true);
}
function looksLikeCompanyMatch(item, company) {
  if (!company) return true;
  const c = norm(company);
  const hay = norm(item?.headline || item?.occupation || item?.title || item?.company || item?.experience?.[0]?.companyName);
  return hay.includes(c) || c.split(" ").some(w => w.length > 3 && hay.includes(w));
}

function extractPublicUrlFromItem(item) {
  // common variants across providers
  const slug =
    item?.publicIdentifier ||
    item?.miniProfile?.publicIdentifier ||
    item?.mini_profile?.public_identifier ||
    null;

  const direct =
    item?.publicProfileUrl ||
    item?.public_profile_url ||
    item?.profileUrl ||
    item?.url ||
    item?.link ||
    null;

  if (slug && /^[-a-zA-Z0-9_\.%]+$/.test(slug)) {
    return `https://www.linkedin.com/in/${slug}`;
  }
  if (direct && /linkedin\.com\/in\//i.test(direct)) {
    return direct.startsWith("http") ? direct : `https://${direct}`;
  }
  return null;
}

async function rapidapiFetch(path, { method = "GET", body } = {}) {
  if (!RAPIDAPI_KEY) return { ok: false, status: 0, error: "No RAPIDAPI_KEY set", json: null, text: "" };

  const url = `https://${RAPIDAPI_HOST}${path}`;
  try {
    const resp = await fetch(url, {
      method,
      headers: {
        "x-rapidapi-key": RAPIDAPI_KEY,
        "x-rapidapi-host": RAPIDAPI_HOST,
        ...(body ? { "Content-Type": "application/json" } : {})
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout ? AbortSignal.timeout(RAPIDAPI_TIMEOUT_MS) : undefined
    });

    const text = await safeText(resp);
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* leave json null */ }

    if (RAPIDAPI_DEBUG) {
      console.log("[RapidAPI]", method, url, "->", resp.status, text?.slice(0, 400));
    }

    return { ok: resp.ok, status: resp.status, json, text };
  } catch (e) {
    if (RAPIDAPI_DEBUG) console.warn("[RapidAPI] network error", e.message);
    return { ok: false, status: 0, error: e.message, json: null, text: "" };
  }
}

function buildKeywordQuery(first, last, company) {
  const parts = [first, last, company].filter(Boolean).join(" ").trim();
  return encodeURIComponent(parts);
}

function buildLinkedInSearchUrl(first, last, company) {
  const kw = encodeURIComponent([first, last, company].filter(Boolean).join(" ").trim());
  // Can add currentCompany facet if you know company ID; we're keywording for portability.
  return `https://www.linkedin.com/search/results/people/?keywords=${kw}&origin=FACETED_SEARCH`;
}

// GET /search-people
async function rapidapiSearchPeople(keywords) {
  const params = new URLSearchParams({ keywords, start: "0" });
  if (RAPIDAPI_GEO) params.set("geo", RAPIDAPI_GEO);
  // Some vendors ignore unknown params, but avoid 'count' unless documented
  return rapidapiFetch(`/search-people?${params.toString()}`, { method: "GET" });
}

// POST /search-people-by-url
async function rapidapiSearchPeopleByUrl(searchUrl) {
  return rapidapiFetch(`/search-people-by-url`, {
    method: "POST",
    body: { url: searchUrl }
  });
}

function flattenCandidates(json) {
  if (!json) return [];
  const a = [];
  // Common shapes seen across RapidAPI “LinkedIn” providers
  const roots = [
    json.data, json.results, json.list, json.items, json.profiles, json.people, json
  ].filter(Boolean);
  for (const r of roots) {
    if (Array.isArray(r)) a.push(...r);
    else if (Array.isArray(r?.data)) a.push(...r.data);
    else if (Array.isArray(r?.results)) a.push(...r.results);
  }
  return a;
}

async function rapidapiFindPublicUrlByName({ first, last, company }) {
  if (!RAPIDAPI_KEY) return null;

  const keywords = buildKeywordQuery(first, last, company);
  // 1) Try search-people (with optional geo)
  const r1 = await rapidapiSearchPeople(keywords);
  if (r1.ok) {
    const items = flattenCandidates(r1.json);
    for (const it of items) {
      const url = extractPublicUrlFromItem(it);
      if (url && looksLikeNameMatch(it, first, last) && looksLikeCompanyMatch(it, company)) {
        return url;
      }
    }
  }

  // 2) Fall back: craft LinkedIn search URL and POST /search-people-by-url
  const liSearch = buildLinkedInSearchUrl(first, last, company);
  const r2 = await rapidapiSearchPeopleByUrl(liSearch);
  if (r2.ok) {
    const items = flattenCandidates(r2.json);
    for (const it of items) {
      const url = extractPublicUrlFromItem(it);
      if (url && looksLikeNameMatch(it, first, last) && looksLikeCompanyMatch(it, company)) {
        return url;
      }
    }
  }

  // 3) Nothing found
  return null;
}

// ---------------- Auth Middleware ----------------
function authenticateToken(req, res, next) {
  const auth = req.headers["authorization"];
  const token = auth && auth.split(" ")[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user; // { email }
    next();
  });
}

// ---------------- Auth Endpoints ----------------
app.post("/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ success: false, message: "Email and password are required." });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const info = db.prepare("INSERT INTO users (email, password) VALUES (?, ?)").run(email, hashed);
    if (info.changes > 0) return res.status(201).json({ success: true, message: "User registered successfully." });
    return res.status(409).json({ success: false, message: "User with this email already exists." });
  } catch (e) {
    console.error("Register error:", e);
    return res.status(500).json({ success: false, message: "Internal server error during registration." });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ success: false, message: "Email and password are required." });
  try {
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user) return res.status(401).json({ success: false, message: "Invalid credentials." });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ success: false, message: "Invalid credentials." });
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: "24h" });
    return res.status(200).json({ success: true, message: "Logged in successfully.", token, userEmail: user.email });
  } catch (e) {
    console.error("Login error:", e);
    return res.status(500).json({ success: false, message: "Internal server error during login." });
  }
});

// ---------------- Job Queue Endpoints ----------------
app.post("/jobs", async (req, res) => {
  try {
    const { type, payload, priority = 5 } = req.body || {};
    if (!type) return res.status(400).json({ error: "Missing job 'type'." });
    const job = {
      id: uuidv4(),
      type,
      payload: payload || {},
      priority,
      status: "queued",
      enqueuedAt: new Date().toISOString(),
      attempts: 0,
      lastError: null,
    };
    const d = await readJobs();
    d.queued.push(job);
    d.queued.sort((a, b) => a.priority - b.priority);
    await writeJobs(d);
    res.json({ ok: true, job });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to enqueue." });
  }
});

app.get("/jobs/:id", async (req, res) => {
  try {
    const found = await findJobById(req.params.id);
    if (!found) return res.status(404).json({ error: "Job not found" });
    res.json({ ok: true, job: found.job, pool: found.pool });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to get job." });
  }
});

app.post("/jobs/next", requireWorkerAuth, async (req, res) => {
  try {
    const { types } = req.body || {};
    const d = await readJobs();
    let idx = -1;
    if (Array.isArray(types) && types.length) {
      idx = d.queued.findIndex(j => types.includes(j.type));
    } else {
      idx = d.queued.length ? 0 : -1;
    }
    if (idx === -1) return res.json({ ok: true, job: null });
    const job = d.queued.splice(idx, 1)[0];
    job.status = "active";
    job.attempts += 1;
    job.startedAt = new Date().toISOString();
    d.active.push(job);
    await writeJobs(d);
    res.json({ ok: true, job });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to fetch next job." });
  }
});

app.post("/jobs/:id/complete", requireWorkerAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { result } = req.body || {};
    const d = await readJobs();
    const i = d.active.findIndex(j => j.id === id);
    if (i === -1) return res.status(404).json({ error: "Active job not found" });
    const job = d.active.splice(i, 1)[0];
    job.status = "done";
    job.completedAt = new Date().toISOString();
    job.result = result ?? null;
    d.done.push(job);
    await writeJobs(d);
    res.json({ ok: true, job });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to complete job." });
  }
});

app.post("/jobs/:id/fail", requireWorkerAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { error, requeue = false, delayMs = 0 } = req.body || {};
    const d = await readJobs();
    const i = d.active.findIndex(j => j.id === id);
    if (i === -1) return res.status(404).json({ error: "Active job not found" });
    const job = d.active.splice(i, 1)[0];
    job.status = "failed";
    job.lastError = error || "Unknown";
    job.failedAt = new Date().toISOString();
    if (requeue) {
      job.status = "queued";
      delete job.startedAt;
      if (delayMs > 0) {
        setTimeout(async () => {
          const d2 = await readJobs();
          d2.queued.push(job);
          d2.queued.sort((a, b) => a.priority - b.priority);
          await writeJobs(d2);
        }, delayMs);
      } else {
        d.queued.push(job);
        d.queued.sort((a, b) => a.priority - b.priority);
      }
    } else {
      d.failed.push(job);
    }
    await writeJobs(d);
    res.json({ ok: true, job });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to fail job." });
  }
});

app.get("/jobs/stats", async (_req, res) => {
  const d = await readJobs();
  res.json({ counts: { queued: d.queued.length, active: d.active.length, done: d.done.length, failed: d.failed.length } });
});

// ---------------- Cookies from extension ----------------
app.post("/store-cookies", (req, res) => {
  try {
    const body = req.body || {};
    const email = body.userEmail || body.email;
    const cookies = body.cookies || {};
    const timestamp = body.timestamp || new Date().toISOString();
    if (!email || !cookies.li_at) {
      return res.status(400).json({ success: false, message: "Missing email or li_at cookie." });
    }
    db.prepare(`
      INSERT INTO cookies (email, li_at, jsessionid, bcookie, timestamp)
      VALUES (?, ?, ?, ?, ?)
    `).run(email, cookies.li_at, cookies.JSESSIONID || null, cookies.bcookie || null, timestamp);

    logConn(email, "info", "cookies_saved", {
      has_li_at: !!cookies.li_at,
      has_jsessionid: !!cookies.JSESSIONID,
      has_bcookie: !!cookies.bcookie
    });

    return res.json({ success: true, message: "Cookies stored successfully." });
  } catch (e) {
    console.error("store-cookies error:", e);
    return res.status(500).json({ success: false, message: "Internal server error while storing cookies." });
  }
});

app.get("/api/me/liat", authenticateToken, (req, res) => {
  try {
    const row = db.prepare("SELECT li_at FROM cookies WHERE email = ? ORDER BY id DESC LIMIT 1").get(req.user.email);
    if (!row?.li_at) return res.status(404).json({ success: false, message: "No li_at found for user." });
    return res.json({ success: true, li_at: row.li_at });
  } catch (e) {
    console.error("liat error:", e);
    return res.status(500).json({ success: false, message: "Internal server error." });
  }
});

// ---------------- Messaging/Connection jobs ----------------
app.post("/jobs/enqueue-send-connection", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const { profileUrl, note = null, priority = 3 } = req.body || {};
    if (!profileUrl) return res.status(400).json({ error: "profileUrl required" });

    const row = db.prepare(
      "SELECT li_at, jsessionid, bcookie FROM cookies WHERE email = ? ORDER BY id DESC LIMIT 1"
    ).get(email);

    const cookieBundle = row?.li_at ? { li_at: row.li_at, jsessionid: row.jsessionid || null, bcookie: row.bcookie || null } : null;

    const d = await readJobs();
    const job = {
      id: uuidv4(),
      type: "SEND_CONNECTION",
      payload: {
        tenantId: "default",
        userId: email,
        profileUrl,
        note,
        cookieBundle // may be null; worker can still login with creds+totp
      },
      priority,
      status: "queued",
      enqueuedAt: new Date().toISOString(),
      attempts: 0,
      lastError: null,
    };
    d.queued.push(job);
    d.queued.sort((a, b) => a.priority - b.priority);
    await writeJobs(d);
    res.json({ ok: true, job });
  } catch (e) {
    console.error("enqueue-send-connection error:", e);
    res.status(500).json({ error: "Failed to enqueue" });
  }
});

app.post("/jobs/enqueue-send-message", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const { profileUrl, message, priority = 3 } = req.body || {};
    if (!profileUrl) return res.status(400).json({ error: "profileUrl required" });
    if (!message)   return res.status(400).json({ error: "message required" });

    const row = db.prepare(
      "SELECT li_at, jsessionid, bcookie FROM cookies WHERE email = ? ORDER BY id DESC LIMIT 1"
    ).get(email);

    const cookieBundle = row?.li_at ? { li_at: row.li_at, jsessionid: row.jsessionid || null, bcookie: row.bcookie || null } : null;

    const d = await readJobs();
    const job = {
      id: uuidv4(),
      type: "SEND_MESSAGE",
      payload: {
        tenantId: "default",
        userId: email,
        profileUrl,
        message,
        cookieBundle
      },
      priority,
      status: "queued",
      enqueuedAt: new Date().toISOString(),
      attempts: 0,
      lastError: null,
    };
    d.queued.push(job);
    d.queued.sort((a, b) => a.priority - b.priority);
    await writeJobs(d);
    res.json({ ok: true, job });
  } catch (e) {
    console.error("enqueue-send-message error:", e);
    res.status(500).json({ error: "Failed to enqueue" });
  }
});

// ---------------- Leads upload (now with RapidAPI enrichment) ----------------
app.post("/upload-leads", async (req, res) => {
  if (process.env.LOG_UPLOADS === "true") console.log("Received /upload-leads");
  const { leads, timestamp } = req.body || {};
  const userEmail = req.body.userEmail || req.body.email;
  if (!userEmail || !Array.isArray(leads) || leads.length === 0) {
    return res.status(400).json({ success: false, message: "Missing userEmail or leads." });
  }

  const liAt = getLatestLiAtForUser(userEmail);
  if (!liAt) console.warn("[upload-leads] No li_at stored for", userEmail, "- will rely on RapidAPI/fallbacks.");

  const insertLeadSql = `
    INSERT OR IGNORE INTO leads
      (user_email, first_name, last_name, profile_url, public_profile_url, sales_nav_url,
       organization, title, timestamp, automation_status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
  `;
  const insertStmt = db.prepare(insertLeadSql);

  let inserted = 0, skipped = 0;

  const CONCURRENCY = 4;
  const queue = [...leads];
  const workers = [];

  async function processOne(rawLead) {
    try {
      const firstName = rawLead.first_name || null;
      const lastName  = rawLead.last_name || null;
      const organization = rawLead.company || rawLead.organization || null;
      const title = rawLead.title || null;

      let publicUrl = (rawLead.public_linkedin_url && rawLead.public_linkedin_url !== "N/A")
        ? rawLead.public_linkedin_url
        : null;

      let salesNavUrl =
        (rawLead.sales_nav_url && rawLead.sales_nav_url !== "N/A")
          ? rawLead.sales_nav_url
          : (rawLead.profile_url || null);

      const profileUrlLegacy = rawLead.profile_url || null;

      // Resolution order controlled by RAPIDAPI_STRATEGY
      const tryRapidFirst = RAPIDAPI_STRATEGY === "rapidapi-first";

      async function tryRapid() {
        if (!publicUrl) {
          publicUrl = await rapidapiFindPublicUrlByName({
            first: firstName,
            last: lastName,
            company: organization
          });
        }
      }
      async function tryCookies() {
        if (!publicUrl && salesNavUrl && liAt) {
          publicUrl = await resolveSalesNavToPublicUrl(salesNavUrl, liAt);
        }
        if (!publicUrl && salesNavUrl && salesNavUrl.includes("/sales/lead/")) {
          publicUrl = derivePublicFromSalesNav(salesNavUrl);
        }
      }

      if (tryRapidFirst) {
        await tryRapid();
        await tryCookies();
      } else {
        await tryCookies();
        await tryRapid();
      }

      const public_profile_url_to_store = publicUrl || null;

      // Require at least one URL to store (public, legacy, or sales nav)
      if (!public_profile_url_to_store && !profileUrlLegacy && !salesNavUrl) { skipped++; return; }

      const info = insertStmt.run(
        userEmail, firstName, lastName, profileUrlLegacy, public_profile_url_to_store, salesNavUrl,
        organization, title, timestamp || new Date().toISOString(), "scraped"
      );
      if (info.changes > 0) inserted++; else skipped++;
    } catch (e) {
      if (RAPIDAPI_DEBUG) console.warn("[upload-leads] processOne error", e.message);
      skipped++;
    }
  }

  for (let w = 0; w < Math.min(CONCURRENCY, queue.length); w++) {
    workers.push((async function runWorker() {
      while (queue.length) {
        const next = queue.shift();
        await processOne(next);
      }
    })());
  }
  await Promise.all(workers);

  return res.status(200).json({
    success: true,
    message: "Leads processed and saved successfully!",
    received: leads.length,
    inserted,
    skipped_duplicates: skipped,
    user_email: userEmail,
  });
});

// ---------------- Leads / Excel / Automation ----------------
app.get("/api/leads", authenticateToken, (req, res) => {
  try {
    const rows = db.prepare("SELECT * FROM leads WHERE user_email = ? ORDER BY scraped_at DESC").all(req.user.email);
    return res.json({ success: true, leads: rows });
  } catch (e) {
    console.error("api/leads error:", e);
    return res.status(500).json({ success: false, message: "Internal server error fetching leads." });
  }
});

app.get("/download-leads-excel", authenticateToken, async (req, res) => {
  try {
    const rows = db.prepare("SELECT * FROM leads WHERE user_email = ? ORDER BY scraped_at DESC").all(req.user.email);
    if (rows.length === 0) return res.status(404).send(`No leads found for ${req.user.email}.`);

    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet("Leads Data");
    ws.columns = [
      { header: "User Email", key: "user_email", width: 25 },
      { header: "First Name", key: "first_name", width: 20 },
      { header: "Last Name", key: "last_name", width: 20 },
      { header: "Organization", key: "organization", width: 30 },
      { header: "Title", key: "title", width: 30 },
      { header: "Public Profile URL", key: "public_profile_url", width: 50 },
      { header: "Legacy/Profile URL", key: "profile_url", width: 50 },
      { header: "Sales Nav URL", key: "sales_nav_url", width: 50 },
      { header: "Scrape Timestamp (Ext)", key: "timestamp", width: 25 },
      { header: "Saved To DB At", key: "scraped_at", width: 25 },
      { header: "Automation Status", key: "automation_status", width: 20 },
      { header: "Last Action", key: "last_action_timestamp", width: 25 },
      { header: "Next Action Due", key: "next_action_due_date", width: 25 },
      { header: "Connection Note", key: "connection_note", width: 40 },
      { header: "Follow-up 1", key: "followup_1_message", width: 40 },
      { header: "Follow-up 2", key: "followup_2_message", width: 40 },
      { header: "Follow-up 3", key: "followup_3_message", width: 40 },
      { header: "Liked Post URL", key: "liked_post_url", width: 50 },
    ];
    rows.forEach(r => ws.addRow(r));

    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", `attachment; filename=linqbridge_leads_${req.user.email.split("@")[0]}_${Date.now()}.xlsx`);
    await wb.xlsx.write(res);
    res.end();
  } catch (e) {
    console.error("download excel error:", e);
    return res.status(500).send("Internal server error: Could not generate Excel file.");
  }
});

app.get("/api/automation/get-next-leads", authenticateToken, (req, res) => {
  const limit = parseInt(req.query.limit || "1", 10);
  const email = req.user.email;
  try {
    let leads = [];
    db.transaction(() => {
      const sel = db.prepare(`
        SELECT id, COALESCE(public_profile_url, profile_url) AS profile_url,
               first_name, last_name, organization, title, connection_note
        FROM leads
        WHERE user_email = ?
          AND (automation_status = 'scraped' OR automation_status = 'pending_connect')
          AND (next_action_due_date IS NULL OR next_action_due_date <= CURRENT_TIMESTAMP)
        LIMIT ?;
      `);
      leads = sel.all(email, limit);
      if (leads.length > 0) {
        const upd = db.prepare(`
          UPDATE leads
          SET automation_status = 'in_progress',
              last_action_timestamp = CURRENT_TIMESTAMP
          WHERE id = ?;
        `);
        leads.forEach(l => upd.run(l.id));
      }
    })();
    return res.json({ success: true, leads });
  } catch (e) {
    console.error("get-next-leads error:", e);
    return res.status(500).json({ success: false, message: "Internal server error getting leads." });
  }
});

app.get("/api/automation/runner/tick", authenticateToken, (req, res) => {
  try {
    const sel = db.prepare(`
      SELECT id, COALESCE(public_profile_url, profile_url) AS profile_url,
             first_name, last_name, organization, title, connection_note
      FROM leads
      WHERE user_email = ?
        AND (automation_status = 'scraped' OR automation_status = 'pending_connect')
        AND (next_action_due_date IS NULL OR next_action_due_date <= CURRENT_TIMESTAMP)
      LIMIT 1;
    `);
    const lead = sel.get(req.user.email);
    if (!lead) return res.json({ success: true, leads: [] });

    db.prepare(`
      UPDATE leads
      SET automation_status = 'in_progress',
          last_action_timestamp = CURRENT_TIMESTAMP
      WHERE id = ?;
    `).run(lead.id);

    return res.json({ success: true, leads: [lead] });
  } catch (e) {
    console.error("runner/tick error:", e);
    return res.status(500).json({ success: false, message: "Internal server error." });
  }
});

app.post("/api/automation/update-status", authenticateToken, (req, res) => {
  const { lead_id, status, action_details = {} } = req.body || {};
  const email = req.user.email;
  if (!lead_id || !status) return res.status(400).json({ success: false, message: "Missing lead_id or status." });

  let setClauses = [`automation_status = ?`, `last_action_timestamp = CURRENT_TIMESTAMP`];
  const params = [status];

  let nextActionDate = null;
  switch (status) {
    case "connection_sent":
      nextActionDate = new Date(Date.now() + (Math.random() * (5 - 3) + 3) * 86400000).toISOString();
      if (action_details.connection_note_sent) { setClauses.push(`connection_note = ?`); params.push(action_details.connection_note_sent); }
      break;
    case "accepted":
      nextActionDate = new Date(Date.now() + (Math.random() * (2 - 1) + 1) * 3600000).toISOString();
      break;
    case "msg1_sent":
    case "msg2_sent":
      nextActionDate = new Date(Date.now() + (Math.random() * (7 - 4) + 4) * 86400000).toISOString();
      break;
    case "replied":
    case "skipped":
    case "error":
      nextActionDate = null;
      break;
    case "profile_viewed":
      nextActionDate = new Date(Date.now() + (Math.random() * (24 - 12) + 12) * 3600000).toISOString();
      break;
  }

  if (nextActionDate) { setClauses.push(`next_action_due_date = ?`); params.push(nextActionDate); }
  else { setClauses.push(`next_action_due_date = NULL`); }

  if (action_details.liked_post_url) { setClauses.push(`liked_post_url = ?`); params.push(action_details.liked_post_url); }

  const sql = `UPDATE leads SET ${setClauses.join(", ")} WHERE id = ? AND user_email = ?;`;
  params.push(lead_id, email);

  try {
    const info = db.prepare(sql).run(...params);
    if (info.changes > 0) return res.json({ success: true, message: "Lead status updated successfully." });
    return res.status(404).json({ success: false, message: "Lead not found or not authorized." });
  } catch (e) {
    console.error("update-status error:", e);
    return res.status(500).json({ success: false, message: "Internal server error updating lead status." });
  }
});

// ---------------- Connection status & logs ----------------
const LIVE_CHECK_COOLDOWN_MS = 10 * 60 * 1000;

app.get("/api/connection/check", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const wantLive = req.query.live === "1";

    const row = db.prepare(
      "SELECT li_at, jsessionid, bcookie FROM cookies WHERE email = ? ORDER BY id DESC LIMIT 1"
    ).get(email);

    if (!row?.li_at) {
      logConn(email, "warn", "status_fail", { reason: "no_li_at" });
      return res.json({
        connected: false,
        mode: "none",
        reason: "No li_at cookie on server. Capture cookies from the extension."
      });
    }

    if (!wantLive) {
      logConn(email, "info", "status_soft_ok", {
        has_li_at: true,
        has_jsessionid: !!row.jsessionid,
        has_bcookie: !!row.bcookie
      });
      return res.json({
        connected: "stored",
        mode: "soft",
        hint: "Click Verify in the dashboard to run a live check."
      });
    }

    const last = db.prepare(`
      SELECT created_at FROM connection_logs
      WHERE user_email = ? AND event = 'status_live_ok'
      ORDER BY id DESC LIMIT 1
    `).get(email);
    const lastTime = last ? new Date(last.created_at).getTime() : 0;
    if (Date.now() - lastTime < LIVE_CHECK_COOLDOWN_MS) {
      const msLeft = LIVE_CHECK_COOLDOWN_MS - (Date.now() - lastTime);
      return res.json({ connected: "stored", mode: "cooldown", cooldownMs: msLeft });
    }

    const js = (row.jsessionid || "").replace(/^"|"$/g, "");
    const csrf = js || "ajax:123456789";
    const cookieHeader = [
      `li_at=${row.li_at}`,
      js ? `JSESSIONID="${js}"` : null,
      row.bcookie ? `bcookie=${row.bcookie}` : null
    ].filter(Boolean).join("; ");

    const url = "https://www.linkedin.com/voyager/api/me";
    try {
      const resp = await fetch(url, {
        method: "GET",
        headers: {
          "accept": "application/json",
          "csrf-token": csrf,
          "cookie": cookieHeader,
          "accept-language": "en-US,en;q=0.9",
          "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        },
        signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined
      });

      if (!resp.ok) {
        const body = await safeText(resp);
        logConn(email, "warn", "status_fail", { http: resp.status, body: body?.slice(0, 200) });
        return res.json({ connected: false, mode: "live", reason: `HTTP ${resp.status}` });
      }

      const data = await (async () => { try { return await resp.json(); } catch { return {}; } })();
      const name =
        data?.miniProfile?.firstName && data?.miniProfile?.lastName
          ? `${data.miniProfile.firstName} ${data.miniProfile.lastName}`
          : (data?.firstName && data?.lastName ? `${data.firstName} ${data.lastName}` : null);

      logConn(email, "info", "status_live_ok", { name: name || null });
      return res.json({ connected: true, mode: "live", name: name || null });

    } catch (e) {
      logConn(email, "error", "status_fail", { error: e.message });
      return res.json({ connected: false, mode: "live", reason: "network_error" });
    }
  } catch (e) {
    console.error("/api/connection/check error:", e);
    return res.status(500).json({ connected: false, mode: "server", reason: "server_error" });
  }
});

app.get("/api/connection/logs", authenticateToken, (req, res) => {
  const email = req.user.email;
  const limit = Math.min(parseInt(req.query.limit || "25", 10), 100);
  try {
    const rows = db.prepare(`
      SELECT level, event, details, created_at
      FROM connection_logs
      WHERE user_email = ?
      ORDER BY id DESC
      LIMIT ?;
    `).all(email, limit);
    const logs = rows.map(r => ({
      level: r.level,
      event: r.event,
      details: (() => { try { return JSON.parse(r.details); } catch { return r.details; } })(),
      at: r.created_at,
    }));
    res.json({ success: true, logs });
  } catch (e) {
    console.error("/api/connection/logs error:", e);
    res.status(500).json({ success: false, logs: [] });
  }
});

// ---------------- Connect flow endpoints ----------------
app.post("/api/connect/start", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    // Enqueue AUTH_CHECK for this user. Worker will save storageState per userId=email.
    const d = await readJobs();
    const job = {
      id: uuidv4(),
      type: "AUTH_CHECK",
      payload: { tenantId: "default", userId: email },
      priority: 1,
      status: "queued",
      enqueuedAt: new Date().toISOString(),
      attempts: 0,
      lastError: null,
    };
    d.queued.push(job);
    d.queued.sort((a, b) => a.priority - b.priority);
    await writeJobs(d);

    // Compose viewer URL if configured
    const viewerUrl = VIEWER_BASE_URL
      ? `${VIEWER_BASE_URL.replace(/\/+$/,"")}/vnc_lite.html?autoconnect=1&view_only=0&password=${encodeURIComponent(NOVNC_PASSWORD)}`
      : null;

    return res.json({ ok: true, jobId: job.id, viewerUrl });
  } catch (e) {
    console.error("/api/connect/start error:", e);
    return res.status(500).json({ ok: false, error: "Failed to start connect" });
  }
});

app.get("/api/connect/status/:jobId", authenticateToken, async (req, res) => {
  try {
    const item = await findJobById(req.params.jobId);
    if (!item) return res.status(404).json({ ok: false, error: "Job not found" });
    return res.json({ ok: true, job: item.job, pool: item.pool });
  } catch (e) {
    console.error("/api/connect/status error:", e);
    return res.status(500).json({ ok: false, error: "Failed to fetch status" });
  }
});

app.post("/api/connect/test", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const d = await readJobs();
    const job = {
      id: uuidv4(),
      type: "AUTH_CHECK",
      payload: { tenantId: "default", userId: email },
      priority: 2,
      status: "queued",
      enqueuedAt: new Date().toISOString(),
      attempts: 0,
      lastError: null,
    };
    d.queued.push(job);
    d.queued.sort((a, b) => a.priority - b.priority);
    await writeJobs(d);
    return res.json({ ok: true, jobId: job.id });
  } catch (e) {
    console.error("/api/connect/test error:", e);
    return res.status(500).json({ ok: false, error: "Failed to enqueue test" });
  }
});

// ---------------- Account settings (Sprouts-mode) ----------------
app.post("/api/account/creds", authenticateToken, (req, res) => {
  const email = req.user.email;
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ ok: false, error: "username and password required" });

  const up = db.prepare(`
    INSERT INTO account_settings (email, li_username_enc, li_password_enc, updated_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(email) DO UPDATE SET
      li_username_enc=excluded.li_username_enc,
      li_password_enc=excluded.li_password_enc,
      updated_at=CURRENT_TIMESTAMP
  `);
  up.run(email, enc(username), enc(password));
  res.json({ ok: true });
});

app.post("/api/account/totp", authenticateToken, (req, res) => {
  const email = req.user.email;
  const { totpSecret } = req.body || {};
  if (!totpSecret) return res.status(400).json({ ok: false, error: "totpSecret required" });

  const up = db.prepare(`
    INSERT INTO account_settings (email, totp_secret_enc, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(email) DO UPDATE SET
      totp_secret_enc=excluded.totp_secret_enc,
      updated_at=CURRENT_TIMESTAMP
  `);
  up.run(email, enc(totpSecret));
  res.json({ ok: true });
});

app.post("/api/account/proxy", authenticateToken, (req, res) => {
  const email = req.user.email;
  const { server, username, password } = req.body || {};
  const up = db.prepare(`
    INSERT INTO account_settings (email, proxy_server, proxy_username_enc, proxy_password_enc, updated_at)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(email) DO UPDATE SET
      proxy_server=excluded.proxy_server,
      proxy_username_enc=excluded.proxy_username_enc,
      proxy_password_enc=excluded.proxy_password_enc,
      updated_at=CURRENT_TIMESTAMP
  `);
  up.run(email, server || null, username ? enc(username) : null, password ? enc(password) : null);
  res.json({ ok: true });
});

app.get("/api/account/settings", authenticateToken, (req, res) => {
  const email = req.user.email;
  const row = db.prepare("SELECT * FROM account_settings WHERE email = ?").get(email) || {};
  res.json({
    ok: true,
    settings: {
      username: row.li_username_enc ? "saved" : null,
      password: row.li_password_enc ? "saved" : null,
      totp:     row.totp_secret_enc ? "saved" : null,
      proxy: {
        server: row.proxy_server || null,
        username: row.proxy_username_enc ? "saved" : null,
        password: row.proxy_password_enc ? "saved" : null
      },
      updated_at: row.updated_at || null
    }
  });
});

app.get("/worker/account/settings", requireWorkerAuth, (req, res) => {
  const userId = req.query.userId;
  if (!userId) return res.status(400).json({ ok: false, error: "userId required" });
  const row = db.prepare("SELECT * FROM account_settings WHERE email = ?").get(userId);
  if (!row) return res.json({ ok: true, settings: null });
  res.json({
    ok: true,
    settings: {
      username: row.li_username_enc ? dec(row.li_username_enc) : null,
      password: row.li_password_enc ? dec(row.li_password_enc) : null,
      totpSecret: row.totp_secret_enc ? dec(row.totp_secret_enc) : null,
      proxy: {
        server: row.proxy_server || null,
        username: row.proxy_username_enc ? dec(row.proxy_username_enc) : null,
        password: row.proxy_password_enc ? dec(row.proxy_password_enc) : null
      }
    }
  });
});

// ---------------- Dev endpoints (for debugging RapidAPI) ----------------
app.get("/api/dev/rapidapi-test", async (req, res) => {
  const first = req.query.first || "";
  const last = req.query.last || "";
  const company = req.query.company || "";
  const debug = req.query.debug === "1";

  let found = null;
  let steps = [];

  if (!RAPIDAPI_KEY) {
    return res.json({ ok: false, error: "RAPIDAPI_KEY not set on server" });
  }

  // Step 1: search-people
  const kw = buildKeywordQuery(first, last, company);
  const r1 = await rapidapiSearchPeople(kw);
  steps.push({ step: "search-people", status: r1.status, ok: r1.ok, sample: debug ? (r1.text || "").slice(0, 800) : undefined });
  if (r1.ok) {
    const items = flattenCandidates(r1.json);
    for (const it of items) {
      const url = extractPublicUrlFromItem(it);
      if (url && looksLikeNameMatch(it, first, last) && looksLikeCompanyMatch(it, company)) {
        found = url; break;
      }
    }
  }

  // Step 2: search-people-by-url
  if (!found) {
    const liSearch = buildLinkedInSearchUrl(first, last, company);
    const r2 = await rapidapiSearchPeopleByUrl(liSearch);
    steps.push({ step: "search-people-by-url", status: r2.status, ok: r2.ok, sample: debug ? (r2.text || "").slice(0, 800) : undefined, liSearch });
    if (r2.ok) {
      const items = flattenCandidates(r2.json);
      for (const it of items) {
        const url = extractPublicUrlFromItem(it);
        if (url && looksLikeNameMatch(it, first, last) && looksLikeCompanyMatch(it, company)) {
          found = url; break;
        }
      }
    }
  }

  return res.json({
    ok: true,
    found,
    provider: RAPIDAPI_HOST,
    strategy: RAPIDAPI_STRATEGY,
    steps
  });
});

// ---------------- Root (Dashboard) ----------------
app.get("/", (req, res) => {
  const file = path.join(__dirname, "public", "dashboard.html");
  fs.pathExists(file).then(exists => {
    if (exists) return res.sendFile(file);
    res.type("text/plain").send("LinqBridge API OK");
  });
});

// ---------------- Start ----------------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server is running on port ${PORT}`);
  if (!RAPIDAPI_KEY) {
    console.log("NOTE: RAPIDAPI_KEY not set – RapidAPI enrichment is disabled.");
  } else {
    console.log(`RapidAPI host: ${RAPIDAPI_HOST} | strategy: ${RAPIDAPI_STRATEGY} | geo: ${RAPIDAPI_GEO || "(none)"}`);
    if (RAPIDAPI_DEBUG) console.log("RapidAPI debug logging is ON");
  }
});
