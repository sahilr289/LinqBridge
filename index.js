// index.js — LinqBridge backend (FINAL: creds vault + /api/connect + existing flows)

"use strict";

const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const path = require("path");
const ExcelJS = require("exceljs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs-extra");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
require("dotenv").config();

// --- Server ---
const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key_change_this_for_prod";
const MASTER_KEY = process.env.MASTER_KEY || ""; // REQUIRED for secrets vault

// --- Optional viewer info for Connect flow ---
const VIEWER_BASE_URL = process.env.VIEWER_BASE_URL || "";     // e.g. https://linqbridge-worker-xxxx.up.railway.app
const NOVNC_PASSWORD  = process.env.NOVNC_PASSWORD  || "changeme123";

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

// --- Encryption helpers (AES-256-GCM) ---
function _getKey() {
  if (!MASTER_KEY) throw new Error("MASTER_KEY env not set");
  if (/^[A-Fa-f0-9]{64}$/.test(MASTER_KEY)) return Buffer.from(MASTER_KEY, "hex");         // 32 bytes hex
  if (/^[A-Za-z0-9+/=]{43,44}$/.test(MASTER_KEY)) return Buffer.from(MASTER_KEY, "base64"); // 32 bytes b64
  return crypto.createHash("sha256").update(MASTER_KEY).digest();                           // derive
}
function encryptJson(obj) {
  const key = _getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const pt = Buffer.from(JSON.stringify(obj), "utf8");
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString("base64"); // iv(12) | tag(16) | ct
}
function decryptJson(b64) {
  const key = _getKey();
  const buf = Buffer.from(b64, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct = buf.subarray(28);
  const dec = crypto.createDecipheriv("aes-256-gcm", key, iv);
  dec.setAuthTag(tag);
  const pt = Buffer.concat([dec.update(ct), dec.final()]);
  return JSON.parse(pt.toString("utf8"));
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
    if (!origin || ALLOWED_ORIGINS.has(origin)) return cb(null, true);
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
      level TEXT NOT NULL,
      event TEXT NOT NULL,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // NEW: secrets vault (AES-256-GCM encrypted blob per user)
  db.exec(`
    CREATE TABLE IF NOT EXISTS li_secrets (
      user_email TEXT PRIMARY KEY,
      secret_blob TEXT NOT NULL,
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

// --- Helpers ---
function logConn(email, level, event, detailsObj) {
  try {
    db.prepare(`
      INSERT INTO connection_logs (user_email, level, event, details)
      VALUES (?, ?, ?, ?)
    `).run(email, level, event, detailsObj ? JSON.stringify(detailsObj) : null);
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
      console.warn("resolveSalesNavToPublicUrl non-OK:", resp.status, await safeText(resp));
      return null;
    }
    const data = await (async () => { try { return await resp.json(); } catch { return {}; } })();
    const candidates = [
      data?.profile?.profileUrl,
      data?.profile?.profileUrn,
      data?.publicProfileUrl,
      data?.profile?.publicIdentifier ? `https://www.linkedin.com/in/${data.profile.publicIdentifier}` : null,
    ].filter(Boolean);
    return candidates[0] || null;
  } catch (e) {
    console.error("resolveSalesNavToPublicUrl error:", e);
    return null;
  }
}

async function safeText(res) { try { return await res.text(); } catch { return ""; } }

function derivePublicFromSalesNav(salesNavUrl) {
  if (!salesNavUrl) return null;
  const m = salesNavUrl.match(/\/sales\/lead\/([^,\/\?]+)/i);
  if (m && m[1]) return `https://www.linkedin.com/in/${m[1]}`;
  return null;
}

// --- Auth Middleware ---
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

// --- Auth Endpoints ---
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

// --- Job Queue Endpoints ---
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

// --- Cookies from extension ---
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

// --- Secrets: upsert (user) & fetch (worker) ---

// Upsert/update secrets for the logged-in app user
// Body: { li_username, li_password, totp_secret, proxy_server, proxy_username, proxy_password }
app.post("/api/secrets/upsert", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    let existing = null;
    try {
      const row = db.prepare("SELECT secret_blob FROM li_secrets WHERE user_email = ?").get(email);
      existing = row ? decryptJson(row.secret_blob) : null;
    } catch { existing = null; }

    const body = req.body || {};
    const merged = {
      li_username: body.li_username ?? existing?.li_username ?? null,
      li_password: body.li_password ?? existing?.li_password ?? null,
      totp_secret: body.totp_secret ?? existing?.totp_secret ?? null,
      proxy_server: body.proxy_server ?? existing?.proxy_server ?? null,
      proxy_username: body.proxy_username ?? existing?.proxy_username ?? null,
      proxy_password: body.proxy_password ?? existing?.proxy_password ?? null,
    };

    if (!merged.li_username || !merged.li_password) {
      return res.status(400).json({ success: false, message: "li_username and li_password are required at least once." });
    }

    const blob = encryptJson(merged);
    db.prepare(`
      INSERT INTO li_secrets (user_email, secret_blob, updated_at)
      VALUES (?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(user_email) DO UPDATE SET secret_blob=excluded.secret_blob, updated_at=CURRENT_TIMESTAMP
    `).run(email, blob);

    return res.json({ success: true, message: "Secrets saved." });
  } catch (e) {
    console.error("/api/secrets/upsert error:", e);
    return res.status(500).json({ success: false, message: "Failed to save secrets." });
  }
});

// Fetch decrypted secrets for worker (never exposed to browser)
// Query: ?email=<app user email>
app.get("/secrets/for-user", requireWorkerAuth, (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.status(400).json({ ok: false, error: "email required" });
    const row = db.prepare("SELECT secret_blob FROM li_secrets WHERE user_email = ?").get(email);
    if (!row?.secret_blob) return res.status(404).json({ ok: false, error: "no_secrets" });
    const secret = decryptJson(row.secret_blob);
    return res.json({
      ok: true,
      li_username: secret.li_username || null,
      li_password: secret.li_password || null,
      totp_secret: secret.totp_secret || null,
      proxy_server: secret.proxy_server || null,
      proxy_username: secret.proxy_username || null,
      proxy_password: secret.proxy_password || null,
    });
  } catch (e) {
    console.error("/secrets/for-user error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// --- Simple wrapper for your Console SDK: POST /api/connect ---
app.post("/api/connect", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const { profileUrl, note = null, priority = 3 } = req.body || {};
    if (!profileUrl) return res.status(400).json({ ok: false, error: "profileUrl required" });

    const row = db.prepare(
      "SELECT li_at, jsessionid, bcookie FROM cookies WHERE email = ? ORDER BY id DESC LIMIT 1"
    ).get(email);

    // Create job regardless; worker will credential-login if cookie is missing
    const d = await readJobs();
    const job = {
      id: uuidv4(),
      type: "SEND_CONNECTION",
      payload: {
        tenantId: "default",
        userId: email,
        profileUrl,
        note,
        cookieBundle: row?.li_at ? { li_at: row.li_at, jsessionid: row.jsessionid || null, bcookie: row.bcookie || null } : {},
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
    return res.json({ ok: true, jobId: job.id, job });
  } catch (e) {
    console.error("/api/connect error:", e);
    return res.status(500).json({ ok: false, error: "Failed to enqueue connect" });
  }
});

// Existing convenience route (kept)
app.post("/jobs/enqueue-send-connection", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const { profileUrl, note = null, priority = 3 } = req.body || {};
    if (!profileUrl) return res.status(400).json({ error: "profileUrl required" });

    const row = db.prepare(
      "SELECT li_at, jsessionid, bcookie FROM cookies WHERE email = ? ORDER BY id DESC LIMIT 1"
    ).get(email);

    const d = await readJobs();
    const job = {
      id: uuidv4(),
      type: "SEND_CONNECTION",
      payload: {
        tenantId: "default",
        userId: email,
        profileUrl,
        note,
        cookieBundle: row?.li_at ? { li_at: row.li_at, jsessionid: row.jsessionid || null, bcookie: row.bcookie || null } : {},
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

// --- Leads upload / Leads / Excel / Automation (unchanged) ---
app.post("/upload-leads", async (req, res) => {
  if (process.env.LOG_UPLOADS === "true") console.log("Received /upload-leads");
  const { leads, timestamp } = req.body || {};
  const userEmail = req.body.userEmail || req.body.email;
  if (!userEmail || !Array.isArray(leads) || leads.length === 0) {
    return res.status(400).json({ success: false, message: "Missing userEmail or leads." });
  }

  const liAt = getLatestLiAtForUser(userEmail);
  if (!liAt) console.warn("[upload-leads] No li_at stored for", userEmail, "- will save Sales Nav URLs as-is.");

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
      const organization = rawLead.company || null;
      const title = rawLead.title || null;

      let publicUrl = (rawLead.public_linkedin_url && rawLead.public_linkedin_url !== "N/A")
        ? rawLead.public_linkedin_url
        : null;

      let salesNavUrl =
        (rawLead.sales_nav_url && rawLead.sales_nav_url !== "N/A")
          ? rawLead.sales_nav_url
          : (rawLead.profile_url || null);

      const profileUrlLegacy = rawLead.profile_url || null;

      if (!publicUrl && salesNavUrl && liAt) {
        publicUrl = await resolveSalesNavToPublicUrl(salesNavUrl, liAt);
      }
      let inferredPublic = null;
      if (!publicUrl && salesNavUrl && salesNavUrl.includes("/sales/lead/")) {
        inferredPublic = derivePublicFromSalesNav(salesNavUrl);
      }

      const public_profile_url_to_store = publicUrl || inferredPublic || null;

      if (!public_profile_url_to_store && !profileUrlLegacy && !salesNavUrl) { skipped++; return; }

      const info = insertStmt.run(
        userEmail, firstName, lastName, profileUrlLegacy, public_profile_url_to_store, salesNavUrl,
        organization, title, timestamp || new Date().toISOString(), "scraped"
      );
      if (info.changes > 0) inserted++; else skipped++;
    } catch {
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

// --- Automation status / logs ---
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

// --- Connection status & logs ---
const LIVE_CHECK_COOLDOWN_MS = 10 * 60 * 1000;

app.get("/api/connection/check", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const wantLive = req.query.live === "1";

    const row = db.prepare(
      "SELECT li_at, jsessionid, bcookie FROM cookies WHERE email = ? ORDER BY id DESC LIMIT 1"
    ).get(email);

    if (!row?.li_at && !wantLive) {
      logConn(email, "warn", "status_fail", { reason: "no_li_at" });
      return res.json({
        connected: false,
        mode: "none",
        reason: "No li_at cookie on server. Capture cookies from the extension or store credentials."
      });
    }

    if (!wantLive) {
      logConn(email, "info", "status_soft_ok", {
        has_li_at: !!row?.li_at,
        has_jsessionid: !!row?.jsessionid,
        has_bcookie: !!row?.bcookie
      });
      return res.json({
        connected: row?.li_at ? "stored" : false,
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

    const js = (row?.jsessionid || "").replace(/^"|"$/g, "");
    const csrf = js || "ajax:123456789";
    const cookieHeader = [
      row?.li_at ? `li_at=${row.li_at}` : null,
      js ? `JSESSIONID="${js}"` : null,
      row?.bcookie ? `bcookie=${row.bcookie}` : null
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

// --- Connect flow (start/test/status) ---
app.post("/api/connect/start", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
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

// --- Root (Dashboard) ---
app.get("/", (req, res) => {
  const file = path.join(__dirname, "public", "dashboard.html");
  fs.pathExists(file).then(exists => {
    if (exists) return res.sendFile(file);
    res.type("text/plain").send("LinqBridge API OK");
  });
});

// --- Start ---
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server is running on port ${PORT}`);
});
