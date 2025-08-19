// index.js — LinqBridge backend (Auth + Leads + Automation) FINAL

// --- Core Modules ---
const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const path = require("path");
const ExcelJS = require("exceljs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs-extra"); // File-system helper
const { v4: uuidv4 } = require("uuid"); // For unique job IDs
require("dotenv").config(); // IMPORTANT: Load environment variables from .env file

// --- Server Setup ---
const app = express();
const PORT = process.env.PORT || 5000;

// SECURITY: Use environment variable for JWT secret. The fallback is for local dev only.
// In a production environment, this variable MUST be set.
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key_change_this_for_prod";

// --- Job Queue (file-backed) ---
// Note: A file-backed queue is simple but not atomic. For high-volume or critical
// production use, consider a robust message broker like Redis or RabbitMQ.
const DATA_DIR = path.join(__dirname, "data");
const JOBS_FILE = path.join(DATA_DIR, "jobs.json");

// Initializes queue storage on boot.
(async () => {
  await fs.ensureDir(DATA_DIR);
  if (!(await fs.pathExists(JOBS_FILE))) {
    await fs.writeJson(JOBS_FILE, { queued: [], active: [], done: [], failed: [] }, { spaces: 2 });
  }
})();

async function readJobs() { return fs.readJson(JOBS_FILE); }
async function writeJobs(d) { return fs.writeJson(JOBS_FILE, d, { spaces: 2 }); }

// Worker-only authentication middleware.
function requireWorkerAuth(req, res, next) {
  const header = req.get("x-worker-secret");
  // The worker secret MUST be set in an environment variable for security.
  if (!header || header !== process.env.WORKER_SHARED_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// --- Middleware ---
app.use(express.json({ limit: "50mb" }));
app.use(express.static("public"));

// CORS: allow specific origins for security.
const ALLOWED_ORIGINS = [
  "chrome-extension://mhfjpfanjgflnflifenhoejbfjecleen",
  "http://localhost:3000",
  "https://calm-rejoicing-linqbridge.up.railway.app"
];
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error(`Origin ${origin} not allowed by CORS`));
  },
  methods: ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "x-worker-secret"],
  credentials: false
}));
app.options("*", cors());

// --- DB Initialization ---
const dbPath = path.join(__dirname, "linqbridge.db");
const db = new Database(dbPath, { verbose: console.log });

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

  // Partial UNIQUE indexes enforce per-user uniqueness.
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

  console.log(
    "Database initialized: Leads, Message Templates, Users, Cookies, and unique indexes ready."
  );
}
initializeDatabase();

// --- Helper Functions ---
// Get latest 'li_at' cookie for a user.
function getLatestLiAtForUser(email) {
  try {
    const row = db
      .prepare("SELECT li_at FROM cookies WHERE email = ? ORDER BY id DESC LIMIT 1")
      .get(email);
    return row?.li_at || null;
  } catch (e) {
    console.error("getLatestLiAtForUser error:", e);
    return null;
  }
}

// Extracts Sales Navigator profile ID.
function extractFsSalesProfileId(salesNavUrl = "") {
  const m =
    salesNavUrl.match(/fs_salesProfile:(\d+)/) ||
    salesNavUrl.match(/fs_salesProfile:\((\d+)\)/);
  return m ? m[1] : null;
}

// Attempts to resolve a Sales Nav URL to a public URL. This relies on an undocumented
// LinkedIn API and may break if LinkedIn changes their API.
async function resolveSalesNavToPublicUrl(salesNavUrl, liAtCookie) {
  if (!salesNavUrl || !liAtCookie) return null;
  const profileId = extractFsSalesProfileId(salesNavUrl);
  if (!profileId) return null;

  const apiUrl = `https://www.linkedin.com/sales-api/salesApiProfiles/${profileId}`;

  try {
    const res = await fetch(apiUrl, {
      method: "GET",
      headers: {
        "accept": "application/json",
        "x-restli-protocol-version": "2.0.0",
        "csrf-token": "ajax:123456789",
        "cookie": `li_at=${liAtCookie};`
      },
      // Timeout using the modern AbortController pattern.
      signal: AbortSignal.timeout ? AbortSignal.timeout(12_000) : undefined
    });

    if (!res.ok) {
      console.warn("resolveSalesNavToPublicUrl non-OK:", res.status, await safeText(res));
      return null;
    }

    const data = await res.json().catch(() => ({}));
    const candidates = [
      data?.profile?.profileUrl,
      data?.profile?.profileUrn,
      data?.publicProfileUrl,
      data?.profile?.publicIdentifier
        ? `https://www.linkedin.com/in/${data.profile.publicIdentifier}`
        : null
    ].filter(Boolean);

    return candidates[0] || null;
  } catch (e) {
    console.error("resolveSalesNavToPublicUrl error:", e);
    return null;
  }
}

// Tiny helper to safely read response body as text.
async function safeText(res) {
  try { return await res.text(); } catch { return ""; }
}

// Heuristic fallback for resolving Sales Nav to public URL.
function derivePublicFromSalesNav(salesNavUrl) {
  if (!salesNavUrl) return null;
  const m = salesNavUrl.match(/\/sales\/lead\/([^,\/\?]+)/i);
  if (m && m[1]) {
    return `https://www.linkedin.com/in/${m[1]}`;
  }
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
  if (!email || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Email and password are required." });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    const stmt = db.prepare("INSERT INTO users (email, password) VALUES (?, ?)");
    const info = stmt.run(email, hashed);
    if (info.changes > 0) {
      console.log(`User registered: ${email}`);
      return res
        .status(201)
        .json({ success: true, message: "User registered successfully." });
    }
    return res
      .status(409)
      .json({ success: false, message: "User with this email already exists." });
  } catch (e) {
    console.error("Register error:", e);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error during registration." });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Email and password are required." });
  }
  try {
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user) return res.status(401).json({ success: false, message: "Invalid credentials." });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ success: false, message: "Invalid credentials." });
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: "24h" });
    console.log(`User logged in: ${email}`);
    return res.status(200).json({ success: true, message: "Logged in successfully.", token, userEmail: user.email });
  } catch (e) {
    console.error("Login error:", e);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error during login." });
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
          d2.queued.sort((a,b) => a.priority - b.priority);
          await writeJobs(d2);
        }, delayMs);
      } else {
        d.queued.push(job);
        d.queued.sort((a,b) => a.priority - b.priority);
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
  res.json({
    counts: {
      queued: d.queued.length,
      active: d.active.length,
      done: d.done.length,
      failed: d.failed.length,
    },
  });
});

// --- Cookie Endpoints from extension ---
app.post("/store-cookies", (req, res) => {
  try {
    const { email, cookies, timestamp } = req.body || {};
    if (!email || !cookies || !cookies.li_at) {
      return res.status(400).json({ success: false, message: "Missing email or li_at cookie." });
    }
    const insertStmt = db.prepare(
      "INSERT INTO cookies (email, li_at, jsessionid, bcookie, timestamp) VALUES (?, ?, ?, ?, ?)"
    );
    insertStmt.run(email, cookies.li_at, cookies.JSESSIONID || null, cookies.bcookie || null, timestamp || new Date().toISOString());
    return res.json({ success: true, message: "Cookies stored successfully." });
  } catch (e) {
    console.error("store-cookies error:", e);
    return res.status(500).json({ success: false, message: "Internal server error while storing cookies." });
  }
});

app.get("/api/me/liat", authenticateToken, (req, res) => {
  try {
    const row = db
      .prepare("SELECT li_at FROM cookies WHERE email = ? ORDER BY id DESC LIMIT 1")
      .get(req.user.email);
    if (!row || !row.li_at) {
      return res.status(404).json({ success: false, message: "No li_at found for user." });
    }
    return res.json({ success: true, li_at: row.li_at });
  } catch (e) {
    console.error("liat error:", e);
    return res.status(500).json({ success: false, message: "Internal server error." });
  }
});

app.post("/jobs/enqueue-send-connection", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const { profileUrl, note = null, priority = 3 } = req.body || {};
    if (!profileUrl) return res.status(400).json({ error: "profileUrl required" });

    const row = db.prepare(
      "SELECT li_at, jsessionid, bcookie FROM cookies WHERE email = ? ORDER BY id DESC LIMIT 1"
    ).get(email);

    if (!row?.li_at) return res.status(404).json({ error: "No li_at stored. Capture cookies first." });

    const d = await readJobs();
    const job = {
      id: uuidv4(),
      type: "SEND_CONNECTION",
      payload: {
        profileUrl,
        note,
        cookieBundle: {
          li_at: row.li_at,
          jsessionid: row.jsessionid || null,
          bcookie: row.bcookie || null
        }
      },
      priority,
      status: "queued",
      enqueuedAt: new Date().toISOString(),
      attempts: 0,
      lastError: null
    };
    d.queued.push(job);
    d.queued.sort((a,b) => a.priority - b.priority);
    await writeJobs(d);

    res.json({ ok: true, job });
  } catch (e) {
    console.error("enqueue-send-connection error:", e);
    res.status(500).json({ error: "Failed to enqueue" });
  }
});

// --- Lead Management Endpoints ---
app.post("/upload-leads", async (req, res) => {
  console.log("Received /upload-leads");
  const { leads, userEmail, timestamp } = req.body || {};
  if (!userEmail || !Array.isArray(leads) || leads.length === 0) {
    return res.status(400).json({ success: false, message: "Missing userEmail or leads." });
  }

  const liAt = getLatestLiAtForUser(userEmail);
  if (!liAt) {
    console.warn("[upload-leads] No li_at stored for", userEmail, "- will save Sales Nav URLs as-is.");
  }

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

  async function processOne(rawLead, index) {
    try {
      const fullName = rawLead.full_name || "";
      const firstName = rawLead.first_name || null;
      const lastName = rawLead.last_name || null;
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
        if (publicUrl) {
          console.log(`[Resolver] Resolved public URL for #${index + 1}: ${publicUrl}`);
        } else {
          console.warn(`[Resolver] Could not resolve public URL for #${index + 1} (${fullName}).`);
        }
      }

      let inferredPublic = null;
      if (!publicUrl && salesNavUrl && salesNavUrl.includes('/sales/lead/')) {
        inferredPublic = derivePublicFromSalesNav(salesNavUrl);
        if (inferredPublic) {
          console.log(`[Heuristic] Derived public URL for #${index + 1}: ${inferredPublic}`);
        }
      }

      const public_profile_url_to_store = publicUrl || inferredPublic || null;

      if (!public_profile_url_to_store && !profileUrlLegacy && !salesNavUrl) {
        console.warn(`[Data Warning] Skipping lead ${index + 1} (no URL fields at all): ${fullName}`);
        skipped++;
        return;
      }

      const info = insertStmt.run(
        userEmail,
        firstName,
        lastName,
        profileUrlLegacy,
        public_profile_url_to_store,
        salesNavUrl,
        organization,
        title,
        timestamp || new Date().toISOString(),
        "scraped"
      );

      if (info.changes > 0) inserted++; else skipped++;
    } catch (e) {
      console.error(`Lead #${index + 1} insert error:`, e.message);
      skipped++;
    }
  }

  for (let w = 0; w < Math.min(CONCURRENCY, queue.length); w++) {
    workers.push(
      (async function runWorker() {
        while (queue.length) {
          const idx = leads.length - queue.length;
          const next = queue.shift();
          await processOne(next, idx);
        }
      })()
    );
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
  console.log("Received /api/leads");
  try {
    const rows = db
      .prepare("SELECT * FROM leads WHERE user_email = ? ORDER BY scraped_at DESC")
      .all(req.user.email);
    return res.json({ success: true, leads: rows });
  } catch (e) {
    console.error("api/leads error:", e);
    return res.status(500).json({ success: false, message: "Internal server error fetching leads." });
  }
});

app.get("/download-leads-excel", authenticateToken, async (req, res) => {
  console.log("Received /download-leads-excel");
  try {
    const rows = db
      .prepare("SELECT * FROM leads WHERE user_email = ? ORDER BY scraped_at DESC")
      .all(req.user.email);

    if (rows.length === 0) {
      return res.status(404).send(`No leads found for ${req.user.email}.`);
    }

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
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=linqbridge_leads_${req.user.email.split("@")[0]}_${Date.now()}.xlsx`
    );

    await wb.xlsx.write(res);
    res.end();
  } catch (e) {
    console.error("download excel error:", e);
    return res.status(500).send("Internal server error: Could not generate Excel file.");
  }
});

// --- Automation Endpoints ---
app.get("/api/automation/get-next-leads", authenticateToken, (req, res) => {
  const limit = parseInt(req.query.limit || "1", 10);
  const email = req.user.email;

  try {
    let leads = [];
    // Use a transaction for atomicity.
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
  const { lead_id, status, message, action_details = {} } = req.body || {};
  const email = req.user.email;
  if (!lead_id || !status) {
    return res.status(400).json({ success: false, message: "Missing lead_id or status." });
  }

  let setClauses = [
    `automation_status = ?`,
    `last_action_timestamp = CURRENT_TIMESTAMP`,
  ];
  const params = [status];

  let nextActionDate = null;
  switch (status) {
    case "connection_sent":
      nextActionDate = new Date(Date.now() + (Math.random() * (5 - 3) + 3) * 24 * 60 * 60 * 1000).toISOString();
      if (action_details.connection_note_sent) {
        setClauses.push(`connection_note = ?`);
        params.push(action_details.connection_note_sent);
      }
      break;
    case "accepted":
      nextActionDate = new Date(Date.now() + (Math.random() * (2 - 1) + 1) * 60 * 60 * 1000).toISOString();
      break;
    case "msg1_sent":
    case "msg2_sent":
      nextActionDate = new Date(Date.now() + (Math.random() * (7 - 4) + 4) * 24 * 60 * 60 * 1000).toISOString();
      break;
    case "replied":
    case "skipped":
    case "error":
      nextActionDate = null;
      break;
    case "profile_viewed":
      nextActionDate = new Date(Date.now() + (Math.random() * (24 - 12) + 12) * 60 * 60 * 1000).toISOString();
      break;
  }

  if (nextActionDate) {
    setClauses.push(`next_action_due_date = ?`);
    params.push(nextActionDate);
  } else {
    setClauses.push(`next_action_due_date = NULL`);
  }

  if (action_details.liked_post_url) {
    setClauses.push(`liked_post_url = ?`);
    params.push(action_details.liked_post_url);
  }

  const sql = `
    UPDATE leads
    SET ${setClauses.join(", ")}
    WHERE id = ? AND user_email = ?;
  `;
  params.push(lead_id, email);

  try {
    const info = db.prepare(sql).run(...params);
    if (info.changes > 0) {
      return res.json({ success: true, message: "Lead status updated successfully." });
    }
    return res.status(404).json({ success: false, message: "Lead not found or not authorized." });
  } catch (e) {
    console.error("update-status error:", e);
    return res.status(500).json({ success: false, message: "Internal server error updating lead status." });
  }
});

// --- Root Endpoint ---
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// --- Start Server ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(
    `Access your LinqBridge Dashboard at: https://${process.env.REPL_SLUG}.${process.env.REPL_OWNER}.repl.co`
  );
});
