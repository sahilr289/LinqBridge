// index.js — LinqBridge backend (Auth + Leads + Automation) FINAL

const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const path = require("path");
const ExcelJS = require("exceljs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

// ---------- Middleware ----------
app.use(express.json({ limit: "50mb" }));
app.use(express.static("public"));
app.use(
  cors({
    origin: "*", // tighten in prod
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ---------- DB ----------
const dbPath = path.join(__dirname, "linqbridge.db");
const db = new Database(dbPath, { verbose: console.log });

function initializeDatabase() {
  // Tables (no expressions in UNIQUE constraints)
  db.exec(`
    CREATE TABLE IF NOT EXISTS leads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL,
      first_name TEXT,
      last_name TEXT,
      profile_url TEXT,              -- legacy or generic
      public_profile_url TEXT,       -- preferred /in/ URL
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

  // Partial UNIQUE indexes (valid in SQLite; enforce per-user uniqueness)
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

// ---------- Auth ----------
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

// ---------- Cookies from extension ----------
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

// Worker needs li_at for the logged-in user
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

// ---------- Upload leads from extension ----------
app.post("/upload-leads", async (req, res) => {
  console.log("Received /upload-leads");
  const { leads, userEmail, timestamp } = req.body || {};
  if (!userEmail || !Array.isArray(leads) || leads.length === 0) {
    return res.status(400).json({ success: false, message: "Missing userEmail or leads." });
  }

  const insertLeadSql = `
    INSERT OR IGNORE INTO leads
      (user_email, first_name, last_name, profile_url, public_profile_url, sales_nav_url,
       organization, title, timestamp, automation_status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
  `;
  const insertStmt = db.prepare(insertLeadSql);

  let inserted = 0, skipped = 0;

  try {
    db.transaction(() => {
      for (let i = 0; i < leads.length; i++) {
        const lead = leads[i] || {};
        const fullName = lead.full_name || "";
        const firstName = lead.first_name || null;
        const lastName  = lead.last_name || null;
        const organization = lead.company || null;
        const title = lead.title || null;

        const publicUrl = lead.public_linkedin_url && lead.public_linkedin_url !== "N/A"
          ? lead.public_linkedin_url
          : null;

        const salesNavUrl = lead.sales_nav_url && lead.sales_nav_url !== "N/A"
          ? lead.sales_nav_url
          : (lead.profile_url || null); // some extensions call this profile_url

        const profileUrlLegacy = lead.profile_url || null; // keep for backward compat

        if (!publicUrl && !profileUrlLegacy) {
          console.warn(`[Data Warning] Skipping lead ${i + 1} (no URL): ${fullName}`);
          skipped++;
          continue;
        }

        const info = insertStmt.run(
          userEmail,
          firstName,
          lastName,
          profileUrlLegacy,
          publicUrl,
          salesNavUrl,
          organization,
          title,
          timestamp || new Date().toISOString(),
          "scraped"
        );

        if (info.changes > 0) {
          inserted++;
        } else {
          skipped++;
        }
      }
    })();

    return res.status(200).json({
      success: true,
      message: "Leads processed and saved successfully!",
      received: leads.length,
      inserted,
      skipped_duplicates: skipped,
      user_email: userEmail,
    });
  } catch (e) {
    console.error("upload-leads error:", e);
    return res.status(500).json({ success: false, message: "Internal server error during lead processing." });
  }
});

// ---------- Dashboard (protected) ----------
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

// ---------- Automation (protected) ----------
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

// Alias used by worker
app.get("/api/automation/runner/tick", authenticateToken, (req, res) => {
  // simply calls the same logic as get-next-leads with limit=1
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

// ---------- Root ----------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// ---------- Start ----------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(
    `Access your LinqBridge Dashboard at: https://${process.env.REPL_SLUG}.${process.env.REPL_OWNER}.repl.co`
  );
});
