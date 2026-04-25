import express from "express";
import cors from "cors";
import pg from "pg";
import "dotenv/config";
import jwt from "jsonwebtoken";

// ==========================================
// 1. SYSTEM SETUP
// ==========================================
const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false,
});

// ==========================================
// 2. SECURITY MIDDLEWARE
// ==========================================
const authenticate = (req, res, next) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ message: "Access denied." });
  
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || "fallback_secret");
    next();
  } catch {
    res.status(401).json({ message: "Session expired." });
  }
};

const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ message: "Forbidden." });
  next();
};

// ==========================================
// 3. API ROUTES
// ==========================================

// --- AUTHENTICATION ---
app.post("/api/v1/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const { rows } = await pool.query(
      `SELECT id, full_name, email, password_hash, role, is_active FROM users WHERE LOWER(email) = LOWER($1)`,
      [email]
    );
    
    if (!rows.length) return res.status(401).json({ message: "Invalid credentials." });
    
    const user = rows[0];
    if (user.is_active === false) return res.status(401).json({ message: "Account inactive." });
    
    // Direct string match (No bcrypt, matches your SQL exactly)
    if (password !== user.password_hash) return res.status(401).json({ message: "Invalid credentials." });

    const token = jwt.sign(
      { id: user.id, role: user.role, name: user.full_name }, 
      process.env.JWT_SECRET || "fallback_secret", 
      { expiresIn: "24h" }
    );
    
    res.json({ token, user: { id: user.id, name: user.full_name, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: "Server error during login." });
  }
});

// --- PRICING CATALOG ---
app.get("/api/v1/pricing", authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT name AS service, base_cost AS "baseCost", margin_percentage AS margin FROM services ORDER BY id ASC');
    res.json(rows);
  } catch (err) { res.status(500).send(err.message); }
});

app.put("/api/v1/pricing", authenticate, authorize("ADMIN"), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); 
    for (let row of req.body.rows) {
      await client.query('UPDATE services SET base_cost = $1, margin_percentage = $2 WHERE name = $3', [row.baseCost, row.margin, row.service]);
    }
    await client.query('COMMIT'); 
    res.json({ message: "Pricing updated." });
  } catch (error) {
    await client.query('ROLLBACK'); 
    res.status(500).json({ message: "Update failed." });
  } finally {
    client.release();
  }
});

// --- STAFF ROSTER ---
app.get("/api/v1/staff", authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, full_name AS name, role, current_site AS site, status FROM staff ORDER BY id DESC');
    res.json(rows);
  } catch (err) { res.status(500).send(err.message); }
});

app.post("/api/v1/staff", authenticate, authorize("ADMIN"), async (req, res) => {
  try {
    const { name, role, site } = req.body;
    const { rows } = await pool.query(
      'INSERT INTO staff (full_name, role, current_site, status) VALUES ($1, $2, $3, $4) RETURNING id, full_name AS name, role, current_site AS site, status',
      [name, role, site, 'Active']
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).send(err.message); }
});

app.delete("/api/v1/staff/:id", authenticate, authorize("ADMIN"), async (req, res) => {
  try {
    await pool.query('DELETE FROM staff WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).send(err.message); }
});

app.put("/api/v1/staff/:id/status", authenticate, authorize("ADMIN", "STAFF"), async (req, res) => {
  try {
    await pool.query('UPDATE staff SET status = $1 WHERE id = $2', [req.body.status, req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).send(err.message); }
});

// --- CLIENTS ---
app.get("/api/v1/clients", authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, company_name AS name, contract_end_date AS "contractEnd", monthly_value AS "totalMonthly" FROM clients ORDER BY id DESC');
    res.json(rows);
  } catch (err) { res.status(500).send(err.message); }
});

app.post("/api/v1/clients", authenticate, authorize("ADMIN", "STAFF"), async (req, res) => {
  try {
    const { name, contractEnd, totalMonthly } = req.body;
    const { rows } = await pool.query(
      'INSERT INTO clients (company_name, contract_end_date, monthly_value) VALUES ($1, $2, $3) RETURNING id, company_name AS name, contract_end_date AS "contractEnd", monthly_value AS "totalMonthly"',
      [name, contractEnd, totalMonthly]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).send(err.message); }
});

// ==========================================
// 4. START
// ==========================================
app.listen(PORT, () => console.log(`Zenith Server running on port ${PORT}`));
