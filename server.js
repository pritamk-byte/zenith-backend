import express from "express";
import cors from "cors";
import pg from "pg";
import "dotenv/config";
import pino from "pino";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { z } from "zod";
import multer from "multer";

// ==========================================
// 1. SYSTEM SETUP & DATABASE
// ==========================================
const app = express();
const PORT = process.env.PORT || 8080;
const logger = pino({ level: process.env.LOG_LEVEL || "info" });

app.use(cors());
app.use(express.json());

// Initialize PostgreSQL Pool
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false,
});

// ==========================================
// 2. MIDDLEWARE
// ==========================================
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  
  if (!token) return res.status(401).json({ message: "Access denied. Missing bearer token." });
  
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired session. Please log in again." });
  }
};

const authorizeRoles = (...roles) => (req, res, next) => {
  if (!req.user?.role) return res.status(403).json({ message: "Role not available." });
  if (!roles.includes(req.user.role)) return res.status(403).json({ message: "Forbidden. Higher clearance required." });
  return next();
};

const errorHandler = (err, req, res, next) => {
  logger.error({ err: err.message, path: req.path }, "Unhandled error");
  res.status(500).json({ message: "Internal server error." });
};

// ==========================================
// 3. API ROUTES
// ==========================================

// --- HEALTH CHECK ---
app.get("/api/v1/health", async (req, res, next) => {
  try {
    const start = Date.now();
    await pool.query("SELECT 1");
    res.json({ status: "ok", uptime: process.uptime(), dbLatencyMs: Date.now() - start });
  } catch (error) {
    next(error);
  }
});

// --- AUTHENTICATION ---
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(6) });

app.post("/api/v1/auth/login", async (req, res, next) => {
  try {
    const { email, password } = loginSchema.parse(req.body);
    const { rows } = await pool.query(`SELECT id, full_name, email, password_hash, role, is_active FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`, [email]);
    
    if (!rows.length) throw new Error("Invalid credentials.");
    const user = rows[0];
    if (!user.is_active) throw new Error("User account is locked or inactive.");
    
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) throw new Error("Invalid credentials.");

    const token = jwt.sign({ id: user.id, role: user.role, email: user.email, name: user.full_name }, process.env.JWT_SECRET, { expiresIn: "24h" });
    res.json({ token, user: { id: user.id, name: user.full_name, email: user.email, role: user.role } });
  } catch (error) {
    if (error.name === "ZodError") return res.status(400).json({ message: "Invalid email or password format." });
    if (error.message === "Invalid credentials." || error.message.includes("inactive")) return res.status(401).json({ message: error.message });
    next(error);
  }
});

// --- PRICING ENGINE ---

// GET: Fetch live pricing for the dashboard
app.get("/api/v1/pricing", authenticate, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      'SELECT name AS service, base_cost AS "baseCost", margin_percentage AS margin FROM services ORDER BY id ASC'
    );
    res.json({ data: rows });
  } catch (error) {
    next(error);
  }
});

// PUT: Bulk update pricing (Wrapped in a SQL Transaction)
app.put("/api/v1/pricing", authenticate, authorizeRoles("ADMIN", "SUPER_ADMIN"), async (req, res, next) => {
  const client = await pool.connect();
  try {
    const { rows } = req.body;
    if (!Array.isArray(rows) || rows.length === 0) return res.status(400).json({ message: "No pricing data provided." });

    logger.info(`[PRICING] ${req.user.name} updating ${rows.length} services.`);
    
    await client.query('BEGIN'); // Start transaction
    
    for (let row of rows) {
      await client.query(
        'UPDATE services SET base_cost = $1, margin_percentage = $2 WHERE name = $3',
        [row.baseCost, row.margin, row.service]
      );
    }
    
    await client.query('COMMIT'); // Lock in the changes
    res.status(200).json({ message: "Pricing updated successfully." });
  } catch (error) {
    await client.query('ROLLBACK'); // Cancel everything if one fails
    next(error);
  } finally {
    client.release();
  }
});

// --- STAFF ROSTER ---
app.get("/api/v1/staff", authenticate, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, full_name AS name, role, current_site AS site, status FROM staff ORDER BY full_name ASC'
    );
    res.json({ data: rows });
  } catch (error) {
    next(error);
  }
});

// --- CLIENTS & INVOICING ---
app.get("/api/v1/clients", authenticate, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, company_name AS name, contract_end_date AS "contractEnd", monthly_value AS "totalMonthly" FROM clients ORDER BY company_name ASC'
    );
    res.json({ data: rows });
  } catch (error) {
    next(error);
  }
});

// --- SYSTEM ANALYTICS ---
app.post("/api/v1/analytics/events", authenticate, async (req, res, next) => {
  try {
    const schema = z.object({ eventType: z.string().min(3), metadata: z.record(z.any()).optional() });
    const { eventType, metadata } = schema.parse(req.body);
    
    await pool.query(
      'INSERT INTO analytics_events (user_id, event_type, metadata) VALUES ($1, $2, $3)',
      [req.user.id, eventType, JSON.stringify(metadata || {})]
    );
    
    res.status(201).json({ message: "Event tracked." });
  } catch (error) {
    if (error.name === "ZodError") return res.status(400).json({ message: "Invalid payload." });
    next(error);
  }
});

app.use(errorHandler);

// ==========================================
// 4. START SERVER
// ==========================================
app.listen(PORT, () => {
  logger.info(`Zenith ERP Backend running smoothly on port ${PORT}`);
});
