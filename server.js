import express from "express";
import cors from "cors";
import pg from "pg";
import "dotenv/config";
import pino from "pino";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { z } from "zod";
import multer from "multer";
import crypto from "crypto";

// ==========================================
// 1. SYSTEM SETUP & DATABASE
// ==========================================
const app = express();
const PORT = process.env.PORT || 8080;
const logger = pino({ level: process.env.LOG_LEVEL || "info" });

app.use(cors());
app.use(express.json());

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false,
});

// ==========================================
// 2. MOCKED SERVICES (Skipping Redis setup for local testing)
// ==========================================
const queueSlaReminder = async (ticketId, slaDeadlineAt) => {
  logger.info(`[MOCK QUEUE] SLA Reminder set for Ticket ${ticketId} at ${slaDeadlineAt}`);
};
const queueNotification = async (eventType, payload) => {
  logger.info(`[MOCK QUEUE] Notification queued: ${eventType}`, payload);
};
const notifyTicketUpdated = async (payload) => {
  logger.info(`[MOCK NOTIFY] Ticket updated:`, payload);
};
const scanUploadedFileOrThrow = async (_filePath) => {
  return true; // Mocked virus scan
};

// ==========================================
// 3. MIDDLEWARE
// ==========================================
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing bearer token." });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token." });
  }
};

const authorizeRoles = (...roles) => (req, res, next) => {
  if (!req.user?.role) return res.status(403).json({ message: "Role not available." });
  if (!roles.includes(req.user.role)) return res.status(403).json({ message: "Forbidden for current role." });
  return next();
};

const errorHandler = (err, req, res, next) => {
  logger.error({ err: err.message, path: req.path }, "Unhandled error");
  res.status(500).json({ message: "Internal server error." });
};

// ==========================================
// 4. API ROUTES
// ==========================================

// --- HEALTH CHECK ---
app.get("/api/v1/health", async (req, res, next) => {
  try {
    const start = Date.now();
    await pool.query("SELECT 1");
    res.json({ status: "ok", uptime: process.uptime(), dbLatencyMs: Date.now() - start, timestamp: new Date().toISOString() });
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
    if (!user.is_active) throw new Error("User is inactive.");
    
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) throw new Error("Invalid credentials.");

    const token = jwt.sign({ id: user.id, role: user.role, email: user.email, name: user.full_name }, process.env.JWT_SECRET, { expiresIn: "12h" });
    res.json({ token, user: { id: user.id, name: user.full_name, email: user.email, role: user.role } });
  } catch (error) {
    if (error.name === "ZodError") return res.status(400).json({ message: "Invalid login payload." });
    if (error.message === "Invalid credentials." || error.message === "User is inactive.") return res.status(401).json({ message: error.message });
    next(error);
  }
});

// --- ANALYTICS ---
// Note: We removed the 'authenticate' middleware here temporarily so your frontend can test saving without a login screen!
app.post("/api/v1/analytics/events", async (req, res, next) => {
  try {
    const schema = z.object({ eventType: z.string().min(3), metadata: z.record(z.any()).optional() });
    const { eventType, metadata } = schema.parse(req.body);
    // Real DB track event mocked for local testing without DB setup yet
    logger.info(`[ANALYTICS] Event Tracked: ${eventType}`, metadata);
    res.status(201).json({ message: "Event tracked." });
  } catch (error) {
    if (error.name === "ZodError") return res.status(400).json({ message: "Invalid analytics event payload." });
    next(error);
  }
});

// --- PRICING & SERVICES ---
// Note: Removed 'authenticate' middleware temporarily for frontend testing
app.put("/api/v1/pricing/services", async (req, res, next) => {
  try {
    const { rows } = req.body;
    logger.info(`[PRICING] Received Bulk Pricing Update for ${rows.length} services.`);
    
    // In production, this would loop through rows and do:
    // await pool.query('UPDATE services SET base_cost = $1, margin_percentage = $2 WHERE name = $3', [...])
    
    res.status(200).json({ message: "Pricing updated successfully.", data: rows });
  } catch (error) {
    next(error);
  }
});

app.get("/api/v1/pricing/services/:serviceName/final-price", authenticate, authorizeRoles("ADMIN", "CLIENT", "STAFF"), async (req, res, next) => {
  try {
    // Mocked DB lookup
    const data = { serviceName: req.params.serviceName, finalPrice: 9999 }; 
    const etag = crypto.createHash("sha1").update(JSON.stringify(data)).digest("hex");
    if (req.headers["if-none-match"] === etag) return res.status(304).end();
    res.setHeader("ETag", etag);
    res.setHeader("Cache-Control", "private, max-age=60");
    res.json({ data });
  } catch (error) {
    next(error);
  }
});

// --- TICKETS (WITH UPLOADS) ---
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp", "video/mp4", "video/webm"];
    if (!allowed.includes(file.mimetype)) return cb(new Error("Unsupported file type."));
    cb(null, true);
  },
});

app.post("/api/v1/tickets", authenticate, authorizeRoles("CLIENT"), upload.single("attachment"), async (req, res, next) => {
  try {
    const schema = z.object({
      bookingId: z.coerce.number().optional(),
      relatedServiceId: z.coerce.number().optional(),
      subject: z.string().min(3),
      description: z.string().min(10),
      priority: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    });
    const payload = schema.parse(req.body);
    if (req.file?.path) await scanUploadedFileOrThrow(req.file.path);
    
    // Mocked DB Insertion
    const ticket = { id: Math.floor(Math.random() * 1000), ...payload, client_id: req.user.id, status: "OPEN" };
    
    await queueSlaReminder(ticket.id, new Date().toISOString());
    await queueNotification("TICKET_CREATED", { ticketId: ticket.id, clientId: ticket.client_id });
    
    res.status(201).json({ message: "Ticket created", data: ticket });
  } catch (error) {
    if (error.name === "ZodError") return res.status(400).json({ message: "Invalid ticket payload." });
    next(error);
  }
});

app.use(errorHandler);

// ==========================================
// 5. START SERVER
// ==========================================
app.listen(PORT, () => {
  logger.info(`Zenith ERP Backend running smoothly on http://localhost:${PORT}`);
});