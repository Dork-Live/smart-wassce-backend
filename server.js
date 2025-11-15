// server.js — Smart WASSCE backend (Mongoose + Paystack webhook + Admin JWT)
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import bodyParser from "body-parser";
import fs from "fs";
import path from "path";
import multer from "multer";
import axios from "axios";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "url";

dotenv.config();

// --- __dirname for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Config (via .env in Render or your host)
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || "";
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || "";
const PAYSTACK_WEBHOOK_SECRET = process.env.PAYSTACK_WEBHOOK_SECRET || PAYSTACK_SECRET_KEY; // use secret for signature check
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const FRONTEND_SUCCESS_URL = process.env.FRONTEND_SUCCESS_URL || `${BASE_URL}/success.html`;
const PRICE_PER_VOUCHER = Number(process.env.PRICE_PER_VOUCHER || 25);
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "change-this-secret";
const UPLOADS_DIR = path.join(__dirname, "uploads");

// ensure upload dir
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// -------------------------
// Connect to MongoDB
// -------------------------
async function connectDb() {
  if (!MONGO_URI) {
    console.error("MONGO_URI not set in environment.");
    process.exit(1);
  }
  await mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  console.log("✅ Connected to MongoDB");
}
connectDb().catch((err) => {
  console.error("Mongo connect error:", err);
  process.exit(1);
});

// -------------------------
// Mongoose Schemas
// -------------------------
const CounterSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  seq: { type: Number, default: 0 },
});
const Counter = mongoose.model("Counter", CounterSchema);

async function getNextSequence(name, inc = 1) {
  const doc = await Counter.findOneAndUpdate(
    { name },
    { $inc: { seq: inc } },
    { new: true, upsert: true }
  );
  return doc.seq;
}

const VoucherSchema = new mongoose.Schema({
  cardId: { type: Number, required: true, unique: true },
  filename: { type: String, required: true },
  status: { type: String, enum: ["unused", "used"], default: "unused" },
  batchId: { type: String },
  uploadedAt: { type: Date, default: Date.now },
  usedAt: { type: Date },
  reference: { type: String }, // paystack reference if used
});
const Voucher = mongoose.model("Voucher", VoucherSchema);

const HistorySchema = new mongoose.Schema({
  cardId: Number,
  filename: String,
  usedBy: String,
  usedByEmail: String,
  reference: String,
  dateUsed: { type: Date, default: Date.now },
});
const History = mongoose.model("History", HistorySchema);

// -------------------------
// Express app
// -------------------------
const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json({ limit: "1mb" }));
app.use(cookieParser());
app.use("/uploads", express.static(UPLOADS_DIR));

// -------------------------
// Multer config for uploads
// -------------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    // Temporary unique name — we will rename to voucher_<seq>.ext
    const safe = Date.now() + "-" + file.originalname.replace(/\s+/g, "_");
    cb(null, safe);
  },
});
const upload = multer({
  storage,
  limits: { files: 20, fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if ([".jpg", ".jpeg", ".png"].includes(ext)) cb(null, true);
    else cb(new Error("Only JPG/JPEG/PNG allowed"));
  },
});

// -------------------------
// Admin auth (JWT)
// -------------------------
function signAdminToken(payload = {}) {
  return jwt.sign(payload, ADMIN_JWT_SECRET, { expiresIn: "12h" });
}
function verifyAdminToken(token) {
  try {
    return jwt.verify(token, ADMIN_JWT_SECRET);
  } catch (e) {
    return null;
  }
}
function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization || "";
  let token = null;
  if (authHeader.startsWith("Bearer ")) token = authHeader.split(" ")[1];
  else if (req.cookies && req.cookies.admin_token) token = req.cookies.admin_token;
  else if (req.headers["x-admin-token"]) token = req.headers["x-admin-token"];

  if (!token) return res.status(401).json({ success: false, error: "Unauthorized - no token" });
  const payload = verifyAdminToken(token);
  if (!payload) return res.status(401).json({ success: false, error: "Unauthorized - invalid token" });
  req.admin = payload;
  next();
}

// -------------------------
// Helpers
// -------------------------
async function allocateUnused(qty, reference = null, phone = "unknown", email = null) {
  // find N unused vouchers by cardId ascending
  const unused = await Voucher.find({ status: "unused" }).sort({ cardId: 1 }).limit(qty);
  if (unused.length < qty) return null;

  const ids = unused.map(u => u._id);
  await Voucher.updateMany({ _id: { $in: ids } }, { $set: { status: "used", usedAt: new Date(), reference } });

  const hist = unused.map(u => ({
    cardId: u.cardId,
    filename: u.filename,
    usedBy: phone,
    usedByEmail: email || null,
    reference: reference || null,
    dateUsed: new Date(),
  }));
  await History.insertMany(hist);

  return unused.map(u => ({ id: u.cardId, filename: u.filename, url: `${BASE_URL}/uploads/${u.filename}` }));
}

// -------------------------
// Routes
// -------------------------
app.get("/", (req, res) => res.send("✅ Smart WASSCE backend (Mongo + webhook)"));

/**
 * Admin login -> returns JWT token
 * Body: { email, password }
 */
app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ success: false, error: "Missing credentials" });
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, error: "Invalid credentials" });
  }
  const token = signAdminToken({ email });
  return res.json({ success: true, token, email });
});

app.post("/api/admin/logout", (req, res) => {
  return res.json({ success: true });
});

/**
 * Upload vouchers (admin) — rename to sequential voucher_<seq>.ext and save to DB
 */
app.post("/api/upload-vouchers", requireAdmin, upload.array("vouchers", 20), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) return res.status(400).json({ success: false, error: "No files" });
    const batchId = `batch-${Date.now()}`;
    const added = [];
    for (const file of req.files) {
      const seq = await getNextSequence("voucherSeq", 1);
      const ext = path.extname(file.originalname).toLowerCase() || ".jpg";
      const newFilename = `voucher_${seq}${ext}`;
      const oldPath = path.join(UPLOADS_DIR, file.filename);
      const newPath = path.join(UPLOADS_DIR, newFilename);
      fs.renameSync(oldPath, newPath);
      const v = new Voucher({
        cardId: seq,
        filename: newFilename,
        status: "unused",
        batchId,
        uploadedAt: new Date(),
      });
      await v.save();
      added.push({ id: seq, filename: newFilename, url: `${BASE_URL}/uploads/${newFilename}` });
    }
    return res.json({ success: true, added });
  } catch (err) {
    console.error("Upload error:", err);
    return res.status(500).json({ success: false, error: "Upload failed", details: err.message });
  }
});

/**
 * GET /api/vouchers/all (admin)
 */
app.get("/api/vouchers/all", requireAdmin, async (req, res) => {
  try {
    const vouchers = await Voucher.find({}).sort({ cardId: 1 }).lean();
    return res.json({ success: true, vouchers });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: "Failed to read vouchers" });
  }
});

/**
 * GET /api/history (admin)
 */
app.get("/api/history", requireAdmin, async (req, res) => {
  try {
    const history = await History.find({}).sort({ dateUsed: -1 }).lean();
    return res.json({ success: true, history });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: "Failed to read history" });
  }
});

/**
 * DELETE /api/vouchers/used (admin)
 */
app.delete("/api/vouchers/used", requireAdmin, async (req, res) => {
  try {
    const used = await Voucher.find({ status: "used" }).lean();
    if (!used.length) return res.json({ success: true, message: "No used vouchers" });
    for (const v of used) {
      const filePath = path.join(UPLOADS_DIR, v.filename);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
    const result = await Voucher.deleteMany({ status: "used" });
    return res.json({ success: true, message: `Deleted ${result.deletedCount} used vouchers.` });
  } catch (err) {
    console.error("Delete used error:", err);
    return res.status(500).json({ success: false, error: "Failed to delete used vouchers", details: err.message });
  }
});

/**
 * GET /api/find-by-reference/:ref
 * Returns voucher URLs previously allocated for this reference (idempotent)
 * This endpoint is used by success.html and retrieve.html to fetch vouchers without
 * contacting Paystack (so the frontend works regardless of Paystack callback).
 */
app.get("/api/find-by-reference/:ref", async (req, res) => {
  try {
    const ref = req.params.ref;
    if (!ref) return res.status(400).json({ success: false, error: "Missing reference" });
    const history = await History.find({ reference: ref }).lean();
    if (!history.length) return res.json({ success: false, error: "No vouchers found for this reference" });
    const urls = history.map(h => `${BASE_URL}/uploads/${h.filename}`);
    return res.json({ success: true, vouchers: urls, message: "Found" });
  } catch (err) {
    console.error("find-by-reference error:", err);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});

/**
 * POST /api/pay
 * Initialize Paystack transaction (unchanged logic)
 * Body: { email, phone, quantity, amount }
 */
app.post("/api/pay", async (req, res) => {
  try {
    const { email, phone, quantity, amount } = req.body || {};
    if (!email || !phone || !quantity || !amount) return res.status(400).json({ success: false, error: "Missing fields" });

    const expected = Number(quantity) * PRICE_PER_VOUCHER;
    if (Number(amount) !== expected) return res.status(400).json({ success: false, error: `Amount mismatch. Expected ${expected}` });

    const unusedCount = await Voucher.countDocuments({ status: "unused" });
    if (unusedCount < quantity) return res.status(400).json({ success: false, error: `Only ${unusedCount} voucher(s) available.` });

    if (!PAYSTACK_SECRET_KEY) return res.status(500).json({ success: false, error: "Paystack key not configured" });

    const payload = {
      email,
      amount: Number(amount) * 100,
      metadata: { phone, quantity },
      callback_url: FRONTEND_SUCCESS_URL,
    };

    const response = await axios.post("https://api.paystack.co/transaction/initialize", payload, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`, "Content-Type": "application/json" },
    });

    return res.json(response.data);
  } catch (err) {
    console.error("Pay init error:", err.response?.data || err.message);
    return res.status(500).json({ success: false, error: "Payment initialization failed", details: err.response?.data || err.message });
  }
});

/**
 * GET /api/verify/:reference
 * Backwards-compatible verify route (will still call Paystack verify) — not used by success.html anymore,
 * but kept for backward compatibility.
 */
app.get("/api/verify/:reference", async (req, res) => {
  try {
    const ref = req.params.reference;
    if (!ref) return res.status(400).json({ success: false, error: "Missing reference" });
    if (!PAYSTACK_SECRET_KEY) return res.status(500).json({ success: false, error: "Paystack key not configured" });

    // If we already have history, return immediately
    const existing = await History.find({ reference: ref }).lean();
    if (existing.length > 0) {
      const urls = existing.map(h => `${BASE_URL}/uploads/${h.filename}`);
      return res.json({ success: true, vouchers: urls, message: "Already verified" });
    }

    // verify with Paystack
    const verifyResp = await axios.get(`https://api.paystack.co/transaction/verify/${encodeURIComponent(ref)}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
    });
    const payload = verifyResp.data;
    if (!payload.status || payload.data.status !== "success") {
      return res.status(400).json({ success: false, error: "Payment not successful" });
    }

    const metadata = payload.data.metadata || {};
    let quantity = parseInt(metadata.quantity, 10);
    if (!quantity || isNaN(quantity)) quantity = Math.round(Number(payload.data.amount) / (PRICE_PER_VOUCHER * 100));
    if (quantity < 1) quantity = 1;
    if (quantity > 100) quantity = 100;

    const phone = metadata.phone || (payload.data.customer && payload.data.customer.phone) || "unknown";
    const email = payload.data.customer?.email || null;

    // allocate vouchers (atomic-ish)
    const assigned = await allocateUnused(quantity, ref, phone, email);
    if (!assigned) {
      return res.status(400).json({ success: false, error: "Payment successful but not enough vouchers left." });
    }

    return res.json({ success: true, vouchers: assigned.map(a => a.url), assigned });
  } catch (err) {
    console.error("Verify error:", err.response?.data || err.message);
    return res.status(500).json({ success: false, error: "Verification failed", details: err.response?.data || err.message });
  }
});

/**
 * POST /api/paystack/webhook
 * Paystack will POST transaction events here (use in Paystack dashboard -> Webhooks)
 * We verify the X-Paystack-Signature header (HMAC SHA512).
 *
 * Behavior:
 *  - On successful payments: allocate vouchers using metadata.quantity (if not already allocated).
 *  - This route is idempotent: it will check history for reference and skip if already handled.
 */
app.post("/api/paystack/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    // Raw body is required to verify signature
    const signature = req.headers["x-paystack-signature"] || req.headers["x-paystack-signature".toLowerCase()];
    const raw = req.body; // Buffer

    // verify signature (HMAC SHA512 with your Paystack SECRET)
    const computed = crypto.createHmac("sha512", PAYSTACK_WEBHOOK_SECRET).update(raw).digest("hex");
    if (signature !== computed) {
      console.warn("Webhook signature mismatch");
      return res.status(400).send("Invalid signature");
    }

    // parse JSON
    const payload = JSON.parse(raw.toString("utf8"));

    // Only handle transaction.success events
    const event = payload.event || payload.type || "";
    if (!event.toLowerCase().includes("transaction")) {
      return res.status(200).send("ignored");
    }

    const data = payload.data || payload;
    if (!data || data.status !== "success") {
      return res.status(200).send("ignored");
    }

    const ref = data.reference || data.trxref || data.id || null;
    if (!ref) return res.status(400).send("no reference");

    // If already processed (history exists for reference) -> idempotent
    const existing = await History.find({ reference: ref }).lean();
    if (existing.length > 0) {
      console.log(`Webhook: reference ${ref} already processed`);
      return res.status(200).send("already-processed");
    }

    // determine quantity and metadata
    const metadata = data.metadata || {};
    let quantity = parseInt(metadata.quantity, 10);
    if (!quantity || isNaN(quantity)) {
      quantity = Math.round(Number(data.amount) / (PRICE_PER_VOUCHER * 100));
    }
    if (quantity < 1) quantity = 1;
    if (quantity > 100) quantity = 100;

    const phone = metadata.phone || (data.customer && data.customer.phone) || "unknown";
    const email = data.customer?.email || null;

    const allocated = await allocateUnused(quantity, ref, phone, email);
    if (!allocated) {
      // Payment OK but no vouchers left -> store a History record indicating failure (optional)
      console.error(`Webhook: Payment success but insufficient vouchers for ref ${ref}`);
      return res.status(200).send("insufficient-vouchers");
    }

    console.log(`Webhook: allocated ${allocated.length} vouchers for ref ${ref}`);
    return res.status(200).send("ok");
  } catch (err) {
    console.error("Webhook handler error:", err);
    return res.status(500).send("error");
  }
});

// -------------------------
// Start server
// -------------------------
app.listen(PORT, () => {
  console.log(`✅ Backend running on port ${PORT}`);
});