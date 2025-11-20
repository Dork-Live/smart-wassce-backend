// server.js — Smart WASSCE backend (Mongoose + Paystack webhook + Admin JWT + Cloudflare R2)
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import bodyParser from "body-parser";
import path from "path";
import { S3Client, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import multer from "multer";
import axios from "axios";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "url";

dotenv.config();

// --- __dirname for ESM (kept if you need local files later)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Config (via .env in Render or your host)
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || "";
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || "";
const PAYSTACK_WEBHOOK_SECRET = process.env.PAYSTACK_WEBHOOK_SECRET || PAYSTACK_SECRET_KEY;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const FRONTEND_SUCCESS_URL = process.env.FRONTEND_SUCCESS_URL || `${BASE_URL}/success.html`;
const PRICE_PER_VOUCHER = Number(process.env.PRICE_PER_VOUCHER || 25);
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "change-this-secret";

// R2 config — MUST be provided in env
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || "";
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || "";
const R2_BUCKET = process.env.R2_BUCKET || ""; // bucket name
const R2_ENDPOINT = process.env.R2_ENDPOINT || ""; // e.g. https://<account>.r2.dev
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL || ""; // e.g. https://pub-....r2.dev

if (!R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET || !R2_ENDPOINT || !R2_PUBLIC_URL) {
  console.warn("⚠️ R2 configuration missing. Set R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET, R2_ENDPOINT, R2_PUBLIC_URL in env.");
}

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
  filename: { type: String, required: true }, // object key used in R2
  r2url: { type: String },                     // public URL for direct access
  status: { type: String, enum: ["unused", "used", "archived"], default: "unused" },
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
// S3 (R2) Client
// -------------------------
const s3 = new S3Client({
  region: "auto",
  endpoint: R2_ENDPOINT || undefined,
  credentials: {
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_ACCESS_KEY,
  },
  forcePathStyle: false,
});

// helper to upload to R2 (PutObject)
async function uploadToR2(buffer, key, contentType = "image/jpeg") {
  if (!R2_BUCKET || !R2_ENDPOINT) throw new Error("R2 not configured");
  const cmd = new PutObjectCommand({
    Bucket: R2_BUCKET,
    Key: key,
    Body: buffer,
    ContentType: contentType,
    // You can set ACL or metadata here if needed.
  });
  await s3.send(cmd);
  return `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(key)}`;
}

// helper to delete from R2 (DeleteObject)
async function deleteFromR2(key) {
  if (!R2_BUCKET || !R2_ENDPOINT) throw new Error("R2 not configured");
  const cmd = new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key });
  await s3.send(cmd);
}

// -------------------------
// Express app
// -------------------------
const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json({ limit: "2mb" }));
app.use(cookieParser());

// NOTE: No local /uploads static serving — we rely on R2 public URLs

// -------------------------
// Multer config (memory storage — upload straight from memory to R2)
// -------------------------
const memStorage = multer.memoryStorage();
const upload = multer({
  storage: memStorage,
  limits: { files: 50, fileSize: 8 * 1024 * 1024 }, // adjust as needed
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
  else if (req.cookies?.admin_token) token = req.cookies.admin_token;
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
// allocateUnused now returns r2url from DB
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

  return unused.map(u => ({ id: u.cardId, filename: u.filename, url: u.r2url }));
}

// -------------------------
// Routes
// -------------------------
app.get("/", (req, res) => res.send("✅ Smart WASSCE backend (Mongo + Paystack webhook)"));

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
 * Upload vouchers (admin) — upload straight to R2 and save DB doc
 * multer.memoryStorage -> file.buffer
 */
app.post("/api/upload-vouchers", requireAdmin, upload.array("vouchers", 50), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) return res.status(400).json({ success: false, error: "No files" });
    if (!R2_BUCKET || !R2_ENDPOINT) return res.status(500).json({ success: false, error: "R2 not configured" });

    const batchId = `batch-${Date.now()}`;
    const added = [];

    for (const file of req.files) {
      const seq = await getNextSequence("voucherSeq", 1);
      const ext = path.extname(file.originalname).toLowerCase() || ".jpg";
      const newFilename = `voucher_${seq}${ext}`;
      const contentType = file.mimetype || "image/jpeg";

      // upload to R2
      await uploadToR2(file.buffer, newFilename, contentType);

      const r2url = `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(newFilename)}`;

      const v = new Voucher({
        cardId: seq,
        filename: newFilename,
        r2url,
        status: "unused",
        batchId,
        uploadedAt: new Date(),
      });
      await v.save();

      added.push({ id: seq, filename: newFilename, url: r2url });
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
    // ensure we return r2url for frontend
    const mapped = vouchers.map(v => ({
      ...v,
      r2url: v.r2url || (v.filename ? `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(v.filename)}` : null),
    }));
    return res.json({ success: true, vouchers: mapped });
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
 * DELETE /api/voucher/:id  (admin)
 * - deletes the object from R2 (if present)
 * - deletes the Voucher document
 * - DOES NOT delete History (you chose B)
 */
app.delete("/api/voucher/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) return res.status(400).json({ success: false, error: "Missing id" });

    // look up by cardId or Mongo _id (allow both)
    let voucher = await Voucher.findOne({ cardId: Number(id) }).lean();
    if (!voucher) voucher = await Voucher.findById(id).lean();
    if (!voucher) return res.status(404).json({ success: false, error: "Voucher not found" });

    // attempt delete from R2 if filename present
    if (voucher.filename) {
      try {
        await deleteFromR2(voucher.filename);
      } catch (e) {
        console.warn("R2 delete failed or object not found:", e.message || e);
        // continue — we'll still remove the DB doc to keep admin view accurate
      }
    }

    // delete voucher doc from DB
    await Voucher.deleteOne({ _id: voucher._id });

    return res.json({ success: true, message: "Voucher deleted (history preserved)." });
  } catch (err) {
    console.error("Delete voucher error:", err);
    return res.status(500).json({ success: false, error: "Failed to delete voucher", details: err.message });
  }
});

/**
 * GET /api/find-by-reference/:ref
 * Returns voucher URLs previously allocated for this reference (idempotent)
 */
app.get("/api/find-by-reference/:ref", async (req, res) => {
  try {
    const ref = req.params.ref;
    if (!ref) return res.status(400).json({ success: false, error: "Missing reference" });
    const history = await History.find({ reference: ref }).lean();
    if (!history.length) return res.json({ success: false, error: "No vouchers found for this reference" });
    const urls = history.map(h => `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(h.filename)}`);
    return res.json({ success: true, vouchers: urls, message: "Found" });
  } catch (err) {
    console.error("find-by-reference error:", err);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});

/**
 * POST /api/pay
 * Initialize Paystack transaction
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
 * Verifies with Paystack (if not yet allocated) and allocates vouchers.
 */
app.get("/api/verify/:reference", async (req, res) => {
  try {
    const ref = req.params.reference;
    if (!ref) return res.status(400).json({ success: false, error: "Missing reference" });
    if (!PAYSTACK_SECRET_KEY) return res.status(500).json({ success: false, error: "Paystack key not configured" });

    // If we already have history, return immediately
    const existing = await History.find({ reference: ref }).lean();
    if (existing.length > 0) {
      const urls = existing.map(h => `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(h.filename)}`);
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
 */
app.post("/api/paystack/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const signature = req.headers["x-paystack-signature"];
    const computed = crypto.createHmac("sha512", PAYSTACK_WEBHOOK_SECRET).update(req.body).digest("hex");
    if (signature !== computed) {
      console.warn("Webhook signature mismatch");
      return res.status(400).send("Invalid signature");
    }

    const payload = JSON.parse(req.body.toString("utf8"));
    const data = payload.data || payload;
    if (!data || data.status !== "success") return res.status(200).send("ignored");

    const ref = data.reference || data.trxref || data.id || null;
    if (!ref) return res.status(400).send("no reference");

    // idempotent: skip if history exists
    const existing = await History.find({ reference: ref }).lean();
    if (existing.length > 0) {
      console.log(`Webhook: reference ${ref} already processed`);
      return res.status(200).send("already-processed");
    }

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

/**
 * GET /api/public/history
 * Public route — lookup vouchers by phone ONLY
 * Example: /api/public/history?phone=0241234567
 */
app.get("/api/public/history", async (req, res) => {
  try {
    const rawPhone = (req.query.phone || "").trim();
    if (!rawPhone) return res.status(400).json({ success: false, error: "Missing phone number" });

    const cleaned = rawPhone.replace(/\D/g, "");
    if (cleaned.length < 9) return res.json({ success: true, vouchers: [] });

    const history = await History.find({}).lean();

    const matches = history.filter(h => {
      const phoneField = (h.usedBy || "").replace(/\D/g, "");
      return phoneField.endsWith(cleaned);
    });

    const vouchers = matches.map(h => `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(h.filename)}`);

    res.json({ success: true, vouchers });
  } catch (err) {
    console.error("Public history error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// -------------------------
// Start server
// -------------------------
app.listen(PORT, () => {
  console.log(`✅ Backend running on port ${PORT}`);
});-
