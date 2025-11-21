// =======================================================
// Smart WASSCE — Backend (MongoDB + Paystack + Cloudflare R2)
// =======================================================

import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import bodyParser from "body-parser";
import { S3Client, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import multer from "multer";
import axios from "axios";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "url";
import path from "path";

dotenv.config();

// dirname for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -------------------------------------------------------
// ENV CONFIG
// -------------------------------------------------------
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

// Cloudflare R2
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || "";
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || "";
const R2_BUCKET = process.env.R2_BUCKET || "";
const R2_ENDPOINT = process.env.R2_ENDPOINT || "";
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL || "";

// If R2 is required for your workflow, fail early (you had this behavior before).
if (!R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET || !R2_ENDPOINT || !R2_PUBLIC_URL) {
  console.error("❌ Missing R2 env variables. Please set R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET, R2_ENDPOINT, R2_PUBLIC_URL");
  process.exit(1);
}

// -------------------------------------------------------
// Mongoose Connect
// -------------------------------------------------------
async function connectDB() {
  if (!MONGO_URI) {
    console.error("❌ MONGO_URI not provided in environment.");
    process.exit(1);
  }
  try {
    await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log("✅ MongoDB Connected");
  } catch (err) {
    console.error("❌ MongoDB Error:", err);
    process.exit(1);
  }
}
connectDB();

// -------------------------------------------------------
// Schemas
// -------------------------------------------------------
const CounterSchema = new mongoose.Schema({ name: String, seq: { type: Number, default: 0 } });
const Counter = mongoose.model("Counter", CounterSchema);

async function getNextSequence(name) {
  const doc = await Counter.findOneAndUpdate(
    { name },
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return doc.seq;
}

const VoucherSchema = new mongoose.Schema({
  cardId: Number,
  filename: String,
  r2url: String,
  status: { type: String, default: "unused" },  // unused | used | archived
  batchId: String,
  uploadedAt: Date,
  usedAt: Date,
  reference: String
});
const Voucher = mongoose.model("Voucher", VoucherSchema);

const HistorySchema = new mongoose.Schema({
  cardId: Number,
  filename: String,
  usedBy: String,
  usedByEmail: String,
  reference: String,
  dateUsed: Date
});
const History = mongoose.model("History", HistorySchema);

// -------------------------------------------------------
// Cloudflare R2 Client
// -------------------------------------------------------
const r2 = new S3Client({
  region: "auto",
  endpoint: R2_ENDPOINT,
  credentials: {
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_ACCESS_KEY
  }
});

// Upload helper
async function uploadToR2(buffer, key, contentType = "application/octet-stream") {
  const cmd = new PutObjectCommand({
    Bucket: R2_BUCKET,
    Key: key,
    Body: buffer,
    ContentType: contentType
  });
  await r2.send(cmd);
  // return public URL (ensure R2_PUBLIC_URL set correctly)
  return `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(key)}`;
}

// Delete helper
async function deleteFromR2(key) {
  const cmd = new DeleteObjectCommand({
    Bucket: R2_BUCKET,
    Key: key
  });
  await r2.send(cmd);
}

// -------------------------------------------------------
// Express App
// -------------------------------------------------------
const app = express();
app.use(cors({ origin: true, credentials: true }));
// parse JSON bodies
app.use(bodyParser.json({ limit: "10mb" }));
app.use(cookieParser());

// Multer (Memory Upload)
const upload = multer({ storage: multer.memoryStorage() });

// -------------------------------------------------------
// Admin Auth helpers
// -------------------------------------------------------
function signAdminToken(payload = {}) {
  return jwt.sign(payload, ADMIN_JWT_SECRET, { expiresIn: "12h" });
}
function verifyAdminToken(token) {
  try { return jwt.verify(token, ADMIN_JWT_SECRET); }
  catch (e) { return null; }
}
function requireAdmin(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    let token = null;
    if (auth.startsWith("Bearer ")) token = auth.split(" ")[1];
    else if (req.cookies && req.cookies.admin_token) token = req.cookies.admin_token;
    else if (req.headers["x-admin-token"]) token = req.headers["x-admin-token"];

    if (!token) return res.status(401).json({ success: false, error: "Unauthorized - no token" });

    const payload = verifyAdminToken(token);
    if (!payload) return res.status(401).json({ success: false, error: "Unauthorized - invalid token" });

    req.admin = payload;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
}

// -------------------------------------------------------
// Root + health (simple checks)
// -------------------------------------------------------
app.get("/", (req, res) => res.send("✅ Smart WASSCE backend (MongoDB + Paystack + R2)"));
app.get("/healthz", (req, res) => res.send("ok"));

// -------------------------------------------------------
// Admin login
// POST /api/admin/login  { email, password }
// returns { success, token, email }
// -------------------------------------------------------
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

// -------------------------------------------------------
// Upload Vouchers to R2
// multipart/form-data field "vouchers" (multiple)
// -------------------------------------------------------
app.post("/api/upload-vouchers", requireAdmin, upload.array("vouchers", 50), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) return res.status(400).json({ success: false, error: "No files" });

    const batchId = `batch-${Date.now()}`;
    const added = [];

    for (const file of req.files) {
      const seq = await getNextSequence("voucherSeq");
      const ext = path.extname(file.originalname).toLowerCase() || ".jpg";
      const newFilename = `voucher_${seq}${ext}`;
      const contentType = file.mimetype || "image/jpeg";

      // upload to R2
      const r2url = await uploadToR2(file.buffer, newFilename, contentType);

      const v = new Voucher({
        cardId: seq,
        filename: newFilename,
        r2url,
        status: "unused",
        batchId,
        uploadedAt: new Date()
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

// -------------------------------------------------------
// GET all vouchers (admin)
// -------------------------------------------------------
app.get("/api/vouchers/all", requireAdmin, async (req, res) => {
  try {
    const vouchers = await Voucher.find({}).sort({ cardId: 1 }).lean();
    return res.json({ success: true, vouchers });
  } catch (err) {
    console.error("Read vouchers error:", err);
    return res.status(500).json({ success: false, error: "Failed to read vouchers" });
  }
});

// -------------------------------------------------------
// Delete one voucher (admin)
// POST /api/vouchers/delete-one { id, filename }
// - deletes object from R2 (best-effort) and deletes DB doc
// -------------------------------------------------------
app.post("/api/vouchers/delete-one", requireAdmin, async (req, res) => {
  try {
    const { id, filename } = req.body || {};
    if (!id) return res.status(400).json({ success: false, error: "Missing id" });

    if (filename) {
      try {
        await deleteFromR2(filename);
      } catch (e) {
        console.warn("R2 delete failed for", filename, e.message);
      }
    }

    await Voucher.deleteOne({ cardId: Number(id) });

    return res.json({ success: true, message: `Deleted voucher ${id}` });
  } catch (err) {
    console.error("Delete-one error:", err);
    return res.status(500).json({ success: false, error: "Delete failed", details: err.message });
  }
});

// -------------------------------------------------------
// GET history (admin)
// -------------------------------------------------------
app.get("/api/history", requireAdmin, async (req, res) => {
  try {
    const hist = await History.find({}).sort({ dateUsed: -1 }).lean();
    return res.json({ success: true, history: hist });
  } catch (err) {
    console.error("Read history error:", err);
    return res.status(500).json({ success: false, error: "Failed to read history" });
  }
});

// -------------------------------------------------------
// Allocate unused vouchers helper
// -------------------------------------------------------
async function allocateUnused(qty, reference = null, phone = "unknown", email = null) {
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
    dateUsed: new Date()
  }));
  await History.insertMany(hist);

  return unused.map(u => `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(u.filename)}`);
}

// -------------------------------------------------------
// PAYSTACK — initiate
// POST /api/pay { email, phone, quantity, amount }
// -------------------------------------------------------
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
      callback_url: FRONTEND_SUCCESS_URL
    };

    const response = await axios.post("https://api.paystack.co/transaction/initialize", payload, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`, "Content-Type": "application/json" }
    });

    return res.json(response.data);
  } catch (err) {
    console.error("Pay init error:", err.response?.data || err.message);
    return res.status(500).json({ success: false, error: "Payment initialization failed", details: err.response?.data || err.message });
  }
});

// -------------------------------------------------------
// PAYSTACK — verify (backwards-compatible)
// GET /api/verify/:reference
// -------------------------------------------------------
app.get("/api/verify/:reference", async (req, res) => {
  try {
    const ref = req.params.reference;
    if (!ref) return res.status(400).json({ success: false, error: "Missing reference" });
    if (!PAYSTACK_SECRET_KEY) return res.status(500).json({ success: false, error: "Paystack key not configured" });

    // idempotent: if history exists, return that
    const existing = await History.find({ reference: ref }).lean();
    if (existing.length > 0) {
      const urls = existing.map(h => `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(h.filename)}`);
      return res.json({ success: true, vouchers: urls, message: "Already verified" });
    }

    const verifyResp = await axios.get(`https://api.paystack.co/transaction/verify/${encodeURIComponent(ref)}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
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

    const phone = metadata.phone || payload.data.customer?.phone || "unknown";
    const email = payload.data.customer?.email || null;

    const assigned = await allocateUnused(quantity, ref, phone, email);
    if (!assigned) return res.status(400).json({ success: false, error: "Payment successful but not enough vouchers left." });

    return res.json({ success: true, vouchers: assigned });
  } catch (err) {
    console.error("Verify error:", err.response?.data || err.message);
    return res.status(500).json({ success: false, error: "Verification failed", details: err.response?.data || err.message });
  }
});

// -------------------------------------------------------
// PAYSTACK Webhook — raw body required for signature check
// -------------------------------------------------------
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

    const ref = data.reference;
    if (!ref) return res.status(400).send("no reference");

    const existing = await History.find({ reference: ref }).lean();
    if (existing.length > 0) {
      console.log(`Webhook: reference ${ref} already processed`);
      return res.status(200).send("already-processed");
    }

    const metadata = data.metadata || {};
    let quantity = parseInt(metadata.quantity, 10);
    if (!quantity || isNaN(quantity)) quantity = Math.round(Number(data.amount) / (PRICE_PER_VOUCHER * 100));
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
// -------------------------------------------------------
// SECURE DOWNLOAD PROXY (Fixes R2 CORS download issues)
// -------------------------------------------------------
import fetch from "node-fetch";  // <-- REQUIRED ON RENDER

app.get("/api/download", async (req, res) => {
  try {
    const fileUrl = req.query.url;
    if (!fileUrl) {
      return res.status(400).send("Missing file URL");
    }

    console.log("Downloading:", fileUrl);

    const encodedUrl = encodeURI(fileUrl);

    const response = await fetch(encodedUrl);

    if (!response.ok) {
      console.error("R2 Fetch Error:", response.status);
      return res.status(500).send("Failed to fetch file from R2");
    }

    // Extract filename from URL
    const filename = fileUrl.split("/").pop() || "voucher.jpg";

    // Pass through real content type
    const contentType = response.headers.get("content-type") || "application/octet-stream";
    res.setHeader("Content-Type", contentType);

    // Force browser download with correct filename
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);

    // Pipe file to client
    response.body.pipe(res);

  } catch (err) {
    console.error("Download error:", err);
    res.status(500).send("Server download error");
  }
});
// -------------------------------------------------------
// Public search by phone
// GET /api/public/history?phone=...
// -------------------------------------------------------
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
    return res.json({ success: true, vouchers });
  } catch (err) {
    console.error("Public history error:", err);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});
// -------------------------------------------------------
// SECURE DOWNLOAD PROXY (Fixes R2 CORS download issues)
// -------------------------------------------------------
import fetch from "node-fetch";  // <-- REQUIRED ON RENDER

app.get("/api/download", async (req, res) => {
  try {
    const fileUrl = req.query.url;
    if (!fileUrl) {
      return res.status(400).send("Missing file URL");
    }

    console.log("Downloading:", fileUrl);

    const encodedUrl = encodeURI(fileUrl);

    const response = await fetch(encodedUrl);

    if (!response.ok) {
      console.error("R2 Fetch Error:", response.status);
      return res.status(500).send("Failed to fetch file from R2");
    }

    // Extract filename from URL
    const filename = fileUrl.split("/").pop() || "voucher.jpg";

    // Pass through real content type
    const contentType = response.headers.get("content-type") || "application/octet-stream";
    res.setHeader("Content-Type", contentType);

    // Force browser download with correct filename
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);

    // Pipe file to client
    response.body.pipe(res);

  } catch (err) {
    console.error("Download error:", err);
    res.status(500).send("Server download error");
  }
});
// -------------------------------------------------------
// START SERVER
// -------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
