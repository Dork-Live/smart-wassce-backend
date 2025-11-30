// server.js
// =======================================================
// Smart WASSCE — Backend (MongoDB + Paystack + Cloudflare R2)
// Added: Auto-email generator (auto1@smartwassce.com ...)
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
import { Readable } from "stream";

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

// price can be overridden via env; default to 20.5 as you requested
const PRICE_PER_VOUCHER = Number(process.env.PRICE_PER_VOUCHER || 25.5);

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "change-this-secret";

// Cloudflare R2
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || "";
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || "";
const R2_BUCKET = process.env.R2_BUCKET || "";
const R2_ENDPOINT = process.env.R2_ENDPOINT || "";
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL || "";

// Basic check
if (!R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET || !R2_ENDPOINT || !R2_PUBLIC_URL) {
  console.error("❌ Missing R2 environment variables");
  process.exit(1);
}

// -------------------------------------------------------
// Mongoose Connect
// -------------------------------------------------------
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => {
    console.error("❌ MongoDB Error:", err);
    process.exit(1);
  });

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

async function peekSequence(name) {
  const doc = await Counter.findOneAndUpdate(
    { name },
    {},
    { new: true, upsert: true }
  );
  return doc.seq;
}

async function setSequence(name, value) {
  const v = Math.max(0, Number(value) || 0);
  const doc = await Counter.findOneAndUpdate(
    { name },
    { $set: { seq: v } },
    { new: true, upsert: true }
  );
  return doc.seq;
}

const Voucher = mongoose.model(
  "Voucher",
  new mongoose.Schema({
    cardId: Number,
    filename: String,
    r2url: String,
    status: { type: String, default: "unused" }, // unused | used | archived
    batchId: String,
    uploadedAt: Date,
    usedAt: Date,
    reference: String
  })
);

const History = mongoose.model(
  "History",
  new mongoose.Schema({
    cardId: Number,
    filename: String,
    usedBy: String,
    usedByEmail: String,
    reference: String,
    dateUsed: Date
  })
);

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

// Upload to R2
async function uploadToR2(buffer, key, contentType) {
  await r2.send(
    new PutObjectCommand({
      Bucket: R2_BUCKET,
      Key: key,
      Body: buffer,
      ContentType: contentType
    })
  );
  return `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(key)}`;
}

// Delete from R2
async function deleteFromR2(key) {
  await r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key }));
}

// -------------------------------------------------------
// Express App
// -------------------------------------------------------
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json({ limit: "10mb" }));
app.use(cookieParser());

const upload = multer({ storage: multer.memoryStorage() });

// -------------------------------------------------------
// Auth Helpers
// -------------------------------------------------------
function signAdminToken(payload) {
  return jwt.sign(payload, ADMIN_JWT_SECRET, { expiresIn: "12h" });
}

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || "";
  let token = null;

  if (auth.startsWith("Bearer ")) token = auth.split(" ")[1];

  if (!token) return res.status(401).json({ success: false, error: "Unauthorized" });

  try {
    req.admin = jwt.verify(token, ADMIN_JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: "Invalid token" });
  }
}

// -------------------------------------------------------
// Root Endpoints
// -------------------------------------------------------
app.get("/", (req, res) => res.send("Smart WASSCE Backend Running"));
app.get("/healthz", (req, res) => res.send("ok"));

// -------------------------------------------------------
// Admin Login
// POST /api/admin/login { email, password }
// -------------------------------------------------------
app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body || {};
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, error: "Invalid credentials" });
  }

  return res.json({
    success: true,
    token: signAdminToken({ email }),
    email
  });
});

// -------------------------------------------------------
// Upload Vouchers
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
// GET All Vouchers (Admin)
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
// Delete One Voucher (Admin)
// POST /api/vouchers/delete-one { id, filename }
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
// GET Full Purchase / Usage History (Admin)
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

// =======================================================
// PAYSTACK — initialize payment
// POST /api/pay { email, phone, quantity, amount }
// =======================================================
app.post("/api/pay", async (req, res) => {
  try {
    const { email, phone, quantity, amount } = req.body || {};
    if (!email || !phone || !quantity || amount == null) return res.status(400).json({ success: false, error: "Missing fields" });

    const qty = Number(quantity);
    if (!Number.isFinite(qty) || qty < 1) return res.status(400).json({ success: false, error: "Invalid quantity" });

    // use cents / integer to avoid float errors
    const expectedCents = Math.round(qty * PRICE_PER_VOUCHER * 100);
    const incomingCents = Math.round(Number(amount) * 100);

    if (incomingCents !== expectedCents) {
      return res.status(400).json({ success: false, error: `Amount mismatch. Expected ${(expectedCents/100).toFixed(2)}` });
    }

    const unusedCount = await Voucher.countDocuments({ status: "unused" });
    if (unusedCount < qty) return res.status(400).json({ success: false, error: `Only ${unusedCount} voucher(s) available.` });

    if (!PAYSTACK_SECRET_KEY) return res.status(500).json({ success: false, error: "Paystack key not configured" });

    const payload = {
      email,
      amount: incomingCents,
      metadata: { phone, quantity: qty },
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

// =======================================================
// PAYSTACK — verify (idempotent)
// GET /api/verify/:reference
// =======================================================
app.get("/api/verify/:reference", async (req, res) => {
  try {
    const ref = req.params.reference;
    if (!ref) return res.status(400).json({ success: false, error: "Missing reference" });
    if (!PAYSTACK_SECRET_KEY) return res.status(500).json({ success: false, error: "Paystack key not configured" });

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

// =======================================================
// PAYSTACK Webhook (raw body, signature check)
// =======================================================
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
// PUBLIC retrieve by phone + reference (dual verification)
// GET /api/public/retrieve?phone=...&reference=...
// -------------------------------------------------------
app.get("/api/public/retrieve", async (req, res) => {
  try {
    const rawPhone = String(req.query.phone || "").trim();
    const rawRef = String(req.query.reference || req.query.ref || "").trim();

    if (!rawPhone || !rawRef) {
      return res.status(400).json({ success: false, error: "Missing phone or reference" });
    }

    const cleanedPhone = rawPhone.replace(/\D/g, "");
    if (cleanedPhone.length < 7) {
      return res.status(400).json({ success: false, error: "Invalid phone number" });
    }

    const ref = rawRef.trim();
    const allHistory = await History.find({ reference: ref }).lean();

    const matches = allHistory.filter(h => {
      const phoneField = (h.usedBy || "").replace(/\D/g, "");
      return phoneField.endsWith(cleanedPhone);
    });

    const vouchers = matches.map(h => `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(h.filename)}`);

    return res.json({ success: true, vouchers });
  } catch (err) {
    console.error("/api/public/retrieve error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});

// -------------------------------------------------------
// PUBLIC SEARCH (Retrieve by phone only) - kept for compatibility
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

// =======================================================
// DOWNLOAD PROXY (fixes R2 CORS/download issues)
// GET /api/download?url=...
// =======================================================
app.get("/api/download", async (req, res) => {
  try {
    const fileUrl = req.query.url;
    if (!fileUrl) return res.status(400).send("Missing file URL");

    console.log("[download] proxying:", fileUrl);

    const response = await fetch(fileUrl);

    if (!response.ok) {
      console.error("[download] fetch failed:", response.status, response.statusText);
      return res.status(502).send("Failed to fetch file from origin");
    }

    const contentType = response.headers.get("content-type") || "application/octet-stream";
    res.setHeader("Content-Type", contentType);

    const filename = decodeURIComponent((fileUrl.split("/").pop() || "voucher").replace(/["']/g, ""));
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);

    const body = response.body;
    if (!body) {
      console.error("[download] response has no body");
      return res.status(502).send("Empty response body");
    }

    if (typeof body.pipe === "function") {
      return body.pipe(res);
    }

    // WHATWG -> node stream conversion
    const reader = body.getReader();
    const nodeStream = new Readable({
      async read() {
        try {
          const { done, value } = await reader.read();
          if (done) return this.push(null);
          this.push(Buffer.from(value));
        } catch (err) {
          this.destroy(err);
        }
      }
    });

    return nodeStream.pipe(res);
  } catch (err) {
    console.error("[download] proxy error:", err && err.stack ? err.stack : err);
    try { if (!res.headersSent) res.status(500).send("Server download error"); else res.end(); } catch(e){}
  }
});

// =======================================================
// AUTO-EMAIL FEATURE
// - Public endpoint: GET /api/auto-email/next  (rate-limited per IP)
// - Admin endpoints:
//     GET  /api/admin/auto-email/counter  (peek current counter)
//     POST /api/admin/auto-email/reset    (body: { next: <number> }) to set next seq
// Implementation: uses Counter document named "autoEmailSeq".
// Format: auto{N}@smartwassce.com  (N is the sequence value returned by getNextSequence)
// =======================================================

const AUTO_NAME = "autoEmailSeq";
const AUTO_DOMAIN = process.env.AUTO_EMAIL_DOMAIN || "smartwassce.com";

// simple in-memory rate limiter per IP to avoid repeated auto-increment abuse
const ipLastCall = new Map();
const RATE_LIMIT_MS = 60 * 1000; // 60 seconds

app.get("/api/auto-email/next", async (req, res) => {
  try {
    const ip = (req.headers["x-forwarded-for"] || req.ip || "unknown").toString();
    const last = ipLastCall.get(ip) || 0;
    const now = Date.now();
    if (now - last < RATE_LIMIT_MS) {
      const wait = Math.ceil((RATE_LIMIT_MS - (now - last)) / 1000);
      return res.status(429).json({ success: false, error: `Rate limited. Try again in ${wait}s` });
    }

    // increment and get the next sequence number
    const seq = await getNextSequence(AUTO_NAME); // seq will be 1,2,3...
    ipLastCall.set(ip, now);

    const email = `auto${seq}@${AUTO_DOMAIN}`;
    return res.json({ success: true, email, seq });
  } catch (err) {
    console.error("/api/auto-email/next error:", err);
    return res.status(500).json({ success: false, error: "Failed to generate auto email" });
  }
});

// Admin: peek current counter (next value to be returned will be seq+1)
app.get("/api/admin/auto-email/counter", requireAdmin, async (req, res) => {
  try {
    const seq = await peekSequence(AUTO_NAME);
    // If seq is 0 means not used yet; show next that will be generated (seq+1)
    return res.json({ success: true, currentSeq: seq, nextWouldBe: seq + 1 });
  } catch (err) {
    console.error("admin/auto-email/counter error:", err);
    return res.status(500).json({ success: false, error: "Failed to read counter" });
  }
});

// Admin: reset or set next sequence number
app.post("/api/admin/auto-email/reset", requireAdmin, async (req, res) => {
  try {
    const next = Number(req.body?.next);
    if (!Number.isFinite(next) || next < 1) {
      return res.status(400).json({ success: false, error: "Invalid next number (must be >= 1)" });
    }
    // We store seq = next - 1 because getNextSequence increments before returning
    const storeValue = Math.max(0, next - 1);
    await setSequence(AUTO_NAME, storeValue);
    return res.json({ success: true, message: `Auto-email counter set. Next will be ${next}` });
  } catch (err) {
    console.error("admin/auto-email/reset error:", err);
    return res.status(500).json({ success: false, error: "Failed to set counter" });
  }
});

// -------------------------------------------------------
// DELETE ALL VOUCHERS (Admin)
// -------------------------------------------------------
app.delete("/api/vouchers/delete-all", requireAdmin, async (req, res) => {
  try {
    const vouchers = await Voucher.find({});

    for (const v of vouchers) {
      if (v.filename) {
        try {
          await deleteFromR2(v.filename);
        } catch (err) {
          console.warn("R2 delete failed:", v.filename, err.message);
        }
      }
    }

    await Voucher.deleteMany({});
    return res.json({ success: true, message: "All vouchers deleted" });
  } catch (err) {
    console.error("Delete-all vouchers error:", err);
    return res.status(500).json({ success: false, error: "Failed to delete all vouchers" });
  }
});

// -------------------------------------------------------
// DELETE ALL HISTORY (Admin)
// -------------------------------------------------------
app.delete("/api/history/delete-all", requireAdmin, async (req, res) => {
  try {
    await History.deleteMany({});
    return res.json({ success: true, message: "All history cleared" });
  } catch (err) {
    console.error("Delete-all history error:", err);
    return res.status(500).json({ success: false, error: "Failed to delete history" });
  }
});

// -------------------------------------------------------
// Export endpoints (Admin)
app.get("/api/vouchers/export", requireAdmin, async (req, res) => {
  try {
    const vouchers = await Voucher.find({}).lean();
    return res.json({ success: true, vouchers });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});
app.get("/api/vouchers/export-used", requireAdmin, async (req, res) => {
  try {
    const vouchers = await Voucher.find({ status: "used" }).lean();
    return res.json({ success: true, vouchers });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});
app.get("/api/vouchers/export-unused", requireAdmin, async (req, res) => {
  try {
    const vouchers = await Voucher.find({ status: "unused" }).lean();
    return res.json({ success: true, vouchers });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});
app.get("/api/history/export", requireAdmin, async (req, res) => {
  try {
    const history = await History.find({}).lean();
    return res.json({ success: true, history });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// -------------------------------------------------------
// Admin low-stock & revenue endpoints
app.get("/api/admin/low-stock", requireAdmin, async (req, res) => {
  try {
    const unused = await Voucher.countDocuments({ status: "unused" });
    const low = unused < 5;
    return res.json({ success: true, unused, low, threshold: 50 });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.get("/api/admin/revenue-stats", requireAdmin, async (req, res) => {
  try {
    const PRICE = PRICE_PER_VOUCHER || 22.5;
    const history = await History.find({}).lean();

    const totalVouchers = history.length;
    const totalRevenue = totalVouchers * PRICE;

    const daily = {};
    history.forEach(h => {
      const day = new Date(h.dateUsed).toISOString().split("T")[0];
      if (!daily[day]) daily[day] = 0;
      daily[day] += PRICE;
    });

    return res.json({ success: true, totalRevenue, totalVouchers, PRICE, daily });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// -------------------------------------------------------
// START SERVER
// -------------------------------------------------------
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
