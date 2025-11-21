// =======================================================
// Smart WASSCE — Backend (MongoDB + Paystack + R2 Storage)
// =======================================================

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

// Load env
dotenv.config();

// dirname (ESM)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -------------------------------------------------------
// Environment Config
// -------------------------------------------------------
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_WEBHOOK_SECRET = process.env.PAYSTACK_WEBHOOK_SECRET || PAYSTACK_SECRET_KEY;

const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const FRONTEND_SUCCESS_URL = process.env.FRONTEND_SUCCESS_URL || `${BASE_URL}/success.html`;

const PRICE_PER_VOUCHER = Number(process.env.PRICE_PER_VOUCHER || 25);

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET;

// ----------- R2 STORAGE SETTINGS -------------
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET = process.env.R2_BUCKET;  // bucket name only
const R2_ENDPOINT = process.env.R2_ENDPOINT; // example: https://<accountid>.r2.cloudflarestorage.com
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL; // example: https://pub-xxxxx.r2.dev

if (!R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET || !R2_ENDPOINT || !R2_PUBLIC_URL) {
  console.error("❌ Missing R2 env variables!");
  console.error("You MUST set: R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET, R2_ENDPOINT, R2_PUBLIC_URL");
  process.exit(1);
}

// -------------------------------------------------------
// Mongoose Connection
// -------------------------------------------------------
async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  }
}
connectDB();

// -------------------------------------------------------
// Database Schemas
// -------------------------------------------------------

const CounterSchema = new mongoose.Schema({
  name: String,
  seq: Number
});
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
  filename: String,     // stored file name
  r2url: String,        // public URL
  status: { type: String, default: "unused" }, // unused, used
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
    secretAccessKey: R2_SECRET_ACCESS_KEY,
  }
});

// -------------------------------------------------------
// Express App Setup
// -------------------------------------------------------
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json({ limit: "5mb" }));
app.use(cookieParser());

// ----------------- Multer (Memory Upload to R2) -----------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8 MB each
});
// ----------------------
// PART 2 — Upload / Admin routes / R2 helpers
// ----------------------

// ----------------------
// Admin auth helper
// ----------------------
function signAdminToken(payload = {}) {
  return jwt.sign(payload, ADMIN_JWT_SECRET || "change-me", { expiresIn: "12h" });
}
function verifyAdminToken(token) {
  try { return jwt.verify(token, ADMIN_JWT_SECRET || "change-me"); }
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

// ----------------------
// R2 helpers
// ----------------------
import { PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";

async function uploadToR2(buffer, key, contentType = "image/jpeg") {
  const cmd = new PutObjectCommand({
    Bucket: R2_BUCKET,
    Key: key,
    Body: buffer,
    ContentType: contentType,
    ACL: "public-read" // Cloudflare R2 ignores ACL but harmless
  });
  await r2.send(cmd);
  return `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(key)}`;
}

async function deleteFromR2(key) {
  const cmd = new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key });
  await r2.send(cmd);
}

// ----------------------
// Upload vouchers (admin) — memory multer -> R2 -> DB
// multipart/form-data, field name "vouchers"
// ----------------------
app.post("/api/upload-vouchers", requireAdmin, upload.array("vouchers", 50), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0)
      return res.status(400).json({ success: false, error: "No files uploaded" });

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

// ----------------------
// GET all vouchers (admin) — return r2url
// ----------------------
app.get("/api/vouchers/all", requireAdmin, async (req, res) => {
  try {
    const vouchers = await Voucher.find({}).sort({ cardId: 1 }).lean();
    const mapped = vouchers.map(v => ({
      ...v,
      r2url: v.r2url || (v.filename ? `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(v.filename)}` : null)
    }));
    return res.json({ success: true, vouchers: mapped });
  } catch (err) {
    console.error("Read vouchers error:", err);
    return res.status(500).json({ success: false, error: "Failed to read vouchers" });
  }
});

// ----------------------
// GET single voucher by id (admin)
// ----------------------
app.get("/api/voucher/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const v = await Voucher.findOne({ cardId: id }).lean();
    if (!v) return res.status(404).json({ success: false, error: "Voucher not found" });
    v.r2url = v.r2url || (v.filename ? `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(v.filename)}` : null);
    return res.json({ success: true, voucher: v });
  } catch (err) {
    console.error("Get voucher error:", err);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});

// ----------------------
// DELETE single voucher by id (admin)
// - deletes object from R2 if filename present
// - removes DB voucher doc
// - DOES NOT touch History (so past purchases remain)
// ----------------------
app.delete("/api/voucher/:id/delete", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const v = await Voucher.findOne({ cardId: id }).lean();
    if (!v) return res.status(404).json({ success: false, error: "Voucher not found" });

    // delete from R2 (best-effort)
    if (v.filename) {
      try {
        await deleteFromR2(v.filename);
      } catch (e) {
        console.warn("R2 delete failed for", v.filename, e.message);
        // continue — still attempt DB deletion
      }
    }

    // remove from DB
    await Voucher.deleteOne({ cardId: id });

    return res.json({ success: true, message: `Deleted voucher ${id}` });
  } catch (err) {
    console.error("Delete voucher error:", err);
    return res.status(500).json({ success: false, error: "Failed to delete voucher" });
  }
});

// ----------------------
// GET history (admin)
// ----------------------
app.get("/api/history", requireAdmin, async (req, res) => {
  try {
    const history = await History.find({}).sort({ dateUsed: -1 }).lean();
    return res.json({ success: true, history });
  } catch (err) {
    console.error("Read history error:", err);
    return res.status(500).json({ success: false, error: "Failed to read history" });
  }
});

// ----------------------
// FIND by reference (public) — returns r2 URLs for that reference
// ----------------------
app.get("/api/find-by-reference/:ref", async (req, res) => {
  try {
    const ref = req.params.ref;
    if (!ref) return res.status(400).json({ success: false, error: "Missing reference" });

    const hist = await History.find({ reference: ref }).lean();
    if (!hist.length) return res.json({ success: false, error: "No vouchers found for this reference" });

    const urls = hist.map(h => `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(h.filename)}`);
    return res.json({ success: true, vouchers: urls });
  } catch (err) {
    console.error("find-by-reference error:", err);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});
// ----------------------
// Allocate Unused Vouchers (R2 version)
// ----------------------
async function allocateUnused(qty, reference = null, phone = "unknown", email = null) {
  const unused = await Voucher.find({ status: "unused" })
    .sort({ cardId: 1 })
    .limit(qty);

  if (unused.length < qty) return null;

  const ids = unused.map(u => u._id);

  // mark as used
  await Voucher.updateMany(
    { _id: { $in: ids } },
    { $set: { status: "used", usedAt: new Date(), reference } }
  );

  // history log
  const hist = unused.map(u => ({
    cardId: u.cardId,
    filename: u.filename,
    usedBy: phone,
    usedByEmail: email || null,
    reference,
    dateUsed: new Date()
  }));

  await History.insertMany(hist);

  // return R2 URLs
  return unused.map(u => ({
    id: u.cardId,
    filename: u.filename,
    url: `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(u.filename)}`
  }));
}

// ----------------------
// Paystack INITIATE PAYMENT
// ----------------------
app.post("/api/pay", async (req, res) => {
  try {
    const { email, phone, quantity, amount } = req.body || {};
    if (!email || !phone || !quantity || !amount)
      return res.status(400).json({ success: false, error: "Missing fields" });

    const expected = Number(quantity) * PRICE_PER_VOUCHER;
    if (Number(amount) !== expected)
      return res.status(400).json({ success: false, error: `Amount mismatch. Expected ${expected}` });

    const unusedCount = await Voucher.countDocuments({ status: "unused" });
    if (unusedCount < quantity)
      return res.status(400).json({
        success: false,
        error: `Only ${unusedCount} voucher(s) available.`
      });

    if (!PAYSTACK_SECRET_KEY)
      return res.status(500).json({ success: false, error: "Paystack key missing" });

    const payload = {
      email,
      amount: Number(amount) * 100,
      metadata: { phone, quantity },
      callback_url: FRONTEND_SUCCESS_URL
    };

    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      payload,
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    return res.json(response.data);

  } catch (err) {
    console.error("PAY INIT ERROR:", err.response?.data || err.message);
    return res.status(500).json({
      success: false,
      error: "Payment initialization failed",
      details: err.response?.data
    });
  }
});

// ----------------------
// Paystack VERIFY route
// ----------------------
app.get("/api/verify/:reference", async (req, res) => {
  try {
    const ref = req.params.reference;

    if (!ref)
      return res.status(400).json({ success: false, error: "Missing reference" });

    if (!PAYSTACK_SECRET_KEY)
      return res.status(500).json({ success: false, error: "Paystack key missing" });

    // idempotency: return already allocated vouchers
    const existing = await History.find({ reference: ref }).lean();
    if (existing.length > 0) {
      const urls = existing.map(h =>
        `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(h.filename)}`
      );
      return res.json({ success: true, vouchers: urls, message: "Already verified" });
    }

    // verify with Paystack
    const verifyResp = await axios.get(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(ref)}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } }
    );

    const payload = verifyResp.data;
    if (!payload.status || payload.data.status !== "success")
      return res.status(400).json({ success: false, error: "Payment not successful" });

    const metadata = payload.data.metadata || {};
    let quantity = parseInt(metadata.quantity, 10);

    if (!quantity || isNaN(quantity)) {
      quantity = Math.round(
        Number(payload.data.amount) / (PRICE_PER_VOUCHER * 100)
      );
    }

    const phone = metadata.phone || payload.data.customer?.phone || "unknown";
    const email = payload.data.customer?.email || null;

    const assigned = await allocateUnused(quantity, ref, phone, email);

    if (!assigned)
      return res.status(400).json({
        success: false,
        error: "Payment OK but no vouchers left"
      });

    return res.json({ success: true, vouchers: assigned.map(a => a.url), assigned });

  } catch (err) {
    console.error("VERIFY ERROR:", err.response?.data || err.message);
    return res.status(500).json({ success: false, error: "Verification failed" });
  }
});

// ----------------------
// PAYSTACK WEBHOOK
// ----------------------
app.post(
  "/api/paystack/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature = req.headers["x-paystack-signature"];
      const computed = crypto
        .createHmac("sha512", PAYSTACK_WEBHOOK_SECRET)
        .update(req.body)
        .digest("hex");

      if (signature !== computed) {
        console.warn("Webhook signature mismatch");
        return res.status(400).send("Invalid signature");
      }

      const payload = JSON.parse(req.body.toString("utf8"));
      const data = payload.data;

      if (!data || data.status !== "success")
        return res.status(200).send("ignored");

      const ref = data.reference;
      if (!ref) return res.status(400).send("no reference");

      // idempotent check
      const existing = await History.find({ reference: ref }).lean();
      if (existing.length > 0) return res.status(200).send("already processed");

      const metadata = data.metadata || {};
      let quantity = parseInt(metadata.quantity, 10);

      if (!quantity || isNaN(quantity)) {
        quantity = Math.round(Number(data.amount) / (PRICE_PER_VOUCHER * 100));
      }

      const phone = metadata.phone || data.customer?.phone || "unknown";
      const email = data.customer?.email || null;

      const allocated = await allocateUnused(quantity, ref, phone, email);

      if (!allocated) return res.status(200).send("insufficient vouchers");

      return res.status(200).send("ok");

    } catch (err) {
      console.error("Webhook error:", err);
      return res.status(500).send("error");
    }
  }
);

// ----------------------
// PUBLIC SEARCH BY PHONE
// ----------------------
app.get("/api/public/history", async (req, res) => {
  try {
    const phoneRaw = (req.query.phone || "").trim();

    if (!phoneRaw)
      return res.status(400).json({ success: false, error: "Missing phone" });

    const cleaned = phoneRaw.replace(/\D/g, "");
    if (cleaned.length < 9) return res.json({ success: true, vouchers: [] });

    const hist = await History.find({}).lean();

    const matches = hist.filter(h => {
      const p = (h.usedBy || "").replace(/\D/g, "");
      return p.endsWith(cleaned);
    });

    const urls = matches.map(h =>
      `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(h.filename)}`
    );

    return res.json({ success: true, vouchers: urls });

  } catch (err) {
    console.error("phone history error:", err);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});

// ----------------------
// START SERVER
// ----------------------
app.listen(PORT, () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});