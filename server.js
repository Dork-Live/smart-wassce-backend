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
const R2_BUCKET = process.env.R2_BUCKET;
const R2_ENDPOINT = process.env.R2_ENDPOINT;
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL;

if (!R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET || !R2_ENDPOINT || !R2_PUBLIC_URL) {
  console.error("❌ Missing R2 env variables!");
  process.exit(1);
}

// -------------------------------------------------------
// MongoDB Connection
// -------------------------------------------------------
async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
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

const CounterSchema = new mongoose.Schema({ name: String, seq: Number });
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
  status: { type: String, default: "unused" },
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

// -------------------------------------------------------
// Multer (memory storage for direct upload to R2)
// -------------------------------------------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }
});

// -------------------------------------------------------
// Admin Authentication
// -------------------------------------------------------

function signAdminToken(payload = {}) {
  return jwt.sign(payload, ADMIN_JWT_SECRET, { expiresIn: "12h" });
}

function verifyAdminToken(token) {
  try { return jwt.verify(token, ADMIN_JWT_SECRET); }
  catch { return null; }
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || "";
  let token = null;

  if (header.startsWith("Bearer ")) token = header.split(" ")[1];
  else if (req.headers["x-admin-token"]) token = req.headers["x-admin-token"];
  else if (req.cookies?.admin_token) token = req.cookies.admin_token;

  if (!token) return res.status(401).json({ success: false, error: "Unauthorized" });

  const valid = verifyAdminToken(token);
  if (!valid) return res.status(401).json({ success: false, error: "Unauthorized" });

  req.admin = valid;
  next();
}

// -------------------------------------------------------
// R2 STORAGE FUNCTIONS
// -------------------------------------------------------

async function uploadToR2(buffer, key, contentType = "image/jpeg") {
  await r2.send(new PutObjectCommand({
    Bucket: R2_BUCKET,
    Key: key,
    Body: buffer,
    ContentType: contentType
  }));
  return `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(key)}`;
}

async function deleteFromR2(key) {
  await r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key }));
}

// -------------------------------------------------------
// UPLOAD VOUCHERS (ADMIN)
// -------------------------------------------------------
app.post("/api/upload-vouchers", requireAdmin, upload.array("vouchers", 50), async (req, res) => {
  try {
    if (!req.files?.length)
      return res.status(400).json({ success: false, error: "No files uploaded" });

    const batchId = `batch-${Date.now()}`;
    const added = [];

    for (const file of req.files) {
      const seq = await getNextSequence("voucherSeq");
      const ext = path.extname(file.originalname).toLowerCase();
      const newFilename = `voucher_${seq}${ext}`;
      const r2url = await uploadToR2(file.buffer, newFilename, file.mimetype);

      await new Voucher({
        cardId: seq,
        filename: newFilename,
        r2url,
        status: "unused",
        batchId,
        uploadedAt: new Date()
      }).save();

      added.push({ id: seq, filename: newFilename, url: r2url });
    }

    res.json({ success: true, added });

  } catch (err) {
    console.error("UPLOAD ERROR:", err);
    res.status(500).json({ success: false, error: "Upload failed" });
  }
});

// -------------------------------------------------------
// DELETE SINGLE VOUCHER (ADMIN)
// -------------------------------------------------------
app.delete("/api/voucher/:id/delete", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const v = await Voucher.findOne({ cardId: id }).lean();
    if (!v) return res.status(404).json({ success: false, error: "Not found" });

    try { await deleteFromR2(v.filename); } catch {}

    await Voucher.deleteOne({ cardId: id });

    res.json({ success: true, message: `Voucher ${id} deleted` });
  } catch (err) {
    console.error("DELETE ERROR:", err);
    res.status(500).json({ success: false, error: "Failed to delete voucher" });
  }
});

// -------------------------------------------------------
// GET ALL VOUCHERS (ADMIN)
// -------------------------------------------------------
app.get("/api/vouchers/all", requireAdmin, async (req, res) => {
  const list = await Voucher.find({}).sort({ cardId: 1 }).lean();
  list.forEach(v => v.r2url = `${R2_PUBLIC_URL}/${v.filename}`);
  res.json({ success: true, vouchers: list });
});

// -------------------------------------------------------
// GET HISTORY (ADMIN)
// -------------------------------------------------------
app.get("/api/history", requireAdmin, async (req, res) => {
  const hist = await History.find({}).sort({ dateUsed: -1 }).lean();
  res.json({ success: true, history: hist });
});

// -------------------------------------------------------
// Helper: allocate vouchers
// -------------------------------------------------------
async function allocateUnused(qty, reference, phone, email) {
  const unused = await Voucher.find({ status: "unused" })
    .sort({ cardId: 1 })
    .limit(qty);

  if (unused.length < qty) return null;

  const ids = unused.map(u => u._id);
  await Voucher.updateMany({ _id: { $in: ids } }, { $set: { status: "used", usedAt: new Date(), reference } });

  const hist = unused.map(u => ({
    cardId: u.cardId,
    filename: u.filename,
    usedBy: phone,
    usedByEmail: email,
    reference,
    dateUsed: new Date()
  }));

  await History.insertMany(hist);

  return unused.map(u => `${R2_PUBLIC_URL}/${u.filename}`);
}

// -------------------------------------------------------
// PAYSTACK INIT
// -------------------------------------------------------
app.post("/api/pay", async (req, res) => {
  try {
    const { email, phone, quantity, amount } = req.body;

    if (!email || !phone || !quantity || !amount)
      return res.status(400).json({ success: false, error: "Missing fields" });

    const expected = quantity * PRICE_PER_VOUCHER;
    if (amount !== expected)
      return res.status(400).json({ success: false, error: "Amount mismatch" });

    const unused = await Voucher.countDocuments({ status: "unused" });
    if (unused < quantity)
      return res.json({ success: false, error: `Only ${unused} available` });

    const payload = {
      email,
      amount: amount * 100,
      metadata: { phone, quantity },
      callback_url: FRONTEND_SUCCESS_URL
    };

    const r = await axios.post("https://api.paystack.co/transaction/initialize", payload, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
    });

    res.json(r.data);

  } catch (err) {
    console.error(err.response?.data || err);
    res.status(500).json({ success: false, error: "Pay init failed" });
  }
});

// -------------------------------------------------------
// VERIFY
// -------------------------------------------------------
app.get("/api/verify/:reference", async (req, res) => {
  try {
    const ref = req.params.reference;

    const existing = await History.find({ reference: ref }).lean();
    if (existing.length > 0) {
      return res.json({
        success: true,
        vouchers: existing.map(h => `${R2_PUBLIC_URL}/${h.filename}`),
        message: "Already verified"
      });
    }

    const r = await axios.get(`https://api.paystack.co/transaction/verify/${ref}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
    });

    const data = r.data.data;
    if (data.status !== "success")
      return res.status(400).json({ success: false, error: "Payment failed" });

    const qty = Number(data.metadata?.quantity) || 1;

    const phone = data.metadata?.phone || data.customer?.phone || "unknown";
    const email = data.customer?.email || null;

    const assigned = await allocateUnused(qty, ref, phone, email);

    res.json({ success: true, vouchers: assigned });

  } catch (err) {
    console.error(err.response?.data || err);
    res.status(500).json({ success: false, error: "Verify error" });
  }
});

// -------------------------------------------------------
// PAYSTACK WEBHOOK
// -------------------------------------------------------
app.post("/api/paystack/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const sig = req.headers["x-paystack-signature"];
    const hash = crypto.createHmac("sha512", PAYSTACK_WEBHOOK_SECRET).update(req.body).digest("hex");

    if (sig !== hash) return res.status(400).send("Invalid signature");

    const payload = JSON.parse(req.body.toString());
    const data = payload.data;

    if (data.status !== "success") return res.send("ignored");

    const ref = data.reference;

    const existing = await History.find({ reference: ref }).lean();
    if (existing.length) return res.send("already processed");

    const qty = Number(data.metadata?.quantity) || 1;
    const phone = data.metadata?.phone || data.customer?.phone || "unknown";
    const email = data.customer?.email || null;

    await allocateUnused(qty, ref, phone, email);

    res.send("ok");

  } catch (err) {
    console.error("Webhook error:", err);
    res.status(500).send("error");
  }
});

// -------------------------------------------------------
// PUBLIC SEARCH BY PHONE
// -------------------------------------------------------
app.get("/api/public/history", async (req, res) => {
  const phoneRaw = req.query.phone;
  if (!phoneRaw) return res.json({ success: false, vouchers: [] });

  const cleaned = phoneRaw.replace(/\D/g, "");
  if (cleaned.length < 9) return res.json({ success: true, vouchers: [] });

  const hist = await History.find({}).lean();

  const matches = hist.filter(h => {
    const p = (h.usedBy || "").replace(/\D/g, "");
    return p.endsWith(cleaned);
  });

  const urls = matches.map(h => `${R2_PUBLIC_URL}/${h.filename}`);

  res.json({ success: true, vouchers: urls });
});

// -------------------------------------------------------
// START SERVER
// -------------------------------------------------------
app.listen(PORT, () => console.log(`🚀 Smart WASSCE Backend running on port ${PORT}`));
