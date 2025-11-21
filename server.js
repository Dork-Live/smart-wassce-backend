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
const MONGO_URI = process.env.MONGO_URI;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_WEBHOOK_SECRET = process.env.PAYSTACK_WEBHOOK_SECRET || PAYSTACK_SECRET_KEY;

const BASE_URL = process.env.BASE_URL;
const FRONTEND_SUCCESS_URL = process.env.FRONTEND_SUCCESS_URL;

const PRICE_PER_VOUCHER = Number(process.env.PRICE_PER_VOUCHER || 25);

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET;

// Cloudflare R2
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET = process.env.R2_BUCKET;  
const R2_ENDPOINT = process.env.R2_ENDPOINT;
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL;

if (!R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET || !R2_ENDPOINT || !R2_PUBLIC_URL) {
  console.error("❌ Missing R2 env variables");
  process.exit(1);
}

// -------------------------------------------------------
// Mongoose Connect
// -------------------------------------------------------
async function connectDB() {
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
  status: { type: String, default: "unused" },  // unused | used
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
async function uploadToR2(buffer, key, type) {
  await r2.send(new PutObjectCommand({
    Bucket: R2_BUCKET,
    Key: key,
    Body: buffer,
    ContentType: type
  }));
  return `${R2_PUBLIC_URL}/${encodeURIComponent(key)}`;
}

// Delete helper
async function deleteFromR2(key) {
  await r2.send(new DeleteObjectCommand({
    Bucket: R2_BUCKET,
    Key: key
  }));
}

// -------------------------------------------------------
// Express App
// -------------------------------------------------------
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json({ limit: "10mb" }));
app.use(cookieParser());

// Multer (Memory Upload)
const upload = multer({ storage: multer.memoryStorage() });

// -------------------------------------------------------
// Admin Auth
// -------------------------------------------------------
function signAdminToken(payload = {}) {
  return jwt.sign(payload, ADMIN_JWT_SECRET, { expiresIn: "12h" });
}
function verifyAdminToken(token) {
  try { return jwt.verify(token, ADMIN_JWT_SECRET); }
  catch { return null; }
}
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || "";
  let token = null;
  if (auth.startsWith("Bearer ")) token = auth.split(" ")[1];
  else if (req.headers["x-admin-token"]) token = req.headers["x-admin-token"];

  if (!token) return res.status(401).json({ success: false, error: "Unauthorized" });

  const payload = verifyAdminToken(token);
  if (!payload) return res.status(401).json({ success: false, error: "Unauthorized token" });

  req.admin = payload;
  next();
}

// -------------------------------------------------------
// Upload Vouchers to R2
// -------------------------------------------------------
app.post("/api/upload-vouchers", requireAdmin, upload.array("vouchers", 50), async (req, res) => {
  try {
    const added = [];

    for (const file of req.files) {
      const seq = await getNextSequence("voucherSeq");
      const ext = path.extname(file.originalname).toLowerCase() || ".jpg";
      const key = `voucher_${seq}${ext}`;

      const r2url = await uploadToR2(file.buffer, key, file.mimetype);

      const voucher = new Voucher({
        cardId: seq,
        filename: key,
        r2url,
        status: "unused",
        batchId: `batch-${Date.now()}`,
        uploadedAt: new Date()
      });

      await voucher.save();
      added.push({ id: seq, filename: key, url: r2url });
    }

    return res.json({ success: true, added });

  } catch (err) {
    console.error("Upload error:", err);
    return res.status(500).json({ success: false, error: "Upload failed" });
  }
});

// -------------------------------------------------------
// GET all vouchers
// -------------------------------------------------------
app.get("/api/vouchers/all", requireAdmin, async (req, res) => {
  const vouchers = await Voucher.find({}).sort({ cardId: 1 }).lean();
  return res.json({ success: true, vouchers });
});

// -------------------------------------------------------
// DELETE ONE voucher by ID
// -------------------------------------------------------
app.post("/api/vouchers/delete-one", requireAdmin, async (req, res) => {
  try {
    const { id, filename } = req.body;

    if (filename) {
      await deleteFromR2(filename);
    }

    await Voucher.deleteOne({ cardId: id });

    return res.json({ success: true, message: `Voucher ${id} deleted` });

  } catch (err) {
    console.error("Delete-one error:", err);
    return res.status(500).json({ success: false, error: "Delete failed" });
  }
});

// -------------------------------------------------------
// HISTORY
// -------------------------------------------------------
app.get("/api/history", requireAdmin, async (req, res) => {
  const hist = await History.find({}).sort({ dateUsed: -1 }).lean();
  res.json({ success: true, history: hist });
});

// -------------------------------------------------------
// Allocate Unused Vouchers
// -------------------------------------------------------
async function allocateUnused(qty, reference, phone, email) {
  const unused = await Voucher.find({ status: "unused" }).sort({ cardId: 1 }).limit(qty);

  if (unused.length < qty) return null;

  const ids = unused.map(v => v._id);

  await Voucher.updateMany({ _id: { $in: ids } }, {
    $set: { status: "used", usedAt: new Date(), reference }
  });

  await History.insertMany(unused.map(v => ({
    cardId: v.cardId,
    filename: v.filename,
    usedBy: phone,
    usedByEmail: email,
    reference,
    dateUsed: new Date()
  })));

  return unused.map(v => `${R2_PUBLIC_URL}/${encodeURIComponent(v.filename)}`);
}

// -------------------------------------------------------
// PAYSTACK INIT
// -------------------------------------------------------
app.post("/api/pay", async (req, res) => {
  const { email, phone, quantity, amount } = req.body;

  const expected = quantity * PRICE_PER_VOUCHER;
  if (expected !== amount) {
    return res.status(400).json({ success: false, error: "Amount mismatch" });
  }

  const unusedCount = await Voucher.countDocuments({ status: "unused" });
  if (unusedCount < quantity) {
    return res.status(400).json({ success: false, error: "Not enough vouchers" });
  }

  const payload = {
    email,
    amount: amount * 100,
    metadata: { phone, quantity },
    callback_url: FRONTEND_SUCCESS_URL
  };

  const response = await axios.post(
    "https://api.paystack.co/transaction/initialize",
    payload,
    { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } }
  );

  res.json(response.data);
});

// -------------------------------------------------------
// PAYSTACK VERIFY
// -------------------------------------------------------
app.get("/api/verify/:reference", async (req, res) => {
  const ref = req.params.reference;

  const existing = await History.find({ reference: ref });
  if (existing.length) {
    const urls = existing.map(h => `${R2_PUBLIC_URL}/${encodeURIComponent(h.filename)}`);
    return res.json({ success: true, vouchers: urls });
  }

  const verifyResp = await axios.get(
    `https://api.paystack.co/transaction/verify/${ref}`,
    { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } }
  );

  const data = verifyResp.data.data;
  if (data.status !== "success") {
    return res.status(400).json({ success: false, error: "Payment not successful" });
  }

  const qty = data.metadata.quantity;
  const phone = data.metadata.phone;
  const email = data.customer.email;

  const assigned = await allocateUnused(qty, ref, phone, email);
  if (!assigned) {
    return res.status(400).json({ success: false, error: "Not enough vouchers" });
  }

  res.json({ success: true, vouchers: assigned });
});

// -------------------------------------------------------
// WEBHOOK
// -------------------------------------------------------
app.post("/api/paystack/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {

    const signature = req.headers["x-paystack-signature"];
    const computed = crypto.createHmac("sha512", PAYSTACK_WEBHOOK_SECRET)
      .update(req.body)
      .digest("hex");

    if (signature !== computed) return res.status(400).send("Invalid signature");

    const payload = JSON.parse(req.body.toString());
    const data = payload.data;

    if (data.status !== "success") return res.status(200).send("ignored");

    const ref = data.reference;

    const existing = await History.find({ reference: ref });
    if (existing.length) return res.status(200).send("already processed");

    const qty = data.metadata.quantity;
    const phone = data.metadata.phone;
    const email = data.customer.email;

    await allocateUnused(qty, ref, phone, email);

    res.status(200).send("ok");
  }
);

// -------------------------------------------------------
// PUBLIC CHECK BY PHONE
// -------------------------------------------------------
app.get("/api/public/history", async (req, res) => {
  const phone = (req.query.phone || "").replace(/\D/g, "");

  const hist = await History.find().lean();

  const match = hist.filter(h => (h.usedBy || "").endsWith(phone));

  const urls = match.map(h => `${R2_PUBLIC_URL}/${encodeURIComponent(h.filename)}`);

  res.json({ success: true, vouchers: urls });
});

// -------------------------------------------------------
// START SERVER
// -------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
