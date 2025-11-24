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

const PRICE_PER_VOUCHER = Number(process.env.PRICE_PER_VOUCHER || 22.5);

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "change-this-secret";

// Cloudflare R2
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || "";
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || "";
const R2_BUCKET = process.env.R2_BUCKET || "";
const R2_ENDPOINT = process.env.R2_ENDPOINT || "";
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL || "";

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
const Counter = mongoose.model(
  "Counter",
  new mongoose.Schema({ name: String, seq: { type: Number, default: 0 } })
);

async function getNextSequence(name) {
  const doc = await Counter.findOneAndUpdate(
    { name },
    { $inc: { seq: 1 } },
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
    status: { type: String, default: "unused" },
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
  return `${R2_PUBLIC_URL}/${encodeURIComponent(key)}`;
}

// Delete
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
  } catch {
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
// -------------------------------------------------------
app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body || {};
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD)
    return res.status(401).json({ success: false, error: "Invalid credentials" });

  return res.json({
    success: true,
    token: signAdminToken({ email }),
    email
  });
});

// -------------------------------------------------------
// Upload Vouchers
// -------------------------------------------------------
app.post("/api/upload-vouchers", requireAdmin, upload.array("vouchers"), async (req, res) => {
  try {
    const added = [];

    for (const file of req.files) {
      const seq = await getNextSequence("voucherSeq");
      const ext = path.extname(file.originalname).toLowerCase();
      const filename = `voucher_${seq}${ext}`;
      const url = await uploadToR2(file.buffer, filename, file.mimetype);

      await new Voucher({
        cardId: seq,
        filename,
        r2url: url,
        status: "unused",
        uploadedAt: new Date()
      }).save();

      added.push({ id: seq, url });
    }

    res.json({ success: true, added });
  } catch (err) {
    res.status(500).json({ success: false, error: "Upload failed" });
  }
});
// -------------------------------------------------------
// GET Full Purchase / Usage History (Admin)
// -------------------------------------------------------
app.get("/api/history", requireAdmin, async (req, res) => {
  try {
    const history = await History.find().sort({ dateUsed: -1 }).lean();
    return res.json({ success: true, history });
  } catch (err) {
    console.error("History load error:", err);
    return res.status(500).json({ success: false, error: "Failed to load history" });
  }
});
// -------------------------------------------------------
// GET All Vouchers (Admin)
// -------------------------------------------------------
app.get("/api/vouchers/all", requireAdmin, async (req, res) => {
  res.json({ success: true, vouchers: await Voucher.find().sort({ cardId: 1 }) });
});

// -------------------------------------------------------
// Delete One Voucher
// -------------------------------------------------------
app.post("/api/vouchers/delete-one", requireAdmin, async (req, res) => {
  const { id, filename } = req.body;

  if (filename) await deleteFromR2(filename);

  await Voucher.deleteOne({ cardId: id });

  res.json({ success: true });
});

// -------------------------------------------------------
// Allocate Vouchers
// -------------------------------------------------------
async function allocateUnused(qty, reference, phone, email) {
  const unused = await Voucher.find({ status: "unused" })
    .sort({ cardId: 1 })
    .limit(qty);

  if (unused.length < qty) return null;

  const ids = unused.map((v) => v._id);

  await Voucher.updateMany(
    { _id: { $in: ids } },
    { $set: { status: "used", usedAt: new Date(), reference } }
  );

  await History.insertMany(
    unused.map((v) => ({
      cardId: v.cardId,
      filename: v.filename,
      usedBy: phone,
      usedByEmail: email,
      reference,
      dateUsed: new Date()
    }))
  );

  return unused.map((v) => `${R2_PUBLIC_URL}/${encodeURIComponent(v.filename)}`);
}
// =======================================================
// PAYSTACK — Initialize Payment
// POST /api/pay
// =======================================================
app.post("/api/pay", async (req, res) => {
  try {
    const { email, phone, quantity, amount } = req.body || {};

    if (!email || !phone || !quantity || amount == null) {
      return res.status(400).json({ success: false, error: "Missing fields" });
    }

    const qty = Number(quantity);
    if (!Number.isFinite(qty) || qty < 1) {
      return res.status(400).json({ success: false, error: "Invalid quantity" });
    }

    // -------- SAFE PRICE CHECK (avoid float errors) --------
    const expectedCents = Math.round(qty * PRICE_PER_VOUCHER * 100);   // 22.5 → 2250
    const incomingCents = Math.round(Number(amount) * 100);

    console.log("[PAY INIT] ", { email, phone, qty, amount, expectedCents, incomingCents });

    if (incomingCents !== expectedCents) {
      return res.status(400).json({
        success: false,
        error: `Amount mismatch. Expected ${(expectedCents/100).toFixed(2)}`
      });
    }

    // -------- CHECK AVAILABLE VOUCHERS --------
    const unusedCount = await Voucher.countDocuments({ status: "unused" });
    if (unusedCount < qty) {
      return res.status(400).json({
        success: false,
        error: `Only ${unusedCount} voucher(s) available`
      });
    }

    if (!PAYSTACK_SECRET_KEY) {
      return res.status(500).json({ success: false, error: "Paystack key not configured" });
    }

    // -------- INITIALIZE PAYSTACK --------
    const payload = {
      email,
      amount: incomingCents,   // PAYSTACK USES KOBO (integer)
      metadata: { phone, quantity: qty },
      callback_url: FRONTEND_SUCCESS_URL,
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
      details: err.response?.data || err.message
    });
  }
});
// -------------------------------------------------------
// Paystack Verify
// -------------------------------------------------------
app.get("/api/verify/:reference", async (req, res) => {
  try {
    const ref = req.params.reference;

    const existing = await History.find({ reference: ref });

    if (existing.length)
      return res.json({
        success: true,
        vouchers: existing.map(
          (h) => `${R2_PUBLIC_URL}/${encodeURIComponent(h.filename)}`
        )
      });

    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${ref}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } }
    );

    const data = verify.data;

    if (data.data.status !== "success")
      return res.status(400).json({ success: false, error: "Payment not successful" });

    const qty = data.data.metadata.quantity;
    const phone = data.data.metadata.phone;
    const email = data.data.customer.email;

    const vouchers = await allocateUnused(qty, ref, phone, email);

    res.json({ success: true, vouchers });
  } catch {
    res.status(500).json({ success: false, error: "Verification failed" });
  }
});
// ---------------------------------------------
// PUBLIC: retrieve by phone + paystack reference
// GET /api/public/retrieve?phone=...&reference=...
// ---------------------------------------------
app.get("/api/public/retrieve", async (req, res) => {
  try {
    const rawPhone = String(req.query.phone || "").trim();
    const rawRef = String(req.query.reference || req.query.ref || "").trim();

    if (!rawPhone || !rawRef) {
      return res.status(400).json({ success: false, error: "Missing phone or reference" });
    }

    // Normalize phone: digits only; require at least 7 digits to avoid accidental matches
    const cleanedPhone = rawPhone.replace(/\D/g, "");
    if (cleanedPhone.length < 7) {
      return res.status(400).json({ success: false, error: "Invalid phone number" });
    }

    const ref = rawRef.trim();

    // Find history entries that match reference exactly and the phone ending (keeps previous behavior)
    const allHistory = await History.find({ reference: ref }).lean();

    // Filter by phone match (endsWith to support international / local formats)
    const matches = allHistory.filter(h => {
      const phoneField = (h.usedBy || "").replace(/\D/g, "");
      return phoneField.endsWith(cleanedPhone);
    });

    // Create voucher URLs
    const vouchers = matches.map(h => `${R2_PUBLIC_URL.replace(/\/$/, "")}/${encodeURIComponent(h.filename)}`);

    return res.json({ success: true, vouchers });
  } catch (err) {
    console.error("/api/public/retrieve error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});
// -------------------------------------------------------
// PUBLIC SEARCH (Retrieve by phone)
// -------------------------------------------------------
app.get("/api/public/history", async (req, res) => {
  const phone = (req.query.phone || "").trim();

  const matches = await History.find({
    usedBy: { $regex: phone.replace(/\D/g, "") }
  });

  res.json({
    success: true,
    vouchers: matches.map(
      (h) => `${R2_PUBLIC_URL}/${encodeURIComponent(h.filename)}`
    )
  });
});

// =======================================================
// DOWNLOAD PROXY (FINAL WORKING VERSION)
// =======================================================

app.get("/api/download", async (req, res) => {
  try {
    const fileUrl = req.query.url;
    if (!fileUrl) return res.status(400).send("Missing file URL");

    console.log("Downloading:", fileUrl);

    const response = await fetch(fileUrl);

    if (!response.ok) {
      console.error("Fetch failed:", response.status);
      return res.status(502).send("Failed to fetch file");
    }

    const filename = decodeURIComponent(fileUrl.split("/").pop());
    const contentType =
      response.headers.get("content-type") || "application/octet-stream";

    res.setHeader("Content-Type", contentType);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}"`
    );

    // If response.body supports .pipe() (Node stream)
    if (typeof response.body.pipe === "function") {
      return response.body.pipe(res);
    }

    // Otherwise convert WHATWG -> Node stream
    const reader = response.body.getReader();

    const stream = new Readable({
      async read() {
        const { done, value } = await reader.read();
        if (done) return this.push(null);
        this.push(Buffer.from(value));
      }
    });

    stream.pipe(res);
  } catch (err) {
    console.error("Download error:", err);
    res.status(500).send("Server download error");
  }
});
// =======================================================
// 🔥 DELETE ALL VOUCHERS (DB + Cloudflare R2)
// =======================================================
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

// =======================================================
// 🔥 DELETE ALL HISTORY
// =======================================================
app.delete("/api/history/delete-all", requireAdmin, async (req, res) => {
  try {
    await History.deleteMany({});
    return res.json({ success: true, message: "All history cleared" });
  } catch (err) {
    console.error("Delete-all history error:", err);
    return res.status(500).json({ success: false, error: "Failed to delete history" });
  }
});

// =======================================================
// 🔥 EXPORT ALL VOUCHERS (for Excel)
// =======================================================
app.get("/api/vouchers/export", requireAdmin, async (req, res) => {
  try {
    const vouchers = await Voucher.find({}).lean();
    return res.json({ success: true, vouchers });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// =======================================================
// 🔥 EXPORT USED VOUCHERS
// =======================================================
app.get("/api/vouchers/export-used", requireAdmin, async (req, res) => {
  try {
    const vouchers = await Voucher.find({ status: "used" }).lean();
    return res.json({ success: true, vouchers });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// =======================================================
// 🔥 EXPORT UNUSED VOUCHERS
// =======================================================
app.get("/api/vouchers/export-unused", requireAdmin, async (req, res) => {
  try {
    const vouchers = await Voucher.find({ status: "unused" }).lean();
    return res.json({ success: true, vouchers });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// =======================================================
// 🔥 EXPORT FULL HISTORY
// =======================================================
app.get("/api/history/export", requireAdmin, async (req, res) => {
  try {
    const history = await History.find({}).lean();
    return res.json({ success: true, history });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});
// =======================================================
// ⚠ LOW-STOCK ALERT
// =======================================================
app.get("/api/admin/low-stock", requireAdmin, async (req, res) => {
  try {
    const unused = await Voucher.countDocuments({ status: "unused" });
    const low = unused < 50;

    return res.json({
      success: true,
      unused,
      low,
      threshold: 50
    });

  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// =======================================================
// 📊 REVENUE ANALYTICS
// =======================================================
app.get("/api/admin/revenue-stats", requireAdmin, async (req, res) => {
  try {
    const PRICE = PRICE_PER_VOUCHER || 22.5;

    const history = await History.find({}).lean();

    let totalVouchers = history.length;
    let totalRevenue = totalVouchers * PRICE;

    // Group by day
    let daily = {};
    history.forEach(h => {
      const day = new Date(h.dateUsed).toISOString().split("T")[0];
      if (!daily[day]) daily[day] = 0;
      daily[day] += PRICE;
    });

    return res.json({
      success: true,
      totalRevenue,
      totalVouchers,
      PRICE,
      daily
    });

  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});
// -------------------------------------------------------
// START SERVER
// -------------------------------------------------------
app.listen(PORT, () =>
  console.log(`🚀 Server running at http://localhost:${PORT}`)
);
