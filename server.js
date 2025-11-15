// server.js
// Smart WASSCE backend — MongoDB + JWT admin + Paystack
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
import cookieParser from "cookie-parser";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---- Config (ENV)
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || "";
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || "";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "please-change-me";
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const FRONTEND_SUCCESS_URL = process.env.FRONTEND_SUCCESS_URL || `${BASE_URL}/success.html`;
const PRICE_PER_VOUCHER = Number(process.env.PRICE_PER_VOUCHER || 25);

// ---- Paths
const UPLOADS_DIR = path.join(__dirname, "uploads");
const DATA_DIR = path.join(__dirname, "data"); // optional migration
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ---- Mongoose connection + models
if (!MONGO_URI) {
  console.error("MONGO_URI not set. Set it in your .env");
  process.exit(1);
}
await mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
console.log("✅ Connected to MongoDB");

const counterSchema = new mongoose.Schema({
  name: { type: String, unique: true },
  seq: { type: Number, default: 0 },
});
const Counter = mongoose.model("Counter", counterSchema);

async function getNextSequence(name, inc = 1) {
  const doc = await Counter.findOneAndUpdate(
    { name },
    { $inc: { seq: inc } },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
  return doc.seq;
}

const voucherSchema = new mongoose.Schema({
  cardId: { type: Number, required: true, unique: true },
  filename: { type: String, required: true },
  status: { type: String, enum: ["unused", "used"], default: "unused" },
  batchId: String,
  uploadedAt: { type: Date, default: Date.now },
  usedAt: Date,
  reference: String,
});
const Voucher = mongoose.model("Voucher", voucherSchema);

const historySchema = new mongoose.Schema({
  cardId: Number,
  filename: String,
  usedBy: String,
  usedByEmail: String,
  reference: String,
  dateUsed: { type: Date, default: Date.now },
});
const History = mongoose.model("History", historySchema);

// Optional: migrate old JSON files located in ./data into Mongo (one-time)
async function migrateJsonToMongoIfPresent() {
  try {
    const vouchersFile = path.join(DATA_DIR, "vouchers.json");
    const historyFile = path.join(DATA_DIR, "history.json");
    let imported = false;

    if (fs.existsSync(vouchersFile)) {
      const raw = fs.readFileSync(vouchersFile, "utf8");
      const arr = JSON.parse(raw || "[]");
      if (arr.length) {
        for (const item of arr) {
          // allocate new sequential id
          const seq = await getNextSequence("voucherSeq", 1);
          const ext = path.extname(item.filename || ".jpg") || ".jpg";
          const newFilename = `voucher_${seq}${ext}`;
          // try rename if file exists in uploads
          const possibleOld = path.join(UPLOADS_DIR, item.filename || "");
          if (item.filename && fs.existsSync(possibleOld)) {
            try { fs.renameSync(possibleOld, path.join(UPLOADS_DIR, newFilename)); } catch(e) {}
          }
          const v = new Voucher({
            cardId: seq,
            filename: newFilename,
            status: item.status || "unused",
            batchId: item.batchId || `migrated-${Date.now()}`,
            uploadedAt: item.uploadedAt ? new Date(item.uploadedAt) : new Date(),
          });
          await v.save();
        }
        imported = true;
      }
      fs.unlinkSync(vouchersFile);
    }

    if (fs.existsSync(historyFile)) {
      const raw = fs.readFileSync(historyFile, "utf8");
      const arr = JSON.parse(raw || "[]");
      if (arr.length) {
        for (const h of arr) {
          const doc = new History({
            cardId: h.cardId,
            filename: h.filename,
            usedBy: h.usedBy,
            usedByEmail: h.usedByEmail || null,
            reference: h.reference || null,
            dateUsed: h.dateUsed ? new Date(h.dateUsed) : new Date(),
          });
          await doc.save();
        }
        imported = true;
      }
      fs.unlinkSync(historyFile);
    }

    if (imported) console.log("✅ Migrated JSON data into MongoDB (data/*.json removed)");
  } catch (e) {
    console.error("Migration error:", e);
  }
}

// ---- Express app
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());
app.use(cookieParser && cookieParser()); // optional if cookieParser import exists
app.use("/uploads", express.static(UPLOADS_DIR));

// ---- Multer
const storage = multer.diskStorage({
  destination: UPLOADS_DIR,
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
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

// ---- Admin JWT helpers
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
  else if (req.headers["x-admin-token"]) token = req.headers["x-admin-token"];
  else if (req.cookies && req.cookies.admin_token) token = req.cookies.admin_token;

  if (!token) return res.status(401).json({ success: false, error: "Unauthorized - no token" });
  const payload = verifyAdminToken(token);
  if (!payload) return res.status(401).json({ success: false, error: "Unauthorized - invalid token" });
  req.admin = payload;
  next();
}

// ---- Routes

app.get("/", (req, res) => res.send("✅ Smart WASSCE backend (Mongo + Paystack)"));

/**
 * POST /api/admin/login
 * Body: { email, password } -> returns { success:true, token, email }
 */
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ success: false, error: "Missing credentials" });
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, error: "Invalid credentials" });
  }
  const token = signAdminToken({ email });
  return res.json({ success: true, token, email });
});

app.post("/api/admin/logout", (req, res) => {
  // stateless JWT: simply instruct client to drop token
  return res.json({ success: true, message: "Logged out" });
});

/**
 * POST /api/upload-vouchers
 * Protected by requireAdmin
 */
app.post("/api/upload-vouchers", requireAdmin, upload.array("vouchers", 20), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) return res.status(400).json({ success: false, error: "No files uploaded" });

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
 * GET /api/vouchers/all
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
 * GET /api/history
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
 * DELETE /api/vouchers/used
 * removes used files and DB docs
 */
app.delete("/api/vouchers/used", requireAdmin, async (req, res) => {
  try {
    const used = await Voucher.find({ status: "used" }).lean();
    if (!used.length) return res.json({ success: true, message: "No used vouchers found." });

    for (const v of used) {
      const fp = path.join(UPLOADS_DIR, v.filename);
      if (fs.existsSync(fp)) {
        try { fs.unlinkSync(fp); } catch (e) {}
      }
    }

    const result = await Voucher.deleteMany({ status: "used" });
    return res.json({ success: true, message: `Deleted ${result.deletedCount} used vouchers.` });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: "Failed to delete used vouchers", details: err.message });
  }
});

/**
 * GET /api/vouchers/request?quantity=2&phone=...
 * Admin/manual request (no auth here)
 */
app.get("/api/vouchers/request", async (req, res) => {
  try {
    const qty = Math.max(1, Math.min(100, parseInt(req.query.quantity || "1", 10)));
    const phone = req.query.phone || "unknown";

    const unused = await Voucher.find({ status: "unused" }).sort({ cardId: 1 }).limit(qty);
    if (unused.length < qty) return res.status(400).json({ success: false, error: "Not enough vouchers" });

    const ids = unused.map(u => u._id);
    await Voucher.updateMany({ _id: { $in: ids } }, { $set: { status: "used", usedAt: new Date(), reference: `manual-${Date.now()}` } });

    const hist = unused.map(u => ({
      cardId: u.cardId,
      filename: u.filename,
      usedBy: phone,
      usedByEmail: null,
      reference: `manual-${Date.now()}`,
      dateUsed: new Date(),
    }));
    await History.insertMany(hist);

    const urls = unused.map(u => `${BASE_URL}/uploads/${u.filename}`);
    return res.json({ success: true, vouchers: urls, assigned: unused.map(u => ({ id: u.cardId, filename: u.filename })) });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: "Failed to allocate vouchers" });
  }
});

/**
 * POST /api/pay — initialize Paystack transaction
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
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
    });

    return res.json(response.data);
  } catch (err) {
    console.error("Pay init error:", err.response?.data || err.message);
    return res.status(500).json({ success: false, error: "Payment initialization failed", details: err.response?.data || err.message });
  }
});

/**
 * GET /api/verify/:reference — verify paystack and allocate vouchers
 */
app.get("/api/verify/:reference", async (req, res) => {
  try {
    const ref = req.params.reference;
    if (!ref) return res.status(400).json({ success: false, error: "Missing reference" });
    if (!PAYSTACK_SECRET_KEY) return res.status(500).json({ success: false, error: "Paystack key not configured" });

    // idempotent: if history exists for this reference return saved vouchers
    const existing = await History.find({ reference: ref }).lean();
    if (existing.length > 0) {
      const savedUrls = existing.map(h => `${BASE_URL}/uploads/${h.filename}`);
      return res.json({ success: true, vouchers: savedUrls, message: "Already verified" });
    }

    // verify with paystack
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
    quantity = Math.max(1, Math.min(quantity, 100));

    const phone = metadata.phone || (payload.data.customer && payload.data.customer.phone) || "unknown";
    const email = payload.data.customer?.email || null;

    const unused = await Voucher.find({ status: "unused" }).sort({ cardId: 1 }).limit(quantity);
    if (unused.length < quantity) {
      return res.status(400).json({
        success: false,
        error: "Payment successful but not enough vouchers left. Contact admin.",
        available: await Voucher.countDocuments({ status: "unused" }),
      });
    }

    const ids = unused.map(u => u._id);
    await Voucher.updateMany({ _id: { $in: ids } }, { $set: { status: "used", usedAt: new Date(), reference: ref } });

    const historyDocs = unused.map(u => ({
      cardId: u.cardId,
      filename: u.filename,
      usedBy: phone,
      usedByEmail: email,
      reference: ref,
      dateUsed: new Date(),
    }));
    await History.insertMany(historyDocs);

    const urls = unused.map(u => `${BASE_URL}/uploads/${u.filename}`);
    return res.json({ success: true, vouchers: urls, assigned: unused.map(u => ({ id: u.cardId, filename: u.filename })) });
  } catch (err) {
    console.error("Verify error:", err.response?.data || err.message);
    return res.status(500).json({ success: false, error: "Verification failed", details: err.response?.data || err.message });
  }
});

// ---- Server start: migrate then listen
(async () => {
  try {
    await migrateJsonToMongoIfPresent();
    app.listen(PORT, () => console.log(`✅ Backend running on port ${PORT}`));
  } catch (e) {
    console.error("Startup error:", e);
    process.exit(1);
  }
})();
