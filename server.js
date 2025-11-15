// server.js — Smart WASSCE backend (simple, robust, cookie auth)
// Put in backend/ and run: node server.js
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import fs from "fs";
import path from "path";
import multer from "multer";
import axios from "axios";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 4000);
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/smartwassce";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "likeStars!546@_";
const JWT_SECRET = process.env.JWT_SECRET || "change_this_jwt_secret";
const PRICE_PER_VOUCHER = Number(process.env.PRICE_PER_VOUCHER || 22.5);
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY || "";
const FRONTEND_SUCCESS_URL = process.env.FRONTEND_SUCCESS_URL || `http://localhost:5500/success.html`;
const IS_PROD = process.env.NODE_ENV === "production";

const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// Mongoose connect
await mongoose.connect(MONGO_URI);
console.log("Connected to MongoDB");

// Models
const voucherSchema = new mongoose.Schema({
  id: { type: Number, index: true, unique: true },
  filename: String,
  status: { type: String, default: "unused" },
  uploadedAt: { type: Date, default: Date.now },
  usedAt: Date,
  reference: String,
  batchId: String
});
const Voucher = mongoose.models.Voucher || mongoose.model("Voucher", voucherSchema);

const historySchema = new mongoose.Schema({
  cardId: Number,
  filename: String,
  usedBy: String,
  usedByEmail: String,
  reference: String,
  dateUsed: { type: Date, default: Date.now }
});
const History = mongoose.models.History || mongoose.model("History", historySchema);

// Express app
const app = express();
app.use(cookieParser());
app.use(bodyParser.json({ limit: "1mb" }));

// CORS - allow localhost frontends; credentials true so cookies work
const ALLOWED = [
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:3000",
  "http://127.0.0.1:3000"
];
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED.includes(origin)) return cb(null, true);
    cb(new Error("CORS not allowed"));
  },
  credentials: true
}));

app.use("/uploads", express.static(uploadsDir));

// Helpers
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
}
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
function requireAdmin(req, res, next) {
  const token = req.cookies?.admin_token || (req.headers.authorization && req.headers.authorization.split(" ")[1]);
  if (!token) return res.status(401).json({ success: false, error: "Unauthorized" });
  const dec = verifyToken(token);
  if (!dec || !dec.admin) return res.status(401).json({ success: false, error: "Unauthorized" });
  req.admin = dec;
  next();
}

let lock = Promise.resolve();
function withLock(fn) {
  lock = lock.then(() => fn()).catch(e => { console.error("Lock error", e); throw e; });
  return lock;
}

async function getLastId() {
  const doc = await Voucher.findOne({}).sort({ id: -1 }).lean().exec();
  return doc ? doc.id : 0;
}

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_"))
});
const upload = multer({
  storage,
  limits: { files: 20, fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if ([".jpg", ".jpeg", ".png"].includes(ext)) cb(null, true);
    else cb(new Error("Only JPG/JPEG/PNG allowed"));
  }
});

// Routes
app.get("/", (req, res) => res.send("✅ Smart WASSCE backend running"));

app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ success: false, error: "Missing credentials" });
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, error: "Invalid credentials" });
  }
  const token = signToken({ admin: true, email });
  res.cookie("admin_token", token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 12,
    path: "/"
  });
  return res.json({ success: true });
});

app.post("/api/admin/logout", (req, res) => {
  res.clearCookie("admin_token", { path: "/" });
  return res.json({ success: true });
});

app.post("/api/upload-vouchers", requireAdmin, upload.array("vouchers", 20), async (req, res) => {
  try {
    if (!req.files || !req.files.length) return res.status(400).json({ success: false, error: "No files" });
    const added = await withLock(async () => {
      let last = await getLastId();
      const batch = `batch-${Date.now()}`;
      const out = [];
      for (const f of req.files) {
        last += 1;
        const ext = path.extname(f.originalname).toLowerCase();
        const newName = `voucher_${last}${ext}`;
        fs.renameSync(path.join(uploadsDir, f.filename), path.join(uploadsDir, newName));
        const v = new Voucher({ id: last, filename: newName, status: "unused", uploadedAt: new Date(), batchId: batch });
        await v.save();
        out.push({ id: v.id, filename: v.filename, url: `${req.protocol}://${req.get("host")}/uploads/${v.filename}` });
      }
      return out;
    });
    return res.json({ success: true, added });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: "Upload failed", details: err.message });
  }
});

app.get("/api/vouchers/all", requireAdmin, async (req, res) => {
  const vouchers = await Voucher.find({}).sort({ id: 1 }).lean().exec();
  return res.json({ success: true, vouchers });
});

app.get("/api/history", requireAdmin, async (req, res) => {
  const history = await History.find({}).sort({ dateUsed: -1 }).lean().exec();
  return res.json({ success: true, history });
});

app.delete("/api/vouchers/used", requireAdmin, async (req, res) => {
  try {
    const result = await withLock(async () => {
      const used = await Voucher.find({ status: "used" }).lean().exec();
      if (!used.length) return { removed: 0, remaining: await Voucher.countDocuments({}) };
      for (const v of used) {
        const p = path.join(uploadsDir, v.filename);
        if (fs.existsSync(p)) try { fs.unlinkSync(p); } catch (e) {}
      }
      await Voucher.deleteMany({ status: "used" });
      const remaining = await Voucher.countDocuments({});
      return { removed: used.length, remaining };
    });
    return res.json({ success: true, message: `Removed ${result.removed} used vouchers. ${result.remaining} remain.` });
  } catch (err) {
    return res.status(500).json({ success: false, error: "Delete failed" });
  }
});

// Immediate request (manual)
app.get("/api/vouchers/request", async (req, res) => {
  const qty = Math.max(1, Math.min(100, parseInt(req.query.quantity || "1", 10)));
  const phone = req.query.phone || "unknown";
  const assigned = await withLock(async () => {
    const unused = await Voucher.find({ status: "unused" }).sort({ id: 1 }).limit(qty).exec();
    if (unused.length < qty) return null;
    const ids = unused.map(u => u._id);
    const ref = `manual-${Date.now()}`;
    await Voucher.updateMany({ _id: { $in: ids } }, { $set: { status: "used", usedAt: new Date(), reference: ref } });
    const historyDocs = unused.map(u => ({ cardId: u.id, filename: u.filename, usedBy: phone, usedByEmail: null, reference: ref, dateUsed: new Date() }));
    await History.insertMany(historyDocs);
    return unused.map(u => ({ id: u.id, filename: u.filename, url: `${req.protocol}://${req.get("host")}/uploads/${u.filename}` }));
  });
  if (!assigned) return res.status(400).json({ success: false, error: "Not enough vouchers" });
  return res.json({ success: true, vouchers: assigned.map(a => a.url) });
});

// Paystack init
app.post("/api/pay", async (req, res) => {
  try {
    const { email, phone, quantity, amount } = req.body || {};
    if (!email || !phone || !quantity || !amount) return res.status(400).json({ success: false, error: "Missing fields" });
    const expected = Number(quantity) * PRICE_PER_VOUCHER;
    if (Number(amount) !== expected) return res.status(400).json({ success: false, error: `Amount mismatch, expected ${expected}` });
    const unusedCount = await Voucher.countDocuments({ status: "unused" });
    if (unusedCount < quantity) return res.status(400).json({ success: false, error: `Only ${unusedCount} voucher(s) available` });
    if (!PAYSTACK_SECRET) return res.status(500).json({ success: false, error: "Payment gateway not configured" });

    const payload = { email, amount: Number(amount) * 100, metadata: { phone, quantity }, callback_url: FRONTEND_SUCCESS_URL };
    const response = await axios.post("https://api.paystack.co/transaction/initialize", payload, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET}`, "Content-Type": "application/json" }, timeout: 15000
    });
    return res.json(response.data);
  } catch (err) {
    console.error("Pay init error", err.response?.data || err.message);
    return res.status(500).json({ success: false, error: "Payment initialization failed" });
  }
});

// Verify and allocate vouchers
app.get("/api/verify/:reference", async (req, res) => {
  try {
    const ref = String(req.params.reference || "").trim();
    if (!ref) return res.status(400).json({ success: false, error: "Missing reference" });
    const existing = await History.find({ reference: ref }).lean().exec();
    if (existing.length > 0) {
      const urls = existing.map(h => `${req.protocol}://${req.get("host")}/uploads/${h.filename}`);
      return res.json({ success: true, vouchers: urls, message: "Already verified" });
    }
    if (!PAYSTACK_SECRET) return res.status(500).json({ success: false, error: "Paystack not configured" });
    const verifyResp = await axios.get(`https://api.paystack.co/transaction/verify/${ref}`, { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }, timeout: 15000 });
    const payload = verifyResp.data;
    if (!payload.status || payload.data.status !== "success") return res.status(400).json({ success: false, error: "Payment not successful" });

    const metadata = payload.data.metadata || {};
    let quantity = parseInt(metadata.quantity, 10);
    if (!quantity || isNaN(quantity)) quantity = Math.round(Number(payload.data.amount) / (PRICE_PER_VOUCHER * 100));
    quantity = Math.max(1, Math.min(10, quantity));
    const phone = metadata.phone || payload.data.customer?.phone || "unknown";
    const email = payload.data.customer?.email || null;

    const assigned = await withLock(async () => {
      const unused = await Voucher.find({ status: "unused" }).sort({ id: 1 }).limit(quantity).exec();
      if (unused.length < quantity) return null;
      const ids = unused.map(u => u._id);
      await Voucher.updateMany({ _id: { $in: ids } }, { $set: { status: "used", usedAt: new Date(), reference: ref } });
      const historyDocs = unused.map(u => ({ cardId: u.id, filename: u.filename, usedBy: phone, usedByEmail: email, reference: ref, dateUsed: new Date() }));
      await History.insertMany(historyDocs);
      return unused.map(u => ({ id: u.id, filename: u.filename, url: `${req.protocol}://${req.get("host")}/uploads/${u.filename}` }));
    });

    if (!assigned) {
      const available = await Voucher.countDocuments({ status: "unused" });
      return res.status(400).json({ success: false, error: "Payment OK but not enough vouchers left", available });
    }
    return res.json({ success: true, vouchers: assigned.map(a => a.url) });
  } catch (err) {
    console.error("Verify error", err.response?.data || err.message);
    return res.status(500).json({ success: false, error: "Verification failed" });
  }
});

// Start
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
