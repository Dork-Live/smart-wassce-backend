// server.js — Smart WASSCE backend (Mongoose + Paystack + Admin JWT)
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
import { fileURLToPath } from "url";

dotenv.config();

// --- Setup __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Config
const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGO_URI || "";
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || "";
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const FRONTEND_SUCCESS_URL = process.env.FRONTEND_SUCCESS_URL || `${BASE_URL}/success.html`;
const PRICE_PER_VOUCHER = Number(process.env.PRICE_PER_VOUCHER || 25);
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "please-change-me";
const UPLOADS_DIR = path.join(__dirname, "uploads");
const DATA_DIR = path.join(__dirname, "data"); // only used for migration step

// ensure uploads folder exists
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// --- Mongoose models / connection
async function connectDb() {
  if (!MONGODB_URI) {
    console.error("MONGODB_URI is not set in .env");
    process.exit(1);
  }
  await mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  console.log("✅ Connected to MongoDB");
}

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
  cardId: { type: Number, required: true, unique: true }, // sequential id
  filename: { type: String, required: true },
  status: { type: String, enum: ["unused", "used"], default: "unused" },
  batchId: { type: String },
  uploadedAt: { type: Date, default: Date.now },
  usedAt: { type: Date },
  reference: { type: String }, // paystack reference when used
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

// --- Express app
const app = express();

// CORS — allow your frontends (add deployed domain later)
app.use(
  cors({
    origin: (origin, cb) => {
      // allow requests from local dev origins or undefined (postman)
      const allowed = [
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
      ];
      if (!origin || allowed.indexOf(origin) !== -1) return cb(null, true);
      return cb(new Error("CORS not allowed"), false);
    },
    credentials: true,
  })
);

app.use(bodyParser.json());

// serve uploaded images
app.use("/uploads", express.static(UPLOADS_DIR));

// ---------- Multer (uploads) ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
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

// ---------- Helpers ----------
async function migrateJsonToMongoIfPresent() {
  // If there are JSON files in /data, import them once and remove those files
  try {
    if (!fs.existsSync(DATA_DIR)) return;
    const vouchersFile = path.join(DATA_DIR, "vouchers.json");
    const historyFile = path.join(DATA_DIR, "history.json");
    let imported = false;

    if (fs.existsSync(vouchersFile)) {
      const raw = fs.readFileSync(vouchersFile, "utf8");
      const arr = JSON.parse(raw || "[]");
      if (arr.length) {
        // find current max cardId (from counter)
        let maxExisting = await getNextSequence("voucherSeq", 0).catch(() => 0);
        // ensure counter is set to at least maxExisting from DB documents
        const maxFromArr = arr.reduce((m, v) => Math.max(m, v.id || 0), 0);
        if (maxFromArr > maxExisting) {
          // set counter to maxFromArr
          await Counter.findOneAndUpdate({ name: "voucherSeq" }, { seq: maxFromArr }, { upsert: true });
          maxExisting = maxFromArr;
        }

        // import entries
        for (const item of arr) {
          const next = await getNextSequence("voucherSeq", 1);
          const ext = path.extname(item.filename || ".jpg") || ".jpg";
          const newFilename = `voucher_${next}${ext}`;
          // If the JSON referenced files in uploads, try to rename/move: best-effort
          const possibleOldPath = path.join(UPLOADS_DIR, item.filename || "");
          if (item.filename && fs.existsSync(possibleOldPath)) {
            fs.renameSync(possibleOldPath, path.join(UPLOADS_DIR, newFilename));
          } else {
            // leave it — admin will re-upload
          }
          const doc = new Voucher({
            cardId: next,
            filename: newFilename,
            status: item.status || "unused",
            batchId: item.batchId || `migrated-${Date.now()}`,
            uploadedAt: item.uploadedAt || new Date(),
          });
          await doc.save();
        }
        imported = true;
      }
      // remove file after importing
      fs.unlinkSync(vouchersFile);
    }

    if (fs.existsSync(historyFile)) {
      const raw = fs.readFileSync(historyFile, "utf8");
      const arr = JSON.parse(raw || "[]");
      if (arr.length) {
        for (const h of arr) {
          const hist = new History({
            cardId: h.cardId,
            filename: h.filename,
            usedBy: h.usedBy,
            usedByEmail: h.usedByEmail || null,
            reference: h.reference || null,
            dateUsed: h.dateUsed ? new Date(h.dateUsed) : new Date(),
          });
          await hist.save();
        }
        imported = true;
      }
      fs.unlinkSync(historyFile);
    }
    if (imported) console.log("✅ Migrated JSON data into MongoDB and removed local JSON files.");
  } catch (err) {
    console.error("Migration error:", err);
  }
}

// --- Admin auth (JWT) ---
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
  // Accept token via Authorization header Bearer <token> OR cookie 'admin_token'
  const authHeader = req.headers.authorization || "";
  let token = null;
  if (authHeader.startsWith("Bearer ")) token = authHeader.split(" ")[1];
  else if (req.cookies && req.cookies.admin_token) token = req.cookies.admin_token;
  else if (req.headers["x-admin-token"]) token = req.headers["x-admin-token"]; // fallback header option

  if (!token) return res.status(401).json({ success: false, error: "Unauthorized - no token" });
  const payload = verifyAdminToken(token);
  if (!payload) return res.status(401).json({ success: false, error: "Unauthorized - invalid token" });
  req.admin = payload;
  next();
}

// --- Simple routes ---
// Health
app.get("/", (req, res) => res.send("✅ Smart WASSCE backend running (MongoDB + Paystack)"));

/**
 * POST /api/admin/login
 * Body: { email, password }
 * Exchanges email/password for an admin JWT (do not store token on frontend in localStorage - can store in cookie).
 */
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ success: false, error: "Missing credentials" });

  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, error: "Invalid credentials" });
  }

  const token = signAdminToken({ email });
  // Return token in body; frontend should use it in Authorization header or send it as x-admin-token.
  return res.json({ success: true, token, email });
});

app.post("/api/admin/logout", (req, res) => {
  // client-side can just forget token; nothing server needs to do for stateless JWT
  res.json({ success: true, message: "Logged out" });
});

/**
 * POST /api/upload-vouchers
 * Admin uploads up to 20 images. Files are renamed sequentially (voucher_1.jpg ...)
 * Protected by JWT admin token
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
 * Admin listing of all vouchers (with status)
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
 * Admin listing of usage history
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
 * Admin route — delete all used vouchers (images + remove entries)
 */
app.delete("/api/vouchers/used", requireAdmin, async (req, res) => {
  try {
    const used = await Voucher.find({ status: "used" }).lean();
    if (!used.length) return res.json({ success: true, message: "No used vouchers found." });

    // delete files
    for (const v of used) {
      const filePath = path.join(UPLOADS_DIR, v.filename);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }

    // remove used docs
    const result = await Voucher.deleteMany({ status: "used" });
    return res.json({ success: true, message: `Deleted ${result.deletedCount} used vouchers.` });
  } catch (err) {
    console.error("Delete used vouchers error:", err);
    return res.status(500).json({ success: false, error: "Failed to delete used vouchers", details: err.message });
  }
});

/**
 * GET /api/vouchers/request?quantity=2&phone=...
 * Allocate N unused vouchers immediately and mark them used (useful for admin/manual flow).
 */
app.get("/api/vouchers/request", async (req, res) => {
  try {
    const qty = Math.max(1, Math.min(100, parseInt(req.query.quantity || "1", 10)));
    const phone = req.query.phone || "unknown";

    // atomic-ish using a transaction-like pattern with a JS lock
    // simple approach: find unused, slice, update their status
    const unused = await Voucher.find({ status: "unused" }).sort({ cardId: 1 }).limit(qty).exec();
    if (unused.length < qty) return res.status(400).json({ success: false, error: `Not enough vouchers available` });

    const ids = unused.map(u => u._id);
    await Voucher.updateMany({ _id: { $in: ids } }, { $set: { status: "used", usedAt: new Date(), reference: `manual-${Date.now()}` } });

    // write history
    const historyDocs = unused.map(u => ({
      cardId: u.cardId,
      filename: u.filename,
      usedBy: phone,
      usedByEmail: null,
      reference: `manual-${Date.now()}`,
      dateUsed: new Date(),
    }));
    await History.insertMany(historyDocs);

    const urls = unused.map(u => `${BASE_URL}/uploads/${u.filename}`);
    return res.json({ success: true, vouchers: urls, assigned: unused.map(u => ({ id: u.cardId, filename: u.filename })) });
  } catch (err) {
    console.error("Request coupons error:", err);
    return res.status(500).json({ success: false, error: "Failed to allocate vouchers" });
  }
});

/**
 * POST /api/pay
 * Initialize Paystack payment.
 * Body: { email, phone, quantity, amount }
 * Validates stock BEFORE initializing Paystack.
 */
app.post("/api/pay", async (req, res) => {
  try {
    const { email, phone, quantity, amount } = req.body || {};
    if (!email || !phone || !quantity || !amount) {
      return res.status(400).json({ success: false, error: "Missing required fields" });
    }

    // validate amount equals expected
    const expected = Number(quantity) * PRICE_PER_VOUCHER;
    if (Number(amount) !== expected) {
      return res.status(400).json({ success: false, error: `Amount mismatch. Expected ${expected}` });
    }

    // check available stock
    const unusedCount = await Voucher.countDocuments({ status: "unused" });
    if (unusedCount < quantity) {
      return res.status(400).json({ success: false, error: `Only ${unusedCount} voucher(s) available. Reduce quantity.` });
    }

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
 * GET /api/verify/:reference
 * Verifies Paystack payment and allocates vouchers (quantity from metadata or amount)
 */
app.get("/api/verify/:reference", async (req, res) => {
  try {
    const ref = req.params.reference;
    if (!ref) return res.status(400).json({ success: false, error: "Missing reference" });

    if (!PAYSTACK_SECRET_KEY) return res.status(500).json({ success: false, error: "Paystack key not configured" });

    // If already in history, return the saved vouchers (idempotent)
    const existing = await History.find({ reference: ref }).lean();
    if (existing.length > 0) {
      const savedUrls = existing.map(h => `${BASE_URL}/uploads/${h.filename}`);
      return res.json({ success: true, vouchers: savedUrls, message: "Already verified" });
    }

    // verify with Paystack
    const verifyResp = await axios.get(`https://api.paystack.co/transaction/verify/${ref}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
    });

    const payload = verifyResp.data;
    if (!payload.status || payload.data.status !== "success") {
      return res.status(400).json({ success: false, error: "Payment not successful" });
    }

    const metadata = payload.data.metadata || {};
    let quantity = parseInt(metadata.quantity, 10);

    if (!quantity || isNaN(quantity)) {
      quantity = Math.round(Number(payload.data.amount) / (PRICE_PER_VOUCHER * 100));
    }

    // clamp quantity
    if (quantity < 1) quantity = 1;
    if (quantity > 100) quantity = 100;

    const phone = metadata.phone || (payload.data.customer && payload.data.customer.phone) || "unknown";
    const email = payload.data.customer?.email || null;

    // allocate vouchers
    const unused = await Voucher.find({ status: "unused" }).sort({ cardId: 1 }).limit(quantity);
    if (unused.length < quantity) {
      return res.status(400).json({
        success: false,
        error: `Payment successful but not enough vouchers left.`,
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

// ---------- Start server ----------
(async () => {
  try {
    await connectDb();
    await migrateJsonToMongoIfPresent();
    app.listen(PORT, () => console.log(`✅ Backend running on port ${PORT}`));
  } catch (err) {
    console.error("Startup error:", err);
    process.exit(1);
  }
})();