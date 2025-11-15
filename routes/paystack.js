import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const router = express.Router();

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const BASE_URL = process.env.BASE_URL || "http://localhost:4000";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const vouchersFile = path.join(__dirname, "../data/vouchers.json");
const historyFile = path.join(__dirname, "../data/history.json");

function readJSON(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
function writeJSON(p, data) {
  fs.writeFileSync(p, JSON.stringify(data, null, 2));
}

// ✅ Initialize Payment
router.post("/pay", async (req, res) => {
  try {
    const { email, amount, phone, quantity } = req.body;
    if (!email || !amount || !phone || !quantity)
      return res.status(400).json({ error: "Missing fields" });

    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email,
        amount: amount * 100,
        metadata: { phone, quantity },
        callback_url: `${process.env.FRONTEND_URL}`,
      },
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } }
    );
    res.json(response.data);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: "Paystack initialization failed" });
  }
});

// ✅ Verify Payment + allocate vouchers
router.get("/verify/:ref", async (req, res) => {
  try {
    const { ref } = req.params;
    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${ref}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } }
    );

    const { status, customer, metadata, amount } = verify.data.data;
    if (status !== "success")
      return res.status(400).json({ error: "Payment not verified" });

    const quantity = metadata?.quantity || Math.floor(amount / 2500);
    const phone = metadata?.phone || "unknown";
    const vouchers = readJSON(vouchersFile);
    const unused = vouchers.filter((v) => v.status === "unused");

    if (unused.length < quantity) {
      return res.status(400).json({ error: `Not enough vouchers left (${unused.length}).` });
    }

    const assigned = unused.slice(0, quantity);
    const updated = vouchers.map((v) =>
      assigned.find((a) => a.id === v.id)
        ? { ...v, status: "used", usedAt: new Date().toISOString() }
        : v
    );
    writeJSON(vouchersFile, updated);

    // Save history
    const hist = readJSON(historyFile);
    assigned.forEach((a) => {
      hist.push({
        cardId: a.id,
        filename: a.filename,
        usedBy: phone,
        dateUsed: new Date().toISOString(),
      });
    });
    writeJSON(historyFile, hist);

    const urls = assigned.map((a) => `${BASE_URL}/uploads/${a.filename}`);
    return res.json({ success: true, vouchers: urls });
  } catch (err) {
    console.error("Verify error:", err.response?.data || err.message);
    res.status(500).json({ error: "Verification failed" });
  }
});

export default router;