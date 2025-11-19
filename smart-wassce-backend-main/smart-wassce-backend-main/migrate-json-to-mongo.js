// migrate-json-to-mongo.js
import fs from "fs";
import path from "path";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/smartwassce";
await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const voucherSchema = new mongoose.Schema({}, { strict: false });
const historySchema = new mongoose.Schema({}, { strict: false });
const Voucher = mongoose.model("MigrateVoucher", voucherSchema, "vouchers");
const History = mongoose.model("MigrateHistory", historySchema, "history");

function readJSON(p) {
  if (!fs.existsSync(p)) return [];
  return JSON.parse(fs.readFileSync(p,"utf8"));
}

const dataDir = path.join(process.cwd(),"data");
const vouchersFile = path.join(dataDir, "vouchers.json");
const historyFile = path.join(dataDir, "history.json");

const vouchers = readJSON(vouchersFile);
const history = readJSON(historyFile);

if (vouchers.length) {
  await Voucher.insertMany(vouchers.map(v => ({ ...v })));
  console.log("Imported vouchers:", vouchers.length);
} else {
  console.log("No vouchers to import");
}
if (history.length) {
  await History.insertMany(history.map(h => ({ ...h })));
  console.log("Imported history:", history.length);
} else {
  console.log("No history to import");
}

process.exit(0);
