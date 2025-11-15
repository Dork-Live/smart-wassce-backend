import mongoose from "mongoose";

const voucherSchema = new mongoose.Schema({
  id: Number,
  filename: String,
  status: { type: String, default: "unused" },
  uploadedAt: String,
  usedAt: String,
  reference: String,
  batchId: String
});

export default mongoose.model("Voucher", voucherSchema);
