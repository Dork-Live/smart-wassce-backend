import mongoose from "mongoose";

const historySchema = new mongoose.Schema({
  cardId: Number,
  filename: String,
  usedBy: String,
  usedByEmail: String,
  reference: String,
  dateUsed: String
});

export default mongoose.model("History", historySchema);
