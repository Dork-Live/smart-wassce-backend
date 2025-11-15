import mongoose from "mongoose";

const adminSchema = new mongoose.Schema({
  email: String,
  passwordHash: String,
});

export default mongoose.model("Admin", adminSchema);
