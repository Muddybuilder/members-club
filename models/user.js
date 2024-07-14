const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const UserSchema = new Schema({
  first_name: { type: String, required: true, maxLength: 30 },
  family_name: { type: String, required: true, maxLength: 30 },
  username: { type: String, required:true },
  password: { type: String, required:true }
});

// Export model
module.exports = mongoose.model("User", UserSchema);
