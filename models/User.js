const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  birthday: { type: String, required: false }, // Optional birthday
  phone: { type: String, required: false }, // Optional phone number
  address: { type: String, required: false }, // Optional address
  password: { type: String, required: true }, 
  isAdmin: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false }, // Email verification status
}, { timestamps: true });

// Before saving, hash password if it's modified
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare password for login
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', userSchema);