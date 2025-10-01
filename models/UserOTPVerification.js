const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserOTPVerificationSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
});

// TTL index: Tự xóa document sau expiresAt
UserOTPVerificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const UserOTPVerification = mongoose.model('UserOTPVerification', UserOTPVerificationSchema);

module.exports = UserOTPVerification;