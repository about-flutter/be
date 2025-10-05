const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// Schema cho temporary OTP verification (lưu user info pending trước khi tạo User)
const UserOTPVerificationSchema = new Schema({
  // Thay userId bằng email làm key chính (unique, required)
  email: { 
    type: String, 
    required: true, 
    lowercase: true,  // Tự động lowercase để nhất quán
    unique: true  // Ngăn multiple pending cho cùng email
  },
  // Temporary user info (sẽ dùng để tạo User sau verify)
  name: { type: String, required: true },
  password: { type: String, required: true },  // Đã hashed trước khi lưu
  birthday: { type: String, required: false },  // Optional (giữ String nếu frontend gửi string)
  phone: { type: String, required: true },  // Bắt buộc
  address: { type: String, required: false },  // Optional
  // OTP fields
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
});

// TTL index trên expiresAt (tự xóa expired records)
UserOTPVerificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Unique index cho email (đã có trong schema, nhưng explicit để chắc)
UserOTPVerificationSchema.index({ email: 1 }, { unique: true });

const UserOTPVerification = mongoose.model('UserOTPVerification', UserOTPVerificationSchema);

module.exports = UserOTPVerification;
