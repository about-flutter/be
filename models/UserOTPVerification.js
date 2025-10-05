const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// 👈 SỬA: Schema cho temporary OTP verification (lưu user info pending trước khi tạo User)
const UserOTPVerificationSchema = new Schema({
  // 👈 SỬA: Thay userId bằng email làm key chính (unique, required)
  email: { 
    type: String, 
    required: true, 
    lowercase: true,  // Tự động lowercase để nhất quán
    unique: true  // Ngăn multiple pending cho cùng email
  },
  // 👈 THÊM: Temporary user info (sẽ dùng để tạo User sau verify)
  name: { type: String, required: true },
  password: { type: String, required: true },  // Đã hashed trước khi lưu
  birthday: { type: String, required: true },  // Hoặc Date nếu parse
  phone: { type: String },  // Optional
  address: { type: String },  // Optional
  // OTP fields (giữ nguyên)
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
});

// 👈 SỬA: TTL index trên expiresAt (tự xóa expired records, giữ nguyên)
UserOTPVerificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// 👈 THÊM: Index unique cho email để tránh duplicate pending
UserOTPVerificationSchema.index({ email: 1 }, { unique: true });

const UserOTPVerification = mongoose.model('UserOTPVerification', UserOTPVerificationSchema);

module.exports = UserOTPVerification;
