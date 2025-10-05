const express = require('express');
const router = express.Router();
const User = require('../models/User');
const UserOTPVerification = require('../models/UserOTPVerification');
const bcrypt = require('bcryptjs');  // Giữ import nếu cần cho OTP
const jwt = require('jsonwebtoken');
const { sendOTPVerificationEmail } = require('../utils/sendOTP');
require('dotenv').config();

// POST /signup
// 👈 Không tạo user ngay, chỉ validate + gửi OTP + lưu temporary data vào UserOTPVerification
router.post('/signup', async (req, res) => {
  let { name, email, password, dateOfBirth, phone, address } = req.body;  // Thêm address
  name = name?.trim();
  email = email?.toLowerCase().trim();  // Thêm toLowerCase cho case-insensitive
  password = password?.trim();
  dateOfBirth = dateOfBirth?.trim();
  phone = phone?.trim();
  address = address?.trim();  // Optional

  // Validation empty fields (phone/address optional)
  if (!name || !email || !password || !dateOfBirth) {
    return res.json({ status: 'FAILED', message: 'Empty input fields' });
  }

  // Validate name (basic regex)
  if (!/^[a-zA-Z\s]+$/.test(name)) {
    return res.json({ status: 'FAILED', message: 'Invalid name entered' });
  }

  // Validate email (basic)
  if (!/^[\w-.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    return res.json({ status: 'FAILED', message: 'Invalid email' });
  }

  // Optional: Validate phone
  if (phone && !/^\d{10,11}$/.test(phone)) {
    return res.json({ status: 'FAILED', message: 'Invalid phone number' });
  }

  try {
    // 👈 Check nếu email đã tồn tại (verified user hoặc pending OTP)
    const existingUser = await User.findOne({ email });
    const existingOTP = await UserOTPVerification.findOne({ email });
    if (existingUser || existingOTP) {
      return res.json({ status: 'FAILED', message: 'User with the provided email already exists or pending verification' });
    }

    // 👈 Hash password trước khi lưu temporary
    const hashedPassword = await bcrypt.hash(password, 10);

    // 👈 SỬA: Gọi sendOTPVerificationEmail chỉ với email (bỏ null userId)
    const { hashedOTP, expiresAt } = await sendOTPVerificationEmail(email);

    // 👈 Lưu temporary data vào UserOTPVerification (thêm fields user info)
    // Giả sử schema đã thêm: email (unique), name, hashedPassword, birthday, phone, address
    const otpVerification = new UserOTPVerification({
      email,  // 👈 Sử dụng email làm key chính thay vì userId
      name,
      password: hashedPassword,  // Lưu hashed password
      birthday: dateOfBirth,
      phone,
      address,
      otp: hashedOTP,
      expiresAt
    });
    await otpVerification.save();

    // Trả PENDING, email
    res.json({ 
      status: 'PENDING', 
      message: 'Verification OTP email sent',
      email: email  // Bonus: Trả email để frontend dễ dùng ở /verify-otp
    });
  } catch (error) {
    res.status(500).json({ status: 'FAILED', message: error.message });
  }
});

// POST /verify-otp (Nhận email thay vì userId, tạo user sau verify)
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;  // Nhận email và otp
  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and OTP required' });
  }

  try {
    // Tìm OTP record bằng email
    const otpRecord = await UserOTPVerification.findOne({ email: email.toLowerCase().trim() })
      .sort({ createdAt: -1 })
      .lean();

    if (!otpRecord) {
      return res.status(400).json({ message: 'No OTP record found' });
    }

    if (Date.now() > otpRecord.expiresAt) {
      return res.status(400).json({ message: 'OTP expired' });
    }

    const isValidOTP = await bcrypt.compare(otp, otpRecord.otp);
    if (!isValidOTP) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    // 👈 Tạo user mới từ temporary data sau khi verify thành công
    const newUser = new User({
      name: otpRecord.name,
      email: otpRecord.email,
      password: otpRecord.password,  // Đã hashed
      birthday: otpRecord.birthday,
      phone: otpRecord.phone,
      address: otpRecord.address,
      isVerified: true  // Set verified ngay
    });
    await newUser.save();

    // Xóa OTP record sau khi tạo user
    await UserOTPVerification.deleteOne({ _id: otpRecord._id });

    const payload = { id: newUser._id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ 
      message: 'Email verified successfully!',
      token,
      user: { id: newUser._id, name: newUser.name, email: newUser.email }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /login (Giữ nguyên, chỉ login verified user)
router.post('/login', async (req, res) => {
  let { email, password } = req.body;
  email = email?.toLowerCase().trim();  // Sửa: Trim + lowercase cho nhất quán
  password = password?.trim();

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await user.matchPassword(password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    if (!user.isVerified) return res.status(400).json({ message: 'Please verify your email first' });

    const payload = { id: user._id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({
      id: user._id,
      name: user.name,
      email: user.email, 
      token
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /resend-otp (Dùng email, check pending record)
router.post('/resend-otp', async (req, res) => {
  let { email } = req.body;  // Thêm trim + lowercase
  email = email?.toLowerCase().trim();

  try {
    // 👈 Check pending record hoặc verified user
    const user = await User.findOne({ email });
    if (user && user.isVerified) return res.status(400).json({ message: 'Already verified' });

    const existingOTP = await UserOTPVerification.findOne({ email });
    if (!existingOTP) return res.status(400).json({ message: 'User not found or no pending verification' });

    // Xóa old OTP records
    await UserOTPVerification.deleteMany({ email });

    // 👈 SỬA: Gửi new OTP, nhưng cần temporary data từ existingOTP
    const { hashedOTP, expiresAt } = await sendOTPVerificationEmail(email);  // 👈 Bỏ null userId

    // Tạo new OTP record với data cũ
    const newOtpVerification = new UserOTPVerification({
      email: existingOTP.email,
      name: existingOTP.name,
      password: existingOTP.password,
      birthday: existingOTP.birthday,
      phone: existingOTP.phone,
      address: existingOTP.address,
      otp: hashedOTP,
      expiresAt
    });
    await newOtpVerification.save();

    res.json({ message: 'New OTP sent to email' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
