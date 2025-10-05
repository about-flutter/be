const express = require('express');
const router = express.Router();
const User = require('../models/User');
const UserOTPVerification = require('../models/UserOTPVerification');
const bcrypt = require('bcryptjs');  // Giữ import nếu cần cho OTP
const jwt = require('jsonwebtoken');
const { sendOTPVerificationEmail } = require('../utils/sendOTP');
require('dotenv').config();

// POST /signup
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
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.json({ status: 'FAILED', message: 'User with the provided email already exists' });
    }

    // SỬA: Không hash manual - để pre-save hook handle
    const newUser = new User({
      name,
      email,
      password,  // Plain password - pre-save sẽ hash
      birthday: dateOfBirth,
      phone,
      address  // Thêm nếu có
    });
    await newUser.save();  // Pre-save hook chạy ở đây, hash password

    // Send OTP and get hashedOTP
    const { hashedOTP, expiresAt } = await sendOTPVerificationEmail(newUser._id, email);

    // Create OTP record
    const otpVerification = new UserOTPVerification({
      userId: newUser._id,
      otp: hashedOTP,
      expiresAt
    });
    await otpVerification.save();

    // SỬA: Không trả userId nữa, chỉ message (frontend sẽ dùng email để verify)
    res.json({ 
      status: 'PENDING', 
      message: 'Verification OTP email sent',
      email: email  // Bonus: Trả email để frontend dễ dùng ở /verify-otp
    });
  } catch (error) {
    res.status(500).json({ status: 'FAILED', message: error.message });
  }
});

// POST /verify-otp (SỬA: Nhận email thay vì userId)
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;  // SỬA: Nhận email và otp
  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and OTP required' });
  }

  try {
    // SỬA: Tìm user bằng email thay vì userId
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(400).json({ message: 'User not found' });

    // SỬA: Tìm OTP record bằng userId (từ user tìm được)
    const otpRecord = await UserOTPVerification.findOne({ userId: user._id })
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

    await UserOTPVerification.deleteOne({ _id: otpRecord._id });

    user.isVerified = true;
    await user.save();

    const payload = { id: user._id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ 
      message: 'Email verified successfully!',
      token,
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /login (Thêm trim + toLowerCase cho email)
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

// POST /resend-otp (Giữ nguyên, đã dùng email)
router.post('/resend-otp', async (req, res) => {
  let { email } = req.body;  // Thêm trim + lowercase
  email = email?.toLowerCase().trim();

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });
    if (user.isVerified) return res.status(400).json({ message: 'Already verified' });

    await UserOTPVerification.deleteMany({ userId: user._id });

    const { hashedOTP, expiresAt } = await sendOTPVerificationEmail(user._id, email);
    const otpVerification = new UserOTPVerification({
      userId: user._id,
      otp: hashedOTP,
      expiresAt
    });
    await otpVerification.save();

    res.json({ message: 'New OTP sent to email' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
