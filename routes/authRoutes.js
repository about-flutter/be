const express = require('express');
const router = express.Router();
const User = require('../models/User');
const UserOTPVerification = require('../models/UserOTPVerification');
const bcrypt = require('bcryptjs');  // Import cho hash trong signup
const jwt = require('jsonwebtoken');
const { sendOTPVerificationEmail } = require('../utils/sendOTP');
require('dotenv').config();

// POST /signup
router.post('/signup', async (req, res) => {
  let { name, email, password, dateOfBirth, phone } = req.body;  // Thêm phone vào destructuring
  name = name?.trim();
  email = email?.trim();
  password = password?.trim();
  dateOfBirth = dateOfBirth?.trim();
  phone = phone?.trim();  // Trim nếu có, optional nên không check empty

  // Validation empty fields (phone optional, bỏ check !phone)
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

  // Optional: Validate phone (nếu muốn, ví dụ: số điện thoại Việt Nam)
  if (phone && !/^\d{10,11}$/.test(phone)) {
    return res.json({ status: 'FAILED', message: 'Invalid phone number' });
  }

  try {
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.json({ status: 'FAILED', message: 'User with the provided email already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user (isVerified: false default)
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      birthday: dateOfBirth,
      phone,  // Giờ phone đã defined, optional nên nếu undefined thì không set
    });
    await newUser.save();

    // Send OTP and get hashedOTP
    const { hashedOTP, expiresAt } = await sendOTPVerificationEmail(newUser._id, email);

    // Create OTP record in separate collection
    const otpVerification = new UserOTPVerification({
      userId: newUser._id,
      otp: hashedOTP,
      expiresAt
    });
    await otpVerification.save();

    res.json({ status: 'PENDING', message: 'Verification OTP email sent' });
  } catch (error) {
    res.status(500).json({ status: 'FAILED', message: error.message });
  }
});

// POST /verify-otp (Sửa: Dùng schema riêng, query by userId, xóa record sau verify)
router.post('/verify-otp', async (req, res) => {
  const { userId, otp } = req.body;  // Nhận userId thay vì email (từ frontend sau signup)
  if (!userId || !otp) {
    return res.status(400).json({ message: 'User ID and OTP required' });
  }

  try {
    // Tìm user
    const user = await User.findById(userId);
    if (!user) return res.status(400).json({ message: 'User not found' });

    // Tìm OTP record mới nhất cho user
    const otpRecord = await UserOTPVerification.findOne({ userId })
      .sort({ createdAt: -1 })  // Latest first
      .lean();

    if (!otpRecord) {
      return res.status(400).json({ message: 'No OTP record found' });
    }

    // Check expiry
    if (Date.now() > otpRecord.expiresAt) {
      return res.status(400).json({ message: 'OTP expired' });
    }

    // Compare hashed OTP
    const isValidOTP = await bcrypt.compare(otp, otpRecord.otp);
    if (!isValidOTP) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    // Xóa OTP record
    await UserOTPVerification.deleteOne({ _id: otpRecord._id });

    // Set user verified
    user.isVerified = true;
    await user.save();

    // Issue JWT
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

// POST /login (Giữ nguyên, check isVerified)
router.post('/login', async (req, res) => {
let { email, password } = req.body;  // Thêm let để trim
  email = email?.trim();  // Sửa: Trim email để tránh space (bug phổ biến)
  password = password?.trim();  // Trim password cho an toàn

  try {
    console.log('Login attempt for email:', email);  // Debug: Log email input

    const user = await User.findOne({ email });
    console.log('User found:', user ? user.email : 'No user');  // Debug: Có tìm thấy user không?

    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await user.matchPassword(password);
    console.log('Password match:', isMatch);  // Debug: Compare result

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
    console.error('Login error:', err);  // Log full error
    res.status(500).json({ message: err.message });
  }
});

// Bonus: POST /resend-otp (Nếu user chưa verified, gửi OTP mới)
router.post('/resend-otp', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });
    if (user.isVerified) return res.status(400).json({ message: 'Already verified' });

    // Xóa OTP cũ nếu có
    await UserOTPVerification.deleteMany({ userId: user._id });

    // Gửi OTP mới
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
