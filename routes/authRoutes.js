const express = require('express');
const router = express.Router();
const User = require('../models/User');
const UserOTPVerification = require('../models/UserOTPVerification');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sendOTPVerificationEmail } = require('../utils/sendOTP');
require('dotenv').config();

// POST /signup: Không tạo user ngay, chỉ validate + gửi OTP + lưu temporary data
router.post('/signup', async (req, res) => {
  let { name, email, password, dateOfBirth, phone, address } = req.body;
  // Trim và lowercase nhất quán
  name = name?.trim();
  email = email?.toLowerCase().trim();
  password = password?.trim();
  dateOfBirth = dateOfBirth?.trim();
  phone = phone?.trim();
  address = address?.trim();

  // Validation empty fields: Bắt buộc name, email, password, phone
  if (!name || !email || !password || !phone) {
    return res.status(400).json({ status: 'FAILED', message: 'Empty input fields' });
  }

  // Validate name (chỉ chữ cái và space)
  if (!/^[a-zA-Z\s]+$/.test(name)) {
    return res.status(400).json({ status: 'FAILED', message: 'Invalid name entered' });
  }

  // Validate email (basic regex)
  if (!/^[\w-.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    return res.status(400).json({ status: 'FAILED', message: 'Invalid email' });
  }

  // Validate phone (10-11 chữ số VN)
  if (!/^\d{10,11}$/.test(phone)) {
    return res.status(400).json({ status: 'FAILED', message: 'Invalid phone number' });
  }

  // Validate password length (thêm cho an toàn)
  if (password.length < 6) {
    return res.status(400).json({ status: 'FAILED', message: 'Password too short' });
  }

  try {
    // Check nếu email đã tồn tại (verified user hoặc pending OTP)
    const existingUser = await User.findOne({ email });
    const existingOTP = await UserOTPVerification.findOne({ email });
    if (existingUser || existingOTP) {
      return res.status(400).json({ status: 'FAILED', message: 'User with the provided email already exists or pending verification' });
    }

    // Hash password trước khi lưu temporary
    const hashedPassword = await bcrypt.hash(password, 10);

    // Gửi OTP và lấy hashedOTP, expiresAt
    const { hashedOTP, expiresAt } = await sendOTPVerificationEmail(email);

    // Lưu temporary data
    const otpVerification = new UserOTPVerification({
      email,
      name,
      password: hashedPassword,
      birthday: dateOfBirth,  // Optional
      phone,
      address,  // Optional
      otp: hashedOTP,
      expiresAt
    });
    await otpVerification.save();

    // Trả PENDING với email để frontend dùng
    res.status(201).json({ 
      status: 'PENDING', 
      message: 'Verification OTP email sent',
      email
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ status: 'FAILED', message: 'Internal server error' });
  }
});

// POST /verify-otp: Nhận email + otp, tạo user sau verify
router.post('/verify-otp', async (req, res) => {
  let { email, otp } = req.body;
  email = email?.toLowerCase().trim();
  if (!email || !otp) {
    return res.status(400).json({ status: 'FAILED', message: 'Email and OTP required' });
  }

  try {
    // Tìm OTP record bằng email (không cần sort vì unique)
    const otpRecord = await UserOTPVerification.findOne({ email }).lean();

    if (!otpRecord) {
      return res.status(400).json({ status: 'FAILED', message: 'No OTP record found' });
    }

    if (Date.now() > otpRecord.expiresAt) {
      // Xóa expired record luôn
      await UserOTPVerification.deleteOne({ email });
      return res.status(400).json({ status: 'FAILED', message: 'OTP expired' });
    }

    // Verify OTP (plain vs hashed)
    const isValidOTP = await bcrypt.compare(otp, otpRecord.otp);
    if (!isValidOTP) {
      return res.status(400).json({ status: 'FAILED', message: 'Invalid OTP' });
    }

    // Tạo user mới từ temporary data
    const newUser = new User({
      name: otpRecord.name,
      email: otpRecord.email,
      password: otpRecord.password,  // Đã hashed
      birthday: otpRecord.birthday,
      phone: otpRecord.phone,
      address: otpRecord.address,
      isVerified: true
    });
    await newUser.save();

    // Xóa OTP record
    await UserOTPVerification.deleteOne({ _id: otpRecord._id });

    // Tạo token
    const payload = { id: newUser._id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ 
      status: 'SUCCESS',
      message: 'Email verified successfully!',
      token,
      user: { id: newUser._id, name: newUser.name, email: newUser.email }
    });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ status: 'FAILED', message: 'Internal server error' });
  }
});

// POST /login: Chỉ login verified user
router.post('/login', async (req, res) => {
  let { email, password } = req.body;
  email = email?.toLowerCase().trim();
  if (!email || !password) {
    return res.status(400).json({ status: 'FAILED', message: 'Email and password required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ status: 'FAILED', message: 'Invalid credentials' });
    }

    const isMatch = await user.matchPassword(password);  // Giả sử method có sẵn
    if (!isMatch) {
      return res.status(400).json({ status: 'FAILED', message: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(400).json({ status: 'FAILED', message: 'Please verify your email first' });
    }

    const payload = { id: user._id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({
      status: 'SUCCESS',
      id: user._id,
      name: user.name,
      email: user.email, 
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ status: 'FAILED', message: 'Internal server error' });
  }
});

// POST /resend-otp: Gửi OTP mới cho pending email
router.post('/resend-otp', async (req, res) => {
  let { email } = req.body;
  email = email?.toLowerCase().trim();
  if (!email) {
    return res.status(400).json({ status: 'FAILED', message: 'Email required' });
  }

  try {
    // Check verified user
    const user = await User.findOne({ email });
    if (user && user.isVerified) {
      return res.status(400).json({ status: 'FAILED', message: 'Already verified' });
    }

    // Check pending record
    const existingOTP = await UserOTPVerification.findOne({ email }).lean();
    if (!existingOTP) {
      return res.status(400).json({ status: 'FAILED', message: 'No pending verification found' });
    }

    // Copy data trước khi xóa old records
    const tempData = {
      name: existingOTP.name,
      password: existingOTP.password,
      birthday: existingOTP.birthday,
      phone: existingOTP.phone,
      address: existingOTP.address
    };

    // Xóa old OTP records
    await UserOTPVerification.deleteMany({ email });

    // Gửi new OTP
    const { hashedOTP, expiresAt } = await sendOTPVerificationEmail(email);

    // Tạo new OTP record với data cũ
    const newOtpVerification = new UserOTPVerification({
      email,
      ...tempData,  // Spread để copy fields
      otp: hashedOTP,
      expiresAt
    });
    await newOtpVerification.save();

    res.json({ status: 'SUCCESS', message: 'New OTP sent to email' });
  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ status: 'FAILED', message: 'Internal server error' });
  }
});

module.exports = router;
