const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { generateOTP, sendOTP, hashAndStoreOTP } = require('../utils/sendOTP');
require('dotenv').config();

// Register - Send OTP instead of immediate token
router.post('/register', async (req, res) => {
  const { name, email, password, phone, birthday } = req.body; // Fixed: Destructure all fields
  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: 'User already exists' });

    user = new User({ name, email, password, phone, birthday });
    await user.save();

    // Generate and send OTP
    const otp = generateOTP();
    await hashAndStoreOTP(user, otp);
    await sendOTP(email, otp);

    res.status(201).json({ message: 'User registered. Check your email for OTP.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// New: Verify OTP and issue token
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isValidOTP = await user.matchOTP(otp);
    if (!isValidOTP) return res.status(400).json({ message: 'Invalid or expired OTP' });

    // Clear OTP fields
    user.otp = undefined;
    user.otpExpiry = undefined;
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

// Login - Now checks isVerified
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
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

module.exports = router;
