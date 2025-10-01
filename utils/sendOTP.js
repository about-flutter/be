const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const transporter = nodemailer.createTransporter({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
};

const sendOTP = async (email, otp) => {
  try {
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'Your OTP for Verification',
      text: `Your One-Time Password is: ${otp}. It expires in ${process.env.OTP_EXPIRY || 10} minutes.`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}`);
  } catch (error) {
    console.error('Error sending OTP:', error);
    throw new Error('Failed to send OTP');
  }
};

const hashAndStoreOTP = async (user, otp) => {
  const salt = await bcrypt.genSalt(10);
  user.otp = await bcrypt.hash(otp, salt);
  user.otpExpiry = new Date(Date.now() + (process.env.OTP_EXPIRY || 10) * 60 * 1000);
  await user.save();
};

module.exports = { generateOTP, sendOTP, hashAndStoreOTP };
