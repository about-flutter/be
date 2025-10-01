const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Transporter config (explicit SMTP để fix timeout trên Render)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  requireTLS: true,
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,  // App Password
  },
  connectionTimeout: 10000,
  greetingTimeout: 5000,
  socketTimeout: 5000,
});

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();  // 6 digits

const sendOTPVerificationEmail = async (userId, email) => {
  try {
    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'Verify Your Email',
      html: `
        <p>Enter <b>${otp}</b> in the app to verify your email address and complete signup.</p>
        <p>This code expires in 1 hour.</p>
      `,
    };
console.log('Attempting to send to:', email);
console.log('Gmail user:', process.env.GMAIL_USER ? 'Set' : 'Missing');
console.log('Gmail pass:', process.env.GMAIL_PASS ? 'Set' : 'Missing');
    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}`);
    return { hashedOTP, expiresAt: new Date(Date.now() + 60 * 60 * 1000) };  // 1h expiry
  } catch (error) {
    console.error('Error sending OTP:', error);
    throw new Error('Failed to send OTP');
  }
};

module.exports = { sendOTPVerificationEmail, generateOTP };