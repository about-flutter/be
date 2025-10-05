const sgMail = require('@sendgrid/mail');
const bcrypt = require('bcryptjs');
require('dotenv').config();

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// OTP 4 số
const generateOTP = () => Math.floor(1000 + Math.random() * 9000).toString();

const sendOTPVerificationEmail = async (email) => {  // 👈 SỬA: Bỏ userId param (không dùng trong flow mới)
  try {
    // Debug: Log env để confirm
    if (!process.env.SENDER_EMAIL) {
      throw new Error('SENDER_EMAIL env var is missing');
    }
    console.log('Sender email loaded:', process.env.SENDER_EMAIL);

    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    const msg = {
      to: email,
      from: { 
        email: process.env.SENDER_EMAIL,  // Đảm bảo object với 'email' required
        name: 'Outfity App'  // 👈 SỬA: Đổi tên app cho phù hợp
      },
      subject: 'Verify Your Email',
      html: `
        <p>Enter <b>${otp}</b> in the app to verify your email address and complete signup.</p>
        <p>This code expires in ${process.env.OTP_EXPIRY || 10} minutes.</p>
      `,
    };

    await sgMail.send(msg);
    console.log(`OTP sent to ${email} via SendGrid`);
    const expiryMinutes = parseInt(process.env.OTP_EXPIRY) || 10;
    return { hashedOTP, expiresAt: new Date(Date.now() + expiryMinutes * 60 * 1000) };
  } catch (error) {
    console.error('SendGrid full error:', {
      message: error.message,
      response: error.response ? error.response.body : 'No response'
    });
    throw new Error('Failed to send OTP');
  }
};

module.exports = { sendOTPVerificationEmail, generateOTP };
