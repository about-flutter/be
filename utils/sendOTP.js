const sgMail = require('@sendgrid/mail');
const bcrypt = require('bcryptjs');
require('dotenv').config();

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Generate OTP 4 chữ số
const generateOTP = () => Math.floor(1000 + Math.random() * 9000).toString();

const sendOTPVerificationEmail = async (email) => {
  try {
    // Check env vars
    if (!process.env.SENDGRID_API_KEY || !process.env.SENDER_EMAIL) {
      throw new Error('Missing SENDGRID_API_KEY or SENDER_EMAIL env vars');
    }
    console.log('Sender email loaded:', process.env.SENDER_EMAIL);

    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    const msg = {
      to: email,
      from: { 
        email: process.env.SENDER_EMAIL,
        name: 'Outfity App'  // Tên app
      },
      subject: 'Verify Your Email',
      html: `
        <p>Enter <b>${otp}</b> in the app to verify your email address and complete signup.</p>
        <p>This code expires in ${process.env.OTP_EXPIRY || 10} minutes.</p>
      `,
    };

    await sgMail.send(msg);
    console.log(`OTP sent to ${email} via SendGrid`);

    // Fallback expiry nếu env không set
    const expiryMinutes = parseInt(process.env.OTP_EXPIRY) || 10;
    const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);
    return { hashedOTP, expiresAt };
  } catch (error) {
    console.error('SendGrid error:', {
      message: error.message,
      code: error.code,
      response: error.response ? error.response.body : 'No response'
    });
    throw new Error('Failed to send OTP email');
  }
};

module.exports = { sendOTPVerificationEmail, generateOTP };
