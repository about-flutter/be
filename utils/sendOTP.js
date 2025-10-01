const sgMail = require('@sendgrid/mail');
const bcrypt = require('bcryptjs');
require('dotenv').config();

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();  // 6 digits

const sendOTPVerificationEmail = async (userId, email) => {
  try {
    const otp = generateOTP();
    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(otp, salt);

    const msg = {
      to: email,
      from: { 
        email: process.env.SENDER_EMAIL,  // Sửa: Object với 'email' required
        name: 'Ecommerce App'  // Optional: Tên sender để email chuyên nghiệp hơn
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
    console.error('SendGrid error:', error.response ? error.response.body : error.message);
    throw new Error('Failed to send OTP');
  }
};

module.exports = { sendOTPVerificationEmail, generateOTP };