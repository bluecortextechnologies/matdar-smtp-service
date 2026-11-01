import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { db } from './database.js';
import { sendOtpEmail, testSmtpConnection } from './mailer.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Helper: Secure SHA-256 hash
const hashToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

// Helper: Generate secure 6-digit OTP
const generateSecureOtp = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// Helper: Generate secure random token
const generateRandomToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// ============================================================================
// 1. HEALTH & SMTP DIAGNOSTICS
// ============================================================================
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    service: 'MATDAR Auth & SMTP Service',
    timestamp: new Date().toISOString()
  });
});

app.post('/api/auth/verify-smtp', async (req, res) => {
  try {
    await testSmtpConnection();
    res.json({
      success: true,
      message: 'SMTP connection established successfully.'
    });
  } catch (err) {
    console.error('SMTP test error:', err);
    res.status(500).json({
      success: false,
      error: `SMTP प्रमाणीकरण त्रुटी: ${err.message || 'Connection failed'}. (कृपया .env फाईलमध्ये Gmail App Password तपासा)`
    });
  }
});

// ============================================================================
// 2. FORGOT PASSWORD FLOW
// ============================================================================

/**
 * Step 1: Send OTP for Forgot Password
 */
app.post('/api/auth/forgot-password/send-otp', async (req, res) => {
  const { email, target_type = 'FIRST_PASSWORD' } = req.body;

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({
      success: false,
      error: 'कृपया वैध ईमेल पत्ता प्रविष्ट करा.'
    });
  }

  const cleanEmail = email.trim().toLowerCase();
  const user = db.findUserByEmail(cleanEmail);

  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'हा ईमेल पत्ता नोंदणीकृत नाही. कृपया अधिकृत ईमेल प्रविष्ट करा.'
    });
  }

  // Check 60-second resend cooldown
  const activeOtp = db.findActiveOtp(cleanEmail, 'FORGOT_PASSWORD');
  const now = Date.now();
  if (activeOtp) {
    const elapsedSeconds = Math.floor((now - new Date(activeOtp.created_at).getTime()) / 1000);
    if (elapsedSeconds < 60) {
      const waitTime = 60 - elapsedSeconds;
      return res.status(429).json({
        success: false,
        cooldownRemaining: waitTime,
        error: `पुन्हा OTP मागवण्यासाठी कृपया ${waitTime} सेकंद प्रतीक्षा करा.`
      });
    }
  }

  // Generate 6-digit OTP
  const rawOtp = generateSecureOtp();
  const salt = bcrypt.genSaltSync(10);
  const otpHash = bcrypt.hashSync(rawOtp, salt);

  const otpRecord = {
    id: `otp_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    user_id: user.id,
    email: cleanEmail,
    otp_hash: otpHash,
    purpose: 'FORGOT_PASSWORD',
    target_type: target_type === 'SECOND_PASSWORD' ? 'SECOND_PASSWORD' : 'FIRST_PASSWORD',
    expires_at: now + 5 * 60 * 1000, // 5 minutes validity
    attempts: 0,
    max_attempts: 5,
    verified_at: null,
    used_at: null,
    reset_token_hash: null,
    token_expires_at: null,
    created_at: new Date().toISOString()
  };

  // Save to DB (invalidates previous OTPs for this email automatically)
  db.saveOtp(otpRecord);

  // Send Email via Nodemailer SMTP
  try {
    await sendOtpEmail({
      to: cleanEmail,
      otp: rawOtp,
      purpose: 'FORGOT_PASSWORD',
      targetType: otpRecord.target_type
    });

    db.logAudit(user.username, 'FORGOT_PASSWORD_OTP_SENT', `OTP sent to ${cleanEmail} for ${otpRecord.target_type}`);

    const label = otpRecord.target_type === 'SECOND_PASSWORD' ? 'द्वितीय सुरक्षा पासवर्ड' : '१ ला प्राथमिक पासवर्ड';
    return res.json({
      success: true,
      message: `${label} रीसेट करण्यासाठी ६-अंकी OTP आपल्या ईमेलवर पाठवला आहे.`,
      target_type: otpRecord.target_type,
      cooldown: 60,
      expiresIn: 300
    });
  } catch (err) {
    console.error('SMTP Delivery Error:', err);
    return res.status(500).json({
      success: false,
      error: `ईमेल पाठवता आला नाही: ${err.message || 'SMTP Server Error'}. कृपया .env मधील SMTP क्रेडेन्शियल्स तपासा.`
    });
  }
});

/**
 * Step 2: Verify OTP for Forgot Password
 */
app.post('/api/auth/forgot-password/verify-otp', async (req, res) => {
  const { email, otp, target_type = 'FIRST_PASSWORD' } = req.body;

  if (!email || !otp) {
    return res.status(400).json({
      success: false,
      error: 'ईमेल आणि ६-अंकी OTP दोन्ही आवश्यक आहेत.'
    });
  }

  const cleanEmail = email.trim().toLowerCase();
  const activeOtp = db.findActiveOtp(cleanEmail, 'FORGOT_PASSWORD');

  if (!activeOtp) {
    return res.status(400).json({
      success: false,
      error: 'कोणताही सक्रिय OTP आढळला नाही किंवा OTP कालबाह्य झाला आहे. कृपया नवीन OTP मागवा.'
    });
  }

  // Ensure OTP target matches (First vs Second)
  if (activeOtp.target_type && activeOtp.target_type !== target_type) {
    return res.status(400).json({
      success: false,
      error: 'अवैध पासवर्ड प्रकार. OTP आणि निवडलेला पासवर्ड प्रकार जुळत नाही.'
    });
  }

  // Check 5 maximum incorrect attempts
  if (activeOtp.attempts >= activeOtp.max_attempts) {
    db.invalidatePreviousOtps(cleanEmail, 'FORGOT_PASSWORD');
    return res.status(403).json({
      success: false,
      error: '५ पेक्षा जास्त चुकीचे प्रयत्न झाले. सुरक्षिततेसाठी हा OTP रद्द करण्यात आला आहे. कृपया नवीन OTP मागवा.'
    });
  }

  // Compare OTP hash
  const isValid = bcrypt.compareSync(otp.trim(), activeOtp.otp_hash);

  if (!isValid) {
    const totalAttempts = db.incrementOtpAttempts(activeOtp.id);
    const remaining = Math.max(0, activeOtp.max_attempts - totalAttempts);

    if (remaining === 0) {
      db.invalidatePreviousOtps(cleanEmail, 'FORGOT_PASSWORD');
      return res.status(403).json({
        success: false,
        remainingAttempts: 0,
        error: 'अवैध OTP! सर्व ५ प्रयत्न संपले आहेत. कृपया नवीन OTP मागवा.'
      });
    }

    return res.status(400).json({
      success: false,
      remainingAttempts: remaining,
      error: `चुकीचा OTP! आपल्याकडे फक्त ${remaining} प्रयत्न शिल्लक आहेत.`
    });
  }

  // Generate single-use reset token
  const resetToken = generateRandomToken();
  const resetTokenHash = hashToken(resetToken);
  const tokenExpiresAt = Date.now() + 5 * 60 * 1000; // 5 mins to enter new password

  db.markOtpVerified(activeOtp.id, resetTokenHash, tokenExpiresAt);
  db.logAudit(cleanEmail, 'FORGOT_PASSWORD_OTP_VERIFIED', 'OTP successfully verified.');

  return res.json({
    success: true,
    reset_token: resetToken,
    target_type: activeOtp.target_type || target_type,
    message: 'OTP पडताळणी यशस्वी झाली.'
  });
});

/**
 * Step 3: Update Password with verified single-use reset token
 */
app.post('/api/auth/forgot-password/reset', async (req, res) => {
  const { reset_token, new_password, confirm_password, target_type = 'FIRST_PASSWORD' } = req.body;

  if (!reset_token || !new_password || !confirm_password) {
    return res.status(400).json({
      success: false,
      error: 'सर्व फील्ड्स आवश्यक आहेत.'
    });
  }

  if (new_password !== confirm_password) {
    return res.status(400).json({
      success: false,
      error: 'दोन्ही पासवर्ड जुळत नाहीत.'
    });
  }

  if (new_password.length < 6) {
    return res.status(400).json({
      success: false,
      error: 'पासवर्ड किमान ६ वर्णांचा असावा.'
    });
  }

  // Find verified OTP record by token hash
  const tokenHash = hashToken(reset_token);
  const otpRecord = db.findOtpByResetToken(tokenHash, 'FORGOT_PASSWORD');

  if (!otpRecord) {
    return res.status(403).json({
      success: false,
      error: 'पासवर्ड रीसेट सत्र कालबाह्य झाले आहे किंवा अवैध आहे. कृपया पुन्हा OTP पडताळणी करा.'
    });
  }

  // Ensure target matches
  if (otpRecord.target_type && otpRecord.target_type !== target_type) {
    return res.status(403).json({
      success: false,
      error: 'सुरक्षा मर्यादा: एका पासवर्डचा OTP दुसरा पासवर्ड रीसेट करू शकत नाही.'
    });
  }

  // Hash new password using bcrypt
  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync(new_password.trim(), salt);

  // Update password in database
  const updated = db.updateUserPassword(otpRecord.user_id, passwordHash);
  if (!updated) {
    return res.status(500).json({
      success: false,
      error: 'डेटाबेसमध्ये पासवर्ड अपडेट करताना त्रुटी आली.'
    });
  }

  // Mark OTP used (invalidates reset token immediately)
  db.markOtpUsed(otpRecord.id);
  db.logAudit(otpRecord.email, 'PASSWORD_RESET_SUCCESS', `Password updated successfully for ${otpRecord.target_type || target_type}`);

  const label = (otpRecord.target_type || target_type) === 'SECOND_PASSWORD' ? 'द्वितीय सुरक्षा पासवर्ड' : '१ ला प्राथमिक पासवर्ड';
  return res.json({
    success: true,
    target_type: otpRecord.target_type || target_type,
    message: `${label} यशस्वीरित्या बदलला आहे. नवीन पासवर्ड वापरून लॉगिन करा.`
  });
});

// ============================================================================
// 3. FIRST PASSWORD SETUP FLOW (SECTION 5)
// ============================================================================

/**
 * Step 1: Send OTP for First Password Setup
 */
app.post('/api/auth/first-password/send-otp', async (req, res) => {
  const { email } = req.body;

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({
      success: false,
      error: 'कृपया वैध ईमेल पत्ता प्रविष्ट करा.'
    });
  }

  const cleanEmail = email.trim().toLowerCase();
  const user = db.findUserByEmail(cleanEmail);

  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'हा ईमेल पत्ता प्रणालीमध्ये नोंदणीकृत नाही.'
    });
  }

  // Check if user has already completed first password setup
  if (user.is_first_password_completed) {
    return res.status(400).json({
      success: false,
      error: 'प्रथम पासवर्ड आधीच सेट केलेला आहे! कृपया पासवर्ड रीसेट करण्यासाठी "Forgot Password" पर्याय वापरा.'
    });
  }

  // Check 60-second cooldown
  const activeOtp = db.findActiveOtp(cleanEmail, 'FIRST_PASSWORD');
  const now = Date.now();
  if (activeOtp) {
    const elapsedSeconds = Math.floor((now - new Date(activeOtp.created_at).getTime()) / 1000);
    if (elapsedSeconds < 60) {
      const waitTime = 60 - elapsedSeconds;
      return res.status(429).json({
        success: false,
        cooldownRemaining: waitTime,
        error: `पुन्हा OTP मागवण्यासाठी कृपया ${waitTime} सेकंद प्रतीक्षा करा.`
      });
    }
  }

  // Generate 6-digit OTP
  const rawOtp = generateSecureOtp();
  const salt = bcrypt.genSaltSync(10);
  const otpHash = bcrypt.hashSync(rawOtp, salt);

  const otpRecord = {
    id: `otp_first_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    user_id: user.id,
    email: cleanEmail,
    otp_hash: otpHash,
    purpose: 'FIRST_PASSWORD',
    expires_at: now + 5 * 60 * 1000,
    attempts: 0,
    max_attempts: 5,
    verified_at: null,
    used_at: null,
    reset_token_hash: null,
    token_expires_at: null,
    created_at: new Date().toISOString()
  };

  db.saveOtp(otpRecord);

  try {
    await sendOtpEmail({
      to: cleanEmail,
      otp: rawOtp,
      purpose: 'FIRST_PASSWORD'
    });

    db.logAudit(user.username, 'FIRST_PASSWORD_OTP_SENT', `First password OTP sent to ${cleanEmail}`);

    return res.json({
      success: true,
      message: 'प्रथम पासवर्ड सेट करण्यासाठी ६-अंकी OTP पाठवला आहे.',
      cooldown: 60,
      expiresIn: 300
    });
  } catch (err) {
    console.error('SMTP Delivery Error:', err);
    return res.status(500).json({
      success: false,
      error: `ईमेल पाठवता आला नाही: ${err.message || 'SMTP Server Error'}.`
    });
  }
});

/**
 * Step 2: Verify OTP for First Password Setup
 */
app.post('/api/auth/first-password/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({
      success: false,
      error: 'ईमेल आणि OTP दोन्ही आवश्यक आहेत.'
    });
  }

  const cleanEmail = email.trim().toLowerCase();
  const activeOtp = db.findActiveOtp(cleanEmail, 'FIRST_PASSWORD');

  if (!activeOtp) {
    return res.status(400).json({
      success: false,
      error: 'कोणताही सक्रिय OTP आढळला नाही किंवा तो कालबाह्य झाला आहे.'
    });
  }

  if (activeOtp.attempts >= activeOtp.max_attempts) {
    db.invalidatePreviousOtps(cleanEmail, 'FIRST_PASSWORD');
    return res.status(403).json({
      success: false,
      error: '५ पेक्षा जास्त चुकीचे प्रयत्न झाले. सुरक्षिततेसाठी हा OTP रद्द केला आहे.'
    });
  }

  const isValid = bcrypt.compareSync(otp.trim(), activeOtp.otp_hash);

  if (!isValid) {
    const totalAttempts = db.incrementOtpAttempts(activeOtp.id);
    const remaining = Math.max(0, activeOtp.max_attempts - totalAttempts);

    if (remaining === 0) {
      db.invalidatePreviousOtps(cleanEmail, 'FIRST_PASSWORD');
      return res.status(403).json({
        success: false,
        remainingAttempts: 0,
        error: 'अवैध OTP! सर्व प्रयत्न संपले आहेत.'
      });
    }

    return res.status(400).json({
      success: false,
      remainingAttempts: remaining,
      error: `चुकीचा OTP! आपल्याकडे फक्त ${remaining} प्रयत्न शिल्लक आहेत.`
    });
  }

  const resetToken = generateRandomToken();
  const resetTokenHash = hashToken(resetToken);
  const tokenExpiresAt = Date.now() + 5 * 60 * 1000;

  db.markOtpVerified(activeOtp.id, resetTokenHash, tokenExpiresAt);
  db.logAudit(cleanEmail, 'FIRST_PASSWORD_OTP_VERIFIED', 'First password OTP verified.');

  return res.json({
    success: true,
    reset_token: resetToken,
    message: 'OTP पडताळणी यशस्वी.'
  });
});

/**
 * Step 3: Complete First Password Setup
 */
app.post('/api/auth/first-password/set', async (req, res) => {
  const { reset_token, new_password, confirm_password } = req.body;

  if (!reset_token || !new_password || !confirm_password) {
    return res.status(400).json({
      success: false,
      error: 'सर्व फील्ड्स आवश्यक आहेत.'
    });
  }

  if (new_password !== confirm_password) {
    return res.status(400).json({
      success: false,
      error: 'दोन्ही पासवर्ड जुळत नाहीत.'
    });
  }

  if (new_password.length < 6) {
    return res.status(400).json({
      success: false,
      error: 'पासवर्ड किमान ६ वर्णांचा असावा.'
    });
  }

  const tokenHash = hashToken(reset_token);
  const otpRecord = db.findOtpByResetToken(tokenHash, 'FIRST_PASSWORD');

  if (!otpRecord) {
    return res.status(403).json({
      success: false,
      error: 'सत्र कालबाह्य झाले आहे. कृपया पुन्हा सुरू करा.'
    });
  }

  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync(new_password.trim(), salt);

  // Update password and mark first password setup as completed
  const updated = db.updateUserPassword(otpRecord.user_id, passwordHash, true);
  if (!updated) {
    return res.status(500).json({
      success: false,
      error: 'डेटाबेस अपडेट करताना त्रुटी आली.'
    });
  }

  db.markOtpUsed(otpRecord.id);
  db.logAudit(otpRecord.email, 'FIRST_PASSWORD_SET_SUCCESS', 'First password setup completed successfully.');

  return res.json({
    success: true,
    message: 'प्रथम पासवर्ड यशस्वीरित्या सेट केला आहे! आता आपण लॉगिन करू शकता.'
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`MATDAR Auth & SMTP Server running on port ${PORT}`);
  console.log(`Health Check: http://localhost:${PORT}/api/health`);
  console.log(`====================================================`);
});

