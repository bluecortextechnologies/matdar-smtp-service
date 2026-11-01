import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

// Create Nodemailer Transporter
export const createTransporter = () => {
  const host = process.env.SMTP_HOST || 'smtp.gmail.com';
  const port = parseInt(process.env.SMTP_PORT || '587', 10);
  const secure = process.env.SMTP_SECURE === 'true';
  const user = process.env.SMTP_USER || '';
  const pass = process.env.SMTP_PASS || '';

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: {
      user,
      pass
    },
    tls: {
      rejectUnauthorized: false
    }
  });
};

/**
 * Send OTP Email via SMTP matching Section 7 specifications
 */
export const sendOtpEmail = async ({
  to,
  otp,
  purpose = 'FORGOT_PASSWORD',
  targetType = 'FIRST_PASSWORD'
}) => {
  const transporter = createTransporter();
  const fromName = process.env.SMTP_FROM_NAME || 'MATDAR';
  const fromEmail = process.env.SMTP_FROM_EMAIL || process.env.SMTP_USER || 'no-reply@matdar.gov.in';

  const isSecondPassword = targetType === 'SECOND_PASSWORD';
  const passwordLabel = isSecondPassword
    ? 'Second Password (द्वितीय सुरक्षा पासवर्ड)'
    : 'First Password (प्राथमिक पासवर्ड)';

  const subject = isSecondPassword
    ? 'Your MATDAR Second Password Reset OTP'
    : 'Your MATDAR First Password Reset OTP';

  const actionText = `We received a request to reset your MATDAR ${passwordLabel}.`;

  // Section 7 Email HTML Layout
  const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subject}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 0;
      background-color: #f8fafc;
      color: #1e293b;
    }
    .email-container {
      max-width: 540px;
      margin: 24px auto;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
    }
    .header {
      background: #0284c7;
      padding: 24px;
      text-align: center;
    }
    .brand-name {
      color: #ffffff;
      font-size: 24px;
      font-weight: 800;
      letter-spacing: 2px;
      margin: 0;
    }
    .brand-sub {
      color: #e0f2fe;
      font-size: 13px;
      margin: 4px 0 0;
    }
    .content {
      padding: 32px 24px;
      line-height: 1.6;
    }
    .greeting {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 12px;
    }
    .otp-box {
      background: #f0f9ff;
      border: 1.5px dashed #0284c7;
      border-radius: 10px;
      padding: 20px;
      text-align: center;
      margin: 28px 0;
    }
    .otp-label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #0369a1;
      font-weight: 700;
      display: block;
      margin-bottom: 6px;
    }
    .otp-code {
      font-size: 36px;
      font-weight: 800;
      color: #0284c7;
      letter-spacing: 8px;
      font-family: monospace, Courier, sans-serif;
      display: inline-block;
    }
    .validity-note {
      font-size: 14px;
      color: #475569;
      margin-top: 16px;
    }
    .footer {
      border-top: 1px solid #f1f5f9;
      padding: 20px 24px;
      text-align: left;
      font-size: 13px;
      color: #64748b;
    }
  </style>
</head>
<body>
  <div class="email-container">
    <div class="header">
      <h1 class="brand-name">${fromName}</h1>
      <p class="brand-sub">Voting Management System • Secure Identity Service</p>
    </div>
    <div class="content">
      <div class="greeting">Hello,</div>
      <p>${actionText}</p>
      
      <div class="otp-box">
        <span class="otp-label">Your OTP verification code is:</span>
        <span class="otp-code">${otp}</span>
      </div>

      <p class="validity-note">
        <strong>This OTP is valid for 5 minutes.</strong>
      </p>

      <p style="color: #64748b; font-size: 13px; margin-top: 24px;">
        If you did not request this password reset, please ignore this email.
      </p>

      <p style="margin-top: 28px; font-size: 14px;">
        Regards,<br>
        <strong>${fromName} Support Team</strong>
      </p>
    </div>
    <div class="footer">
      This is an automated security notification. Please do not reply directly to this email.
    </div>
  </div>
</body>
</html>
  `;

  const textContent = `Hello,

${actionText}

Your OTP verification code is:
${otp}

This OTP is valid for 5 minutes.

If you did not request this password reset, please ignore this email.

Regards,
${fromName} Support Team`;

  const mailOptions = {
    from: `"${fromName}" <${fromEmail}>`,
    to,
    subject,
    text: textContent,
    html: htmlContent
  };

  const info = await transporter.sendMail(mailOptions);
  return info;
};

/**
 * Verify SMTP connection test helper
 */
export const testSmtpConnection = async () => {
  const transporter = createTransporter();
  return transporter.verify();
};

