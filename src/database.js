import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, '../data');
const DB_FILE = path.join(DATA_DIR, 'matdar_db.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Initial seed users
const getInitialSeedUsers = () => {
  const salt = bcrypt.genSaltSync(10);
  const now = new Date().toISOString();

  return [
    {
      id: 'usr_ram_kadam',
      username: 'Ram Kadam',
      displayName: 'Ram Kadam',
      email: 'chinmayarane491@gmail.com',
      password_hash: bcrypt.hashSync('RamKadam@12344', salt),
      role: 'admin',
      is_first_password_completed: true,
      created_at: now,
      updated_at: now
    },
    {
      id: 'usr_admin',
      username: 'admin',
      displayName: 'प्रशासक (Admin)',
      email: 'admin@matdar.gov.in',
      password_hash: bcrypt.hashSync('admin123', salt),
      role: 'admin',
      is_first_password_completed: true,
      created_at: now,
      updated_at: now
    },
    {
      id: 'usr_new_operator',
      username: 'operator',
      displayName: 'नवीन ऑपरेटर (Operator)',
      email: 'operator@matdar.gov.in',
      password_hash: null,
      role: 'operator',
      is_first_password_completed: false, // For testing First Password Setup!
      created_at: now,
      updated_at: now
    }
  ];
};

class MatdarDatabase {
  constructor() {
    this.data = this.loadDatabase();
  }

  loadDatabase() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed.users && parsed.otps) {
          return parsed;
        }
      }
    } catch (e) {
      console.warn('Failed to load existing matdar_db.json, re-initializing database:', e);
    }

    const initialDb = {
      users: getInitialSeedUsers(),
      otps: [],
      audit_logs: []
    };
    this.persist(initialDb);
    return initialDb;
  }

  persist(dataToSave = this.data) {
    try {
      const tempFile = `${DB_FILE}.tmp`;
      fs.writeFileSync(tempFile, JSON.stringify(dataToSave, null, 2), 'utf-8');
      fs.renameSync(tempFile, DB_FILE);
    } catch (e) {
      console.error('Database write error:', e);
    }
  }

  // User operations
  findUserByEmail(email) {
    const clean = email.trim().toLowerCase();
    return this.data.users.find(u => u.email.toLowerCase() === clean) || null;
  }

  findUserById(id) {
    return this.data.users.find(u => u.id === id) || null;
  }

  findUserByUsername(username) {
    const clean = username.trim().toLowerCase();
    return this.data.users.find(u => u.username.toLowerCase() === clean) || null;
  }

  updateUserPassword(userId, newPasswordHash, isFirstSetup = false) {
    const user = this.findUserById(userId);
    if (!user) return false;

    user.password_hash = newPasswordHash;
    user.updated_at = new Date().toISOString();
    if (isFirstSetup) {
      user.is_first_password_completed = true;
    }
    this.persist();
    return true;
  }

  // OTP Table Operations (Matching Section 9)
  invalidatePreviousOtps(email, purpose) {
    const clean = email.trim().toLowerCase();
    const now = Date.now();
    this.data.otps.forEach(record => {
      if (record.email.toLowerCase() === clean && record.purpose === purpose && !record.used_at) {
        record.expires_at = now - 1000;
      }
    });
    this.persist();
  }

  saveOtp(record) {
    this.invalidatePreviousOtps(record.email, record.purpose);
    this.data.otps.push(record);
    if (this.data.otps.length > 200) {
      this.data.otps = this.data.otps.slice(-200);
    }
    this.persist();
  }

  findActiveOtp(email, purpose) {
    const clean = email.trim().toLowerCase();
    const now = Date.now();
    const matches = this.data.otps
      .filter(o => o.email.toLowerCase() === clean && o.purpose === purpose && !o.used_at && o.expires_at > now)
      .sort((a, b) => b.expires_at - a.expires_at);

    return matches.length > 0 ? matches[0] : null;
  }

  findOtpByResetToken(tokenHash, purpose) {
    const now = Date.now();
    return this.data.otps.find(o => 
      o.reset_token_hash === tokenHash && 
      o.purpose === purpose && 
      !o.used_at && 
      o.token_expires_at && 
      o.token_expires_at > now
    ) || null;
  }

  incrementOtpAttempts(otpId) {
    const otp = this.data.otps.find(o => o.id === otpId);
    if (!otp) return 0;
    otp.attempts = (otp.attempts || 0) + 1;
    this.persist();
    return otp.attempts;
  }

  markOtpVerified(otpId, resetTokenHash, tokenExpiresAt) {
    const otp = this.data.otps.find(o => o.id === otpId);
    if (!otp) return;
    otp.verified_at = new Date().toISOString();
    otp.reset_token_hash = resetTokenHash;
    otp.token_expires_at = tokenExpiresAt;
    this.persist();
  }

  markOtpUsed(otpId) {
    const otp = this.data.otps.find(o => o.id === otpId);
    if (!otp) return;
    otp.used_at = new Date().toISOString();
    otp.reset_token_hash = null;
    this.persist();
  }

  logAudit(username, action, message) {
    this.data.audit_logs.unshift({
      id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      username,
      action,
      message
    });
    if (this.data.audit_logs.length > 100) {
      this.data.audit_logs = this.data.audit_logs.slice(0, 100);
    }
    this.persist();
  }
}

export const db = new MatdarDatabase();
