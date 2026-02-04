/**
 * Quantum Finance Engine - Security Utilities
 */
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

export class SecurityUtils {
  // Generate cryptographically secure random string
  static generateToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  // Generate numeric PIN
  static generatePin(length: number = 6): string {
    const min = Math.pow(10, length - 1);
    const max = Math.pow(10, length) - 1;
    return crypto.randomInt(min, max).toString();
  }

  // Hash password with bcrypt
  static async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(12);
    return await bcrypt.hash(password, salt);
  }

  // Verify password
  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(password, hash);
  }

  // Hash PIN (simpler hash for faster verification)
  static async hashPin(pin: string): Promise<string> {
    const salt = await bcrypt.genSalt(6);
    return await bcrypt.hash(pin, salt);
  }

  // Verify PIN
  static async verifyPin(pin: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(pin, hash);
  }

  // Generate device ID
  static generateDeviceId(): string {
    return `DEV-${crypto.randomBytes(16).toString('hex')}`;
  }

  // Generate session ID
  static generateSessionId(): string {
    return `SESS-${crypto.randomBytes(24).toString('hex')}`;
  }

  // Encrypt sensitive data (for PII)
  static encrypt(text: string, key: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
  }

  // Decrypt sensitive data
  static decrypt(encryptedText: string, key: string): string {
    const [ivHex, encrypted, authTagHex] = encryptedText.split(':');

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  // Generate password reset token
  static generatePasswordResetToken(): { token: string; expiresAt: Date } {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000); // 1 hour

    return { token, expiresAt };
  }

  // Generate email verification token
  static generateEmailVerificationToken(): { token: string; expiresAt: Date } {
    const token = crypto.randomBytes(20).toString('hex');
    const expiresAt = new Date(Date.now() + 86400000); // 24 hours

    return { token, expiresAt };
  }

  // Check password strength
  static checkPasswordStrength(password: string): {
    score: number;
    strength: 'weak' | 'fair' | 'good' | 'strong' | 'excellent';
    feedback: string[];
  } {
    const feedback: string[] = [];
    let score = 0;

    // Length check
    if (password.length >= 12) score += 2;
    else if (password.length >= 8) score += 1;
    else feedback.push('Password should be at least 8 characters');

    // Character variety checks
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Add lowercase letters');

    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Add uppercase letters');

    if (/\d/.test(password)) score += 1;
    else feedback.push('Add numbers');

    if (/[@$!%*?&]/.test(password)) score += 1;
    else feedback.push('Add special characters (@$!%*?&)');

    // Common pattern checks
    const commonPatterns = [
      '123456', 'password', 'qwerty', 'admin', 'welcome',
      new Date().getFullYear().toString(),
    ];

    if (commonPatterns.some(pattern => password.toLowerCase().includes(pattern))) {
      score -= 1;
      feedback.push('Avoid common patterns and current year');
    }

    // Determine strength
    let strength: 'weak' | 'fair' | 'good' | 'strong' | 'excellent';
    if (score >= 5) strength = 'excellent';
    else if (score >= 4) strength = 'strong';
    else if (score >= 3) strength = 'good';
    else if (score >= 2) strength = 'fair';
    else strength = 'weak';

    return { score, strength, feedback };
  }

  // Validate phone number format
  static validatePhoneNumber(phone: string): boolean {
    const pattern = /^\+?[1-9]\d{1,14}$/;
    return pattern.test(phone.replace(/\s/g, ''));
  }

  // Validate email format
  static validateEmail(email: string): boolean {
    const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return pattern.test(email.toLowerCase());
  }

  // Sanitize input for SQL injection prevention
  static sanitizeInput(input: string): string {
    return input
      .replace(/[<>"'`;]/g, '')
      .trim()
      .substring(0, 1000);
  }

  // Generate audit trail hash
  static generateAuditHash(data: any): string {
    const stringified = JSON.stringify(data, Object.keys(data).sort());
    return crypto.createHash('sha256').update(stringified).digest('hex');
  }
}
