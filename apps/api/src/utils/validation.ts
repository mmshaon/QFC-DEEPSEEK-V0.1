/**
 * Quantum Finance Engine - Validation Utilities
 */
import { ValidationError } from './errors';

// Validation patterns
export const VALIDATION_PATTERNS = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  PHONE: /^\+?[1-9]\d{1,14}$/, // E.164 format
  PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/,
  PIN: /^\d{6}$/,
  ID_NUMBER: /^[A-Za-z0-9\-]{5,20}$/,
  CURRENCY: /^\d+(\.\d{1,2})?$/,
  PERCENTAGE: /^(100(\.0{1,2})?|\d{1,2}(\.\d{1,2})?)$/,
};

// Validation rules
export const VALIDATION_RULES = {
  USER: {
    email: {
      required: true,
      pattern: VALIDATION_PATTERNS.EMAIL,
      maxLength: 255,
    },
    password: {
      required: true,
      pattern: VALIDATION_PATTERNS.PASSWORD,
      minLength: 12,
      maxLength: 100,
    },
    fullName: {
      required: true,
      minLength: 2,
      maxLength: 100,
    },
    phone: {
      required: true,
      pattern: VALIDATION_PATTERNS.PHONE,
    },
    address: {
      required: true,
      minLength: 5,
      maxLength: 500,
    },
    idNumber: {
      required: true,
      pattern: VALIDATION_ID_NUMBER,
      maxLength: 20,
    },
    emergencyContactPhone: {
      required: true,
      pattern: VALIDATION_PATTERNS.PHONE,
    },
  },

  COMPANY: {
    name: {
      required: true,
      minLength: 2,
      maxLength: 200,
    },
    taxId: {
      required: false,
      minLength: 5,
      maxLength: 50,
    },
    address: {
      required: true,
      minLength: 5,
      maxLength: 500,
    },
    phone: {
      required: true,
      pattern: VALIDATION_PATTERNS.PHONE,
    },
    email: {
      required: true,
      pattern: VALIDATION_PATTERNS.EMAIL,
    },
  },
};

// Validation function
export function validate(data: any, rules: any): { isValid: boolean; errors: Record<string, string[]> } {
  const errors: Record<string, string[]> = {};

  for (const [field, rule] of Object.entries(rules)) {
    const value = data[field];
    const fieldErrors: string[] = [];

    // Check required
    if (rule.required && (value === undefined || value === null || value === '')) {
      fieldErrors.push(`${field} is required`);
    }

    if (value !== undefined && value !== null && value !== '') {
      // Check min length
      if (rule.minLength && String(value).length < rule.minLength) {
        fieldErrors.push(`${field} must be at least ${rule.minLength} characters`);
      }

      // Check max length
      if (rule.maxLength && String(value).length > rule.maxLength) {
        fieldErrors.push(`${field} must be at most ${rule.maxLength} characters`);
      }

      // Check pattern
      if (rule.pattern && !rule.pattern.test(String(value))) {
        fieldErrors.push(`${field} format is invalid`);
      }

      // Check enum
      if (rule.enum && !rule.enum.includes(value)) {
        fieldErrors.push(`${field} must be one of: ${rule.enum.join(', ')}`);
      }

      // Check custom validator
      if (rule.validator && !rule.validator(value)) {
        fieldErrors.push(rule.message || `${field} validation failed`);
      }
    }

    if (fieldErrors.length > 0) {
      errors[field] = fieldErrors;
    }
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
}

// Sanitization functions
export function sanitizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

export function sanitizePhone(phone: string): string {
  // Remove all non-digit characters except leading +
  let sanitized = phone.trim();
  if (!sanitized.startsWith('+')) {
    // Assume local number, add country code for KSA
    if (sanitized.startsWith('0')) {
      sanitized = '+966' + sanitized.substring(1);
    } else {
      sanitized = '+966' + sanitized;
    }
  }
  return sanitized.replace(/[^\d+]/g, '');
}

export function sanitizeText(text: string): string {
  return text.trim().replace(/\s+/g, ' ');
}

export function sanitizeObject(obj: any, fields: string[]): any {
  const sanitized = { ...obj };

  for (const field of fields) {
    if (sanitized[field] && typeof sanitized[field] === 'string') {
      sanitized[field] = sanitizeText(sanitized[field]);
    }
  }

  return sanitized;
}

// Rate limiting helper
export class RateLimiter {
  private attempts = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private maxAttempts: number = 5,
    private windowMs: number = 15 * 60 * 1000 // 15 minutes
  ) {}

  check(key: string): { allowed: boolean; remaining: number; resetIn: number } {
    const now = Date.now();
    const attempt = this.attempts.get(key);

    if (!attempt || attempt.resetAt < now) {
      // No attempt or window expired
      this.attempts.set(key, { count: 1, resetAt: now + this.windowMs });
      return {
        allowed: true,
        remaining: this.maxAttempts - 1,
        resetIn: this.windowMs,
      };
    }

    if (attempt.count >= this.maxAttempts) {
      return {
        allowed: false,
        remaining: 0,
        resetIn: attempt.resetAt - now,
      };
    }

    attempt.count++;
    return {
      allowed: true,
      remaining: this.maxAttempts - attempt.count,
      resetIn: attempt.resetAt - now,
    };
  }

  reset(key: string): void {
    this.attempts.delete(key);
  }
}
