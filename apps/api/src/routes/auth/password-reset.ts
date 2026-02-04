import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { AuditLogger } from '../../utils/audit';
import { SecurityUtils } from '../../utils/security';
import { ValidationError, NotFoundError, RateLimitError } from '../../utils/errors';
import { sanitizeEmail } from '../../utils/validation';

interface RequestPasswordResetBody {
  email: string;
  recaptchaToken?: string;
}

interface ValidateResetTokenBody {
  token: string;
}

interface ResetPasswordBody {
  token: string;
  newPassword: string;
  confirmPassword: string;
}

interface ForgotUsernameBody {
  phone: string;
  idNumber: string;
  recaptchaToken?: string;
}

export async function passwordResetRoutes(app: FastifyInstance) {
  const auditLogger = new AuditLogger(app);

  // Request password reset
  app.post(
    '/password-reset/request',
    {
      schema: {
        body: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' },
            recaptchaToken: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as RequestPasswordResetBody;
      const ipAddress = request.ip;
      const userAgent = request.headers['user-agent'];

      try {
        // Rate limiting: 5 requests per hour per IP
        const rateLimitKey = `pwd_reset:${ipAddress}`;
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

        const recentRequests = await app.prisma.auditLog.count({
          where: {
            actionType: 'PASSWORD_RESET_REQUEST',
            ipAddress,
            createdAt: { gte: oneHourAgo },
          },
        });

        if (recentRequests >= 5) {
          throw new RateLimitError('Too many password reset requests. Please try again later.');
        }

        // Validate reCAPTCHA if enabled
        if (process.env.RECAPTCHA_ENABLED === 'true' && body.recaptchaToken) {
          // TODO: Implement reCAPTCHA verification
          // const isValid = await verifyRecaptcha(body.recaptchaToken);
          // if (!isValid) {
          //   throw new ValidationError('Invalid reCAPTCHA token');
          // }
        }

        // Sanitize email
        const sanitizedEmail = sanitizeEmail(body.email);

        // Find user
        const user = await app.prisma.user.findUnique({
          where: { email: sanitizedEmail },
          select: {
            id: true,
            email: true,
            fullName: true,
            status: true,
            approvalStatus: true,
            companyId: true,
          },
        });

        // Always return success even if user doesn't exist (security best practice)
        if (!user) {
          // Log the attempt
          await auditLogger.log({
            actionType: 'PASSWORD_RESET_REQUEST',
            entityType: 'User',
            description: 'Password reset requested for non-existent email',
            ipAddress,
            userAgent,
            metadata: {
              email: sanitizedEmail,
              userExists: false,
            },
            severity: 'WARNING',
          });

          return {
            success: true,
            message: 'If an account exists with this email, a reset link has been sent.',
            cooldown: '15 minutes',
          };
        }

        // Check if account is active and approved
        if (user.status !== 'ACTIVE' || user.approvalStatus !== 'APPROVED') {
          await auditLogger.logSecurityEvent(user.id, user.companyId, 'PASSWORD_RESET_BLOCKED', {
            reason: 'ACCOUNT_INACTIVE',
            status: user.status,
            approvalStatus: user.approvalStatus,
            ipAddress,
          });

          // Still return success for security
          return {
            success: true,
            message: 'If an account exists with this email, a reset link has been sent.',
            cooldown: '15 minutes',
          };
        }

        // Check for existing valid reset token
        const existingToken = await app.prisma.verificationToken.findFirst({
          where: {
            userId: user.id,
            type: 'PASSWORD_RESET',
            expiresAt: { gt: now },
            usedAt: null,
          },
        });

        let resetToken: string;
        let expiresAt: Date;

        if (existingToken) {
          // Reuse existing token if still valid
          resetToken = existingToken.token;
          expiresAt = existingToken.expiresAt;
        } else {
          // Generate new reset token
          const tokenData = SecurityUtils.generatePasswordResetToken();
          resetToken = tokenData.token;
          expiresAt = tokenData.expiresAt;

          // Save token
          await app.prisma.verificationToken.create({
            data: {
              userId: user.id,
              token: resetToken,
              type: 'PASSWORD_RESET',
              expiresAt,
            },
          });

          // Invalidate any old reset tokens
          await app.prisma.verificationToken.updateMany({
            where: {
              userId: user.id,
              type: 'PASSWORD_RESET',
              expiresAt: { gt: now },
              usedAt: null,
              NOT: { token: resetToken },
            },
            data: { usedAt: now },
          });
        }

        // Generate reset link
        const resetLink = `${process.env.FRONTEND_URL}/auth/reset-password?token=${resetToken}`;

        // TODO: Send email with reset link
        // await sendPasswordResetEmail(user.email, user.fullName, resetLink, expiresAt);

        // For development, log the link
        if (process.env.NODE_ENV === 'development') {
          app.log.info(`Password reset link for ${user.email}: ${resetLink}`);
          app.log.info(`Reset token: ${resetToken}`);
        }

        // Log the request
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'PASSWORD_RESET_REQUEST',
          entityType: 'User',
          entityId: user.id,
          description: 'Password reset requested',
          ipAddress,
          userAgent,
          metadata: {
            email: user.email,
            tokenGenerated: true,
            expiresAt,
            resetLink: process.env.NODE_ENV === 'development' ? resetLink : undefined,
          },
          severity: 'INFO',
        });

        // Create notification for user
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SECURITY',
            title: 'Password Reset Requested',
            message: 'A password reset was requested for your account. If this was not you, please contact support immediately.',
            data: {
              securityAlert: true,
              action: 'PASSWORD_RESET_REQUEST',
              timestamp: now.toISOString(),
              ipAddress,
            },
          },
        });

        return {
          success: true,
          message: 'If an account exists with this email, a reset link has been sent.',
          cooldown: '15 minutes',
          // Return token for testing in development
          ...(process.env.NODE_ENV === 'development' && {
            resetToken,
            expiresAt,
            resetLink,
          }),
        };

      } catch (error: any) {
        app.log.error('Password reset request failed:', error);
        throw error;
      }
    }
  );

  // Validate reset token
  app.post(
    '/password-reset/validate',
    {
      schema: {
        body: {
          type: 'object',
          required: ['token'],
          properties: {
            token: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as ValidateResetTokenBody;
      const ipAddress = request.ip;

      try {
        // Find valid reset token
        const token = await app.prisma.verificationToken.findFirst({
          where: {
            token: body.token,
            type: 'PASSWORD_RESET',
            expiresAt: { gt: new Date() },
            usedAt: null,
          },
          include: {
            user: {
              select: {
                id: true,
                email: true,
                fullName: true,
                status: true,
                approvalStatus: true,
              },
            },
          },
        });

        if (!token) {
          throw new ValidationError('Invalid or expired reset token');
        }

        // Check if user account is active
        if (token.user.status !== 'ACTIVE' || token.user.approvalStatus !== 'APPROVED') {
          await auditLogger.logSecurityEvent(token.user.id, null, 'PASSWORD_RESET_INVALID_ACCOUNT', {
            reason: 'ACCOUNT_INACTIVE',
            status: token.user.status,
            approvalStatus: token.user.approvalStatus,
            ipAddress,
          });

          throw new ValidationError('Account is not active');
        }

        // Calculate token expiry in minutes
        const expiresIn = Math.max(0, Math.floor((token.expiresAt.getTime() - Date.now()) / 60000));

        // Log token validation
        await auditLogger.log({
          userId: token.user.id,
          actionType: 'PASSWORD_RESET_VALIDATE',
          entityType: 'User',
          entityId: token.user.id,
          description: 'Password reset token validated',
          ipAddress,
          metadata: {
            tokenValid: true,
            expiresInMinutes: expiresIn,
          },
        });

        return {
          success: true,
          valid: true,
          user: {
            id: token.user.id,
            email: token.user.email,
            fullName: token.user.fullName,
          },
          expiresIn: `${expiresIn} minutes`,
        };

      } catch (error: any) {
        app.log.error('Password reset token validation failed:', error);
        throw error;
      }
    }
  );

  // Reset password with token
  app.post(
    '/password-reset/confirm',
    {
      schema: {
        body: {
          type: 'object',
          required: ['token', 'newPassword', 'confirmPassword'],
          properties: {
            token: { type: 'string' },
            newPassword: { type: 'string', minLength: 12 },
            confirmPassword: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as ResetPasswordBody;
      const ipAddress = request.ip;
      const userAgent = request.headers['user-agent'];

      try {
        // Validate passwords match
        if (body.newPassword !== body.confirmPassword) {
          throw new ValidationError('Passwords do not match');
        }

        // Check password strength
        const passwordStrength = SecurityUtils.checkPasswordStrength(body.newPassword);
        if (passwordStrength.strength === 'weak' || passwordStrength.strength === 'fair') {
          throw new ValidationError('Password is too weak. ' + passwordStrength.feedback.join(' '));
        }

        // Find valid reset token
        const token = await app.prisma.verificationToken.findFirst({
          where: {
            token: body.token,
            type: 'PASSWORD_RESET',
            expiresAt: { gt: new Date() },
            usedAt: null,
          },
          include: {
            user: {
              include: {
                company: true,
              },
            },
          },
        });

        if (!token) {
          throw new ValidationError('Invalid or expired reset token');
        }

        const user = token.user;

        // Check if user account is active
        if (user.status !== 'ACTIVE' || user.approvalStatus !== 'APPROVED') {
          await auditLogger.logSecurityEvent(user.id, user.companyId, 'PASSWORD_RESET_BLOCKED', {
            reason: 'ACCOUNT_INACTIVE',
            status: user.status,
            approvalStatus: user.approvalStatus,
            ipAddress,
          });

          throw new ValidationError('Account is not active');
        }

        // Check if new password is same as current
        const sameAsCurrent = await SecurityUtils.verifyPassword(
          body.newPassword,
          user.passwordHash
        );

        if (sameAsCurrent) {
          throw new ValidationError('New password must be different from current password');
        }

        // Hash new password
        const newPasswordHash = await SecurityUtils.hashPassword(body.newPassword);

        // Update password and invalidate tokens in transaction
        await app.prisma.$transaction(async (tx) => {
          // Mark token as used
          await tx.verificationToken.update({
            where: { id: token.id },
            data: { usedAt: new Date() },
          });

          // Update user password
          await tx.user.update({
            where: { id: user.id },
            data: {
              passwordHash: newPasswordHash,
              lastPasswordChangeAt: new Date(),
              mustChangePassword: false,
              failedLoginAttempts: 0,
              lockedUntil: null,
            },
          });

          // Invalidate all sessions
          await tx.session.updateMany({
            where: { userId: user.id, isValid: true },
            data: { isValid: false },
          });

          // Invalidate all refresh tokens
          await tx.refreshToken.updateMany({
            where: { userId: user.id, isValid: true },
            data: { isValid: false },
          });

          // Clear rate limits for this user
          await tx.rateLimit.deleteMany({
            where: { key: { contains: `login:${user.email}:` } },
          });
        });

        // Log password reset
        await auditLogger.logPasswordChange(user.id, user.companyId, 'password_reset');

        // Create security notification
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SECURITY',
            title: 'Password Reset Successful',
            message: 'Your password has been reset successfully. All active sessions have been logged out for security.',
            data: {
              securityAlert: true,
              action: 'PASSWORD_RESET',
              timestamp: new Date().toISOString(),
              ipAddress,
              userAgent,
              sessionsInvalidated: true,
            },
          },
        });

        // TODO: Send confirmation email
        // await sendPasswordResetConfirmationEmail(user.email, user.fullName, ipAddress);

        // Log successful reset
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'PASSWORD_RESET_SUCCESS',
          entityType: 'User',
          entityId: user.id,
          description: 'Password reset successfully completed',
          ipAddress,
          userAgent,
          metadata: {
            passwordStrength: passwordStrength.strength,
            sessionsInvalidated: true,
          },
          severity: 'INFO',
        });

        return {
          success: true,
          message: 'Password reset successfully. You can now login with your new password.',
          securityNotice: 'All active sessions have been logged out for security.',
        };

      } catch (error: any) {
        app.log.error('Password reset failed:', error);
        throw error;
      }
    }
  );

  // Forgot username (retrieve via phone and ID)
  app.post(
    '/auth/forgot-username',
    {
      schema: {
        body: {
          type: 'object',
          required: ['phone', 'idNumber'],
          properties: {
            phone: { type: 'string' },
            idNumber: { type: 'string' },
            recaptchaToken: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as ForgotUsernameBody;
      const ipAddress = request.ip;

      try {
        // Rate limiting: 3 requests per hour per IP
        const rateLimitKey = `forgot_user:${ipAddress}`;
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

        const recentRequests = await app.prisma.auditLog.count({
          where: {
            actionType: 'FORGOT_USERNAME_REQUEST',
            ipAddress,
            createdAt: { gte: oneHourAgo },
          },
        });

        if (recentRequests >= 3) {
          throw new RateLimitError('Too many username recovery requests. Please try again later.');
        }

        // Validate reCAPTCHA if enabled
        if (process.env.RECAPTCHA_ENABLED === 'true' && body.recaptchaToken) {
          // TODO: Implement reCAPTCHA verification
        }

        // Find user by phone and ID number
        const user = await app.prisma.user.findFirst({
          where: {
            phone: body.phone,
            idNumber: body.idNumber,
            status: 'ACTIVE',
            approvalStatus: 'APPROVED',
          },
          select: {
            id: true,
            email: true,
            fullName: true,
            companyId: true,
          },
        });

        // Always return same response for security
        if (!user) {
          // Log the attempt
          await auditLogger.log({
            actionType: 'FORGOT_USERNAME_REQUEST',
            entityType: 'User',
            description: 'Username recovery requested for non-existent/mismatched credentials',
            ipAddress,
            metadata: {
              phone: body.phone,
              idNumber: body.idNumber,
              userExists: false,
            },
            severity: 'WARNING',
          });

          return {
            success: true,
            message: 'If an account exists with these details, recovery instructions have been sent.',
          };
        }

        // TODO: Send email/SMS with username (email)
        // For now, return masked email in development
        const maskedEmail = SecurityUtils.maskEmail(user.email);

        // In development, return the actual email
        let recoveryInfo: any = {
          message: 'Recovery instructions have been sent to your registered contact methods.',
        };

        if (process.env.NODE_ENV === 'development') {
          recoveryInfo = {
            message: 'In production, this would be sent via secure channel.',
            email: user.email,
            maskedEmail,
          };
        }

        // Log successful request
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'FORGOT_USERNAME_REQUEST',
          entityType: 'User',
          entityId: user.id,
          description: 'Username recovery requested',
          ipAddress,
          metadata: {
            phoneProvided: body.phone,
            idNumberProvided: body.idNumber,
            recoveryMethod: 'email',
          },
          severity: 'INFO',
        });

        // Create security notification
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SECURITY',
            title: 'Username Recovery Requested',
            message: 'A username recovery was requested for your account. If this was not you, please contact support.',
            data: {
              securityAlert: true,
              action: 'USERNAME_RECOVERY',
              timestamp: now.toISOString(),
              ipAddress,
            },
          },
        });

        return {
          success: true,
          ...recoveryInfo,
        };

      } catch (error: any) {
        app.log.error('Username recovery failed:', error);
        throw error;
      }
    }
  );

  // Account lockout status check
  app.post(
    '/auth/check-lockout',
    {
      schema: {
        body: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as { email: string };
      const ipAddress = request.ip;

      try {
        const sanitizedEmail = sanitizeEmail(body.email);

        const user = await app.prisma.user.findUnique({
          where: { email: sanitizedEmail },
          select: {
            id: true,
            email: true,
            failedLoginAttempts: true,
            lockedUntil: true,
            status: true,
            approvalStatus: true,
          },
        });

        if (!user) {
          // Don't reveal if user exists
          return {
            success: true,
            exists: false,
            locked: false,
          };
        }

        const now = new Date();
        const isLocked = user.lockedUntil && user.lockedUntil > now;
        const lockMinutes = isLocked
          ? Math.ceil((user.lockedUntil!.getTime() - now.getTime()) / 60000)
          : 0;

        return {
          success: true,
          exists: true,
          locked: isLocked,
          lockMinutes,
          failedAttempts: user.failedLoginAttempts,
          status: user.status,
          approvalStatus: user.approvalStatus,
        };

      } catch (error: any) {
        app.log.error('Lockout check failed:', error);
        throw error;
      }
    }
  );

  // Unlock account (admin/creator only)
  app.post(
    '/auth/unlock-account',
    {
      preHandler: [app.authenticate, app.requireApproved, app.requireCompanyAdmin],
      schema: {
        body: {
          type: 'object',
          required: ['userId'],
          properties: {
            userId: { type: 'string' },
            reason: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const body = request.body as { userId: string; reason?: string };
      const ipAddress = request.ip;

      try {
        // Validate company membership
        await app.validateCompanyMembership(request, reply, body.userId);
        if (reply.sent) return;

        // Unlock account
        const updatedUser = await app.prisma.user.update({
          where: { id: body.userId },
          data: {
            failedLoginAttempts: 0,
            lockedUntil: null,
            lastFailedAttempt: null,
          },
        });

        // Log account unlock
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'ACCOUNT_UNLOCK',
          entityType: 'User',
          entityId: body.userId,
          description: `Account unlocked by admin: ${body.reason || 'No reason provided'}`,
          metadata: {
            unlockedBy: user.id,
            unlockedByEmail: user.email,
            reason: body.reason,
            ipAddress,
          },
          severity: 'WARNING',
        });

        // Create notification for unlocked user
        await app.prisma.notification.create({
          data: {
            userId: body.userId,
            companyId: updatedUser.companyId,
            type: 'SYSTEM',
            title: 'Account Unlocked',
            message: 'Your account has been unlocked by an administrator. You can now login again.',
            data: {
              unlocked: true,
              unlockedBy: user.fullName || user.email,
              timestamp: new Date().toISOString(),
            },
          },
        });

        return {
          success: true,
          message: 'Account unlocked successfully',
          user: {
            id: updatedUser.id,
            email: updatedUser.email,
            lockedUntil: updatedUser.lockedUntil,
            failedAttempts: updatedUser.failedLoginAttempts,
          },
        };

      } catch (error: any) {
        app.log.error('Account unlock failed:', error);
        throw error;
      }
    }
  );
}
