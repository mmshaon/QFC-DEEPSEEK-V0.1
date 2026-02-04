import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { AuditLogger } from '../../utils/audit';
import { SecurityUtils } from '../../utils/security';
import { ValidationError, NotFoundError, AuthorizationError } from '../../utils/errors';
import { sanitizePhone, sanitizeEmail } from '../../utils/validation';

interface VerifyIdentityBody {
  email: string;
  phone: string;
  idNumber: string;
  recaptchaToken?: string;
}

interface RecoveryOptionsBody {
  verificationToken: string;
  recoveryMethod: 'email' | 'sms' | 'authenticator';
}

interface VerifyRecoveryCodeBody {
  verificationToken: string;
  recoveryCode: string;
}

interface CompleteRecoveryBody {
  verificationToken: string;
  recoveryToken: string;
  newPassword: string;
  confirmPassword: string;
}

interface UpdateSecurityQuestionsBody {
  question1: string;
  answer1: string;
  question2: string;
  answer2: string;
  question3: string;
  answer3: string;
  currentPassword: string;
}

interface VerifySecurityQuestionsBody {
  email: string;
  question1: string;
  answer1: string;
  question2: string;
  answer2: string;
  question3: string;
  answer3: string;
}

export async function accountRecoveryRoutes(app: FastifyInstance) {
  const auditLogger = new AuditLogger(app);

  // Step 1: Verify identity for account recovery
  app.post(
    '/recovery/verify-identity',
    {
      schema: {
        body: {
          type: 'object',
          required: ['email', 'phone', 'idNumber'],
          properties: {
            email: { type: 'string', format: 'email' },
            phone: { type: 'string' },
            idNumber: { type: 'string' },
            recaptchaToken: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as VerifyIdentityBody;
      const ipAddress = request.ip;
      const userAgent = request.headers['user-agent'];

      try {
        // Rate limiting
        const rateLimitKey = `recovery_id:${ipAddress}`;
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

        const recentAttempts = await app.prisma.auditLog.count({
          where: {
            actionType: 'RECOVERY_IDENTITY_VERIFICATION',
            ipAddress,
            createdAt: { gte: oneHourAgo },
          },
        });

        if (recentAttempts >= 3) {
          throw new ValidationError('Too many recovery attempts. Please try again later.');
        }

        // Validate reCAPTCHA
        if (process.env.RECAPTCHA_ENABLED === 'true' && body.recaptchaToken) {
          // TODO: Verify reCAPTCHA
        }

        // Sanitize inputs
        const sanitizedEmail = sanitizeEmail(body.email);
        const sanitizedPhone = sanitizePhone(body.phone);

        // Find user matching all three factors
        const user = await app.prisma.user.findFirst({
          where: {
            email: sanitizedEmail,
            phone: sanitizedPhone,
            idNumber: body.idNumber,
            status: 'ACTIVE',
            approvalStatus: 'APPROVED',
          },
          select: {
            id: true,
            email: true,
            fullName: true,
            phone: true,
            phoneVerified: true,
            companyId: true,
            securityQuestions: true,
            twoFactorEnabled: true,
          },
        });

        // Always return same response for security
        if (!user) {
          await auditLogger.log({
            actionType: 'RECOVERY_IDENTITY_VERIFICATION_FAILED',
            entityType: 'User',
            description: 'Failed identity verification for account recovery',
            ipAddress,
            userAgent,
            metadata: {
              email: sanitizedEmail,
              phone: sanitizedPhone,
              idNumber: body.idNumber,
              match: false,
            },
            severity: 'WARNING',
          });

          // Return generic success message
          return {
            success: true,
            verified: false,
            message: 'If the information matches an account, you will receive recovery options.',
            nextStep: 'wait',
          };
        }

        // Generate verification token (valid for 10 minutes)
        const verificationToken = SecurityUtils.generateToken(32);
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

        // Store verification token
        await app.prisma.verificationToken.create({
          data: {
            userId: user.id,
            token: verificationToken,
            type: 'ACCOUNT_RECOVERY',
            expiresAt,
          },
        });

        // Determine available recovery methods
        const recoveryMethods = [];

        if (user.email) {
          recoveryMethods.push({
            method: 'email',
            value: SecurityUtils.maskEmail(user.email),
            available: true,
          });
        }

        if (user.phone && user.phoneVerified) {
          recoveryMethods.push({
            method: 'sms',
            value: SecurityUtils.maskPhone(user.phone),
            available: true,
          });
        }

        if (user.twoFactorEnabled) {
          recoveryMethods.push({
            method: 'authenticator',
            value: 'Authenticator App',
            available: true,
          });
        }

        // Log successful verification
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'RECOVERY_IDENTITY_VERIFICATION_SUCCESS',
          entityType: 'User',
          entityId: user.id,
          description: 'Identity verified for account recovery',
          ipAddress,
          userAgent,
          metadata: {
            verificationToken,
            expiresAt,
            recoveryMethodsAvailable: recoveryMethods.length,
          },
          severity: 'INFO',
        });

        // Create security notification
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SECURITY',
            title: 'Account Recovery Initiated',
            message: 'Account recovery process has been initiated for your account. If this was not you, please contact support immediately.',
            data: {
              securityAlert: true,
              action: 'ACCOUNT_RECOVERY_INITIATED',
              timestamp: now.toISOString(),
              ipAddress,
              recoveryMethods: recoveryMethods.map(m => m.method),
            },
          },
        });

        return {
          success: true,
          verified: true,
          verificationToken,
          expiresAt,
          recoveryMethods,
          nextStep: 'select_method',
          securityNotice: 'A security notification has been sent to your account.',
        };

      } catch (error: any) {
        app.log.error('Identity verification failed:', error);
        throw error;
      }
    }
  );

  // Step 2: Request recovery code via selected method
  app.post(
    '/recovery/request-code',
    {
      schema: {
        body: {
          type: 'object',
          required: ['verificationToken', 'recoveryMethod'],
          properties: {
            verificationToken: { type: 'string' },
            recoveryMethod: { type: 'string', enum: ['email', 'sms', 'authenticator'] },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as RecoveryOptionsBody;
      const ipAddress = request.ip;

      try {
        // Validate verification token
        const token = await app.prisma.verificationToken.findFirst({
          where: {
            token: body.verificationToken,
            type: 'ACCOUNT_RECOVERY',
            expiresAt: { gt: new Date() },
            usedAt: null,
          },
          include: {
            user: {
              select: {
                id: true,
                email: true,
                phone: true,
                phoneVerified: true,
                fullName: true,
                companyId: true,
                twoFactorEnabled: true,
              },
            },
          },
        });

        if (!token) {
          throw new ValidationError('Invalid or expired verification token');
        }

        const user = token.user;

        // Check if selected method is available
        let canUseMethod = false;
        let contactValue = '';

        switch (body.recoveryMethod) {
          case 'email':
            canUseMethod = !!user.email;
            contactValue = user.email!;
            break;
          case 'sms':
            canUseMethod = !!user.phone && user.phoneVerified;
            contactValue = user.phone!;
            break;
          case 'authenticator':
            canUseMethod = !!user.twoFactorEnabled;
            contactValue = 'Authenticator App';
            break;
        }

        if (!canUseMethod) {
          throw new ValidationError(`Selected recovery method is not available for your account`);
        }

        // Generate recovery code (6 digits)
        const recoveryCode = SecurityUtils.generatePin(6);
        const recoveryToken = SecurityUtils.generateToken(32);
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

        // Store recovery code
        await app.prisma.verificationToken.create({
          data: {
            userId: user.id,
            token: recoveryToken,
            type: 'RECOVERY_CODE',
            expiresAt,
            metadata: {
              recoveryCode,
              recoveryMethod: body.recoveryMethod,
              verificationToken: body.verificationToken,
            },
          },
        });

        // Send recovery code via selected method
        switch (body.recoveryMethod) {
          case 'email':
            // TODO: Send email with recovery code
            app.log.info(`Recovery code for ${user.email}: ${recoveryCode}`);
            break;

          case 'sms':
            // TODO: Send SMS with recovery code
            app.log.info(`Recovery code SMS to ${user.phone}: ${recoveryCode}`);
            break;

          case 'authenticator':
            // For authenticator, we need to handle 2FA recovery
            app.log.info(`Authenticator recovery for ${user.email}`);
            break;
        }

        // Log recovery code request
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'RECOVERY_CODE_REQUESTED',
          entityType: 'User',
          entityId: user.id,
          description: `Recovery code requested via ${body.recoveryMethod}`,
          ipAddress,
          metadata: {
            recoveryMethod: body.recoveryMethod,
            contactValue: SecurityUtils.maskContact(contactValue, body.recoveryMethod),
            recoveryToken,
            expiresAt,
          },
          severity: 'INFO',
        });

        return {
          success: true,
          message: `Recovery code sent via ${body.recoveryMethod}`,
          recoveryToken,
          expiresAt,
          method: body.recoveryMethod,
          contactMasked: SecurityUtils.maskContact(contactValue, body.recoveryMethod),
          // For testing in development
          ...(process.env.NODE_ENV === 'development' && {
            recoveryCode,
            contactValue,
          }),
        };

      } catch (error: any) {
        app.log.error('Recovery code request failed:', error);
        throw error;
      }
    }
  );

  // Step 3: Verify recovery code
  app.post(
    '/recovery/verify-code',
    {
      schema: {
        body: {
          type: 'object',
          required: ['verificationToken', 'recoveryCode'],
          properties: {
            verificationToken: { type: 'string' },
            recoveryCode: { type: 'string', pattern: '^\\d{6}$' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as VerifyRecoveryCodeBody;
      const ipAddress = request.ip;

      try {
        // Find recovery token
        const recoveryToken = await app.prisma.verificationToken.findFirst({
          where: {
            token: body.verificationToken,
            type: 'RECOVERY_CODE',
            expiresAt: { gt: new Date() },
            usedAt: null,
          },
        });

        if (!recoveryToken) {
          throw new ValidationError('Invalid or expired recovery token');
        }

        // Verify recovery code from metadata
        const metadata = recoveryToken.metadata as any;
        if (!metadata || metadata.recoveryCode !== body.recoveryCode) {
          // Increment failed attempts
          const failedAttempts = (metadata?.failedAttempts || 0) + 1;

          await app.prisma.verificationToken.update({
            where: { id: recoveryToken.id },
            data: {
              metadata: {
                ...metadata,
                failedAttempts,
                lastAttempt: new Date().toISOString(),
              },
            },
          });

          // Block after 3 failed attempts
          if (failedAttempts >= 3) {
            await app.prisma.verificationToken.update({
              where: { id: recoveryToken.id },
              data: { usedAt: new Date() },
            });

            await auditLogger.logSecurityEvent(recoveryToken.userId, null, 'RECOVERY_CODE_BLOCKED', {
              reason: 'TOO_MANY_FAILED_ATTEMPTS',
              failedAttempts,
              ipAddress,
            });

            throw new ValidationError('Too many failed attempts. Recovery process has been blocked.');
          }

          throw new ValidationError('Invalid recovery code');
        }

        // Mark recovery token as used
        await app.prisma.verificationToken.update({
          where: { id: recoveryToken.id },
          data: { usedAt: new Date() },
        });

        // Generate final recovery token for password reset
        const finalRecoveryToken = SecurityUtils.generateToken(48);
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

        await app.prisma.verificationToken.create({
          data: {
            userId: recoveryToken.userId,
            token: finalRecoveryToken,
            type: 'FINAL_RECOVERY',
            expiresAt,
            metadata: {
              verificationToken: body.verificationToken,
              recoveryMethod: metadata.recoveryMethod,
            },
          },
        });

        // Log successful code verification
        await auditLogger.log({
          userId: recoveryToken.userId,
          actionType: 'RECOVERY_CODE_VERIFIED',
          entityType: 'User',
          entityId: recoveryToken.userId,
          description: 'Recovery code verified successfully',
          ipAddress,
          metadata: {
            recoveryMethod: metadata.recoveryMethod,
          },
          severity: 'INFO',
        });

        return {
          success: true,
          message: 'Recovery code verified successfully',
          finalRecoveryToken,
          expiresAt,
          nextStep: 'reset_password',
        };

      } catch (error: any) {
        app.log.error('Recovery code verification failed:', error);
        throw error;
      }
    }
  );

  // Step 4: Complete account recovery with new password
  app.post(
    '/recovery/complete',
    {
      schema: {
        body: {
          type: 'object',
          required: ['verificationToken', 'recoveryToken', 'newPassword', 'confirmPassword'],
          properties: {
            verificationToken: { type: 'string' },
            recoveryToken: { type: 'string' },
            newPassword: { type: 'string', minLength: 12 },
            confirmPassword: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as CompleteRecoveryBody;
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

        // Find verification token
        const verificationToken = await app.prisma.verificationToken.findFirst({
          where: {
            token: body.verificationToken,
            type: 'ACCOUNT_RECOVERY',
            expiresAt: { gt: new Date() },
            usedAt: null,
          },
          include: {
            user: true,
          },
        });

        if (!verificationToken) {
          throw new ValidationError('Invalid or expired verification token');
        }

        // Find final recovery token
        const finalToken = await app.prisma.verificationToken.findFirst({
          where: {
            token: body.recoveryToken,
            type: 'FINAL_RECOVERY',
            userId: verificationToken.userId,
            expiresAt: { gt: new Date() },
            usedAt: null,
          },
        });

        if (!finalToken) {
          throw new ValidationError('Invalid or expired recovery token');
        }

        const user = verificationToken.user;

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

        // Complete recovery in transaction
        await app.prisma.$transaction(async (tx) => {
          // Mark tokens as used
          await tx.verificationToken.update({
            where: { id: verificationToken.id },
            data: { usedAt: new Date() },
          });

          await tx.verificationToken.update({
            where: { id: finalToken.id },
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
        });

        // Log successful recovery
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'ACCOUNT_RECOVERY_COMPLETE',
          entityType: 'User',
          entityId: user.id,
          description: 'Account recovery completed successfully',
          ipAddress,
          userAgent,
          metadata: {
            passwordStrength: passwordStrength.strength,
            sessionsInvalidated: true,
          },
          severity: 'INFO',
        });

        // Create security notification
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SECURITY',
            title: 'Account Recovery Completed',
            message: 'Your account has been recovered successfully. All active sessions have been logged out for security.',
            data: {
              securityAlert: true,
              action: 'ACCOUNT_RECOVERY_COMPLETED',
              timestamp: new Date().toISOString(),
              ipAddress,
              userAgent,
            },
          },
        });

        // TODO: Send recovery completion email
        // await sendRecoveryCompletionEmail(user.email, user.fullName, ipAddress);

        return {
          success: true,
          message: 'Account recovered successfully. You can now login with your new password.',
          securityNotice: 'All active sessions have been logged out for security.',
          nextSteps: [
            'Login with your new password',
            'Review your account security settings',
            'Consider enabling two-factor authentication',
          ],
        };

      } catch (error: any) {
        app.log.error('Account recovery failed:', error);
        throw error;
      }
    }
  );

  // Set up security questions (authenticated users)
  app.post(
    '/security/questions',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        body: {
          type: 'object',
          required: [
            'question1', 'answer1',
            'question2', 'answer2',
            'question3', 'answer3',
            'currentPassword',
          ],
          properties: {
            question1: { type: 'string', minLength: 10 },
            answer1: { type: 'string', minLength: 2 },
            question2: { type: 'string', minLength: 10 },
            answer2: { type: 'string', minLength: 2 },
            question3: { type: 'string', minLength: 10 },
            answer3: { type: 'string', minLength: 2 },
            currentPassword: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const body = request.body as UpdateSecurityQuestionsBody;
      const ipAddress = request.ip;

      try {
        // Verify current password
        const dbUser = await app.prisma.user.findUnique({
          where: { id: user.id },
        });

        if (!dbUser) {
          throw new NotFoundError('User');
        }

        const validPassword = await SecurityUtils.verifyPassword(
          body.currentPassword,
          dbUser.passwordHash
        );

        if (!validPassword) {
          throw new ValidationError('Current password is incorrect');
        }

        // Hash answers for security
        const hashedAnswers = {
          question1: body.question1.trim(),
          answer1: await SecurityUtils.hashPassword(body.answer1.trim().toLowerCase()),
          question2: body.question2.trim(),
          answer2: await SecurityUtils.hashPassword(body.answer2.trim().toLowerCase()),
          question3: body.question3.trim(),
          answer3: await SecurityUtils.hashPassword(body.answer3.trim().toLowerCase()),
          setAt: new Date().toISOString(),
          setByIp: ipAddress,
        };

        // Update user with security questions
        await app.prisma.user.update({
          where: { id: user.id },
          data: {
            securityQuestions: hashedAnswers,
          },
        });

        // Log security questions setup
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'SECURITY_QUESTIONS_SET',
          entityType: 'User',
          entityId: user.id,
          description: 'Security questions set up',
          ipAddress,
          metadata: {
            questionsSet: 3,
          },
          severity: 'INFO',
        });

        // Create notification
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SECURITY',
            title: 'Security Questions Updated',
            message: 'Your security questions have been updated successfully.',
            data: {
              securityUpdated: true,
              feature: 'security_questions',
            },
          },
        });

        return {
          success: true,
          message: 'Security questions set up successfully',
          notice: 'Keep your answers secure and memorable. They will be used for account recovery.',
        };

      } catch (error: any) {
        app.log.error('Failed to set security questions:', error);
        throw error;
      }
    }
  );

  // Verify security questions (for account recovery)
  app.post(
    '/recovery/security-questions',
    {
      schema: {
        body: {
          type: 'object',
          required: [
            'email',
            'question1', 'answer1',
            'question2', 'answer2',
            'question3', 'answer3',
          ],
          properties: {
            email: { type: 'string', format: 'email' },
            question1: { type: 'string' },
            answer1: { type: 'string' },
            question2: { type: 'string' },
            answer2: { type: 'string' },
            question3: { type: 'string' },
            answer3: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as VerifySecurityQuestionsBody;
      const ipAddress = request.ip;

      try {
        const sanitizedEmail = sanitizeEmail(body.email);

        // Find user
        const user = await app.prisma.user.findUnique({
          where: { email: sanitizedEmail },
          select: {
            id: true,
            email: true,
            securityQuestions: true,
            status: true,
            approvalStatus: true,
            companyId: true,
          },
        });

        if (!user) {
          // Don't reveal if user exists
          return {
            success: true,
            verified: false,
            message: 'Security questions processed.',
          };
        }

        // Check if user has security questions set
        if (!user.securityQuestions) {
          await auditLogger.logSecurityEvent(user.id, user.companyId, 'SECURITY_QUESTIONS_MISSING', {
            reason: 'QUESTIONS_NOT_SET',
            ipAddress,
          });

          return {
            success: true,
            verified: false,
            message: 'Security questions processed.',
          };
        }

        const questions = user.securityQuestions as any;

        // Verify answers
        const answersCorrect = [
          await SecurityUtils.verifyPassword(body.answer1.trim().toLowerCase(), questions.answer1),
          await SecurityUtils.verifyPassword(body.answer2.trim().toLowerCase(), questions.answer2),
          await SecurityUtils.verifyPassword(body.answer3.trim().toLowerCase(), questions.answer3),
        ];

        const correctCount = answersCorrect.filter(correct => correct).length;

        // Require at least 2 out of 3 correct answers
        if (correctCount < 2) {
          await auditLogger.logSecurityEvent(user.id, user.companyId, 'SECURITY_QUESTIONS_FAILED', {
            correctAnswers: correctCount,
            required: 2,
            ipAddress,
          });

          return {
            success: true,
            verified: false,
            message: 'Security questions processed.',
          };
        }

        // Generate recovery token
        const recoveryToken = SecurityUtils.generateToken(32);
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

        await app.prisma.verificationToken.create({
          data: {
            userId: user.id,
            token: recoveryToken,
            type: 'SECURITY_QUESTIONS_RECOVERY',
            expiresAt,
            metadata: {
              correctAnswers: correctCount,
              ipAddress,
            },
          },
        });

        // Log successful verification
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'SECURITY_QUESTIONS_VERIFIED',
          entityType: 'User',
          entityId: user.id,
          description: 'Security questions verified for recovery',
          ipAddress,
          metadata: {
            correctAnswers: correctCount,
          },
          severity: 'INFO',
        });

        // Create security notification
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SECURITY',
            title: 'Security Questions Used for Recovery',
            message: 'Your security questions were used for account recovery. If this was not you, please contact support immediately.',
            data: {
              securityAlert: true,
              action: 'SECURITY_QUESTIONS_RECOVERY',
              timestamp: new Date().toISOString(),
              ipAddress,
            },
          },
        });

        return {
          success: true,
          verified: true,
          recoveryToken,
          expiresAt,
          nextStep: 'reset_password',
          securityNotice: 'A security notification has been sent to your account.',
        };

      } catch (error: any) {
        app.log.error('Security questions verification failed:', error);
        throw error;
      }
    }
  );

  // Get account recovery status
  app.get(
    '/recovery/status/:userId',
    {
      preHandler: [app.authenticate, app.requireApproved],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const { userId } = request.params as { userId: string };

      try {
        // Only allow users to check their own status or admin to check others
        if (user.id !== userId && !user.isCreator && !user.isCompanyAdmin) {
          throw new AuthorizationError('Not authorized to view recovery status');
        }

        // Validate company membership for admins
        if (user.id !== userId) {
          await app.validateCompanyMembership(request, reply, userId);
          if (reply.sent) return;
        }

        const targetUser = await app.prisma.user.findUnique({
          where: { id: userId },
          select: {
            id: true,
            email: true,
            phone: true,
            phoneVerified: true,
            twoFactorEnabled: true,
            securityQuestions: true,
            lastPasswordChangeAt: true,
            failedLoginAttempts: true,
            lockedUntil: true,
            status: true,
            approvalStatus: true,
          },
        });

        if (!targetUser) {
          throw new NotFoundError('User');
        }

        // Get recent recovery attempts
        const recentAttempts = await app.prisma.auditLog.findMany({
          where: {
            userId: targetUser.id,
            actionType: {
              contains: 'RECOVERY',
            },
            createdAt: {
              gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // Last 7 days
            },
          },
          select: {
            actionType: true,
            description: true,
            createdAt: true,
            ipAddress: true,
          },
          orderBy: { createdAt: 'desc' },
          take: 10,
        });

        return {
          success: true,
          recoverySettings: {
            email: {
              configured: !!targetUser.email,
              verified: true, // Email is always verified if we have it
            },
            phone: {
              configured: !!targetUser.phone,
              verified: targetUser.phoneVerified,
            },
            twoFactor: {
              configured: targetUser.twoFactorEnabled,
            },
            securityQuestions: {
              configured: !!targetUser.securityQuestions,
              count: targetUser.securityQuestions ? 3 : 0,
            },
          },
          securityStatus: {
            lastPasswordChange: targetUser.lastPasswordChangeAt,
            failedAttempts: targetUser.failedLoginAttempts,
            lockedUntil: targetUser.lockedUntil,
            accountStatus: targetUser.status,
            approvalStatus: targetUser.approvalStatus,
          },
          recentRecoveryAttempts: recentAttempts,
          recommendations: this.getRecoveryRecommendations(targetUser),
        };

      } catch (error: any) {
        app.log.error('Failed to get recovery status:', error);
        throw error;
      }
    }
  );

  // Helper function to get recovery recommendations
  function getRecoveryRecommendations(user: any): string[] {
    const recommendations: string[] = [];

    if (!user.phoneVerified) {
      recommendations.push('Verify your phone number for SMS recovery');
    }

    if (!user.twoFactorEnabled) {
      recommendations.push('Enable two-factor authentication for additional security');
    }

    if (!user.securityQuestions) {
      recommendations.push('Set up security questions for account recovery');
    }

    const passwordAge = user.lastPasswordChangeAt
      ? (Date.now() - new Date(user.lastPasswordChangeAt).getTime()) / (1000 * 60 * 60 * 24)
      : Infinity;

    if (passwordAge > 90) {
      recommendations.push('Consider updating your password (last changed over 90 days ago)');
    }

    if (user.failedLoginAttempts > 0) {
      recommendations.push('Review recent failed login attempts in your security log');
    }

    return recommendations;
  }
}

// Add missing utility functions to SecurityUtils
SecurityUtils.maskEmail = function(email: string): string {
  const [local, domain] = email.split('@');
  if (local.length <= 2) {
    return `${local[0]}***@${domain}`;
  }
  return `${local[0]}***${local[local.length - 1]}@${domain}`;
};

SecurityUtils.maskPhone = function(phone: string): string {
  if (phone.length <= 4) return '***';
  return `${phone.slice(0, 2)}****${phone.slice(-2)}`;
};

SecurityUtils.maskContact = function(contact: string, method: string): string {
  switch (method) {
    case 'email':
      return SecurityUtils.maskEmail(contact);
    case 'sms':
      return SecurityUtils.maskPhone(contact);
    default:
      return '***';
  }
};
