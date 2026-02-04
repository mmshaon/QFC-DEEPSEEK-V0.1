import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { AuditLogger } from '../../utils/audit';
import { SecurityUtils } from '../../utils/security';
import { ValidationError, NotFoundError, AuthorizationError } from '../../utils/errors';
import { sanitizePhone, sanitizeEmail } from '../../utils/validation';

interface UpdateProfileBody {
  fullName?: string;
  phone?: string;
  address?: string;
  city?: string;
  state?: string;
  country?: string;
  postalCode?: string;
  profileImage?: string;
  emergencyContactName?: string;
  emergencyContactPhone?: string;
  emergencyContactRelation?: string;
}

interface ChangePasswordBody {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

interface SetPinBody {
  pin: string;
  confirmPin: string;
}

interface UpdatePinBody {
  currentPin: string;
  newPin: string;
  confirmPin: string;
}

interface VerifyPinBody {
  pin: string;
}

export async function profileRoutes(app: FastifyInstance) {
  const auditLogger = new AuditLogger(app);

  // Get user profile
  app.get(
    '/profile',
    {
      preHandler: [app.authenticate, app.requireApproved],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;

      try {
        const userProfile = await app.prisma.user.findUnique({
          where: { id: user.id },
          select: {
            id: true,
            email: true,
            fullName: true,
            address: true,
            city: true,
            state: true,
            country: true,
            postalCode: true,
            profileImage: true,
            idImage: true,
            idNumber: true,
            idType: true,
            phone: true,
            phoneVerified: true,
            emergencyContactName: true,
            emergencyContactPhone: true,
            emergencyContactRelation: true,
            isCreator: true,
            isSuperAdmin: true,
            isCompanyAdmin: true,
            status: true,
            approvalStatus: true,
            emailVerifiedAt: true,
            phoneVerifiedAt: true,
            lastLoginAt: true,
            lastActiveAt: true,
            mustChangePassword: true,
            pinSet: true,
            companyId: true,
            company: {
              select: {
                id: true,
                name: true,
                logoUrl: true,
                primaryColor: true,
                secondaryColor: true,
              },
            },
            roles: {
              select: {
                role: {
                  select: {
                    id: true,
                    name: true,
                    description: true,
                    level: true,
                  },
                },
              },
            },
            createdAt: true,
            updatedAt: true,
          },
        });

        if (!userProfile) {
          throw new NotFoundError('User');
        }

        // Get permissions
        const permissions = await app.rbac.getUserPermissions(user.id);

        return {
          success: true,
          profile: {
            ...userProfile,
            roles: userProfile.roles.map(r => r.role),
            permissions: Array.from(permissions),
          },
        };

      } catch (error: any) {
        app.log.error('Failed to fetch user profile:', error);
        throw error;
      }
    }
  );

  // Update user profile
  app.patch(
    '/profile',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        body: {
          type: 'object',
          properties: {
            fullName: { type: 'string', minLength: 2 },
            phone: { type: 'string' },
            address: { type: 'string', minLength: 5 },
            city: { type: 'string' },
            state: { type: 'string' },
            country: { type: 'string' },
            postalCode: { type: 'string' },
            profileImage: { type: 'string' },
            emergencyContactName: { type: 'string' },
            emergencyContactPhone: { type: 'string' },
            emergencyContactRelation: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const body = request.body as UpdateProfileBody;
      const ipAddress = request.ip;

      try {
        // Get current user data for audit
        const currentUser = await app.prisma.user.findUnique({
          where: { id: user.id },
        });

        if (!currentUser) {
          throw new NotFoundError('User');
        }

        // Prepare update data
        const updateData: any = {};

        if (body.fullName) updateData.fullName = body.fullName.trim();
        if (body.address) updateData.address = body.address.trim();
        if (body.city) updateData.city = body.city.trim();
        if (body.state) updateData.state = body.state.trim();
        if (body.country) updateData.country = body.country.trim();
        if (body.postalCode) updateData.postalCode = body.postalCode.trim();
        if (body.profileImage) updateData.profileImage = body.profileImage;
        if (body.emergencyContactName) updateData.emergencyContactName = body.emergencyContactName.trim();
        if (body.emergencyContactRelation) updateData.emergencyContactRelation = body.emergencyContactRelation.trim();

        // Handle phone update with verification
        if (body.phone) {
          const sanitizedPhone = sanitizePhone(body.phone);

          if (!SecurityUtils.validatePhoneNumber(sanitizedPhone)) {
            throw new ValidationError('Invalid phone number format');
          }

          // Check if phone is already used by another user
          const phoneExists = await app.prisma.user.findFirst({
            where: {
              phone: sanitizedPhone,
              id: { not: user.id },
            },
          });

          if (phoneExists) {
            throw new ConflictError('Phone number already registered');
          }

          updateData.phone = sanitizedPhone;
          updateData.phoneVerified = false;
          updateData.phoneVerifiedAt = null;
        }

        if (body.emergencyContactPhone) {
          const sanitizedEmergencyPhone = sanitizePhone(body.emergencyContactPhone);

          if (!SecurityUtils.validatePhoneNumber(sanitizedEmergencyPhone)) {
            throw new ValidationError('Invalid emergency contact phone number');
          }

          updateData.emergencyContactPhone = sanitizedEmergencyPhone;
        }

        // Update user
        const updatedUser = await app.prisma.user.update({
          where: { id: user.id },
          data: updateData,
        });

        // Log profile update
        await auditLogger.logUserUpdate(
          user.id,
          user.companyId,
          user.id,
          currentUser,
          updatedUser
        );

        // Create notification if phone was changed
        if (body.phone) {
          await app.prisma.notification.create({
            data: {
              userId: user.id,
              companyId: user.companyId,
              type: 'SYSTEM',
              title: 'Phone Number Updated',
              message: 'Your phone number has been updated and requires verification.',
              data: {
                phoneUpdated: true,
                requiresVerification: true,
              },
            },
          });
        }

        return {
          success: true,
          message: 'Profile updated successfully',
          profile: {
            id: updatedUser.id,
            fullName: updatedUser.fullName,
            phone: updatedUser.phone,
            phoneVerified: updatedUser.phoneVerified,
            address: updatedUser.address,
            profileImage: updatedUser.profileImage,
            emergencyContactName: updatedUser.emergencyContactName,
            emergencyContactPhone: updatedUser.emergencyContactPhone,
            updatedAt: updatedUser.updatedAt,
          },
        };

      } catch (error: any) {
        app.log.error('Failed to update profile:', error);
        throw error;
      }
    }
  );

  // Change password
  app.post(
    '/profile/change-password',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        body: {
          type: 'object',
          required: ['currentPassword', 'newPassword', 'confirmPassword'],
          properties: {
            currentPassword: { type: 'string' },
            newPassword: { type: 'string', minLength: 12 },
            confirmPassword: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const body = request.body as ChangePasswordBody;
      const ipAddress = request.ip;

      try {
        // Validate new password
        if (body.newPassword !== body.confirmPassword) {
          throw new ValidationError('New passwords do not match');
        }

        // Check password strength
        const passwordStrength = SecurityUtils.checkPasswordStrength(body.newPassword);
        if (passwordStrength.strength === 'weak' || passwordStrength.strength === 'fair') {
          throw new ValidationError('New password is too weak. ' + passwordStrength.feedback.join(' '));
        }

        // Get user with password hash
        const dbUser = await app.prisma.user.findUnique({
          where: { id: user.id },
        });

        if (!dbUser) {
          throw new NotFoundError('User');
        }

        // Verify current password
        const validCurrentPassword = await SecurityUtils.verifyPassword(
          body.currentPassword,
          dbUser.passwordHash
        );

        if (!validCurrentPassword) {
          await auditLogger.logSecurityEvent(user.id, user.companyId, 'PASSWORD_CHANGE_FAILED', {
            reason: 'INVALID_CURRENT_PASSWORD',
            ipAddress,
          });

          throw new ValidationError('Current password is incorrect');
        }

        // Check if new password is same as current
        const sameAsCurrent = await SecurityUtils.verifyPassword(
          body.newPassword,
          dbUser.passwordHash
        );

        if (sameAsCurrent) {
          throw new ValidationError('New password must be different from current password');
        }

        // Hash new password
        const newPasswordHash = await SecurityUtils.hashPassword(body.newPassword);

        // Update password
        await app.prisma.user.update({
          where: { id: user.id },
          data: {
            passwordHash: newPasswordHash,
            lastPasswordChangeAt: new Date(),
            mustChangePassword: false,
            failedLoginAttempts: 0,
            lockedUntil: null,
          },
        });

        // Log password change
        await auditLogger.logPasswordChange(user.id, user.companyId, user.id);

        // Invalidate all sessions except current
        const currentToken = request.authToken;
        await app.prisma.session.updateMany({
          where: {
            userId: user.id,
            token: { not: currentToken },
            isValid: true,
          },
          data: { isValid: false },
        });

        // Create notification
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SYSTEM',
            title: 'Password Changed',
            message: 'Your password has been changed successfully. All other sessions have been logged out.',
            data: {
              passwordChanged: true,
              sessionsInvalidated: true,
            },
          },
        });

        return {
          success: true,
          message: 'Password changed successfully. All other sessions have been logged out.',
        };

      } catch (error: any) {
        app.log.error('Failed to change password:', error);
        throw error;
      }
    }
  );

  // Set PIN (first time)
  app.post(
    '/profile/set-pin',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        body: {
          type: 'object',
          required: ['pin', 'confirmPin'],
          properties: {
            pin: { type: 'string', pattern: '^\\d{6}$' },
            confirmPin: { type: 'string', pattern: '^\\d{6}$' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const body = request.body as SetPinBody;
      const ipAddress = request.ip;
      const deviceId = request.deviceId;

      try {
        // Validate PINs match
        if (body.pin !== body.confirmPin) {
          throw new ValidationError('PINs do not match');
        }

        // Check if user already has PIN
        const dbUser = await app.prisma.user.findUnique({
          where: { id: user.id },
        });

        if (!dbUser) {
          throw new NotFoundError('User');
        }

        if (dbUser.pinHash) {
          throw new ConflictError('PIN is already set');
        }

        // Hash PIN
        const pinHash = await SecurityUtils.hashPin(body.pin);

        // Update user with PIN
        await app.prisma.user.update({
          where: { id: user.id },
          data: {
            pinHash,
            pinSetAt: new Date(),
          },
        });

        // Enable PIN on current device if device ID is available
        if (deviceId) {
          await app.prisma.device.updateMany({
            where: {
              deviceId,
              userId: user.id,
            },
            data: {
              pinEnabled: true,
            },
          });
        }

        // Log PIN setup
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'PIN_SET',
          entityType: 'User',
          entityId: user.id,
          description: 'PIN set for the first time',
          metadata: {
            deviceId,
            ipAddress,
          },
          severity: 'INFO',
        });

        // Create notification
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SYSTEM',
            title: 'PIN Set Successfully',
            message: 'Your 6-digit PIN has been set up successfully.',
            data: {
              pinSet: true,
              deviceId,
            },
          },
        });

        return {
          success: true,
          message: 'PIN set successfully',
        };

      } catch (error: any) {
        app.log.error('Failed to set PIN:', error);
        throw error;
      }
    }
  );

  // Update PIN
  app.post(
    '/profile/update-pin',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        body: {
          type: 'object',
          required: ['currentPin', 'newPin', 'confirmPin'],
          properties: {
            currentPin: { type: 'string', pattern: '^\\d{6}$' },
            newPin: { type: 'string', pattern: '^\\d{6}$' },
            confirmPin: { type: 'string', pattern: '^\\d{6}$' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const body = request.body as UpdatePinBody;
      const ipAddress = request.ip;

      try {
        // Validate new PINs match
        if (body.newPin !== body.confirmPin) {
          throw new ValidationError('New PINs do not match');
        }

        // Check if new PIN is same as current
        if (body.currentPin === body.newPin) {
          throw new ValidationError('New PIN must be different from current PIN');
        }

        // Get user with PIN hash
        const dbUser = await app.prisma.user.findUnique({
          where: { id: user.id },
        });

        if (!dbUser) {
          throw new NotFoundError('User');
        }

        if (!dbUser.pinHash) {
          throw new ValidationError('PIN is not set. Please set a PIN first.');
        }

        // Verify current PIN
        const validCurrentPin = await SecurityUtils.verifyPin(
          body.currentPin,
          dbUser.pinHash
        );

        if (!validCurrentPin) {
          await auditLogger.logSecurityEvent(user.id, user.companyId, 'PIN_UPDATE_FAILED', {
            reason: 'INVALID_CURRENT_PIN',
            ipAddress,
          });

          throw new ValidationError('Current PIN is incorrect');
        }

        // Hash new PIN
        const newPinHash = await SecurityUtils.hashPin(body.newPin);

        // Update PIN
        await app.prisma.user.update({
          where: { id: user.id },
          data: {
            pinHash: newPinHash,
            pinSetAt: new Date(),
          },
        });

        // Log PIN update
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'PIN_UPDATE',
          entityType: 'User',
          entityId: user.id,
          description: 'PIN updated',
          metadata: {
            ipAddress,
          },
          severity: 'INFO',
        });

        // Create notification
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SYSTEM',
            title: 'PIN Updated',
            message: 'Your 6-digit PIN has been updated successfully.',
          },
        });

        return {
          success: true,
          message: 'PIN updated successfully',
        };

      } catch (error: any) {
        app.log.error('Failed to update PIN:', error);
        throw error;
      }
    }
  );

  // Verify PIN (for sensitive operations)
  app.post(
    '/profile/verify-pin',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        body: {
          type: 'object',
          required: ['pin'],
          properties: {
            pin: { type: 'string', pattern: '^\\d{6}$' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const body = request.body as VerifyPinBody;
      const ipAddress = request.ip;

      try {
        // Get user with PIN hash
        const dbUser = await app.prisma.user.findUnique({
          where: { id: user.id },
        });

        if (!dbUser) {
          throw new NotFoundError('User');
        }

        if (!dbUser.pinHash) {
          throw new ValidationError('PIN is not set');
        }

        // Verify PIN
        const validPin = await SecurityUtils.verifyPin(body.pin, dbUser.pinHash);

        if (!validPin) {
          await auditLogger.logSecurityEvent(user.id, user.companyId, 'PIN_VERIFICATION_FAILED', {
            reason: 'INVALID_PIN',
            ipAddress,
            operation: request.url,
          });

          throw new ValidationError('Invalid PIN');
        }

        // Log successful verification
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'PIN_VERIFIED',
          entityType: 'User',
          entityId: user.id,
          description: 'PIN verified for sensitive operation',
          metadata: {
            operation: request.url,
            ipAddress,
          },
          severity: 'INFO',
        });

        // Generate temporary token for sensitive operation (valid for 5 minutes)
        const tempToken = app.jwt.sign({
          userId: user.id,
          pinVerified: true,
          expiresIn: '5m',
        });

        return {
          success: true,
          message: 'PIN verified successfully',
          tempToken,
          expiresIn: '5 minutes',
        };

      } catch (error: any) {
        app.log.error('PIN verification failed:', error);
        throw error;
      }
    }
  );

  // Remove PIN
  app.delete(
    '/profile/pin',
    {
      preHandler: [app.authenticate, app.requireApproved],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const ipAddress = request.ip;

      try {
        // Get user
        const dbUser = await app.prisma.user.findUnique({
          where: { id: user.id },
        });

        if (!dbUser) {
          throw new NotFoundError('User');
        }

        if (!dbUser.pinHash) {
          throw new ValidationError('PIN is not set');
        }

        // Remove PIN from all devices
        await app.prisma.device.updateMany({
          where: { userId: user.id },
          data: { pinEnabled: false },
        });

        // Remove PIN from user
        await app.prisma.user.update({
          where: { id: user.id },
          data: {
            pinHash: null,
            pinSetAt: null,
          },
        });

        // Log PIN removal
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'PIN_REMOVED',
          entityType: 'User',
          entityId: user.id,
          description: 'PIN removed from account',
          metadata: {
            ipAddress,
          },
          severity: 'WARNING',
        });

        // Create notification
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SYSTEM',
            title: 'PIN Removed',
            message: 'Your 6-digit PIN has been removed from your account.',
            data: {
              pinRemoved: true,
            },
          },
        });

        return {
          success: true,
          message: 'PIN removed successfully',
        };

      } catch (error: any) {
        app.log.error('Failed to remove PIN:', error);
        throw error;
      }
    }
  );

  // Upload profile image
  app.post(
    '/profile/image',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        consumes: ['multipart/form-data'],
        body: {
          type: 'object',
          required: ['image'],
          properties: {
            image: { isFile: true },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const ipAddress = request.ip;

      try {
        // This endpoint requires file upload handling
        // In a real implementation, you would:
        // 1. Validate file type and size
        // 2. Upload to S3 or similar storage
        // 3. Get the URL and save to user profile

        // For now, return a mock response
        const mockImageUrl = `https://storage.example.com/profiles/${user.id}/avatar-${Date.now()}.jpg`;

        // Update user profile with image URL
        await app.prisma.user.update({
          where: { id: user.id },
          data: { profileImage: mockImageUrl },
        });

        // Log profile image update
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'PROFILE_IMAGE_UPLOAD',
          entityType: 'User',
          entityId: user.id,
          description: 'Profile image uploaded',
          metadata: {
            imageUrl: mockImageUrl,
            ipAddress,
          },
        });

        return {
          success: true,
          message: 'Profile image uploaded successfully',
          imageUrl: mockImageUrl,
        };

      } catch (error: any) {
        app.log.error('Failed to upload profile image:', error);
        throw error;
      }
    }
  );

  // Get user statistics
  app.get(
    '/profile/stats',
    {
      preHandler: [app.authenticate, app.requireApproved],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;

      try {
        // Get counts for user activities
        const [
          sessionCount,
          deviceCount,
          notificationCount,
          unreadNotificationCount,
          auditLogCount,
        ] = await Promise.all([
          // Active sessions
          app.prisma.session.count({
            where: {
              userId: user.id,
              isValid: true,
              expiresAt: { gt: new Date() },
            },
          }),

          // Registered devices
          app.prisma.device.count({
            where: { userId: user.id },
          }),

          // Total notifications
          app.prisma.notification.count({
            where: { userId: user.id },
          }),

          // Unread notifications
          app.prisma.notification.count({
            where: {
              userId: user.id,
              isRead: false,
            },
          }),

          // Recent audit logs (last 30 days)
          app.prisma.auditLog.count({
            where: {
              userId: user.id,
              createdAt: {
                gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
              },
            },
          }),
        ]);

        return {
          success: true,
          stats: {
            sessions: {
              active: sessionCount,
              maxAllowed: 5,
            },
            devices: {
              registered: deviceCount,
              trusted: await app.prisma.device.count({
                where: { userId: user.id, isTrusted: true },
              }),
              maxAllowed: 10,
            },
            notifications: {
              total: notificationCount,
              unread: unreadNotificationCount,
            },
            security: {
              recentActivities: auditLogCount,
              lastPasswordChange: await app.prisma.user
                .findUnique({
                  where: { id: user.id },
                  select: { lastPasswordChangeAt: true },
                })
                .then(user => user?.lastPasswordChangeAt),
              pinSet: !!user.pinSet,
            },
          },
        };

      } catch (error: any) {
        app.log.error('Failed to fetch user stats:', error);
        throw error;
      }
    }
  );
}
