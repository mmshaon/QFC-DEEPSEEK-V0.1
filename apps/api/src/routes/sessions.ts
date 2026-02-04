import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { AuditLogger } from '../utils/audit';
import { SecurityUtils } from '../utils/security';
import { ValidationError, NotFoundError, AuthorizationError } from '../utils/errors';

interface CreateSessionBody {
  deviceId?: string;
  rememberMe?: boolean;
}

export async function sessionRoutes(app: FastifyInstance) {
  const auditLogger = new AuditLogger(app);

  // Create new session (login)
  app.post(
    '/sessions',
    {
      schema: {
        body: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string' },
            deviceId: { type: 'string' },
            deviceName: { type: 'string' },
            deviceType: {
              type: 'string',
              enum: ['WEB', 'ANDROID', 'IOS', 'DESKTOP']
            },
            rememberMe: { type: 'boolean', default: false },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as any;
      const ipAddress = request.ip;
      const userAgent = request.headers['user-agent'];

      try {
        // Rate limiting for login attempts
        const rateLimitKey = `login:${body.email}:${ipAddress}`;
        const rateLimit = await app.prisma.rateLimit.findUnique({
          where: { key: rateLimitKey },
        });

        const now = new Date();
        const lockDuration = 15 * 60 * 1000; // 15 minutes
        const maxAttempts = 5;

        if (rateLimit && rateReset.lockedUntil > now) {
          const lockMinutes = Math.ceil((rateReset.lockedUntil.getTime() - now.getTime()) / 60000);

          await auditLogger.logSecurityEvent(null, null, 'RATE_LIMIT_LOCKED', {
            email: body.email,
            ipAddress,
            lockMinutes,
          });

          throw new ValidationError(
            `Too many failed attempts. Account locked for ${lockMinutes} minutes.`
          );
        }

        // Find user by email
        const user = await app.prisma.user.findUnique({
          where: { email: body.email.toLowerCase() },
          include: {
            company: true,
            roles: {
              include: {
                role: {
                  include: {
                    permissions: {
                      include: {
                        permission: true,
                      },
                    },
                  },
                },
              },
            },
          },
        });

        // Validate user exists and is approved
        if (!user) {
          await handleFailedLogin(null, body.email, ipAddress, 'USER_NOT_FOUND');
          throw new ValidationError('Invalid email or password');
        }

        if (user.status !== 'ACTIVE') {
          await auditLogger.logLogin(user.id, user.companyId, false, {
            reason: 'ACCOUNT_INACTIVE',
            status: user.status,
            ipAddress,
          });

          throw new ValidationError(
            `Account is ${user.status.toLowerCase()}. Please contact administrator.`
          );
        }

        if (user.approvalStatus !== 'APPROVED') {
          await auditLogger.logLogin(user.id, user.companyId, false, {
            reason: 'PENDING_APPROVAL',
            status: user.approvalStatus,
            ipAddress,
          });

          throw new ValidationError(
            'Account pending approval. Please wait for administrator approval.'
          );
        }

        // Check if account is locked
        if (user.lockedUntil && user.lockedUntil > now) {
          const lockMinutes = Math.ceil((user.lockedUntil.getTime() - now.getTime()) / 60000);

          await auditLogger.logSecurityEvent(user.id, user.companyId, 'ACCOUNT_LOCKED', {
            lockedUntil: user.lockedUntil,
            lockMinutes,
            ipAddress,
          });

          throw new ValidationError(
            `Account locked due to too many failed attempts. Try again in ${lockMinutes} minutes.`
          );
        }

        // Verify password
        const validPassword = await SecurityUtils.verifyPassword(body.password, user.passwordHash);

        if (!validPassword) {
          await handleFailedLogin(user, body.email, ipAddress, 'INVALID_PASSWORD');
          throw new ValidationError('Invalid email or password');
        }

        // Reset failed attempts on successful login
        await app.prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: 0,
            lockedUntil: null,
            lastLoginAt: now,
            lastActiveAt: now,
          },
        });

        // Clear rate limit
        await app.prisma.rateLimit.deleteMany({
          where: { key: { startsWith: `login:${body.email}:` } },
        });

        // Register/update device
        let device;
        if (body.deviceId) {
          device = await app.prisma.device.upsert({
            where: { deviceId: body.deviceId },
            update: {
              deviceName: body.deviceName,
              deviceType: body.deviceType,
              lastUsedAt: now,
            },
            create: {
              userId: user.id,
              deviceId: body.deviceId,
              deviceName: body.deviceName || 'Unknown Device',
              deviceType: body.deviceType || 'WEB',
              lastUsedAt: now,
            },
          });
        }

        // Create session
        const sessionToken = SecurityUtils.generateSessionId();
        const sessionExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

        const session = await app.prisma.session.create({
          data: {
            userId: user.id,
            token: sessionToken,
            deviceId: device?.id,
            ipAddress,
            userAgent,
            isValid: true,
            expiresAt: sessionExpiry,
            lastActivityAt: now,
          },
        });

        // Create refresh token if remember me is enabled
        let refreshToken;
        if (body.rememberMe) {
          refreshToken = SecurityUtils.generateToken(40);
          const refreshExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

          await app.prisma.refreshToken.create({
            data: {
              userId: user.id,
              token: refreshToken,
              deviceId: device?.id,
              isValid: true,
              expiresAt: refreshExpiry,
            },
          });
        }

        // Generate JWT token
        const jwtToken = app.jwt.sign({
          userId: user.id,
          sessionId: session.id,
          deviceId: body.deviceId,
          companyId: user.companyId,
        });

        // Build permissions set
        const permissions = new Set<string>();
        const roles: Array<{ id: string; name: string; level: number }> = [];

        for (const userRole of user.roles) {
          roles.push({
            id: userRole.role.id,
            name: userRole.role.name,
            level: userRole.role.level,
          });

          for (const rolePermission of userRole.role.permissions) {
            const perm = rolePermission.permission;
            permissions.add(`${perm.module}:${perm.action}`);
          }
        }

        // Creator has all permissions
        if (user.isCreator) {
          const allPermissions = await app.prisma.permission.findMany();
          for (const perm of allPermissions) {
            permissions.add(`${perm.module}:${perm.action}`);
          }
        }

        // Log successful login
        await auditLogger.logLogin(user.id, user.companyId, true, {
          deviceId: body.deviceId,
          deviceType: body.deviceType,
          ipAddress,
          userAgent,
        });

        // Prepare response
        const response: any = {
          success: true,
          user: {
            id: user.id,
            email: user.email,
            fullName: user.fullName,
            phone: user.phone,
            profileImage: user.profileImage,
            isCreator: user.isCreator,
            isSuperAdmin: user.isSuperAdmin,
            isCompanyAdmin: user.isCompanyAdmin,
            companyId: user.companyId,
            company: user.company ? {
              id: user.company.id,
              name: user.company.name,
              logoUrl: user.company.logoUrl,
            } : null,
            roles,
            permissions: Array.from(permissions),
            mustChangePassword: user.mustChangePassword,
            pinSet: !!user.pinHash,
          },
          token: jwtToken,
          expiresAt: sessionExpiry,
        };

        if (refreshToken) {
          response.refreshToken = refreshToken;
        }

        // Set cookie
        reply.setCookie('qfe_token', jwtToken, {
          path: '/',
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          expires: sessionExpiry,
        });

        return response;

      } catch (error: any) {
        app.log.error('Login failed:', error);
        throw error;
      }
    }
  );

  // Refresh session
  app.post(
    '/sessions/refresh',
    {
      schema: {
        body: {
          type: 'object',
          required: ['refreshToken'],
          properties: {
            refreshToken: { type: 'string' },
            deviceId: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as any;
      const ipAddress = request.ip;
      const userAgent = request.headers['user-agent'];

      try {
        // Find valid refresh token
        const refreshToken = await app.prisma.refreshToken.findFirst({
          where: {
            token: body.refreshToken,
            isValid: true,
            expiresAt: { gt: new Date() },
          },
          include: {
            user: {
              include: {
                company: true,
              },
            },
            device: true,
          },
        });

        if (!refreshToken) {
          throw new ValidationError('Invalid or expired refresh token');
        }

        const user = refreshToken.user;

        // Validate user status
        if (user.status !== 'ACTIVE' || user.approvalStatus !== 'APPROVED') {
          await app.prisma.refreshToken.update({
            where: { id: refreshToken.id },
            data: { isValid: false },
          });

          throw new ValidationError('Account is not active');
        }

        // Update last activity
        await app.prisma.user.update({
          where: { id: user.id },
          data: { lastActiveAt: new Date() },
        });

        // Update device last used
        if (refreshToken.deviceId) {
          await app.prisma.device.update({
            where: { id: refreshToken.deviceId },
            data: { lastUsedAt: new Date() },
          });
        }

        // Create new session
        const sessionToken = SecurityUtils.generateSessionId();
        const sessionExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

        const session = await app.prisma.session.create({
          data: {
            userId: user.id,
            token: sessionToken,
            deviceId: refreshToken.deviceId,
            ipAddress,
            userAgent,
            isValid: true,
            expiresAt: sessionExpiry,
            lastActivityAt: new Date(),
          },
        });

        // Generate new JWT
        const jwtToken = app.jwt.sign({
          userId: user.id,
          sessionId: session.id,
          deviceId: refreshToken.device?.deviceId,
          companyId: user.companyId,
        });

        // Get user permissions
        const permissions = await app.rbac.getUserPermissions(user.id);

        // Log token refresh
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'SESSION_REFRESH',
          entityType: 'Session',
          entityId: session.id,
          description: 'Session refreshed using refresh token',
          metadata: {
            ipAddress,
            userAgent,
            deviceId: refreshToken.device?.deviceId,
          },
        });

        // Set cookie
        reply.setCookie('qfe_token', jwtToken, {
          path: '/',
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          expires: sessionExpiry,
        });

        return {
          success: true,
          token: jwtToken,
          expiresAt: sessionExpiry,
          user: {
            id: user.id,
            email: user.email,
            fullName: user.fullName,
            isCreator: user.isCreator,
            isCompanyAdmin: user.isCompanyAdmin,
            companyId: user.companyId,
            company: user.company ? {
              id: user.company.id,
              name: user.company.name,
            } : null,
            permissions: Array.from(permissions),
          },
        };

      } catch (error: any) {
        app.log.error('Session refresh failed:', error);
        throw error;
      }
    }
  );

  // Get current session
  app.get(
    '/sessions/current',
    {
      preHandler: [app.authenticate, app.requireApproved],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const authToken = request.authToken;

      try {
        // Find current session
        const session = await app.prisma.session.findFirst({
          where: {
            userId: user.id,
            token: authToken,
            isValid: true,
            expiresAt: { gt: new Date() },
          },
          include: {
            device: true,
          },
        });

        if (!session) {
          throw new ValidationError('Session not found or expired');
        }

        // Update last activity
        await app.prisma.session.update({
          where: { id: session.id },
          data: { lastActivityAt: new Date() },
        });

        return {
          success: true,
          session: {
            id: session.id,
            device: session.device ? {
              id: session.device.id,
              deviceId: session.device.deviceId,
              deviceName: session.device.deviceName,
              deviceType: session.device.deviceType,
            } : null,
            ipAddress: session.ipAddress,
            lastActivityAt: session.lastActivityAt,
            expiresAt: session.expiresAt,
            createdAt: session.createdAt,
          },
        };

      } catch (error: any) {
        app.log.error('Failed to fetch current session:', error);
        throw error;
      }
    }
  );

  // Get all active sessions
  app.get(
    '/sessions',
    {
      preHandler: [app.authenticate, app.requireApproved],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;

      try {
        const sessions = await app.prisma.session.findMany({
          where: {
            userId: user.id,
            isValid: true,
            expiresAt: { gt: new Date() },
          },
          include: {
            device: true,
          },
          orderBy: { lastActivityAt: 'desc' },
        });

        return {
          success: true,
          sessions: sessions.map(session => ({
            id: session.id,
            device: session.device ? {
              id: session.device.id,
              deviceId: session.device.deviceId,
              deviceName: session.device.deviceName,
              deviceType: session.device.deviceType,
            } : null,
            ipAddress: session.ipAddress,
            userAgent: session.userAgent,
            lastActivityAt: session.lastActivityAt,
            expiresAt: session.expiresAt,
            createdAt: session.createdAt,
          })),
        };

      } catch (error: any) {
        app.log.error('Failed to fetch sessions:', error);
        throw error;
      }
    }
  );

  // Logout (end specific session)
  app.delete(
    '/sessions/:sessionId',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        params: {
          type: 'object',
          required: ['sessionId'],
          properties: {
            sessionId: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const { sessionId } = request.params as { sessionId: string };
      const ipAddress = request.ip;

      try {
        // Find and invalidate session
        const session = await app.prisma.session.findFirst({
          where: {
            id: sessionId,
            userId: user.id,
          },
        });

        if (!session) {
          throw new NotFoundError('Session');
        }

        await app.prisma.session.update({
          where: { id: sessionId },
          data: { isValid: false },
        });

        await auditLogger.logLogout(user.id, user.companyId, {
          sessionId: session.id,
          ipAddress,
          manual: true,
        });

        // Clear cookie if this is the current session
        if (request.authToken === session.token) {
          reply.clearCookie('qfe_token');
        }

        return {
          success: true,
          message: 'Session ended successfully',
        };

      } catch (error: any) {
        app.log.error('Failed to end session:', error);
        throw error;
      }
    }
  );

  // Logout all sessions
  app.delete(
    '/sessions',
    {
      preHandler: [app.authenticate, app.requireApproved],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const ipAddress = request.ip;

      try {
        // Invalidate all user sessions
        await app.prisma.session.updateMany({
          where: {
            userId: user.id,
            isValid: true,
          },
          data: { isValid: false },
        });

        // Invalidate all refresh tokens
        await app.prisma.refreshToken.updateMany({
          where: {
            userId: user.id,
            isValid: true,
          },
          data: { isValid: false },
        });

        await auditLogger.logLogout(user.id, user.companyId, {
          allSessions: true,
          ipAddress,
          manual: true,
        });

        // Clear cookie
        reply.clearCookie('qfe_token');

        return {
          success: true,
          message: 'All sessions ended successfully',
        };

      } catch (error: any) {
        app.log.error('Failed to end all sessions:', error);
        throw error;
      }
    }
  );

  // Helper function for failed login handling
  async function handleFailedLogin(user: any, email: string, ipAddress: string, reason: string) {
    if (user) {
      // Increment failed attempts
      const failedAttempts = user.failedLoginAttempts + 1;
      let lockedUntil = null;

      // Lock account after 5 failed attempts
      if (failedAttempts >= 5) {
        lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
      }

      await app.prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: failedAttempts,
          lastFailedAttempt: new Date(),
          lockedUntil,
        },
      });

      await auditLogger.logLogin(user.id, user.companyId, false, {
        reason,
        failedAttempts,
        lockedUntil,
        ipAddress,
      });

      // Update rate limit
      const rateLimitKey = `login:${email}:${ipAddress}`;
      const existingLimit = await app.prisma.rateLimit.findUnique({
        where: { key: rateLimitKey },
      });

      if (existingLimit) {
        await app.prisma.rateLimit.update({
          where: { key: rateLimitKey },
          data: {
            attempts: existingLimit.attempts + 1,
            lockedUntil: failedAttempts >= 5 ? lockedUntil : existingLimit.lockedUntil,
          },
        });
      } else {
        await app.prisma.rateLimit.create({
          data: {
            key: rateLimitKey,
            attempts: 1,
            lockedUntil: failedAttempts >= 5 ? lockedUntil : null,
          },
        });
      }
    } else {
      // User not found, still track IP attempts
      await auditLogger.logSecurityEvent(null, null, 'FAILED_LOGIN_ATTEMPT', {
        email,
        ipAddress,
        reason,
      });
    }
  }
}
