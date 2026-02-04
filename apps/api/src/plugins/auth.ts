import fp from 'fastify-plugin';
import jwt from '@fastify/jwt';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { User, Company, Role, Permission } from '@prisma/client';

export interface AuthUser {
  id: string;
  email: string;
  companyId?: string;
  isCreator: boolean;
  isSuperAdmin: boolean;
  isCompanyAdmin: boolean;
  status: string;
  approvalStatus: string;
  permissions: Set<string>;
  roles: Array<{
    id: string;
    name: string;
    level: number;
  }>;
}

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireApproved: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireCreator: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireCompanyAdmin: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }

  interface FastifyRequest {
    currentUser?: AuthUser;
    authToken?: string;
    deviceId?: string;
  }
}

export default fp(async (app: FastifyInstance) => {
  // Register JWT plugin
  await app.register(jwt, {
    secret: process.env.JWT_SECRET || 'dev-secret-change-in-production',
    sign: {
      expiresIn: process.env.JWT_EXPIRES_IN || '24h',
      issuer: 'quantum-finance-engine',
      audience: 'qfe-users',
    },
    verify: {
      maxAge: process.env.JWT_MAX_AGE || '24h',
    },
    cookie: {
      cookieName: 'qfe_token',
      signed: false,
    },
  });

  // Authentication middleware
  app.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Extract token from Authorization header or cookie
      let token: string | undefined;

      // Check Authorization header
      const authHeader = request.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }

      // Check cookie
      if (!token && request.cookies.qfe_token) {
        token = request.cookies.qfe_token;
      }

      if (!token) {
        return reply.status(401).send({
          error: 'Authentication required',
          code: 'AUTH_REQUIRED',
          message: 'No authentication token provided',
        });
      }

      // Verify JWT token
      const decoded = await request.jwtVerify<{
        userId: string;
        sessionId?: string;
        deviceId?: string;
        companyId?: string;
      }>();

      // Store token and device ID
      request.authToken = token;
      request.deviceId = decoded.deviceId;

      // Load user with permissions
      const user = await app.prisma.user.findUnique({
        where: { id: decoded.userId },
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

      if (!user) {
        return reply.status(401).send({
          error: 'Invalid credentials',
          code: 'USER_NOT_FOUND',
          message: 'User account not found',
        });
      }

      // Check if account is active
      if (user.status !== 'ACTIVE') {
        return reply.status(403).send({
          error: 'Account suspended',
          code: 'ACCOUNT_SUSPENDED',
          message: 'Your account has been suspended',
          status: user.status,
        });
      }

      // Check if account is approved
      if (user.approvalStatus !== 'APPROVED') {
        return reply.status(403).send({
          error: 'Account pending approval',
          code: 'PENDING_APPROVAL',
          message: 'Your account is pending approval by an administrator',
          status: user.approvalStatus,
        });
      }

      // Check if account is locked due to failed attempts
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        const lockMinutes = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
        return reply.status(423).send({
          error: 'Account locked',
          code: 'ACCOUNT_LOCKED',
          message: `Account locked due to too many failed login attempts. Try again in ${lockMinutes} minutes.`,
          lockedUntil: user.lockedUntil,
        });
      }

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
        // Add all possible permissions
        const allPermissions = await app.prisma.permission.findMany();
        for (const perm of allPermissions) {
          permissions.add(`${perm.module}:${perm.action}`);
        }
      }

      // Create auth user object
      const authUser: AuthUser = {
        id: user.id,
        email: user.email,
        companyId: user.companyId || undefined,
        isCreator: user.isCreator,
        isSuperAdmin: user.isSuperAdmin,
        isCompanyAdmin: user.isCompanyAdmin,
        status: user.status,
        approvalStatus: user.approvalStatus,
        permissions,
        roles,
      };

      // Store in request
      request.currentUser = authUser;

      // Update last activity
      await app.prisma.user.update({
        where: { id: user.id },
        data: { lastActiveAt: new Date() },
      });

    } catch (error: any) {
      app.log.error('Authentication error:', error);

      if (error.code === 'FST_JWT_NO_AUTHORIZATION_IN_HEADER') {
        return reply.status(401).send({
          error: 'Authentication required',
          code: 'AUTH_REQUIRED',
          message: 'No authentication token provided',
        });
      }

      if (error.code === 'FST_JWT_AUTHORIZATION_TOKEN_EXPIRED') {
        return reply.status(401).send({
          error: 'Token expired',
          code: 'TOKEN_EXPIRED',
          message: 'Your session has expired. Please login again.',
        });
      }

      if (error.code === 'FST_JWT_AUTHORIZATION_TOKEN_INVALID') {
        return reply.status(401).send({
          error: 'Invalid token',
          code: 'TOKEN_INVALID',
          message: 'Invalid authentication token',
        });
      }

      return reply.status(401).send({
        error: 'Authentication failed',
        code: 'AUTH_FAILED',
        message: 'Failed to authenticate user',
      });
    }
  });

  // Require approved account middleware
  app.decorate('requireApproved', async (request: FastifyRequest, reply: FastifyReply) => {
    const user = request.currentUser;

    if (!user) {
      return reply.status(401).send({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED',
      });
    }

    if (user.approvalStatus !== 'APPROVED') {
      return reply.status(403).send({
        error: 'Account not approved',
        code: 'ACCOUNT_NOT_APPROVED',
        message: 'Your account must be approved by an administrator',
      });
    }
  });

  // Require creator middleware
  app.decorate('requireCreator', async (request: FastifyRequest, reply: FastifyReply) => {
    const user = request.currentUser;

    if (!user) {
      return reply.status(401).send({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED',
      });
    }

    if (!user.isCreator) {
      return reply.status(403).send({
        error: 'Creator access required',
        code: 'CREATOR_REQUIRED',
        message: 'This action requires creator-level access',
      });
    }
  });

  // Require company admin middleware
  app.decorate('requireCompanyAdmin', async (request: FastifyRequest, reply: FastifyReply) => {
    const user = request.currentUser;

    if (!user) {
      return reply.status(401).send({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED',
      });
    }

    if (!user.isCompanyAdmin && !user.isCreator) {
      return reply.status(403).send({
        error: 'Admin access required',
        code: 'ADMIN_REQUIRED',
        message: 'This action requires company administrator access',
      });
    }
  });

  // Add auth-related utilities to app instance
  app.decorate('auth', {
    generateSessionToken: () => {
      return require('crypto').randomBytes(32).toString('hex');
    },

    generateRefreshToken: () => {
      return require('crypto').randomBytes(40).toString('hex');
    },

    generateVerificationToken: () => {
      return require('crypto').randomBytes(20).toString('hex');
    },

    hashPin: async (pin: string) => {
      const bcrypt = require('bcryptjs');
      const salt = await bcrypt.genSalt(10);
      return await bcrypt.hash(pin, salt);
    },

    verifyPin: async (pin: string, hash: string) => {
      const bcrypt = require('bcryptjs');
      return await bcrypt.compare(pin, hash);
    },
  });
});
