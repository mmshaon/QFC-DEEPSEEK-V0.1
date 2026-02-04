import fp from 'fastify-plugin';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

export default fp(async (app: FastifyInstance) => {
  // Permission requirement middleware factory
  app.decorate('requirePermission', (moduleKey: string, action: string) => {
    return async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser;

      if (!user) {
        return reply.status(401).send({
          error: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
      }

      // Creator has all permissions
      if (user.isCreator) {
        return;
      }

      // Check if user has the required permission
      const requiredPermission = `${moduleKey}:${action}`;

      if (!user.permissions.has(requiredPermission)) {
        // Log permission denial
        await app.prisma.auditLog.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            actionType: 'PERMISSION_DENIED',
            entityType: moduleKey,
            description: `User attempted action '${action}' on module '${moduleKey}' without permission`,
            severity: 'WARNING',
            metadata: {
              requiredPermission,
              userPermissions: Array.from(user.permissions),
              requestPath: request.url,
              requestMethod: request.method,
            },
          },
        });

        return reply.status(403).send({
          error: 'Permission denied',
          code: 'PERMISSION_DENIED',
          message: `You do not have permission to ${action.toLowerCase()} ${moduleKey.toLowerCase()}`,
          requiredPermission,
          userPermissions: Array.from(user.permissions),
        });
      }
    };
  });

  // Module access middleware
  app.decorate('requireModuleAccess', (moduleKey: string) => {
    return async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser;

      if (!user) {
        return reply.status(401).send({
          error: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
      }

      // Creator has access to all modules
      if (user.isCreator) {
        return;
      }

      // Check if module is enabled for user's company
      const companyModule = await app.prisma.companyModule.findFirst({
        where: {
          companyId: user.companyId,
          module: {
            key: moduleKey,
          },
          isEnabled: true,
        },
        include: {
          module: true,
        },
      });

      if (!companyModule) {
        return reply.status(403).send({
          error: 'Module not available',
          code: 'MODULE_DISABLED',
          message: `The ${moduleKey} module is not available for your company`,
        });
      }

      // Check if module is locked
      if (companyModule.isLocked) {
        return reply.status(403).send({
          error: 'Module locked',
          code: 'MODULE_LOCKED',
          message: `The ${moduleKey} module is currently locked`,
        });
      }

      // Store module info in request for later use
      request.module = companyModule;
    };
  });

  // Role level requirement middleware
  app.decorate('requireRoleLevel', (minLevel: number) => {
    return async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser;

      if (!user) {
        return reply.status(401).send({
          error: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
      }

      // Creator has highest level
      if (user.isCreator) {
        return;
      }

      // Get user's highest role level
      const userLevel = Math.min(...user.roles.map(r => r.level));

      if (userLevel > minLevel) {
        return reply.status(403).send({
          error: 'Insufficient role level',
          code: 'ROLE_LEVEL_INSUFFICIENT',
          message: `This action requires role level ${minLevel} or higher. Your level is ${userLevel}.`,
          requiredLevel: minLevel,
          userLevel,
        });
      }
    };
  });

  // Add RBAC utilities to app instance
  app.decorate('rbac', {
    getUserPermissions: async (userId: string): Promise<Set<string>> => {
      const user = await app.prisma.user.findUnique({
        where: { id: userId },
        include: {
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

      const permissions = new Set<string>();

      if (user?.isCreator) {
        // Creator gets all permissions
        const allPerms = await app.prisma.permission.findMany();
        allPerms.forEach(p => permissions.add(`${p.module}:${p.action}`));
      } else if (user) {
        // Regular users get permissions from their roles
        user.roles.forEach(userRole => {
          userRole.role.permissions.forEach(rolePerm => {
            const perm = rolePerm.permission;
            permissions.add(`${perm.module}:${perm.action}`);
          });
        });
      }

      return permissions;
    },

    canUserAccessModule: async (userId: string, moduleKey: string): Promise<boolean> => {
      const user = await app.prisma.user.findUnique({
        where: { id: userId },
        include: {
          company: true,
        },
      });

      if (!user?.companyId) {
        return false;
      }

      // Creator can access all modules
      if (user.isCreator) {
        return true;
      }

      const companyModule = await app.prisma.companyModule.findFirst({
        where: {
          companyId: user.companyId,
          module: {
            key: moduleKey,
          },
          isEnabled: true,
          isLocked: false,
        },
      });

      return !!companyModule;
    },
  });
});

declare module 'fastify' {
  interface FastifyInstance {
    requirePermission: (moduleKey: string, action: string) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireModuleAccess: (moduleKey: string) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireRoleLevel: (minLevel: number) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    rbac: {
      getUserPermissions: (userId: string) => Promise<Set<string>>;
      canUserAccessModule: (userId: string, moduleKey: string) => Promise<boolean>;
    };
  }

  interface FastifyRequest {
    module?: any;
  }
}
