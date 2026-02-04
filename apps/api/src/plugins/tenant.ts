import fp from 'fastify-plugin';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

export default fp(async (app: FastifyInstance) => {
  // Company scope middleware
  app.decorate('withCompanyScope', async (request: FastifyRequest, reply: FastifyReply) => {
    const user = request.currentUser;

    if (!user) {
      return reply.status(401).send({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED',
      });
    }

    // Creator can specify company ID in header or query
    if (user.isCreator) {
      const companyId =
        request.headers['x-company-id']?.toString() ||
        (request.query as any).companyId;

      if (companyId) {
        // Verify company exists
        const company = await app.prisma.company.findUnique({
          where: { id: companyId },
        });

        if (!company) {
          return reply.status(404).send({
            error: 'Company not found',
            code: 'COMPANY_NOT_FOUND',
            message: 'The specified company does not exist',
          });
        }

        request.companyId = companyId;
        request.company = company;
      } else if (user.companyId) {
        // Use creator's default company
        request.companyId = user.companyId;
      }
    } else {
      // Non-creator users must have company context
      if (!user.companyId) {
        return reply.status(400).send({
          error: 'No company context',
          code: 'NO_COMPANY_CONTEXT',
          message: 'Your account is not associated with any company',
        });
      }

      request.companyId = user.companyId;
    }

    // Verify company exists and is active
    if (request.companyId) {
      const company = await app.prisma.company.findUnique({
        where: { id: request.companyId },
      });

      if (!company) {
        return reply.status(404).send({
          error: 'Company not found',
          code: 'COMPANY_NOT_FOUND',
          message: 'The associated company no longer exists',
        });
      }

      if (!company.isActive) {
        return reply.status(403).send({
          error: 'Company inactive',
          code: 'COMPANY_INACTIVE',
          message: 'The associated company is not active',
        });
      }

      request.company = company;
    }
  });

  // Data isolation middleware for specific models
  app.decorate('isolateData', (modelName: string) => {
    return async (request: FastifyRequest, reply: FastifyReply) => {
      await app.withCompanyScope(request, reply);

      if (reply.sent) return;

      // Modify request query/params to include company filter
      if (request.params && (request.params as any).id) {
        // For single resource access
        const resource = await (app.prisma as any)[modelName].findUnique({
          where: { id: (request.params as any).id },
        });

        if (!resource) {
          return reply.status(404).send({
            error: 'Resource not found',
            code: 'RESOURCE_NOT_FOUND',
          });
        }

        // Check company access
        if (resource.companyId !== request.companyId && !request.currentUser?.isCreator) {
          return reply.status(403).send({
            error: 'Access denied',
            code: 'ACCESS_DENIED',
            message: 'You do not have access to this resource',
          });
        }

        request.resource = resource;
      } else {
        // For list requests, add company filter to query
        const query = request.query || {};
        (request as any).query = {
          ...query,
          companyId: request.companyId,
        };
      }
    };
  });

  // Company membership validation
  app.decorate('validateCompanyMembership', async (request: FastifyRequest, reply: FastifyReply, userId?: string) => {
    await app.withCompanyScope(request, reply);

    if (reply.sent) return;

    const targetUserId = userId || (request.body as any).userId || (request.params as any).userId;

    if (!targetUserId) {
      return reply.status(400).send({
        error: 'User ID required',
        code: 'USER_ID_REQUIRED',
      });
    }

    // Check if user belongs to the same company
    const targetUser = await app.prisma.user.findUnique({
      where: { id: targetUserId },
      select: { companyId: true, isCreator: true },
    });

    if (!targetUser) {
      return reply.status(404).send({
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    // Creator can access any user
    if (request.currentUser?.isCreator) {
      return;
    }

    // Check company membership
    if (targetUser.companyId !== request.companyId) {
      return reply.status(403).send({
        error: 'Access denied',
        code: 'CROSS_COMPANY_ACCESS',
        message: 'You cannot access users from other companies',
      });
    }
  });

  // Add tenant utilities to app instance
  app.decorate('tenant', {
    switchCompany: async (userId: string, companyId: string): Promise<boolean> => {
      const user = await app.prisma.user.findUnique({
        where: { id: userId },
        include: {
          company: true,
        },
      });

      if (!user) return false;

      // Only creator can switch companies freely
      if (!user.isCreator) {
        return false;
      }

      const company = await app.prisma.company.findUnique({
        where: { id: companyId },
      });

      if (!company) return false;

      // Update user's current company
      await app.prisma.user.update({
        where: { id: userId },
        data: { companyId },
      });

      return true;
    },

    getUserCompanies: async (userId: string): Promise<any[]> => {
      const user = await app.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) return [];

      if (user.isCreator) {
        // Creator can access all companies
        return await app.prisma.company.findMany({
          where: { isActive: true },
          orderBy: { name: 'asc' },
        });
      }

      // Regular users only have their company
      if (user.companyId) {
        const company = await app.prisma.company.findUnique({
          where: { id: user.companyId },
        });

        return company ? [company] : [];
      }

      return [];
    },
  });
});

declare module 'fastify' {
  interface FastifyInstance {
    withCompanyScope: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    isolateData: (modelName: string) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    validateCompanyMembership: (request: FastifyRequest, reply: FastifyReply, userId?: string) => Promise<void>;
    tenant: {
      switchCompany: (userId: string, companyId: string) => Promise<boolean>;
      getUserCompanies: (userId: string) => Promise<any[]>;
    };
  }

  interface FastifyRequest {
    companyId?: string;
    company?: any;
    resource?: any;
  }
}
