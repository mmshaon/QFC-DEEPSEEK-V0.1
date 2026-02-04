import fp from 'fastify-plugin';
import { PrismaClient } from '@prisma/client';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

// Extend PrismaClient with custom methods
class ExtendedPrismaClient extends PrismaClient {
  // Transaction helper with automatic retry
  async $transactionWithRetry<T>(
    fn: (prisma: PrismaClient) => Promise<T>,
    maxRetries: number = 3
  ): Promise<T> {
    let lastError: Error;

    for (let i = 0; i < maxRetries; i++) {
      try {
        return await this.$transaction(fn);
      } catch (error: any) {
        lastError = error;

        // Retry on deadlock or serialization failure
        if (error.code === 'P2034' || error.code === 'P1008') {
          await new Promise(resolve => setTimeout(resolve, Math.pow(2, i) * 100));
          continue;
        }
        throw error;
      }
    }

    throw lastError!;
  }

  // Safe find with company isolation
  async findWithCompanyIsolation<T extends { companyId?: string }>(
    model: keyof PrismaClient,
    where: any,
    user: any
  ): Promise<T | null> {
    // Creator can access any company's data
    if (user?.isCreator) {
      return (this as any)[model].findUnique({ where });
    }

    // Non-creator users must have company context
    if (!user?.companyId) {
      throw new Error('No company context available');
    }

    // Add company filter
    const companyWhere = {
      ...where,
      companyId: user.companyId
    };

    return (this as any)[model].findUnique({ where: companyWhere });
  }

  // Safe findMany with company isolation
  async findManyWithCompanyIsolation<T extends { companyId?: string }>(
    model: keyof PrismaClient,
    where: any,
    user: any,
    options?: any
  ): Promise<T[]> {
    // Creator can access any company's data
    if (user?.isCreator) {
      return (this as any)[model].findMany({ where, ...options });
    }

    // Non-creator users must have company context
    if (!user?.companyId) {
      throw new Error('No company context available');
    }

    // Add company filter
    const companyWhere = {
      ...where,
      companyId: user.companyId
    };

    return (this as any)[model].findMany({ where: companyWhere, ...options });
  }
}

const prisma = new ExtendedPrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
  errorFormat: 'pretty',
});

export default fp(async (app: FastifyInstance) => {
  // Decorate fastify with prisma
  app.decorate('prisma', prisma);

  // Add health check endpoint
  app.addHook('onRoute', (route) => {
    if (route.url === '/health') {
      route.preHandler = async (request: FastifyRequest, reply: FastifyReply) => {
        try {
          // Test database connection
          await prisma.$queryRaw`SELECT 1`;
          request.dbHealthy = true;
        } catch (error) {
          request.dbHealthy = false;
          app.log.error('Database health check failed:', error);
        }
      };
    }
  });

  // Cleanup on server close
  app.addHook('onClose', async () => {
    await prisma.$disconnect();
  });

  // Log slow queries
  if (process.env.NODE_ENV === 'development') {
    prisma.$use(async (params, next) => {
      const start = Date.now();
      const result = await next(params);
      const duration = Date.now() - start;

      if (duration > 1000) { // Log queries longer than 1 second
        app.log.warn(`Slow query detected (${duration}ms):`, {
          model: params.model,
          action: params.action,
          duration,
        });
      }

      return result;
    });
  }
});

// Type declarations
declare module 'fastify' {
  interface FastifyInstance {
    prisma: ExtendedPrismaClient;
  }

  interface FastifyRequest {
    dbHealthy?: boolean;
  }
}
