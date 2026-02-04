import Fastify, { FastifyInstance, FastifyServerOptions } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import multipart from '@fastify/multipart';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import sensible from '@fastify/sensible';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';

// Import plugins
import prismaPlugin from './plugins/prisma';
import authPlugin from './plugins/auth';
import rbacPlugin from './plugins/rbac';
import tenantPlugin from './plugins/tenant';
import auditPlugin from './plugins/audit';
import notificationPlugin from './plugins/notification';

// Import routes
import { healthRoutes } from './routes/health';
import { authRoutes } from './routes/auth';
import { userRoutes } from './routes/users';
import { companyRoutes } from './routes/companies';
import { roleRoutes } from './routes/roles';
import { expenseRoutes } from './routes/expenses';
import { incomeRoutes } from './routes/income';
import { projectRoutes } from './routes/projects';
import { dashboardRoutes } from './routes/dashboard';
import { settingsRoutes } from './routes/settings';
import { notificationRoutes } from './routes/notifications';
import { reportRoutes } from './routes/reports';

// Import error handler
import { errorHandler } from './utils/errors';

export async function buildServer(opts: FastifyServerOptions = {}): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL || 'info',
      transport: {
        target: 'pino-pretty',
        options: {
          translateTime: 'HH:MM:ss Z',
          ignore: 'pid,hostname',
        },
      },
    },
    disableRequestLogging: process.env.NODE_ENV === 'production',
    trustProxy: process.env.NODE_ENV === 'production',
    ...opts,
  });

  // ==================== REGISTER PLUGINS ====================

  // Security plugins
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
  });

  await app.register(cors, {
    origin: process.env.NODE_ENV === 'production'
      ? [process.env.FRONTEND_URL!]
      : ['http://localhost:3000', 'http://localhost:3001'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Company-Id'],
  });

  await app.register(rateLimit, {
    max: Number(process.env.API_RATE_LIMIT) || 100,
    timeWindow: '1 minute',
    keyGenerator: (request) => {
      return request.ip;
    },
    errorResponseBuilder: (request, context) => {
      return {
        statusCode: 429,
        error: 'Too Many Requests',
        message: `Rate limit exceeded. Try again in ${context.after}`,
        code: 'RATE_LIMIT_EXCEEDED',
      };
    },
  });

  // Utility plugins
  await app.register(sensible);
  await app.register(cookie, {
    secret: process.env.SESSION_SECRET,
    parseOptions: {},
  });
  await app.register(formbody);
  await app.register(multipart, {
    limits: {
      fileSize: 5 * 1024 * 1024, // 5MB
      files: 10,
    },
  });

  // Documentation
  if (process.env.NODE_ENV === 'development') {
    await app.register(swagger, {
      swagger: {
        info: {
          title: 'Quantum Finance Engine API',
          description: 'Complete financial management system API',
          version: '1.0.0',
        },
        externalDocs: {
          url: 'https://docs.quantumfinance.dev',
          description: 'API Documentation',
        },
        host: 'localhost:4000',
        schemes: ['http'],
        consumes: ['application/json'],
        produces: ['application/json'],
        securityDefinitions: {
          bearerAuth: {
            type: 'apiKey',
            name: 'Authorization',
            in: 'header',
            description: 'Bearer token authorization',
          },
        },
      },
    });

    await app.register(swaggerUi, {
      routePrefix: '/docs',
      uiConfig: {
        docExpansion: 'list',
        deepLinking: false,
      },
    });
  }

  // Custom plugins
  await app.register(prismaPlugin);
  await app.register(authPlugin);
  await app.register(rbacPlugin);
  await app.register(tenantPlugin);
  await app.register(auditPlugin);
  await app.register(notificationPlugin);

  // ==================== ERROR HANDLING ====================

  app.setErrorHandler(errorHandler);

  // Not found handler
  app.setNotFoundHandler((request, reply) => {
    reply.status(404).send({
      error: 'Not Found',
      code: 'NOT_FOUND',
      message: `Route ${request.method}:${request.url} not found`,
    });
  });

  // ==================== REGISTER ROUTES ====================

  // Health check (public)
  await app.register(healthRoutes, { prefix: '/health' });

  // Auth routes (public)
  await app.register(authRoutes, { prefix: '/auth' });

  // Protected routes (require authentication)
  await app.register(userRoutes, { prefix: '/users' });
  await app.register(companyRoutes, { prefix: '/companies' });
  await app.register(roleRoutes, { prefix: '/roles' });
  await app.register(expenseRoutes, { prefix: '/expenses' });
  await app.register(incomeRoutes, { prefix: '/income' });
  await app.register(projectRoutes, { prefix: '/projects' });
  await app.register(dashboardRoutes, { prefix: '/dashboard' });
  await app.register(settingsRoutes, { prefix: '/settings' });
  await app.register(notificationRoutes, { prefix: '/notifications' });
  await app.register(reportRoutes, { prefix: '/reports' });

  // ==================== STARTUP HOOKS ====================

  app.addHook('onReady', async () => {
    try {
      // Test database connection
      await app.prisma.$queryRaw`SELECT 1`;
      app.log.info('✅ Database connection established');
    } catch (error) {
      app.log.error('❌ Database connection failed:', error);
      process.exit(1);
    }
  });

  app.addHook('onClose', async () => {
    await app.prisma.$disconnect();
    app.log.info('Server closed gracefully');
  });

  return app;
}

export async function startServer() {
  try {
    const server = await buildServer();
    const port = Number(process.env.PORT) || 4000;
    const host = process.env.HOST || '0.0.0.0';

    await server.listen({ port, host });

    console.log(`
🚀 Quantum Finance Engine API Server Started!
   Environment: ${process.env.NODE_ENV || 'development'}
   URL: http://${host}:${port}
   Docs: http://${host}:${port}/docs
   Health: http://${host}:${port}/health
   PID: ${process.pid}
    `);

    return server;
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start server if this file is run directly
if (require.main === module) {
  startServer();
}