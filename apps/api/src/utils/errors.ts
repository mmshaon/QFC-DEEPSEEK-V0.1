/**
 * Quantum Finance Engine - Error Handling Utilities
 */

export class AppError extends Error {
  constructor(
    public message: string,
    public statusCode: number = 500,
    public code: string = 'INTERNAL_ERROR',
    public details?: any
  ) {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationError extends AppError {
  constructor(message: string, details?: any) {
    super(message, 400, 'VALIDATION_ERROR', details);
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication failed') {
    super(message, 401, 'AUTHENTICATION_ERROR');
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string = 'Permission denied') {
    super(message, 403, 'AUTHORIZATION_ERROR');
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string = 'Resource') {
    super(`${resource} not found`, 404, 'NOT_FOUND');
  }
}

export class ConflictError extends AppError {
  constructor(message: string = 'Resource already exists') {
    super(message, 409, 'CONFLICT');
  }
}

export class RateLimitError extends AppError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 429, 'RATE_LIMIT_EXCEEDED');
  }
}

// Error response formatter
export function formatError(error: any) {
  if (error instanceof AppError) {
    return {
      error: error.message,
      code: error.code,
      details: error.details,
      statusCode: error.statusCode,
    };
  }

  // Prisma errors
  if (error.code?.startsWith('P')) {
    switch (error.code) {
      case 'P2002':
        return {
          error: 'Duplicate entry',
          code: 'DUPLICATE_ENTRY',
          details: { target: error.meta?.target },
          statusCode: 409,
        };
      case 'P2025':
        return {
          error: 'Record not found',
          code: 'RECORD_NOT_FOUND',
          statusCode: 404,
        };
      default:
        return {
          error: 'Database error',
          code: 'DATABASE_ERROR',
          details: { code: error.code },
          statusCode: 500,
        };
    }
  }

  // Default error
  return {
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    statusCode: 500,
  };
}

// Error handler middleware
export async function errorHandler(error: any, request: any, reply: any) {
  const formattedError = formatError(error);

  // Log error
  request.log.error({
    error: formattedError,
    requestId: request.id,
    url: request.url,
    method: request.method,
    userId: request.currentUser?.id,
    companyId: request.currentUser?.companyId,
  });

  // Send error response
  reply.status(formattedError.statusCode).send(formattedError);
}
