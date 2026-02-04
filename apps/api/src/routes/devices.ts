import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { AuditLogger } from '../utils/audit';
import { SecurityUtils } from '../utils/security';
import { ValidationError, NotFoundError, AuthorizationError } from '../utils/errors';

interface RegisterDeviceBody {
  deviceId?: string;
  deviceName?: string;
  deviceType?: 'WEB' | 'ANDROID' | 'IOS' | 'DESKTOP';
  platform?: string;
  osVersion?: string;
  appVersion?: string;
  fcmToken?: string;
}

interface UpdateDeviceBody {
  deviceName?: string;
  fcmToken?: string;
  biometricEnabled?: boolean;
  pinEnabled?: boolean;
}

export async function deviceRoutes(app: FastifyInstance) {
  const auditLogger = new AuditLogger(app);

  // Register new device
  app.post(
    '/devices/register',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        body: {
          type: 'object',
          required: [],
          properties: {
            deviceId: { type: 'string' },
            deviceName: { type: 'string' },
            deviceType: {
              type: 'string',
              enum: ['WEB', 'ANDROID', 'IOS', 'DESKTOP']
            },
            platform: { type: 'string' },
            osVersion: { type: 'string' },
            appVersion: { type: 'string' },
            fcmToken: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const body = request.body as RegisterDeviceBody;
      const ipAddress = request.ip;
      const userAgent = request.headers['user-agent'];

      try {
        // Generate device ID if not provided
        const deviceId = body.deviceId || SecurityUtils.generateDeviceId();

        // Check if device already exists
        const existingDevice = await app.prisma.device.findUnique({
          where: { deviceId },
        });

        let device;

        if (existingDevice) {
          // Update existing device
          if (existingDevice.userId !== user.id) {
            throw new AuthorizationError('Device is registered to another user');
          }

          device = await app.prisma.device.update({
            where: { id: existingDevice.id },
            data: {
              deviceName: body.deviceName || existingDevice.deviceName,
              deviceType: body.deviceType || existingDevice.deviceType,
              platform: body.platform || existingDevice.platform,
              osVersion: body.osVersion || existingDevice.osVersion,
              appVersion: body.appVersion || existingDevice.appVersion,
              fcmToken: body.fcmToken || existingDevice.fcmToken,
              lastUsedAt: new Date(),
            },
          });

          await auditLogger.log({
            userId: user.id,
            companyId: user.companyId,
            actionType: 'DEVICE_UPDATE',
            entityType: 'Device',
            entityId: device.id,
            description: 'Device information updated',
            metadata: {
              deviceId: device.deviceId,
              deviceName: device.deviceName,
              ipAddress,
            },
          });

        } else {
          // Create new device
          device = await app.prisma.device.create({
            data: {
              userId: user.id,
              deviceId,
              deviceName: body.deviceName || 'Unknown Device',
              deviceType: body.deviceType || 'WEB',
              platform: body.platform,
              osVersion: body.osVersion,
              appVersion: body.appVersion,
              fcmToken: body.fcmToken,
              lastUsedAt: new Date(),
            },
          });

          await auditLogger.log({
            userId: user.id,
            companyId: user.companyId,
            actionType: 'DEVICE_REGISTER',
            entityType: 'Device',
            entityId: device.id,
            description: 'New device registered',
            metadata: {
              deviceId: device.deviceId,
              deviceName: device.deviceName,
              deviceType: device.deviceType,
              ipAddress,
            },
          });
        }

        return {
          success: true,
          device: {
            id: device.id,
            deviceId: device.deviceId,
            deviceName: device.deviceName,
            deviceType: device.deviceType,
            isTrusted: device.isTrusted,
            biometricEnabled: device.biometricEnabled,
            pinEnabled: device.pinEnabled,
            lastUsedAt: device.lastUsedAt,
          },
        };

      } catch (error: any) {
        app.log.error('Device registration failed:', error);
        throw error;
      }
    }
  );

  // Get user's devices
  app.get(
    '/devices',
    {
      preHandler: [app.authenticate, app.requireApproved],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;

      try {
        const devices = await app.prisma.device.findMany({
          where: { userId: user.id },
          select: {
            id: true,
            deviceId: true,
            deviceName: true,
            deviceType: true,
            platform: true,
            osVersion: true,
            appVersion: true,
            biometricEnabled: true,
            pinEnabled: true,
            isTrusted: true,
            lastUsedAt: true,
            createdAt: true,
          },
          orderBy: { lastUsedAt: 'desc' },
        });

        return {
          success: true,
          devices,
        };

      } catch (error: any) {
        app.log.error('Failed to fetch devices:', error);
        throw error;
      }
    }
  );

  // Update device
  app.patch(
    '/devices/:deviceId',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        params: {
          type: 'object',
          required: ['deviceId'],
          properties: {
            deviceId: { type: 'string' },
          },
        },
        body: {
          type: 'object',
          properties: {
            deviceName: { type: 'string' },
            fcmToken: { type: 'string' },
            biometricEnabled: { type: 'boolean' },
            pinEnabled: { type: 'boolean' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const { deviceId } = request.params as { deviceId: string };
      const body = request.body as UpdateDeviceBody;
      const ipAddress = request.ip;

      try {
        // Find device
        const device = await app.prisma.device.findFirst({
          where: {
            deviceId,
            userId: user.id,
          },
        });

        if (!device) {
          throw new NotFoundError('Device');
        }

        // Update device
        const updatedDevice = await app.prisma.device.update({
          where: { id: device.id },
          data: {
            deviceName: body.deviceName,
            fcmToken: body.fcmToken,
            biometricEnabled: body.biometricEnabled,
            pinEnabled: body.pinEnabled,
            lastUsedAt: new Date(),
          },
        });

        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'DEVICE_UPDATE',
          entityType: 'Device',
          entityId: device.id,
          description: 'Device settings updated',
          metadata: {
            deviceId: device.deviceId,
            updates: body,
            ipAddress,
          },
        });

        return {
          success: true,
          device: {
            id: updatedDevice.id,
            deviceId: updatedDevice.deviceId,
            deviceName: updatedDevice.deviceName,
            biometricEnabled: updatedDevice.biometricEnabled,
            pinEnabled: updatedDevice.pinEnabled,
            isTrusted: updatedDevice.isTrusted,
            lastUsedAt: updatedDevice.lastUsedAt,
          },
        };

      } catch (error: any) {
        app.log.error('Device update failed:', error);
        throw error;
      }
    }
  );

  // Trust device (mark as trusted)
  app.post(
    '/devices/:deviceId/trust',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        params: {
          type: 'object',
          required: ['deviceId'],
          properties: {
            deviceId: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const { deviceId } = request.params as { deviceId: string };
      const ipAddress = request.ip;

      try {
        // Find device
        const device = await app.prisma.device.findFirst({
          where: {
            deviceId,
            userId: user.id,
          },
        });

        if (!device) {
          throw new NotFoundError('Device');
        }

        // Mark device as trusted
        const trustedDevice = await app.prisma.device.update({
          where: { id: device.id },
          data: {
            isTrusted: true,
            lastUsedAt: new Date(),
          },
        });

        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'DEVICE_TRUST',
          entityType: 'Device',
          entityId: device.id,
          description: 'Device marked as trusted',
          metadata: {
            deviceId: device.deviceId,
            ipAddress,
          },
        });

        return {
          success: true,
          device: {
            id: trustedDevice.id,
            deviceId: trustedDevice.deviceId,
            deviceName: trustedDevice.deviceName,
            isTrusted: trustedDevice.isTrusted,
          },
        };

      } catch (error: any) {
        app.log.error('Device trust failed:', error);
        throw error;
      }
    }
  );

  // Remove/unregister device
  app.delete(
    '/devices/:deviceId',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        params: {
          type: 'object',
          required: ['deviceId'],
          properties: {
            deviceId: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const { deviceId } = request.params as { deviceId: string };
      const ipAddress = request.ip;

      try {
        // Find device
        const device = await app.prisma.device.findFirst({
          where: {
            deviceId,
            userId: user.id,
          },
        });

        if (!device) {
          throw new NotFoundError('Device');
        }

        // Delete device and related sessions/tokens
        await app.prisma.$transaction(async (tx) => {
          // Delete sessions for this device
          await tx.session.deleteMany({
            where: {
              deviceId: device.id,
              userId: user.id,
            },
          });

          // Delete refresh tokens for this device
          await tx.refreshToken.deleteMany({
            where: {
              deviceId: device.id,
              userId: user.id,
            },
          });

          // Delete the device
          await tx.device.delete({
            where: { id: device.id },
          });
        });

        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'DEVICE_REMOVE',
          entityType: 'Device',
          entityId: device.id,
          description: 'Device removed/unregistered',
          metadata: {
            deviceId: device.deviceId,
            deviceName: device.deviceName,
            ipAddress,
          },
        });

        return {
          success: true,
          message: 'Device removed successfully',
        };

      } catch (error: any) {
        app.log.error('Device removal failed:', error);
        throw error;
      }
    }
  );

  // Get current device info
  app.get(
    '/devices/current',
    {
      preHandler: [app.authenticate, app.requireApproved],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const deviceId = request.deviceId;

      if (!deviceId) {
        return reply.status(400).send({
          error: 'Device ID not found',
          code: 'DEVICE_ID_REQUIRED',
        });
      }

      try {
        const device = await app.prisma.device.findFirst({
          where: {
            deviceId,
            userId: user.id,
          },
          select: {
            id: true,
            deviceId: true,
            deviceName: true,
            deviceType: true,
            platform: true,
            osVersion: true,
            appVersion: true,
            biometricEnabled: true,
            pinEnabled: true,
            isTrusted: true,
            lastUsedAt: true,
            createdAt: true,
          },
        });

        if (!device) {
          throw new NotFoundError('Device');
        }

        return {
          success: true,
          device,
        };

      } catch (error: any) {
        app.log.error('Failed to fetch current device:', error);
        throw error;
      }
    }
  );
}
