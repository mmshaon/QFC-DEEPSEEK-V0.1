/**
 * Quantum Finance Engine - Audit Logging Utility
 */
import type { FastifyInstance } from 'fastify';

export interface AuditLogData {
  userId?: string;
  companyId?: string;
  actionType: string;
  entityType: string;
  entityId?: string;
  description?: string;
  oldData?: any;
  newData?: any;
  changes?: any;
  metadata?: any;
  ipAddress?: string;
  userAgent?: string;
  location?: string;
  severity?: 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
}

export class AuditLogger {
  constructor(private app: FastifyInstance) {}

  async log(data: AuditLogData): Promise<void> {
    try {
      await this.app.prisma.auditLog.create({
        data: {
          userId: data.userId,
          companyId: data.companyId,
          actionType: data.actionType,
          entityType: data.entityType,
          entityId: data.entityId,
          description: data.description,
          oldData: data.oldData,
          newData: data.newData,
          changes: data.changes,
          metadata: data.metadata,
          ipAddress: data.ipAddress,
          userAgent: data.userAgent,
          location: data.location,
          severity: data.severity || 'INFO',
        },
      });
    } catch (error) {
      // Don't let audit logging failures break the main flow
      this.app.log.error('Failed to write audit log:', error);
    }
  }

  // Common audit actions
  async logLogin(userId: string, companyId: string | undefined, success: boolean, metadata: any = {}) {
    await this.log({
      userId,
      companyId,
      actionType: success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILED',
      entityType: 'User',
      entityId: userId,
      description: success ? 'User logged in successfully' : 'Failed login attempt',
      metadata: {
        ...metadata,
        success,
        timestamp: new Date().toISOString(),
      },
      severity: success ? 'INFO' : 'WARNING',
    });
  }

  async logLogout(userId: string, companyId: string | undefined, metadata: any = {}) {
    await this.log({
      userId,
      companyId,
      actionType: 'LOGOUT',
      entityType: 'User',
      entityId: userId,
      description: 'User logged out',
      metadata: {
        ...metadata,
        timestamp: new Date().toISOString(),
      },
    });
  }

  async logUserCreation(creatorId: string, companyId: string | undefined, newUserId: string, userData: any) {
    await this.log({
      userId: creatorId,
      companyId,
      actionType: 'USER_CREATE',
      entityType: 'User',
      entityId: newUserId,
      description: `User created: ${userData.email}`,
      newData: this.sanitizeUserData(userData),
      metadata: {
        createdById: creatorId,
        timestamp: new Date().toISOString(),
      },
    });
  }

  async logUserUpdate(userId: string, companyId: string | undefined, updaterId: string, oldData: any, newData: any) {
    const changes = this.calculateChanges(oldData, newData);

    await this.log({
      userId: updaterId,
      companyId,
      actionType: 'USER_UPDATE',
      entityType: 'User',
      entityId: userId,
      description: 'User information updated',
      oldData: this.sanitizeUserData(oldData),
      newData: this.sanitizeUserData(newData),
      changes,
      metadata: {
        updatedById: updaterId,
        timestamp: new Date().toISOString(),
      },
    });
  }

  async logPasswordChange(userId: string, companyId: string | undefined, changedBy: string = 'system') {
    await this.log({
      userId,
      companyId,
      actionType: 'PASSWORD_CHANGE',
      entityType: 'User',
      entityId: userId,
      description: 'Password changed',
      metadata: {
        changedBy,
        timestamp: new Date().toISOString(),
      },
      severity: 'INFO',
    });
  }

  async logPermissionChange(userId: string, companyId: string | undefined, adminId: string, changes: any) {
    await this.log({
      userId: adminId,
      companyId,
      actionType: 'PERMISSION_CHANGE',
      entityType: 'User',
      entityId: userId,
      description: 'User permissions modified',
      changes,
      metadata: {
        modifiedBy: adminId,
        timestamp: new Date().toISOString(),
      },
      severity: 'WARNING',
    });
  }

  async logAccountApproval(userId: string, companyId: string | undefined, approverId: string, approved: boolean, reason?: string) {
    await this.log({
      userId: approverId,
      companyId,
      actionType: approved ? 'ACCOUNT_APPROVE' : 'ACCOUNT_REJECT',
      entityType: 'User',
      entityId: userId,
      description: approved ? 'User account approved' : `User account rejected: ${reason}`,
      metadata: {
        approved,
        reason,
        timestamp: new Date().toISOString(),
      },
      severity: 'INFO',
    });
  }

  async logSecurityEvent(userId: string, companyId: string | undefined, event: string, details: any) {
    await this.log({
      userId,
      companyId,
      actionType: 'SECURITY_EVENT',
      entityType: 'Security',
      description: event,
      metadata: details,
      severity: 'WARNING',
    });
  }

  // Helper methods
  private sanitizeUserData(userData: any): any {
    if (!userData) return userData;

    const sanitized = { ...userData };

    // Remove sensitive fields
    delete sanitized.passwordHash;
    delete sanitized.pinHash;
    delete sanitized.refreshTokens;
    delete sanitized.sessions;

    return sanitized;
  }

  private calculateChanges(oldData: any, newData: any): any {
    const changes: any = {};

    for (const key in newData) {
      if (oldData[key] !== newData[key]) {
        changes[key] = {
          old: oldData[key],
          new: newData[key],
        };
      }
    }

    return changes;
  }

  // Batch logging for performance
  async logBatch(logs: AuditLogData[]): Promise<void> {
    try {
      await this.app.prisma.$transaction(
        logs.map(log =>
          this.app.prisma.auditLog.create({
            data: {
              userId: log.userId,
              companyId: log.companyId,
              actionType: log.actionType,
              entityType: log.entityType,
              entityId: log.entityId,
              description: log.description,
              oldData: log.oldData,
              newData: log.newData,
              changes: log.changes,
              metadata: log.metadata,
              ipAddress: log.ipAddress,
              userAgent: log.userAgent,
              location: log.location,
              severity: log.severity || 'INFO',
            },
          })
        )
      );
    } catch (error) {
      this.app.log.error('Failed to write batch audit logs:', error);
    }
  }
}
