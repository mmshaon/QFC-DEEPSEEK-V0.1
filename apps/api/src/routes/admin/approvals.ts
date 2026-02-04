import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { AuditLogger } from '../../utils/audit';
import { SecurityUtils } from '../../utils/security';
import { ValidationError, NotFoundError, AuthorizationError } from '../../utils/errors';

interface GetPendingUsersQuery {
  page?: number;
  limit?: number;
  search?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

interface ApproveUserBody {
  userId: string;
  roleId?: string;
  sendWelcomeEmail?: boolean;
  notes?: string;
}

interface RejectUserBody {
  userId: string;
  reason: string;
  sendNotification?: boolean;
}

interface BulkActionBody {
  userIds: string[];
  action: 'approve' | 'reject';
  roleId?: string;
  reason?: string;
  sendNotifications?: boolean;
}

interface UpdateUserStatusBody {
  status: 'ACTIVE' | 'SUSPENDED' | 'DELETED';
  reason?: string;
  notifyUser?: boolean;
}

export async function approvalRoutes(app: FastifyInstance) {
  const auditLogger = new AuditLogger(app);

  // Get pending approval users
  app.get(
    '/admin/users/pending',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'APPROVE'),
      ],
      schema: {
        querystring: {
          type: 'object',
          properties: {
            page: { type: 'number', minimum: 1, default: 1 },
            limit: { type: 'number', minimum: 1, maximum: 100, default: 20 },
            search: { type: 'string' },
            sortBy: {
              type: 'string',
              enum: ['createdAt', 'fullName', 'email', 'phone'],
              default: 'createdAt'
            },
            sortOrder: { type: 'string', enum: ['asc', 'desc'], default: 'desc' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const query = request.query as GetPendingUsersQuery;
      const companyId = user.companyId;

      try {
        // Build where clause
        const where: any = {
          approvalStatus: 'PENDING',
          status: 'PENDING_APPROVAL',
        };

        // Creator can see all pending users, others only see their company's users
        if (!user.isCreator && companyId) {
          where.companyId = companyId;
        }

        // Add search
        if (query.search) {
          where.OR = [
            { email: { contains: query.search, mode: 'insensitive' } },
            { fullName: { contains: query.search, mode: 'insensitive' } },
            { phone: { contains: query.search, mode: 'insensitive' } },
            { idNumber: { contains: query.search, mode: 'insensitive' } },
          ];
        }

        // Get total count
        const total = await app.prisma.user.count({ where });

        // Get users with pagination
        const users = await app.prisma.user.findMany({
          where,
          select: {
            id: true,
            email: true,
            fullName: true,
            phone: true,
            phoneVerified: true,
            address: true,
            city: true,
            state: true,
            country: true,
            idNumber: true,
            idType: true,
            profileImage: true,
            idImage: true,
            emergencyContactName: true,
            emergencyContactPhone: true,
            emergencyContactRelation: true,
            status: true,
            approvalStatus: true,
            createdAt: true,
            updatedAt: true,
            company: {
              select: {
                id: true,
                name: true,
                logoUrl: true,
              },
            },
            // For creator, include which admin needs to approve
            ...(user.isCreator && {
              company: {
                select: {
                  id: true,
                  name: true,
                  createdBy: {
                    select: {
                      id: true,
                      fullName: true,
                      email: true,
                    },
                  },
                },
              },
            }),
          },
          orderBy: { [query.sortBy]: query.sortOrder },
          skip: (query.page - 1) * query.limit,
          take: query.limit,
        });

        // Get company roles for assignment dropdown
        const companyRoles = user.isCreator
          ? await app.prisma.role.findMany({
              where: { companyId: companyId },
              select: { id: true, name: true, level: true },
              orderBy: { level: 'asc' },
            })
          : await app.prisma.role.findMany({
              where: {
                companyId: companyId,
                level: { gte: 2 }, // Don't show creator/admin roles to non-creators
              },
              select: { id: true, name: true, level: true },
              orderBy: { level: 'asc' },
            });

        return {
          success: true,
          data: {
            users,
            pagination: {
              page: query.page,
              limit: query.limit,
              total,
              pages: Math.ceil(total / query.limit),
            },
            roles: companyRoles,
            stats: {
              pending: total,
              approvedToday: await app.prisma.user.count({
                where: {
                  approvalStatus: 'APPROVED',
                  approvedAt: {
                    gte: new Date(new Date().setHours(0, 0, 0, 0)),
                  },
                  ...(companyId && !user.isCreator && { companyId }),
                },
              }),
              rejectedToday: await app.prisma.user.count({
                where: {
                  approvalStatus: 'REJECTED',
                  updatedAt: {
                    gte: new Date(new Date().setHours(0, 0, 0, 0)),
                  },
                  ...(companyId && !user.isCreator && { companyId }),
                },
              }),
            },
          },
        };

      } catch (error: any) {
        app.log.error('Failed to fetch pending users:', error);
        throw error;
      }
    }
  );

  // Get user details for approval
  app.get(
    '/admin/users/:userId/approval-details',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'APPROVE'),
      ],
      schema: {
        params: {
          type: 'object',
          required: ['userId'],
          properties: {
            userId: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const { userId } = request.params as { userId: string };

      try {
        // Validate company membership
        await app.validateCompanyMembership(request, reply, userId);
        if (reply.sent) return;

        const targetUser = await app.prisma.user.findUnique({
          where: { id: userId },
          select: {
            id: true,
            email: true,
            fullName: true,
            phone: true,
            phoneVerified: true,
            address: true,
            city: true,
            state: true,
            country: true,
            postalCode: true,
            idNumber: true,
            idType: true,
            profileImage: true,
            idImage: true,
            emergencyContactName: true,
            emergencyContactPhone: true,
            emergencyContactRelation: true,
            status: true,
            approvalStatus: true,
            rejectionReason: true,
            createdAt: true,
            updatedAt: true,
            company: {
              select: {
                id: true,
                name: true,
                address: true,
                phone: true,
                email: true,
                logoUrl: true,
              },
            },
            // For creator, include audit logs
            ...(user.isCreator && {
              auditLogs: {
                where: {
                  actionType: {
                    in: ['USER_CREATE', 'REGISTRATION', 'PROFILE_UPDATE'],
                  },
                },
                select: {
                  actionType: true,
                  description: true,
                  createdAt: true,
                  ipAddress: true,
                  userAgent: true,
                },
                orderBy: { createdAt: 'desc' },
                take: 10,
              },
            }),
          },
        });

        if (!targetUser) {
          throw new NotFoundError('User');
        }

        // Check if user is pending approval
        if (targetUser.approvalStatus !== 'PENDING') {
          return {
            success: true,
            data: {
              user: targetUser,
              canApprove: false,
              status: targetUser.approvalStatus,
              message: `User is already ${targetUser.approvalStatus.toLowerCase()}`,
            },
          };
        }

        // Get available roles for this user's company
        const roles = await app.prisma.role.findMany({
          where: {
            companyId: targetUser.companyId,
            ...(user.isCreator ? {} : { level: { gte: 2 } }), // Non-creators can't assign admin roles
          },
          select: {
            id: true,
            name: true,
            description: true,
            level: true,
            isDefault: true,
            permissions: {
              select: {
                permission: {
                  select: {
                    module: true,
                    action: true,
                    name: true,
                  },
                },
              },
            },
          },
          orderBy: { level: 'asc' },
        });

        // Format roles with permission summary
        const formattedRoles = roles.map(role => ({
          id: role.id,
          name: role.name,
          description: role.description,
          level: role.level,
          isDefault: role.isDefault,
          permissions: role.permissions.map(p => ({
            module: p.permission.module,
            action: p.permission.action,
            name: p.permission.name,
          })),
          permissionCount: role.permissions.length,
        }));

        return {
          success: true,
          data: {
            user: targetUser,
            canApprove: true,
            roles: formattedRoles,
            defaultRole: formattedRoles.find(r => r.isDefault) || formattedRoles[0],
            company: targetUser.company,
            verificationStatus: {
              email: !!targetUser.email,
              phone: targetUser.phoneVerified,
              id: !!targetUser.idNumber,
            },
          },
        };

      } catch (error: any) {
        app.log.error('Failed to fetch user approval details:', error);
        throw error;
      }
    }
  );

  // Approve user
  app.post(
    '/admin/users/:userId/approve',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'APPROVE'),
      ],
      schema: {
        params: {
          type: 'object',
          required: ['userId'],
          properties: {
            userId: { type: 'string' },
          },
        },
        body: {
          type: 'object',
          required: [],
          properties: {
            roleId: { type: 'string' },
            sendWelcomeEmail: { type: 'boolean', default: true },
            notes: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const { userId } = request.params as { userId: string };
      const body = request.body as ApproveUserBody;
      const ipAddress = request.ip;

      try {
        // Validate company membership
        await app.validateCompanyMembership(request, reply, userId);
        if (reply.sent) return;

        // Get target user
        const targetUser = await app.prisma.user.findUnique({
          where: { id: userId },
          include: {
            company: true,
          },
        });

        if (!targetUser) {
          throw new NotFoundError('User');
        }

        // Check if already approved
        if (targetUser.approvalStatus === 'APPROVED') {
          throw new ValidationError('User is already approved');
        }

        // Validate role if provided
        let roleId = body.roleId;
        if (roleId) {
          const role = await app.prisma.role.findUnique({
            where: { id: roleId },
          });

          if (!role) {
            throw new ValidationError('Invalid role specified');
          }

          // Check role belongs to same company
          if (role.companyId !== targetUser.companyId) {
            throw new AuthorizationError('Cannot assign role from different company');
          }

          // Non-creators can't assign admin roles (level < 2)
          if (!user.isCreator && role.level < 2) {
            throw new AuthorizationError('Cannot assign admin-level roles');
          }
        } else {
          // Get default role for company
          const defaultRole = await app.prisma.role.findFirst({
            where: {
              companyId: targetUser.companyId,
              isDefault: true,
            },
          });

          roleId = defaultRole?.id;
        }

        // Approve user in transaction
        const approvedUser = await app.prisma.$transaction(async (tx) => {
          // Update user status
          const updatedUser = await tx.user.update({
            where: { id: userId },
            data: {
              status: 'ACTIVE',
              approvalStatus: 'APPROVED',
              approvedById: user.id,
              approvedAt: new Date(),
            },
          });

          // Assign role if available
          if (roleId) {
            // Remove any existing roles
            await tx.userRole.deleteMany({
              where: { userId },
            });

            // Assign new role
            await tx.userRole.create({
              data: {
                userId,
                roleId,
                assignedById: user.id,
                assignedAt: new Date(),
              },
            });

            // Update user flags based on role level
            const role = await tx.role.findUnique({
              where: { id: roleId },
            });

            if (role) {
              const updates: any = {};
              if (role.level <= 1) updates.isCompanyAdmin = true;
              if (role.level === 0) updates.isCreator = true;

              if (Object.keys(updates).length > 0) {
                await tx.user.update({
                  where: { id: userId },
                  data: updates,
                });
              }
            }
          }

          // Create audit log
          await tx.auditLog.create({
            data: {
              userId: user.id,
              companyId: user.companyId,
              actionType: 'USER_APPROVE',
              entityType: 'User',
              entityId: userId,
              description: `User approved by ${user.fullName || user.email}`,
              metadata: {
                approvedBy: {
                  id: user.id,
                  email: user.email,
                  fullName: user.fullName,
                },
                roleAssigned: roleId ? true : false,
                roleId,
                notes: body.notes,
                sendWelcomeEmail: body.sendWelcomeEmail,
              },
              ipAddress,
            },
          });

          return updatedUser;
        });

        // Send welcome email if requested
        if (body.sendWelcomeEmail) {
          // TODO: Send welcome email
          app.log.info(`Welcome email would be sent to: ${approvedUser.email}`);
        }

        // Create notification for approved user
        await app.prisma.notification.create({
          data: {
            userId: approvedUser.id,
            companyId: approvedUser.companyId,
            type: 'SYSTEM',
            title: 'Account Approved!',
            message: `Your account has been approved. You can now login and access the system.`,
            data: {
              accountApproved: true,
              approvedBy: user.fullName || user.email,
              approvedAt: new Date().toISOString(),
              nextSteps: ['Complete your profile', 'Explore dashboard', 'Set up security preferences'],
            },
          },
        });

        // Create notification for approver
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SYSTEM',
            title: 'User Approved',
            message: `You approved ${approvedUser.fullName} (${approvedUser.email})`,
            data: {
              action: 'USER_APPROVAL',
              targetUser: {
                id: approvedUser.id,
                email: approvedUser.email,
                fullName: approvedUser.fullName,
              },
            },
          },
        });

        // Log approval
        await auditLogger.logAccountApproval(
          approvedUser.id,
          approvedUser.companyId,
          user.id,
          true,
          body.notes
        );

        return {
          success: true,
          message: 'User approved successfully',
          user: {
            id: approvedUser.id,
            email: approvedUser.email,
            fullName: approvedUser.fullName,
            status: approvedUser.status,
            approvalStatus: approvedUser.approvalStatus,
            approvedAt: approvedUser.approvedAt,
            approvedBy: {
              id: user.id,
              email: user.email,
              fullName: user.fullName,
            },
          },
          notifications: {
            user: true,
            approver: true,
            email: body.sendWelcomeEmail,
          },
        };

      } catch (error: any) {
        app.log.error('Failed to approve user:', error);
        throw error;
      }
    }
  );

  // Reject user
  app.post(
    '/admin/users/:userId/reject',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'REJECT'),
      ],
      schema: {
        params: {
          type: 'object',
          required: ['userId'],
          properties: {
            userId: { type: 'string' },
          },
        },
        body: {
          type: 'object',
          required: ['reason'],
          properties: {
            reason: { type: 'string', minLength: 10 },
            sendNotification: { type: 'boolean', default: true },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const { userId } = request.params as { userId: string };
      const body = request.body as RejectUserBody;
      const ipAddress = request.ip;

      try {
        // Validate company membership
        await app.validateCompanyMembership(request, reply, userId);
        if (reply.sent) return;

        const targetUser = await app.prisma.user.findUnique({
          where: { id: userId },
        });

        if (!targetUser) {
          throw new NotFoundError('User');
        }

        // Check if already processed
        if (targetUser.approvalStatus !== 'PENDING') {
          throw new ValidationError(`User is already ${targetUser.approvalStatus.toLowerCase()}`);
        }

        // Reject user
        const rejectedUser = await app.prisma.$transaction(async (tx) => {
          const updatedUser = await tx.user.update({
            where: { id: userId },
            data: {
              approvalStatus: 'REJECTED',
              status: 'SUSPENDED',
              rejectionReason: body.reason,
              updatedAt: new Date(),
            },
          });

          // Create audit log
          await tx.auditLog.create({
            data: {
              userId: user.id,
              companyId: user.companyId,
              actionType: 'USER_REJECT',
              entityType: 'User',
              entityId: userId,
              description: `User rejected: ${body.reason}`,
              metadata: {
                rejectedBy: {
                  id: user.id,
                  email: user.email,
                  fullName: user.fullName,
                },
                reason: body.reason,
                sendNotification: body.sendNotification,
              },
              ipAddress,
            },
          });

          return updatedUser;
        });

        // Send rejection notification if requested
        if (body.sendNotification) {
          // TODO: Send rejection email
          app.log.info(`Rejection notification would be sent to: ${rejectedUser.email}`);

          // Create in-app notification
          await app.prisma.notification.create({
            data: {
              userId: rejectedUser.id,
              companyId: rejectedUser.companyId,
              type: 'SYSTEM',
              title: 'Account Registration Rejected',
              message: `Your account registration has been rejected. Reason: ${body.reason}`,
              data: {
                accountRejected: true,
                reason: body.reason,
                rejectedBy: user.fullName || user.email,
                rejectedAt: new Date().toISOString(),
                contactSupport: true,
              },
            },
          });
        }

        // Create notification for admin
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SYSTEM',
            title: 'User Rejected',
            message: `You rejected ${rejectedUser.fullName} (${rejectedUser.email})`,
            data: {
              action: 'USER_REJECTION',
              targetUser: {
                id: rejectedUser.id,
                email: rejectedUser.email,
              },
              reason: body.reason,
            },
          },
        });

        // Log rejection
        await auditLogger.logAccountApproval(
          rejectedUser.id,
          rejectedUser.companyId,
          user.id,
          false,
          body.reason
        );

        return {
          success: true,
          message: 'User rejected successfully',
          user: {
            id: rejectedUser.id,
            email: rejectedUser.email,
            approvalStatus: rejectedUser.approvalStatus,
            rejectionReason: rejectedUser.rejectionReason,
            updatedAt: rejectedUser.updatedAt,
          },
          notifications: {
            user: body.sendNotification,
            admin: true,
          },
        };

      } catch (error: any) {
        app.log.error('Failed to reject user:', error);
        throw error;
      }
    }
  );

  // Bulk approve/reject users
  app.post(
    '/admin/users/bulk-action',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'APPROVE'),
        app.requirePermission('AUTH', 'REJECT'),
      ],
      schema: {
        body: {
          type: 'object',
          required: ['userIds', 'action'],
          properties: {
            userIds: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 50 },
            action: { type: 'string', enum: ['approve', 'reject'] },
            roleId: { type: 'string' },
            reason: { type: 'string' },
            sendNotifications: { type: 'boolean', default: true },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const body = request.body as BulkActionBody;
      const ipAddress = request.ip;

      try {
        // Limit bulk actions
        if (body.userIds.length > 50) {
          throw new ValidationError('Cannot process more than 50 users at once');
        }

        // Get all target users
        const targetUsers = await app.prisma.user.findMany({
          where: {
            id: { in: body.userIds },
            approvalStatus: 'PENDING',
            ...(user.isCreator ? {} : { companyId: user.companyId }),
          },
          include: {
            company: true,
          },
        });

        if (targetUsers.length === 0) {
          throw new ValidationError('No pending users found for the specified IDs');
        }

        // Validate all users belong to same company (for non-creators)
        if (!user.isCreator) {
          const differentCompany = targetUsers.find(u => u.companyId !== user.companyId);
          if (differentCompany) {
            throw new AuthorizationError('Cannot process users from different companies');
          }
        }

        // Validate role if provided for approval
        if (body.action === 'approve' && body.roleId) {
          const role = await app.prisma.role.findUnique({
            where: { id: body.roleId },
          });

          if (!role) {
            throw new ValidationError('Invalid role specified');
          }

          // Check role belongs to same company as users
          const userCompanies = [...new Set(targetUsers.map(u => u.companyId))];
          if (userCompanies.length > 1 || (userCompanies[0] && role.companyId !== userCompanies[0])) {
            throw new AuthorizationError('Role does not belong to the users\' company');
          }
        }

        // Process bulk action
        const results = await app.prisma.$transaction(async (tx) => {
          const processed: any[] = [];
          const failed: any[] = [];

          for (const targetUser of targetUsers) {
            try {
              if (body.action === 'approve') {
                // Approve user
                const updatedUser = await tx.user.update({
                  where: { id: targetUser.id },
                  data: {
                    status: 'ACTIVE',
                    approvalStatus: 'APPROVED',
                    approvedById: user.id,
                    approvedAt: new Date(),
                  },
                });

                // Assign role if specified
                if (body.roleId) {
                  await tx.userRole.deleteMany({ where: { userId: targetUser.id } });

                  await tx.userRole.create({
                    data: {
                      userId: targetUser.id,
                      roleId: body.roleId,
                      assignedById: user.id,
                      assignedAt: new Date(),
                    },
                  });
                }

                processed.push({
                  id: targetUser.id,
                  email: targetUser.email,
                  action: 'approved',
                  success: true,
                });

                // Create audit log
                await tx.auditLog.create({
                  data: {
                    userId: user.id,
                    companyId: user.companyId,
                    actionType: 'USER_APPROVE',
                    entityType: 'User',
                    entityId: targetUser.id,
                    description: `User approved via bulk action by ${user.fullName || user.email}`,
                    metadata: {
                      bulkAction: true,
                      roleAssigned: !!body.roleId,
                      roleId: body.roleId,
                    },
                    ipAddress,
                  },
                });

                // Create notification for user
                if (body.sendNotifications) {
                  await tx.notification.create({
                    data: {
                      userId: targetUser.id,
                      companyId: targetUser.companyId,
                      type: 'SYSTEM',
                      title: 'Account Approved!',
                      message: 'Your account has been approved via bulk processing.',
                      data: {
                        accountApproved: true,
                        bulkProcessed: true,
                      },
                    },
                  });
                }

              } else if (body.action === 'reject') {
                // Reject user
                const updatedUser = await tx.user.update({
                  where: { id: targetUser.id },
                  data: {
                    approvalStatus: 'REJECTED',
                    status: 'SUSPENDED',
                    rejectionReason: body.reason || 'Rejected via bulk action',
                    updatedAt: new Date(),
                  },
                });

                processed.push({
                  id: targetUser.id,
                  email: targetUser.email,
                  action: 'rejected',
                  success: true,
                });

                // Create audit log
                await tx.auditLog.create({
                  data: {
                    userId: user.id,
                    companyId: user.companyId,
                    actionType: 'USER_REJECT',
                    entityType: 'User',
                    entityId: targetUser.id,
                    description: `User rejected via bulk action: ${body.reason || 'No reason provided'}`,
                    metadata: {
                      bulkAction: true,
                      reason: body.reason,
                    },
                    ipAddress,
                  },
                });

                // Create notification for user
                if (body.sendNotifications && body.reason) {
                  await tx.notification.create({
                    data: {
                      userId: targetUser.id,
                      companyId: targetUser.companyId,
                      type: 'SYSTEM',
                      title: 'Account Registration Rejected',
                      message: `Your account registration has been rejected. Reason: ${body.reason}`,
                      data: {
                        accountRejected: true,
                        reason: body.reason,
                        bulkProcessed: true,
                      },
                    },
                  });
                }
              }
            } catch (error: any) {
              failed.push({
                id: targetUser.id,
                email: targetUser.email,
                error: error.message,
              });
            }
          }

          return { processed, failed };
        });

        // Create notification for admin
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SYSTEM',
            title: 'Bulk User Action Completed',
            message: `Bulk ${body.action} action completed. Processed: ${results.processed.length}, Failed: ${results.failed.length}`,
            data: {
              action: `BULK_${body.action.toUpperCase()}`,
              processedCount: results.processed.length,
              failedCount: results.failed.length,
              timestamp: new Date().toISOString(),
            },
          },
        });

        // Log bulk action
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: `BULK_${body.action.toUpperCase()}`,
          entityType: 'User',
          description: `Bulk ${body.action} action completed`,
          metadata: {
            processed: results.processed.length,
            failed: results.failed.length,
            total: body.userIds.length,
            action: body.action,
            roleId: body.roleId,
            ipAddress,
          },
          severity: 'INFO',
        });

        return {
          success: true,
          message: `Bulk ${body.action} action completed`,
          results,
          summary: {
            total: body.userIds.length,
            processed: results.processed.length,
            failed: results.failed.length,
            successRate: (results.processed.length / body.userIds.length) * 100,
          },
        };

      } catch (error: any) {
        app.log.error('Bulk action failed:', error);
        throw error;
      }
    }
  );

  // Update user status (active/suspended/deleted)
  app.post(
    '/admin/users/:userId/status',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'EDIT'),
      ],
      schema: {
        params: {
          type: 'object',
          required: ['userId'],
          properties: {
            userId: { type: 'string' },
          },
        },
        body: {
          type: 'object',
          required: ['status'],
          properties: {
            status: { type: 'string', enum: ['ACTIVE', 'SUSPENDED', 'DELETED'] },
            reason: { type: 'string' },
            notifyUser: { type: 'boolean', default: true },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const { userId } = request.params as { userId: string };
      const body = request.body as UpdateUserStatusBody;
      const ipAddress = request.ip;

      try {
        // Cannot modify own status
        if (userId === user.id) {
          throw new ValidationError('Cannot modify your own account status');
        }

        // Validate company membership
        await app.validateCompanyMembership(request, reply, userId);
        if (reply.sent) return;

        const targetUser = await app.prisma.user.findUnique({
          where: { id: userId },
        });

        if (!targetUser) {
          throw new NotFoundError('User');
        }

        // Prevent modifying creator accounts (only creator can modify other creators)
        if (targetUser.isCreator && !user.isCreator) {
          throw new AuthorizationError('Cannot modify creator accounts');
        }

        // Update user status
        const updatedUser = await app.prisma.$transaction(async (tx) => {
          const updateData: any = {
            status: body.status,
            updatedAt: new Date(),
          };

          // Handle deletion (soft delete)
          if (body.status === 'DELETED') {
            updateData.deletedAt = new Date();
            // Invalidate all sessions
            await tx.session.updateMany({
              where: { userId },
              data: { isValid: false },
            });
            // Invalidate all refresh tokens
            await tx.refreshToken.updateMany({
              where: { userId },
              data: { isValid: false },
            });
          }

          const updated = await tx.user.update({
            where: { id: userId },
            data: updateData,
          });

          // Create audit log
          await tx.auditLog.create({
            data: {
              userId: user.id,
              companyId: user.companyId,
              actionType: 'USER_STATUS_UPDATE',
              entityType: 'User',
              entityId: userId,
              description: `User status changed to ${body.status}: ${body.reason || 'No reason provided'}`,
              metadata: {
                oldStatus: targetUser.status,
                newStatus: body.status,
                reason: body.reason,
                updatedBy: {
                  id: user.id,
                  email: user.email,
                  fullName: user.fullName,
                },
              },
              ipAddress,
            },
          });

          return updated;
        });

        // Send notification to user if requested
        if (body.notifyUser && body.reason) {
          let notificationTitle = '';
          let notificationMessage = '';

          switch (body.status) {
            case 'SUSPENDED':
              notificationTitle = 'Account Suspended';
              notificationMessage = `Your account has been suspended. Reason: ${body.reason}`;
              break;
            case 'ACTIVE':
              notificationTitle = 'Account Reactivated';
              notificationMessage = `Your account has been reactivated. Reason: ${body.reason}`;
              break;
            case 'DELETED':
              notificationTitle = 'Account Deleted';
              notificationMessage = `Your account has been deleted. Reason: ${body.reason}`;
              break;
          }

          if (notificationTitle) {
            await app.prisma.notification.create({
              data: {
                userId: updatedUser.id,
                companyId: updatedUser.companyId,
                type: 'SYSTEM',
                title: notificationTitle,
                message: notificationMessage,
                data: {
                  statusChanged: true,
                  newStatus: body.status,
                  reason: body.reason,
                  changedBy: user.fullName || user.email,
                  timestamp: new Date().toISOString(),
                },
              },
            });
          }
        }

        // Create notification for admin
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SYSTEM',
            title: 'User Status Updated',
            message: `You changed ${targetUser.fullName}'s status to ${body.status}`,
            data: {
              action: 'USER_STATUS_UPDATE',
              targetUser: {
                id: targetUser.id,
                email: targetUser.email,
                fullName: targetUser.fullName,
              },
              oldStatus: targetUser.status,
              newStatus: body.status,
              reason: body.reason,
            },
          },
        });

        // Log status change
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'USER_STATUS_CHANGE',
          entityType: 'User',
          entityId: userId,
          description: `User status changed from ${targetUser.status} to ${body.status}`,
          metadata: {
            oldStatus: targetUser.status,
            newStatus: body.status,
            reason: body.reason,
            notifyUser: body.notifyUser,
            ipAddress,
          },
          severity: 'WARNING',
        });

        return {
          success: true,
          message: `User status updated to ${body.status}`,
          user: {
            id: updatedUser.id,
            email: updatedUser.email,
            status: updatedUser.status,
            updatedAt: updatedUser.updatedAt,
            deletedAt: updatedUser.deletedAt,
          },
          notifications: {
            user: body.notifyUser,
            admin: true,
          },
        };

      } catch (error: any) {
        app.log.error('Failed to update user status:', error);
        throw error;
      }
    }
  );

  // Get approval statistics
  app.get(
    '/admin/approval-stats',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'VIEW'),
      ],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const companyId = user.companyId;
      const now = new Date();
      const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

      try {
        // Build base where clause
        const baseWhere = user.isCreator ? {} : { companyId };

        // Get overall statistics
        const [totalUsers, pendingUsers, approvedUsers, rejectedUsers] = await Promise.all([
          app.prisma.user.count({ where: baseWhere }),
          app.prisma.user.count({
            where:
