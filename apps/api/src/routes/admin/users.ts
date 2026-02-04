import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { AuditLogger } from '../../utils/audit';
import { SecurityUtils } from '../../utils/security';
import { ValidationError, NotFoundError, AuthorizationError, ConflictError } from '../../utils/errors';
import { sanitizePhone, sanitizeEmail } from '../../utils/validation';

interface CreateUserBody {
  email: string;
  password: string;
  fullName: string;
  phone: string;
  address: string;
  city?: string;
  state?: string;
  country?: string;
  postalCode?: string;
  profileImage?: string;
  idImage?: string;
  idNumber: string;
  idType?: string;
  emergencyContactName: string;
  emergencyContactPhone: string;
  emergencyContactRelation?: string;
  roleIds?: string[];
  department?: string;
  position?: string;
  salary?: number;
  hireDate?: string;
  sendWelcomeEmail?: boolean;
  autoApprove?: boolean;
}

interface UpdateUserBody {
  fullName?: string;
  phone?: string;
  address?: string;
  city?: string;
  state?: string;
  country?: string;
  postalCode?: string;
  profileImage?: string;
  idImage?: string;
  idNumber?: string;
  idType?: string;
  emergencyContactName?: string;
  emergencyContactPhone?: string;
  emergencyContactRelation?: string;
  department?: string;
  position?: string;
  salary?: number;
  hireDate?: string;
  status?: 'ACTIVE' | 'SUSPENDED' | 'DELETED';
}

interface ApproveUserBody {
  userId: string;
  approve: boolean;
  reason?: string;
  roleIds?: string[];
  sendNotification?: boolean;
}

interface BulkActionBody {
  userIds: string[];
  action: 'APPROVE' | 'REJECT' | 'SUSPEND' | 'ACTIVATE' | 'DELETE';
  reason?: string;
  sendNotifications?: boolean;
}

interface UserFilterQuery {
  page?: number;
  limit?: number;
  search?: string;
  status?: string;
  approvalStatus?: string;
  roleId?: string;
  department?: string;
  startDate?: string;
  endDate?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export async function adminUserRoutes(app: FastifyInstance) {
  const auditLogger = new AuditLogger(app);

  // Get all users (with filters and pagination)
  app.get(
    '/admin/users',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'VIEW'),
        app.withCompanyScope,
      ],
      schema: {
        querystring: {
          type: 'object',
          properties: {
            page: { type: 'number', minimum: 1, default: 1 },
            limit: { type: 'number', minimum: 1, maximum: 100, default: 20 },
            search: { type: 'string' },
            status: { type: 'string' },
            approvalStatus: { type: 'string' },
            roleId: { type: 'string' },
            department: { type: 'string' },
            startDate: { type: 'string', format: 'date' },
            endDate: { type: 'string', format: 'date' },
            sortBy: { type: 'string', enum: ['createdAt', 'fullName', 'email', 'lastLoginAt'] },
            sortOrder: { type: 'string', enum: ['asc', 'desc'], default: 'desc' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const companyId = request.companyId;
      const query = request.query as UserFilterQuery;

      try {
        // Build filter conditions
        const where: any = {};

        // Company isolation (except for creator)
        if (!user.isCreator) {
          where.companyId = companyId;
        } else if (companyId) {
          // Creator can filter by company
          where.companyId = companyId;
        }

        // Search filter
        if (query.search) {
          where.OR = [
            { email: { contains: query.search, mode: 'insensitive' } },
            { fullName: { contains: query.search, mode: 'insensitive' } },
            { phone: { contains: query.search, mode: 'insensitive' } },
            { idNumber: { contains: query.search, mode: 'insensitive' } },
          ];
        }

        // Status filters
        if (query.status) {
          where.status = query.status;
        }

        if (query.approvalStatus) {
          where.approvalStatus = query.approvalStatus;
        }

        // Date range filter
        if (query.startDate || query.endDate) {
          where.createdAt = {};
          if (query.startDate) {
            where.createdAt.gte = new Date(query.startDate);
          }
          if (query.endDate) {
            where.createdAt.lte = new Date(query.endDate);
          }
        }

        // Department filter
        if (query.department) {
          where.staff = {
            department: { contains: query.department, mode: 'insensitive' },
          };
        }

        // Role filter
        if (query.roleId) {
          where.roles = {
            some: {
              roleId: query.roleId,
            },
          };
        }

        // Calculate pagination
        const page = query.page || 1;
        const limit = query.limit || 20;
        const skip = (page - 1) * limit;

        // Determine sort order
        const orderBy: any = {};
        if (query.sortBy) {
          orderBy[query.sortBy] = query.sortOrder || 'desc';
        } else {
          orderBy.createdAt = 'desc';
        }

        // Get users with count
        const [users, total] = await Promise.all([
          app.prisma.user.findMany({
            where,
            select: {
              id: true,
              email: true,
              fullName: true,
              phone: true,
              profileImage: true,
              status: true,
              approvalStatus: true,
              isCreator: true,
              isSuperAdmin: true,
              isCompanyAdmin: true,
              lastLoginAt: true,
              createdAt: true,
              approvedAt: true,
              approvedBy: {
                select: {
                  id: true,
                  fullName: true,
                  email: true,
                },
              },
              company: {
                select: {
                  id: true,
                  name: true,
                },
              },
              roles: {
                select: {
                  role: {
                    select: {
                      id: true,
                      name: true,
                      level: true,
                    },
                  },
                },
              },
              staff: {
                select: {
                  department: true,
                  position: true,
                },
              },
            },
            orderBy,
            skip,
            take: limit,
          }),
          app.prisma.user.count({ where }),
        ]);

        // Transform roles
        const transformedUsers = users.map(u => ({
          ...u,
          roles: u.roles.map(r => r.role),
          staff: u.staff || null,
        }));

        // Get statistics
        const stats = await app.prisma.user.groupBy({
          by: ['status', 'approvalStatus'],
          where: {
            companyId: user.isCreator ? undefined : companyId,
          },
          _count: true,
        });

        // Transform stats
        const statusStats = {
          total: stats.reduce((sum, s) => sum + s._count, 0),
          active: stats.filter(s => s.status === 'ACTIVE').reduce((sum, s) => sum + s._count, 0),
          pending: stats.filter(s => s.approvalStatus === 'PENDING').reduce((sum, s) => sum + s._count, 0),
          approved: stats.filter(s => s.approvalStatus === 'APPROVED').reduce((sum, s) => sum + s._count, 0),
          suspended: stats.filter(s => s.status === 'SUSPENDED').reduce((sum, s) => sum + s._count, 0),
        };

        return {
          success: true,
          data: {
            users: transformedUsers,
            pagination: {
              page,
              limit,
              total,
              pages: Math.ceil(total / limit),
            },
            statistics: statusStats,
            filters: {
              search: query.search,
              status: query.status,
              approvalStatus: query.approvalStatus,
              roleId: query.roleId,
              department: query.department,
              dateRange: query.startDate && query.endDate
                ? `${query.startDate} to ${query.endDate}`
                : null,
            },
          },
        };

      } catch (error: any) {
        app.log.error('Failed to fetch users:', error);
        throw error;
      }
    }
  );

  // Get user details (admin view)
  app.get(
    '/admin/users/:userId',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'VIEW'),
        app.validateCompanyMembership,
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
      const { userId } = request.params as { userId: string };
      const user = request.currentUser!;

      try {
        const targetUser = await app.prisma.user.findUnique({
          where: { id: userId },
          select: {
            id: true,
            email: true,
            fullName: true,
            address: true,
            city: true,
            state: true,
            country: true,
            postalCode: true,
            profileImage: true,
            idImage: true,
            idNumber: true,
            idType: true,
            phone: true,
            phoneVerified: true,
            emergencyContactName: true,
            emergencyContactPhone: true,
            emergencyContactRelation: true,
            isCreator: true,
            isSuperAdmin: true,
            isCompanyAdmin: true,
            status: true,
            approvalStatus: true,
            approvedAt: true,
            approvedById: true,
            approvedBy: {
              select: {
                id: true,
                fullName: true,
                email: true,
              },
            },
            rejectionReason: true,
            failedLoginAttempts: true,
            lockedUntil: true,
            lastLoginAt: true,
            lastActiveAt: true,
            lastPasswordChangeAt: true,
            emailVerifiedAt: true,
            phoneVerifiedAt: true,
            mustChangePassword: true,
            pinSet: true,
            createdAt: true,
            updatedAt: true,
            companyId: true,
            company: {
              select: {
                id: true,
                name: true,
                logoUrl: true,
              },
            },
            roles: {
              select: {
                role: {
                  select: {
                    id: true,
                    name: true,
                    description: true,
                    level: true,
                    isSystem: true,
                  },
                },
                assignedAt: true,
                assignedBy: {
                  select: {
                    id: true,
                    fullName: true,
                  },
                },
              },
            },
            staff: {
              select: {
                id: true,
                department: true,
                position: true,
                hireDate: true,
                salary: true,
                createdAt: true,
              },
            },
            sessions: {
              select: {
                id: true,
                device: {
                  select: {
                    deviceName: true,
                    deviceType: true,
                  },
                },
                ipAddress: true,
                lastActivityAt: true,
                createdAt: true,
              },
              where: {
                isValid: true,
                expiresAt: { gt: new Date() },
              },
              orderBy: { lastActivityAt: 'desc' },
              take: 5,
            },
            devices: {
              select: {
                id: true,
                deviceId: true,
                deviceName: true,
                deviceType: true,
                isTrusted: true,
                lastUsedAt: true,
                createdAt: true,
              },
              orderBy: { lastUsedAt: 'desc' },
            },
            auditLogs: {
              select: {
                id: true,
                actionType: true,
                description: true,
                createdAt: true,
                ipAddress: true,
              },
              orderBy: { createdAt: 'desc' },
              take: 10,
            },
          },
        });

        if (!targetUser) {
          throw new NotFoundError('User');
        }

        // Get permissions
        const permissions = await app.rbac.getUserPermissions(userId);

        return {
          success: true,
          user: {
            ...targetUser,
            roles: targetUser.roles.map(r => ({
              ...r.role,
              assignedAt: r.assignedAt,
              assignedBy: r.assignedBy,
            })),
            permissions: Array.from(permissions),
          },
        };

      } catch (error: any) {
        app.log.error('Failed to fetch user details:', error);
        throw error;
      }
    }
  );

  // Create new user (admin)
  app.post(
    '/admin/users',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'CREATE'),
        app.withCompanyScope,
      ],
      schema: {
        body: {
          type: 'object',
          required: [
            'email',
            'password',
            'fullName',
            'phone',
            'address',
            'idNumber',
            'emergencyContactName',
            'emergencyContactPhone',
          ],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string', minLength: 12 },
            fullName: { type: 'string', minLength: 2 },
            phone: { type: 'string' },
            address: { type: 'string', minLength: 5 },
            city: { type: 'string' },
            state: { type: 'string' },
            country: { type: 'string', default: 'SA' },
            postalCode: { type: 'string' },
            profileImage: { type: 'string' },
            idImage: { type: 'string' },
            idNumber: { type: 'string' },
            idType: { type: 'string', default: 'NATIONAL_ID' },
            emergencyContactName: { type: 'string' },
            emergencyContactPhone: { type: 'string' },
            emergencyContactRelation: { type: 'string' },
            roleIds: { type: 'array', items: { type: 'string' } },
            department: { type: 'string' },
            position: { type: 'string' },
            salary: { type: 'number', minimum: 0 },
            hireDate: { type: 'string', format: 'date' },
            sendWelcomeEmail: { type: 'boolean', default: true },
            autoApprove: { type: 'boolean', default: true },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const companyId = request.companyId!;
      const body = request.body as CreateUserBody;
      const ipAddress = request.ip;

      try {
        // Validate password strength
        const passwordStrength = SecurityUtils.checkPasswordStrength(body.password);
        if (passwordStrength.strength === 'weak' || passwordStrength.strength === 'fair') {
          throw new ValidationError('Password is too weak. ' + passwordStrength.feedback.join(' '));
        }

        // Validate phone numbers
        if (!SecurityUtils.validatePhoneNumber(body.phone)) {
          throw new ValidationError('Invalid phone number format');
        }

        if (!SecurityUtils.validatePhoneNumber(body.emergencyContactPhone)) {
          throw new ValidationError('Invalid emergency contact phone number');
        }

        // Sanitize inputs
        const sanitizedEmail = sanitizeEmail(body.email);
        const sanitizedPhone = sanitizePhone(body.phone);
        const sanitizedEmergencyPhone = sanitizePhone(body.emergencyContactPhone);

        // Check if user already exists
        const existingUser = await app.prisma.user.findFirst({
          where: {
            OR: [
              { email: sanitizedEmail },
              { phone: sanitizedPhone },
              { idNumber: body.idNumber },
            ],
          },
        });

        if (existingUser) {
          let conflictField = 'email';
          if (existingUser.email === sanitizedEmail) conflictField = 'email';
          else if (existingUser.phone === sanitizedPhone) conflictField = 'phone';
          else if (existingUser.idNumber === body.idNumber) conflictField = 'ID number';

          throw new ConflictError(`${conflictField} already registered`);
        }

        // Validate roles (must belong to same company)
        let validRoleIds: string[] = [];
        if (body.roleIds && body.roleIds.length > 0) {
          const roles = await app.prisma.role.findMany({
            where: {
              id: { in: body.roleIds },
              companyId,
            },
          });

          validRoleIds = roles.map(r => r.id);

          if (validRoleIds.length !== body.roleIds.length) {
            throw new ValidationError('Some roles are invalid or belong to different company');
          }
        }

        // Hash password
        const passwordHash = await SecurityUtils.hashPassword(body.password);

        // Create user in transaction
        const newUser = await app.prisma.$transaction(async (tx) => {
          // Create user
          const userData: any = {
            email: sanitizedEmail,
            passwordHash,
            fullName: body.fullName.trim(),
            phone: sanitizedPhone,
            address: body.address.trim(),
            city: body.city?.trim(),
            state: body.state?.trim(),
            country: body.country || 'SA',
            postalCode: body.postalCode?.trim(),
            profileImage: body.profileImage,
            idImage: body.idImage,
            idNumber: body.idNumber.trim(),
            idType: body.idType || 'NATIONAL_ID',
            emergencyContactName: body.emergencyContactName.trim(),
            emergencyContactPhone: sanitizedEmergencyPhone,
            emergencyContactRelation: body.emergencyContactRelation?.trim(),
            companyId,
            status: 'ACTIVE',
            approvalStatus: body.autoApprove ? 'APPROVED' : 'PENDING',
            mustChangePassword: true,
            emailVerifiedAt: new Date(),
            phoneVerifiedAt: new Date(),
          };

          if (body.autoApprove) {
            userData.approvedAt = new Date();
            userData.approvedById = user.id;
          }

          const createdUser = await tx.user.create({
            data: userData,
          });

          // Assign roles
          for (const roleId of validRoleIds) {
            await tx.userRole.create({
              data: {
                userId: createdUser.id,
                roleId,
                assignedById: user.id,
              },
            });
          }

          // Create staff record if department/position provided
          if (body.department || body.position) {
            await tx.staff.create({
              data: {
                companyId,
                userId: createdUser.id,
                fullName: body.fullName.trim(),
                department: body.department?.trim(),
                position: body.position?.trim(),
                salary: body.salary,
                hireDate: body.hireDate ? new Date(body.hireDate) : new Date(),
              },
            });
          }

          return createdUser;
        });

        // Log user creation
        await auditLogger.logUserCreation(user.id, companyId, newUser.id, {
          email: newUser.email,
          fullName: newUser.fullName,
          createdByAdmin: true,
          autoApproved: body.autoApprove,
          rolesAssigned: validRoleIds.length,
          ipAddress,
        });

        // Create notifications
        if (body.autoApprove) {
          // User notification
          await app.prisma.notification.create({
            data: {
              userId: newUser.id,
              companyId,
              type: 'SYSTEM',
              title: 'Account Created',
              message: `Your account has been created by ${user.fullName || 'an administrator'}. You can now login with the provided credentials.`,
              data: {
                accountCreated: true,
                createdBy: user.fullName || user.email,
                requiresPasswordChange: true,
              },
            },
          });
        } else {
          // Pending approval notification
          await app.prisma.notification.create({
            data: {
              userId: newUser.id,
              companyId,
              type: 'SYSTEM',
              title: 'Account Created - Pending Approval',
              message: 'Your account has been created and is pending administrator approval.',
              data: {
                pendingApproval: true,
                createdBy: user.fullName || user.email,
              },
            },
          });
        }

        // Admin notification for pending approval
        if (!body.autoApprove) {
          const admins = await app.prisma.user.findMany({
            where: {
              companyId,
              OR: [
                { isCreator: true },
                { isSuperAdmin: true },
                { isCompanyAdmin: true },
              ],
              status: 'ACTIVE',
              approvalStatus: 'APPROVED',
              id: { not: user.id },
            },
          });

          for (const admin of admins) {
            await app.prisma.notification.create({
              data: {
                userId: admin.id,
                companyId,
                type: 'SYSTEM',
                title: 'New User Requires Approval',
                message: `New user ${newUser.fullName} (${newUser.email}) requires approval.`,
                data: {
                  approvalRequired: true,
                  userId: newUser.id,
                  userName: newUser.fullName,
                  userEmail: newUser.email,
                  createdAt: new Date().toISOString(),
                },
              },
            });
          }
        }

        // TODO: Send welcome email if requested
        if (body.sendWelcomeEmail) {
          // await sendWelcomeEmail(newUser.email, newUser.fullName, body.password, body.autoApprove);
          app.log.info(`Welcome email would be sent to ${newUser.email}`);
        }

        return {
          success: true,
          message: body.autoApprove
            ? 'User created and approved successfully'
            : 'User created successfully (pending approval)',
          user: {
            id: newUser.id,
            email: newUser.email,
            fullName: newUser.fullName,
            status: newUser.status,
            approvalStatus: newUser.approvalStatus,
            rolesAssigned: validRoleIds.length,
            requiresPasswordChange: true,
          },
          nextSteps: body.autoApprove ? [
            'User can login immediately',
            'User must change password on first login',
          ] : [
            'User requires administrator approval',
            'Notify user when approved',
          ],
        };

      } catch (error: any) {
        app.log.error('Failed to create user:', error);
        throw error;
      }
    }
  );

  // Update user (admin)
  app.patch(
    '/admin/users/:userId',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'EDIT'),
        app.validateCompanyMembership,
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
          properties: {
            fullName: { type: 'string', minLength: 2 },
            phone: { type: 'string' },
            address: { type: 'string', minLength: 5 },
            city: { type: 'string' },
            state: { type: 'string' },
            country: { type: 'string' },
            postalCode: { type: 'string' },
            profileImage: { type: 'string' },
            idImage: { type: 'string' },
            idNumber: { type: 'string' },
            idType: { type: 'string' },
            emergencyContactName: { type: 'string' },
            emergencyContactPhone: { type: 'string' },
            emergencyContactRelation: { type: 'string' },
            department: { type: 'string' },
            position: { type: 'string' },
            salary: { type: 'number', minimum: 0 },
            hireDate: { type: 'string', format: 'date' },
            status: { type: 'string', enum: ['ACTIVE', 'SUSPENDED', 'DELETED'] },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { userId } = request.params as { userId: string };
      const user = request.currentUser!;
      const body = request.body as UpdateUserBody;
      const ipAddress = request.ip;

      try {
        // Get current user data
        const currentUser = await app.prisma.user.findUnique({
          where: { id: userId },
          include: {
            staff: true,
          },
        });

        if (!currentUser) {
          throw new NotFoundError('User');
        }

        // Prevent modifying creator users unless you're a creator
        if (currentUser.isCreator && !user.isCreator) {
          throw new AuthorizationError('Cannot modify creator users');
        }

        // Prepare update data
        const updateData: any = {};
        const staffUpdateData: any = {};

        // Basic info updates
        if (body.fullName) updateData.fullName = body.fullName.trim();
        if (body.address) updateData.address = body.address.trim();
        if (body.city) updateData.city = body.city.trim();
        if (body.state) updateData.state = body.state.trim();
        if (body.country) updateData.country = body.country.trim();
        if (body.postalCode) updateData.postalCode = body.postalCode.trim();
        if (body.profileImage) updateData.profileImage = body.profileImage;
        if (body.idImage) updateData.idImage = body.idImage;
        if (body.idNumber) updateData.idNumber = body.idNumber.trim();
        if (body.idType) updateData.idType = body.idType;
        if (body.emergencyContactName) updateData.emergencyContactName = body.emergencyContactName.trim();
        if (body.emergencyContactRelation) updateData.emergencyContactRelation = body.emergencyContactRelation.trim();
        if (body.status) updateData.status = body.status;

        // Phone updates
        if (body.phone) {
          const sanitizedPhone = sanitizePhone(body.phone);

          if (!SecurityUtils.validatePhoneNumber(sanitizedPhone)) {
            throw new ValidationError('Invalid phone number format');
          }

          // Check if phone is already used by another user
          const phoneExists = await app.prisma.user.findFirst({
            where: {
              phone: sanitizedPhone,
              id: { not: userId },
            },
          });

          if (phoneExists) {
            throw new ConflictError('Phone number already registered to another user');
          }

          updateData.phone = sanitizedPhone;
          updateData.phoneVerified = false;
          updateData.phoneVerifiedAt = null;
        }

        if (body.emergencyContactPhone) {
          const sanitizedEmergencyPhone = sanitizePhone(body.emergencyContactPhone);

          if (!SecurityUtils.validatePhoneNumber(sanitizedEmergencyPhone)) {
            throw new ValidationError('Invalid emergency contact phone number');
          }

          updateData.emergencyContactPhone = sanitizedEmergencyPhone;
        }

        // Staff updates
        if (body.department || body.position || body.salary || body.hireDate) {
          staffUpdateData.department = body.department?.trim();
          staffUpdateData.position = body.position?.trim();
          if (body.salary !== undefined) staffUpdateData.salary = body.salary;
          if (body.hireDate) staffUpdateData.hireDate = new Date(body.hireDate);
        }

        // Update user in transaction
        const updatedUser = await app.prisma.$transaction(async (tx) => {
          // Update user
          const userUpdate = await tx.user.update({
            where: { id: userId },
            data: updateData,
          });

          // Update or create staff record
          if (Object.keys(staffUpdateData).length > 0) {
            if (currentUser.staff) {
              await tx.staff.update({
                where: { id: currentUser.staff.id },
                data: staffUpdateData,
              });
            } else {
              await tx.staff.create({
                data: {
                  companyId: currentUser.companyId!,
                  userId: currentUser.id,
                  fullName: userUpdate.fullName,
                  ...staffUpdateData,
                },
              });
            }
          }

          return userUpdate;
        });

        // Log user update
        await auditLogger.logUserUpdate(
          userId,
          currentUser.companyId,
          user.id,
          currentUser,
          updatedUser
        );

        // Create notification for user if status changed
        if (body.status && body.status !== currentUser.status) {
          await app.prisma.notification.create({
            data: {
              userId,
              companyId: currentUser.companyId,
              type: 'SYSTEM',
              title: `Account ${body.status.toLowerCase()}`,
              message: `Your account has been ${body.status.toLowerCase()} by an administrator.`,
              data: {
                statusChanged: true,
                oldStatus: currentUser.status,
                newStatus: body.status,
                changedBy: user.fullName || user.email,
                timestamp: new Date().toISOString(),
              },
            },
          });
        }

        return {
          success: true,
          message: 'User updated successfully',
          user: {
            id: updatedUser.id,
            email: updatedUser.email,
            fullName: updatedUser.fullName,
            phone: updatedUser.phone,
            status: updatedUser.status,
            updatedAt: updatedUser.updatedAt,
          },
        };

      } catch (error: any) {
        app.log.error('Failed to update user:', error);
        throw error;
      }
    }
  );

  // Approve/Reject user
  app.post(
    '/admin/users/approve',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'APPROVE'),
        app.withCompanyScope,
      ],
      schema: {
        body: {
          type: 'object',
          required: ['userId', 'approve'],
          properties: {
            userId: { type: 'string' },
            approve: { type: 'boolean' },
            reason: { type: 'string' },
            roleIds: { type: 'array', items: { type: 'string' } },
            sendNotification: { type: 'boolean', default: true },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const companyId = request.companyId!;
      const body = request.body as ApproveUserBody;
      const ipAddress = request.ip;

      try {
        // Get target user
        const targetUser = await app.prisma.user.findUnique({
          where: { id: body.userId },
          include: {
            roles: true,
          },
        });

        if (!targetUser) {
          throw new NotFoundError('User');
        }

        // Validate company membership
        if (targetUser.companyId !== companyId && !user.isCreator) {
          throw new AuthorizationError('Cannot approve users from other companies');
        }

        // Check current status
        if (targetUser.approvalStatus === 'APPROVED' && body.approve) {
          throw new ConflictError('User is already approved');
        }

        if (targetUser.approvalStatus === 'REJECTED' && !body.approve) {
          throw new ConflictError('User is already rejected');
        }

        // Validate roles if provided
        let validRoleIds: string[] = [];
        if (body.roleIds && body.roleIds.length > 0) {
          const roles = await app.prisma.role.findMany({
            where: {
              id: { in: body.roleIds },
              companyId,
            },
          });

          validRoleIds = roles.map(r => r.id);

          if (validRoleIds.length !== body.roleIds.length) {
            throw new ValidationError('Some roles are invalid or belong to different company');
          }
        }

        // Update user approval status
        const updatedUser = await app.prisma.$transaction(async (tx) => {
          const updateData: any = {
            approvalStatus: body.approve ? 'APPROVED' : 'REJECTED',
            approvedAt: body.approve ? new Date() : null,
            approvedById: user.id,
            rejectionReason: !body.approve ? body.reason : null,
          };

          if (body.approve) {
            updateData.status = 'ACTIVE';
          }

          const userUpdate = await tx.user.update({
            where: { id: body.userId },
            data: updateData,
          });

          // Assign roles if provided
          if (validRoleIds.length > 0) {
            // Remove existing roles
            await tx.userRole.deleteMany({
              where: { userId: body.userId },
            });

            // Assign new roles
            for (const roleId of validRoleIds) {
              await tx.userRole.create({
                data: {
                  userId: body.userId,
                  roleId,
                  assignedById: user.id,
                },
              });
            }
          }

          return userUpdate;
        });

        // Log approval/rejection
        await auditLogger.logAccountApproval(
          body.userId,
          companyId,
          user.id,
          body.approve,
          body.reason
        );

        // Create notification for user
        if (body.sendNotification) {
          await app.prisma.notification.create({
            data: {
              userId: body.userId,
              companyId,
              type: 'SYSTEM',
              title: body.approve ? 'Account Approved' : 'Account Rejected',
              message: body.approve
                ? `Your account has been approved by ${user.fullName || 'an administrator'}. You can now login.`
                : `Your account has been rejected. Reason: ${body.reason || 'No reason provided'}`,
              data: {
                approved: body.approve,
                rejected: !body.approve,
                reason: body.reason,
                approvedBy: user.fullName || user.email,
                timestamp: new Date().toISOString(),
                rolesAssigned: validRoleIds.length,
              },
            },
          });
        }

        // TODO: Send approval/rejection email
        if (body.sendNotification) {
          // await sendApprovalEmail(targetUser.email, targetUser.fullName, body.approve, body.reason);
          app.log.info(`Approval email would be sent to ${targetUser.email}`);
        }

        return {
          success: true,
          message: body.approve ? 'User approved successfully' : 'User rejected successfully',
          user: {
            id: updatedUser.id,
            email: updatedUser.email,
            fullName: updatedUser.fullName,
            approvalStatus: updatedUser.approvalStatus,
            status: updatedUser.status,
            approvedAt: updatedUser.approvedAt,
            rolesAssigned: validRoleIds.length,
          },
        };

      } catch (error: any) {
        app.log.error('User approval failed:', error);
        throw error;
      }
    }
  );

  // Bulk user actions
  app.post(
    '/admin/users/bulk-action',
    {
      preHandler: [
        app.authenticate,
        app.requireApproved,
        app.requirePermission('AUTH', 'EDIT'),
        app.withCompanyScope,
      ],
      schema: {
        body: {
          type: 'object',
          required: ['userIds', 'action'],
          properties: {
            userIds: { type: 'array', items: { type: 'string' }, minItems: 1 },
            action: { type: 'string', enum: ['APPROVE', 'REJECT', 'SUSPEND', 'ACTIVATE', 'DELETE'] },
            reason: { type: 'string' },
            sendNotifications: { type: 'boolean', default: true },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const companyId = request.companyId!;
      const body = request.body as BulkActionBody;
      const ipAddress = request.ip;

      try {
        // Validate all users belong to same company (for non-creators)
        if (!user.isCreator) {
          const users = await app.prisma.user.findMany({
            where: {
              id: { in: body.userIds },
            },
            select: {
              id: true,
              companyId: true,
              isCreator: true,
            },
          });

          const invalidUsers = users.filter(u => u.companyId !== companyId ||
