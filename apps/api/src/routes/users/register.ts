import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { AuditLogger } from '../../utils/audit';
import { SecurityUtils } from '../../utils/security';
import { ValidationError, ConflictError, NotFoundError } from '../../utils/errors';
import { validate, sanitizePhone, sanitizeEmail, VALIDATION_PATTERNS } from '../../utils/validation';

interface RegisterUserBody {
  email: string;
  password: string;
  confirmPassword: string;
  fullName: string;
  phone: string;
  address: string;
  city?: string;
  state?: string;
  country?: string;
  postalCode?: string;
  companyName?: string;
  profileImage?: string;
  idImage?: string;
  idNumber: string;
  idType?: string;
  emergencyContactName: string;
  emergencyContactPhone: string;
  emergencyContactRelation?: string;
  acceptTerms: boolean;
  marketingConsent?: boolean;
}

interface RegisterCompanyBody {
  name: string;
  legalName?: string;
  taxId?: string;
  registrationNumber?: string;
  address: string;
  city?: string;
  state?: string;
  country?: string;
  postalCode?: string;
  phone: string;
  email: string;
  website?: string;
  logoUrl?: string;
}

export async function registerRoutes(app: FastifyInstance) {
  const auditLogger = new AuditLogger(app);

  // User registration (public endpoint)
  app.post(
    '/register',
    {
      schema: {
        body: {
          type: 'object',
          required: [
            'email',
            'password',
            'confirmPassword',
            'fullName',
            'phone',
            'address',
            'idNumber',
            'emergencyContactName',
            'emergencyContactPhone',
            'acceptTerms',
          ],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string', minLength: 12 },
            confirmPassword: { type: 'string' },
            fullName: { type: 'string', minLength: 2 },
            phone: { type: 'string' },
            address: { type: 'string', minLength: 5 },
            city: { type: 'string' },
            state: { type: 'string' },
            country: { type: 'string', default: 'SA' },
            postalCode: { type: 'string' },
            companyName: { type: 'string' },
            profileImage: { type: 'string' },
            idImage: { type: 'string' },
            idNumber: { type: 'string' },
            idType: { type: 'string', default: 'NATIONAL_ID' },
            emergencyContactName: { type: 'string' },
            emergencyContactPhone: { type: 'string' },
            emergencyContactRelation: { type: 'string' },
            acceptTerms: { type: 'boolean' },
            marketingConsent: { type: 'boolean' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as RegisterUserBody;
      const ipAddress = request.ip;
      const userAgent = request.headers['user-agent'];

      try {
        // Validate required fields
        if (!body.acceptTerms) {
          throw new ValidationError('You must accept the terms and conditions');
        }

        if (body.password !== body.confirmPassword) {
          throw new ValidationError('Passwords do not match');
        }

        // Validate password strength
        const passwordStrength = SecurityUtils.checkPasswordStrength(body.password);
        if (passwordStrength.strength === 'weak' || passwordStrength.strength === 'fair') {
          throw new ValidationError('Password is too weak. ' + passwordStrength.feedback.join(' '));
        }

        // Validate phone number
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

        // Hash password
        const passwordHash = await SecurityUtils.hashPassword(body.password);

        // Create user in transaction
        const user = await app.prisma.$transaction(async (tx) => {
          // Create user
          const newUser = await tx.user.create({
            data: {
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
              status: 'PENDING_APPROVAL',
              approvalStatus: 'PENDING',
              mustChangePassword: true,
            },
          });

          // If company name provided, create company and assign user as admin
          if (body.companyName) {
            const company = await tx.company.create({
              data: {
                name: body.companyName.trim(),
                address: body.address.trim(),
                phone: sanitizedPhone,
                email: sanitizedEmail,
                createdById: newUser.id,
              },
            });

            // Update user with company ID
            await tx.user.update({
              where: { id: newUser.id },
              data: { companyId: company.id, isCompanyAdmin: true },
            });

            // Create company admin role
            const adminRole = await tx.role.create({
              data: {
                companyId: company.id,
                name: 'Company Admin',
                description: 'Company administrator with full access',
                isSystem: true,
                isDefault: true,
                level: 1,
              },
            });

            // Assign permissions to admin role
            const adminPermissions = await tx.permission.findMany({
              where: {
                OR: [
                  { module: 'DASHBOARD' },
                  { module: 'AUTH' },
                  { module: 'EXPENSES' },
                  { module: 'INCOME' },
                  { module: 'PROJECTS' },
                  { module: 'HR_ADMIN' },
                  { module: 'SETTINGS' },
                ],
              },
            });

            for (const permission of adminPermissions) {
              await tx.rolePermission.create({
                data: {
                  roleId: adminRole.id,
                  permissionId: permission.id,
                },
              });
            }

            // Assign admin role to user
            await tx.userRole.create({
              data: {
                userId: newUser.id,
                roleId: adminRole.id,
                assignedById: newUser.id,
              },
            });

            // Create company settings
            await tx.companySettings.create({
              data: {
                companyId: company.id,
                language: 'en',
                currency: 'SAR',
                darkModeDefault: true,
              },
            });

            // Enable all modules for company
            const modules = await tx.moduleDefinition.findMany();
            for (const module of modules) {
              await tx.companyModule.create({
                data: {
                  companyId: company.id,
                  moduleId: module.id,
                  isEnabled: true,
                  isLocked: module.key === 'CONTROL_PANEL',
                },
              });
            }

            // Update user with company context
            newUser.companyId = company.id;
            newUser.isCompanyAdmin = true;
          }

          return newUser;
        });

        // Send notification to creators/admins about new registration
        const creatorsAndAdmins = await app.prisma.user.findMany({
          where: {
            OR: [
              { isCreator: true },
              { isSuperAdmin: true },
              { isCompanyAdmin: true },
            ],
            status: 'ACTIVE',
            approvalStatus: 'APPROVED',
          },
        });

        for (const admin of creatorsAndAdmins) {
          await app.prisma.notification.create({
            data: {
              userId: admin.id,
              companyId: admin.companyId,
              type: 'SYSTEM',
              title: 'New User Registration',
              message: `New user registered: ${user.fullName} (${user.email})`,
              data: {
                userId: user.id,
                userName: user.fullName,
                userEmail: user.email,
                hasCompany: !!body.companyName,
                companyName: body.companyName,
              },
            },
          });
        }

        // Log registration
        await auditLogger.logUserCreation('system', user.companyId, user.id, {
          email: user.email,
          fullName: user.fullName,
          phone: user.phone,
          companyCreated: !!body.companyName,
          companyName: body.companyName,
          ipAddress,
          userAgent,
        });

        // Create welcome notification for user
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: user.companyId,
            type: 'SYSTEM',
            title: 'Welcome to Quantum Finance Engine!',
            message: 'Your registration is pending approval. You will be notified once your account is approved.',
            data: {
              welcome: true,
              status: 'PENDING_APPROVAL',
            },
          },
        });

        return {
          success: true,
          message: 'Registration successful. Your account is pending approval.',
          userId: user.id,
          requiresApproval: true,
          hasCompany: !!body.companyName,
          estimatedApprovalTime: '24-48 hours',
        };

      } catch (error: any) {
        app.log.error('User registration failed:', error);
        throw error;
      }
    }
  );

  // Complete company registration (for users who didn't provide company during registration)
  app.post(
    '/register/company',
    {
      preHandler: [app.authenticate, app.requireApproved],
      schema: {
        body: {
          type: 'object',
          required: ['name', 'address', 'phone', 'email'],
          properties: {
            name: { type: 'string', minLength: 2 },
            legalName: { type: 'string' },
            taxId: { type: 'string' },
            registrationNumber: { type: 'string' },
            address: { type: 'string', minLength: 5 },
            city: { type: 'string' },
            state: { type: 'string' },
            country: { type: 'string', default: 'SA' },
            postalCode: { type: 'string' },
            phone: { type: 'string' },
            email: { type: 'string', format: 'email' },
            website: { type: 'string' },
            logoUrl: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser!;
      const body = request.body as RegisterCompanyBody;
      const ipAddress = request.ip;

      try {
        // Check if user already has a company
        if (user.companyId) {
          throw new ConflictError('User already has a company assigned');
        }

        // Check if company name already exists
        const existingCompany = await app.prisma.company.findFirst({
          where: {
            OR: [
              { name: body.name },
              { taxId: body.taxId },
              { email: body.email },
            ],
          },
        });

        if (existingCompany) {
          throw new ConflictError('Company already registered');
        }

        // Create company in transaction
        const company = await app.prisma.$transaction(async (tx) => {
          // Create company
          const newCompany = await tx.company.create({
            data: {
              name: body.name.trim(),
              legalName: body.legalName?.trim() || body.name.trim(),
              taxId: body.taxId?.trim(),
              registrationNumber: body.registrationNumber?.trim(),
              address: body.address.trim(),
              city: body.city?.trim(),
              state: body.state?.trim(),
              country: body.country || 'SA',
              postalCode: body.postalCode?.trim(),
              phone: sanitizePhone(body.phone),
              email: sanitizeEmail(body.email),
              website: body.website?.trim(),
              logoUrl: body.logoUrl,
              createdById: user.id,
            },
          });

          // Update user as company admin
          await tx.user.update({
            where: { id: user.id },
            data: {
              companyId: newCompany.id,
              isCompanyAdmin: true,
            },
          });

          // Create company admin role
          const adminRole = await tx.role.create({
            data: {
              companyId: newCompany.id,
              name: 'Company Admin',
              description: 'Company administrator with full access',
              isSystem: true,
              isDefault: true,
              level: 1,
            },
          });

          // Assign permissions to admin role
          const adminPermissions = await tx.permission.findMany({
            where: {
              OR: [
                { module: 'DASHBOARD' },
                { module: 'AUTH' },
                { module: 'EXPENSES' },
                { module: 'INCOME' },
                { module: 'PROJECTS' },
                { module: 'HR_ADMIN' },
                { module: 'SETTINGS' },
              ],
            },
          });

          for (const permission of adminPermissions) {
            await tx.rolePermission.create({
              data: {
                roleId: adminRole.id,
                permissionId: permission.id,
              },
            });
          }

          // Assign admin role to user
          await tx.userRole.create({
            data: {
              userId: user.id,
              roleId: adminRole.id,
              assignedById: user.id,
            },
          });

          // Create company settings
          await tx.companySettings.create({
            data: {
              companyId: newCompany.id,
              language: 'en',
              currency: 'SAR',
              darkModeDefault: true,
            },
          });

          // Enable all modules for company
          const modules = await tx.moduleDefinition.findMany();
          for (const module of modules) {
            await tx.companyModule.create({
              data: {
                companyId: newCompany.id,
                moduleId: module.id,
                isEnabled: true,
                isLocked: module.key === 'CONTROL_PANEL',
              },
            });
          }

          return newCompany;
        });

        // Log company registration
        await auditLogger.log({
          userId: user.id,
          companyId: company.id,
          actionType: 'COMPANY_CREATE',
          entityType: 'Company',
          entityId: company.id,
          description: `Company registered: ${company.name}`,
          metadata: {
            companyName: company.name,
            taxId: company.taxId,
            ipAddress,
          },
        });

        // Create notification for user
        await app.prisma.notification.create({
          data: {
            userId: user.id,
            companyId: company.id,
            type: 'SYSTEM',
            title: 'Company Registered Successfully',
            message: `Your company "${company.name}" has been registered and all features are now available.`,
            data: {
              companyId: company.id,
              companyName: company.name,
              setupComplete: true,
            },
          },
        });

        // Update user in request context
        user.companyId = company.id;
        user.isCompanyAdmin = true;

        return {
          success: true,
          message: 'Company registered successfully',
          company: {
            id: company.id,
            name: company.name,
            legalName: company.legalName,
            taxId: company.taxId,
            email: company.email,
            phone: company.phone,
          },
          user: {
            id: user.id,
            isCompanyAdmin: true,
            companyId: company.id,
          },
        };

      } catch (error: any) {
        app.log.error('Company registration failed:', error);
        throw error;
      }
    }
  );

  // Check registration status
  app.get(
    '/register/status/:userId',
    {
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

      try {
        const user = await app.prisma.user.findUnique({
          where: { id: userId },
          select: {
            id: true,
            email: true,
            fullName: true,
            status: true,
            approvalStatus: true,
            approvedAt: true,
            approvedBy: {
              select: {
                id: true,
                fullName: true,
                email: true,
              },
            },
            rejectionReason: true,
            companyId: true,
            company: {
              select: {
                id: true,
                name: true,
                isVerified: true,
              },
            },
            createdAt: true,
          },
        });

        if (!user) {
          throw new NotFoundError('User');
        }

        // Don't expose sensitive info for pending users
        if (user.approvalStatus !== 'APPROVED') {
          return {
            success: true,
            user: {
              id: user.id,
              status: user.status,
              approvalStatus: user.approvalStatus,
              rejectionReason: user.rejectionReason,
              createdAt: user.createdAt,
              requiresApproval: true,
            },
          };
        }

        return {
          success: true,
          user,
        };

      } catch (error: any) {
        app.log.error('Failed to fetch registration status:', error);
        throw error;
      }
    }
  );

  // Resend verification email
  app.post(
    '/register/resend-verification',
    {
      schema: {
        body: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as { email: string };
      const ipAddress = request.ip;

      try {
        const user = await app.prisma.user.findUnique({
          where: { email: sanitizeEmail(body.email) },
        });

        if (!user) {
          // Don't reveal if user exists or not
          return {
            success: true,
            message: 'If an account exists with this email, a verification email has been sent.',
          };
        }

        // Check if already verified
        if (user.emailVerifiedAt) {
          return {
            success: true,
            message: 'Email is already verified.',
          };
        }

        // Generate verification token
        const { token, expiresAt } = SecurityUtils.generateEmailVerificationToken();

        // Save verification token
        await app.prisma.verificationToken.create({
          data: {
            userId: user.id,
            token,
            type: 'EMAIL_VERIFICATION',
            expiresAt,
          },
        });

        // TODO: Send actual email (integration with email service)
        // For now, log it
        app.log.info(`Verification email would be sent to ${user.email}`);
        app.log.info(`Verification token: ${token}`);

        // Log verification request
        await auditLogger.log({
          userId: user.id,
          companyId: user.companyId,
          actionType: 'VERIFICATION_RESEND',
          entityType: 'User',
          entityId: user.id,
          description: 'Email verification requested',
          metadata: {
            email: user.email,
            ipAddress,
          },
        });

        return {
          success: true,
          message: 'Verification email sent successfully.',
          // In development, return token for testing
          ...(process.env.NODE_ENV === 'development' && { token }),
        };

      } catch (error: any) {
        app.log.error('Failed to resend verification:', error);
        throw error;
      }
    }
  );

  // Verify email
  app.post(
    '/register/verify-email',
    {
      schema: {
        body: {
          type: 'object',
          required: ['token'],
          properties: {
            token: { type: 'string' },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const body = request.body as { token: string };
      const ipAddress = request.ip;

      try {
        // Find valid verification token
        const verificationToken = await app.prisma.verificationToken.findFirst({
          where: {
            token: body.token,
            type: 'EMAIL_VERIFICATION',
            expiresAt: { gt: new Date() },
            usedAt: null,
          },
          include: {
            user: true,
          },
        });

        if (!verificationToken) {
          throw new ValidationError('Invalid or expired verification token');
        }

        // Mark token as used and verify email
        await app.prisma.$transaction(async (tx) => {
          await tx.verificationToken.update({
            where: { id: verificationToken.id },
            data: { usedAt: new Date() },
          });

          await tx.user.update({
            where: { id: verificationToken.user.id },
            data: { emailVerifiedAt: new Date() },
          });
        });

        // Log verification
        await auditLogger.log({
          userId: verificationToken.user.id,
          companyId: verificationToken.user.companyId,
          actionType: 'EMAIL_VERIFIED',
          entityType: 'User',
          entityId: verificationToken.user.id,
          description: 'Email address verified',
          metadata: {
            ipAddress,
          },
        });

        // Create notification for user
        await app.prisma.notification.create({
          data: {
            userId: verificationToken.user.id,
            companyId: verificationToken.user.companyId,
            type: 'SYSTEM',
            title: 'Email Verified',
            message: 'Your email address has been successfully verified.',
          },
        });

        return {
          success: true,
          message: 'Email verified successfully.',
        };

      } catch (error: any) {
        app.log.error('Email verification failed:', error);
        throw error;
      }
    }
  );
}
