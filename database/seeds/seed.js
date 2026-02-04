// This seed script creates the initial system setup
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting system bootstrap...');

  // ==================== CREATE SYSTEM PERMISSIONS ====================
  console.log('Creating system permissions...');

  const permissions = [
    // Dashboard
    { module: 'DASHBOARD', action: 'VIEW', name: 'View Dashboard', category: 'Dashboard' },
    { module: 'DASHBOARD', action: 'EXPORT', name: 'Export Dashboard Data', category: 'Dashboard' },

    // Auth & Users
    { module: 'AUTH', action: 'VIEW', name: 'View Users', category: 'Administration' },
    { module: 'AUTH', action: 'CREATE', name: 'Create Users', category: 'Administration' },
    { module: 'AUTH', action: 'EDIT', name: 'Edit Users', category: 'Administration' },
    { module: 'AUTH', action: 'DELETE', name: 'Delete Users', category: 'Administration' },
    { module: 'AUTH', action: 'APPROVE', name: 'Approve Users', category: 'Administration' },
    { module: 'AUTH', action: 'REJECT', name: 'Reject Users', category: 'Administration' },

    // Expenses
    { module: 'EXPENSES', action: 'VIEW', name: 'View Expenses', category: 'Finance' },
    { module: 'EXPENSES', action: 'CREATE', name: 'Create Expenses', category: 'Finance' },
    { module: 'EXPENSES', action: 'EDIT', name: 'Edit Expenses', category: 'Finance' },
    { module: 'EXPENSES', action: 'DELETE', name: 'Delete Expenses', category: 'Finance' },
    { module: 'EXPENSES', action: 'APPROVE', name: 'Approve Expenses', category: 'Finance' },
    { module: 'EXPENSES', action: 'REJECT', name: 'Reject Expenses', category: 'Finance' },
    { module: 'EXPENSES', action: 'EXPORT', name: 'Export Expenses', category: 'Finance' },

    // Income
    { module: 'INCOME', action: 'VIEW', name: 'View Income', category: 'Finance' },
    { module: 'INCOME', action: 'CREATE', name: 'Create Bills', category: 'Finance' },
    { module: 'INCOME', action: 'EDIT', name: 'Edit Bills', category: 'Finance' },
    { module: 'INCOME', action: 'DELETE', name: 'Delete Bills', category: 'Finance' },
    { module: 'INCOME', action: 'APPROVE', name: 'Approve Bills', category: 'Finance' },
    { module: 'INCOME', action: 'REJECT', name: 'Reject Bills', category: 'Finance' },
    { module: 'INCOME', action: 'EXPORT', name: 'Export Income Data', category: 'Finance' },

    // Projects
    { module: 'PROJECTS', action: 'VIEW', name: 'View Projects', category: 'Operations' },
    { module: 'PROJECTS', action: 'CREATE', name: 'Create Projects', category: 'Operations' },
    { module: 'PROJECTS', action: 'EDIT', name: 'Edit Projects', category: 'Operations' },
    { module: 'PROJECTS', action: 'DELETE', name: 'Delete Projects', category: 'Operations' },

    // HR
    { module: 'HR_ADMIN', action: 'VIEW', name: 'View HR Data', category: 'HR' },
    { module: 'HR_ADMIN', action: 'CREATE', name: 'Create HR Records', category: 'HR' },
    { module: 'HR_ADMIN', action: 'EDIT', name: 'Edit HR Records', category: 'HR' },
    { module: 'HR_ADMIN', action: 'DELETE', name: 'Delete HR Records', category: 'HR' },

    // Control Panel (Creator Only)
    { module: 'CONTROL_PANEL', action: 'VIEW', name: 'Access Control Panel', category: 'System' },
    { module: 'CONTROL_PANEL', action: 'EDIT', name: 'Modify System Settings', category: 'System' },

    // Settings
    { module: 'SETTINGS', action: 'VIEW', name: 'View Settings', category: 'System' },
    { module: 'SETTINGS', action: 'EDIT', name: 'Edit Settings', category: 'System' },
  ];

  for (const perm of permissions) {
    await prisma.permission.upsert({
      where: { module_action: { module: perm.module, action: perm.action } },
      update: perm,
      create: perm,
    });
  }

  console.log(`✅ Created ${permissions.length} system permissions`);

  // ==================== CREATE DEFAULT THEMES ====================
  console.log('Creating default themes...');

  const themes = [
    {
      name: 'Deep Cyan Professional',
      primaryColor: '#00bcd4',
      secondaryColor: '#00e5ff',
      backgroundGradient: 'linear-gradient(135deg, #002b36, #003f5c)',
      fontFamily: 'Inter, system-ui, sans-serif',
      borderRadius: '12px',
      animationSpeed: '300ms',
    },
    {
      name: 'Light Modern',
      primaryColor: '#0366d6',
      secondaryColor: '#2188ff',
      backgroundGradient: 'linear-gradient(135deg, #f6f8fa, #ffffff)',
      fontFamily: 'Inter, system-ui, sans-serif',
      borderRadius: '8px',
      animationSpeed: '200ms',
    },
    {
      name: 'Dark Matrix',
      primaryColor: '#00ff41',
      secondaryColor: '#008f11',
      backgroundGradient: 'linear-gradient(135deg, #0a0a0a, #1a1a1a)',
      fontFamily: 'Monaco, Consolas, monospace',
      borderRadius: '4px',
      animationSpeed: '150ms',
    },
  ];

  for (const theme of themes) {
    await prisma.theme.upsert({
      where: { name: theme.name },
      update: theme,
      create: theme,
    });
  }

  console.log('✅ Created default themes');

  // ==================== CREATE SYSTEM MODULES ====================
  console.log('Creating system modules...');

  const modules = [
    { key: 'DASHBOARD', name: 'Dashboard', description: 'Main dashboard with analytics and overview' },
    { key: 'EXPENSES', name: 'Expenses', description: 'Manage and track company expenses' },
    { key: 'INCOME', name: 'Income & Billing', description: 'Manage income, bills, and payments' },
    { key: 'INVESTMENTS', name: 'Investments', description: 'Track and manage investments' },
    { key: 'ASSETS', name: 'Assets', description: 'Manage company assets' },
    { key: 'LIABILITIES', name: 'Liabilities', description: 'Track company liabilities' },
    { key: 'PROJECTS', name: 'Projects', description: 'Manage projects and related operations' },
    { key: 'HR_ADMIN', name: 'HR & Admin', description: 'Human resources and administration' },
    { key: 'CONTROL_PANEL', name: 'Control Panel', description: 'System configuration and management' },
    { key: 'SETTINGS', name: 'Settings', description: 'User and system settings' },
    { key: 'CONTACT', name: 'Contact & Help', description: 'Contact information and help resources' },
  ];

  for (const moduleDef of modules) {
    await prisma.moduleDefinition.upsert({
      where: { key: moduleDef.key },
      update: moduleDef,
      create: moduleDef,
    });
  }

  console.log(`✅ Created ${modules.length} system modules`);
}

main()
  .catch((e) => {
    console.error('❌ Bootstrap failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
