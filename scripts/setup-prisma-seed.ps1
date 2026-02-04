Write-Host "=== Setting up Prisma seed (one-time) ==="
$ErrorActionPreference = "Stop"

# 1. Ensure scripts folder exists
if (!(Test-Path "scripts")) {
    New-Item -ItemType Directory -Path "scripts" | Out-Null
}

# 2. Create seed script
$seed = @"
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

async function main() {
  const creator = await prisma.user.upsert({
    where: { email: "creator@email.com" },
    update: {},
    create: {
      email: "creator@email.com",
      password: "your-password",
      role: "CREATOR"
    }
  });

  console.log("Seeded creator:", creator.email);
}

main()
  .catch(e => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.\$disconnect();
  });
"@

$seed | Set-Content scripts/bootstrap-creator.js -Encoding ASCII
Write-Host "Seed file created: scripts/bootstrap-creator.js"

# 3. Update prisma.config.ts to include seed
$config = @"
import { defineConfig } from "prisma/config";

export default defineConfig({
  schema: "./prisma/schema.prisma",
  datasource: {
    url: process.env.DATABASE_URL
  },
  migrations: {
    seed: "node scripts/bootstrap-creator.js"
  }
});
"@

$config | Set-Content prisma/prisma.config.ts -Encoding ASCII
Write-Host "Prisma seed registered"

# 4. Run seed
Write-Host "Running Prisma seed..."
npx prisma db seed

Write-Host "PRISMA SEED COMPLETE"
