Write-Host "=== Prisma v7 PostgreSQL adapter fix ===" -ForegroundColor Cyan
$ErrorActionPreference = "Stop"

Write-Host "Installing Prisma PostgreSQL adapter..."
npm install @prisma/adapter-pg pg dotenv

$seedPath = "scripts/bootstrap-creator.js"

$seedCode = @'
const { PrismaClient } = require("@prisma/client");
const { PrismaPg } = require("@prisma/adapter-pg");
const { Pool } = require("pg");
require("dotenv").config();

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

async function main() {
  console.log("Seeding database...");

  const email = "creator@email.com";

  const existing = await prisma.user.findUnique({
    where: { email }
  });

  if (existing) {
    console.log("Creator already exists. Skipping.");
    return;
  }

  await prisma.user.create({
    data: {
      email,
      password: "changeme",
      role: "CREATOR"
    }
  });

  console.log("Creator user created.");
}

main()
  .catch((e) => {
    console.error("Seed failed:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    await pool.end();
  });
'@

Set-Content -Path $seedPath -Value $seedCode -Encoding ASCII

Write-Host "Prisma v7 PostgreSQL adapter configured correctly." -ForegroundColor Green
