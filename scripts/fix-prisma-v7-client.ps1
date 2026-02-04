Write-Host "=== Fixing Prisma v7 client initialization ===" -ForegroundColor Cyan
$ErrorActionPreference = "Stop"

$seedPath = "scripts/bootstrap-creator.js"

$seedCode = @'
const { PrismaClient } = require("@prisma/client");
require("dotenv").config();

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing");
  process.exit(1);
}

const prisma = new PrismaClient({
  datasourceUrl: process.env.DATABASE_URL
});

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
      email: email,
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
  });
'@

Set-Content -Path $seedPath -Value $seedCode -Encoding ASCII

Write-Host "Prisma v7 seed script fixed correctly." -ForegroundColor Green
