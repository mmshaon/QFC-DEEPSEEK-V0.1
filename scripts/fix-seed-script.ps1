Write-Host "=== Fixing Prisma seed script (hard reset) ===" -ForegroundColor Cyan
$ErrorActionPreference = "Stop"

$seedPath = "scripts/bootstrap-creator.js"

$seedCode = @'
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

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

Write-Host "Seed script fixed successfully." -ForegroundColor Green
