Write-Host "=== Setting up Prisma structure ==="
$ErrorActionPreference = "Stop"

# 1. Create prisma directory
if (!(Test-Path "prisma")) {
    New-Item -ItemType Directory -Path "prisma" | Out-Null
}

# 2. Create minimal schema.prisma
$schema = @"
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}
"@

$schema | Set-Content prisma/schema.prisma -Encoding ASCII

Write-Host "schema.prisma created"

# 3. Create prisma.config.ts
$config = @"
import { defineConfig } from "prisma/config";

export default defineConfig({
  schema: "./prisma/schema.prisma",
  migrations: {
    seed: "node scripts/bootstrap-creator.js"
  }
});
"@

$config | Set-Content prisma/prisma.config.ts -Encoding ASCII

Write-Host "prisma.config.ts created"

# 4. Generate Prisma Client
Write-Host "Generating Prisma Client..."
npx prisma generate

# 5. Validate schema
Write-Host "Validating Prisma schema..."
npx prisma validate

Write-Host "Prisma setup COMPLETE"
