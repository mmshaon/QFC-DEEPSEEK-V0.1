Write-Host "=== Fixing Prisma v7 configuration ==="
$ErrorActionPreference = "Stop"

# Ensure prisma directory exists
if (!(Test-Path "prisma")) {
    New-Item -ItemType Directory -Path "prisma" | Out-Null
}

# 1. Correct schema.prisma (NO url)
$schema = @"
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
}
"@

$schema | Set-Content prisma/schema.prisma -Encoding ASCII
Write-Host "schema.prisma fixed (Prisma v7 compatible)"

# 2. Correct prisma.config.ts (URL moved here)
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
Write-Host "prisma.config.ts fixed"

# 3. Generate client
Write-Host "Generating Prisma Client..."
npx prisma generate

# 4. Validate schema
Write-Host "Validating Prisma schema..."
npx prisma validate

Write-Host "Prisma v7 FIX COMPLETE"
