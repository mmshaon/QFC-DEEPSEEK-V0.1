Write-Host "=== Initializing Database (Migrate + Seed) ===" -ForegroundColor Cyan
$ErrorActionPreference = "Stop"

Write-Host "Running Prisma migrate (creating tables)..."
npx prisma migrate dev --name init --skip-seed

Write-Host "Database tables created."

Write-Host "Running seed script..."
node scripts/bootstrap-creator.js

Write-Host "DATABASE INITIALIZED SUCCESSFULLY" -ForegroundColor Green
