Write-Host "=== Quantum Finance Engine :: DEV START ===" -ForegroundColor Cyan
$ErrorActionPreference = "Stop"

# 1. Check PostgreSQL
$pg = Get-Service -Name postgresql* -ErrorAction SilentlyContinue
if (-not $pg -or $pg.Status -ne "Running") {
  Write-Host "❌ PostgreSQL is not running." -ForegroundColor Red
  Write-Host "Run scripts/install-postgres.ps1 first." -ForegroundColor Yellow
  exit 1
}

# 2. Check .env
if (-not (Test-Path ".env")) {
  Write-Host "❌ .env file missing." -ForegroundColor Red
  Write-Host "Run scripts/setup-database.ps1 first." -ForegroundColor Yellow
  exit 1
}

# 3. Prisma client
Write-Host "Generating Prisma Client..."
npx prisma generate | Out-Null

# 4. Seed database
Write-Host "Seeding database..."
node scripts/bootstrap-creator.js

# 5. Start API + Web
Write-Host "Starting API and Web servers..."
Start-Process powershell -ArgumentList "npm run dev:api"
Start-Process powershell -ArgumentList "npm run dev:web"

Write-Host "🚀 SYSTEM UP AND RUNNING" -ForegroundColor Green
Write-Host "API  → http://localhost:4000"
Write-Host "WEB  → http://localhost:3000"
