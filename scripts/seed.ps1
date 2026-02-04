Write-Host "=== Quantum Finance Engine :: Database Seed ===" -ForegroundColor Cyan
$ErrorActionPreference = "Stop"

if (-not (Test-Path ".env")) {
  Write-Host "❌ No .env file found. Run setup-database.ps1 first." -ForegroundColor Red
  exit 1
}

Write-Host "Running database seed..."

node scripts/bootstrap-creator.js

if ($LASTEXITCODE -ne 0) {
  Write-Host "❌ DATABASE SEED FAILED" -ForegroundColor Red
  exit 1
}

Write-Host "✅ DATABASE SEEDED SUCCESSFULLY" -ForegroundColor Green
