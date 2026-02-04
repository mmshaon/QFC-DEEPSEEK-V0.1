Write-Host "=== Database configuration setup ===" -ForegroundColor Cyan
$ErrorActionPreference = "Stop"

$envPath = ".env"

if (Test-Path $envPath) {
  Write-Host ".env already exists. Skipping." -ForegroundColor Yellow
  exit 0
}

$envContent = @"
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/quantum_finance
"@

Set-Content -Path $envPath -Value $envContent -Encoding ASCII

Write-Host ".env file created successfully." -ForegroundColor Green
Write-Host "IMPORTANT: You must have PostgreSQL running locally." -ForegroundColor Yellow
