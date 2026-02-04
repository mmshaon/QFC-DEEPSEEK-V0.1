Write-Host "=== Fixing missing User model ===" -ForegroundColor Cyan
$ErrorActionPreference = "Stop"

$schemaPath = "prisma/schema.prisma"

if (!(Test-Path $schemaPath)) {
  Write-Error "schema.prisma not found"
}

$schema = Get-Content $schemaPath -Raw

if ($schema -match "model User") {
  Write-Host "User model already exists. Skipping."
  exit 0
}

Write-Host "Injecting User model into Prisma schema..."

$userModel = @'

model User {
  id        String   @id @default(uuid())
  email     String   @unique
  password  String
  role      String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
'@

Add-Content -Path $schemaPath -Value $userModel

Write-Host "User model added."
Write-Host "Regenerating Prisma client..."

npx prisma generate

Write-Host "Prisma client regenerated successfully." -ForegroundColor Green
