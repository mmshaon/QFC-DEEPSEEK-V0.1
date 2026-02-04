Write-Host "=== FINAL Prisma seed fix (guaranteed) ==="
$ErrorActionPreference = "Stop"

# Load root package.json
$pkgPath = "package.json"
$pkg = Get-Content $pkgPath | ConvertFrom-Json

# Ensure prisma section exists
if (-not $pkg.prisma) {
    $pkg | Add-Member -MemberType NoteProperty -Name prisma -Value @{}
}

# Register seed command (Prisma ALWAYS reads this)
$pkg.prisma.seed = "node scripts/bootstrap-creator.js"

# Save clean JSON (NO BOM)
$pkg | ConvertTo-Json -Depth 10 | Set-Content $pkgPath -Encoding ASCII

Write-Host "Seed registered in package.json"

# Run seed
Write-Host "Running Prisma seed..."
npx prisma db seed

Write-Host "PRISMA SEED SUCCESSFUL"
