Write-Host "🛠️ Quantum Finance Engine – Full Repair Script" -ForegroundColor Cyan
$ErrorActionPreference = "Stop"

# 1. Remove BOM from ALL json/ts/js files
Write-Host "🧹 Removing BOM from project files..."
Get-ChildItem -Recurse -Include *.json,*.ts,*.js |
ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Write-Host "  Fixed BOM: $($_.FullName)"
        $text = [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
        [System.IO.File]::WriteAllText($_.FullName, $text, [System.Text.Encoding]::ASCII)
    }
}

# 2. Install Prisma properly
Write-Host "📦 Installing Prisma dependencies..."
npm install prisma @prisma/client tsx --save-dev

# 3. Generate Prisma Client
Write-Host "⚙️ Generating Prisma Client..."
npx prisma generate

# 4. Force API to use tsx instead of ts-node
Write-Host "🔧 Fixing API dev script..."
$apiPkg = "apps/api/package.json"
$pkgJson = Get-Content $apiPkg | ConvertFrom-Json
$pkgJson.scripts.dev = "tsx server.ts"
$pkgJson | ConvertTo-Json -Depth 10 | Set-Content $apiPkg -Encoding ASCII

# 5. Validate Prisma
Write-Host "🔍 Validating Prisma schema..."
npx prisma validate

# 6. Seed database (safe)
Write-Host "🌱 Seeding database..."
npx prisma db seed

Write-Host ""
Write-Host "✅ SYSTEM FIXED SUCCESSFULLY" -ForegroundColor Green
Write-Host "Next commands:"
Write-Host "  npm run dev:api"
Write-Host "  npm run dev:web"
