Write-Host "🚀 Quantum Finance Engine – Dev Setup Starting..." -ForegroundColor Cyan

$ErrorActionPreference = "Stop"

# 1. Remove BOM from common files
Write-Host "🧹 Removing BOM from config files..."

Get-ChildItem -Recurse -Include *.json,*.ts,*.js |
ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Write-Host "  Fixing BOM: $($_.FullName)"
        $text = [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
        [System.IO.File]::WriteAllText($_.FullName, $text, [System.Text.Encoding]::ASCII)
    }
}

# 2. Ensure prisma folder exists
if (-not (Test-Path "prisma")) {
    New-Item -ItemType Directory prisma | Out-Null
}

# 3. Create prisma.config.ts
Write-Host "🧠 Configuring Prisma seed..."

@"
import { defineConfig } from 'prisma/config'

export default defineConfig({
  migrations: {
    seed: 'node prisma/seed.ts',
  },
})
"@ | Set-Content prisma/prisma.config.ts -Encoding ASCII

# 4. Create placeholder seed.ts if missing
if (-not (Test-Path "prisma/seed.ts")) {
    Write-Host "🌱 Creating prisma/seed.ts placeholder"

@"
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

async function main() {
  console.log('Prisma seed running (placeholder)')
}

main()
  .catch(console.error)
  .finally(() => prisma.\$disconnect())
"@ | Set-Content prisma/seed.ts -Encoding ASCII
}

# 5. Install required dev deps
Write-Host "📦 Installing required dependencies..."
npm install -D prisma tsx typescript @types/node --silent

# 6. Validate Prisma schema
Write-Host "🔍 Validating Prisma schema..."
npx prisma validate

# 7. Run seed
Write-Host "🌱 Running Prisma seed..."
npx prisma db seed

Write-Host "✅ Setup complete. You can now run:" -ForegroundColor Green
Write-Host "   npm run dev:web"
Write-Host "   npm run dev:api"
