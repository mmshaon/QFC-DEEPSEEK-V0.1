Write-Host "=== Installing PostgreSQL for Quantum Finance Engine ===" -ForegroundColor Cyan
$ErrorActionPreference = "Stop"

$installerUrl = "https://get.enterprisedb.com/postgresql/postgresql-16.2-1-windows-x64.exe"
$installerPath = "$env:TEMP\postgresql-installer.exe"

if (Get-Service -Name postgresql* -ErrorAction SilentlyContinue) {
  Write-Host "PostgreSQL already installed. Skipping install." -ForegroundColor Yellow
  exit 0
}

Write-Host "Downloading PostgreSQL installer..."
Invoke-WebRequest $installerUrl -OutFile $installerPath

Write-Host "Installing PostgreSQL (this may take a few minutes)..."

Start-Process -FilePath $installerPath -ArgumentList `
  "--mode unattended",
  "--superpassword postgres",
  "--servicename postgresql",
  "--serverport 5432" `
  -Wait

Write-Host "Starting PostgreSQL service..."
Start-Service postgresql

Write-Host "PostgreSQL installed and running." -ForegroundColor Green
