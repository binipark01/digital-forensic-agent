param(
    [string]$TempDir = (Join-Path $env:TEMP "dfaa-frontend-dev"),
    [string]$HostName = "127.0.0.1",
    [int]$Port = 5173
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$frontend = Join-Path $repoRoot "frontend"

New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
Copy-Item -LiteralPath `
    (Join-Path $frontend "package.json"), `
    (Join-Path $frontend "index.html"), `
    (Join-Path $frontend "tsconfig.json"), `
    (Join-Path $frontend "tsconfig.node.json"), `
    (Join-Path $frontend "vite.config.ts") `
    -Destination $TempDir -Force

$srcTarget = Join-Path $TempDir "src"
if (Test-Path -LiteralPath $srcTarget) {
    Remove-Item -LiteralPath $srcTarget -Recurse -Force
}
Copy-Item -LiteralPath (Join-Path $frontend "src") -Destination $srcTarget -Recurse

Push-Location $TempDir
try {
    npm install --prefer-online --no-audit --no-fund
    npm run dev -- --host $HostName --port $Port
}
finally {
    Pop-Location
}

