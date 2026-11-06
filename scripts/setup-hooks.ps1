# Enable project git hooks (.githooks).
# Usage: powershell -ExecutionPolicy Bypass -File scripts/setup-hooks.ps1

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
git config core.hooksPath .githooks
Write-Host ("Git hooks path: " + (git config core.hooksPath))
Write-Host "Done: pre-commit and pre-push are active."
