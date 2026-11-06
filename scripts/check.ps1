# Local run of all available gates (L1 + part of L2).
# Usage: powershell -ExecutionPolicy Bypass -File scripts/check.ps1

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$env:Path = "$env:USERPROFILE\.cargo\bin;C:\msys64\ucrt64\bin;$env:Path"
if (-not $env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = Join-Path $env:TEMP "opencode\vpn-target"
}

$checks = @(
    @{ Name = "fmt";    Cmd = "cargo fmt --all -- --check" },
    @{ Name = "clippy"; Cmd = "cargo clippy --workspace --all-targets -- -D warnings" },
    @{ Name = "test";   Cmd = "cargo test --workspace" }
)

$failed = @()
$results = @()

foreach ($c in $checks) {
    Write-Host "==> $($c.Name)" -ForegroundColor Cyan
    cmd /c "$($c.Cmd) 2>&1" | Out-Host
    $code = $LASTEXITCODE
    $results += [pscustomobject]@{ Gate = $c.Name; Result = if ($code -eq 0) { "PASS" } else { "FAIL" } }
    if ($code -ne 0) { $failed += $c.Name }
}

Write-Host "==> docs" -ForegroundColor Cyan
$env:RUSTDOCFLAGS = "-D warnings"
cmd /c "cargo doc --workspace --no-deps 2>&1" | Out-Host
$code = $LASTEXITCODE
$results += [pscustomobject]@{ Gate = "docs"; Result = if ($code -eq 0) { "PASS" } else { "FAIL" } }
if ($code -ne 0) { $failed += "docs" }
Remove-Item Env:RUSTDOCFLAGS -ErrorAction SilentlyContinue

if (Get-Command cargo-llvm-cov -ErrorAction SilentlyContinue) {
    Write-Host "==> coverage" -ForegroundColor Cyan
    cmd /c "cargo llvm-cov --workspace --exclude vpn-service --exclude vpn-desktop --fail-under-lines 100 --summary-only 2>&1" | Out-Host
    if ($LASTEXITCODE -eq 0) {
        $results += [pscustomobject]@{ Gate = "coverage"; Result = "PASS" }
    } else {
        $results += [pscustomobject]@{ Gate = "coverage"; Result = "SKIP (gnu toolchain cannot instrument)" }
        Write-Host "Coverage is not available on the local gnu toolchain; enforced in CI (MSVC)." -ForegroundColor Yellow
    }
} else {
    $results += [pscustomobject]@{ Gate = "coverage"; Result = "SKIP (cargo-llvm-cov not installed)" }
}

Write-Host ""
$results | Format-Table -AutoSize

if ($failed.Count -gt 0) {
    Write-Host ("FAILED: " + ($failed -join ", ")) -ForegroundColor Red
    exit 1
}
Write-Host "ALL GREEN" -ForegroundColor Green
exit 0
