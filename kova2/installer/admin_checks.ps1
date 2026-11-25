# Pre-release admin checks: runs the ignored tests that need administrator rights (VSS, WORM ACL).
# Usage (elevated PowerShell): powershell -NoProfile -ExecutionPolicy Bypass -File installerdmin_checks.ps1
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'FAIL: run as administrator'; exit 2 }
$tests = @(
    @('-p', 'kova-core', 'vss::tests::real_shadow'),
    @('-p', 'kova-core', 'worm::tests::acl_protect'),
    @('-p', 'kova-service', 'vss_backup_reads')
)
$fail = 0
foreach ($t in $tests) {
    & cargo test @t -- --ignored
    if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: $($t -join ' ')"; $fail++ } else { Write-Host "OK: $($t -join ' ')" }
}
if ($fail -eq 0) { Write-Host 'ADMIN CHECKS PASS'; exit 0 } else { Write-Host "ADMIN CHECKS FAIL ($fail)"; exit 1 }
