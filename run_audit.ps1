[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path $PSScriptRoot 'audit_output'),
    [string]$Adb,
    [string]$Serial,
    [int]$Timeout = 45,
    [switch]$RequireDevice
)
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Error '未找到 Python 3。请安装 Python 3 后重试。'
    exit 2
}
$args = @('hyperos_audit.py', '--output-dir', $OutputDir, '--timeout', $Timeout)
if ($Adb) { $args += @('--adb', $Adb) }
if ($Serial) { $args += @('--serial', $Serial) }
if ($RequireDevice) { $args += '--require-device' }
& $python.Source @args
exit $LASTEXITCODE
