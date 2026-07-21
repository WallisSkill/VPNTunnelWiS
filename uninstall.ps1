# Removes the package registration and the installed layout.
#
#     powershell -ExecutionPolicy Bypass -File uninstall.ps1
#
# Connections stay. install.ps1 never created any, so removing them here would delete
# something the user made by hand; -RemoveProfiles asks for that explicitly.

[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'FortiVpnMatrix'),
    # Also delete every VPN connection bound to this provider.
    [switch]$RemoveProfiles
)

$ErrorActionPreference = 'Continue'

$pkg = Get-AppxPackage -Name FortiGateSslVpn.Plugin
$family = if ($pkg) { $pkg.PackageFamilyName } else { $null }

# Disconnect before unregistering: the package owns the files serving the tunnel.
Get-VpnConnection -ErrorAction SilentlyContinue |
    Where-Object { $_.ConnectionStatus -eq 'Connected' } |
    ForEach-Object { & rasdial $_.Name /disconnect 2>&1 | Out-Null }

if ($RemoveProfiles -and $family) {
    Get-VpnConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.PlugInApplicationID -eq $family } |
        ForEach-Object {
            Remove-VpnConnection -Name $_.Name -Force
            Write-Host "Removed the connection $($_.Name)"
        }
}

Get-AppxPackage -Name FortiGateSslVpn.Plugin | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-Process -Name FortiVpnHost -ErrorAction SilentlyContinue | Stop-Process -Force

if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "Removed $InstallDir"
}

Write-Host "Done."
