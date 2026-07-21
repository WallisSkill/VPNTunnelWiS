# Installs what build.ps1 produced, so that "FortiGate SSL-VPN" appears as a VPN
# provider to choose from in Settings.
#
#     powershell -ExecutionPolicy Bypass -File install.ps1
#
# It deliberately creates no connection. The package is a provider: which gateway to
# dial, under what name, is the user's to decide in Settings > Network & internet >
# VPN > Add VPN, picking "FortiGate SSL-VPN" as the VPN provider. The plugin reads the
# server address out of whatever profile is dialled.
#
# No administrator anywhere in here: the package is registered for the current user
# from a loose folder. Nothing depends on FortiClient, which can be removed.
#
# One requirement, checked below: Developer Mode on, which registering an unsigned
# layout needs. .NET is not one: dist\ is a self-contained publish and the shim starts
# CoreCLR from the copy of the runtime sitting inside it.

[CmdletBinding()]
param(
    # Where the layout lives once installed. A registered package reads its files from
    # this path for as long as it stays registered, so it must not be a temp folder.
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'FortiVpnMatrix')
)

$ErrorActionPreference = 'Stop'
$dist = Join-Path $PSScriptRoot 'dist'
if (-not (Test-Path (Join-Path $dist 'AppxManifest.xml'))) {
    throw "No dist\ yet. Run build.ps1 first."
}

# --- prerequisites ---------------------------------------------------------
$devmode = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' `
    -Name AllowDevelopmentWithoutDevLicense -ErrorAction SilentlyContinue
if ($devmode.AllowDevelopmentWithoutDevLicense -ne 1) {
    throw "Developer Mode must be on (Settings > System > For developers) before installing."
}

# --- stop anything holding the files ---------------------------------------
# A registered package locks its own DLLs, so the old registration goes first and the
# host process with it. Any live tunnel goes down too: it is being served by the files
# about to be replaced.
Get-VpnConnection -ErrorAction SilentlyContinue |
    Where-Object { $_.ConnectionStatus -eq 'Connected' } |
    ForEach-Object { & rasdial $_.Name /disconnect 2>&1 | Out-Null }
Get-AppxPackage -Name FortiGateSslVpn.Plugin | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-Process -Name FortiVpnHost -ErrorAction SilentlyContinue | Stop-Process -Force

# --- copy ------------------------------------------------------------------
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
Copy-Item $dist $InstallDir -Recurse -Force

# --- register --------------------------------------------------------------
Add-AppxPackage -Register (Join-Path $InstallDir 'AppxManifest.xml') -ErrorAction Stop
$pkg = Get-AppxPackage -Name FortiGateSslVpn.Plugin
if (-not $pkg) { throw "Registering the package failed." }

Write-Host "Package: $($pkg.PackageFullName)"
Write-Host "Provider: $($pkg.PackageFamilyName)"
Write-Host ""
Write-Host "Done. Settings > Network & internet > VPN > Add VPN,"
Write-Host "set VPN provider = ""FortiGate SSL-VPN"", enter your gateway address including"
Write-Host "the port (for example vpn.example.com:10443) and Save."
