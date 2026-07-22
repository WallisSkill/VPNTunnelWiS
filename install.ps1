# Installs what build.ps1 produced, so that "VPNTunnelWiS" appears as a VPN
# provider to choose from in Settings.
#
#     powershell -ExecutionPolicy Bypass -File install.ps1
#
# It deliberately creates no connection. The package is a provider: which gateway to
# dial, under what name, is the user's to decide in Settings > Network & internet >
# VPN > Add VPN, picking "VPNTunnelWiS" as the VPN provider. The plugin reads the
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
# Windows 10 is supported, from version 2004 (build 19041) upwards -- that is what the
# manifest's MinVersion says and what the projects compile against, and the platform
# compatibility analyzer reports no call to anything newer. Checked here rather than left
# to the platform because Add-AppxPackage answers a machine below the floor with a
# complaint about the manifest, which reads like a broken package instead of an old
# Windows. Nothing below 19041 is worth lowering to: 22H2 (19045) was the last serviced
# Windows 10, so the floor already covers every build still receiving updates.
$build = [Environment]::OSVersion.Version.Build
if ($build -lt 19041) {
    throw ("Windows 10 version 2004 (build 19041) or newer is required; this is build $build. " +
           "Windows 10 22H2 is build 19045.")
}

# x64 only, because the package declares ProcessorArchitecture="x64" and the publish is
# win-x64. On an ARM64 or 32-bit Windows the registration fails for the architecture, and
# that failure reads no more clearly than the one above. PROCESSOR_ARCHITEW6432 first: a
# 32-bit PowerShell on 64-bit Windows reports x86 in the ordinary variable.
$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
if ($arch -ne 'AMD64') {
    throw "This package is x64 only; this machine reports $arch."
}

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
# Retried, because Stop-Process returns before the kernel has torn the process down and
# released its file handles: the loaded runtime files go last, and a delete that lands in
# that window fails on clrjit.dll with "access denied" or leaves the directory not empty.
# Seen twice in one afternoon of reinstalls. Five attempts a second apart is far longer
# than the gap has ever been, and failing after that is honest -- something else is
# holding the files and deleting harder will not find out what.
if (Test-Path $InstallDir) {
    for ($attempt = 1; ; $attempt++) {
        try { Remove-Item $InstallDir -Recurse -Force -ErrorAction Stop; break }
        catch {
            if ($attempt -ge 5) {
                throw ("Could not clear $InstallDir after $attempt attempts: $($_.Exception.Message). " +
                       "Something still holds the files; a reboot clears it.")
            }
            Start-Sleep -Seconds 1
        }
    }
}
Copy-Item $dist $InstallDir -Recurse -Force

# --- register --------------------------------------------------------------
Add-AppxPackage -Register (Join-Path $InstallDir 'AppxManifest.xml') -ErrorAction Stop
$pkg = Get-AppxPackage -Name FortiGateSslVpn.Plugin
if (-not $pkg) { throw "Registering the package failed." }

Write-Host "Package: $($pkg.PackageFullName)"
Write-Host "Provider: $($pkg.PackageFamilyName)"
Write-Host ""
Write-Host "Done. Settings > Network & internet > VPN > Add VPN,"
Write-Host "set VPN provider = ""VPNTunnelWiS"", enter your gateway address including"
Write-Host "the port (for example vpn.example.com:10443) and Save."
