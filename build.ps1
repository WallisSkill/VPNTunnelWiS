# Assembles the package layout under dist\. Does not install anything -- that is
# install.ps1 -- and does not produce a signed .msix.
#
#     powershell -ExecutionPolicy Bypass -File build.ps1
#
# There is no makeappx and no signtool step on purpose. A signed .msix can only be
# installed once its certificate is trusted in LocalMachine\Root, which needs an
# administrator; a registered layout needs neither, and this machine has no admin.
# Add-AppxPackage -Register accepts an unsigned loose folder from a dev-unlocked user,
# which is exactly the shape produced here.

[CmdletBinding()]
param(
    [switch]$NoBump,
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$dist = Join-Path $root 'dist'
$manifestSrc = Join-Path $root 'src\Shell\Package.appxmanifest'
$nativeOut = Join-Path $root 'src\Native\build'
$pluginOut = Join-Path $root "src\Plugin\bin\$Configuration\net9.0-windows10.0.26100.0\win-x64"

# makepri is not on PATH. Take the newest bin\<version>\x64 that has it.
$sdkBin = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Directory |
    Where-Object { $_.Name -match '^10\.' } |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName 'x64' } |
    Where-Object { Test-Path (Join-Path $_ 'makepri.exe') } |
    Select-Object -First 1
if (-not $sdkBin) { throw "makepri.exe was not found in the Windows SDK." }
Write-Host "SDK tools: $sdkBin"

# --- version ---------------------------------------------------------------
# Windows refuses to register a package whose version is not higher than the one
# already installed, so the revision moves on every build unless told otherwise.
[xml]$manifest = Get-Content $manifestSrc
if (-not $NoBump) {
    $v = [version]$manifest.Package.Identity.Version
    $manifest.Package.Identity.Version =
        '{0}.{1}.{2}.{3}' -f $v.Major, $v.Minor, $v.Build, ($v.Revision + 1)
    $manifest.Save($manifestSrc)
}
$version = ([xml](Get-Content $manifestSrc)).Package.Identity.Version
Write-Host "Version: $version"

# --- managed ---------------------------------------------------------------
# Self-contained, and published from the shell rather than the plugin: it is the only
# way to get the whole framework plus WinRT.Runtime.dll and the SDK projections into one
# flat folder. Self-contained is not a convenience here -- it is what the shim starts
# CoreCLR from, so the package needs no .NET installed on the machine at all.
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
Write-Host "`ndotnet publish..."
& dotnet publish (Join-Path $root 'src\Shell\Shell.csproj') `
    -c $Configuration -r win-x64 --self-contained true -o $dist --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

# --- native ----------------------------------------------------------------
Write-Host "`ncl.exe..."
& cmd /c (Join-Path $root 'src\Native\build-native.cmd')
if ($LASTEXITCODE -ne 0) { throw "build-native.cmd failed." }

# FortiVpnHost.exe overwrites the managed apphost of the same name that publish just
# wrote. The app model refuses to launch a packaged app whose image is not marked
# /APPCONTAINER, which the managed apphost is not.
foreach ($name in 'FortiVpnHost.exe', 'FortiVpnShim.dll', 'FortiVpnNative.dll') {
    Copy-Item (Join-Path $nativeOut $name) $dist -Force
}

# The winmd carries the class metadata the platform reads to validate the activatable
# class; the runtimeconfig is what the shim hands to hostfxr. No deps.json goes next to
# it on purpose -- without one, hostfxr puts every assembly in this folder on the
# trusted list, which is where the projections are.
Copy-Item (Join-Path $pluginOut 'FortiVpnPlugin.winmd') $dist -Force

# Copied from the host's own config rather than written by hand: it is the self-contained
# one publish just produced, so it names the exact runtime version sitting in this folder
# and cannot drift out of step with it. That is what lets the package start CoreCLR from
# its own files on a machine with no .NET installed.
Copy-Item (Join-Path $dist 'FortiVpnHost.runtimeconfig.json') `
          (Join-Path $dist 'FortiVpnPlugin.runtimeconfig.json') -Force
Copy-Item $manifestSrc (Join-Path $dist 'AppxManifest.xml') -Force

# --- resources -------------------------------------------------------------
# resources.pri is not optional: without it the package has no display name or logo to
# show and Add-AppxPackage rejects it outright.
& (Join-Path $sdkBin 'makepri.exe') new /pr $dist /cf (Join-Path $root 'priconfig.xml') `
    /of (Join-Path $dist 'resources.pri') /o | Out-Null
if ($LASTEXITCODE -ne 0) { throw "makepri failed." }

Write-Host "`nDone: $dist (version $version)"
Write-Host "Install with: powershell -ExecutionPolicy Bypass -File install.ps1"
