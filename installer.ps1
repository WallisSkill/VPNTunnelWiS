# Produces out\FortiVpnSetup-<version>.exe: one file that installs the whole thing.
#
#     powershell -ExecutionPolicy Bypass -File installer.ps1
#
# Where package.ps1 makes a zip somebody has to unpack and then run install.ps1 out of,
# this carries the same layout inside an executable and does the install itself. Neither
# needs an administrator; this one also needs no PowerShell on the far side.
#
# Built from whatever dist\ currently holds -- run build.ps1 first if the sources have
# moved on.

[CmdletBinding()]
param(
    # Defaulted below rather than here: $PSScriptRoot is not yet bound while the
    # parameter defaults are being evaluated under -File.
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (-not $OutputDir) { $OutputDir = Join-Path $root 'out' }
$dist = Join-Path $root 'dist'
$manifest = Join-Path $dist 'AppxManifest.xml'
if (-not (Test-Path $manifest)) { throw "No dist\ yet. Run build.ps1 first." }

$version = ([xml](Get-Content $manifest)).Package.Identity.Version
Write-Host "Version: $version"

$src = Join-Path $root 'src\Installer'
$build = Join-Path $src 'build'
if (Test-Path $build) { Remove-Item $build -Recurse -Force }
New-Item $build -ItemType Directory | Out-Null

# dist\* rather than dist: the archive has to hold AppxManifest.xml at its root, because
# that is the shape the installer unpacks straight into the install folder.
Write-Host "`nZipping dist\..."
Compress-Archive -Path (Join-Path $dist '*') -DestinationPath (Join-Path $build 'payload.zip')

Write-Host "`nrc.exe, cl.exe..."
& cmd /c (Join-Path $src 'build-installer.cmd')
if ($LASTEXITCODE -ne 0) { throw "build-installer.cmd failed." }

if (-not (Test-Path $OutputDir)) { New-Item $OutputDir -ItemType Directory | Out-Null }
$exe = Join-Path $OutputDir "FortiVpnSetup-$version.exe"
Copy-Item (Join-Path $build 'FortiVpnSetup.exe') $exe -Force

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "`nDone: $exe ($size MB)"
