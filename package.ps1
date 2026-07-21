# Zips dist\ together with the two scripts into one file that can be handed to someone
# else and unpacked anywhere.
#
#     powershell -ExecutionPolicy Bypass -File package.ps1
#
# Nothing is fetched at install time on the far side: the runtime is inside dist\, so the
# archive is the whole product. It is built from whatever dist\ currently holds -- run
# build.ps1 first if the sources have moved on.

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

# Staged in a temp folder rather than zipped in place: the archive has to carry dist\ as a
# subfolder next to the scripts, which is the layout install.ps1 expects to find itself in.
$stage = Join-Path ([IO.Path]::GetTempPath()) "FortiVpnPlugin-$version"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item $stage -ItemType Directory | Out-Null

Copy-Item $dist (Join-Path $stage 'dist') -Recurse
foreach ($name in 'install.ps1', 'uninstall.ps1') {
    Copy-Item (Join-Path $root $name) $stage
}
Copy-Item (Join-Path $root 'docs\readme-package.md') (Join-Path $stage 'README.md')

if (-not (Test-Path $OutputDir)) { New-Item $OutputDir -ItemType Directory | Out-Null }
$zip = Join-Path $OutputDir "FortiVpnPlugin-$version.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
Remove-Item $stage -Recurse -Force

$size = [math]::Round((Get-Item $zip).Length / 1MB, 1)
Write-Host "Done: $zip ($size MB)"
