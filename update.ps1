<#
.SYNOPSIS
    Checks GitHub Releases for a newer build and, with your say-so, installs it.

.DESCRIPTION
    The provider is an unsigned side-loaded package, so nothing on the machine updates it
    for you. This asks the release page of

        https://github.com/WallisSkill/FortinetVpn

    for the latest version, compares it against the copy registered on this machine, and if
    the release is newer downloads FortiVpnSetup-<version>.exe and runs it. Downloading and
    running an executable is never silent: it prints what it is about to fetch and waits for
    a yes, unless you pass -Yes.

    No administrator anywhere. It only reads a public API and runs the same setup you would
    have downloaded by hand.

.PARAMETER Check
    Only report whether a newer version exists. Never downloads, never runs anything, and
    sets the exit code to 10 when an update is available so a scheduled task can act on it.

.PARAMETER Yes
    Skip the download/run confirmation. For an unattended update; on its own the script
    always asks first.

.PARAMETER SelfTest
    Run the offline checks on the version-parsing and comparison logic and exit. No network.
    Exit code 0 when every case passes, 1 otherwise, so CI can gate on it.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File update.ps1
    powershell -ExecutionPolicy Bypass -File update.ps1 -Check
#>
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Yes,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Both come from Package.appxmanifest / the repo URL and are the only two things that tie
# this script to a particular product. Keep PackageName matching the manifest identity.
$Repo        = 'WallisSkill/FortinetVpn'
$PackageName = 'FortiGateSslVpn.Plugin'

# --- pure logic, no network, no machine state: this is what -SelfTest exercises ----------

# A release tag is 'v1.0.0.3' (occasionally 'v1.0.0'); the manifest version is '1.0.0.3'.
# Return a [version] for either, or $null for anything that is not one -- a release named
# 'nightly' or 'latest' must not be mistaken for a number and must not throw.
function ConvertTo-PluginVersion {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.Trim()
    if ($t.StartsWith('v') -or $t.StartsWith('V')) { $t = $t.Substring(1) }
    [version]$parsed = $null
    if ([version]::TryParse($t, [ref]$parsed)) { return $parsed }
    return $null
}

# True when $latest is a strictly higher version than $installed. A missing or unparsable
# side is treated as "cannot tell, so do not claim an update" -- never nag on bad data.
function Test-UpdateAvailable {
    param([string]$Installed, [string]$Latest)
    $a = ConvertTo-PluginVersion $Installed
    $b = ConvertTo-PluginVersion $Latest
    if ($null -eq $a -or $null -eq $b) { return $false }
    return $b -gt $a
}

# Pick the setup .exe out of a release's asset list. GitHub gives each asset a name and a
# browser_download_url; take the first whose name looks like the installer.
function Select-SetupAsset {
    param($Assets)
    foreach ($asset in @($Assets)) {
        if ($asset.name -match '^FortiVpnSetup.*\.exe$') { return $asset }
    }
    return $null
}

if ($SelfTest) {
    $failures = 0
    function Assert($name, $ok, $detail) {
        Write-Host ("  [{0}] {1}" -f ($(if ($ok) {'PASS'} else {'FAIL'})), $name)
        if (-not $ok) { $script:failures++; if ($detail) { Write-Host "         $detail" } }
    }

    Write-Host '=== version parsing ==='
    Assert 'v-prefixed tag parses'      ((ConvertTo-PluginVersion 'v1.0.0.3') -eq [version]'1.0.0.3') 'v1.0.0.3'
    Assert 'bare manifest version parses' ((ConvertTo-PluginVersion '1.0.0.3') -eq [version]'1.0.0.3') '1.0.0.3'
    Assert 'three-part tag parses'      ((ConvertTo-PluginVersion 'v1.0.0') -eq [version]'1.0.0') 'v1.0.0'
    Assert 'whitespace tolerated'       ((ConvertTo-PluginVersion '  v2.1.0.0 ') -eq [version]'2.1.0.0') 'padded'
    Assert 'non-numeric tag is null'    ($null -eq (ConvertTo-PluginVersion 'nightly'))  'nightly'
    Assert 'empty is null'              ($null -eq (ConvertTo-PluginVersion ''))         'empty'
    Assert 'null is null'               ($null -eq (ConvertTo-PluginVersion $null))      'null'

    Write-Host "`n=== update comparison ==="
    Assert 'higher revision is an update'  (Test-UpdateAvailable '1.0.0.3' 'v1.0.0.4')
    Assert 'higher minor is an update'     (Test-UpdateAvailable '1.0.0.9' 'v1.1.0.0')
    Assert 'equal is not an update'        (-not (Test-UpdateAvailable '1.0.0.3' 'v1.0.0.3'))
    Assert 'lower is not an update'        (-not (Test-UpdateAvailable '1.0.0.4' 'v1.0.0.3'))
    Assert 'unparsable latest never nags'  (-not (Test-UpdateAvailable '1.0.0.3' 'nightly'))
    Assert 'unknown installed never nags'  (-not (Test-UpdateAvailable '' 'v1.0.0.4'))
    Assert 'shorter installed vs longer'   (Test-UpdateAvailable '1.0.0' 'v1.0.0.1')

    Write-Host "`n=== asset selection ==="
    $assets = @(
        [pscustomobject]@{ name = 'FortiVpnPlugin-1.0.0.4.zip'; browser_download_url = 'z' },
        [pscustomobject]@{ name = 'FortiVpnSetup-1.0.0.4.exe';  browser_download_url = 'e' }
    )
    $picked = Select-SetupAsset $assets
    Assert 'setup exe chosen over zip'  ($null -ne $picked -and $picked.name -eq 'FortiVpnSetup-1.0.0.4.exe') $(if ($picked) {$picked.name})
    Assert 'no exe yields null'         ($null -eq (Select-SetupAsset @([pscustomobject]@{ name='readme.txt' })))

    Write-Host ''
    if ($failures -eq 0) { Write-Host 'All update-logic cases passed.'; exit 0 }
    Write-Host "$failures case(s) failed."; exit 1
}

# --- live path: read the machine, ask GitHub, then (only with consent) fetch and run ------

function Get-InstalledVersion {
    $pkg = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue |
           Sort-Object { [version]$_.Version } -Descending |
           Select-Object -First 1
    if ($pkg) { return $pkg.Version }
    return $null
}

function Get-LatestRelease {
    # Public, unauthenticated, read-only. A User-Agent is required by the GitHub API.
    $uri = "https://api.github.com/repos/$Repo/releases/latest"
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    return Invoke-RestMethod -Uri $uri -Headers @{
        'User-Agent' = 'FortiVpnPlugin-Updater'
        'Accept'     = 'application/vnd.github+json'
    }
}

$installed = Get-InstalledVersion
if (-not $installed) {
    Write-Host 'The provider is not registered on this machine. Install it first, then update.'
    exit 2
}
Write-Host "Installed: $installed"

try {
    $release = Get-LatestRelease
} catch {
    Write-Host "Could not reach the release page: $($_.Exception.Message)"
    exit 3
}

$latestTag = $release.tag_name
Write-Host "Latest published: $latestTag"

if (-not (Test-UpdateAvailable $installed $latestTag)) {
    Write-Host 'Up to date. Nothing to do.'
    exit 0
}

Write-Host "A newer version is available: $latestTag (you have $installed)."

if ($Check) {
    # Report-only mode leaves a machine-readable exit code for a scheduled task to key on.
    exit 10
}

$asset = Select-SetupAsset $release.assets
if (-not $asset) {
    Write-Host "Release $latestTag has no FortiVpnSetup .exe asset to install."
    exit 4
}

Write-Host ''
Write-Host "About to download and run:"
Write-Host "    $($asset.name)"
Write-Host "    from $($asset.browser_download_url)"

if (-not $Yes) {
    $answer = Read-Host 'Download and install it now? [y/N]'
    if ($answer -notmatch '^(y|yes)$') {
        Write-Host 'Left alone. Nothing downloaded.'
        exit 0
    }
}

$dest = Join-Path ([IO.Path]::GetTempPath()) $asset.name
Write-Host "Downloading to $dest ..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $dest -Headers @{
    'User-Agent' = 'FortiVpnPlugin-Updater'
}

Write-Host "Running the installer ..."
# The setup re-registers over the old package in place; existing connections keep binding
# because the package family name does not change between versions.
& $dest
$code = $LASTEXITCODE
Write-Host "Installer exited with code $code."
exit $code
