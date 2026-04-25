<#
.SYNOPSIS
    Validate and publish the SysUtils module to PowerShell Gallery.

.DESCRIPTION
    Runs Test-ModuleManifest, compares the manifest version against the
    latest one on PSGallery (refusing to republish or downgrade), and
    finally calls Publish-Module. The API key is read from
    $env:PSGALLERY_API_KEY by default so it is never hard-coded.

.PARAMETER ApiKey
    PowerShell Gallery API key. Defaults to $env:PSGALLERY_API_KEY.

.PARAMETER ModulePath
    Path to the module directory. Defaults to .\SysUtils next to this script.

.PARAMETER WhatIfOnly
    Run validation only — do not publish.

.EXAMPLE
    $env:PSGALLERY_API_KEY = '<your key>'
    .\Build-Module.ps1

.EXAMPLE
    .\Build-Module.ps1 -WhatIfOnly

.NOTES
    A version that already exists on the Gallery is immutable. Bump
    SysUtils.psd1 ModuleVersion before re-running this script.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ModulePath = (Join-Path $PSScriptRoot 'SysUtils'),
    [string]$ApiKey     = $env:PSGALLERY_API_KEY,
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'

$manifestPath = Join-Path $ModulePath 'SysUtils.psd1'
if (-not (Test-Path $manifestPath)) {
    throw "Manifest not found at $manifestPath"
}

$manifest = Test-ModuleManifest -Path $manifestPath
Write-Host ('Module : {0} v{1}' -f $manifest.Name, $manifest.Version)
Write-Host ('GUID   : {0}' -f $manifest.Guid)
Write-Host ('Exports: {0}' -f ($manifest.ExportedFunctions.Keys -join ', '))

# Compare against what is already on the Gallery
$existing = $null
try {
    $existing = Find-Module -Name $manifest.Name -Repository PSGallery -ErrorAction Stop
} catch {
    Write-Host 'Gallery: not yet published (this would be the first release).'
}
if ($existing) {
    Write-Host ('Gallery: latest is v{0}' -f $existing.Version)
    if ([version]$existing.Version -ge [version]$manifest.Version) {
        throw ("Manifest version $($manifest.Version) is not greater than the " +
               "version already on the Gallery ($($existing.Version)). " +
               'Bump ModuleVersion in SysUtils.psd1 first.')
    }
}

if ($WhatIfOnly) {
    Write-Host 'WhatIfOnly: skipping Publish-Module.'
    return
}

if (-not $ApiKey) {
    throw 'No API key. Set $env:PSGALLERY_API_KEY or pass -ApiKey.'
}

if ($PSCmdlet.ShouldProcess(
    "$($manifest.Name) v$($manifest.Version)",
    'Publish to PSGallery'))
{
    Publish-Module -Path $ModulePath -NuGetApiKey $ApiKey -Repository PSGallery -Verbose
    Write-Host ''
    Write-Host 'Published. Browse at:'
    Write-Host ('  https://www.powershellgallery.com/packages/{0}/{1}' -f $manifest.Name, $manifest.Version)
}
