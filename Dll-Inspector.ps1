<#
.SYNOPSIS
    Wrapper script for Get-DllInfo from the SysUtils module.

.DESCRIPTION
    Imports the SysUtils module from the sibling SysUtils\ directory and
    forwards every parameter to Get-DllInfo. Lets users who clone this repo
    keep running ".\Dll-Inspector.ps1" without installing the module.

    For full documentation see:
        Import-Module .\SysUtils\SysUtils.psd1
        Get-Help Get-DllInfo -Full

.EXAMPLE
    .\Dll-Inspector.ps1 -Path C:\Windows\System32\scrrun.dll -Detailed |
        ConvertTo-Json -Depth 12

.EXAMPLE
    Get-ChildItem C:\App -Filter *.dll | .\Dll-Inspector.ps1 -IncludeImports

.NOTES
    Once installed via "Install-Module SysUtils", call Get-DllInfo directly
    instead of running this script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('FullName', 'PSPath')]
    [string[]]$Path,

    [switch]$IncludeImports,
    [switch]$IncludeExports,
    [switch]$IncludeResources,
    [switch]$IncludeTypeLib,
    [switch]$IncludeDotNetTypes,
    [switch]$IncludeSignature,
    [switch]$IncludeHash,
    [switch]$Detailed
)

begin {
    Import-Module (Join-Path $PSScriptRoot 'SysUtils\SysUtils.psd1') -Force
}

process {
    foreach ($p in $Path) {
        Get-DllInfo -Path $p `
            -IncludeImports:$IncludeImports `
            -IncludeExports:$IncludeExports `
            -IncludeResources:$IncludeResources `
            -IncludeTypeLib:$IncludeTypeLib `
            -IncludeDotNetTypes:$IncludeDotNetTypes `
            -IncludeSignature:$IncludeSignature `
            -IncludeHash:$IncludeHash `
            -Detailed:$Detailed
    }
}
