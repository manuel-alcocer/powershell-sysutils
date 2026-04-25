<#
.SYNOPSIS
    Headless wrapper for Invoke-DllSuiteAnalysis. Translates -Strict +
    HasIssues into a non-zero exit code, intended for CI/CD pipelines.

.DESCRIPTION
    Loads the SysUtils module (next-to-this-script first, then any
    installed copy), runs the analysis on the given paths, writes the
    artifacts (report.json, summary.txt, report.html) to -OutputDir,
    and exits with:

      0 = success (no issues, OR issues found but -Strict not set)
      1 = fatal error (bad path, etc.)
      2 = drift / GUID conflicts found AND -Strict was passed

.PARAMETER Path
    One or more directories or file paths to scan.

.PARAMETER OutputDir
    Directory to write report.json, summary.txt and report.html into.
    Created if missing. Defaults to .\dll-suite-report next to the cwd.

.PARAMETER Recurse
    Walk directories recursively.

.PARAMETER Strict
    Translate analysis issues (conflicts/drift) into exit code 2.

.PARAMETER Quiet
    Minimal stdout: just the final SUMMARY line.

.EXAMPLE
    .\DllSuite-Run.ps1 -Path C:\Apps\Team1, C:\Apps\Team2 -Recurse `
                       -OutputDir C:\Reports -Strict
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Path,
    [string]$OutputDir = (Join-Path (Get-Location) 'dll-suite-report'),
    [string[]]$Include = @('*.dll','*.ocx'),
    [switch]$Recurse,
    [switch]$Strict,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

# Locate the module: next to this script (release zip layout) first,
# fall back to PSGallery-installed copy.
$bundled = Join-Path $PSScriptRoot '..\SysUtils\SysUtils.psd1'
try {
    if (Test-Path $bundled) {
        Import-Module $bundled -Force -ErrorAction Stop
    } else {
        Import-Module SysUtils -Force -ErrorAction Stop
    }
} catch {
    Write-Error "Cannot load SysUtils module: $($_.Exception.Message)"
    exit 1
}

try {
    $r = Invoke-DllSuiteAnalysis `
        -Path      $Path `
        -Include   $Include `
        -Recurse:$Recurse `
        -OutputDir $OutputDir `
        -Strict:$Strict `
        -Quiet:$Quiet
} catch {
    Write-Error "Analysis failed: $($_.Exception.Message)"
    exit 1
}

# r.HasIssues is set only when -Strict was passed AND conflicts exist.
if ($r.HasIssues) { exit 2 } else { exit 0 }
