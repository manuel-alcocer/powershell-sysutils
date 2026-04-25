# SysUtils module loader. Dot-sources every .ps1 under Private\ first
# (constants, helpers), then Public\ (cmdlet entry points), and exports
# only the public functions.

$Private = @( Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue )
$Public  = @( Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1"  -ErrorAction SilentlyContinue )

foreach ($f in @($Private + $Public)) {
    try {
        . $f.FullName
    } catch {
        Write-Error -Message "Failed to import $($f.FullName): $($_.Exception.Message)"
    }
}

if ($Public) {
    Export-ModuleMember -Function $Public.BaseName
}
