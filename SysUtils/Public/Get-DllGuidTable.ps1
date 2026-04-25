function Get-DllGuidTable {
    <#
    .SYNOPSIS
        Flat GUID/CLSID/IID table extracted from a DLL's embedded TypeLib.

    .DESCRIPTION
        Reads the TYPELIB resource of a Windows PE binary (DLL/OCX) via
        oleaut32!LoadTypeLibEx (REGKIND_NONE - no registration) and emits one
        PSCustomObject per TypeLib entry with three fields: Type, Name, Guid.
        Suitable for Format-Table or quick eyeballing of every CoClass /
        interface / dispinterface / enum / record / union / alias / module
        the binary declares.

        Strictly read-only: the TypeLib is loaded with REGKIND_NONE so the
        registry is not touched. LoadLibrary is never called either.

    .PARAMETER Path
        One or more paths to PE files. Accepts pipeline input (e.g. from
        Get-ChildItem) and the FullName / PSPath / FilePath property aliases.

    .PARAMETER Kind
        Optional filter. One or more of: coclass, interface, dispatch, enum,
        record, union, alias, module. When omitted, every TypeLib entry is
        emitted.

    .EXAMPLE
        Get-DllGuidTable -Path C:\App\Administrador.dll | Format-Table

    .EXAMPLE
        Get-DllGuidTable .\foo.dll -Kind coclass

    .EXAMPLE
        Get-ChildItem C:\Legacy -Include *.dll,*.ocx -Recurse |
            Get-DllGuidTable | Sort-Object Type, Name

    .NOTES
        PowerShell 5.1+ on Windows. Files without a TypeLib resource emit
        no output (use -Verbose to see them being skipped).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName', 'PSPath', 'FilePath')]
        [string[]]$Path,

        [ValidateSet('coclass','interface','dispatch','enum','record','union','alias','module')]
        [string[]]$Kind
    )

    process {
        foreach ($p in $Path) {
            try {
                $resolved = (Resolve-Path -LiteralPath $p -ErrorAction Stop).ProviderPath
            } catch {
                Write-Error "Failed to resolve '$p': $($_.Exception.Message)"
                continue
            }

            $tlib = Get-TypeLibInfoSafe -FilePath $resolved
            if (-not $tlib) {
                Write-Verbose "No TypeLib in $resolved (file missing, not a PE, or no TYPELIB resource) - skipped."
                continue
            }
            if (-not $tlib.TypeInfos -or $tlib.TypeInfos.Count -eq 0) {
                Write-Verbose "TypeLib in $resolved is empty - skipped."
                continue
            }

            $libName = $tlib.Name
            foreach ($ti in $tlib.TypeInfos) {
                $type = ($ti.Kind -replace '^TKIND_', '').ToLowerInvariant()
                if ($Kind -and ($Kind -notcontains $type)) { continue }

                if ([string]::IsNullOrEmpty($libName)) {
                    $qname = $ti.Name
                } else {
                    $qname = "$libName.$($ti.Name)"
                }

                [pscustomobject]@{
                    Type = $type
                    Name = $qname
                    Guid = $ti.Guid.ToString().ToUpperInvariant()
                }
            }
        }
    }
}
