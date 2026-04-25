function Get-DllGuidTable {
    <#
    .SYNOPSIS
        Flat GUID/CLSID/IID table extracted from a DLL's embedded TypeLib.

    .DESCRIPTION
        Reads the TYPELIB resource of a Windows PE binary (DLL/OCX) via
        oleaut32!LoadTypeLibEx (REGKIND_NONE - no registration) and emits one
        PSCustomObject per TypeLib entry with four fields: Type, Name, Guid,
        RegKey. Suitable for Format-Table or quick eyeballing of every
        CoClass / interface / dispinterface / enum / record / union / alias /
        module the binary declares.

        RegKey is the registry path under which that GUID is registered, or
        empty when the entry is not registered (or its kind is not normally
        registered, e.g. enum/record/union/alias/module). CoClasses are
        looked up under HKCR\CLSID, interfaces and dispinterfaces under
        HKCR\Interface; both HKLM and HKCU plus 32-bit (Wow6432Node) views
        are searched. Lookups are read-only - no LoadLibrary, no regsvr32.

    .PARAMETER Path
        One or more paths to PE files. Accepts pipeline input (e.g. from
        Get-ChildItem) and the FullName / PSPath / FilePath property aliases.

    .PARAMETER Kind
        Optional filter. One or more of: coclass, interface, dispatch, enum,
        record, union, alias, module. When omitted, every TypeLib entry is
        emitted.

    .PARAMETER RegKey
        Default Format-Table view shows the columns Type, Name, Guid. With
        -RegKey it shows Type, Name, RegKey instead - useful to avoid line
        wrapping in narrow consoles since the RegKey path already contains
        the GUID. The underlying objects always expose all four properties
        regardless of this switch, so ConvertTo-Json / Where-Object / etc.
        keep seeing the full record. Mutually exclusive with -Both.

    .PARAMETER Both
        Show both Guid and RegKey columns at once (Type, Name, Guid,
        RegKey). The combined width is around 130 characters and will
        wrap on the typical 120-char console. See the wrap-avoidance
        EXAMPLE below. Mutually exclusive with -RegKey.

    .EXAMPLE
        Get-DllGuidTable -Path C:\App\Administrador.dll | Format-Table

    .EXAMPLE
        Get-DllGuidTable .\foo.dll -Kind coclass

    .EXAMPLE
        Get-ChildItem C:\Legacy -Include *.dll,*.ocx -Recurse |
            Get-DllGuidTable | Sort-Object Type, Name

    .EXAMPLE
        # Show both Guid and RegKey columns without wrapping on a 120-char
        # console. Format-Table -Wrap would split each row across multiple
        # visual lines (ugly); piping through Out-String -Width N produces
        # a single rendered string per row, so each entry stays on one line
        # even if it exceeds the console width:
        Get-DllGuidTable .\foo.dll -Both |
            Format-Table -AutoSize |
            Out-String -Width 250 |
            Write-Host

        # Alternative: enlarge the console buffer once per session and use
        # Format-Table normally afterwards:
        $bs = $host.UI.RawUI.BufferSize
        $bs.Width = 250
        $host.UI.RawUI.BufferSize = $bs
        Get-DllGuidTable .\foo.dll -Both | Format-Table -AutoSize

    .NOTES
        PowerShell 5.1+ on Windows. Files without a TypeLib resource emit
        no output (use -Verbose to see them being skipped).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Guid')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName', 'PSPath', 'FilePath')]
        [string[]]$Path,

        [ValidateSet('coclass','interface','dispatch','enum','record','union','alias','module')]
        [string[]]$Kind,

        [Parameter(ParameterSetName = 'RegKey')]
        [switch]$RegKey,

        [Parameter(ParameterSetName = 'Both')]
        [switch]$Both
    )

    begin {
        # Pre-build the PSStandardMembers used for default Format-Table
        # display. Output objects always carry all four fields (so JSON /
        # Where-Object see everything); the parameter set only controls
        # which columns are shown by default to avoid wrapping.
        $defaultCols = switch ($PSCmdlet.ParameterSetName) {
            'Both'   { 'Type','Name','Guid','RegKey' }
            'RegKey' { 'Type','Name','RegKey' }
            default  { 'Type','Name','Guid' }
        }
        $displaySet  = New-Object System.Management.Automation.PSPropertySet(
            'DefaultDisplayPropertySet', [string[]]$defaultCols)
        $stdMembers  = [System.Management.Automation.PSMemberInfo[]]@($displaySet)
    }

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

                $guidStr = $ti.Guid.ToString().ToUpperInvariant()
                $regKeyVal = Resolve-RegistryKeyForGuid -Guid $guidStr -Kind $type

                $obj = [pscustomobject]@{
                    Type   = $type
                    Name   = $qname
                    Guid   = $guidStr
                    RegKey = $regKeyVal
                }
                $obj | Add-Member -MemberType MemberSet -Name PSStandardMembers `
                                  -Value $stdMembers -Force
                $obj
            }
        }
    }
}
