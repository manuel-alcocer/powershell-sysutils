# COM registration inspector. Cross-references the CoClasses declared in
# the DLL's embedded TypeLib against what is actually registered under
# HKCR\CLSID, using Microsoft.Win32.RegistryKey directly (the PowerShell
# registry provider is too slow for a full HKCR\CLSID walk — ~30k keys).
#
# Strictly read-only: nothing is registered, no LoadLibrary is performed,
# the DLL is never loaded into the process. Works without admin rights.

# Microsoft.Win32.Registry* types exist on non-Windows .NET, but throw
# PlatformNotSupportedException on first use. Detect early and bail out.
function Test-IsWindowsPlatform {
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }
    try { return [bool](Get-Variable -Name IsWindows -ValueOnly -ErrorAction Stop) }
    catch { return $false }
}

# Registry InprocServer32 values may contain %SystemRoot%, surrounding
# quotes, or forward slashes. Normalize so OrdinalIgnoreCase comparison
# against the inspected DLL path actually works.
function ConvertTo-NormalizedPath {
    param([string]$RawPath)
    if ([string]::IsNullOrWhiteSpace($RawPath)) { return $null }
    $p = $RawPath.Trim()
    if ($p.StartsWith('"') -and $p.EndsWith('"') -and $p.Length -ge 2) {
        $p = $p.Substring(1, $p.Length - 2)
    }
    $p = [Environment]::ExpandEnvironmentVariables($p)
    try { $p = [IO.Path]::GetFullPath($p) } catch { }
    return $p
}

# Read (Default) of a subkey if it exists. Returns $null when the value
# is missing or empty. Caller closes the parent; we close the subkey.
function Get-RegDefaultValue {
    param(
        [Microsoft.Win32.RegistryKey]$Parent,
        [string]$SubKeyName
    )
    if (-not $Parent) { return $null }
    $sub = $null
    try {
        $sub = $Parent.OpenSubKey($SubKeyName)
        if (-not $sub) { return $null }
        $v = $sub.GetValue('')
        if ([string]::IsNullOrWhiteSpace($v)) { return $null }
        return [string]$v
    } catch { return $null }
    finally { if ($sub) { $sub.Close() } }
}

# Build the (Hive, View) tuples we want to scan. HKLM and HKCU each in
# Registry64 + Registry32 views — 4 places total. On a 32-bit OS the
# Registry32 view aliases the same hive; harmless duplicates are filtered
# downstream by the (Clsid, Hive, View) key.
function Get-ComRegistryRoots {
    @(
        @{ Hive = 'LocalMachine'; View = 'Registry64'; Label = '64-bit' }
        @{ Hive = 'LocalMachine'; View = 'Registry32'; Label = '32-bit' }
        @{ Hive = 'CurrentUser';  View = 'Registry64'; Label = '64-bit' }
        @{ Hive = 'CurrentUser';  View = 'Registry32'; Label = '32-bit' }
    )
}

# Read the metadata around a single CLSID key: friendly name, ProgID,
# ThreadingModel, InprocServer32 path and TypeLib GUID. Used both by the
# inverse scan (after a path match) and by the direct lookup of CLSIDs
# declared in the TypeLib.
function Read-ClsidEntry {
    param(
        [Microsoft.Win32.RegistryKey]$ClsidKey,
        [string]$Clsid,
        [string]$HiveLabel,
        [string]$ViewLabel
    )
    if (-not $ClsidKey) { return $null }

    $friendly = $null
    try { $friendly = [string]$ClsidKey.GetValue('') } catch { }
    if ([string]::IsNullOrWhiteSpace($friendly)) { $friendly = $null }

    $progId = Get-RegDefaultValue -Parent $ClsidKey -SubKeyName 'ProgID'
    if (-not $progId) {
        $progId = Get-RegDefaultValue -Parent $ClsidKey -SubKeyName 'VersionIndependentProgID'
    }

    $tlbGuid = Get-RegDefaultValue -Parent $ClsidKey -SubKeyName 'TypeLib'

    $inproc = $ClsidKey.OpenSubKey('InprocServer32')
    if (-not $inproc) { return $null }
    try {
        $rawPath = [string]$inproc.GetValue('')
        $threading = [string]$inproc.GetValue('ThreadingModel')
        if ([string]::IsNullOrWhiteSpace($rawPath)) { return $null }
        return [pscustomobject]@{
            Clsid          = $Clsid
            FriendlyName   = $friendly
            ProgId         = $progId
            ThreadingModel = if ($threading) { $threading } else { $null }
            InprocServer32 = $rawPath
            NormalizedPath = ConvertTo-NormalizedPath -RawPath $rawPath
            TypeLib        = $tlbGuid
            Hive           = $HiveLabel
            View           = $ViewLabel
        }
    } finally { $inproc.Close() }
}

# Inverse scan: walk every CLSID in HKLM/HKCU x64+x86 and yield entries
# whose InprocServer32 normalizes to $TargetPath.
function Find-ComRegistrationsForFile {
    param(
        [string]$TargetPath,
        [hashtable]$DeclaredLookup   # CLSID (uppercase, braced) -> $true
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($root in Get-ComRegistryRoots) {
        $base = $null; $clsidRoot = $null
        try {
            $hive = [Microsoft.Win32.RegistryHive]($root.Hive)
            $view = [Microsoft.Win32.RegistryView]($root.View)
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
        } catch { continue }

        try {
            $clsidRoot = $base.OpenSubKey('Software\Classes\CLSID')
            if (-not $clsidRoot) { continue }

            foreach ($name in $clsidRoot.GetSubKeyNames()) {
                $ck = $null
                try {
                    $ck = $clsidRoot.OpenSubKey($name)
                    if (-not $ck) { continue }
                    $entry = Read-ClsidEntry -ClsidKey $ck -Clsid $name `
                                             -HiveLabel $root.Hive -ViewLabel $root.Label
                    if (-not $entry) { continue }
                    if (-not [string]::Equals($entry.NormalizedPath, $TargetPath,
                                              [System.StringComparison]::OrdinalIgnoreCase)) {
                        continue
                    }
                    $clsidUpper = $name.ToUpperInvariant()
                    $isDeclared = $DeclaredLookup.ContainsKey($clsidUpper)
                    $entryStatus = if ($isDeclared) { 'Registered' } else { 'RegisteredOnly' }
                    Add-Member -InputObject $entry -NotePropertyName DeclaredInTypeLib `
                               -NotePropertyValue $isDeclared -Force
                    Add-Member -InputObject $entry -NotePropertyName PathMatchesTarget `
                               -NotePropertyValue $true -Force
                    Add-Member -InputObject $entry -NotePropertyName Status `
                               -NotePropertyValue $entryStatus -Force
                    $results.Add($entry) | Out-Null
                } finally { if ($ck) { $ck.Close() } }
            }
        } finally {
            if ($clsidRoot) { $clsidRoot.Close() }
            if ($base)      { $base.Close() }
        }
    }

    # Comma operator: keep the List intact; otherwise PS unrolls it to Object[].
    , $results
}

# Direct lookup of one CLSID across the 4 views. Used for declared
# CoClasses that the inverse scan did not match: distinguishes "not
# registered at all" (DeclaredOnly) from "registered but pointing
# elsewhere" (PathMismatch).
function Resolve-ClsidEverywhere {
    param([string]$Clsid)

    $found = New-Object System.Collections.Generic.List[object]
    foreach ($root in Get-ComRegistryRoots) {
        $base = $null; $ck = $null
        try {
            $hive = [Microsoft.Win32.RegistryHive]($root.Hive)
            $view = [Microsoft.Win32.RegistryView]($root.View)
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            $ck = $base.OpenSubKey("Software\Classes\CLSID\$Clsid")
            if (-not $ck) { continue }
            $entry = Read-ClsidEntry -ClsidKey $ck -Clsid $Clsid `
                                     -HiveLabel $root.Hive -ViewLabel $root.Label
            if ($entry) { $found.Add($entry) | Out-Null }
        } catch { }
        finally {
            if ($ck)   { $ck.Close() }
            if ($base) { $base.Close() }
        }
    }
    , $found
}

# Quick "where is this GUID registered" lookup. Searches the appropriate
# subtree based on TypeLib kind: CoClasses live under CLSID, interfaces
# (and dispinterfaces) under Interface; everything else is not registered
# under a per-GUID node and returns $null. Walks the same 4 hive/view
# combinations as the rest of this file; on hit, returns a single
# displayable path string with priority HKLM-x64 > HKLM-x86 > HKCU-x64 >
# HKCU-x86. The 32-bit views resolve to the Wow6432Node redirected
# location, which is what we surface so the path is paste-friendly.
function Resolve-RegistryKeyForGuid {
    param(
        [Parameter(Mandatory)][string]$Guid,
        [Parameter(Mandatory)][string]$Kind
    )

    if (-not (Test-IsWindowsPlatform)) { return $null }

    $subpath = switch ($Kind) {
        'coclass'   { 'CLSID' }
        'interface' { 'Interface' }
        'dispatch'  { 'Interface' }
        default     { return $null }
    }

    $g = $Guid.Trim('{','}').ToUpperInvariant()
    if ($g -eq '00000000-0000-0000-0000-000000000000') { return $null }
    $braced = '{' + $g + '}'

    foreach ($root in Get-ComRegistryRoots) {
        $base = $null; $ck = $null
        try {
            $hive = [Microsoft.Win32.RegistryHive]($root.Hive)
            $view = [Microsoft.Win32.RegistryView]($root.View)
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            $ck = $base.OpenSubKey("Software\Classes\$subpath\$braced")
            if (-not $ck) { continue }

            $hivePrefix = if ($root.Hive -eq 'LocalMachine') { 'HKLM' } else { 'HKCU' }
            $wow = if ($root.View -eq 'Registry32') { 'Wow6432Node\' } else { '' }
            return "${hivePrefix}:Software\Classes\${wow}${subpath}\${braced}"
        } catch { }
        finally {
            if ($ck)   { $ck.Close() }
            if ($base) { $base.Close() }
        }
    }
    return $null
}

function Get-ComRegistrationInfo {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [object]$TypeLibInfo  # output of Get-TypeLibInfoSafe; may be $null
    )

    if (-not (Test-IsWindowsPlatform)) {
        return [pscustomobject]@{
            Scanned         = $false
            Status          = 'NotApplicable'
            Issues          = @('Registry inspection requires Windows.')
            DeclaredCount   = 0
            RegisteredCount = 0
            Clsids          = @()
        }
    }

    $target = ConvertTo-NormalizedPath -RawPath $FilePath

    # Build the set of CLSIDs that the TypeLib declares as creatable
    # (CoClass with CanCreate flag — TypeFlag bit 0x0002). Without
    # CanCreate the class is not meant to be CoCreateInstance'd, so it
    # need not appear in the registry.
    $declared = New-Object System.Collections.Generic.List[object]
    $declaredLookup = @{}
    if ($TypeLibInfo -and $TypeLibInfo.TypeInfos) {
        foreach ($ti in $TypeLibInfo.TypeInfos) {
            if ($ti.Kind -ne 'TKIND_COCLASS') { continue }
            $canCreate = (($ti.TypeFlags -band 0x0002) -ne 0)
            if (-not $canCreate) { continue }
            $clsidStr = '{' + $ti.Guid.ToString().ToUpperInvariant() + '}'
            $declaredLookup[$clsidStr] = $true
            $declared.Add([pscustomobject]@{
                Clsid = $clsidStr
                Name  = $ti.Name
            }) | Out-Null
        }
    }

    # Pass 1 — inverse scan.
    $entries = Find-ComRegistrationsForFile -TargetPath $target -DeclaredLookup $declaredLookup

    # Pass 2 — for each declared CLSID we did NOT match by path, look it
    # up directly. If found anywhere, it is registered but pointing
    # elsewhere → PathMismatch. If not found at all → DeclaredOnly.
    foreach ($d in $declared) {
        $matched = $entries | Where-Object {
            [string]::Equals($_.Clsid, $d.Clsid, [System.StringComparison]::OrdinalIgnoreCase) `
                -and $_.PathMatchesTarget
        }
        if ($matched) { continue }

        $hits = Resolve-ClsidEverywhere -Clsid $d.Clsid
        if ($hits.Count -eq 0) {
            $entries.Add([pscustomobject]@{
                Clsid             = $d.Clsid
                FriendlyName      = $d.Name
                ProgId            = $null
                ThreadingModel    = $null
                InprocServer32    = $null
                NormalizedPath    = $null
                TypeLib           = $null
                Hive              = $null
                View              = $null
                DeclaredInTypeLib = $true
                PathMatchesTarget = $false
                Status            = 'DeclaredOnly'
            }) | Out-Null
        } else {
            foreach ($h in $hits) {
                Add-Member -InputObject $h -NotePropertyName DeclaredInTypeLib `
                           -NotePropertyValue $true -Force
                Add-Member -InputObject $h -NotePropertyName PathMatchesTarget `
                           -NotePropertyValue $false -Force
                Add-Member -InputObject $h -NotePropertyName Status `
                           -NotePropertyValue 'PathMismatch' -Force
                $entries.Add($h) | Out-Null
            }
        }
    }

    # Verdict + issue list.
    $registeredCount   = @($entries | Where-Object { $_.Status -eq 'Registered' }).Count
    $declaredOnly      = @($entries | Where-Object { $_.Status -eq 'DeclaredOnly' })
    $pathMismatches    = @($entries | Where-Object { $_.Status -eq 'PathMismatch' })
    $registeredOnly    = @($entries | Where-Object { $_.Status -eq 'RegisteredOnly' })

    $issues = New-Object System.Collections.Generic.List[string]
    foreach ($d in $declaredOnly) {
        $issues.Add("CLSID $($d.Clsid) ($($d.FriendlyName)) declared in TypeLib but not registered.") | Out-Null
    }
    foreach ($m in $pathMismatches) {
        $issues.Add("CLSID $($m.Clsid) registered but InprocServer32 points to '$($m.InprocServer32)' instead of the inspected DLL.") | Out-Null
    }

    $status = if ($declared.Count -eq 0 -and $entries.Count -eq 0) {
        'NotApplicable'
    } elseif ($declared.Count -gt 0 -and $declaredOnly.Count -eq 0 -and $pathMismatches.Count -eq 0) {
        'OK'
    } elseif ($declared.Count -gt 0 -and $registeredCount -eq 0) {
        'Unregistered'
    } else {
        'Partial'
    }

    return [pscustomobject]@{
        Scanned         = $true
        Status          = $status
        DeclaredCount   = $declared.Count
        RegisteredCount = $registeredCount
        RegisteredOnlyCount = $registeredOnly.Count
        MismatchCount   = $pathMismatches.Count
        Issues          = $issues.ToArray()
        Clsids          = $entries.ToArray()
    }
}
