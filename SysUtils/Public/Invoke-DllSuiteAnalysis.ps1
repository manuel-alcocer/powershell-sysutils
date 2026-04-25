function Invoke-DllSuiteAnalysis {
    <#
    .SYNOPSIS
        Cross-DLL inventory: duplicates, GUID conflicts, interface drift,
        registry state. Aimed at legacy COM suites where DLLs got copied
        across teams and silently diverged while keeping the same CLSIDs.

    .DESCRIPTION
        Walks one or more directories, parses every PE found (DLL/OCX),
        and produces a structured analysis suitable for both interactive
        review and CI pipelines. Output object carries:

          - Per-DLL records: hash, size, COM/TypeLib metadata, declared
            CoClass/Interface/Dispatch GUIDs and their signatures.
          - Duplicate groups: byte-identical DLLs grouped by SHA-256.
          - GUID conflicts: GUIDs that appear in more than one distinct
            DLL (different SHA-256). Flagged with HasDrift=true when the
            interface or method set differs across versions.
          - Registration status: for each conflicted CoClass GUID, which
            on-disk copy is currently registered in HKCR\CLSID, or whether
            registration points outside the scanned set.

        Strictly read-only: no LoadLibrary, no regsvr32. Reuses Get-DllInfo
        for parsing and Resolve-ClsidEverywhere (private) for registry
        lookup, both in the same module.

    .PARAMETER Path
        One or more directories or file paths. Directories are walked; if
        -Recurse is set, the walk descends into subdirectories.

    .PARAMETER Include
        File patterns to consider. Default: '*.dll','*.ocx'.

    .PARAMETER Recurse
        Walk directories recursively.

    .PARAMETER OutputDir
        When set, writes report.json (full structured output, schema
        'dllsuite/1') and summary.txt (human-readable digest) into the
        directory. Created if missing.

    .PARAMETER Strict
        Marks the result as failed (HasIssues=true) when conflicts or
        drift are found. The cmdlet itself never throws or sets
        $LASTEXITCODE - the consumer (CI wrapper script, GUI button) is
        expected to translate Strict + HasIssues into the desired exit.

    .PARAMETER Quiet
        Suppress progress and per-step Write-Host. Final one-line summary
        is still emitted.

    .EXAMPLE
        # Scan two app trees, write report next to them
        Invoke-DllSuiteAnalysis -Path C:\Apps\Team1, C:\Apps\Team2 -Recurse `
                                -OutputDir C:\Reports\Suite

    .EXAMPLE
        # CI pipeline: fail the build on drift
        $r = Invoke-DllSuiteAnalysis -Path .\bin -Recurse -Strict -Quiet `
                                     -OutputDir .\artifacts
        if ($r.HasIssues) { exit 2 }

    .NOTES
        PowerShell 5.1+ on Windows. Performance: ~50 ms per DLL for the
        full parse + hash; registry lookup adds ~5 ms per conflicted CLSID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string[]]$Path,

        [string[]]$Include = @('*.dll','*.ocx'),

        [switch]$Recurse,

        [string]$OutputDir,

        [switch]$Strict,

        [switch]$Quiet
    )

    begin {
        $allFiles = New-Object System.Collections.Generic.List[string]
    }

    process {
        foreach ($p in $Path) {
            try {
                $resolved = (Resolve-Path -LiteralPath $p -ErrorAction Stop).ProviderPath
            } catch {
                Write-Error "Cannot resolve '$p': $($_.Exception.Message)"
                continue
            }

            if (Test-Path -LiteralPath $resolved -PathType Container) {
                $gciArgs = @{ LiteralPath = $resolved; File = $true; ErrorAction = 'SilentlyContinue' }
                if ($Recurse) { $gciArgs['Recurse'] = $true }
                Get-ChildItem @gciArgs | Where-Object {
                    $n = $_.Name
                    @($Include | Where-Object { $n -like $_ }).Count -gt 0
                } | ForEach-Object { [void]$allFiles.Add($_.FullName) }
            } else {
                [void]$allFiles.Add($resolved)
            }
        }
    }

    end {
        if ($allFiles.Count -eq 0) {
            Write-Warning "No matching DLL/OCX files found under the given paths."
            return
        }

        if (-not $Quiet) {
            Write-Host ("Scanning {0} files..." -f $allFiles.Count) -ForegroundColor Cyan
        }

        # ---- Per-file deep parse ---------------------------------------
        $records = New-Object System.Collections.Generic.List[object]
        $i = 0
        foreach ($f in $allFiles) {
            $i++
            Write-Verbose ("[{0}/{1}] {2}" -f $i, $allFiles.Count, (Split-Path -Leaf $f))

            try {
                $info = Get-DllInfo -Path $f -IncludeHash -IncludeTypeLib -ErrorAction Stop
            } catch {
                [void]$records.Add([pscustomobject]@{
                    Path       = $f
                    Sha256     = $null
                    Size       = $null
                    ParseError = $_.Exception.Message
                    Entries    = @()
                })
                continue
            }

            $entries = New-Object System.Collections.Generic.List[object]
            if ($info.Com -and $info.Com.HasTypeLib -and $info.Com.TypeLib -and $info.Com.TypeLib.TypeInfos) {
                foreach ($ti in $info.Com.TypeLib.TypeInfos) {
                    $kind = ($ti.Kind -replace '^TKIND_', '').ToLowerInvariant()
                    $methodSig    = $null
                    $interfaceSig = $null

                    if ($ti.Methods) {
                        $methodSig = @($ti.Methods | ForEach-Object {
                            "{0}#{1}" -f $_.Name, $_.DispId
                        } | Sort-Object) -join '|'
                    }
                    if ($ti.Interfaces) {
                        $interfaceSig = @($ti.Interfaces |
                            ForEach-Object { $_.Iid.ToString().ToUpperInvariant() } |
                            Sort-Object) -join '|'
                    }

                    [void]$entries.Add([pscustomobject]@{
                        Kind         = $kind
                        Name         = $ti.Name
                        Guid         = $ti.Guid.ToString().ToUpperInvariant()
                        MethodSig    = $methodSig
                        InterfaceSig = $interfaceSig
                        MethodCount  = if ($ti.Methods)    { $ti.Methods.Count }    else { 0 }
                        IfaceCount   = if ($ti.Interfaces) { $ti.Interfaces.Count } else { 0 }
                    })
                }
            }

            $libId = $null; $libName = $null; $libVersion = $null
            if ($info.Com -and $info.Com.TypeLib) {
                $libId      = $info.Com.TypeLib.LibId.ToString().ToUpperInvariant()
                $libName    = $info.Com.TypeLib.Name
                $libVersion = "{0}.{1}" -f $info.Com.TypeLib.MajorVersion, $info.Com.TypeLib.MinorVersion
            }

            # Build the per-file record. Explicit type coercions on the
            # primitive fields avoid the "Argument types do not match"
            # ArgumentException that PS 5.1 throws during pscustomobject
            # construction when a hashtable value is a complex CIM/PSObject
            # type (some Get-DllInfo fields are CIM-backed primitives).
            $h = [ordered]@{}
            $h['Path']        = [string]$info.Path
            $h['Size']        = [int64]$info.FileSize
            $h['Sha256']      = if ($info.Sha256) { [string]$info.Sha256 } else { $null }
            $h['IsComServer'] = [bool]$info.Com.IsComServer
            $h['HasTypeLib']  = [bool]$info.Com.HasTypeLib
            $h['LibId']       = $libId
            $h['LibName']     = $libName
            $h['LibVersion']  = $libVersion
            $h['Entries']     = $entries.ToArray()
            $h['ParseError']  = if ($info.ParseError) { [string]$info.ParseError } else { $null }
            [void]$records.Add([pscustomobject]$h)
        }

        # ---- Duplicate groups ------------------------------------------
        $duplicateGroups = @(
            $records |
                Where-Object { $_.Sha256 } |
                Group-Object Sha256 |
                Where-Object { $_.Count -gt 1 } |
                ForEach-Object {
                    [pscustomobject]@{
                        Sha256 = $_.Name
                        Size   = $_.Group[0].Size
                        Count  = $_.Count
                        Paths  = @($_.Group | ForEach-Object Path)
                    }
                }
        )

        # ---- GUID conflicts --------------------------------------------
        # Build inverted index GUID -> list of (Path, Sha256, Kind, Name, Sigs).
        $guidIndex = @{}
        foreach ($rec in $records) {
            foreach ($e in $rec.Entries) {
                if ($e.Guid -eq '00000000-0000-0000-0000-000000000000') { continue }
                if (-not $guidIndex.ContainsKey($e.Guid)) {
                    $guidIndex[$e.Guid] = New-Object System.Collections.Generic.List[object]
                }
                [void]$guidIndex[$e.Guid].Add([pscustomobject]@{
                    Path         = $rec.Path
                    Sha256       = $rec.Sha256
                    Kind         = $e.Kind
                    Name         = $e.Name
                    MethodSig    = $e.MethodSig
                    InterfaceSig = $e.InterfaceSig
                    MethodCount  = $e.MethodCount
                    IfaceCount   = $e.IfaceCount
                })
            }
        }

        $guidConflicts = New-Object System.Collections.Generic.List[object]
        # PS 5.1: enumerating Hashtable.Keys directly while indexing back
        # into the same hashtable can throw ArgumentException ("argument
        # types do not match"). Snapshot the keys to a string[] first.
        $allGuids = [string[]]@($guidIndex.Keys)
        foreach ($guid in $allGuids) {
            $occs = $guidIndex[$guid].ToArray()
            $distinctHashes = @($occs | ForEach-Object Sha256 | Where-Object { $_ } | Sort-Object -Unique)
            if ($distinctHashes.Count -le 1) { continue }   # not a conflict

            # Drift signature varies by kind: coclass uses InterfaceSig,
            # interface/dispatch use MethodSig. Anything else: not checked.
            $byHash = $occs | Group-Object Sha256
            $sigs = @($byHash | ForEach-Object {
                $first = $_.Group[0]
                switch ($first.Kind) {
                    'coclass'   { "iface:" + $first.InterfaceSig }
                    'interface' { "meth:"  + $first.MethodSig }
                    'dispatch'  { "meth:"  + $first.MethodSig }
                    default     { '' }
                }
            } | Sort-Object -Unique)
            $hasDrift = $sigs.Count -gt 1

            [void]$guidConflicts.Add([pscustomobject]@{
                Guid             = $guid
                Kind             = $occs[0].Kind
                Name             = $occs[0].Name
                DistinctVersions = $distinctHashes.Count
                HasDrift         = $hasDrift
                Occurrences      = @($occs | ForEach-Object {
                    [pscustomobject]@{
                        Path         = $_.Path
                        Sha256       = $_.Sha256
                        MethodCount  = $_.MethodCount
                        IfaceCount   = $_.IfaceCount
                        MethodSig    = $_.MethodSig
                        InterfaceSig = $_.InterfaceSig
                    }
                })
            })
        }

        # ---- Registration status for conflicted CoClasses --------------
        # Resolve-ClsidEverywhere is private to the module and already
        # reads HKLM/HKCU x64+x86. We only call it for CoClasses that
        # appear in multiple distinct DLLs.
        $registrationStatus = New-Object System.Collections.Generic.List[object]
        foreach ($c in $guidConflicts) {
            if ($c.Kind -ne 'coclass') { continue }
            $clsidBraced = '{' + $c.Guid + '}'
            $hits = Resolve-ClsidEverywhere -Clsid $clsidBraced

            if (-not $hits -or $hits.Count -eq 0) {
                [void]$registrationStatus.Add([pscustomobject]@{
                    Clsid                 = $clsidBraced
                    Name                  = $c.Name
                    State                 = 'NotRegistered'
                    RegisteredPath        = $null
                    RegisteredSha256      = $null
                    RegisteredScannedPath = $null
                    Hive                  = $null
                    View                  = $null
                })
                continue
            }

            $h = $hits[0]
            $regPath = $h.NormalizedPath
            $matchedRec = $records | Where-Object {
                $_.Path -and [string]::Equals(
                    [IO.Path]::GetFullPath($_.Path),
                    $regPath,
                    [System.StringComparison]::OrdinalIgnoreCase)
            } | Select-Object -First 1

            $state = if ($matchedRec) { 'RegisteredToScanned' } else { 'RegisteredOutsideScan' }
            [void]$registrationStatus.Add([pscustomobject]@{
                Clsid                 = $clsidBraced
                Name                  = $c.Name
                State                 = $state
                RegisteredPath        = $regPath
                RegisteredSha256      = if ($matchedRec) { $matchedRec.Sha256 } else { $null }
                RegisteredScannedPath = if ($matchedRec) { $matchedRec.Path }   else { $null }
                Hive                  = $h.Hive
                View                  = $h.View
            })
        }

        # ---- Build analysis object -------------------------------------
        # Materialize lists into arrays first; PS 5.1 piping over generic
        # List[object] sometimes throws "Argument types do not match"
        # depending on element types.
        $recordsArr  = $records.ToArray()
        $conflictsArr = $guidConflicts.ToArray()
        $regStatusArr = $registrationStatus.ToArray()

        $parseErrors = 0
        $comServers  = 0
        $uniqueHashes = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($r in $recordsArr) {
            if ($r.ParseError)   { $parseErrors++ }
            if ($r.IsComServer)  { $comServers++ }
            if ($r.Sha256)       { [void]$uniqueHashes.Add($r.Sha256) }
        }
        $driftIssues = 0
        foreach ($c in $conflictsArr) {
            if ($c.HasDrift) { $driftIssues++ }
        }

        $hasIssues = ($conflictsArr.Length -gt 0)
        $analysis = [pscustomobject]@{
            Schema        = 'dllsuite/1'
            ScannedAt     = (Get-Date).ToUniversalTime().ToString('o')
            HostName      = $env:COMPUTERNAME
            ScannedPaths  = @($Path)
            Recurse       = [bool]$Recurse
            Strict        = [bool]$Strict
            HasIssues     = [bool]($hasIssues -and $Strict)
            Summary       = [pscustomobject]@{
                FilesScanned    = $allFiles.Count
                ParseErrors     = $parseErrors
                ComServers      = $comServers
                UniqueByHash    = $uniqueHashes.Count
                DuplicateGroups = $duplicateGroups.Count
                GuidConflicts   = $conflictsArr.Length
                DriftIssues     = $driftIssues
            }
            Dlls               = $recordsArr
            DuplicateGroups    = @($duplicateGroups)
            GuidConflicts      = $conflictsArr
            RegistrationStatus = $regStatusArr
        }

        # ---- Write artifacts -------------------------------------------
        if ($OutputDir) {
            try {
                $null = New-Item -ItemType Directory -Path $OutputDir -Force -ErrorAction Stop
            } catch {
                throw "Cannot create OutputDir '$OutputDir': $($_.Exception.Message)"
            }

            $jsonPath    = Join-Path $OutputDir 'report.json'
            $summaryPath = Join-Path $OutputDir 'summary.txt'

            $analysis | ConvertTo-Json -Depth 12 | Set-Content -Path $jsonPath -Encoding UTF8

            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine("DLL Suite Analysis - $($analysis.ScannedAt)")
            [void]$sb.AppendLine("Host: $($analysis.HostName)")
            [void]$sb.AppendLine("Paths:")
            foreach ($pp in $analysis.ScannedPaths) { [void]$sb.AppendLine("  $pp") }
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("Files scanned    : $($analysis.Summary.FilesScanned)")
            [void]$sb.AppendLine("Parse errors     : $($analysis.Summary.ParseErrors)")
            [void]$sb.AppendLine("COM servers      : $($analysis.Summary.ComServers)")
            [void]$sb.AppendLine("Unique by hash   : $($analysis.Summary.UniqueByHash)")
            [void]$sb.AppendLine("Duplicate groups : $($analysis.Summary.DuplicateGroups)")
            [void]$sb.AppendLine("GUID conflicts   : $($analysis.Summary.GuidConflicts)")
            [void]$sb.AppendLine("Drift issues     : $($analysis.Summary.DriftIssues)")

            if ($duplicateGroups.Count -gt 0) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("=== Duplicate groups (byte-identical) ===")
                foreach ($g in $duplicateGroups) {
                    [void]$sb.AppendLine(("[{0}]  {1} bytes  ({2} copies)" -f $g.Sha256.Substring(0,12), $g.Size, $g.Count))
                    foreach ($p in $g.Paths) { [void]$sb.AppendLine("    $p") }
                }
            }

            if ($guidConflicts.Count -gt 0) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("=== GUID conflicts (same GUID, different DLLs) ===")
                foreach ($c in $guidConflicts) {
                    $tag = if ($c.HasDrift) { 'DRIFT' } else { 'dup-guid' }
                    [void]$sb.AppendLine(("[{0}] {1} {2}  ({3} versions)" -f $tag, $c.Kind, $c.Name, $c.DistinctVersions))
                    [void]$sb.AppendLine("    GUID: $($c.Guid)")
                    foreach ($o in $c.Occurrences) {
                        $extra = if ($c.Kind -eq 'coclass') { "ifaces=$($o.IfaceCount)" }
                                 else { "methods=$($o.MethodCount)" }
                        [void]$sb.AppendLine(("    {0}  sha={1}  {2}" -f $o.Path, ($o.Sha256.Substring(0,12)), $extra))
                    }
                }
            }

            if ($registrationStatus.Count -gt 0) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("=== Registry state of conflicted CoClasses ===")
                foreach ($r in $registrationStatus) {
                    [void]$sb.AppendLine(("[{0}] {1} {2}" -f $r.State, $r.Clsid, $r.Name))
                    if ($r.RegisteredPath) { [void]$sb.AppendLine("    -> $($r.RegisteredPath)") }
                }
            }

            $sb.ToString() | Set-Content -Path $summaryPath -Encoding UTF8

            if (-not $Quiet) {
                Write-Host "  report.json  : $jsonPath"  -ForegroundColor DarkGray
                Write-Host "  summary.txt  : $summaryPath" -ForegroundColor DarkGray
            }
        }

        # ---- Final one-liner -------------------------------------------
        $level = if ($hasIssues -and $Strict) { 'FAIL' }
                 elseif ($hasIssues)          { 'WARN' }
                 else                         { 'OK' }
        $msg = "{0} : files={1} duplicates={2} conflicts={3} drift={4}" -f `
            $level,
            $analysis.Summary.FilesScanned,
            $analysis.Summary.DuplicateGroups,
            $analysis.Summary.GuidConflicts,
            $analysis.Summary.DriftIssues

        if     ($level -eq 'FAIL') { Write-Warning $msg }
        elseif ($level -eq 'WARN') { Write-Warning $msg }
        else                       { Write-Host    $msg -ForegroundColor Green }

        # Always emit the structured analysis to the pipeline. CI wrappers
        # consume HasIssues to decide their exit code.
        $analysis
    }
}
