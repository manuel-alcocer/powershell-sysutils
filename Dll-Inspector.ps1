<#
.SYNOPSIS
    Read-only inspector for Windows PE files (DLL, OCX, EXE, SYS).

.DESCRIPTION
    Parses the PE/COFF headers, version resource, and (optionally) the
    Authenticode signature of a Windows binary, and reports whether it is a
    self-registering COM server and/or a managed (.NET) assembly. Emits one
    PSCustomObject per input path; output serializes cleanly with
    ConvertTo-Json (suitable for Ansible).

    Layers 1-2 are implemented: PE header + flags + COM/.NET detection,
    plus full Imports/Exports/Resources enumeration when requested via the
    Include* switches. TypeLib parsing (CoClasses/Interfaces) and .NET type
    listing are reserved for layers 3-4.

    The inspector NEVER calls LoadLibrary. The file is opened read-only with
    FileShare.ReadWrite and parsed as raw bytes. Consequences:

      * 32-bit DLLs can be inspected from 64-bit PowerShell and vice versa.
      * Old / corrupt / unsigned binaries can be examined without side effects.
      * DllMain is never executed.

.PARAMETER Path
    One or more paths to PE files. Accepts pipeline input (e.g. from
    Get-ChildItem) and the FullName / PSPath property aliases.

.PARAMETER IncludeImports
    Include the full imports table — modules and per-module function lists
    (with name+hint or ordinal). Reads the IDT and ILT/IAT from the PE.

.PARAMETER IncludeExports
    Include the full exports table — name, ordinal, RVA, and forwarder info
    (when an export points back into the export directory and resolves to
    "OtherModule.OtherFunction" or "OtherModule.#ordinal").

.PARAMETER IncludeResources
    Include a flat list of resource entries (Type, Name, Language, Size,
    CodePage). Walks the full 3-level resource directory tree.

.PARAMETER IncludeSignature
    Include Authenticode signature info (signer, issuer, validity, status).
    Slower since it goes through CryptoAPI.

.PARAMETER IncludeHash
    Include the SHA-256 hash of the file.

.PARAMETER Detailed
    Convenience switch — turns on every Include* switch.

.EXAMPLE
    .\Dll-Inspector.ps1 -Path C:\Windows\System32\scrrun.dll |
        ConvertTo-Json -Depth 10

.EXAMPLE
    Get-ChildItem C:\App -Filter *.dll -Recurse |
        .\Dll-Inspector.ps1 -IncludeHash -IncludeSignature

.EXAMPLE
    # Find every COM-registrable DLL under a directory
    Get-ChildItem C:\Legacy -Include *.dll,*.ocx -Recurse |
        .\Dll-Inspector.ps1 |
        Where-Object { $_.Com.IsComServer }

.EXAMPLE
    # Full inventory (all sections + signature + hash) for one binary
    .\Dll-Inspector.ps1 -Path .\foo.dll -Detailed | ConvertTo-Json -Depth 12

.EXAMPLE
    # Audit which DLLs in a directory import a given API
    Get-ChildItem C:\App -Filter *.dll |
        .\Dll-Inspector.ps1 -IncludeImports |
        Where-Object {
            $_.Imports.Functions.Name -contains 'CreateRemoteThread'
        } |
        Select-Object Path

.NOTES
    PowerShell 5.1+ on Windows.
    Layer 1 of the inspector — COM TypeLib reading and .NET type enumeration
    will arrive in subsequent layers. The Com / DotNet sub-objects already
    expose the placeholder fields they will populate.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('FullName', 'PSPath')]
    [string[]]$Path,

    [switch]$IncludeImports,
    [switch]$IncludeExports,
    [switch]$IncludeResources,
    [switch]$IncludeSignature,
    [switch]$IncludeHash,
    [switch]$Detailed
)

begin {
    # -------------------------------------------------------------------------
    # Constants — PE / COFF / DllCharacteristics
    # -------------------------------------------------------------------------

    $script:MachineMap = @{
        0x014c = 'x86'
        0x0200 = 'IA64'
        0x8664 = 'x64'
        0x01c0 = 'ARM'
        0x01c2 = 'ARM-Thumb'
        0x01c4 = 'ARMNT'
        0xAA64 = 'ARM64'
        0x0EBC = 'EFI'
    }

    $script:SubsystemMap = @{
        0  = 'Unknown'
        1  = 'Native'
        2  = 'Windows GUI'
        3  = 'Windows CUI'
        5  = 'OS/2 CUI'
        7  = 'POSIX CUI'
        8  = 'Native Win9x driver'
        9  = 'Windows CE GUI'
        10 = 'EFI Application'
        11 = 'EFI Boot Service Driver'
        12 = 'EFI Runtime Driver'
        13 = 'EFI ROM'
        14 = 'Xbox'
        16 = 'Windows Boot Application'
    }

    $script:CharacteristicsMap = [ordered]@{
        0x0001 = 'RelocsStripped'
        0x0002 = 'ExecutableImage'
        0x0004 = 'LineNumsStripped'
        0x0008 = 'LocalSymsStripped'
        0x0010 = 'AggressiveWsTrim'
        0x0020 = 'LargeAddressAware'
        0x0080 = 'BytesReversedLo'
        0x0100 = '32BitMachine'
        0x0200 = 'DebugStripped'
        0x0400 = 'RemovableRunFromSwap'
        0x0800 = 'NetRunFromSwap'
        0x1000 = 'System'
        0x2000 = 'Dll'
        0x4000 = 'UpSystemOnly'
        0x8000 = 'BytesReversedHi'
    }

    $script:DllCharacteristicsMap = [ordered]@{
        0x0020 = 'HighEntropyVA'
        0x0040 = 'DynamicBase'         # ASLR
        0x0080 = 'ForceIntegrity'
        0x0100 = 'NxCompat'            # DEP
        0x0200 = 'NoIsolation'
        0x0400 = 'NoSEH'
        0x0800 = 'NoBind'
        0x1000 = 'AppContainer'
        0x2000 = 'WdmDriver'
        0x4000 = 'GuardCF'             # Control Flow Guard
        0x8000 = 'TerminalServerAware'
    }

    # Standard resource type IDs (numeric). TYPELIB is conventionally
    # string-named (so it does not appear here); a few tools emit it as
    # numeric 13 — we keep that slot intentionally empty.
    $script:ResourceTypeMap = @{
        1  = 'CURSOR'
        2  = 'BITMAP'
        3  = 'ICON'
        4  = 'MENU'
        5  = 'DIALOG'
        6  = 'STRING'
        7  = 'FONTDIR'
        8  = 'FONT'
        9  = 'ACCELERATOR'
        10 = 'RCDATA'
        11 = 'MESSAGETABLE'
        12 = 'GROUP_CURSOR'
        14 = 'GROUP_ICON'
        16 = 'VERSION'
        17 = 'DLGINCLUDE'
        19 = 'PLUGPLAY'
        20 = 'VXD'
        21 = 'ANICURSOR'
        22 = 'ANIICON'
        23 = 'HTML'
        24 = 'MANIFEST'
    }

    # 0x8000_0000_0000_0000 cannot be written as an int64 literal in PS 5.1
    # (overflows). Build it via BitConverter once.
    $script:OrdinalFlag64 = [BitConverter]::ToUInt64(
        [byte[]](0,0,0,0,0,0,0,0x80), 0)

    # Data directory indices
    $script:DD_EXPORT   = 0
    $script:DD_IMPORT   = 1
    $script:DD_RESOURCE = 2
    $script:DD_SECURITY = 4
    $script:DD_DEBUG    = 6
    $script:DD_TLS      = 9
    $script:DD_CLR      = 14

    # The four self-registration entry points that a COM in-proc server must
    # export. DllGetClassObject + DllRegisterServer is the minimum signal.
    $script:ComSelfRegSymbols = @(
        'DllRegisterServer'
        'DllUnregisterServer'
        'DllGetClassObject'
        'DllCanUnloadNow'
        'DllInstall'
    )

    # -------------------------------------------------------------------------
    # PE parser — pure byte reading, never loads the image.
    # -------------------------------------------------------------------------

    function ConvertTo-Flags {
        # Decodes a bitmask into the matching string names from a map.
        # Uses GetEnumerator() so that with [ordered]@{} dictionaries we read by
        # key — the int indexer on OrderedDictionary would silently return the
        # value at a positional index instead.
        param([uint32]$Value, [System.Collections.IDictionary]$Map)
        $out = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $Map.GetEnumerator()) {
            $k = [uint32]$entry.Key
            if ($k -ne 0 -and (($Value -band $k) -eq $k)) {
                [void]$out.Add([string]$entry.Value)
            }
        }
        , $out.ToArray()
    }

    function Read-PEImage {
        # Opens the file (shared read/write), parses DOS+PE+COFF+Optional+section
        # table, and returns a hashtable. Caller must dispose Reader and Stream.
        param([string]$FilePath)

        $fs = [System.IO.File]::Open($FilePath, 'Open', 'Read', 'ReadWrite')
        $br = New-Object System.IO.BinaryReader($fs)

        try {
            if ($fs.Length -lt 64) { throw 'File too small to be a PE image' }

            if ($br.ReadUInt16() -ne 0x5A4D) {
                throw "Not a PE file (missing 'MZ' DOS signature)"
            }
            $fs.Position = 0x3C
            $eLfanew = $br.ReadUInt32()
            if ($eLfanew -le 0 -or $eLfanew -ge ($fs.Length - 24)) {
                throw "Invalid e_lfanew offset ($eLfanew)"
            }

            $fs.Position = $eLfanew
            if ($br.ReadUInt32() -ne 0x00004550) {
                throw "Not a PE file (missing 'PE\0\0' signature at $eLfanew)"
            }

            # IMAGE_FILE_HEADER (COFF), 20 bytes
            $machine          = $br.ReadUInt16()
            $numberOfSections = $br.ReadUInt16()
            $timeDateStamp    = $br.ReadUInt32()
            $null             = $br.ReadUInt32()    # PointerToSymbolTable
            $null             = $br.ReadUInt32()    # NumberOfSymbols
            $sizeOptHdr       = $br.ReadUInt16()
            $characteristics  = $br.ReadUInt16()

            # IMAGE_OPTIONAL_HEADER — magic word tells us PE32 vs PE32+
            $optStart = $fs.Position
            $magic    = $br.ReadUInt16()
            $is64 = switch ($magic) {
                0x10b { $false }
                0x20b { $true  }
                0x107 { $false }   # ROM image (rare)
                default { throw ("Unknown optional header magic 0x{0:X4}" -f $magic) }
            }

            # Subsystem and DllCharacteristics live at fixed offsets relative to
            # the start of the optional header (same for PE32 and PE32+):
            #   +68 Subsystem (uint16)
            #   +70 DllCharacteristics (uint16)
            $fs.Position = $optStart + 68
            $subsystem          = $br.ReadUInt16()
            $dllCharacteristics = $br.ReadUInt16()

            # NumberOfRvaAndSizes — different offset between PE32 (+92) and
            # PE32+ (+108). The field counts how many data directory entries
            # follow.
            $fs.Position = $optStart + ($(if ($is64) { 108 } else { 92 }))
            $numRvaSizes = $br.ReadUInt32()
            if ($numRvaSizes -gt 32) { $numRvaSizes = 32 }   # sanity clamp

            $dataDirs = New-Object 'object[]' $numRvaSizes
            for ($i = 0; $i -lt $numRvaSizes; $i++) {
                $dataDirs[$i] = [pscustomobject]@{
                    Rva  = $br.ReadUInt32()
                    Size = $br.ReadUInt32()
                }
            }

            # Section table — IMAGE_SECTION_HEADER * NumberOfSections, 40 bytes each.
            $fs.Position = $optStart + $sizeOptHdr
            $sections = New-Object 'object[]' $numberOfSections
            for ($i = 0; $i -lt $numberOfSections; $i++) {
                $nameBytes = $br.ReadBytes(8)
                $name = [Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
                $sections[$i] = [pscustomobject]@{
                    Name             = $name
                    VirtualSize      = $br.ReadUInt32()
                    VirtualAddress   = $br.ReadUInt32()
                    SizeOfRawData    = $br.ReadUInt32()
                    PointerToRawData = $br.ReadUInt32()
                    PointerToRelocs  = $br.ReadUInt32()
                    PointerToLineNum = $br.ReadUInt32()
                    NumberOfRelocs   = $br.ReadUInt16()
                    NumberOfLineNum  = $br.ReadUInt16()
                    Characteristics  = $br.ReadUInt32()
                }
            }

            return @{
                Stream             = $fs
                Reader             = $br
                Machine            = $machine
                Is64Bit            = $is64
                NumberOfSections   = $numberOfSections
                TimeDateStamp      = $timeDateStamp
                Characteristics    = $characteristics
                Subsystem          = $subsystem
                DllCharacteristics = $dllCharacteristics
                DataDirectories    = $dataDirs
                Sections           = $sections
            }
        }
        catch {
            $br.Dispose()
            $fs.Dispose()
            throw
        }
    }

    function ConvertTo-FileOffset {
        # RVA -> file offset using the section table. Returns $null when the RVA
        # is outside any mapped section.
        param([uint32]$Rva, [object[]]$Sections)
        foreach ($s in $Sections) {
            $vaEnd = $s.VirtualAddress + [Math]::Max($s.VirtualSize, $s.SizeOfRawData)
            if ($Rva -ge $s.VirtualAddress -and $Rva -lt $vaEnd) {
                return ($Rva - $s.VirtualAddress + $s.PointerToRawData)
            }
        }
        return $null
    }

    function Read-CStringAt {
        param([System.IO.BinaryReader]$Reader, [long]$Offset)
        $Reader.BaseStream.Position = $Offset
        $sb = New-Object System.Text.StringBuilder
        while ($true) {
            $b = $Reader.BaseStream.ReadByte()
            if ($b -le 0) { break }
            [void]$sb.Append([char]$b)
        }
        $sb.ToString()
    }

    function Get-PEExportsFull {
        # Reads the full export directory: ordinal, name, RVA, and forwarder
        # info (when an export's RVA falls within the export directory range,
        # the value at that location is an ASCII "OtherDll.OtherFunc" string).
        # Returns @{ Names = string[]; Exports = pscustomobject[] }. The Names
        # list is also used for the shallow COM-self-reg detector.
        param($Pe)
        $empty = @{ Names = @(); Exports = @() }
        $dd = $Pe.DataDirectories[$script:DD_EXPORT]
        if (-not $dd -or $dd.Size -eq 0) { return $empty }

        $expOff = ConvertTo-FileOffset -Rva $dd.Rva -Sections $Pe.Sections
        if ($null -eq $expOff) { return $empty }

        $br = $Pe.Reader
        $br.BaseStream.Position = $expOff

        # IMAGE_EXPORT_DIRECTORY (40 bytes)
        $null         = $br.ReadUInt32()   # Characteristics
        $null         = $br.ReadUInt32()   # TimeDateStamp
        $null         = $br.ReadUInt16()   # MajorVersion
        $null         = $br.ReadUInt16()   # MinorVersion
        $null         = $br.ReadUInt32()   # NameRva (DLL name)
        $ordinalBase  = $br.ReadUInt32()
        $numFuncs     = $br.ReadUInt32()
        $numNames     = $br.ReadUInt32()
        $rvaFuncs     = $br.ReadUInt32()
        $rvaNames     = $br.ReadUInt32()
        $rvaOrdinals  = $br.ReadUInt32()

        # Address-of-functions table -> RVA per ordinal slot
        $funcs = @()
        if ($numFuncs -gt 0 -and $rvaFuncs -ne 0) {
            $foff = ConvertTo-FileOffset -Rva $rvaFuncs -Sections $Pe.Sections
            if ($null -ne $foff) {
                $br.BaseStream.Position = $foff
                $funcs = for ($i = 0; $i -lt $numFuncs; $i++) { $br.ReadUInt32() }
            }
        }

        # Names + name-ordinals tables (parallel arrays of length NumberOfNames).
        # NameOrdinals[i] is the index into AddressOfFunctions that Names[i]
        # refers to.
        $nameRvasArr = @()
        $nameOrdsArr = @()
        if ($numNames -gt 0 -and $rvaNames -ne 0 -and $rvaOrdinals -ne 0) {
            $nFOff = ConvertTo-FileOffset -Rva $rvaNames    -Sections $Pe.Sections
            $nOOff = ConvertTo-FileOffset -Rva $rvaOrdinals -Sections $Pe.Sections
            if ($null -ne $nFOff -and $null -ne $nOOff) {
                $br.BaseStream.Position = $nFOff
                $nameRvasArr = for ($i = 0; $i -lt $numNames; $i++) { $br.ReadUInt32() }
                $br.BaseStream.Position = $nOOff
                $nameOrdsArr = for ($i = 0; $i -lt $numNames; $i++) { $br.ReadUInt16() }
            }
        }

        # Map ordinal slot index -> name
        $namesByIndex = @{}
        $namesList    = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $numNames; $i++) {
            $idx = [int]$nameOrdsArr[$i]
            $rva = [uint32]$nameRvasArr[$i]
            $off = ConvertTo-FileOffset -Rva $rva -Sections $Pe.Sections
            if ($null -ne $off) {
                $nm = Read-CStringAt -Reader $br -Offset $off
                $namesByIndex[$idx] = $nm
                [void]$namesList.Add($nm)
            }
        }

        # Build full exports list
        $exports = New-Object System.Collections.Generic.List[object]
        $expDirEnd = $dd.Rva + $dd.Size
        for ($i = 0; $i -lt $numFuncs; $i++) {
            $rva = [uint32]$funcs[$i]
            if ($rva -eq 0) { continue }   # gap in the ordinal range
            $name    = if ($namesByIndex.ContainsKey($i)) { $namesByIndex[$i] } else { $null }
            $ordinal = [int]($ordinalBase + $i)
            $isFwd   = ($rva -ge $dd.Rva -and $rva -lt $expDirEnd)
            $fwd     = $null
            if ($isFwd) {
                $fwdOff = ConvertTo-FileOffset -Rva $rva -Sections $Pe.Sections
                if ($null -ne $fwdOff) { $fwd = Read-CStringAt -Reader $br -Offset $fwdOff }
            }
            [void]$exports.Add([pscustomobject]@{
                Name        = $name
                Ordinal     = $ordinal
                Rva         = $rva
                IsForwarder = $isFwd
                ForwardsTo  = $fwd
            })
        }

        # NOTE: do NOT use @($exports) here — PowerShell 5.1 fails with
        # "Argument types do not match" when @() coerces a
        # System.Collections.Generic.List[object] of PSCustomObject items.
        # Use the .NET ToArray() method directly.
        @{ Names = $namesList.ToArray(); Exports = $exports.ToArray() }
    }

    function Get-PEImports {
        # Reads the IMAGE_IMPORT_DESCRIPTOR array and walks each module's ILT
        # (preferred) or IAT to enumerate imported functions. Returns
        # [{ Module, Functions: [{ Name, Ordinal, Hint, ByOrdinal }] }, ...].
        param($Pe)
        $dd = $Pe.DataDirectories[$script:DD_IMPORT]
        if (-not $dd -or $dd.Size -eq 0) { return @() }
        $impOff = ConvertTo-FileOffset -Rva $dd.Rva -Sections $Pe.Sections
        if ($null -eq $impOff) { return @() }

        $br      = $Pe.Reader
        $is64    = $Pe.Is64Bit
        $thunkSz = if ($is64) { 8 } else { 4 }
        $modules = New-Object System.Collections.Generic.List[object]

        $cursor = [long]$impOff
        $maxDescriptors = 4096   # sanity cap for malformed PEs
        for ($mi = 0; $mi -lt $maxDescriptors; $mi++) {
            $br.BaseStream.Position = $cursor
            $oft  = $br.ReadUInt32()      # OriginalFirstThunk (ILT)
            $null = $br.ReadUInt32()      # TimeDateStamp
            $null = $br.ReadUInt32()      # ForwarderChain
            $name = $br.ReadUInt32()      # Module name RVA
            $ft   = $br.ReadUInt32()      # FirstThunk (IAT)
            if ($oft -eq 0 -and $name -eq 0 -and $ft -eq 0) { break }
            $cursor += 20

            $modName = ''
            $nOff = ConvertTo-FileOffset -Rva $name -Sections $Pe.Sections
            if ($null -ne $nOff) { $modName = Read-CStringAt -Reader $br -Offset $nOff }

            # Prefer ILT (not patched at runtime); fall back to IAT when bound.
            $thunkRva = if ($oft -ne 0) { $oft } else { $ft }
            $functions = New-Object System.Collections.Generic.List[object]
            $thunkOff = ConvertTo-FileOffset -Rva $thunkRva -Sections $Pe.Sections
            if ($null -ne $thunkOff) {
                # First pass: collect raw thunk values until terminator.
                $thunks = New-Object System.Collections.Generic.List[uint64]
                $br.BaseStream.Position = $thunkOff
                while ($thunks.Count -lt 65536) {
                    $t = if ($is64) { $br.ReadUInt64() } else { [uint64]$br.ReadUInt32() }
                    if ($t -eq 0) { break }
                    [void]$thunks.Add($t)
                }
                # Second pass: resolve names/ordinals.
                foreach ($t in $thunks) {
                    $isOrd = if ($is64) {
                        (($t -band $script:OrdinalFlag64) -ne 0)
                    } else {
                        (($t -band 0x80000000) -ne 0)
                    }
                    if ($isOrd) {
                        [void]$functions.Add([pscustomobject]@{
                            Name      = $null
                            Ordinal   = [int]($t -band 0xFFFF)
                            Hint      = $null
                            ByOrdinal = $true
                        })
                    } else {
                        $rvaByName = [uint32]($t -band 0xFFFFFFFF)
                        $byNameOff = ConvertTo-FileOffset -Rva $rvaByName -Sections $Pe.Sections
                        $hint = $null; $fname = $null
                        if ($null -ne $byNameOff) {
                            $br.BaseStream.Position = $byNameOff
                            $hint  = $br.ReadUInt16()
                            $fname = Read-CStringAt -Reader $br -Offset ($byNameOff + 2)
                        }
                        [void]$functions.Add([pscustomobject]@{
                            Name      = $fname
                            Ordinal   = $null
                            Hint      = $hint
                            ByOrdinal = $false
                        })
                    }
                }
            }

            [void]$modules.Add([pscustomobject]@{
                Module    = $modName
                Functions = $functions.ToArray()
            })
        }

        # Emit the modules as a stream — caller wraps with @() to materialize.
        $modules.ToArray()
    }

    function Read-ResourceString {
        # Reads a UTF-16 length-prefixed name starting at the given absolute
        # file offset. Used for level entries with the high bit set on NameOrId.
        param([System.IO.BinaryReader]$Reader, [long]$Offset)
        $Reader.BaseStream.Position = $Offset
        $len = $Reader.ReadUInt16()
        $bytes = $Reader.ReadBytes([int]$len * 2)
        [Text.Encoding]::Unicode.GetString($bytes)
    }

    function Read-ResourceDirectory {
        # Recursively walks one IMAGE_RESOURCE_DIRECTORY and pushes leaf data
        # entries into $Acc. $Path is a 1..3 hashtable keyed by level (1=Type,
        # 2=Name, 3=Language); values are int IDs or strings.
        param(
            $Pe,
            [long]$RootOff,
            [long]$DirOff,
            [int]$Level,
            [hashtable]$Path,
            [System.Collections.IList]$Acc
        )
        $br = $Pe.Reader
        $br.BaseStream.Position = $DirOff
        $null  = $br.ReadUInt32()   # Characteristics
        $null  = $br.ReadUInt32()   # TimeDateStamp
        $null  = $br.ReadUInt16()   # MajorVersion
        $null  = $br.ReadUInt16()   # MinorVersion
        $named = $br.ReadUInt16()
        $idCnt = $br.ReadUInt16()
        $total = [int]$named + [int]$idCnt

        $entries = for ($i = 0; $i -lt $total; $i++) {
            [pscustomobject]@{
                NameOrId     = $br.ReadUInt32()
                OffsetToData = $br.ReadUInt32()
            }
        }

        foreach ($e in $entries) {
            $key = if (($e.NameOrId -band 0x80000000) -ne 0) {
                Read-ResourceString -Reader $br `
                    -Offset ($RootOff + ($e.NameOrId -band 0x7FFFFFFF))
            } else {
                [int]$e.NameOrId
            }

            $newPath = @{} + $Path
            $newPath[$Level] = $key

            if (($e.OffsetToData -band 0x80000000) -ne 0) {
                $subOff = $RootOff + ($e.OffsetToData -band 0x7FFFFFFF)
                Read-ResourceDirectory -Pe $Pe -RootOff $RootOff -DirOff $subOff `
                    -Level ($Level + 1) -Path $newPath -Acc $Acc
            } else {
                # IMAGE_RESOURCE_DATA_ENTRY (16 bytes)
                $deOff = $RootOff + $e.OffsetToData
                $br.BaseStream.Position = $deOff
                $dataRva  = $br.ReadUInt32()
                $size     = $br.ReadUInt32()
                $codepage = $br.ReadUInt32()
                $null     = $br.ReadUInt32()    # Reserved
                [void]$Acc.Add([pscustomobject]@{
                    TypeRaw  = $newPath[1]
                    Name     = $newPath[2]
                    Language = $newPath[3]
                    DataRva  = $dataRva
                    Size     = $size
                    CodePage = $codepage
                })
            }
        }
    }

    function Get-PEResources {
        # Walks the full resource tree and returns a flat list with friendly
        # type names (decoded from ResourceTypeMap when numeric).
        param($Pe)
        $dd = $Pe.DataDirectories[$script:DD_RESOURCE]
        if (-not $dd -or $dd.Size -eq 0) { return @() }
        $rootOff = ConvertTo-FileOffset -Rva $dd.Rva -Sections $Pe.Sections
        if ($null -eq $rootOff) { return @() }

        $list = New-Object System.Collections.Generic.List[object]
        Read-ResourceDirectory -Pe $Pe -RootOff $rootOff -DirOff $rootOff `
            -Level 1 -Path @{} -Acc $list

        $list | ForEach-Object {
            $typeName = if ($_.TypeRaw -is [int]) {
                $script:ResourceTypeMap[[int]$_.TypeRaw]
            } else { [string]$_.TypeRaw }
            if (-not $typeName) { $typeName = "ID:$($_.TypeRaw)" }
            [pscustomobject]@{
                Type     = $typeName
                TypeRaw  = $_.TypeRaw
                Name     = $_.Name
                Language = $_.Language
                Size     = $_.Size
                CodePage = $_.CodePage
                DataRva  = $_.DataRva
            }
        }
    }

    function Test-PEHasTypeLibResource {
        # Walks the level-1 (Type) entries of the resource directory and returns
        # $true when a string-named "TYPELIB" type entry exists. Sufficient for
        # the shallow detector — full TypeLib parsing comes in layer 3.
        param($Pe)
        $dd = $Pe.DataDirectories[$script:DD_RESOURCE]
        if (-not $dd -or $dd.Size -eq 0) { return $false }

        $rootOff = ConvertTo-FileOffset -Rva $dd.Rva -Sections $Pe.Sections
        if ($null -eq $rootOff) { return $false }

        $br = $Pe.Reader
        $br.BaseStream.Position = $rootOff

        # IMAGE_RESOURCE_DIRECTORY
        $null       = $br.ReadUInt32()    # Characteristics
        $null       = $br.ReadUInt32()    # TimeDateStamp
        $null       = $br.ReadUInt16()    # MajorVersion
        $null       = $br.ReadUInt16()    # MinorVersion
        $namedCount = $br.ReadUInt16()
        $idCount    = $br.ReadUInt16()

        $total = $namedCount + $idCount
        $entries = for ($i = 0; $i -lt $total; $i++) {
            [pscustomobject]@{
                NameOrId     = $br.ReadUInt32()
                OffsetToData = $br.ReadUInt32()
            }
        }

        foreach ($e in $entries) {
            if (($e.NameOrId -band 0x80000000) -ne 0) {
                # Named entry: high bit set, low 31 bits are an offset (relative
                # to the resource section root) to a UTF-16 length-prefixed string.
                $strOff = $rootOff + ($e.NameOrId -band 0x7FFFFFFF)
                $br.BaseStream.Position = $strOff
                $strLen   = $br.ReadUInt16()
                $strBytes = $br.ReadBytes([int]$strLen * 2)
                $name     = [Text.Encoding]::Unicode.GetString($strBytes)
                if ($name -ieq 'TYPELIB') { return $true }
            }
        }
        return $false
    }

    # -------------------------------------------------------------------------
    # Side helpers — version info, signature, hash
    # -------------------------------------------------------------------------

    function Get-PEVersionInfoSafe {
        param([string]$FilePath)
        try {
            $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
            [pscustomobject]@{
                FileVersion       = $vi.FileVersion
                ProductVersion    = $vi.ProductVersion
                FileVersionRaw    = "$($vi.FileMajorPart).$($vi.FileMinorPart).$($vi.FileBuildPart).$($vi.FilePrivatePart)"
                ProductVersionRaw = "$($vi.ProductMajorPart).$($vi.ProductMinorPart).$($vi.ProductBuildPart).$($vi.ProductPrivatePart)"
                CompanyName       = $vi.CompanyName
                ProductName       = $vi.ProductName
                FileDescription   = $vi.FileDescription
                OriginalFilename  = $vi.OriginalFilename
                InternalName      = $vi.InternalName
                LegalCopyright    = $vi.LegalCopyright
                LegalTrademarks   = $vi.LegalTrademarks
                Comments          = $vi.Comments
                Language          = $vi.Language
                IsDebug           = $vi.IsDebug
                IsPreRelease      = $vi.IsPreRelease
                IsPatched         = $vi.IsPatched
                IsPrivateBuild    = $vi.IsPrivateBuild
                IsSpecialBuild    = $vi.IsSpecialBuild
            }
        }
        catch { $null }
    }

    function Get-PESignatureInfoSafe {
        param([string]$FilePath)
        try {
            $sig  = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
            $cert = $sig.SignerCertificate
            [pscustomobject]@{
                Status        = "$($sig.Status)"
                StatusMessage = $sig.StatusMessage
                SignatureType = "$($sig.SignatureType)"
                IsOSBinary    = [bool]$sig.IsOSBinary
                Subject       = if ($cert) { $cert.Subject }      else { $null }
                Issuer        = if ($cert) { $cert.Issuer }       else { $null }
                NotBefore     = if ($cert) { $cert.NotBefore }    else { $null }
                NotAfter      = if ($cert) { $cert.NotAfter }     else { $null }
                Thumbprint    = if ($cert) { $cert.Thumbprint }   else { $null }
                SerialNumber  = if ($cert) { $cert.SerialNumber } else { $null }
            }
        }
        catch {
            [pscustomobject]@{
                Status        = 'Error'
                StatusMessage = $_.Exception.Message
            }
        }
    }

    # -------------------------------------------------------------------------
    # Orchestrator — turns one file path into one PSCustomObject.
    # -------------------------------------------------------------------------

    function Get-DllInfo {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$FilePath,
            [switch]$IncludeImports,
            [switch]$IncludeExports,
            [switch]$IncludeResources,
            [switch]$IncludeSignature,
            [switch]$IncludeHash
        )

        $resolved = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).ProviderPath
        $fi = Get-Item -LiteralPath $resolved

        $result = [ordered]@{
            Path       = $resolved
            FileSize   = $fi.Length
            LastWrite  = $fi.LastWriteTimeUtc
            IsValidPE  = $false
            ParseError = $null
            PE         = $null
            Version    = $null
            Com        = $null
            DotNet     = $null
            Imports    = $null
            Exports    = $null
            Resources  = $null
            Signature  = $null
            Sha256     = $null
        }

        $pe = $null
        try {
            $pe = Read-PEImage -FilePath $resolved
            $result.IsValidPE = $true

            $arch = $script:MachineMap[[int]$pe.Machine]
            if (-not $arch) { $arch = ('Unknown(0x{0:X4})' -f $pe.Machine) }
            $sub  = $script:SubsystemMap[[int]$pe.Subsystem]
            if (-not $sub)  { $sub  = ('Unknown({0})'    -f $pe.Subsystem) }

            # Some compilers emit a deterministic "reproducible build" hash in
            # TimeDateStamp instead of a real time_t. We surface the decoded
            # value as-is and let the caller decide.
            $tsUtc = $null
            if ($pe.TimeDateStamp -gt 0) {
                try {
                    $tsUtc = ([System.DateTimeOffset]::FromUnixTimeSeconds([int64]$pe.TimeDateStamp)).UtcDateTime
                } catch { $tsUtc = $null }
            }

            $result.PE = [pscustomobject]@{
                Architecture       = $arch
                MachineRaw         = ('0x{0:X4}' -f $pe.Machine)
                Is64Bit            = $pe.Is64Bit
                Subsystem          = $sub
                IsDll              = (($pe.Characteristics    -band 0x2000) -ne 0)
                IsExecutable       = (($pe.Characteristics    -band 0x0002) -ne 0)
                Characteristics    = (ConvertTo-Flags -Value $pe.Characteristics    -Map $script:CharacteristicsMap)
                DllCharacteristics = (ConvertTo-Flags -Value $pe.DllCharacteristics -Map $script:DllCharacteristicsMap)
                TimestampUtc       = $tsUtc
                NumberOfSections   = $pe.NumberOfSections
                Sections           = $pe.Sections | Select-Object Name, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData
            }

            $result.Version = Get-PEVersionInfoSafe -FilePath $resolved

            # Exports — always read (cheap), used both for COM detection and
            # for the Exports field when -IncludeExports is set.
            $expData = @{ Names = @(); Exports = @() }
            try { $expData = Get-PEExportsFull -Pe $pe } catch { }
            $exportNames = $expData.Names
            $selfReg = @($script:ComSelfRegSymbols | Where-Object { $exportNames -contains $_ })

            # Resources — when requested, do a full walk and derive HasTypeLib
            # from it; otherwise the cheap level-1 detector is enough.
            $resources = $null
            $hasTlb    = $false
            if ($IncludeResources) {
                try { $resources = @(Get-PEResources -Pe $pe) } catch { $resources = @() }
                $hasTlb = [bool]($resources | Where-Object { $_.Type -ieq 'TYPELIB' -or $_.TypeRaw -ieq 'TYPELIB' })
            } else {
                try { $hasTlb = Test-PEHasTypeLibResource -Pe $pe } catch { }
            }

            $result.Com = [pscustomobject]@{
                IsComServer    = (($selfReg -contains 'DllGetClassObject') -and ($selfReg -contains 'DllRegisterServer'))
                HasTypeLib     = $hasTlb
                SelfRegExports = @($selfReg)
                # Filled by layer 3:
                TypeLib        = $null
            }

            # .NET detection (shallow): CLR data directory present and non-empty
            $clr       = $pe.DataDirectories[$script:DD_CLR]
            $isManaged = ($clr -and $clr.Size -gt 0 -and $clr.Rva -gt 0)
            $result.DotNet = [pscustomobject]@{
                IsManaged      = [bool]$isManaged
                # Filled by layer 4:
                RuntimeVersion = $null
                AssemblyName   = $null
                Version        = $null
                IsComVisible   = $null
            }

            if ($IncludeImports) {
                try   { $result.Imports = @(Get-PEImports -Pe $pe) }
                catch { $result.Imports = @() }
            }
            if ($IncludeExports) {
                $result.Exports = @($expData.Exports)
            }
            if ($IncludeResources) {
                $result.Resources = @($resources)
            }
        }
        catch {
            $result.ParseError = $_.Exception.Message
        }
        finally {
            if ($pe) {
                try { $pe.Reader.Dispose() } catch {}
                try { $pe.Stream.Dispose() } catch {}
            }
        }

        if ($IncludeSignature) {
            $result.Signature = Get-PESignatureInfoSafe -FilePath $resolved
        }
        if ($IncludeHash) {
            try   { $result.Sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash }
            catch { $result.Sha256 = $null }
        }

        [pscustomobject]$result
    }
}

process {
    if ($Detailed) {
        $IncludeImports   = $true
        $IncludeExports   = $true
        $IncludeResources = $true
        $IncludeSignature = $true
        $IncludeHash      = $true
    }
    foreach ($p in $Path) {
        try {
            Get-DllInfo -FilePath $p `
                -IncludeImports:$IncludeImports `
                -IncludeExports:$IncludeExports `
                -IncludeResources:$IncludeResources `
                -IncludeSignature:$IncludeSignature `
                -IncludeHash:$IncludeHash
        }
        catch {
            Write-Error "Failed to inspect '$p': $($_.Exception.Message)"
        }
    }
}
