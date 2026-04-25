# PE/COFF/Optional/Section parser plus directory readers (imports, exports,
# resources). Pure byte reading — never calls LoadLibrary, so cross-bitness
# inspection works and DllMain never executes.

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
    # $true when a string-named "TYPELIB" type entry exists.
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
