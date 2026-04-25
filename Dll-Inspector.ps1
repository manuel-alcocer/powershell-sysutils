<#
.SYNOPSIS
    Read-only inspector for Windows PE files (DLL, OCX, EXE, SYS).

.DESCRIPTION
    Parses the PE/COFF headers, version resource, and (optionally) the
    Authenticode signature of a Windows binary, and reports whether it is a
    self-registering COM server and/or a managed (.NET) assembly. Emits one
    PSCustomObject per input path; output serializes cleanly with
    ConvertTo-Json (suitable for Ansible).

    This is layer 1 — header + flags + COM/.NET detection. Imports/Exports,
    full resource enumeration, TypeLib reading, and .NET type listing are
    reserved for later layers. The current detection paths read a minimal
    amount from the export and resource directories to decide flags.

    The inspector NEVER calls LoadLibrary. The file is opened read-only with
    FileShare.ReadWrite and parsed as raw bytes. Consequences:

      * 32-bit DLLs can be inspected from 64-bit PowerShell and vice versa.
      * Old / corrupt / unsigned binaries can be examined without side effects.
      * DllMain is never executed.

.PARAMETER Path
    One or more paths to PE files. Accepts pipeline input (e.g. from
    Get-ChildItem) and the FullName / PSPath property aliases.

.PARAMETER IncludeSignature
    Include Authenticode signature info (signer, issuer, validity, status).
    Slower since it goes through CryptoAPI.

.PARAMETER IncludeHash
    Include the SHA-256 hash of the file.

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

    [switch]$IncludeSignature,
    [switch]$IncludeHash
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

    function Get-PEExportNamesInternal {
        # Minimal export-name reader used for COM detection only. Returns the
        # list of named exports (no ordinals, no forwarders) — full export
        # parsing is reserved for layer 2.
        param($Pe)
        $dd = $Pe.DataDirectories[$script:DD_EXPORT]
        if (-not $dd -or $dd.Size -eq 0) { return @() }

        $expOff = ConvertTo-FileOffset -Rva $dd.Rva -Sections $Pe.Sections
        if ($null -eq $expOff) { return @() }

        $br = $Pe.Reader
        $br.BaseStream.Position = $expOff

        # IMAGE_EXPORT_DIRECTORY — only NumberOfNames + AddressOfNames are needed
        $null     = $br.ReadUInt32()    # Characteristics
        $null     = $br.ReadUInt32()    # TimeDateStamp
        $null     = $br.ReadUInt16()    # MajorVersion
        $null     = $br.ReadUInt16()    # MinorVersion
        $null     = $br.ReadUInt32()    # NameRva
        $null     = $br.ReadUInt32()    # OrdinalBase
        $null     = $br.ReadUInt32()    # NumberOfFunctions
        $numNames = $br.ReadUInt32()
        $null     = $br.ReadUInt32()    # AddressOfFunctions
        $rvaNames = $br.ReadUInt32()
        $null     = $br.ReadUInt32()    # AddressOfNameOrdinals

        if ($numNames -eq 0 -or $rvaNames -eq 0) { return @() }
        $namesTableOff = ConvertTo-FileOffset -Rva $rvaNames -Sections $Pe.Sections
        if ($null -eq $namesTableOff) { return @() }

        $br.BaseStream.Position = $namesTableOff
        $nameRvas = for ($i = 0; $i -lt $numNames; $i++) { $br.ReadUInt32() }

        $names = foreach ($rva in $nameRvas) {
            $off = ConvertTo-FileOffset -Rva $rva -Sections $Pe.Sections
            if ($null -ne $off) { Read-CStringAt -Reader $br -Offset $off }
        }
        , @($names)
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

            # COM detection (shallow)
            $exportNames = @()
            try { $exportNames = Get-PEExportNamesInternal -Pe $pe } catch { }
            $selfReg = @($script:ComSelfRegSymbols | Where-Object { $exportNames -contains $_ })

            $hasTlb = $false
            try { $hasTlb = Test-PEHasTypeLibResource -Pe $pe } catch { }

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
    foreach ($p in $Path) {
        try {
            Get-DllInfo -FilePath $p `
                -IncludeSignature:$IncludeSignature `
                -IncludeHash:$IncludeHash
        }
        catch {
            Write-Error "Failed to inspect '$p': $($_.Exception.Message)"
        }
    }
}
