function Get-DllInfo {
    <#
    .SYNOPSIS
        Read-only inspector for Windows PE files (DLL, OCX, EXE, SYS).

    .DESCRIPTION
        Parses the PE/COFF headers, version resource, and (optionally) the
        Authenticode signature of a Windows binary, and reports whether it is a
        self-registering COM server and/or a managed (.NET) assembly. Emits one
        PSCustomObject per input path; output serializes cleanly with
        ConvertTo-Json (suitable for Ansible).

        The inspector NEVER calls LoadLibrary. The file is opened read-only with
        FileShare.ReadWrite and parsed as raw bytes. Consequences:

          * 32-bit DLLs can be inspected from 64-bit PowerShell and vice versa.
          * Old / corrupt / unsigned binaries can be examined without side effects.
          * DllMain is never executed.

    .PARAMETER Path
        One or more paths to PE files. Accepts pipeline input (e.g. from
        Get-ChildItem) and the FullName / PSPath / FilePath property aliases.

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

    .PARAMETER IncludeTypeLib
        When the binary carries a TYPELIB resource, load it via oleaut32!
        LoadTypeLibEx (REGKIND_NONE — no registration) and emit the COM type
        library: LibId, version, name, plus every CoClass / interface /
        dispinterface / enum / alias with their GUIDs, parents, methods, params
        and members.

    .PARAMETER IncludeDotNetTypes
        For managed assemblies, additionally load the file via
        Assembly.ReflectionOnlyLoadFrom and enumerate every type with its
        attributes (IsComVisible, Guid, ProgId, base type, kind). The
        cheap fields (RuntimeVersion, PEKind, CorFlags, AssemblyName,
        Version, Culture, PublicKeyToken) are reported always when the
        binary has a CLR header.

    .PARAMETER IncludeSignature
        Include Authenticode signature info (signer, issuer, validity, status).
        Slower since it goes through CryptoAPI.

    .PARAMETER IncludeHash
        Include the SHA-256 hash of the file.

    .PARAMETER Detailed
        Convenience switch — turns on every Include* switch.

    .EXAMPLE
        Get-DllInfo -Path C:\Windows\System32\scrrun.dll | ConvertTo-Json -Depth 12

    .EXAMPLE
        Get-ChildItem C:\App -Filter *.dll -Recurse |
            Get-DllInfo -IncludeHash -IncludeSignature

    .EXAMPLE
        # Find every COM-registrable DLL under a directory
        Get-ChildItem C:\Legacy -Include *.dll,*.ocx -Recurse |
            Get-DllInfo |
            Where-Object { $_.Com.IsComServer }

    .EXAMPLE
        # Audit which DLLs in a directory import a given API
        Get-ChildItem C:\App -Filter *.dll |
            Get-DllInfo -IncludeImports |
            Where-Object {
                $_.Imports.Functions.Name -contains 'CreateRemoteThread'
            } |
            Select-Object Path

    .EXAMPLE
        # Full inventory (all sections + signature + hash) for one binary
        Get-DllInfo -Path .\foo.dll -Detailed | ConvertTo-Json -Depth 12

    .NOTES
        PowerShell 5.1+ on Windows.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName', 'PSPath', 'FilePath')]
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

    process {
        if ($Detailed) {
            $IncludeImports     = $true
            $IncludeExports     = $true
            $IncludeResources   = $true
            $IncludeTypeLib     = $true
            $IncludeDotNetTypes = $true
            $IncludeSignature   = $true
            $IncludeHash        = $true
        }

        foreach ($p in $Path) {
            try {
                $resolved = (Resolve-Path -LiteralPath $p -ErrorAction Stop).ProviderPath
            } catch {
                Write-Error "Failed to resolve '$p': $($_.Exception.Message)"
                continue
            }
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

                $tlibInfo = $null
                if ($IncludeTypeLib -and $hasTlb) {
                    $tlibInfo = Get-TypeLibInfoSafe -FilePath $resolved
                }
                $result.Com = [pscustomobject]@{
                    IsComServer    = (($selfReg -contains 'DllGetClassObject') -and ($selfReg -contains 'DllRegisterServer'))
                    HasTypeLib     = $hasTlb
                    SelfRegExports = @($selfReg)
                    TypeLib        = $tlibInfo
                }

                # .NET — cheap path: CLR header + MetaData root + AssemblyName.
                $dotNet = Get-DotNetCheapInfo -Pe $pe -FilePath $resolved
                if ($null -eq $dotNet) {
                    $dotNet = [pscustomobject]@{ IsManaged = $false }
                } elseif ($IncludeDotNetTypes) {
                    $deep = Get-DotNetDeepInfo -FilePath $resolved -IncludeTypes $true
                    if ($deep) {
                        $dotNet.IsComVisible = $deep.IsComVisible
                        $dotNet.Types        = $deep.Types
                    }
                }
                $result.DotNet = $dotNet

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
}
